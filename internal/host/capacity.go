package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"pgws/internal/control"
	"pgws/internal/storage/zfs"
)

func profileMemory(profile string) (int64, error) {
	switch profile {
	case "", "small":
		return 1 << 30, nil
	case "medium":
		return 2 << 30, nil
	default:
		return 0, errors.New("unsupported resource profile")
	}
}

// Reserve before external effects. Failed and paused generations remain
// charged until removal is confirmed; restart cannot erase their reservations.
func (h *Host) reserve(ctx context.Context, t control.Task, s state) error {
	return h.capacityCheck(ctx, t, s, true)
}
func (h *Host) capacityCheck(ctx context.Context, t control.Task, s state, persist bool) error {
	h.capacity.Lock()
	defer h.capacity.Unlock()
	max := h.Config.MaxManagedMemory
	if max == 0 {
		max = 4 << 30
	}
	floor := h.Config.MinPoolAvailable
	if floor == 0 {
		floor = 256 << 20
	}
	if max < 1<<30 || floor < 32<<20 || s.ReservedMemory < 256<<20 {
		return errors.New("invalid host capacity policy")
	}
	paths, e := filepath.Glob(filepath.Join(h.Config.Root, "objects", "*", "*", "state.json"))
	if e != nil {
		return e
	}
	if len(paths) > 10000 {
		return errors.New("host generation inventory limit reached")
	}
	total := s.ReservedMemory
	for _, path := range paths {
		if path == filepath.Join(h.folder(t), "state.json") {
			continue
		}
		var old state
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if json.Unmarshal(b, &old) != nil {
			return errors.New("unreadable capacity reservation")
		}
		if old.Phase == "deleted" {
			continue
		}
		memory, e := chargedMemory(filepath.Dir(path), old)
		if e != nil {
			return e
		}
		if memory < 0 || memory > max-total {
			return errors.New("host memory admission limit reached")
		}
		total += memory
	}
	if total > max {
		return errors.New("host memory admission limit reached")
	}
	available, e := h.storage.Available(ctx)
	if e != nil {
		return e
	}
	if available < floor {
		return errors.New("ZFS free-space reserve reached")
	}
	if _, e = h.projectAllocation(ctx, t); e != nil {
		return e
	}
	if persist {
		return h.save(t, s)
	}
	return nil
}

type projectAllocation struct {
	Tenant  string  `json:"tenant"`
	Project string  `json:"project"`
	Quota   int64   `json:"quota_bytes"`
	Ref     zfs.Ref `json:"dataset"`
}

// Caller holds the host capacity lock. Limits are fixed for the provisioned
// project; changing them needs an explicit administrative migration, not a stale
// workspace task replay. The GUID record lives outside the charged datasets.
func (h *Host) projectAllocation(ctx context.Context, t control.Task) (zfs.Allocation, error) {
	limit := h.Config.ProjectQuotaBytes
	if limit == 0 {
		limit = 2 << 30
	}
	if !control.ValidID(t.Command.Tenant) || !control.ValidID(t.Command.Project) || limit < 128<<20 || limit > 1<<60 {
		return zfs.Allocation{}, errors.New("invalid project allocation policy")
	}
	path := filepath.Join(h.Config.Root, "project-limits", t.Command.Tenant, t.Command.Project+".json")
	var old projectAllocation
	b, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(b, &old) != nil || old.Tenant != t.Command.Tenant || old.Project != t.Command.Project || old.Quota != limit || old.Ref.GUID == "" {
			return zfs.Allocation{}, errors.New("project quota differs from its durable allocation policy")
		}
	} else if !os.IsNotExist(err) {
		return zfs.Allocation{}, err
	}
	ref, err := h.storage.EnsureProject(ctx, t.Command, limit, old.Ref)
	if err != nil {
		return zfs.Allocation{}, err
	}
	if old.Ref.GUID == "" {
		if err = save(path, projectAllocation{Tenant: t.Command.Tenant, Project: t.Command.Project, Quota: limit, Ref: ref}); err != nil {
			return zfs.Allocation{}, err
		}
	}
	allocation, err := h.storage.ProjectAllocation(ctx, t.Command, ref)
	if err != nil {
		return allocation, err
	}
	if allocation.Available < 32<<20 {
		return allocation, errors.New("project allocation growth allowance exhausted")
	}
	return allocation, nil
}
