package zfs

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"pgws/internal/lease"
)

// RootAvailable is the read-only capacity probe used by an independently
// supervised watchdog. It neither opens the host mutation journal nor needs
// that process's lock, and still verifies the root's local ownership label.
func RootAvailable(ctx context.Context, binary, root string) (int64, error) {
	if !filepath.IsAbs(binary) || !datasetPattern.MatchString(root) {
		return 0, errors.New("invalid ZFS capacity probe scope")
	}
	b := &Backend{root: root, run: commandRunner{Binary: binary}}
	return b.Available(ctx)
}

func ReadProjectAllocation(ctx context.Context, binary, root string, c lease.Command, ref Ref) (Allocation, error) {
	if !filepath.IsAbs(binary) || !datasetPattern.MatchString(root) {
		return Allocation{}, errors.New("invalid ZFS allocation probe scope")
	}
	b := &Backend{root: root, run: commandRunner{Binary: binary}}
	return b.ProjectAllocation(ctx, c, ref)
}

// EnsureProject provisions an immutable hard allocation limit at the common
// ancestor of a project's baseline, snapshots and clones. It never changes an
// existing limit or adopts an unlabelled ancestor. The authenticated host keeps
// the returned GUID durably and supplies it on subsequent calls; replacing or
// deleting that ancestor therefore cannot silently reset its accounting.
func (b *Backend) EnsureProject(ctx context.Context, c lease.Command, maxBytes int64, expected Ref) (Ref, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	name, err := b.scope(c)
	if err != nil || maxBytes < 128<<20 || maxBytes > 1<<60 {
		return Ref{}, errors.New("invalid project allocation policy")
	}
	if expected.Name != "" && (expected.Name != name || expected.GUID == "") {
		return Ref{}, errors.New("project allocation identity differs")
	}
	items, err := b.inventory(ctx)
	if err != nil {
		return Ref{}, err
	}
	want := map[string]string{"org.pgws:tenant": c.Tenant, "org.pgws:project": c.Project, "org.pgws:managed": "project", "quota": strconv.FormatInt(maxBytes, 10), "mountpoint": "none", "canmount": "off"}
	if _, exists := items[name]; !exists {
		if expected.GUID != "" {
			return Ref{}, errors.New("recorded project dataset was removed; refuse recreation")
		}
		args := append([]string{"create", "-p"}, propertyArgs(want)...)
		if _, err = b.run.Run(ctx, append(args, name)...); err != nil {
			return Ref{}, err
		}
		items, err = b.inventory(ctx)
		if err != nil {
			return Ref{}, err
		}
	}
	found, exists := items[name]
	if !exists || found.Kind != "filesystem" || found.Origin != "-" || (expected.GUID != "" && expected.GUID != found.GUID) {
		return Ref{}, errors.New("project allocation dataset GUID or type differs")
	}
	if err = b.owned(ctx, name, want); err != nil {
		return Ref{}, err
	}
	return found.Ref, nil
}

// Allocation reports physical allocation at one common ancestor. Referenced is
// a separate logical-size gauge and must not be summed across shared clones as
// a measure of physical growth. Quota includes descendants and pinned snapshots.
type Allocation struct {
	Project       Ref   `json:"project_dataset"`
	Quota         int64 `json:"quota_bytes"`
	Used          int64 `json:"used_bytes"`
	Available     int64 `json:"available_bytes"`
	Referenced    int64 `json:"referenced_bytes"`
	ByDataset     int64 `json:"used_by_dataset_bytes"`
	ByChildren    int64 `json:"used_by_children_bytes"`
	BySnapshots   int64 `json:"used_by_snapshots_bytes"`
	ByReservation int64 `json:"used_by_refreservation_bytes"`
}

func (b *Backend) ProjectAllocation(ctx context.Context, c lease.Command, ref Ref) (Allocation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var result Allocation
	scope, err := b.scope(c)
	if err != nil || ref.Name != scope || ref.GUID == "" {
		return result, errors.New("invalid project allocation identity")
	}
	items, err := b.inventory(ctx)
	if err != nil {
		return result, err
	}
	if _, err = verify(items, ref, "filesystem"); err != nil {
		return result, err
	}
	if err = b.owned(ctx, ref.Name, map[string]string{"org.pgws:tenant": c.Tenant, "org.pgws:project": c.Project, "org.pgws:managed": "project"}); err != nil {
		return result, err
	}
	raw, err := b.run.Run(ctx, "get", "-H", "-p", "-o", "property,value", "quota,used,available,referenced,usedbydataset,usedbychildren,usedbysnapshots,usedbyrefreservation", ref.Name)
	if err != nil {
		return result, err
	}
	values := map[string]*int64{"quota": &result.Quota, "used": &result.Used, "available": &result.Available, "referenced": &result.Referenced, "usedbydataset": &result.ByDataset, "usedbychildren": &result.ByChildren, "usedbysnapshots": &result.BySnapshots, "usedbyrefreservation": &result.ByReservation}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 2 || values[parts[0]] == nil {
			return Allocation{}, errors.New("invalid project allocation counters")
		}
		value, e := strconv.ParseInt(parts[1], 10, 64)
		if e != nil || value < 0 {
			return Allocation{}, errors.New("invalid project allocation value")
		}
		*values[parts[0]] = value
		delete(values, parts[0])
	}
	if len(values) != 0 || result.Quota < 128<<20 {
		return Allocation{}, errors.New("incomplete project allocation or absent quota")
	}
	result.Project = ref
	return result, nil
}
