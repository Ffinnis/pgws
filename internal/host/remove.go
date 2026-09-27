package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"pgws/internal/control"
	"pgws/internal/storage/zfs"
)

// Remove includes an unpublished reset candidate. Its command carries the
// highest attempted generation, so it cannot move host authority backwards.
func (h *Host) remove(ctx context.Context, t control.Task) (control.Outcome, error) {
	if t.Command.Generation < 1 || t.Command.Generation > 10000 {
		return control.Outcome{}, errors.New("cleanup generation limit exceeded")
	}
	for generation := t.Command.Generation; generation >= 1; generation-- {
		target := t
		target.Command.Generation = generation
		s, e := h.load(target)
		if e != nil && !os.IsNotExist(e) {
			return control.Outcome{}, e
		}
		if e == nil {
			if s.Task.Command.Tenant != t.Command.Tenant || s.Task.Command.Project != t.Command.Project || s.Task.Command.Workspace != t.Command.Workspace || s.Task.Command.Generation != generation {
				return control.Outcome{}, errors.New("cleanup resource owner differs")
			}
			if s.Phase == "deleted" {
				continue
			}
		} else {
			s = state{Task: target}
		}
		if s.GuardDirectory != "" {
			_ = guardRequest(ctx, s.GuardDirectory, "shutdown", nil, nil)
		}
		if s.Container.ID == "" {
			if s.RuntimeIntent != nil {
				container, exists, err := h.oci.Lookup(ctx, *s.RuntimeIntent)
				if err != nil {
					return control.Outcome{}, err
				}
				if exists {
					s.Container = container
					if e = h.save(target, s); e != nil {
						return control.Outcome{}, e
					}
				}
			} else if e = h.oci.VerifyAbsent(ctx, target.Command.Identity); e != nil {
				return control.Outcome{}, e
			}
		}
		if s.Container.ID != "" {
			if e = h.oci.Remove(ctx, s.Container); e != nil {
				return control.Outcome{}, e
			}
		}
		if s.Volume.GUID == "" {
			record, ok := h.storageJournal.Current(t.Command.Identity)
			if ok && record.Completed && record.Command.Generation == generation && (record.Command.Kind == "zfs-clone" || record.Command.Kind == "zfs-mount") {
				var ref zfs.Ref
				if json.Unmarshal(record.Evidence, &ref) == nil {
					s.Volume = ref
				}
			}
		}
		if s.Volume.GUID != "" {
			step := t.Command.Generation - generation + 1
			if step >= 100 {
				return control.Outcome{}, errors.New("cleanup effect limit exceeded")
			}
			c := storageCommand(t, step)
			if generation == t.Command.Generation {
				e = h.storage.DestroyClone(ctx, c, s.Volume)
			} else {
				e = h.storage.DestroyRetired(ctx, c, generation, s.Volume)
			}
		} else {
			e = h.storage.VerifyCloneAbsent(ctx, target.Command)
		}
		if e != nil {
			return control.Outcome{}, e
		}
		s.Phase = "deleted"
		s.Task = target
		s.Outcome = control.Outcome{Phase: "deleted"}
		if e = h.save(target, s); e != nil {
			return control.Outcome{}, e
		}
	}
	return control.Outcome{Phase: "deleted"}, nil
}
