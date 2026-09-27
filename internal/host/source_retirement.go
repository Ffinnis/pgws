package host

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/storage/zfs"
)

// Captures and GC advance storage fences independently of API source jobs.
// Source serialization is held by the caller, so never derive a new storage
// fence solely from the less frequent management operation count.
func (h *Host) sourceStorageCommand(t control.Task, step int64) lease.Command {
	c := storageCommand(t, step)
	if current, ok := h.storageJournal.Current(c.Identity); ok {
		c.Token = max(c.Token, current.Command.Token+1)
		c.Revision = max(c.Revision, current.Command.Revision)
	}
	return c
}

// The caller holds source authority for the next generation. Existing snapshots
// and workspace clones stay intact; only upstream ingestion is retired here.
func (h *Host) retireSource(ctx context.Context, next control.Task) error {
	paths, err := filepath.Glob(filepath.Join(h.Config.Root, "objects", next.SourceID, "*", "state.json"))
	if err != nil {
		return err
	}
	if len(paths) > 10000 {
		return errors.New("source generation inventory exceeds host limit")
	}
	for _, path := range paths {
		generation, err := strconv.ParseInt(filepath.Base(filepath.Dir(path)), 10, 64)
		if err != nil || generation < 1 || generation > next.Command.Generation {
			return errors.New("source generation path differs")
		}
		if generation == next.Command.Generation {
			continue
		}
		if err = h.retireSourceGeneration(ctx, next, generation); err != nil {
			return err
		}
	}
	return nil
}

func (h *Host) retireSourceGeneration(ctx context.Context, next control.Task, generation int64) error {
	previous := next
	previous.Command.Generation = generation
	s, err := h.load(previous)
	if err != nil {
		return err
	}
	id := s.Task.Command.Identity
	if id.Epoch != next.Command.Epoch || id.Host != next.Command.Host || id.Tenant != next.Command.Tenant || id.Project != next.Command.Project || id.Workspace != next.SourceID || id.Generation != previous.Command.Generation || s.Task.SourceID != next.SourceID {
		return errors.New("previous source generation owner differs")
	}
	if err = recordStop(h.folder(previous), "SOURCE_RESEEDED"); err != nil {
		return err
	}
	if err = removeStoppedRuntime(ctx, h.oci, h.folder(previous), s); err != nil {
		return err
	}
	if s.Container.ID == "" {
		if err = h.oci.VerifyAbsent(ctx, s.Task.Command.Identity); err != nil {
			return err
		}
		if err = recordAbsentRuntimeRelease(h.folder(previous), s.Task.Command.Identity); err != nil {
			return err
		}
	}
	h.sourceEffect("previous_runtime")
	if s.SlotOwned {
		source, err := h.resolve(s.Task)
		if err != nil {
			return err
		}
		source.ExpectedSystemID = s.SourceIdentity.SystemID
		// A changed system ID is deliberately not treated as proof that the old
		// slot disappeared. Resolve its cleanup before reseeding this reference.
		if err = source.DropSlot(ctx, s.Slot); err != nil {
			return err
		}
		s.SlotOwned = false
		s.SlotRetired = true
	} else if s.Slot != "" && !s.SlotRetired {
		return errors.New("unconfirmed previous source slot requires reconciliation")
	}
	h.sourceEffect("previous_slot")
	s.Phase = "blocked"
	if err = h.save(previous, s); err != nil {
		return err
	}
	if err = h.collectRetiredSourceVolume(ctx, next, previous, &s); err != nil {
		return err
	}
	h.sourceEffect("previous_retired")
	return nil
}

func (h *Host) collectRetiredSourceVolume(ctx context.Context, authority, target control.Task, s *state) error {
	if target.Command.Generation >= authority.Command.Generation || !s.SlotRetired || s.Volume.GUID == "" {
		return nil
	}
	if err := checkStopped(h.folder(target)); err == nil {
		return nil
	}
	if _, err := readStop(h.folder(target)); err != nil {
		return err
	}
	if err := h.oci.VerifyAbsent(ctx, s.Task.Command.Identity); err != nil {
		return err
	}
	err := h.storage.DestroyRetiredBaseline(ctx, h.sourceStorageCommand(authority, 4), target.Command.Generation, s.Volume)
	if errors.Is(err, zfs.ErrBaselineReferenced) {
		return nil
	}
	if err != nil {
		return err
	}
	s.Phase = "deleted"
	return h.save(target, *s)
}
