package host

import (
	"context"
	"errors"
	"pgws/internal/control"
	"pgws/internal/storage/zfs"
)

func (h *Host) collectSnapshot(ctx context.Context, t control.Task) (control.Outcome, error) {
	if !control.ValidID(t.Snapshot.Baseline) || t.Command.Workspace != t.SourceID || t.Snapshot.BaselineGeneration < 1 || t.Snapshot.BaselineGeneration > t.Command.Generation {
		return control.Outcome{}, errors.New("snapshot cleanup baseline identity differs")
	}
	target := t
	target.Command.Generation = t.Snapshot.BaselineGeneration
	s, e := h.load(target)
	if e != nil {
		return control.Outcome{}, e
	}
	if s.Outcome.Source == nil || s.Outcome.Source.Snapshot.Baseline != t.Snapshot.Baseline || s.Outcome.Source.Snapshot.SourceEpoch != t.Snapshot.SourceEpoch {
		return control.Outcome{}, errors.New("snapshot cleanup lineage differs")
	}
	if target.Command.Generation == t.Command.Generation {
		if e = h.storage.VerifyGeneration(ctx, target.Command, s.Volume, "baselines"); e != nil {
			return control.Outcome{}, e
		}
	}
	c := t.Command
	current, ok := h.storageJournal.Current(c.Identity)
	if !ok {
		return control.Outcome{}, errors.New("snapshot storage authority missing")
	}
	c.Token = current.Command.Token + 1
	c.Revision = max(c.Revision, current.Command.Revision)
	ref := zfs.Ref{Name: t.Snapshot.Name, GUID: t.Snapshot.GUID}
	if target.Command.Generation < c.Generation {
		e = h.storage.DestroyRetiredSnapshot(ctx, c, target.Command.Generation, ref, t.Snapshot.ID)
	} else {
		e = h.storage.DestroySnapshot(ctx, c, ref, t.Snapshot.ID)
	}
	if e != nil {
		return control.Outcome{}, e
	}
	if e = h.collectRetiredSourceVolume(ctx, t, target, &s); e != nil {
		return control.Outcome{}, e
	}
	return control.Outcome{Phase: "snapshot_deleted"}, nil
}
