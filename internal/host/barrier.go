package host

import (
	"context"
	"errors"
	"pgws/internal/control"
)

func (h *Host) issueBarrier(ctx context.Context, t control.Task) (control.Outcome, error) {
	s, e := h.load(t)
	if e != nil {
		return control.Outcome{}, e
	}
	if s.Phase != "streaming" || s.Task.Command.Tenant != t.Command.Tenant || s.Task.Command.Project != t.Command.Project || s.Outcome.Source == nil || s.Outcome.Source.Snapshot.SourceEpoch != t.SourceContract.SourceEpoch || s.SourceIdentity.SystemID != t.SourceContract.SystemID || s.SourceIdentity.Timeline != t.SourceContract.Timeline {
		return control.Outcome{}, errors.New("source baseline authority changed")
	}
	source, e := h.resolve(t)
	if e != nil {
		return control.Outcome{}, e
	}
	source.ExpectedSystemID = t.SourceContract.SystemID
	b, e := source.CaptureBarrier(ctx)
	if e != nil {
		return control.Outcome{}, e
	}
	if b.Timeline != t.SourceContract.Timeline {
		return control.Outcome{}, errors.New("source timeline changed")
	}
	c := t.SourceContract
	c.LSN = b.LSN
	return control.Outcome{Phase: "barrier", Barrier: &c}, nil
}
