package host

import (
	"context"
	"errors"
	"time"

	"pgws/internal/control"
)

// RevokeServing cannot create authority or advance a host fence. It stops only
// the exact generation/revision/fence observed by the connected control plane.
func (h *Host) RevokeServing(ctx context.Context, t control.Task) (control.StopObservation, error) {
	var out control.StopObservation
	if t.Kind != "revoke_serving" || t.Command.Host != h.Config.ID || t.Command.Epoch != h.Config.Epoch || !control.ValidID(t.Command.Workspace) {
		return out, errors.New("invalid serving revocation scope")
	}
	unlock := h.lock(t.Command.Workspace)
	defer unlock()
	current, ok := h.journal.Current(t.Command.Identity)
	if !ok || current.Command.Identity != t.Command.Identity || current.Command.Token != t.Command.Token {
		return out, errors.New("serving revocation was superseded")
	}
	s, err := h.load(t)
	if err != nil {
		return out, err
	}
	if s.Task.Command.Identity != t.Command.Identity || s.Task.Command.Token != t.Command.Token || s.GuardDirectory == "" || (s.Phase != "ready" && s.Phase != "paused") {
		return out, errors.New("serving revocation generation changed")
	}
	if err = recordStop(h.folder(t), "AUTHORIZATION_REVOKED"); err != nil {
		return out, err
	}
	if err = removeStoppedRuntime(ctx, h.oci, h.folder(t), s); err != nil {
		return out, err
	}
	// Socket closure is best effort after PostgreSQL has gone. A stopped guard
	// must not hold up the durable management revocation acknowledgement.
	closeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_ = guardRequest(closeCtx, s.GuardDirectory, "close", nil, nil)
	cancel()
	t.Kind = "observe_workspace"
	return h.Observe(ctx, t)
}
