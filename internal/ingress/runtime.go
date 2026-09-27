package ingress

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"

	"pgws/internal/lease"
)

// RuntimeAuthority is written by the guard before acknowledging a lease.
// The file is root-owned and never mounted into a workspace container.
type RuntimeAuthority struct {
	Token               string    `json:"token"`
	ReceivedAt          time.Time `json:"received_at"`
	BootID              string    `json:"boot_id"`
	ReceivedNS          int64     `json:"received_ns"`
	DeadlineNS          int64     `json:"deadline_ns"`
	WorkspaceDeadlineNS int64     `json:"workspace_deadline_ns"`
}

func (s *Server) runtimeStopped() bool {
	if s.config.RuntimeStopFile == "" {
		return false
	}
	_, err := os.Lstat(s.config.RuntimeStopFile)
	return !os.IsNotExist(err)
}

// RuntimeLease reads only durable guard evidence. It never calls the guard,
// so a SIGSTOP or failed control socket cannot block expiry enforcement.
func RuntimeLease(path string, key ed25519.PublicKey, want lease.Identity, boot string, ticks int64) (revision int64, expired bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false, err
	}
	var r receipt
	if len(b) > 2<<20 || json.Unmarshal(b, &r) != nil || r.Runtime == nil {
		return 0, true, errors.New("runtime lease evidence unavailable")
	}
	a := r.Runtime
	revision = r.Identity.Revision
	// A renewal can be newer than the watchdog's state.json read. Its signed
	// generation identity remains authoritative; rejecting the newer revision
	// here would kill a healthy runtime during ordinary credential issuance.
	if revision < 1 {
		return revision, true, lease.ErrLease
	}
	want.Revision = revision
	claims, deadline, err := lease.Verify(key, a.Token, want, a.ReceivedAt)
	if err != nil || r.Identity != want || !claims.IssuedAt.Equal(r.LastIssued) || !claims.WorkspaceExpiry.Equal(r.Expiry) || a.ReceivedNS < 0 || a.DeadlineNS <= a.ReceivedNS || a.WorkspaceDeadlineNS <= 0 || a.DeadlineNS > a.ReceivedNS+int64(deadline.Sub(a.ReceivedAt)) || a.DeadlineNS > a.WorkspaceDeadlineNS {
		return revision, true, lease.ErrLease
	}
	return revision, r.Terminal || a.BootID != boot || ticks < a.ReceivedNS || ticks >= a.DeadlineNS, nil
}
