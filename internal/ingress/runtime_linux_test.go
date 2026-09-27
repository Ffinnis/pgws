//go:build linux

package ingress

import (
	"path/filepath"
	"testing"
	"time"

	"pgws/internal/lease"
)

func TestBootExpiryCannotBeRevivedByWorkspaceExtension(t *testing.T) {
	c, key, _ := fixture(t)
	c.RuntimeStopFile = filepath.Join(filepath.Dir(c.StateFile), "safety-stop.json")
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := lease.Claims{Identity: c.Identity, IssuedAt: now, ExpiresAt: now.Add(time.Minute), WorkspaceExpiry: now.Add(time.Hour)}
	token, _ := lease.Sign(key, claims)
	if err = s.Install(token); err != nil {
		t.Fatal(err)
	}
	boot, ticks, err := lease.BootClock()
	if err != nil {
		t.Fatal(err)
	}
	if s.state.Runtime == nil || s.state.Runtime.BootID != boot || s.state.Runtime.ReceivedNS > ticks {
		t.Fatal("missing boot-clock receipt")
	}
	// Represent a prior conservative workspace deadline already elapsed on the
	// boot clock, while wall time and a later signed extension still look valid.
	s.state.Runtime.WorkspaceDeadlineNS = ticks - 1
	if err = s.persist(); err != nil {
		t.Fatal(err)
	}
	s, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	claims.IssuedAt = time.Now()
	claims.ExpiresAt = claims.IssuedAt.Add(time.Minute)
	claims.WorkspaceExpiry = claims.WorkspaceExpiry.Add(time.Hour)
	token, _ = lease.Sign(key, claims)
	if err = s.Install(token); err == nil {
		t.Fatal("extension revived expired boot-clock authority")
	}
	if s.Active() || !s.state.Terminal {
		t.Fatal("boot-clock expiry did not remain terminal")
	}
}
