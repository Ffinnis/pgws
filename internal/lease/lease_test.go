package lease

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestLeaseAuthorityAndDeadline(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	id := Identity{"epoch", "tenant", "project", "workspace", "host", 1, 1}
	c := Claims{id, now, now.Add(120 * time.Second), now.Add(time.Hour)}
	token, _ := Sign(key, c)
	_, deadline, e := Verify(pub, token, id, now)
	if e != nil || deadline.Sub(now) != 115*time.Second {
		t.Fatalf("deadline: %v %v", deadline, e)
	}
	for name, alter := range map[string]func(*Identity){"host": func(i *Identity) { i.Host = "other" }, "epoch": func(i *Identity) { i.Epoch = "restored" }, "generation": func(i *Identity) { i.Generation++ }, "revision": func(i *Identity) { i.Revision++ }, "tenant": func(i *Identity) { i.Tenant = "other" }} {
		t.Run(name, func(t *testing.T) {
			other := id
			alter(&other)
			if _, _, e := Verify(pub, token, other, now); e == nil {
				t.Fatal("accepted wrong identity")
			}
		})
	}
	if _, _, e := Verify(pub, token+"x", id, now); e == nil {
		t.Fatal("accepted tampered lease")
	}
	if _, _, e := Verify(pub, token, id, now.Add(116*time.Second)); e == nil {
		t.Fatal("accepted expired lease")
	}
	c.ExpiresAt = now.Add(121 * time.Second)
	tooLong, _ := Sign(key, c)
	if _, _, e := Verify(pub, tooLong, id, now); e == nil {
		t.Fatal("accepted long lease")
	}
	c.ExpiresAt = now.Add(120 * time.Second)
	c.WorkspaceExpiry = now.Add(30 * time.Second)
	short, _ := Sign(key, c)
	_, d, e := Verify(pub, short, id, now)
	if e != nil || d.Sub(now) != 25*time.Second {
		t.Fatal("workspace expiry not enforced")
	}
	var g Guard
	if !g.Tick(now) {
		t.Fatal("guard starts open")
	}
	if e = g.Install(pub, token, id, now); e != nil {
		t.Fatal(e)
	}
	if g.Tick(now) {
		t.Fatal("fresh lease closed")
	}
	if e = g.Install(pub, token, id, now.Add(-time.Minute)); e == nil {
		t.Fatal("replay extended authority after clock rollback")
	}
	if !g.Tick(now.Add(115 * time.Second)) {
		t.Fatal("deadline not enforced")
	}
	var expired Guard
	if e = expired.Install(pub, short, id, now); e != nil {
		t.Fatal(e)
	}
	if !expired.Tick(now.Add(25 * time.Second)) {
		t.Fatal("workspace not expired")
	}
	c.IssuedAt = now.Add(26 * time.Second)
	c.ExpiresAt = now.Add(100 * time.Second)
	c.WorkspaceExpiry = now.Add(time.Hour)
	resurrect, _ := Sign(key, c)
	if e = expired.Install(pub, resurrect, id, now.Add(26*time.Second)); e == nil {
		t.Fatal("expired workspace resurrected")
	}
}

func TestRenewalCannotRelaxWorkspaceMonotonicBound(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	id := Identity{"epoch", "tenant", "project", "workspace", "host", 1, 1}
	c := Claims{id, now, now.Add(time.Minute), now.Add(time.Hour)}
	token, _ := Sign(key, c)
	var g Guard
	if err := g.Install(pub, token, id, now); err != nil {
		t.Fatal(err)
	}
	// An already established conservative bound wins over a later wall-based
	// conversion of the same signed expiry, including after clock adjustment.
	bound := now.Add(10 * time.Second)
	g.workspaceDeadline = bound
	c.IssuedAt = now.Add(time.Second)
	c.ExpiresAt = c.IssuedAt.Add(time.Minute)
	token, _ = Sign(key, c)
	if err := g.Install(pub, token, id, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !g.Deadline.Equal(bound) || !g.workspaceDeadline.Equal(bound) {
		t.Fatal("renewal relaxed established workspace deadline")
	}
	if !g.Tick(bound) {
		t.Fatal("workspace expiry retained authority")
	}
}
