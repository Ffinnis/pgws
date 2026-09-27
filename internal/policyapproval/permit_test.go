package policyapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func permitFixture(t *testing.T) (Permit, Claims, ed25519.PrivateKey) {
	t.Helper()
	id := "12345678-1234-1234-1234-123456789abc"
	now := time.Now().UTC()
	c := Claims{Binding: Binding{Authority: id, Tenant: id, Project: id, Policy: id, Source: id, SourceEpoch: 1, SystemID: "12345", Timeline: 1, PlanHash: strings.Repeat("a", 64), SchemaHash: strings.Repeat("b", 64), KeyFingerprint: strings.Repeat("c", 64), Compiler: "pgws-transform-v1"}, ApprovedAt: now.Add(-time.Hour), IssuedAt: now, ExpiresAt: now.Add(90 * time.Second)}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return Permit{Binding: c.Binding, PublicKey: key.Public().(ed25519.PublicKey), Path: filepath.Join(dir, "permit.json"), Runtime: strings.Repeat("d", 64)}, c, key
}

func TestPermitBootDeadline(t *testing.T) {
	p, c, key := permitFixture(t)
	token, _ := Sign(key, c)
	now := c.IssuedAt
	r := receipt{Runtime: p.Runtime, Token: token, ReceivedAt: now, Boot: "boot", ReceivedNS: 100, DeadlineNS: 100 + int64(85*time.Second)}
	for name, alter := range map[string]func(*receipt){
		"other runtime":     func(r *receipt) { r.Runtime = strings.Repeat("e", 64) },
		"changed boot":      func(r *receipt) { r.Boot = "other" },
		"future ticks":      func(r *receipt) { r.ReceivedNS = 1000 },
		"extended deadline": func(r *receipt) { r.DeadlineNS++ },
		"corrupt token":     func(r *receipt) { r.Token += "x" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			alter(&changed)
			if _, err := p.check(changed, "boot", 101); err == nil {
				t.Fatal("accepted changed receipt")
			}
		})
	}
	if _, err := p.check(r, "boot", r.DeadlineNS-1); err != nil {
		t.Fatal(err)
	}
	if _, err := p.check(r, "boot", r.DeadlineNS); err == nil {
		t.Fatal("accepted expired permission")
	}
}

func TestPermitDurabilityAndRenewal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux boot clock required")
	}
	p, c, key := permitFixture(t)
	token, _ := Sign(key, c)
	if err := p.Install(token); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(p.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Check(); err != nil {
		t.Fatal(err)
	}
	if err = p.Install(token); err != nil {
		t.Fatal(err)
	}
	repeated, _ := os.ReadFile(p.Path)
	if !bytes.Equal(first, repeated) {
		t.Fatal("replay extended permission")
	}
	c.IssuedAt = c.IssuedAt.Add(-time.Second)
	c.ExpiresAt = c.ExpiresAt.Add(-time.Second)
	older, _ := Sign(key, c)
	if err = p.Install(older); err == nil {
		t.Fatal("accepted older renewal")
	}
	c.IssuedAt = time.Now().UTC().Add(time.Millisecond)
	c.ExpiresAt = c.IssuedAt.Add(90 * time.Second)
	newer, _ := Sign(key, c)
	if err = p.Install(newer); err != nil {
		t.Fatal(err)
	}
	var r receipt
	data, _ := os.ReadFile(p.Path)
	if json.Unmarshal(data, &r) != nil {
		t.Fatal("receipt decode")
	}
	r.DeadlineNS = r.ReceivedNS + 1
	data, _ = json.Marshal(r)
	if err = os.WriteFile(p.Path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.Check(); err == nil {
		t.Fatal("expired receipt remained active")
	}
	c.IssuedAt = c.IssuedAt.Add(time.Millisecond)
	c.ExpiresAt = c.IssuedAt.Add(90 * time.Second)
	token, _ = Sign(key, c)
	if err = p.Install(token); err == nil {
		t.Fatal("renewal revived expired runtime")
	}
}
