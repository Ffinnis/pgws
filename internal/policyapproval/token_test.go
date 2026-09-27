package policyapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestApprovalScopeAndSignature(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now().UTC()
	id := "12345678-1234-1234-1234-123456789abc"
	c := Claims{Binding: Binding{Authority: id, Tenant: id, Project: id, Policy: id, Source: id, SourceEpoch: 1, SystemID: "12345", Timeline: 1, PlanHash: strings.Repeat("a", 64), SchemaHash: strings.Repeat("b", 64), KeyFingerprint: strings.Repeat("c", 64), Compiler: "pgws-transform-v1"}, ApprovedAt: now.Add(-time.Hour), IssuedAt: now, ExpiresAt: now.Add(90 * time.Second)}
	token, err := Sign(key, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(pub, token, c.Binding, now); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*Binding){
		"authority": func(b *Binding) { b.Authority = "22345678-1234-1234-1234-123456789abc" },
		"tenant":    func(b *Binding) { b.Tenant = "22345678-1234-1234-1234-123456789abc" },
		"project":   func(b *Binding) { b.Project = "22345678-1234-1234-1234-123456789abc" },
		"policy":    func(b *Binding) { b.Policy = "22345678-1234-1234-1234-123456789abc" },
		"source":    func(b *Binding) { b.Source = "22345678-1234-1234-1234-123456789abc" },
		"epoch":     func(b *Binding) { b.SourceEpoch++ }, "system": func(b *Binding) { b.SystemID = "12346" }, "timeline": func(b *Binding) { b.Timeline++ },
		"plan": func(b *Binding) { b.PlanHash = strings.Repeat("d", 64) }, "schema": func(b *Binding) { b.SchemaHash = strings.Repeat("d", 64) }, "key": func(b *Binding) { b.KeyFingerprint = strings.Repeat("d", 64) }, "compiler": func(b *Binding) { b.Compiler = "unqualified" },
	} {
		t.Run(name, func(t *testing.T) {
			expected := c.Binding
			alter(&expected)
			if _, e := Verify(pub, token, expected, now); e == nil {
				t.Fatal("changed binding accepted")
			}
		})
	}
	for _, at := range []time.Time{now.Add(-6 * time.Second), now.Add(85 * time.Second), now.Add(time.Hour)} {
		if _, err = Verify(pub, token, c.Binding, at); err == nil {
			t.Fatal("invalid clock boundary accepted")
		}
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
	if _, err = Verify(other, token, c.Binding, now); err == nil {
		t.Fatal("wrong authority accepted")
	}
	parts := strings.Split(token, ".")
	data, _ := base64.RawURLEncoding.DecodeString(parts[0])
	duplicate := strings.Replace(string(data), `"plan_hash":`, `"plan_hash":"`+c.PlanHash+`","plan_hash":`, 1)
	sign := func(payload, prefix string) string {
		signature := ed25519.Sign(key, append([]byte(prefix), []byte(payload)...))
		return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	for _, bad := range []string{sign(duplicate, domain), sign(string(data), "pgws/source-barrier/v1\x00"), token + ".extra"} {
		if _, err = Verify(pub, bad, c.Binding, now); err == nil {
			t.Fatal("malformed or cross-protocol token accepted")
		}
	}
	c.ExpiresAt = now.Add(91 * time.Second)
	if _, err = Sign(key, c); err == nil {
		t.Fatal("unbounded approval signed")
	}
}
