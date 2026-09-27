package freshness

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestSignedSourceBarrier(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	c := Claims{ID: "barrier", Authority: "epoch", Tenant: "tenant", Project: "project", Source: "source", SourceEpoch: 1, SystemID: "123", Timeline: 1, LSN: "0/ABC", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	token, e := Sign(key, c)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Verify(pub, token, now)
	if e != nil || got != c {
		t.Fatal(got, e)
	}
	for _, bad := range []string{token + "x", strings.Replace(token, ".", "x.", 1), token + "."} {
		if _, e = Verify(pub, bad, now); e == nil {
			t.Fatal("accepted tampering")
		}
	}
	if _, e = Verify(pub, token, now.Add(time.Hour)); e == nil {
		t.Fatal("accepted expired token")
	}
	if _, e = Verify(pub, token, now.Add(-time.Minute)); e == nil {
		t.Fatal("accepted future token")
	}
}
