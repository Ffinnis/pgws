package ingress

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"pgws/internal/lease"
)

func TestRuntimeReceiptBoundsAndIdentity(t *testing.T) {
	c, key, _ := fixture(t)
	pub, _ := base64.StdEncoding.DecodeString(c.AuthorityKey)
	now := time.Now().UTC()
	claims := lease.Claims{Identity: c.Identity, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second), WorkspaceExpiry: now.Add(time.Hour)}
	token, _ := lease.Sign(key, claims)
	anchor := int64(time.Hour)
	original := receipt{Identity: c.Identity, LastIssued: now, Expiry: claims.WorkspaceExpiry, Runtime: &RuntimeAuthority{Token: token, ReceivedAt: now, BootID: "boot-a", ReceivedNS: anchor, DeadlineNS: anchor + int64(25*time.Second), WorkspaceDeadlineNS: anchor + int64(time.Hour-5*time.Second)}}
	for _, tc := range []struct {
		name             string
		boot             string
		tick             int64
		alter            func(*receipt)
		expired, invalid bool
	}{
		{"active", "boot-a", anchor + int64(time.Second), nil, false, false},
		{"deadline", "boot-a", anchor + int64(25*time.Second), nil, true, false},
		{"reboot", "boot-b", 1, nil, true, false},
		{"counter_rollback", "boot-a", anchor - 1, nil, true, false},
		{"foreign_generation", "boot-a", anchor, func(r *receipt) { r.Identity.Generation++ }, true, true},
		{"forged_token", "boot-a", anchor, func(r *receipt) { r.Runtime.Token += "x" }, true, true},
		{"extended_deadline", "boot-a", anchor, func(r *receipt) { r.Runtime.DeadlineNS++ }, true, true},
		{"terminal", "boot-a", anchor, func(r *receipt) { r.Terminal = true }, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := original
			a := *original.Runtime
			r.Runtime = &a
			if tc.alter != nil {
				tc.alter(&r)
			}
			b, _ := json.Marshal(r)
			if err := os.WriteFile(c.StateFile, b, 0600); err != nil {
				t.Fatal(err)
			}
			_, expired, err := RuntimeLease(c.StateFile, ed25519.PublicKey(pub), c.Identity, tc.boot, tc.tick)
			if expired != tc.expired || (err != nil) != tc.invalid {
				t.Fatalf("expired=%v err=%v", expired, err)
			}
		})
	}
	// State inventory may lag a signed guard renewal by one lifecycle revision.
	claims.Revision++
	token, _ = lease.Sign(key, claims)
	original.Identity = claims.Identity
	original.Runtime.Token = token
	b, _ := json.Marshal(original)
	if err := os.WriteFile(c.StateFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, expired, err := RuntimeLease(c.StateFile, pub, c.Identity, "boot-a", anchor); err != nil || expired {
		t.Fatal("newer signed revision raced state inventory", expired, err)
	}
}
