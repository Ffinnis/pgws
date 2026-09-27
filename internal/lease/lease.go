// Package lease verifies serving authority and computes conservative monotonic
// deadlines. Wiring it to an independent ingress/session guard remains required.
package lease

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrLease = errors.New("invalid serving lease")

type Identity struct {
	Epoch      string `json:"epoch"`
	Tenant     string `json:"tenant"`
	Project    string `json:"project"`
	Workspace  string `json:"workspace"`
	Host       string `json:"host"`
	Generation int64  `json:"generation"`
	Revision   int64  `json:"revision"`
}
type Claims struct {
	Identity
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	WorkspaceExpiry time.Time `json:"workspace_expiry"`
}

func Sign(key ed25519.PrivateKey, c Claims) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", ErrLease
	}
	b, e := json.Marshal(c)
	if e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, b)), nil
}
func Verify(key ed25519.PublicKey, token string, want Identity, now time.Time) (Claims, time.Time, error) {
	var c Claims
	bad := func() (Claims, time.Time, error) { return Claims{}, time.Time{}, ErrLease }
	if len(token) > 8192 || len(key) != ed25519.PublicKeySize {
		return bad()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return bad()
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return bad()
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || !ed25519.Verify(key, b, sig) {
		return bad()
	}
	if json.Unmarshal(b, &c) != nil || c.Identity != want || want.Epoch == "" || want.Tenant == "" || want.Project == "" || want.Workspace == "" || want.Host == "" || want.Generation < 1 || want.Revision < 1 {
		return bad()
	}
	if c.IssuedAt.After(now.Add(5*time.Second)) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 120*time.Second {
		return bad()
	}
	end := c.ExpiresAt
	if c.WorkspaceExpiry.Before(end) {
		end = c.WorkspaceExpiry
	}
	remaining := end.Sub(now) - 5*time.Second
	if remaining <= 0 {
		return bad()
	}
	// Add to the received time to retain its monotonic component. Wall-clock
	// adjustments after installation therefore cannot extend the deadline.
	return c, now.Add(remaining), nil
}

// Guard starts closed. Caller serializes access and invokes CloseAccess whenever
// Tick returns true, even if its ordinary control-plane worker is stalled.
type Guard struct {
	Deadline          time.Time
	lastIssued        time.Time
	workspaceDeadline time.Time
	workspaceExpiry   time.Time
	terminal          bool
	open              bool
}

func (g *Guard) Install(key ed25519.PublicKey, token string, want Identity, now time.Time) error {
	if g.terminal || (!g.workspaceDeadline.IsZero() && !now.Before(g.workspaceDeadline)) {
		g.terminal = true
		g.open = false
		return ErrLease
	}
	c, deadline, e := Verify(key, token, want, now)
	if e != nil {
		return e
	}
	if !g.lastIssued.IsZero() && !c.IssuedAt.After(g.lastIssued) {
		return ErrLease
	}
	workspaceDeadline := now.Add(c.WorkspaceExpiry.Sub(now) - 5*time.Second)
	if c.WorkspaceExpiry.Equal(g.workspaceExpiry) && g.workspaceDeadline.Before(workspaceDeadline) {
		workspaceDeadline = g.workspaceDeadline
	}
	if workspaceDeadline.Before(deadline) {
		deadline = workspaceDeadline
	}
	g.Deadline = deadline
	g.lastIssued = c.IssuedAt
	g.workspaceDeadline = workspaceDeadline
	g.workspaceExpiry = c.WorkspaceExpiry
	g.open = true
	return nil
}
func (g *Guard) Tick(now time.Time) bool {
	if !g.workspaceDeadline.IsZero() && !now.Before(g.workspaceDeadline) {
		g.terminal = true
	}
	if g.terminal || !g.open || !now.Before(g.Deadline) {
		g.open = false
		return true
	}
	return false
}
