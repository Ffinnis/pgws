// Package policyapproval authenticates a short-lived operator policy decision.
// A token is not evidence of seed completion, integrity or workspace readiness.
package policyapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const domain = "pgws/policy-approval/v1\x00"

type Binding struct {
	Authority      string `json:"authority_epoch"`
	Tenant         string `json:"tenant_id"`
	Project        string `json:"project_id"`
	Policy         string `json:"policy_id"`
	PlanHash       string `json:"plan_hash"`
	SchemaHash     string `json:"schema_hash"`
	Source         string `json:"source_id"`
	SourceEpoch    int64  `json:"source_epoch"`
	SystemID       string `json:"system_id"`
	Timeline       int64  `json:"timeline"`
	KeyFingerprint string `json:"key_fingerprint"`
	Compiler       string `json:"compiler_version"`
}

type Claims struct {
	Binding
	ApprovedAt time.Time `json:"approved_at"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func valid(c Claims) bool {
	for _, id := range []string{c.Authority, c.Tenant, c.Project, c.Policy, c.Source} {
		if !uuid.MatchString(id) {
			return false
		}
	}
	for _, hash := range []string{c.PlanHash, c.SchemaHash, c.KeyFingerprint} {
		if !digest.MatchString(hash) {
			return false
		}
	}
	system, err := strconv.ParseUint(c.SystemID, 10, 64)
	return err == nil && system > 0 && strconv.FormatUint(system, 10) == c.SystemID && c.SourceEpoch > 0 && c.Timeline > 0 && c.Compiler == "pgws-transform-v1" && !c.ApprovedAt.IsZero() && !c.IssuedAt.IsZero() && !c.ApprovedAt.After(c.IssuedAt.Add(5*time.Second)) && c.ExpiresAt.After(c.IssuedAt) && c.ExpiresAt.Sub(c.IssuedAt) <= 90*time.Second
}

func Sign(key ed25519.PrivateKey, c Claims) (string, error) {
	if len(key) != ed25519.PrivateKeySize || !valid(c) {
		return "", errors.New("invalid policy approval claims or key")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		return "", errors.New("policy signing key is inconsistent")
	}
	c.ApprovedAt, c.IssuedAt, c.ExpiresAt = c.ApprovedAt.UTC(), c.IssuedAt.UTC(), c.ExpiresAt.UTC()
	data, err := json.Marshal(c)
	if err != nil {
		return "", errors.New("policy approval encoding failed")
	}
	sig := ed25519.Sign(key, append([]byte(domain), data...))
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify requires the entire expected binding, including the externally pinned
// authority epoch and key fingerprint. Five seconds are subtracted from expiry
// to account conservatively for the qualified host clock error.
func Verify(key ed25519.PublicKey, token string, expected Binding, now time.Time) (Claims, error) {
	var empty Claims
	if len(key) != ed25519.PublicKeySize || len(token) > 8192 || now.IsZero() {
		return empty, errors.New("invalid policy approval")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return empty, errors.New("invalid policy approval")
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return empty, errors.New("invalid policy approval encoding")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || !ed25519.Verify(key, append([]byte(domain), data...), sig) {
		return empty, errors.New("policy approval signature rejected")
	}
	var claims Claims
	if json.Unmarshal(data, &claims) != nil || !valid(claims) {
		return empty, errors.New("policy approval claims rejected")
	}
	canonical, _ := json.Marshal(claims)
	if !bytes.Equal(data, canonical) || claims.Binding != expected {
		return empty, errors.New("policy approval binding or encoding differs")
	}
	if claims.IssuedAt.After(now.Add(5*time.Second)) || !now.Before(claims.ExpiresAt.Add(-5*time.Second)) {
		return empty, errors.New("policy approval expired or issued in the future")
	}
	return claims, nil
}
