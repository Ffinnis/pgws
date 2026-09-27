// Package freshness authenticates source WAL lower bounds. Tokens authorize no
// data access; callers must separately authorize source and baseline lineage.
package freshness

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"pgws/internal/physical"
	"strings"
	"time"
)

const domain = "pgws/source-barrier/v1\x00"

type Claims struct {
	ID          string    `json:"id"`
	Authority   string    `json:"authority_epoch"`
	Tenant      string    `json:"tenant_id"`
	Project     string    `json:"project_id"`
	Source      string    `json:"source_id"`
	SourceEpoch int64     `json:"source_epoch"`
	SystemID    string    `json:"system_id"`
	Timeline    int64     `json:"timeline"`
	LSN         string    `json:"lsn"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func valid(c Claims) bool {
	_, err := physical.ParseLSN(c.LSN)
	return err == nil && c.ID != "" && c.Authority != "" && c.Tenant != "" && c.Project != "" && c.Source != "" && c.SourceEpoch > 0 && c.SystemID != "" && c.Timeline > 0 && !c.IssuedAt.IsZero() && c.ExpiresAt.After(c.IssuedAt) && c.ExpiresAt.Sub(c.IssuedAt) <= time.Hour
}
func Sign(key ed25519.PrivateKey, c Claims) (string, error) {
	if len(key) != ed25519.PrivateKeySize || !valid(c) {
		return "", errors.New("invalid source barrier claims")
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(key, append([]byte(domain), b...))
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
func Verify(key ed25519.PublicKey, token string, now time.Time) (Claims, error) {
	var c Claims
	if len(key) != ed25519.PublicKeySize || len(token) > 8192 {
		return c, errors.New("invalid source barrier")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid source barrier")
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return c, errors.New("invalid source barrier")
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || !ed25519.Verify(key, append([]byte(domain), b...), sig) {
		return c, errors.New("source barrier signature rejected")
	}
	if json.Unmarshal(b, &c) != nil || !valid(c) {
		return Claims{}, errors.New("source barrier claims are invalid")
	}
	if !now.Before(c.ExpiresAt) {
		return Claims{}, errors.New("source barrier expired")
	}
	if c.IssuedAt.After(now.Add(5 * time.Second)) {
		return Claims{}, errors.New("source barrier issuance is in the future")
	}
	return c, nil
}
