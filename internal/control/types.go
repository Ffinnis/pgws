package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

type Object = map[string]any
type Fault struct {
	Status    int    `json:"-"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *Fault) Error() string { return e.Code }
func fail(status int, code, message string) error {
	return &Fault{Status: status, Code: code, Message: message, Retryable: status == 503}
}
func ID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[:8], s[8:12], s[12:16], s[16:20], s[20:])
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func ValidID(s string) bool { return uuidPattern.MatchString(s) }

type Principal struct {
	ID, Tenant, Project string
	Admin, Raw          bool
}
type Freshness struct {
	Mode         string `json:"mode"`
	SnapshotID   string `json:"snapshot_id,omitempty"`
	BarrierToken string `json:"barrier_token,omitempty"`
}

// Each mode has its own closed shape; even an empty field from another mode is invalid.
func (f *Freshness) UnmarshalJSON(b []byte) error {
	type plain Freshness
	var value plain
	if err := decode(b, &value, "mode"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	want := 2
	if value.Mode == "latest" {
		want = 1
	}
	if len(fields) != want {
		return fail(400, "INVALID_REQUEST", "Freshness fields do not match its mode")
	}
	*f = Freshness(value)
	return checkFreshness(*f)
}

type CreateWorkspace struct {
	BaselineID   string    `json:"baseline_id"`
	TaskID       string    `json:"task_id"`
	Freshness    Freshness `json:"freshness"`
	Profile      string    `json:"resource_profile"`
	TTL          int       `json:"ttl_seconds"`
	CodeRevision string    `json:"code_revision,omitempty"`
}
type Action struct {
	Action         string     `json:"action"`
	Generation     int64      `json:"expected_generation"`
	ExpectedExpiry time.Time  `json:"expected_expires_at,omitempty"`
	Expiry         time.Time  `json:"expires_at,omitempty"`
	Discard        bool       `json:"discard_local_changes,omitempty"`
	BaselineID     string     `json:"baseline_id,omitempty"`
	Freshness      *Freshness `json:"freshness,omitempty"`
}
type SourceRequest struct {
	Connector string `json:"connector"`
	Endpoint  string `json:"approved_endpoint_reference"`
	Secret    string `json:"secret_reference"`
}
