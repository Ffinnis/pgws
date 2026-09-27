package host

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pgws/internal/hostclient"
	"pgws/internal/runtime"
)

// LogicalApprovalHandler accepts signed renewals for exactly one operator-
// configured enclosure. The relay receives no signing key or SQL credentials.
// It cannot provision a candidate, seed it, or undo a terminal stop.
func LogicalApprovalHandler(candidate LogicalCandidate, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(token) < 32 || subtle.ConstantTimeCompare([]byte(token), []byte(got)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/approve_logical" {
			http.Error(w, "not found", 404)
			return
		}
		var request hostclient.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		d.DisallowUnknownFields()
		if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid approval request", 400)
			return
		}
		var document struct {
			Runtime string `json:"runtime_sha256"`
		}
		p := candidate.Approval
		if p == nil || request.Task.Kind != "approve_logical" || request.Task.Command.Identity != candidate.Container.Spec.Identity || json.Unmarshal(request.Task.Document, &document) != nil || document.Runtime != p.Runtime || len(request.Lease) > 16<<10 {
			http.Error(w, "approval scope differs", 409)
			return
		}
		if err := runtime.ValidateApproval(candidate.Container, *p); err != nil {
			http.Error(w, "approval configuration differs", 409)
			return
		}
		terminal := func() bool {
			_, err := os.Lstat(filepath.Join(candidate.Container.Spec.ControlDir, "logical-stop.json"))
			return !os.IsNotExist(err)
		}
		if terminal() {
			http.Error(w, "logical candidate is terminal", 409)
			return
		}
		o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := o.Verify(ctx, candidate.Container); err != nil {
			http.Error(w, "logical runtime unavailable", 409)
			return
		}
		if err := p.Install(request.Lease); err != nil {
			http.Error(w, "approval rejected", 409)
			return
		}
		if terminal() {
			http.Error(w, "logical candidate is terminal", 409)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
