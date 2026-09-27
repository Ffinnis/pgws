package host

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"pgws/internal/control"
	"pgws/internal/hostclient"
	"pgws/internal/lease"
	"pgws/internal/policyapproval"
	"pgws/internal/runtime"
)

func TestApprovalRelayRejectsScopeBeforeHostIO(t *testing.T) {
	id := lease.Identity{Epoch: control.ID(), Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Host: "relay-host", Generation: 2, Revision: 1}
	c := LogicalCandidate{Container: runtime.Container{Spec: runtime.Spec{Identity: id}}, Approval: &policyapproval.Permit{Runtime: strings.Repeat("a", 64)}}
	token := strings.Repeat("x", 64)
	h := LogicalApprovalHandler(c, token)
	for _, kind := range []string{"token", "identity", "generation", "runtime", "oversize", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			doc, _ := json.Marshal(control.Object{"runtime_sha256": c.Approval.Runtime})
			q := hostclient.Request{Task: control.Task{Kind: "approve_logical", Command: lease.Command{Identity: id}, Document: doc}, Lease: "token"}
			auth := token
			switch kind {
			case "token":
				auth = "wrong"
			case "identity":
				q.Task.Command.Workspace = control.ID()
			case "generation":
				q.Task.Command.Generation++
			case "runtime":
				q.Task.Document = json.RawMessage(`{"runtime_sha256":"changed"}`)
			case "oversize":
				q.Lease = strings.Repeat("a", 33<<10)
			}
			body, _ := json.Marshal(q)
			if kind == "unknown" {
				body = []byte(`{"unknown":true}`)
			}
			r := httptest.NewRequest("POST", "/approve_logical", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+auth)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != 400 && rec.Code != 401 && rec.Code != 409 {
				t.Fatal(rec.Code)
			}
		})
	}
}
