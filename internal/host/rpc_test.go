package host

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"pgws/internal/control"
	"pgws/internal/hostclient"
	"pgws/internal/lease"
)

func TestRPCResponseFormsAndRejections(t *testing.T) {
	h := &Host{Config: Config{Root: t.TempDir(), ID: "host", Epoch: control.ID()}}
	task := control.Task{Kind: "observe_workspace", Command: lease.Command{Identity: lease.Identity{
		Epoch: h.Config.Epoch, Host: h.Config.ID, Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Generation: 1,
	}}}
	if err := h.save(task, state{Task: task, Phase: "ready"}); err != nil {
		t.Fatal(err)
	}
	observed, err := json.Marshal(hostclient.Request{Task: task})
	if err != nil {
		t.Fatal(err)
	}
	task.Kind = "acknowledge_usage"
	task.Document = json.RawMessage(`{"batch_id":"` + control.ID() + `"}`)
	ack, err := json.Marshal(hostclient.Request{Task: task})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 32)
	handler := h.Handler(token)
	for _, tc := range []struct {
		name, path, method, body, token string
		status                          int
	}{
		{"json", "/observe", "POST", string(observed), token, 200},
		{"empty", "/acknowledge_usage", "POST", string(ack), token, 204},
		{"rejected", "/observe", "POST", "{}", token, 409},
		{"unknown field", "/observe", "POST", `{"unknown":true}`, token, 400},
		{"trailing document", "/observe", "POST", string(observed) + "{}", token, 400},
		{"authentication", "/observe", "POST", string(observed), "wrong", 401},
		{"method", "/observe", "GET", string(observed), token, 405},
		{"route", "/missing", "POST", "{}", token, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
			}
			if tc.status == 204 && w.Body.Len() != 0 {
				t.Fatal("204 has a response body")
			}
			if tc.status == 200 {
				var result control.StopObservation
				if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Identity != task.Command.Identity || result.Stopped {
					t.Fatal("invalid JSON result", w.Body.String())
				}
			}
		})
	}
}
