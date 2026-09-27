package host

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"pgws/internal/hostclient"
)

func (h *Host) Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(token) < 32 || subtle.ConstantTimeCompare([]byte(token), []byte(got)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		var request hostclient.Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
		d.DisallowUnknownFields()
		if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid host request", 400)
			return
		}
		var out any
		var err error
		switch r.URL.Path {
		case "/recovery_report":
			out, err = h.RecoveryReport(r.Context(), request.Task)
		case "/collect_usage":
			out, err = h.CollectUsage(r.Context(), request.Task)
		case "/acknowledge_usage":
			err = h.AcknowledgeUsage(r.Context(), request.Task)
		case "/revoke_credentials":
			err = h.RevokeCredentials(r.Context(), request.Task)
		case "/revoke_serving":
			out, err = h.RevokeServing(r.Context(), request.Task)
		case "/observe":
			out, err = h.Observe(r.Context(), request.Task)
		case "/execute":
			out, err = h.Execute(r.Context(), request.Task)
		case "/activate":
			err = h.Activate(r.Context(), request.Task, request.Lease)
		case "/revoke":
			err = h.Revoke(r.Context(), request.Task)
		default:
			http.Error(w, "not found", 404)
			return
		}
		if err != nil {
			slog.Error("host operation failed", "kind", request.Task.Kind, "error", err)
			http.Error(w, "host operation failed", 409)
			return
		}
		if out != nil {
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		w.WriteHeader(204)
	})
}
