package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	Pool         *pgxpool.Pool
	Epoch        string
	Log          *slog.Logger
	Physical     bool
	SecretKey    []byte
	AuthorityKey ed25519.PublicKey
}
type handler func(context.Context, pgx.Tx, Principal, *http.Request, []byte) (int, any, error)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, Object{"status": "alive"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var ready bool
		err := s.Pool.QueryRow(ctx, `SELECT reconciled AND epoch=$1::uuid FROM pgws_control.authority WHERE singleton`, s.Epoch).Scan(&ready)
		if err != nil || !ready {
			reply(w, 503, &Fault{Code: "AUTHORITY_RECONCILIATION_REQUIRED", Message: "Control authority is unavailable or unreconciled", Retryable: true})
			return
		}
		backend := "unavailable"
		if s.Physical {
			backend = "configured"
		}
		reply(w, 200, Object{"status": "ready", "workspace_backend": backend})
	})
	prefix := "/v1/projects/{project_id}"
	mux.HandleFunc("POST "+prefix+"/sources", s.wrap(s.createSource))
	mux.HandleFunc("GET "+prefix+"/sources/{source_id}", s.wrap(s.getSource))
	mux.HandleFunc("POST "+prefix+"/sources/{source_id}/actions", s.wrap(s.sourceAction))
	mux.HandleFunc("GET "+prefix+"/baselines", s.wrap(s.listBaselines))
	mux.HandleFunc("GET "+prefix+"/usage", s.wrap(s.listUsage))
	mux.HandleFunc("POST "+prefix+"/workspaces", s.wrap(s.createWorkspace))
	mux.HandleFunc("GET "+prefix+"/workspaces/{workspace_id}", s.wrap(s.getWorkspace))
	mux.HandleFunc("POST "+prefix+"/workspaces/{workspace_id}/actions", s.wrap(s.action))
	mux.HandleFunc("DELETE "+prefix+"/workspaces/{workspace_id}", s.wrap(s.remove))
	mux.HandleFunc("GET "+prefix+"/operations/{operation_id}", s.wrap(s.getOperation))
	mux.HandleFunc("POST "+prefix+"/sources/{source_id}/barriers", s.wrap(s.barrier))
	mux.HandleFunc("POST "+prefix+"/workspaces/{workspace_id}/credentials", s.wrap(s.credentials))
	return mux
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		status, result, err := s.request(ctx, h, w, r)
		if err == nil && status == 202 {
			b, _ := json.Marshal(result)
			var p pendingResponse
			if json.Unmarshal(b, &p) == nil && ValidID(p.OperationID) {
				status, result, err = s.awaitCredential(ctx, r, p.OperationID)
			}
		}
		if err != nil {
			var f *Fault
			if errors.As(err, &f) {
				reply(w, f.Status, f)
				return
			}
			if errors.Is(err, pgx.ErrNoRows) {
				reply(w, 404, &Fault{Code: "NOT_FOUND", Message: "Resource not found"})
				return
			}
			if s.Log != nil {
				s.Log.Error("request failed", "method", r.Method, "route", r.Pattern)
			}
			reply(w, 503, &Fault{Code: "CONTROL_UNAVAILABLE", Message: "Management operation unavailable", Retryable: true})
			return
		}
		reply(w, status, result)
	}
}
func (s *Server) request(ctx context.Context, h handler, w http.ResponseWriter, r *http.Request) (int, any, error) {
	project := r.PathValue("project_id")
	for _, name := range []string{"project_id", "workspace_id", "source_id", "operation_id"} {
		if v := r.PathValue(name); v != "" && !ValidID(v) {
			return 0, nil, fail(400, "INVALID_REQUEST", "Invalid resource ID")
		}
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) < 40 || len(auth) > 512 {
		return 0, nil, fail(401, "UNAUTHENTICATED", "A valid bearer token is required")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE pgws_runtime; SET LOCAL search_path=pgws_control,pg_catalog`); err != nil {
		return 0, nil, err
	}
	var p Principal
	p.Project = project
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer "))))
	err = tx.QueryRow(ctx, `SELECT principal_id::text,tenant_id::text,is_admin,allow_raw FROM api_tokens WHERE token_hash=$1 AND project_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, hash, project).Scan(&p.ID, &p.Tenant, &p.Admin, &p.Raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, fail(401, "UNAUTHENTICATED", "Token is invalid, expired or outside this project")
	}
	if err != nil {
		return 0, nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('pgws.tenant_id',$1,true),set_config('pgws.project_id',$2,true)`, p.Tenant, project); err != nil {
		return 0, nil, err
	}
	var ready bool
	if err = tx.QueryRow(ctx, `SELECT epoch=$1::uuid AND reconciled FROM authority WHERE singleton`, s.Epoch).Scan(&ready); err != nil || !ready {
		return 0, nil, fail(503, "AUTHORITY_RECONCILIATION_REQUIRED", "Authority must be reconciled before API access")
	}
	var body []byte
	write := r.Method != "GET"
	key := r.Header.Get("Idempotency-Key")
	scope := r.Method + " " + r.URL.EscapedPath()
	if write {
		if len(key) < 1 || len(key) > 200 {
			return 0, nil, fail(400, "INVALID_REQUEST", "Idempotency-Key must contain 1 to 200 bytes")
		}
		if r.Method == "DELETE" {
			body = []byte(`{}`)
			if r.ContentLength != 0 {
				return 0, nil, fail(400, "INVALID_REQUEST", "DELETE does not accept a body")
			}
			body, _ = json.Marshal(Object{"query": r.URL.Query().Encode()})
		} else {
			media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if e != nil || media != "application/json" {
				return 0, nil, fail(400, "INVALID_REQUEST", "Content-Type must be application/json")
			}
			b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
			if e != nil {
				return 0, nil, fail(400, "INVALID_REQUEST", "Request body exceeds the limit")
			}
			var object map[string]any
			d := json.NewDecoder(bytes.NewReader(b))
			d.UseNumber()
			if d.Decode(&object) != nil || object == nil || !json.Valid(b) {
				return 0, nil, fail(400, "INVALID_REQUEST", "Body must be one JSON object")
			}
			body, _ = json.Marshal(object)
		}
		// One short admission transaction per project. Long-running work never holds this lock.
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, p.Tenant+project); err != nil {
			return 0, nil, err
		}
		requestHash := fmt.Sprintf("%x", sha256.Sum256(body))
		var oldHash string
		var raw []byte
		var oldStatus int
		var created time.Time
		err = tx.QueryRow(ctx, `SELECT request_hash,status,response,created_at FROM api_replays WHERE tenant_id=$1 AND project_id=$2 AND principal_id=$3 AND scope=$4 AND key=$5`, p.Tenant, project, p.ID, scope, key).Scan(&oldHash, &oldStatus, &raw, &created)
		if err == nil {
			if oldHash != requestHash {
				return 0, nil, fail(409, "IDEMPOTENCY_CONFLICT", "Key was used with a different request")
			}
			if time.Since(created) > 7*24*time.Hour {
				return 0, nil, fail(409, "IDEMPOTENCY_KEY_EXPIRED", "This key is retired; inspect the original operation")
			}
			return oldStatus, json.RawMessage(raw), nil
		}
		if err != pgx.ErrNoRows {
			return 0, nil, err
		}
		status, result, e := h(ctx, tx, p, r, body)
		if e != nil {
			return 0, nil, e
		}
		raw, e = json.Marshal(result)
		if e != nil {
			return 0, nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO api_replays(tenant_id,project_id,principal_id,scope,key,request_hash,status,response) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, p.Tenant, project, p.ID, scope, key, requestHash, status, raw); e != nil {
			return 0, nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome) VALUES($1,$2,$3,$4,$5,$6,'accepted')`, ID(), p.Tenant, project, p.ID, r.Method, r.URL.EscapedPath()); e != nil {
			return 0, nil, e
		}
		if e = tx.Commit(ctx); e != nil {
			return 0, nil, e
		}
		return status, result, nil
	}
	status, result, err := h(ctx, tx, p, r, body)
	if err != nil {
		return 0, nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, nil, err
	}
	return status, result, nil
}
func decode(body []byte, v any, required ...string) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return fail(400, "INVALID_REQUEST", "Invalid JSON")
	}
	for _, name := range required {
		if b, ok := fields[name]; !ok || bytes.Equal(b, []byte("null")) {
			return fail(400, "INVALID_REQUEST", "Missing required field: "+name)
		}
	}
	for _, b := range fields {
		if bytes.Equal(b, []byte("null")) {
			return fail(400, "INVALID_REQUEST", "Null fields are not supported")
		}
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return fail(400, "INVALID_REQUEST", "Invalid field or value")
	}
	return nil
}
