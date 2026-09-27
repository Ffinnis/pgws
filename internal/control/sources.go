package control

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Server) enqueue(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, ws, kind string, gen, rev int64, body []byte) (Object, error) {
	id := ID()
	var workspace any
	if ws != "" {
		workspace = ws
	}
	_, e := tx.Exec(ctx, `INSERT INTO operations(tenant_id,project_id,id,workspace_id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,actor_reference,authority_epoch)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'queued',$11,$12,$13)`, p.Tenant, p.Project, id, workspace, kind, gen, rev, p.ID+":"+r.Method+":"+r.URL.EscapedPath(), r.Header.Get("Idempotency-Key"), fmt.Sprintf("%x", sha256.Sum256(body)), body, p.ID, s.Epoch)
	op := Object{"id": id, "kind": kind, "status": "queued", "attempt": 0}
	if ws != "" {
		op["workspace_id"] = ws
	}
	return op, e
}
func (s *Server) createSource(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, body []byte) (int, any, error) {
	if !p.Admin {
		return 0, nil, fail(403, "FORBIDDEN", "Source registration requires a project administrator")
	}
	var in SourceRequest
	if e := decode(body, &in, "connector", "approved_endpoint_reference", "secret_reference"); e != nil {
		return 0, nil, e
	}
	if in.Connector != "physical" && in.Connector != "logical" {
		return 0, nil, fail(400, "INVALID_REQUEST", "Invalid connector")
	}
	if in.Connector == "logical" {
		return 0, nil, fail(422, "UNSUPPORTED_SOURCE", "Sanitized ingestion has not passed its release gates")
	}
	var approved bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM approved_source_references WHERE tenant_id=$1 AND project_id=$2 AND endpoint_reference=$3 AND secret_reference=$4)`, p.Tenant, p.Project, in.Endpoint, in.Secret).Scan(&approved)
	if e != nil {
		return 0, nil, e
	}
	if !approved {
		return 0, nil, fail(403, "SOURCE_NOT_APPROVED", "Source reference pair is not approved")
	}
	id := ID()
	if _, e = tx.Exec(ctx, `INSERT INTO sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status) VALUES($1,$2,$3,$4,$5,$6,'registered')`, p.Tenant, p.Project, id, in.Connector, in.Endpoint, in.Secret); e != nil {
		return 0, nil, e
	}
	// Persist only references, never a source DSN or password.
	job, _ := json.Marshal(Object{"source_id": id})
	op, e := s.enqueue(ctx, tx, p, r, "", "register_source", 1, 1, job)
	return 202, Object{"source_id": id, "operation": op}, e
}
func (s *Server) listBaselines(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, _ []byte) (int, any, error) {
	limit := 100
	var after any
	query := r.URL.Query()
	for k, values := range query {
		if (k != "limit" && k != "cursor") || len(values) != 1 || values[0] == "" {
			return 0, nil, fail(400, "INVALID_REQUEST", "Invalid pagination query")
		}
	}
	if value := query.Get("limit"); value != "" {
		n, e := strconv.Atoi(value)
		if e != nil || n < 1 || n > 200 {
			return 0, nil, fail(400, "INVALID_REQUEST", "Page limit must be between 1 and 200")
		}
		limit = n
	}
	if cursor := query.Get("cursor"); cursor != "" {
		var parts []string
		b, e := base64.RawURLEncoding.DecodeString(cursor)
		if len(cursor) > 1024 || e != nil || json.Unmarshal(b, &parts) != nil || len(parts) != 3 || parts[0] != p.Tenant || parts[1] != p.Project || !ValidID(parts[2]) {
			return 0, nil, fail(400, "INVALID_CURSOR", "Cursor does not belong to this project")
		}
		after = parts[2]
	}
	rows, e := tx.Query(ctx, `SELECT b.id::text,b.source_id::text,b.generation,b.source_epoch,b.kind,b.state,b.runtime_digest,b.observed_at
 FROM baselines b LEFT JOIN privacy_policies pp ON (pp.tenant_id,pp.project_id,pp.id)=(b.tenant_id,b.project_id,b.privacy_policy_id)
 WHERE b.tenant_id=$1 AND b.project_id=$2 AND (b.kind='physical_standby' AND $3) AND ($4::uuid IS NULL OR b.id>$4::uuid) ORDER BY b.id LIMIT $5`, p.Tenant, p.Project, p.Raw, after, limit+1)
	if e != nil {
		return 0, nil, e
	}
	defer rows.Close()
	items := []Object{}
	for rows.Next() {
		var id, source, kind, state, digest string
		var gen, epoch int64
		var observed *time.Time
		if e = rows.Scan(&id, &source, &gen, &epoch, &kind, &state, &digest, &observed); e != nil {
			return 0, nil, e
		}
		mode := "raw"
		if kind == "logical_writer" {
			mode = "sanitized"
		}
		item := Object{"id": id, "source_id": source, "generation": gen, "source_epoch": epoch, "kind": kind, "state": state, "runtime_digest": digest, "privacy_mode": mode}
		if observed != nil {
			item["observed_at"] = observed
		}
		items = append(items, item)
	}
	if e = rows.Err(); e != nil {
		return 0, nil, e
	}
	result := Object{"items": items}
	if len(items) > limit {
		items = items[:limit]
		cursor, _ := json.Marshal([]string{p.Tenant, p.Project, items[len(items)-1]["id"].(string)})
		result["items"] = items
		result["next_cursor"] = base64.RawURLEncoding.EncodeToString(cursor)
	}
	return 200, result, nil
}
func (s *Server) getOperation(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, _ []byte) (int, any, error) {
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT jsonb_strip_nulls(jsonb_build_object('id',id,'kind',kind,'status',status,'workspace_id',workspace_id,'phase',current_step,'attempt',attempt,'error',safe_error)) FROM operations WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND (actor_reference=$4 OR $5)`, p.Tenant, p.Project, r.PathValue("operation_id"), p.ID, p.Admin).Scan(&raw)
	return 200, json.RawMessage(raw), e
}
func (s *Server) barrier(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, body []byte) (int, any, error) {
	var in struct {
		After bool `json:"after_commit_asserted"`
	}
	if e := decode(body, &in, "after_commit_asserted"); e != nil {
		return 0, nil, e
	}
	if !in.After {
		return 0, nil, fail(400, "INVALID_REQUEST", "Commit assertion is required")
	}
	if !p.Raw {
		return 0, nil, fail(403, "FORBIDDEN", "Source barriers require raw source access")
	}
	if !s.Physical || len(s.AuthorityKey) != 32 {
		return 0, nil, fail(503, "CONNECTOR_UNAVAILABLE", "Durable source barriers require the physical connector")
	}
	var eligible bool
	var generation int64
	e := tx.QueryRow(ctx, `SELECT status='streaming',baseline_generation FROM sources s WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND EXISTS(SELECT FROM approved_source_references a WHERE (a.tenant_id,a.project_id,a.endpoint_reference,a.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference))`, p.Tenant, p.Project, r.PathValue("source_id")).Scan(&eligible, &generation)
	if e != nil {
		return 0, nil, e
	}
	if !eligible {
		return 0, nil, fail(409, "SOURCE_NOT_READY", "Source is not streaming")
	}
	doc, _ := json.Marshal(Object{"source_id": r.PathValue("source_id")})
	op, e := s.enqueue(ctx, tx, p, r, "", "issue_barrier", generation, generation, doc)
	if e != nil {
		return 0, nil, e
	}
	return 202, pendingResponse{OperationID: op["id"].(string)}, nil
}
func (s *Server) credentials(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, body []byte) (int, any, error) {
	var in struct {
		Generation int64  `json:"expected_generation"`
		Role       string `json:"role"`
		TTL        int    `json:"ttl_seconds"`
	}
	if e := decode(body, &in, "expected_generation", "role", "ttl_seconds"); e != nil {
		return 0, nil, e
	}
	if in.Generation < 1 || (in.Role != "owner" && in.Role != "reader") || in.TTL < 60 || in.TTL > 3600 {
		return 0, nil, fail(400, "INVALID_REQUEST", "Invalid credential parameters")
	}
	if _, e := workspace(ctx, tx, p, r.PathValue("workspace_id")); e != nil {
		return 0, nil, e
	}
	if !s.Physical || len(s.SecretKey) != 32 {
		return 0, nil, fail(503, "RUNTIME_UNAVAILABLE", "Credential issuance requires a runtime and secret store")
	}
	var gen, rev int64
	var expiry time.Time
	var phase, desired string
	e := tx.QueryRow(ctx, `SELECT current_generation,desired_revision,expires_at,phase,desired_state FROM workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, p.Tenant, p.Project, r.PathValue("workspace_id")).Scan(&gen, &rev, &expiry, &phase, &desired)
	if e != nil {
		return 0, nil, e
	}
	if gen != in.Generation {
		return 0, nil, fail(409, "GENERATION_CONFLICT", "Workspace generation changed")
	}
	if phase != "ready" || desired != "running" || !time.Now().Before(expiry.Add(-5*time.Second)) {
		return 0, nil, fail(409, "INVALID_STATE", "Credentials require a running unexpired workspace")
	}
	var busy bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM operations WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND status IN ('queued','running'))`, p.Tenant, p.Project, r.PathValue("workspace_id")).Scan(&busy); e != nil {
		return 0, nil, e
	}
	if busy {
		return 0, nil, fail(409, "OPERATION_IN_PROGRESS", "Wait for the current operation")
	}
	until := time.Now().UTC().Add(time.Duration(in.TTL) * time.Second)
	if until.After(expiry) {
		until = expiry
	}
	doc, _ := json.Marshal(CredentialRequest{Role: in.Role, Expiry: until})
	op, e := s.enqueue(ctx, tx, p, r, r.PathValue("workspace_id"), "issue_credential", gen, rev, doc)
	if e != nil {
		return 0, nil, e
	}
	return 202, pendingResponse{OperationID: op["id"].(string)}, nil
}
