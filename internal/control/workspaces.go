package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"pgws/internal/freshness"
)

func checkFreshness(f Freshness) error {
	switch f.Mode {
	case "latest":
		if f.SnapshotID == "" && f.BarrierToken == "" {
			return nil
		}
	case "snapshot":
		if ValidID(f.SnapshotID) && f.BarrierToken == "" {
			return nil
		}
	case "at_least":
		if f.BarrierToken != "" && f.SnapshotID == "" {
			return nil
		}
	}
	return fail(400, "INVALID_REQUEST", "Invalid freshness mode or fields")
}
func eligible(ctx context.Context, tx pgx.Tx, p Principal, id string) error {
	var kind, state string
	var policyOK bool
	err := tx.QueryRow(ctx, `SELECT b.kind,b.state,coalesce(pp.state='approved',b.privacy_policy_id IS NULL)
 FROM baselines b LEFT JOIN privacy_policies pp ON (pp.tenant_id,pp.project_id,pp.id)=(b.tenant_id,b.project_id,b.privacy_policy_id)
 WHERE b.id=$1 AND b.tenant_id=$2 AND b.project_id=$3`, id, p.Tenant, p.Project).Scan(&kind, &state, &policyOK)
	if err != nil {
		return err
	}
	if kind == "logical_writer" {
		return fail(422, "UNSUPPORTED_SOURCE", "Sanitized publication has not passed its release gates")
	}
	if kind == "physical_standby" && !p.Raw {
		return fail(403, "PRIVACY_POLICY_BLOCKED", "Raw access is not permitted")
	}
	if !policyOK {
		return fail(403, "PRIVACY_POLICY_BLOCKED", "Privacy policy is not approved")
	}
	if state != "ready" {
		return fail(409, "BASELINE_NOT_READY", "Baseline is not ready")
	}
	return nil
}
func (s *Server) createWorkspace(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, body []byte) (int, any, error) {
	var in CreateWorkspace
	if e := decode(body, &in, "baseline_id", "task_id", "freshness", "resource_profile", "ttl_seconds"); e != nil {
		return 0, nil, e
	}
	if !ValidID(in.BaselineID) || utf8.RuneCountInString(in.TaskID) < 1 || utf8.RuneCountInString(in.TaskID) > 200 || utf8.RuneCountInString(in.CodeRevision) > 200 || in.TTL < 300 || in.TTL > 604800 || (in.Profile != "small" && in.Profile != "medium") {
		return 0, nil, fail(400, "INVALID_REQUEST", "Invalid workspace parameters")
	}
	if e := checkFreshness(in.Freshness); e != nil {
		return 0, nil, e
	}
	if e := eligible(ctx, tx, p, in.BaselineID); e != nil {
		return 0, nil, e
	}
	// Admission binds the baseline; source I/O is deferred to the worker.
	if e := s.validateFreshness(ctx, tx, p, in.BaselineID, in.Freshness); e != nil {
		return 0, nil, e
	}
	id := ID()
	fresh, _ := json.Marshal(in.Freshness)
	_, e := tx.Exec(ctx, `INSERT INTO workspaces(tenant_id,project_id,id,task_id,desired_state,phase,resource_profile,code_revision,expires_at,requested_baseline_id,requested_freshness)
 VALUES($1,$2,$3,$4,'running','queued',$5,$6,now()+make_interval(secs=>$7),$8,$9)`, p.Tenant, p.Project, id, in.TaskID, in.Profile, in.CodeRevision, in.TTL, in.BaselineID, fresh)
	if e != nil {
		return 0, nil, e
	}
	op, e := s.enqueue(ctx, tx, p, r, id, "create", 1, 1, body)
	if e != nil {
		return 0, nil, e
	}
	ws, e := workspace(ctx, tx, p, id)
	if e != nil {
		return 0, nil, e
	}
	return 202, Object{"workspace": ws, "operation": op}, nil
}
func validateSnapshot(ctx context.Context, tx pgx.Tx, p Principal, baseline string, f Freshness) error {
	if f.Mode != "snapshot" {
		return fail(503, "CONNECTOR_UNAVAILABLE", "Source freshness is unavailable until the physical connector is configured")
	}
	var ok *bool
	e := tx.QueryRow(ctx, `SELECT pgws_control.lock_ready_snapshot($1,$2,$3,$4)`, p.Tenant, p.Project, f.SnapshotID, baseline).Scan(&ok)
	if e != nil {
		return e
	}
	if ok == nil {
		return pgx.ErrNoRows
	}
	if !*ok {
		return fail(409, "SNAPSHOT_NOT_READY", "Snapshot is not ready")
	}
	return nil
}

func workspace(ctx context.Context, tx pgx.Tx, p Principal, id string) (json.RawMessage, error) {
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT jsonb_strip_nulls(jsonb_build_object(
 'id',w.id,'project_id',w.project_id,'generation',coalesce(w.current_generation,w.next_generation),
 'task_id',w.task_id,'desired_state',w.desired_state,'phase',w.phase,'resource_profile',w.resource_profile,
 'expires_at',w.expires_at,'baseline_id',w.requested_baseline_id,'snapshot_id',g.snapshot_id,
 'privacy_mode',CASE WHEN b.kind='logical_writer' THEN 'sanitized' ELSE 'raw' END,
 'policy_hash',b.privacy_policy_hash,
 'endpoint',CASE WHEN w.phase='ready' AND w.desired_state='running' AND w.expires_at>clock_timestamp() THEN g.endpoint_metadata END,
 'last_operation_id',(SELECT o.id FROM operations o WHERE o.tenant_id=w.tenant_id AND o.project_id=w.project_id AND o.workspace_id=w.id ORDER BY o.created_at DESC,o.id DESC LIMIT 1)))
 FROM workspaces w JOIN baselines b ON (b.tenant_id,b.project_id,b.id)=(w.tenant_id,w.project_id,w.requested_baseline_id)
 LEFT JOIN workspace_generations g ON (g.tenant_id,g.project_id,g.workspace_id,g.generation)=(w.tenant_id,w.project_id,w.id,w.current_generation)
 LEFT JOIN privacy_policies pp ON (pp.tenant_id,pp.project_id,pp.id)=(b.tenant_id,b.project_id,b.privacy_policy_id)
 WHERE w.tenant_id=$1 AND w.project_id=$2 AND w.id=$3 AND
 (b.kind='physical_standby' AND $4)`, p.Tenant, p.Project, id, p.Raw).Scan(&raw)
	return raw, e
}
func (s *Server) getWorkspace(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, _ []byte) (int, any, error) {
	w, e := workspace(ctx, tx, p, r.PathValue("workspace_id"))
	return 200, w, e
}

func (s *Server) action(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, body []byte) (int, any, error) {
	var a Action
	if e := decode(body, &a, "action", "expected_generation"); e != nil {
		return 0, nil, e
	}
	allowed := map[string]bool{"action": true, "expected_generation": true}
	switch a.Action {
	case "pause", "resume":
	case "extend_ttl":
		allowed["expected_expires_at"] = true
		allowed["expires_at"] = true
		if a.ExpectedExpiry.IsZero() || a.Expiry.IsZero() {
			return 0, nil, fail(400, "INVALID_REQUEST", "Expiry preconditions are required")
		}
	case "reset":
		allowed["discard_local_changes"] = true
		allowed["baseline_id"] = true
		allowed["freshness"] = true
		if !a.Discard || !ValidID(a.BaselineID) || a.Freshness == nil {
			return 0, nil, fail(400, "INVALID_REQUEST", "Reset requires discard confirmation, baseline and freshness")
		}
		if e := checkFreshness(*a.Freshness); e != nil {
			return 0, nil, e
		}
	default:
		return 0, nil, fail(400, "INVALID_REQUEST", "Unknown action")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(body, &fields)
	for k := range fields {
		if !allowed[k] {
			return 0, nil, fail(400, "INVALID_REQUEST", "Field not allowed for this action")
		}
	}
	return s.change(ctx, tx, p, r, a, body)
}
func (s *Server) remove(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, _ []byte) (int, any, error) {
	q := r.URL.Query()
	if len(q) != 1 || len(q["expected_generation"]) != 1 {
		return 0, nil, fail(400, "INVALID_REQUEST", "expected_generation is required")
	}
	n, e := strconv.ParseInt(q.Get("expected_generation"), 10, 64)
	if e != nil || n < 1 {
		return 0, nil, fail(400, "INVALID_REQUEST", "Invalid generation")
	}
	a := Action{Action: "delete", Generation: n}
	body, _ := json.Marshal(a)
	return s.change(ctx, tx, p, r, a, body)
}
func (s *Server) change(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, a Action, body []byte) (int, any, error) {
	id := r.PathValue("workspace_id")
	if a.Generation < 1 {
		return 0, nil, fail(400, "INVALID_REQUEST", "Generation must be positive")
	}
	if _, e := workspace(ctx, tx, p, id); e != nil {
		return 0, nil, e
	}
	var generation, revision int64
	var desired, phase string
	var created, expiry, now time.Time
	e := tx.QueryRow(ctx, `SELECT coalesce(current_generation,next_generation),desired_revision,desired_state,phase,created_at,expires_at,clock_timestamp() FROM workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, p.Tenant, p.Project, id).Scan(&generation, &revision, &desired, &phase, &created, &expiry, &now)
	if e != nil {
		return 0, nil, e
	}
	if phase == "recovery_blocked" {
		return 0, nil, fail(409, "AUTHORITY_RECOVERED", "Retained workspace is quarantined after authority recovery")
	}
	if generation != a.Generation {
		return 0, nil, fail(409, "GENERATION_CONFLICT", "Workspace generation changed")
	}
	if desired == "deleted" {
		return 0, nil, fail(409, "WORKSPACE_DELETED", "Deletion is already requested")
	}
	if a.Action != "delete" && !now.Before(expiry) {
		return 0, nil, fail(409, "WORKSPACE_EXPIRED", "Expired workspace cannot be revived")
	}
	var busy bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM operations WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND status IN ('queued','running'))`, p.Tenant, p.Project, id).Scan(&busy); e != nil {
		return 0, nil, e
	}
	if busy && a.Action != "delete" {
		return 0, nil, fail(409, "OPERATION_IN_PROGRESS", "Wait for the current operation")
	}
	switch a.Action {
	case "pause":
		if phase != "ready" {
			return 0, nil, fail(409, "INVALID_STATE", "Pause requires a ready workspace")
		}
		desired = "paused"
		phase = "pausing"
	case "resume":
		if phase != "paused" {
			return 0, nil, fail(409, "INVALID_STATE", "Resume requires a paused workspace")
		}
		desired = "running"
		phase = "starting"
	case "delete":
		desired = "deleted"
		phase = "deleting"
	case "extend_ttl":
		if phase != "ready" && phase != "paused" {
			return 0, nil, fail(409, "INVALID_STATE", "Extension requires a ready or paused workspace")
		}
		if !a.ExpectedExpiry.Equal(expiry) {
			return 0, nil, fail(409, "EXPIRY_CONFLICT", "Effective expiry changed")
		}
		if !a.Expiry.After(expiry) || a.Expiry.After(created.Add(7*24*time.Hour)) {
			return 0, nil, fail(400, "INVALID_EXPIRY", "Extension must increase expiry within seven days of creation")
		}
	case "reset":
		if phase != "ready" && phase != "paused" {
			return 0, nil, fail(409, "INVALID_STATE", "Reset requires a ready or paused workspace")
		}
		if e = eligible(ctx, tx, p, a.BaselineID); e != nil {
			return 0, nil, e
		}
		if e = s.validateFreshness(ctx, tx, p, a.BaselineID, *a.Freshness); e != nil {
			return 0, nil, e
		}
		phase = "resetting"
	}
	revision++
	// Effective expires_at and current generation remain unchanged until host acknowledgement.
	if _, e = tx.Exec(ctx, `UPDATE workspaces SET desired_state=$4,phase=$5,desired_revision=$6,updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, p.Tenant, p.Project, id, desired, phase, revision); e != nil {
		return 0, nil, e
	}
	op, e := s.enqueue(ctx, tx, p, r, id, a.Action, generation, revision, body)
	return 202, op, e
}

func (s *Server) validateFreshness(ctx context.Context, tx pgx.Tx, p Principal, baseline string, f Freshness) error {
	if f.Mode == "snapshot" {
		return validateSnapshot(ctx, tx, p, baseline, f)
	}
	if !s.Physical {
		return fail(503, "CONNECTOR_UNAVAILABLE", "Source freshness requires the configured physical connector")
	}
	if f.Mode != "latest" && f.Mode != "at_least" {
		return fail(400, "INVALID_REQUEST", "Invalid freshness mode")
	}
	var eligible bool
	err := tx.QueryRow(ctx, `SELECT s.status='streaming' AND s.source_epoch=b.source_epoch AND s.timeline=b.source_timeline AND EXISTS(SELECT FROM approved_source_references a WHERE (a.tenant_id,a.project_id,a.endpoint_reference,a.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference)) FROM baselines b JOIN sources s ON (s.tenant_id,s.project_id,s.id)=(b.tenant_id,b.project_id,b.source_id) WHERE b.tenant_id=$1 AND b.project_id=$2 AND b.id=$3 AND b.kind='physical_standby' AND b.state='ready'`, p.Tenant, p.Project, baseline).Scan(&eligible)
	if err != nil {
		return err
	}
	if !eligible {
		return fail(409, "SOURCE_NOT_READY", "Source lineage or approval changed")
	}
	if f.Mode == "at_least" {
		c, e := freshness.Verify(s.AuthorityKey, f.BarrierToken, time.Now())
		if e != nil || c.Authority != s.Epoch || c.Tenant != p.Tenant || c.Project != p.Project {
			return fail(409, "INVALID_BARRIER", "Barrier signature, scope or expiry is invalid")
		}
		var matches bool
		e = tx.QueryRow(ctx, `SELECT b.source_id=$4::uuid AND b.source_epoch=$5 AND b.source_timeline=$6 AND s.system_identifier=$7 FROM baselines b JOIN sources s ON (s.tenant_id,s.project_id,s.id)=(b.tenant_id,b.project_id,b.source_id) WHERE b.tenant_id=$1 AND b.project_id=$2 AND b.id=$3`, p.Tenant, p.Project, baseline, c.Source, c.SourceEpoch, c.Timeline, c.SystemID).Scan(&matches)
		if e != nil {
			return e
		}
		if !matches {
			return fail(409, "SOURCE_LINEAGE_CHANGED", "Barrier does not belong to this baseline lineage")
		}
	}
	return nil
}
