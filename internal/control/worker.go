package control

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Worker executes fenced operations through the privileged host boundary.
// Missing backends fail explicitly and never publish readiness.
type Worker struct {
	Pool       *pgxpool.Pool
	Epoch, ID  string
	Backend    Backend
	HostID     string
	SigningKey ed25519.PrivateKey
}
type Job struct {
	Tenant, Project, ID, Kind   string
	Workspace                   *string
	Revision, Generation, Fence int64
	Document                    []byte
}

func (w *Worker) Claim(ctx context.Context) (*Job, error) {
	tx, e := w.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	var active bool
	e = tx.QueryRow(ctx, `SELECT pgws_control.lock_authority($1::uuid)`, w.Epoch).Scan(&active)
	if e != nil {
		return nil, e
	}
	if !active {
		return nil, fail(503, "AUTHORITY_RECONCILIATION_REQUIRED", "Worker authority is not active")
	}
	var j Job
	var epoch string
	e = tx.QueryRow(ctx, `SELECT tenant_id::text,project_id::text,id::text,kind,workspace_id::text,coalesce(desired_revision,0),coalesce(expected_generation,0),request_document,authority_epoch::text
 FROM pgws_control.operations o WHERE ((status='queued' AND not_before<=clock_timestamp()) OR (status='running' AND lease_until<clock_timestamp()))
 AND (workspace_id IS NOT NULL OR NOT EXISTS(SELECT FROM pgws_control.operations busy WHERE busy.tenant_id=o.tenant_id AND busy.project_id=o.project_id AND busy.workspace_id IS NULL AND busy.id<>o.id AND busy.request_document->>'source_id'=o.request_document->>'source_id' AND busy.status='running' AND busy.lease_until>clock_timestamp()))
 ORDER BY created_at,id FOR UPDATE OF o SKIP LOCKED LIMIT 1`).Scan(&j.Tenant, &j.Project, &j.ID, &j.Kind, &j.Workspace, &j.Revision, &j.Generation, &j.Document, &epoch)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	valid := epoch == w.Epoch
	var authorized bool
	e = tx.QueryRow(ctx, `SELECT kind IN ('expire','gc_snapshot') OR EXISTS(SELECT FROM pgws_control.api_tokens t WHERE (t.tenant_id,t.project_id,t.principal_id)=(o.tenant_id,o.project_id,o.actor_reference) AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() AND (o.workspace_id IS NULL AND (o.kind IN ('register_source','reseed_source') AND t.is_admin OR o.kind='issue_barrier' AND t.allow_raw) OR o.workspace_id IS NOT NULL AND t.allow_raw)) FROM pgws_control.operations o WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID).Scan(&authorized)
	if e != nil {
		return nil, e
	}
	valid = valid && authorized
	if j.Workspace != nil {
		var revision, generation int64
		var expired bool
		e = tx.QueryRow(ctx, `SELECT desired_revision,coalesce(current_generation,next_generation),expires_at<=clock_timestamp() FROM pgws_control.workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, j.Tenant, j.Project, *j.Workspace).Scan(&revision, &generation, &expired)
		if e != nil {
			return nil, e
		}
		valid = valid && revision == j.Revision && generation == j.Generation && (!expired || j.Kind == "delete" || j.Kind == "expire") && (j.Kind != "expire" || expired)
		if valid {
			e = tx.QueryRow(ctx, `UPDATE pgws_control.workspaces SET fencing_token=fencing_token+1 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 RETURNING fencing_token`, j.Tenant, j.Project, *j.Workspace).Scan(&j.Fence)
			if e != nil {
				return nil, e
			}
		}
	}
	if !valid {
		_, e = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='cancelled',completed_at=now(),updated_at=now(),safe_error='{"code":"SUPERSEDED","message":"Operation authority, revision or expiry is no longer current","retryable":false}' WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID)
		if e != nil {
			return nil, e
		}
		if j.Kind == "register_source" || j.Kind == "reseed_source" {
			var doc sourceJob
			if json.Unmarshal(j.Document, &doc) != nil || !ValidID(doc.SourceID) {
				return nil, errors.New("invalid cancelled source operation")
			}
			if _, e = tx.Exec(ctx, `UPDATE pgws_control.sources SET status='blocked' WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND baseline_generation=$4 AND status<>'disabled'`, j.Tenant, j.Project, doc.SourceID, j.Generation); e != nil {
				return nil, e
			}
		}
		return nil, tx.Commit(ctx)
	}
	if j.Workspace == nil {
		var doc struct {
			SourceID string `json:"source_id"`
		}
		if json.Unmarshal(j.Document, &doc) != nil || !ValidID(doc.SourceID) {
			return nil, errors.New("invalid source operation")
		}
		// The candidate query is only a hint: competing claims may have read the
		// same old snapshot. Serialize on the source and recheck after the lock.
		var fence, generation int64
		e = tx.QueryRow(ctx, `SELECT host_fencing_token,baseline_generation FROM pgws_control.sources WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, j.Tenant, j.Project, doc.SourceID).Scan(&fence, &generation)
		if e != nil {
			return nil, e
		}
		if j.Kind == "gc_snapshot" {
			// Collection keeps current source authority while targeting old bytes.
			j.Generation, j.Revision = generation, generation
			if _, e = tx.Exec(ctx, `UPDATE pgws_control.operations SET expected_generation=$4,desired_revision=$4 WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID, generation); e != nil {
				return nil, e
			}
		} else if generation != j.Generation {
			_, e = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='cancelled',completed_at=now(),safe_error='{"code":"SUPERSEDED","message":"Source generation changed","retryable":false}' WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID)
			if e != nil {
				return nil, e
			}
			return nil, tx.Commit(ctx)
		}
		var busy bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pgws_control.operations WHERE tenant_id=$1 AND project_id=$2 AND workspace_id IS NULL AND id<>$3 AND request_document->>'source_id'=$4 AND status='running' AND lease_until>clock_timestamp())`, j.Tenant, j.Project, j.ID, doc.SourceID).Scan(&busy)
		if e != nil {
			return nil, e
		}
		if busy {
			return nil, nil
		}
		e = tx.QueryRow(ctx, `UPDATE pgws_control.sources SET host_fencing_token=host_fencing_token+1 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 RETURNING host_fencing_token`, j.Tenant, j.Project, doc.SourceID).Scan(&j.Fence)
		if e != nil {
			return nil, e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='running',attempt=attempt+1,lease_owner=$4,lease_until=clock_timestamp()+interval '30 seconds',fencing_token=$5,updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID, w.ID, j.Fence)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return &j, nil
}

// CompleteUnavailable checks both the job lease and resource fence. An old
// attempt cannot overwrite a newer claim or a concurrent delete request.
func (w *Worker) CompleteUnavailable(ctx context.Context, j *Job) error {
	return w.completeFailure(ctx, j, "BACKEND_UNAVAILABLE", "A qualified Linux/PostgreSQL/OpenZFS backend is not installed", true)
}
func (w *Worker) completeFailure(ctx context.Context, j *Job, code, message string, unavailable bool) error {
	tx, e := w.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var active bool
	e = tx.QueryRow(ctx, `SELECT pgws_control.lock_authority($1::uuid)`, w.Epoch).Scan(&active)
	if e != nil {
		return e
	}
	if !active {
		return fail(503, "AUTHORITY_RECONCILIATION_REQUIRED", "Authority changed")
	}
	var valid bool
	e = tx.QueryRow(ctx, `SELECT status='running' AND lease_owner=$4 AND fencing_token=$5 AND lease_until>clock_timestamp() FROM pgws_control.operations WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, j.Tenant, j.Project, j.ID, w.ID, j.Fence).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return fail(409, "STALE_WORKER", "Worker lease or fence changed")
	}
	if j.Workspace != nil {
		var revision, fence int64
		e = tx.QueryRow(ctx, `SELECT desired_revision,fencing_token FROM pgws_control.workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, j.Tenant, j.Project, *j.Workspace).Scan(&revision, &fence)
		if e != nil {
			return e
		}
		if revision != j.Revision || fence != j.Fence {
			_, e = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='cancelled',completed_at=now(),lease_until=NULL,updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID)
			if e != nil {
				return e
			}
			return tx.Commit(ctx)
		}
		if !unavailable || j.Kind != "extend_ttl" {
			_, e = tx.Exec(ctx, `UPDATE pgws_control.workspaces SET phase='failed',updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, *j.Workspace)
			if e != nil {
				return e
			}
		}
	}
	if j.Kind == "register_source" || j.Kind == "reseed_source" {
		var doc struct {
			SourceID string `json:"source_id"`
		}
		if e = json.Unmarshal(j.Document, &doc); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE pgws_control.sources SET status='blocked' WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, doc.SourceID)
		if e != nil {
			return e
		}
	}
	failure, _ := json.Marshal(Object{"code": code, "message": message, "retryable": false})
	_, e = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='failed',current_step=$4,safe_error=$5,lease_until=NULL,completed_at=now(),updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID, map[bool]string{true: "capability_check", false: "host_execution"}[unavailable], failure)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (w *Worker) Once(ctx context.Context) (bool, error) {
	j, e := w.Claim(ctx)
	if e != nil || j == nil {
		return false, e
	}
	if w.Backend == nil {
		return true, w.CompleteUnavailable(ctx, j)
	}
	return true, w.execute(ctx, j)
}
