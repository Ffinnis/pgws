package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
)

// Snapshot collection preserves the newest ready snapshot of each baseline.
// Admission locks the selected snapshot through enqueue, closing the GC race.
func (w *Worker) SweepSnapshots(ctx context.Context) (int, error) {
	tx, e := w.Pool.Begin(ctx)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback(ctx)
	var active bool
	if e = tx.QueryRow(ctx, `SELECT pgws_control.lock_authority($1)`, w.Epoch).Scan(&active); e != nil {
		return 0, e
	}
	if !active {
		return 0, errors.New("GC authority changed")
	}
	rows, e := tx.Query(ctx, `SELECT s.tenant_id::text,s.project_id::text,s.id::text,b.source_id::text FROM pgws_control.snapshots s JOIN pgws_control.baselines b ON (b.tenant_id,b.project_id,b.id)=(s.tenant_id,s.project_id,s.baseline_id) WHERE b.kind='physical_standby' AND NOT EXISTS(SELECT FROM pgws_control.snapshot_refs r WHERE (r.tenant_id,r.project_id,r.snapshot_id)=(s.tenant_id,s.project_id,s.id)) AND NOT EXISTS(SELECT FROM pgws_control.operations o WHERE o.tenant_id=s.tenant_id AND o.project_id=s.project_id AND o.status IN ('queued','running') AND o.request_document->'freshness'->>'snapshot_id'=s.id::text) AND ((s.state='ready' AND s.created_at<clock_timestamp()-interval '1 hour' AND (b.state='retired' OR EXISTS(SELECT FROM pgws_control.snapshots newer WHERE (newer.tenant_id,newer.project_id,newer.baseline_id)=(s.tenant_id,s.project_id,s.baseline_id) AND newer.state='ready' AND (newer.captured_at,newer.id)>(s.captured_at,s.id)))) OR (s.state='deleting' AND (SELECT o.completed_at<clock_timestamp()-interval '1 minute' AND o.status IN ('failed','cancelled') FROM pgws_control.operations o WHERE o.tenant_id=s.tenant_id AND o.project_id=s.project_id AND o.kind='gc_snapshot' AND o.request_document->>'snapshot_id'=s.id::text ORDER BY o.created_at DESC,o.id DESC LIMIT 1))) ORDER BY s.created_at,s.id FOR UPDATE OF s SKIP LOCKED LIMIT 50`)
	if e != nil {
		return 0, e
	}
	type item struct{ tenant, project, snapshot, source string }
	var candidates []item
	for rows.Next() {
		var x item
		if e = rows.Scan(&x.tenant, &x.project, &x.snapshot, &x.source); e != nil {
			rows.Close()
			return 0, e
		}
		candidates = append(candidates, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	for _, x := range candidates {
		doc, _ := json.Marshal(Object{"source_id": x.source, "snapshot_id": x.snapshot})
		hash := fmt.Sprintf("%x", sha256.Sum256(doc))
		id := ID()
		_, e = tx.Exec(ctx, `UPDATE pgws_control.snapshots SET state='deleting' WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, x.tenant, x.project, x.snapshot)
		if e != nil {
			return 0, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO pgws_control.operations(tenant_id,project_id,id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,authority_epoch) VALUES($1,$2,$3,'gc_snapshot',1,1,'system:snapshot-gc',$4,$5,'queued',$6,$7)`, x.tenant, x.project, id, x.snapshot+":"+id, hash, doc, w.Epoch)
		if e != nil {
			return 0, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,operation_id) VALUES($1,$2,$3,'system:snapshot-gc','gc_snapshot',$4,'accepted',$5)`, ID(), x.tenant, x.project, x.snapshot, id)
		if e != nil {
			return 0, e
		}
	}
	return len(candidates), tx.Commit(ctx)
}
func (w *Worker) completeGC(ctx context.Context, tx pgx.Tx, j *Job, t Task, out Outcome) error {
	if out.Phase != "snapshot_deleted" {
		return errors.New("snapshot destruction was not confirmed")
	}
	var referenced bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pgws_control.snapshot_refs WHERE tenant_id=$1 AND project_id=$2 AND snapshot_id=$3)`, j.Tenant, j.Project, t.Snapshot.ID).Scan(&referenced); e != nil {
		return e
	}
	if referenced {
		return errors.New("snapshot acquired a reference during collection")
	}
	tag, e := tx.Exec(ctx, `UPDATE pgws_control.snapshots SET state='deleted' WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND state='deleting' AND storage_guid=$4`, j.Tenant, j.Project, t.Snapshot.ID, t.Snapshot.GUID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("snapshot cleanup identity changed")
	}
	_, e = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='succeeded',current_step='snapshot_deleted',lease_until=NULL,completed_at=now(),updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE pgws_control.operation_steps SET state='completed',finished_at=now() WHERE tenant_id=$1 AND project_id=$2 AND operation_id=$3 AND fencing_token=$4`, j.Tenant, j.Project, j.ID, j.Fence)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
