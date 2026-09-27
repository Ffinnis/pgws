package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// SweepExpired only records desired cleanup. The independent guard already
// closes sessions at its persisted deadline, even if this worker is unavailable.
func (w *Worker) SweepExpired(ctx context.Context) (int, error) {
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var active bool
	if err = tx.QueryRow(ctx, `SELECT pgws_control.lock_authority($1::uuid)`, w.Epoch).Scan(&active); err != nil {
		return 0, err
	}
	if !active {
		return 0, fail(503, "AUTHORITY_RECONCILIATION_REQUIRED", "Expiry worker authority changed")
	}
	rows, err := tx.Query(ctx, `SELECT tenant_id::text,project_id::text,id::text,coalesce(current_generation,next_generation),desired_revision FROM pgws_control.workspaces WHERE expires_at<=clock_timestamp() AND desired_state<>'deleted' ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT 100`)
	if err != nil {
		return 0, err
	}
	var jobs []Job
	for rows.Next() {
		var j Job
		var id string
		if err = rows.Scan(&j.Tenant, &j.Project, &id, &j.Generation, &j.Revision); err != nil {
			rows.Close()
			return 0, err
		}
		j.Workspace = &id
		jobs = append(jobs, j)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, j := range jobs {
		id := ID()
		body, _ := json.Marshal(Action{Action: "expire", Generation: j.Generation})
		hash := fmt.Sprintf("%x", sha256.Sum256(body))
		_, err = tx.Exec(ctx, `UPDATE pgws_control.workspaces SET desired_state='deleted',phase='expired',desired_revision=desired_revision+1,updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, *j.Workspace)
		if err != nil {
			return 0, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO pgws_control.operations(tenant_id,project_id,id,workspace_id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,authority_epoch) VALUES($1,$2,$3,$4::uuid,'expire',$5,$6,'system:expiry',$4::uuid::text,$7,'queued',$8,$9)`, j.Tenant, j.Project, id, *j.Workspace, j.Generation, j.Revision+1, hash, body, w.Epoch)
		if err != nil {
			return 0, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,operation_id) VALUES($1,$2,$3,'system:expiry','expire',$4,'accepted',$5)`, ID(), j.Tenant, j.Project, *j.Workspace, id)
		if err != nil {
			return 0, err
		}
	}
	return len(jobs), tx.Commit(ctx)
}
