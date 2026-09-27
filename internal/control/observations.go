package control

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"pgws/internal/lease"
	"pgws/internal/parallel"
)

// StopObservation is positive evidence of a durable host safety decision.
// Missing files, transport failure and an absent response are not proof of a
// stopped or healthy resource. Observations never grant serving authorization.
type StopObservation struct {
	Identity    lease.Identity `json:"identity"`
	Stopped     bool           `json:"stopped"`
	Reason      string         `json:"reason,omitempty"`
	StoppedAt   time.Time      `json:"stopped_at,omitempty"`
	SourceEpoch int64          `json:"source_epoch,omitempty"`
}

type StopObserver interface {
	Observe(context.Context, Task) (StopObservation, error)
}

// ReconcileHost mirrors terminal host stops into management. All external I/O
// finishes before the short authority/CAS transaction; a stale observation
// cannot overwrite a changed revision, generation, source epoch or authority.
func (w *Worker) ReconcileHost(ctx context.Context) error {
	observer, ok := w.Backend.(StopObserver)
	if !ok {
		return nil
	}
	rows, err := w.Pool.Query(ctx, `SELECT kind,tenant,project,resource,generation,revision,fence,source_epoch FROM (
 SELECT 'observe_workspace'::text kind,w.tenant_id::text tenant,w.project_id::text project,w.id::text resource,w.current_generation generation,w.desired_revision revision,w.fencing_token fence,0::bigint source_epoch
 FROM pgws_control.workspaces w WHERE w.phase IN ('ready','paused') AND w.desired_state<>'deleted' AND w.current_generation IS NOT NULL
 UNION ALL
 SELECT 'observe_source',s.tenant_id::text,s.project_id::text,s.id::text,b.generation,0,s.host_fencing_token,s.source_epoch
 FROM pgws_control.sources s JOIN pgws_control.baselines b ON (b.tenant_id,b.project_id,b.source_id)=(s.tenant_id,s.project_id,s.id)
 WHERE s.status='streaming' AND b.state='ready' AND b.kind='physical_standby' AND s.source_epoch=b.source_epoch
 ) q WHERE EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$1::uuid) ORDER BY kind,resource LIMIT 1024`, w.Epoch)
	if err != nil {
		return err
	}
	var tasks []Task
	for rows.Next() {
		var task Task
		task.Command.Epoch, task.Command.Host = w.Epoch, w.HostID
		if err = rows.Scan(&task.Kind, &task.Command.Tenant, &task.Command.Project, &task.Command.Workspace, &task.Command.Generation, &task.Command.Revision, &task.Command.Token, &task.Snapshot.SourceEpoch); err != nil {
			rows.Close()
			return err
		}
		tasks = append(tasks, task)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	return parallel.Run(ctx, 8, tasks, func(ctx context.Context, task Task) error {
		check, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		observation, err := observer.Observe(check, task)
		if err == nil && observation.Stopped {
			err = w.recordHostStop(check, task, observation)
		}
		return err
	})
}

func (w *Worker) recordHostStop(ctx context.Context, t Task, observed StopObservation) error {
	if !observed.Stopped || observed.Identity != t.Command.Identity || t.Command.Host != w.HostID || t.Command.Epoch != w.Epoch || observed.StoppedAt.IsZero() {
		return errors.New("host stop evidence identity or time differs")
	}
	// The authenticated host's wall timestamp is audit data. A clock rollback
	// after the durable stop must not prevent closing management access. Scope,
	// generation, revision, fence and authority are checked independently below.
	switch observed.Reason {
	case "POOL_PRESSURE", "SOURCE_WAL_BUDGET", "SOURCE_LINEAGE_CHANGED", "SOURCE_RESEEDED", "WORKSPACE_EXPIRED", "SERVING_LEASE_EXPIRED", "AUTHORIZATION_REVOKED", "SAFETY_STOP", "SOURCE_REVOKED":
	default:
		return errors.New("unsupported host safety decision")
	}
	if t.Kind != "observe_workspace" && t.Kind != "observe_source" {
		return errors.New("invalid host observation kind")
	}
	if t.Kind == "observe_source" && observed.SourceEpoch != t.Snapshot.SourceEpoch {
		return errors.New("host source epoch differs")
	}
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var valid bool
	if err = tx.QueryRow(ctx, `SELECT pgws_control.lock_authority($1::uuid)`, w.Epoch).Scan(&valid); err != nil || !valid {
		return errors.New("authority changed before recording host stop")
	}
	if t.Kind == "observe_workspace" {
		tag, e := tx.Exec(ctx, `UPDATE pgws_control.workspaces SET phase='failed',updated_at=now()
 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND current_generation=$4 AND desired_revision=$5 AND fencing_token=$6
 AND phase IN ('ready','paused') AND desired_state<>'deleted'`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Command.Generation, t.Command.Revision, t.Command.Token)
		if e != nil || tag.RowsAffected() == 0 {
			return e
		}
		_, err = tx.Exec(ctx, `UPDATE pgws_control.workspace_generations SET phase='failed' WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND generation=$4`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Command.Generation)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE pgws_control.credentials SET revoked_at=coalesce(revoked_at,now()) WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND generation=$4`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Command.Generation)
		}
	} else {
		tag, e := tx.Exec(ctx, `UPDATE pgws_control.sources SET status='blocked',observed_at=now()
 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND source_epoch=$4 AND host_fencing_token=$5 AND status='streaming'
 AND EXISTS(SELECT FROM pgws_control.baselines b WHERE (b.tenant_id,b.project_id,b.source_id)=(sources.tenant_id,sources.project_id,sources.id) AND b.generation=$6 AND b.source_epoch=$4 AND b.state='ready')`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Snapshot.SourceEpoch, t.Command.Token, t.Command.Generation)
		if e != nil || tag.RowsAffected() == 0 {
			return e
		}
		_, err = tx.Exec(ctx, `UPDATE pgws_control.baselines SET state='blocked',observed_at=now() WHERE tenant_id=$1 AND project_id=$2 AND source_id=$3 AND generation=$4 AND source_epoch=$5 AND state='ready'`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Command.Generation, t.Snapshot.SourceEpoch)
	}
	if err != nil {
		return err
	}
	metadata, _ := json.Marshal(observed)
	_, err = tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,safe_metadata) VALUES($1,$2,$3,$4,'host.safety_stop',$5,'blocked',$6)`, ID(), t.Command.Tenant, t.Command.Project, "host:"+t.Command.Host, t.Command.Workspace, metadata)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
