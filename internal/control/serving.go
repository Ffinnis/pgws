package control

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/lease"
	"pgws/internal/parallel"
)

func (w *Worker) servingToken(t Task) (string, error) {
	now := time.Now().UTC()
	return lease.Sign(w.SigningKey, lease.Claims{Identity: t.Command.Identity, IssuedAt: now, ExpiresAt: now.Add(90 * time.Second), WorkspaceExpiry: t.Expiry})
}

// RefreshServing is independent of job execution; slow storage/source work
// cannot delay short serving-lease renewals. It rechecks current authorization.
func (w *Worker) RefreshServing(ctx context.Context) error {
	if w.Backend == nil {
		return nil
	}
	rows, err := w.Pool.Query(ctx, `SELECT w.tenant_id::text,w.project_id::text,w.id::text,w.current_generation,w.desired_revision,w.fencing_token,w.expires_at
 FROM pgws_control.workspaces w WHERE w.phase='ready' AND w.desired_state='running' AND w.expires_at>clock_timestamp()
 AND EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$1::uuid)
 AND `+servingGrantSQL, w.Epoch)
	if err != nil {
		return err
	}
	var tasks []Task
	for rows.Next() {
		t := Task{Kind: "refresh"}
		t.Command.Epoch = w.Epoch
		t.Command.Host = w.HostID
		if err = rows.Scan(&t.Command.Tenant, &t.Command.Project, &t.Command.Workspace, &t.Command.Generation, &t.Command.Revision, &t.Command.Token, &t.Expiry); err != nil {
			rows.Close()
			return err
		}
		tasks = append(tasks, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// A stalled endpoint cannot consume the renewal window of unrelated ones.
	return parallel.Run(ctx, 8, tasks, func(ctx context.Context, t Task) error {
		refresh, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return w.refreshOne(refresh, t)
	})
}
func (w *Worker) refreshOne(ctx context.Context, t Task) error {
	var valid bool
	e := w.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pgws_control.workspaces w WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND desired_revision=$4 AND fencing_token=$5 AND phase='ready' AND desired_state='running' AND expires_at>clock_timestamp() AND EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$6::uuid) AND `+servingGrantSQL+`)`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Command.Revision, t.Command.Token, w.Epoch).Scan(&valid)
	if e == nil && valid {
		var token string
		token, e = w.servingToken(t)
		if e == nil {
			e = w.Backend.Activate(ctx, t, token)
		}
	}
	return e
}

func (w *Worker) completeSource(ctx context.Context, tx pgx.Tx, j *Job, t Task, out Outcome) error {
	s := out.Source
	if out.Phase != "streaming" || s == nil || !ValidID(s.ID) || !ValidID(s.Snapshot.ID) || !ValidID(s.Snapshot.Baseline) || s.SystemID == "" || s.Timeline < 1 || s.Snapshot.GUID == "" || s.Snapshot.LowerBound == "" || !json.Valid(s.Snapshot.Manifest) {
		return errors.New("incomplete source execution evidence")
	}
	var doc struct {
		SourceID string `json:"source_id"`
	}
	if json.Unmarshal(j.Document, &doc) != nil || s.ID != doc.SourceID {
		return errors.New("source outcome identity differs")
	}
	baseline, epoch := t.SourceID, int64(1)
	if j.Kind == "reseed_source" {
		baseline, epoch = t.Snapshot.Baseline, t.Snapshot.SourceEpoch
	}
	if s.Snapshot.Baseline != baseline || s.Snapshot.BaselineGeneration != j.Generation || s.Snapshot.SourceEpoch != epoch || s.Snapshot.ID != j.ID || s.Snapshot.Timeline != s.Timeline {
		return errors.New("source generation evidence differs from its admitted request")
	}
	var current bool
	if err := tx.QueryRow(ctx, `SELECT source_epoch=$4 AND baseline_generation=$5 FROM pgws_control.sources WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, s.ID, epoch, j.Generation).Scan(&current); err != nil {
		return err
	}
	if !current {
		return errors.New("source generation changed before completion")
	}
	_, err := tx.Exec(ctx, `UPDATE pgws_control.sources SET system_identifier=$4,timeline=$5,status='streaming',discovery_manifest=$6,observed_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, s.ID, s.SystemID, s.Timeline, s.Discovery)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pgws_control.baselines(tenant_id,project_id,id,source_id,generation,source_epoch,source_timeline,kind,runtime_digest,compatibility_manifest,state,observed_applied_source_lsn,observed_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,'physical_standby',$8,$9,'ready',$10,now())`, j.Tenant, j.Project, baseline, s.ID, j.Generation, epoch, s.Timeline, s.Snapshot.Digest, s.Snapshot.Manifest, s.Snapshot.LowerBound)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pgws_control.snapshots(tenant_id,project_id,id,baseline_id,source_epoch,source_timeline,captured_source_lower_bound,storage_name,storage_guid,capture_operation_id,state,captured_at,requested_source_lsn)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$3,'ready',now(),nullif($10,'')::pg_lsn)`, j.Tenant, j.Project, s.Snapshot.ID, baseline, s.Snapshot.SourceEpoch, s.Timeline, s.Snapshot.LowerBound, s.Snapshot.Name, s.Snapshot.GUID, s.Snapshot.RequestedLSN)
	if err != nil {
		return err
	}
	result, _ := json.Marshal(Object{"source_id": s.ID, "baseline_id": baseline, "snapshot_id": s.Snapshot.ID, "source_epoch": epoch, "generation": j.Generation})
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operation_steps SET state='completed',finished_at=now() WHERE tenant_id=$1 AND project_id=$2 AND operation_id=$3 AND fencing_token=$4`, j.Tenant, j.Project, j.ID, j.Fence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='succeeded',current_step='streaming',safe_result=$4,lease_until=NULL,completed_at=now(),updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID, result)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
