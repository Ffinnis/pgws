package control

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/freshness"
	"pgws/internal/lease"
)

// Backend is implemented by an authenticated host client. The public API has
// neither a backend reference nor storage/runtime privileges.
type Backend interface {
	Execute(context.Context, Task) (Outcome, error)
	Revoke(context.Context, Task) error
	Activate(context.Context, Task, string) error
}

// ErrHostUnavailable means no trustworthy completion response was received.
// It does not assert whether the host performed the requested side effects.
var ErrHostUnavailable = errors.New("host operation result is unavailable")

type Task struct {
	Command           lease.Command    `json:"command"`
	Kind              string           `json:"kind"`
	Document          json.RawMessage  `json:"document"`
	Expiry            time.Time        `json:"expires_at"`
	Desired           string           `json:"desired_state"`
	SourceID          string           `json:"source_id,omitempty"`
	EndpointReference string           `json:"endpoint_reference,omitempty"`
	SecretReference   string           `json:"secret_reference,omitempty"`
	Snapshot          Snapshot         `json:"snapshot"`
	Actor             string           `json:"actor"`
	Freshness         *Freshness       `json:"freshness,omitempty"`
	SourceContract    freshness.Claims `json:"source_contract"`
	Profile           string           `json:"resource_profile"`
}
type Snapshot struct {
	ID, Baseline, Name, GUID, Digest string
	SourceEpoch, Timeline            int64
	BaselineGeneration               int64
	LowerBound                       string
	RequestedLSN                     string
	Manifest                         json.RawMessage
}
type Realization struct {
	Generation int64           `json:"generation"`
	SnapshotID string          `json:"snapshot_id"`
	VolumeName string          `json:"volume_name"`
	VolumeGUID string          `json:"volume_guid"`
	Runtime    string          `json:"runtime"`
	Digest     string          `json:"digest"`
	Endpoint   json.RawMessage `json:"endpoint"`
	Evidence   json.RawMessage `json:"evidence"`
}
type Outcome struct {
	Phase      string             `json:"phase"`
	Generation *Realization       `json:"generation,omitempty"`
	Expiry     *time.Time         `json:"expires_at,omitempty"`
	Source     *SourceOutcome     `json:"source,omitempty"`
	Credential *CredentialOutcome `json:"credential,omitempty"`
	Snapshot   *Snapshot          `json:"snapshot,omitempty"`
	Barrier    *freshness.Claims  `json:"barrier,omitempty"`
}
type SourceOutcome struct {
	ID        string          `json:"id"`
	SystemID  string          `json:"system_id"`
	Timeline  int64           `json:"timeline"`
	Discovery json.RawMessage `json:"discovery"`
	Snapshot  Snapshot        `json:"snapshot"`
}

func (w *Worker) renew(ctx context.Context, j *Job) error {
	var valid bool
	err := w.Pool.QueryRow(ctx, `UPDATE pgws_control.operations o SET lease_until=clock_timestamp()+interval '30 seconds',updated_at=now()
 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND status='running' AND lease_owner=$4 AND fencing_token=$5 AND lease_until>clock_timestamp()
 AND EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$6::uuid)
 AND (o.kind IN ('expire','gc_snapshot') OR EXISTS(SELECT FROM pgws_control.api_tokens t WHERE t.tenant_id=o.tenant_id AND t.project_id=o.project_id AND t.principal_id=o.actor_reference AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() AND (o.workspace_id IS NULL AND (o.kind IN ('register_source','reseed_source') AND t.is_admin OR o.kind='issue_barrier' AND t.allow_raw) OR o.workspace_id IS NOT NULL AND t.allow_raw)))
 AND (o.workspace_id IS NOT NULL OR EXISTS(SELECT FROM pgws_control.sources s WHERE (s.tenant_id,s.project_id,s.id)=(o.tenant_id,o.project_id,(o.request_document->>'source_id')::uuid) AND s.host_fencing_token=o.fencing_token AND s.baseline_generation=o.expected_generation AND (o.kind='gc_snapshot' OR EXISTS(SELECT FROM pgws_control.approved_source_references a WHERE (a.tenant_id,a.project_id,a.endpoint_reference,a.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference)))))
 AND (o.kind<>'gc_snapshot' OR EXISTS(SELECT FROM pgws_control.snapshots s WHERE (s.tenant_id,s.project_id,s.id)=(o.tenant_id,o.project_id,(o.request_document->>'snapshot_id')::uuid) AND s.state='deleting' AND NOT EXISTS(SELECT FROM pgws_control.snapshot_refs r WHERE (r.tenant_id,r.project_id,r.snapshot_id)=(s.tenant_id,s.project_id,s.id))))
 AND (workspace_id IS NULL OR EXISTS(SELECT FROM pgws_control.workspaces w WHERE (w.tenant_id,w.project_id,w.id)=(o.tenant_id,o.project_id,o.workspace_id) AND w.desired_revision=o.desired_revision AND w.fencing_token=o.fencing_token AND (w.expires_at>clock_timestamp() OR o.kind IN ('delete','expire')) AND (o.kind<>'expire' OR w.expires_at<=clock_timestamp())))
 RETURNING true`, j.Tenant, j.Project, j.ID, w.ID, j.Fence, w.Epoch).Scan(&valid)
	if err != nil || !valid {
		return fail(409, "STALE_WORKER", "Operation authority, lease, permission or revision changed")
	}
	return nil
}
func (w *Worker) task(ctx context.Context, j *Job) (Task, error) {
	if err := w.renew(ctx, j); err != nil {
		return Task{}, err
	}
	t := Task{Kind: j.Kind, Document: j.Document, Command: lease.Command{Identity: lease.Identity{Epoch: w.Epoch, Tenant: j.Tenant, Project: j.Project, Host: w.ID, Generation: j.Generation, Revision: j.Revision}, Operation: j.ID, Token: j.Fence}}
	if w.HostID != "" {
		t.Command.Host = w.HostID
	}
	if err := w.Pool.QueryRow(ctx, `SELECT coalesce(actor_reference::text,'') FROM pgws_control.operations WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID).Scan(&t.Actor); err != nil {
		return t, err
	}
	if j.Workspace == nil {
		var doc sourceJob
		if json.Unmarshal(j.Document, &doc) != nil || !ValidID(doc.SourceID) {
			return t, errors.New("invalid source operation")
		}
		t.SourceID = doc.SourceID
		t.Command.Workspace = doc.SourceID
		if j.Kind == "reseed_source" {
			if !ValidID(doc.BaselineID) || doc.SourceEpoch < 2 || j.Generation < 2 {
				return t, errors.New("invalid reseed identity")
			}
			t.Snapshot = Snapshot{Baseline: doc.BaselineID, BaselineGeneration: j.Generation, SourceEpoch: doc.SourceEpoch}
		}
		if j.Kind == "gc_snapshot" {
			var request struct {
				SnapshotID string `json:"snapshot_id"`
			}
			if json.Unmarshal(j.Document, &request) != nil || !ValidID(request.SnapshotID) {
				return t, errors.New("invalid snapshot collection request")
			}
			err := w.Pool.QueryRow(ctx, `SELECT s.id::text,s.baseline_id::text,s.storage_name,s.storage_guid,s.source_epoch,s.source_timeline,b.generation FROM pgws_control.snapshots s JOIN pgws_control.baselines b ON (b.tenant_id,b.project_id,b.id)=(s.tenant_id,s.project_id,s.baseline_id) WHERE s.tenant_id=$1 AND s.project_id=$2 AND s.id=$3 AND b.source_id=$4 AND s.state='deleting'`, j.Tenant, j.Project, request.SnapshotID, doc.SourceID).Scan(&t.Snapshot.ID, &t.Snapshot.Baseline, &t.Snapshot.Name, &t.Snapshot.GUID, &t.Snapshot.SourceEpoch, &t.Snapshot.Timeline, &t.Snapshot.BaselineGeneration)
			return t, err
		}

		err := w.Pool.QueryRow(ctx, `SELECT endpoint_reference,secret_reference FROM pgws_control.sources s WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND EXISTS(SELECT FROM pgws_control.approved_source_references a WHERE (a.tenant_id,a.project_id,a.endpoint_reference,a.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference))`, j.Tenant, j.Project, doc.SourceID).Scan(&t.EndpointReference, &t.SecretReference)
		if err == nil && j.Kind == "issue_barrier" {
			err = w.Pool.QueryRow(ctx, `SELECT source_epoch,system_identifier,timeline FROM pgws_control.sources WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND status='streaming'`, j.Tenant, j.Project, t.SourceID).Scan(&t.SourceContract.SourceEpoch, &t.SourceContract.SystemID, &t.SourceContract.Timeline)
		}
		return t, err
	}
	t.Command.Workspace = *j.Workspace
	var baseline string
	var freshness Freshness
	var raw []byte
	err := w.Pool.QueryRow(ctx, `SELECT expires_at,desired_state,requested_baseline_id::text,requested_freshness,resource_profile FROM pgws_control.workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, *j.Workspace).Scan(&t.Expiry, &t.Desired, &baseline, &raw, &t.Profile)
	if err != nil {
		return t, err
	}
	if json.Unmarshal(raw, &freshness) != nil {
		return t, errors.New("invalid persisted freshness")
	}
	if j.Kind == "reset" {
		var a Action
		if json.Unmarshal(j.Document, &a) != nil || a.Freshness == nil {
			return t, errors.New("invalid reset operation")
		}
		baseline = a.BaselineID
		freshness = *a.Freshness
		t.Command.Generation++
	}
	if j.Kind == "delete" || j.Kind == "expire" {
		err = w.Pool.QueryRow(ctx, `SELECT greatest($4::bigint,coalesce(max(CASE WHEN kind='reset' THEN expected_generation+1 ELSE expected_generation END),$4::bigint)) FROM pgws_control.operations WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3`, j.Tenant, j.Project, *j.Workspace, j.Generation).Scan(&t.Command.Generation)
		return t, err
	}
	if j.Kind == "create" || j.Kind == "reset" {
		t.Freshness = &freshness
		if freshness.Mode != "snapshot" {
			err = w.Pool.QueryRow(ctx, `SELECT b.id::text,b.generation,b.runtime_digest,b.source_epoch,b.source_timeline,b.compatibility_manifest,s.id::text,s.endpoint_reference,s.secret_reference FROM pgws_control.baselines b JOIN pgws_control.sources s ON (s.tenant_id,s.project_id,s.id)=(b.tenant_id,b.project_id,b.source_id) WHERE b.tenant_id=$1 AND b.project_id=$2 AND b.id=$3 AND b.state='ready' AND b.kind='physical_standby' AND s.status='streaming' AND s.source_epoch=b.source_epoch AND s.timeline=b.source_timeline AND EXISTS(SELECT FROM pgws_control.approved_source_references a WHERE (a.tenant_id,a.project_id,a.endpoint_reference,a.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference))`, j.Tenant, j.Project, baseline).Scan(&t.Snapshot.Baseline, &t.Snapshot.BaselineGeneration, &t.Snapshot.Digest, &t.Snapshot.SourceEpoch, &t.Snapshot.Timeline, &t.Snapshot.Manifest, &t.SourceID, &t.EndpointReference, &t.SecretReference)
			return t, err
		}
		err = w.Pool.QueryRow(ctx, `SELECT s.id::text,s.baseline_id::text,s.storage_name,s.storage_guid,b.runtime_digest,s.source_epoch,s.source_timeline,s.captured_source_lower_bound::text,b.compatibility_manifest,b.generation
 FROM pgws_control.snapshots s JOIN pgws_control.baselines b ON (b.tenant_id,b.project_id,b.id)=(s.tenant_id,s.project_id,s.baseline_id)
 WHERE s.tenant_id=$1 AND s.project_id=$2 AND s.id=$3 AND s.baseline_id=$4 AND s.state='ready' AND b.state='ready' AND b.kind='physical_standby'`, j.Tenant, j.Project, freshness.SnapshotID, baseline).Scan(&t.Snapshot.ID, &t.Snapshot.Baseline, &t.Snapshot.Name, &t.Snapshot.GUID, &t.Snapshot.Digest, &t.Snapshot.SourceEpoch, &t.Snapshot.Timeline, &t.Snapshot.LowerBound, &t.Snapshot.Manifest, &t.Snapshot.BaselineGeneration)
	}
	return t, err
}
func (w *Worker) execute(ctx context.Context, j *Job) error {
	t, err := w.task(ctx, j)
	if err != nil {
		failed, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = w.completeFailure(failed, j, "AUTHORITY_CHANGED", "Operation authorization or resource preconditions changed", false)
		return err
	}
	if err = w.step(ctx, j, "started", nil); err != nil {
		return err
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-ticker.C:
				check, done := context.WithTimeout(work, 3*time.Second)
				err := w.renew(check, j)
				done()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	originalTask := t
	result, err := w.Backend.Execute(work, t)
	if err == nil && result.Snapshot != nil {
		snap := result.Snapshot
		if t.Freshness == nil || t.Freshness.Mode == "snapshot" || snap.ID != j.ID || snap.Baseline != t.Snapshot.Baseline || snap.Digest != t.Snapshot.Digest || snap.SourceEpoch != t.Snapshot.SourceEpoch || snap.BaselineGeneration != t.Snapshot.BaselineGeneration || snap.Timeline != t.Snapshot.Timeline || snap.GUID == "" || snap.LowerBound == "" {
			err = errors.New("captured snapshot identity differs")
		} else {
			t.Snapshot = *snap
		}
	}
	cancel()
	<-renewed
	if err == nil && (result.Phase == "ready" || j.Kind == "extend_ttl") {
		if result.Expiry != nil {
			t.Expiry = *result.Expiry
		}
		if err = w.renew(ctx, j); err == nil {
			var token string
			token, err = w.servingToken(t)
			if err == nil {
				err = w.Backend.Activate(ctx, t, token)
			}
		}
	}
	if err == nil {
		err = w.complete(ctx, j, t, result)
		if err != nil {
			// A lost COMMIT acknowledgement must not revoke a realization whose
			// exact operation attempt was durably published.
			check, done := context.WithTimeout(context.Background(), 3*time.Second)
			var committed bool
			e := w.Pool.QueryRow(check, `SELECT status='succeeded' AND lease_owner=$4 AND fencing_token=$5 AND authority_epoch=$6::uuid FROM pgws_control.operations WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID, w.ID, j.Fence, w.Epoch).Scan(&committed)
			done()
			if e == nil && committed {
				return nil
			}
		}
	}
	if errors.Is(err, ErrHostUnavailable) && w.retryUnknownHostResult(j) == nil {
		return err
	}
	if err != nil {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if j.Kind != "issue_barrier" && j.Kind != "gc_snapshot" {
			_ = w.Backend.Revoke(cleanup, originalTask)
		}
		_ = w.step(cleanup, j, "failed", nil)
		_ = w.completeFailure(cleanup, j, "HOST_EXECUTION_FAILED", "Host execution did not complete; resources remain private pending reconciliation", false)
		return err
	}
	return nil
}

// Release this worker attempt, then let ordinary Claim recheck authorization,
// expiry and revision and allocate a newer fence. Host reconciliation runs
// outside this transaction. A persistent outage is bounded to ten attempts.
func (w *Worker) retryUnknownHostResult(j *Job) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.renew(ctx, j); err != nil {
		return err
	}
	tag, err := w.Pool.Exec(ctx, `UPDATE pgws_control.operations SET status='queued',current_step='host_reconciliation',not_before=clock_timestamp()+interval '5 seconds',lease_until=NULL,updated_at=now()
 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND status='running' AND lease_owner=$4 AND fencing_token=$5 AND lease_until>clock_timestamp() AND attempt<10`, j.Tenant, j.Project, j.ID, w.ID, j.Fence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("host retry is stale or exhausted")
	}
	return nil
}
func (w *Worker) step(ctx context.Context, j *Job, state string, evidence []byte) error {
	if evidence == nil {
		evidence = []byte(`{}`)
	}
	_, err := w.Pool.Exec(ctx, `INSERT INTO pgws_control.operation_steps(tenant_id,project_id,operation_id,step_name,attempt,fencing_token,state,safe_evidence,finished_at)
 SELECT tenant_id,project_id,id,'host_execution',attempt,fencing_token,$6,$7,CASE WHEN $6<>'started' THEN now() END FROM pgws_control.operations WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND status='running' AND lease_owner=$4 AND fencing_token=$5 AND lease_until>clock_timestamp()
 ON CONFLICT(tenant_id,project_id,operation_id,step_name,attempt) DO UPDATE SET state=excluded.state,safe_evidence=excluded.safe_evidence,finished_at=excluded.finished_at`, j.Tenant, j.Project, j.ID, w.ID, j.Fence, state, evidence)
	return err
}
func (w *Worker) complete(ctx context.Context, j *Job, t Task, out Outcome) error {
	if err := w.renew(ctx, j); err != nil {
		return err
	}
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = w.lockAuthority(ctx, tx, j); err != nil {
		return err
	}
	if t.SourceID != "" && j.Kind != "gc_snapshot" {
		var approved bool
		if err = tx.QueryRow(ctx, `SELECT pgws_control.lock_source_reference($1,$2,$3,$4)`, j.Tenant, j.Project, t.EndpointReference, t.SecretReference).Scan(&approved); err != nil {
			return err
		}
		if !approved {
			return errors.New("source reference approval changed")
		}
	}
	var valid bool
	err = tx.QueryRow(ctx, `SELECT status='running' AND lease_owner=$4 AND fencing_token=$5 AND lease_until>clock_timestamp() FROM pgws_control.operations WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, j.Tenant, j.Project, j.ID, w.ID, j.Fence).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return fail(409, "STALE_WORKER", "Operation attempt changed")
	}
	if j.Workspace == nil {
		var sourceFence int64
		if err = tx.QueryRow(ctx, `SELECT host_fencing_token FROM pgws_control.sources WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, j.Tenant, j.Project, t.SourceID).Scan(&sourceFence); err != nil {
			return err
		}
		if sourceFence != j.Fence {
			return fail(409, "STALE_WORKER", "Source fence changed")
		}
		if j.Kind == "gc_snapshot" {
			return w.completeGC(ctx, tx, j, t, out)
		}
		if j.Kind == "issue_barrier" {
			return w.completeBarrier(ctx, tx, j, t, out)
		}
		return w.completeSource(ctx, tx, j, t, out)
	}
	var revision, fence int64
	var expired bool
	err = tx.QueryRow(ctx, `SELECT desired_revision,fencing_token,expires_at<=clock_timestamp() FROM pgws_control.workspaces WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, j.Tenant, j.Project, *j.Workspace).Scan(&revision, &fence, &expired)
	if err != nil {
		return err
	}
	if revision != j.Revision || fence != j.Fence || (expired && j.Kind != "delete" && j.Kind != "expire") || (j.Kind == "expire" && !expired) {
		return fail(409, "STALE_WORKER", "Resource revision changed")
	}
	if j.Kind == "issue_credential" {
		return w.completeCredential(ctx, tx, j, t, out)
	}
	expected := map[string]string{"create": "ready", "reset": "ready", "pause": "paused", "resume": "ready", "delete": "deleted", "expire": "deleted"}
	if j.Kind == "reset" && t.Desired == "paused" {
		expected["reset"] = "paused"
	}
	if j.Kind != "extend_ttl" && out.Phase != expected[j.Kind] {
		return errors.New("host returned unexpected phase")
	}
	if j.Kind == "create" || j.Kind == "reset" {
		g := out.Generation
		if out.Snapshot != nil {
			s := out.Snapshot
			_, err = tx.Exec(ctx, `INSERT INTO pgws_control.snapshots(tenant_id,project_id,id,baseline_id,source_epoch,source_timeline,captured_source_lower_bound,storage_name,storage_guid,capture_operation_id,state,captured_at,requested_source_lsn) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$3,'ready',now(),nullif($10,'')::pg_lsn)`, j.Tenant, j.Project, s.ID, s.Baseline, s.SourceEpoch, s.Timeline, s.LowerBound, s.Name, s.GUID, s.RequestedLSN)
			if err != nil {
				return err
			}
		}
		if g == nil || g.Generation != t.Command.Generation || g.SnapshotID != t.Snapshot.ID || g.VolumeGUID == "" || g.Runtime == "" || g.Digest != t.Snapshot.Digest || len(g.Evidence) == 0 || len(g.Endpoint) == 0 {
			return errors.New("incomplete host realization evidence")
		}
		_, err = tx.Exec(ctx, `INSERT INTO pgws_control.workspace_generations(tenant_id,project_id,workspace_id,generation,snapshot_id,phase,volume_name,volume_guid,runtime_reference,runtime_digest,endpoint_metadata,readiness_evidence,ready_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())`, j.Tenant, j.Project, *j.Workspace, g.Generation, g.SnapshotID, out.Phase, g.VolumeName, g.VolumeGUID, g.Runtime, g.Digest, g.Endpoint, g.Evidence)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO pgws_control.snapshot_refs(tenant_id,project_id,snapshot_id,owner_kind,owner_id,owner_generation,hold_tag) VALUES($1,$2,$3,'workspace',$4,$5,$6)`, j.Tenant, j.Project, g.SnapshotID, *j.Workspace, g.Generation, "pgws:"+g.SnapshotID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE pgws_control.workspaces SET current_generation=$4::bigint,next_generation=$4::bigint+1,requested_baseline_id=$5,requested_freshness=jsonb_build_object('mode','snapshot','snapshot_id',$6::text) WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, *j.Workspace, g.Generation, t.Snapshot.Baseline, g.SnapshotID)
		if err != nil {
			return err
		}
	}
	if j.Kind == "extend_ttl" {
		var a Action
		_ = json.Unmarshal(j.Document, &a)
		if out.Expiry == nil || !out.Expiry.Equal(a.Expiry) {
			return errors.New("host did not acknowledge requested expiry")
		}
		tag, e := tx.Exec(ctx, `UPDATE pgws_control.workspaces SET expires_at=$4,updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND expires_at=$5 AND expires_at>clock_timestamp()`, j.Tenant, j.Project, *j.Workspace, *out.Expiry, a.ExpectedExpiry)
		err = e
		if err == nil && tag.RowsAffected() != 1 {
			return errors.New("effective expiry compare failed")
		}
	} else {
		_, err = tx.Exec(ctx, `UPDATE pgws_control.workspaces SET phase=$4,updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, *j.Workspace, out.Phase)
	}
	if err != nil {
		return err
	}
	if j.Kind == "pause" || j.Kind == "resume" {
		_, err = tx.Exec(ctx, `UPDATE pgws_control.workspace_generations SET phase=$4 WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND generation=$5`, j.Tenant, j.Project, *j.Workspace, out.Phase, j.Generation)
		if err != nil {
			return err
		}
	}
	if j.Kind == "reset" || j.Kind == "delete" || j.Kind == "expire" {
		_, err = tx.Exec(ctx, `UPDATE pgws_control.workspace_generations SET phase='deleted',deleted_at=coalesce(deleted_at,now()) WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND generation<=$4`, j.Tenant, j.Project, *j.Workspace, j.Generation)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE pgws_control.credentials SET revoked_at=coalesce(revoked_at,now()) WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND generation<=$4`, j.Tenant, j.Project, *j.Workspace, j.Generation)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM pgws_control.snapshot_refs WHERE tenant_id=$1 AND project_id=$2 AND owner_kind='workspace' AND owner_id=$3 AND owner_generation<=$4`, j.Tenant, j.Project, *j.Workspace, j.Generation)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operation_steps SET state='completed',finished_at=now() WHERE tenant_id=$1 AND project_id=$2 AND operation_id=$3 AND fencing_token=$4 AND step_name='host_execution'`, j.Tenant, j.Project, j.ID, j.Fence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='succeeded',current_step='completed',lease_until=NULL,completed_at=now(),updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Hold authority and the authorizing grant through the final metadata commit.
// The host call happens before this short transaction.
func (w *Worker) lockAuthority(ctx context.Context, tx pgx.Tx, j *Job) error {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT pgws_control.lock_authority($1::uuid)`, w.Epoch).Scan(&active); err != nil {
		return err
	}
	if !active {
		return errors.New("control authority changed")
	}
	if j.Kind == "expire" || j.Kind == "gc_snapshot" {
		return nil
	}
	var granted bool
	err := tx.QueryRow(ctx, `SELECT pgws_control.lock_execution_grant($1,$2,$3)`, j.Tenant, j.Project, j.ID).Scan(&granted)
	if err != nil {
		return err
	}
	if !granted {
		return errors.New("operation grant changed")
	}
	return nil
}
