package control

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
)

type ServingRevoker interface {
	RevokeServing(context.Context, Task) (StopObservation, error)
}

// Uses the same current-revision grant rule as serving renewal. A token that
// cannot authorize a fresh lease cannot keep an existing session alive merely
// because its previously signed lease still has time remaining.
const servingGrantSQL = `EXISTS(SELECT FROM pgws_control.operations o
 JOIN pgws_control.api_tokens t ON (t.tenant_id,t.project_id,t.principal_id)=(o.tenant_id,o.project_id,o.actor_reference)
 WHERE (o.tenant_id,o.project_id,o.workspace_id)=(w.tenant_id,w.project_id,w.id)
 AND o.desired_revision=w.desired_revision AND o.status='succeeded'
 AND o.authority_epoch=(SELECT epoch FROM pgws_control.authority WHERE singleton)
 AND t.allow_raw AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()
 AND NOT EXISTS(SELECT FROM pgws_control.baselines b JOIN pgws_control.privacy_policies p ON (p.tenant_id,p.project_id,p.id)=(b.tenant_id,b.project_id,b.privacy_policy_id)
 LEFT JOIN pgws_control.privacy_policy_bindings binding ON (binding.tenant_id,binding.project_id,binding.policy_id)=(p.tenant_id,p.project_id,p.id)
 WHERE (b.tenant_id,b.project_id,b.id)=(w.tenant_id,w.project_id,w.requested_baseline_id)
 AND (p.state<>'approved' OR binding.approval_epoch IS DISTINCT FROM (SELECT epoch FROM pgws_control.authority WHERE singleton))))`

func (w *Worker) ReconcileRevocations(ctx context.Context) error {
	revoker, ok := w.Backend.(ServingRevoker)
	if !ok {
		return nil
	}
	rows, err := w.Pool.Query(ctx, `SELECT tenant_id::text,project_id::text,id::text,current_generation,desired_revision,fencing_token
 FROM pgws_control.workspaces w WHERE phase IN ('ready','paused') AND desired_state<>'deleted' AND current_generation IS NOT NULL
 AND NOT EXISTS(SELECT FROM pgws_control.operations busy WHERE (busy.tenant_id,busy.project_id,busy.workspace_id)=(w.tenant_id,w.project_id,w.id) AND busy.status IN ('queued','running'))
 AND EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$1::uuid)
 AND NOT `+servingGrantSQL+` ORDER BY id LIMIT 1024`, w.Epoch)
	if err != nil {
		return err
	}
	var tasks []Task
	for rows.Next() {
		t := Task{Kind: "revoke_serving"}
		t.Command.Epoch, t.Command.Host = w.Epoch, w.HostID
		if err = rows.Scan(&t.Command.Tenant, &t.Command.Project, &t.Command.Workspace, &t.Command.Generation, &t.Command.Revision, &t.Command.Token); err != nil {
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
	var group errgroup.Group
	group.SetLimit(8)
	for _, t := range tasks {
		group.Go(func() error {
			check, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			var revoked bool
			err := w.Pool.QueryRow(check, `SELECT EXISTS(SELECT FROM pgws_control.workspaces w
 WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND current_generation=$4 AND desired_revision=$5 AND fencing_token=$6
 AND phase IN ('ready','paused') AND desired_state<>'deleted'
 AND NOT EXISTS(SELECT FROM pgws_control.operations busy WHERE (busy.tenant_id,busy.project_id,busy.workspace_id)=(w.tenant_id,w.project_id,w.id) AND busy.status IN ('queued','running'))
 AND EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$7::uuid)
 AND NOT `+servingGrantSQL+`)`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Command.Generation, t.Command.Revision, t.Command.Token, w.Epoch).Scan(&revoked)
			if err != nil || !revoked {
				return err
			}
			out, err := revoker.RevokeServing(check, t)
			if err != nil {
				return err
			}
			t.Kind = "observe_workspace"
			return w.recordHostStop(check, t, out)
		})
	}
	return group.Wait()
}
