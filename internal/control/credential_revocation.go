package control

import (
	"context"
	"encoding/json"
	"time"

	"golang.org/x/sync/errgroup"
	"pgws/internal/lease"
)

type CredentialRevoker interface {
	RevokeCredentials(context.Context, Task) error
}
type CredentialRevocation struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (w *Worker) ReconcileCredentialRevocations(ctx context.Context) error {
	revoker, ok := w.Backend.(CredentialRevoker)
	if !ok {
		return nil
	}
	// This statement commits revocation before the private host call. Its rows
	// are drained and closed first; no management transaction spans host I/O.
	rows, err := w.Pool.Query(ctx, `UPDATE pgws_control.credentials c SET revoked_at=coalesce(c.revoked_at,clock_timestamp())
 FROM pgws_control.workspaces w WHERE (w.tenant_id,w.project_id,w.id,w.current_generation)=(c.tenant_id,c.project_id,c.workspace_id,c.generation)
 AND w.phase<>'deleted' AND c.host_revoked_at IS NULL AND c.expires_at>clock_timestamp()
 AND EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$1::uuid)
 AND (c.revoked_at IS NOT NULL OR NOT EXISTS(SELECT FROM pgws_control.api_tokens t WHERE (t.tenant_id,t.project_id,t.principal_id::text)=(c.tenant_id,c.project_id,c.principal_reference) AND t.allow_raw AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()))
 RETURNING c.tenant_id::text,c.project_id::text,c.workspace_id::text,c.generation,w.desired_revision,w.fencing_token,c.id::text,c.role_name`, w.Epoch)
	if err != nil {
		return err
	}
	type batch struct {
		task        Task
		credentials []CredentialRevocation
	}
	batches := map[lease.Identity]*batch{}
	for rows.Next() {
		t := Task{Kind: "revoke_credentials"}
		t.Command.Epoch, t.Command.Host = w.Epoch, w.HostID
		var request CredentialRevocation
		if err = rows.Scan(&t.Command.Tenant, &t.Command.Project, &t.Command.Workspace, &t.Command.Generation, &t.Command.Revision, &t.Command.Token, &request.ID, &request.Username); err != nil {
			rows.Close()
			return err
		}
		b := batches[t.Command.Identity]
		if b == nil {
			b = &batch{task: t}
			batches[t.Command.Identity] = b
		}
		b.credentials = append(b.credentials, request)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var group errgroup.Group
	group.SetLimit(8)
	for _, b := range batches {
		t := b.task
		t.Document, _ = json.Marshal(b.credentials)
		group.Go(func() error {
			check, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if err := revoker.RevokeCredentials(check, t); err != nil {
				return err
			}
			var ids, users []string
			for _, credential := range b.credentials {
				ids = append(ids, credential.ID)
				users = append(users, credential.Username)
			}
			_, err := w.Pool.Exec(check, `UPDATE pgws_control.credentials c SET host_revoked_at=clock_timestamp()
 FROM unnest($5::uuid[],$6::text[]) AS delivered(id,username)
 WHERE c.tenant_id=$1 AND c.project_id=$2 AND c.workspace_id=$3 AND c.generation=$4 AND c.id=delivered.id AND c.role_name=delivered.username AND c.revoked_at IS NOT NULL AND c.host_revoked_at IS NULL
 AND EXISTS(SELECT FROM pgws_control.authority WHERE singleton AND reconciled AND epoch=$7::uuid)`, t.Command.Tenant, t.Command.Project, t.Command.Workspace, t.Command.Generation, ids, users, w.Epoch)
			return err
		})
	}
	return group.Wait()
}
