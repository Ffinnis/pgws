package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/secrets"
)

type pendingResponse struct {
	OperationID string `json:"_pending_operation"`
}
type CredentialRequest struct {
	Role   string    `json:"role"`
	Expiry time.Time `json:"expires_at"`
}
type CredentialOutcome struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Expiry   time.Time `json:"expires_at"`
	Sealed   string    `json:"sealed"`
}

func CredentialAAD(t Task) []byte {
	b, _ := json.Marshal([]string{t.Command.Tenant, t.Command.Project, t.Actor, t.Command.Operation})
	return b
}
func (s *Server) awaitCredential(ctx context.Context, r *http.Request, operation string) (int, any, error) {
	for {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return 0, nil, err
		}
		status, result, err := s.credentialResult(ctx, tx, r, operation)
		_ = tx.Rollback(ctx)
		if err != nil {
			return 0, nil, err
		}
		if status != 0 {
			return status, result, nil
		}
		select {
		case <-ctx.Done():
			return 0, nil, fail(503, "OPERATION_PENDING", "Operation is still pending; retry with the same idempotency key")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func (s *Server) credentialResult(ctx context.Context, tx pgx.Tx, r *http.Request, operation string) (int, any, error) {
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE pgws_runtime;SET LOCAL search_path=pgws_control,pg_catalog`); err != nil {
		return 0, nil, err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))))
	var actor, tenant string
	if err := tx.QueryRow(ctx, `SELECT principal_id::text,tenant_id::text FROM api_tokens WHERE token_hash=$1 AND project_id=$2 AND allow_raw AND revoked_at IS NULL AND expires_at>clock_timestamp()`, hash, r.PathValue("project_id")).Scan(&actor, &tenant); err != nil {
		return 0, nil, fail(401, "UNAUTHENTICATED", "Current credential authorization is required")
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('pgws.tenant_id',$1,true),set_config('pgws.project_id',$2,true)`, tenant, r.PathValue("project_id")); err != nil {
		return 0, nil, err
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT reconciled AND epoch=$1::uuid FROM authority WHERE singleton`, s.Epoch).Scan(&active); err != nil || !active {
		return 0, nil, fail(503, "AUTHORITY_RECONCILIATION_REQUIRED", "Authority changed")
	}
	var status, kind string
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT status,kind,safe_result FROM operations WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND actor_reference=$4 AND kind IN ('issue_credential','issue_barrier')`, tenant, r.PathValue("project_id"), operation, actor).Scan(&status, &kind, &raw); err != nil {
		return 0, nil, err
	}
	if status == "queued" || status == "running" {
		return 0, nil, nil
	}
	if status != "succeeded" {
		return 0, nil, fail(409, "OPERATION_FAILED", "Operation did not succeed")
	}
	if kind == "issue_barrier" {
		return s.barrierResult(ctx, tx, tenant, r.PathValue("project_id"), raw)
	}
	var sealed CredentialOutcome
	if json.Unmarshal(raw, &sealed) != nil {
		return 0, nil, errors.New("invalid credential receipt")
	}
	var current bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM credentials c JOIN workspaces w ON (w.tenant_id,w.project_id,w.id,w.current_generation)=(c.tenant_id,c.project_id,c.workspace_id,c.generation) WHERE c.tenant_id=$1 AND c.project_id=$2 AND c.id=$3 AND c.principal_reference=$4 AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() AND w.expires_at>clock_timestamp() AND w.phase='ready' AND w.desired_state='running')`, tenant, r.PathValue("project_id"), sealed.ID, actor).Scan(&current); err != nil {
		return 0, nil, err
	}
	if !current {
		return 0, nil, fail(409, "CREDENTIAL_EXPIRED", "Credential or workspace generation is no longer active")
	}
	t := Task{Actor: actor}
	t.Command.Tenant = tenant
	t.Command.Project = r.PathValue("project_id")
	t.Command.Operation = operation
	plain, err := secrets.Open(s.SecretKey, sealed.Sealed, CredentialAAD(t))
	if err != nil {
		return 0, nil, fail(503, "SECRET_UNAVAILABLE", "Credential receipt cannot be decrypted")
	}
	return 201, json.RawMessage(plain), nil
}
func (w *Worker) completeCredential(ctx context.Context, tx pgx.Tx, j *Job, t Task, out Outcome) error {
	c := out.Credential
	var request CredentialRequest
	if json.Unmarshal(j.Document, &request) != nil || c == nil || out.Phase != "ready" || !ValidID(c.ID) || c.Username == "" || c.Sealed == "" || !c.Expiry.Equal(request.Expiry) {
		return errors.New("incomplete credential receipt")
	}
	_, err := tx.Exec(ctx, `INSERT INTO pgws_control.credentials(tenant_id,project_id,id,workspace_id,generation,role_name,secret_reference,principal_reference,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, j.Tenant, j.Project, c.ID, *j.Workspace, j.Generation, c.Username, "operation:"+j.ID, t.Actor, c.Expiry)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(c)
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='succeeded',current_step='credential_issued',safe_result=$4,lease_until=NULL,completed_at=now(),updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID, raw)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operation_steps SET state='completed',finished_at=now() WHERE tenant_id=$1 AND project_id=$2 AND operation_id=$3 AND fencing_token=$4`, j.Tenant, j.Project, j.ID, j.Fence)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
