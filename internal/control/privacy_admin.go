package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/privacy"
)

// PolicyDraft contains reviewed schema and rules, never sampled source values.
// A trusted operator supplies a random transform key separately for compilation;
// neither the key nor its path enters the management database.
type PolicyDraft struct {
	Tenant      string         `json:"tenant_id"`
	Project     string         `json:"project_id"`
	ID          string         `json:"policy_id"`
	Revision    int            `json:"revision"`
	Source      string         `json:"source_id"`
	SourceEpoch int64          `json:"source_epoch"`
	SystemID    string         `json:"system_id"`
	Timeline    int64          `json:"timeline"`
	Schema      privacy.Schema `json:"schema"`
	Policy      privacy.Policy `json:"policy"`
}

type PolicyRecord struct {
	ID            string     `json:"id"`
	Hash          string     `json:"plan_hash"`
	SchemaHash    string     `json:"schema_hash"`
	State         string     `json:"state"`
	ApprovalEpoch *string    `json:"approval_epoch,omitempty"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

func GetPrivacyPolicy(ctx context.Context, pool *pgxpool.Pool, tenant, project, id string) (PolicyRecord, error) {
	if !ValidID(tenant) || !ValidID(project) || !ValidID(id) {
		return PolicyRecord{}, errors.New("explicit policy scope required")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return PolicyRecord{}, err
	}
	defer tx.Rollback(ctx)
	return readPolicy(ctx, tx, tenant, project, id)
}

func lockPolicySource(ctx context.Context, tx pgx.Tx, d PolicyDraft) error {
	var valid bool
	var endpoint, secret string
	err := tx.QueryRow(ctx, `SELECT source_epoch=$4 AND system_identifier=$5 AND timeline=$6 AND status NOT IN ('disabled','blocked')
 AND EXISTS(SELECT FROM pgws_control.approved_source_references r WHERE (r.tenant_id,r.project_id,r.endpoint_reference,r.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference))
 ,endpoint_reference,secret_reference FROM pgws_control.sources s WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR SHARE`, d.Tenant, d.Project, d.Source, d.SourceEpoch, d.SystemID, d.Timeline).Scan(&valid, &endpoint, &secret)
	if err != nil || !valid {
		return errors.New("policy source lineage or approval differs")
	}
	if err = tx.QueryRow(ctx, `SELECT pgws_control.lock_source_reference($1,$2,$3,$4)`, d.Tenant, d.Project, endpoint, secret).Scan(&valid); err != nil || !valid {
		return errors.New("policy source reference was revoked")
	}
	return nil
}

func readPolicy(ctx context.Context, tx pgx.Tx, tenant, project, id string) (PolicyRecord, error) {
	var record PolicyRecord
	err := tx.QueryRow(ctx, `SELECT p.id::text,p.policy_hash,b.schema_hash,p.state,b.approval_epoch::text,p.approved_at,p.revoked_at
 FROM pgws_control.privacy_policies p JOIN pgws_control.privacy_policy_bindings b ON (b.tenant_id,b.project_id,b.policy_id)=(p.tenant_id,p.project_id,p.id)
 WHERE p.tenant_id=$1 AND p.project_id=$2 AND p.id=$3`, tenant, project, id).Scan(&record.ID, &record.Hash, &record.SchemaHash, &record.State, &record.ApprovalEpoch, &record.ApprovedAt, &record.RevokedAt)
	if err != nil {
		return record, errors.New("bound policy not found in requested scope")
	}
	return record, nil
}

func policyAudit(ctx context.Context, tx pgx.Tx, tenant, project, id, action, hash string) error {
	metadata, _ := json.Marshal(Object{"plan_hash": hash})
	_, err := tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,safe_metadata)
 VALUES($1,$2,$3,'operator:'||current_user::text,$4,$5,'succeeded',$6)`, ID(), tenant, project, action, id, metadata)
	if err != nil {
		return errors.New("policy audit failed")
	}
	return nil
}

func CreatePrivacyPolicy(ctx context.Context, pool *pgxpool.Pool, epoch string, d PolicyDraft, key []byte) (PolicyRecord, error) {
	var empty PolicyRecord
	if !ValidID(d.Tenant) || !ValidID(d.Project) || !ValidID(d.ID) || !ValidID(d.Source) || d.Revision < 1 || d.SourceEpoch < 1 || d.Timeline < 1 {
		return empty, errors.New("explicit policy and source scope required")
	}
	plan, err := privacy.Compile(d.Schema, d.Policy, key)
	if err != nil {
		return empty, err
	}
	d.Schema = plan.Schema()
	d.Policy.Rules = slices.Clone(d.Policy.Rules)
	slices.SortFunc(d.Policy.Rules, func(a, b privacy.Rule) int {
		if a.Table < b.Table {
			return -1
		}
		if a.Table > b.Table {
			return 1
		}
		return int(a.Column) - int(b.Column)
	})
	document, _ := json.Marshal(struct {
		Schema privacy.Schema `json:"schema"`
		Policy privacy.Policy `json:"policy"`
		Review string         `json:"review"`
	}{d.Schema, d.Policy, "manual"})
	if len(document) > 1<<20 {
		return empty, errors.New("policy document exceeds management budget")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback(ctx)
	if err = tokenAuthority(ctx, tx, epoch, true); err != nil {
		return empty, err
	}
	if err = lockPolicySource(ctx, tx, d); err != nil {
		return empty, err
	}
	insert, err := tx.Exec(ctx, `INSERT INTO pgws_control.privacy_policies(tenant_id,project_id,id,version,policy_hash,policy_document,state)
 VALUES($1,$2,$3,$4,$5,$6,'draft') ON CONFLICT DO NOTHING`, d.Tenant, d.Project, d.ID, d.Revision, plan.Hash(), document)
	if err != nil {
		return empty, errors.New("policy creation requires operator privileges")
	}
	var same bool
	if err = tx.QueryRow(ctx, `SELECT version=$4 AND policy_hash=$5 AND policy_document=$6::jsonb FROM pgws_control.privacy_policies WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, d.Tenant, d.Project, d.ID, d.Revision, plan.Hash(), document).Scan(&same); err != nil || !same {
		return empty, errors.New("policy identity already binds different content")
	}
	keyHash := fmt.Sprintf("%x", sha256.Sum256(key))
	_, err = tx.Exec(ctx, `INSERT INTO pgws_control.privacy_policy_bindings(tenant_id,project_id,policy_id,source_id,source_epoch,system_identifier,timeline,schema_hash,key_fingerprint,compiler_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pgws-transform-v1') ON CONFLICT DO NOTHING`, d.Tenant, d.Project, d.ID, d.Source, d.SourceEpoch, d.SystemID, d.Timeline, plan.SchemaHash(), keyHash)
	if err != nil {
		return empty, errors.New("policy source binding failed")
	}
	if err = tx.QueryRow(ctx, `SELECT source_id=$4 AND source_epoch=$5 AND system_identifier=$6 AND timeline=$7 AND schema_hash=$8 AND key_fingerprint=$9
 FROM pgws_control.privacy_policy_bindings WHERE tenant_id=$1 AND project_id=$2 AND policy_id=$3`, d.Tenant, d.Project, d.ID, d.Source, d.SourceEpoch, d.SystemID, d.Timeline, plan.SchemaHash(), keyHash).Scan(&same); err != nil || !same {
		return empty, errors.New("policy source binding already differs")
	}
	if insert.RowsAffected() > 0 {
		if err = policyAudit(ctx, tx, d.Tenant, d.Project, d.ID, "privacy.create", plan.Hash()); err != nil {
			return empty, err
		}
	}
	record, err := readPolicy(ctx, tx, d.Tenant, d.Project, d.ID)
	if err != nil {
		return empty, err
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, errors.New("policy commit unconfirmed; retry the same policy identity")
	}
	return record, nil
}

// ApprovePrivacyPolicy is an explicit operator review of the exact compiled
// plan and schema. It grants no public endpoint and performs no source I/O.
func ApprovePrivacyPolicy(ctx context.Context, pool *pgxpool.Pool, epoch, tenant, project, id, planHash, schemaHash string) (PolicyRecord, error) {
	return changePrivacyPolicy(ctx, pool, epoch, tenant, project, id, planHash, schemaHash, false)
}

func RevokePrivacyPolicy(ctx context.Context, pool *pgxpool.Pool, epoch, tenant, project, id, planHash string) (PolicyRecord, error) {
	return changePrivacyPolicy(ctx, pool, epoch, tenant, project, id, planHash, "", true)
}

func changePrivacyPolicy(ctx context.Context, pool *pgxpool.Pool, epoch, tenant, project, id, planHash, schemaHash string, revoke bool) (PolicyRecord, error) {
	var empty PolicyRecord
	if !ValidID(tenant) || !ValidID(project) || !ValidID(id) || len(planHash) != 64 {
		return empty, errors.New("explicit policy scope and expected hash required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback(ctx)
	if err = tokenAuthority(ctx, tx, epoch, !revoke); err != nil {
		return empty, err
	}
	d := PolicyDraft{Tenant: tenant, Project: project, ID: id}
	var state, storedHash, storedSchema string
	err = tx.QueryRow(ctx, `SELECT p.state,p.policy_hash,b.schema_hash,b.source_id::text,b.source_epoch,b.system_identifier,b.timeline
 FROM pgws_control.privacy_policies p JOIN pgws_control.privacy_policy_bindings b ON (b.tenant_id,b.project_id,b.policy_id)=(p.tenant_id,p.project_id,p.id)
 WHERE p.tenant_id=$1 AND p.project_id=$2 AND p.id=$3 FOR UPDATE OF p,b`, tenant, project, id).Scan(&state, &storedHash, &storedSchema, &d.Source, &d.SourceEpoch, &d.SystemID, &d.Timeline)
	if err != nil || storedHash != planHash || !revoke && storedSchema != schemaHash {
		return empty, errors.New("reviewed policy identity or hash differs")
	}
	if !revoke {
		if state == "revoked" {
			return empty, errors.New("revoked policy requires a new version")
		}
		if err = lockPolicySource(ctx, tx, d); err != nil {
			return empty, err
		}
		var already bool
		if err = tx.QueryRow(ctx, `SELECT coalesce(approval_epoch=$4::uuid,false) FROM pgws_control.privacy_policy_bindings WHERE tenant_id=$1 AND project_id=$2 AND policy_id=$3`, tenant, project, id, epoch).Scan(&already); err != nil {
			return empty, err
		}
		if !already || state != "approved" {
			if _, err = tx.Exec(ctx, `UPDATE pgws_control.privacy_policy_bindings SET approval_epoch=$4,approved_by='operator:'||current_user::text WHERE tenant_id=$1 AND project_id=$2 AND policy_id=$3`, tenant, project, id, epoch); err != nil {
				return empty, errors.New("policy approval requires operator privileges")
			}
			if _, err = tx.Exec(ctx, `UPDATE pgws_control.privacy_policies SET state='approved',approved_at=clock_timestamp() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, tenant, project, id); err != nil {
				return empty, errors.New("policy approval failed")
			}
			if err = policyAudit(ctx, tx, tenant, project, id, "privacy.approve", planHash); err != nil {
				return empty, err
			}
		}
	} else if state != "revoked" {
		if _, err = tx.Exec(ctx, `UPDATE pgws_control.privacy_policies SET state='revoked',revoked_at=clock_timestamp() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, tenant, project, id); err != nil {
			return empty, errors.New("policy revocation requires operator privileges")
		}
		if _, err = tx.Exec(ctx, `UPDATE pgws_control.baselines SET state='blocked' WHERE tenant_id=$1 AND project_id=$2 AND privacy_policy_id=$3 AND state IN ('seeding','catching_up','ready')`, tenant, project, id); err != nil {
			return empty, err
		}
		if _, err = tx.Exec(ctx, `UPDATE pgws_control.credentials c SET revoked_at=coalesce(c.revoked_at,clock_timestamp())
 FROM pgws_control.workspace_generations g JOIN pgws_control.snapshots s ON (s.tenant_id,s.project_id,s.id)=(g.tenant_id,g.project_id,g.snapshot_id)
 JOIN pgws_control.baselines b ON (b.tenant_id,b.project_id,b.id)=(s.tenant_id,s.project_id,s.baseline_id)
 WHERE (c.tenant_id,c.project_id,c.workspace_id,c.generation)=(g.tenant_id,g.project_id,g.workspace_id,g.generation)
 AND b.tenant_id=$1 AND b.project_id=$2 AND b.privacy_policy_id=$3`, tenant, project, id); err != nil {
			return empty, err
		}
		if err = policyAudit(ctx, tx, tenant, project, id, "privacy.revoke", planHash); err != nil {
			return empty, err
		}
	}
	record, err := readPolicy(ctx, tx, tenant, project, id)
	if err != nil {
		return empty, err
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, errors.New("policy decision commit unconfirmed; repeat the same request")
	}
	return record, nil
}
