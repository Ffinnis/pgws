package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/lease"
)

// CheckAuthorityKey pins configuration to a recovered authority. Pre-recovery
// installations with no recorded public key retain their existing behavior.
func CheckAuthorityKey(ctx context.Context, pool *pgxpool.Pool, epoch string, key []byte) error {
	var valid bool
	if err := pool.QueryRow(ctx, `SELECT epoch=$1::uuid AND (signing_public_key IS NULL OR signing_public_key=$2) FROM pgws_control.authority WHERE singleton`, epoch, key).Scan(&valid); err != nil || !valid {
		return errors.New("configured signing authority differs from management recovery")
	}
	return nil
}

// RecoveryPlan is generated outside the restored database. It contains public
// keys only. Every host and management step binds the exact same plan hash.
type RecoveryPlan struct {
	Epoch       string    `json:"epoch"`
	Previous    string    `json:"previous_epoch"`
	Restored    string    `json:"restored_epoch,omitempty"`
	PublicKey   []byte    `json:"public_key"`
	PreviousKey []byte    `json:"previous_public_key"`
	Hosts       []string  `json:"hosts"`
	Operator    string    `json:"operator"`
	CreatedAt   time.Time `json:"created_at"`
}

func (p RecoveryPlan) Validate() error {
	if !ValidID(p.Epoch) || !ValidID(p.Previous) || p.Epoch == p.Previous || p.Restored != "" && (!ValidID(p.Restored) || p.Restored == p.Epoch) || len(p.PublicKey) != ed25519.PublicKeySize || len(p.PreviousKey) != ed25519.PublicKeySize || bytes.Equal(p.PublicKey, p.PreviousKey) || len(p.Hosts) < 1 || len(p.Hosts) > 32 || p.Operator == "" || len(p.Operator) > 200 || p.CreatedAt.IsZero() {
		return errors.New("invalid external authority recovery plan")
	}
	for i, host := range p.Hosts {
		if host == "" || len(host) > 200 || strings.ContainsAny(host, "\r\n\x00") || i > 0 && p.Hosts[i-1] >= host {
			return errors.New("recovery hosts must be unique and sorted")
		}
	}
	return nil
}

func (p RecoveryPlan) Hash() string {
	b, _ := json.Marshal(p)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

type RecoveryGeneration struct {
	Identity   lease.Identity `json:"identity"`
	Source     bool           `json:"source"`
	Deleted    bool           `json:"deleted"`
	VolumeName string         `json:"volume_name,omitempty"`
	VolumeGUID string         `json:"volume_guid,omitempty"`
}

type RecoveryReport struct {
	Host        string               `json:"host"`
	Epoch       string               `json:"epoch"`
	PlanHash    string               `json:"plan_hash"`
	PublicKey   []byte               `json:"public_key"`
	Commands    []lease.Command      `json:"commands"`
	Storage     []lease.Command      `json:"storage_commands"`
	Generations []RecoveryGeneration `json:"generations"`
}

// BeginRecovery closes all restored authorizations in one durable transaction.
// Host I/O is deliberately a separate operator step. Old data stays private;
// reopening it is not part of this cold recovery procedure.
func BeginRecovery(ctx context.Context, pool *pgxpool.Pool, plan RecoveryPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return err
	}
	var epoch string
	var key []byte
	if err = tx.QueryRow(ctx, `SELECT epoch::text,signing_public_key FROM pgws_control.authority WHERE singleton FOR UPDATE`).Scan(&epoch, &key); err != nil {
		return err
	}
	if epoch == plan.Epoch {
		var hash string
		if err = tx.QueryRow(ctx, `SELECT plan_hash FROM pgws_control.authority_recoveries WHERE epoch=$1`, plan.Epoch).Scan(&hash); err != nil || hash != plan.Hash() {
			return errors.New("recovery retry differs from the sealed plan")
		}
		return tx.Commit(ctx)
	}
	restoredEpoch := plan.Restored
	if restoredEpoch == "" {
		restoredEpoch = plan.Previous
	}
	if epoch != restoredEpoch || epoch == plan.Previous && len(key) != 0 && !bytes.Equal(key, plan.PreviousKey) {
		return errors.New("previous recovery authority differs")
	}
	document, _ := json.Marshal(plan)
	if _, err = tx.Exec(ctx, `INSERT INTO pgws_control.authority_recoveries(epoch,previous_epoch,plan_hash,plan) VALUES($1,$2,$3,$4)`, plan.Epoch, plan.Previous, plan.Hash(), document); err != nil {
		return err
	}
	queries := []string{
		`UPDATE pgws_control.authority SET epoch=$1,reconciled=false,signing_public_key=$2 WHERE singleton`,
		`UPDATE pgws_control.api_tokens SET revoked_at=coalesce(revoked_at,clock_timestamp())`,
		`UPDATE pgws_control.credentials SET revoked_at=coalesce(revoked_at,clock_timestamp())`,
		`UPDATE pgws_control.privacy_policies SET state='revoked',revoked_at=clock_timestamp() WHERE state<>'revoked'`,
		`DELETE FROM pgws_control.approved_source_references`,
		`UPDATE pgws_control.operations SET status='cancelled',lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp(),safe_error='{"code":"AUTHORITY_RECOVERED","message":"Old authority was quarantined by the operator","retryable":false}' WHERE status IN ('queued','running')`,
		`UPDATE pgws_control.sources SET status='disabled'`,
		`UPDATE pgws_control.baselines SET state='blocked' WHERE state<>'retired'`,
		`UPDATE pgws_control.snapshots SET state='failed' WHERE state<>'deleted'`,
		`UPDATE pgws_control.workspaces SET desired_state='deleted',phase='recovery_blocked',updated_at=clock_timestamp() WHERE phase<>'deleted'`,
		`UPDATE pgws_control.workspace_generations SET phase='recovery_blocked' WHERE phase<>'deleted'`,
	}
	for i, query := range queries {
		var args []any
		if i == 0 {
			args = []any{plan.Epoch, plan.PublicKey}
		}
		if _, err = tx.Exec(ctx, query, args...); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,safe_metadata)
 SELECT gen_random_uuid(),tenant_id,id,$1,'authority.recovery.begin',$2,'closed',$3::jsonb FROM pgws_control.projects`, plan.Operator, plan.Epoch, Object{"previous_epoch": plan.Previous, "restored_epoch": restoredEpoch, "plan_hash": plan.Hash()}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type RecoveryHost interface {
	RecoveryReport(context.Context, Task) (RecoveryReport, error)
}

// FinishRecovery reads every authenticated host before opening a management
// transaction. It never trusts a restored database's old host acknowledgements.
func FinishRecovery(ctx context.Context, pool *pgxpool.Pool, plan RecoveryPlan, hosts map[string]RecoveryHost) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if len(hosts) != len(plan.Hosts) {
		return errors.New("every external recovery host must acknowledge")
	}
	reports := make([]RecoveryReport, 0, len(hosts))
	for _, name := range plan.Hosts {
		host := hosts[name]
		if host == nil {
			return errors.New("recovery host unavailable")
		}
		report, err := host.RecoveryReport(ctx, Task{Kind: "recovery_report", Command: lease.Command{Identity: lease.Identity{Epoch: plan.Epoch, Host: name}}, Document: json.RawMessage(fmt.Sprintf(`{"plan_hash":%q}`, plan.Hash()))})
		if err != nil {
			return err
		}
		if err = validateRecoveryReport(plan, name, report); err != nil {
			return err
		}
		reports = append(reports, report)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return err
	}
	var current bool
	if err = tx.QueryRow(ctx, `SELECT epoch=$1::uuid AND signing_public_key=$2 FROM pgws_control.authority WHERE singleton FOR UPDATE`, plan.Epoch, plan.PublicKey).Scan(&current); err != nil || !current {
		return errors.New("recovery authority differs")
	}
	var hash string
	var completed *time.Time
	if err = tx.QueryRow(ctx, `SELECT plan_hash,completed_at FROM pgws_control.authority_recoveries WHERE epoch=$1 FOR UPDATE`, plan.Epoch).Scan(&hash, &completed); err != nil || hash != plan.Hash() {
		return errors.New("recovery plan was not sealed")
	}
	if completed != nil {
		return tx.Commit(ctx)
	}
	var unknown bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pgws_control.workspace_generations WHERE cell_reference IS NOT NULL AND NOT(cell_reference=ANY($1::text[])))`, plan.Hosts).Scan(&unknown); err != nil || unknown {
		return errors.New("restored generation belongs to an unacknowledged host")
	}
	for _, report := range reports {
		for _, generation := range report.Generations {
			id := generation.Identity
			if !generation.Source && !generation.Deleted {
				var differs bool
				if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pgws_control.workspace_generations WHERE tenant_id=$1 AND project_id=$2 AND workspace_id=$3 AND generation=$4 AND volume_guid IS NOT NULL AND (volume_guid IS DISTINCT FROM $5 OR volume_name IS DISTINCT FROM $6))`, id.Tenant, id.Project, id.Workspace, id.Generation, generation.VolumeGUID, generation.VolumeName).Scan(&differs); err != nil || differs {
					return errors.New("restored volume differs from the host GUID")
				}
			}
		}
		for _, group := range [][]lease.Command{report.Commands, report.Storage} {
			for _, cmd := range group {
				// Storage steps use token*100+step. Taking the complete value is
				// conservative and also fences unknown future step layouts.
				if _, err = tx.Exec(ctx, `UPDATE pgws_control.workspaces SET fencing_token=greatest(fencing_token,$4)+1,desired_revision=greatest(desired_revision,$5)+1 WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, cmd.Tenant, cmd.Project, cmd.Workspace, cmd.Token, cmd.Revision); err != nil {
					return err
				}
				if _, err = tx.Exec(ctx, `UPDATE pgws_control.sources SET host_fencing_token=greatest(host_fencing_token,$4)+1 WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, cmd.Tenant, cmd.Project, cmd.Workspace, cmd.Token); err != nil {
					return err
				}
			}
		}
		data, _ := json.Marshal(report)
		if _, err = tx.Exec(ctx, `INSERT INTO pgws_control.authority_recovery_hosts(epoch,host_id,report) VALUES($1,$2,$3)`, plan.Epoch, report.Host, data); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE pgws_control.authority_recoveries SET completed_at=clock_timestamp() WHERE epoch=$1;`, plan.Epoch); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE pgws_control.authority SET reconciled=true WHERE singleton`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO pgws_control.audit_events(id,tenant_id,project_id,actor_reference,action,target_reference,outcome,safe_metadata) SELECT gen_random_uuid(),tenant_id,id,$1,'authority.recovery.complete',$2,'new_admission_only',$3::jsonb FROM pgws_control.projects`, plan.Operator, plan.Epoch, Object{"plan_hash": plan.Hash(), "hosts": plan.Hosts}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validateRecoveryReport(plan RecoveryPlan, host string, r RecoveryReport) error {
	if r.Host != host || r.Epoch != plan.Epoch || r.PlanHash != plan.Hash() || !bytes.Equal(r.PublicKey, plan.PublicKey) || len(r.Generations) > 10000 || len(r.Commands) > 10000 || len(r.Storage) > 10000 {
		return errors.New("host recovery acknowledgement differs")
	}
	valid := func(id lease.Identity) bool {
		return id.Host == host && ValidID(id.Epoch) && id.Epoch != plan.Epoch && ValidID(id.Tenant) && ValidID(id.Project) && ValidID(id.Workspace) && id.Generation > 0 && id.Generation < 1e9 && id.Revision > 0 && id.Revision < 1e15
	}
	for _, commands := range [][]lease.Command{r.Commands, r.Storage} {
		for _, c := range commands {
			if !valid(c.Identity) || c.Token < 1 || c.Token >= 1e15 {
				return errors.New("invalid host recovery high-water mark")
			}
		}
	}
	seen := map[string]bool{}
	for _, g := range r.Generations {
		key := fmt.Sprintf("%s/%d", g.Identity.Workspace, g.Identity.Generation)
		if !valid(g.Identity) || seen[key] || (g.VolumeName == "") != (g.VolumeGUID == "") {
			return errors.New("invalid host recovery generation")
		}
		seen[key] = true
	}
	if !slices.Contains(plan.Hosts, host) {
		return errors.New("unexpected recovery host")
	}
	return nil
}
