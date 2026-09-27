package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/lease"
)

type recoveryFixture struct {
	report RecoveryReport
	check  func()
}

func (h recoveryFixture) RecoveryReport(_ context.Context, _ Task) (RecoveryReport, error) {
	if h.check != nil {
		h.check()
	}
	return h.report, nil
}

func testAuthorityRecovery(t *testing.T, ctx context.Context, pool, workerPool *pgxpool.Pool, epoch, tenant, project string) {
	oldKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey)
	plan := RecoveryPlan{Epoch: ID(), Previous: epoch, PublicKey: newKey, PreviousKey: oldKey, Hosts: []string{"test-host"}, Operator: "recovery-test-operator", CreatedAt: time.Now().UTC()}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	workspace := ID()
	exec(`INSERT INTO pgws_control.workspaces(tenant_id,project_id,id,task_id,desired_state,phase,resource_profile,expires_at) VALUES($1,$2,$3,'restore-test','running','paused','small',now()+interval '1 hour')`, tenant, project, workspace)
	_, token, err := CreateAPIToken(ctx, pool, epoch, TokenGrant{Tenant: tenant, Project: project, Admin: true, Raw: true}, time.Hour, "")
	if err != nil || token == "" {
		t.Fatal(err)
	}
	if err = BeginRecovery(ctx, workerPool, plan); err == nil {
		t.Fatal("worker started authority recovery")
	}
	if err = BeginRecovery(ctx, pool, plan); err != nil {
		t.Fatal(err)
	}
	if err = BeginRecovery(ctx, pool, plan); err != nil {
		t.Fatal("idempotent begin", err)
	}
	changed := plan
	changed.Operator = "another-operator"
	if err = BeginRecovery(ctx, pool, changed); err == nil {
		t.Fatal("different recovery plan adopted")
	}
	for _, e := range []string{epoch, plan.Epoch} {
		if _, _, err = CreateAPIToken(ctx, pool, e, TokenGrant{Tenant: tenant, Project: project}, time.Hour, ""); err == nil {
			t.Fatal("issued token before host reconciliation")
		}
		if _, err = (&Worker{Pool: workerPool, Epoch: e, ID: "recovery-worker"}).Claim(ctx); err == nil {
			t.Fatal("worker ran before host reconciliation")
		}
	}
	var count int
	for _, q := range []string{`SELECT count(*) FROM pgws_control.api_tokens WHERE revoked_at IS NULL`, `SELECT count(*) FROM pgws_control.credentials WHERE revoked_at IS NULL`, `SELECT count(*) FROM pgws_control.privacy_policies WHERE state<>'revoked'`, `SELECT count(*) FROM pgws_control.approved_source_references`, `SELECT count(*) FROM pgws_control.operations WHERE status IN ('queued','running')`} {
		if err = pool.QueryRow(ctx, q).Scan(&count); err != nil || count != 0 {
			t.Fatal("restored authority remained active", q, count, err)
		}
	}
	if _, err = pool.Exec(ctx, `UPDATE pgws_control.workspaces SET desired_state='running',phase='ready' WHERE id=$1`, workspace); err == nil {
		t.Fatal("quarantined workspace revived")
	}
	cmd := lease.Command{Identity: lease.Identity{Epoch: epoch, Host: "test-host", Tenant: tenant, Project: project, Workspace: workspace, Generation: 4, Revision: 65}, Token: 321, Operation: ID(), Kind: "reset"}
	report := RecoveryReport{Host: "test-host", Epoch: plan.Epoch, PlanHash: plan.Hash(), PublicKey: plan.PublicKey, Commands: []lease.Command{cmd}}
	fixture := recoveryFixture{report: report, check: func() {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `LOCK TABLE pgws_control.authority IN ACCESS EXCLUSIVE MODE NOWAIT`); e != nil {
			t.Fatal("host I/O overlapped authority transaction", e)
		}
	}}
	if err = FinishRecovery(ctx, pool, plan, nil); err == nil {
		t.Fatal("offline cell was silently excluded")
	}
	bad := fixture
	bad.report.Epoch = ID()
	if err = FinishRecovery(ctx, pool, plan, map[string]RecoveryHost{"test-host": bad}); err == nil {
		t.Fatal("foreign acknowledgement accepted")
	}
	if err = FinishRecovery(ctx, pool, plan, map[string]RecoveryHost{"test-host": fixture}); err != nil {
		t.Fatal(err)
	}
	if err = FinishRecovery(ctx, pool, plan, map[string]RecoveryHost{"test-host": fixture}); err != nil {
		t.Fatal("idempotent completion", err)
	}
	var fence, revision int64
	if err = pool.QueryRow(ctx, `SELECT fencing_token,desired_revision FROM pgws_control.workspaces WHERE id=$1`, workspace).Scan(&fence, &revision); err != nil || fence <= cmd.Token || revision <= cmd.Revision {
		t.Fatal("host high-water mark was not reconstructed", fence, revision, err)
	}
	if err = CheckAuthorityKey(ctx, pool, plan.Epoch, oldKey); err == nil {
		t.Fatal("old signing key accepted after recovery")
	}
	if err = CheckAuthorityKey(ctx, pool, plan.Epoch, newKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err = CreateAPIToken(ctx, pool, plan.Epoch, TokenGrant{Tenant: tenant, Project: project}, time.Hour, ""); err != nil {
		t.Fatal("explicit new grant rejected", err)
	}
	if _, _, err = CreateAPIToken(ctx, pool, epoch, TokenGrant{Tenant: tenant, Project: project}, time.Hour, ""); err == nil {
		t.Fatal("old authority grant revived")
	}
	// A delayed job inserted after recovery still carries the old epoch. It
	// must be cancelled before the backend sees a create for an unseen source.
	source := ID()
	exec(`INSERT INTO pgws_control.sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status) VALUES($1,$2,$3,'physical','restore-test','restore-test','registered')`, tenant, project, source)
	doc, _ := json.Marshal(sourceJob{SourceID: source})
	op := ID()
	exec(`INSERT INTO pgws_control.operations(tenant_id,project_id,id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,authority_epoch) VALUES($1,$2,$3,'register_source',1,1,'delayed-restore','delayed-restore',repeat('a',64),'queued',$4,$5)`, tenant, project, op, doc, epoch)
	if job, e := (&Worker{Pool: workerPool, Epoch: plan.Epoch, ID: "new-worker"}).Claim(ctx); e != nil || job != nil {
		t.Fatal("delayed old create escaped", job, e)
	}
	var status string
	if err = pool.QueryRow(ctx, `SELECT status FROM pgws_control.operations WHERE id=$1`, op).Scan(&status); err != nil || status != "cancelled" {
		t.Fatal(status, err)
	}
	// A backup may predate a previous recovery. Keep its expected epoch
	// separate from the current external host authority.
	ancient := ID()
	exec(`UPDATE pgws_control.authority SET epoch=$1,signing_public_key=$2`, ancient, oldKey)
	third := RecoveryPlan{Epoch: ID(), Previous: plan.Epoch, Restored: ancient, PublicKey: bytes.Repeat([]byte{3}, 32), PreviousKey: newKey, Hosts: plan.Hosts, Operator: "historical-restore", CreatedAt: time.Now().UTC()}
	if err = BeginRecovery(ctx, pool, third); err != nil {
		t.Fatal("older backup epoch confused with current host epoch", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE pgws_runtime`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SELECT * FROM pgws_control.authority_recovery_hosts`); err == nil {
		t.Fatal("runtime read operator recovery inventory")
	}
}

func TestRecoveryPlanRejectsReusedOrAmbiguousAuthority(t *testing.T) {
	p := RecoveryPlan{Epoch: ID(), Previous: ID(), PublicKey: bytes.Repeat([]byte{1}, 32), PreviousKey: bytes.Repeat([]byte{2}, 32), Hosts: []string{"host"}, Operator: "operator", CreatedAt: time.Now()}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RecoveryPlan){func(p *RecoveryPlan) { p.Epoch = p.Previous }, func(p *RecoveryPlan) { p.PublicKey = p.PreviousKey }, func(p *RecoveryPlan) { p.Hosts = []string{"b", "a"} }, func(p *RecoveryPlan) { p.Hosts = []string{"a", "a"} }, func(p *RecoveryPlan) { p.Hosts = nil }} {
		c := p
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatal(errors.New("unsafe recovery plan accepted"))
		}
	}
}
