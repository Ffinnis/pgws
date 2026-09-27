package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/lease"
	"pgws/internal/migrations"
)

type observationBackend struct {
	Backend
	observe func(context.Context, Task) (StopObservation, error)
	revoke  func(context.Context, Task) (StopObservation, error)
}

func (b observationBackend) RevokeServing(ctx context.Context, task Task) (StopObservation, error) {
	return b.revoke(ctx, task)
}

type credentialRevocationBackend struct {
	Backend
	revoke func(context.Context, Task) error
}

func (b credentialRevocationBackend) RevokeCredentials(ctx context.Context, t Task) error {
	return b.revoke(ctx, t)
}

func (b observationBackend) Observe(ctx context.Context, task Task) (StopObservation, error) {
	return b.observe(ctx, task)
}

func TestHostStopTransactions(t *testing.T) {
	dsn := os.Getenv("PGWS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires the disposable management integration cluster")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	database := "stops_" + strings.ReplaceAll(ID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	tenant, project, epoch, source, baseline, snapshot, workspaceID, operation := ID(), ID(), ID(), ID(), ID(), ID(), ID(), ID()
	exec(`INSERT INTO pgws_control.tenants(id,name) VALUES($1,'stop-test')`, tenant)
	exec(`INSERT INTO pgws_control.projects(tenant_id,id,name) VALUES($1,$2,'stop-test')`, tenant, project)
	exec(`INSERT INTO pgws_control.authority(epoch,reconciled) VALUES($1,true)`, epoch)
	exec(`INSERT INTO pgws_control.sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status) VALUES($1,$2,$3,'physical','test','test','streaming')`, tenant, project, source)
	exec(`INSERT INTO pgws_control.baselines(tenant_id,project_id,id,source_id,generation,source_epoch,source_timeline,kind,runtime_digest,compatibility_manifest,state) VALUES($1,$2,$3,$4,1,1,1,'physical_standby','TEST-ONLY','{}','ready')`, tenant, project, baseline, source)
	exec(`INSERT INTO pgws_control.snapshots(tenant_id,project_id,id,baseline_id,source_epoch,source_timeline,storage_guid,state,captured_at) VALUES($1,$2,$3,$4,1,1,'TEST-ONLY','ready',now())`, tenant, project, snapshot, baseline)
	exec(`INSERT INTO pgws_control.workspaces(tenant_id,project_id,id,task_id,desired_state,phase,resource_profile,expires_at,requested_baseline_id,requested_freshness) VALUES($1,$2,$3,'test','running','ready','small',now()+interval '1 hour',$4,jsonb_build_object('mode','snapshot','snapshot_id',$5::text))`, tenant, project, workspaceID, baseline, snapshot)
	for _, generation := range []int{1, 2} {
		exec(`INSERT INTO pgws_control.workspace_generations(tenant_id,project_id,workspace_id,generation,snapshot_id,phase,runtime_digest,endpoint_metadata,readiness_evidence,ready_at) VALUES($1,$2,$3,$4,$5,'ready','TEST-ONLY','{"hostname":"test.invalid","port":5432,"database":"test"}','{}',now())`, tenant, project, workspaceID, generation, snapshot)
		exec(`INSERT INTO pgws_control.credentials(tenant_id,project_id,id,workspace_id,generation,role_name,secret_reference,principal_reference,expires_at) VALUES($1,$2,$3,$4,$5,'reader','TEST-ONLY','test',now()+interval '1 hour')`, tenant, project, ID(), workspaceID, generation)
	}
	exec(`UPDATE pgws_control.workspaces SET current_generation=1,fencing_token=1 WHERE id=$1`, workspaceID)
	exec(`INSERT INTO pgws_control.operations(tenant_id,project_id,id,workspace_id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,authority_epoch) VALUES($1,$2,$3,$4,'create',1,1,'test','create',repeat('0',64),'succeeded','{}',$5)`, tenant, project, operation, workspaceID, epoch)
	workerCfg := cfg.Copy()
	workerCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE pgws_worker")
		return err
	}
	workerPool, err := pgxpool.NewWithConfig(ctx, workerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer workerPool.Close()
	w := Worker{Pool: workerPool, Epoch: epoch, ID: "test-worker", HostID: "test-host"}
	t.Run("durable_usage_measurements", func(t *testing.T) { testUsageMeasurements(t, ctx, pool, w, tenant, project) })
	w.Backend = observationBackend{observe: func(ctx context.Context, task Task) (StopObservation, error) {
		// A read-only host observation must not run while a management snapshot
		// still holds table locks. Separate callbacks may arrive concurrently.
		if task.Kind == "observe_workspace" {
			tx, err := pool.Begin(ctx)
			if err != nil {
				return StopObservation{}, err
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, "LOCK TABLE pgws_control.workspaces IN ACCESS EXCLUSIVE MODE NOWAIT"); err != nil {
				return StopObservation{}, err
			}
		}
		return StopObservation{}, nil
	}}
	if err = w.ReconcileHost(ctx); err != nil {
		t.Fatal("host I/O overlapped a management transaction", err)
	}
	task := Task{Kind: "observe_workspace", Command: lease.Command{Identity: lease.Identity{Epoch: epoch, Host: w.HostID, Tenant: tenant, Project: project, Workspace: workspaceID, Generation: 1, Revision: 1}, Token: 1}}
	// A valid durable receipt can appear in the future after wall-clock rollback.
	observation := StopObservation{Identity: task.Command.Identity, Stopped: true, Reason: "SERVING_LEASE_EXPIRED", StoppedAt: time.Now().UTC().Add(time.Hour)}
	assertPhase := func(want string) {
		t.Helper()
		var phase string
		if e := pool.QueryRow(ctx, "SELECT phase FROM pgws_control.workspaces WHERE id=$1", workspaceID).Scan(&phase); e != nil || phase != want {
			t.Fatal("workspace phase", phase, e)
		}
	}
	other := observation
	other.Identity.Project = ID()
	if err = w.recordHostStop(ctx, task, other); err == nil {
		t.Fatal("foreign observation accepted")
	}
	exec(`UPDATE pgws_control.workspaces SET desired_revision=2 WHERE id=$1`, workspaceID)
	if err = w.recordHostStop(ctx, task, observation); err != nil {
		t.Fatal(err)
	}
	assertPhase("ready")
	task.Command.Revision = 2
	observation.Identity = task.Command.Identity
	exec(`UPDATE pgws_control.workspaces SET current_generation=2 WHERE id=$1`, workspaceID)
	if err = w.recordHostStop(ctx, task, observation); err != nil {
		t.Fatal(err)
	}
	assertPhase("ready")
	task.Command.Generation = 2
	observation.Identity = task.Command.Identity
	exec(`UPDATE pgws_control.authority SET epoch=$1`, ID())
	if err = w.recordHostStop(ctx, task, observation); err == nil {
		t.Fatal("old authority recorded a stop")
	}
	assertPhase("ready")
	exec(`UPDATE pgws_control.authority SET epoch=$1`, epoch)
	if err = w.recordHostStop(ctx, task, observation); err != nil {
		t.Fatal(err)
	}
	assertPhase("failed")
	if err = w.recordHostStop(ctx, task, observation); err != nil {
		t.Fatal(err)
	}
	var auditCount, revoked int
	var originalOutcome string
	pool.QueryRow(ctx, "SELECT count(*) FROM pgws_control.audit_events WHERE action='host.safety_stop'").Scan(&auditCount)
	pool.QueryRow(ctx, "SELECT count(*) FROM pgws_control.credentials WHERE workspace_id=$1 AND generation=2 AND revoked_at IS NOT NULL", workspaceID).Scan(&revoked)
	pool.QueryRow(ctx, "SELECT status FROM pgws_control.operations WHERE id=$1", operation).Scan(&originalOutcome)
	if auditCount != 1 || revoked != 1 || originalOutcome != "succeeded" {
		t.Fatal("stop replay, revocation or historical operation outcome differs", auditCount, revoked, originalOutcome)
	}
	request := Task{Kind: "observe_source", Command: lease.Command{Identity: lease.Identity{Epoch: epoch, Host: w.HostID, Tenant: tenant, Project: project, Workspace: source, Generation: 1}}, Snapshot: Snapshot{SourceEpoch: 1}}
	sourceStop := StopObservation{Identity: request.Command.Identity, Stopped: true, Reason: "SOURCE_LINEAGE_CHANGED", StoppedAt: time.Now().UTC(), SourceEpoch: 2}
	if err = w.recordHostStop(ctx, request, sourceStop); err == nil {
		t.Fatal("wrong source epoch accepted")
	}
	sourceStop.SourceEpoch = 1
	exec(`UPDATE pgws_control.sources SET host_fencing_token=1 WHERE id=$1`, source)
	if err = w.recordHostStop(ctx, request, sourceStop); err != nil {
		t.Fatal(err)
	}
	var status string
	pool.QueryRow(ctx, "SELECT status FROM pgws_control.sources WHERE id=$1", source).Scan(&status)
	if status != "streaming" {
		t.Fatal("stale source observation changed status")
	}
	request.Command.Token = 1
	if err = w.recordHostStop(ctx, request, sourceStop); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, "SELECT status FROM pgws_control.sources WHERE id=$1", source).Scan(&status)
	var baselineState string
	pool.QueryRow(ctx, "SELECT state FROM pgws_control.baselines WHERE id=$1", baseline).Scan(&baselineState)
	if status != "blocked" || baselineState != "blocked" {
		t.Fatal("source stop did not block fresh admission", status, baselineState)
	}
	t.Run("connected_revocation", func(t *testing.T) {
		principal := ID()
		exec(`UPDATE pgws_control.workspaces SET phase='ready' WHERE id=$1`, workspaceID)
		exec(`UPDATE pgws_control.operations SET desired_revision=2,actor_reference=$2 WHERE id=$1`, operation, principal)
		exec(`INSERT INTO pgws_control.api_tokens(token_hash,principal_id,tenant_id,project_id,allow_raw,expires_at) VALUES(repeat('a',64),$1,$2,$3,true,now()+interval '1 hour')`, principal, tenant, project)
		calls := 0
		w.Backend = observationBackend{revoke: func(ctx context.Context, task Task) (StopObservation, error) {
			calls++
			tx, e := pool.Begin(ctx)
			if e != nil {
				return StopObservation{}, e
			}
			defer tx.Rollback(ctx)
			if _, e = tx.Exec(ctx, "LOCK TABLE pgws_control.workspaces IN ACCESS EXCLUSIVE MODE NOWAIT"); e != nil {
				return StopObservation{}, e
			}
			if task.Kind != "revoke_serving" || task.Command.Generation != 2 || task.Command.Revision != 2 || task.Command.Token != 1 {
				t.Error("revocation identity differs")
			}
			return StopObservation{Identity: task.Command.Identity, Stopped: true, Reason: "AUTHORIZATION_REVOKED", StoppedAt: time.Now()}, nil
		}}
		if err = w.ReconcileRevocations(ctx); err != nil || calls != 0 {
			t.Fatal("active grant was revoked", calls, err)
		}
		assertPhase("ready")
		exec(`UPDATE pgws_control.api_tokens SET allow_raw=false WHERE principal_id=$1`, principal)
		foreignProject := ID()
		exec(`INSERT INTO pgws_control.projects(tenant_id,id,name) VALUES($1,$2,'foreign-revocation-test')`, tenant, foreignProject)
		exec(`INSERT INTO pgws_control.api_tokens(token_hash,principal_id,tenant_id,project_id,allow_raw,expires_at) VALUES(repeat('b',64),$1,$2,$3,true,now()+interval '1 hour')`, principal, tenant, foreignProject)
		pending := ID()
		exec(`INSERT INTO pgws_control.operations(tenant_id,project_id,id,workspace_id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,authority_epoch,actor_reference) VALUES($1,$2,$3,$4,'extend_ttl',2,2,'test','pending-extension',repeat('0',64),'queued','{}',$5,$6)`, tenant, project, pending, workspaceID, epoch, principal)
		if err = w.ReconcileRevocations(ctx); err != nil || calls != 0 {
			t.Fatal("revocation raced an in-flight lifecycle operation", calls, err)
		}
		exec(`UPDATE pgws_control.operations SET status='cancelled' WHERE id=$1`, pending)
		if err = w.ReconcileRevocations(ctx); err != nil || calls != 1 {
			t.Fatal("connected revocation", calls, err)
		}
		assertPhase("failed")
		if err = w.ReconcileRevocations(ctx); err != nil || calls != 1 {
			t.Fatal("revocation replay", calls, err)
		}
	})
	t.Run("credential_revocation_delivery", func(t *testing.T) {
		exec(`UPDATE pgws_control.credentials SET host_revoked_at=now() WHERE revoked_at IS NOT NULL`)
		exec(`UPDATE pgws_control.workspaces SET phase='ready' WHERE id=$1`, workspaceID)
		principal, credential := ID(), ID()
		username := "pgws_" + strings.ReplaceAll(credential, "-", "")
		second := ID()
		secondUsername := "pgws_" + strings.ReplaceAll(second, "-", "")
		exec(`INSERT INTO pgws_control.api_tokens(token_hash,principal_id,tenant_id,project_id,allow_raw,expires_at) VALUES(repeat('c',64),$1,$2,$3,true,now()+interval '1 hour')`, principal, tenant, project)
		exec(`INSERT INTO pgws_control.credentials(tenant_id,project_id,id,workspace_id,generation,role_name,secret_reference,principal_reference,expires_at) VALUES($1,$2,$3,$4,2,$5,'TEST-ONLY',$6,now()+interval '1 hour')`, tenant, project, credential, workspaceID, username, principal)
		exec(`INSERT INTO pgws_control.credentials(tenant_id,project_id,id,workspace_id,generation,role_name,secret_reference,principal_reference,expires_at) VALUES($1,$2,$3,$4,2,$5,'TEST-ONLY',$6,now()+interval '1 hour')`, tenant, project, second, workspaceID, secondUsername, principal)
		calls := 0
		lost := true
		w.Backend = credentialRevocationBackend{revoke: func(ctx context.Context, task Task) error {
			calls++
			var request []CredentialRevocation
			if json.Unmarshal(task.Document, &request) != nil || len(request) != 2 || task.Command.Project != project || task.Command.Generation != 2 {
				return errors.New("credential revocation identity differs")
			}
			seen := map[string]string{}
			for _, entry := range request {
				seen[entry.ID] = entry.Username
			}
			if seen[credential] != username || seen[second] != secondUsername {
				return errors.New("credential batch membership differs")
			}
			tx, e := pool.Begin(ctx)
			if e != nil {
				return e
			}
			defer tx.Rollback(ctx)
			if _, e = tx.Exec(ctx, "LOCK TABLE pgws_control.credentials IN ACCESS EXCLUSIVE MODE NOWAIT"); e != nil {
				return e
			}
			var revoked bool
			if e = tx.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM pgws_control.credentials WHERE id=$1", credential).Scan(&revoked); e != nil || !revoked {
				return errors.New("revocation was not committed before host I/O")
			}
			if lost {
				return ErrHostUnavailable
			}
			return nil
		}}
		if err = w.ReconcileCredentialRevocations(ctx); err != nil || calls != 0 {
			t.Fatal("active credential revoked", calls, err)
		}
		exec(`UPDATE pgws_control.api_tokens SET revoked_at=now() WHERE principal_id=$1`, principal)
		if err = w.ReconcileCredentialRevocations(ctx); err == nil || calls != 1 {
			t.Fatal("missing host response was acknowledged", calls, err)
		}
		var pending bool
		if err = pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL AND host_revoked_at IS NULL FROM pgws_control.credentials WHERE id=$1", credential).Scan(&pending); err != nil || !pending {
			t.Fatal("revocation delivery was lost", pending, err)
		}
		lost = false
		if err = w.ReconcileCredentialRevocations(ctx); err != nil || calls != 2 {
			t.Fatal("credential revocation retry", calls, err)
		}
		if err = w.ReconcileCredentialRevocations(ctx); err != nil || calls != 2 {
			t.Fatal("delivered credential revocation repeated", calls, err)
		}
		var delivered int
		if err = pool.QueryRow(ctx, "SELECT count(*) FROM pgws_control.credentials WHERE principal_reference=$1 AND host_revoked_at IS NOT NULL", principal).Scan(&delivered); err != nil || delivered != 2 {
			t.Fatal("partial batch acknowledgement", delivered, err)
		}
		assertPhase("ready")
	})
	t.Run("operator_token_lifecycle", func(t *testing.T) {
		grant, secret, err := CreateAPIToken(ctx, pool, epoch, TokenGrant{Tenant: tenant, Project: project, Raw: true}, time.Hour, "")
		if err != nil || len(secret) != 64 || !ValidID(grant.ID) || !ValidID(grant.Principal) || !grant.Raw || grant.Admin {
			t.Fatal("operator token creation", err)
		}
		var hash string
		if err = pool.QueryRow(ctx, "SELECT token_hash FROM pgws_control.api_tokens WHERE id=$1", grant.ID).Scan(&hash); err != nil || hash != fmt.Sprintf("%x", sha256.Sum256([]byte(secret))) {
			t.Fatal("token hash persistence", err)
		}
		items, err := ListAPITokens(ctx, pool, tenant, project, "", 1000)
		if err != nil {
			t.Fatal(err)
		}
		listing, _ := json.Marshal(items)
		if strings.Contains(string(listing), secret) || strings.Contains(string(listing), hash) {
			t.Fatal("token inventory exposed authentication material")
		}
		rotated, nextSecret, err := CreateAPIToken(ctx, pool, epoch, TokenGrant{Tenant: tenant, Project: project, Admin: true}, 30*time.Minute, grant.ID)
		if err != nil || rotated.ID == grant.ID || nextSecret == secret || rotated.Principal != grant.Principal || !rotated.Raw || rotated.Admin {
			t.Fatal("atomic rotation changed privileges or principal", err)
		}
		var revoked bool
		if err = pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM pgws_control.api_tokens WHERE id=$1", grant.ID).Scan(&revoked); err != nil || !revoked {
			t.Fatal("rotation retained prior token", err)
		}
		if _, _, err = CreateAPIToken(ctx, pool, epoch, TokenGrant{Tenant: tenant, Project: project}, time.Hour, grant.ID); err == nil {
			t.Fatal("rotated token reused")
		}
		if count, e := RevokeAPITokens(ctx, pool, epoch, tenant, ID(), rotated.ID, ""); e != nil || count != 0 {
			t.Fatal("foreign project token revocation", count, e)
		}
		if _, _, err = CreateAPIToken(ctx, workerPool, epoch, TokenGrant{Tenant: tenant, Project: project}, time.Hour, ""); err == nil {
			t.Fatal("worker minted API authority")
		}
		if _, _, err = CreateAPIToken(ctx, pool, ID(), TokenGrant{Tenant: tenant, Project: project}, time.Hour, ""); err == nil {
			t.Fatal("stale epoch minted API authority")
		}
		if _, _, err = CreateAPIToken(ctx, pool, epoch, TokenGrant{Tenant: tenant, Project: project}, 25*time.Hour, ""); err == nil {
			t.Fatal("unbounded API token lifetime")
		}
		exec(`UPDATE pgws_control.authority SET reconciled=false`)
		if _, _, err = CreateAPIToken(ctx, pool, epoch, TokenGrant{Tenant: tenant, Project: project}, time.Hour, ""); err == nil {
			t.Fatal("unreconciled authority minted a token")
		}
		if count, e := RevokeAPITokens(ctx, pool, epoch, tenant, project, "", grant.Principal); e != nil || count != 1 {
			t.Fatal("principal revocation while issuance fenced", count, e)
		}
		if count, e := RevokeAPITokens(ctx, pool, epoch, tenant, project, "", grant.Principal); e != nil || count != 0 {
			t.Fatal("principal revocation replay", count, e)
		}
		exec(`UPDATE pgws_control.authority SET reconciled=true`)
		var audit string
		if err = pool.QueryRow(ctx, "SELECT coalesce(string_agg(safe_metadata::text,''),'') FROM pgws_control.audit_events WHERE action LIKE 'token.%'").Scan(&audit); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(audit, secret) || strings.Contains(audit, nextSecret) || strings.Contains(audit, hash) {
			t.Fatal("token audit exposed authentication material")
		}
	})
	t.Run("operator_privacy_policy_lifecycle", func(t *testing.T) { testPrivacyAdministration(t, ctx, pool, workerPool, epoch, tenant, project) })
}
