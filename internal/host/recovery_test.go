package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/hostclient"
	"pgws/internal/lease"
	"pgws/internal/migrations"
	"pgws/internal/privacy"
	"pgws/internal/runtime"
)

type recoveryCrashJob struct {
	Old, Next Config
	Plan      control.RecoveryPlan
	Stage     string
}

func TestAuthorityRecoveryCrashHelper(t *testing.T) {
	path := os.Getenv("PGWS_RECOVERY_CRASH_INPUT")
	if path == "" {
		t.Skip("child of recovery crash campaign")
	}
	data, err := os.ReadFile(path)
	var job recoveryCrashJob
	if err != nil || json.Unmarshal(data, &job) != nil {
		t.Fatal("invalid crash fixture")
	}
	_, err = recoverAuthority(context.Background(), job.Old, job.Next, job.Plan, func(stage string) {
		if stage == job.Stage {
			if err := save(path+".killed", stage); err != nil {
				t.Fatal(err)
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("recovery crash boundary did not execute")
}

func killRecoveryAt(t *testing.T, ctx context.Context, job recoveryCrashJob) {
	t.Helper()
	path := filepath.Join(job.Old.Root, "recovery-crash-input.json")
	if err := save(path, job); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestAuthorityRecoveryCrashHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "PGWS_RECOVERY_CRASH_INPUT="+path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("recovery helper survived")
	}
	if _, e := os.Stat(path + ".killed"); e != nil {
		t.Fatalf("recovery helper missed %s: %s", job.Stage, out)
	}
}

func TestLiveAuthorityRecoveryJournalCrashes(t *testing.T) {
	if os.Getenv("PGWS_ZFS_ROOT") == "" {
		t.Skip("run scripts/host_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, stage := range []string{"marker", "runtimes", "commands", "storage", "archive", "complete"} {
		t.Run(stage, func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "pgws-rc-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			c := Config{ID: control.ID(), Epoch: control.ID(), Root: root, Sockets: filepath.Join(root, "s"), Dataset: os.Getenv("PGWS_ZFS_ROOT"), MountRoot: os.Getenv("PGWS_ZFS_MOUNTS"), AuthorityKey: base64.StdEncoding.EncodeToString(oldPub)}
			h, err := Open(c)
			if err != nil {
				t.Fatal(err)
			}
			h.Close()
			plan := control.RecoveryPlan{Epoch: control.ID(), Previous: c.Epoch, PublicKey: pub, PreviousKey: oldPub, Hosts: []string{c.ID}, Operator: "crash-fixture", CreatedAt: time.Now().UTC()}
			next := c
			next.Epoch = plan.Epoch
			next.AuthorityKey = base64.StdEncoding.EncodeToString(pub)
			killRecoveryAt(t, ctx, recoveryCrashJob{c, next, plan, stage})
			if h, err = Open(c); err == nil {
				h.Close()
				t.Fatal("old configuration resumed interrupted recovery")
			}
			if stage != "complete" {
				if h, err = Open(next); err == nil {
					h.Close()
					t.Fatal("normal startup bypassed partial recovery")
				}
			}
			if _, err = RecoverAuthority(ctx, c, next, plan); err != nil {
				t.Fatal("resume", err)
			}
			h, err = Open(next)
			if err != nil {
				t.Fatal(err)
			}
			h.Close()
		})
	}
}

func TestLiveAuthorityBackupRestore(t *testing.T) {
	if os.Getenv("PGWS_ZFS_ROOT") == "" {
		t.Skip("run scripts/host_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("/tmp", "pgws-restore-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	source := labPrimary(t, ctx, root, "source")
	management, mgmtContainer := labPrimaryRuntime(t, ctx, root, "management", "", "")
	sourceConn, err := source.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceConn.Close(context.Background())
	if _, err = sourceConn.Exec(ctx, `CREATE TABLE fixture(id bigint PRIMARY KEY,value text);INSERT INTO fixture VALUES(1,'source')`); err != nil {
		t.Fatal(err)
	}
	dsn := "host=" + management.Host + " user=postgres dbname=postgres sslmode=disable"
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	sql := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	tenant, project, epoch := control.ID(), control.ID(), control.ID()
	sql(`INSERT INTO pgws_control.tenants(id,name) VALUES($1,'recovery')`, tenant)
	sql(`INSERT INTO pgws_control.projects(tenant_id,id,name) VALUES($1,$2,'recovery')`, tenant, project)
	sql(`INSERT INTO pgws_control.authority(epoch,reconciled) VALUES($1,true)`, epoch)
	sql(`INSERT INTO pgws_control.approved_source_references VALUES($1,$2,'restore-source','restore-secret')`, tenant, project)
	grant, token, err := control.CreateAPIToken(ctx, pool, epoch, control.TokenGrant{Tenant: tenant, Project: project, Admin: true, Raw: true}, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	cert, key, pub, signing := labCertificate(t, root)
	secret := bytes.Repeat([]byte{9}, 32)
	c := Config{ID: control.ID(), Epoch: epoch, Root: filepath.Join(root, "host"), Sockets: filepath.Join(root, "s"), Dataset: os.Getenv("PGWS_ZFS_ROOT"), MountRoot: os.Getenv("PGWS_ZFS_MOUNTS"), GuardBinary: os.Getenv("PGWS_GUARD_BINARY"), Certificate: cert, CertificateKey: key, AuthorityKey: base64.StdEncoding.EncodeToString(pub), SecretKey: base64.StdEncoding.EncodeToString(secret), Sources: []SourceConfig{{Tenant: tenant, Project: project, EndpointReference: "restore-source", SecretReference: "restore-secret", Source: source}}}
	h, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { h.Close() }()
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(c.Root, "objects", "*", "*", "state.json"))
		for _, path := range paths {
			data, _ := os.ReadFile(path)
			var s state
			if json.Unmarshal(data, &s) == nil {
				cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
				_ = recordStop(filepath.Dir(path), "TEST_CLEANUP")
				_ = removeStoppedRuntime(cleanup, runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}, filepath.Dir(path), s)
				if s.GuardDirectory != "" {
					_ = guardRequest(cleanup, s.GuardDirectory, "shutdown", nil, nil)
				}
				done()
			}
		}
	})
	api := (&control.Server{Pool: pool, Epoch: epoch, Physical: true, AuthorityKey: pub, SecretKey: secret}).Handler()
	w := control.Worker{Pool: pool, Epoch: epoch, ID: "restore-worker", HostID: c.ID, SigningKey: signing, Backend: h}
	call := func(method, path, body string, want int) map[string]json.RawMessage {
		t.Helper()
		r := httptest.NewRequest(method, "/v1/projects/"+project+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", control.ID())
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Fatalf("%s %s returned %d: %s", method, path, rec.Code, rec.Body.String())
		}
		var value map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &value)
		return value
	}
	run := func() {
		t.Helper()
		if did, err := w.Once(ctx); err != nil || !did {
			t.Fatal("worker", did, err)
		}
	}
	onboard := func() string {
		t.Helper()
		v := call("POST", "/sources", `{"connector":"physical","approved_endpoint_reference":"restore-source","secret_reference":"restore-secret"}`, 202)
		var id string
		_ = json.Unmarshal(v["source_id"], &id)
		run()
		return id
	}
	create := func(baseline string) string {
		t.Helper()
		v := call("POST", "/workspaces", fmt.Sprintf(`{"baseline_id":%q,"task_id":"restore","freshness":{"mode":"latest"},"resource_profile":"small","ttl_seconds":600}`, baseline), 202)
		var obj struct{ ID string }
		_ = json.Unmarshal(v["workspace"], &obj)
		run()
		return obj.ID
	}
	connect := func(id string) (*pgx.Conn, string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			for {
				did, e := w.Once(ctx)
				if e != nil || did {
					done <- e
					return
				}
				select {
				case <-ctx.Done():
					done <- ctx.Err()
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}()
		v := call("POST", "/workspaces/"+id+"/credentials", `{"expected_generation":1,"role":"owner","ttl_seconds":600}`, 201)
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		var username, password string
		var endpoint struct {
			Hostname string
			Port     int
			Database string
		}
		_ = json.Unmarshal(v["username"], &username)
		_ = json.Unmarshal(v["password"], &password)
		_ = json.Unmarshal(v["endpoint"], &endpoint)
		u := url.URL{Scheme: "postgresql", Host: fmt.Sprintf("%s:%d", endpoint.Hostname, endpoint.Port), Path: "/" + endpoint.Database, User: url.UserPassword(username, password)}
		u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {cert}, "connect_timeout": {"2"}}.Encode()
		conn, e := pgx.Connect(ctx, u.String())
		if e != nil {
			t.Fatal("application connection failed")
		}
		return conn, u.String()
	}
	baseline := onboard()
	workspace := create(baseline)
	client, oldDSN := connect(workspace)
	defer client.Close(context.Background())
	if _, err = client.Exec(ctx, `UPDATE fixture SET value='private-workspace' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var system string
	var timeline int64
	if err = pool.QueryRow(ctx, `SELECT system_identifier,timeline FROM pgws_control.sources WHERE id=$1`, baseline).Scan(&system, &timeline); err != nil {
		t.Fatal(err)
	}
	schema := privacy.Schema{Tables: []privacy.Table{{ID: 17, Schema: "public", Name: "fixture", Columns: []privacy.Column{{ID: 1, Name: "id", Type: "int8"}, {ID: 2, Name: "value", Type: "text"}}, PrimaryKey: []int16{1}}}}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "restore-fixture", Rules: []privacy.Rule{{Table: 17, Column: 1, Action: "copy_original"}, {Table: 17, Column: 2, Action: "keyed_text", Domain: "values"}}}
	draft := control.PolicyDraft{Tenant: tenant, Project: project, ID: control.ID(), Revision: 1, Source: baseline, SourceEpoch: 1, SystemID: system, Timeline: timeline, Schema: schema, Policy: policy}
	policyRecord, err := control.CreatePrivacyPolicy(ctx, pool, epoch, draft, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, policyRecord.ID, policyRecord.Hash, policyRecord.SchemaHash); err != nil {
		t.Fatal(err)
	}
	// Actual PostgreSQL backup precedes both revocations and a host-only clone.
	dumpCmd := exec.CommandContext(ctx, "/usr/bin/docker", "exec", mgmtContainer.ID, filepath.Join(runtime.PostgresBin, "pg_dump"), "-h", management.Host, "-U", "postgres", "-Fc", "postgres")
	dump, err := dumpCmd.Output()
	if err != nil {
		t.Fatal("management backup failed")
	}
	orphan := create(baseline)
	if _, err = control.RevokeAPITokens(ctx, pool, epoch, tenant, project, grant.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = control.RevokePrivacyPolicy(ctx, pool, epoch, tenant, project, policyRecord.ID, policyRecord.Hash); err != nil {
		t.Fatal(err)
	}
	call("GET", "/baselines", "", 401)
	sql(`CREATE DATABASE recovered_management`)
	restoreCmd := exec.CommandContext(ctx, "/usr/bin/docker", "exec", "-i", mgmtContainer.ID, filepath.Join(runtime.PostgresBin, "pg_restore"), "-h", management.Host, "-U", "postgres", "--exit-on-error", "-d", "recovered_management")
	restoreCmd.Stdin = bytes.NewReader(dump)
	if err = restoreCmd.Run(); err != nil {
		t.Fatal("management restore failed")
	}
	clear(dump)
	restored, err := pgxpool.New(ctx, "host="+management.Host+" user=postgres dbname=recovered_management sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var restoredActive bool
	if err = restored.QueryRow(ctx, `SELECT revoked_at IS NULL FROM pgws_control.api_tokens WHERE id=$1`, grant.ID).Scan(&restoredActive); err != nil || !restoredActive {
		t.Fatal("backup did not predate user revocation", err)
	}
	newPub, newSigning, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := control.RecoveryPlan{Epoch: control.ID(), Previous: epoch, PublicKey: newPub, PreviousKey: pub, Hosts: []string{c.ID}, Operator: "restore-drill", CreatedAt: time.Now().UTC()}
	if err = control.BeginRecovery(ctx, restored, plan); err != nil {
		t.Fatal(err)
	}
	if _, _, err = control.CreateAPIToken(ctx, restored, plan.Epoch, control.TokenGrant{Tenant: tenant, Project: project, Admin: true, Raw: true}, time.Hour, ""); err == nil {
		t.Fatal("reopened before host acknowledgement")
	}
	if _, _, err = control.SignPrivacyPolicy(ctx, restored, plan.Epoch, tenant, project, policyRecord.ID, policyRecord.Hash, newSigning); err == nil {
		t.Fatal("restored policy revived")
	}
	next := c
	next.Epoch = plan.Epoch
	next.AuthorityKey = base64.StdEncoding.EncodeToString(newPub)
	if _, err = RecoverAuthority(ctx, c, next, plan); err == nil {
		t.Fatal("recovery ran beside live host")
	}
	h.Close()
	killRecoveryAt(t, ctx, recoveryCrashJob{c, next, plan, "commands"})
	if stale, e := Open(c); e == nil {
		stale.Close()
		t.Fatal("old host started after partial journal transition")
	}
	report, err := RecoverAuthority(ctx, c, next, plan)
	if err != nil {
		t.Fatal("recover interrupted authority", err)
	}
	planPath := filepath.Join(root, "recovery-plan.json")
	oldConfigPath := filepath.Join(root, "old-host.json")
	nextConfigPath := filepath.Join(root, "new-host.json")
	for path, value := range map[string]any{planPath: plan, oldConfigPath: c, nextConfigPath: next} {
		if err = save(path, value); err != nil {
			t.Fatal(err)
		}
	}
	cli := exec.CommandContext(ctx, filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgws-host-linux"), "recover", oldConfigPath, nextConfigPath, planPath)
	cliOut, e := cli.Output()
	if e != nil {
		t.Fatal("operator host recovery CLI retry", e)
	}
	var cliReport control.RecoveryReport
	if json.Unmarshal(cliOut, &cliReport) != nil || cliReport.PlanHash != report.PlanHash {
		t.Fatal("host recovery CLI acknowledgement differs")
	}
	seenOrphan := false
	for _, g := range report.Generations {
		seenOrphan = seenOrphan || g.Identity.Workspace == orphan
	}
	if !seenOrphan {
		t.Fatal("host-only resource missing from recovery")
	}
	if _, err = client.Exec(ctx, "SELECT 1"); err == nil {
		t.Fatal("old SQL session survived recovery")
	}
	if conn, e := pgx.Connect(ctx, oldDSN); e == nil {
		conn.Close(context.Background())
		t.Fatal("old database login reconnected")
	}
	h, err = Open(next)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := h.load(control.Task{Command: lease.Command{Identity: lease.Identity{Workspace: workspace, Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.storage.VerifyGeneration(ctx, stopped.Task.Command, stopped.Volume, "workspaces"); err != nil {
		t.Fatal("retained volume lost", err)
	}
	oldTask := stopped.Task
	oldTask.Command.Workspace = control.ID()
	oldTask.Kind = "create"
	if _, err = h.Execute(ctx, oldTask); err == nil {
		t.Fatal("old authority created unseen resource")
	}
	listener, err := net.Listen("unix", filepath.Join(root, "recovery-rpc.sock"))
	if err != nil {
		t.Fatal(err)
	}
	rpcToken := strings.Repeat("recovery-rpc-secret", 3)
	server := http.Server{Handler: h.Handler(rpcToken)}
	go server.Serve(listener)
	defer server.Close()
	channel := hostclient.Client{Socket: listener.Addr().String(), Token: rpcToken}
	rpcTokenPath := filepath.Join(root, "recovery-rpc-token")
	if err = os.WriteFile(rpcTokenPath, []byte(rpcToken), 0600); err != nil {
		t.Fatal(err)
	}
	channelsPath := filepath.Join(root, "recovery-channels.json")
	if err = save(channelsPath, []map[string]string{{"host": c.ID, "socket": channel.Socket, "token_file": rpcTokenPath}}); err != nil {
		t.Fatal(err)
	}
	finish := exec.CommandContext(ctx, filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgwsd-linux"), "recovery-finish", planPath, channelsPath)
	finish.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "PGWS_DATABASE_URL=host=" + management.Host + " user=postgres dbname=recovered_management sslmode=disable"}
	finished, e := finish.CombinedOutput()
	if e != nil {
		t.Fatalf("operator recovery completion CLI: %s", finished)
	}
	var confirmation struct{ Reconciled bool }
	if json.Unmarshal(finished, &confirmation) != nil || !confirmation.Reconciled {
		t.Fatal("operator completion did not acknowledge recovery")
	}
	api = (&control.Server{Pool: restored, Epoch: plan.Epoch, Physical: true, AuthorityKey: newPub, SecretKey: secret}).Handler()
	call("GET", "/baselines", "", 401)
	_, token, err = control.CreateAPIToken(ctx, restored, plan.Epoch, control.TokenGrant{Tenant: tenant, Project: project, Admin: true, Raw: true}, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	call("POST", "/workspaces/"+workspace+"/actions", `{"action":"resume","expected_generation":1}`, 409)
	retained := call("GET", "/workspaces/"+workspace, "", 200)
	if _, exists := retained["endpoint"]; exists {
		t.Fatal("retained generation exposed an endpoint")
	}
	call("POST", "/sources", `{"connector":"physical","approved_endpoint_reference":"restore-source","secret_reference":"restore-secret"}`, 403)
	pool = restored
	sql(`INSERT INTO pgws_control.approved_source_references VALUES($1,$2,'restore-source','restore-secret')`, tenant, project)
	w = control.Worker{Pool: restored, Epoch: plan.Epoch, ID: "reapproved-worker", HostID: c.ID, SigningKey: newSigning, Backend: channel}
	newBaseline := onboard()
	newWorkspace := create(newBaseline)
	newClient, _ := connect(newWorkspace)
	defer newClient.Close(context.Background())
	var value string
	if err = newClient.QueryRow(ctx, `SELECT value FROM fixture WHERE id=1`).Scan(&value); err != nil || value != "source" {
		t.Fatal("explicitly reapproved fresh workspace failed", value, err)
	}
	if err = w.CollectUsage(ctx); err != nil {
		t.Fatal("post-recovery usage collection", err)
	}
	t.Log("Actual PG18 dump before user/policy revocation restored; host-only clone quarantined, SQL closed, journal SIGKILL recovered, exact ZFS retained, explicit new grant/source produced writable SQL")
}
