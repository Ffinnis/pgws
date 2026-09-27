package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"pgws/internal/control"
	"pgws/internal/freshness"
	"pgws/internal/hostclient"
	"pgws/internal/runtime"
	"pgws/internal/storage/zfs"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLiveDaemons(t *testing.T) {
	runLiveDaemons(t, false)
}

func TestLiveDaemonsOneGiB(t *testing.T) {
	if os.Getenv("PGWS_ONE_GIB_LAB") != "1" {
		t.Skip("run scripts/host_lab.py --one-gib")
	}
	runLiveDaemons(t, true)
}

func runLiveDaemons(t *testing.T, oneGiB bool) {
	bin := os.Getenv("PGWS_LAB_BIN")
	if os.Getenv("PGWS_ZFS_ROOT") == "" || bin == "" {
		t.Skip("run scripts/host_lab.py")
	}
	limit := 3 * time.Minute
	if oneGiB {
		limit = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	root, e := os.MkdirTemp("/tmp", "pgws-daemons-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if e = os.Chmod(root, 0711); e != nil {
		t.Fatal(e)
	}
	source := labPrimary(t, ctx, root, "source")
	management := labPrimary(t, ctx, root, "management")
	sourceConn, e := source.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer sourceConn.Close(context.Background())
	if _, e = sourceConn.Exec(ctx, `CREATE TABLE fixture(id int primary key,value text);INSERT INTO fixture VALUES(1,'original')`); e != nil {
		t.Fatal(e)
	}
	var bulk bulkFixture
	if oneGiB {
		bulk = fillOneGiB(t, ctx, sourceConn)
	}
	dsn := "host=" + management.Host + " user=postgres dbname=postgres sslmode=disable"
	daemonEnv := []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "PGWS_DATABASE_URL=" + dsn}
	run := func(binary string, env []string, input string, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, filepath.Join(bin, binary), args...)
		command.Env = env
		command.Stdin = strings.NewReader(input)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, e := command.Output()
		if e != nil {
			t.Fatalf("%s %s failed: %s", binary, strings.Join(args, " "), stderr.String())
		}
		return output
	}
	run("pgwsd-linux", daemonEnv, "", "migrate")
	var boot struct {
		Tenant  string `json:"tenant_id"`
		Project string `json:"project_id"`
		Epoch   string `json:"authority_epoch"`
		Token   string `json:"token"`
	}
	if e = json.Unmarshal(run("pgwsd-linux", daemonEnv, "", "bootstrap"), &boot); e != nil {
		t.Fatal(e)
	}
	mg, e := management.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer mg.Close(context.Background())
	if _, e = mg.Exec(ctx, `INSERT INTO pgws_control.approved_source_references VALUES($1,$2,'source','secret')`, boot.Tenant, boot.Project); e != nil {
		t.Fatal(e)
	}
	cert, key, pub, signing := labCertificate(t, root)
	secret := bytes.Repeat([]byte{9}, 32)
	write := func(name, value string) string {
		t.Helper()
		p := filepath.Join(root, name)
		if e = os.WriteFile(p, []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	rpcToken := strings.Repeat("daemon-test-private-", 4)
	tokenFile := write("rpc-token", rpcToken)
	publicFile := write("authority-key", base64.StdEncoding.EncodeToString(pub))
	signingFile := write("signing-key", base64.StdEncoding.EncodeToString(signing))
	secretFile := write("secret-key", base64.StdEncoding.EncodeToString(secret))
	cfg := Config{ID: "daemon-host", Epoch: boot.Epoch, Root: filepath.Join(root, "host"), Sockets: filepath.Join(root, "s"), Dataset: os.Getenv("PGWS_ZFS_ROOT"), MountRoot: os.Getenv("PGWS_ZFS_MOUNTS"), GuardBinary: filepath.Join(bin, "pgws-guard-linux"), Certificate: cert, CertificateKey: key, AuthorityKey: base64.StdEncoding.EncodeToString(pub), SecretKey: base64.StdEncoding.EncodeToString(secret), RPCSocket: filepath.Join(root, "rpc", "host.sock"), RPCGroup: 33, Sources: []SourceConfig{{Tenant: boot.Tenant, Project: boot.Project, EndpointReference: "source", SecretReference: "secret", Source: source}}}
	expectedQuota := int64(2 << 30)
	if oneGiB {
		cfg.SeedMaxBytes = 1536 << 20
		cfg.ProjectQuotaBytes = 4 << 30
		expectedQuota = 4 << 30
	}
	configBytes, _ := json.Marshal(cfg)
	configFile := write("host.json", string(configBytes))
	// Cleanup only resources recorded by this newly created fixture.
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(cfg.Root, "objects", "*", "*", "state.json"))
		for _, p := range paths {
			var s state
			b, _ := os.ReadFile(p)
			if json.Unmarshal(b, &s) != nil {
				continue
			}
			cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
			if s.GuardDirectory != "" {
				_ = guardRequest(cleanup, s.GuardDirectory, "shutdown", nil, nil)
			}
			if s.Container.ID != "" {
				_ = (runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}).Remove(cleanup, s.Container)
			}
			done()
		}
	})
	start := func(binary string, env []string, args ...string) *exec.Cmd {
		t.Helper()
		log, e := os.CreateTemp(root, "process-*.log")
		if e != nil {
			t.Fatal(e)
		}
		c := exec.Command(filepath.Join(bin, binary), args...)
		if binary == "pgwsd-linux" && len(args) == 1 {
			switch args[0] {
			case "serve":
				c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
			case "worker":
				c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 33, Gid: 33}}
			}
		}
		c.Env = env
		c.Stdout = log
		c.Stderr = log
		if e = c.Start(); e != nil {
			log.Close()
			t.Fatal(e)
		}
		stopped := make(chan struct{})
		go func() { _ = c.Wait(); close(stopped) }()
		t.Cleanup(func() {
			_ = c.Process.Signal(syscall.SIGTERM)
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				_ = c.Process.Kill()
				<-stopped
			}
			log.Close()
			if t.Failed() {
				b, _ := os.ReadFile(log.Name())
				t.Log(string(b))
			}
		})
		return c
	}
	hostProcess := start("pgws-host-linux", daemonEnv, configFile, tokenFile)
	start("pgws-watchdog-linux", daemonEnv, configFile)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	env := append(append([]string{}, daemonEnv...), "PGWS_AUTHORITY_EPOCH="+boot.Epoch, "PGWS_PHYSICAL_ENABLED=true", "PGWS_SECRET_KEY_FILE="+secretFile, "PGWS_AUTHORITY_KEY_FILE="+publicFile, "PGWS_SIGNING_KEY_FILE="+signingFile, "PGWS_HOST_TOKEN_FILE="+tokenFile, "PGWS_HOST_SOCKET="+cfg.RPCSocket, "PGWS_HOST_ID="+cfg.ID, "PGWS_LISTEN="+address)
	apiLogin := "api_" + strings.ReplaceAll(boot.Project, "-", "")
	workerLogin := "worker_" + strings.ReplaceAll(boot.Project, "-", "")
	for _, pair := range [][2]string{{apiLogin, "pgws_runtime"}, {workerLogin, "pgws_worker"}} {
		if _, e = mg.Exec(ctx, "CREATE ROLE "+pgx.Identifier{pair[0]}.Sanitize()+" LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '"+strings.ReplaceAll(boot.Project, "-", "")+"'; GRANT "+pgx.Identifier{pair[1]}.Sanitize()+" TO "+pgx.Identifier{pair[0]}.Sanitize()); e != nil {
			t.Fatal(e)
		}
	}
	// Shared management socket requires SCRAM; the private source remains
	// inaccessible to both unprivileged service users. Host RPC is worker-only.
	if e = os.Chmod(filepath.Dir(management.Host), 0711); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(management.Host, 0755); e != nil {
		t.Fatal(e)
	}
	hba := filepath.Join(filepath.Dir(management.Host), "data", "pg_hba.conf")
	if e = os.WriteFile(hba, []byte("local all postgres peer\nlocal all all scram-sha-256\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = mg.Exec(ctx, "SELECT pg_reload_conf()"); e != nil {
		t.Fatal(e)
	}
	environmentFor := func(login string) []string {
		result := append([]string{}, env...)
		uid := 65534
		if login == workerLogin {
			uid = 33
		}
		private := filepath.Join(root, login)
		if e = os.Mkdir(private, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Chown(private, uid, uid); e != nil {
			t.Fatal(e)
		}
		for i, v := range result {
			if strings.HasPrefix(v, "PGWS_DATABASE_URL=") {
				result[i] = "PGWS_DATABASE_URL=host=" + management.Host + " user=" + login + " password=" + strings.ReplaceAll(boot.Project, "-", "") + " dbname=postgres sslmode=disable"
			}
			for _, key := range []string{"PGWS_SECRET_KEY_FILE=", "PGWS_AUTHORITY_KEY_FILE=", "PGWS_SIGNING_KEY_FILE=", "PGWS_HOST_TOKEN_FILE="} {
				if !strings.HasPrefix(v, key) {
					continue
				}
				if login == apiLogin && (key == "PGWS_SIGNING_KEY_FILE=" || key == "PGWS_HOST_TOKEN_FILE=") {
					result[i] = strings.TrimSuffix(key, "=") + "="
					continue
				}
				sourceFile := strings.TrimPrefix(v, key)
				content, err := os.ReadFile(sourceFile)
				if err != nil {
					t.Fatal(err)
				}
				destination := filepath.Join(private, filepath.Base(sourceFile))
				if e = os.WriteFile(destination, content, 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.Chown(destination, uid, uid); e != nil {
					t.Fatal(e)
				}
				result[i] = key + destination
			}
		}
		return result
	}
	start("pgwsd-linux", environmentFor(workerLogin), "worker")
	start("pgwsd-linux", environmentFor(apiLogin), "serve")
	for {
		response, err := (&http.Client{Timeout: time.Second}).Get("http://" + address + "/readyz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("API startup timeout")
		case <-time.After(50 * time.Millisecond):
		}
	}
	cliEnv := append(append([]string{}, daemonEnv...), "PGWS_URL=http://"+address, "PGWS_PROJECT_ID="+boot.Project, "PGWS_TOKEN="+boot.Token)
	cli := func(input string, args ...string) map[string]json.RawMessage {
		t.Helper()
		b := run("pgws-linux", cliEnv, input, args...)
		var result map[string]json.RawMessage
		if e = json.Unmarshal(b, &result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	wait := func(op json.RawMessage) {
		t.Helper()
		var o struct{ ID string }
		if e = json.Unmarshal(op, &o); e != nil {
			t.Fatal(e)
		}
		cli("", "wait", "--id", o.ID, "--timeout", "6m")
	}
	seedStarted := time.Now()
	registered := cli(`{"connector":"physical","approved_endpoint_reference":"source","secret_reference":"secret"}`, "source", "--file", "-", "--key", "source")
	wait(registered["operation"])
	var sourceID string
	json.Unmarshal(registered["source_id"], &sourceID)
	if oneGiB {
		t.Logf("ONE_GIB initial_seed_seconds=%.3f", time.Since(seedStarted).Seconds())
		benchmarkOneGiB(t, ctx, bulk, sourceConn, mg, sourceID, cert, cfg, cli, wait)
	}
	created := cli(fmt.Sprintf(`{"baseline_id":%q,"task_id":"daemon-test","freshness":{"mode":"latest"},"resource_profile":"small","ttl_seconds":300}`, sourceID), "create", "--file", "-", "--key", "create")
	var workspace struct{ ID string }
	json.Unmarshal(created["workspace"], &workspace)
	// Interrupt the production host while the unprivileged worker is waiting
	// on its real Unix RPC. No test hook or synthetic runtime outcome is used.
	creationState := filepath.Join(cfg.Root, "objects", workspace.ID, "1", "state.json")
	for until := time.Now().Add(20 * time.Second); ; {
		var candidate state
		raw, err := os.ReadFile(creationState)
		if err == nil && json.Unmarshal(raw, &candidate) == nil && candidate.CreateStage == "prepared" {
			if err = hostProcess.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal("missed the real host creation interruption boundary")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for until := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(filepath.Join("/proc", fmt.Sprint(hostProcess.Process.Pid))); os.IsNotExist(err) {
			break
		}
		if time.Now().After(until) {
			t.Fatal("killed host still owns its journal")
		}
		time.Sleep(10 * time.Millisecond)
	}
	hostProcess = start("pgws-host-linux", daemonEnv, configFile, tokenFile)
	wait(created["operation"])
	var createOperation struct{ ID string }
	json.Unmarshal(created["operation"], &createOperation)
	var attempts int
	if e = mg.QueryRow(ctx, "SELECT attempt FROM pgws_control.operations WHERE id=$1 AND status='succeeded'", createOperation.ID).Scan(&attempts); e != nil || attempts < 2 {
		t.Fatal("worker did not reconcile the interrupted real host request", attempts, e)
	}
	t.Logf("Production host SIGKILL during create reconciled automatically in %d worker attempts", attempts)
	credential := cli(`{"expected_generation":1,"role":"owner","ttl_seconds":120}`, "credentials", "--id", workspace.ID, "--file", "-", "--key", "credentials")
	var user, password string
	var endpoint struct {
		Hostname string
		Port     int
		Database string
	}
	json.Unmarshal(credential["username"], &user)
	json.Unmarshal(credential["password"], &password)
	json.Unmarshal(credential["endpoint"], &endpoint)
	u := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(endpoint.Hostname, fmt.Sprint(endpoint.Port)), Path: "/" + endpoint.Database, User: url.UserPassword(user, password)}
	u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {cert}}.Encode()
	conn, e := pgx.Connect(ctx, u.String())
	if e != nil {
		t.Fatal("daemon SQL endpoint unavailable")
	}
	defer conn.Close(context.Background())
	if oneGiB {
		verifyOneGiB(t, ctx, conn, bulk)
	}
	if _, e = conn.Exec(ctx, `UPDATE fixture SET value='daemon-workspace'`); e != nil {
		t.Fatal(e)
	}
	var value string
	if e = sourceConn.QueryRow(ctx, `SELECT value FROM fixture WHERE id=1`).Scan(&value); e != nil || value != "original" {
		t.Fatal("workspace isolation", e)
	}
	// Read counters with the host's journal locked by its live daemon.
	capacityJSON, e := exec.CommandContext(ctx, filepath.Join(bin, "pgws-host-linux"), "capacity", configFile).Output()
	var capacity CapacityReport
	if e != nil || json.Unmarshal(capacityJSON, &capacity) != nil || len(capacity.Projects) != 1 || capacity.Projects[0].Project != boot.Project || capacity.Projects[0].Quota != expectedQuota || capacity.Projects[0].Used == 0 || capacity.ReservedMemory != 2<<30 {
		t.Fatal("independent capacity inspection", e)
	}
	// Exercise the dependency-free Python SDK against these real daemons.
	python := exec.CommandContext(ctx, "/usr/bin/python3", "-", workspace.ID, sourceID)
	python.Env = append(append([]string{}, cliEnv...), "PYTHONPATH="+filepath.Join(os.Getenv("PGWS_LAB_ROOT"), "sdk", "python"))
	python.Stdin = strings.NewReader(`import os, sys
from pgws import Client
c = Client(os.environ["PGWS_URL"], os.environ["PGWS_PROJECT_ID"], os.environ["PGWS_TOKEN"])
assert c.get(sys.argv[1])["phase"] == "ready"
assert c.baselines()["items"]
barrier = c.barrier(sys.argv[2], key="python-barrier")
created = c.create(sys.argv[2], "python-sdk", key="python-create", freshness={"mode":"at_least", "barrier_token":barrier["barrier_token"]}, ttl=300)
c.wait(created["operation"]["id"])
w = c.get(created["workspace"]["id"])
credentials = c.credentials(w["id"], w["generation"], key="python-credential", role="reader", ttl=60)
assert credentials["password"] and credentials == c.credentials(w["id"], w["generation"], key="python-credential", role="reader", ttl=60)
c.wait(c.delete(w["id"], w["generation"], key="python-delete")["id"])
assert c.get(w["id"])["phase"] == "deleted"
`)
	if output, e := python.CombinedOutput(); e != nil {
		// Diagnostics contain verification results and timestamps, never tokens.
		rows, queryErr := mg.Query(ctx, "SELECT safe_result FROM pgws_control.operations WHERE kind='issue_barrier' AND status='succeeded'")
		if queryErr == nil {
			for rows.Next() {
				var raw []byte
				var response control.BarrierResponse
				if rows.Scan(&raw) == nil && json.Unmarshal(raw, &response) == nil {
					_, verifyErr := freshness.Verify(pub, response.Token, time.Now())
					t.Logf("barrier verification=%v issued=%s expires=%s now=%s", verifyErr, response.IssuedAt, response.ExpiresAt, time.Now().UTC())
				}
			}
			rows.Close()
		}
		t.Fatalf("Python SDK daemon flow failed: %s", output)
	}
	// Kill the guard without unlinking its socket. Renewal must recreate a
	// closed guard on the same published port and authorize a new SQL session.
	guardDir := filepath.Join(cfg.Root, "objects", workspace.ID, "1", "ingress")
	var previousGuard guardStatus
	if e = guardRequest(ctx, guardDir, "status", nil, &previousGuard); e != nil || previousGuard.PID < 1 {
		t.Fatal("guard identity", e)
	}
	if e = syscall.Kill(previousGuard.PID, syscall.SIGKILL); e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Exec(ctx, "SELECT 1"); e == nil {
		t.Fatal("killed guard retained SQL session")
	}
	if e = hostProcess.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	// The host journal lock and stale socket are recovered after SIGKILL.
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join("/proc", fmt.Sprint(hostProcess.Process.Pid))); os.IsNotExist(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	start("pgws-host-linux", daemonEnv, configFile, tokenFile)
	recovered := false
	for until := time.Now().Add(40 * time.Second); time.Now().Before(until); {
		var status guardStatus
		if guardRequest(ctx, guardDir, "status", nil, &status) == nil && status.Active && status.PID != previousGuard.PID && status.Address == previousGuard.Address {
			recovered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("host/guard did not recover the published endpoint")
	}
	conn, e = pgx.Connect(ctx, u.String())
	if e != nil {
		t.Fatal("SQL reconnect after guard recovery", e)
	}
	defer conn.Close(context.Background())
	// Wait across the worker's independent serving refresh cycle.
	deadline := time.Now().Add(22 * time.Second)
	for time.Now().Before(deadline) {
		if e = conn.QueryRow(ctx, "SELECT value FROM fixture WHERE id=1").Scan(&value); e != nil || value != "daemon-workspace" {
			t.Fatal("serving refresh", e)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	testPrincipalRevocation(t, ctx, mg, conn, address, boot.Tenant, boot.Project, workspace.ID, cert)
	testConnectedRevocation(t, ctx, mg, conn, cfg, workspace.ID, hostclient.Client{Socket: cfg.RPCSocket, Token: rpcToken})
	deleted := cli("", "delete", "--id", workspace.ID, "--generation", "1", "--key", "delete")
	op, _ := json.Marshal(deleted)
	wait(op)
	if _, e = conn.Exec(ctx, "SELECT 1"); e == nil {
		t.Fatal("deleted endpoint retained a session")
	}
	observed := cli("", "get", "--id", workspace.ID)
	if string(observed["phase"]) != `"deleted"` {
		t.Fatal("daemon delete not confirmed")
	}
	// Reserve space in a sibling belonging to this disposable pool. This changes
	// actual ZFS available bytes without filling a disk or changing service limits.
	pressureWorkspace := cli(fmt.Sprintf(`{"baseline_id":%q,"task_id":"pool-pressure","freshness":{"mode":"latest"},"resource_profile":"small","ttl_seconds":300}`, sourceID), "create", "--file", "-", "--key", "pressure-create")
	wait(pressureWorkspace["operation"])
	json.Unmarshal(pressureWorkspace["workspace"], &workspace)
	pressureCredential := cli(`{"expected_generation":1,"role":"reader","ttl_seconds":60}`, "credentials", "--id", workspace.ID, "--file", "-", "--key", "pressure-credential")
	json.Unmarshal(pressureCredential["username"], &user)
	json.Unmarshal(pressureCredential["password"], &password)
	json.Unmarshal(pressureCredential["endpoint"], &endpoint)
	u = url.URL{Scheme: "postgresql", Host: net.JoinHostPort(endpoint.Hostname, fmt.Sprint(endpoint.Port)), Path: "/" + endpoint.Database, User: url.UserPassword(user, password)}
	u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {cert}}.Encode()
	pressureConn, e := pgx.Connect(ctx, u.String())
	if e != nil {
		t.Fatal("pressure fixture SQL", e)
	}
	defer pressureConn.Close(context.Background())
	available, e := zfs.RootAvailable(ctx, "/usr/sbin/zfs", cfg.Dataset)
	if e != nil || available < 512<<20 {
		t.Fatal("pressure fixture lacks initial capacity", e)
	}
	pressureDataset := cfg.Dataset + "-pressure"
	if output, e := exec.CommandContext(ctx, "/usr/sbin/zfs", "create", "-o", "mountpoint=none", "-o", "canmount=off", "-o", fmt.Sprintf("refreservation=%d", available-(128<<20)), pressureDataset).CombinedOutput(); e != nil {
		t.Fatalf("pressure reservation: %s", output)
	}
	defer exec.Command("/usr/sbin/zfs", "destroy", pressureDataset).Run()
	cutOff := false
	var cutoffElapsed time.Duration
	pressureStarted := time.Now()
	for time.Since(pressureStarted) < 12*time.Second {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		_, e = pressureConn.Exec(probe, "SELECT 1")
		cancel()
		if e != nil {
			cutOff = true
			cutoffElapsed = time.Since(pressureStarted)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !cutOff {
		t.Fatal("pool pressure did not close an existing SQL session")
	}
	markerPath := filepath.Join(cfg.Root, "objects", workspace.ID, "1", "safety-stop.json")
	var marker safetyStop
	data, e := os.ReadFile(markerPath)
	if e != nil || json.Unmarshal(data, &marker) != nil || marker.Reason != "POOL_PRESSURE" {
		t.Fatal("pool-pressure stop is not durable", e)
	}
	for until := time.Now().Add(10 * time.Second); ; {
		var slots int
		e = sourceConn.QueryRow(ctx, "SELECT count(*) FROM pg_replication_slots WHERE slot_name=$1", "pgws_"+strings.ReplaceAll(sourceID, "-", "")+"_g1").Scan(&slots)
		if e == nil && slots == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("pool pressure retained the source slot", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if output, e := exec.CommandContext(ctx, "/usr/sbin/zfs", "destroy", pressureDataset).CombinedOutput(); e != nil {
		t.Fatalf("pressure reservation release: %s", output)
	}
	if checkStopped(filepath.Dir(markerPath)) == nil {
		t.Fatal("restored free space cleared a terminal safety decision")
	}
	for until := time.Now().Add(20 * time.Second); ; {
		observed := cli("", "get", "--id", workspace.ID)
		var sourceStatus string
		_ = mg.QueryRow(ctx, "SELECT status FROM pgws_control.sources WHERE id=$1", sourceID).Scan(&sourceStatus)
		if string(observed["phase"]) == `"failed"` && len(observed["endpoint"]) == 0 && sourceStatus == "blocked" {
			break
		}
		if time.Now().After(until) {
			t.Fatal("host stop did not reach management phase and source eligibility")
		}
		time.Sleep(200 * time.Millisecond)
	}
	capacityJSON, e = exec.CommandContext(ctx, filepath.Join(bin, "pgws-host-linux"), "capacity", configFile).Output()
	if e != nil || json.Unmarshal(capacityJSON, &capacity) != nil || capacity.ReservedMemory != 0 || len(capacity.Projects) != 1 || capacity.Projects[0].ReservedMemory != 0 || capacity.Projects[0].Used == 0 {
		t.Fatal("confirmed runtime removal did not release memory while retaining disk allocation", e)
	}
	pressureDeleted := cli("", "delete", "--id", workspace.ID, "--generation", "1", "--key", "pressure-delete")
	op, _ = json.Marshal(pressureDeleted)
	wait(op)
	history := cli("", "usage", "--limit", "2")
	var samples []json.RawMessage
	if json.Unmarshal(history["items"], &samples) != nil || len(samples) == 0 || string(history["measurement_kind"]) != `"observed_gauge"` {
		t.Fatal("worker did not persist real host capacity measurements")
	}
	t.Logf("Actual pool pressure: root available before=%d, floor=%d, SQL session closed in %s, source slot removed; restored free space did not clear the safety stop", available, 256<<20, cutoffElapsed)
	t.Log("Distinct unprivileged API/worker, SIGKILL host/guard recovery, CLI/Python SDK lifecycle, project hard quotas, actual pool-pressure session cutoff and owned source-slot cleanup, and deletion passed")
}
