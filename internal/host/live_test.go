package host

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/hostclient"
	"pgws/internal/lease"
	"pgws/internal/migrations"
	"pgws/internal/physical"
	"pgws/internal/runtime"
)

func labPrimary(t *testing.T, ctx context.Context, root, id string) physical.Source {
	return labConfiguredPrimary(t, ctx, root, id, "", "")
}

func labConfiguredPrimary(t *testing.T, ctx context.Context, root, id, cert, key string) physical.Source {
	source, _ := labPrimaryRuntime(t, ctx, root, id, cert, key)
	return source
}

func labPrimaryRuntime(t *testing.T, ctx context.Context, root, id, cert, key string) (physical.Source, runtime.Container) {
	t.Helper()
	o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
	s := runtime.Spec{Identity: lease.Identity{Epoch: "fixture", Host: id, Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Generation: 1, Revision: 1}, DataDir: filepath.Join(root, id, "data"), ControlDir: filepath.Join(root, id, "control"), SocketDir: filepath.Join(root, id, "socket"), MemoryBytes: 512 << 20}
	for _, p := range []string{s.DataDir, s.ControlDir, s.SocketDir} {
		if e := os.MkdirAll(p, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown(p, 999, 999); e != nil {
			t.Fatal(e)
		}
	}
	c, e := o.Ensure(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if e := o.Remove(cleanup, c); e != nil {
			t.Error(e)
		}
	})
	tools := o.Tools(c)
	if _, e = tools.Executor.Run(ctx, "initdb", nil, "-D", s.DataDir, "-U", "postgres", "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"); e != nil {
		t.Fatal(e)
	}
	conf := "data_directory='" + s.DataDir + "'\nlisten_addresses=''\nunix_socket_directories='" + s.SocketDir + "'\nshared_buffers='32MB'\nmax_connections=20\nmax_wal_senders=10\nmax_worker_processes=8\ncheckpoint_completion_target=0\nmax_slot_wal_keep_size='128MB'\n"
	if cert != "" {
		for name, source := range map[string]string{"server.crt": cert, "server.key": key, "tcp-bridge.test": filepath.Join(os.Getenv("PGWS_LAB_BIN"), "host-linux.test")} {
			data, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0600)
			if name == "tcp-bridge.test" {
				mode = 0700
			}
			destination := filepath.Join(s.ControlDir, name)
			if err = os.WriteFile(destination, data, mode); err != nil {
				t.Fatal(err)
			}
			if err = os.Chown(destination, 999, 999); err != nil {
				t.Fatal(err)
			}
		}
		conf += "listen_addresses='127.0.0.1'\nssl=on\nssl_cert_file='" + filepath.Join(s.ControlDir, "server.crt") + "'\nssl_key_file='" + filepath.Join(s.ControlDir, "server.key") + "'\nssl_min_protocol_version='TLSv1.2'\n"
	}
	path := filepath.Join(s.ControlDir, "postgresql.conf")
	if e = os.WriteFile(path, []byte(conf), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = tools.Executor.Run(ctx, "pg_ctl", nil, "-D", s.DataDir, "-l", filepath.Join(s.ControlDir, "postgres.log"), "-o", "-c config_file="+path, "-w", "start"); e != nil {
		t.Fatal(e)
	}
	if cert != "" {
		bridgeCtx, stopBridge := context.WithCancel(ctx)
		bridge := exec.CommandContext(bridgeCtx, "/usr/bin/docker", "exec", "--user", "999:999", "--env", "PGWS_NATIVE_TLS_BRIDGE="+filepath.Join(s.SocketDir, "native-tls.sock"), c.ID, filepath.Join(s.ControlDir, "tcp-bridge.test"), "-test.run=^TestSourceTCPBridgeHelper$")
		if err := bridge.Start(); err != nil {
			stopBridge()
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		go func() { finished <- bridge.Wait() }()
		t.Cleanup(func() { stopBridge(); <-finished })
		for {
			if info, err := os.Stat(filepath.Join(s.SocketDir, "native-tls.sock")); err == nil && info.Mode()&os.ModeSocket != 0 {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	return physical.Source{Host: s.SocketDir, Port: 5432, User: "postgres", Database: "postgres", ApprovedDatabases: []string{"postgres"}}, c
}
func labCertificate(t *testing.T, root string) (string, string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PGWS lab"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	// TLS certificates and the Ed25519 serving authority are independent keys.
	// ECDSA/SHA-256 has a defined tls-server-end-point binding for native PG18.
	tlsKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &tlsKey.PublicKey, tlsKey)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(tlsKey)
	if e != nil {
		t.Fatal(e)
	}
	certFile, keyFile := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if e = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); e != nil {
		t.Fatal(e)
	}
	return certFile, keyFile, pub, key
}

func TestLiveHost(t *testing.T) {
	if os.Getenv("PGWS_ZFS_ROOT") == "" {
		t.Skip("run scripts/host_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	root, e := os.MkdirTemp("/tmp", "pgws-host-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	source := labPrimary(t, ctx, root, "source")
	management := labPrimary(t, ctx, root, "management")
	conn, e := source.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(context.Background())
	if _, e = conn.Exec(ctx, "CREATE TABLE fixture(id integer primary key,value text); INSERT INTO fixture VALUES(1,'source')"); e != nil {
		t.Fatal(e)
	}
	pool, e := pgxpool.New(ctx, "host="+management.Host+" user=postgres dbname=postgres sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	if e = migrations.Apply(ctx, pool); e != nil {
		t.Fatal(e)
	}
	tenant, project, actor, epoch := control.ID(), control.ID(), control.ID(), control.ID()
	token := strings.Repeat("f", 64)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	for _, q := range []string{
		fmt.Sprintf("INSERT INTO pgws_control.tenants(id,name) VALUES('%s','lab')", tenant),
		fmt.Sprintf("INSERT INTO pgws_control.projects(tenant_id,id,name) VALUES('%s','%s','lab')", tenant, project),
		fmt.Sprintf("INSERT INTO pgws_control.authority(epoch,reconciled) VALUES('%s',true)", epoch),
		fmt.Sprintf("INSERT INTO pgws_control.api_tokens(token_hash,principal_id,tenant_id,project_id,is_admin,allow_raw,expires_at) VALUES('%s','%s','%s','%s',true,true,now()+interval '1 hour')", hash, actor, tenant, project),
		fmt.Sprintf("INSERT INTO pgws_control.approved_source_references VALUES('%s','%s','lab-source','lab-secret')", tenant, project),
	} {
		if _, e = pool.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	cert, key, pub, signing := labCertificate(t, root)
	secretKey := bytes.Repeat([]byte{7}, 32)
	h, e := Open(Config{ID: "host-lab", Epoch: epoch, Root: filepath.Join(root, "host"), Sockets: filepath.Join(root, "s"), Dataset: os.Getenv("PGWS_ZFS_ROOT"), MountRoot: os.Getenv("PGWS_ZFS_MOUNTS"), GuardBinary: os.Getenv("PGWS_GUARD_BINARY"), Certificate: cert, CertificateKey: key, AuthorityKey: base64.StdEncoding.EncodeToString(pub), SecretKey: base64.StdEncoding.EncodeToString(secretKey), Sources: []SourceConfig{{Tenant: tenant, Project: project, EndpointReference: "lab-source", SecretReference: "lab-secret", Source: source}}})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(h.Config.Root, "objects", "*", "*", "state.json"))
		for _, path := range paths {
			var s state
			b, _ := os.ReadFile(path)
			if json.Unmarshal(b, &s) != nil {
				continue
			}
			cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
			if s.GuardDirectory != "" {
				_ = guardRequest(cleanup, s.GuardDirectory, "shutdown", nil, nil)
			}
			if s.Container.ID != "" {
				_ = h.oci.Remove(cleanup, s.Container)
			}
			done()
		}
	})
	api := (&control.Server{Pool: pool, Epoch: epoch, Physical: true, AuthorityKey: pub, SecretKey: secretKey}).Handler()
	call := func(method, path, body, key string) map[string]json.RawMessage {
		t.Helper()
		r := httptest.NewRequest(method, "/v1/projects/"+project+path, bytes.NewBufferString(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		var value map[string]json.RawMessage
		if e = json.Unmarshal(w.Body.Bytes(), &value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	rpcSocket := filepath.Join(root, "host-rpc.sock")
	listener, e := net.Listen("unix", rpcSocket)
	if e != nil {
		t.Fatal(e)
	}
	rpcToken := strings.Repeat("private-host-token", 4)
	rpcServer := &http.Server{Handler: h.Handler(rpcToken)}
	go rpcServer.Serve(listener)
	defer rpcServer.Close()
	w := control.Worker{Pool: pool, Epoch: epoch, ID: "worker-lab", HostID: "host-lab", SigningKey: signing, Backend: hostclient.Client{Socket: rpcSocket, Token: rpcToken}}
	replayLostResult := func(kind string, activation bool) {
		t.Helper()
		transport := &lostHostResponse{Backend: w.Backend, kind: kind, activation: activation}
		retrying := w
		retrying.Backend = transport
		// SKIP LOCKED and not_before allow an idle claim even after admission.
		// Wait for the operation within a bound, as the real worker loop does.
		deadline := time.Now().Add(3 * time.Second)
		var did bool
		var err error
		for {
			did, err = retrying.Once(ctx)
			if did || err != nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !errors.Is(err, control.ErrHostUnavailable) {
			var states string
			diagnostic := pool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('kind',o.kind,'status',o.status,'step',o.current_step,'revision',o.desired_revision,'actual_revision',w.desired_revision,'generation',o.expected_generation,'actual_generation',w.current_generation,'expiry_remaining',extract(epoch from w.expires_at-clock_timestamp()),'delay',extract(epoch from o.not_before-clock_timestamp()),'error',o.safe_error))::text,'[]') FROM pgws_control.operations o LEFT JOIN pgws_control.workspaces w ON w.id=o.workspace_id WHERE o.kind=$1`, kind).Scan(&states)
			t.Fatal("fixture did not lose the completed host response", kind, did, err, transport.task.Kind, states, diagnostic)
		}
		var status, step string
		if err := pool.QueryRow(ctx, "SELECT status,current_step FROM pgws_control.operations WHERE id=$1", transport.task.Command.Operation).Scan(&status, &step); err != nil || status != "queued" || step != "host_reconciliation" {
			t.Fatal("unknown host result became terminal", status, step, err)
		}
		// Exercise admission without adding five seconds per injected response loss.
		if _, err := pool.Exec(ctx, "UPDATE pgws_control.operations SET not_before=clock_timestamp() WHERE id=$1", transport.task.Command.Operation); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Once(ctx); err != nil {
			t.Fatal("lost host response replay", kind, err)
		}
		var fence int64
		if err := pool.QueryRow(ctx, "SELECT status,fencing_token FROM pgws_control.operations WHERE id=$1", transport.task.Command.Operation).Scan(&status, &fence); err != nil || status != "succeeded" || fence <= transport.task.Command.Token {
			t.Fatal("reclaimed operation did not publish under a newer fence", status, err)
		}
		t.Logf("Lost host response reconciled: kind=%s activation=%t fence=%d->%d", kind, activation, transport.task.Command.Token, fence)
	}
	registered := call("POST", "/sources", `{"connector":"physical","approved_endpoint_reference":"lab-source","secret_reference":"lab-secret"}`, "source")
	var sourceID string
	json.Unmarshal(registered["source_id"], &sourceID)
	replayLostResult("register_source", false)
	var snapshot string
	if e = pool.QueryRow(ctx, `SELECT id::text FROM pgws_control.snapshots WHERE baseline_id=$1 AND state='ready'`, sourceID).Scan(&snapshot); e != nil {
		t.Fatal(e)
	}
	baselineTask := control.Task{Command: lease.Command{Identity: lease.Identity{Workspace: sourceID, Generation: 1}}}
	baseline, e := h.load(baselineTask)
	if e != nil || baseline.Outcome.Source == nil {
		t.Fatal("crash campaign needs the actual baseline snapshot", e)
	}
	testCreateCrashCampaign(t, ctx, h, baseline.Outcome.Source.Snapshot, tenant, project)
	testResetCrashCampaign(t, ctx, h, baseline.Outcome.Source.Snapshot, tenant, project)
	if _, e = conn.Exec(ctx, `INSERT INTO fixture VALUES(2,'fresh')`); e != nil {
		t.Fatal(e)
	}
	barrierDone := make(chan error, 1)
	go func() {
		for {
			did, e := w.Once(ctx)
			if did || e != nil {
				barrierDone <- e
				return
			}
			select {
			case <-ctx.Done():
				barrierDone <- ctx.Err()
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	barrierResult := call("POST", "/sources/"+sourceID+"/barriers", `{"after_commit_asserted":true}`, "barrier")
	if e = <-barrierDone; e != nil {
		t.Fatal("source barrier", e)
	}
	var barrierToken string
	json.Unmarshal(barrierResult["barrier_token"], &barrierToken)
	replayBarrier := call("POST", "/sources/"+sourceID+"/barriers", `{"after_commit_asserted":true}`, "barrier")
	if !bytes.Equal(barrierResult["barrier_token"], replayBarrier["barrier_token"]) {
		t.Fatal("barrier replay changed token")
	}
	created := call("POST", "/workspaces", fmt.Sprintf(`{"baseline_id":%q,"task_id":"lab","freshness":{"mode":"latest"},"resource_profile":"small","ttl_seconds":300}`, sourceID), "create")
	var workspace struct {
		ID string `json:"id"`
	}
	json.Unmarshal(created["workspace"], &workspace)
	replayLostResult("create", false)
	usageClient := &lostUsageAcknowledgement{Client: hostclient.Client{Socket: rpcSocket, Token: rpcToken}}
	collector := w
	collector.Backend = usageClient
	if err := collector.CollectUsage(ctx); !errors.Is(err, control.ErrHostUnavailable) {
		t.Fatal("usage response loss fixture", err)
	}
	if _, err := os.Stat(h.usagePath()); err != nil {
		t.Fatal("unacknowledged usage batch missing", err)
	}
	if err := collector.CollectUsage(ctx); err != nil {
		t.Fatal("usage retry", err)
	}
	var measurements int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pgws_control.usage_events WHERE tenant_id=$1 AND project_id=$2", tenant, project).Scan(&measurements); err != nil || measurements != 7 {
		t.Fatal("usage delivery lost or duplicated measurements", measurements, err)
	}
	history := call("GET", "/usage?limit=2", "", "")
	if len(history["next_cursor"]) == 0 || string(history["measurement_kind"]) != `"observed_gauge"` {
		t.Fatal("real capacity history unavailable")
	}

	// Simulate losing only the final snapshot receipt after ZFS capture. The
	// baseline then advances; replay must retain the pre-capture lower bound.
	createdTask := control.Task{Command: lease.Command{Identity: lease.Identity{Workspace: workspace.ID, Generation: 1}}}
	createdState, e := h.load(createdTask)
	if e != nil {
		t.Fatal(e)
	}
	capturePath := filepath.Join(h.folder(createdState.Task), "capture.json")
	var capture capturePlan
	rawCapture, e := os.ReadFile(capturePath)
	if e != nil || json.Unmarshal(rawCapture, &capture) != nil {
		t.Fatal("capture proof", e)
	}
	beforeCapture := capture.Snapshot
	capture.Complete = false
	capture.Snapshot.Name, capture.Snapshot.GUID = "", ""
	if e = save(capturePath, capture); e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Exec(ctx, "INSERT INTO fixture VALUES(3,'after-capture')"); e != nil {
		t.Fatal(e)
	}
	afterCapture, e := source.CaptureBarrier(ctx)
	if e != nil {
		t.Fatal(e)
	}
	baselineSQL := physical.Source{Host: baseline.Recovery.SocketDir, Port: 5432, User: baseline.Recovery.SourceUser, Database: "postgres"}
	if _, e = physical.WaitReplay(ctx, baselineSQL, afterCapture); e != nil {
		t.Fatal(e)
	}
	recoveredCapture, e := h.capture(ctx, createdState.Task)
	if e != nil || recoveredCapture.GUID != beforeCapture.GUID || recoveredCapture.LowerBound != beforeCapture.LowerBound {
		t.Fatal("lost snapshot response advanced immutable capture evidence", e)
	}
	observed := call("GET", "/workspaces/"+workspace.ID, "", "")
	if string(observed["phase"]) != `"ready"` || len(observed["endpoint"]) == 0 {
		t.Fatal("workspace not published", observed)
	}
	issue := func(generation int64, key string) map[string]json.RawMessage {
		t.Helper()
		finished := make(chan error, 1)
		go func() {
			for {
				did, e := w.Once(ctx)
				if e != nil || did {
					finished <- e
					return
				}
				select {
				case <-ctx.Done():
					finished <- ctx.Err()
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
		}()
		result := call("POST", "/workspaces/"+workspace.ID+"/credentials", fmt.Sprintf(`{"expected_generation":%d,"role":"owner","ttl_seconds":120}`, generation), key)
		if e := <-finished; e != nil {
			t.Fatal("credential worker", e)
		}
		return result
	}
	credential := issue(1, "credential-1")
	connect := func(value map[string]json.RawMessage) *pgx.Conn {
		t.Helper()
		var user, password string
		var endpoint struct {
			Host     string `json:"hostname"`
			Port     int
			Database string
		}
		json.Unmarshal(value["username"], &user)
		json.Unmarshal(value["password"], &password)
		json.Unmarshal(value["endpoint"], &endpoint)
		u := url.URL{Scheme: "postgresql", Host: fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port), Path: "/" + endpoint.Database, User: url.UserPassword(user, password)}
		q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {cert}}
		u.RawQuery = q.Encode()
		c, e := pgx.Connect(ctx, u.String())
		if e != nil {
			t.Fatal("application connection", e)
		}
		return c
	}
	client := connect(credential)
	var fresh string
	if e = client.QueryRow(ctx, "SELECT value FROM fixture WHERE id=2").Scan(&fresh); e != nil || fresh != "fresh" {
		t.Fatal("latest lost committed source data", e)
	}
	defer client.Close(context.Background())
	if _, e = client.Exec(ctx, "UPDATE fixture SET value='workspace'"); e != nil {
		t.Fatal(e)
	}
	var value string
	if e = conn.QueryRow(ctx, "SELECT value FROM fixture WHERE id=1").Scan(&value); e != nil || value != "source" {
		t.Fatal("workspace changed source", e)
	}
	currentAccess, err := h.load(createdTask)
	if err != nil {
		t.Fatal(err)
	}
	testGuardStall(t, ctx, currentAccess, client, signing)
	if err = w.RefreshServing(ctx); err != nil {
		t.Fatal("fresh serving lease after guard stall", err)
	}
	client = connect(credential)
	defer client.Close(context.Background())
	replay := call("POST", "/workspaces/"+workspace.ID+"/credentials", `{"expected_generation":1,"role":"owner","ttl_seconds":120}`, "credential-1")
	if !bytes.Equal(credential["password"], replay["password"]) {
		t.Fatal("credential replay changed secret")
	}
	var stored string
	if e = pool.QueryRow(ctx, `SELECT string_agg(coalesce(safe_result::text,''),'') FROM pgws_control.operations`).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	var password string
	json.Unmarshal(credential["password"], &password)
	if strings.Contains(stored, password) {
		t.Fatal("plaintext credential stored in operations")
	}
	for _, action := range []string{"pause", "resume"} {
		call("POST", "/workspaces/"+workspace.ID+"/actions", fmt.Sprintf(`{"action":%q,"expected_generation":1}`, action), action)
		replayLostResult(action, action == "resume")
	}
	if _, e = client.Exec(ctx, "SELECT 1"); e == nil {
		t.Fatal("pause retained an established session")
	}
	client = connect(credential)
	defer client.Close(context.Background())
	if e = client.QueryRow(ctx, "SELECT value FROM fixture WHERE id=1").Scan(&value); e != nil || value != "workspace" {
		t.Fatal("resume lost local writes", e)
	}
	observed = call("GET", "/workspaces/"+workspace.ID, "", "")
	var expiry time.Time
	json.Unmarshal(observed["expires_at"], &expiry)
	call("POST", "/workspaces/"+workspace.ID+"/actions", fmt.Sprintf(`{"action":"extend_ttl","expected_generation":1,"expected_expires_at":%q,"expires_at":%q}`, expiry.Format(time.RFC3339Nano), expiry.Add(time.Minute).Format(time.RFC3339Nano)), "extend")
	replayLostResult("extend_ttl", false)
	call("POST", "/workspaces/"+workspace.ID+"/actions", fmt.Sprintf(`{"action":"reset","expected_generation":1,"discard_local_changes":true,"baseline_id":%q,"freshness":{"mode":"snapshot","snapshot_id":%q}}`, sourceID, snapshot), "reset")
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("reset", e)
	}
	resetCredential := issue(2, "credential-2")
	resetClient := connect(resetCredential)
	defer resetClient.Close(context.Background())
	if e = resetClient.QueryRow(ctx, "SELECT value FROM fixture WHERE id=1").Scan(&value); e != nil || value != "source" {
		t.Fatal("reset retained old generation writes", e)
	}
	call("DELETE", "/workspaces/"+workspace.ID+"?expected_generation=2", "", "delete")
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("delete", e)
	}
	observed = call("GET", "/workspaces/"+workspace.ID, "", "")
	if string(observed["phase"]) != `"deleted"` {
		t.Fatal("delete not acknowledged")
	}
	leaseFixture := call("POST", "/workspaces", fmt.Sprintf(`{"baseline_id":%q,"task_id":"serving-expiry","freshness":{"mode":"snapshot","snapshot_id":%q},"resource_profile":"small","ttl_seconds":300}`, sourceID, snapshot), "serving-expiry-create")
	var leaseWorkspace struct {
		ID string `json:"id"`
	}
	json.Unmarshal(leaseFixture["workspace"], &leaseWorkspace)
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("serving expiry fixture", e)
	}
	leaseState, e := h.load(control.Task{Command: lease.Command{Identity: lease.Identity{Workspace: leaseWorkspace.ID, Generation: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	testRuntimeLeaseStop(t, ctx, h, leaseState, signing)
	if e = w.ReconcileHost(ctx); e != nil {
		t.Fatal("serving stop reconciliation", e)
	}
	call("DELETE", "/workspaces/"+leaseWorkspace.ID+"?expected_generation=1", "", "serving-expiry-delete")
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("delete stopped serving runtime", e)
	}
	// Expiry cleanup follows its persisted desired revision without actor credentials.
	expired := call("POST", "/workspaces", fmt.Sprintf(`{"baseline_id":%q,"task_id":"expiry","freshness":{"mode":"at_least","barrier_token":%q},"resource_profile":"small","ttl_seconds":300}`, sourceID, barrierToken), "expiry-create")
	var expiring struct {
		ID string `json:"id"`
	}
	json.Unmarshal(expired["workspace"], &expiring)
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("expiry fixture", e)
	}
	if _, e = pool.Exec(ctx, `UPDATE pgws_control.workspaces SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1`, expiring.ID); e != nil {
		t.Fatal(e)
	}
	if count, e := w.SweepExpired(ctx); e != nil || count != 1 {
		t.Fatal("expiry sweep", count, e)
	}
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("expiry cleanup", e)
	}
	observed = call("GET", "/workspaces/"+expiring.ID, "", "")
	if string(observed["phase"]) != `"deleted"` {
		t.Fatal("expired workspace not deleted")
	}
	// Deletion must supersede a physically prepared, unpublished reset generation.
	raced := call("POST", "/workspaces", fmt.Sprintf(`{"baseline_id":%q,"task_id":"reset-race","freshness":{"mode":"snapshot","snapshot_id":%q},"resource_profile":"small","ttl_seconds":300}`, sourceID, snapshot), "race-create")
	var racing struct {
		ID string `json:"id"`
	}
	json.Unmarshal(raced["workspace"], &racing)
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("race fixture", e)
	}
	resetOperation := call("POST", "/workspaces/"+racing.ID+"/actions", fmt.Sprintf(`{"action":"reset","expected_generation":1,"discard_local_changes":true,"baseline_id":%q,"freshness":{"mode":"snapshot","snapshot_id":%q}}`, sourceID, snapshot), "race-reset")
	gate := &preparedResetGate{Backend: w.Backend, prepared: make(chan struct{}), release: make(chan struct{})}
	resetting := w
	resetting.Backend = gate
	resetDone := make(chan error, 1)
	go func() { _, e := resetting.Once(ctx); resetDone <- e }()
	select {
	case <-gate.prepared:
	case e := <-resetDone:
		t.Fatal("reset failed before race", e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	call("DELETE", "/workspaces/"+racing.ID+"?expected_generation=1", "", "race-delete")
	if _, e = w.Once(ctx); e != nil {
		close(gate.release)
		t.Fatal("delete superseding reset", e)
	}
	close(gate.release)
	if e = <-resetDone; e == nil {
		t.Fatal("superseded reset published readiness")
	}
	observed = call("GET", "/workspaces/"+racing.ID, "", "")
	if string(observed["phase"]) != `"deleted"` {
		t.Fatal("raced workspace not deleted")
	}
	var resetID string
	json.Unmarshal(resetOperation["id"], &resetID)
	operation := call("GET", "/operations/"+resetID, "", "")
	if string(operation["status"]) != `"cancelled"` {
		t.Fatal("superseded reset did not terminate")
	}
	for generation := int64(1); generation <= 2; generation++ {
		task := control.Task{}
		task.Command.Workspace = racing.ID
		task.Command.Generation = generation
		st, e := h.load(task)
		if e != nil || st.Phase != "deleted" {
			t.Fatal("reset candidate leaked", generation, e)
		}
	}
	// Deleting before creation also succeeds without inventing a volume GUID.
	cancelled := call("POST", "/workspaces", fmt.Sprintf(`{"baseline_id":%q,"task_id":"cancel-before-start","freshness":{"mode":"snapshot","snapshot_id":%q},"resource_profile":"small","ttl_seconds":300}`, sourceID, snapshot), "cancel-create")
	var cancelledWS struct {
		ID string `json:"id"`
	}
	json.Unmarshal(cancelled["workspace"], &cancelledWS)
	call("DELETE", "/workspaces/"+cancelledWS.ID+"?expected_generation=1", "", "cancel-delete")
	for i := 0; i < 2; i++ {
		if _, e = w.Once(ctx); e != nil {
			t.Fatal("delete before host creation", e)
		}
	}
	observed = call("GET", "/workspaces/"+cancelledWS.ID, "", "")
	if string(observed["phase"]) != `"deleted"` {
		t.Fatal("unstarted workspace did not delete")
	}
	// Old unreferenced snapshots release their service hold and ZFS storage.
	if _, e = pool.Exec(ctx, `UPDATE pgws_control.snapshots SET created_at=now()-interval '2 hours' WHERE id=$1`, snapshot); e != nil {
		t.Fatal(e)
	}
	if count, e := w.SweepSnapshots(ctx); e != nil || count != 1 {
		t.Fatal("snapshot sweep", count, e)
	}
	if _, e = w.Once(ctx); e != nil {
		t.Fatal("snapshot collection", e)
	}
	var snapshotPhase string
	if e = pool.QueryRow(ctx, `SELECT state FROM pgws_control.snapshots WHERE id=$1`, snapshot).Scan(&snapshotPhase); e != nil || snapshotPhase != "deleted" {
		t.Fatal("snapshot deletion not recorded", e)
	}
	if count, e := w.SweepSnapshots(ctx); e != nil || count != 0 {
		t.Fatal("snapshot sweep replay", count, e)
	}
	testSourceReseed(t, ctx, h, pool, &w, sourceID, call, replayLostResult)
	// Exercise the independent WAL guard against a stalled real standby.
	unrelatedSlot := "fixture_" + strings.ReplaceAll(control.ID(), "-", "")
	if _, e = conn.Exec(ctx, "SELECT pg_create_physical_replication_slot($1,true)", unrelatedSlot); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name=$1", unrelatedSlot)
	}()
	sourceTask := control.Task{}
	sourceTask.Command.Workspace = sourceID
	sourceTask.Command.Generation = 2
	baselineState, e := h.load(sourceTask)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.oci.Tools(baselineState.Container).Stop(ctx, baselineState.Recovery.DataDir); e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Exec(ctx, `SET statement_timeout='60s';CREATE TABLE wal_pressure(v bytea);ALTER TABLE wal_pressure ALTER COLUMN v SET STORAGE EXTERNAL;INSERT INTO wal_pressure SELECT repeat('x',16*1024*1024)::bytea FROM generate_series(1,14);CHECKPOINT`); e != nil {
		t.Fatal("WAL pressure fixture", e)
	}
	if e = WatchdogOnce(ctx, h.Config); e != nil {
		t.Fatal("independent WAL guard", e)
	}
	var slots int
	if e = conn.QueryRow(ctx, `SELECT count(*) FROM pg_replication_slots WHERE slot_name=$1`, baselineState.Slot).Scan(&slots); e != nil || slots != 0 {
		t.Fatal("WAL guard retained slot", slots, e)
	}
	if e = conn.QueryRow(ctx, `SELECT count(*) FROM pg_replication_slots WHERE slot_name=$1`, unrelatedSlot).Scan(&slots); e != nil || slots != 1 {
		t.Fatal("WAL guard removed an unrelated slot", slots, e)
	}
	if e = checkStopped(h.folder(sourceTask)); e == nil {
		t.Fatal("WAL guard did not persist terminal source stop")
	}
	if e = WatchdogOnce(ctx, h.Config); e != nil {
		t.Fatal("WAL guard replay", e)
	}
	t.Log("Snapshot hold release and GC, reset/delete race and cancel-before-create, independent WAL watchdog, signed barrier replay, latest and at_least capture, TTL cleanup, API source registration, ZFS clone, TLS credentials and encrypted replay, independent writes, pause/session revocation, resume, TTL extension, reset and delete passed")
}

type preparedResetGate struct {
	control.Backend
	prepared, release chan struct{}
}

type lostHostResponse struct {
	control.Backend
	kind       string
	activation bool
	task       control.Task
}

func (b *lostHostResponse) Execute(ctx context.Context, task control.Task) (control.Outcome, error) {
	b.task = task
	out, err := b.Backend.Execute(ctx, task)
	if err == nil && task.Kind == b.kind && !b.activation {
		return control.Outcome{}, control.ErrHostUnavailable
	}
	return out, err
}

func (b *lostHostResponse) Activate(ctx context.Context, task control.Task, token string) error {
	err := b.Backend.Activate(ctx, task, token)
	if err == nil && task.Kind == b.kind && b.activation {
		return control.ErrHostUnavailable
	}
	return err
}

func (g *preparedResetGate) Execute(ctx context.Context, t control.Task) (control.Outcome, error) {
	out, e := g.Backend.Execute(ctx, t)
	if e != nil || t.Kind != "reset" {
		return out, e
	}
	close(g.prepared)
	select {
	case <-g.release:
		return out, nil
	case <-ctx.Done():
		return out, ctx.Err()
	}
}

type lostUsageAcknowledgement struct {
	hostclient.Client
	lost bool
}

func (c *lostUsageAcknowledgement) AcknowledgeUsage(ctx context.Context, t control.Task) error {
	if !c.lost {
		c.lost = true
		return control.ErrHostUnavailable
	}
	return c.Client.AcknowledgeUsage(ctx, t)
}
