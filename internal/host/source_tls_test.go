package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/physical"
	"pgws/internal/sourcebroker"
)

// This helper runs inside the source container's network=none namespace.
// The host bridge and this helper relay opaque bytes to PG18's native TCP/TLS
// listener. Neither relay terminates TLS or authenticates replication sessions.
func TestSourceTCPBridgeHelper(t *testing.T) {
	socket := os.Getenv("PGWS_NATIVE_TLS_BRIDGE")
	if socket == "" {
		t.Skip("native TLS fixture child")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for {
		client, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer client.Close()
			remote, err := net.DialTimeout("tcp", "127.0.0.1:5432", time.Second)
			if err != nil {
				return
			}
			defer remote.Close()
			relayFixtureBytes(client, remote)
		}()
	}
}

func relayFixtureBytes(client, upstream net.Conn) {
	done := make(chan struct{})
	go func() { io.Copy(upstream, client); upstream.Close(); close(done) }()
	io.Copy(client, upstream)
	client.Close()
	<-done
}

func labSourceTLS(t *testing.T, socket string) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	clients := map[net.Conn]bool{}
	closed := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				client.Close()
				return
			}
			clients[client] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() { client.Close(); mu.Lock(); delete(clients, client); mu.Unlock() }()
				upstream, err := net.DialTimeout("unix", filepath.Join(socket, "native-tls.sock"), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				relayFixtureBytes(client, upstream)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		closed = true
		for client := range clients {
			client.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func TestLiveTCPSource(t *testing.T) {
	if os.Getenv("PGWS_ZFS_ROOT") == "" {
		t.Skip("run scripts/host_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("/tmp", "pgws-tls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	cert, key, public, _ := labCertificate(t, root)
	local := labConfiguredPrimary(t, ctx, root, "source", cert, key)
	conn, err := local.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	password := control.ID()
	if _, err = conn.Exec(ctx, "CREATE TABLE fixture(id integer primary key, value text); INSERT INTO fixture VALUES(1,'source'); ALTER ROLE postgres PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "source", "data", "pg_hba.conf"), []byte("local all all scram-sha-256\nlocal replication all scram-sha-256\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostssl replication all 127.0.0.1/32 scram-sha-256\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "source-password")
	if err = os.WriteFile(secret, []byte(password), 0600); err != nil {
		t.Fatal(err)
	}
	port := labSourceTLS(t, local.Host)
	source := physical.Source{Host: "localhost", Port: port, User: "postgres", Database: "postgres", ApprovedDatabases: []string{"postgres"}, ApprovedAddresses: []string{"127.0.0.1"}, RootCertificate: cert, PasswordFile: secret}
	// Confirm password authentication, independent of the existing trust session.
	bad := source
	bad.PasswordFile = ""
	for {
		probe, err := bad.Connect(ctx)
		if err != nil {
			break
		}
		probe.Close(ctx)
		select {
		case <-ctx.Done():
			t.Fatal("source still trusts passwordless connections")
		case <-time.After(20 * time.Millisecond):
		}
	}
	probe, err := source.Connect(ctx)
	connectDeadline := time.Now().Add(3 * time.Second)
	for err != nil && time.Now().Before(connectDeadline) && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
		probe, err = source.Connect(ctx)
	}
	if err != nil {
		debug, parseErr := pgx.ParseConfig(fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=postgres sslmode=verify-full sslrootcert=%s connect_timeout=3", port, cert))
		if parseErr != nil {
			t.Fatal("fixture diagnostic configuration", parseErr)
		}
		debug.Password = password
		if c, e := pgx.ConnectConfig(ctx, debug); e != nil {
			t.Fatal("TLS source authentication", strings.ReplaceAll(e.Error(), password, "[redacted]"))
		} else {
			c.Close(ctx)
		}
		t.Fatal("TLS source authentication through pinned hostname", err)
	}
	var ssl bool
	var protocol string
	if err = probe.QueryRow(ctx, "SELECT ssl,version FROM pg_stat_ssl WHERE pid=pg_backend_pid()").Scan(&ssl, &protocol); err != nil || !ssl || (protocol != "TLSv1.2" && protocol != "TLSv1.3") {
		t.Fatal("source did not negotiate native PostgreSQL TLS", err)
	}
	probe.Close(ctx)
	if probe, err := bad.Connect(ctx); err == nil {
		probe.Close(ctx)
		t.Fatal("native TLS source accepted a missing password")
	}
	tenant, project, sourceID := control.ID(), control.ID(), control.ID()
	cfg := Config{ID: "tcp-host", Epoch: control.ID(), Root: filepath.Join(root, "host"), Sockets: filepath.Join(root, "s"), Dataset: os.Getenv("PGWS_ZFS_ROOT"), MountRoot: os.Getenv("PGWS_ZFS_MOUNTS"), GuardBinary: os.Getenv("PGWS_GUARD_BINARY"), SourceBrokerBinary: filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgws-host-linux"), Certificate: cert, CertificateKey: key, AuthorityKey: base64.StdEncoding.EncodeToString(public), SecretKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Sources: []SourceConfig{{Tenant: tenant, Project: project, EndpointReference: "tls-source", SecretReference: "tls-secret", Source: source}}}
	h, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { h.Close() }()
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(cfg.Root, "objects", "*", "*", "state.json"))
		for _, path := range paths {
			var s state
			data, err := os.ReadFile(path)
			if err != nil || json.Unmarshal(data, &s) != nil {
				continue
			}
			cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
			_ = stopSourceBroker(cleanup, filepath.Dir(path))
			if s.GuardDirectory != "" {
				_ = guardRequest(cleanup, s.GuardDirectory, "shutdown", nil, nil)
			}
			c := s.Container
			if c.ID == "" && s.RuntimeIntent != nil {
				c, _, _ = h.oci.Lookup(cleanup, *s.RuntimeIntent)
			}
			if c.ID != "" {
				_ = h.oci.Remove(cleanup, c)
			}
			if s.SlotOwned {
				owned := source
				owned.ExpectedSystemID = s.SourceIdentity.SystemID
				_ = owned.DropSlot(cleanup, s.Slot)
			}
			done()
		}
	})
	registration := control.Task{Kind: "register_source", SourceID: sourceID, EndpointReference: "tls-source", SecretReference: "tls-secret", Command: lease.Command{Identity: lease.Identity{Epoch: cfg.Epoch, Host: cfg.ID, Tenant: tenant, Project: project, Workspace: sourceID, Generation: 1, Revision: 1}, Operation: control.ID(), Token: 1}}
	out, err := h.Execute(ctx, registration)
	if err != nil {
		t.Fatal("TCP registration", err)
	}
	controlSocket := filepath.Join(h.folder(registration), "source-broker", "control.sock")
	var before sourcebroker.ProcessStatus
	if err = brokerRequest(ctx, controlSocket, "status", &before); err != nil || before.Config.Identity != registration.Command.Identity || before.PID <= 1 {
		t.Fatal("broker identity", err)
	}
	if err = syscall.Kill(before.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for brokerRequest(ctx, controlSocket, "status", nil) == nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err = conn.Exec(ctx, "INSERT INTO fixture VALUES(2,'after-broker-kill')"); err != nil {
		t.Fatal(err)
	}
	rotated := control.ID()
	if _, err = conn.Exec(ctx, "ALTER ROLE postgres PASSWORD '"+rotated+"'"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(secret, []byte(rotated), 0600); err != nil {
		t.Fatal(err)
	}
	// The normal host daemon must repair an idle source without a create call.
	h.Close()
	configPath, tokenPath := filepath.Join(root, "host.json"), filepath.Join(root, "rpc-token")
	if err = save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenPath, []byte(control.ID()+control.ID()), 0600); err != nil {
		t.Fatal(err)
	}
	process := exec.CommandContext(ctx, cfg.SourceBrokerBinary, configPath, tokenPath)
	var output bytes.Buffer
	process.Stdout, process.Stderr = &output, &output
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	t.Cleanup(func() { _ = process.Process.Kill() })
	var restarted sourcebroker.ProcessStatus
	restartDeadline := time.Now().Add(12 * time.Second)
	for {
		if brokerRequest(ctx, controlSocket, "status", &restarted) == nil && restarted.PID != before.PID {
			break
		}
		if time.Now().After(restartDeadline) {
			t.Fatal("host daemon did not restore idle broker")
		}
		select {
		case err := <-processDone:
			t.Fatalf("maintenance host stopped: %v: %s", err, output.String())
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	baseline, err := h.load(registration)
	if err != nil {
		t.Fatal(err)
	}
	barrier, err := source.CaptureBarrier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	baselineSQL := physical.Source{Host: baseline.Recovery.SocketDir, Port: 5432, User: baseline.Recovery.SourceUser, Database: "postgres"}
	if _, err = physical.WaitReplay(ctx, baselineSQL, barrier); err != nil {
		t.Fatal("idle broker did not restore replication", err)
	}
	if err = process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("maintenance host shutdown: %v: %s", err, output.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance host did not stop")
	}
	h, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(restarted.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for brokerRequest(ctx, controlSocket, "status", nil) == nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err = conn.Exec(ctx, "INSERT INTO fixture VALUES(3,'after-second-kill')"); err != nil {
		t.Fatal(err)
	}
	workspace := registration
	workspace.Kind, workspace.Command.Workspace, workspace.Command.Operation = "create", control.ID(), control.ID()
	workspace.Expiry, workspace.Desired, workspace.Profile = time.Now().UTC().Add(5*time.Minute), "ready", "small"
	workspace.Snapshot, workspace.Freshness = out.Source.Snapshot, &control.Freshness{Mode: "latest"}
	if _, err = h.Execute(ctx, workspace); err != nil {
		t.Fatal("latest after broker kill", err)
	}
	var after sourcebroker.ProcessStatus
	if err = brokerRequest(ctx, controlSocket, "status", &after); err != nil || after.PID == before.PID || after.Config.Identity != before.Config.Identity {
		t.Fatal("broker recovery", err)
	}
	current, err := h.load(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if current.Container.Spec.SourceSocket != "" {
		t.Fatal("workspace inherited upstream socket")
	}
	if err = h.oci.Verify(ctx, current.Container); err != nil {
		t.Fatal("workspace isolation", err)
	}
	private := physical.Source{Host: current.Recovery.SocketDir, Port: 5432, User: current.Access.Admin, Database: "postgres"}
	check, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	err = check.QueryRow(ctx, "SELECT value FROM public.fixture WHERE id=2").Scan(&value)
	check.Close(ctx)
	if err != nil || value != "after-broker-kill" {
		t.Fatal("lost source commit after broker recovery", err)
	}
	check, err = private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = check.QueryRow(ctx, "SELECT value FROM public.fixture WHERE id=3").Scan(&value)
	check.Close(ctx)
	if err != nil || value != "after-second-kill" {
		t.Fatal("latest capture did not recover broker", err)
	}
	oldControl := controlSocket
	registration.Kind = "reseed_source"
	registration.Command.Generation, registration.Command.Revision = 2, 2
	registration.Command.Token++
	registration.Command.Operation = control.ID()
	registration.Snapshot = control.Snapshot{Baseline: control.ID(), BaselineGeneration: 2, SourceEpoch: 2}
	reseeded, err := h.Execute(ctx, registration)
	if err != nil {
		t.Fatal("TCP reseed", err)
	}
	controlSocket = filepath.Join(h.folder(registration), "source-broker", "control.sock")
	var reseedBroker sourcebroker.ProcessStatus
	if err = brokerRequest(ctx, controlSocket, "status", &reseedBroker); err != nil || reseedBroker.Config.Identity != registration.Command.Identity || reseedBroker.Config.Socket == after.Config.Socket {
		t.Fatal("TCP reseed broker generation", err)
	}
	if brokerRequest(ctx, oldControl, "status", nil) == nil {
		t.Fatal("retired TCP broker still running")
	}
	check, err = private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal("old TCP workspace after reseed", err)
	}
	err = check.QueryRow(ctx, "SELECT value FROM public.fixture WHERE id=3").Scan(&value)
	check.Close(ctx)
	if err != nil || value != "after-second-kill" {
		t.Fatal("TCP reseed damaged prior workspace", err)
	}
	nextWorkspace := workspace
	nextWorkspace.Command.Workspace, nextWorkspace.Command.Operation = control.ID(), control.ID()
	nextWorkspace.Snapshot = reseeded.Source.Snapshot
	if _, err = h.Execute(ctx, nextWorkspace); err != nil {
		t.Fatal("TCP new generation capture", err)
	}
	nextWorkspace.Kind, nextWorkspace.Command.Operation = "delete", control.ID()
	nextWorkspace.Command.Token++
	nextWorkspace.Command.Revision++
	if _, err = h.Execute(ctx, nextWorkspace); err != nil {
		t.Fatal("TCP new generation workspace cleanup", err)
	}
	workspace.Kind, workspace.Command.Operation = "delete", control.ID()
	workspace.Command.Token++
	workspace.Command.Revision++
	if _, err = h.Execute(ctx, workspace); err != nil {
		t.Fatal("TCP workspace deletion", err)
	}
	registration.Command.Token++
	if err = h.Revoke(ctx, registration); err != nil {
		t.Fatal("TCP source revoke", err)
	}
	if err = h.MaintainSources(ctx); err != nil {
		t.Fatal("maintenance after revoke", err)
	}
	if brokerRequest(ctx, controlSocket, "status", nil) == nil {
		t.Fatal("revoked broker still running")
	}
	var slots int
	if err = conn.QueryRow(ctx, "SELECT count(*) FROM pg_replication_slots WHERE slot_name LIKE 'pgws_%'").Scan(&slots); err != nil || slots != 0 {
		t.Fatal("TCP source retained owned slot", slots, err)
	}
	t.Log("Real PG18 SCRAM through pinned verify-full TLS: basebackup, streaming, password rotation and idle daemon recovery, latest after broker SIGKILL, reseed with a separate broker generation, preserved old workspace, new generation capture and source revocation passed")
}
