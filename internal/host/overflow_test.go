package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/physical"
)

func TestLiveOverflowZFS(t *testing.T) {
	if os.Getenv("PGWS_ZFS_ROOT") == "" {
		t.Skip("run scripts/host_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("/tmp", "pgws-overflow-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	source, primary := labPrimaryRuntime(t, ctx, root, "source", "", "")
	conn, err := source.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { conn.Close(context.Background()) }()
	if _, err = conn.Exec(ctx, "CREATE TABLE fixture(id integer primary key,value text); INSERT INTO fixture VALUES(1,'source')"); err != nil {
		t.Fatal(err)
	}
	cert, key, public, _ := labCertificate(t, root)
	tenant, project, sourceID := control.ID(), control.ID(), control.ID()
	cfg := Config{ID: "overflow-host", Epoch: control.ID(), Root: filepath.Join(root, "host"), Sockets: filepath.Join(root, "s"), Dataset: os.Getenv("PGWS_ZFS_ROOT"), MountRoot: os.Getenv("PGWS_ZFS_MOUNTS"), GuardBinary: os.Getenv("PGWS_GUARD_BINARY"), Certificate: cert, CertificateKey: key, AuthorityKey: base64.StdEncoding.EncodeToString(public), Sources: []SourceConfig{{Tenant: tenant, Project: project, EndpointReference: "source", SecretReference: "secret", Source: source}}}
	h, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(cfg.Root, "objects", "*", "*", "state.json"))
		for _, path := range paths {
			var s state
			data, err := os.ReadFile(path)
			if err != nil || json.Unmarshal(data, &s) != nil {
				continue
			}
			cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
			if s.GuardDirectory != "" {
				_ = guardRequest(cleanup, s.GuardDirectory, "shutdown", nil, nil)
			}
			container := s.Container
			if container.ID == "" && s.RuntimeIntent != nil {
				container, _, _ = h.oci.Lookup(cleanup, *s.RuntimeIntent)
			}
			if container.ID != "" {
				_ = h.oci.Remove(cleanup, container)
			}
			done()
		}
	})
	registration := control.Task{Kind: "register_source", SourceID: sourceID, EndpointReference: "source", SecretReference: "secret", Command: lease.Command{Identity: lease.Identity{Epoch: cfg.Epoch, Host: cfg.ID, Tenant: tenant, Project: project, Workspace: sourceID, Generation: 1, Revision: 1}, Operation: control.ID(), Token: 1}}
	registered, err := h.Execute(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	long, err := source.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer long.Close(context.Background())
	tx, err := long.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	for i := 0; i < 70; i++ {
		if _, err = tx.Exec(ctx, fmt.Sprintf("SAVEPOINT s%d", i)); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO fixture VALUES($1,'uncommitted')", 100+i); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.Exec(ctx, "INSERT INTO fixture VALUES(999,'committed'); CHECKPOINT"); err != nil {
		t.Fatal(err)
	}
	barrier, err := source.CaptureBarrier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := h.load(registration)
	if err != nil {
		t.Fatal(err)
	}
	baselineSQL := physical.Source{Host: baseline.Recovery.SocketDir, Port: 5432, User: baseline.Recovery.SourceUser, Database: "postgres"}
	if _, err = physical.WaitReplay(ctx, baselineSQL, barrier); err != nil {
		t.Fatal(err)
	}
	replica, err := baselineSQL.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = replica.Exec(ctx, "CHECKPOINT"); err != nil {
		replica.Close(ctx)
		t.Fatal(err)
	}
	replica.Close(ctx)
	workspace := registration
	workspace.Kind, workspace.Command.Workspace, workspace.Command.Operation = "create", control.ID(), control.ID()
	workspace.Expiry, workspace.Desired, workspace.Profile = time.Now().UTC().Add(5*time.Minute), "ready", "small"
	workspace.Snapshot, workspace.Freshness = registered.Source.Snapshot, &control.Freshness{Mode: "latest"}
	blockedStandby := false
	h.afterCreateEffect = func(stage string) {
		if stage == "clone" {
			// Capture is complete. Stop the actual source while its 70 nested
			// transactions were still open at capture, before clone startup.
			if err := h.oci.Tools(primary).Stop(ctx, primary.Spec.DataDir); err != nil {
				t.Fatal("disconnect source after ZFS capture", err)
			}
		}
		if stage == "start" {
			s, err := h.load(workspace)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				log, _ := os.ReadFile(filepath.Join(s.Recovery.ControlDir, "postgres.log"))
				if strings.Contains(string(log), "consistent recovery state reached") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("clone did not reach consistent recovery")
				}
				time.Sleep(20 * time.Millisecond)
			}
			probe, stop := context.WithTimeout(ctx, 250*time.Millisecond)
			private := physical.Source{Host: s.Recovery.SocketDir, Port: 5432, User: s.Recovery.SourceUser, Database: "postgres"}
			c, err := private.ConnectPrivateAdmin(probe)
			stop()
			if err == nil {
				c.Close(ctx)
				t.Fatal("fixture did not reproduce unavailable standby SQL")
			}
			blockedStandby = true
		}
	}
	created, err := h.Execute(ctx, workspace)
	h.afterCreateEffect = nil
	if err != nil || !blockedStandby || created.Snapshot == nil {
		t.Fatal("disconnected overflow clone", err)
	}
	first, err := h.load(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if first.Container.Spec.SourceSocket != "" {
		t.Fatal("disconnected clone has an upstream mount")
	}
	verifyRows := func(s state) {
		t.Helper()
		private := physical.Source{Host: s.Recovery.SocketDir, Port: 5432, User: s.Access.Admin, Database: "postgres"}
		c, err := private.ConnectPrivateAdmin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		var count int
		if err = c.QueryRow(ctx, "SELECT count(*) FROM public.fixture").Scan(&count); err != nil || count != 2 {
			t.Fatal("overflow recovery included unfinished rows or lost committed rows", count, err)
		}
		var value string
		if err = c.QueryRow(ctx, "SELECT value FROM public.fixture WHERE id=999").Scan(&value); err != nil || value != "committed" {
			t.Fatal("committed source row missing", err)
		}
	}
	verifyRows(first)
	tools := h.oci.Tools(first.Container)
	if err = tools.StopDisconnected(ctx, first.Recovery); err != nil {
		t.Fatal(err)
	}
	if err = tools.StartDisconnected(ctx, first.Recovery); err != nil {
		t.Fatal(err)
	}
	if _, err = physical.VerifyPromoted(ctx, first.Recovery, first.Access.Admin); err != nil {
		t.Fatal("overflow proof after primary restart", err)
	}
	verifyRows(first)
	sibling := workspace
	sibling.Command.Workspace, sibling.Command.Operation = control.ID(), control.ID()
	sibling.Snapshot, sibling.Freshness = *created.Snapshot, &control.Freshness{Mode: "snapshot", SnapshotID: created.Snapshot.ID}
	if _, err = h.Execute(ctx, sibling); err != nil {
		t.Fatal("sibling from disconnected source capture", err)
	}
	second, err := h.load(sibling)
	if err != nil {
		t.Fatal(err)
	}
	private := physical.Source{Host: first.Recovery.SocketDir, Port: 5432, User: first.Access.Admin, Database: "postgres"}
	writable, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writable.Exec(ctx, "UPDATE public.fixture SET value='branch' WHERE id=1"); err != nil {
		writable.Close(ctx)
		t.Fatal(err)
	}
	writable.Close(ctx)
	workspace.Kind, workspace.Command.Operation = "delete", control.ID()
	workspace.Command.Token++
	workspace.Command.Revision++
	if _, err = h.Execute(ctx, workspace); err != nil {
		t.Fatal(err)
	}
	verifyRows(second)
	private.Host, private.User = second.Recovery.SocketDir, second.Access.Admin
	other, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	err = other.QueryRow(ctx, "SELECT value FROM public.fixture WHERE id=1").Scan(&value)
	other.Close(ctx)
	if err != nil || value != "source" {
		t.Fatal("sibling changed after other workspace write/deletion", err)
	}
	// Point only this watchdog fixture at a real promoted child of the source.
	// It has the same system identifier but a new timeline. The established
	// baseline must stop instead of silently adopting that lineage.
	hbaPath := filepath.Join(second.Recovery.ControlDir, "hba.conf")
	hba, err := os.ReadFile(hbaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(hbaPath, append(hba, []byte("local replication "+second.Access.Admin+" trust\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	upstreamAdmin, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = upstreamAdmin.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
		upstreamAdmin.Close(ctx)
		t.Fatal(err)
	}
	upstreamAdmin.Close(ctx)
	forkIdentity, err := private.Identify(ctx)
	identityDeadline := time.Now().Add(3 * time.Second)
	for err != nil && time.Now().Before(identityDeadline) {
		time.Sleep(20 * time.Millisecond)
		forkIdentity, err = private.Identify(ctx)
	}
	if err != nil || forkIdentity.SystemID != baseline.SourceIdentity.SystemID || forkIdentity.Timeline == baseline.SourceIdentity.Timeline {
		t.Fatal("fixture has no actual source timeline transition", err)
	}
	watchConfig := h.Config
	watchConfig.Sources = append([]SourceConfig(nil), h.Config.Sources...)
	watchConfig.Sources[0].Source = private
	if err = WatchdogOnce(ctx, watchConfig); err != nil {
		t.Fatal("source timeline watchdog", err)
	}
	stop, err := readStop(h.folder(registration))
	if err != nil || stop.Reason != "SOURCE_LINEAGE_CHANGED" {
		t.Fatal("source timeline transition did not become terminal", err)
	}
	observationTask := registration
	observationTask.Kind = "observe_source"
	observation, err := h.Observe(ctx, observationTask)
	if err != nil || !observation.Stopped || observation.Reason != "SOURCE_LINEAGE_CHANGED" {
		t.Fatal("timeline stop observation", err)
	}
	if err = h.MaintainSources(ctx); err != nil {
		t.Fatal(err)
	}
	if err = h.oci.VerifyAbsent(ctx, registration.Command.Identity); err != nil {
		t.Fatal("maintenance revived an old timeline", err)
	}
	verifyRows(second)
	sibling.Kind, sibling.Command.Operation = "delete", control.ID()
	sibling.Command.Token++
	sibling.Command.Revision++
	if _, err = h.Execute(ctx, sibling); err != nil {
		t.Fatal(err)
	}
	primaryTools := h.oci.Tools(primary)
	if _, err = primaryTools.Executor.Run(ctx, "pg_ctl", nil, "-D", primary.Spec.DataDir, "-l", filepath.Join(primary.Spec.ControlDir, "postgres.log"), "-o", "-c config_file="+filepath.Join(primary.Spec.ControlDir, "postgresql.conf"), "-w", "start"); err != nil {
		t.Fatal(err)
	}
	conn, err = source.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.QueryRow(ctx, "SELECT value FROM fixture WHERE id=1").Scan(&value); err != nil || value != "source" {
		t.Fatal("workspace changed source", err)
	}
	registration.Command.Token++
	if err = h.Revoke(ctx, registration); err != nil {
		t.Fatal(err)
	}
	// A different system may coincidentally contain a slot with the same name.
	// Stop our old runtime, but never delete that foreign system's slot.
	replacement := registration
	replacement.SourceID = control.ID()
	replacement.Command.Workspace, replacement.Command.Operation, replacement.Command.Token = replacement.SourceID, control.ID(), 1
	if _, err = h.Execute(ctx, replacement); err != nil {
		t.Fatal("second lineage fixture", err)
	}
	pending, err := h.load(replacement)
	if err != nil {
		t.Fatal(err)
	}
	foreign := labPrimary(t, ctx, root, "foreign")
	foreignConn, err := foreign.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignConn.Close(context.Background())
	if _, err = foreignConn.Exec(ctx, "SELECT pg_create_physical_replication_slot($1,true)", pending.Slot); err != nil {
		t.Fatal(err)
	}
	watchConfig.Sources[0].Source = foreign
	if err = WatchdogOnce(ctx, watchConfig); err == nil {
		t.Fatal("watchdog claimed cleanup of a foreign source system")
	}
	stop, err = readStop(h.folder(replacement))
	if err != nil || stop.Reason != "SOURCE_LINEAGE_CHANGED" {
		t.Fatal("changed system identifier did not block source", err)
	}
	if err = h.oci.VerifyAbsent(ctx, replacement.Command.Identity); err != nil {
		t.Fatal("old runtime survived source replacement", err)
	}
	var foreignSlots int
	if err = foreignConn.QueryRow(ctx, "SELECT count(*) FROM pg_replication_slots WHERE slot_name=$1", pending.Slot).Scan(&foreignSlots); err != nil || foreignSlots != 1 {
		t.Fatal("watchdog removed a foreign system's same-name slot", err)
	}
	replacement.Command.Token++
	if err = h.Revoke(ctx, replacement); err != nil {
		t.Fatal("original source's confirmed slot cleanup", err)
	}
	if _, err = foreignConn.Exec(ctx, "SELECT pg_drop_replication_slot($1)", pending.Slot); err != nil {
		t.Fatal(err)
	}
	t.Log("Real ZFS capture with 70 open subtransactions: source stopped before clone startup, standby SQL unavailable, promotion/current proof after restart, committed rows only, sibling-safe deletion and terminal watchdog stop on a real timeline transition passed")
	t.Log("Changed source system identifier blocks ingestion and removes only the owned runtime; the foreign system's same-name replication slot remains intact")
}
