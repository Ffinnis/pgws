package physical

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestParseLSN(t *testing.T) {
	for _, bad := range []string{"", "1", "1/1/1", "100000000/0", "0/100000000", "-1/0"} {
		if _, e := ParseLSN(bad); e == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	v, e := ParseLSN("FFFFFFFF/FFFFFFFF")
	if e != nil || v != ^uint64(0) {
		t.Fatal(v, e)
	}
}

func TestOverflowSubtransactionRecovery(t *testing.T) {
	if os.Getenv("PGWS_PHYSICAL_LAB") != "1" {
		t.Skip("run scripts/physical_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root := t.TempDir()
	bin := os.Getenv("PGWS_PG_BIN")
	tools := Tools{BinDir: bin}
	run := func(name string, args ...string) {
		t.Helper()
		out, e := exec.CommandContext(ctx, filepath.Join(bin, name), args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s: %v %s", name, e, out)
		}
	}
	data, socket := filepath.Join(root, "source"), filepath.Join(root, "source-socket")
	os.Mkdir(socket, 0700)
	run("initdb", "-D", data, "-U", "postgres", "--auth-local=trust", "--auth-host=reject", "--encoding=UTF8", "--no-locale")
	f, _ := os.OpenFile(filepath.Join(data, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("\nlisten_addresses=''\nunix_socket_directories='" + socket + "'\nmax_connections=20\nmax_wal_senders=10\nmax_worker_processes=8\nshared_buffers='32MB'\nwal_level=replica\ncheckpoint_completion_target=0\nmax_slot_wal_keep_size='128MB'\n")
	f.Close()
	run("pg_ctl", "-D", data, "-l", filepath.Join(root, "source.log"), "-w", "start")
	stop := func(dir string) {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_ = tools.Stop(c, dir)
	}
	defer stop(data)
	source := Source{Host: socket, Port: 5432, User: "postgres", Database: "postgres", ApprovedDatabases: []string{"postgres"}}
	conn, e := source.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(context.Background())
	if _, e = conn.Exec(ctx, "CREATE TABLE fixture(id integer PRIMARY KEY)"); e != nil {
		t.Fatal(e)
	}
	m, e := source.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	initial, e := source.CaptureBarrier(ctx)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := tools.Seed(ctx, source, root, "10000000-0000-4000-8000-000000000002", 1, 256<<20)
	if e != nil {
		t.Fatal(e)
	}
	baseline := Recovery{DataDir: seed.DataDir, ControlDir: filepath.Join(root, "baseline-control"), SocketDir: filepath.Join(root, "baseline-socket"), SourceUser: "postgres", Barrier: initial, Settings: m.Settings}
	if e = tools.PrepareDisconnected(baseline); e != nil {
		t.Fatal(e)
	}
	// Only this test fixture enables replication, through a socket inside the
	// network-disabled container. This is not the disconnected clone config.
	f, _ = os.OpenFile(filepath.Join(baseline.ControlDir, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("primary_conninfo='host=" + socket + " user=postgres port=5432'\n")
	f.Close()
	if e = tools.StartDisconnected(ctx, baseline); e != nil {
		t.Fatal(e)
	}
	defer stop(baseline.DataDir)
	replica := Source{Host: baseline.SocketDir, Port: 5432, User: "postgres", Database: "postgres"}
	var ready bool
	for i := 0; i < 100; i++ {
		c, e := replica.Connect(ctx)
		if e == nil {
			var recovery bool
			e = c.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery)
			c.Close(context.Background())
			if e == nil && recovery {
				ready = true
				break
			}
		}
		wait(ctx, 50*time.Millisecond)
	}
	if !ready {
		t.Fatal("baseline never became queryable")
	}
	txn, e := conn.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer txn.Rollback(context.Background())
	for i := 0; i < 70; i++ {
		if _, e = txn.Exec(ctx, fmt.Sprintf("SAVEPOINT s%d", i)); e != nil {
			t.Fatal(e)
		}
		if _, e = txn.Exec(ctx, "INSERT INTO fixture VALUES($1)", i); e != nil {
			t.Fatal(e)
		}
	}
	checkpoint, e := source.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer checkpoint.Close(context.Background())
	if _, e = checkpoint.Exec(ctx, "INSERT INTO fixture VALUES(999); CHECKPOINT"); e != nil {
		t.Fatal(e)
	}
	barrier, e := source.CaptureBarrier(ctx)
	if e != nil {
		t.Fatal(e)
	}
	rc, e := replica.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for {
		var reached bool
		if e = rc.QueryRow(ctx, "SELECT pg_last_wal_replay_lsn()>=$1::pg_lsn", barrier.LSN).Scan(&reached); e != nil {
			t.Fatal(e)
		}
		if reached {
			break
		}
		if e = wait(ctx, 20*time.Millisecond); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = rc.Exec(ctx, "CHECKPOINT"); e != nil {
		t.Fatal(e)
	}
	rc.Close(context.Background())
	if e = tools.Stop(ctx, baseline.DataDir); e != nil {
		t.Fatal(e)
	}
	cloneDir := filepath.Join(root, "clone")
	if out, e := exec.CommandContext(ctx, "/bin/cp", "-a", baseline.DataDir, cloneDir).CombinedOutput(); e != nil {
		t.Fatalf("offline fixture capture: %v %s", e, out)
	}
	clone := Recovery{DataDir: cloneDir, ControlDir: filepath.Join(root, "clone-control"), SocketDir: filepath.Join(root, "clone-socket"), SourceUser: "postgres", Barrier: barrier, Settings: m.Settings}
	if e = tools.PrepareDisconnected(clone); e != nil {
		t.Fatal(e)
	}
	if e = tools.StartDisconnected(ctx, clone); e != nil {
		t.Fatal(e)
	}
	defer stop(clone.DataDir)
	consistent := false
	for i := 0; i < 100; i++ {
		log, _ := os.ReadFile(filepath.Join(clone.ControlDir, "postgres.log"))
		if strings.Contains(string(log), "consistent recovery state reached") {
			consistent = true
			break
		}
		wait(ctx, 50*time.Millisecond)
	}
	if !consistent {
		log, _ := os.ReadFile(filepath.Join(clone.ControlDir, "postgres.log"))
		t.Fatalf("clone never reached consistency: %s", log)
	}
	blockedCtx, done := context.WithTimeout(ctx, 500*time.Millisecond)
	cc, connectErr := (Source{Host: clone.SocketDir, Port: 5432, User: "postgres", Database: "postgres"}).Connect(blockedCtx)
	done()
	if connectErr == nil {
		cc.Close(context.Background())
		t.Fatal("fixture did not reproduce unavailable standby SQL")
	}
	evidence, e := tools.PromoteAndVerify(ctx, clone)
	if e != nil {
		log, _ := os.ReadFile(filepath.Join(clone.ControlDir, "postgres.log"))
		t.Fatalf("overflow promotion: %v %s", e, log)
	}
	cc, e = (Source{Host: clone.SocketDir, Port: 5432, User: "postgres", Database: "postgres"}).Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer cc.Close(context.Background())
	var count int
	if e = cc.QueryRow(ctx, "SELECT count(*) FROM fixture").Scan(&count); e != nil || count != 1 {
		t.Fatal("uncommitted rows became visible", count, e)
	}
	var sourceCount int
	if e = txn.QueryRow(ctx, "SELECT count(*) FROM fixture").Scan(&sourceCount); e != nil || sourceCount != 71 {
		t.Fatal("source transaction did not remain open", sourceCount, e)
	}
	output, _ := json.Marshal(map[string]any{"case": "overflowed_subtransactions", "subtransactions": 70, "standby_sql_unavailable": true, "source_transaction_still_open": true, "visible_committed_rows": count, "evidence": evidence, "capture": "offline standby directory copy, not ZFS"})
	t.Log(string(output))
}
func TestRejectUnsafeArchive(t *testing.T) {
	for _, name := range []string{"../escape", "/tmp/escape"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "archive.tar")
			f, _ := os.Create(path)
			w := tar.NewWriter(f)
			w.WriteHeader(&tar.Header{Name: name, Size: 1, Mode: 0600})
			w.Write([]byte("x"))
			w.Close()
			f.Close()
			budget := int64(100)
			if e := extract(path, filepath.Join(dir, "data"), &budget); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	dir := t.TempDir()
	f, _ := os.Create(filepath.Join(dir, "link.tar"))
	w := tar.NewWriter(f)
	w.WriteHeader(&tar.Header{Name: "pg_wal", Typeflag: tar.TypeSymlink, Linkname: "/tmp"})
	w.Close()
	f.Close()
	budget := int64(100)
	if e := extract(filepath.Join(dir, "link.tar"), dir, &budget); e == nil {
		t.Fatal("symlink accepted")
	}
}

// This test is enabled only by scripts/physical_lab.py in a network-disabled,
// disposable PostgreSQL 18 container. It is a recovery test, not a ZFS test.
func TestPhysicalLab(t *testing.T) {
	if os.Getenv("PGWS_PHYSICAL_LAB") != "1" {
		t.Skip("run scripts/physical_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
	bin := os.Getenv("PGWS_PG_BIN")
	tools := Tools{BinDir: bin}
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(bin, name), args...)
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("%s: %v\n%s", name, e, b)
		}
	}
	data, socket := filepath.Join(root, "source"), filepath.Join(root, "source-socket")
	os.Mkdir(socket, 0700)
	run("initdb", "-D", data, "-U", "postgres", "--auth-local=trust", "--auth-host=reject", "--encoding=UTF8", "--no-locale")
	f, _ := os.OpenFile(filepath.Join(data, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("\nlisten_addresses = ''\nunix_socket_directories = '" + socket + "'\nmax_connections=20\nmax_wal_senders=10\nmax_worker_processes=8\nshared_buffers='32MB'\nwal_level=replica\ncheckpoint_completion_target=0\nmax_slot_wal_keep_size='128MB'\n")
	f.Close()
	run("pg_ctl", "-D", data, "-l", filepath.Join(root, "source.log"), "-w", "start")
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_ = tools.Stop(stop, data)
	}()
	source := Source{Host: socket, Port: 5432, User: "postgres", Database: "postgres", ApprovedDatabases: []string{"postgres"}}
	conn, e := source.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(context.Background())
	if _, e = conn.Exec(ctx, `CREATE TABLE public.fixture(id integer primary key, value text); INSERT INTO public.fixture VALUES(1,'committed source row');
CREATE TYPE public.fixture_state AS ENUM ('pending');
CREATE DOMAIN public.fixture_positive AS integer CHECK (VALUE > 0);
CREATE TYPE public.fixture_pair AS (id integer, value text);
CREATE AGGREGATE public.fixture_sum(integer) (sfunc=int4pl, stype=integer, initcond='0');
CREATE PROCEDURE public.imported_write() LANGUAGE SQL SECURITY DEFINER AS 'DELETE FROM public.fixture';`); e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Exec(ctx, `CREATE FUNCTION public.pg_is_in_recovery() RETURNS boolean LANGUAGE SQL AS 'SELECT true'; ALTER ROLE postgres SET search_path=public,pg_catalog; ALTER ROLE postgres SET synchronous_commit=off`); e != nil {
		t.Fatal(e)
	}
	unsafeDefaults, e := source.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var shadowed bool
	var commitMode string
	if e = unsafeDefaults.QueryRow(ctx, "SELECT pg_is_in_recovery(),current_setting('synchronous_commit')").Scan(&shadowed, &commitMode); e != nil || !shadowed || commitMode != "off" {
		t.Fatal("hostile session default fixture was not applied", e)
	}
	unsafeDefaults.Close(context.Background())
	inspector, e := source.ConnectAdmin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = inspector.QueryRow(ctx, "SELECT pg_is_in_recovery(),current_setting('synchronous_commit')").Scan(&shadowed, &commitMode); e != nil || shadowed || commitMode != "on" {
		t.Fatal("source role defaults shadowed administrative catalog calls", e)
	}
	inspector.Close(context.Background())
	m, e := source.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.RequireSeedable(); e != nil {
		t.Fatal(e)
	}
	source.ExpectedSystemID = m.SystemID
	barrier, e := source.CaptureBarrier(ctx)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := tools.Seed(ctx, source, root, "10000000-0000-4000-8000-000000000001", 1, 256<<20)
	if e != nil {
		t.Fatal(e)
	}
	if !seed.Verified || seed.ContinuousReplication {
		t.Fatal(seed)
	}
	if _, e = os.Lstat(filepath.Join(filepath.Dir(seed.DataDir), "source.pgpass")); !os.IsNotExist(e) {
		t.Fatal("temporary source secret remains after backup")
	}
	// Inject copied configuration hooks to verify the helper overrides the entire
	// imported config chain. These must never run during disconnected recovery.
	marker := filepath.Join(root, "unsafe-hook-ran")
	os.WriteFile(filepath.Join(seed.DataDir, "postgresql.auto.conf"), []byte("shared_preload_libraries='missing_unsafe_library'\narchive_mode=on\narchive_command='touch "+marker+"'\n"), 0600)
	r := Recovery{DataDir: seed.DataDir, ControlDir: filepath.Join(root, "clone-control"), SocketDir: filepath.Join(root, "clone-socket"), SourceUser: "postgres", Barrier: barrier, Settings: m.Settings}
	if e = tools.PrepareDisconnected(r); e != nil {
		t.Fatal(e)
	}
	t.Run("changed_recovery_plan_rejected", func(t *testing.T) {
		changed := r
		changed.Barrier.SystemID = "1"
		if e := tools.StartDisconnected(ctx, changed); e == nil {
			t.Fatal("changed source identity accepted")
		}
		changed = r
		changed.ControlDir += ";false"
		if e := tools.StartDisconnected(ctx, changed); e == nil {
			t.Fatal("shell metacharacters accepted")
		}
	})
	if e = tools.StartDisconnected(ctx, r); e != nil {
		t.Fatal(e)
	}
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_ = tools.Stop(stop, r.DataDir)
	}()
	evidence, e := tools.PromoteAndVerify(ctx, r)
	if e != nil {
		log, _ := os.ReadFile(filepath.Join(r.ControlDir, "postgres.log"))
		t.Fatalf("recovery: %v\n%s", e, log)
	}
	clone := Source{Host: r.SocketDir, Port: 5432, User: "postgres", Database: "postgres"}
	if _, e = tools.PromoteAndVerify(ctx, r); e != nil {
		t.Fatal("lost promotion response replay", e)
	}
	for i := 0; i < 2; i++ {
		if e = tools.StopDisconnected(ctx, r); e != nil {
			t.Fatal("shutdown replay", e)
		}
	}
	for i := 0; i < 2; i++ {
		if e = tools.StartDisconnected(ctx, r); e != nil {
			t.Fatal("start replay", e)
		}
	}
	if _, e = VerifyPromoted(ctx, r, "postgres"); e != nil {
		t.Fatal("promoted primary restart lost timeline recovery proof", e)
	}
	cc, e := clone.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer cc.Close(context.Background())
	var value string
	if e = cc.QueryRow(ctx, "SELECT value FROM fixture WHERE id=1").Scan(&value); e != nil || value != "committed source row" {
		t.Fatal(value, e)
	}
	if _, e = cc.Exec(ctx, "UPDATE fixture SET value='clone-local change' WHERE id=1"); e != nil {
		t.Fatal(e)
	}
	if e = conn.QueryRow(ctx, "SELECT value FROM fixture WHERE id=1").Scan(&value); e != nil || value != "committed source row" {
		t.Fatal("source changed", value, e)
	}
	if _, e = os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("imported archive hook executed")
	}
	var listen string
	cc.QueryRow(ctx, "SHOW listen_addresses").Scan(&listen)
	if listen != "" {
		t.Fatal("TCP endpoint enabled")
	}
	var slots int
	conn.QueryRow(ctx, "SELECT count(*) FROM pg_replication_slots").Scan(&slots)
	if slots != 0 {
		t.Fatal("backup slot leaked")
	}
	output, _ := json.Marshal(map[string]any{"case": "verified_seed_and_disconnected_recovery", "server_version": m.ServerVersion, "evidence": evidence, "source_unchanged": true, "slots_after_backup": slots, "storage": "ordinary files; no ZFS qualification"})
	t.Log(string(output))
	t.Run("missing_wal_never_verifies", func(t *testing.T) {
		bad := r
		bad.DataDir = filepath.Join(root, "missing-wal-data")
		bad.ControlDir = filepath.Join(root, "missing-wal-control")
		bad.SocketDir = filepath.Join(root, "missing-wal-socket")
		archive := filepath.Join(filepath.Dir(seed.DataDir), "archive")
		budget := int64(256 << 20)
		if err := extract(filepath.Join(archive, "base.tar"), bad.DataDir, &budget); err != nil {
			t.Fatal(err)
		}
		if err := extract(filepath.Join(archive, "pg_wal.tar"), filepath.Join(bad.DataDir, "pg_wal"), &budget); err != nil {
			t.Fatal(err)
		}
		segments, err := os.ReadDir(filepath.Join(bad.DataDir, "pg_wal"))
		if err != nil {
			t.Fatal(err)
		}
		removed := 0
		for _, file := range segments {
			if regexp.MustCompile(`^[0-9A-F]{24}$`).MatchString(file.Name()) {
				if err = os.Remove(filepath.Join(bad.DataDir, "pg_wal", file.Name())); err != nil {
					t.Fatal(err)
				}
				removed++
			}
		}
		if removed == 0 {
			t.Fatal("fixture contained no WAL segments")
		}
		if err = tools.PrepareDisconnected(bad); err != nil {
			t.Fatal(err)
		}
		limited, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		err = tools.StartDisconnected(limited, bad)
		if err == nil {
			_, err = tools.PromoteAndVerify(limited, bad)
		}
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_ = tools.Stop(cleanup, bad.DataDir)
		if err == nil {
			t.Fatal("missing WAL accepted as verified recovery")
		}
		if _, err = os.Stat(filepath.Join(bad.ControlDir, "recovery-evidence.json")); !os.IsNotExist(err) {
			t.Fatal("failed recovery wrote success evidence")
		}
	})
	t.Run("event_trigger_source_rejected", func(t *testing.T) {
		if _, err := conn.Exec(ctx, `CREATE FUNCTION public.source_event() RETURNS event_trigger LANGUAGE plpgsql AS 'BEGIN RETURN; END'; CREATE EVENT TRIGGER source_event ON ddl_command_end EXECUTE FUNCTION public.source_event()`); err != nil {
			t.Fatal(err)
		}
		defer conn.Exec(ctx, "DROP EVENT TRIGGER source_event; DROP FUNCTION public.source_event()")
		manifest, err := source.Inspect(ctx)
		if err != nil || manifest.RequireSeedable() == nil || !strings.Contains(strings.Join(manifest.Blockers, ";"), "event triggers in postgres") {
			t.Fatal("source event trigger admitted", manifest.Blockers, err)
		}
	})
	t.Run("unlogged_source_rejected", func(t *testing.T) {
		if _, err := conn.Exec(ctx, "CREATE UNLOGGED TABLE unsupported_fixture(id integer)"); err != nil {
			t.Fatal(err)
		}
		manifest, err := source.Inspect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.RequireSeedable() == nil {
			t.Fatal("unlogged source admitted")
		}
	})
	t.Run("private_catalog_drift_rejected_before_access_changes", func(t *testing.T) {
		for _, db := range []string{"postgres", "template1"} {
			for _, event := range []string{"login", "ddl_command_start"} {
				t.Run(db+"/"+event, func(t *testing.T) {
					fixture := clone
					fixture.Database = db
					dc, err := fixture.ConnectPrivateAdmin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer dc.Close(context.Background())
					if _, err = dc.Exec(ctx, `CREATE FUNCTION public.unsafe_event() RETURNS event_trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''copied event trigger executed''; END'; CREATE EVENT TRIGGER unsafe_event ON `+event+` EXECUTE FUNCTION public.unsafe_event()`); err != nil {
						t.Fatal(err)
					}
					defer dc.Exec(ctx, "DROP EVENT TRIGGER unsafe_event; DROP FUNCTION public.unsafe_event()")
					if event == "login" {
						if unexpected, err := fixture.Connect(ctx); err == nil {
							unexpected.Close(context.Background())
							t.Fatal("login event fixture did not execute on an ordinary connection")
						}
					}
					if _, err = HardenAccess(ctx, r); err == nil || !strings.Contains(err.Error(), "event triggers in "+db) {
						t.Fatal("private event trigger was not rejected by preflight", err)
					}
					var created int
					if err = dc.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname LIKE 'pgws_service_%'`).Scan(&created); err != nil || created != 0 {
						t.Fatal("preflight changed access roles", created, err)
					}
					if _, err = os.Stat(filepath.Join(r.ControlDir, "access-plan.json")); !os.IsNotExist(err) {
						t.Fatal("preflight published an access plan", err)
					}
				})
			}
		}
		for _, fixture := range []struct{ name, create, drop string }{
			{"unlogged", "CREATE UNLOGGED TABLE public.drifted(id int)", "DROP TABLE public.drifted"},
			{"native_function", `CREATE FUNCTION public.drifted() RETURNS language_handler AS '$libdir/plpgsql', 'plpgsql_call_handler' LANGUAGE C`, "DROP FUNCTION public.drifted()"},
		} {
			t.Run(fixture.name, func(t *testing.T) {
				if _, err := cc.Exec(ctx, fixture.create); err != nil {
					t.Fatal(err)
				}
				defer cc.Exec(ctx, fixture.drop)
				if _, err := HardenAccess(ctx, r); err == nil || !strings.Contains(err.Error(), "unsupported persistent objects") {
					t.Fatal("private catalog drift admitted", err)
				}
			})
		}
	})
	t.Run("imported_authority_removed", func(t *testing.T) {
		if _, err := cc.Exec(ctx, `ALTER ROLE postgres SET session_preload_libraries='pgws_missing_preload'; ALTER ROLE postgres SET local_preload_libraries='pgws_missing_preload'`); err != nil {
			t.Fatal(err)
		}
		if unexpected, err := clone.Connect(ctx); err == nil {
			unexpected.Close(context.Background())
			t.Fatal("copied preload fixture did not block ordinary login")
		}
		private, err := clone.ConnectPrivateAdmin(ctx)
		if err != nil {
			t.Fatal("private startup executed copied preload defaults", err)
		}
		var session, local string
		if err = private.QueryRow(ctx, "SELECT current_setting('session_preload_libraries'),current_setting('local_preload_libraries')").Scan(&session, &local); err != nil || session != "" || local != "" {
			t.Fatal("private startup did not override copied libraries", err)
		}
		private.Close(context.Background())
		// Break the file write AFTER the global role transaction. A retry must
		// reconnect with its reserved administrator, since the source login is
		// already disabled and no successful access result was returned.
		hbaPath := filepath.Join(r.ControlDir, "hba.conf")
		originalHBA, err := os.ReadFile(hbaPath)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Remove(hbaPath); err != nil {
			t.Fatal(err)
		}
		if err = os.Mkdir(hbaPath, 0700); err != nil {
			t.Fatal(err)
		}
		partial, err := HardenAccess(ctx, r)
		if err == nil {
			t.Fatal("hardening ignored a failed HBA installation")
		}
		if err = os.Remove(hbaPath); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(hbaPath, originalHBA, 0600); err != nil {
			t.Fatal(err)
		}
		access, err := HardenAccess(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		if access.Admin != partial.Admin || access.Owner != partial.Owner || access.Reader != partial.Reader {
			t.Fatal("retry replaced the reserved access roles")
		}
		replayed, err := HardenAccess(ctx, r)
		if err != nil || replayed.Admin != access.Admin {
			t.Fatal("lost access response could not be reconciled", err)
		}
		owner, err := IssueCredential(ctx, r, access, "owner", time.Now().Add(10*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		password := filepath.Join(root, "owner.secret")
		if err = os.WriteFile(password, []byte(owner.Password), 0600); err != nil {
			t.Fatal(err)
		}
		client := clone
		client.User = owner.Username
		client.PasswordFile = password
		oc, err := client.Connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer oc.Close(context.Background())
		if _, err = oc.Exec(ctx, "ALTER TABLE fixture ADD COLUMN migrated boolean; INSERT INTO fixture(id,value) VALUES(2,'owned')"); err != nil {
			t.Fatal("owner migration", err)
		}
		if _, err = oc.Exec(ctx, `ALTER TYPE fixture_state ADD VALUE 'ready'; ALTER DOMAIN fixture_positive ADD CONSTRAINT small CHECK (VALUE < 100); ALTER TYPE fixture_pair ADD ATTRIBUTE active boolean; ALTER AGGREGATE fixture_sum(integer) RENAME TO migrated_sum; CREATE PROCEDURE new_write() LANGUAGE SQL SECURITY DEFINER AS 'DELETE FROM public.fixture'`); err != nil {
			t.Fatal("type and routine migration", err)
		}
		if _, err = oc.Exec(ctx, "SET ROLE NONE; CREATE PROCEDURE bypass_defaults() LANGUAGE SQL AS 'SELECT 1'"); err == nil {
			t.Fatal("credential bypasses owner defaults")
		}
		if _, err = oc.Exec(ctx, "SET ROLE "+ident(access.Owner)); err != nil {
			t.Fatal(err)
		}
		if _, err = oc.Exec(ctx, "SELECT * FROM pg_authid"); err == nil {
			t.Fatal("owner can read authentication catalog")
		}
		if _, err = oc.Exec(ctx, "COPY fixture TO PROGRAM 'true'"); err == nil {
			t.Fatal("owner can execute programs")
		}
		if _, err = oc.Exec(ctx, "SET ROLE postgres"); err == nil {
			t.Fatal("owner can assume imported source role")
		}
		reader, err := IssueCredential(ctx, r, access, "reader", time.Now().Add(10*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		password = filepath.Join(root, "reader.secret")
		if err = os.WriteFile(password, []byte(reader.Password), 0600); err != nil {
			t.Fatal(err)
		}
		client.User = reader.Username
		client.PasswordFile = password
		rc, err := client.Connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close(context.Background())
		var n int
		if err = rc.QueryRow(ctx, "SELECT count(*) FROM fixture").Scan(&n); err != nil || n != 2 {
			t.Fatal("reader", n, err)
		}
		if _, err = rc.Exec(ctx, "SET default_transaction_read_only=off; DELETE FROM fixture"); err == nil {
			t.Fatal("reader can write")
		}
		if _, err = rc.Exec(ctx, "SET default_transaction_read_only=off"); err != nil {
			t.Fatal(err)
		}
		for _, procedure := range []string{"imported_write", "new_write"} {
			if _, err = rc.Exec(ctx, "CALL "+procedure+"()"); err == nil {
				t.Fatal("reader can execute writing procedure", procedure)
			}
		}
		template := client
		template.Database = "template1"
		if c, err := template.Connect(ctx); err == nil {
			c.Close(context.Background())
			t.Fatal("template database reachable by credential")
		}
		if c, err := clone.Connect(ctx); err == nil {
			c.Close(context.Background())
			t.Fatal("imported login remains usable")
		}
		if err = conn.QueryRow(ctx, "SELECT count(*) FROM fixture").Scan(&n); err != nil || n != 1 {
			t.Fatal("source changed during access hardening", n, err)
		}
	})
}
