package host

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/lease"
	"pgws/internal/physical"
)

func testGuardStall(t *testing.T, ctx context.Context, s state, client *pgx.Conn, key ed25519.PrivateKey) {
	t.Helper()
	var status guardStatus
	if err := guardRequest(ctx, s.GuardDirectory, "status", nil, &status); err != nil || !status.Active || status.PID <= 1 {
		t.Fatal("guard before stall", err)
	}
	now := time.Now()
	token, err := lease.Sign(key, lease.Claims{Identity: s.Task.Command.Identity, IssuedAt: now, ExpiresAt: now.Add(7 * time.Second), WorkspaceExpiry: s.Task.Expiry})
	if err != nil {
		t.Fatal(err)
	}
	if err = guardRequest(ctx, s.GuardDirectory, "lease", []byte(token), nil); err != nil {
		t.Fatal("short fixture lease", err)
	}
	if err = syscall.Kill(status.PID, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(status.PID, syscall.SIGCONT)
	stoppedBy := time.Now().Add(time.Second)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", status.PID))
		if err != nil {
			t.Fatal(err)
		}
		stopped := false
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "State:") {
				fields := strings.Fields(line)
				stopped = len(fields) > 1 && fields[1] == "T"
			}
		}
		if stopped {
			break
		}
		if time.Now().After(stoppedBy) {
			t.Fatal("fixture guard did not enter stopped state")
		}
		time.Sleep(time.Millisecond)
	}
	query, stop := context.WithTimeout(ctx, 6*time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() {
		_, err := client.Exec(query, "INSERT INTO fixture VALUES(800,'must-not-forward-after-expiry')")
		done <- err
	}()
	// SQL reaches the suspended process's socket while the grant is valid.
	// Resume only after its conservative two-second serving deadline passes.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(3 * time.Second):
	}
	if err = syscall.Kill(status.PID, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("suspended guard forwarded buffered SQL after lease expiry")
	}
	private := physical.Source{Host: s.Recovery.SocketDir, Port: 5432, User: s.Access.Admin, Database: "postgres"}
	check, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close(context.Background())
	var count int
	if err = check.QueryRow(ctx, "SELECT count(*) FROM public.fixture WHERE id=800").Scan(&count); err != nil || count != 0 {
		t.Fatal("expired buffered SQL reached PostgreSQL", count, err)
	}
	if err = guardRequest(ctx, s.GuardDirectory, "status", nil, &status); err != nil || status.Active {
		t.Fatal("guard remained active after stalled lease expiry", err)
	}
	t.Log("Actual ingress SIGSTOP/SIGCONT across serving expiry closed the session and did not execute buffered SQL")
}

func testRuntimeLeaseStop(t *testing.T, ctx context.Context, h *Host, s state, key ed25519.PrivateKey) {
	t.Helper()
	private := physical.Source{Host: s.Recovery.SocketDir, Port: 5432, User: s.Access.Admin, Database: "postgres"}
	client, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())
	query, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := client.Exec(query, "SELECT pg_sleep(25)"); done <- e }()
	observer, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	for {
		var sleeping bool
		if err = observer.QueryRow(ctx, "SELECT coalesce(wait_event='PgSleep',false) FROM pg_stat_activity WHERE pid=$1", client.PgConn().PID()).Scan(&sleeping); err != nil {
			t.Fatal(err)
		}
		if sleeping {
			break
		}
		select {
		case <-query.Done():
			t.Fatal(query.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	var status guardStatus
	if err = guardRequest(ctx, s.GuardDirectory, "status", nil, &status); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := lease.Sign(key, lease.Claims{Identity: s.Task.Command.Identity, IssuedAt: now, ExpiresAt: now.Add(7 * time.Second), WorkspaceExpiry: s.Task.Expiry})
	if err != nil {
		t.Fatal(err)
	}
	if err = guardRequest(ctx, s.GuardDirectory, "lease", []byte(token), nil); err != nil {
		t.Fatal(err)
	}
	watchConfig := filepath.Join(filepath.Dir(h.Config.Root), "serving-watchdog.json")
	if err = save(watchConfig, h.Config); err != nil {
		t.Fatal(err)
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	watch := exec.CommandContext(watchCtx, filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgws-watchdog-linux"), watchConfig)
	watch.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	if err = watch.Start(); err != nil {
		stopWatch()
		t.Fatal(err)
	}
	defer func() { stopWatch(); _ = watch.Wait() }()
	if err = syscall.Kill(status.PID, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(status.PID, syscall.SIGCONT)
	time.Sleep(3 * time.Second)
	for h.oci.VerifyAbsent(ctx, s.Task.Command.Identity) != nil {
		if time.Since(now) > 6*time.Second {
			t.Fatal("independent watchdog failed to stop runtime")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if time.Since(now) > 7*time.Second {
		t.Fatal("runtime stop exceeded signed lease lifetime")
	}
	if err = <-done; err == nil {
		t.Fatal("query survived serving expiry")
	}
	if err = h.oci.VerifyAbsent(ctx, s.Task.Command.Identity); err != nil {
		t.Fatal("expired runtime still exists", err)
	}
	if _, err = os.Stat(s.Recovery.DataDir); err != nil {
		t.Fatal("lease expiry removed retained storage", err)
	}
	stop, err := readStop(h.folder(s.Task))
	if err != nil || stop.Reason != "SERVING_LEASE_EXPIRED" {
		t.Fatal("serving expiry receipt", stop.Reason, err)
	}
	if _, err = os.Stat(filepath.Join(h.folder(s.Task), "runtime-release.json")); err != nil {
		t.Fatal("removed runtime remains charged", err)
	}
	if err = syscall.Kill(status.PID, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	claims := lease.Claims{Identity: s.Task.Command.Identity, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), WorkspaceExpiry: s.Task.Expiry}
	fresh, _ := lease.Sign(key, claims)
	if err = guardRequest(ctx, s.GuardDirectory, "lease", []byte(fresh), nil); err == nil {
		t.Fatal("fresh grant revived terminally stopped runtime")
	}
	t.Log("Independent watchdog removed PostgreSQL during guard SIGSTOP, killed active SQL, retained storage and rejected resurrection")
}
