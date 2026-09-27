package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"pgws/internal/control"
	"pgws/internal/lease"
)

func TestStopObservationScopeAndDurability(t *testing.T) {
	h := &Host{Config: Config{Root: t.TempDir(), ID: "test-host", Epoch: control.ID()}}
	task := control.Task{Kind: "observe_workspace", Command: lease.Command{Identity: lease.Identity{Epoch: h.Config.Epoch, Host: h.Config.ID, Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Generation: 1, Revision: 1}}}
	if _, err := h.Observe(context.Background(), task); err == nil {
		t.Fatal("missing state was reported as healthy")
	}
	if err := h.save(task, state{Task: task, Phase: "ready"}); err != nil {
		t.Fatal(err)
	}
	if observed, err := h.Observe(context.Background(), task); err != nil || observed.Stopped {
		t.Fatal("invented a terminal stop", err)
	}
	if err := recordStop(h.folder(task), "POOL_PRESSURE"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.folder(task), "safety-stop.json")
	before, _ := os.ReadFile(path)
	if err := recordStop(h.folder(task), "WORKSPACE_EXPIRED"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("repeated watchdog pass rewrote the original safety decision")
	}
	if observed, err := h.Observe(context.Background(), task); err != nil || !observed.Stopped || observed.Reason != "POOL_PRESSURE" || observed.Identity != task.Command.Identity {
		t.Fatal("lost or mis-scoped safety decision", err)
	}
	task.Command.Tenant = control.ID()
	if _, err := h.Observe(context.Background(), task); err == nil {
		t.Fatal("foreign tenant could observe a generation")
	}
}
