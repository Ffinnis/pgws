package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/physical"
	"pgws/internal/runtime"
)

func testResetCrashCampaign(t *testing.T, ctx context.Context, parent *Host, snapshot control.Snapshot, tenant, project string) {
	t.Helper()
	cfg := parent.Config
	cfg.ID = "reset-crash-host"
	cfg.Root = filepath.Join(filepath.Dir(cfg.Root), "reset-crash")
	cfg.Sockets = filepath.Join(filepath.Dir(cfg.Sockets), "r")
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(cfg.Root, "objects", "*", "*", "state.json"))
		o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
		for _, path := range paths {
			var s state
			data, err := os.ReadFile(path)
			if err != nil || json.Unmarshal(data, &s) != nil {
				continue
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if s.GuardDirectory != "" {
				_ = guardRequest(cleanup, s.GuardDirectory, "shutdown", nil, nil)
			}
			container := s.Container
			if container.ID == "" && s.RuntimeIntent != nil {
				container, _, _ = o.Lookup(cleanup, *s.RuntimeIntent)
			}
			if container.ID != "" {
				_ = o.Remove(cleanup, container)
			}
			cancel()
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"resume", "delete"} {
		for _, stage := range []string{"old_stop", "clone", "controls", "runtime", "start", "promotion", "access", "guard", "ready", "retired_runtime", "retired_volume"} {
			if mode == "delete" && !slices.Contains([]string{"old_stop", "runtime", "ready", "retired_volume"}, stage) {
				continue
			}
			t.Run("reset_"+mode+"_after_"+stage, func(t *testing.T) {
				request := control.Task{Kind: "create", Expiry: time.Now().UTC().Add(5 * time.Minute), Desired: "ready", Profile: "small", Snapshot: snapshot, Freshness: &control.Freshness{Mode: "snapshot", SnapshotID: snapshot.ID}, Command: lease.Command{Identity: lease.Identity{Epoch: cfg.Epoch, Host: cfg.ID, Tenant: tenant, Project: project, Workspace: control.ID(), Generation: 1, Revision: 1}, Operation: control.ID(), Token: 1}}
				h, err := Open(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = h.Execute(ctx, request); err != nil {
					h.Close()
					t.Fatal(err)
				}
				old, err := h.load(request)
				if err != nil {
					h.Close()
					t.Fatal(err)
				}
				private := physical.Source{Host: old.Recovery.SocketDir, Port: 5432, User: old.Access.Admin, Database: "postgres"}
				conn, err := private.ConnectPrivateAdmin(ctx)
				if err != nil {
					h.Close()
					t.Fatal(err)
				}
				if _, err = conn.Exec(ctx, "UPDATE public.fixture SET value='reset-local'"); err != nil {
					conn.Close(ctx)
					h.Close()
					t.Fatal(err)
				}
				defer conn.Close(context.Background())
				h.Close()
				request.Kind, request.Command.Operation = "reset", control.ID()
				request.Command.Generation, request.Command.Revision, request.Command.Token = 2, 2, 2
				input := filepath.Join(cfg.Root, "injection.json")
				run := func(stage string) error {
					t.Helper()
					job := struct {
						Config Config
						Task   control.Task
						Stage  string
					}{cfg, request, stage}
					if err := save(input, job); err != nil {
						t.Fatal(err)
					}
					cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCreateCrashHelper$", "-test.v")
					cmd.Env = append(os.Environ(), "PGWS_CREATE_CRASH_INPUT="+input)
					output, err := cmd.CombinedOutput()
					if stage == "" && err != nil {
						t.Logf("reset child: %v\n%s", err, output)
					}
					return err
				}
				err = run(stage)
				var killed *exec.ExitError
				if !errors.As(err, &killed) || killed.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatal("reset did not die at requested boundary", err)
				}
				var reached string
				data, err := os.ReadFile(input + ".killed")
				if err != nil || json.Unmarshal(data, &reached) != nil || reached != stage {
					t.Fatal("wrong reset interruption boundary", err)
				}
				if _, err = conn.Exec(ctx, "SELECT 1"); err == nil {
					t.Fatal("reset kept an old-generation session alive")
				}
				request.Command.Token++
				if mode == "delete" {
					request.Kind, request.Command.Operation = "delete", control.ID()
					request.Command.Revision++
				}
				if err = run(""); err != nil {
					t.Fatal("interrupted reset did not reconcile", err)
				}
				h, err = Open(cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer h.Close()
				if mode == "resume" {
					current, err := h.load(request)
					if err != nil || current.Phase != "ready" {
						t.Fatal("reset did not prepare its replacement", err)
					}
					if _, err = physical.VerifyPromoted(ctx, current.Recovery, current.Access.Admin); err != nil {
						t.Fatal(err)
					}
					private.Host, private.User = current.Recovery.SocketDir, current.Access.Admin
					check, err := private.ConnectPrivateAdmin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					var value string
					err = check.QueryRow(ctx, "SELECT value FROM public.fixture WHERE id=1").Scan(&value)
					check.Close(context.Background())
					if err != nil || value != "source" {
						t.Fatal("reset retained old-generation writes", value, err)
					}
					var status guardStatus
					if err = guardRequest(ctx, current.GuardDirectory, "status", nil, &status); err != nil || status.Active {
						t.Fatal("reset exposed an unleased candidate", err)
					}
					retired := request
					retired.Command.Generation = 1
					if err = h.oci.VerifyAbsent(ctx, retired.Command.Identity); err != nil {
						t.Fatal("old runtime retained", err)
					}
					if err = h.storage.VerifyCloneAbsent(ctx, retired.Command); err != nil {
						t.Fatal("old volume retained", err)
					}
					request.Kind, request.Command.Operation = "delete", control.ID()
					request.Command.Token++
					request.Command.Revision++
					if _, err = h.Execute(ctx, request); err != nil {
						t.Fatal(err)
					}
				}
				for generation := int64(1); generation <= 2; generation++ {
					deleted := request
					deleted.Command.Generation = generation
					if err = h.oci.VerifyAbsent(ctx, deleted.Command.Identity); err != nil {
						t.Fatal(err)
					}
					if err = h.storage.VerifyCloneAbsent(ctx, deleted.Command); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
