package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/physical"
	"pgws/internal/runtime"
)

// This child is the real host process and owns the actual journals, ZFS clone,
// OCI runtime and PostgreSQL. Injection exists only in the test binary.
func TestCreateCrashHelper(t *testing.T) {
	input := os.Getenv("PGWS_CREATE_CRASH_INPUT")
	if input == "" {
		t.Skip("child of the isolated ZFS crash campaign")
	}
	var job struct {
		Config Config
		Task   control.Task
		Stage  string
	}
	data, err := os.ReadFile(input)
	if err != nil || json.Unmarshal(data, &job) != nil {
		t.Fatal("invalid crash fixture")
	}
	h, err := Open(job.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if job.Stage != "" {
		h.afterCreateEffect = func(stage string) {
			if stage == job.Stage {
				if err := save(input+".killed", stage); err != nil {
					t.Fatal(err)
				}
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
				select {} // Never return a host response after the requested kill.
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := h.Execute(ctx, job.Task)
	if err != nil {
		t.Fatal(err)
	}
	if err = save(input+".result", out); err != nil {
		t.Fatal(err)
	}
}

func testCreateCrashCampaign(t *testing.T, ctx context.Context, parent *Host, snapshot control.Snapshot, tenant, project string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := parent.Config
	cfg.ID = "crash-host"
	cfg.Root = filepath.Join(filepath.Dir(parent.Config.Root), "crash")
	cfg.Sockets = filepath.Join(filepath.Dir(parent.Config.Sockets), "c")
	t.Cleanup(func() {
		// A failed assertion must not leave fixture-owned runtimes using the
		// disposable pool. Unknown names/specifications are never adopted.
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
	for _, mode := range []string{"resume", "delete"} {
		for _, stage := range []string{"clone", "controls", "runtime", "start", "promotion", "access", "guard", "ready"} {
			t.Run(mode+"_after_"+stage, func(t *testing.T) {
				request := control.Task{Kind: "create", Expiry: time.Now().UTC().Add(5 * time.Minute), Desired: "ready", Profile: "small", Snapshot: snapshot, Freshness: &control.Freshness{Mode: "snapshot", SnapshotID: snapshot.ID}, Command: lease.Command{Identity: lease.Identity{Epoch: cfg.Epoch, Host: cfg.ID, Tenant: tenant, Project: project, Workspace: control.ID(), Generation: 1, Revision: 1}, Operation: control.ID(), Token: 1}}
				input := filepath.Join(cfg.Root, "injection.json")
				run := func(stage string) error {
					t.Helper()
					if err := save(input, struct {
						Config Config
						Task   control.Task
						Stage  string
					}{cfg, request, stage}); err != nil {
						t.Fatal(err)
					}
					cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCreateCrashHelper$", "-test.v")
					cmd.Env = append(os.Environ(), "PGWS_CREATE_CRASH_INPUT="+input)
					output, err := cmd.CombinedOutput()
					if stage == "" && err != nil {
						t.Fatalf("restarted host: %v\n%s", err, output)
					}
					return err
				}
				err := run(stage)
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatal("host did not die by SIGKILL at the requested boundary", err)
				}
				var reached string
				data, err := os.ReadFile(input + ".killed")
				if err != nil || json.Unmarshal(data, &reached) != nil || reached != stage {
					t.Fatal("unexpected crash boundary", err)
				}
				request.Command.Token++ // Reclaimed worker attempt has a newer fence.
				if mode == "delete" {
					request.Kind = "delete"
					request.Command.Operation = control.ID()
					request.Command.Revision++
					if stage == "runtime" {
						h, err := Open(cfg)
						if err != nil {
							t.Fatal(err)
						}
						defer h.Close()
						pending, err := h.load(request)
						if err != nil || pending.RuntimeIntent == nil || pending.Container.ID != "" {
							t.Fatal("lost runtime observation fixture", err)
						}
						owned := *pending.RuntimeIntent
						pending.RuntimeIntent.Identity.Project = control.ID()
						if err = h.save(request, pending); err != nil {
							t.Fatal(err)
						}
						if _, err = h.Execute(ctx, request); err == nil {
							t.Fatal("cleanup adopted a foreign runtime specification")
						}
						if _, exists, err := h.oci.Lookup(ctx, owned); err != nil || !exists {
							t.Fatal("rejected cleanup removed the runtime", err)
						}
						pending.RuntimeIntent = &owned
						if err = h.save(request, pending); err != nil {
							t.Fatal(err)
						}
						h.Close()
					}
					_ = run("")
					var result control.Outcome
					data, err := os.ReadFile(input + ".result")
					if err != nil || json.Unmarshal(data, &result) != nil || result.Phase != "deleted" {
						t.Fatal("interrupted creation was not deleted", err)
					}
					h, err := Open(cfg)
					if err != nil {
						t.Fatal(err)
					}
					defer h.Close()
					if err = h.oci.VerifyAbsent(ctx, request.Command.Identity); err != nil {
						t.Fatal(err)
					}
					if err = h.storage.VerifyCloneAbsent(ctx, request.Command); err != nil {
						t.Fatal(err)
					}
					return
				}
				_ = run("")
				var result control.Outcome
				data, err = os.ReadFile(input + ".result")
				if err != nil || json.Unmarshal(data, &result) != nil || result.Phase != "ready" || result.Generation == nil {
					t.Fatal("restarted host did not return actual realization", err)
				}
				h, err := Open(cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer h.Close()
				s, err := h.load(request)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = physical.VerifyPromoted(ctx, s.Recovery, s.Access.Admin); err != nil {
					t.Fatal("reconciled clone has no current SQL recovery proof", err)
				}
				var status guardStatus
				if err = guardRequest(ctx, s.GuardDirectory, "status", nil, &status); err != nil || status.Active {
					t.Fatal("reconciled candidate exposed access without a serving lease", err)
				}
				// A different snapshot request cannot adopt the recorded candidate.
				changed := request
				changed.Command.Token++
				changed.Snapshot.GUID = "1"
				if _, err = h.Execute(ctx, changed); err == nil {
					t.Fatal("recovery accepted changed creation intent")
				}
				request.Kind = "delete"
				request.Command.Operation = control.ID()
				request.Command.Token += 2
				request.Command.Revision++
				if _, err = h.Execute(ctx, request); err != nil {
					t.Fatal("recovered candidate cleanup", err)
				}
			})
		}
	}
}
