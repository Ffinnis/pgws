package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/physical"
	"pgws/internal/runtime"
)

type sourceCrashJob struct {
	Config Config
	Task   control.Task
	Stage  string
}

func TestSourceCrashHelper(t *testing.T) {
	input := os.Getenv("PGWS_SOURCE_CRASH_INPUT")
	if input == "" {
		t.Skip("child of the isolated source recovery campaign")
	}
	var job sourceCrashJob
	data, err := os.ReadFile(input)
	if err != nil || json.Unmarshal(data, &job) != nil {
		t.Fatal("invalid source crash fixture")
	}
	h, err := Open(job.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	kill := func(stage string) {
		if err := save(input+".killed", stage); err != nil {
			t.Error(err)
			return
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		select {}
	}
	h.afterSourceEffect = func(stage string) {
		if stage == job.Stage {
			kill(stage)
		}
		if stage == "runtime" && job.Stage == "backup" {
			go func() {
				// The transfer must actually have begun before killing its host.
				archive := filepath.Join(job.Config.MountRoot, job.Task.Command.Tenant, job.Task.Command.Project, "baselines", job.Task.SourceID, fmt.Sprint(job.Task.Command.Generation), "seeds", job.Task.SourceID, fmt.Sprint(job.Task.Command.Generation), "archive", "base.tar")
				for {
					if info, err := os.Stat(archive); err == nil && info.Size() > 0 {
						kill("backup")
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := h.Execute(ctx, job.Task)
	if err != nil {
		t.Fatal(err)
	}
	if err = save(input+".result", out); err != nil {
		t.Fatal(err)
	}
}

func TestLiveSourceRecovery(t *testing.T)       { testSourceRecovery(t, false) }
func TestLiveSourceReseedRecovery(t *testing.T) { testSourceRecovery(t, true) }
func testSourceRecovery(t *testing.T, reseed bool) {
	if os.Getenv("PGWS_ZFS_ROOT") == "" {
		t.Skip("run scripts/host_lab.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("/tmp", "pgws-seed-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	source := labPrimary(t, ctx, root, "source")
	conn, err := source.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err = conn.Exec(ctx, "CREATE TABLE fixture(id integer primary key); INSERT INTO fixture VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	tenant, project := control.ID(), control.ID()
	cfg := Config{ID: "seed-crash-host", Epoch: control.ID(), Root: filepath.Join(root, "host"), Sockets: filepath.Join(root, "s"), Dataset: os.Getenv("PGWS_ZFS_ROOT"), MountRoot: os.Getenv("PGWS_ZFS_MOUNTS"), Sources: []SourceConfig{{Tenant: tenant, Project: project, EndpointReference: "lab-source", SecretReference: "lab-secret", Source: source}}}
	t.Cleanup(func() {
		paths, _ := filepath.Glob(filepath.Join(cfg.Root, "objects", "*", "*", "state.json"))
		o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
		for _, path := range paths {
			var s state
			data, err := os.ReadFile(path)
			if err != nil || json.Unmarshal(data, &s) != nil {
				continue
			}
			cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
			container := s.Container
			if container.ID == "" && s.RuntimeIntent != nil {
				container, _, _ = o.Lookup(cleanup, *s.RuntimeIntent)
			}
			if container.ID != "" {
				_ = o.Remove(cleanup, container)
			}
			if s.SlotOwned {
				owned := source
				owned.ExpectedSystemID = s.SourceIdentity.SystemID
				_ = owned.DropSlot(cleanup, s.Slot)
			}
			done()
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stages := []string{"unconfirmed_slot", "slot", "volume", "runtime", "backup", "seed", "controls", "start", "capture", "streaming"}
	if reseed {
		stages = []string{"previous_runtime", "previous_slot", "previous_retired", "backup", "capture", "streaming"}
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			sourceID := control.ID()
			request := control.Task{Kind: "register_source", SourceID: sourceID, EndpointReference: "lab-source", SecretReference: "lab-secret", Command: lease.Command{Identity: lease.Identity{Epoch: cfg.Epoch, Host: cfg.ID, Tenant: tenant, Project: project, Workspace: sourceID, Generation: 1, Revision: 1}, Operation: control.ID(), Token: 1}}
			if reseed {
				initial, err := Open(cfg)
				if err != nil {
					t.Fatal(err)
				}
				_, err = initial.Execute(ctx, request)
				initial.Close()
				if err != nil {
					t.Fatal("initial source before reseed crash", err)
				}
				request.Kind = "reseed_source"
				request.Command.Generation, request.Command.Revision, request.Command.Token = 2, 2, 2
				request.Command.Operation = control.ID()
				request.Snapshot = control.Snapshot{Baseline: control.ID(), BaselineGeneration: 2, SourceEpoch: 2}
			}
			input := filepath.Join(root, "injection.json")
			run := func(stage string) error {
				t.Helper()
				if err := save(input, sourceCrashJob{cfg, request, stage}); err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSourceCrashHelper$", "-test.v")
				cmd.Env = append(os.Environ(), "PGWS_SOURCE_CRASH_INPUT="+input)
				output, err := cmd.CombinedOutput()
				var killed *exec.ExitError
				if err != nil && (!errors.As(err, &killed) || killed.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL) {
					t.Logf("source child: %v\n%s", err, output)
				}
				return err
			}
			err := run(stage)
			var killed *exec.ExitError
			if !errors.As(err, &killed) || killed.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal("source host did not die at requested boundary", err)
			}
			var reached string
			data, err := os.ReadFile(input + ".killed")
			if err != nil || json.Unmarshal(data, &reached) != nil || reached != stage {
				t.Fatal("wrong source interruption boundary", err)
			}
			request.Command.Token++
			h, err := Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := h.load(request)
			if err != nil && !(reseed && strings.HasPrefix(stage, "previous_") && os.IsNotExist(err)) {
				h.Close()
				t.Fatal(err)
			}
			if stage == "unconfirmed_slot" {
				defer h.Close()
				owned := source
				owned.ExpectedSystemID = pending.SourceIdentity.SystemID
				// Only this fixture knows its child created the slot. The host
				// must neither adopt it nor drop it without its durable receipt.
				defer owned.DropSlot(ctx, pending.Slot)
				if _, err = h.Execute(ctx, request); err == nil || !strings.Contains(err.Error(), "slot ownership") {
					t.Fatal("unconfirmed slot adopted", err)
				}
				if err = h.Revoke(ctx, request); err != nil {
					t.Fatal(err)
				}
				var count int
				if err = conn.QueryRow(ctx, "SELECT count(*) FROM pg_replication_slots WHERE slot_name=$1", pending.Slot).Scan(&count); err != nil || count != 1 {
					t.Fatal("unconfirmed slot removed", count, err)
				}
				return
			}
			before := ""
			if pending.Seeding != nil {
				before = pending.Seeding.LowerBound
			}
			if stage == "capture" {
				if _, err = conn.Exec(ctx, "INSERT INTO fixture VALUES(2)"); err != nil {
					h.Close()
					t.Fatal(err)
				}
				barrier, err := source.CaptureBarrier(ctx)
				if err != nil {
					h.Close()
					t.Fatal(err)
				}
				baseline := physical.Source{Host: pending.Recovery.SocketDir, Port: 5432, User: pending.Recovery.SourceUser, Database: "postgres"}
				if _, err = physical.WaitReplay(ctx, baseline, barrier); err != nil {
					h.Close()
					t.Fatal(err)
				}
			}
			h.Close()
			if err = run(""); err != nil {
				t.Fatal("source registration did not resume", err)
			}
			h, err = Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			completed, err := h.load(request)
			if err != nil || completed.Phase != "streaming" || completed.Outcome.Source == nil {
				t.Fatal("source not streaming", err)
			}
			if reseed {
				if completed.Outcome.Source.Snapshot.SourceEpoch != 2 || completed.Outcome.Source.Snapshot.Baseline != request.Snapshot.Baseline || completed.Outcome.Source.Snapshot.BaselineGeneration != 2 {
					t.Fatal("reseed recovery changed lineage")
				}
				oldTask := request
				oldTask.Command.Generation = 1
				retired, err := h.load(oldTask)
				if err != nil || !retired.SlotRetired || retired.SlotOwned || retired.Phase != "blocked" {
					t.Fatal("previous source retirement unconfirmed", err)
				}
				if err = h.oci.VerifyAbsent(ctx, retired.Task.Command.Identity); err != nil {
					t.Fatal("previous source runtime survived", err)
				}
			}
			if stage == "capture" && completed.Outcome.Source.Snapshot.LowerBound != before {
				t.Fatal("source capture replay advanced lower bound")
			}
			if pending.Volume.GUID != "" && completed.Volume.GUID != pending.Volume.GUID {
				t.Fatal("source retry replaced its volume")
			}
			if stage == "backup" && completed.Container.ID == pending.Container.ID {
				t.Fatal("source retry retained interrupted backup runtime")
			}
			secrets, err := filepath.Glob(filepath.Join(h.folder(request), "postgres-controls", "pgws-backup-secret-*"))
			if err != nil || len(secrets) != 0 {
				t.Fatal("source retry retained temporary backup credentials", err)
			}
			private := physical.Source{Host: completed.Recovery.SocketDir, Port: 5432, User: completed.Recovery.SourceUser, Database: "postgres"}
			if _, err = physical.WaitReplay(ctx, private, completed.Recovery.Barrier); err != nil {
				t.Fatal("recovered source has no current replay proof", err)
			}
			changed := request
			changed.Command.Token++
			changed.Command.Operation = control.ID()
			if _, err = h.Execute(ctx, changed); err == nil {
				t.Fatal("source retry accepted a different operation")
			}
			request.Command.Token += 2
			if err = h.Revoke(ctx, request); err != nil {
				t.Fatal("recovered source cleanup", err)
			}
		})
	}
}
