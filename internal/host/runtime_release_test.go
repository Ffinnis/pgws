package host

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/runtime"
)

func TestRuntimeReleaseRequiresExactRemovalAndTerminalStop(t *testing.T) {
	folder := t.TempDir()
	id := lease.Identity{Epoch: control.ID(), Host: "test-host", Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Generation: 1, Revision: 1}
	s := state{Phase: "ready", ReservedMemory: 1 << 30, Container: runtime.Container{ID: strings.Repeat("a", 64), Spec: runtime.Spec{Identity: id, MemoryBytes: 1 << 30}}}
	assertCharge := func(want int64) {
		t.Helper()
		if got, err := chargedMemory(folder, s); err != nil || got != want {
			t.Fatalf("charge %d, want %d: %v", got, want, err)
		}
	}
	assertCharge(1 << 30)
	if err := recordRuntimeRelease(folder, s.Container); err == nil {
		t.Fatal("released a runtime that may resume")
	}
	if err := recordStop(folder, "POOL_PRESSURE"); err != nil {
		t.Fatal(err)
	}
	assertCharge(1 << 30) // Stop intent is not confirmation of removal.
	if err := recordRuntimeRelease(folder, s.Container); err != nil {
		t.Fatal(err)
	}
	assertCharge(0)
	path := filepath.Join(folder, "runtime-release.json")
	before, _ := os.ReadFile(path)
	if err := recordRuntimeRelease(folder, s.Container); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("repeat removal rewrote receipt")
	}
	s.Container.Spec.Identity.Generation++
	if _, err := chargedMemory(folder, s); err == nil {
		t.Fatal("replayed receipt freed another generation")
	}
	s.Container.Spec.Identity.Generation--
	s.Container.ID = strings.Repeat("b", 64)
	if _, err := chargedMemory(folder, s); err == nil {
		t.Fatal("old receipt freed a replacement container")
	}
	s.Container.ID = strings.Repeat("a", 64)
	if err := os.Remove(filepath.Join(folder, "safety-stop.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := chargedMemory(folder, s); err == nil {
		t.Fatal("release survived removal of terminal stop")
	}
	s.Phase = "deleted"
	assertCharge(0)
}

func TestRuntimeReleaseSurvivesWallClockRollback(t *testing.T) {
	folder := t.TempDir()
	id := lease.Identity{Epoch: control.ID(), Host: "test-host", Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Generation: 1, Revision: 1}
	s := state{Phase: "blocked", ReservedMemory: 1 << 30, Container: runtime.Container{ID: strings.Repeat("a", 64), Spec: runtime.Spec{Identity: id, MemoryBytes: 1 << 30}}}
	stop := safetyStop{Reason: "SOURCE_LINEAGE_CHANGED", At: time.Now().UTC().Add(time.Hour)}
	if err := saveOnce(filepath.Join(folder, "safety-stop.json"), stop); err != nil {
		t.Fatal(err)
	}
	if err := recordRuntimeRelease(folder, s.Container); err != nil {
		t.Fatal(err)
	}
	if got, err := chargedMemory(folder, s); err != nil || got != 0 {
		t.Fatalf("clock rollback invalidated confirmed removal: charge=%d err=%v", got, err)
	}
	s.Container.Spec.Identity.Generation++
	if _, err := chargedMemory(folder, s); err == nil {
		t.Fatal("clock rollback allowed release of a different generation")
	}
}

func TestConcurrentSafetyStopAndReleaseAreImmutable(t *testing.T) {
	folder := t.TempDir()
	id := lease.Identity{Epoch: control.ID(), Host: "test-host", Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Generation: 1, Revision: 1}
	s := state{Phase: "blocked", ReservedMemory: 1 << 30, Container: runtime.Container{ID: strings.Repeat("a", 64), Spec: runtime.Spec{Identity: id, MemoryBytes: 1 << 30}}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Go(func() {
			<-start
			reason := "SOURCE_LINEAGE_CHANGED"
			if i%2 == 0 {
				reason = "POOL_PRESSURE"
			}
			if err := recordStop(folder, reason); err != nil {
				t.Error(err)
				return
			}
			before, err := readStop(folder)
			if err != nil {
				t.Error(err)
				return
			}
			if err := recordRuntimeRelease(folder, s.Container); err != nil {
				t.Error(err)
			}
			after, err := readStop(folder)
			if err != nil || before != after {
				t.Error("concurrent publisher replaced an acknowledged stop", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if got, err := chargedMemory(folder, s); err != nil || got != 0 {
		t.Fatalf("concurrent release: charge=%d err=%v", got, err)
	}
}

func TestRuntimeAbsenceReleasesOnlyUnrealizedReservation(t *testing.T) {
	folder := t.TempDir()
	id := lease.Identity{Epoch: control.ID(), Host: "test-host", Tenant: control.ID(), Project: control.ID(), Workspace: control.ID(), Generation: 1, Revision: 1}
	s := state{Task: control.Task{Command: lease.Command{Identity: id}}, Phase: "blocked", ReservedMemory: 1 << 30}
	if err := recordAbsentRuntimeRelease(folder, id); err == nil {
		t.Fatal("released nonterminal reservation")
	}
	if err := recordStop(folder, "SOURCE_RESEEDED"); err != nil {
		t.Fatal(err)
	}
	if err := recordAbsentRuntimeRelease(folder, id); err != nil {
		t.Fatal(err)
	}
	if charge, err := chargedMemory(folder, s); err != nil || charge != 0 {
		t.Fatal("confirmed absence remains charged", charge, err)
	}
	if err := recordAbsentRuntimeRelease(folder, id); err != nil {
		t.Fatal("absence replay", err)
	}
	s.Container = runtime.Container{ID: strings.Repeat("a", 64), Spec: runtime.Spec{Identity: id, MemoryBytes: 1 << 30}}
	if _, err := chargedMemory(folder, s); err == nil {
		t.Fatal("absence proof released an observed container")
	}
	s.Container = runtime.Container{}
	s.Task.Command.Generation++
	if _, err := chargedMemory(folder, s); err == nil {
		t.Fatal("absence proof released a different generation")
	}
}
