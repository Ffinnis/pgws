package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"pgws/internal/lease"
	"pgws/internal/runtime"
)

func removeStoppedRuntime(ctx context.Context, o runtime.OCI, folder string, s state) (result error) {
	if s.SourceIdentity.SystemID != "" {
		brokerErr := stopSourceBroker(ctx, folder)
		defer func() { result = errors.Join(result, brokerErr) }()
	}
	container := s.Container
	if container.ID == "" {
		if s.RuntimeIntent == nil {
			return o.VerifyAbsent(ctx, s.Task.Command.Identity)
		}
		observed, exists, err := o.Lookup(ctx, *s.RuntimeIntent)
		if err != nil || !exists {
			return err
		}
		container = observed
	}
	if err := o.Remove(ctx, container); err != nil {
		return err
	}
	if s.Container.ID == "" {
		// The host has not persisted its own observation yet. Keep admission
		// charged until that happens or ordinary deletion removes the intent.
		return nil
	}
	return recordRuntimeRelease(folder, container)
}

// Kept separate from state.json: the independent watchdog must not overwrite
// a concurrent host lifecycle update. Only a confirmed OCI removal can write
// this receipt. Disk allocation is unaffected.
type runtimeRelease struct {
	Container runtime.Container `json:"container"`
	Absent    *lease.Identity   `json:"absent_identity,omitempty"`
	Stop      safetyStop        `json:"stop"`
	RemovedAt time.Time         `json:"removed_at"`
}

func readStop(folder string) (safetyStop, error) {
	var stop safetyStop
	data, err := os.ReadFile(filepath.Join(folder, "safety-stop.json"))
	if err != nil {
		return stop, err
	}
	if json.Unmarshal(data, &stop) != nil || stop.Reason == "" || stop.At.IsZero() {
		return stop, errors.New("invalid durable safety stop")
	}
	return stop, nil
}

// Caller has just successfully removed this exact immutable container ID.
// Unknown or partially recorded runtimes keep their capacity reservation.
func recordRuntimeRelease(folder string, container runtime.Container) error {
	if container.ID == "" {
		return errors.New("runtime removal needs an observed container identity")
	}
	stop, err := readStop(folder)
	if err != nil {
		return err
	}
	path := filepath.Join(folder, "runtime-release.json")
	var old runtimeRelease
	if data, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(data, &old) != nil || old.Absent != nil || old.Container != container || old.Stop != stop || old.RemovedAt.IsZero() {
			return errors.New("runtime release differs from its durable receipt")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = saveOnce(path, runtimeRelease{Container: container, Stop: stop, RemovedAt: time.Now().UTC()}); os.IsExist(err) {
		// Validate the concurrent winner exactly as an ordinary repeated removal.
		return recordRuntimeRelease(folder, container)
	}
	return err
}

// Only the host may record this after VerifyAbsent while holding the resource
// lock and terminal stop. The watchdog cannot: an in-flight host could still
// create its reserved runtime after the watchdog's absence observation.
func recordAbsentRuntimeRelease(folder string, identity lease.Identity) error {
	stop, err := readStop(folder)
	if err != nil {
		return err
	}
	path := filepath.Join(folder, "runtime-release.json")
	var old runtimeRelease
	if data, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(data, &old) != nil || old.Absent == nil || *old.Absent != identity || old.Container.ID != "" || old.Stop != stop || old.RemovedAt.IsZero() {
			return errors.New("absent runtime release differs from its durable receipt")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = saveOnce(path, runtimeRelease{Absent: &identity, Stop: stop, RemovedAt: time.Now().UTC()}); os.IsExist(err) {
		return recordAbsentRuntimeRelease(folder, identity)
	}
	return err
}

func chargedMemory(folder string, s state) (int64, error) {
	if s.Phase == "deleted" {
		return 0, nil
	}
	memory := s.ReservedMemory
	if memory == 0 {
		memory = s.Container.Spec.MemoryBytes
	}
	if memory < 0 || memory > 8<<30 {
		return 0, errors.New("invalid durable memory reservation")
	}
	data, err := os.ReadFile(filepath.Join(folder, "runtime-release.json"))
	if os.IsNotExist(err) {
		return memory, nil
	}
	var receipt runtimeRelease
	if err != nil || json.Unmarshal(data, &receipt) != nil || receipt.RemovedAt.IsZero() {
		return 0, errors.New("runtime release receipt is unreadable")
	}
	stop, err := readStop(folder)
	if err != nil {
		return 0, errors.New("runtime release has no terminal safety decision")
	}
	if receipt.Absent != nil {
		if *receipt.Absent != s.Task.Command.Identity || s.Container.ID != "" || receipt.Container.ID != "" {
			return 0, errors.New("runtime absence receipt differs from its reserved generation")
		}
	} else if receipt.Container.ID == "" || receipt.Container != s.Container {
		return 0, errors.New("runtime release does not match the reserved generation")
	}
	if receipt.Stop != stop {
		return 0, errors.New("runtime release does not match the terminal safety decision")
	}
	// Ordering is established by reading the immutable stop after confirmed OCI
	// removal. Wall time can move backwards between those two durable records.
	// It is audit metadata, not authority to release a different container.
	return 0, nil
}
