package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"pgws/internal/control"
)

func (h *Host) Observe(ctx context.Context, task control.Task) (control.StopObservation, error) {
	var result control.StopObservation
	id := task.Command.Identity
	if ctx.Err() != nil || id.Host != h.Config.ID || id.Epoch != h.Config.Epoch || !control.ValidID(id.Tenant) || !control.ValidID(id.Project) || !control.ValidID(id.Workspace) || id.Generation < 1 || (task.Kind != "observe_source" && task.Kind != "observe_workspace") {
		return result, errors.New("invalid host observation scope")
	}
	state, err := h.load(task)
	if err != nil {
		return result, errors.New("host generation state unavailable")
	}
	stored := state.Task.Command.Identity
	if stored.Epoch != id.Epoch || stored.Host != id.Host || stored.Tenant != id.Tenant || stored.Project != id.Project || stored.Workspace != id.Workspace || stored.Generation != id.Generation {
		return result, errors.New("host observation generation differs")
	}
	result.Identity = id
	if task.Kind == "observe_source" {
		if state.Outcome.Source == nil || state.Task.SourceID != id.Workspace {
			return result, errors.New("host observation is not a source baseline")
		}
		result.SourceEpoch = state.Outcome.Source.Snapshot.SourceEpoch
	} else if state.Task.SourceID == id.Workspace {
		return result, errors.New("host observation is not a workspace")
	}
	data, err := os.ReadFile(filepath.Join(h.folder(task), "safety-stop.json"))
	if os.IsNotExist(err) {
		return result, nil
	}
	var stop safetyStop
	if err != nil || json.Unmarshal(data, &stop) != nil || stop.Reason == "" || stop.At.IsZero() {
		return result, errors.New("durable host stop is unreadable")
	}
	result.Stopped, result.Reason, result.StoppedAt = true, stop.Reason, stop.At
	return result, nil
}
