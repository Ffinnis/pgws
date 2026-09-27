package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"pgws/internal/config"
	"pgws/internal/control"
	"pgws/internal/lease"
)

func (h *Host) usageScope(t control.Task, kind string) error {
	if t.Kind != kind || t.Command.Epoch != h.Config.Epoch || t.Command.Host != h.Config.ID {
		return errors.New("usage host authority differs")
	}
	return nil
}
func (h *Host) usagePath() string { return filepath.Join(h.Config.Root, "usage", "pending.json") }
func (h *Host) readUsage() (control.CapacityBatch, error) {
	var batch control.CapacityBatch
	text, err := config.PrivateText(h.usagePath())
	if err != nil {
		return batch, err
	}
	if json.Unmarshal([]byte(text), &batch) != nil {
		return batch, errors.New("invalid durable capacity batch")
	}
	if err = batch.Validate(); err != nil {
		return batch, err
	}
	if batch.Epoch != h.Config.Epoch || batch.Host != h.Config.ID {
		return batch, errors.New("pending usage belongs to a different host authority")
	}
	return batch, nil
}

// CollectUsage keeps one bounded, fsynced batch until management confirms its
// commit. Backpressure pauses sampling instead of dropping or inventing samples.
func (h *Host) CollectUsage(ctx context.Context, t control.Task) (control.CapacityBatch, error) {
	if err := h.usageScope(t, "collect_usage"); err != nil {
		return control.CapacityBatch{}, err
	}
	h.usage.Lock()
	defer h.usage.Unlock()
	if _, err := os.Lstat(h.usagePath()); err == nil {
		batch, e := h.readUsage()
		if e != nil {
			return batch, e
		}
		if e = syncUsageDirectory(filepath.Dir(h.usagePath())); e != nil {
			return batch, e
		}
		if e = syncUsageDirectory(h.Config.Root); e != nil {
			return batch, e
		}
		return batch, nil
	} else if !os.IsNotExist(err) {
		return control.CapacityBatch{}, err
	}
	boot, startTicks, err := lease.BootClock()
	if err != nil {
		return control.CapacityBatch{}, err
	}
	start := time.Now().UTC().Truncate(time.Microsecond)
	report, err := InspectCapacity(ctx, h.Config)
	if err != nil {
		return control.CapacityBatch{}, err
	}
	end := time.Now().UTC().Truncate(time.Microsecond)
	endBoot, endTicks, err := lease.BootClock()
	if err != nil || endBoot != boot {
		return control.CapacityBatch{}, errors.New("capacity observation boot changed")
	}
	batch := control.CapacityBatch{ID: control.ID(), Epoch: h.Config.Epoch, Host: h.Config.ID, Start: start, End: end, Boot: boot, ElapsedNS: endTicks - startTicks, Projects: []control.CapacitySample{}}
	for _, p := range report.Projects {
		batch.Projects = append(batch.Projects, control.CapacitySample{Tenant: p.Tenant, Project: p.Project, DatasetGUID: p.Allocation.Project.GUID, Used: p.Used, Referenced: p.Referenced, ByChildren: p.ByChildren, BySnapshots: p.BySnapshots, ByDataset: p.ByDataset, ByReservation: p.ByReservation, ReservedMemory: p.ReservedMemory})
	}
	if err = batch.Validate(); err != nil {
		return control.CapacityBatch{}, err
	}
	if err = saveOnce(h.usagePath(), batch); err != nil {
		return control.CapacityBatch{}, err
	}
	if err = syncUsageDirectory(h.Config.Root); err != nil {
		return control.CapacityBatch{}, err
	}
	return batch, nil
}

func (h *Host) AcknowledgeUsage(ctx context.Context, t control.Task) error {
	if err := h.usageScope(t, "acknowledge_usage"); err != nil {
		return err
	}
	var request struct {
		ID string `json:"batch_id"`
	}
	if json.Unmarshal(t.Document, &request) != nil || !control.ValidID(request.ID) {
		return errors.New("invalid usage acknowledgement")
	}
	h.usage.Lock()
	defer h.usage.Unlock()
	if _, err := os.Lstat(h.usagePath()); os.IsNotExist(err) {
		if _, e := os.Stat(filepath.Dir(h.usagePath())); os.IsNotExist(e) {
			return nil
		}
		return syncUsageDirectory(filepath.Dir(h.usagePath()))
	} else if err != nil {
		return err
	}
	batch, err := h.readUsage()
	if err != nil {
		return err
	}
	// Another worker may already have acknowledged this batch and sampled again.
	if batch.ID != request.ID {
		return nil
	}
	if err = os.Remove(h.usagePath()); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(h.usagePath()))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func syncUsageDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
