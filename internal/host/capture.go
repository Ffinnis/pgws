package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"pgws/internal/control"
	"pgws/internal/freshness"
	"pgws/internal/lease"
	"pgws/internal/physical"
	"time"
)

type capturePlan struct {
	Command  lease.Command    `json:"command"`
	Barrier  physical.Barrier `json:"barrier"`
	Snapshot control.Snapshot `json:"snapshot"`
	Complete bool             `json:"complete"`
}

func (h *Host) resolve(t control.Task) (physical.Source, error) {
	for _, s := range h.Config.Sources {
		if s.Tenant == t.Command.Tenant && s.Project == t.Command.Project && s.EndpointReference == t.EndpointReference && s.SecretReference == t.SecretReference {
			return s.Source, nil
		}
	}
	return physical.Source{}, errors.New("source reference pair is not provisioned on this host")
}
func (h *Host) capture(ctx context.Context, t control.Task) (control.Snapshot, error) {
	if !control.ValidID(t.SourceID) || !control.ValidID(t.Snapshot.Baseline) || t.Snapshot.BaselineGeneration < 1 {
		return control.Snapshot{}, errors.New("unsupported baseline source mapping")
	}
	unlock := h.lock(t.SourceID)
	defer unlock()
	sourceTask := t
	sourceTask.Command.Workspace = t.SourceID
	sourceTask.Command.Generation = t.Snapshot.BaselineGeneration
	if e := checkStopped(h.folder(sourceTask)); e != nil {
		return control.Snapshot{}, e
	}
	baseline, e := h.load(sourceTask)
	if e != nil {
		return control.Snapshot{}, e
	}
	if baseline.Phase != "streaming" || baseline.Task.Command.Tenant != t.Command.Tenant || baseline.Task.Command.Project != t.Command.Project {
		return control.Snapshot{}, errors.New("baseline owner or phase changed")
	}
	if baseline.Outcome.Source == nil || baseline.Outcome.Source.Snapshot.Baseline != t.Snapshot.Baseline || baseline.Outcome.Source.Snapshot.SourceEpoch != t.Snapshot.SourceEpoch {
		return control.Snapshot{}, errors.New("baseline generation lineage differs")
	}
	if e = h.storage.VerifyGeneration(ctx, sourceTask.Command, baseline.Volume, "baselines"); e != nil {
		return control.Snapshot{}, e
	}
	if baseline.Seeding != nil {
		source, err := h.resolve(baseline.Task)
		if err != nil {
			return control.Snapshot{}, err
		}
		source.ExpectedSystemID = baseline.SourceIdentity.SystemID
		if err = h.oci.Tools(baseline.Container).RefreshStreamingSecret(baseline.Recovery, source, baseline.Slot); err != nil {
			return control.Snapshot{}, err
		}
		if !filepath.IsAbs(source.Host) {
			if _, err = h.ensureSourceBroker(ctx, baseline.Task, source); err != nil {
				return control.Snapshot{}, err
			}
		}
	}
	path := filepath.Join(h.folder(t), "capture.json")
	var plan capturePlan
	b, e := os.ReadFile(path)
	if e == nil {
		if json.Unmarshal(b, &plan) != nil || plan.Snapshot.ID != t.Command.Operation || plan.Snapshot.Baseline != t.Snapshot.Baseline {
			return control.Snapshot{}, errors.New("capture receipt identity differs")
		}
		if plan.Snapshot.LowerBound != "" {
			lower, err := physical.ParseLSN(plan.Snapshot.LowerBound)
			required, barrierErr := physical.ParseLSN(plan.Barrier.LSN)
			if err != nil || barrierErr != nil || lower < required {
				return control.Snapshot{}, errors.New("capture replay proof is below its reserved barrier")
			}
		}
		if plan.Complete {
			if plan.Snapshot.LowerBound == "" || plan.Snapshot.GUID == "" {
				return control.Snapshot{}, errors.New("completed capture has no durable proof")
			}
			return plan.Snapshot, nil
		}
	} else if os.IsNotExist(e) {
		source, e := h.resolve(t)
		if e != nil {
			return control.Snapshot{}, e
		}
		var manifest Manifest
		if json.Unmarshal(t.Snapshot.Manifest, &manifest) != nil {
			return control.Snapshot{}, errors.New("invalid baseline manifest")
		}
		source.ExpectedSystemID = manifest.Physical.SystemID
		m, e := source.Inspect(ctx)
		if e != nil {
			return control.Snapshot{}, e
		}
		if e = m.RequireSeedable(); e != nil {
			return control.Snapshot{}, e
		}
		if m.SystemID != manifest.Physical.SystemID || m.Timeline != t.Snapshot.Timeline {
			return control.Snapshot{}, errors.New("source lineage changed")
		}
		for _, setting := range []string{"max_connections", "max_prepared_transactions", "max_locks_per_transaction", "max_wal_senders", "max_worker_processes"} {
			if m.Settings[setting] != manifest.Physical.Settings[setting] {
				return control.Snapshot{}, errors.New("source recovery settings changed; baseline requalification is required")
			}
		}

		// A retry retains the original barrier, so latest does not move forward.
		if t.Freshness.Mode == "latest" {
			plan.Barrier, e = source.CaptureBarrier(ctx)
			if e != nil {
				return control.Snapshot{}, e
			}
		} else if t.Freshness.Mode == "at_least" {
			key, e := base64.StdEncoding.DecodeString(h.Config.AuthorityKey)
			if e != nil {
				return control.Snapshot{}, e
			}
			c, e := freshness.Verify(key, t.Freshness.BarrierToken, time.Now())
			if e != nil || c.Authority != t.Command.Epoch || c.Tenant != t.Command.Tenant || c.Project != t.Command.Project || c.Source != t.SourceID || c.SourceEpoch != t.Snapshot.SourceEpoch || c.SystemID != manifest.Physical.SystemID || c.Timeline != t.Snapshot.Timeline {
				return control.Snapshot{}, errors.New("source barrier scope or lineage rejected")
			}
			plan.Barrier = physical.Barrier{Identity: physical.Identity{SystemID: c.SystemID, Timeline: c.Timeline}, LSN: c.LSN, ObservedAt: c.IssuedAt}
		} else {
			return control.Snapshot{}, errors.New("unsupported source freshness")
		}
		if plan.Barrier.Identity != m.Identity {
			return control.Snapshot{}, errors.New("source lineage changed during capture")
		}
		plan.Command = baseline.Task.Command
		current, ok := h.storageJournal.Current(plan.Command.Identity)
		if !ok {
			return control.Snapshot{}, errors.New("baseline storage authority missing")
		}
		plan.Command.Token = current.Command.Token + 1
		plan.Command.Revision = current.Command.Revision
		plan.Command.Operation = t.Command.Operation
		plan.Snapshot = t.Snapshot
		plan.Snapshot.Name, plan.Snapshot.GUID, plan.Snapshot.LowerBound = "", "", ""
		plan.Snapshot.ID = t.Command.Operation
		plan.Snapshot.RequestedLSN = plan.Barrier.LSN
		if e = save(path, plan); e != nil {
			return control.Snapshot{}, e
		}
	} else {
		return control.Snapshot{}, e
	}
	if plan.Snapshot.LowerBound == "" {
		sql := physical.Source{Host: baseline.Recovery.SocketDir, Port: 5432, User: baseline.Recovery.SourceUser, Database: "postgres"}
		lower, e := physical.WaitReplay(ctx, sql, plan.Barrier)
		if e != nil {
			return control.Snapshot{}, e
		}
		// The lower bound must survive before ZFS can create the snapshot.
		// Retrying a lost snapshot response must not attach a later replay
		// position to the already captured, older filesystem state.
		plan.Snapshot.LowerBound = lower
		if e = save(path, plan); e != nil {
			return control.Snapshot{}, e
		}
	}
	ref, e := h.storage.EnsureSnapshot(ctx, plan.Command, baseline.Volume, plan.Snapshot.ID)
	if e != nil {
		return control.Snapshot{}, e
	}
	plan.Snapshot.Name = ref.Name
	plan.Snapshot.GUID = ref.GUID
	plan.Complete = true
	if e = save(path, plan); e != nil {
		return control.Snapshot{}, e
	}
	return plan.Snapshot, nil
}
