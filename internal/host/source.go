package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/runtime"
)

type sourceProgress struct {
	Request      string              `json:"request"`
	Source       physical.Source     `json:"source"`
	Manifest     physical.Manifest   `json:"manifest"`
	Stage        string              `json:"stage"`
	Seed         physical.SeedResult `json:"seed"`
	LowerBound   string              `json:"lower_bound,omitempty"`
	SeedMaxBytes int64               `json:"seed_max_bytes,omitempty"`
}

func (h *Host) register(ctx context.Context, t control.Task) (control.Outcome, error) {
	seedBudget, baselineQuota, err := h.Config.seedLimits()
	if err != nil {
		return control.Outcome{}, err
	}
	source, err := h.resolve(t)
	if err != nil {
		return control.Outcome{}, err
	}
	if t.SourceID != t.Command.Workspace || t.Command.Generation < 1 || (t.Kind == "register_source" && t.Command.Generation != 1) {
		return control.Outcome{}, errors.New("source registration requires its initial generation")
	}
	baselineID, epoch := t.SourceID, int64(1)
	if t.Kind == "reseed_source" {
		if t.Command.Generation < 2 || t.Command.Generation > 1e9 || !control.ValidID(t.Snapshot.Baseline) || t.Snapshot.Baseline == t.SourceID || t.Snapshot.BaselineGeneration != t.Command.Generation || t.Snapshot.SourceEpoch < 2 {
			return control.Outcome{}, errors.New("invalid new source generation")
		}
		baselineID, epoch = t.Snapshot.Baseline, t.Snapshot.SourceEpoch
		if err = h.retireSource(ctx, t); err != nil {
			return control.Outcome{}, err
		}
	}
	request := t
	request.Command.Token = 0
	requestHash := command(request).PayloadHash
	s, loadErr := h.load(t)
	if loadErr != nil && !os.IsNotExist(loadErr) {
		return control.Outcome{}, loadErr
	}
	if loadErr == nil {
		if s.Seeding != nil && effectiveSeedBudget(s.Seeding.SeedMaxBytes) != seedBudget {
			return control.Outcome{}, errors.New("seed budget differs from its reserved generation")
		}
		if s.Seeding == nil || s.Seeding.Request != requestHash || s.Task.Command.Identity != t.Command.Identity || !reflect.DeepEqual(s.Seeding.Source, source) {
			return control.Outcome{}, errors.New("source retry differs from its reserved request or configuration")
		}
		if (s.Phase != "seeding" && s.Phase != "streaming") || !s.SlotOwned {
			// A slot created just before a lost receipt is never adopted by name.
			return control.Outcome{}, errors.New("source slot ownership or generation requires reconciliation")
		}
		s.Task = t
	} else {
		manifest, err := source.Inspect(ctx)
		if err != nil {
			return control.Outcome{}, err
		}
		if err = manifest.RequireSeedable(); err != nil {
			return control.Outcome{}, err
		}
		s = state{Task: t, Phase: "seeding", ReservedMemory: 1 << 30, SourceIdentity: manifest.Identity, Slot: "pgws_" + strings.ReplaceAll(t.SourceID, "-", "") + fmt.Sprintf("_g%d", t.Command.Generation), Seeding: &sourceProgress{Request: requestHash, Source: source, Manifest: manifest, Stage: "reserved", SeedMaxBytes: seedBudget}}
		if err = h.reserve(ctx, t, s); err != nil {
			return control.Outcome{}, err
		}
		source.ExpectedSystemID = manifest.SystemID
		if err = source.ReserveSlot(ctx, s.Slot, 256<<20); err != nil {
			return control.Outcome{}, err
		}
		h.sourceEffect("unconfirmed_slot")
		s.SlotOwned = true
		if err = h.save(t, s); err != nil {
			return control.Outcome{}, err
		}
		h.sourceEffect("slot")
	}
	p := s.Seeding
	if p.Stage != "reserved" && p.Stage != "seeded" && p.Stage != "prepared" && p.Stage != "capturing" && p.Stage != "streaming" {
		return control.Outcome{}, errors.New("unknown source recovery stage")
	}
	source.ExpectedSystemID = s.SourceIdentity.SystemID
	if identity, err := source.Identify(ctx); err != nil || identity != s.SourceIdentity {
		return control.Outcome{}, errors.New("source lineage changed during registration retry")
	}
	if retained, lost, err := source.SlotPressure(ctx, s.Slot); err != nil || lost || retained >= 192<<20 {
		return control.Outcome{}, errors.New("owned source slot is unavailable or exceeds its WAL budget")
	}
	if s.Volume.GUID == "" {
		volume, err := h.storage.EnsureBaseline(ctx, h.sourceStorageCommand(t, 1))
		if err != nil {
			return control.Outcome{}, err
		}
		s.Volume = volume
		h.sourceEffect("volume")
		if err = h.save(t, s); err != nil {
			return control.Outcome{}, err
		}
	} else if err = h.storage.VerifyGeneration(ctx, t.Command, s.Volume, "baselines"); err != nil {
		return control.Outcome{}, err
	}
	path, err := h.storage.Mount(ctx, h.sourceStorageCommand(t, 2), s.Volume, baselineQuota)
	if err != nil {
		return control.Outcome{}, err
	}
	ctrl, socket := filepath.Join(h.folder(t), "postgres-controls"), h.socket(t)
	for _, directory := range []string{ctrl, socket} {
		if err = os.MkdirAll(directory, 0700); err != nil {
			return control.Outcome{}, err
		}
		if err = os.Chown(directory, 999, 999); err != nil {
			return control.Outcome{}, err
		}
	}
	upstreamSocket := source.Host
	if !filepath.IsAbs(source.Host) {
		upstreamSocket, err = h.ensureSourceBroker(ctx, t, source)
		if err != nil {
			return control.Outcome{}, err
		}
	}
	spec := runtime.Spec{Identity: t.Command.Identity, DataDir: path, ControlDir: ctrl, SocketDir: socket, MemoryBytes: 1 << 30, SourceSocket: upstreamSocket, Purpose: "baseline"}
	if s.RuntimeIntent != nil && *s.RuntimeIntent != spec {
		return control.Outcome{}, errors.New("baseline runtime differs from its reserved intent")
	}
	if p.Stage == "reserved" && loadErr == nil {
		// A killed host can leave pg_basebackup running inside Docker. Remove
		// the exact reserved runtime before discarding any partial backup.
		if err = h.discardPartialSeed(ctx, t, &s, path); err != nil {
			return control.Outcome{}, err
		}
	}
	if s.Container.ID == "" {
		s.RuntimeIntent = &spec
		if err = h.save(t, s); err != nil {
			return control.Outcome{}, err
		}
		container, err := h.oci.Ensure(ctx, spec)
		if err != nil {
			return control.Outcome{}, err
		}
		s.Container = container
		h.sourceEffect("runtime")
		if err = h.save(t, s); err != nil {
			return control.Outcome{}, err
		}
	} else if err = h.oci.Verify(ctx, s.Container); err != nil {
		return control.Outcome{}, err
	}
	tools := h.oci.Tools(s.Container)
	if p.Stage == "reserved" {
		seed, err := tools.Seed(ctx, source, path, t.SourceID, t.Command.Generation, seedBudget)
		if err != nil {
			return control.Outcome{}, err
		}
		h.sourceEffect("seed")
		manifest, err := seedManifest(seed)
		if err != nil {
			return control.Outcome{}, err
		}
		barrier, err := source.CaptureBarrier(ctx)
		if err != nil || barrier.Identity != s.SourceIdentity || seed.SourceIdentity != s.SourceIdentity {
			return control.Outcome{}, errors.New("source lineage changed between seed and barrier")
		}
		p.Seed, p.Manifest, p.Stage = seed, manifest, "seeded"
		s.Recovery = physical.Recovery{DataDir: seed.DataDir, ControlDir: filepath.Join(ctrl, "recovery"), SocketDir: socket, SourceUser: source.User, Barrier: barrier, Settings: p.Manifest.Settings}
		if err = h.save(t, s); err != nil {
			return control.Outcome{}, err
		}
	}
	expectedSeed := physical.SeedResult{SourceIdentity: s.SourceIdentity, Generation: t.Command.Generation, DataDir: filepath.Join(path, "seeds", t.SourceID, fmt.Sprint(t.Command.Generation), "data"), Verified: true}
	if p.Seed != expectedSeed || s.Recovery.DataDir != expectedSeed.DataDir || s.Recovery.ControlDir != filepath.Join(ctrl, "recovery") || s.Recovery.SocketDir != socket || s.Recovery.SourceUser != source.User || s.Recovery.Barrier.Identity != s.SourceIdentity || p.Manifest.Identity != s.SourceIdentity || !reflect.DeepEqual(s.Recovery.Settings, p.Manifest.Settings) {
		return control.Outcome{}, errors.New("persisted seed differs from its source generation")
	}
	if p.Stage == "seeded" {
		if err = pruneSeedArchives(p.Seed); err != nil {
			return control.Outcome{}, err
		}
		if err = tools.ResumeStreamingPreparation(s.Recovery, source, s.Slot); err != nil {
			return control.Outcome{}, err
		}
		if err = chownTree(ctrl); err != nil {
			return control.Outcome{}, err
		}
		h.sourceEffect("controls")
		p.Stage = "prepared"
		if err = h.save(t, s); err != nil {
			return control.Outcome{}, err
		}
	}
	if err = checkStopped(h.folder(t)); err != nil {
		return control.Outcome{}, err
	}
	if err = tools.RefreshStreamingSecret(s.Recovery, source, s.Slot); err != nil {
		return control.Outcome{}, err
	}
	if err = tools.StartDisconnected(ctx, s.Recovery); err != nil {
		return control.Outcome{}, err
	}
	h.sourceEffect("start")
	baseline := physical.Source{Host: socket, Port: 5432, User: source.User, Database: "postgres"}
	lower, err := physical.WaitReplay(ctx, baseline, s.Recovery.Barrier)
	if err != nil {
		return control.Outcome{}, err
	}
	if p.Stage == "prepared" {
		p.LowerBound, p.Stage = lower, "capturing"
		if err = h.save(t, s); err != nil {
			return control.Outcome{}, err
		}
	}
	// This position precedes the ZFS call. Never attach newer WAL evidence to
	// older bytes when a snapshot response is lost.
	if minimum, e := physical.ParseLSN(p.LowerBound); e != nil {
		return control.Outcome{}, errors.New("invalid persisted source capture position")
	} else if required, e := physical.ParseLSN(s.Recovery.Barrier.LSN); e != nil || minimum < required {
		return control.Outcome{}, errors.New("persisted source capture precedes the required barrier")
	} else if actual, e := physical.ParseLSN(lower); e != nil || actual < minimum {
		return control.Outcome{}, errors.New("baseline replay moved behind its captured lower bound")
	}
	snapshot, err := h.storage.EnsureSnapshot(ctx, h.sourceStorageCommand(t, 3), s.Volume, t.Command.Operation)
	if err != nil {
		return control.Outcome{}, err
	}
	h.sourceEffect("capture")
	rel, err := filepath.Rel(path, p.Seed.DataDir)
	if err != nil {
		return control.Outcome{}, err
	}
	compat, _ := json.Marshal(Manifest{Physical: p.Manifest, DataRelative: rel, SourceUser: source.User})
	discovery, _ := json.Marshal(p.Manifest)
	out := control.Outcome{Phase: "streaming", Source: &control.SourceOutcome{ID: t.SourceID, SystemID: s.SourceIdentity.SystemID, Timeline: s.SourceIdentity.Timeline, Discovery: discovery, Snapshot: control.Snapshot{ID: t.Command.Operation, Baseline: baselineID, BaselineGeneration: t.Command.Generation, Name: snapshot.Name, GUID: snapshot.GUID, Digest: runtime.PostgresImage, SourceEpoch: epoch, Timeline: s.SourceIdentity.Timeline, LowerBound: p.LowerBound, RequestedLSN: s.Recovery.Barrier.LSN, Manifest: compat}}}
	if s.Phase == "streaming" {
		before, _ := json.Marshal(s.Outcome)
		after, _ := json.Marshal(out)
		if !bytes.Equal(before, after) {
			return control.Outcome{}, errors.New("source realization differs from its completed receipt")
		}
	}
	s.Phase, p.Stage, s.Outcome = "streaming", "streaming", out
	if err = h.save(t, s); err != nil {
		return out, err
	}
	h.sourceEffect("streaming")
	return out, nil
}
