package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/runtime"
	"pgws/internal/storage/zfs"
)

func (h *Host) create(ctx context.Context, t control.Task) (control.Outcome, error) {
	if !time.Now().Before(t.Expiry) {
		return control.Outcome{}, errors.New("workspace expired before creation")
	}
	memory, e := profileMemory(t.Profile)
	if e != nil {
		return control.Outcome{}, e
	}
	request := t
	request.Command.Token = 0 // Claims may advance the fence, not the request.
	requestHash := command(request).PayloadHash
	s, loadErr := h.load(t)
	if loadErr != nil && !os.IsNotExist(loadErr) {
		return control.Outcome{}, loadErr
	}
	if loadErr == nil {
		if s.CreateRequest != requestHash || s.Task.Command.Identity != t.Command.Identity || s.Task.Command.Operation != t.Command.Operation {
			return control.Outcome{}, errors.New("creation retry differs from its reserved request")
		}
		if s.Phase != "creating" && s.Phase != "ready" && s.Phase != "paused" {
			return control.Outcome{}, errors.New("generation is no longer a creation candidate")
		}
		if s.Phase == "ready" || s.Phase == "paused" {
			if e = h.storage.VerifyGeneration(ctx, t.Command, s.Volume, "workspaces"); e != nil {
				return control.Outcome{}, e
			}
			if e = h.oci.Verify(ctx, s.Container); e != nil {
				return control.Outcome{}, e
			}
			if s.Phase == "ready" {
				if e = h.oci.Tools(s.Container).StartDisconnected(ctx, s.Recovery); e != nil {
					return control.Outcome{}, e
				}
				if _, e = physical.VerifyPromoted(ctx, s.Recovery, s.Access.Admin); e != nil {
					return control.Outcome{}, e
				}
			}
			if e = h.collectPrevious(ctx, t); e != nil {
				return control.Outcome{}, e
			}
			t.Snapshot = s.Task.Snapshot
			s.Task = t
			if e = h.save(t, s); e != nil {
				return control.Outcome{}, e
			}
			return s.Outcome, nil
		}
	}
	if e = h.capacityCheck(ctx, t, state{ReservedMemory: memory}, false); e != nil {
		return control.Outcome{}, e
	}
	var captured *control.Snapshot
	if t.Freshness != nil && t.Freshness.Mode != "snapshot" {
		if loadErr == nil {
			t.Snapshot = s.Task.Snapshot
		} else {
			snap, e := h.capture(ctx, t)
			if e != nil {
				return control.Outcome{}, e
			}
			t.Snapshot = snap
		}
		snap := t.Snapshot
		captured = &snap
	}
	var manifest Manifest
	if json.Unmarshal(t.Snapshot.Manifest, &manifest) != nil || manifest.Physical.SystemID == "" || !regexp.MustCompile(`^seeds/[a-f0-9-]{36}/[1-9][0-9]*/data$`).MatchString(manifest.DataRelative) {
		return control.Outcome{}, errors.New("unqualified snapshot manifest")
	}
	if t.Snapshot.Digest != runtime.PostgresImage {
		return control.Outcome{}, errors.New("snapshot runtime digest mismatch")
	}
	if t.Kind == "reset" {
		old := t
		old.Command.Generation--
		if s, e := h.load(old); e == nil {
			_ = guardRequest(ctx, s.GuardDirectory, "close", nil, nil)
			if e = h.oci.Tools(s.Container).StopDisconnected(ctx, s.Recovery); e != nil {
				return control.Outcome{}, e
			}
			h.createdEffect("old_stop")
		}
	}
	if loadErr != nil {
		s = state{Task: t, Phase: "creating", CreateRequest: requestHash, CreateStage: "reserved", ReservedMemory: memory}
		if e := h.reserve(ctx, t, s); e != nil {
			return control.Outcome{}, e
		}
	} else {
		s.Task = t
	}
	if s.Volume.GUID == "" {
		ref, e := h.storage.EnsureClone(ctx, storageCommand(t, 1), zfs.Ref{Name: t.Snapshot.Name, GUID: t.Snapshot.GUID})
		if e != nil {
			return control.Outcome{}, e
		}
		s.Volume = ref
		h.createdEffect("clone")
		if e = h.save(t, s); e != nil {
			return control.Outcome{}, e
		}
	} else if e = h.storage.VerifyGeneration(ctx, t.Command, s.Volume, "workspaces"); e != nil {
		return control.Outcome{}, e
	}
	ref := s.Volume
	path, e := h.storage.Mount(ctx, storageCommand(t, 2), ref, 2<<30)
	if e != nil {
		return control.Outcome{}, e
	}
	data := filepath.Join(path, manifest.DataRelative)
	controlParent := filepath.Join(h.folder(t), "postgres-controls")
	socket := h.socket(t)
	for _, p := range []string{controlParent, socket} {
		if e = os.MkdirAll(p, 0700); e != nil {
			return control.Outcome{}, e
		}
		if e = os.Chown(p, 999, 999); e != nil {
			return control.Outcome{}, e
		}
	}
	r := physical.Recovery{DataDir: data, ControlDir: filepath.Join(controlParent, "recovery"), SocketDir: socket, SourceUser: manifest.SourceUser, Barrier: physical.Barrier{Identity: physical.Identity{SystemID: manifest.Physical.SystemID, Timeline: t.Snapshot.Timeline}, LSN: t.Snapshot.LowerBound}, Settings: manifest.Physical.Settings}
	if s.CreateStage == "reserved" {
		// No OCI command can run before the prepared stage is fsynced. Only
		// here may PID files inherited from the baseline be removed.
		if s.Container.ID != "" {
			return control.Outcome{}, errors.New("unprepared clone already has a runtime")
		}
		for _, name := range []string{"postmaster.pid", "postmaster.opts"} {
			if e = os.Remove(filepath.Join(data, name)); e != nil && !os.IsNotExist(e) {
				return control.Outcome{}, e
			}
		}
		if e = (physical.Tools{}).ResumePreparation(r); e != nil {
			return control.Outcome{}, e
		}
		if e = chownTree(controlParent); e != nil {
			return control.Outcome{}, e
		}
		h.createdEffect("controls")
		s.Recovery, s.CreateStage = r, "prepared"
		if e = h.save(t, s); e != nil {
			return control.Outcome{}, e
		}
	}
	if e = physical.ValidateRecoveryPlan(r); e != nil {
		return control.Outcome{}, e
	}
	if e = checkStopped(h.folder(t)); e != nil {
		return control.Outcome{}, e
	}
	if s.Container.ID == "" {
		spec := runtime.Spec{Identity: t.Command.Identity, DataDir: data, ControlDir: controlParent, SocketDir: socket, MemoryBytes: s.ReservedMemory}
		if s.RuntimeIntent != nil && *s.RuntimeIntent != spec {
			return control.Outcome{}, errors.New("runtime differs from its reserved creation intent")
		}
		s.RuntimeIntent = &spec
		if e = h.save(t, s); e != nil {
			return control.Outcome{}, e
		}
		c, e := h.oci.Ensure(ctx, spec)
		if e != nil {
			return control.Outcome{}, e
		}
		s.Container = c
		h.createdEffect("runtime")
		if e = h.save(t, s); e != nil {
			return control.Outcome{}, e
		}
	} else if e = h.oci.Verify(ctx, s.Container); e != nil {
		return control.Outcome{}, e
	}
	c := s.Container
	tools := h.oci.Tools(c)
	if e = tools.StartDisconnected(ctx, r); e != nil {
		return control.Outcome{}, e
	}
	h.createdEffect("start")
	if s.CreateStage == "prepared" {
		if _, e = tools.PromoteAndVerify(ctx, r); e != nil {
			return control.Outcome{}, e
		}
		h.createdEffect("promotion")
		s.CreateStage = "recovered"
		if e = h.save(t, s); e != nil {
			return control.Outcome{}, e
		}
	}
	if s.CreateStage == "recovered" {
		access, e := physical.HardenAccess(ctx, r)
		if e != nil {
			return control.Outcome{}, e
		}
		s.Access, s.CreateStage = access, "hardened"
		h.createdEffect("access")
		if e = h.save(t, s); e != nil {
			return control.Outcome{}, e
		}
	}
	if s.CreateStage != "hardened" || len(s.Access.Databases) != 1 {
		return control.Outcome{}, errors.New("endpoint database selection requires one admitted application database")
	}
	evidence, e := physical.VerifyPromoted(ctx, r, s.Access.Admin)
	if e != nil {
		return control.Outcome{}, e
	}
	s.GuardDirectory = filepath.Join(h.folder(t), "ingress")
	if e = h.save(t, s); e != nil {
		return control.Outcome{}, e
	}
	endpoint, e := h.startGuard(ctx, t, s)
	if e != nil {
		return control.Outcome{}, e
	}
	s.Endpoint = endpoint
	h.createdEffect("guard")
	proof, _ := json.Marshal(map[string]any{"recovery": evidence, "runtime_network": "none", "source_mounts": false, "imported_logins_disabled": true, "tls_required": true})
	out := control.Outcome{Phase: "ready", Snapshot: captured, Generation: &control.Realization{Generation: t.Command.Generation, SnapshotID: t.Snapshot.ID, VolumeName: ref.Name, VolumeGUID: ref.GUID, Runtime: c.ID, Digest: runtime.PostgresImage, Endpoint: endpoint, Evidence: proof}}
	if t.Desired == "paused" {
		if e = tools.StopDisconnected(ctx, r); e != nil {
			return out, e
		}
		out.Phase = "paused"
	}
	s.Phase = out.Phase
	s.Outcome = out
	if e = h.save(t, s); e != nil {
		return out, e
	}
	h.createdEffect("ready")
	if e = h.collectPrevious(ctx, t); e != nil {
		return out, e
	}
	return out, nil
}
