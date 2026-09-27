package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/runtime"
	"pgws/internal/storage/zfs"
)

type hostRecovery struct {
	Plan     control.RecoveryPlan   `json:"plan"`
	Complete bool                   `json:"complete"`
	Report   control.RecoveryReport `json:"report"`
}

// RecoverAuthority is offline: both command journals must be exclusively
// locked, so a live host daemon cannot race recovery. A durable root marker
// fences normal startup before any runtime is touched. Retained data is never
// promoted or destroyed by this procedure.
func RecoverAuthority(ctx context.Context, old, next Config, plan control.RecoveryPlan) (control.RecoveryReport, error) {
	return recoverAuthority(ctx, old, next, plan, func(string) {})
}

func recoverAuthority(ctx context.Context, old, next Config, plan control.RecoveryPlan, effect func(string)) (control.RecoveryReport, error) {
	var empty control.RecoveryReport
	if err := plan.Validate(); err != nil {
		return empty, err
	}
	priorKey, e := base64.StdEncoding.DecodeString(old.AuthorityKey)
	newKey, e2 := base64.StdEncoding.DecodeString(next.AuthorityKey)
	compare := next
	compare.Epoch = old.Epoch
	compare.AuthorityKey = old.AuthorityKey
	if e != nil || e2 != nil || old.Epoch != plan.Previous || next.Epoch != plan.Epoch || !bytes.Equal(priorKey, plan.PreviousKey) || !bytes.Equal(newKey, plan.PublicKey) || !reflect.DeepEqual(old, compare) || !filepath.IsAbs(old.Root) {
		return empty, errors.New("recovery configs must retain the host and storage identity and rotate exactly the authority epoch and public key")
	}
	found := false
	for _, host := range plan.Hosts {
		found = found || host == old.ID
	}
	if !found {
		return empty, errors.New("host missing from external recovery plan")
	}
	j, e := lease.OpenRecoveryJournal(filepath.Join(old.Root, "commands"), old.Epoch, next.Epoch)
	if e != nil {
		return empty, e
	}
	defer j.Close()
	sj, e := lease.OpenRecoveryJournal(filepath.Join(old.Root, "storage-journal"), old.Epoch, next.Epoch)
	if e != nil {
		return empty, e
	}
	defer sj.Close()
	storage, e := zfs.New("/usr/sbin/zfs", old.Dataset, old.MountRoot, sj)
	if e != nil {
		return empty, e
	}
	h := &Host{Config: old, storage: storage, journal: j, storageJournal: sj, oci: runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}}
	marker := filepath.Join(old.Root, "authority-recovery.json")
	progress := hostRecovery{Plan: plan}
	if data, err := os.ReadFile(marker); err == nil {
		var previous hostRecovery
		if json.Unmarshal(data, &previous) != nil {
			return empty, errors.New("host recovery marker is unreadable")
		}
		if previous.Plan.Hash() == plan.Hash() {
			progress = previous
		} else if !previous.Complete || previous.Plan.Epoch != plan.Previous {
			return empty, errors.New("another host recovery is in progress")
		}
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	if e = save(marker, progress); e != nil {
		return empty, e
	}
	if progress.Complete {
		return progress.Report, nil
	}
	effect("marker")
	paths, e := filepath.Glob(filepath.Join(old.Root, "objects", "*", "*", "state.json"))
	if e != nil || len(paths) > 10000 {
		return empty, errors.New("recovery generation inventory unavailable")
	}
	report := control.RecoveryReport{Host: old.ID, Epoch: plan.Epoch, PlanHash: plan.Hash(), PublicKey: plan.PublicKey}
	var failures []error
	for _, path := range paths {
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		data, err := os.ReadFile(path)
		var s state
		if err != nil || json.Unmarshal(data, &s) != nil || s.Task.Command.Host != old.ID || !control.ValidID(s.Task.Command.Epoch) || s.Task.Command.Epoch == plan.Epoch || filepath.Join(h.folder(s.Task), "state.json") != path {
			failures = append(failures, errors.New("recovery generation identity differs"))
			continue
		}
		folder := filepath.Dir(path)
		// Always stop before inspecting storage. A changed GUID must block
		// reconciliation without allowing its old database to keep serving.
		if err = recordStop(folder, "AUTHORITY_RECOVERY"); err == nil {
			err = removeStoppedRuntime(ctx, h.oci, folder, s)
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if s.GuardDirectory != "" {
			_ = guardRequest(ctx, s.GuardDirectory, "shutdown", nil, nil)
		}
		if s.Container.ID == "" {
			if err = recordAbsentRuntimeRelease(folder, s.Task.Command.Identity); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		deleted := s.Phase == "deleted"
		source := s.Task.SourceID == s.Task.Command.Workspace
		if !deleted && s.Volume.GUID != "" {
			kind := "workspaces"
			if source {
				kind = "baselines"
			}
			if err = h.storage.VerifyGeneration(ctx, s.Task.Command, s.Volume, kind); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if !deleted {
			s.Phase = "quarantined"
			if err = h.save(s.Task, s); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		report.Generations = append(report.Generations, control.RecoveryGeneration{Identity: s.Task.Command.Identity, Source: source, Deleted: deleted, VolumeName: s.Volume.Name, VolumeGUID: s.Volume.GUID})
	}
	// Any unrecorded runtime keeps the cell closed. Never infer ownership from
	// its name and kill it as part of an inventory sweep.
	if e = h.oci.VerifyHostAbsent(ctx, old.ID); e != nil {
		failures = append(failures, e)
	}
	if e = errors.Join(failures...); e != nil {
		return empty, e
	}
	effect("runtimes")
	// Keep old unacknowledged measurements for operator audit without replaying
	// them as new authority measurements or blocking the new outbox.
	if _, err := os.Lstat(h.usagePath()); err == nil {
		batch, err := h.readUsage()
		if err != nil {
			return empty, err
		}
		archive := filepath.Join(old.Root, "usage", "recovered-"+batch.Epoch+"-"+batch.ID+".json")
		if e = os.Rename(h.usagePath(), archive); e != nil {
			return empty, e
		}
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	// A retry may observe the rename from an earlier failed directory fsync.
	if e = syncUsageDirectory(filepath.Dir(h.usagePath())); e != nil && !os.IsNotExist(e) {
		return empty, e
	}
	commands, e := j.AdvanceEpoch(plan.Previous, plan.Epoch)
	if e != nil {
		return empty, e
	}
	effect("commands")
	storageCommands, e := sj.AdvanceEpoch(plan.Previous, plan.Epoch)
	if e != nil {
		return empty, e
	}
	effect("storage")
	for _, r := range commands {
		report.Commands = append(report.Commands, r.Command)
	}
	for _, r := range storageCommands {
		report.Storage = append(report.Storage, r.Command)
	}
	sort.Slice(report.Commands, func(i, j int) bool { return report.Commands[i].Workspace < report.Commands[j].Workspace })
	sort.Slice(report.Storage, func(i, j int) bool { return report.Storage[i].Workspace < report.Storage[j].Workspace })
	progress.Complete = true
	progress.Report = report
	archive := filepath.Join(old.Root, "authority-recoveries", plan.Epoch+".json")
	if e = save(archive, progress); e != nil {
		return empty, e
	}
	effect("archive")
	if e = save(marker, progress); e != nil {
		return empty, e
	}
	effect("complete")
	return report, nil
}

func checkRecoveryConfig(c Config) error {
	data, err := os.ReadFile(filepath.Join(c.Root, "authority-recovery.json"))
	if os.IsNotExist(err) {
		return nil
	}
	var state hostRecovery
	key, e := base64.StdEncoding.DecodeString(c.AuthorityKey)
	if err != nil || json.Unmarshal(data, &state) != nil || state.Plan.Validate() != nil || !state.Complete || state.Plan.Epoch != c.Epoch || e != nil || !bytes.Equal(key, state.Plan.PublicKey) || state.Report.Host != c.ID || state.Report.PlanHash != state.Plan.Hash() {
		return errors.New("host authority recovery requires the offline operator entrypoint")
	}
	return nil
}

func (h *Host) RecoveryReport(ctx context.Context, t control.Task) (control.RecoveryReport, error) {
	var state hostRecovery
	var query struct {
		Hash string `json:"plan_hash"`
	}
	if t.Kind != "recovery_report" || t.Command.Epoch != h.Config.Epoch || t.Command.Host != h.Config.ID || json.Unmarshal(t.Document, &query) != nil {
		return state.Report, errors.New("invalid recovery acknowledgement scope")
	}
	if err := checkRecoveryConfig(h.Config); err != nil {
		return state.Report, err
	}
	data, err := os.ReadFile(filepath.Join(h.Config.Root, "authority-recovery.json"))
	if err != nil || json.Unmarshal(data, &state) != nil || state.Plan.Hash() != query.Hash || !state.Complete {
		return control.RecoveryReport{}, errors.New("host recovery acknowledgement unavailable")
	}
	return state.Report, ctx.Err()
}
