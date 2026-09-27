// Package host owns the privileged, tenant-local storage/runtime boundary.
package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"pgws/internal/atomicfile"
	"sync"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/physical"
	"pgws/internal/runtime"
	"pgws/internal/storage/zfs"
)

type SourceConfig struct {
	Tenant            string          `json:"tenant"`
	Project           string          `json:"project"`
	EndpointReference string          `json:"endpoint_reference"`
	SecretReference   string          `json:"secret_reference"`
	Source            physical.Source `json:"source"`
}
type Config struct {
	ID                 string         `json:"id"`
	Epoch              string         `json:"epoch"`
	Root               string         `json:"root"`
	Sockets            string         `json:"sockets"`
	Dataset            string         `json:"dataset"`
	MountRoot          string         `json:"mount_root"`
	GuardBinary        string         `json:"guard_binary"`
	SourceBrokerBinary string         `json:"source_broker_binary,omitempty"`
	Certificate        string         `json:"certificate"`
	CertificateKey     string         `json:"certificate_key"`
	AuthorityKey       string         `json:"authority_key"`
	SecretKey          string         `json:"secret_key"`
	Sources            []SourceConfig `json:"sources"`
	RPCSocket          string         `json:"rpc_socket,omitempty"`
	RPCGroup           int            `json:"rpc_group,omitempty"`
	MaxManagedMemory   int64          `json:"max_managed_memory_bytes,omitempty"`
	MinPoolAvailable   int64          `json:"min_pool_available_bytes,omitempty"`
	ProjectQuotaBytes  int64          `json:"project_quota_bytes,omitempty"`
	SeedMaxBytes       int64          `json:"seed_max_bytes,omitempty"`
}
type Manifest struct {
	Physical     physical.Manifest `json:"physical"`
	DataRelative string            `json:"data_relative"`
	SourceUser   string            `json:"source_user"`
}
type state struct {
	Task           control.Task      `json:"task"`
	Volume         zfs.Ref           `json:"volume"`
	Container      runtime.Container `json:"container"`
	RuntimeIntent  *runtime.Spec     `json:"runtime_intent,omitempty"`
	Recovery       physical.Recovery `json:"recovery"`
	Access         physical.Access   `json:"access"`
	Outcome        control.Outcome   `json:"outcome"`
	Phase          string            `json:"phase"`
	GuardDirectory string            `json:"guard_directory"`
	ServingStarted bool              `json:"serving_started,omitempty"`
	Endpoint       json.RawMessage   `json:"endpoint"`
	Slot           string            `json:"slot,omitempty"`
	SlotOwned      bool              `json:"slot_owned"`
	SlotRetired    bool              `json:"slot_retired,omitempty"`
	SourceIdentity physical.Identity `json:"source_identity"`
	ReservedMemory int64             `json:"reserved_memory_bytes"`
	CreateRequest  string            `json:"create_request,omitempty"`
	CreateStage    string            `json:"create_stage,omitempty"`
	Seeding        *sourceProgress   `json:"seeding,omitempty"`
}
type Host struct {
	Config                  Config
	storage                 *zfs.Backend
	oci                     runtime.OCI
	journal, storageJournal *lease.Journal
	locks                   sync.Map
	capacity                sync.Mutex
	usage                   sync.Mutex
	afterCreateEffect       func(string) // Test-only process-crash injection; never configured by RPC.
	afterSourceEffect       func(string) // Test-only process-crash injection; never configured by RPC.
}

func (h *Host) sourceEffect(stage string) {
	if h.afterSourceEffect != nil {
		h.afterSourceEffect(stage)
	}
}

func (h *Host) createdEffect(stage string) {
	if h.afterCreateEffect != nil {
		h.afterCreateEffect(stage)
	}
}

func Open(c Config) (*Host, error) {
	if _, _, err := c.seedLimits(); err != nil {
		return nil, err
	}
	if c.ID == "" || !control.ValidID(c.Epoch) || !filepath.IsAbs(c.Root) || !filepath.IsAbs(c.Sockets) || len(c.Sockets) > 45 {
		return nil, errors.New("invalid host identity or private directories")
	}
	for _, p := range []string{c.Root, c.Sockets} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return nil, e
		}
	}
	if e := checkRecoveryConfig(c); e != nil {
		return nil, e
	}
	j, e := lease.OpenJournal(filepath.Join(c.Root, "commands"), c.Epoch)
	if e != nil {
		return nil, e
	}
	sj, e := lease.OpenJournal(filepath.Join(c.Root, "storage-journal"), c.Epoch)
	if e != nil {
		j.Close()
		return nil, e
	}
	// Recheck while holding both locks: offline recovery may have started
	// between the first marker read and acquiring the command journal.
	if e = checkRecoveryConfig(c); e != nil {
		j.Close()
		sj.Close()
		return nil, e
	}
	b, e := zfs.New("/usr/sbin/zfs", c.Dataset, c.MountRoot, sj)
	if e != nil {
		j.Close()
		sj.Close()
		return nil, e
	}
	return &Host{Config: c, storage: b, oci: runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}, journal: j, storageJournal: sj}, nil
}
func (h *Host) Close() { h.journal.Close(); h.storageJournal.Close() }
func (h *Host) lock(id string) func() {
	v, _ := h.locks.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
func (h *Host) folder(t control.Task) string {
	return filepath.Join(h.Config.Root, "objects", t.Command.Workspace, fmt.Sprint(t.Command.Generation))
}
func (h *Host) socket(t control.Task) string {
	return filepath.Join(h.Config.Sockets, fmt.Sprintf("%s-%d", t.Command.Workspace, t.Command.Generation))
}
func save(path string, value any) error {
	return saveFile(path, value, false)
}

// saveOnce publishes fully synced bytes without replacing an existing record.
// Host and independent watchdog processes can race without changing the winner.
func saveOnce(path string, value any) error {
	return saveFile(path, value, true)
}

func saveFile(path string, value any, exclusive bool) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if exclusive {
		return atomicfile.Create(path, b)
	}
	return atomicfile.Replace(path, b)
}
func (h *Host) save(t control.Task, s state) error {
	return save(filepath.Join(h.folder(t), "state.json"), s)
}
func (h *Host) load(t control.Task) (state, error) {
	var s state
	b, e := os.ReadFile(filepath.Join(h.folder(t), "state.json"))
	if e != nil {
		return s, e
	}
	e = json.Unmarshal(b, &s)
	return s, e
}
func command(t control.Task) lease.Command {
	c := t.Command
	c.Kind = t.Kind
	b, _ := json.Marshal(t)
	c.PayloadHash = fmt.Sprintf("%x", sha256.Sum256(b))
	return c
}
func storageCommand(t control.Task, step int64) lease.Command {
	c := t.Command
	c.Token = c.Token*100 + step
	return c
}
func chownTree(path string) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in runtime data")
		}
		return os.Chown(p, 999, 999)
	})
}
func (h *Host) Execute(ctx context.Context, t control.Task) (control.Outcome, error) {
	if !control.ValidID(t.Command.Workspace) || t.Command.Host != h.Config.ID || t.Command.Epoch != h.Config.Epoch || t.Command.Token < 1 || t.Command.Token > 1e15 {
		return control.Outcome{}, errors.New("host command identity rejected")
	}
	unlock := h.lock(t.Command.Workspace)
	defer unlock()
	if t.Kind != "delete" && t.Kind != "expire" && t.Kind != "gc_snapshot" {
		if e := checkStopped(h.folder(t)); e != nil {
			return control.Outcome{}, e
		}
	}
	record, _, e := h.journal.Accept(command(t))
	if e != nil {
		return control.Outcome{}, e
	}
	if record.Completed {
		var out control.Outcome
		if json.Unmarshal(record.Evidence, &out) != nil {
			return out, errors.New("invalid host receipt")
		}
		if out.Phase != "deleted" && out.Phase != "snapshot_deleted" {
			s, e := h.load(t)
			if e != nil {
				return out, e
			}
			kind := "workspaces"
			if t.Kind == "register_source" || t.Kind == "reseed_source" || t.Kind == "issue_barrier" {
				kind = "baselines"
			}
			if e = h.storage.VerifyGeneration(ctx, t.Command, s.Volume, kind); e != nil {
				return out, e
			}
			if e = h.oci.Verify(ctx, s.Container); e != nil {
				return out, e
			}
		}
		return out, nil
	}
	var out control.Outcome
	switch t.Kind {
	case "create", "reset":
		out, e = h.create(ctx, t)
	case "pause", "resume", "extend_ttl":
		out, e = h.lifecycle(ctx, t)
	case "delete", "expire":
		out, e = h.remove(ctx, t)
	case "register_source", "reseed_source":
		out, e = h.register(ctx, t)
	case "issue_credential":
		out, e = h.issueCredential(ctx, t)
	case "issue_barrier":
		out, e = h.issueBarrier(ctx, t)
	case "gc_snapshot":
		out, e = h.collectSnapshot(ctx, t)
	default:
		e = errors.New("unsupported host command")
	}
	if e != nil {
		return out, e
	}
	if t.Kind != "delete" && t.Kind != "expire" && t.Kind != "gc_snapshot" {
		if e = checkStopped(h.folder(t)); e != nil {
			return control.Outcome{}, e
		}
	}
	b, _ := json.Marshal(out)
	if e = h.journal.CompleteWithEvidence(command(t), b); e != nil {
		return out, e
	}
	return out, nil
}
func (h *Host) Revoke(ctx context.Context, t control.Task) error {
	unlock := h.lock(t.Command.Workspace)
	defer unlock()
	if _, _, e := h.journal.Accept(command(t)); e != nil {
		return e
	}
	s, e := h.load(t)
	if e != nil {
		return e
	}
	if t.Kind == "register_source" || t.Kind == "reseed_source" {
		if e = recordStop(h.folder(t), "SOURCE_REVOKED"); e != nil {
			return e
		}
		if e = removeStoppedRuntime(ctx, h.oci, h.folder(t), s); e != nil {
			return e
		}
		if s.SlotOwned {
			source, e := h.resolve(t)
			if e != nil {
				return e
			}
			source.ExpectedSystemID = s.SourceIdentity.SystemID
			if e = source.DropSlot(ctx, s.Slot); e != nil {
				return e
			}
			s.SlotOwned = false
			s.SlotRetired = true
		}
		s.Phase = "blocked"
		return h.save(t, s)
	}
	if s.GuardDirectory != "" {
		_ = guardRequest(ctx, s.GuardDirectory, "close", nil, nil)
	}
	if s.Container.ID != "" && s.Recovery.DataDir != "" {
		_ = h.oci.Tools(s.Container).Stop(ctx, s.Recovery.DataDir)
	}
	return nil
}
func (h *Host) collectPrevious(ctx context.Context, t control.Task) error {
	if t.Kind != "reset" || t.Command.Generation < 2 {
		return nil
	}
	old := t
	old.Command.Generation--
	s, e := h.load(old)
	if e != nil {
		return e
	}
	if s.Task.Command.Tenant != t.Command.Tenant || s.Task.Command.Project != t.Command.Project || s.Task.Command.Workspace != t.Command.Workspace || s.Task.Command.Generation != old.Command.Generation {
		return errors.New("retired generation owner differs")
	}
	_ = guardRequest(ctx, s.GuardDirectory, "shutdown", nil, nil)
	if e = h.oci.Remove(ctx, s.Container); e != nil {
		return e
	}
	h.createdEffect("retired_runtime")
	if e = h.storage.DestroyRetired(ctx, storageCommand(t, 3), old.Command.Generation, s.Volume); e != nil {
		return e
	}
	h.createdEffect("retired_volume")
	s.Phase = "deleted"
	return h.save(old, s)
}
