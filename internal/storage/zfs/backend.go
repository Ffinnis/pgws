// Package zfs operates only below an administrator-provisioned PGWS dataset.
// It does not create/import pools and never recursively destroys resources.
package zfs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"pgws/internal/lease"
)

type Ref struct {
	Name string `json:"name"`
	GUID string `json:"guid"`
}
type entry struct {
	Ref
	Kind, Origin, Mountpoint string
}
type runner interface {
	Run(context.Context, ...string) (string, error)
}
type commandRunner struct{ Binary string }

func (r commandRunner) Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	b, e := cmd.Output()
	if e != nil {
		return "", errors.New("ZFS command failed")
	}
	if len(b) > 8<<20 {
		return "", errors.New("ZFS inventory exceeds limit")
	}
	return string(b), nil
}

type Backend struct {
	mu              sync.Mutex
	root, mountRoot string
	run             runner
	journal         *lease.Journal
}

var datasetPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func New(binary, root, mountRoot string, journal *lease.Journal) (*Backend, error) {
	if !filepath.IsAbs(binary) || !datasetPattern.MatchString(root) || !filepath.IsAbs(mountRoot) || filepath.Clean(mountRoot) != mountRoot || journal == nil {
		return nil, errors.New("invalid ZFS backend configuration")
	}
	return &Backend{root: root, mountRoot: mountRoot, run: commandRunner{binary}, journal: journal}, nil
}
func (b *Backend) scope(c lease.Command) (string, error) {
	if !uuidPattern.MatchString(c.Tenant) || !uuidPattern.MatchString(c.Project) || !uuidPattern.MatchString(c.Workspace) || c.Generation < 1 {
		return "", errors.New("invalid ZFS resource identity")
	}
	return b.root + "/t_" + c.Tenant + "/p_" + c.Project, nil
}
func tags(c lease.Command) map[string]string {
	return map[string]string{"org.pgws:tenant": c.Tenant, "org.pgws:project": c.Project, "org.pgws:resource": c.Workspace, "org.pgws:generation": strconv.FormatInt(c.Generation, 10)}
}
func (b *Backend) owned(ctx context.Context, name string, want map[string]string) error {
	if !strings.HasPrefix(name, b.root+"/") && name != b.root {
		return errors.New("dataset outside configured root")
	}
	keys := []string{"org.pgws:tenant", "org.pgws:project", "org.pgws:resource", "org.pgws:generation", "org.pgws:origin_guid", "org.pgws:managed", "mountpoint", "canmount", "refquota", "quota"}
	out, e := b.run.Run(ctx, "get", "-H", "-p", "-o", "property,value,source", strings.Join(keys, ","), name)
	if e != nil {
		return e
	}
	seen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return errors.New("invalid ZFS property response")
		}
		if f[2] == "local" {
			seen[f[0]] = f[1]
		}
	}
	for key, value := range want {
		if seen[key] != value {
			return errors.New("ZFS local ownership property mismatch")
		}
	}
	return nil
}
func (b *Backend) inventory(ctx context.Context) (map[string]entry, error) {
	if e := b.owned(ctx, b.root, map[string]string{"org.pgws:managed": "on"}); e != nil {
		return nil, e
	}
	out, e := b.run.Run(ctx, "list", "-H", "-p", "-t", "filesystem,snapshot", "-o", "name,type,guid,origin,mountpoint", "-r", b.root)
	if e != nil {
		return nil, e
	}
	items := map[string]entry{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			return nil, errors.New("invalid ZFS inventory response")
		}
		if _, e = strconv.ParseUint(f[2], 10, 64); e != nil {
			return nil, errors.New("invalid ZFS GUID")
		}
		items[f[0]] = entry{Ref: Ref{f[0], f[2]}, Kind: f[1], Origin: f[3], Mountpoint: f[4]}
	}
	return items, nil
}
func verify(items map[string]entry, ref Ref, kind string) (entry, error) {
	e, ok := items[ref.Name]
	if !ok || ref.GUID == "" || e.GUID != ref.GUID || e.Kind != kind {
		return entry{}, errors.New("ZFS resource GUID/type mismatch")
	}
	return e, nil
}
func propertyArgs(values map[string]string) []string {
	// Fixed iteration order keeps command traces and incident evidence reproducible.
	keys := []string{"org.pgws:tenant", "org.pgws:project", "org.pgws:resource", "org.pgws:generation", "org.pgws:origin_guid", "org.pgws:managed", "mountpoint", "canmount", "quota"}
	var args []string
	for _, key := range keys {
		if value, ok := values[key]; ok {
			args = append(args, "-o", key+"="+value)
		}
	}
	return args
}
func (b *Backend) withFence(ctx context.Context, c lease.Command, kind string, payload any, fn func() (Ref, error)) (Ref, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, e := b.scope(c); e != nil {
		return Ref{}, e
	}
	if e := ctx.Err(); e != nil {
		return Ref{}, e
	}
	data, e := json.Marshal(payload)
	if e != nil {
		return Ref{}, e
	}
	c.Kind = kind
	c.PayloadHash = fmt.Sprintf("%x", sha256.Sum256(data))
	record, _, e := b.journal.Accept(c)
	if e != nil {
		return Ref{}, e
	}
	var prior Ref
	if record.Completed {
		if len(record.Evidence) == 0 || json.Unmarshal(record.Evidence, &prior) != nil {
			return Ref{}, errors.New("completed storage receipt has no GUID evidence")
		}
		items, e := b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		found, exists := items[prior.Name]
		destroy := kind == "zfs-destroy-clone" || kind == "zfs-destroy-retired" || kind == "zfs-destroy-snapshot" || kind == "zfs-destroy-retired-baseline"
		if (!exists && !destroy) || (exists && found.GUID != prior.GUID) {
			return Ref{}, errors.New("completed resource was removed or replaced; refuse recreation")
		}
	}
	// Inspect actual objects even after a completed replay; a durable receipt
	// alone cannot prove the object still exists with the recorded identity.
	result, e := fn()
	if e != nil {
		return Ref{}, e
	}
	if record.Completed && prior != result {
		return Ref{}, errors.New("resource differs from completed GUID receipt")
	}
	evidence, _ := json.Marshal(result)
	if e = b.journal.CompleteWithEvidence(c, evidence); e != nil {
		return Ref{}, e
	}
	return result, nil
}

func (b *Backend) EnsureBaseline(ctx context.Context, c lease.Command) (Ref, error) {
	return b.withFence(ctx, c, "zfs-baseline", c.Identity, func() (Ref, error) {
		scope, _ := b.scope(c)
		name := fmt.Sprintf("%s/baselines/%s/g%d", scope, c.Workspace, c.Generation)
		want := tags(c)
		want["mountpoint"] = b.mountpoint(c, "baselines")
		want["canmount"] = "noauto"
		items, e := b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, ok := items[name]; !ok {
			props := tags(c)
			props["mountpoint"] = filepath.Join(b.mountRoot, c.Tenant, c.Project, "baselines", c.Workspace, strconv.FormatInt(c.Generation, 10))
			props["canmount"] = "noauto"
			args := append([]string{"create", "-p"}, propertyArgs(props)...)
			args = append(args, name)
			if _, e = b.run.Run(ctx, args...); e != nil {
				return Ref{}, e
			}
			items, e = b.inventory(ctx)
			if e != nil {
				return Ref{}, e
			}
		}
		found, ok := items[name]
		if !ok || found.Kind != "filesystem" || found.Origin != "-" {
			return Ref{}, errors.New("baseline dataset identity mismatch")
		}
		if e = b.owned(ctx, name, want); e != nil {
			return Ref{}, e
		}
		return found.Ref, nil
	})
}
func (b *Backend) EnsureSnapshot(ctx context.Context, c lease.Command, baseline Ref, snapshotID string) (Ref, error) {
	if !uuidPattern.MatchString(snapshotID) {
		return Ref{}, errors.New("invalid snapshot ID")
	}
	return b.withFence(ctx, c, "zfs-snapshot", struct {
		Baseline Ref
		Snapshot string
	}{baseline, snapshotID}, func() (Ref, error) {
		scope, _ := b.scope(c)
		expected := fmt.Sprintf("%s/baselines/%s/g%d", scope, c.Workspace, c.Generation)
		if baseline.Name != expected {
			return Ref{}, errors.New("baseline outside operation identity")
		}
		items, e := b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, e = verify(items, baseline, "filesystem"); e != nil {
			return Ref{}, e
		}
		if e = b.owned(ctx, baseline.Name, tags(c)); e != nil {
			return Ref{}, e
		}
		name := baseline.Name + "@s_" + snapshotID
		want := tags(c)
		want["org.pgws:origin_guid"] = baseline.GUID
		if _, ok := items[name]; !ok {
			args := append([]string{"snapshot"}, propertyArgs(want)...)
			args = append(args, name)
			if _, e = b.run.Run(ctx, args...); e != nil {
				return Ref{}, e
			}
			items, e = b.inventory(ctx)
			if e != nil {
				return Ref{}, e
			}
		}
		found, ok := items[name]
		if !ok || found.Kind != "snapshot" {
			return Ref{}, errors.New("snapshot absent after creation")
		}
		if e = b.owned(ctx, name, want); e != nil {
			return Ref{}, e
		}
		// zfs hold fails on an existing tag, so inspect before retrying it.
		hold := "pgws:" + snapshotID
		out, e := b.run.Run(ctx, "holds", "-H", name)
		if e != nil {
			return Ref{}, e
		}
		held := false
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) >= 2 && fields[0] == name && fields[1] == hold {
				held = true
			}
		}
		if !held {
			if _, e = b.run.Run(ctx, "hold", hold, name); e != nil {
				return Ref{}, e
			}
		}
		return found.Ref, nil
	})
}
func (b *Backend) EnsureClone(ctx context.Context, c lease.Command, snapshot Ref) (Ref, error) {
	return b.withFence(ctx, c, "zfs-clone", snapshot, func() (Ref, error) {
		scope, _ := b.scope(c)
		if !strings.HasPrefix(snapshot.Name, scope+"/baselines/") || !strings.Contains(snapshot.Name, "@s_") {
			return Ref{}, errors.New("snapshot outside workspace project")
		}
		items, e := b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, e = verify(items, snapshot, "snapshot"); e != nil {
			return Ref{}, e
		}
		if e = b.owned(ctx, snapshot.Name, map[string]string{"org.pgws:tenant": c.Tenant, "org.pgws:project": c.Project}); e != nil {
			return Ref{}, e
		}
		name := fmt.Sprintf("%s/workspaces/%s/g%d", scope, c.Workspace, c.Generation)
		want := tags(c)
		want["org.pgws:origin_guid"] = snapshot.GUID
		want["mountpoint"] = b.mountpoint(c, "workspaces")
		want["canmount"] = "noauto"
		if _, ok := items[name]; !ok {
			props := tags(c)
			props["org.pgws:origin_guid"] = snapshot.GUID
			props["mountpoint"] = filepath.Join(b.mountRoot, c.Tenant, c.Project, "workspaces", c.Workspace, strconv.FormatInt(c.Generation, 10))
			props["canmount"] = "noauto"
			args := append([]string{"clone", "-p"}, propertyArgs(props)...)
			args = append(args, snapshot.Name, name)
			if _, e = b.run.Run(ctx, args...); e != nil {
				return Ref{}, e
			}
			items, e = b.inventory(ctx)
			if e != nil {
				return Ref{}, e
			}
		}
		found, ok := items[name]
		if !ok || found.Kind != "filesystem" || found.Origin != snapshot.Name {
			return Ref{}, errors.New("clone origin differs from requested snapshot")
		}
		if e = b.owned(ctx, name, want); e != nil {
			return Ref{}, e
		}
		return found.Ref, nil
	})
}
func (b *Backend) DestroyClone(ctx context.Context, c lease.Command, clone Ref) error {
	return b.destroyClone(ctx, c, c.Generation, clone)
}

// DestroyRetired retains the current generation's fence while deleting an
// explicitly identified older volume belonging to the same workspace.
func (b *Backend) DestroyRetired(ctx context.Context, c lease.Command, generation int64, clone Ref) error {
	if generation < 1 || generation >= c.Generation {
		return errors.New("only older generations may be collected")
	}
	return b.destroyClone(ctx, c, generation, clone)
}
func (b *Backend) destroyClone(ctx context.Context, c lease.Command, generation int64, clone Ref) error {
	kind := "zfs-destroy-clone"
	if generation != c.Generation {
		kind = "zfs-destroy-retired"
	}
	target := c
	target.Generation = generation
	guid, err := strconv.ParseUint(clone.GUID, 10, 64)
	if err != nil || guid == 0 {
		return errors.New("clone GUID is required for destruction")
	}
	_, e := b.withFence(ctx, c, kind, struct {
		Ref        Ref
		Generation int64
	}{clone, generation}, func() (Ref, error) {
		scope, _ := b.scope(c)
		expected := fmt.Sprintf("%s/workspaces/%s/g%d", scope, c.Workspace, generation)
		if clone.Name != expected {
			return Ref{}, errors.New("clone outside operation identity")
		}
		items, e := b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, ok := items[clone.Name]; !ok {
			return clone, nil
		}
		if _, e = verify(items, clone, "filesystem"); e != nil {
			return Ref{}, e
		}
		if e = b.owned(ctx, clone.Name, tags(target)); e != nil {
			return Ref{}, e
		}
		if _, e = b.run.Run(ctx, "destroy", clone.Name); e != nil {
			return Ref{}, e
		}
		items, e = b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, exists := items[clone.Name]; exists {
			return Ref{}, errors.New("clone remains after destroy")
		}
		return clone, nil
	})
	return e
}

func (b *Backend) mountpoint(c lease.Command, kind string) string {
	return filepath.Join(b.mountRoot, c.Tenant, c.Project, kind, c.Workspace, strconv.FormatInt(c.Generation, 10))
}

// Mount establishes a hard referenced-byte quota before explicitly mounting the
// owned generation. The pool administrator must reserve free space separately.
func (b *Backend) Mount(ctx context.Context, c lease.Command, ref Ref, maxBytes int64) (string, error) {
	if maxBytes < 32<<20 {
		return "", errors.New("dataset quota must be at least 32 MiB")
	}
	var path string
	_, err := b.withFence(ctx, c, "zfs-mount", struct {
		Ref      Ref
		MaxBytes int64
	}{ref, maxBytes}, func() (Ref, error) {
		scope, _ := b.scope(c)
		kind := ""
		for _, candidate := range []string{"baselines", "workspaces"} {
			if ref.Name == fmt.Sprintf("%s/%s/%s/g%d", scope, candidate, c.Workspace, c.Generation) {
				kind = candidate
			}
		}
		if kind == "" {
			return Ref{}, errors.New("dataset outside command identity")
		}
		items, e := b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, e = verify(items, ref, "filesystem"); e != nil {
			return Ref{}, e
		}
		path = b.mountpoint(c, kind)
		want := tags(c)
		want["mountpoint"] = path
		want["canmount"] = "noauto"
		if e = b.owned(ctx, ref.Name, want); e != nil {
			return Ref{}, e
		}
		quota := strconv.FormatInt(maxBytes, 10)
		if e = b.owned(ctx, ref.Name, map[string]string{"refquota": quota}); e != nil {
			if _, e = b.run.Run(ctx, "set", "refquota="+quota, ref.Name); e != nil {
				return Ref{}, e
			}
		}
		mounted, e := b.run.Run(ctx, "get", "-H", "-o", "value", "mounted", ref.Name)
		if e != nil {
			return Ref{}, e
		}
		switch strings.TrimSpace(mounted) {
		case "no":
			if _, e = b.run.Run(ctx, "mount", ref.Name); e != nil {
				return Ref{}, e
			}
		case "yes":
		default:
			return Ref{}, errors.New("invalid mount status")
		}
		return ref, nil
	})
	return path, err
}

// VerifyGeneration reads actual GUID and local ownership without changing
// fences, mounts or objects. Receipts alone never prove a live realization.
func (b *Backend) VerifyGeneration(ctx context.Context, c lease.Command, ref Ref, kind string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if kind != "baselines" && kind != "workspaces" {
		return errors.New("invalid generation kind")
	}
	scope, e := b.scope(c)
	if e != nil {
		return e
	}
	if ref.Name != fmt.Sprintf("%s/%s/%s/g%d", scope, kind, c.Workspace, c.Generation) {
		return errors.New("generation outside owner scope")
	}
	items, e := b.inventory(ctx)
	if e != nil {
		return e
	}
	if _, e = verify(items, ref, "filesystem"); e != nil {
		return e
	}
	want := tags(c)
	want["mountpoint"] = b.mountpoint(c, kind)
	want["canmount"] = "noauto"
	return b.owned(ctx, ref.Name, want)
}

// Available returns the root dataset's allocatable bytes, not host disk space.
func (b *Backend) Available(ctx context.Context) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.owned(ctx, b.root, map[string]string{"org.pgws:managed": "on"}); e != nil {
		return 0, e
	}
	raw, e := b.run.Run(ctx, "get", "-H", "-p", "-o", "value", "available", b.root)
	if e != nil {
		return 0, e
	}
	n, e := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if e != nil || n < 0 {
		return 0, errors.New("invalid ZFS available capacity")
	}
	return n, nil
}

func (b *Backend) VerifyCloneAbsent(ctx context.Context, c lease.Command) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	scope, e := b.scope(c)
	if e != nil {
		return e
	}
	items, e := b.inventory(ctx)
	if e != nil {
		return e
	}
	name := fmt.Sprintf("%s/workspaces/%s/g%d", scope, c.Workspace, c.Generation)
	if _, present := items[name]; present {
		return errors.New("unrecorded generation exists; explicit GUID reconciliation is required")
	}
	return nil
}

// DestroySnapshot only releases this service's hold and never destroys clones.
func (b *Backend) DestroySnapshot(ctx context.Context, c lease.Command, ref Ref, snapshotID string) error {
	return b.destroySnapshot(ctx, c, c.Generation, ref, snapshotID)
}

// DestroyRetiredSnapshot keeps the current source fence while verifying the
// original generation's path, GUID and ownership labels.
func (b *Backend) DestroyRetiredSnapshot(ctx context.Context, c lease.Command, generation int64, ref Ref, snapshotID string) error {
	if generation < 1 || generation >= c.Generation {
		return errors.New("only older baseline snapshots may be collected")
	}
	return b.destroySnapshot(ctx, c, generation, ref, snapshotID)
}

var ErrBaselineReferenced = errors.New("retired baseline still has snapshots or dependents")

// Nonrecursive destruction can collect an old baseline only after every actual
// snapshot and dependent clone has gone. Metadata alone cannot grant deletion.
func (b *Backend) DestroyRetiredBaseline(ctx context.Context, c lease.Command, generation int64, ref Ref) error {
	if generation < 1 || generation >= c.Generation {
		return errors.New("only older baselines may be collected")
	}
	_, err := b.withFence(ctx, c, "zfs-destroy-retired-baseline", ref, func() (Ref, error) {
		scope, _ := b.scope(c)
		expected := fmt.Sprintf("%s/baselines/%s/g%d", scope, c.Workspace, generation)
		if ref.Name != expected || ref.GUID == "" {
			return Ref{}, errors.New("baseline outside cleanup authority")
		}
		items, err := b.inventory(ctx)
		if err != nil {
			return Ref{}, err
		}
		if _, ok := items[ref.Name]; !ok {
			return ref, nil
		}
		if _, err = verify(items, ref, "filesystem"); err != nil {
			return Ref{}, err
		}
		owner := c
		owner.Generation = generation
		if err = b.owned(ctx, ref.Name, tags(owner)); err != nil {
			return Ref{}, err
		}
		for name, item := range items {
			if strings.HasPrefix(name, ref.Name+"@") || strings.HasPrefix(name, ref.Name+"/") || strings.HasPrefix(item.Origin, ref.Name+"@") {
				return Ref{}, ErrBaselineReferenced
			}
		}
		if _, err = b.run.Run(ctx, "destroy", ref.Name); err != nil {
			return Ref{}, err
		}
		items, err = b.inventory(ctx)
		if err != nil {
			return Ref{}, err
		}
		if _, ok := items[ref.Name]; ok {
			return Ref{}, errors.New("retired baseline remains after cleanup")
		}
		return ref, nil
	})
	return err
}

func (b *Backend) destroySnapshot(ctx context.Context, c lease.Command, generation int64, ref Ref, snapshotID string) error {
	if !uuidPattern.MatchString(snapshotID) {
		return errors.New("invalid snapshot identity")
	}
	_, e := b.withFence(ctx, c, "zfs-destroy-snapshot", ref, func() (Ref, error) {
		scope, _ := b.scope(c)
		expected := fmt.Sprintf("%s/baselines/%s/g%d@s_%s", scope, c.Workspace, generation, snapshotID)
		if ref.Name != expected || ref.GUID == "" {
			return Ref{}, errors.New("snapshot outside cleanup authority")
		}
		items, e := b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, exists := items[ref.Name]; !exists {
			return ref, nil
		}
		if _, e = verify(items, ref, "snapshot"); e != nil {
			return Ref{}, e
		}
		owner := c
		owner.Generation = generation
		if e = b.owned(ctx, ref.Name, tags(owner)); e != nil {
			return Ref{}, e
		}
		for _, item := range items {
			if item.Origin == ref.Name {
				return Ref{}, errors.New("snapshot still has a clone")
			}
		}
		raw, e := b.run.Run(ctx, "holds", "-H", ref.Name)
		if e != nil {
			return Ref{}, e
		}
		tag := "pgws:" + snapshotID
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) >= 2 && fields[0] == ref.Name && fields[1] == tag {
				if _, e = b.run.Run(ctx, "release", tag, ref.Name); e != nil {
					return Ref{}, e
				}
			}
		}
		if _, e = b.run.Run(ctx, "destroy", ref.Name); e != nil {
			return Ref{}, e
		}
		items, e = b.inventory(ctx)
		if e != nil {
			return Ref{}, e
		}
		if _, exists := items[ref.Name]; exists {
			return Ref{}, errors.New("snapshot remains after cleanup")
		}
		return ref, nil
	})
	return e
}
