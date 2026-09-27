// Package runtime controls tenant-local PostgreSQL containers. Only the trusted
// host process receives Docker access; API clients supply no container options.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"pgws/internal/lease"
	"pgws/internal/physical"
)

const PostgresImage = "postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae"
const PostgresBin = "/usr/lib/postgresql/18/bin"

type OCI struct{ Binary, Image string }
type Container struct {
	ID   string `json:"id"`
	Spec Spec   `json:"spec"`
}
type Spec struct {
	Identity           lease.Identity `json:"identity"`
	DataDir            string         `json:"data_directory"`
	ControlDir         string         `json:"control_directory"`
	SocketDir          string         `json:"socket_directory"`
	MemoryBytes        int64          `json:"memory_bytes"`
	SourceSocket       string         `json:"source_socket,omitempty"`
	Purpose            string         `json:"purpose,omitempty"`
	LogicalBinarySHA   string         `json:"logical_binary_sha256,omitempty"`
	LogicalSource      string         `json:"logical_source_id,omitempty"`
	LogicalSourceEpoch int64          `json:"logical_source_epoch,omitempty"`
}
type inspected struct {
	ID     string `json:"Id"`
	Config struct {
		Image, User     string
		Labels          map[string]string
		Entrypoint, Cmd []string
		Volumes         map[string]any
	}
	State      struct{ Running bool }
	HostConfig struct {
		NetworkMode                  string
		ReadonlyRootfs, Privileged   bool
		CapDrop, CapAdd, SecurityOpt []string
		Memory, MemorySwap, NanoCpus int64
		PidsLimit                    int64
		Binds                        []string
	}
	Mounts []struct {
		Type, Source, Destination, Propagation string
		RW                                     bool
	}
}

var digestPattern = regexp.MustCompile(`^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$`)
var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var pathPattern = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)

func (o OCI) command(ctx context.Context, args ...string) ([]byte, error) {
	if !filepath.IsAbs(o.Binary) || !digestPattern.MatchString(o.Image) {
		return nil, errors.New("invalid pinned OCI configuration")
	}
	cmd := exec.CommandContext(ctx, o.Binary, append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C"}
	b, e := cmd.Output()
	if e != nil {
		return nil, errors.New("OCI operation failed")
	}
	return b, nil
}
func validate(s Spec) error {
	if err := validateIdentity(s); err != nil {
		return err
	}
	if s.LogicalBinarySHA != "" && (s.Purpose != "baseline" || s.SourceSocket == "" || !containerIDPattern.MatchString(s.LogicalBinarySHA)) {
		return errors.New("logical ingestion requires a pinned baseline executable and upstream mount")
	}
	if (s.LogicalSource != "" || s.LogicalSourceEpoch != 0) && (s.LogicalBinarySHA == "" || !uuid.MatchString(s.LogicalSource) || s.LogicalSourceEpoch < 1) {
		return errors.New("invalid logical baseline source binding")
	}
	paths := []string{s.DataDir, s.ControlDir, s.SocketDir}
	if s.SourceSocket != "" {
		if s.Purpose != "baseline" {
			return errors.New("workspace cannot mount an upstream socket")
		}
		paths = append(paths, s.SourceSocket)
	}
	for i, p := range paths {
		if p == "/" || !pathPattern.MatchString(p) || filepath.Clean(p) != p {
			return errors.New("invalid runtime path")
		}
		for j, q := range paths {
			if i != j && (p == q || strings.HasPrefix(p, q+"/")) {
				return errors.New("runtime mounts must be separate")
			}
		}
		for a := p; a != "/"; a = filepath.Dir(a) {
			st, e := os.Lstat(a)
			if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				return errors.New("runtime mount path must contain ordinary directories")
			}
		}
	}
	return nil
}

func validateIdentity(s Spec) error {
	id := s.Identity
	if id.Epoch == "" || id.Host == "" || !uuid.MatchString(id.Tenant) || !uuid.MatchString(id.Project) || !uuid.MatchString(id.Workspace) || id.Generation < 1 || s.MemoryBytes < 256<<20 || s.MemoryBytes > 8<<30 {
		return errors.New("invalid runtime identity or memory admission")
	}
	return nil
}

// Lookup reconciles a lost create response without creating or starting any
// process. A matching name alone never establishes ownership.
func (o OCI) Lookup(ctx context.Context, s Spec) (Container, bool, error) {
	if err := validateIdentity(s); err != nil {
		return Container{}, false, err
	}
	raw, err := o.command(ctx, "ps", "-aq", "--no-trunc", "--filter", "name=^/"+name(s)+"$")
	if err != nil {
		return Container{}, false, err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return Container{}, false, nil
	}
	if err = validate(s); err != nil {
		return Container{}, false, err
	}
	v, err := o.inspect(ctx, id)
	if err != nil {
		return Container{}, false, err
	}
	if err = o.verify(v, s); err != nil {
		return Container{}, false, err
	}
	return Container{ID: v.ID, Spec: s}, true, nil
}

func (o OCI) VerifyAbsent(ctx context.Context, id lease.Identity) error {
	s := Spec{Identity: id, MemoryBytes: 256 << 20}
	if err := validateIdentity(s); err != nil {
		return err
	}
	raw, err := o.command(ctx, "ps", "-aq", "--no-trunc", "--filter", "name=^/"+name(s)+"$")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) != "" {
		return errors.New("unrecorded runtime exists; ownership reconciliation is required")
	}
	return nil
}

// VerifyHostAbsent is an offline recovery inventory check, never a selector
// for deleting containers whose exact admitted identity is unknown.
func (o OCI) VerifyHostAbsent(ctx context.Context, host string) error {
	if host == "" || len(host) > 200 || strings.ContainsAny(host, "\r\n\x00") {
		return errors.New("invalid recovery host")
	}
	raw, err := o.command(ctx, "ps", "-aq", "--no-trunc", "--filter", "label=org.pgws:host="+host)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) != "" {
		return errors.New("unreconciled host runtime remains")
	}
	return nil
}
func labels(s Spec) map[string]string {
	b, _ := json.Marshal(s)
	return map[string]string{"org.pgws:tenant": s.Identity.Tenant, "org.pgws:project": s.Identity.Project, "org.pgws:workspace": s.Identity.Workspace, "org.pgws:generation": strconv.FormatInt(s.Identity.Generation, 10), "org.pgws:epoch": s.Identity.Epoch, "org.pgws:host": s.Identity.Host, "org.pgws:spec": fmt.Sprintf("%x", sha256.Sum256(b))}
}
func name(s Spec) string {
	return "pgws-" + s.Identity.Workspace + "-g" + strconv.FormatInt(s.Identity.Generation, 10)
}
func (o OCI) inspect(ctx context.Context, id string) (inspected, error) {
	var items []inspected
	b, e := o.command(ctx, "inspect", "--type", "container", id)
	if e != nil || json.Unmarshal(b, &items) != nil || len(items) != 1 {
		return inspected{}, errors.New("container inspection failed")
	}
	return items[0], nil
}
func (o OCI) verify(v inspected, s Spec) error {
	if !containerIDPattern.MatchString(v.ID) || v.Config.Image != o.Image || v.Config.User != "999:999" || v.HostConfig.Privileged || !v.HostConfig.ReadonlyRootfs || v.HostConfig.NetworkMode != "none" || !slices.Contains(v.HostConfig.CapDrop, "ALL") || len(v.HostConfig.CapAdd) != 0 || !slices.Contains(v.HostConfig.SecurityOpt, "no-new-privileges") || v.HostConfig.Memory != s.MemoryBytes || v.HostConfig.MemorySwap != s.MemoryBytes || v.HostConfig.NanoCpus != 1e9 || v.HostConfig.PidsLimit != 128 {
		return errors.New("runtime isolation settings differ from admitted spec")
	}
	for k, want := range labels(s) {
		if v.Config.Labels[k] != want {
			return errors.New("runtime ownership mismatch")
		}
	}
	want := map[string]bool{s.DataDir: true, s.ControlDir: true, s.SocketDir: true}
	if s.SourceSocket != "" {
		want[s.SourceSocket] = true
	}
	for _, m := range v.Mounts {
		if m.Type == "tmpfs" && (m.Destination == "/tmp" || m.Destination == "/var/lib/postgresql") {
			continue
		}
		if !want[m.Source] || m.Source != m.Destination || m.Type != "bind" || m.RW != (m.Source != s.SourceSocket) || m.Propagation != "rprivate" {
			return errors.New("unexpected runtime mount")
		}
		delete(want, m.Source)
	}
	if len(want) != 0 {
		return errors.New("runtime mounts missing")
	}
	return nil
}

// Ensure reconciles an existing container by immutable ID, labels and actual
// namespace/mount/resource settings before it can be used. It publishes no port.
func (o OCI) Ensure(ctx context.Context, s Spec) (Container, error) {
	if e := validate(s); e != nil {
		return Container{}, e
	}
	if e := logicalStopped(s); e != nil {
		return Container{}, e
	}
	// Listing distinguishes absence from an inspect/daemon failure.
	b, e := o.command(ctx, "ps", "-aq", "--no-trunc", "--filter", "name=^/"+name(s)+"$")
	if e != nil {
		return Container{}, e
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		args := []string{"create", "--name", name(s), "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", strconv.FormatInt(s.MemoryBytes, 10), "--memory-swap", strconv.FormatInt(s.MemoryBytes, 10), "--cpus", "1", "--shm-size", "64m", "--user", "999:999", "--init", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"}
		ls := labels(s)
		keys := make([]string, 0, len(ls))
		for k := range ls {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			args = append(args, "--label", k+"="+ls[k])
		}
		for _, p := range []string{s.DataDir, s.ControlDir, s.SocketDir} {
			args = append(args, "--mount", "type=bind,src="+p+",dst="+p+",bind-propagation=rprivate")
		}
		if s.SourceSocket != "" {
			args = append(args, "--mount", "type=bind,src="+s.SourceSocket+",dst="+s.SourceSocket+",readonly,bind-propagation=rprivate")
		}
		// Suppress the image's inherited anonymous volume. No host directory is
		// exposed at this location and it cannot persist source data.
		args = append(args, "--tmpfs", "/var/lib/postgresql:rw,noexec,nosuid,size=1m", "--entrypoint", "/bin/sleep", o.Image, "infinity")
		b, e = o.command(ctx, args...)
		if e != nil {
			return Container{}, e
		}
		id = strings.TrimSpace(string(b))
	}
	v, e := o.inspect(ctx, id)
	if e != nil {
		return Container{}, e
	}
	if e = o.verify(v, s); e != nil {
		return Container{}, e
	}
	if e = logicalStopped(s); e != nil {
		_ = o.Remove(ctx, Container{ID: v.ID, Spec: s})
		return Container{}, e
	}
	if !v.State.Running {
		if _, e = o.command(ctx, "start", v.ID); e != nil {
			return Container{}, e
		}
	}
	if e = logicalStopped(s); e != nil {
		_ = o.Remove(ctx, Container{ID: v.ID, Spec: s})
		return Container{}, e
	}
	return Container{ID: v.ID, Spec: s}, nil
}
func (o OCI) Remove(ctx context.Context, c Container) error {
	if !containerIDPattern.MatchString(c.ID) {
		return errors.New("invalid runtime ID")
	}
	listed, e := o.command(ctx, "ps", "--all", "--no-trunc", "--filter", "name=^/"+name(c.Spec)+"$", "--format", "{{.ID}}")
	if e != nil {
		return e
	}
	found := strings.TrimSpace(string(listed))
	if found == "" {
		return nil
	}
	if found != c.ID {
		return errors.New("runtime name was replaced")
	}
	v, e := o.inspect(ctx, c.ID)
	if e != nil {
		return e
	}
	if e = o.verify(v, c.Spec); e != nil {
		return e
	}
	_, e = o.command(ctx, "rm", "--force", c.ID)
	return e
}
func (o OCI) Tools(c Container) physical.Tools {
	return physical.Tools{BinDir: PostgresBin, Executor: containerCommands{o, c}, CredentialDir: c.Spec.ControlDir, UpstreamSocket: c.Spec.SourceSocket}
}

type containerCommands struct {
	oci       OCI
	container Container
}

func (r containerCommands) Run(ctx context.Context, tool string, env []string, args ...string) ([]byte, error) {
	if !slices.Contains([]string{"pg_ctl", "postgres", "pg_basebackup", "pg_verifybackup", "initdb"}, tool) || !containerIDPattern.MatchString(r.container.ID) {
		return nil, errors.New("unapproved runtime command")
	}
	v, e := r.oci.inspect(ctx, r.container.ID)
	if e != nil {
		return nil, e
	}
	if e = r.oci.verify(v, r.container.Spec); e != nil {
		return nil, e
	}
	cmd := []string{"exec", "--user", "999:999"}
	for _, v := range env {
		cmd = append(cmd, "--env", v)
	}
	cmd = append(cmd, r.container.ID, filepath.Join(PostgresBin, tool))
	cmd = append(cmd, args...)
	return r.oci.command(ctx, cmd...)
}

func (r containerCommands) PrepareFiles(path string) error {
	root := ""
	for _, mount := range []string{r.container.Spec.DataDir, r.container.Spec.ControlDir} {
		if strings.HasPrefix(path, mount+"/") {
			root = mount
			break
		}
	}
	if filepath.Clean(path) != path || root == "" {
		return errors.New("backup files outside runtime data/control mounts")
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid backup parent")
		}
		if e = os.Chown(p, 999, 999); e != nil {
			return e
		}
		if p == root {
			break
		}
	}
	return filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in backup generation")
		}
		return os.Chown(p, 999, 999)
	})
}

func (o OCI) Verify(ctx context.Context, c Container) error {
	if !containerIDPattern.MatchString(c.ID) {
		return errors.New("invalid runtime ID")
	}
	v, e := o.inspect(ctx, c.ID)
	if e != nil {
		return e
	}
	if e = o.verify(v, c.Spec); e != nil {
		return e
	}
	if !v.State.Running {
		return errors.New("runtime is not running")
	}
	return nil
}
