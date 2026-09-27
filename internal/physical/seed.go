package physical

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// CommandRunner executes PostgreSQL tools in an already isolated runtime.
// The host caller chooses it; it is never supplied through an API request.
type CommandRunner interface {
	Run(context.Context, string, []string, ...string) ([]byte, error)
}
type FilePreparer interface{ PrepareFiles(string) error }
type Tools struct {
	BinDir   string
	Executor CommandRunner
	// CredentialDir is an unsnapshotted runtime control mount. Direct local
	// tools use an OS temporary directory instead of writing into backup data.
	CredentialDir string
	// UpstreamSocket belongs to the host's TLS broker. It is mounted only in
	// a baseline runtime; administrator discovery still uses the original source.
	UpstreamSocket string
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (t Tools) run(ctx context.Context, tool string, env []string, args ...string) error {
	if t.Executor != nil {
		if _, err := t.Executor.Run(ctx, tool, env, args...); err != nil {
			return safeError(tool)
		}
		return nil
	}
	if !filepath.IsAbs(t.BinDir) {
		return errors.New("PostgreSQL binary directory must be absolute")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(t.BinDir, tool), args...)
	cmd.Env = append([]string{"PATH=" + t.BinDir + ":/usr/bin:/bin", "LC_ALL=C", "HOME=/nonexistent"}, env...)
	// Source process output may contain credentials or customer identifiers. The
	// public error intentionally records only the command name and exit outcome.
	if e := cmd.Run(); e != nil {
		return safeError(tool)
	}
	return nil
}
func (t Tools) Require18(ctx context.Context) error {
	if !filepath.IsAbs(t.BinDir) {
		return errors.New("PostgreSQL binary directory must be absolute")
	}
	for _, name := range []string{"pg_basebackup", "pg_verifybackup", "pg_ctl", "postgres"} {
		cmd := exec.CommandContext(ctx, filepath.Join(t.BinDir, name), "--version")
		var b []byte
		var e error
		if t.Executor != nil {
			b, e = t.Executor.Run(ctx, name, nil, "--version")
		} else {
			b, e = cmd.Output()
		}
		if e != nil || !strings.Contains(string(b), "(PostgreSQL) 18.") {
			return errors.New("matching PostgreSQL 18 binaries are required")
		}
	}
	return nil
}

type SeedResult struct {
	SourceIdentity        Identity `json:"source_identity"`
	Generation            int64    `json:"generation"`
	DataDir               string   `json:"data_directory"`
	Verified              bool     `json:"backup_verified"`
	ContinuousReplication bool     `json:"continuous_replication"`
}

// Seed performs a bounded, verified full backup using pg_basebackup's temporary
// replication slot. Continuous replication requires the later persistent-slot
// ownership/watchdog workflow. Failed generations remain private for diagnosis.
func (t Tools) Seed(ctx context.Context, s Source, root, sourceID string, generation int64, maxBytes int64) (SeedResult, error) {
	if !filepath.IsAbs(root) || !idPattern.MatchString(sourceID) || generation < 1 || maxBytes < 32<<20 {
		return SeedResult{}, errors.New("invalid seed identity or storage budget")
	}
	if e := t.Require18(ctx); e != nil {
		return SeedResult{}, e
	}
	m, e := s.Inspect(ctx)
	if e != nil {
		return SeedResult{}, e
	}
	if e = m.RequireSeedable(); e != nil {
		return SeedResult{}, e
	}
	parent := filepath.Join(root, "seeds", sourceID)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return SeedResult{}, e
	}
	generationDir := filepath.Join(parent, strconv.FormatInt(generation, 10))
	if e = os.Mkdir(generationDir, 0700); e != nil {
		return SeedResult{}, errors.New("generation path already exists or cannot be reserved")
	}
	result := SeedResult{SourceIdentity: m.Identity, Generation: generation, DataDir: filepath.Join(generationDir, "data")}
	if e = writeJSON(filepath.Join(generationDir, "intent.json"), result); e != nil {
		return result, e
	}
	if e = writeJSON(filepath.Join(generationDir, "manifest.json"), m); e != nil {
		return result, e
	}
	archive := filepath.Join(generationDir, "archive")
	if e = os.Mkdir(archive, 0700); e != nil {
		return result, e
	}
	secretDir, e := os.MkdirTemp(t.CredentialDir, "pgws-backup-secret-")
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(secretDir)
	transfer := t.transferSource(s)
	env, e := transfer.environment(secretDir)
	if e != nil {
		return result, e
	}
	if p, ok := t.Executor.(FilePreparer); ok {
		if e = p.PrepareFiles(generationDir); e != nil {
			return result, e
		}
		if e = p.PrepareFiles(secretDir); e != nil {
			return result, e
		}
	}
	// Tar mode prevents a source tablespace introduced after discovery from being
	// materialized at a source-chosen absolute path on this host.
	if e = t.backupWithBudget(ctx, archive, maxBytes, env, "--pgdata="+archive, "--format=tar", "--wal-method=stream", "--checkpoint=spread", "--manifest-checksums=SHA256", "--max-rate=10240", "--no-password"); e != nil {
		return result, e
	}
	entries, e := os.ReadDir(archive)
	if e != nil {
		return result, e
	}
	var size int64
	for _, entry := range entries {
		if entry.Name() != "base.tar" && entry.Name() != "pg_wal.tar" && entry.Name() != "backup_manifest" {
			return result, errors.New("backup contains an unexpected tablespace/archive")
		}
		info, e := entry.Info()
		if e != nil || !info.Mode().IsRegular() {
			return result, errors.New("invalid backup archive")
		}
		size += info.Size()
	}
	if size > maxBytes {
		return result, errors.New("backup exceeds storage budget")
	}
	if e = os.Mkdir(result.DataDir, 0700); e != nil {
		return result, e
	}
	budget := maxBytes
	if e = extract(filepath.Join(archive, "base.tar"), result.DataDir, &budget); e != nil {
		return result, e
	}
	wal := filepath.Join(result.DataDir, "pg_wal")
	if e = os.MkdirAll(wal, 0700); e != nil {
		return result, e
	}
	if e = extract(filepath.Join(archive, "pg_wal.tar"), wal, &budget); e != nil {
		return result, e
	}
	b, e := os.ReadFile(filepath.Join(archive, "backup_manifest"))
	if e != nil {
		return result, e
	}
	if e = os.WriteFile(filepath.Join(result.DataDir, "backup_manifest"), b, 0600); e != nil {
		return result, e
	}
	if p, ok := t.Executor.(FilePreparer); ok {
		if e = p.PrepareFiles(result.DataDir); e != nil {
			return result, e
		}
	}
	if e = t.run(ctx, "pg_verifybackup", nil, result.DataDir); e != nil {
		return result, e
	}
	after, e := s.Identify(ctx)
	if e != nil || after != m.Identity {
		return result, errors.New("source identity changed during seed")
	}
	result.Verified = true
	if e = writeJSON(filepath.Join(generationDir, "verified.json"), result); e != nil {
		return result, e
	}
	return result, nil
}

// This admission monitor bounds ordinary transfer growth; it is not a hard
// filesystem quota. A production dataset must also have a qualified ZFS quota.
func (t Tools) backupWithBudget(ctx context.Context, dir string, limit int64, env []string, args ...string) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	var exceeded atomic.Bool
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-child.Done():
				return
			case <-tick.C:
				entries, e := os.ReadDir(dir)
				if e != nil {
					exceeded.Store(true)
					cancel()
					return
				}
				var total int64
				for _, entry := range entries {
					info, e := entry.Info()
					if e != nil || !info.Mode().IsRegular() {
						exceeded.Store(true)
						cancel()
						return
					}
					total += info.Size()
				}
				if total > limit {
					exceeded.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	err := t.run(child, "pg_basebackup", env, args...)
	cancel()
	<-done
	if exceeded.Load() {
		return errors.New("backup stopped at storage budget")
	}
	return err
}
func (s Source) environment(privateDir string) ([]string, error) {
	if _, e := s.config(); e != nil {
		return nil, e
	}
	sslmode := "verify-full"
	if filepath.IsAbs(s.Host) {
		sslmode = "disable"
	}
	env := []string{"PGHOST=" + s.Host, "PGPORT=" + strconv.Itoa(int(s.Port)), "PGUSER=" + s.User, "PGDATABASE=" + s.Database, "PGSSLMODE=" + sslmode, "PGCONNECT_TIMEOUT=5", "PGAPPNAME=pgws-basebackup"}
	if !filepath.IsAbs(s.Host) {
		env = append(env, "PGHOSTADDR="+s.ApprovedAddresses[0])
		if s.RootCertificate == "" {
			env = append(env, "PGSSLROOTCERT=system")
		}
	}
	if s.RootCertificate != "" {
		env = append(env, "PGSSLROOTCERT="+s.RootCertificate)
	}
	passfile := filepath.Join(privateDir, "source.pgpass")
	contents, e := s.passfileContents()
	if e != nil {
		return nil, e
	}
	if e := os.WriteFile(passfile, contents, 0600); e != nil {
		return nil, e
	}
	env = append(env, "PGPASSFILE="+passfile)
	return env, nil
}

func (s Source) passfileContents() ([]byte, error) {
	password := ""
	if s.PasswordFile != "" {
		var e error
		password, e = readSecret(s.PasswordFile)
		if e != nil {
			return nil, e
		}
	}
	escape := func(s string) string { return strings.NewReplacer(`\`, `\\`, ":", `\:`).Replace(s) }
	return []byte("*:*:*:" + escape(s.User) + ":" + escape(password) + "\n"), nil
}

func (t Tools) transferSource(source Source) Source {
	if t.UpstreamSocket != "" && !filepath.IsAbs(source.Host) {
		source.Host, source.Port, source.RootCertificate = t.UpstreamSocket, 5432, ""
	}
	return source
}
func extract(archive, target string, budget *int64) error {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	r := tar.NewReader(f)
	for {
		h, e := r.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		name := filepath.Clean(h.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return errors.New("unsafe backup archive path")
		}
		path := filepath.Join(target, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(path, 0700); e != nil {
				return e
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > *budget {
				return errors.New("expanded backup exceeds budget")
			}
			*budget -= h.Size
			if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
				return e
			}
			out, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			_, e = io.CopyN(out, r, h.Size)
			if e == nil {
				e = out.Sync()
			}
			closeErr := out.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unsupported backup archive entry type %d", h.Typeflag)
		}
	}
}
func writeJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".receipt-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(append(b, '\n'))
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	// Publish complete bytes without replacing a prior immutable receipt.
	// A killed writer can leave an ignored temporary file, never a torn plan.
	if e = os.Link(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
