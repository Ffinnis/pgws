package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/runtime"
)

// Seed performs a second source inspection immediately before the backup. Its
// manifest, rather than an older registration inspection, defines recovery.
func seedManifest(seed physical.SeedResult) (physical.Manifest, error) {
	var manifest physical.Manifest
	path := filepath.Join(filepath.Dir(seed.DataDir), "manifest.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return manifest, errors.New("verified seed manifest is unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.Identity != seed.SourceIdentity || manifest.RequireSeedable() != nil {
		return manifest, errors.New("verified seed manifest differs from its source")
	}
	return manifest, nil
}

func (h *Host) discardPartialSeed(ctx context.Context, t control.Task, s *state, root string) error {
	if s.Seeding == nil || s.Seeding.Stage != "reserved" || s.Recovery.DataDir != "" {
		return errors.New("only an unstarted baseline backup may be discarded")
	}
	if s.Container.ID != "" {
		if err := h.oci.Remove(ctx, s.Container); err != nil {
			return err
		}
	} else if s.RuntimeIntent != nil {
		observed, exists, err := h.oci.Lookup(ctx, *s.RuntimeIntent)
		if err != nil {
			return err
		}
		if exists {
			if err = h.oci.Remove(ctx, observed); err != nil {
				return err
			}
		}
	} else if err := h.oci.VerifyAbsent(ctx, t.Command.Identity); err != nil {
		return err
	}
	controls := filepath.Join(h.folder(t), "postgres-controls")
	entries, err := os.ReadDir(controls)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "pgws-backup-secret-") {
			continue
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("partial backup credential directory is invalid")
		}
		if err = os.RemoveAll(filepath.Join(controls, entry.Name())); err != nil {
			return err
		}
	}
	// register verified this volume's GUID and ownership. Only the service's
	// fixed generation path is eligible, never an upstream source path.
	parent := filepath.Join(root, "seeds", t.SourceID)
	for _, path := range []string{filepath.Join(root, "seeds"), parent, filepath.Join(parent, fmt.Sprint(t.Command.Generation))} {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("partial seed path is not an owned directory")
		}
	}
	if err := os.RemoveAll(filepath.Join(parent, fmt.Sprint(t.Command.Generation))); err != nil {
		return err
	}
	s.Container = runtime.Container{}
	return h.save(t, *s)
}

func pruneSeedArchives(seed physical.SeedResult) error {
	if !seed.Verified || seed.ContinuousReplication {
		return errors.New("baseline seed lacks verified backup evidence")
	}
	archive := filepath.Join(filepath.Dir(seed.DataDir), "archive")
	for _, name := range []string{"base.tar", "pg_wal.tar"} {
		if err := os.Remove(filepath.Join(archive, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	directory, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
