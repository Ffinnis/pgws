package physical

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

// RefreshStreamingSecret changes only the external passfile for an immutable
// prepared source. Existing replication connections retain their session; the
// next connection reads the new secret. No password enters a dataset or plan.
func (t Tools) RefreshStreamingSecret(r Recovery, s Source, slot string) error {
	if err := validateRecovery(r); err != nil {
		return err
	}
	var plan streamingPlan
	data, err := os.ReadFile(filepath.Join(r.ControlDir, "streaming-plan.json"))
	if err != nil || json.Unmarshal(data, &plan) != nil || !reflect.DeepEqual(plan, streamingPlan{r, s, slot, t.UpstreamSocket}) {
		return errors.New("streaming secret differs from its immutable source plan")
	}
	if err = ValidateRecoveryPlan(r); err != nil {
		return err
	}
	contents, err := s.passfileContents()
	if err != nil {
		return err
	}
	path := filepath.Join(r.ControlDir, "source.pgpass")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 {
		return errors.New("streaming passfile is unavailable or unsafe")
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return errors.New("streaming passfile is unreadable")
	}
	if bytes.Equal(old, contents) {
		return nil
	}
	f, err := os.CreateTemp(r.ControlDir, ".source-secret-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(contents); err != nil {
		return err
	}
	// Set the runtime owner before rename: libpq never sees a root-owned
	// replacement between publication and a separate chown operation.
	if preparer, ok := t.Executor.(FilePreparer); ok {
		if err = preparer.PrepareFiles(f.Name()); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(r.ControlDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
