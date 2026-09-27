package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"pgws/internal/config"
)

type logicalStop struct {
	ContainerID string    `json:"container_id"`
	SpecHash    string    `json:"spec_sha256"`
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
}

func logicalStopped(s Spec) error {
	if s.LogicalBinarySHA == "" {
		return nil
	}
	if _, err := os.Lstat(filepath.Join(s.ControlDir, "logical-stop.json")); !os.IsNotExist(err) {
		return errors.New("logical baseline is stopped or requires reconciliation")
	}
	return nil
}

// StopIngestion persists a terminal fence before removing the verified exact
// container. Retained data and receipts survive; Ensure and Ingest refuse to
// restart this generation even if source pressure later disappears.
func (o OCI) StopIngestion(ctx context.Context, c Container, reason string) error {
	if err := validate(c.Spec); err != nil {
		return err
	}
	if c.Spec.LogicalBinarySHA == "" || !containerIDPattern.MatchString(c.ID) || len(reason) < 1 || len(reason) > 80 {
		return errors.New("invalid logical stop identity")
	}
	spec, _ := json.Marshal(c.Spec)
	record := logicalStop{ContainerID: c.ID, SpecHash: fmt.Sprintf("%x", sha256.Sum256(spec)), Reason: reason, At: time.Now().UTC()}
	data, _ := json.Marshal(record)
	path := filepath.Join(c.Spec.ControlDir, "logical-stop.json")
	f, err := os.CreateTemp(c.Spec.ControlDir, ".logical-stop-")
	if err != nil {
		return errors.New("logical stop file unavailable")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return errors.New("logical stop write failed")
	}
	if err = f.Sync(); err != nil {
		return errors.New("logical stop sync failed")
	}
	if err = f.Close(); err != nil {
		return errors.New("logical stop close failed")
	}
	if err = os.Link(f.Name(), path); err != nil {
		if !os.IsExist(err) {
			return errors.New("logical stop publication failed")
		}
		text, e := config.PrivateText(path)
		var prior logicalStop
		if e != nil || json.Unmarshal([]byte(text), &prior) != nil || prior.ContainerID != c.ID || prior.SpecHash != record.SpecHash || prior.Reason == "" || prior.At.IsZero() {
			return errors.New("logical stop differs from admitted runtime")
		}
	}
	dir, err := os.Open(c.Spec.ControlDir)
	if err != nil {
		return errors.New("logical stop directory unavailable")
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return errors.New("logical stop directory sync failed")
	}
	return o.Remove(ctx, c)
}
