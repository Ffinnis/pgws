package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaintainSources restores only the broker of an already streaming, verified
// generation. It cannot allocate a runtime, reseed data or clear a safety stop.
// TryLock keeps maintenance from waiting behind active source operations.
func (h *Host) MaintainSources(ctx context.Context) error {
	paths, err := filepath.Glob(filepath.Join(h.Config.Root, "objects", "*", "*", "state.json"))
	if err != nil {
		return err
	}
	if len(paths) > 10000 {
		return errors.New("source maintenance inventory exceeds host limit")
	}
	var failures []error
	for _, path := range paths {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		data, err := os.ReadFile(path)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var candidate state
		if json.Unmarshal(data, &candidate) != nil {
			failures = append(failures, errors.New("source maintenance state is unreadable"))
			continue
		}
		if candidate.Seeding == nil || candidate.Phase != "streaming" {
			continue
		}
		if candidate.Task.Command.Host != h.Config.ID || candidate.Task.Command.Epoch != h.Config.Epoch || filepath.Join(h.folder(candidate.Task), "state.json") != path {
			failures = append(failures, errors.New("source maintenance state identity differs"))
			continue
		}
		value, _ := h.locks.LoadOrStore(candidate.Task.Command.Workspace, &sync.Mutex{})
		lock := value.(*sync.Mutex)
		if !lock.TryLock() {
			continue
		}
		func() {
			defer lock.Unlock()
			// Re-read under the source lock: revocation may have completed since
			// the inventory was read. The watchdog's stop is checked separately.
			s, err := h.load(candidate.Task)
			if err != nil {
				failures = append(failures, err)
				return
			}
			if s.Phase != "streaming" || checkStopped(h.folder(s.Task)) != nil {
				return
			}
			check, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			if err = h.storage.VerifyGeneration(check, s.Task.Command, s.Volume, "baselines"); err == nil {
				err = h.oci.Verify(check, s.Container)
			}
			if err == nil {
				source, sourceErr := h.resolve(s.Task)
				if sourceErr != nil {
					err = sourceErr
				} else {
					source.ExpectedSystemID = s.SourceIdentity.SystemID
					err = h.oci.Tools(s.Container).RefreshStreamingSecret(s.Recovery, source, s.Slot)
					if err == nil && !filepath.IsAbs(source.Host) {
						_, err = h.ensureSourceBroker(check, s.Task, source)
					}
				}
			}
			if err != nil {
				failures = append(failures, err)
			}
		}()
	}
	return errors.Join(failures...)
}
