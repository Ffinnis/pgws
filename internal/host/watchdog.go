package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"pgws/internal/ingress"
	"pgws/internal/lease"
	"pgws/internal/runtime"
	"pgws/internal/storage/zfs"
	"time"
)

type safetyStop struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

func checkStopped(folder string) error {
	_, e := os.Lstat(filepath.Join(folder, "safety-stop.json"))
	if e == nil {
		return errors.New("generation is stopped by the independent watchdog")
	}
	if !os.IsNotExist(e) {
		return e
	}
	return nil
}

func recordStop(folder, reason string) error {
	path := filepath.Join(folder, "safety-stop.json")
	if data, err := os.ReadFile(path); err == nil {
		var prior safetyStop
		if json.Unmarshal(data, &prior) != nil || prior.Reason == "" || prior.At.IsZero() {
			return errors.New("invalid durable safety stop")
		}
		return nil // Keep the original reason and avoid repeated fsync churn.
	} else if !os.IsNotExist(err) {
		return err
	}
	if reason == "" {
		return errors.New("safety stop requires a reason")
	}
	if err := saveOnce(path, safetyStop{reason, time.Now().UTC()}); err != nil {
		if !os.IsExist(err) {
			return err
		}
		_, err = readStop(folder)
		return err
	}
	return nil
}

// WatchdogOnce runs in a separate process. It does not depend on management
// availability, the worker's job loop, or the host command journal lock.
func WatchdogOnce(ctx context.Context, c Config) error {
	paths, e := filepath.Glob(filepath.Join(c.Root, "objects", "*", "*", "state.json"))
	if e != nil {
		return e
	}
	if len(paths) > 10000 {
		return errors.New("watchdog inventory exceeds host limit")
	}
	o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
	var failures []error
	floor := c.MinPoolAvailable
	if floor == 0 {
		floor = 256 << 20
	}
	if floor < 32<<20 {
		return errors.New("invalid independent pool capacity floor")
	}
	probe, stop := context.WithTimeout(ctx, 2*time.Second)
	available, capacityErr := zfs.RootAvailable(probe, "/usr/sbin/zfs", c.Dataset)
	stop()
	if capacityErr != nil {
		failures = append(failures, capacityErr)
	}
	pressure := capacityErr == nil && available < floor
	for _, path := range paths {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		b, e := os.ReadFile(path)
		if e != nil {
			failures = append(failures, e)
			continue
		}
		var s state
		if json.Unmarshal(b, &s) != nil || s.Task.Command.Host != c.ID || (s.Task.Command.Epoch != c.Epoch && s.Phase != "quarantined" && s.Phase != "deleted") {
			failures = append(failures, errors.New("watchdog state identity differs"))
			continue
		}
		if s.Phase == "deleted" || s.Phase == "quarantined" {
			continue
		}
		folder := filepath.Dir(path)
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		reason := ""
		if pressure {
			reason = "POOL_PRESSURE"
		}
		if !s.Task.Expiry.IsZero() && !time.Now().Before(s.Task.Expiry) {
			reason = "WORKSPACE_EXPIRED"
		}
		if reason == "" && s.GuardDirectory != "" && (s.Phase == "ready" || s.Phase == "resuming") {
			if expired, err := runtimeLeaseExpired(c, s); err != nil || expired {
				reason = "SERVING_LEASE_EXPIRED"
			}
		}
		if s.SlotOwned {
			source, sourceErr := (&Host{Config: c}).resolve(s.Task)
			source.ExpectedSystemID = s.SourceIdentity.SystemID
			if reason == "" && checkStopped(folder) == nil {
				if sourceErr != nil {
					cancel()
					failures = append(failures, sourceErr)
					continue
				}
				identitySource := source
				identitySource.ExpectedSystemID = ""
				identity, identityErr := identitySource.Identify(check)
				if identityErr != nil {
					cancel()
					failures = append(failures, identityErr)
					continue
				}
				if identity != s.SourceIdentity {
					reason = "SOURCE_LINEAGE_CHANGED"
				} else {
					retained, lost, e := source.SlotPressure(check, s.Slot)
					if e != nil {
						cancel()
						failures = append(failures, e)
						continue
					}
					if lost || retained >= 192<<20 {
						reason = "SOURCE_WAL_BUDGET"
					}
				}
			}
			if reason != "" || checkStopped(folder) != nil {
				if reason == "" {
					reason = "SOURCE_WAL_BUDGET"
				}
				if e = recordStop(folder, reason); e == nil {
					e = removeStoppedRuntime(check, o, folder, s)
				}
				if e == nil {
					if sourceErr != nil {
						e = sourceErr
					} else {
						e = source.DropSlot(check, s.Slot)
					}
				}
				if e != nil {
					failures = append(failures, e)
				}
			}
		} else if reason != "" || checkStopped(folder) != nil {
			if reason == "" {
				reason = "SAFETY_STOP"
			}
			if e = recordStop(folder, reason); e != nil {
				cancel()
				failures = append(failures, e)
				continue
			}
			if e = removeStoppedRuntime(check, o, folder, s); e != nil {
				failures = append(failures, e)
			}
			// Remove PostgreSQL first: a stopped ingress process may take the full
			// control-socket timeout, but must not prolong already executing SQL.
			if s.GuardDirectory != "" {
				_ = guardRequest(check, s.GuardDirectory, "close", nil, nil)
			}
		}
		cancel()
	}
	return errors.Join(failures...)
}

func runtimeLeaseExpired(c Config, s state) (bool, error) {
	path := filepath.Join(s.GuardDirectory, "receipt.json")
	if _, err := os.Stat(path); os.IsNotExist(err) && !s.ServingStarted {
		return false, nil
	}
	key, err := base64.StdEncoding.DecodeString(c.AuthorityKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return true, errors.New("invalid runtime lease authority")
	}
	boot, ticks, err := lease.BootClock()
	if err != nil {
		return true, err
	}
	revision, expired, err := ingress.RuntimeLease(path, key, s.Task.Command.Identity, boot, ticks)
	// Execute(resume) has not started PostgreSQL. Only Activate with this exact
	// revision can start it, and must first install a fresh serving receipt.
	if err == nil && s.Phase == "resuming" && revision < s.Task.Command.Revision {
		return false, nil
	}
	return expired, err
}
