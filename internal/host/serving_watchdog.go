package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"pgws/internal/parallel"
	"pgws/internal/runtime"
)

// WatchdogServingOnce does not inspect sources or wait for guard HTTP. A slow
// upstream or suspended guard cannot consume another workspace's deadline.
func WatchdogServingOnce(ctx context.Context, c Config) error {
	paths, err := filepath.Glob(filepath.Join(c.Root, "objects", "*", "*", "state.json"))
	if err != nil {
		return err
	}
	if len(paths) > 10000 {
		return errors.New("serving watchdog inventory exceeds host limit")
	}
	return parallel.Run(ctx, 16, paths, func(ctx context.Context, path string) error {
		return checkServingRuntime(ctx, c, path)
	})
}

func checkServingRuntime(ctx context.Context, c Config, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var s state
	if json.Unmarshal(b, &s) != nil || s.Task.Command.Host != c.ID || (s.Task.Command.Epoch != c.Epoch && s.Phase != "quarantined" && s.Phase != "deleted") {
		return errors.New("serving watchdog identity differs")
	}
	if s.GuardDirectory == "" || s.Phase == "deleted" || s.Phase == "quarantined" || s.Phase == "paused" {
		return nil
	}
	if s.Phase != "ready" && s.Phase != "resuming" {
		return nil
	}
	expired, err := runtimeLeaseExpired(c, s)
	if !expired && err == nil {
		return nil
	}
	folder := filepath.Dir(path)
	if err = recordStop(folder, "SERVING_LEASE_EXPIRED"); err != nil {
		return err
	}
	o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
	return removeStoppedRuntime(ctx, o, folder, s)
}
