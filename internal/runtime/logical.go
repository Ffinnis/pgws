package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pgws/internal/policyapproval"
	"time"
)

// Ingest runs the pinned private connector inside its baseline's namespace.
// Removing that exact container kills both PostgreSQL and the source consumer;
// cancelling only a docker-exec client would leave the consumer running.
func (o OCI) Ingest(ctx context.Context, c Container, mode string) ([]byte, error) {
	return o.ingest(ctx, c, mode, nil)
}

func (o OCI) ingest(ctx context.Context, c Container, mode string, approval *policyapproval.Binding) ([]byte, error) {
	if err := validate(c.Spec); err != nil {
		return nil, err
	}
	if c.Spec.LogicalBinarySHA == "" || c.Spec.Purpose != "baseline" || c.Spec.SourceSocket == "" || (mode != "seed" && mode != "run") {
		return nil, errors.New("logical command requires an admitted ingestion baseline")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := logicalStopped(c.Spec); err != nil {
		return nil, err
	}
	if err := o.Verify(ctx, c); err != nil {
		return nil, err
	}
	path := filepath.Join(c.Spec.ControlDir, "pgws-logical")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("pinned logical executable unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("pinned logical executable unreadable")
	}
	hash := sha256.New()
	_, err = io.Copy(hash, io.LimitReader(f, 64<<20+1))
	f.Close()
	if err != nil || fmt.Sprintf("%x", hash.Sum(nil)) != c.Spec.LogicalBinarySHA {
		return nil, errors.New("logical executable differs from admitted digest")
	}
	args := []string{"exec", "--user", "999:999"}
	if approval != nil {
		encoded, _ := json.Marshal(approval)
		args = append(args, "--env", "PGWS_LOGICAL_APPROVAL_BINDING="+string(encoded))
	}
	if c.Spec.LogicalSource != "" {
		encoded, _ := json.Marshal(struct {
			Source     string `json:"source"`
			Epoch      int64  `json:"epoch"`
			Baseline   string `json:"baseline_id"`
			Generation int64  `json:"baseline_generation"`
		}{c.Spec.LogicalSource, c.Spec.LogicalSourceEpoch, c.Spec.Identity.Workspace, c.Spec.Identity.Generation})
		args = append(args, "--env", "PGWS_LOGICAL_RUNTIME_BINDING="+string(encoded))
	}
	args = append(args, c.ID, path, mode, filepath.Join(c.Spec.ControlDir, "logical.json"))
	output, err := o.command(ctx, args...)
	if ctx.Err() != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := o.StopIngestion(stopCtx, c, "INGESTION_CANCELLED"); e != nil {
			return nil, errors.New("logical cancellation could not confirm runtime removal")
		}
		return nil, ctx.Err()
	}
	return output, err
}
