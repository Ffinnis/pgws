package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"pgws/internal/policyapproval"
)

func LogicalRuntimeDigest(c Container) string {
	data, _ := json.Marshal(c)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// ValidateApproval pins management scope and keeps durable authority outside
// every container mount. The connector separately checks the compiled plan,
// actual source lineage and transform key against the injected binding.
func ValidateApproval(c Container, p policyapproval.Permit) error {
	if err := p.Validate(); err != nil {
		return err
	}
	id := c.Spec.Identity
	source, sourceEpoch := id.Workspace, id.Generation
	if c.Spec.LogicalSource != "" {
		source, sourceEpoch = c.Spec.LogicalSource, c.Spec.LogicalSourceEpoch
	}
	if p.Runtime != LogicalRuntimeDigest(c) || p.Binding.Authority != id.Epoch || p.Binding.Tenant != id.Tenant || p.Binding.Project != id.Project || p.Binding.Source != source || p.Binding.SourceEpoch != sourceEpoch {
		return errors.New("policy approval differs from admitted runtime")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(p.Path))
	if err != nil {
		return errors.New("policy receipt directory unavailable")
	}
	path := filepath.Join(parent, filepath.Base(p.Path))
	for _, mount := range []string{c.Spec.DataDir, c.Spec.ControlDir, c.Spec.SocketDir, c.Spec.SourceSocket} {
		resolved, e := filepath.EvalSymlinks(mount)
		if e != nil {
			return errors.New("policy runtime mount unavailable")
		}
		rel, err := filepath.Rel(resolved, path)
		if err != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("policy permission must be outside container mounts")
		}
	}
	return nil
}

// IngestApproved runs a pinned connector with host-side expiry enforcement.
// Independent WatchLogicalOnce supervision remains required for host stalls.
func (o OCI) IngestApproved(ctx context.Context, c Container, mode string, p policyapproval.Permit) ([]byte, error) {
	if err := ValidateApproval(c, p); err != nil {
		return nil, err
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	finished := make(chan struct{})
	failure := make(chan error, 1)
	go func() {
		defer close(finished)
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-run.Done():
				return
			case <-tick.C:
				if err := p.Check(); err != nil {
					failure <- err
					stop, done := context.WithTimeout(context.Background(), 5*time.Second)
					_ = o.StopIngestion(stop, c, "POLICY_APPROVAL_EXPIRED")
					done()
					cancel()
					return
				}
			}
		}
	}()
	output, err := o.ingest(run, c, mode, &p.Binding)
	cancel()
	<-finished
	select {
	case e := <-failure:
		return nil, e
	default:
	}
	// The command may finish between ticks; do not accept seed completion under
	// an expired permit. Stop is terminal even if the data transaction committed.
	if e := p.Check(); e != nil {
		stop, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if stopErr := o.StopIngestion(stop, c, "POLICY_APPROVAL_EXPIRED"); stopErr != nil {
			return nil, stopErr
		}
		return nil, e
	}
	return output, err
}
