package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/config"
	"pgws/internal/logical"
	"pgws/internal/policyapproval"
	"pgws/internal/runtime"
)

// LogicalCandidate is private host supervision configuration. Register it only
// after confirmed slot ownership. It is not a public baseline publication.
type LogicalCandidate struct {
	Container     runtime.Container      `json:"container"`
	SourceDSN     string                 `json:"source_dsn"`
	OwnershipPath string                 `json:"ownership_file"`
	Approval      *policyapproval.Permit `json:"approval,omitempty"`
}

func (c LogicalCandidate) source() (*pgx.ConnConfig, logical.SlotOwnership, error) {
	owned, err := logical.ReadSlotOwnership(c.OwnershipPath)
	if err != nil {
		return nil, owned, err
	}
	spec := c.Container.Spec
	matches := owned.Source.Source == spec.Identity.Workspace && owned.Source.Epoch == spec.Identity.Generation && owned.Source.Baseline == "" && owned.Source.Generation == 0
	if spec.LogicalSource != "" {
		matches = owned.Source.Source == spec.LogicalSource && owned.Source.Epoch == spec.LogicalSourceEpoch && owned.Source.Baseline == spec.Identity.Workspace && owned.Source.Generation == spec.Identity.Generation
	}
	if spec.Purpose != "baseline" || spec.LogicalBinarySHA == "" || c.OwnershipPath != filepath.Join(spec.ControlDir, "slot.json") || !matches {
		return nil, owned, errors.New("logical candidate differs from admitted runtime")
	}
	source, err := pgx.ParseConfig(c.SourceDSN)
	if err != nil || !filepath.IsAbs(source.Host) || source.Host != spec.SourceSocket || source.Database != owned.Database || len(source.Fallbacks) != 0 {
		return nil, owned, errors.New("logical monitor source differs from baseline mount")
	}
	source.Tracer = nil
	source.OnNotice, source.OnNotification, source.OnPgError = nil, nil, nil
	source.MaxProtocolMessageBodyLen = 1 << 20
	source.ConnectTimeout = 2 * time.Second
	source.RuntimeParams["search_path"] = "pg_catalog"
	source.RuntimeParams["statement_timeout"] = "2000"
	source.RuntimeParams["lock_timeout"] = "500"
	delete(source.RuntimeParams, "replication")
	return source, owned, nil
}

// WatchLogicalOnce is independent of management and the host's command locks.
// It writes a terminal runtime fence, kills the verified enclosure, and only
// then attempts bounded cleanup of a still-provable inactive logical slot.
func WatchLogicalOnce(parent context.Context, c LogicalCandidate) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
	if c.Approval != nil {
		if err := runtime.ValidateApproval(c.Container, *c.Approval); err != nil {
			return err
		}
		if err := c.Approval.Check(); err != nil {
			if err = o.StopIngestion(ctx, c.Container, "POLICY_APPROVAL_EXPIRED"); err != nil {
				return err
			}
		}
	}
	source, owned, err := c.source()
	if err != nil {
		// Missing ownership cannot keep a consumer running. Stop the known runtime;
		// source deletion still requires an independently provable ownership receipt.
		if stopErr := o.StopIngestion(ctx, c.Container, "SOURCE_OWNERSHIP_UNPROVEN"); stopErr != nil {
			return stopErr
		}
		return err
	}
	status, inspectionErr := logical.InspectSlot(ctx, source, c.OwnershipPath)
	reason := status.Reason
	if inspectionErr != nil {
		reason = "SOURCE_INSPECTION_FAILED"
	}
	if _, e := os.Lstat(filepath.Join(c.Container.Spec.ControlDir, "logical-stop.json")); !os.IsNotExist(e) && reason == "" {
		reason = "INGESTION_STOPPED"
	}
	if reason == "" {
		return nil
	}
	if err = o.StopIngestion(ctx, c.Container, reason); err != nil {
		return err
	}
	if err = o.VerifyAbsent(ctx, c.Container.Spec.Identity); err != nil {
		return err
	}
	return retireLogicalSlot(ctx, c, source, owned)
}

type logicalRetirement struct {
	OwnershipHash string `json:"ownership_sha256"`
	ContainerID   string `json:"container_id"`
}

// One durable attempt prevents a lost DROP response from later deleting a
// replacement slot. A surviving slot after an uncertain attempt needs an
// operator; the watchdog never silently retries that destructive operation.
func retireLogicalSlot(ctx context.Context, c LogicalCandidate, source *pgx.ConnConfig, owned logical.SlotOwnership) error {
	owner, err := pgx.ConnectConfig(ctx, source)
	if err != nil {
		return errors.New("logical retirement source unavailable")
	}
	defer owner.Close(context.Background())
	if err = logical.AcquireSource(ctx, owner, owned.Slot); err != nil {
		return err
	}
	status, err := logical.InspectSlot(ctx, source, c.OwnershipPath)
	if err != nil {
		return err
	}
	if status.Reason == "SOURCE_SLOT_MISSING" {
		return nil
	}
	if status.Active || (status.Reason != "" && status.Reason != "SOURCE_WAL_BUDGET" && status.Reason != "SOURCE_WAL_LIMIT_CHANGED") {
		return errors.New("logical slot continuity is unproven; explicit reconciliation required")
	}
	// Verify on the very session that will execute DROP. A separate monitoring
	// connection cannot authorize a mutation after a socket/server replacement.
	var matches bool
	err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_replication_slots s
 WHERE slot_name=$1 AND slot_type='logical' AND plugin='pgoutput' AND database=$2
 AND database=current_database() AND NOT active AND NOT temporary AND NOT two_phase AND NOT failover AND NOT synced
 AND invalidation_reason IS NULL AND wal_status IN ('reserved','extended')
 AND confirmed_flush_lsn BETWEEN $3::pg_lsn AND $4::pg_lsn)
 AND (pg_control_system()).system_identifier::text=$5 AND (pg_control_checkpoint()).timeline_id=$6
 AND EXISTS(SELECT FROM pg_publication WHERE oid=$7 AND pubname=$8)`, owned.Slot, owned.Database, owned.SeedLSN, status.ProvenAppliedLSN, owned.Source.SystemID, owned.Source.Timeline, owned.PublicationOID, owned.Publication).Scan(&matches)
	if err != nil || !matches {
		return errors.New("logical retirement session cannot prove the original slot")
	}
	data, _ := json.Marshal(owned)
	intent := logicalRetirement{OwnershipHash: fmt.Sprintf("%x", sha256.Sum256(data)), ContainerID: c.Container.ID}
	path := filepath.Join(c.Container.Spec.ControlDir, "logical-retirement.json")
	if err = saveOnce(path, intent); err != nil {
		if os.IsExist(err) {
			text, e := config.PrivateText(path)
			var prior logicalRetirement
			if e != nil || json.Unmarshal([]byte(text), &prior) != nil || prior != intent {
				return errors.New("logical retirement intent differs")
			}
			return errors.New("logical retirement outcome is uncertain; explicit reconciliation required")
		}
		return err
	}
	if _, err = owner.Exec(ctx, "SELECT pg_drop_replication_slot($1)", owned.Slot); err != nil {
		return errors.New("logical slot removal was not confirmed; explicit reconciliation required")
	}
	return nil
}
