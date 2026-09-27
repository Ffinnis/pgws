package logical

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/physical"
)

// SlotObservation is a bounded read of the source and external receipts. It
// needs neither a running target nor the transformation key. Empty Reason means
// these safety checks passed, not that the candidate is ready for publication.
type SlotObservation struct {
	Source           Identity  `json:"source"`
	Reason           string    `json:"stop_reason,omitempty"`
	Active           bool      `json:"active"`
	RetainedBytes    int64     `json:"retained_bytes"`
	ConfirmedLSN     string    `json:"confirmed_lsn"`
	ProvenAppliedLSN string    `json:"proven_applied_lsn"`
	SeedCommitted    bool      `json:"seed_commit_recorded"`
	ObservedAt       time.Time `json:"observed_at"`
}

// InspectSlot does not adopt, advance, terminate or delete source objects. Its
// receipt is historical evidence; a destructive supervisor must additionally
// fence the ingestion runtime and reconcile slot removal/recreation.
func InspectSlot(parent context.Context, source *pgx.ConnConfig, ownershipPath string) (SlotObservation, error) {
	owned, err := ReadSlotOwnership(ownershipPath)
	if err != nil {
		return SlotObservation{}, err
	}
	observation := SlotObservation{Source: owned.Source, ObservedAt: time.Now().UTC()}
	if source == nil || source.Database != owned.Database || !filepath.IsAbs(source.Host) || filepath.Clean(source.Host) != source.Host || len(source.Fallbacks) != 0 {
		return observation, errors.New("logical monitor requires the configured private source database")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cfg := source.Copy()
	cfg.Tracer = nil
	cfg.OnNotice, cfg.OnNotification, cfg.OnPgError = nil, nil, nil
	cfg.MaxProtocolMessageBodyLen = 1 << 20
	cfg.ConnectTimeout = 2 * time.Second
	delete(cfg.RuntimeParams, "replication")
	cfg.RuntimeParams["search_path"] = "pg_catalog"
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "2000"
	cfg.RuntimeParams["lock_timeout"] = "500"
	cfg.RuntimeParams["application_name"] = "pgws-logical-monitor"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return observation, errors.New("logical monitor source unavailable")
	}
	closeOnDeadline := context.AfterFunc(ctx, func() { _ = conn.PgConn().Conn().Close() })
	defer closeOnDeadline()
	defer closeSource(conn)
	var system string
	var timeline int64
	var bounded bool
	err = conn.QueryRow(ctx, `SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id,
 current_setting('server_version_num')::int BETWEEN 180000 AND 189999 AND current_setting('max_slot_wal_keep_size')<>'-1'
 AND pg_size_bytes(current_setting('max_slot_wal_keep_size')) BETWEEN 1 AND 268435456`).Scan(&system, &timeline, &bounded)
	if err != nil {
		return observation, errors.New("logical monitor lineage unavailable")
	}
	if system != owned.Source.SystemID || timeline != owned.Source.Timeline {
		observation.Reason = "SOURCE_LINEAGE_CHANGED"
		return observation, nil
	}
	var identity, healthy, publication bool
	err = conn.QueryRow(ctx, `SELECT active,coalesce(confirmed_flush_lsn::text,''),
 slot_type='logical' AND plugin='pgoutput' AND database=current_database() AND NOT temporary AND NOT two_phase AND NOT failover AND NOT synced,
 invalidation_reason IS NULL AND wal_status IN ('reserved','extended') AND restart_lsn IS NOT NULL,
 coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(),restart_lsn),0)::bigint,
 EXISTS(SELECT FROM pg_publication WHERE oid=$2 AND pubname=$3)
 FROM pg_replication_slots WHERE slot_name=$1`, owned.Slot, owned.PublicationOID, owned.Publication).Scan(&observation.Active, &observation.ConfirmedLSN, &identity, &healthy, &observation.RetainedBytes, &publication)
	if errors.Is(err, pgx.ErrNoRows) {
		observation.Reason = "SOURCE_SLOT_MISSING"
		return observation, nil
	}
	if err != nil {
		return observation, errors.New("logical monitor slot state unavailable")
	}
	// Read after the slot observation: an acknowledged position necessarily had
	// its file fsynced first. Reading before SQL can falsely report an ACK ahead
	// of progress when a concurrent transaction commits between the two reads.
	observation.ProvenAppliedLSN = owned.SeedLSN
	if _, err = os.Lstat(ownershipPath + ".applied"); err == nil {
		progress, e := ReadApplied(ownershipPath, owned)
		if e != nil {
			return observation, e
		}
		observation.ProvenAppliedLSN = progress.AppliedLSN
		observation.SeedCommitted = true
	} else if !os.IsNotExist(err) {
		return observation, errors.New("logical monitor progress unavailable")
	}
	confirmed, parseErr := physical.ParseLSN(observation.ConfirmedLSN)
	proven, _ := physical.ParseLSN(observation.ProvenAppliedLSN)
	seed, _ := physical.ParseLSN(owned.SeedLSN)
	switch {
	case !identity:
		observation.Reason = "SOURCE_SLOT_IDENTITY_CHANGED"
	case !publication:
		observation.Reason = "SOURCE_PUBLICATION_REPLACED"
	case !healthy:
		observation.Reason = "SOURCE_WAL_LOST"
	case parseErr != nil || confirmed < seed || confirmed > proven:
		observation.Reason = "SOURCE_ACK_NOT_PROVEN"
	case !bounded:
		observation.Reason = "SOURCE_WAL_LIMIT_CHANGED"
	case observation.RetainedBytes < 0 || observation.RetainedBytes >= 64<<20:
		observation.Reason = "SOURCE_WAL_BUDGET"
	}
	return observation, nil
}
