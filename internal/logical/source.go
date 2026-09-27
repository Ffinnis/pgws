package logical

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"pgws/internal/privacy"
)

// Connector is private ingestion machinery. Its source connection is supplied
// by a trusted secret adapter, never by workspace requests. DDL must be frozen
// by the source operator during initial onboarding. Publication remains gated
// independently of successful seeding or streaming.
type Connector struct {
	Source *pgx.ConnConfig
	Target Target
	// Persist ownership immediately after confirmed creation, before reading
	// seed rows. A missing receipt is never replaced by adopting a slot name.
	AfterSlotCreated func(SlotOwnership) error
	// Called only after a confirmed target commit, before acknowledging the
	// source. A failed external receipt stops ingestion without advancing ACK.
	AfterDurableApply func(string) error
}

func (c Connector) names() (slot, publication string, err error) {
	if _, err = c.Target.contract(); err != nil || c.Source == nil || c.Source.Database == "" {
		return "", "", errors.New("invalid logical connector contract")
	}
	return sourceObjectNames(c.Target.Identity)
}

func (c Connector) connect(ctx context.Context) (*pgx.Conn, error) {
	if _, _, err := c.names(); err != nil {
		return nil, err
	}
	cfg := c.Source.Copy()
	cfg.MaxProtocolMessageBodyLen = 8 << 20
	delete(cfg.RuntimeParams, "replication")
	cfg.RuntimeParams["search_path"] = "pg_catalog"
	cfg.RuntimeParams["application_name"] = "pgws-logical"
	cfg.RuntimeParams["statement_timeout"] = "30000"
	cfg.RuntimeParams["lock_timeout"] = "5000"
	cfg.RuntimeParams["row_security"] = "off"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("logical source unavailable")
	}
	var system string
	var timeline int64
	var bounded bool
	err = conn.QueryRow(ctx, `SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id,
 current_setting('max_slot_wal_keep_size')<>'-1' AND pg_size_bytes(current_setting('max_slot_wal_keep_size')) BETWEEN 1 AND 268435456`).Scan(&system, &timeline, &bounded)
	if err != nil || system != c.Target.Identity.SystemID || timeline != c.Target.Identity.Timeline || !bounded {
		conn.Close(ctx)
		return nil, errors.New("source lineage or retained WAL bound differs")
	}
	return conn, nil
}

func (c Connector) replication(ctx context.Context) (*pgconn.PgConn, error) {
	cfg := c.Source.Config.Copy()
	cfg.RuntimeParams["replication"] = "database"
	cfg.RuntimeParams["application_name"] = "pgws-logical"
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("logical replication connection unavailable")
	}
	identity, err := pglogrepl.IdentifySystem(ctx, conn)
	if err != nil || identity.SystemID != c.Target.Identity.SystemID || int64(identity.Timeline) != c.Target.Identity.Timeline || identity.DBName != c.Source.Database {
		conn.Close(ctx)
		return nil, errors.New("replication connection lineage differs")
	}
	// Refuse an oversized CopyData before pgproto allocates its advertised body.
	conn.Frontend().SetMaxBodyLen(2<<20 + 1024)
	return conn, nil
}

// AcquireSource serializes PGWS ingestion and retirement for a slot. Source
// administrators must not bypass this lock to modify PGWS-owned objects.
func AcquireSource(ctx context.Context, conn *pgx.Conn, slot string) error {
	digest := sha256.Sum256([]byte("pgws-logical-owner-v1:" + slot))
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", int64(binary.BigEndian.Uint64(digest[:8]))).Scan(&ok); err != nil || !ok {
		return errors.New("logical generation already has an ingestion owner")
	}
	return nil // The dedicated connection owns this lock until Close.
}

func (c Connector) checkSchema(ctx context.Context, tx pgx.Tx) error {
	schema, err := ReadCatalog(ctx, tx)
	if err != nil {
		return err
	}
	if privacy.SchemaHash(schema) != c.Target.Plan.SchemaHash() {
		return errors.New("source catalog differs from the approved immutable plan")
	}
	return nil
}

func (c Connector) checkPublication(ctx context.Context, conn *pgx.Conn, name string) error {
	var ok bool
	var ids []uint32
	err := conn.QueryRow(ctx, `SELECT NOT puballtables AND pubinsert AND pubupdate AND pubdelete AND pubtruncate AND NOT pubviaroot AND pubgencols='n'
 AND NOT EXISTS(SELECT FROM pg_publication_namespace WHERE pnpubid=p.oid)
 AND NOT EXISTS(SELECT FROM pg_publication_rel WHERE prpubid=p.oid AND (prqual IS NOT NULL OR prattrs IS NOT NULL)),
 ARRAY(SELECT prrelid FROM pg_publication_rel WHERE prpubid=p.oid ORDER BY prrelid)
 FROM pg_publication p WHERE pubname=$1`, name).Scan(&ok, &ids)
	tables := c.Target.Plan.Schema().Tables
	if err != nil || !ok || len(ids) != len(tables) {
		return errors.New("logical publication differs from the complete approved table set")
	}
	for i := range ids {
		if ids[i] != tables[i].ID {
			return errors.New("logical publication relation identity differs")
		}
	}
	return nil
}

func checkSlot(ctx context.Context, conn *pgx.Conn, slot string) (string, error) {
	var confirmed string
	var valid bool
	err := conn.QueryRow(ctx, `SELECT confirmed_flush_lsn::text,slot_type='logical' AND plugin='pgoutput' AND database=current_database()
 AND NOT temporary AND NOT two_phase AND NOT failover AND NOT synced AND invalidation_reason IS NULL
 AND wal_status IN ('reserved','extended') AND restart_lsn IS NOT NULL
 AND pg_wal_lsn_diff(pg_current_wal_lsn(),restart_lsn) BETWEEN 0 AND 67108864
 FROM pg_replication_slots WHERE slot_name=$1`, slot).Scan(&confirmed, &valid)
	if err != nil || !valid {
		return "", errors.New("logical slot identity, health or 64 MiB WAL budget differs")
	}
	return confirmed, nil
}

func closeSource(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
