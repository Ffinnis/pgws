package logical

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/privacy"
)

// MarkerBoundary is a durable applied-source boundary, not a target WAL LSN.
// Signing/publication still requires the caller's current authority checks.
type MarkerBoundary struct {
	ID        string    `json:"id"`
	Source    Identity  `json:"source"`
	PlanHash  string    `json:"plan_hash"`
	LSN       string    `json:"source_commit_end_lsn"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Reserve capacity before any source write. Serializing on the checkpoint
// prevents concurrent issuers from exhausting the receipt cap during CDC lag.
func (t Target) reserveMarker(ctx context.Context, id string, expires time.Time) error {
	contract, err := t.contract()
	if err != nil {
		return err
	}
	tx, err := t.Pool.Begin(ctx)
	if err != nil {
		return errors.New("barrier reservation unavailable")
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on; SET LOCAL search_path=pg_catalog"); err != nil {
		return errors.New("barrier reservation session failed")
	}
	var actual string
	var seeded bool
	if err = tx.QueryRow(ctx, "SELECT contract,seed_lsn IS NOT NULL FROM _pgws_ingestion.checkpoint WHERE singleton FOR UPDATE").Scan(&actual, &seeded); err != nil || actual != contract || !seeded {
		return errors.New("barrier reservation requires the seeded immutable target")
	}
	if _, err = tx.Exec(ctx, "DELETE FROM _pgws_ingestion.barriers WHERE expires_at<=$1", time.Now().Unix()); err != nil {
		return errors.New("barrier retention cleanup failed")
	}
	var prior int64
	err = tx.QueryRow(ctx, "SELECT expires_at FROM _pgws_ingestion.barriers WHERE id=$1", id).Scan(&prior)
	if err == nil {
		if prior != expires.Unix() {
			return errors.New("barrier identity has different reserved claims")
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return errors.New("barrier reservation lookup failed")
	}
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM _pgws_ingestion.barriers").Scan(&count); err != nil || count >= 4096 {
		return errors.New("barrier receipt budget exhausted before source mutation")
	}
	if _, err = tx.Exec(ctx, "INSERT INTO _pgws_ingestion.barriers(id,expires_at) VALUES($1,$2)", id, expires.Unix()); err != nil {
		return errors.New("barrier identity reservation failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.New("barrier reservation commit uncertain")
	}
	return nil
}

func (t Target) markerTable() (privacy.Table, error) {
	if t.Plan == nil || t.MarkerTable == 0 {
		return privacy.Table{}, errors.New("logical marker relation is not configured")
	}
	var marker privacy.Table
	for _, table := range t.Plan.Schema().Tables {
		if table.ID == t.MarkerTable {
			marker = table
		}
		if table.Schema == "_pgws_barriers" && table.ID != t.MarkerTable {
			return marker, errors.New("reserved marker schema contains application data")
		}
		for _, fk := range table.ForeignKeys {
			if fk.Table == t.MarkerTable {
				return marker, errors.New("application relation references a service marker")
			}
		}
	}
	if marker.Schema != "_pgws_barriers" || marker.Name != "marker" || len(marker.Columns) != 3 || len(marker.ForeignKeys) > 0 || len(marker.Unique) > 0 || !slices.Equal(marker.PrimaryKey, []int16{marker.Columns[0].ID}) {
		return marker, errors.New("logical marker relation shape differs")
	}
	for i, want := range []struct{ name, kind string }{{"id", "int8"}, {"token", "uuid"}, {"expires_at", "int8"}} {
		c := marker.Columns[i]
		if c.Name != want.name || c.Type != want.kind || c.Nullable || !t.Plan.CopiesOriginal(marker.ID, c.ID) {
			return marker, errors.New("logical marker columns require unchanged service metadata")
		}
	}
	for _, seq := range t.Plan.Schema().Sequences {
		if seq.Table == marker.ID {
			return marker, errors.New("marker relation cannot own a sequence")
		}
	}
	return marker, nil
}

// recordMarker runs in the same target transaction as every application change
// and the checkpoint. A late constraint failure rolls all three back together.
func (t Target) recordMarker(ctx context.Context, tx pgx.Tx, change Change, end string) error {
	if change.Kind != "update" || len(change.Row) != 3 || len(change.OldKey) != 1 || change.OldKey["id"] == nil || *change.OldKey["id"] != "1" || change.Row["id"] == nil || *change.Row["id"] != "1" || change.Row["token"] == nil || change.Row["expires_at"] == nil || !control.ValidID(*change.Row["token"]) {
		return errors.New("invalid service marker mutation")
	}
	expires, err := strconv.ParseInt(*change.Row["expires_at"], 10, 64)
	if err != nil || expires <= 0 || expires > time.Now().Add(time.Hour+5*time.Second).Unix() {
		return errors.New("service marker expiry exceeds its bound")
	}
	if _, err = tx.Exec(ctx, "DELETE FROM _pgws_ingestion.barriers WHERE expires_at<=$1", time.Now().Unix()); err != nil {
		return errors.New("expired barrier cleanup failed")
	}
	// Expired source messages still advance ordinary apply, but cannot recreate
	// a usable barrier or exhaust retained receipt space during backlog replay.
	if expires <= time.Now().Unix() {
		return nil
	}
	updated, err := tx.Exec(ctx, "UPDATE _pgws_ingestion.barriers SET end_lsn=coalesce(end_lsn,$3::pg_lsn) WHERE id=$1 AND expires_at=$2", *change.Row["token"], expires, end)
	if err != nil || updated.RowsAffected() != 1 {
		return errors.New("logical marker has no matching reserved identity")
	}
	return nil
}

func (t Target) markerBoundary(ctx context.Context, id string, expires time.Time) (MarkerBoundary, error) {
	contract, err := t.contract()
	if err != nil {
		return MarkerBoundary{}, err
	}
	var actual, end, applied string
	var expiry int64
	var seeded bool
	err = t.Pool.QueryRow(ctx, `SELECT c.contract,b.end_lsn::text,c.applied_lsn::text,b.expires_at,c.seed_lsn IS NOT NULL
 FROM _pgws_ingestion.checkpoint c CROSS JOIN _pgws_ingestion.barriers b WHERE c.singleton AND b.id=$1 AND b.end_lsn IS NOT NULL`, id).Scan(&actual, &end, &applied, &expiry, &seeded)
	if errors.Is(err, pgx.ErrNoRows) {
		return MarkerBoundary{}, pgx.ErrNoRows
	}
	a, e1 := physical.ParseLSN(applied)
	b, e2 := physical.ParseLSN(end)
	if err != nil || e1 != nil || e2 != nil || b == 0 || a < b || !seeded || actual != contract || expiry != expires.Unix() || expiry <= time.Now().Unix() {
		return MarkerBoundary{}, errors.New("logical barrier lacks a matching durable target boundary")
	}
	return MarkerBoundary{ID: id, Source: t.Identity, PlanHash: t.Plan.Hash(), LSN: end, ExpiresAt: time.Unix(expiry, 0).UTC()}, nil
}

// Barrier updates a single service-owned published row through a role with
// UPDATE(token,expires_at) and SELECT(id) only. It waits for actual source COMMIT
// decoding and target Apply; receiver keepalives never satisfy this wait.
// Run must already consume this connector in another goroutine/process.
func (c Connector) Barrier(parent context.Context, writer *pgx.ConnConfig, id string, expires time.Time) (MarkerBoundary, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	slot, publication, err := c.names()
	if err != nil {
		return MarkerBoundary{}, err
	}
	if _, err = c.Target.markerTable(); err != nil {
		return MarkerBoundary{}, err
	}
	if writer == nil || !control.ValidID(id) || expires.Unix() <= time.Now().Unix() || expires.After(time.Now().Add(time.Hour)) || !filepath.IsAbs(c.Source.Host) || writer.Host != c.Source.Host || writer.Port != c.Source.Port || writer.Database != c.Source.Database || len(writer.Fallbacks) != 0 {
		return MarkerBoundary{}, errors.New("invalid private marker writer or expiry")
	}
	owner, err := c.connect(ctx)
	if err != nil {
		return MarkerBoundary{}, err
	}
	defer closeSource(owner)
	if err = c.checkCurrent(ctx, owner, publication); err != nil {
		return MarkerBoundary{}, err
	}
	if _, err = checkSlot(ctx, owner, slot); err != nil {
		return MarkerBoundary{}, err
	}
	var singleton bool
	if err = owner.QueryRow(ctx, "SELECT count(*)=1 AND min(id)=1 FROM _pgws_barriers.marker").Scan(&singleton); err != nil || !singleton {
		return MarkerBoundary{}, errors.New("source marker is not the reserved singleton")
	}
	if result, e := c.Target.markerBoundary(ctx, id, expires); e == nil {
		return result, nil
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return MarkerBoundary{}, e
	}
	cfg := writer.Copy()
	cfg.Tracer = nil
	cfg.OnNotice = nil
	cfg.OnPgError = nil
	cfg.OnNotification = nil
	cfg.MaxProtocolMessageBodyLen = 1 << 20
	cfg.RuntimeParams = map[string]string{"search_path": "pg_catalog", "row_security": "off", "statement_timeout": "5000", "lock_timeout": "5000", "application_name": "pgws-barrier-writer"}
	cfg.ConnectTimeout = 5 * time.Second
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return MarkerBoundary{}, errors.New("restricted marker writer unavailable")
	}
	defer closeSource(conn)
	var restricted bool
	err = conn.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
 AND NOT pg_has_role(current_user,c.relowner,'USAGE')
 AND NOT has_table_privilege(c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_column_privilege(c.oid,'id','UPDATE,INSERT,REFERENCES')
 AND NOT has_column_privilege(c.oid,'token','INSERT,REFERENCES,SELECT')
 AND NOT has_column_privilege(c.oid,'expires_at','INSERT,REFERENCES,SELECT')
 AND has_column_privilege(c.oid,'id','SELECT')
 AND has_column_privilege(c.oid,'token','UPDATE') AND has_column_privilege(c.oid,'expires_at','UPDATE')
 FROM pg_roles r CROSS JOIN pg_class c WHERE r.rolname=current_user AND c.oid='_pgws_barriers.marker'::regclass`).Scan(&restricted)
	if err != nil || !restricted {
		return MarkerBoundary{}, errors.New("marker writer privileges exceed the bounded role")
	}
	if err = c.Target.reserveMarker(ctx, id, expires); err != nil {
		return MarkerBoundary{}, err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return MarkerBoundary{}, errors.New("marker transaction unavailable")
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return MarkerBoundary{}, errors.New("marker durability setting failed")
	}
	updated, err := tx.Exec(ctx, "UPDATE _pgws_barriers.marker SET token=$1,expires_at=$2 WHERE id=1", id, expires.Unix())
	if err != nil || updated.RowsAffected() != 1 {
		return MarkerBoundary{}, errors.New("source marker update failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return MarkerBoundary{}, errors.New("source marker commit uncertain; retry the same identity")
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, e := c.Target.markerBoundary(ctx, id, expires)
		if e == nil {
			if err = c.checkCurrent(ctx, owner, publication); err != nil {
				return MarkerBoundary{}, err
			}
			if _, err = checkSlot(ctx, owner, slot); err != nil {
				return MarkerBoundary{}, err
			}
			// A fresh connection rechecks source system/timeline after the wait.
			check, e := c.connect(ctx)
			if e != nil {
				return MarkerBoundary{}, e
			}
			closeSource(check)
			return result, nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return MarkerBoundary{}, e
		}
		select {
		case <-ctx.Done():
			return MarkerBoundary{}, errors.New("logical marker has no durable apply before deadline")
		case <-ticker.C:
		}
	}
}
