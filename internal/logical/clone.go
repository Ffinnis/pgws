package logical

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/physical"
	"pgws/internal/privacy"
)

type CloneProof struct {
	Source         Identity  `json:"source"`
	PlanHash       string    `json:"plan_hash"`
	AppliedLSN     string    `json:"applied_source_lsn"`
	TargetSystemID string    `json:"target_system_id"`
	TargetTimeline int64     `json:"target_timeline"`
	ObservedAt     time.Time `json:"observed_at"`
}

// PrepareClone must run only on an unexposed, disconnected clone after normal
// primary crash recovery. It verifies the recovered source checkpoint and
// removes ingestion metadata before ordinary workspace ownership is installed.
// Its receipt is not endpoint eligibility: runtime isolation, GUID, policy
// revocation and serving authorization remain the host's separate obligations.
// An uncertain commit requires reconciliation, never blind readiness adoption.
func (t Target) PrepareClone(ctx context.Context, minimumLSN string) (CloneProof, error) {
	var proof CloneProof
	contract, err := t.contract()
	minimum, positionErr := physical.ParseLSN(minimumLSN)
	if err != nil || positionErr != nil || minimum == 0 {
		return proof, errors.New("invalid sanitized clone contract or source lower bound")
	}
	tx, err := t.Pool.Begin(ctx)
	if err != nil {
		return proof, errors.New("sanitized clone SQL unavailable")
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on; SET LOCAL search_path=pg_catalog; SET LOCAL lock_timeout='5s'"); err != nil {
		return proof, errors.New("sanitized clone validation session unavailable")
	}
	var actual, applied string
	var valid bool
	err = tx.QueryRow(ctx, `SELECT contract,applied_lsn::text,seed_lsn IS NOT NULL AND seed_lsn<>'0/0' AND seed_lsn<=applied_lsn
 FROM _pgws_ingestion.checkpoint WHERE singleton FOR UPDATE`).Scan(&actual, &applied, &valid)
	position, parseErr := physical.ParseLSN(applied)
	if err != nil || parseErr != nil || actual != contract || !valid || position < minimum {
		return proof, errors.New("recovered sanitized checkpoint does not prove the approved source lower bound")
	}
	err = tx.QueryRow(ctx, `SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'
 AND NOT EXISTS(SELECT FROM pg_subscription)
 AND NOT EXISTS(SELECT FROM pg_replication_slots WHERE database=current_database())
 AND NOT EXISTS(SELECT FROM pg_foreign_server),
 (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id`).Scan(&valid, &proof.TargetSystemID, &proof.TargetTimeline)
	if err != nil || !valid {
		return CloneProof{}, errors.New("sanitized clone is not an independent writable primary")
	}
	if err = t.verifyCloneSchema(ctx, tx); err != nil {
		return CloneProof{}, err
	}
	for _, table := range t.Plan.Schema().Tables {
		if _, err = tx.Exec(ctx, "LOCK TABLE "+qualified(table)+" IN ACCESS EXCLUSIVE MODE"); err != nil {
			return CloneProof{}, errors.New("sanitized clone schema could not be locked")
		}
		if err = restoreRelationships(ctx, tx, table, t.Plan.Schema()); err != nil {
			return CloneProof{}, err
		}
	}
	if err = t.prepareSequences(ctx, tx); err != nil {
		return CloneProof{}, err
	}
	if t.MarkerTable != 0 {
		if _, err = tx.Exec(ctx, `DROP TABLE _pgws_ingestion.barriers; DROP TABLE _pgws_barriers.marker; DROP SCHEMA _pgws_barriers`); err != nil {
			return CloneProof{}, errors.New("sanitized clone service marker removal failed")
		}
	}
	if _, err = tx.Exec(ctx, `DROP TABLE _pgws_ingestion.transactions; DROP TABLE _pgws_ingestion.checkpoint; DROP TABLE _pgws_ingestion.sequence_watermarks; DROP SCHEMA _pgws_ingestion`); err != nil {
		return CloneProof{}, errors.New("sanitized clone ingestion metadata could not be removed")
	}
	if err = tx.Commit(ctx); err != nil {
		return CloneProof{}, errors.New("sanitized clone detach commit was not confirmed; reconciliation required")
	}
	proof.Source, proof.PlanHash, proof.AppliedLSN, proof.ObservedAt = t.Identity, t.Plan.Hash(), applied, time.Now().UTC()
	return proof, nil
}

func (t Target) verifyCloneSchema(ctx context.Context, tx pgx.Tx) error {
	var count int
	var safe bool
	err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname NOT IN ('information_schema','_pgws_ingestion') AND c.relkind='r'),
 NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname NOT IN ('information_schema','_pgws_ingestion') AND (c.relkind NOT IN ('r','i') OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity))
 AND NOT EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema')
 AND NOT EXISTS(SELECT FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema' AND NOT g.tgisinternal)
 AND NOT EXISTS(SELECT FROM pg_description d JOIN pg_class c ON c.oid=d.objoid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE d.classoid='pg_class'::regclass AND n.nspname!~'^pg_' AND n.nspname NOT IN ('information_schema','_pgws_ingestion'))`).Scan(&count, &safe)
	schema := t.Plan.Schema()
	if err != nil || !safe || count != len(schema.Tables) {
		return errors.New("sanitized clone contains unapproved schema objects")
	}
	for _, expected := range schema.Tables {
		if _, err = tx.Exec(ctx, "LOCK TABLE "+qualified(expected)+" IN ACCESS EXCLUSIVE MODE"); err != nil {
			return errors.New("sanitized clone table identity unavailable")
		}
		var actual privacy.Table
		if err = tx.QueryRow(ctx, "SELECT $1::regclass::oid", qualified(expected)).Scan(&actual.ID); err != nil {
			return errors.New("sanitized clone table identity differs")
		}
		if err = readColumns(ctx, tx, &actual); err != nil || len(actual.Columns) != len(expected.Columns) {
			return errors.New("sanitized clone fields differ from the approved plan")
		}
		for i, column := range expected.Columns {
			column.ID = actual.Columns[i].ID // Physical attnums belong to this target.
			if column != actual.Columns[i] {
				return errors.New("sanitized clone field type or nullability changed")
			}
		}
		if err = readKeys(ctx, tx, &actual); err != nil {
			return errors.New("sanitized clone constraints are not qualified")
		}
		if !slices.Equal(columnNames(actual, actual.PrimaryKey), columnNames(expected, expected.PrimaryKey)) {
			return errors.New("sanitized clone primary key differs")
		}
		keyNames := func(table privacy.Table) []string {
			var names []string
			for _, key := range table.Unique {
				names = append(names, quoted(columnNames(table, key)))
			}
			slices.Sort(names)
			return names
		}
		if !slices.Equal(keyNames(actual), keyNames(expected)) {
			return errors.New("sanitized clone unique keys differ")
		}
	}
	return nil
}

func restoreRelationships(ctx context.Context, tx pgx.Tx, table privacy.Table, schema privacy.Schema) error {
	rows, err := tx.Query(ctx, `SELECT c.conname,
 ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(id,ord) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.id ORDER BY k.ord),
 n.nspname,r.relname,
 ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(id,ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.id ORDER BY k.ord),
 c.convalidated AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
 FROM pg_constraint c JOIN pg_class r ON r.oid=c.confrelid JOIN pg_namespace n ON n.oid=r.relnamespace
 WHERE c.conrelid=$1::regclass AND c.contype='f' ORDER BY c.oid`, qualified(table))
	if err != nil {
		return errors.New("sanitized clone relationship inventory unavailable")
	}
	type change struct{ name, mode string }
	var changes []change
	matched := make([]bool, len(table.ForeignKeys))
	for rows.Next() {
		var name, otherSchema, otherName string
		var columns, references []string
		var valid bool
		if err = rows.Scan(&name, &columns, &otherSchema, &otherName, &references, &valid); err != nil || !valid {
			rows.Close()
			return errors.New("sanitized clone relationship semantics changed")
		}
		found := false
		for i, fk := range table.ForeignKeys {
			var other privacy.Table
			for _, candidate := range schema.Tables {
				if candidate.ID == fk.Table {
					other = candidate
					break
				}
			}
			if matched[i] || other.Schema != otherSchema || other.Name != otherName || !slices.Equal(columns, columnNames(table, fk.Columns)) || !slices.Equal(references, columnNames(other, fk.References)) {
				continue
			}
			mode := "NOT DEFERRABLE INITIALLY IMMEDIATE"
			if fk.Deferrable {
				mode = "DEFERRABLE INITIALLY IMMEDIATE"
				if fk.InitiallyDeferred {
					mode = "DEFERRABLE INITIALLY DEFERRED"
				}
			}
			changes = append(changes, change{name, mode})
			matched[i], found = true, true
			break
		}
		if !found {
			rows.Close()
			return errors.New("sanitized clone relationship differs from the approved plan")
		}
	}
	rows.Close()
	if rows.Err() != nil || len(changes) != len(table.ForeignKeys) {
		return errors.New("sanitized clone is missing an approved relationship")
	}
	for _, change := range changes {
		if _, err = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ALTER CONSTRAINT %s %s", qualified(table), pgx.Identifier{change.name}.Sanitize(), change.mode)); err != nil {
			return errors.New("sanitized clone relationship restoration failed")
		}
	}
	return nil
}
