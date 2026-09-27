// Package logical applies approved, transformed source transactions to a clean
// private target. Connector acknowledgement must follow successful Apply only.
package logical

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/privacy"
)

type Identity struct {
	Source     string `json:"source"`
	SystemID   string `json:"system_id"`
	Epoch      int64  `json:"epoch"`
	Timeline   int64  `json:"timeline"`
	Baseline   string `json:"baseline_id,omitempty"`
	Generation int64  `json:"baseline_generation,omitempty"`
}
type Change struct {
	Table  uint32             `json:"table"`
	Kind   string             `json:"kind"`
	Row    map[string]*string `json:"row,omitempty"`
	OldKey map[string]*string `json:"old_key,omitempty"`
}
type Transaction struct {
	PreviousLSN string   `json:"previous_lsn"`
	EndLSN      string   `json:"end_lsn"`
	Changes     []Change `json:"changes"`
}
type Target struct {
	Pool        *pgxpool.Pool
	Plan        *privacy.Compiled
	Identity    Identity
	MarkerTable uint32
}

func (t Target) contract() (string, error) {
	if t.Pool == nil || t.Plan == nil || !validBaselineIdentity(t.Identity) || !control.ValidID(t.Identity.Source) || t.Identity.SystemID == "" || t.Identity.Epoch < 1 || t.Identity.Timeline < 1 {
		return "", errors.New("invalid logical target identity")
	}
	for _, table := range t.Plan.Schema().Tables {
		if table.Schema == "_pgws_barriers" && t.MarkerTable == 0 {
			return "", errors.New("reserved marker schema requires an explicit marker contract")
		}
	}
	format := 2
	if t.MarkerTable != 0 {
		if _, err := t.markerTable(); err != nil {
			return "", err
		}
		format = 3
	}
	b, _ := json.Marshal(struct {
		Identity Identity
		Plan     string
		Format   int
		Marker   uint32 `json:",omitempty"`
	}{t.Identity, t.Plan.Hash(), format, t.MarkerTable})
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}
func qualified(t privacy.Table) string { return pgx.Identifier{t.Schema, t.Name}.Sanitize() }
func columnNames(t privacy.Table, ids []int16) []string {
	var result []string
	for _, id := range ids {
		for _, c := range t.Columns {
			if c.ID == id {
				result = append(result, c.Name)
				break
			}
		}
	}
	return result
}
func quoted(names []string) string {
	values := make([]string, len(names))
	for i, n := range names {
		values[i] = pgx.Identifier{n}.Sanitize()
	}
	return strings.Join(values, ",")
}

// Initialize refuses an existing application schema. It builds only approved
// scalar columns and declarative keys; no source SQL, defaults or code runs.
func (t Target) Initialize(ctx context.Context) error {
	contract, err := t.contract()
	if err != nil {
		return err
	}
	tx, err := t.Pool.Begin(ctx)
	if err != nil {
		return errors.New("logical target unavailable")
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on; SET LOCAL search_path=pg_catalog"); err != nil {
		return errors.New("logical initializer session could not be isolated")
	}
	var empty bool
	err = tx.QueryRow(ctx, `SELECT current_setting('server_encoding')='UTF8'
 AND EXISTS(SELECT FROM pg_database d WHERE datname=current_database() AND coalesce(to_jsonb(d)->>'datlocprovider','c')='c' AND datcollate IN ('C','C.UTF-8','C.utf8','POSIX') AND datctype IN ('C','C.UTF-8','C.utf8','POSIX'))
 AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema')
 AND NOT EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema')
 AND NOT EXISTS(SELECT FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema')
 AND NOT EXISTS(SELECT FROM pg_namespace WHERE nspname!~'^pg_' AND nspname NOT IN ('public','information_schema'))`).Scan(&empty)
	if err != nil || !empty {
		return errors.New("logical target must be an empty private database")
	}
	if _, err = tx.Exec(ctx, `CREATE SCHEMA _pgws_ingestion; REVOKE ALL ON SCHEMA _pgws_ingestion FROM PUBLIC;
 CREATE TABLE _pgws_ingestion.checkpoint(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),contract text NOT NULL,applied_lsn pg_lsn NOT NULL,seed_lsn pg_lsn);
 CREATE TABLE _pgws_ingestion.transactions(end_lsn pg_lsn PRIMARY KEY,payload_hash text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp());
 CREATE TABLE _pgws_ingestion.sequence_watermarks(source_table oid NOT NULL,source_column smallint NOT NULL,high_water bigint NOT NULL DEFAULT 0,PRIMARY KEY(source_table,source_column))`); err != nil {
		return errors.New("logical journal creation failed")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO _pgws_ingestion.checkpoint(contract,applied_lsn) VALUES($1,'0/0')`, contract); err != nil {
		return errors.New("logical journal initialization failed")
	}
	if t.MarkerTable != 0 {
		if _, err = tx.Exec(ctx, `CREATE TABLE _pgws_ingestion.barriers(id uuid PRIMARY KEY,end_lsn pg_lsn,expires_at bigint NOT NULL)`); err != nil {
			return errors.New("barrier journal initialization failed")
		}
	}
	schema := t.Plan.Schema()
	for _, seq := range schema.Sequences {
		if _, err = tx.Exec(ctx, `INSERT INTO _pgws_ingestion.sequence_watermarks(source_table,source_column) VALUES($1,$2)`, seq.Table, seq.Column); err != nil {
			return errors.New("identity high water initialization failed")
		}
	}
	schemas := map[string]bool{"public": true}
	tables := map[uint32]privacy.Table{}
	for _, table := range schema.Tables {
		if table.Schema == "_pgws_ingestion" {
			return errors.New("application policy uses the protected journal schema")
		}
		tables[table.ID] = table
		if !schemas[table.Schema] {
			if _, err = tx.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{table.Schema}.Sanitize()); err != nil {
				return errors.New("target schema creation failed")
			}
			schemas[table.Schema] = true
		}
		var definitions []string
		for _, c := range table.Columns {
			typeSQL := c.Type
			if c.Type == "varchar" && c.MaxChars > 0 {
				typeSQL = fmt.Sprintf("varchar(%d)", c.MaxChars)
			}
			column := pgx.Identifier{c.Name}.Sanitize() + " " + typeSQL
			if !c.Nullable {
				column += " NOT NULL"
			}
			definitions = append(definitions, column)
		}
		definitions = append(definitions, "PRIMARY KEY ("+quoted(columnNames(table, table.PrimaryKey))+")")
		for _, key := range table.Unique {
			definitions = append(definitions, "UNIQUE ("+quoted(columnNames(table, key))+")")
		}
		if _, err = tx.Exec(ctx, "CREATE TABLE "+qualified(table)+" ("+strings.Join(definitions, ",")+")"); err != nil {
			return errors.New("approved table creation failed")
		}
	}
	for _, table := range schema.Tables {
		for _, fk := range table.ForeignKeys {
			other := tables[fk.Table]
			initial := "IMMEDIATE"
			if fk.InitiallyDeferred {
				initial = "DEFERRED"
			}
			// The private writer needs deferrable checks across each complete
			// source transaction. Clone publication must restore the source's
			// exact deferrability from the immutable plan before user access.
			q := "ALTER TABLE " + qualified(table) + " ADD FOREIGN KEY (" + quoted(columnNames(table, fk.Columns)) + ") REFERENCES " + qualified(other) + " (" + quoted(columnNames(other, fk.References)) + ") DEFERRABLE INITIALLY " + initial
			if _, err = tx.Exec(ctx, q); err != nil {
				return errors.New("approved relationship creation failed")
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.New("logical initialization commit was not confirmed")
	}
	return nil
}

func (t Target) prepare(batch Transaction) (Transaction, map[uint32]privacy.Table, string, error) {
	previous, e := physical.ParseLSN(batch.PreviousLSN)
	if e != nil {
		return Transaction{}, nil, "", e
	}
	end, e := physical.ParseLSN(batch.EndLSN)
	if e != nil || end <= previous || len(batch.Changes) > 10000 {
		return Transaction{}, nil, "", errors.New("invalid logical transaction boundary or row budget")
	}
	tables := map[uint32]privacy.Table{}
	for _, table := range t.Plan.Schema().Tables {
		tables[table.ID] = table
	}
	out := Transaction{PreviousLSN: batch.PreviousLSN, EndLSN: batch.EndLSN}
	size := 0
	for _, change := range batch.Changes {
		for _, row := range []map[string]*string{change.Row, change.OldKey} {
			for name, value := range row {
				size += len(name)
				if value != nil {
					size += len(*value)
				}
			}
		}
		if size > 16<<20 {
			return Transaction{}, nil, "", errors.New("source transaction exceeds memory budget")
		}
		table, exists := tables[change.Table]
		if !exists {
			return Transaction{}, nil, "", errors.New("source relation is outside the approved plan")
		}
		c := Change{Table: change.Table, Kind: change.Kind}
		switch change.Kind {
		case "insert":
			if len(change.OldKey) != 0 {
				return Transaction{}, nil, "", errors.New("insert has an old identity")
			}
			c.Row, e = t.Plan.Transform(change.Table, change.Row)
		case "update", "delete":
			keys := columnNames(table, table.PrimaryKey)
			if len(change.OldKey) != len(keys) {
				return Transaction{}, nil, "", errors.New("change lacks a complete stable row identity")
			}
			for _, name := range keys {
				if change.OldKey[name] == nil {
					return Transaction{}, nil, "", errors.New("missing primary key value")
				}
			}
			c.OldKey, e = t.Plan.TransformPartial(change.Table, change.OldKey)
			if e == nil && change.Kind == "update" {
				if len(change.Row) == 0 {
					return Transaction{}, nil, "", errors.New("empty update")
				}
				c.Row, e = t.Plan.TransformPartial(change.Table, change.Row)
			}
			if change.Kind == "delete" && len(change.Row) != 0 {
				return Transaction{}, nil, "", errors.New("delete includes new fields")
			}
		default:
			return Transaction{}, nil, "", errors.New("unsupported logical change")
		}
		if e != nil {
			return Transaction{}, nil, "", e
		}
		out.Changes = append(out.Changes, c)
	}
	b, _ := json.Marshal(out)
	return out, tables, fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

// Apply returns true for an exact durable replay. A failed or uncertain commit
// must never be acknowledged upstream; replay resolves a lost acknowledgement.
func (t Target) Apply(ctx context.Context, batch Transaction) (bool, error) {
	contract, err := t.contract()
	if err != nil {
		return false, err
	}
	prepared, tables, hash, err := t.prepare(batch)
	if err != nil {
		return false, err
	}
	tx, err := t.Pool.Begin(ctx)
	if err != nil {
		return false, errors.New("logical target unavailable")
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on; SET LOCAL search_path=pg_catalog; SET LOCAL session_replication_role=origin; SET CONSTRAINTS ALL DEFERRED"); err != nil {
		return false, errors.New("logical apply session could not be isolated")
	}
	var actual, current string
	if err = tx.QueryRow(ctx, `SELECT contract,applied_lsn::text FROM _pgws_ingestion.checkpoint WHERE singleton FOR UPDATE`).Scan(&actual, &current); err != nil || actual != contract {
		return false, errors.New("target lineage or immutable policy differs")
	}
	var prior string
	err = tx.QueryRow(ctx, `SELECT payload_hash FROM _pgws_ingestion.transactions WHERE end_lsn=$1::pg_lsn`, batch.EndLSN).Scan(&prior)
	if err == nil {
		if prior != hash {
			return false, errors.New("replayed transaction has different transformed content")
		}
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, errors.New("logical replay journal unavailable")
	}
	currentLSN, _ := physical.ParseLSN(current)
	previousLSN, _ := physical.ParseLSN(batch.PreviousLSN)
	if currentLSN != previousLSN {
		return false, errors.New("source transaction gap or out-of-order apply")
	}
	sequences := t.Plan.Schema().Sequences
	for _, change := range prepared.Changes {
		if t.MarkerTable != 0 && change.Table == t.MarkerTable {
			if err = t.recordMarker(ctx, tx, change, batch.EndLSN); err != nil {
				return false, err
			}
		}
		if err = applyChange(ctx, tx, tables[change.Table], change); err != nil {
			return false, err
		}
		if err = advanceSequences(ctx, tx, tables[change.Table], sequences, change.Row); err != nil {
			return false, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO _pgws_ingestion.transactions(end_lsn,payload_hash) VALUES($1::pg_lsn,$2)`, batch.EndLSN, hash); err != nil {
		return false, errors.New("logical commit journal failed")
	}
	if _, err = tx.Exec(ctx, `UPDATE _pgws_ingestion.checkpoint SET applied_lsn=$1::pg_lsn WHERE singleton`, batch.EndLSN); err != nil {
		return false, errors.New("logical position update failed")
	}
	if err = tx.Commit(ctx); err != nil {
		return false, errors.New("logical transaction commit was not confirmed; retry without acknowledging")
	}
	return false, nil
}
func applyChange(ctx context.Context, tx pgx.Tx, table privacy.Table, change Change) error {
	var names, values, assignments, where []string
	var args []any
	for _, c := range table.Columns {
		value, exists := change.Row[c.Name]
		if !exists {
			continue
		}
		names = append(names, c.Name)
		args = append(args, value)
		parameter := fmt.Sprintf("$%d", len(args))
		values = append(values, parameter)
		assignments = append(assignments, pgx.Identifier{c.Name}.Sanitize()+"="+parameter)
	}
	for _, name := range columnNames(table, table.PrimaryKey) {
		if change.Kind == "insert" {
			break
		}
		args = append(args, change.OldKey[name])
		where = append(where, pgx.Identifier{name}.Sanitize()+fmt.Sprintf("=$%d", len(args)))
	}
	var q string
	switch change.Kind {
	case "insert":
		q = "INSERT INTO " + qualified(table) + " (" + quoted(names) + ") VALUES (" + strings.Join(values, ",") + ")"
	case "update":
		q = "UPDATE " + qualified(table) + " SET " + strings.Join(assignments, ",") + " WHERE " + strings.Join(where, " AND ")
	case "delete":
		q = "DELETE FROM " + qualified(table) + " WHERE " + strings.Join(where, " AND ")
	}
	result, err := tx.Exec(ctx, q, args...)
	if err != nil {
		return errors.New("sanitized change failed; transaction rolled back")
	}
	if result.RowsAffected() != 1 {
		return errors.New("sanitized change did not match exactly one row")
	}
	return nil
}
