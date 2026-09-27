package logical

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"pgws/internal/privacy"
)

type SeedReceipt struct {
	LSN   string `json:"source_lsn"`
	Rows  int64  `json:"rows"`
	Bytes int64  `json:"source_bytes_processed"`
}

var snapshotName = regexp.MustCompile(`^[A-Fa-f0-9-]{1,100}$`)

// Seed streams an exported snapshot into one target transaction. This initial
// profile caps seed duration at five minutes, input at 64 MiB / 100,000 rows and
// transfer at 8 MiB/s. It never spools raw data. A failed seed must be discarded;
// it cannot be adopted as an eligible baseline even after an uncertain commit.
func (c Connector) Seed(parent context.Context) (receipt SeedReceipt, err error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	slot, publication, err := c.names()
	if err != nil {
		return receipt, err
	}
	owner, err := c.connect(ctx)
	if err != nil {
		return receipt, err
	}
	defer closeSource(owner)
	if err = AcquireSource(ctx, owner, slot); err != nil {
		return receipt, err
	}
	// Validate before creating source-side objects. Refuse an existing name;
	// ownership is never inferred merely from a matching naming convention.
	check, err := owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return receipt, errors.New("source catalog transaction unavailable")
	}
	err = c.checkSchema(ctx, check)
	_ = check.Rollback(ctx)
	if err != nil {
		return receipt, err
	}
	var names []string
	for _, table := range c.Target.Plan.Schema().Tables {
		names = append(names, qualified(table))
	}
	if _, err = owner.Exec(ctx, "CREATE PUBLICATION "+pgx.Identifier{publication}.Sanitize()+" FOR TABLE "+strings.Join(names, ",")); err != nil {
		return receipt, errors.New("source publication creation failed; existing names are not adopted")
	}
	var publicationOID uint32
	createdSlot := false
	defer func() {
		if err == nil {
			return
		}
		// Only objects successfully created by this invocation are cleaned up.
		// A lost CREATE response intentionally requires explicit reconciliation.
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		cleanup, e := c.connect(cleanupCtx)
		if e != nil {
			return
		}
		defer closeSource(cleanup)
		if createdSlot {
			_, _ = cleanup.Exec(cleanupCtx, "SELECT pg_drop_replication_slot($1)", slot)
		}
		_, _ = cleanup.Exec(cleanupCtx, "DROP PUBLICATION "+pgx.Identifier{publication}.Sanitize())
	}()
	if err = owner.QueryRow(ctx, "SELECT oid FROM pg_publication WHERE pubname=$1", publication).Scan(&publicationOID); err != nil || publicationOID == 0 {
		return receipt, errors.New("source publication identity was not confirmed")
	}
	// ACCESS SHARE prevents destructive table DDL while permitting ordinary
	// source writes. The operator's DDL freeze additionally covers new objects.
	freeze, err := owner.Begin(ctx)
	if err != nil {
		return receipt, errors.New("source DDL guard unavailable")
	}
	defer freeze.Rollback(context.Background())
	if _, err = freeze.Exec(ctx, "LOCK TABLE "+strings.Join(names, ",")+" IN ACCESS SHARE MODE"); err != nil {
		return receipt, errors.New("source DDL guard could not be acquired")
	}
	repl, err := c.replication(ctx)
	if err != nil {
		return receipt, err
	}
	defer repl.Close(context.Background())
	created, err := pglogrepl.CreateReplicationSlot(ctx, repl, slot, "pgoutput", pglogrepl.CreateReplicationSlotOptions{Mode: pglogrepl.LogicalReplication, SnapshotAction: "EXPORT_SNAPSHOT"})
	if err != nil {
		return receipt, errors.New("logical slot creation was not confirmed; reconcile before retry")
	}
	createdSlot = true
	if created.SlotName != slot || created.OutputPlugin != "pgoutput" || !snapshotName.MatchString(created.SnapshotName) {
		return receipt, errors.New("logical slot export identity differs")
	}
	if c.AfterSlotCreated != nil {
		contract, _ := c.Target.contract()
		owned := SlotOwnership{Format: "pgws.logical-slot.v1", Source: c.Target.Identity, Database: c.Source.Database, Slot: slot, Publication: publication, PublicationOID: publicationOID, Contract: contract, SeedLSN: created.ConsistentPoint, ObservedAt: time.Now().UTC()}
		if err = c.AfterSlotCreated(owned); err != nil {
			return receipt, errors.New("logical slot ownership receipt was not persisted")
		}
	}
	reader, err := c.connect(ctx)
	if err != nil {
		return receipt, err
	}
	defer closeSource(reader)
	read, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return receipt, errors.New("consistent source reader unavailable")
	}
	defer read.Rollback(context.Background())
	if _, err = read.Exec(ctx, "SET TRANSACTION SNAPSHOT '"+created.SnapshotName+"'"); err != nil {
		return receipt, errors.New("consistent source snapshot could not be imported")
	}
	if err = c.checkSchema(ctx, read); err != nil {
		return receipt, err
	}
	if err = c.checkPublication(ctx, owner, publication); err != nil {
		return receipt, err
	}
	// The exporter remains open and untouched until the reader finishes.
	receipt, err = c.seedTarget(ctx, read, created.ConsistentPoint, func() error {
		_, e := checkSlot(ctx, owner, slot)
		return e
	}, func() error { return c.checkSchema(ctx, freeze) })
	if err == nil {
		err = c.persistApplied(receipt.LSN)
	}
	return receipt, err
}

func (c Connector) seedTarget(ctx context.Context, source pgx.Tx, position string, health, finalCheck func() error) (receipt SeedReceipt, err error) {
	contract, _ := c.Target.contract()
	dst, err := c.Target.Pool.Begin(ctx)
	if err != nil {
		return receipt, errors.New("seed target unavailable")
	}
	defer dst.Rollback(context.Background())
	if _, err = dst.Exec(ctx, "SET LOCAL synchronous_commit=on; SET LOCAL search_path=pg_catalog; SET LOCAL session_replication_role=origin; SET CONSTRAINTS ALL DEFERRED"); err != nil {
		return receipt, errors.New("seed target session could not be isolated")
	}
	var actual string
	var unused bool
	if err = dst.QueryRow(ctx, `SELECT contract,applied_lsn='0/0' AND seed_lsn IS NULL AND NOT EXISTS(SELECT FROM _pgws_ingestion.transactions) FROM _pgws_ingestion.checkpoint WHERE singleton FOR UPDATE`).Scan(&actual, &unused); err != nil || actual != contract || !unused {
		return receipt, errors.New("seed requires a fresh target with the approved contract")
	}
	digest := sha256.New()
	started := time.Now()
	for _, table := range c.Target.Plan.Schema().Tables {
		var empty bool
		if _, err = dst.Exec(ctx, "LOCK TABLE "+qualified(table)+" IN ACCESS EXCLUSIVE MODE"); err != nil {
			return receipt, errors.New("seed target table could not be locked")
		}
		if err = dst.QueryRow(ctx, "SELECT NOT EXISTS(SELECT FROM "+qualified(table)+")").Scan(&empty); err != nil || !empty {
			return receipt, errors.New("seed target contains application rows")
		}
		if err = copyTable(ctx, source, dst, table, c.Target.Plan, &receipt, started, func(change Change) { b, _ := json.Marshal(change); digest.Write(b) }, health); err != nil {
			return receipt, err
		}
	}
	if err = health(); err != nil {
		return receipt, err
	}
	if err = finalCheck(); err != nil {
		return receipt, err
	}
	if _, err = dst.Exec(ctx, `INSERT INTO _pgws_ingestion.transactions(end_lsn,payload_hash) VALUES($1::pg_lsn,$2)`, position, fmt.Sprintf("seed:%x", digest.Sum(nil))); err != nil {
		return receipt, errors.New("seed journal write failed")
	}
	if _, err = dst.Exec(ctx, `UPDATE _pgws_ingestion.checkpoint SET applied_lsn=$1::pg_lsn,seed_lsn=$1::pg_lsn WHERE singleton`, position); err != nil {
		return receipt, errors.New("seed position write failed")
	}
	if err = dst.Commit(ctx); err != nil {
		return receipt, errors.New("seed commit was not confirmed; candidate remains ineligible")
	}
	receipt.LSN = position
	return receipt, nil
}

func copyTable(ctx context.Context, source, dst pgx.Tx, table privacy.Table, plan *privacy.Compiled, receipt *SeedReceipt, started time.Time, record func(Change), health func() error) error {
	sequences := plan.Schema().Sequences
	var values, lengths, limits []string
	for _, column := range table.Columns {
		value := pgx.Identifier{column.Name}.Sanitize() + "::text"
		if column.Type == "bool" {
			name := pgx.Identifier{column.Name}.Sanitize()
			value = "CASE WHEN " + name + " IS NULL THEN NULL WHEN " + name + " THEN 't' ELSE 'f' END"
		}
		length := "coalesce(octet_length(" + value + "),0)::bigint"
		values = append(values, value)
		lengths = append(lengths, length)
		limits = append(limits, length+"<=1048576")
	}
	q := "DECLARE pgws_seed NO SCROLL CURSOR FOR SELECT CASE WHEN (" + strings.Join(lengths, "+") + ")<=2097152 AND " + strings.Join(limits, " AND ") + " THEN ARRAY[" + strings.Join(values, ",") + "] ELSE NULL::text[] END FROM " + qualified(table) + " ORDER BY " + quoted(columnNames(table, table.PrimaryKey))
	if _, err := source.Exec(ctx, q); err != nil {
		return errors.New("bounded source seed cursor unavailable")
	}
	for {
		rows, err := source.Query(ctx, "FETCH 32 FROM pgws_seed")
		if err != nil {
			return errors.New("source seed read failed")
		}
		count := 0
		for rows.Next() {
			var fields []*string
			if err = rows.Scan(&fields); err != nil || len(fields) != len(table.Columns) {
				rows.Close()
				return errors.New("source seed row exceeds its encoding or memory budget")
			}
			count++
			receipt.Rows++
			row := map[string]*string{}
			for i, f := range fields {
				row[table.Columns[i].Name] = f
				if f != nil {
					receipt.Bytes += int64(len(*f))
				}
			}
			if receipt.Rows > 100000 || receipt.Bytes > 64<<20 {
				rows.Close()
				return errors.New("consistent seed exceeds its row or byte budget")
			}
			transformed, e := plan.Transform(table.ID, row)
			if e == nil {
				change := Change{Table: table.ID, Kind: "insert", Row: transformed}
				e = applyChange(ctx, dst, table, change)
				if e == nil {
					e = advanceSequences(ctx, dst, table, sequences, transformed)
				}
				record(change)
			}
			if e != nil {
				rows.Close()
				return e
			}
		}
		rows.Close()
		if rows.Err() != nil {
			return errors.New("source seed cursor interrupted")
		}
		if err = health(); err != nil {
			return err
		}
		if delay := time.Duration(receipt.Bytes*int64(time.Second)/(8<<20)) - time.Since(started); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return errors.New("consistent seed deadline exceeded")
			}
		}
		if count == 0 {
			break
		}
	}
	if _, err := source.Exec(ctx, "CLOSE pgws_seed"); err != nil {
		return errors.New("source seed cursor close failed")
	}
	return nil
}
