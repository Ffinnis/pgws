package logical

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/privacy"
)

func TestFrameRejectsUnboundedAllocations(t *testing.T) {
	for _, raw := range [][]byte{nil, {'I', 0, 0, 0, 1, 'N', 0, 1, 't', 255, 255, 255, 255}, {'R', 0, 0, 0, 1, 'a'}, {'T', 0, 0, 0, 1, 0, 0, 0, 0, 1}} {
		if validateFrame(raw) == nil {
			t.Fatal("accepted invalid or unsupported frame")
		}
	}
}
func FuzzFrameBounds(f *testing.F) {
	f.Add([]byte{'I', 0, 0, 0, 1, 'N', 0, 1, 't', 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) { _ = validateFrame(b) })
}

func TestPGOutputTransactions(t *testing.T) {
	if os.Getenv("PGWS_LOGICAL_LAB") != "1" {
		t.Skip("run scripts/physical_lab.py with PostgreSQL 18 logical decoding")
	}
	ctx := context.Background()
	dsn := os.Getenv("PGWS_TEST_DATABASE_URL")
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	open := func(prefix string) *pgxpool.Pool {
		t.Helper()
		name := prefix + strings.ReplaceAll(control.ID(), "-", "")
		if _, e := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Fatal(e)
		}
		cfg, e := pgxpool.ParseConfig(dsn)
		if e != nil {
			t.Fatal(e)
		}
		cfg.ConnConfig.Database = name
		pool, e := pgxpool.NewWithConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			pool.Close()
			cleanup, e := pgx.Connect(context.Background(), dsn)
			if e == nil {
				defer cleanup.Close(context.Background())
				_, _ = cleanup.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize())
			}
		})
		return pool
	}
	source, replica := open("src_"), open("dst_")
	if _, err = source.Exec(ctx, `CREATE TABLE public.people(id bigint PRIMARY KEY,email text UNIQUE,bio text NOT NULL);ALTER TABLE people ALTER COLUMN bio SET STORAGE EXTERNAL; CREATE PUBLICATION pgws_test FOR TABLE people`); err != nil {
		t.Fatal(err)
	}
	var oid uint32
	if err = source.QueryRow(ctx, "SELECT 'public.people'::regclass::oid").Scan(&oid); err != nil {
		t.Fatal(err)
	}
	schema := privacy.Schema{Tables: []privacy.Table{{ID: oid, Schema: "public", Name: "people", Columns: []privacy.Column{{ID: 1, Name: "id", Type: "int8"}, {ID: 2, Name: "email", Type: "text", Nullable: true}, {ID: 3, Name: "bio", Type: "text"}}, PrimaryKey: []int16{1}, Unique: [][]int16{{2}}}}}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "fixture-v1", Rules: []privacy.Rule{{Table: oid, Column: 1, Action: "copy_original"}, {Table: oid, Column: 2, Action: "keyed_email", Domain: "email"}, {Table: oid, Column: 3, Action: "fixture", Fixture: ptr("Approved fixture")}}}
	plan, err := privacy.Compile(schema, policy, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var system string
	if err = source.QueryRow(ctx, "SELECT (pg_control_system()).system_identifier::text").Scan(&system); err != nil {
		t.Fatal(err)
	}
	target := Target{Pool: replica, Plan: plan, Identity: Identity{Source: control.ID(), SystemID: system, Epoch: 1, Timeline: 1}}
	if err = target.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	slot := "pgws_test_" + strings.ReplaceAll(control.ID(), "-", "")
	var slotName, start string
	if err = source.QueryRow(ctx, "SELECT slot_name,lsn::text FROM pg_create_logical_replication_slot($1,'pgoutput')", slot).Scan(&slotName, &start); err != nil {
		t.Fatal(err)
	}
	defer source.Exec(ctx, "SELECT pg_drop_replication_slot($1)", slot)
	// This fixture has an empty source at slot creation. A populated source
	// requires the separate exported-snapshot seed path before this checkpoint.
	if _, err = target.Apply(ctx, Transaction{PreviousLSN: "0/0", EndLSN: start}); err != nil {
		t.Fatal(err)
	}
	drain := func(wantError bool) {
		t.Helper()
		var before string
		if e := source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&before); e != nil {
			t.Fatal(e)
		}
		d, e := NewDecoder(plan, before)
		if e != nil {
			t.Fatal(e)
		}
		rows, e := source.Query(ctx, `SELECT data FROM pg_logical_slot_peek_binary_changes($1,NULL,NULL,'proto_version','1','publication_names','pgws_test')`, slot)
		if e != nil {
			t.Fatal(e)
		}
		var transactions []Transaction
		var decodeErr error
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				t.Fatal(e)
			}
			batch, e := d.Decode(raw)
			if e != nil {
				decodeErr = e
				break
			}
			if batch != nil {
				transactions = append(transactions, *batch)
			}
		}
		rows.Close()
		if rows.Err() != nil {
			t.Fatal(rows.Err())
		}
		if wantError {
			if decodeErr == nil {
				t.Fatal("source DDL did not block decoder")
			}
			var after string
			source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&after)
			if after != before {
				t.Fatal("invalid schema was acknowledged")
			}
			return
		}
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if len(transactions) != 1 {
			t.Fatal("source transaction was split", len(transactions))
		}
		batch := transactions[0]
		if _, e = target.Apply(ctx, batch); e != nil {
			t.Fatal(e)
		}
		// Simulate an apply process restart before upstream acknowledgement.
		if replay, e := target.Apply(ctx, batch); e != nil || !replay {
			t.Fatal("committed source transaction cannot replay", e)
		}
		var observed string
		source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&observed)
		if observed != before {
			t.Fatal("peek acknowledged before target commit")
		}
		if e = source.QueryRow(ctx, "SELECT end_lsn::text FROM pg_replication_slot_advance($1,$2::pg_lsn)", slot, batch.EndLSN).Scan(&observed); e != nil || observed != batch.EndLSN {
			t.Fatal("source acknowledgement", observed, e)
		}
	}
	if _, err = source.Exec(ctx, `BEGIN;INSERT INTO people VALUES(1,'private@example.org',repeat('raw secret narrative',2000)),(2,'second@example.org','secret');COMMIT`); err != nil {
		t.Fatal(err)
	}
	drain(false)
	var count int
	var bio, email string
	if err = replica.QueryRow(ctx, "SELECT count(*) FROM people").Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	if _, err = source.Exec(ctx, `UPDATE people SET id=3,email='changed@example.org' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	drain(false)
	if err = replica.QueryRow(ctx, "SELECT email,bio FROM people WHERE id=3").Scan(&email, &bio); err != nil || email == "changed@example.org" || bio != "Approved fixture" {
		t.Fatal("TOAST/key update", err)
	}
	if _, err = source.Exec(ctx, `DELETE FROM people WHERE id=2`); err != nil {
		t.Fatal(err)
	}
	drain(false)
	if _, err = source.Exec(ctx, `ALTER TABLE people ADD COLUMN new_secret text;UPDATE people SET new_secret='never expose'`); err != nil {
		t.Fatal(err)
	}
	drain(true)
	if err = replica.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_name='people'").Scan(&count); err != nil || count != 3 {
		t.Fatal("unknown schema reached target", count, err)
	}
}
