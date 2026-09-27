package logical

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/privacy"
)

func ptr(s string) *string { return &s }
func TestTargetTransactions(t *testing.T) {
	dsn := os.Getenv("PGWS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("run scripts/integration.py")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	database := "logical_" + strings.ReplaceAll(control.ID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()+" TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize())
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := privacy.Schema{Tables: []privacy.Table{
		{ID: 1, Schema: "public", Name: "people", Columns: []privacy.Column{{ID: 1, Name: "id", Type: "int8"}, {ID: 2, Name: "email", Type: "text"}, {ID: 3, Name: "bio", Type: "text"}}, PrimaryKey: []int16{1}, Unique: [][]int16{{2}}},
		{ID: 2, Schema: "public", Name: "orders", Columns: []privacy.Column{{ID: 1, Name: "id", Type: "int8"}, {ID: 2, Name: "person_id", Type: "int8"}}, PrimaryKey: []int16{1}, ForeignKeys: []privacy.ForeignKey{{Columns: []int16{2}, Table: 1, References: []int16{1}}}},
	}, Sequences: []privacy.Sequence{{Table: 1, Column: 1, Schema: "public", Name: "people_id_seq", Identity: "d", Start: 1, Increment: 1, Min: 1, Max: 9223372036854775807}}}
	p := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(s), KeyID: "test-v1", Rules: []privacy.Rule{{Table: 1, Column: 1, Action: "copy_original"}, {Table: 1, Column: 2, Action: "keyed_email", Domain: "email"}, {Table: 1, Column: 3, Action: "fixture", Fixture: ptr("Approved fixture")}, {Table: 2, Column: 1, Action: "copy_original"}, {Table: 2, Column: 2, Action: "copy_original"}}}
	plan, err := privacy.Compile(s, p, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Pool: pool, Plan: plan, Identity: Identity{Source: control.ID(), SystemID: "12345", Epoch: 1, Timeline: 1}}
	if err = target.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if target.Initialize(ctx) == nil {
		t.Fatal("adopted existing application target")
	}
	batch := Transaction{PreviousLSN: "0/0", EndLSN: "0/10", Changes: []Change{
		{Table: 2, Kind: "insert", Row: map[string]*string{"id": ptr("1"), "person_id": ptr("1")}},
		{Table: 1, Kind: "insert", Row: map[string]*string{"id": ptr("1"), "email": ptr("raw@example.org"), "bio": ptr("secret source narrative")}},
	}}
	t.Run("concurrent replay commits once", func(t *testing.T) {
		var group sync.WaitGroup
		replays := make(chan bool, 2)
		failures := make(chan error, 2)
		for i := 0; i < 2; i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				replayed, e := target.Apply(ctx, batch)
				replays <- replayed
				failures <- e
			}()
		}
		group.Wait()
		close(replays)
		close(failures)
		for e := range failures {
			if e != nil {
				t.Fatal(e)
			}
		}
		n := 0
		for replayed := range replays {
			if replayed {
				n++
			}
		}
		if n != 1 {
			t.Fatal("transaction was not applied exactly once", n)
		}
	})
	var email, bio string
	if err = pool.QueryRow(ctx, "SELECT email,bio FROM people WHERE id=1").Scan(&email, &bio); err != nil || email == "raw@example.org" || bio != "Approved fixture" {
		t.Fatal("untransformed data reached target", err)
	}
	check := func(count int, lsn string) {
		var high int64
		if e := pool.QueryRow(ctx, "SELECT high_water FROM _pgws_ingestion.sequence_watermarks WHERE source_table=1 AND source_column=1").Scan(&high); e != nil || high != 1 {
			t.Fatal("high water escaped transaction atomicity", high, e)
		}
		t.Helper()
		var n int
		var actual string
		if e := pool.QueryRow(ctx, "SELECT count(*) FROM people").Scan(&n); e != nil || n != count {
			t.Fatal("partial data", n, e)
		}
		if e := pool.QueryRow(ctx, "SELECT applied_lsn::text FROM _pgws_ingestion.checkpoint").Scan(&actual); e != nil || actual != lsn {
			t.Fatal("incorrect durable position", actual, e)
		}
	}
	t.Run("late FK error rolls back data and journal", func(t *testing.T) {
		bad := Transaction{PreviousLSN: "0/10", EndLSN: "0/20", Changes: []Change{{Table: 1, Kind: "insert", Row: map[string]*string{"id": ptr("2"), "email": ptr("second@example.org"), "bio": ptr("private")}}, {Table: 2, Kind: "insert", Row: map[string]*string{"id": ptr("2"), "person_id": ptr("999")}}}}
		if _, e := target.Apply(ctx, bad); e == nil {
			t.Fatal("broken foreign key committed")
		}
		check(1, "0/10")
	})
	t.Run("uniqueness failure never drops a row or advances", func(t *testing.T) {
		bad := Transaction{PreviousLSN: "0/10", EndLSN: "0/20", Changes: []Change{{Table: 1, Kind: "insert", Row: map[string]*string{"id": ptr("2"), "email": ptr("raw@example.org"), "bio": ptr("private")}}}}
		if _, e := target.Apply(ctx, bad); e == nil {
			t.Fatal("duplicate transformed key committed")
		}
		check(1, "0/10")
	})
	t.Run("changed replay and source identity are rejected", func(t *testing.T) {
		changed := batch
		changed.Changes = []Change{{Table: 1, Kind: "delete", OldKey: map[string]*string{"id": ptr("1")}}}
		if _, e := target.Apply(ctx, changed); e == nil {
			t.Fatal("conflicting replay accepted")
		}
		other := target
		other.Identity.Epoch++
		if _, e := other.Apply(ctx, batch); e == nil {
			t.Fatal("different source epoch accepted")
		}
		check(1, "0/10")
	})
	t.Run("unknown column and position gap block apply", func(t *testing.T) {
		bad := Transaction{PreviousLSN: "0/10", EndLSN: "0/20", Changes: []Change{{Table: 1, Kind: "update", OldKey: map[string]*string{"id": ptr("1")}, Row: map[string]*string{"new_secret": ptr("do not expose")}}}}
		if _, e := target.Apply(ctx, bad); e == nil || strings.Contains(e.Error(), "do not expose") {
			t.Fatal("unknown field accepted or leaked")
		}
		bad.Changes = nil
		bad.PreviousLSN = "0/11"
		if _, e := target.Apply(ctx, bad); e == nil {
			t.Fatal("missing source transaction skipped")
		}
		check(1, "0/10")
	})
	t.Run("partial update retains previously transformed values", func(t *testing.T) {
		update := Transaction{PreviousLSN: "0/10", EndLSN: "0/20", Changes: []Change{{Table: 1, Kind: "update", OldKey: map[string]*string{"id": ptr("1")}, Row: map[string]*string{"email": ptr("changed@example.org")}}}}
		if _, e := target.Apply(ctx, update); e != nil {
			t.Fatal(e)
		}
		var next string
		if e := pool.QueryRow(ctx, "SELECT email,bio FROM people WHERE id=1").Scan(&next, &bio); e != nil || next == email || bio != "Approved fixture" {
			t.Fatal("unchanged field was lost", e)
		}
		if replay, e := target.Apply(ctx, update); e != nil || !replay {
			t.Fatal("lost acknowledgement replay", e)
		}
		check(1, "0/20")
	})
	t.Run("related deletes are one source transaction", func(t *testing.T) {
		remove := Transaction{PreviousLSN: "0/20", EndLSN: "0/30", Changes: []Change{{Table: 1, Kind: "delete", OldKey: map[string]*string{"id": ptr("1")}}, {Table: 2, Kind: "delete", OldKey: map[string]*string{"id": ptr("1")}}}}
		if _, e := target.Apply(ctx, remove); e != nil {
			t.Fatal(e)
		}
		check(0, "0/30")
	})
}
