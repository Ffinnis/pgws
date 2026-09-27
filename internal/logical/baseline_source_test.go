package logical

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/control"
	"pgws/internal/privacy"
)

func TestParallelBaselineGenerations(t *testing.T) {
	source, first := logicalFixture(t)
	_, second := logicalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := source.Exec(ctx, "CREATE TABLE people(id bigint PRIMARY KEY,email text NOT NULL); INSERT INTO people VALUES(1,'private@example.org')"); err != nil {
		t.Fatal(err)
	}
	tx, err := source.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ReadCatalog(ctx, tx)
	tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{Source: control.ID(), Epoch: 1, Baseline: control.ID(), Generation: 1}
	if err = source.QueryRow(ctx, "SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id").Scan(&identity.SystemID, &identity.Timeline); err != nil {
		t.Fatal(err)
	}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "parallel", Rules: []privacy.Rule{{Table: schema.Tables[0].ID, Column: 1, Action: "copy_original"}, {Table: schema.Tables[0].ID, Column: 2, Action: "keyed_email", Domain: "emails"}}}
	plan, err := privacy.Compile(schema, policy, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherPlan, err := privacy.Compile(schema, policy, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	a := Connector{Source: source.Config().ConnConfig, Target: Target{Pool: first, Plan: plan, Identity: identity}}
	identity.Generation++
	b := Connector{Source: source.Config().ConnConfig, Target: Target{Pool: second, Plan: otherPlan, Identity: identity}}
	var ownedA, ownedB SlotOwnership
	a.AfterSlotCreated = func(r SlotOwnership) error { ownedA = r; return nil }
	b.AfterSlotCreated = func(r SlotOwnership) error { ownedB = r; return nil }
	for _, c := range []Connector{a, b} {
		if err = c.Target.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = c.Seed(ctx); err != nil {
			t.Fatal(err)
		}
		slot, pub, _ := c.names()
		defer source.Exec(context.Background(), "SELECT pg_drop_replication_slot($1)", slot)
		defer source.Exec(context.Background(), "DROP PUBLICATION "+pgx.Identifier{pub}.Sanitize())
	}
	if ownedA.Slot == ownedB.Slot || ownedA.Publication == ownedB.Publication || !ownedA.valid() || !ownedB.valid() {
		t.Fatal("parallel source ownership collided")
	}
	if err = b.MatchSlotOwnership(ownedA); err == nil {
		t.Fatal("new generation adopted old ownership")
	}
	wrong := a.Target
	wrong.Identity = b.Target.Identity
	if err = wrong.Initialize(ctx); err == nil {
		t.Fatal("existing target adopted another generation")
	}
	runA, stopA := context.WithCancel(ctx)
	defer stopA()
	runB, stopB := context.WithCancel(ctx)
	defer stopB()
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneA <- a.Run(runA) }()
	go func() { doneB <- b.Run(runB) }()
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(2,'another-private@example.org')"); err != nil {
		t.Fatal(err)
	}
	awaitLogical(t, ctx, func() bool {
		var x, y int
		return first.QueryRow(ctx, "SELECT count(*) FROM people").Scan(&x) == nil && second.QueryRow(ctx, "SELECT count(*) FROM people").Scan(&y) == nil && x == 2 && y == 2
	})
	var emailA, emailB string
	if err = first.QueryRow(ctx, "SELECT email FROM people WHERE id=2").Scan(&emailA); err != nil {
		t.Fatal(err)
	}
	if err = second.QueryRow(ctx, "SELECT email FROM people WHERE id=2").Scan(&emailB); err != nil || emailA == emailB {
		t.Fatal("independent policies did not transform independently", err)
	}
	stopA()
	if err = <-doneA; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = source.Exec(ctx, "SELECT pg_drop_replication_slot($1)", ownedA.Slot); err != nil {
		t.Fatal(err)
	}
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(3,'retained@example.org')"); err != nil {
		t.Fatal(err)
	}
	awaitLogical(t, ctx, func() bool {
		var n int
		return second.QueryRow(ctx, "SELECT count(*) FROM people").Scan(&n) == nil && n == 3
	})
	stopB()
	if err = <-doneB; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	t.Log("Two baseline generations at one source epoch seeded, transformed and streamed independently; retiring the old slot preserved its sibling")
}
