package logical

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/privacy"
)

func TestMarkerContractRequiresUnchangedServiceMetadata(t *testing.T) {
	schema := privacy.Schema{Tables: []privacy.Table{{ID: 1, Schema: "_pgws_barriers", Name: "marker", Columns: []privacy.Column{{ID: 1, Name: "id", Type: "int8"}, {ID: 2, Name: "token", Type: "uuid"}, {ID: 3, Name: "expires_at", Type: "int8"}}, PrimaryKey: []int16{1}}}}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "marker-test", Rules: []privacy.Rule{{Table: 1, Column: 1, Action: "copy_original"}, {Table: 1, Column: 2, Action: "copy_original"}, {Table: 1, Column: 3, Action: "copy_original"}}}
	plan, err := privacy.Compile(schema, policy, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Pool: new(pgxpool.Pool), Plan: plan, Identity: Identity{Source: control.ID(), Epoch: 1, SystemID: "12345", Timeline: 1}, MarkerTable: 1}
	if _, err = target.contract(); err != nil {
		t.Fatal(err)
	}
	target.MarkerTable = 0
	if _, err = target.contract(); err == nil {
		t.Fatal("service marker could escape as ordinary application data")
	}
	target.MarkerTable = 2
	if _, err = target.contract(); err == nil {
		t.Fatal("wrong marker relation accepted")
	}
	target.MarkerTable = 1
	policy.Rules[1].Action, policy.Rules[1].Domain = "keyed_uuid", "marker"
	target.Plan, err = privacy.Compile(schema, policy, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = target.contract(); err == nil {
		t.Fatal("transformed marker identity accepted")
	}
}

func TestLogicalCommittedMarkers(t *testing.T) {
	source, destination := logicalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, err := source.Exec(ctx, `CREATE TABLE people(id bigint PRIMARY KEY,email text NOT NULL UNIQUE);
 INSERT INTO people VALUES(1,'private@example.org');
 CREATE SCHEMA _pgws_barriers; REVOKE ALL ON SCHEMA _pgws_barriers FROM PUBLIC;
 CREATE TABLE _pgws_barriers.marker(id bigint PRIMARY KEY,token uuid NOT NULL,expires_at bigint NOT NULL);
 INSERT INTO _pgws_barriers.marker VALUES(1,'00000000-0000-0000-0000-000000000000',0);
 REVOKE ALL ON _pgws_barriers.marker FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	read, err := source.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ReadCatalog(ctx, read)
	read.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "marker-fixture-v1"}
	var marker, people uint32
	for _, table := range schema.Tables {
		if table.Schema == "_pgws_barriers" {
			marker = table.ID
		} else {
			people = table.ID
		}
		for _, column := range table.Columns {
			rule := privacy.Rule{Table: table.ID, Column: column.ID, Action: "copy_original"}
			if column.Name == "email" {
				rule.Action, rule.Domain = "keyed_email", "email"
			}
			policy.Rules = append(policy.Rules, rule)
		}
	}
	plan, err := privacy.Compile(schema, policy, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{Source: control.ID(), Epoch: 1}
	if err = source.QueryRow(ctx, "SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id").Scan(&identity.SystemID, &identity.Timeline); err != nil {
		t.Fatal(err)
	}
	target := Target{Pool: destination, Plan: plan, Identity: identity, MarkerTable: marker}
	if err = target.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	connector := Connector{Source: source.Config().ConnConfig, Target: target}
	seed, err := connector.Seed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	role := "marker_" + strings.ReplaceAll(control.ID(), "-", "")
	if _, err = source.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN; GRANT USAGE ON SCHEMA _pgws_barriers TO "+pgx.Identifier{role}.Sanitize()+"; GRANT SELECT(id),UPDATE(token,expires_at) ON _pgws_barriers.marker TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		source.Exec(cleanup, "REVOKE ALL ON _pgws_barriers.marker FROM "+pgx.Identifier{role}.Sanitize())
		source.Exec(cleanup, "REVOKE ALL ON SCHEMA _pgws_barriers FROM "+pgx.Identifier{role}.Sanitize())
		source.Exec(cleanup, "DROP ROLE "+pgx.Identifier{role}.Sanitize())
	})
	writer := source.Config().ConnConfig.Copy()
	writer.User = role
	writer.Password = ""
	id, expiry := control.ID(), time.Now().Add(10*time.Minute).Truncate(time.Second)
	if _, err = connector.Barrier(ctx, connector.Source, id, expiry); err == nil {
		t.Fatal("privileged writer accepted")
	}
	short, stop := context.WithTimeout(ctx, 250*time.Millisecond)
	_, err = connector.Barrier(short, writer, id, expiry)
	stop()
	if err == nil {
		t.Fatal("source commit without target apply satisfied a barrier")
	}
	if _, err = target.markerBoundary(ctx, id, expiry); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("unapplied reservation has a source boundary", err)
	}
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- connector.Run(runCtx) }()
	t.Cleanup(func() {
		stopRun()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})
	boundary, err := connector.Barrier(ctx, writer, id, expiry)
	if err != nil {
		t.Fatal(err)
	}
	if boundary.ID != id || boundary.Source != identity || boundary.PlanHash != plan.Hash() || boundary.LSN == seed.LSN {
		t.Fatal("barrier did not bind the actual source commit")
	}
	replayed, err := target.Apply(ctx, Transaction{PreviousLSN: seed.LSN, EndLSN: boundary.LSN, Changes: []Change{{Table: marker, Kind: "update", OldKey: map[string]*string{"id": ptr("1")}, Row: map[string]*string{"id": ptr("1"), "token": ptr(id), "expires_at": ptr(strconv.FormatInt(expiry.Unix(), 10))}}}})
	if err != nil || !replayed {
		t.Fatal("lost acknowledgement replay changed marker boundary", err)
	}
	again, err := connector.Barrier(ctx, writer, id, expiry)
	if err != nil || again != boundary {
		t.Fatal("barrier replay moved its boundary", err)
	}
	if _, err = connector.Barrier(ctx, writer, id, expiry.Add(time.Second)); err == nil {
		t.Fatal("barrier identity reused with different expiry")
	}
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(2,'second-private@example.org')"); err != nil {
		t.Fatal(err)
	}
	next, err := connector.Barrier(ctx, writer, control.ID(), expiry)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = destination.QueryRow(ctx, "SELECT count(*) FROM people").Scan(&count); err != nil || count != 2 {
		t.Fatal("barrier omitted earlier committed data", err)
	}
	stopRun()
	select {
	case <-done:
		done <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not stop")
	}
	var applied string
	if err = destination.QueryRow(ctx, "SELECT applied_lsn::text FROM _pgws_ingestion.checkpoint").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	position, _ := pglogrepl.ParseLSN(applied)
	failedID := control.ID()
	if err = target.reserveMarker(ctx, failedID, expiry); err != nil {
		t.Fatal(err)
	}
	_, err = target.Apply(ctx, Transaction{PreviousLSN: applied, EndLSN: (position + 16).String(), Changes: []Change{
		{Table: marker, Kind: "update", OldKey: map[string]*string{"id": ptr("1")}, Row: map[string]*string{"id": ptr("1"), "token": ptr(failedID), "expires_at": ptr(strconv.FormatInt(expiry.Unix(), 10))}},
		{Table: people, Kind: "insert", Row: map[string]*string{"id": ptr("1"), "email": ptr("late-constraint@example.org")}},
	}})
	if err == nil {
		t.Fatal("late constraint accepted")
	}
	if _, err = target.markerBoundary(ctx, failedID, expiry); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("marker escaped failed transaction", err)
	}
	if _, err = destination.Exec(ctx, `INSERT INTO _pgws_ingestion.barriers(id,expires_at) SELECT md5(n::text)::uuid,$1 FROM generate_series(1,4096-(SELECT count(*)::int FROM _pgws_ingestion.barriers)) n`, expiry.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = connector.Barrier(ctx, writer, control.ID(), expiry); err == nil {
		t.Fatal("marker admission ignored receipt budget")
	}
	var sourceToken string
	if err = source.QueryRow(ctx, "SELECT token::text FROM _pgws_barriers.marker").Scan(&sourceToken); err != nil || sourceToken != next.ID {
		t.Fatal("budget failure mutated source", err)
	}
	if _, err = destination.Exec(ctx, "UPDATE _pgws_ingestion.barriers SET expires_at=$1 WHERE end_lsn IS NULL", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if err = target.reserveMarker(ctx, control.ID(), expiry); err != nil {
		t.Fatal("expired reservations were not collected", err)
	}
	proof, err := target.PrepareClone(ctx, next.LSN)
	if err != nil || proof.PlanHash != plan.Hash() {
		t.Fatal("marker clone detach failed", err)
	}
	var removed bool
	if err = destination.QueryRow(ctx, "SELECT to_regnamespace('_pgws_barriers') IS NULL AND to_regnamespace('_pgws_ingestion') IS NULL").Scan(&removed); err != nil || !removed {
		t.Fatal("service markers reached detached clone", err)
	}
}
