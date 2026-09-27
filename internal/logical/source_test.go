package logical

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/privacy"
)

func logicalFixture(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	if os.Getenv("PGWS_LOGICAL_LAB") != "1" {
		t.Skip("requires the disposable PostgreSQL 18 logical lab")
	}
	ctx := context.Background()
	dsn := os.Getenv("PGWS_TEST_DATABASE_URL")
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	open := func(prefix string) *pgxpool.Pool {
		name := prefix + strings.ReplaceAll(control.ID(), "-", "")
		if _, e := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"); e != nil {
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
				_, _ = cleanup.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
			}
		})
		return pool
	}
	return open("src_"), open("dst_")
}

func TestConsistentSeedAndStream(t *testing.T) {
	source, replica := logicalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := source.Exec(ctx, `CREATE TABLE people(id bigint PRIMARY KEY,email text NOT NULL UNIQUE,bio text NOT NULL);
 CREATE TABLE orders(id bigint PRIMARY KEY,person bigint NOT NULL REFERENCES people(id),paid boolean NOT NULL);
 INSERT INTO people SELECT n,'private-'||n||'@example.org',repeat('raw private narrative',1000) FROM generate_series(1,100) n;
 INSERT INTO orders VALUES(1,1,true);`)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := source.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ReadCatalog(ctx, discovery)
	discovery.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "seed-test-v1"}
	var people uint32
	for _, table := range schema.Tables {
		if table.Name == "people" {
			people = table.ID
		}
		for _, col := range table.Columns {
			rule := privacy.Rule{Table: table.ID, Column: col.ID, Action: "copy_original"}
			switch col.Name {
			case "email":
				rule.Action, rule.Domain = "keyed_email", "email"
			case "bio":
				rule.Action, rule.Fixture = "fixture", ptr("Approved fixture")
			}
			policy.Rules = append(policy.Rules, rule)
		}
	}
	plan, err := privacy.Compile(schema, policy, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var system string
	var timeline int64
	source.QueryRow(ctx, "SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id").Scan(&system, &timeline)
	target := Target{Pool: replica, Plan: plan, Identity: Identity{Source: control.ID(), SystemID: system, Epoch: 1, Timeline: timeline}}
	if err = target.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	connector := Connector{Source: source.Config().ConnConfig, Target: target}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownershipPath := filepath.Join(dir, "slot.json")
	connector.AfterSlotCreated = func(owned SlotOwnership) error { return WriteSlotOwnership(ownershipPath, owned) }
	connector.AfterDurableApply = func(position string) error { return PersistApplied(ownershipPath, position) }
	slot, publication, _ := connector.names()
	t.Cleanup(func() {
		source.Exec(context.Background(), "SELECT pg_drop_replication_slot($1)", slot)
		source.Exec(context.Background(), "DROP PUBLICATION IF EXISTS "+pgx.Identifier{publication}.Sanitize())
	})
	locker, err := replica.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback(context.Background())
	// A row lock assigns an XID and can block logical snapshot creation in the
	// same test cluster. This relation lock delays only the target seed write.
	if _, err = locker.Exec(ctx, "LOCK TABLE _pgws_ingestion.checkpoint IN EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	type seedResult struct {
		receipt SeedReceipt
		err     error
	}
	seedDone := make(chan seedResult, 1)
	go func() { receipt, e := connector.Seed(ctx); seedDone <- seedResult{receipt, e} }()
	diagnoseAt := time.Now().Add(3 * time.Second)
	awaitLogical(t, ctx, func() bool {
		select {
		case result := <-seedDone:
			t.Fatal("seed ended before its held target lock", result.err)
		default:
		}
		var waiting bool
		_ = source.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE '%seed_lsn%')`, replica.Config().ConnConfig.Database).Scan(&waiting)
		if !waiting && time.Now().After(diagnoseAt) {
			var activity string
			_ = source.QueryRow(ctx, `SELECT coalesce(json_agg(json_build_object('pid',pid,'xid',backend_xid,'blockers',pg_blocking_pids(pid),'db',datname,'wait_type',wait_event_type,'wait',wait_event,'query',left(query,100)))::text,'[]') FROM pg_stat_activity WHERE datname IN ($1,$2)`, source.Config().ConnConfig.Database, replica.Config().ConnConfig.Database).Scan(&activity)
			t.Log("seed fixture wait:", activity)
			diagnoseAt = time.Now().Add(time.Hour)
		}
		return waiting
	})
	if _, err = source.Exec(ctx, `BEGIN;UPDATE people SET email='after-snapshot@example.org' WHERE id=1;DELETE FROM people WHERE id=2;INSERT INTO people VALUES(101,'new-after-snapshot@example.org','raw new secret');COMMIT`); err != nil {
		t.Fatal(err)
	}
	if err = locker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-seedDone
	if result.err != nil || result.receipt.Rows != 101 || result.receipt.LSN == "" {
		t.Fatal("consistent seed", result.receipt, result.err)
	}
	var count int
	var email, bio string
	if err = replica.QueryRow(ctx, "SELECT count(*) FROM people WHERE id=2").Scan(&count); err != nil || count != 1 {
		t.Fatal("seed did not retain its original snapshot", err)
	}
	if err = replica.QueryRow(ctx, "SELECT email,bio FROM people WHERE id=1").Scan(&email, &bio); err != nil || email == "private-1@example.org" || bio != "Approved fixture" {
		t.Fatal("raw seed value reached the target", err)
	}
	runCtx, stop := context.WithCancel(ctx)
	runDone := make(chan error, 1)
	go func() { runDone <- connector.Run(runCtx) }()
	defer stop()
	awaitLogical(t, ctx, func() bool {
		select {
		case e := <-runDone:
			t.Fatal("stream ended", e)
		default:
		}
		return replica.QueryRow(ctx, "SELECT count(*) FROM people WHERE id=101").Scan(&count) == nil && count == 1
	})
	var applied, confirmed string
	awaitLogical(t, ctx, func() bool {
		replica.QueryRow(ctx, "SELECT applied_lsn::text FROM _pgws_ingestion.checkpoint").Scan(&applied)
		source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&confirmed)
		return applied == confirmed
	})
	stop()
	if e := <-runDone; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if err = replica.QueryRow(ctx, "SELECT count(*) FROM people WHERE id=2").Scan(&count); err != nil || count != 0 {
		t.Fatal("CDC deletion lost", err)
	}
	newEmail, _ := plan.TransformPartial(people, map[string]*string{"email": ptr("after-snapshot@example.org")})
	if err = replica.QueryRow(ctx, "SELECT email,bio FROM people WHERE id=1").Scan(&email, &bio); err != nil || email != *newEmail["email"] || bio != "Approved fixture" {
		t.Fatal("CDC update lost or raw", err)
	}
	var paid bool
	if err = replica.QueryRow(ctx, "SELECT paid FROM orders WHERE id=1").Scan(&paid); err != nil || !paid {
		t.Fatal("seed boolean encoding differs from pgoutput", err)
	}
	// Break the replication socket precisely when it sends the first ACK beyond
	// the already confirmed boundary, after the new target transaction committed.
	beforeAck, _ := physical.ParseLSN(confirmed)
	lost := connector
	lost.Source = connector.Source.Copy()
	dial := lost.Source.DialFunc
	lost.Source.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, e := dial(ctx, network, address)
		if e != nil {
			return nil, e
		}
		return &lostAckConn{Conn: conn, after: beforeAck}, nil
	}
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(201,'lost-ack@example.org','raw')"); err != nil {
		t.Fatal(err)
	}
	if err = lost.Run(ctx); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
		t.Fatal("lost ACK did not interrupt ingestion", err)
	}
	if err = replica.QueryRow(ctx, "SELECT count(*) FROM people WHERE id=201").Scan(&count); err != nil || count != 1 {
		t.Fatal("lost ACK happened before durable apply", err)
	}
	var notAcknowledged string
	source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&notAcknowledged)
	if notAcknowledged != confirmed {
		t.Fatal("dropped ACK advanced the source")
	}
	runCtx, stop = context.WithCancel(ctx)
	defer stop()
	go func() { runDone <- connector.Run(runCtx) }()
	awaitLogical(t, ctx, func() bool {
		select {
		case e := <-runDone:
			t.Fatal("durable replay failed", e)
		default:
		}
		replica.QueryRow(ctx, "SELECT applied_lsn::text FROM _pgws_ingestion.checkpoint").Scan(&applied)
		source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&confirmed)
		return applied == confirmed && confirmed != notAcknowledged
	})
	stop()
	if e := <-runDone; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	// Fail external progress persistence after a real target commit. Source ACK
	// must remain behind and the private callback error must not escape.
	owned, err := ReadSlotOwnership(ownershipPath)
	if err != nil {
		t.Fatal(err)
	}
	priorProgress, err := ReadApplied(ownershipPath, owned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(202,'progress-failure@example.org','raw')"); err != nil {
		t.Fatal(err)
	}
	blocked := connector
	startPosition, _ := physical.ParseLSN(confirmed)
	blocked.AfterDurableApply = func(position string) error {
		next, _ := physical.ParseLSN(position)
		if next > startPosition {
			return errors.New("private persistence canary")
		}
		return PersistApplied(ownershipPath, position)
	}
	if err = blocked.Run(ctx); err == nil || !strings.Contains(err.Error(), "receipt") || strings.Contains(err.Error(), "canary") {
		t.Fatal("receipt failure did not stop before ACK", err)
	}
	if err = replica.QueryRow(ctx, "SELECT count(*) FROM people WHERE id=202").Scan(&count); err != nil || count != 1 {
		t.Fatal("failure did not follow committed data", err)
	}
	if err = source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&notAcknowledged); err != nil || notAcknowledged != confirmed {
		t.Fatal("failed receipt advanced ACK", err)
	}
	if progress, e := ReadApplied(ownershipPath, owned); e != nil || progress != priorProgress {
		t.Fatal("failed receipt changed external proof", e)
	}
	runCtx, stop = context.WithCancel(ctx)
	defer stop()
	go func() { runDone <- connector.Run(runCtx) }()
	awaitLogical(t, ctx, func() bool {
		select {
		case e := <-runDone:
			t.Fatal("progress recovery ended", e)
		default:
		}
		replica.QueryRow(ctx, "SELECT applied_lsn::text FROM _pgws_ingestion.checkpoint").Scan(&applied)
		source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&confirmed)
		return applied == confirmed && confirmed != notAcknowledged
	})
	stop()
	if e := <-runDone; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if progress, e := ReadApplied(ownershipPath, owned); e != nil || progress.AppliedLSN != confirmed {
		t.Fatal("ACK exceeded external committed proof", e)
	}
	// Inject a target uniqueness conflict. The source change must stay unacked,
	// and removing the obstruction must allow exact resume without dropping it.
	conflict, _ := plan.TransformPartial(people, map[string]*string{"email": ptr("conflict@example.org")})
	if _, err = replica.Exec(ctx, "INSERT INTO people VALUES(9999,$1,'Approved fixture')", *conflict["email"]); err != nil {
		t.Fatal(err)
	}
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(102,'conflict@example.org','raw')"); err != nil {
		t.Fatal(err)
	}
	if err = connector.Run(ctx); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatal("target constraint did not stop the stream", err)
	}
	var after string
	source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", slot).Scan(&after)
	if after != confirmed {
		t.Fatal("failed target transaction was acknowledged")
	}
	replica.Exec(ctx, "DELETE FROM people WHERE id=9999")
	runCtx, stop = context.WithCancel(ctx)
	defer stop()
	go func() { runDone <- connector.Run(runCtx) }()
	awaitLogical(t, ctx, func() bool {
		select {
		case e := <-runDone:
			t.Fatal("resume ended", e)
		default:
		}
		return replica.QueryRow(ctx, "SELECT count(*) FROM people WHERE id=102").Scan(&count) == nil && count == 1
	})
	// A new field stops ingestion even without a row change to trigger Relation.
	if _, err = source.Exec(ctx, "ALTER TABLE people ADD COLUMN unreviewed_secret text"); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-runDone:
		if e == nil || !strings.Contains(e.Error(), "approved") {
			t.Fatal("idle schema drift did not stop streaming", e)
		}
	case <-ctx.Done():
		t.Fatal("schema drift detection timed out")
	}
	if err = replica.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_name='people'").Scan(&count); err != nil || count != 3 {
		t.Fatal("unknown column reached the private target", err)
	}
	verifyPrivateClone(t, ctx, target, source, confirmed)
}

func verifyPrivateClone(t *testing.T, ctx context.Context, target Target, source *pgxpool.Pool, confirmed string) {
	t.Helper()
	// Database copy tests SQL detachment. Writer crash recovery from an actual
	// ZFS snapshot remains a separate host acceptance gate.
	replicaConfig := target.Pool.Config()
	target.Pool.Close()
	cloneName := "clone_" + strings.ReplaceAll(control.ID(), "-", "")
	if _, err := source.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{cloneName}.Sanitize()+" TEMPLATE "+pgx.Identifier{replicaConfig.ConnConfig.Database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cloneConfig := replicaConfig.Copy()
	cloneConfig.ConnConfig.Database = cloneName
	clonePool, err := pgxpool.NewWithConfig(ctx, cloneConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		clonePool.Close()
		source.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{cloneName}.Sanitize()+" WITH (FORCE)")
	}()
	cloneTarget := target
	cloneTarget.Pool = clonePool
	wrong := cloneTarget
	wrong.Identity.Epoch++
	if _, err = wrong.PrepareClone(ctx, confirmed); err == nil {
		t.Fatal("clone with changed lineage was accepted")
	}
	if _, err = cloneTarget.PrepareClone(ctx, "FFFFFFFF/FFFFFFFF"); err == nil {
		t.Fatal("clone below the required source position was accepted")
	}
	if _, err = clonePool.Exec(ctx, "ALTER TABLE people ALTER COLUMN email DROP NOT NULL"); err != nil {
		t.Fatal(err)
	}
	if _, err = cloneTarget.PrepareClone(ctx, confirmed); err == nil {
		t.Fatal("clone with altered schema was accepted")
	}
	if _, err = clonePool.Exec(ctx, "ALTER TABLE people ALTER COLUMN email SET NOT NULL"); err != nil {
		t.Fatal(err)
	}
	proof, err := cloneTarget.PrepareClone(ctx, confirmed)
	if err != nil || proof.Source != target.Identity || proof.PlanHash != target.Plan.Hash() || proof.TargetSystemID == "" {
		t.Fatal("private clone detach", err)
	}
	var clean, sourceSemantics bool
	err = clonePool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM pg_namespace WHERE nspname='_pgws_ingestion'), NOT condeferrable AND NOT condeferred FROM pg_constraint WHERE conrelid='orders'::regclass AND contype='f'`).Scan(&clean, &sourceSemantics)
	if err != nil || !clean || !sourceSemantics {
		t.Fatal("ingestion metadata or altered relationship semantics survived detach", err)
	}
	if _, err = clonePool.Exec(ctx, "UPDATE people SET email='independent@example.invalid' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	original, err := pgx.ConnectConfig(ctx, replicaConfig.ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close(context.Background())
	var email string
	if err = original.QueryRow(ctx, "SELECT email FROM people WHERE id=1").Scan(&email); err != nil || email == "independent@example.invalid" {
		t.Fatal("clone write affected the baseline", err)
	}
}

type lostAckConn struct {
	net.Conn
	after uint64
}

func (c *lostAckConn) Write(b []byte) (int, error) {
	if len(b) == 39 && b[0] == 'd' && b[5] == 'r' && binary.BigEndian.Uint64(b[14:22]) > c.after {
		_ = c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}

func awaitLogical(t *testing.T, ctx context.Context, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !predicate() {
		select {
		case <-ctx.Done():
			t.Fatal("logical fixture deadline exceeded")
		case <-deadline.C:
			t.Fatal("logical fixture condition timed out")
		case <-tick.C:
		}
	}
}

func TestLogicalCatalogRejectsUnsupportedObjects(t *testing.T) {
	source, _ := logicalFixture(t)
	ctx := context.Background()
	if _, err := source.Exec(ctx, "CREATE TABLE people(id bigint PRIMARY KEY,email text)"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unlogged":                "CREATE UNLOGGED TABLE extra(id bigint PRIMARY KEY)",
		"sequence":                "CREATE SEQUENCE source_ids",
		"modified serial default": "ALTER TABLE people ADD COLUMN serial_id bigserial; ALTER TABLE people ALTER COLUMN serial_id SET DEFAULT nextval('people_serial_id_seq')+1",
		"shared serial":           "ALTER TABLE people ADD COLUMN serial_id bigserial; ALTER TABLE people ADD COLUMN shared bigint DEFAULT nextval('people_serial_id_seq')",
		"unowned serial":          "ALTER TABLE people ADD COLUMN serial_id bigserial; ALTER SEQUENCE people_serial_id_seq OWNED BY NONE",
		"cycling identity":        "ALTER TABLE people ADD COLUMN generated_id bigint GENERATED ALWAYS AS IDENTITY (CYCLE)",
		"descending identity":     "ALTER TABLE people ADD COLUMN generated_id bigint GENERATED ALWAYS AS IDENTITY (INCREMENT -1)",
		"check":                   "ALTER TABLE people ADD CHECK(id>0)",
		"generated":               "ALTER TABLE people ADD COLUMN derived bigint GENERATED ALWAYS AS(id+1) STORED",
		"defaults":                "ALTER TABLE people ALTER COLUMN email SET DEFAULT 'embedded secret'",
		"dropped column":          "ALTER TABLE people DROP COLUMN email",
		"partial unique":          "CREATE UNIQUE INDEX partial_key ON people(email) WHERE email IS NOT NULL",
		"nulls not distinct":      "ALTER TABLE people ADD UNIQUE NULLS NOT DISTINCT(email)",
		"replica identity":        "ALTER TABLE people REPLICA IDENTITY FULL",
		"row policies":            "ALTER TABLE people ENABLE ROW LEVEL SECURITY",
		"large object":            "SELECT lo_create(0)",
	}
	for name, ddl := range cases {
		t.Run(name, func(t *testing.T) {
			tx, err := source.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, ddl); err != nil {
				t.Fatal(err)
			}
			if _, err = ReadCatalog(ctx, tx); err == nil {
				t.Fatal("unsupported source was accepted")
			}
		})
	}
}
