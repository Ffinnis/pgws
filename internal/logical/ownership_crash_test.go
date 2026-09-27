package logical

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/physical"
	"pgws/internal/privacy"
)

type ownershipCrashFixture struct {
	SourceDSN, TargetDSN, Receipt  string
	SourceDatabase, TargetDatabase string
	Identity                       Identity
	Schema                         privacy.Schema
	Policy                         privacy.Policy
	Boundary                       string
}

func TestLogicalOwnershipCrashChild(t *testing.T) {
	path := os.Getenv("PGWS_LOGICAL_OWNERSHIP_CHILD")
	if path == "" {
		t.Skip("child of the private ownership crash fixture")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("crash fixture unavailable")
	}
	var cfg ownershipCrashFixture
	if json.Unmarshal(data, &cfg) != nil {
		t.Fatal("crash fixture invalid")
	}
	ctx := context.Background()
	source, err := pgx.ParseConfig(cfg.SourceDSN)
	if err != nil {
		t.Fatal("fixture source unavailable")
	}
	source.Database = cfg.SourceDatabase
	targetConfig, err := pgxpool.ParseConfig(cfg.TargetDSN)
	if err != nil {
		t.Fatal("fixture target configuration unavailable")
	}
	targetConfig.ConnConfig.Database = cfg.TargetDatabase
	target, err := pgxpool.NewWithConfig(ctx, targetConfig)
	if err != nil {
		t.Fatal("fixture target unavailable")
	}
	defer target.Close()
	plan, err := privacy.Compile(cfg.Schema, cfg.Policy, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := Connector{Source: source, Target: Target{Pool: target, Plan: plan, Identity: cfg.Identity}}
	kill := func() error {
		if e := syscall.Kill(os.Getpid(), syscall.SIGKILL); e != nil {
			return e
		}
		select {}
	}
	c.AfterSlotCreated = func(receipt SlotOwnership) error {
		if cfg.Boundary == "unrecorded" {
			return kill()
		}
		if e := WriteSlotOwnership(cfg.Receipt, receipt); e != nil {
			return e
		}
		if cfg.Boundary == "created" {
			return kill()
		}
		return nil
	}
	var seeded bool
	c.AfterDurableApply = func(position string) error {
		if e := PersistApplied(cfg.Receipt, position); e != nil {
			return e
		}
		if cfg.Boundary == "applied" && seeded {
			owned, e := ReadSlotOwnership(cfg.Receipt)
			if e != nil {
				return e
			}
			next, _ := physical.ParseLSN(position)
			seed, _ := physical.ParseLSN(owned.SeedLSN)
			if next > seed {
				return kill()
			}
		}
		return nil
	}
	if _, err = c.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	seeded = true
	writer, err := pgx.ConnectConfig(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec(ctx, "INSERT INTO people VALUES(2)"); err != nil {
		t.Fatal(err)
	}
	writer.Close(ctx)
	if err = c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash fixture survived ownership boundary")
}

func TestLogicalOwnershipSurvivesSIGKILL(t *testing.T) {
	for _, boundary := range []string{"unrecorded", "created", "applied"} {
		t.Run(boundary, func(t *testing.T) { verifyOwnershipCrash(t, boundary) })
	}
}

func verifyOwnershipCrash(t *testing.T, boundary string) {
	source, destination := logicalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := source.Exec(ctx, "CREATE TABLE people(id bigint PRIMARY KEY);INSERT INTO people VALUES(1)"); err != nil {
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
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "ownership-crash", Rules: []privacy.Rule{{Table: schema.Tables[0].ID, Column: 1, Action: "copy_original"}}}
	plan, err := privacy.Compile(schema, policy, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{Source: control.ID(), Epoch: 1}
	if err = source.QueryRow(ctx, "SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id").Scan(&identity.SystemID, &identity.Timeline); err != nil {
		t.Fatal(err)
	}
	target := Target{Pool: destination, Plan: plan, Identity: identity}
	if err = target.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(dir, "slot.json")
	cfg := ownershipCrashFixture{SourceDSN: source.Config().ConnConfig.ConnString(), TargetDSN: destination.Config().ConnConfig.ConnString(), Receipt: receipt, Identity: identity, Schema: schema, Policy: policy}
	// ConnString retains the originally parsed DSN, before the fixture selects
	// its disposable databases. Preserve those selections across exec explicitly.
	cfg.SourceDatabase = source.Config().ConnConfig.Database
	cfg.TargetDatabase = destination.Config().ConnConfig.Database
	cfg.Boundary = boundary
	encoded, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "fixture.json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLogicalOwnershipCrashChild$", "-test.timeout=15s")
	child.Env = append(os.Environ(), "PGWS_LOGICAL_OWNERSHIP_CHILD="+path)
	output, err := child.CombinedOutput()
	exited, ok := err.(*exec.ExitError)
	if !ok || !exited.Sys().(syscall.WaitStatus).Signaled() || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child did not stop at real SIGKILL: %v %s", err, output)
	}
	if boundary == "unrecorded" {
		verifyUnrecordedSlot(t, ctx, source, target, receipt)
		return
	}
	owned, err := ReadSlotOwnership(receipt)
	if err != nil {
		t.Fatal(err)
	}
	connector := Connector{Source: source.Config().ConnConfig, Target: target}
	if err = connector.MatchSlotOwnership(owned); err != nil {
		t.Fatal(err)
	}
	defer source.Exec(context.Background(), "SELECT pg_drop_replication_slot($1)", owned.Slot)
	if status, e := InspectSlot(ctx, connector.Source, receipt); e != nil || status.Reason != "" || status.SeedCommitted != (boundary == "applied") {
		t.Fatal("independent monitor could not inspect killed connector", status, e)
	}
	if boundary == "applied" {
		progress, e := ReadApplied(receipt, owned)
		if e != nil {
			t.Fatal(e)
		}
		var actual, confirmed string
		var rows int
		if e = destination.QueryRow(ctx, "SELECT applied_lsn::text,(SELECT count(*) FROM people) FROM _pgws_ingestion.checkpoint").Scan(&actual, &rows); e != nil || actual != progress.AppliedLSN || rows != 2 {
			t.Fatal("external progress preceded target commit", e)
		}
		if e = source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", owned.Slot).Scan(&confirmed); e != nil || confirmed != owned.SeedLSN || confirmed == actual {
			t.Fatal("SIGKILL did not precede source ACK", e)
		}
		connector.AfterDurableApply = func(position string) error { return PersistApplied(receipt, position) }
		runCtx, stop := context.WithCancel(ctx)
		defer stop()
		done := make(chan error, 1)
		go func() { done <- connector.Run(runCtx) }()
		awaitLogical(t, ctx, func() bool {
			select {
			case e := <-done:
				t.Fatal("restart failed", e)
			default:
			}
			return source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1", owned.Slot).Scan(&confirmed) == nil && confirmed == actual
		})
		stop()
		if e = <-done; !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
		if e = destination.QueryRow(ctx, "SELECT count(*) FROM people").Scan(&rows); e != nil || rows != 2 {
			t.Fatal("crash replay duplicated data", e)
		}
		return
	}
	var unseeded, present bool
	if err = destination.QueryRow(ctx, "SELECT seed_lsn IS NULL AND applied_lsn='0/0' AND NOT EXISTS(SELECT FROM people) FROM _pgws_ingestion.checkpoint").Scan(&unseeded); err != nil || !unseeded {
		t.Fatal("crashed seed was adopted as completed", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err = source.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1 AND slot_type='logical' AND plugin='pgoutput' AND NOT active AND confirmed_flush_lsn=$2::pg_lsn)", owned.Slot, owned.SeedLSN).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned slot did not remain available for reconciliation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err = connector.Seed(ctx); err == nil {
		t.Fatal("a new seed adopted the crashed generation's existing source objects")
	}
	var retained bool
	if err = source.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1)", owned.Slot).Scan(&retained); err != nil || !retained {
		t.Fatal("rejected retry removed a preexisting slot", err)
	}
	verifyMonitorFaults(t, ctx, source, receipt, owned)
}

func verifyUnrecordedSlot(t *testing.T, ctx context.Context, source *pgxpool.Pool, target Target, receipt string) {
	t.Helper()
	connector := Connector{Source: source.Config().ConnConfig, Target: target}
	slot, publication, err := connector.names()
	if err != nil {
		t.Fatal(err)
	}
	// Only this disposable fixture owns the pre-arranged source. Production
	// retirement cannot infer ownership from these deterministic names.
	defer source.Exec(context.Background(), "SELECT pg_drop_replication_slot($1)", slot)
	for _, suffix := range []string{"", ".applied"} {
		if _, err = os.Lstat(receipt + suffix); !os.IsNotExist(err) {
			t.Fatal("crash unexpectedly published external ownership or progress", err)
		}
	}
	if _, err = InspectSlot(ctx, connector.Source, receipt); err == nil {
		t.Fatal("monitor accepted an unrecorded slot")
	}
	var publicationOID uint32
	if err = source.QueryRow(ctx, "SELECT oid FROM pg_publication WHERE pubname=$1", publication).Scan(&publicationOID); err != nil {
		t.Fatal("crash did not leave the confirmed source publication", err)
	}
	var confirmed string
	awaitLogical(t, ctx, func() bool {
		return source.QueryRow(ctx, "SELECT confirmed_flush_lsn::text FROM pg_replication_slots WHERE slot_name=$1 AND NOT active", slot).Scan(&confirmed) == nil
	})
	if _, err = connector.Seed(ctx); err == nil {
		t.Fatal("retry adopted source objects without an ownership receipt")
	}
	if err = connector.Run(ctx); err == nil {
		t.Fatal("uncommitted seed started streaming")
	}
	var unchanged bool
	if err = source.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1 AND confirmed_flush_lsn=$2::pg_lsn)
 AND EXISTS(SELECT FROM pg_publication WHERE pubname=$3 AND oid=$4)`, slot, confirmed, publication, publicationOID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("rejected retry modified unconfirmed source objects", err)
	}
	var empty bool
	if err = target.Pool.QueryRow(ctx, "SELECT seed_lsn IS NULL AND applied_lsn='0/0' AND NOT EXISTS(SELECT FROM people) FROM _pgws_ingestion.checkpoint").Scan(&empty); err != nil || !empty {
		t.Fatal("unrecorded seed made target data eligible", err)
	}
}
