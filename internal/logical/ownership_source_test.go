package logical

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgws/internal/control"
	"pgws/internal/privacy"
)

func TestLogicalOwnershipBeforeSeedRows(t *testing.T) {
	source, destination := logicalFixture(t)
	ctx := context.Background()
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
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "ownership-test", Rules: []privacy.Rule{{Table: schema.Tables[0].ID, Column: 1, Action: "copy_original"}}}
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
	connector := Connector{Source: source.Config().ConnConfig, Target: target}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ownership.json")
	called := false
	canary := errors.New("private callback canary")
	var callbackFailure error
	connector.AfterSlotCreated = func(receipt SlotOwnership) (failure error) {
		defer func() { callbackFailure = failure }()
		called = true
		if e := connector.MatchSlotOwnership(receipt); e != nil {
			return e
		}
		var exists, unseeded bool
		if e := source.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1 AND slot_type='logical' AND plugin='pgoutput' AND confirmed_flush_lsn=$2::pg_lsn)", receipt.Slot, receipt.SeedLSN).Scan(&exists); e != nil || !exists {
			return errors.New("receipt preceded actual slot creation")
		}
		if e := destination.QueryRow(ctx, "SELECT seed_lsn IS NULL AND applied_lsn='0/0' AND NOT EXISTS(SELECT FROM people) FROM _pgws_ingestion.checkpoint").Scan(&unseeded); e != nil || !unseeded {
			return errors.New("source rows were transferred before ownership persistence")
		}
		if e := WriteSlotOwnership(path, receipt); e != nil {
			return e
		}
		if status, e := InspectSlot(ctx, source.Config().ConnConfig, path); e != nil || status.Reason != "" || status.SeedCommitted || status.ProvenAppliedLSN != receipt.SeedLSN {
			return errors.New("monitor could not inspect uncommitted seed")
		}
		return canary
	}
	if _, err = connector.Seed(ctx); err == nil || strings.Contains(err.Error(), "canary") || !called || callbackFailure != canary {
		t.Fatal("seed ignored or echoed failed persistence callback", callbackFailure)
	}
	owned, err := ReadSlotOwnership(path)
	if err != nil {
		t.Fatal(err)
	}
	var remains bool
	if err = source.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1) OR EXISTS(SELECT FROM pg_publication WHERE pubname=$2)", owned.Slot, owned.Publication).Scan(&remains); err != nil || remains {
		t.Fatal("confirmed failed creation was not cleaned up", err)
	}
	if status, e := InspectSlot(ctx, source.Config().ConnConfig, path); e != nil || status.Reason != "SOURCE_SLOT_MISSING" {
		t.Fatal("monitor adopted a removed slot", e)
	}
	// The historical receipt remains for reconciliation. It is not a seed or
	// permission to adopt a later same-named source object.
	changed := owned
	changed.Source.Epoch++
	if connector.MatchSlotOwnership(changed) == nil {
		t.Fatal("ownership matched another generation")
	}
}
