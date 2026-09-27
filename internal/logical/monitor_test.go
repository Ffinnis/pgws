package logical

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Runs after an actual seed-process SIGKILL, with an inactive persistent slot
// and no committed target seed. Every mutation is confined to that fixture.
func verifyMonitorFaults(t *testing.T, ctx context.Context, source *pgxpool.Pool, path string, owned SlotOwnership) {
	t.Helper()
	wantReason := func(receipt, want string) SlotObservation {
		t.Helper()
		status, err := InspectSlot(ctx, source.Config().ConnConfig, receipt)
		if err != nil || status.Reason != want {
			t.Fatalf("monitor reason = %q, want %q: %v", status.Reason, want, err)
		}
		return status
	}
	wrong := owned
	wrong.Source.SystemID = "1"
	wrongPath := filepath.Join(filepath.Dir(path), "foreign.json")
	if err := WriteSlotOwnership(wrongPath, wrong); err != nil {
		t.Fatal(err)
	}
	wantReason(wrongPath, "SOURCE_LINEAGE_CHANGED")
	wrongSource := source.Config().ConnConfig.Copy()
	wrongSource.Database = "postgres"
	if _, err := InspectSlot(ctx, wrongSource, path); err == nil {
		t.Fatal("monitor accepted another database")
	}
	// WAL messages avoid adding a large application relation or transferring raw
	// values. The slot is not consumed, so its retained WAL crosses the real cap.
	if _, err := source.Exec(ctx, "SELECT pg_logical_emit_message(false,'pgws-monitor-budget',repeat('x',1048576)) FROM generate_series(1,66)"); err != nil {
		t.Fatal(err)
	}
	if status := wantReason(path, "SOURCE_WAL_BUDGET"); status.RetainedBytes < 64<<20 {
		t.Fatal("monitor did not measure actual retained WAL")
	}
	if _, err := source.Exec(ctx, "SELECT pg_drop_replication_slot($1)", owned.Slot); err != nil {
		t.Fatal(err)
	}
	wantReason(path, "SOURCE_SLOT_MISSING")
	if _, err := source.Exec(ctx, "SELECT pg_create_logical_replication_slot($1,'pgoutput')", owned.Slot); err != nil {
		t.Fatal(err)
	}
	wantReason(path, "SOURCE_ACK_NOT_PROVEN")
	if _, err := source.Exec(ctx, "DROP PUBLICATION "+pgx.Identifier{owned.Publication}.Sanitize()+"; CREATE PUBLICATION "+pgx.Identifier{owned.Publication}.Sanitize()+" FOR TABLE people"); err != nil {
		t.Fatal(err)
	}
	wantReason(path, "SOURCE_PUBLICATION_REPLACED")
	if _, err := source.Exec(ctx, "SELECT pg_drop_replication_slot($1)", owned.Slot); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(ctx, "SELECT pg_create_physical_replication_slot($1)", owned.Slot); err != nil {
		t.Fatal(err)
	}
	wantReason(path, "SOURCE_SLOT_IDENTITY_CHANGED")
	var exists bool
	if err := source.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1 AND slot_type='physical')", owned.Slot).Scan(&exists); err != nil || !exists {
		t.Fatal("read-only monitor mutated a replacement slot", err)
	}
}
