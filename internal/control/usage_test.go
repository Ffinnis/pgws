package control

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type usageBackend struct {
	Backend
	batch CapacityBatch
	ack   func(context.Context, Task) error
}

func (b usageBackend) CollectUsage(context.Context, Task) (CapacityBatch, error) { return b.batch, nil }
func (b usageBackend) AcknowledgeUsage(ctx context.Context, t Task) error        { return b.ack(ctx, t) }
func testUsageMeasurements(t *testing.T, ctx context.Context, admin *pgxpool.Pool, w Worker, tenant, project string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	batch := CapacityBatch{ID: ID(), Epoch: w.Epoch, Host: w.HostID, Start: now.Add(-time.Second), End: now, Boot: ID(), ElapsedNS: int64(time.Second), Projects: []CapacitySample{{Tenant: tenant, Project: project, DatasetGUID: "12345", Used: 100, ByChildren: 90, ByDataset: 10, ReservedMemory: 1024}}}
	count := func() int {
		t.Helper()
		var n int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pgws_control.usage_events WHERE tenant_id=$1 AND project_id=$2`, tenant, project).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	calls := 0
	w.Backend = usageBackend{batch: batch, ack: func(ctx context.Context, task Task) error {
		calls++
		// Commit must precede external ACK and release all management locks.
		tx, err := admin.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "LOCK TABLE pgws_control.usage_events IN ACCESS EXCLUSIVE MODE NOWAIT"); err != nil {
			return err
		}
		var n int
		if err = tx.QueryRow(ctx, "SELECT count(*) FROM pgws_control.usage_events WHERE tenant_id=$1 AND project_id=$2", tenant, project).Scan(&n); err != nil {
			return err
		}
		if n != 7 {
			return errors.New("ack preceded complete batch commit")
		}
		if calls == 1 {
			return ErrHostUnavailable
		}
		return nil
	}}
	if err := w.CollectUsage(ctx); !errors.Is(err, ErrHostUnavailable) {
		t.Fatal("lost usage ACK", err)
	}
	if err := w.CollectUsage(ctx); err != nil || count() != 7 || calls != 2 {
		t.Fatal("usage retry duplicated or lost samples", err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- w.recordUsage(ctx, batch) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent measurement retry", err)
		}
	}
	if count() != 7 {
		t.Fatal("duplicate measurements")
	}
	changed := batch
	changed.Projects = append([]CapacitySample(nil), batch.Projects...)
	changed.Projects[0].Used++
	if err := w.recordUsage(ctx, changed); err == nil {
		t.Fatal("changed measurement reused identity")
	}
	changed = batch
	changed.Projects = nil
	if err := w.recordUsage(ctx, changed); err == nil {
		t.Fatal("partial batch retry accepted")
	}
	for _, q := range []string{"UPDATE pgws_control.usage_events SET amount=0", "DELETE FROM pgws_control.usage_events", "UPDATE pgws_control.usage_batches SET host_id='other'"} {
		if _, err := admin.Exec(ctx, q); err == nil {
			t.Fatal("mutable measurement", q)
		}
	}
	changed = batch
	changed.ID = ID()
	changed.Projects = append([]CapacitySample(nil), batch.Projects...)
	changed.Projects[0].Project = ID()
	if err := w.recordUsage(ctx, changed); err == nil {
		t.Fatal("unknown project accepted")
	}
	if count() != 7 {
		t.Fatal("failed batch left partial rows")
	}
	changed = batch
	changed.ID = ID()
	changed.Epoch = ID()
	if err := w.recordUsage(ctx, changed); err == nil {
		t.Fatal("foreign authority accepted")
	}
}
