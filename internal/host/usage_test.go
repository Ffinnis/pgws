package host

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"pgws/internal/control"
)

func TestUsageOutboxReplay(t *testing.T) {
	h := &Host{Config: Config{Root: t.TempDir(), ID: "host", Epoch: control.ID()}}
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := control.CapacityBatch{ID: control.ID(), Epoch: h.Config.Epoch, Host: h.Config.ID, Start: now.Add(-time.Second), End: now, Boot: control.ID(), ElapsedNS: int64(time.Second), Projects: []control.CapacitySample{}}
	if err := saveOnce(h.usagePath(), b); err != nil {
		t.Fatal(err)
	}
	task := control.Task{Kind: "collect_usage"}
	task.Command.Epoch = b.Epoch
	task.Command.Host = b.Host
	// Replay does not need ZFS, and survives a newly constructed host process.
	for range 2 {
		reopened := &Host{Config: h.Config}
		replay, err := reopened.CollectUsage(context.Background(), task)
		if err != nil || replay.ID != b.ID || !replay.Start.Equal(b.Start) {
			t.Fatal("pending measurement changed", err)
		}
	}
	task.Kind = "acknowledge_usage"
	task.Document, _ = json.Marshal(control.Object{"batch_id": control.ID()})
	if err := h.AcknowledgeUsage(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.usagePath()); err != nil {
		t.Fatal("stale ACK removed pending batch")
	}
	task.Document, _ = json.Marshal(control.Object{"batch_id": b.ID})
	task.Command.Epoch = control.ID()
	if err := h.AcknowledgeUsage(context.Background(), task); err == nil {
		t.Fatal("foreign authority acknowledged batch")
	}
	task.Command.Epoch = b.Epoch
	for range 2 {
		if err := h.AcknowledgeUsage(context.Background(), task); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(h.usagePath()); !os.IsNotExist(err) {
		t.Fatal("acknowledged batch retained", err)
	}
}
