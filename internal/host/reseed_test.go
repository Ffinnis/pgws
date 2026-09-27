package host

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/physical"
)

func testSourceReseed(t *testing.T, ctx context.Context, h *Host, pool *pgxpool.Pool, worker *control.Worker, sourceID string, call func(string, string, string, string) map[string]json.RawMessage, replayLostResult func(string, bool)) {
	t.Helper()
	once := func() {
		t.Helper()
		if _, err := worker.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	create := func(baseline, key string) (string, state) {
		t.Helper()
		out := call("POST", "/workspaces", fmt.Sprintf(`{"baseline_id":%q,"task_id":"reseed-fixture","freshness":{"mode":"latest"},"resource_profile":"small","ttl_seconds":300}`, baseline), key)
		var ws struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(out["workspace"], &ws); err != nil {
			t.Fatal(err)
		}
		once()
		st, err := h.load(control.Task{Command: lease.Command{Identity: lease.Identity{Workspace: ws.ID, Generation: 1}}})
		if err != nil {
			t.Fatal(err)
		}
		return ws.ID, st
	}
	oldWorkspace, old := create(sourceID, "before-reseed")
	private := physical.Source{Host: old.Recovery.SocketDir, Port: 5432, User: old.Access.Admin, Database: "postgres"}
	oldSQL, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer oldSQL.Close(context.Background())
	if _, err = oldSQL.Exec(ctx, "INSERT INTO public.fixture VALUES(700,'local-before-reseed')"); err != nil {
		t.Fatal(err)
	}
	before, err := h.load(control.Task{Command: lease.Command{Identity: lease.Identity{Workspace: sourceID, Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	// Captures can advance storage authority far beyond management jobs.
	current, ok := h.storageJournal.Current(before.Task.Command.Identity)
	if !ok {
		t.Fatal("source storage fence missing")
	}
	high := current.Command
	high.Token += 10000
	if _, _, err = h.storageJournal.Accept(high); err != nil {
		t.Fatal(err)
	}
	accepted := call("POST", "/sources/"+sourceID+"/actions", `{"action":"reseed","expected_source_epoch":1}`, "reseed")
	var baselineID string
	if err = json.Unmarshal(accepted["baseline_id"], &baselineID); err != nil || baselineID == sourceID {
		t.Fatal("new baseline identity", err)
	}
	replayLostResult("reseed_source", false)
	replayed := call("POST", "/sources/"+sourceID+"/actions", `{"action":"reseed","expected_source_epoch":1}`, "reseed")
	if string(replayed["baseline_id"]) != string(accepted["baseline_id"]) {
		t.Fatal("reseed replay changed baseline")
	}
	newTask := before.Task
	newTask.Command.Generation = 2
	next, err := h.load(newTask)
	if err != nil || next.Outcome.Source == nil || next.Outcome.Source.Snapshot.Baseline != baselineID || next.Outcome.Source.Snapshot.SourceEpoch != 2 || next.Outcome.Source.Snapshot.BaselineGeneration != 2 {
		t.Fatal("new source lineage", err)
	}
	if err = h.oci.VerifyAbsent(ctx, before.Task.Command.Identity); err != nil {
		t.Fatal("old baseline runtime survived reseed", err)
	}
	if err = checkStopped(h.folder(before.Task)); err == nil {
		t.Fatal("old baseline can restart")
	}
	var value string
	if err = oldSQL.QueryRow(ctx, "SELECT value FROM public.fixture WHERE id=700").Scan(&value); err != nil || value != "local-before-reseed" {
		t.Fatal("reseed destroyed existing workspace writes", err)
	}
	newWorkspace, newState := create(baselineID, "after-reseed")
	private.Host, private.User = newState.Recovery.SocketDir, newState.Access.Admin
	newSQL, err := private.ConnectPrivateAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = newSQL.QueryRow(ctx, "SELECT count(*) FROM public.fixture WHERE id=700").Scan(&count); err != nil || count != 0 {
		t.Fatal("new baseline inherited old workspace writes", err)
	}
	newSQL.Close(ctx)
	var oldGen, oldEpoch int64
	var phase string
	if err = pool.QueryRow(ctx, `SELECT generation,source_epoch,state FROM pgws_control.baselines WHERE id=$1`, sourceID).Scan(&oldGen, &oldEpoch, &phase); err != nil || oldGen != 1 || oldEpoch != 1 || phase != "retired" {
		t.Fatal("old baseline metadata changed", err)
	}
	// The new generation must issue a barrier through its own runtime and epoch.
	done := make(chan error, 1)
	go func() {
		for {
			ran, err := worker.Once(ctx)
			if ran || err != nil {
				done <- err
				return
			}
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	barrier := call("POST", "/sources/"+sourceID+"/barriers", `{"after_commit_asserted":true}`, "reseed-barrier")
	if err = <-done; err != nil {
		t.Fatal("new generation barrier", err)
	}
	if string(barrier["source_epoch"]) != "2" {
		t.Fatal("barrier used retired source epoch")
	}
	for _, id := range []string{oldWorkspace, newWorkspace} {
		call("DELETE", "/workspaces/"+id+"?expected_generation=1", "", "delete-"+id)
		once()
	}
	if _, err = pool.Exec(ctx, `UPDATE pgws_control.snapshots SET created_at=now()-interval '2 hours' WHERE baseline_id=$1`, sourceID); err != nil {
		t.Fatal(err)
	}
	collected, err := worker.SweepSnapshots(ctx)
	if err != nil || collected < 1 {
		t.Fatal("retired source snapshot GC", collected, err)
	}
	for i := 0; i < collected; i++ {
		once()
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM pgws_control.snapshots WHERE baseline_id=$1 AND state<>'deleted'`, sourceID).Scan(&count); err != nil || count != 0 {
		t.Fatal("retired source snapshots retained", count, err)
	}
	if err = h.oci.Verify(ctx, next.Container); err != nil {
		t.Fatal("old snapshot GC damaged current baseline", err)
	}
	retired, err := h.load(before.Task)
	if err != nil || retired.Phase != "deleted" {
		t.Fatal("unreferenced retired baseline volume retained", err)
	}
	if err = h.storage.VerifyGeneration(ctx, before.Task.Command, before.Volume, "baselines"); err == nil {
		t.Fatal("retired baseline volume still exists")
	}
	if err = h.MaintainSources(ctx); err != nil {
		t.Fatal("post-reseed maintenance", err)
	}
	t.Log("API reseed + lost-response retry: new baseline/epoch/generation, immutable old workspace writes, new generation barrier, independent storage fence and old-generation snapshot GC passed")
}
