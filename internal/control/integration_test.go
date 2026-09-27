package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/migrations"
)

func TestIntegration(t *testing.T) {
	dsn := os.Getenv("PGWS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("run scripts/integration.py for a private PostgreSQL cluster")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	if e = migrations.Apply(ctx, pool); e != nil {
		t.Fatal(e)
	}
	if e = migrations.Apply(ctx, pool); e != nil {
		t.Fatal("migration replay", e)
	}
	tenant, project, principal, epoch, source, baseline, snapshot := ID(), ID(), ID(), ID(), ID(), ID(), ID()
	otherTenant, otherProject := ID(), ID()
	adminToken := strings.Repeat("a", 64)
	limitedToken := strings.Repeat("b", 64)
	otherToken := strings.Repeat("c", 64)
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, a...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO pgws_control.tenants(id,name) VALUES($1,'test'),($2,'other')`, tenant, otherTenant)
	exec(`INSERT INTO pgws_control.projects(tenant_id,id,name) VALUES($1,$2,'test'),($3,$4,'other')`, tenant, project, otherTenant, otherProject)
	exec(`INSERT INTO pgws_control.authority(epoch,reconciled) VALUES($1,true)`, epoch)
	for _, a := range []struct {
		token, tenant, project, principal string
		admin, raw                        bool
	}{{adminToken, tenant, project, principal, true, true}, {limitedToken, tenant, project, ID(), false, false}, {otherToken, otherTenant, otherProject, ID(), true, true}} {
		exec(`INSERT INTO pgws_control.api_tokens(token_hash,principal_id,tenant_id,project_id,is_admin,allow_raw,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 day')`, fmt.Sprintf("%x", sha256.Sum256([]byte(a.token))), a.principal, a.tenant, a.project, a.admin, a.raw)
	}
	exec(`INSERT INTO pgws_control.sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status) VALUES($1,$2,$3,'physical','test-endpoint','test-secret','streaming')`, tenant, project, source)
	exec(`INSERT INTO pgws_control.baselines(tenant_id,project_id,id,source_id,generation,source_epoch,source_timeline,kind,runtime_digest,compatibility_manifest,state) VALUES($1,$2,$3,$4,1,1,1,'physical_standby','TEST-ONLY-NOT-A-RUNTIME','{}','ready')`, tenant, project, baseline, source)
	exec(`INSERT INTO pgws_control.snapshots(tenant_id,project_id,id,baseline_id,source_epoch,source_timeline,storage_guid,state,captured_at) VALUES($1,$2,$3,$4,1,1,'TEST-ONLY-NOT-ZFS','ready',now())`, tenant, project, snapshot, baseline)
	server := httptest.NewServer((&Server{Pool: pool, Epoch: epoch}).Handler())
	defer server.Close()
	type response struct {
		status int
		body   map[string]any
		raw    []byte
	}
	request := func(method, path, token, key string, body any) response {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("Content-Type", "application/json")
		resp, e := server.Client().Do(req)
		if e != nil {
			t.Error(e)
			return response{}
		}
		defer resp.Body.Close()
		raw, _ = io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return response{resp.StatusCode, out, raw}
	}
	prefix := "/v1/projects/" + project
	input := func() Object {
		return Object{"baseline_id": baseline, "task_id": "integration", "freshness": Object{"mode": "snapshot", "snapshot_id": snapshot}, "resource_profile": "small", "ttl_seconds": 3600}
	}
	assertStatus := func(r response, want int) {
		t.Helper()
		if r.status != want {
			t.Fatalf("HTTP %d want %d: %s", r.status, want, r.raw)
		}
	}
	create := func() (string, string) {
		t.Helper()
		r := request("POST", prefix+"/workspaces", adminToken, ID(), input())
		assertStatus(r, 202)
		return r.body["workspace"].(map[string]any)["id"].(string), r.body["operation"].(map[string]any)["id"].(string)
	}

	t.Run("authentication and raw authorization", func(t *testing.T) {
		assertStatus(request("GET", prefix+"/baselines", "", "", nil), 401)
		assertStatus(request("GET", prefix+"/baselines", otherToken, "", nil), 401)
		r := request("GET", prefix+"/baselines", limitedToken, "", nil)
		assertStatus(r, 200)
		if len(r.body["items"].([]any)) != 0 {
			t.Fatal("raw baseline leaked")
		}
		assertStatus(request("POST", prefix+"/workspaces", limitedToken, ID(), input()), 403)
	})
	t.Run("baseline pagination is complete and project scoped", func(t *testing.T) {
		for generation := 2; generation <= 4; generation++ {
			exec(`INSERT INTO pgws_control.baselines(tenant_id,project_id,id,source_id,generation,source_epoch,source_timeline,kind,runtime_digest,compatibility_manifest,state) VALUES($1,$2,$3,$4,$5,1,1,'physical_standby','TEST-ONLY-NOT-A-RUNTIME','{}','ready')`, tenant, project, ID(), source, generation)
		}
		next := ""
		seen := map[string]bool{}
		for page := 0; page < 5; page++ {
			path := prefix + "/baselines?limit=1"
			if next != "" {
				path += "&cursor=" + next
			}
			r := request("GET", path, adminToken, "", nil)
			assertStatus(r, 200)
			for _, v := range r.body["items"].([]any) {
				id := v.(map[string]any)["id"].(string)
				if seen[id] {
					t.Fatal("duplicate pagination result")
				}
				seen[id] = true
			}
			cursor, ok := r.body["next_cursor"].(string)
			if !ok {
				break
			}
			next = cursor
			assertStatus(request("GET", "/v1/projects/"+otherProject+"/baselines?cursor="+cursor, otherToken, "", nil), 400)
		}
		if len(seen) != 4 {
			t.Fatal("incomplete pagination", len(seen))
		}
		assertStatus(request("GET", prefix+"/baselines?limit=201", adminToken, "", nil), 400)
	})
	t.Run("usage history is paginated and project scoped", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		w := Worker{Pool: pool, Epoch: epoch, HostID: "usage-fixture"}
		batch := CapacityBatch{ID: ID(), Epoch: epoch, Host: w.HostID, Start: now.Add(-time.Second), End: now, Boot: ID(), ElapsedNS: int64(time.Second), Projects: []CapacitySample{{Tenant: tenant, Project: project, DatasetGUID: "12345", Used: 9007199254740993}}}
		if err := w.recordUsage(ctx, batch); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		cursor := ""
		for range 4 {
			path := prefix + "/usage?limit=2"
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			r := request("GET", path, adminToken, "", nil)
			assertStatus(r, 200)
			if r.body["measurement_kind"] != "observed_gauge" {
				t.Fatal("missing gauge semantics")
			}
			for _, value := range r.body["items"].([]any) {
				item := value.(map[string]any)
				id := item["id"].(string)
				if seen[id] {
					t.Fatal("duplicate usage page")
				}
				seen[id] = true
				if item["metric"] == "project_allocated_bytes" && item["amount"] != "9007199254740993" {
					t.Fatal("capacity integer lost precision")
				}
			}
			next, ok := r.body["next_cursor"].(string)
			if !ok {
				break
			}
			cursor = next
			assertStatus(request("GET", "/v1/projects/"+otherProject+"/usage?cursor="+cursor, otherToken, "", nil), 400)
		}
		if len(seen) != 7 {
			t.Fatal("usage history incomplete", len(seen))
		}
		other := request("GET", "/v1/projects/"+otherProject+"/usage", otherToken, "", nil)
		assertStatus(other, 200)
		if len(other.body["items"].([]any)) != 0 {
			t.Fatal("usage crossed project scope")
		}
		for _, query := range []string{"limit=201", "limit=0", "limit=1&limit=2", "cursor=invalid", "unknown=1"} {
			assertStatus(request("GET", prefix+"/usage?"+query, adminToken, "", nil), 400)
		}
	})
	t.Run("published snapshot evidence cannot change", func(t *testing.T) {
		if _, e = pool.Exec(ctx, `UPDATE pgws_control.snapshots SET storage_guid='replacement' WHERE id=$1`, snapshot); e == nil {
			t.Fatal("published snapshot GUID changed")
		}
	})
	t.Run("concurrent duplicate admission", func(t *testing.T) {
		key := ID()
		results := make(chan response, 12)
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); results <- request("POST", prefix+"/workspaces", adminToken, key, input()) }()
		}
		wg.Wait()
		close(results)
		first := ""
		for r := range results {
			assertStatus(r, 202)
			id := r.body["workspace"].(map[string]any)["id"].(string)
			if first != "" && id != first {
				t.Fatal("duplicate workspace")
			}
			first = id
		}
		changed := input()
		changed["task_id"] = "different"
		r := request("POST", prefix+"/workspaces", adminToken, key, changed)
		assertStatus(r, 409)
		if r.body["code"] != "IDEMPOTENCY_CONFLICT" {
			t.Fatal(r.body)
		}
		var count int
		pool.QueryRow(ctx, `SELECT count(*) FROM pgws_control.operations WHERE idempotency_key=$1`, key).Scan(&count)
		if count != 1 {
			t.Fatalf("created %d operations", count)
		}
	})
	t.Run("strict requests and freshness", func(t *testing.T) {
		for _, field := range []string{"raw", "superuser", "dataset_path"} {
			bad := input()
			bad[field] = true
			assertStatus(request("POST", prefix+"/workspaces", adminToken, ID(), bad), 400)
		}
		bad := input()
		bad["ttl_seconds"] = 604801
		assertStatus(request("POST", prefix+"/workspaces", adminToken, ID(), bad), 400)
		bad = input()
		bad["freshness"] = Object{"mode": "latest"}
		assertStatus(request("POST", prefix+"/workspaces", adminToken, ID(), bad), 503)
		for _, freshness := range []Object{{"mode": "latest", "snapshot_id": ""}, {"mode": "snapshot", "snapshot_id": snapshot, "barrier_token": nil}} {
			bad = input()
			bad["freshness"] = freshness
			assertStatus(request("POST", prefix+"/workspaces", adminToken, ID(), bad), 400)
		}
		bad = input()
		bad["freshness"] = Object{"mode": "snapshot", "snapshot_id": ID()}
		assertStatus(request("POST", prefix+"/workspaces", adminToken, ID(), bad), 404)
	})
	worker := &Worker{Pool: pool, Epoch: epoch, ID: "worker-a"}
	drain := func() {
		for i := 0; i < 50; i++ {
			ran, e := worker.Once(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if !ran {
				return
			}
		}
		t.Fatal("queue did not drain")
	}
	t.Run("backend unavailable never publishes readiness", func(t *testing.T) {
		id, op := create()
		drain()
		r := request("GET", prefix+"/operations/"+op, adminToken, "", nil)
		assertStatus(r, 200)
		if r.body["status"] != "failed" {
			t.Fatal(r.body)
		}
		r = request("GET", prefix+"/workspaces/"+id, adminToken, "", nil)
		assertStatus(r, 200)
		if _, ok := r.body["endpoint"]; ok {
			t.Fatal("published endpoint")
		}
		if r.body["phase"] != "failed" {
			t.Fatal(r.body)
		}
	})
	t.Run("row level security scopes raw SQL", func(t *testing.T) {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `SET LOCAL ROLE pgws_runtime`); e != nil {
			t.Fatal(e)
		}
		var n int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM pgws_control.workspaces`).Scan(&n); e != nil || n != 0 {
			t.Fatalf("unscoped RLS %d %v", n, e)
		}
		tx.Exec(ctx, `SELECT set_config('pgws.tenant_id',$1,true),set_config('pgws.project_id',$2,true)`, otherTenant, otherProject)
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM pgws_control.workspaces`).Scan(&n); e != nil || n != 0 {
			t.Fatalf("cross-project RLS %d %v", n, e)
		}
	})
	t.Run("TTL admission waits for host acknowledgement", func(t *testing.T) {
		id, _ := create()
		drain()
		exec(`UPDATE pgws_control.workspaces SET phase='paused',desired_state='paused' WHERE id=$1`, id)
		var expiry, created time.Time
		pool.QueryRow(ctx, `SELECT expires_at,created_at FROM pgws_control.workspaces WHERE id=$1`, id).Scan(&expiry, &created)
		path := prefix + "/workspaces/" + id + "/actions"
		a := Object{"action": "extend_ttl", "expected_generation": 1, "expected_expires_at": expiry, "expires_at": expiry.Add(time.Hour)}
		bad := Object{"action": "extend_ttl", "expected_generation": 2, "expected_expires_at": expiry, "expires_at": expiry.Add(time.Hour)}
		assertStatus(request("POST", path, adminToken, ID(), bad), 409)
		bad["expected_generation"] = 1
		bad["expires_at"] = created.Add(8 * 24 * time.Hour)
		assertStatus(request("POST", path, adminToken, ID(), bad), 400)
		r := request("POST", path, adminToken, ID(), a)
		assertStatus(r, 202)
		var actual time.Time
		pool.QueryRow(ctx, `SELECT expires_at FROM pgws_control.workspaces WHERE id=$1`, id).Scan(&actual)
		if !actual.Equal(expiry) {
			t.Fatal("expiry changed before host ack")
		}
		assertStatus(request("POST", path, adminToken, ID(), a), 409)
		drain()
		pool.QueryRow(ctx, `SELECT expires_at FROM pgws_control.workspaces WHERE id=$1`, id).Scan(&actual)
		if !actual.Equal(expiry) {
			t.Fatal("failed extension changed expiry")
		}
		exec(`UPDATE pgws_control.workspaces SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1`, id)
		assertStatus(request("POST", path, adminToken, ID(), a), 409)
	})
	t.Run("delete supersedes a claimed create", func(t *testing.T) {
		id, op := create()
		j, e := worker.Claim(ctx)
		if e != nil || j == nil || j.ID != op {
			t.Fatalf("claim %v %v", j, e)
		}
		r := request("DELETE", prefix+"/workspaces/"+id+"?expected_generation=1", adminToken, ID(), nil)
		assertStatus(r, 202)
		if e = worker.CompleteUnavailable(ctx, j); e != nil {
			t.Fatal(e)
		}
		r = request("GET", prefix+"/operations/"+op, adminToken, "", nil)
		if r.body["status"] != "cancelled" {
			t.Fatal(r.body)
		}
		drain()
	})
	t.Run("expired worker cannot overwrite reclaimed operation", func(t *testing.T) {
		_, op := create()
		j, e := worker.Claim(ctx)
		if e != nil || j == nil {
			t.Fatal(e)
		}
		exec(`UPDATE pgws_control.operations SET lease_until=now()-interval '1 second' WHERE id=$1`, op)
		second := &Worker{Pool: pool, Epoch: epoch, ID: "worker-b"}
		next, e := second.Claim(ctx)
		if e != nil || next == nil || next.Fence <= j.Fence {
			t.Fatalf("reclaim %v %v", next, e)
		}
		if e = worker.CompleteUnavailable(ctx, j); e == nil {
			t.Fatal("stale worker accepted")
		}
		if e = second.CompleteUnavailable(ctx, next); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("source reference pair approval", func(t *testing.T) {
		in := Object{"connector": "physical", "approved_endpoint_reference": "approved", "secret_reference": "secret-ref"}
		assertStatus(request("POST", prefix+"/sources", adminToken, ID(), in), 403)
		exec(`INSERT INTO pgws_control.approved_source_references VALUES($1,$2,'approved','secret-ref')`, tenant, project)
		assertStatus(request("POST", prefix+"/sources", limitedToken, ID(), in), 403)
		r := request("POST", prefix+"/sources", adminToken, ID(), in)
		assertStatus(r, 202)
		drain()
		var state string
		pool.QueryRow(ctx, `SELECT status FROM pgws_control.sources WHERE id=$1`, r.body["source_id"]).Scan(&state)
		if state != "blocked" {
			t.Fatal(state)
		}
	})
	t.Run("source reseed reserves immutable lineage and rechecks authority", func(t *testing.T) {
		physicalServer := httptest.NewServer((&Server{Pool: pool, Epoch: epoch, Physical: true}).Handler())
		original := server
		server = physicalServer
		defer func() { server = original; physicalServer.Close() }()
		id, oldBaseline := ID(), ID()
		exec(`INSERT INTO pgws_control.sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status) VALUES($1,$2,$3,'physical','reseed-test','reseed-secret','streaming')`, tenant, project, id)
		exec(`INSERT INTO pgws_control.baselines(tenant_id,project_id,id,source_id,generation,source_epoch,source_timeline,kind,runtime_digest,compatibility_manifest,state) VALUES($1,$2,$3,$4,1,1,1,'physical_standby','TEST-ONLY-NOT-A-RUNTIME','{}','ready')`, tenant, project, oldBaseline, id)
		path := prefix + "/sources/" + id + "/actions"
		body := Object{"action": "reseed", "expected_source_epoch": 1}
		assertStatus(request("POST", path, limitedToken, ID(), body), 403)
		assertStatus(request("POST", path, otherToken, ID(), body), 401)
		assertStatus(request("POST", path, adminToken, ID(), body), 403)
		exec(`INSERT INTO pgws_control.approved_source_references VALUES($1,$2,'reseed-test','reseed-secret')`, tenant, project)
		assertStatus(request("POST", path, adminToken, ID(), Object{"action": "reseed", "expected_source_epoch": 1, "source_dsn": "unapproved"}), 400)
		assertStatus(request("POST", path, adminToken, ID(), Object{"action": "reseed", "expected_source_epoch": 2}), 409)
		key := ID()
		accepted := request("POST", path, adminToken, key, body)
		assertStatus(accepted, 202)
		replay := request("POST", path, adminToken, key, body)
		assertStatus(replay, 202)
		acceptedJSON, _ := json.Marshal(accepted.body)
		replayJSON, _ := json.Marshal(replay.body)
		if !bytes.Equal(acceptedJSON, replayJSON) {
			t.Fatal("reseed idempotency changed")
		}
		assertStatus(request("POST", path, adminToken, ID(), body), 409)
		assertStatus(request("POST", path, adminToken, ID(), Object{"action": "reseed", "expected_source_epoch": 2}), 409)
		var gen, ep, oldGen, oldEpoch int64
		var status string
		if e = pool.QueryRow(ctx, `SELECT baseline_generation,source_epoch,status FROM pgws_control.sources WHERE id=$1`, id).Scan(&gen, &ep, &status); e != nil || gen != 2 || ep != 2 || status != "seeding" {
			t.Fatal("reseed reservation", gen, ep, status, e)
		}
		if e = pool.QueryRow(ctx, `SELECT generation,source_epoch,state FROM pgws_control.baselines WHERE id=$1`, oldBaseline).Scan(&oldGen, &oldEpoch, &status); e != nil || oldGen != 1 || oldEpoch != 1 || status != "retired" {
			t.Fatal("old baseline lineage changed", e)
		}
		j, err := worker.Claim(ctx)
		if err != nil || j == nil || j.Kind != "reseed_source" || j.Generation != 2 {
			t.Fatal("reseed claim", j, err)
		}
		task, err := worker.task(ctx, j)
		if err != nil || task.Snapshot.Baseline != accepted.body["baseline_id"] || task.Snapshot.SourceEpoch != 2 || task.Snapshot.BaselineGeneration != 2 {
			t.Fatal("reseed host task", err)
		}
		if err = worker.CompleteUnavailable(ctx, j); err != nil {
			t.Fatal(err)
		}
		var baselines int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM pgws_control.baselines WHERE source_id=$1`, id).Scan(&baselines); err != nil || baselines != 1 {
			t.Fatal("published an unqualified baseline", err)
		}
		// Failure retains the consumed generation. A later request gets a new
		// identity and cannot revive or relabel the failed attempt.
		accepted = request("POST", path, adminToken, ID(), Object{"action": "reseed", "expected_source_epoch": 2})
		assertStatus(accepted, 202)
		if accepted.body["generation"] != float64(3) {
			t.Fatal("reused failed source generation")
		}
		exec(`UPDATE pgws_control.api_tokens SET revoked_at=now() WHERE principal_id=$1`, principal)
		if j, err = worker.Claim(ctx); err != nil || j != nil {
			t.Fatal("revoked source administrator claimed operation", err)
		}
		exec(`UPDATE pgws_control.api_tokens SET revoked_at=NULL WHERE principal_id=$1`, principal)
		if err = pool.QueryRow(ctx, `SELECT status FROM pgws_control.sources WHERE id=$1`, id).Scan(&status); err != nil || status != "blocked" {
			t.Fatal("cancelled reseed left source stuck seeding", status, err)
		}
		view := request("GET", prefix+"/sources/"+id, adminToken, "", nil)
		assertStatus(view, 200)
		if view.body["source_epoch"] != float64(3) || view.body["generation"] != float64(3) || view.body["status"] != "blocked" {
			t.Fatal("source recovery status unavailable", view.body)
		}
		assertStatus(request("GET", prefix+"/sources/"+id, limitedToken, "", nil), 403)
		assertStatus(request("GET", "/v1/projects/"+otherProject+"/sources/"+id, otherToken, "", nil), 404)
	})
	t.Run("expiry admission is durable and independent of actor tokens", func(t *testing.T) {
		id, _ := create()
		drain()
		exec(`UPDATE pgws_control.workspaces SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1`, id)
		count, e := worker.SweepExpired(ctx)
		if e != nil || count < 1 {
			t.Fatalf("sweep: %d %v", count, e)
		}
		count, e = worker.SweepExpired(ctx)
		if e != nil || count != 0 {
			t.Fatalf("repeated sweep: %d %v", count, e)
		}
		var n int
		if e = pool.QueryRow(ctx, `SELECT count(*) FROM pgws_control.operations WHERE workspace_id=$1 AND kind='expire' AND actor_reference IS NULL`, id).Scan(&n); e != nil || n != 1 {
			t.Fatalf("expiry operation: %d %v", n, e)
		}
		drain()
	})
	t.Run("execution failure is terminal", func(t *testing.T) {
		_, op := create()
		j, e := worker.Claim(ctx)
		if e != nil || j == nil || j.ID != op {
			t.Fatalf("claim: %v %v", j, e)
		}
		if e = worker.completeFailure(ctx, j, "HOST_EXECUTION_FAILED", "Host failed", false); e != nil {
			t.Fatal(e)
		}
		r := request("GET", prefix+"/operations/"+op, adminToken, "", nil)
		assertStatus(r, 200)
		if r.body["status"] != "failed" {
			t.Fatal(r.body)
		}
	})
	t.Run("unknown host result retries with fresh authority and a bounded attempt count", func(t *testing.T) {
		id, op := create()
		first, err := worker.Claim(ctx)
		if err != nil || first == nil || first.ID != op {
			t.Fatal("claim", err)
		}
		if err = worker.retryUnknownHostResult(first); err != nil {
			t.Fatal(err)
		}
		if next, err := worker.Claim(ctx); err != nil || next != nil {
			t.Fatal("retry ignored backoff", err)
		}
		var phase string
		if err = pool.QueryRow(ctx, "SELECT phase FROM pgws_control.workspaces WHERE id=$1", id).Scan(&phase); err != nil || phase == "failed" || phase == "ready" {
			t.Fatal("unknown result published an outcome", phase, err)
		}
		exec("UPDATE pgws_control.operations SET not_before=clock_timestamp() WHERE id=$1", op)
		second, err := worker.Claim(ctx)
		if err != nil || second == nil || second.ID != op || second.Fence <= first.Fence {
			t.Fatal("retry did not reclaim with a newer fence", err)
		}
		if err = worker.retryUnknownHostResult(first); err == nil {
			t.Fatal("stale attempt requeued a newer worker")
		}
		exec("UPDATE pgws_control.operations SET attempt=10 WHERE id=$1", op)
		if err = worker.retryUnknownHostResult(second); err == nil {
			t.Fatal("unbounded host outage retry")
		}
		if err = worker.CompleteUnavailable(ctx, second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("source claims serialize without starving workspace jobs", func(t *testing.T) {
		drain()
		for i := 0; i < 2; i++ {
			doc, _ := json.Marshal(Object{"source_id": source})
			exec(`INSERT INTO pgws_control.operations(tenant_id,project_id,id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,authority_epoch,actor_reference) VALUES($1,$2,$3::uuid,'issue_barrier',1,1,'test:barrier',$3::text,repeat('d',64),'queued',$4,$5,$6)`, tenant, project, ID(), doc, epoch, principal)
		}
		first, e := worker.Claim(ctx)
		if e != nil || first == nil || first.Kind != "issue_barrier" {
			t.Fatal(first, e)
		}
		other := &Worker{Pool: pool, Epoch: epoch, ID: "worker-b"}
		if j, e := other.Claim(ctx); e != nil || j != nil {
			t.Fatal("concurrent source claim", j, e)
		}
		_, op := create()
		job, e := other.Claim(ctx)
		if e != nil || job == nil || job.ID != op {
			t.Fatal("workspace starved by busy source", job, e)
		}
		if e = other.CompleteUnavailable(ctx, job); e != nil {
			t.Fatal(e)
		}
		if e = worker.CompleteUnavailable(ctx, first); e != nil {
			t.Fatal(e)
		}
		next, e := other.Claim(ctx)
		if e != nil || next == nil || next.Kind != "issue_barrier" || next.Fence <= first.Fence {
			t.Fatal("source queue did not resume", next, e)
		}
		if e = other.CompleteUnavailable(ctx, next); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("failed snapshot collection schedules a new operation", func(t *testing.T) {
		snap := ID()
		exec(`INSERT INTO pgws_control.snapshots(tenant_id,project_id,id,baseline_id,source_epoch,source_timeline,storage_guid,state,captured_at) VALUES($1,$2,$3,$4,1,1,'TEST-ONLY-GC','deleting',now())`, tenant, project, snap, baseline)
		doc, _ := json.Marshal(Object{"source_id": source, "snapshot_id": snap})
		prior := ID()
		exec(`INSERT INTO pgws_control.operations(tenant_id,project_id,id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,request_document,authority_epoch,completed_at) VALUES($1,$2,$3::uuid,'gc_snapshot',1,1,'system:snapshot-gc',$3::text,repeat('d',64),'failed',$4,$5,now()-interval '2 minutes')`, tenant, project, prior, doc, epoch)
		n, e := worker.SweepSnapshots(ctx)
		if e != nil || n != 1 {
			t.Fatal("failed cleanup was not retried", n, e)
		}
		if n, e = worker.SweepSnapshots(ctx); e != nil || n != 0 {
			t.Fatal("duplicate cleanup retry", n, e)
		}
		var status string
		if e = pool.QueryRow(ctx, `SELECT status FROM pgws_control.operations WHERE id=$1`, prior).Scan(&status); e != nil || status != "failed" {
			t.Fatal("terminal operation changed", status, e)
		}
		drain()
		exec(`UPDATE pgws_control.snapshots SET state='deleted' WHERE id=$1`, snap)
	})
	t.Run("worker locks cannot mutate or shadow authority", func(t *testing.T) {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, `CREATE TEMP TABLE authority(singleton bool,epoch uuid,reconciled bool);INSERT INTO authority VALUES(true,'00000000-0000-4000-8000-000000000000',true);SET LOCAL ROLE pgws_worker`); e != nil {
			t.Fatal(e)
		}
		var ok bool
		if e = tx.QueryRow(ctx, `SELECT pgws_control.lock_authority($1)`, epoch).Scan(&ok); e != nil || !ok {
			t.Fatal("authority shadowing", e)
		}
		if _, e = tx.Exec(ctx, `UPDATE pgws_control.authority SET reconciled=false`); e == nil {
			t.Fatal("worker can mutate authority")
		}
	})
	t.Run("restored authority and token revocation fail closed", func(t *testing.T) {
		key := ID()
		r := request("POST", prefix+"/workspaces", adminToken, key, input())
		assertStatus(r, 202)
		exec(`UPDATE pgws_control.authority SET epoch=$1`, ID())
		assertStatus(request("GET", prefix+"/baselines", adminToken, "", nil), 503)
		if _, e = worker.Claim(ctx); e == nil {
			t.Fatal("worker accepted restored authority")
		}
		exec(`UPDATE pgws_control.authority SET epoch=$1`, epoch)
		exec(`UPDATE pgws_control.api_tokens SET revoked_at=now() WHERE principal_id=$1`, principal)
		assertStatus(request("POST", prefix+"/workspaces", adminToken, key, input()), 401)
	})
	t.Run("operator recovery quarantines old authority", func(t *testing.T) {
		cfg := pool.Config()
		cfg.ConnConfig.RuntimeParams["role"] = "pgws_worker"
		workerPool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer workerPool.Close()
		testAuthorityRecovery(t, ctx, pool, workerPool, epoch, tenant, project)
	})
}
