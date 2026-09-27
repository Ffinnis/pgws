package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"pgws/internal/control"
	"pgws/internal/policyapproval"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"pgws/internal/logical"
	"pgws/internal/privacy"
	"pgws/internal/runtime"
)

func TestLiveLogicalRuntime(t *testing.T) {
	if os.Getenv("PGWS_ZFS_ROOT") == "" {
		t.Skip("run scripts/host_lab.py")
	}
	for _, mode := range []string{"cancel", "wal_budget", "seed_wal_budget", "uncertain_retirement", "replacement_slot", "approval_expiry", "approval_stall", "approval_mismatch", "approval_renewal"} {
		t.Run(mode, func(t *testing.T) { verifyLogicalRuntime(t, mode) })
	}
}

func verifyLogicalRuntime(t *testing.T, mode string) {
	timeout := time.Minute
	if mode == "approval_renewal" {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	root, err := os.MkdirTemp("/tmp", "pgws-l-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	_, source := logicalLabRuntime(t, ctx, root, filepath.Join(root, "source-data"), "source", true)
	writer, target := logicalLabRuntime(t, ctx, root, filepath.Join(root, "target-data"), "writer", true, source.Config().ConnConfig.Host, control.ID(), "1")
	if _, err = source.Exec(ctx, "CREATE TABLE people(id bigint PRIMARY KEY,email text NOT NULL); INSERT INTO people VALUES(1,'source-private@example.org')"); err != nil {
		t.Fatal(err)
	}
	tx, err := source.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := logical.ReadCatalog(ctx, tx)
	tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identity := logical.Identity{Source: writer.Spec.LogicalSource, Epoch: writer.Spec.LogicalSourceEpoch, Baseline: writer.Spec.Identity.Workspace, Generation: writer.Spec.Identity.Generation}
	if err = source.QueryRow(ctx, "SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id").Scan(&identity.SystemID, &identity.Timeline); err != nil {
		t.Fatal(err)
	}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "runtime-lab", Rules: []privacy.Rule{
		{Table: schema.Tables[0].ID, Column: 1, Action: "copy_original"},
		{Table: schema.Tables[0].ID, Column: 2, Action: "keyed_email", Domain: "emails"},
	}}
	keyPath := filepath.Join(writer.Spec.ControlDir, "transform.key")
	ownershipPath := filepath.Join(writer.Spec.ControlDir, "slot.json")
	privateFile := func(path string, value []byte) {
		t.Helper()
		if e := os.WriteFile(path, value, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown(path, 999, 999); e != nil {
			t.Fatal(e)
		}
	}
	privateFile(keyPath, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))))
	configuration := map[string]any{"source_dsn": "host=" + source.Config().ConnConfig.Host + " user=postgres dbname=postgres sslmode=disable", "target_dsn": "host=" + writer.Spec.SocketDir + " user=postgres dbname=postgres sslmode=disable", "identity": identity, "policy": policy, "transform_key_file": keyPath, "slot_ownership_file": ownershipPath, "ddl_frozen": true}
	data, _ := json.Marshal(configuration)
	privateFile(filepath.Join(writer.Spec.ControlDir, "logical.json"), data)
	o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
	candidate := LogicalCandidate{Container: writer, SourceDSN: configuration["source_dsn"].(string), OwnershipPath: ownershipPath}
	ingest := o.Ingest
	var permit policyapproval.Permit
	var claims policyapproval.Claims
	var approvalKey ed25519.PrivateKey
	if strings.HasPrefix(mode, "approval_") {
		plan, e := privacy.Compile(schema, policy, bytes.Repeat([]byte{8}, 32))
		if e != nil {
			t.Fatal(e)
		}
		claims = policyapproval.Claims{Binding: policyapproval.Binding{Authority: writer.Spec.Identity.Epoch, Tenant: writer.Spec.Identity.Tenant, Project: writer.Spec.Identity.Project, Policy: control.ID(), Source: identity.Source, SourceEpoch: identity.Epoch, SystemID: identity.SystemID, Timeline: identity.Timeline, PlanHash: plan.Hash(), SchemaHash: plan.SchemaHash(), KeyFingerprint: fmt.Sprintf("%x", sha256.Sum256(bytes.Repeat([]byte{8}, 32))), Compiler: "pgws-transform-v1"}, ApprovedAt: time.Now().UTC().Add(-time.Hour), IssuedAt: time.Now().UTC()}
		if mode == "approval_mismatch" {
			claims.PlanHash = strings.Repeat("a", 64)
		}
		claims.ExpiresAt = claims.IssuedAt.Add(90 * time.Second)
		approvalKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
		permit = policyapproval.Permit{Binding: claims.Binding, PublicKey: approvalKey.Public().(ed25519.PublicKey), Path: filepath.Join(root, "policy-permit.json"), Runtime: runtime.LogicalRuntimeDigest(writer)}
		token, e := policyapproval.Sign(approvalKey, claims)
		if e != nil {
			t.Fatal(e)
		}
		candidate.Approval = &permit
		candidateConfig := filepath.Join(root, "approval-candidate.json")
		approvalDocument := filepath.Join(root, "approval.json")
		if e = saveOnce(candidateConfig, candidate); e != nil {
			t.Fatal(e)
		}
		if e = saveOnce(approvalDocument, control.Object{"approval": claims, "approval_token": token}); e != nil {
			t.Fatal(e)
		}
		approve := exec.CommandContext(ctx, filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgws-logical-watchdog-linux"), "approve", candidateConfig, approvalDocument)
		if output, e := approve.CombinedOutput(); e != nil {
			t.Fatal("host approval command failed", e, string(output))
		}
		ingest = func(ctx context.Context, c runtime.Container, mode string) ([]byte, error) {
			return o.IngestApproved(ctx, c, mode, permit)
		}
		if mode == "approval_mismatch" {
			if _, e = ingest(ctx, writer, "seed"); e == nil {
				t.Fatal("wrong approved plan seeded")
			}
			var touched bool
			if e = target.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_namespace WHERE nspname='_pgws_ingestion')").Scan(&touched); e != nil || touched {
				t.Fatal("mismatched approval touched target", e)
			}
			return
		}
	}
	if mode == "seed_wal_budget" {
		if _, err = source.Exec(ctx, "INSERT INTO people SELECT n,'seed-'||n||'@example.org' FROM generate_series(2,100000) n"); err != nil {
			t.Fatal(err)
		}
		seedCtx, stopSeed := context.WithCancel(ctx)
		defer stopSeed()
		done := make(chan error, 1)
		go func() { _, e := o.Ingest(seedCtx, writer, "seed"); done <- e }()
		deadline := time.Now().Add(10 * time.Second)
		var owned logical.SlotOwnership
		for {
			owned, err = logical.ReadSlotOwnership(ownershipPath)
			if err == nil {
				break
			}
			select {
			case e := <-done:
				t.Fatal("seed ended before ownership", e)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("seed ownership deadline")
			}
			time.Sleep(10 * time.Millisecond)
		}
		defer source.Exec(context.Background(), "SELECT pg_drop_replication_slot($1)", owned.Slot)
		// Application tables are ACCESS EXCLUSIVE-locked by the seed. Reading
		// them would wait for commit and destroy the intended precommit check.
		var unseeded bool
		if err = target.QueryRow(ctx, "SELECT seed_lsn IS NULL FROM _pgws_ingestion.checkpoint").Scan(&unseeded); err != nil || !unseeded {
			t.Fatal("fixture seed completed before watchdog", err)
		}
		if _, err = logical.ReadApplied(ownershipPath, owned); err == nil {
			t.Fatal("uncommitted seed already has progress")
		}
		stopLogicalOnBudget(t, ctx, root, source, candidate, owned, done)
		if err = o.VerifyAbsent(ctx, writer.Spec.Identity); err != nil {
			t.Fatal(err)
		}
		if _, err = o.Ensure(ctx, writer.Spec); err == nil {
			t.Fatal("stopped seed restarted")
		}
		if _, err = os.Stat(filepath.Join(writer.Spec.DataDir, "PG_VERSION")); err != nil {
			t.Fatal(err)
		}
		t.Log("Independent source watchdog stopped a frozen initial load before seed commit")
		return
	}
	if output, e := ingest(ctx, writer, "seed"); e != nil || !strings.Contains(string(output), `"eligible_for_publication":false`) {
		t.Fatal("container seed failed", e)
	}
	owned, err := logical.ReadSlotOwnership(ownershipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Exec(context.Background(), "SELECT pg_drop_replication_slot($1)", owned.Slot)
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(2,'stream-private@example.org')"); err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	runIngest := ingest
	if mode == "approval_stall" {
		runIngest = o.Ingest
	} // Only the separate watchdog enforces this run's expiry.
	go func() { _, e := runIngest(runCtx, writer, "run"); done <- e }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var rows int
		if e := target.QueryRow(ctx, "SELECT count(*) FROM people WHERE email LIKE '%@example.invalid'").Scan(&rows); e == nil && rows == 2 {
			break
		}
		select {
		case e := <-done:
			t.Fatal("container ingestion ended", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("container ingestion did not catch up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e := WatchLogicalOnce(ctx, candidate); e != nil {
		t.Fatal("healthy supervision", e)
	}
	if mode == "approval_renewal" {
		testLivePolicyRenewal(t, ctx, root, candidate, schema, policy, approvalKey, source, owned, done)
		return
	}
	if strings.HasPrefix(mode, "approval_") {
		claims.IssuedAt = time.Now().UTC()
		claims.ExpiresAt = claims.IssuedAt.Add(9 * time.Second)
		token, e := policyapproval.Sign(approvalKey, claims)
		if e != nil {
			t.Fatal(e)
		}
		if e = permit.Install(token); e != nil {
			t.Fatal(e)
		}
		if mode == "approval_stall" {
			pause := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "pause", writer.ID)
			if e = pause.Run(); e != nil {
				t.Fatal(e)
			}
			// Use ordinary ingestion's parent only to receive exit. The independent
			// watchdog must still make and preserve the terminal expiry decision.
		}
		candidatePath := filepath.Join(root, "policy-candidate.json")
		if e = saveOnce(candidatePath, candidate); e != nil {
			t.Fatal(e)
		}
		watchCtx, stopWatch := context.WithCancel(ctx)
		watch := exec.CommandContext(watchCtx, filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgws-logical-watchdog-linux"), candidatePath)
		if e = watch.Start(); e != nil {
			t.Fatal(e)
		}
		defer func() { stopWatch(); _ = watch.Wait() }()
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("expired approval succeeded")
			}
		case <-time.After(12 * time.Second):
			t.Fatal("expired approval retained consumer")
		}
		// The exec stream can close before Docker finishes removing its
		// enclosing container. Await the actual absence and source cleanup.
		stoppedBy := time.Now().Add(8 * time.Second)
		for {
			var slotGone bool
			e = source.QueryRow(ctx, "SELECT NOT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1)", owned.Slot).Scan(&slotGone)
			if e == nil && slotGone && o.VerifyAbsent(ctx, writer.Spec.Identity) == nil {
				break
			}
			if time.Now().After(stoppedBy) {
				t.Fatal("policy watchdog did not confirm runtime and owned-slot removal", e)
			}
			time.Sleep(20 * time.Millisecond)
		}
		var fence struct {
			Reason string `json:"reason"`
		}
		encoded, e := os.ReadFile(filepath.Join(writer.Spec.ControlDir, "logical-stop.json"))
		if e != nil || json.Unmarshal(encoded, &fence) != nil || fence.Reason != "POLICY_APPROVAL_EXPIRED" {
			t.Fatal("policy stop decision differs", e)
		}
		claims.IssuedAt = time.Now().UTC()
		claims.ExpiresAt = claims.IssuedAt.Add(90 * time.Second)
		token, _ = policyapproval.Sign(approvalKey, claims)
		if e = permit.Install(token); e == nil {
			t.Fatal("renewal revived expired permit")
		}
		if _, e = o.Ensure(ctx, writer.Spec); e == nil {
			t.Fatal("expired candidate restarted")
		}
		t.Log("Expired signed policy stopped exact container and refused renewal:", mode)
		return
	}
	if mode == "wal_budget" {
		stopLogicalOnBudget(t, ctx, root, source, candidate, owned, done)
	} else {
		// docker-exec cancellation must remove the enclosure, not just the client.
		stop()
		if e := <-done; !errors.Is(e, context.Canceled) {
			t.Fatal("cancel did not stop enclosure", e)
		}
	}
	if e := o.VerifyAbsent(ctx, writer.Spec.Identity); e != nil {
		t.Fatal(e)
	}
	if _, e := o.Ensure(ctx, writer.Spec); e == nil {
		t.Fatal("cancelled generation restarted")
	}
	status, err := logical.InspectSlot(ctx, source.Config().ConnConfig, ownershipPath)
	if err != nil || status.Active || (mode != "wal_budget" && (!status.SeedCommitted || status.Reason != "")) || (mode == "wal_budget" && status.Reason != "SOURCE_SLOT_MISSING") {
		t.Fatal("source consumer survived enclosure removal", status, err)
	}
	if mode == "uncertain_retirement" {
		encoded, _ := json.Marshal(owned)
		intent := logicalRetirement{OwnershipHash: fmt.Sprintf("%x", sha256.Sum256(encoded)), ContainerID: writer.ID}
		if e := saveOnce(filepath.Join(writer.Spec.ControlDir, "logical-retirement.json"), intent); e != nil {
			t.Fatal(e)
		}
		if e := WatchLogicalOnce(ctx, candidate); e == nil {
			t.Fatal("uncertain retirement was retried")
		}
	} else if mode == "replacement_slot" {
		if _, e := source.Exec(ctx, "SELECT pg_drop_replication_slot($1)", owned.Slot); e != nil {
			t.Fatal(e)
		}
		if _, e := source.Exec(ctx, "SELECT pg_create_logical_replication_slot($1,'pgoutput')", owned.Slot); e != nil {
			t.Fatal(e)
		}
		if e := WatchLogicalOnce(ctx, candidate); e == nil {
			t.Fatal("replacement slot was adopted")
		}
	}
	if mode == "uncertain_retirement" || mode == "replacement_slot" {
		var retained bool
		if e := source.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1)", owned.Slot).Scan(&retained); e != nil || !retained {
			t.Fatal("unproven slot was removed", e)
		}
	}
	if _, err = os.Stat(filepath.Join(writer.Spec.DataDir, "PG_VERSION")); err != nil {
		t.Fatal("stop removed retained target data", err)
	}
	t.Log("Pinned container ingestion and terminal stop passed:", mode)
}

func stopLogicalOnBudget(t *testing.T, ctx context.Context, root string, source *pgxpool.Pool, candidate LogicalCandidate, owned logical.SlotOwnership, done <-chan error) {
	t.Helper()
	writer := candidate.Container
	// A separate process must stop an actual stalled producer. Freezing the
	// entire enclosure prevents both PostgreSQL and the connector from helping.
	pause := exec.CommandContext(ctx, "/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "pause", writer.ID)
	if e := pause.Run(); e != nil {
		t.Fatal(e)
	}
	candidatePath := filepath.Join(root, "candidate.json")
	if e := saveOnce(candidatePath, candidate); e != nil {
		t.Fatal(e)
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	watch := exec.CommandContext(watchCtx, filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgws-logical-watchdog-linux"), candidatePath)
	if e := watch.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { stopWatch(); _ = watch.Wait() }()
	if _, e := source.Exec(ctx, "SELECT pg_logical_emit_message(false,'pgws-supervised-budget',repeat('x',1048576)) FROM generate_series(1,66)"); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		var removed bool
		if e := source.QueryRow(ctx, "SELECT NOT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1)", owned.Slot).Scan(&removed); e == nil && removed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("independent watchdog did not remove stalled consumer and owned slot")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var fence struct {
		Reason string `json:"reason"`
	}
	data, e := os.ReadFile(filepath.Join(writer.Spec.ControlDir, "logical-stop.json"))
	if e != nil || json.Unmarshal(data, &fence) != nil || fence.Reason != "SOURCE_WAL_BUDGET" {
		t.Fatal("watchdog did not preserve its original WAL decision", e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("killed ingestion reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("consumer survived watchdog removal")
	}
	if e := WatchLogicalOnce(ctx, candidate); e != nil {
		t.Fatal("repeated watchdog pass", e)
	}
}
