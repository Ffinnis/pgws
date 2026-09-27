package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
	"pgws/internal/hostclient"
	"pgws/internal/logical"
	"pgws/internal/migrations"
	"pgws/internal/privacy"
	"pgws/internal/runtime"
)

func testLivePolicyRenewal(t *testing.T, ctx context.Context, root string, candidate LogicalCandidate, schema privacy.Schema, policy privacy.Policy, signing ed25519.PrivateKey, source *pgxpool.Pool, owned logical.SlotOwnership, ingestionDone <-chan error) {
	t.Helper()
	management := labPrimary(t, ctx, root, "renewal-management")
	dsn := "host=" + management.Host + " user=postgres dbname=postgres sslmode=disable"
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	b := candidate.Approval.Binding
	sql := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	sql(`INSERT INTO pgws_control.tenants(id,name) VALUES($1,'renewal')`, b.Tenant)
	sql(`INSERT INTO pgws_control.projects(tenant_id,id,name) VALUES($1,$2,'renewal')`, b.Tenant, b.Project)
	sql(`INSERT INTO pgws_control.authority(epoch,reconciled,signing_public_key) VALUES($1,true,$2)`, b.Authority, candidate.Approval.PublicKey)
	sql(`INSERT INTO pgws_control.approved_source_references VALUES($1,$2,'logical-renewal','logical-secret')`, b.Tenant, b.Project)
	sql(`INSERT INTO pgws_control.sources(tenant_id,project_id,id,connector,source_epoch,endpoint_reference,secret_reference,status,system_identifier,timeline) VALUES($1,$2,$3,'logical',$4,'logical-renewal','logical-secret','streaming',$5,$6)`, b.Tenant, b.Project, b.Source, b.SourceEpoch, b.SystemID, b.Timeline)
	draft := control.PolicyDraft{Tenant: b.Tenant, Project: b.Project, ID: b.Policy, Revision: 1, Source: b.Source, SourceEpoch: b.SourceEpoch, SystemID: b.SystemID, Timeline: b.Timeline, Schema: schema, Policy: policy}
	record, err := control.CreatePrivacyPolicy(ctx, pool, b.Authority, draft, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if record.Hash != b.PlanHash {
		t.Fatal("renewal policy hash differs")
	}
	if _, err = control.ApprovePrivacyPolicy(ctx, pool, b.Authority, b.Tenant, b.Project, b.Policy, b.PlanHash, b.SchemaHash); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(root, "approval-rpc.token")
	signingFile := filepath.Join(root, "renewal-signing.key")
	for path, data := range map[string]string{tokenFile: strings.Repeat("renewal-channel", 4), signingFile: base64.StdEncoding.EncodeToString(signing)} {
		if err = os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "renewal-candidate.json")
	if err = save(path, candidate); err != nil {
		t.Fatal(err)
	}
	start := func(binary string, env []string, args ...string) *exec.Cmd {
		t.Helper()
		child, stop := context.WithCancel(ctx)
		cmd := exec.CommandContext(child, filepath.Join(os.Getenv("PGWS_LAB_BIN"), binary+"-linux"), args...)
		cmd.Env = env
		if err := cmd.Start(); err != nil {
			stop()
			t.Fatal(err)
		}
		t.Cleanup(func() { stop(); _ = cmd.Wait() })
		return cmd
	}
	relayProcess := start("pgws-logical-watchdog", nil, "relay", path, tokenFile)
	start("pgws-logical-watchdog", nil, "watch", path)
	plan := control.PolicyRenewal{Binding: b, Identity: candidate.Container.Spec.Identity, Runtime: candidate.Approval.Runtime}
	renewalPath := filepath.Join(root, "renewal.json")
	if err = save(renewalPath, control.Object{"candidate": plan, "socket": candidate.Approval.Path + ".sock", "token_file": tokenFile}); err != nil {
		t.Fatal(err)
	}
	// The server's first signature and a second periodic delivery must reach the
	// actual root relay; the test never installs their tokens itself.
	var initial struct {
		ReceivedNS int64 `json:"received_ns"`
	}
	data, err := os.ReadFile(candidate.Approval.Path)
	if err != nil || json.Unmarshal(data, &initial) != nil {
		t.Fatal("initial approval unavailable")
	}
	start("pgwsd", []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "PGWS_DATABASE_URL=" + dsn, "PGWS_AUTHORITY_EPOCH=" + b.Authority, "PGWS_SIGNING_KEY_FILE=" + signingFile}, "policy-renew", renewalPath)
	first := int64(0)
	deadline := time.Now().Add(50 * time.Second)
	var latest []byte
	for {
		var current struct {
			ReceivedNS int64 `json:"received_ns"`
		}
		latest, err = os.ReadFile(candidate.Approval.Path)
		if err == nil && json.Unmarshal(latest, &current) == nil && current.ReceivedNS > initial.ReceivedNS {
			if first == 0 {
				first = current.ReceivedNS
				duplicate := exec.CommandContext(ctx, filepath.Join(os.Getenv("PGWS_LAB_BIN"), "pgws-logical-watchdog-linux"), "relay", path, tokenFile)
				if duplicate.Run() == nil {
					t.Fatal("two approval relays owned one private socket")
				}
				if err = relayProcess.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				_ = relayProcess.Wait()
				relayProcess = start("pgws-logical-watchdog", nil, "relay", path, tokenFile)
			} else if current.ReceivedNS > first {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic operator policy delivery did not arrive")
		}
		select {
		case e := <-ingestionDone:
			t.Fatal("ingestion stopped before renewal", e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, err = control.RevokePrivacyPolicy(ctx, pool, b.Authority, b.Tenant, b.Project, b.Policy, b.PlanHash); err != nil {
		t.Fatal(err)
	}
	revokedAt := time.Now()
	select {
	case <-ingestionDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(90 * time.Second):
		t.Fatal("revoked policy retained ingestion beyond signed bound")
	}
	o := runtime.OCI{Binary: "/usr/bin/docker", Image: runtime.PostgresImage}
	deadline = time.Now().Add(8 * time.Second)
	for {
		var gone bool
		err = source.QueryRow(ctx, "SELECT NOT EXISTS(SELECT FROM pg_replication_slots WHERE slot_name=$1)", owned.Slot).Scan(&gone)
		if err == nil && gone && o.VerifyAbsent(ctx, candidate.Container.Spec.Identity) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revocation expiry did not retire runtime and owned slot", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	final, err := os.ReadFile(candidate.Approval.Path)
	if err != nil || !bytes.Equal(final, latest) {
		t.Fatal("revoked policy received a new approval")
	}
	relay := hostclient.Client{Socket: candidate.Approval.Path + ".sock", Token: strings.Repeat("renewal-channel", 4)}
	if err = control.RenewPrivacyPolicy(ctx, pool, b.Authority, plan, signing, relay); err == nil {
		t.Fatal("revoked automatic renewal accepted")
	}
	t.Logf("Separate operator signer and host relay delivered two approvals; policy revocation closed real CDC and retired owned slot in %s", time.Since(revokedAt))
}
