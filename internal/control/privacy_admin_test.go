package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/policyapproval"
	"pgws/internal/privacy"
)

func testPrivacyAdministration(t *testing.T, ctx context.Context, pool, workerPool *pgxpool.Pool, epoch, tenant, project string) {
	t.Helper()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("fixture SQL failed: %s: %v", query, err)
		}
	}
	source := ID()
	exec(`INSERT INTO pgws_control.sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status,system_identifier,timeline) VALUES($1,$2,$3,'physical','policy-source','policy-secret','streaming','12345',1)`, tenant, project, source)
	exec(`INSERT INTO pgws_control.approved_source_references VALUES($1,$2,'policy-source','policy-secret')`, tenant, project)
	schema := privacy.Schema{Tables: []privacy.Table{{ID: 17, Schema: "public", Name: "people", Columns: []privacy.Column{{ID: 1, Name: "id", Type: "int8"}, {ID: 2, Name: "email", Type: "text"}}, PrimaryKey: []int16{1}}}}
	policy := privacy.Policy{Version: 1, SchemaHash: privacy.SchemaHash(schema), KeyID: "review-key", Rules: []privacy.Rule{{Table: 17, Column: 1, Action: "copy_original"}, {Table: 17, Column: 2, Action: "keyed_email", Domain: "emails"}}}
	draft := PolicyDraft{Tenant: tenant, Project: project, ID: ID(), Revision: 1, Source: source, SourceEpoch: 1, SystemID: "12345", Timeline: 1, Schema: schema, Policy: policy}
	key := bytes.Repeat([]byte{7}, 32)
	signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	record, err := CreatePrivacyPolicy(ctx, pool, epoch, draft, key)
	if err != nil || record.State != "draft" || record.ApprovalEpoch != nil {
		t.Fatal("create review draft", err)
	}
	if _, _, e := SignPrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash, signingKey); e == nil {
		t.Fatal("draft policy signed")
	}
	reordered := draft
	reordered.Policy.Rules = []privacy.Rule{policy.Rules[1], policy.Rules[0]}
	if replay, e := CreatePrivacyPolicy(ctx, pool, epoch, reordered, key); e != nil || replay.Hash != record.Hash {
		t.Fatal("canonical policy replay", e)
	}
	if _, e := CreatePrivacyPolicy(ctx, pool, epoch, draft, bytes.Repeat([]byte{8}, 32)); e == nil {
		t.Fatal("changed key reused policy identity")
	}
	if _, e := CreatePrivacyPolicy(ctx, workerPool, epoch, draft, key); e == nil {
		t.Fatal("worker authored policy")
	}
	if _, e := ApprovePrivacyPolicy(ctx, workerPool, epoch, tenant, project, record.ID, record.Hash, record.SchemaHash); e == nil {
		t.Fatal("worker approved policy")
	}
	if _, e := ApprovePrivacyPolicy(ctx, pool, epoch, tenant, ID(), record.ID, record.Hash, record.SchemaHash); e == nil {
		t.Fatal("foreign project approved policy")
	}
	if _, e := ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, strings.Repeat("0", 64), record.SchemaHash); e == nil {
		t.Fatal("changed hash approved")
	}
	if _, e := ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash, strings.Repeat("0", 64)); e == nil {
		t.Fatal("changed schema approved")
	}
	record, err = ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash, record.SchemaHash)
	if err != nil || record.State != "approved" || record.ApprovalEpoch == nil || *record.ApprovalEpoch != epoch || record.ApprovedAt == nil {
		t.Fatal("explicit approval", err)
	}
	claims, token, err := SignPrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash, signingKey)
	if err != nil || claims.Source != draft.Source || claims.SourceEpoch != draft.SourceEpoch || claims.PlanHash != record.Hash || claims.SchemaHash != record.SchemaHash {
		t.Fatal("signed approval binding", err)
	}
	if _, e := policyapproval.Verify(signingKey.Public().(ed25519.PublicKey), token, claims.Binding, time.Now()); e != nil {
		t.Fatal(e)
	}
	checkRenewalRevoked := testPolicyRenewal(t, ctx, pool, claims.Binding, signingKey)
	if _, _, e := SignPrivacyPolicy(ctx, workerPool, epoch, tenant, project, record.ID, record.Hash, signingKey); e == nil {
		t.Fatal("worker signed policy authority")
	}
	if repeated, e := ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash, record.SchemaHash); e != nil || !repeated.ApprovedAt.Equal(*record.ApprovedAt) {
		t.Fatal("approval replay changed decision", e)
	}
	for _, query := range []string{`UPDATE pgws_control.privacy_policy_bindings SET source_epoch=2 WHERE policy_id=$1`, `UPDATE pgws_control.privacy_policies SET policy_document='{}' WHERE id=$1`, `UPDATE pgws_control.privacy_policies SET state='draft' WHERE id=$1`} {
		if _, e := pool.Exec(ctx, query, record.ID); e == nil {
			t.Fatal("approved identity mutated")
		}
	}
	other := draft
	other.ID, other.Revision = ID(), 2
	second, err := CreatePrivacyPolicy(ctx, pool, epoch, other, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err = ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, second.ID, second.Hash, second.SchemaHash)
	if err != nil {
		t.Fatal(err)
	}
	principal := ID()
	exec(`INSERT INTO pgws_control.api_tokens(token_hash,principal_id,tenant_id,project_id,allow_raw,expires_at) VALUES($1,$2,$3,$4,true,now()+interval '1 hour')`, strings.ReplaceAll(ID(), "-", "")+strings.ReplaceAll(ID(), "-", ""), principal, tenant, project)
	exposure := func(r PolicyRecord, generation int) (string, string, string) {
		t.Helper()
		baseline, snapshot, workspace, credential, operation := ID(), ID(), ID(), ID(), ID()
		exec(`INSERT INTO pgws_control.baselines(tenant_id,project_id,id,source_id,generation,source_epoch,source_timeline,kind,privacy_policy_id,privacy_policy_hash,runtime_digest,compatibility_manifest,state)
 VALUES($1,$2,$3,$4,$5,1,1,'logical_writer',$6,$7,'SQL-TEST-ONLY','{}','ready')`, tenant, project, baseline, source, generation, r.ID, r.Hash)
		exec(`INSERT INTO pgws_control.snapshots(tenant_id,project_id,id,baseline_id,source_epoch,source_timeline,policy_hash,storage_guid,state,captured_at) VALUES($1,$2,$3,$4,1,1,$5,$6,'ready',now())`, tenant, project, snapshot, baseline, r.Hash, "SQL-TEST-"+snapshot)
		exec(`INSERT INTO pgws_control.workspaces(tenant_id,project_id,id,task_id,desired_state,phase,resource_profile,expires_at,requested_baseline_id) VALUES($1,$2,$3,'policy-test','running','ready','small',now()+interval '1 hour',$4)`, tenant, project, workspace, baseline)
		exec(`INSERT INTO pgws_control.workspace_generations(tenant_id,project_id,workspace_id,generation,snapshot_id,phase,runtime_digest,endpoint_metadata,readiness_evidence,ready_at) VALUES($1,$2,$3,1,$4,'ready','SQL-TEST-ONLY','{}','{}',now())`, tenant, project, workspace, snapshot)
		exec(`UPDATE pgws_control.workspaces SET current_generation=1 WHERE id=$1`, workspace)
		exec(`INSERT INTO pgws_control.credentials(tenant_id,project_id,id,workspace_id,generation,role_name,secret_reference,principal_reference,expires_at) VALUES($1,$2,$3,$4,1,'reader','SQL-TEST-ONLY',$5,now()+interval '1 hour')`, tenant, project, credential, workspace, principal)
		exec(`INSERT INTO pgws_control.operations(tenant_id,project_id,id,workspace_id,kind,expected_generation,desired_revision,idempotency_scope,idempotency_key,request_hash,status,authority_epoch,actor_reference) VALUES($1,$2,$3,$4,'create',1,1,$7,'policy-test',repeat('0',64),'succeeded',$5,$6)`, tenant, project, operation, workspace, epoch, principal, operation)
		return baseline, workspace, credential
	}
	baseline, workspace, credential := exposure(record, 1)
	_, otherWorkspace, otherCredential := exposure(second, 2)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e := eligible(ctx, tx, Principal{Tenant: tenant, Project: project, Raw: true}, baseline); e == nil {
		t.Fatal("operator approval opened unqualified sanitized publication")
	}
	tx.Rollback(ctx)
	grant := func(id string) bool {
		t.Helper()
		var ok bool
		if e := pool.QueryRow(ctx, `SELECT `+servingGrantSQL+` FROM pgws_control.workspaces w WHERE id=$1`, id).Scan(&ok); e != nil {
			t.Fatal(e)
		}
		return ok
	}
	if !grant(workspace) || !grant(otherWorkspace) {
		t.Fatal("fixture grant missing before revocation")
	}
	revoked, err := RevokePrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash)
	if err != nil || revoked.State != "revoked" || revoked.RevokedAt == nil {
		t.Fatal("policy revocation", err)
	}
	checkRenewalRevoked()
	if _, _, e := SignPrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash, signingKey); e == nil {
		t.Fatal("revoked policy signed")
	}
	if grant(workspace) || !grant(otherWorkspace) {
		t.Fatal("policy revocation scope or serving renewal differs")
	}
	var blocked, credentialsMatch bool
	if err = pool.QueryRow(ctx, `SELECT state='blocked' FROM pgws_control.baselines WHERE id=$1`, baseline).Scan(&blocked); err != nil || !blocked {
		t.Fatal("revoked baseline stayed eligible", err)
	}
	if err = pool.QueryRow(ctx, `SELECT (SELECT revoked_at IS NOT NULL FROM pgws_control.credentials WHERE id=$1) AND (SELECT revoked_at IS NULL FROM pgws_control.credentials WHERE id=$2)`, credential, otherCredential).Scan(&credentialsMatch); err != nil || !credentialsMatch {
		t.Fatal("credential revocation did not follow policy lineage", err)
	}
	if replay, e := RevokePrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash); e != nil || !replay.RevokedAt.Equal(*revoked.RevokedAt) {
		t.Fatal("revocation replay changed decision", e)
	}
	if _, e := ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, record.ID, record.Hash, record.SchemaHash); e == nil {
		t.Fatal("revoked policy revived")
	}
	if _, e := pool.Exec(ctx, `UPDATE pgws_control.privacy_policies SET state='approved',revoked_at=NULL WHERE id=$1`, record.ID); e == nil {
		t.Fatal("database allowed policy revival")
	}
	newEpoch := ID()
	exec(`UPDATE pgws_control.authority SET epoch=$1,reconciled=false`, newEpoch)
	if _, e := ApprovePrivacyPolicy(ctx, pool, newEpoch, tenant, project, second.ID, second.Hash, second.SchemaHash); e == nil {
		t.Fatal("unreconciled authority approved policy")
	}
	exec(`UPDATE pgws_control.authority SET reconciled=true`)
	if _, _, e := SignPrivacyPolicy(ctx, pool, newEpoch, tenant, project, second.ID, second.Hash, signingKey); e == nil {
		t.Fatal("restored authority reused historical approval")
	}
	if _, e := ApprovePrivacyPolicy(ctx, pool, epoch, tenant, project, second.ID, second.Hash, second.SchemaHash); e == nil {
		t.Fatal("stale authority approved policy")
	}
	second, err = ApprovePrivacyPolicy(ctx, pool, newEpoch, tenant, project, second.ID, second.Hash, second.SchemaHash)
	if err != nil || second.ApprovalEpoch == nil || *second.ApprovalEpoch != newEpoch {
		t.Fatal("explicit epoch reapproval", err)
	}
	exec(`UPDATE pgws_control.sources SET source_epoch=2 WHERE id=$1`, source)
	if _, _, e := SignPrivacyPolicy(ctx, pool, newEpoch, tenant, project, second.ID, second.Hash, signingKey); e == nil {
		t.Fatal("source drift signed old policy")
	}
	if _, e := ApprovePrivacyPolicy(ctx, pool, newEpoch, tenant, project, second.ID, second.Hash, second.SchemaHash); e == nil {
		t.Fatal("source drift retained approval")
	}
	exec(`UPDATE pgws_control.authority SET reconciled=false`)
	if _, e := RevokePrivacyPolicy(ctx, pool, newEpoch, tenant, project, second.ID, second.Hash); e != nil {
		t.Fatal("fenced authority could not revoke", e)
	}
	exec(`UPDATE pgws_control.authority SET epoch=$1,reconciled=true`, epoch)
	var audit string
	if err = pool.QueryRow(ctx, `SELECT string_agg(safe_metadata::text,'') FROM pgws_control.audit_events WHERE action LIKE 'privacy.%'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, base64.StdEncoding.EncodeToString(key)) || strings.Contains(audit, hex.EncodeToString(key)) || strings.Contains(audit, "review-key") {
		t.Fatal("policy audit exposed keys or document content")
	}
}
