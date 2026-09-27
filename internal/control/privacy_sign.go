package control

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/policyapproval"
)

// SignPrivacyPolicy freezes the current approval while signing its bounded
// receipt. Source inspection and host publication are separate operations.
func SignPrivacyPolicy(ctx context.Context, pool *pgxpool.Pool, epoch, tenant, project, id, hash string, key ed25519.PrivateKey) (policyapproval.Claims, string, error) {
	var empty policyapproval.Claims
	if !ValidID(tenant) || !ValidID(project) || !ValidID(id) || len(hash) != 64 || len(key) != ed25519.PrivateKeySize {
		return empty, "", errors.New("explicit policy signing scope, hash and key required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return empty, "", err
	}
	defer tx.Rollback(ctx)
	if err = tokenAuthority(ctx, tx, epoch, true); err != nil {
		return empty, "", err
	}
	var keyOK bool
	if err = tx.QueryRow(ctx, `SELECT signing_public_key IS NULL OR signing_public_key=$1 FROM pgws_control.authority WHERE singleton`, key.Public().(ed25519.PublicKey)).Scan(&keyOK); err != nil || !keyOK {
		return empty, "", errors.New("policy signing key differs from recovered authority")
	}
	claims := policyapproval.Claims{Binding: policyapproval.Binding{Authority: epoch, Tenant: tenant, Project: project, Policy: id, PlanHash: hash}}
	var approved bool
	err = tx.QueryRow(ctx, `SELECT p.state='approved' AND b.approval_epoch=$4::uuid AND p.policy_hash=$5,
 b.source_id::text,b.source_epoch,b.system_identifier,b.timeline,b.schema_hash,b.key_fingerprint,b.compiler_version,p.approved_at
 FROM pgws_control.privacy_policies p JOIN pgws_control.privacy_policy_bindings b ON (b.tenant_id,b.project_id,b.policy_id)=(p.tenant_id,p.project_id,p.id)
 WHERE p.tenant_id=$1 AND p.project_id=$2 AND p.id=$3 FOR SHARE OF p,b`, tenant, project, id, epoch, hash).Scan(&approved, &claims.Source, &claims.SourceEpoch, &claims.SystemID, &claims.Timeline, &claims.SchemaHash, &claims.KeyFingerprint, &claims.Compiler, &claims.ApprovedAt)
	if err != nil || !approved {
		return empty, "", errors.New("policy has no matching current approval")
	}
	draft := PolicyDraft{Tenant: tenant, Project: project, Source: claims.Source, SourceEpoch: claims.SourceEpoch, SystemID: claims.SystemID, Timeline: claims.Timeline}
	if err = lockPolicySource(ctx, tx, draft); err != nil {
		return empty, "", err
	}
	claims.ApprovedAt = claims.ApprovedAt.UTC()
	claims.IssuedAt = time.Now().UTC()
	claims.ExpiresAt = claims.IssuedAt.Add(90 * time.Second)
	token, err := policyapproval.Sign(key, claims)
	if err != nil {
		return empty, "", err
	}
	if err = policyAudit(ctx, tx, tenant, project, id, "privacy.sign", hash); err != nil {
		return empty, "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, "", errors.New("policy signing decision commit unconfirmed")
	}
	return claims, token, nil
}
