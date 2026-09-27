package control

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/lease"
	"pgws/internal/policyapproval"
)

// PolicyRenewal is an operator's pinned private candidate. It is not a public
// generation registration or permission to change its source/schema/key.
type PolicyRenewal struct {
	Binding  policyapproval.Binding `json:"binding"`
	Identity lease.Identity         `json:"identity"`
	Runtime  string                 `json:"runtime_sha256"`
}

type PolicyRelay interface {
	ApproveLogical(context.Context, Task, string) error
}

func RenewPrivacyPolicy(ctx context.Context, pool *pgxpool.Pool, epoch string, plan PolicyRenewal, key ed25519.PrivateKey, relay PolicyRelay) error {
	id := plan.Identity
	b := plan.Binding
	digest, err := hex.DecodeString(plan.Runtime)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != plan.Runtime || b.Authority != epoch || id.Epoch != epoch || id.Tenant != b.Tenant || id.Project != b.Project || !ValidID(id.Workspace) || id.Generation < 1 || id.Revision < 1 || id.Host == "" || relay == nil {
		return errors.New("invalid pinned policy renewal candidate")
	}
	claims, token, err := SignPrivacyPolicy(ctx, pool, epoch, b.Tenant, b.Project, b.Policy, b.PlanHash, key)
	if err != nil {
		return err
	}
	if claims.Binding != b {
		return errors.New("policy renewal binding changed")
	}
	// SignPrivacyPolicy commits its approval/audit transaction before returning.
	// A failed or lost delivery never extends a receipt on the host by itself.
	document, _ := json.Marshal(Object{"runtime_sha256": plan.Runtime})
	return relay.ApproveLogical(ctx, Task{Kind: "approve_logical", Command: lease.Command{Identity: id}, Document: document}, token)
}
