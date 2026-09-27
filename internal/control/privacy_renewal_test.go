package control

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/lease"
	"pgws/internal/policyapproval"
)

type policyRelayFixture func(context.Context, Task, string) error

func (f policyRelayFixture) ApproveLogical(ctx context.Context, t Task, token string) error {
	return f(ctx, t, token)
}

func testPolicyRenewal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, b policyapproval.Binding, key ed25519.PrivateKey) func() {
	t.Helper()
	plan := PolicyRenewal{Binding: b, Identity: lease.Identity{Epoch: b.Authority, Tenant: b.Tenant, Project: b.Project, Workspace: ID(), Generation: 1, Revision: 1, Host: "private-test-host"}, Runtime: strings.Repeat("a", 64)}
	deliveries := 0
	relay := policyRelayFixture(func(ctx context.Context, task Task, token string) error {
		deliveries++
		if task.Command.Identity != plan.Identity || task.Kind != "approve_logical" {
			t.Fatal("renewal scope changed")
		}
		if _, err := policyapproval.Verify(key.Public().(ed25519.PublicKey), token, b, time.Now()); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `LOCK TABLE pgws_control.authority,pgws_control.privacy_policies,pgws_control.privacy_policy_bindings,pgws_control.sources IN ACCESS EXCLUSIVE MODE NOWAIT`); err != nil {
			t.Fatal("approval delivery held management locks", err)
		}
		return nil
	})
	if err := RenewPrivacyPolicy(ctx, pool, b.Authority, plan, key, relay); err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Binding.KeyFingerprint = strings.Repeat("f", 64)
	if err := RenewPrivacyPolicy(ctx, pool, b.Authority, changed, key, relay); err == nil || deliveries != 1 {
		t.Fatal("changed binding delivered")
	}
	offline := errors.New("fixture lost host response")
	if err := RenewPrivacyPolicy(ctx, pool, b.Authority, plan, key, policyRelayFixture(func(context.Context, Task, string) error { return offline })); !errors.Is(err, offline) {
		t.Fatal("delivery failure swallowed")
	}
	if err := RenewPrivacyPolicy(ctx, pool, b.Authority, plan, key, relay); err != nil || deliveries != 2 {
		t.Fatal("delivery retry", err)
	}
	return func() {
		t.Helper()
		if err := RenewPrivacyPolicy(ctx, pool, b.Authority, plan, key, relay); err == nil || deliveries != 2 {
			t.Fatal("revoked policy delivered fresh authority")
		}
	}
}
