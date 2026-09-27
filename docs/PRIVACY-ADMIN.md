# Operator policy decisions

`pgwsd` now supports private policy creation, review, signing and revocation using
an operator management-database login. API and worker roles have read access to
scoped bindings but cannot author or approve policies. The agent lifecycle API
still rejects logical workspace admission and hides logical baselines.

## Create and review

`pgwsd policy-create PRIVATE_REVIEW.json` accepts a mode-0600 file containing
`transform_key_file` and `draft`. The draft contains:

- `tenant_id`, `project_id`, a new `policy_id`, and positive `revision`.
- `source_id`, `source_epoch`, `system_id` and `timeline` from source discovery.
- `schema` and a complete `policy`, using the private logical compiler contract.

The policy includes its schema hash, transform key reference and an explicit
action for every field. `pgws-logical discover` supplies the qualified source
schema. The operator reviews the schema and rules before creating the draft.
The key file contains a base64 32-byte key and must be private. Compilation runs
before the management transaction. Only the key fingerprint is stored, alongside
the immutable source binding, schema, rules and compiled plan hash.

The management source must have matching lineage and an approved endpoint/secret
reference pair. This check locks those records while recording the decision;
it does not contact the source. Actual schema inspection and later activation
validation are separate responsibilities. A policy document supplied by an
operator is not proof that a live source still has that schema.

Repeating creation with the same ID and canonical content returns the existing
record. A changed key, schema, rules or source binding cannot reuse that ID.
Creation produces a draft. It does not approve raw copying or expose a baseline.

```sh
pgwsd policy-create /private/review.json
pgwsd policy-show --tenant TENANT --project PROJECT --id POLICY
pgwsd policy-approve --tenant TENANT --project PROJECT --id POLICY \
  --hash REVIEWED_PLAN_SHA256 --schema-hash REVIEWED_SCHEMA_SHA256
```

Mutation commands require `PGWS_AUTHORITY_EPOCH`. Creation and approval require a
reconciled matching authority. Approval binds that authority epoch and operator
identity. Repeated approval within the same epoch retains its timestamp. A new
authority epoch requires explicit reapproval, and source lineage changes require
a new policy binding. The database prevents content mutation and revival of a
revoked policy.

## Signed decision receipts

Set `PGWS_SIGNING_KEY_FILE` to the authority's private base64 Ed25519 key file,
then run:

```sh
pgwsd policy-sign --tenant TENANT --project PROJECT --id POLICY \
  --hash REVIEWED_PLAN_SHA256
```

The signer locks the current authority, policy, binding and source approval while
constructing the receipt. Draft, revoked, stale-epoch or changed-source policies
cannot be signed. The signature has its own protocol domain and binds tenant,
project, policy, plan/schema hashes, source lineage, key fingerprint and compiler
version. Receipts live for at most 90 seconds. Verification requires the complete
expected binding and pinned public key, rejects ambiguous JSON, and subtracts
five seconds from expiry for conservative clock handling.

These are policy decision receipts. Seed completion, integrity validation,
current schema verification and endpoint readiness still require their own
evidence. The private host path now enforces these receipts as described below.
A signed receipt does not enable public sanitized access.

## Private host enforcement

The optional `approval` member of `host.LogicalCandidate` holds the complete
expected binding, a base64 `public_key`, an absolute `receipt_file` and
`runtime_sha256` from `runtime.LogicalRuntimeDigest`. The digest covers the
exact container ID and specification. Its authority, tenant, project and source
lineage must match that runtime. For named baseline candidates, the runtime's
workspace/generation identifies the baseline and its separate logical source
fields identify the source epoch. See LOGICAL-OWNERSHIP.md. Keep the receipt in a private host-owned
0700 directory outside every container mount. The signing private key never
belongs on the ingestion host or in its container.

After reviewing and signing the policy, transfer its private JSON output to the
host through the operator's existing trusted channel. These Linux root commands
install or renew that receipt and run the approved connector:

```sh
pgws-logical-watchdog approve /private/candidate.json /private/signed-policy.json
pgws-logical-watchdog seed /private/candidate.json
pgws-logical-watchdog run /private/candidate.json
```

Start the separate `watch` process after the slot ownership receipt appears,
including during an unfinished initial seed. Management must issue a fresh
signed decision before the current receipt expires. The installer serializes
renewals, accepts exact retries without extending their deadline, and rejects
older decisions or renewal after expiry. Automatic delivery for an operator-pinned
private candidate is available through the relay described below.

Receipts retain Linux boot identity and CLOCK_BOOTTIME deadlines. Process restart,
wall-clock rollback or system suspend cannot extend an installed permission.
A host reboot invalidates the receipt. Runtime monitoring checks every 250 ms;
the separate watchdog checks every two seconds and can remove a paused container.
Expiry writes a terminal stop and removes the exact runtime. Validated source
cleanup follows the ownership rules in LOGICAL-SUPERVISION.md. Retained data is
not deleted and the same generation cannot restart on a later signature.

The host injects the verified binding into the pinned connector. Before target
initialization, the connector checks actual source identity, compiled plan,
schema, compiler version and transformation-key fingerprint. The legacy private
`pgws-logical` and `OCI.Ingest` lab paths remain explicit unsigned administrator
tools. Public admission remains closed and does not route through those paths.

## Automatic private renewal

Run a dedicated relay on the ingestion host as root:

```sh
pgws-logical-watchdog relay /private/candidate.json /private/approval-rpc.token
```

The RPC token must contain at least 32 random characters in a 0600 file. The
relay listens on `<receipt_file>.sock`, outside all container mounts, with an
exclusive process lock and socket mode 0600. It accepts only that candidate's
exact runtime digest, identity and signed binding. It cannot create a candidate,
run its seed or clear a terminal stop. Keep the separate `watch` process running.

On the management/operator side, `pgwsd policy-renew PRIVATE_RENEWAL.json` uses
the existing operator database login, external epoch and signing-key file. Its
private JSON document contains `candidate`, `socket` and `token_file`. Copy these
candidate fields from the reviewed host configuration:

| Renewal field | Host candidate field |
| --- | --- |
| `candidate.binding` | `approval.binding` |
| `candidate.identity` | `container.spec.identity` |
| `candidate.runtime_sha256` | `approval.runtime_sha256` |
| `socket` | Path to the private relay socket or its trusted Unix forwarding channel |
| `token_file` | Local private file containing the relay RPC token |

Every 20 seconds the process checks the current authority, policy and source
approval, commits a signed decision and then contacts the host with a ten-second
attempt bound. No management transaction stays open during host I/O. The relay
receives signed decisions only; signing keys and management logins stay on the
management side. Remote deployment must supply a trusted private forwarding
channel; the service does not expose a public renewal endpoint.

Revocation or management failure prevents new signatures. The last installed
decision expires within its 90-second signed bound, with the host's conservative
five-second allowance. Existing expiry enforcement stops the runtime and its
provable slot. This is bounded revocation, not an immediate push stop. A failed
delivery cannot extend a deadline, and a late successful delivery cannot revive
an expired or terminal generation.

## Revocation

```sh
pgwsd policy-revoke --tenant TENANT --project PROJECT --id POLICY \
  --hash REVIEWED_PLAN_SHA256
```

Revocation records a permanent decision, blocks affected active/candidate
baselines and revokes credentials across their snapshot/workspace lineage in one
management transaction. Existing serving renewal and connected revocation checks
reject that policy. Host credential delivery occurs after commit through the
existing reconciliation loop. Other policies remain unchanged. Repeating
revocation retains the original timestamp. Revocation remains available while
issuance is fenced, provided the external authority epoch still matches.

This command revokes access authority; it does not physically erase retained
copies or backups. Audit metadata contains policy hashes and operator identity,
not transformation keys or document contents.

## Validation and remaining integration

PostgreSQL 14 and pinned 18.6 management tests cover canonical retries, changed
key/hash/schema rejection, project scoping, worker privilege rejection, immutable
bindings, approval/revocation, isolated lineage credential revocation, serving
renewal rejection and explicit reapproval after authority changes. Signature
tests cover every binding field, wrong keys, protocol substitution, duplicate
fields and clock bounds. Actual PostgreSQL 14 CLI smoke covers creation, exact
retry, approval, signing, revocation and refusal to sign or reapprove revoked
policies. Linux tests cover durable permit retry, renewal ordering, boot/counter
changes and terminal expiry. The host lab covers the actual approval command,
wrong-plan rejection before target initialization, expiry during CDC and separate
watchdog removal of a paused container with owned-slot cleanup. The policy
commands remain administrator tools.

An actual Linux test launched the operator signer, root relay, CDC and separate
watchdog. Two periodic approvals arrived; revoking the management policy stopped
CDC and retired the owned slot in 86.03 seconds. SQL tests verify that host
delivery occurs after commit, changed bindings never reach the host, failed
delivery can retry and revoked policies never receive another decision.

Discovery-run persistence, classifier decision provenance,
generation cutover, live policy-specific endpoint revocation and the full
sanitized release campaign remain open.
