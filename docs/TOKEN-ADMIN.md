# API token administration

Run these commands with an operator database login in `PGWS_DATABASE_URL` and
the current `PGWS_AUTHORITY_EPOCH`. API and worker roles cannot issue or revoke
API tokens. Apply migrations before using these commands.

```sh
umask 077
./bin/pgwsd token-create --tenant "$TENANT_ID" --project "$PROJECT_ID" --raw --ttl 8h > .local/token.json
./bin/pgwsd token-list --tenant "$TENANT_ID" --project "$PROJECT_ID"
./bin/pgwsd token-rotate --tenant "$TENANT_ID" --project "$PROJECT_ID" --id "$TOKEN_ID" --ttl 8h > .local/replacement-token.json
./bin/pgwsd token-revoke --tenant "$TENANT_ID" --project "$PROJECT_ID" --id "$TOKEN_ID"
./bin/pgwsd principal-revoke --tenant "$TENANT_ID" --project "$PROJECT_ID" --principal "$PRINCIPAL_ID"
```

Create and rotate return a `grant` plus the plaintext `token` once. Keep that
output private. The database stores only its SHA-256 hash. Listings and audit
records contain metadata, never plaintext or token hashes. List pagination uses
`--limit` and the returned `next_cursor` as `--after`.

A new token has no raw or administrator permission unless `--raw` or `--admin`
is supplied. Its lifetime must be between five minutes and 24 hours. Omit
`--principal` to create a new principal. Supplying an existing principal creates
another independent credential for that principal in the requested project.

Rotation atomically creates a replacement and revokes the old token. It retains
the principal and exact permissions; changing privileges requires a separate
create operation. Old bearer authentication stops immediately after commit.
Existing SQL credentials remain authorized while that principal has another
current raw grant, including the replacement token.

Revoking one token does not revoke other tokens belonging to the same principal.
Use `principal-revoke` to revoke all currently issued tokens for that principal
in this tenant/project. This is not a permanent ban on future operator issuance.
The worker delivers SQL credential revocation to the host separately and retries
missing acknowledgements. A settled workspace whose owner loses its raw grant
is terminally stopped with retained disk. See [serving safety](SERVING-SAFETY.md).

Issuance and rotation require reconciled management authority. Revocation remains
available while issuance is fenced, but requires the current epoch. A stale
epoch always fails. Revocation is idempotent. If issuance loses its commit
acknowledgement, inspect metadata and revoke the uncertain grant before issuing
another token; its original secret cannot be recovered.
