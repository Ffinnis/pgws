# PGWS

PostgreSQL workspaces for AI agents. PGWS keeps a PostgreSQL baseline up to date through replication and gives each agent its own independent, writable copy-on-write workspace.

This is the initial implementation of [RFC-0001 revision 0.3](docs/RFC-0001.md), written in Go 1.25 with PostgreSQL and an HTTP/JSON API. The repository includes a copy of the RFC and its contracts.

## Status

The physical PostgreSQL 18 flow works end to end: source registration, a streaming baseline, ZFS clone creation through the API, `latest`, signed barriers and `at_least`, TLS connections with per-workspace credentials, pause/resume, reset, TTL extension and deletion. Imported source logins are disabled. Passwords kept for response replay are stored encrypted in the management database.

Real PostgreSQL 18.6, OpenZFS and Docker have been tested in a Linux VM. The end-to-end test runs the API, worker, host, ingress guard and CLI as separate processes. An independent guard closes existing SQL connections when a serving lease, workspace or credential expires. A separate watchdog monitors source WAL and stops expired runtimes.

Each project gets a shared ZFS limit covering baselines, snapshots and clones. The watchdog also closes access when the pool runs low on space. Counters and the exact meaning of each limit are described in [STORAGE-ACCOUNTING.md](docs/STORAGE-ACCOUNTING.md).

This is a working physical implementation for a dedicated local installation. It supports approved Unix-socket sources and TCP sources through a TLS broker with pinned addresses, one application database, and a conservative list of PostgreSQL features. TCP setup is described in [SOURCE-TLS.md](docs/SOURCE-TLS.md). Sanitized ingestion, classifier training and the RFC's production acceptance gates are not complete. The exact state and limitations are tracked in [IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

## Persistent local installation

```sh
python3 scripts/dev.py up
python3 scripts/dev.py status
python3 scripts/dev.py cli baselines
```

Upgrade a running installation while keeping its data: `python3 scripts/dev.py upgrade`.
End-to-end upgrade check: `python3 scripts/dev_upgrade_check.py`.
Create a new example workspace after the TTL expires: `python3 scripts/dev.py workspace`.

The installation creates its own source and management PostgreSQL 18 databases, a ZFS pool and an example workspace with a one-hour TTL. The API listens on `http://127.0.0.1:18870`. The API and worker run as separate unprivileged Linux users. `python3 scripts/dev.py down` removes this installation's resources. Connection setup, TLS and limitations are described in [LOCAL-SERVICE.md](docs/LOCAL-SERVICE.md).

For programmatic access, use the [Python and TypeScript SDKs](sdk/README.md).

To measure concurrent workspace creation through the API and check SQL isolation:
`python3 scripts/benchmark.py --baseline BASELINE_UUID --workspaces 2 --rounds 2`.
The method and its limits are described in [BENCHMARK.md](docs/BENCHMARK.md).

## Verification

```sh
make build
make test
make sdk-test
make integration
make physical-lab
make zfs-lab
make host-lab
```

`make integration` needs `initdb`, `pg_ctl` and `postgres` from a single installation on PATH. The script creates a private temporary cluster without TCP, runs the HTTP/SQL tests with the race detector, then stops and removes the cluster. It has been run locally against PostgreSQL 14.20 and 18.6 (Homebrew).

`make physical-lab` needs Docker. It runs the management tests and physical recovery in separate PostgreSQL 18 containers with a pinned digest, networking disabled and temporary storage. Existing databases and containers are never used. Details and the `pgws-physical` commands are in [PHYSICAL-LAB.md](docs/PHYSICAL-LAB.md).

Static checks for the source contracts:

```sh
python3 -m pip install -r contracts/requirements.txt
python3 contracts/validate_contracts.py
python3 contracts/classifier/validate.py
```

`make zfs-lab` and `make host-lab` use a dedicated Lima VM, `pgws-lab`, with Linux, OpenZFS and Docker. Each run creates its own file-backed ZFS pool and temporary databases, then removes them. `host-lab` also exercises the service as separate processes. The tests never use user databases or physical disks.

## Running the API

You need a separate, empty management database. Migrations create the `pgws_control` schema and the `pgws_runtime` role, so the migration user needs permission to create roles. Applied SQL files cannot be changed afterwards: the runner verifies each migration's SHA-256.

```sh
export PGWS_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:5432/pgws?sslmode=disable'
./bin/pgwsd migrate
mkdir -p .local
chmod 700 .local
umask 077
./bin/pgwsd bootstrap > .local/bootstrap.json
```

Bootstrap runs once. It creates a tenant, a project, an authority epoch and an administrator token valid for 24 hours. The output file contains a secret and is excluded from Git. Running bootstrap again does not change an existing or restored authority.

```sh
export PGWS_AUTHORITY_EPOCH=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["authority_epoch"])')
export PGWS_PROJECT_ID=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["project_id"])')
export PGWS_TOKEN=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["token"])')
./bin/pgwsd serve
```

The API listens on `127.0.0.1:8080`. `/healthz` checks the process; `/readyz` checks the management authority and reports whether a physical backend is configured. This checks the API configuration, not the readiness of any particular workspace. External access requires a TLS reverse proxy. The project currently targets local development; production login roles and OIDC are not implemented yet. Commands for issuing, listing, rotating and revoking API tokens are described in [TOKEN-ADMIN.md](docs/TOKEN-ADMIN.md).

In another terminal, with the same variables:

```sh
./bin/pgws baselines
./bin/pgwsd worker
```

Run the API and worker under separate login roles without `SUPERUSER`, `BYPASSRLS` or table ownership, as members of `pgws_runtime` and `pgws_worker` respectively. Only the migration owner runs migrations and bootstrap. HTTP handlers drop to `pgws_runtime` inside every transaction. The local installation creates these separate roles automatically.

## CLI

All output is JSON. An API error or a failed operation produces a non-zero exit code. The CLI does not follow HTTP redirects with a bearer token. Mutating requests require an explicit `--key`; reuse the same key when retrying after a network failure.

```sh
./bin/pgws create --file request.json --key create-task-42
./bin/pgws get --id WORKSPACE_UUID
./bin/pgws action --id WORKSPACE_UUID --file action.json --key pause-task-42
./bin/pgws operation --id OPERATION_UUID
./bin/pgws wait --id OPERATION_UUID --timeout 2m
./bin/pgws delete --id WORKSPACE_UUID --generation 1 --key delete-task-42
```

`source`, `barrier` and `credentials` take JSON through `--file`. Request formats are defined in the [OpenAPI contract](contracts/openapi.yaml). A finished wait does not delete the workspace. Do not send an example request with a made-up snapshot: ingestion must create and confirm the snapshot first.

Administrator source recovery is available through `pgws source-get` and `pgws source-action`. See [source generations](docs/SOURCE-RESEED.md) for reseed admission, preserved workspace lineage and reconciliation restrictions.

Usage history is available through `pgws usage` and the `usage` method in both SDKs. The host keeps each batch until the management database acknowledges it, and redelivery does not create duplicates. Semantics and limitations are in [USAGE.md](docs/USAGE.md).

## Management recovery

The management database is restored with `pgwsd recovery-init/begin/finish` and `pgws-host recover`. Old grants are revoked, processes are stopped and data stays closed on disk. Real PostgreSQL 18 backup/restore, crashes during the procedure, and creating a new working database after access is re-approved have been tested. The procedure is described in [MANAGEMENT-RECOVERY.md](docs/MANAGEMENT-RECOVERY.md).

## Private sanitized ingestion and classifier (not public)

`pgws-logical` supports a private sanitized candidate: schema discovery, a consistent initial load and a change stream with data transformation. Replay after a lost ACK and stopping on an unknown field have been tested. Public sanitized workspaces remain disabled; the supported profile and commands are in [LOGICAL-ADAPTER.md](docs/LOGICAL-ADAPTER.md).

The private loader runs inside the baseline container. A separate watchdog checks source WAL, stops the container and removes only a confirmed slot. A frozen initial load, CDC and ZFS snapshot recovery have been tested. Details and remaining limitations are in [LOGICAL-SUPERVISION.md](docs/LOGICAL-SUPERVISION.md). The adapter also supports [committed marker barriers](docs/LOGICAL-BARRIERS.md).

The administrator commands `pgwsd policy-create/show/approve/sign/revoke` store a verifiable policy binding and sign the decision, but do not open public sanitized databases. The private logical loader supports automatic approval renewal: `pgwsd policy-renew` delivers signatures to a separate `pgws-logical-watchdog relay`. Revoking a policy stops renewal and stops CDC within the lifetime of the last permit. The workflow is described in [PRIVACY-ADMIN.md](docs/PRIVACY-ADMIN.md).

For a future local classifier, `pgws-features` exports features and `pgws-classify` verifies a signed weights file and computes class scores. There are no trained weights yet, and every result requires manual review. The format and limitations are described in [CLASSIFIER-RUNTIME.md](docs/CLASSIFIER-RUNTIME.md). Related workflows: [bounded PostgreSQL discovery](docs/BOUNDED-DISCOVERY.md), [offline training](ml/column-classifier/README.md) and [local model scoring](docs/CLASSIFIER-RUNTIME.md).

None of these tools enable the public sanitized connector.

## Code layout

- `cmd/pgwsd`: migrations, bootstrap, HTTP server and worker.
- `cmd/pgws`: CLI.
- `cmd/pgws-host`, `cmd/pgws-guard`, `cmd/pgws-watchdog`: the privileged host, the TLS ingress guard running as a separate process, and independent resource control.
- `cmd/pgws-physical`: local administrator commands inspect/barrier/seed/recover/stop.
- `cmd/pgws-logical`: private administrator commands discover/seed/run/barrier/status. `internal/privacy` and `internal/logical` contain the policy compiler, exported snapshot and transactional CDC.
- `internal/physical`: discovery, verified backup, disconnected recovery and replay/promotion evidence.
- `internal/storage/zfs`: baseline/snapshot/clone creation, holds, ownership/GUID checks and non-recursive clone deletion.
- `internal/control`: transactional request admission, permissions, lifecycle, queueing and attempt fencing.
- `internal/migrations`: the RFC's initial SQL schema and the permissions/API migrations.
- `internal/lease`: Ed25519 signatures, serving-lease checks, monotonic deadlines and a file-based fencing journal with fsync and process locking. Used by the worker and the separate ingress guard.
- `contracts`: the RFC contracts, including the classifier specification.

Planned work for WP-01 through WP-12, current limitations and the next acceptance tests are listed in [IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
