<h1 align="center">PGWS</h1>

<p align="center">
  <strong>Disposable, writable PostgreSQL workspaces for AI agents</strong><br>
  A continuously replicated baseline, copy-on-write clones in seconds, and one isolated database per agent task.
</p>

<p align="center">
  <a href="https://github.com/Ffinnis/pgws/actions/workflows/test.yml"><img src="https://github.com/Ffinnis/pgws/actions/workflows/test.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/Go-1.25-00ADD8.svg?logo=go&logoColor=white" alt="Go 1.25">
  <img src="https://img.shields.io/badge/PostgreSQL-18-336791.svg?logo=postgresql&logoColor=white" alt="PostgreSQL 18">
  <img src="https://img.shields.io/badge/status-experimental-orange.svg" alt="Status: experimental">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="docs/RFC-0001.md">RFC</a>
</p>

> [!WARNING]
> PGWS is an early implementation of [RFC-0001](docs/RFC-0001.md). The physical PostgreSQL 18 path works end to end on a single Linux host, but it is **not production-ready**: deployment networking, power-loss qualification, the full security matrix and the RFC's release gates are still open. Workspaces contain **real copies of the source data**; the sanitized (masked) mode is deliberately disabled. See [project status](#project-status).

---

## Why PGWS?

AI agents are most useful when they can work against a real database: run migrations, try queries, reproduce bugs and write data. Pointing them at production is dangerous, and shared staging databases drift and collide.

PGWS gives each agent task its own PostgreSQL database:

- **Real data, current state.** Workspaces are cloned from a baseline that streams from your source database, so they reflect recent data, and you can require that a specific committed write is included.
- **Fast and cheap.** Clones are ZFS copy-on-write snapshots. In a [1 GiB test](docs/ONE-GIB-RESULTS.md), three concurrent clones were ready in 2.2–5.3 s and used about 2.8 MiB of extra space before writes.
- **Isolated and disposable.** Each workspace is a separate PostgreSQL instance with its own TLS credentials and TTL. Agents get an owner role for ordinary DDL and writes, and the source never sees any of it. Pause, reset or delete it when the task is done.

## Features

- **Streaming baselines** — physical replication from PostgreSQL 18 over a Unix socket or a pinned-address TLS broker, with verified base backups and a persistent replication slot.
- **Freshness control** — request the `latest` snapshot, a specific `snapshot`, or `at_least` a signed source barrier, so a workspace is guaranteed to contain a write you just committed.
- **Per-workspace access** — generated owner/reader roles, SCRAM authentication and TLS `verify-full`. Imported source logins are disabled, and passwords are stored encrypted.
- **Full lifecycle** — create, pause, resume, reset to a fresh generation, extend TTL and delete, all through an idempotent HTTP API.
- **Independent safety processes** — a separate ingress guard closes SQL sessions when a lease, workspace or credential expires; a watchdog stops expired runtimes and protects source WAL and pool space.
- **Crash safety** — idempotency keys, generation checks, host fences and durable operations. Creation, reset and reseed are tested against `SIGKILL` at each stage.
- **Quotas** — per-project ZFS limits covering baselines, snapshots and clones, plus memory admission and a pool free-space floor.
- **Clients** — a JSON CLI, dependency-free Python and TypeScript SDKs, and an [OpenAPI 3.1 contract](contracts/openapi.yaml).

## How it works

```mermaid
flowchart LR
    subgraph Source
        SRC[(PostgreSQL 18<br>source)]
    end

    subgraph Host["PGWS host (Linux + OpenZFS)"]
        BASE[(Baseline<br>streaming standby)]
        SNAP[/ZFS snapshots/]
        W1[(Workspace A)]
        W2[(Workspace B)]
        GUARD[Ingress guard<br>TLS · SCRAM · leases]
        WD[Watchdog<br>TTL · WAL · pool]
    end

    subgraph Control["Control plane"]
        API[pgwsd API] --- MGMT[(Management DB)]
        WORKER[pgwsd worker] --- MGMT
    end

    SRC -- physical replication --> BASE
    BASE -- capture --> SNAP
    SNAP -- copy-on-write clone --> W1 & W2
    WORKER -- host RPC --> BASE
    W1 & W2 --- GUARD
    AGENT([AI agent]) -- CLI / SDK --> API
    AGENT -- SQL over TLS --> GUARD
```

1. **Register a source.** PGWS inspects the source, takes a verified base backup and keeps a baseline replaying WAL continuously.
2. **Capture a snapshot.** On request, the host captures a ZFS snapshot at a known replay position, optionally waiting for a signed barrier.
3. **Create a workspace.** The snapshot is cloned, recovered and promoted in a sandboxed runtime with no network, no source credentials and no management access. Access is hardened and a real SQL probe must pass before the workspace is reported ready.
4. **Connect.** The agent requests short-lived credentials and connects through the ingress guard with TLS `verify-full`.
5. **Clean up.** Pause, reset or delete the workspace, or let its TTL expire. Expiry is enforced on the host even if the control plane is unavailable.

The full design, including failure handling and security model, is in [RFC-0001](docs/RFC-0001.md).

## Quick start

The quickest way to try PGWS is the disposable local installation. It creates its own source database with a `notes` table, a management database, an 8 GiB file-backed ZFS pool, a streaming baseline and an example workspace with a one-hour TTL.

**Requirements**

- Go 1.25+ and Python 3.10+
- A Linux environment with Docker, OpenZFS, Python 3, OpenSSL and systemd, with this repository mounted at the same path. On macOS, use a [Lima](https://lima-vm.io) VM named `pgws-lab` (tested on Ubuntu 24.04 ARM64 with OpenZFS 2.2.2).
- `psql` on the host, for connecting to workspaces

The launcher does not install VM dependencies or format physical disks.

```sh
git clone https://github.com/Ffinnis/pgws.git
cd pgws

python3 scripts/dev.py up          # build, start services, create the example workspace
python3 scripts/dev.py status      # show baseline and workspace IDs
python3 scripts/dev.py cli baselines
```

The API listens on `http://127.0.0.1:18870`. Client settings are written to `.local/dev-client.json` and the SQL CA certificate to `.local/dev-ca.crt` (both mode 0600 and ignored by Git).

Get credentials for the example workspace and connect:

```sh
echo '{"expected_generation":1,"role":"owner","ttl_seconds":900}' > credentials.json
python3 scripts/dev.py cli credentials --id WORKSPACE_UUID --file credentials.json --key my-credential
```

Use the returned `endpoint`, `username` and `password` with `sslmode=verify-full` and `sslrootcert` set to the absolute path of `.local/dev-ca.crt`.

When you are done:

```sh
python3 scripts/dev.py down        # removes this installation's pool, containers and state
```

See [LOCAL-SERVICE.md](docs/LOCAL-SERVICE.md) for upgrades, service logs and details.

## Usage

### Python

```python
import json
from pathlib import Path
from pgws import Client  # PYTHONPATH=sdk/python

config = json.loads(Path(".local/dev-client.json").read_text())
client = Client(config["url"], config["project_id"], config["token"])

baseline = client.baselines()["items"][0]["id"]
created = client.create(baseline, "task-42", key="create-task-42", ttl=3600)
client.wait(created["operation"]["id"])

workspace = client.get(created["workspace"]["id"])
credential = client.credentials(workspace["id"], workspace["generation"], key="credential-task-42")
# Pass credential["endpoint"], ["username"] and ["password"] to your PostgreSQL driver. Never log the password.

client.wait(client.delete(workspace["id"], workspace["generation"], key="delete-task-42")["id"])
```

### TypeScript

```typescript
import { Client } from "./sdk/typescript/index.mjs";

const client = new Client({ url, projectId, token });
const created = await client.create({
  baseline_id: baselineId,
  task_id: "task-42",
  freshness: { mode: "latest" },
  resource_profile: "small",
  ttl_seconds: 3600,
}, "create-task-42");
await client.wait(created.operation.id);
const workspace = await client.get(created.workspace.id);
```

### Read-your-writes freshness

To guarantee a workspace contains a write your application just committed, create a barrier after the commit and pass it when creating the workspace:

```python
barrier = client.barrier(source_id, key="barrier-task-42")
created = client.create(baseline, "task-42", key="create-task-42", ttl=3600,
                        freshness={"mode": "at_least", "barrier_token": barrier["barrier_token"]})
```

### CLI

All output is JSON, and failures exit non-zero. Mutating commands require an explicit `--key`; reuse the same key when retrying after a network error.

```sh
pgws create    --file request.json --key create-task-42
pgws get       --id WORKSPACE_UUID
pgws action    --id WORKSPACE_UUID --file action.json --key pause-task-42
pgws wait      --id OPERATION_UUID --timeout 2m
pgws delete    --id WORKSPACE_UUID --generation 1 --key delete-task-42
pgws usage
```

Request bodies are defined in the [OpenAPI contract](contracts/openapi.yaml). More SDK details are in [sdk/README.md](sdk/README.md).

## Running the service manually

<details>
<summary>Migrate, bootstrap and start the API and worker against your own management database</summary>

You need a separate, empty management database. Migrations create the `pgws_control` schema and the `pgws_runtime` role, so the migration user needs permission to create roles. Applied migrations are checksum-verified and cannot be modified.

```sh
make build

export PGWS_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:5432/pgws?sslmode=disable'
./bin/pgwsd migrate

mkdir -p .local && chmod 700 .local
umask 077
./bin/pgwsd bootstrap > .local/bootstrap.json
```

Bootstrap runs once. It creates a tenant, a project, an authority epoch and an administrator token valid for 24 hours. The output contains a secret.

```sh
export PGWS_AUTHORITY_EPOCH=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["authority_epoch"])')
export PGWS_PROJECT_ID=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["project_id"])')
export PGWS_TOKEN=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["token"])')

./bin/pgwsd serve     # API on 127.0.0.1:8080
./bin/pgwsd worker    # in a second terminal
```

`/healthz` checks the process; `/readyz` checks the management authority and whether a physical backend is configured. It does not report the readiness of any individual workspace.

Run the API and worker under separate login roles without `SUPERUSER`, `BYPASSRLS` or table ownership, as members of `pgws_runtime` and `pgws_worker` respectively. The API is loopback-only; external access requires a TLS reverse proxy. Token administration is described in [TOKEN-ADMIN.md](docs/TOKEN-ADMIN.md).

</details>

## Project status

PGWS follows the work packages in [RFC-0001](docs/RFC-0001.md). Detailed status and remaining acceptance work are tracked in [IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

| Area | Status |
| --- | --- |
| Physical PG18 ingestion, streaming baselines, freshness barriers | ✅ Implemented and tested on real PostgreSQL 18.6 + OpenZFS |
| Workspace lifecycle, credentials, ingress guard, watchdog | ✅ Implemented and tested with separate processes and `SIGKILL` faults |
| Project quotas, usage history, management recovery | ✅ Implemented and tested |
| Python / TypeScript SDKs, CLI | ✅ Implemented; not yet published as packages |
| Production deployment, networking, power-loss and full security qualification | 🚧 Open |
| 1 TB / 14-workspace benchmark | 🚧 Open (a [1 GiB run](docs/ONE-GIB-RESULTS.md) has passed) |
| Sanitized (masked) workspaces | 🔒 Private candidate only; public mode disabled |
| Column classifier | 🔒 Runtime only; no trained weights, review-only |

**Current limits:** one application database per source; a conservative set of supported PostgreSQL features (no unlogged tables, foreign servers, subscriptions, custom C functions, event triggers or unapproved extensions); single host; loopback API.

## Documentation

| Topic | Documents |
| --- | --- |
| Design | [RFC-0001](docs/RFC-0001.md) · [Implementation status](docs/IMPLEMENTATION.md) · [Validation](docs/VALIDATION.md) |
| Running PGWS | [Local service](docs/LOCAL-SERVICE.md) · [Source TLS](docs/SOURCE-TLS.md) · [Token administration](docs/TOKEN-ADMIN.md) · [SDKs](sdk/README.md) |
| Operations | [Source reseed](docs/SOURCE-RESEED.md) · [Management recovery](docs/MANAGEMENT-RECOVERY.md) · [Storage accounting](docs/STORAGE-ACCOUNTING.md) · [Usage](docs/USAGE.md) |
| Safety | [Serving safety](docs/SERVING-SAFETY.md) · [Crash recovery](docs/CRASH-RECOVERY.md) |
| Performance | [Benchmark method](docs/BENCHMARK.md) · [1 GiB results](docs/ONE-GIB-RESULTS.md) |
| Sanitized ingestion (private) | [Logical adapter](docs/LOGICAL-ADAPTER.md) · [Barriers](docs/LOGICAL-BARRIERS.md) · [Ownership](docs/LOGICAL-OWNERSHIP.md) · [Supervision](docs/LOGICAL-SUPERVISION.md) · [Privacy administration](docs/PRIVACY-ADMIN.md) |
| Classifier (review-only) | [Bounded discovery](docs/BOUNDED-DISCOVERY.md) · [Runtime](docs/CLASSIFIER-RUNTIME.md) · [Offline training](ml/column-classifier/README.md) |
| Development | [Physical lab](docs/PHYSICAL-LAB.md) · [Maintainability review](docs/MAINTAINABILITY-REVIEW.md) |

## Repository layout

| Path | Contents |
| --- | --- |
| `cmd/pgwsd` | Migrations, bootstrap, HTTP API server and worker |
| `cmd/pgws` | CLI |
| `cmd/pgws-host`, `cmd/pgws-guard`, `cmd/pgws-watchdog` | Privileged host, TLS ingress guard and independent resource watchdog |
| `cmd/pgws-physical`, `cmd/pgws-logical` | Administrator tools for physical and (private) logical ingestion |
| `internal/control` | Request admission, authorization, lifecycle, queueing and fencing |
| `internal/physical` | Source discovery, verified backup, recovery and promotion |
| `internal/storage/zfs` | Baseline, snapshot and clone management |
| `internal/lease` | Ed25519-signed serving leases and the fencing journal |
| `internal/migrations` | Management schema migrations |
| `contracts` | OpenAPI contract, management SQL contract and classifier specification |
| `sdk` | Python and TypeScript clients |

## Development

```sh
make build            # build all binaries into bin/
make test             # go test -race ./...
make sdk-test         # Python and TypeScript SDK tests
make integration      # SQL/HTTP tests against a disposable local PostgreSQL cluster
make physical-lab     # PostgreSQL 18 recovery tests in isolated Docker containers
make zfs-lab          # ZFS tests in the pgws-lab VM
make host-lab         # end-to-end tests with real PG18, ZFS and separate daemons
```

`make integration` needs `initdb`, `pg_ctl` and `postgres` from a single installation on `PATH`; it has passed on PostgreSQL 14.20 and 18.6. Every test suite creates and removes its own databases, containers and pools, and never touches existing databases or physical disks.

Contract checks:

```sh
python3 -m pip install -r contracts/requirements.txt
python3 contracts/validate_contracts.py
python3 contracts/classifier/validate.py
```

## Contributing

Contributions are welcome. Before changing behavior, read [RFC-0001](docs/RFC-0001.md) and [IMPLEMENTATION.md](docs/IMPLEMENTATION.md), and keep the documented scope and evidence current. For Go changes, run `go test -race ./...` and `go vet ./...`; for SQL, authorization, API or lifecycle changes, also run `python3 scripts/integration.py`. Please describe in your pull request which suites you ran and on which platform.

## Security

Workspaces hold real copies of source data, so treat them with the same care as the source. Please report suspected vulnerabilities privately to the maintainers rather than in a public issue.

## License

PGWS is licensed under the [Apache License 2.0](LICENSE).
