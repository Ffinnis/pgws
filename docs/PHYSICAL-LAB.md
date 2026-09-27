# Physical PostgreSQL development

The local administrator tool is a development primitive for an approved source and private clone. It does not register a ready baseline, issue signed API barriers, publish credentials or create a service workspace. Use a dedicated test environment: imported roles and catalogs are retained, and this low-level CLI does not itself install the service isolation boundary. The separately tested host service does.

## Reproducible lab

```sh
make physical-lab
```

Requires Go and Docker. The runner pins `postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae` (observed PostgreSQL 18.6). It builds Linux Go test binaries and runs them as `postgres` in disposable containers with `--network none`, read-only container roots and bounded tmpfs. It cleans up only its own randomly named containers. `evidence/physical-lab.json` records the latest successful run.

The physical tests exercise discovery, manifest verification, source-independent clone writes, temporary slot cleanup, suppression of imported config hooks, refusal to verify missing-WAL recovery, and rejection of unlogged source tables. The overflow fixture keeps 70 source subtransactions open, copies a stopped streaming standby, starts its disconnected clone, confirms standby SQL is unavailable, then promotes it and checks committed data. The host lab now also covers this case with a live ZFS snapshot, source shutdown before clone startup, post-promotion restart and two independent clones. `TestLiveOverflowZFS` additionally verifies terminal source stops after an actual timeline change or system replacement and preservation of a foreign system's same-name slot. The complete power-loss matrix remains open.

Management tests also run against PostgreSQL 18 in a separate container. They exercise actual HTTP handlers and database transactions. These Linux test binaries use `CGO_ENABLED=0`; the race detector runs separately in `make integration` and `make test` on the development machine.

## Local administrator CLI

Build with `make build`. Run PostgreSQL process commands as an unprivileged operating-system user with PostgreSQL 18 binaries and private data/control/socket directories. `inspect` returns a report even when its `blockers` array is nonempty; `seed` rejects such a source.

Example configuration for an administrator-provisioned test source:

```json
{
  "bin_directory": "/usr/lib/postgresql/18/bin",
  "source": {
    "host": "/srv/pgws-lab/source-socket",
    "port": 5432,
    "user": "postgres",
    "database": "postgres",
    "approved_databases": ["postgres"]
  },
  "root": "/srv/pgws-lab/storage",
  "source_id": "10000000-0000-4000-8000-000000000001",
  "generation": 1,
  "max_archive_bytes": 268435456
}
```

All non-template databases must be approved explicitly. `template1` is also inspected. TCP sources require `approved_addresses` and use TLS `verify-full`; configure `root_certificate` and `password_file` for them. See [SOURCE-TLS.md](SOURCE-TLS.md). The password file contains only the password, has mode 0600 and must be a regular file. A Unix socket source uses the local authentication configuration. Inspection needs catalog visibility and physical replication privileges; the fixture uses its own disposable superuser.

```sh
umask 077
./bin/pgws-physical inspect --config source.json > manifest.json
./bin/pgws-physical barrier --config source.json > barrier.json
./bin/pgws-physical seed --config source.json > seed.json
```

After inspection, pin `source.expected_system_id` to the returned `system_id`. Capture the barrier before the one-shot seed if the clone must contain it. A barrier is local evidence, not a signed service freshness token. Source data can be newer than the barrier; this is not point-in-time recovery.

Seed reserves `root/seeds/source_id/generation` exclusively and saves `intent.json`, `manifest.json`, archives, extracted `data` and `verified.json`. It runs `pg_basebackup` in tar mode to avoid materializing source-controlled tablespace paths. It rejects unexpected archives and unsafe tar entries, then runs `pg_verifybackup` before changing configuration. The temporary password file lives outside the backup dataset, in the service control mount or an OS temporary directory for the local CLI, and is removed after the command. Initial-source crash recovery removes its abandoned temporary credentials only after confirming removal of the interrupted runtime. Failed generations remain private for diagnosis and cannot be silently reused. The transfer monitor and expanded-file budget are not filesystem quotas; archives plus extracted data require additional disk space.

Create `recovery.json` with `bin_directory` and a `recovery` object containing:

| Field | Value |
| --- | --- |
| `data_directory` | `data_directory` from `seed.json`, for a fresh stopped clone |
| `control_directory` | New private directory outside the data directory |
| `socket_directory` | Separate private directory outside data and controls |
| `source_user` | Source administrative role used for local verification |
| `barrier` | Complete object from `barrier.json` |
| `source_settings` | `settings` object from the seed generation's `manifest.json` |

```sh
./bin/pgws-physical recover --config recovery.json --timeout 2m
./bin/pgws-physical stop --config recovery.json
```

Recovery reserves its control directory, installs an external configuration with no TCP/upstream/archive/preload hooks and clears copied `postgresql.auto.conf`. It starts with `pg_ctl -W`, promotes without waiting for standby SQL, checks system ID, replay LSN and source timeline ancestry, checkpoints and writes `recovery-evidence.json`. Success leaves the private PostgreSQL process running until `stop`; no endpoint is published. A failed recovery attempts a fast stop and keeps files for diagnosis. Recovery cannot be repeated over an existing control directory; create a fresh clone for a new attempt.

The ZFS adapter is a library at `internal/storage/zfs`. Its caller must provide an exclusively locked host journal and an administrator-provisioned root dataset with local `org.pgws:managed=on`. It does not create/import pools. Unit tests check ownership, GUIDs, holds, stale fencing, replay after deletion and deletion flags. The host service now connects this adapter to real mounts/refquotas, authenticated host RPC, continuous baselines, source WAL watchdog, private recovery and readiness publication. Run `make zfs-lab` and `make host-lab` in the dedicated Lima VM for those paths.
