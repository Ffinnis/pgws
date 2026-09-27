# PGWS test on a 1 GiB database

On 20 September 2026, `TestLiveDaemonsOneGiB` passed in 236.26 seconds.
The full log and measurements are stored in [one-gib-lab.json](../evidence/one-gib-lab.json).

To reproduce:

```sh
python3 scripts/host_lab.py --one-gib
```

The test used separate source and management databases, separate API, worker,
host and guard processes, PostgreSQL 18.6 containers and a temporary 4 GiB ZFS pool.
Environment: Lima, Ubuntu 24.04 ARM64, 4 CPUs, 8 GiB RAM, OpenZFS 2.2.2.
The existing development service was left intact. The temporary pool and containers were removed.

| Measurement | Result |
| --- | --- |
| Source size by `pg_database_size` | 1,076,975,295 bytes, about 1.003 GiB |
| Rows in the main table | 516,096 |
| Random payload data | 980,582,400 bytes |
| Source generation | 11.79 s |
| Initial baseline load | 113.475 s |
| Clone creation 1 / 2 / 3 | 2.164 / 3.642 / 5.308 s |
| Full data check of clone 1 / 2 / 3 | 2.846 / 2.657 / 3.224 s |
| ZFS used before clones | 1,067,154,944 bytes |
| ZFS used with three clones, before user writes | 1,070,048,256 bytes, +2.76 MiB |
| ZFS used after independent writes | 1,083,821,056 bytes, +15.89 MiB over the baseline |
| ZFS used after deleting the clones | 1,067,550,720 bytes |

All three creation requests were submitted before waiting for any result. A single
worker served them, and all three clones ran at the same time. Creation time includes
queueing and ends at the operation's stored completion timestamp in the management
database. The full data checks were measured separately. The initial load used the
existing `pg_basebackup` rate limit of 10 MiB/s.

Each row contains 1900 random bytes with PLAIN storage. The full checks compared the
row count, total payload size and the MD5 of every row before and after changes. MD5
is used here only as a data integrity check.

The following checks passed:

- Connecting to real PostgreSQL over TLS with `verify-full`.
- Independent changes in all three clones, with the source database and neighbouring clones unaffected.
- Pause closes an open connection; resume keeps the changes.
- Reset creates a new generation, discards changes and restores the baseline data.
- Deleting all three clones is confirmed by completed operations.
- SIGKILL of the host during creation, and SIGKILL of the host together with the guard, followed by recovery of the same SQL endpoint.
- The full lifecycle through the Python SDK, barrier and `at_least`.
- Revoking a principal token closes its SQL session in 0.953 s; revoking a raw grant closes the connection in 1.007 s.
- ZFS pool pressure closes SQL in 1.938 s, removes the source-owned replication slot, and keeps the terminal stop after space is freed.

This database exposed a previously fixed 512 MiB limit on the initial load. A
`seed_max_bytes` parameter with quota checks was added; the default is unchanged.
The test set a budget of 1536 MiB and a project quota of 4 GiB. The baseline quota
accounts for the archive, the extracted copy and a 256 MiB margin. The budget is
stored with the generation and cannot change when an operation is retried.

ZFS counters reflect the state at the moment of measurement. The test did not force
clone checkpoints or `zpool sync`, so these are not measurements of peak space use or
of the full cost of all writes after they are flushed. The memory reservation for the
baseline and three clones was 4 GiB; actual RSS was not measured. This single run does
not establish p95/p99 figures and does not replace the RFC's 1 TB / 14 clone test.

The first run stopped because of a bug in the test itself: it expected `completed_at`
in the public operations API. The measurement was fixed to read the stored timestamp
from the isolated management database. The log of the first run is kept separately
in `evidence/one-gib-initial-fixture-failure.json`.

After these changes, `go test -race ./...`, `go vet ./...` and the SQL/API/lifecycle
integration checks in `python3 scripts/integration.py` passed.
In addition, three `TestLiveSourceRecovery` checks with SIGKILL at the `runtime`,
`backup` and `seed` stages passed in 58.97 seconds in total. They verify recovery of
the initial load with the previous default budget.
