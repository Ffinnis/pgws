# Workspace API benchmark

`scripts/benchmark.py` submits concurrent workspace creations against an approved
baseline, waits for real operation completion and connects over verified TLS.
Each clone must be writable, start without its siblings' benchmark table and
retain its own row after all siblings finish writing. The script deletes only
workspaces admitted by its run and records incomplete cleanup.

```sh
python3 scripts/benchmark.py --baseline BASELINE_UUID --workspaces 2 --rounds 2
```

The defaults use `.local/dev-client.json` and `.local/dev-ca.crt`. Supply
`--client`, `--certificate` and `--output` for another installation. A native
`psql` is required. The source and pre-existing workspaces are not modified.
The approved baseline determines the data size; the script does not substitute
a sparse file or generated size label for actual PostgreSQL data.

The JSON evidence records each API create latency, credential latency, first
verified SQL latency, `pg_database_size`, PostgreSQL version and cleanup result.
Create latency includes admission, queueing, host provisioning and observed
operation completion. Percentiles use nearest rank. A few observations establish
that this path runs; they do not qualify production tail latency.

Choose concurrency within host admission, project allocation and free-pool
limits. The local service reserves 1 GiB per small workspace and has a default
4 GiB aggregate budget shared with its baseline. Fourteen small workspaces need
a host configured and provisioned for those reservations. Raising a configured
limit does not add physical memory.

Lost admission responses retry the same request and key. If the replies remain
unavailable, the report retains `admission_unconfirmed_keys`. Retry the exact
request to inspect its durable outcome; do not invent a replacement key. Known
workspace IDs with unconfirmed deletion appear under `cleanup_unconfirmed`.
Workspace TTL is 30 minutes and does not replace cleanup verification.

The local small-data run is in `evidence/workspace-benchmark.json`. This harness
does not measure source load, cell resident memory or power-loss recovery. The
RFC's 1 TB / fourteen-workspace test still needs a suitably sized source and host,
those additional measurements and the prescribed workload. The evidence does not
claim that qualification merely because a command accepted `--workspaces 14`.

## Isolated 1 GiB test

The completed 20 September 2026 run and its measurement limits are recorded in
[ONE-GIB-RESULTS.md](ONE-GIB-RESULTS.md). The 1,076,975,295-byte source produced
three simultaneously live clones in 2.164, 3.642 and 5.308 seconds. Full data
integrity, lifecycle and separate-process fault checks passed.

```sh
python3 scripts/host_lab.py --one-gib
```

This creates a separate source and management database, API/worker/host/guard
processes and a temporary 4 GiB file-backed ZFS pool in `pgws-lab`. It fills the
source until `pg_database_size` reaches at least 1 GiB, using random 1,900-byte
payloads with per-row MD5 integrity checksums. These checksums detect copying
errors; they are not used for authentication. Payloads use PLAIN storage and
random bytes so compression cannot make this an empty-database benchmark.

The test admits three workspaces before waiting for them, scans all copied rows,
checks independent writes and the unchanged source, then exercises pause,
resume, reset and deletion. It also runs the existing separate-process fault
checks on the larger baseline. Its source generation, baseline seed, clone
latencies, full-scan times and ZFS measurements go to `evidence/one-gib-lab.json`.
Create latency ends at the durable management completion timestamp, excluding
the separate data scan. All clocks for this measurement are in the same VM.

The test leaves the persistent development service intact and removes its own
containers and pool. Run it separately from other performance tests to avoid
competing for VM resources. It is opt-in and skipped in the default host suite.

The host's default physical seed budget remains 512 MiB. For the larger fixture,
`seed_max_bytes` is 1,536 MiB and `project_quota_bytes` is 4 GiB. The host checks
that an explicitly configured project budget covers both the archive and its
extracted copy plus 256 MiB of headroom. The baseline refquota is derived from
that allowance. The seed budget is persisted with its generation and cannot
change during replay. This profile caps configured seeds at 1,536 MiB while
workspace refquotas remain 2 GiB; it does not enable arbitrary large sources.
