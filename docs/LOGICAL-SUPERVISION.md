# Private logical runtime supervision

The logical executable now runs inside the baseline's isolated OCI container,
alongside its private PostgreSQL target. The admitted runtime specification pins
the executable's SHA-256. Only a baseline with an approved upstream Unix socket
mount can run it. The runtime checks the executable before `seed` or `run`.
Source credentials, transformation keys, configuration and ownership/progress
receipts live in its external control directory, outside data snapshots.

`OCI.Ingest` checks the actual container identity, labels, namespaces, mounts,
resource limits and executable digest. Cancelling a Docker exec client alone
would leave its child running. Cancellation instead writes a durable terminal
`logical-stop.json` record and removes the exact verified container, stopping
both PostgreSQL and the source consumer. Data files remain. `Ensure` and `Ingest`
reject that stopped generation; an in-flight `Ensure` rechecks before and after
starting the container.

## Separate source watchdog

Build `pgws-logical-watchdog` for the dedicated Linux host and run it as root with
a private mode-0600 JSON file encoding `host.LogicalCandidate`. That file contains
the full admitted `runtime.Container`, private `source_dsn` and `ownership_file`.
The ownership file must be `slot.json` in that container's control directory.
For named candidates, source UUID/epoch must match the runtime's logical source
fields and baseline UUID/generation must match its workspace/generation. Legacy
unnamed candidates use workspace/generation as source/epoch. The connection
must use the admitted upstream socket and recorded database.

```sh
pgws-logical-watchdog /private/candidate.json
```

Arm this process once the slot creation receipt exists. It can operate during
initial loading; it does not wait for seed completion or connect to the target.
The two-second loop does not depend on management availability or the host's
operation locks. A failed source inspection or a reported safety condition writes
the terminal stop before removing the verified enclosure.

After proving runtime absence, cleanup acquires the source advisory ownership
lock. It rechecks system/timeline/database, publication OID/name, slot type and
flags, inactivity and source ACK against the external progress record. The
connection performing the deletion also verifies these conditions itself.
Only a healthy, still-provable slot is eligible for automatic removal. Missing
slots need no mutation. Changed identity, lost continuity or invalidated WAL
requires operator reconciliation.

A durable `logical-retirement.json` intent precedes the first DROP attempt.
If the response is lost and the slot is still present, a later pass refuses to
repeat the deletion. This sacrifices automatic cleanup in that uncertain case
so a later same-name slot is not silently deleted. Source administrators must
not bypass the PGWS advisory lock to alter its objects concurrently. PostgreSQL
has no immutable slot creation ID; historical receipts cannot defend against
an administrator deliberately racing the deletion itself.

The watchdog does not remove publication metadata or retained target storage.
These still belong to explicit generation reconciliation. A stopped generation
cannot resume just because WAL pressure subsides.

## Observed Linux checks

`scripts/host_lab.py --test-pattern '^TestLiveLogical'` passed on the dedicated
Ubuntu 24.04 ARM64 VM with pinned PostgreSQL 18.6 and OpenZFS 2.2.2:

- Container seed and CDC transformed source rows, then cancellation killed the
  consumer and PostgreSQL while preserving disk and external progress.
- A separate watchdog process removed a Docker-paused baseline and its owned
  slot after more than 64 MiB of actual source WAL. This passed both during CDC
  and during an uncommitted 100,000-row initial load.
- A signed policy with the wrong plan was rejected before target initialization.
  An expiring policy stopped CDC; a separately launched watchdog also removed a
  paused container and its proved slot. Later renewal and restart were rejected.
- Repeated stop/cleanup was safe. A persisted uncertain deletion attempt and an
  actual replacement logical slot were left for reconciliation.
- The pinned container consumer drove ZFS captures before and after commit.
  Forced writer removal and restart replayed the transaction. Recovered clones
  had matching rows, sequence high water, checkpoint and marker evidence, then
  detached ingestion metadata and accepted independent writes.

This remains a private administrator path. Management admission, publication and
generation cutover are not integrated. PRIVACY-ADMIN.md describes signed permit
installation, automatic operator-to-relay renewal, approved ingestion and
independent expiry enforcement. A separate live run delivered two periodic
approvals and stopped actual CDC after management policy revocation within the
last signed permit's bound. A repeat run killed and restarted the relay between
deliveries and rejected a duplicate relay process on its socket.
The source creation interval before a confirmed ownership receipt now has a
SIGKILL test proving that retry refuses adoption and leaves source objects for
explicit reconciliation. Automatic reconciliation in that interval, host reboot,
power loss, watchdog deployment supervision and the complete fault matrix remain
separate acceptance work. Public sanitized workspaces remain disabled.
