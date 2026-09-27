# Physical creation and source recovery

Workspace creation records its request and reserved memory before allocating a
clone. The request hash excludes the worker attempt's fencing token; changing
the operation, generation, revision, snapshot, freshness request, profile or
expiry does not qualify as a replay.

The host retains the captured snapshot for `latest` and `at_least` retries.
It checks existing ZFS GUIDs and container labels, mounts and isolation settings.
A lost container-creation response can be reconciled by its reserved name and
complete immutable specification. A recorded container ID cannot be replaced.

The preparation stage is persisted before any runtime starts. Only this stage
may remove PID files inherited from the baseline. Incomplete known control files
can be rebuilt before startup; an existing complete recovery plan is immutable.
Later retries never remove a running generation's PID file.

PostgreSQL start and promotion accept a lost previous response. Readiness still
requires current SQL checks of system identity, writable state and timeline
ancestry. After a promoted primary restarts, `pg_last_wal_replay_lsn()` can be
NULL. The verified promotion timeline's fork LSN supplies the source lower bound
in that case. Neither process existence nor an old JSON receipt proves readiness.

The real ZFS overflow fixture captures 70 still-open nested source transactions,
then stops the source before starting the clone. It confirms that standby SQL
is unavailable, promotes through host process control and verifies that only
committed rows survive. Current SQL/timeline proof still passes after restarting
the promoted PostgreSQL process. Two clones of that capture remain independent.

The source watchdog compares the observed system identifier and timeline with
the reserved generation. A change records `SOURCE_LINEAGE_CHANGED`, removes
the old runtime and prevents background restart. Slot cleanup still requires
the original system identifier; a different system's same-name slot is never
treated as owned. The administrator reseed workflow creates a new generation after old-slot
cleanup. A foreign system identifier still requires explicit reconciliation
against the original system. See SOURCE-RESEED.md.

Access hardening reserves administrator, owner and reader names in a private
plan before changing SQL roles. The same SQL transaction installs a plan hash
on all three roles and disables imported authority. A retry verifies those
markers and reconnects through the reserved administrator even when the source
login has already been disabled. HBA installation and application ownership
transfer can then finish. Control JSON publication uses a fully written, synced
temporary file and an exclusive link so a killed writer cannot publish a torn
plan. Host administrative connections fix catalog name resolution and enable
synchronous commits despite copied role/database defaults.
Private PG18 connections also override session/local library preloads, role
selection and transaction defaults, and disable event triggers in the startup
packet. Before role changes, the host checks every connectable database,
including template1, for unsupported catalog objects. This catches source DDL
that arrived after discovery and prevents copied login or DDL triggers from
executing during privileged hardening.

An existing ingress process or configuration can be reused during private
creation, but the ingress must still be closed and have the exact generation
identity. Public access requires the worker's separately authorized serving
lease and actual TLS/SQL probe.

## Observed failure boundaries

The Linux/OpenZFS fixture starts a real host in a child process, sends `SIGKILL`
after each of the following effects, then starts a new host with a newer worker
fence and the same request:

- Clone creation, before its GUID reaches host state.
- Recovery control creation, before recording the prepared stage.
- OCI creation, before its ID reaches host state.
- PostgreSQL start.
- Promotion, before recording recovered state.
- Access hardening, before saving its result.
- Closed ingress startup, before saving the endpoint.
- Ready host state, before completing the command journal.

All eight resume cases passed against actual PostgreSQL 18.6, Docker and ZFS. Each
recovered candidate passed current SQL verification, kept ingress closed without
a lease, rejected a changed snapshot request, and was deleted through the normal
host operation. Eight further cases deleted the interrupted candidate directly.
Before OCI creation, the host persists the complete runtime specification. If
the resulting ID was not recorded, deletion can inspect the actual container
against that intent without starting it. A foreign specification was rejected
without removing its container. The independent watchdog uses the same read-only
lookup to stop a runtime with a lost creation response. Its memory reservation
stays charged until the host records the observed ID or deletes the intent.

A separate capture-replay case loses the final ZFS receipt and then advances the
baseline. The snapshot keeps its original GUID and source LSN. The source lower
bound is persisted before snapshot creation so replay cannot attach newer WAL
evidence to older captured bytes.

The physical SQL fixture also passed an HBA-write failure after
the role transaction, repeated start/promotion/stop, and restart of a promoted
primary. It tested copied role defaults that shadow a catalog function and
disable synchronous commits; administrative connections overrode both defaults.
Copied preload settings that broke ordinary logins did not prevent private
administration. Login and DDL triggers in postgres and template1, a newly added
native function and an unlogged table were rejected before access-role changes.

The worker distinguishes a missing or truncated RPC response from an explicit
host rejection. An unknown result requeues the same durable operation after a
five-second backoff, up to ten attempts. Ordinary admission checks run again and
assign a newer fence. The worker does not revoke the candidate or publish an
outcome merely because the response was lost. Explicit host failures remain
terminal. The live service test discarded real successful create, pause and
extend responses, plus a successful resume activation response; each operation
then completed under a newer fence and preserved the intended data and expiry.
The same test also discarded a completed source-registration response; the
worker retried and published the original baseline snapshot under a newer fence.
The separate-daemon fixture also killed the normal pgws-host executable during
creation. The running API and worker recovered the same operation automatically
after host restart; the observed operation completed in two attempts.

The reset campaign passed eleven further SIGKILL resume boundaries: after the
old PostgreSQL instance stops, at the eight creation boundaries above, after
removing the retired runtime and after destroying its volume. Every resumed reset
discarded local writes, verified the new primary through SQL, kept ingress closed
without a serving lease and removed the old runtime and volume. Four additional
cases deleted both generations directly after interruption at old stop, new
runtime creation, ready state and retired-volume destruction. Existing sessions
on the old generation were closed in all fifteen cases.

## Initial source preparation

Registration binds the source configuration and request to a private journal.
Once slot ownership has been durably confirmed, retries verify the source system
and timeline, the owned slot's WAL budget and the recorded ZFS GUID. Before any
container starts, the journal records its full immutable specification.

A host crash can leave pg_basebackup running in the container. If the verified
seed has not reached the host journal, recovery removes that exact container
before discarding the fixed partial generation directory and restarting the
backup. Once the seed is recorded, recovery keeps its data and the manifest
captured immediately before backup. It can finish partial streaming controls
only before the prepared stage, when PostgreSQL has not been allowed to start.
Completed controls bind the recovery plan, upstream configuration and slot.

Retries after startup require current SQL proof of standby identity and replay.
The source lower bound is saved before the initial ZFS snapshot; a lost capture
response preserves that position even if the standby advances meanwhile.

The live source campaign passed nine real SIGKILL recovery cases: after durable
slot ownership, volume creation, runtime creation, during backup transfer,
after verified backup, after streaming controls, after PostgreSQL start, after
snapshot creation and after streaming-state persistence. It checked current SQL
replay, stable volume identity, request binding and owned runtime/slot cleanup.
The capture case advanced the source after the interrupted snapshot and retained
the original lower bound. An additional case lost the slot-ownership receipt and
verified that the host neither adopted nor deleted the unconfirmed slot.

There is no automatic adoption if slot creation succeeds but its ownership
receipt is lost. PostgreSQL physical slots have no service ownership token.
The host blocks that generation and leaves the unconfirmed slot untouched;
the approved source retention cap remains required. Established baselines can
be reseeded into a new generation through the administrator API. Six additional
SIGKILL cases passed old runtime/slot retirement, persisted retirement, backup
transfer, capture and completed streaming state. Old snapshot lineage remains
unchanged, and a retry after capture retains its original lower bound.

## Remaining qualification

These cases do not establish complete power-loss, kernel reboot, automatic failover
or unconfirmed source-slot ownership reconciliation. Recovery from
management restore remains fenced by the separate authority procedure. Existing
development installations are not automatically migrated to the new creation
journal or project-quota layout.
