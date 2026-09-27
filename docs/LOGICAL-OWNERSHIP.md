# Logical slot ownership and progress

The private connector can persist source creation and target progress outside the
writer's data directory. These records support inspection while the writer is
down. They do not approve a policy, publish a baseline or authorize deletion of
an arbitrary same-named source slot.

Set `slot_ownership_file` to an absolute path in an existing mode-0700 directory
in the private administrator configuration. Keep that directory outside ZFS
data snapshots and workspace mounts. The CLI refuses an existing ownership file
before seed initialization. It creates these mode-0600 files:

| File | Meaning |
| --- | --- |
| The configured path | Confirmed slot creation, source UUID/epoch/system/timeline/database, slot name, publication name and OID, target contract, consistent seed position and observation time. |
| Path plus `.applied` | Highest confirmed target commit, bound to the exact ownership record by SHA-256. |
| Path plus `.lock` | Nonblocking interprocess serialization of progress writes. |

Creation uses a temporary file, file fsync, an exclusive hard link and directory
fsync. Exact retry is allowed; a different ownership record never overwrites the
file. It is persisted after the source confirms slot creation and before any
seed row is read. A lost creation response or a crash before this receipt still
requires explicit reconciliation. Names alone are not ownership evidence.

Progress is persisted after the target's synchronous commit and before sending
source ACK. Atomic rename and file/directory fsync protect its durability. Exact
replay and older positions retain the highest recorded position. Invalid,
public, symlinked or differently bound receipts stop ingestion. A failed progress
write never advances ACK, even if target data already committed. Restart checks
the target journal and source position, persists current target progress and
replays unacknowledged transactions through the existing transaction journal.

A failed initial seed remains ineligible, including a failure persisting its
progress after commit. The seed cleanup attempts to remove only objects whose
creation it confirmed. Historical files remain for reconciliation. They are not
a reason to reuse an abandoned target or silently replace a slot.

## Independent inspection

`pgws-logical status PRIVATE_CONFIG.json` needs `source_dsn`, the approved source
`identity` and `slot_ownership_file`. It does not connect to the target, inspect
application values or load the transformation key. Its source connection uses
read-only defaults, a two-second statement deadline and a three-second overall
deadline. Expiry closes the transport.

The status reports source lineage, slot shape, publication OID/name, retained WAL,
source-confirmed position and external commit evidence. It detects missing or
replaced objects, ACK beyond proven progress, a changed server WAL cap, invalid
WAL and retention at or above 64 MiB. It reads progress after observing source ACK
to avoid a false alarm during a concurrent durable apply. Before seed commit,
the only allowable confirmed source position is the slot's creation position.

An empty `stop_reason` means these checks passed. It does not establish current
target health, complete schema validity or publication eligibility. Inspection
does not kill processes, advance replication or drop source objects. Safe
automatic cleanup requires independently supervised runtime fencing and
reconciliation of intervening slot removal/recreation. The implemented private
path is described in [runtime supervision](LOGICAL-SUPERVISION.md). PostgreSQL does not expose
an immutable slot creation ID; a name and historical receipt are insufficient.

## Observed checks

Pinned PostgreSQL 18.6 passed real SIGKILL immediately after ownership persistence
and after target commit/progress persistence before ACK. The first retained an
inactive source slot and an unseeded target. The second resumed without duplicate
rows and acknowledged the original durable transaction. A failed progress write
also left ACK unchanged and recovered through replay.

The same disposable fixture generated more than 64 MiB of actual retained WAL.
Inspection detected the budget, slot removal, same-name logical replacement,
publication replacement and a same-name physical slot. The replacement objects
remained untouched. CLI status passed without target or key configuration.
The separate Linux supervision fixture now covers fenced owned-slot cleanup.
Power loss and the complete public logical host workflow remain unqualified.

A further real SIGKILL before ownership-file publication left the source slot
and publication intact, without seeded target rows or an external receipt.
Inspection, reseeding and streaming refused that unrecorded generation. Retry
preserved the publication OID and slot position. This establishes refusal after
an ambiguous crash; automatic adoption or deletion remains unavailable there.

## Parallel immutable baselines

A new private candidate may provide `baseline_id` and `baseline_generation` in
its logical identity. Both are required together. Its slot and publication names
then include a bounded digest of source UUID, source epoch, baseline UUID and
baseline generation. Separate privacy profiles or replacement generations can
coexist at one source epoch. A retry keeps the same identity and cannot adopt
another candidate's source objects or target checkpoint.

Legacy administrator candidates without these two fields retain their exact
existing names and target contracts. They still permit only one candidate per
source epoch. Do not use that legacy namespace for parallel policy cutover.

Container specifications carry `logical_source_id` and `logical_source_epoch`
for the new layout; their workspace/generation fields identify the baseline.
The pinned connector verifies the host-injected namespace before contacting the
source. The watchdog checks all four identity dimensions against ownership.
Policy receipts continue to bind source lineage and plan, while their host
permit binds the exact baseline container and immutable specification.

The PG18 lab seeded and streamed two differently keyed generations at the same
source epoch. Their outputs and slots remained independent; rejecting cross-
generation ownership and retiring the old slot preserved the new consumer.
Automatic publication/cutover and workspace exposure remain unimplemented.
