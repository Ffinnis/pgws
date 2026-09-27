# Logical connector qualification

The public sanitized connector remains disabled while its host publication and
revocation gates are incomplete. `internal/privacy` compiles explicit field
policies; `internal/logical` coordinates an exported snapshot, transforms rows
before target writes, follows pgoutput and acknowledges only durable source
transactions. The `pgws-logical` administrator CLI operates private candidates.
Successful ingestion does not make a baseline eligible.

## pgstream evaluation

Reviewed upstream commit `732afff71df94ad3c2b06f0234b6f0e40626692d` on 20 September
2026. The checkout used for review is excluded from project distribution.

The stock PostgreSQL writer does not meet this RFC's transaction boundary. Its
[batch sender](https://github.com/xataio/pgstream/blob/732afff71df94ad3c2b06f0234b6f0e40626692d/pkg/wal/processor/batch/wal_batch_sender.go)
flushes on elapsed time, message count and bytes. Its
[PostgreSQL writer](https://github.com/xataio/pgstream/blob/732afff71df94ad3c2b06f0234b6f0e40626692d/pkg/wal/processor/postgres/postgres_batch_writer.go)
flushes separate runs when a table or action changes, with a transaction for each
run. Checkpointing follows these writes. From that code, a multi-table source
transaction can become visible in separate target commits. Strict mode stops a
failing run but does not roll back a run already committed. We therefore do not
use this writer as the RFC applier.

The implementation uses a narrow `pgoutput` transaction adapter with the pinned
`jackc/pglogrepl` protocol library. It must retain source BEGIN/COMMIT boundaries,
stop on unsupported events and acknowledge only a durable target commit. No
upstream pgstream code has been copied into the project.

## Implemented target contract

The compiler binds every included field to an explicit action and checks primary,
unique and foreign-key mapping compatibility. A schema change or key change
changes the immutable plan hash. Supported initial actions are approved original
copy, NULL for nullable fields, an approved fixture, and HMAC-SHA256 mappings for
text, email and UUID. Keys remain private to the ingestion process. Unknown
actions or fields have no fallback. This is pseudonymization under an explicit
policy, not an anonymity claim.

The target starts as an empty private UTF-8 database with a qualified C locale. The initializer creates typed
columns and declarative keys without importing source defaults, comments,
triggers or functions. The private writer makes foreign keys deferrable and its
apply transaction explicitly defers them until commit. The immutable plan retains
source deferrability for restoration in a clone. Any uniqueness or relationship failure rolls back the complete apply.
No failed row is skipped.

Transformed data, an exact replay digest and the applied LSN commit in one target
transaction with synchronous commit enabled. The journal binds the source
identity and immutable plan. A changed replay, position gap or source epoch is
rejected. Updates omit unchanged fields so already transformed TOAST values are
retained. Raw source values are never written into the target journal.

The target transaction behaviors passed disposable PostgreSQL 14.20 and pinned
PostgreSQL 18.6 tests, including concurrent duplicate apply, deferred constraint
failure, uniqueness failure, unknown columns and changed source identity.

## Source and seed profile

The source adapter currently accepts PostgreSQL 18, UTF-8 and libc C/C.UTF-8
locales. It inventories every application table: ordinary logged tables with
primary keys, supported scalar types, declarative unique keys and simple
NO ACTION foreign keys. Positive non-cycling identity and owned serial sequences are supported.
It rejects standalone/shared sequences, arbitrary defaults, computed columns,
dropped attributes, custom collations, user triggers, RLS, partitions, views,
large objects, foreign servers, subscriptions, prepared transactions, unsupported
extensions and uniqueness semantics. These restrictions are checked again while
streaming. Identity ownership, mode, type, start, increment and bounds belong to the
immutable schema hash. A serial default must be exactly the built-in nextval of its owned sequence;
modified expressions and shared generators are rejected.

The operator must freeze DDL during onboarding. ACCESS SHARE locks retain the
approved tables while permitting ordinary writes; an exported logical-slot
snapshot coordinates schema and all seed reads. A cursor streams bounded rows,
transformation runs in memory, and the seed data, receipt digest and source
position commit together. No raw file spool is created. Initial limits are five
minutes, 64 MiB of source values, 100,000 rows, 1 MiB per field, 2 MiB per row and
8 MiB/s. An oversized row is rejected on the source side before its values are
returned to the client. These are laboratory limits, not a 1 TB qualification.

Slot/publication names derive from the source UUID and epoch. A seed refuses
existing names; it does not infer ownership from their spelling. Failed seeds
clean up only source objects whose creation this call confirmed. Uncertain
creation or cleanup requires reconciliation. Failed target generations remain
private and are discarded before retrying with a new generation.

The stream uses pgoutput v1 with whole transactions and text tuples, without
streaming/two-phase mode. A framing validator bounds allocation before protocol
decoding. Unsupported events, new fields or catalog drift stop the stream; there
is no skip-row path. Source transactions are capped at 10,000 changes / 16 MiB.
Keepalives acknowledge only the last durable transaction, never the server WAL
end. Resume starts from the slot's confirmed position so a committed transaction
whose ACK was lost replays through the target journal.

The adapter checks a 64 MiB retained-WAL budget and requires a positive source
`max_slot_wal_keep_size` no larger than 256 MiB. PostgreSQL enforces its slot cap
at checkpoints; this is not an independent wall-clock safety guarantee. Durable
host ownership/reconciliation and an independently supervised logical-slot
watchdog remain required before enabling the public connector.

The optional private ownership/progress receipts and source-only status command
are described in [logical ownership](LOGICAL-OWNERSHIP.md). Real SIGKILL tests
cover confirmed slot creation and durable apply before ACK. Inspection detects
source replacement and WAL pressure while the ingestion process is dead.

## Identity and serial sequences

Initial load and apply maintain the largest copied identity value in ordinary
transactional metadata beside the source checkpoint. A failed transaction rolls
back both. Deleting a row never lowers this high water. Before clone exposure,
preparation checks current rows as well, creates an owned identity sequence and
chooses its first value above that high water, preserving start/increment/bounds
and ALWAYS, BY DEFAULT or serial semantics. Exhaustion blocks preparation. Source
sequence position and cross-workspace uniqueness are outside this contract.

Sequence settings come from [pg_sequence](https://www.postgresql.org/docs/18/catalog-pg-sequence.html).
The implementation uses transactional metadata because PostgreSQL
[sequence value changes are not rolled back](https://www.postgresql.org/docs/18/sql-createsequence.html).
Clone preparation uses CACHE 1 and refuses cycles or descending generators.

PostgreSQL 18 tests passed all three generator profiles through consistent seed,
CDC insert/update/delete, retained
high water after deletion, idle sequence drift, exhausted bounds and subsequent
branch inserts with the expected increment. Target transaction tests include
high-water rollback on deferred FK and uniqueness failures. Clone validation
also rejects missing primary or unique keys before detaching ingestion.

The private target journal uses version 2 without service markers and version 3
with explicit marker binding. Version 1 candidates must be rebuilt. See
[committed barriers](LOGICAL-BARRIERS.md) for idle-source freshness, bounded
marker privileges, retry and retention.

## Observed PostgreSQL 18 cases

`scripts/physical_lab.py` now also runs private logical ingestion tests. A held
target lock delays seeding after the exported snapshot, while source rows are
inserted, updated and deleted. The seed retains its old snapshot and the stream
then catches up completely. A socket wrapper drops exactly the ACK after target
commit: restart replays once and acknowledges without duplicate effects. A
uniqueness conflict leaves both target checkpoint and source ACK unchanged; after
removing the obstruction the same transaction succeeds. A new field stops an
idle stream without waiting for a later row event. Separate cases exercise
unchanged TOAST, unsupported catalog objects and the administrator CLI.

`Target.PrepareClone` verifies a recovered source lower bound and immutable plan,
restores source foreign-key timing and drops the private ingestion journal in a
single transaction before workspace ownership can be installed. Its SQL contract
is tested with a PostgreSQL database copy and independent branch writes. The separate Linux test `TestLiveLogicalWriterZFS` also captured a running
writer through the ZFS adapter before and after target commit. It blocked the
second table write, captured the first uncommitted row, then forcibly removed
the writer OCI container. Restart replayed the unacknowledged transaction. Both
snapshots recovered as independent primaries with complete data, matching
checkpoints and sequence high water. Each clone detached its ingestion metadata
and accepted independent writes. This test does not qualify signed policy
revocation, full endpoint isolation or public host publication.

## Private administrator commands

Build with `make build`. Commands accept a mode-0600 JSON configuration and only
private Unix-socket source/target connections:

```sh
./bin/pgws-logical discover .local/logical.json
./bin/pgws-logical seed .local/logical.json
./bin/pgws-logical run .local/logical.json
./bin/pgws-logical barrier .local/logical.json
./bin/pgws-logical status .local/logical.json
```

The configuration contains `source_dsn`, `target_dsn`, `identity` (source UUID,
epoch, system ID and timeline), an explicit `policy`, `transform_key_file` and
`ddl_frozen`. Discovery needs the source DSN, source UUID and epoch; it returns
actual lineage, schema and schema hash without row values. An operator reviews
that schema and supplies a rule for every field. The key file contains a base64
32-byte key and must also be mode 0600. `seed` requires `ddl_frozen=true` and a
fresh empty target, and its JSON receipt explicitly sets
`eligible_for_publication=false`. `run` ends on cancellation or the first
unsupported boundary. Neither command registers a public baseline or supplies
workspace credentials.

The source protocol follows PostgreSQL's
[logical message formats](https://www.postgresql.org/docs/18/protocol-logicalrep-message-formats.html)
and [snapshot/slot semantics](https://www.postgresql.org/docs/18/logicaldecoding-explanation.html).
