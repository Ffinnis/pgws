# Validation record

19 September 2026. Development machine: macOS arm64, Go 1.25.4, local PostgreSQL 14.20 Homebrew. Physical lab: Docker Linux aarch64, PostgreSQL 18.6 (server_version_num 180006), image pinned by digest in scripts/physical_lab.py.

| Command | Observed result |
| --- | --- |
| `python3 scripts/integration.py` | Go management/HTTP and host-library tests passed with `-race -count=1`. Disposable PostgreSQL used a private Unix socket with TCP disabled. |
| Built daemon/CLI smoke, included in the script | Passed migration, initial bootstrap, refusal to repeat bootstrap, readiness, baseline listing, source registration replay, worker failure recording and CLI wait returning failure for the unavailable backend. |
| `go vet ./...` | Passed. |
| `go test -race ./...` | Passed; database and physical lab integration are opt-in and run separately. |
| `go build -o bin/pgwsd ./cmd/pgwsd` | Passed. |
| `go build -o bin/pgws ./cmd/pgws` | Passed. |
| `go build -o bin/pgws-physical ./cmd/pgws-physical` | Passed. |
| `python3 scripts/physical_lab.py` management fixture | Passed actual management/HTTP integration on PostgreSQL 18.6 in a separate private container. |
| Physical lab: verified seed and recovery | Passed discovery, pg_basebackup/pg_verifybackup, disconnected host promotion, replay/system/timeline checks, independent writes, temporary slot cleanup and copied hook suppression. |
| Physical lab: overflowed subtransactions | Passed with 70 source subtransactions still open: cloned standby SQL unavailable, host promotion succeeds, committed row visible and unfinished rows absent. Capture uses a stopped standby directory copy. |
| Physical lab: negative cases | Changed recovery identity/path rejected before process start; missing WAL produces no successful evidence; unlogged source blocks seed admission. |
| ZFS adapter unit tests | Passed owner/GUID checks, snapshot holds, stale-command rejection, replay without recreation, non-recursive deletion and reconciliation after an observation failure following creation. Live ZFS execution is also covered by the separate VM fixture below. |
| `contracts/validate_contracts.py` with pinned requirements | Passed: 11 operations, 19 schemas, 26 positive/negative examples. This validates the copied contract, not full HTTP conformance. |
| `contracts/classifier/validate.py` through uv with pinned requirements | Passed: 22 static checks. No training or inference evaluation. |
| `python3 scripts/zfs_lab.py` | Passed real OpenZFS snapshot/clone content, independent writes, mount/refquota, GUID/fence validation and non-recursive removal in a temporary file-backed pool. |
| `python3 scripts/host_lab.py` | Passed real source registration and streaming baseline; latest and at_least ZFS captures; durable signed barrier replay; TLS/SCRAM credentials with encrypted replay; pause/resume/reset/extend/delete; old-generation collection, expiry cleanup, snapshot hold release/GC, reset/delete race and delete before create. |
| `python3 scripts/host_lab.py --one-gib`, 20 September 2026 | Passed on a real 1,076,975,295-byte PG18 source with 516,096 random-payload rows. Three simultaneous clones, full checksums, independent writes, lifecycle, host/guard SIGKILL, principal/raw-grant revocation and pool-pressure stop passed in 236.26 seconds. See ONE-GIB-RESULTS.md and evidence/one-gib-lab.json. |
| Separate daemon fixture | Passed pgwsd API/worker, pgws-host, pgws-guard and CLI as separate processes, SQL writes against the returned endpoint, serving refresh, source independence and deletion/session closure. API and worker also pass with distinct unprivileged Linux users and non-owner SCRAM database logins. SIGKILL of host and guard recovers on the same published TLS port with a fresh serving lease. |
| Role hardening | Owner migrations of enum/domain/composite/aggregate objects pass; reader procedure writes, template database access, source-role assumption, catalog secrets and COPY TO PROGRAM are denied. |
| SDK tests | Python and Node tests pass; Python also runs a complete lifecycle against the separate live daemons. |
| Independent WAL watchdog | Passed stalled baseline plus more than 200 MiB generated source WAL: bounded slot cleanup, runtime removal, durable safety stop and safe repeated execution. |
| Private logical target | Passed PostgreSQL 14/18 whole-transaction apply, deferred FK and uniqueness rollback, duplicate replay, source/plan binding and unchanged TOAST handling. |
| PG18 consistent logical seed and stream | Passed concurrent source writes during exported-snapshot loading, INSERT/UPDATE/DELETE catch-up, socket failure after commit before ACK with restart replay, constraint failure without advancing source ACK, idle schema drift and unsupported catalog rejection. |
| Private logical marker barriers | Actual PG18 idle/stopped-consumer, retry, lost-ACK replay, preceding data, late-constraint rollback, pre-write quota and expiry cleanup passed. The CLI passed seed/CDC/barrier. A selected actual ZFS writer crash run recovered matching marker/checkpoint evidence and removed service metadata from clones. Public signing/publication remains disabled. |
| Logical ownership and external progress | Actual PG18 SIGKILL after slot receipt and after target commit/progress before ACK passed. Failed progress persistence withheld ACK; restart replayed without duplicate data. Source-only inspection detected actual 64 MiB WAL pressure, lineage mismatch, logical/physical slot replacement and publication replacement without modifying them. CLI status passed without a target or key. |
| Logical runtime supervision | Linux container seed/CDC and terminal cancellation passed. A separate watchdog stopped a Docker-paused initial load and continuous consumer after actual 64 MiB WAL pressure, retained disk and removed the proved slot. Uncertain retirement and a replacement slot were retained. Container-driven ZFS recovery also passed. See LOGICAL-SUPERVISION.md. |
| Operator privacy policies | PostgreSQL 14/18 passed explicit draft/approval/signing/revocation, immutable source/key/schema binding, canonical replay, scoped privilege checks, source drift and authority reapproval. Revocation blocks baseline admission, serving renewal and lineage credentials. Signature tests cover exact scope, wrong keys/protocols, duplicate fields and expiry. Host approval enforcement and live policy-specific endpoint revocation remain open. |
| Bounded PostgreSQL discovery | Disposable PostgreSQL 14 and pinned 18.6 tests passed for SELECT-only role enforcement, aggregate-only output, oversized/opaque/generated exclusions, 256-byte UTF8, empty evidence, metadata drift and deadline connection cleanup. The actual private CLI smoke also passed. Wider source-load qualification remains. |
| ARM64 classifier resources | Fresh Linux process pinned to CPU 0, GOMAXPROCS=1, arithmetic full-size model: measured p95 extraction+score 0.056/0.020/2.179 ms across three bounded profiles; resident increase 10,506,240 bytes with eight concurrent workers. See evidence/classifier-resources-arm64.json. This covers fixtures on one VM; x86-64, representative corpus and complete T-21 remain open. |
| Synthetic classifier training/export | Offline training from 480 authored records and 20 declared synthetic families passed. Ephemeral signing and all 24 Python/Go scores on 72 held-out profiles agree within 1e-5. Artifacts are deleted; this is engineering evidence only. See evidence/classifier-lab.json. |
| Classifier encoder and review-only runtime | Golden normalization/FNV/sparse vectors, numeric order, in-memory sample denominators/format recognizers/quantiles, feature limits, malformed JSON and a five-second fuzz run passed. Signed arithmetic fixture loading/scoring passed corruption, wrong-key/shape/labels, non-finite weights, concurrency and Python-reference score checks. No trained-model quality or resource qualification is claimed. |
| Logical writer ZFS recovery | Running-writer captures before and after target commit passed normal primary crash recovery with no partial rows, matching checkpoint/high water, detached ingestion and independent branch IDs. OCI writer loss replayed the unacknowledged source transaction. Selected Linux/ZFS fixture passed in 4.06 seconds. |
| Logical identity and serial sequences | PostgreSQL 18 passed ALWAYS/BY DEFAULT/owned serial seed/CDC high-water tracking, deleted maximum preservation, idle sequence drift, exhausted clone rejection and independent identity allocation. Management target tests passed transactional rollback with data/checkpoint. |
| Private logical administrator CLI | Passed discover, explicit policy compilation, seed, continuous stream and cancellation against disposable Unix-socket PostgreSQL 18. Seed receipts do not declare public eligibility. |
| Project allocation quota | Passed real 128 MiB ancestor quota, shared 48 MiB origin, write rejection before a larger clone refquota, independent second-project writes and recovered space after clone deletion. |
| Actual cell-pressure response | A sibling ZFS reservation lowered real availability; the independent daemon closed an existing TLS SQL session and removed its owned upstream slot. Restoring capacity preserved the terminal stop, and API deletion succeeded. |
| Terminal stop reconciliation | Passed actual failed workspace/blocked source metadata, endpoint withholding, scoped credential revocation, stale-observation rejection and unchanged historical operation outcomes. Confirmed container removal frees memory admission while retained ZFS data stays charged. |
| Interrupted physical creation | Eight actual SIGKILL cases passed after clone, controls, OCI creation, start, promotion, access hardening, ingress startup and ready-state persistence. A new host/fence resumed the same request, verified SQL state and kept ingress closed without a serving lease. |
| Deletion after creation interruption | Eight further SIGKILL cases passed direct deletion at the same boundaries. Lost container IDs are reconciled against a prewritten full specification; foreign specifications are rejected before removal. |
| Lost capture receipt | After real ZFS snapshot creation, discarding the final receipt and advancing the baseline did not change the recovered snapshot GUID or source lower bound. |
| Physical SQL replay | Passed repeated start/stop/promotion and recovery proof after primary restart; HBA-write failure after role commit resumes with the same administrator. Copied search-path and asynchronous-commit defaults cannot alter administrative catalog calls or durability. |
| Lost host responses | Passed actual create/pause/extend effects and resume activation followed by discarded responses; worker requeues and a new fence completes the same operation. Management tests reject stale and unbounded retry attempts. |
| Production host interruption during create | SIGKILL of the normal pgws-host process during creation, followed by restart, completed the same API operation automatically in two worker attempts. |
| Copied catalog and session defaults | Private connections suppress copied library preloads and login triggers. Login/DDL triggers in postgres and template1, native-function drift and unlogged-table drift are rejected before access roles change. Source event triggers also block seed admission. |
| Initial source interruption | Nine real SIGKILL cases passed after slot ownership, volume, runtime, during backup transfer, after verified seed, controls, start, capture and streaming-state persistence. Retried registration proves current replay, preserves its volume and capture lower bound, and rejects a changed request. |
| Unconfirmed source slot | A lost slot-ownership receipt blocks automatic adoption. Host revocation leaves that unconfirmed slot untouched; the disposable test fixture alone performs cleanup. |
| Lost registration response | Actual source registration followed by a discarded response is requeued by the worker and completes with the original baseline snapshot under a newer fence. |
| Interrupted reset | Eleven SIGKILL resume boundaries and four direct-delete cases passed. Old-generation sessions close, local writes are discarded, replacement SQL is verified, unleased ingress stays closed and both old runtime and volume are removed. |
| TCP source broker | Real PG18 native TLS with ECDSA/SHA-256 passed SCRAM authentication, verified physical backup, continuous replay, broker SIGKILL/restart, latest capture containing a commit during the outage, workspace isolation and owned-slot cleanup on revocation. `pg_stat_ssl` confirms TLS. Unit tests reject wrong CA/name, plaintext downgrade, unapproved destinations and SQL/logical startup. Deployed routing remains separate qualification. |
| Idle source recovery and password rotation | The normal pgws-host daemon restored a killed broker without an API request, atomically refreshed an updated source password and caught up replication. A second kill recovered during latest capture. Maintenance did not restart a revoked source. |
| Disconnected ZFS overflow recovery | Real ZFS capture with 70 open nested transactions passed after stopping the source before clone startup. Standby SQL was unavailable, promotion succeeded, only committed rows appeared, and current recovery proof survived a PostgreSQL restart. A sibling recovered from the same capture while the source was down and survived writes/deletion of the first workspace. |
| Source lineage protection | The watchdog stopped the old baseline on an actual new PostgreSQL timeline and on a different system identifier. Maintenance did not revive it. A same-name replication slot in the foreign system remained untouched; cleanup completed against the original source. Management transaction tests mirror the lineage stop into blocked source/baseline metadata. |
| Explicit source reseed | Passed real API reseed, lost-response retry under a new fence, immutable old workspace writes, fresh creation and new-epoch barriers, collection of retired generation snapshots and nonrecursive removal of the final old baseline dataset. TCP/TLS reseed also passed separate broker generation/sockets, old workspace preservation and new-generation capture. Six real SIGKILL cases passed old runtime/slot retirement, persisted retirement, new backup transfer, capture and streaming-state persistence. |
| Immutable safety receipts | Race tests pass concurrent stop/release publication and a wall-clock rollback between terminal stop and confirmed container removal. Actual container/generation mismatches still block release. |
| Backup credentials outside snapshots | PG18 physical tests and interrupted backup/control recovery passed with temporary passfiles in an external control mount. Recovered source registrations leave no abandoned backup credential directories. |
| Suspended ingress | Confirmed SIGSTOP, buffered INSERT, lease expiry and SIGCONT passed with no inserted row. The earlier deadline-only implementation failed this case; both directions now recheck authority before forwarding each write. |
| Runtime lease expiry | A separate watchdog process removed PostgreSQL while the guard was stopped, interrupted an already executing query, retained the ZFS directory, recorded memory release and rejected resurrection. The complete host suite and a subsequent selected host run passed. |
| Linux boot-clock receipts | Linux ingress tests passed receipt signature/identity, boot identity, counter rollback, deadline extension, fresh-revision inventory races and rejection of a workspace extension after a persisted boot-clock deadline. |
| Connected raw-grant revocation | Separate API/worker/host processes closed actual SQL in 845.904083 ms, preserved disk and rejected a stale revocation fence. Settled-workspace case; broader concurrent revocation qualification remains. |
| Operator API tokens | PostgreSQL 14/18 management and PostgreSQL 14 HTTP smoke passed create/list/atomic rotation/idempotent token and principal revocation, hash-only storage, scoped access and authority fencing. |
| Credential revocation delivery | Unit tests passed established-session closure and permanent tombstones across guard restart. Management tests passed committed revocation before host I/O, retry after a missing acknowledgement, scoped delivery and unchanged workspace readiness. Multi-user live test closed the revoked user in 907.439542 ms and preserved another user's access. |

An earlier separate-daemon run returned `BARRIER_EXPIRED` immediately after a
Python SDK barrier request. The following complete run passed, so the cause has
not been established. Failure-only diagnostics now record verification reasons
and timestamps without logging tokens. Clock/issuance qualification remains open.
A later run also rejected one credential registration after reset; the next full
run passed. Private guard errors now distinguish expiry, workspace limit,
terminal state, username validation and quota without exposing credentials.
Another selected host run rejected a serving lease during credential issuance.
Subsequent selected and full runs passed. Private diagnostics now distinguish
signature/identity/interval rejection, stale revision, stale issuance and terminal
expiry. The original transient rejection's cause remains unestablished.

The expanded reseed campaign exceeded the previous twelve-minute overall lab
timeout during its final TCP test. The runner now allows eighteen minutes; the
next full run completed every fixture. Leftover resources from the timed-out
fixture were identified by their exact disposable pool/mounts and removed.

One full host run failed a combined runtime-release identity/time check; its
selected rerun passed. The original diagnostic did not distinguish which
comparison failed. Stop and release publication now use exclusive durable links,
and release authority no longer depends on wall-clock ordering. A subsequent
full run passed; this does not establish the original failure's exact cause.

Native TLS testing rejected an Ed25519-signed source certificate during pgx
5.11.0 SCRAM channel binding negotiation. The qualified fixture uses ECDSA/SHA-256;
Ed25519 source certificates remain unsupported. Native testing also exposed
libpq's rejection of SCRAM-PLUS advertised over a Unix connection. The trusted
broker now offers ordinary SCRAM on that local hop while verifying upstream TLS.

The integration runner stops all spawned API/worker/PostgreSQL processes and removes its temporary clusters and bootstrap secrets. The physical runner removes only its own random containers. Local `bin/pgws`, `bin/pgwsd` and `bin/pgws-physical` build outputs remain available and are excluded from Git. Evidence summary: evidence/physical-lab.json.


Management fixtures use synthetic snapshot metadata solely for transaction tests. The Linux host fixture uses actual ZFS datasets and PostgreSQL runtimes. The dedicated Lima VM uses Ubuntu 24.04 ARM64, kernel 6.8.0-134-generic, ZFS userspace 2.2.2-0ubuntu9.5 and kernel module 2.2.2-0ubuntu9.4. Each fixture creates and destroys its own file-backed pool. No physical disk was formatted.

Full RFC acceptance remains open. The initial source and reseed crash cases above do not establish automatic source failover or a complete power-loss campaign. No 1 TB benchmark, sanitized replication service, classifier training or production hosting has been qualified. No remote CI run has been observed. See IMPLEMENTATION.md for remaining work.

Signed-policy Linux acceptance now includes the actual host approval command,
plan mismatch before target initialization, CDC expiry and independent removal
of a Docker-paused candidate with owned-slot cleanup. Boot-clock permit tests
reject replay extension, older renewal, a different boot/runtime, counter
rollback and renewal after expiry. Public logical admission remains closed.

One full host run returned an idle worker claim while the lost-response fixture
expected immediate TTL execution. A selected rerun passed. The fixture now waits
up to three seconds for a runnable claim, matching the worker loop's SKIP LOCKED
semantics, and retains failure diagnostics. The original transient idle claim's
cause was not established. New policy tests initially checked Docker absence
before removal completed, and a test-only ZFS journal epoch mismatched its
command. Both fixtures were corrected; the selected logical host suite passed.

The complete Linux host suite passed with signed-policy expiry enforcement.
A subsequent selected daemon/host run passed durable usage collection from real
ZFS, missing-ACK replay without duplicate measurements and API/CLI history.
PostgreSQL 14 and 18 SQL/HTTP tests passed batch immutability, concurrent retries,
project isolation and exact decimal amounts; both SDK suites passed five tests.

Cold management recovery passed on PG18/OpenZFS with an actual pg_dump taken
before user/policy revocation and restored to another database. Host-only
resources were included; SQL sessions closed, old credentials failed, disk GUIDs
were retained and explicit new grant/source approval produced writable SQL.
Six SIGKILL boundaries and an interrupted data-bearing journal transition passed,
including operator host recovery and management completion CLI commands. Native
PG14 race/HTTP tests and external recovery-init/begin CLI smoke also passed.
MANAGEMENT-RECOVERY.md records the exact cold-recovery scope and remaining work.

The first recovery lab rejected mutation of historical generation evidence and
treated a missing usage file as a malformed secret. Recovery now preserves
immutable evidence, closes access through phase/quarantine, and checks outbox
existence before private-file validation. Both subsequent selected runs passed.

Parallel logical baseline generations passed on PG18 with distinct transform
keys, concurrent CDC and removal of the old slot while the new generation kept
advancing. The Linux logical container/ZFS suite passed with baseline/source
identities separated. An initial seed-pressure fixture waited on the seed's
table lock and missed its crash boundary; it now reads the ingestion checkpoint
outside that lock.

Private automatic policy renewal passed with separately launched management
signer, root relay and watchdog. Two 20-second deliveries reached the bound
runtime. Revocation withheld further receipts and stopped actual CDC with owned
slot retirement in 86.032136328 seconds. Management tests passed post-commit
delivery, failed-response retry, changed-binding rejection and revoked-policy
refusal. Public logical admission remains closed.

The complete Linux host suite subsequently passed with cold management recovery
included: separate daemons, lifecycle/crash campaigns, logical expiry/ZFS,
overflow, six recovery interruption boundaries, actual backup restore, source
creation/reseed and TLS/password-rotation/broker recovery. Automatic policy
renewal was added afterward and has separate selected-run evidence.

The selected approval suite subsequently passed with a relay SIGKILL/restart
between deliveries and rejection of a second relay on the same socket. Revocation
stopped CDC and retired its owned slot in 85.928605329 seconds. Native race tests,
205 management integration tests and the CLI/recovery smoke passed afterward.

The persistent development installation was upgraded without resetting its source,
authority or management database. The first check exposed legacy guard receipts
and an unrecorded project allocation. That check's temporary workspace stopped
and was deleted. Upgrade preflight now rejects incompatible guards and supports
the explicitly scoped legacy project migration. After that migration, a new
workspace passed pre-upgrade write, generation/data/credential preservation,
post-upgrade write, fresh credentials, capacity history and deletion. Evidence
is recorded in `evidence/dev-upgrade.json`.

The API benchmark passed two rounds of three concurrent workspaces on the local
PG18/ZFS service. Six creates took 2.336–6.212 seconds; nearest-rank p50 was
4.137 seconds. Each clone reported 7,919,295 PostgreSQL database bytes before the
benchmark writes. TLS SQL, independent writes and confirmed deletion passed for
all six. See `evidence/workspace-benchmark.json`; this small sample does not
qualify the fourteen-workspace/1 TB target.

The PG18 suite passed a real SIGKILL after slot creation but before publication
of its ownership receipt. Inspection, reseed and stream rejected the generation;
slot position and publication OID were unchanged and the target stayed empty.
Automatic resolution of an unconfirmed slot remains unavailable.
