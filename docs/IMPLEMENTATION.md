# Implementation status

Started 19 September 2026 against RFC-0001 revision 0.3.

## Current milestone

The physical local-host service runs on PostgreSQL 18.6, OpenZFS 2.2.2 and a pinned OCI image in a dedicated Ubuntu 24.04 ARM64 Lima VM. Both the library integration path and separately launched API/worker/host/guard/CLI processes have passed end-to-end tests. TCP sources use an approved-address TLS broker; a real PG18 fixture passed backup, streaming and recovery after broker SIGKILL. This is not a completed P1 release qualification: complete crash reconciliation, deployment networking and the full security matrix remain open. A disposable persistent service can now be started with scripts/dev.py.

| Area | Implemented | Remaining work |
| --- | --- | --- |
| Management | Embedded checksum-verified migrations, immutable lineage, project RLS, durable operations, replay, audit, scoped operator token administration; explicit cold restore with external epoch/key, host acknowledgement and retained-data quarantine | Retained-generation recovery/cleanup, deployed backup/RPO/RTO qualification, production identity integration |
| Physical ingestion | Approved Unix or pinned TCP/TLS source references, actual PG18 inspection, exclusive bounded persistent replication slot, verified basebackup, continuously replaying baseline, real ZFS capture and explicit generation reseed | Deployment network qualification, complete drift/compatibility qualification, foreign-system slot reconciliation, multiple application databases |
| Freshness | Signed and scoped source barriers with durable replay, latest capture, at_least verification, real replay lower bound, immutable snapshot identity and terminal stop on changed source timeline/system ID | Automatic source failover, complete delayed-job/revocation campaign |
| Host execution | Authenticated private Unix RPC, fsynced fences, GUID/runtime inspection, staged creation, nine initial-source, six reseed and fifteen reset interruption cases, disconnected promotion, OCI network=none, project quota, refquota/memory caps, aggregate admission and pool floor | Unconfirmed slot reconciliation, power-loss/reboot campaigns, quota migrations and reserved cell space |
| Readiness and access | Imported logins disabled, limited generated owner/reader roles, application types/aggregates transferred, procedure ACLs and database-pinned ingress, SCRAM and TLS verify-full, real SQL probe before ready, encrypted credential replay | Larger schema/extension matrix, role cleanup and complete tenant adversarial suite |
| Lifecycle | Pause kills sessions; resume retains writes; reset replaces the generation; delete/TTL cleanup and snapshot GC; lost-response reconciliation for create, pause, resume activation and TTL extension | Complete source/reset/delete failure campaign and exact lifecycle usage intervals |
| Independent safety | Separate serving guard, signed 90-second renewal, monotonic deadlines, closed restart, same-port guard recovery after host/guard SIGKILL, per-write checks after SIGSTOP; boot-clock receipts and independent fast watchdog stop runtime while retaining disk; connected raw-grant revocation, per-credential tombstones and durable delivery; source WAL/pool watchdog and API stop reconciliation | Complete concurrent revocation/process-stall/reboot/clock campaign, broader source health reconciliation, production watchdog supervision |
| Clients | JSON CLI, dependency-free Python and TypeScript SDKs, bounded waits, stable replay keys, baseline pagination | Published SDK packages and broader driver compatibility |
| Private sanitized ingestion | Explicit deterministic compiler; strict PG18 catalog/pgoutput; exported-snapshot seed; transactional apply/ACK; sequence high water; actual ZFS writer crash recovery; marker barriers; ownership/progress receipts; container supervision, source watchdog and automatic operator approval renewal for pinned private candidates | Management admission, shared sequences, public policy-specific endpoint revocation and baseline publication |

SOURCE-RESEED.md describes administrator admission, immutable lineage, interrupted reseed recovery and the remaining slot-reconciliation restrictions.

SERVING-SAFETY.md records the failed deadline-only stall test, the passing
per-write guard check and runtime-expiry implementation and qualification.

Backend absence still returns a terminal BACKEND_UNAVAILABLE result. Configured physical execution errors produce terminal failed operations with private resources retained when reconciliation is required. API handlers perform no source or host I/O inside management transactions. Credential and barrier responses wait outside admission transactions and recheck authorization before release.

The source remains intentionally conservative: one approved application database plus PostgreSQL templates, no unlogged application relations, foreign servers, subscriptions, custom C functions, event triggers, external tablespaces, prepared transactions, or unqualified extensions/preload libraries. The private clone is inspected again before access hardening; startup suppresses copied preload settings and event triggers. Raw physical mode is available only to principals granted raw access. Sanitized mode remains disabled.

The host is privileged and accepts commands only over a private local socket and shared RPC credential. Workspace runtimes do not receive source credentials, source socket mounts, management connections or Docker access. The baseline alone receives its approved upstream socket and external passfile. The host restores dead source brokers during idle maintenance and atomically refreshes changed password-file contents without reseeding. Native PG18 TLS is tested with ECDSA/SHA-256; Ed25519 source certificates are unsupported by the pinned client's channel-binding path. The API is loopback-only; external access requires a separately configured TLS proxy. The local launcher uses separate unprivileged OS users and SCRAM database logins for API/worker under systemd. This is a disposable development installation; production deployment remains unqualified.

## Delivery sequence

| RFC package | Status | Next concrete output and required evidence |
| --- | --- | --- |
| WP-01 | Live lab running | Pinned PG18.6, Ubuntu 24.04 ARM64, real ZFS and disposable pools. Broader host compatibility/qualification remains. |
| WP-02 | Physical streaming implemented | Seed, continuous baseline, persistent slot ownership, fresh capture, pinned TLS source broker and separate WAL watchdog. Explicit reseed generations and six interruption cases pass. Power loss and deployment-network qualification remain. |
| WP-03 | Service integrated | Real authenticated host RPC, renewed operation leases, final authorization locks and terminal outcomes. Partial-effect reconciliation remains. |
| WP-04 | Live recovery implemented | Real ZFS clones, disconnected promotion, role cleanup, TLS/credentials and independent writes. Complete T-01–T-07/T-23 campaign remains. |
| WP-05 | Lifecycle and project quotas implemented | Pause/resume/reset/extend/delete and expiry cleanup; independent guards; old generation collection. Snapshot GC, aggregate memory admission, real project allocation limits and read-only capacity inspection work. Durable sampled capacity delivery is implemented. Exact lifecycle usage intervals and complete failure campaign remain. |
| WP-06 | Local process deployment and cold restore tested | Separate API/worker/host/guard/CLI, unprivileged OS users, non-owner SCRAM roles; persistent local systemd launcher. Actual management backup before revocation, external authority rotation, host quarantine and six recovery SIGKILL boundaries pass. Production identities, exact lifecycle usage, off-host backups and RPO/RTO qualification remain. |
| WP-07 | Private ingestion implemented | pgstream stock writer evaluated and rejected for split-transaction semantics; pinned pgoutput adapter, consistent seed with concurrent writes, deterministic compiler, lost-ACK replay and committed-marker barriers tested on PG18 and ZFS. Durable ownership/apply receipts, two real SIGKILL boundaries and independent source-only status pass. Private container seed/CDC and an independent watchdog now stop paused initial loads and CDC on source WAL pressure. Management integration, shared sequences and the full fault campaign remain. |
| WP-08 | Private policy lifecycle implemented | Immutable bindings, epoch approvals, boot-clock permits, compiled-plan checks and automatic signer/relay delivery pass. Actual management revocation stops private CDC within the last permit bound. Parallel immutable baseline generations pass; coordinated cutover, public publication and endpoint revocation remain. T-13–T-15, T-27/T-29. |
| WP-09 | API/SQL benchmark harness and 1 GiB run completed | Actual 1 GiB source, three simultaneous clones, full checksums, TLS SQL isolation, lifecycle and daemon fault tests passed. See ONE-GIB-RESULTS.md. Fourteen-workspace/1 TB qualification, sustained source and pool pressure, recovery memory profiles and retained allocation remain. T-16. |
| WP-10 | Annotation/import workflow implemented | Licensed independent schema families and reviewed provenance remain missing. Family-separated splits are enforced on declared family IDs. A 100-family pilot remains review-only. |
| WP-11 | Review-only training/runtime implemented | Shared Go encoder and in-memory profiling, from-scratch SAGA training, separate temperature split, strict signing and native scoring. Synthetic training/export parity passes; a private read-only PostgreSQL sampler handles bounded built-in types with deadlines and metadata binding. Unbounded text readers, real corpus and resource/accuracy qualification remain. No trained weights or automatic acceptance. T-17/T-21/T-22 remain open. |
| WP-12 | Contract only | Discovery review records, immutable model/plan binding, drift, shadow rollout and qualification per enabled class. T-18–T-20. |

## Local validation

MAINTAINABILITY-REVIEW.md records the verified review findings and the shared
bounded maintenance runner, durable file publisher and RPC response cleanup.
Authority checks, fence handling and transaction boundaries are unchanged.

- `scripts/host_lab.py --one-gib` passed on 20 September 2026 with a 1,076,975,295-byte source and 516,096 random-payload rows. Initial seed took 113.475 seconds; three queued clone creations completed in 2.164, 3.642 and 5.308 seconds. Full integrity scans, independent writes, pause/resume/reset/delete and the separate-daemon fault suite passed. See ONE-GIB-RESULTS.md and evidence/one-gib-lab.json.

- `go test -race ./...` and `go vet ./...` cover control contracts, signed leases/barriers, durable journal behavior, ingress session deadlines, runtime/storage validation and encryption.
- `scripts/integration.py` creates its own native PostgreSQL cluster (passed on this Mac with Homebrew 14.20 and, on 27 September 2026, 18.6: 222 tests in 33 packages) and runs actual SQL/HTTP tests plus migration/bootstrap/API/worker/CLI smoke. It covers idempotency races, RLS, scope/revocation, operation fencing, terminal failure and expiry admission.
- `scripts/physical_lab.py` uses pinned PostgreSQL 18.6 containers for recovery, missing WAL, source identity, role hardening and the 70-open-subtransaction promotion case. The host lab additionally captures that case through real ZFS, stops the source before clone startup, checks unavailable standby SQL and verifies promotion and restart. The physical lab also tests private logical seed/CDC, atomic apply, actual socket failure before ACK, constraint rollback, idle catalog drift and the administrator CLI. See LOGICAL-ADAPTER.md for the narrow supported profile.
- `scripts/zfs_lab.py` creates a disposable 4 GiB file-backed pool in the dedicated Linux VM and verifies snapshot bytes, independent clone writes, GUID checks and deletion.
- `scripts/host_lab.py` executes API/worker source registration, real baseline streaming and ZFS capture, latest/at_least and barrier replay, TLS/SCRAM credentials and encrypted replay, independent writes, pause/resume, TTL extension, reset, old-generation cleanup, expiry cleanup, snapshot GC and bounded source WAL cleanup. Its daemon fixture starts pgwsd API/worker, pgws-host, pgws-guard and CLI separately and observes serving renewal, recovery after host/guard SIGKILL at the same port, and session closure on delete.

CRASH-RECOVERY.md records the eight creation and nine initial-source interruption
boundaries plus six reseed cases tested with real SIGKILL. Power-loss qualification remains open. STORAGE-ACCOUNTING.md
describes quota measurements, terminal-stop reconciliation and confirmed memory
release.

Evidence JSON files record the actual completed runs, platform and timestamps. The copied classifier/model files under contracts remain specification checks. CLASSIFIER-RUNTIME.md describes the implemented encoder and unqualified scoring runtime. No qualified trained model, public sanitized replication service, fourteen-workspace 1 TB benchmark, hosted production operation or complete RFC acceptance is claimed.

## Reference APIs

The implementation uses the [pgx pool API](https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool) and [Go standard HTTP and toolchain behavior](https://go.dev/doc/go1.25). Dependencies are pinned in go.mod/go.sum. The copied RFC remains the source for system behavior and its upstream PostgreSQL/OpenZFS references.

PRIVACY-ADMIN.md describes the new operator policy workflow and its remaining host integration. Approval alone cannot expose a logical baseline.

USAGE.md describes the durable capacity outbox, deduplicated management records
and scoped API/CLI/SDK history. These are observed gauges, not inferred invoices.

MANAGEMENT-RECOVERY.md describes tested cold restore. Old grants, policies and
generations remain closed; operator reapproval creates new resources.

LOCAL-SERVICE.md describes upgrades with private backups, compatibility checks,
legacy project allocation migration and preserved SQL data. BENCHMARK.md describes
the concurrent API/SQL measurement harness and its small-data evidence.
