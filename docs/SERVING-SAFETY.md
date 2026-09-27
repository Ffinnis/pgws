# Serving expiry and stalled processes

The guard verifies each signed lease before accepting SQL connections. Both
directions of an established connection have an I/O deadline bounded by the
serving lease and credential expiry. Each forwarded write checks authority
again. Renewing a lease updates both sockets without extending the credential.

The SIGSTOP fixture first confirms Linux reports the guard in state T. It then
sends an INSERT, waits past the conservative lease deadline and resumes the
process. PostgreSQL must contain no inserted row. The deadline-only version
failed this test: a client error did not prove SQL had not executed. The version
with a per-write check passed the complete selected host test in 148.29 seconds.

## Independent runtime enforcement

The guard now persists the signed lease, its receive time, Linux boot identity
and a CLOCK_BOOTTIME deadline before acknowledging installation. The runtime
and its generated SQL roles cannot access that root-owned file. The watchdog
checks its signature, generation identity and duration bounds without calling
the guard or management service. A changed boot identity or regressed counter
expires the old authority. Renewal keeps the earlier monotonic workspace TTL
bound when the signed workspace expiry has not changed.

CLOCK_BOOTTIME includes system suspend and does not jump with wall-clock changes.
See the [Linux clock documentation](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
and [kernel boot identity documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html#random).
Non-Linux runtime supervision fails explicitly; portable ingress unit tests do
not claim Linux runtime qualification.

A dedicated watchdog loop checks serving deadlines every 500 milliseconds,
with bounded concurrent checks independent of source/WAL inspection. An expired
or invalid established receipt records SERVING_LEASE_EXPIRED and removes the
verified OCI runtime. PostgreSQL stops before any attempt to contact a suspended
guard. The disk remains allocated and private. Confirmed container removal
releases its memory charge. A new lease cannot clear the terminal stop.

Resume prepares its durable host state while PostgreSQL remains stopped.
Activation installs a fresh lease before starting PostgreSQL, verifies the
promoted system identity and probes SQL through the TLS endpoint. This avoids
starting under a lease that expired during a long pause. A newer signed receipt
revision is accepted by the watchdog even if its concurrent state inventory
read preceded that lifecycle update.

The selected host test passed direct watchdog execution during guard SIGSTOP:
it interrupted an actual pg_sleep, verified OCI absence, retained the clone
directory, recorded memory release and rejected a fresh grant. That run took
157.01 seconds. The separate watchdog executable and independent fast loop then
passed in the complete lab run and in a later selected host run of 171.38 seconds.

## Connected revocation

The management worker checks current workspace authorization every second,
separately from job execution and lease renewal. If a settled workspace has no
remaining raw grant for its current desired revision, the worker requests a
stop with its exact generation, revision and fence. The host rejects a stale
fence, records AUTHORIZATION_REVOKED and removes the verified runtime. The
worker then records the failed phase and credential revocation. All host I/O
finishes before that management transaction.

The separate-daemon fixture revoked the actual API raw grant. Its established
SQL connection closed in 845.904083 milliseconds, retained storage survived,
and a stale revocation fence was rejected. This measures the settled-workspace
case. In-flight lifecycle operations use their existing authorization/operation
lease checks; the complete concurrent revocation matrix remains open.

Individual SQL credentials have a separate durable revocation delivery record.
The worker revokes their management record before contacting the host, retries
a missing host acknowledgement, then records delivery. The guard persists a
per-username tombstone and closes that username's sessions. Renewals and process
restarts cannot re-register a revoked username. Other users keep their sessions
while their own grants remain valid. The multi-user daemon case closed the
revoked principal's actual SQL session in 929.920251 milliseconds, rejected
reconnection and kept the other principal connected. Delivery now groups all
pending credentials for a workspace into one atomic host request; management
tests verify grouped retries and acknowledgements.

## Limits and recovery

The current public recovery path for a terminally stopped workspace is deletion
and creation of another workspace. Automatic reopening of retained local writes
is not implemented. A lease that reaches its deadline can be terminally stopped
even if a late renewal races the watchdog's decision; expiry is conservative.

Older guard receipts do not contain runtime authority. They fail closed when
observed as established workspaces by the new watchdog. Existing development
installations have not been migrated or replaced automatically.

The complete T-24 campaign still requires host reboot, VM suspend, real clock
adjustment, the concurrent revocation matrix, management outage and runtime-engine failure tests.
Unit checks cover receipt signature, identity, reboot marker, counter rollback,
deadline extension and terminal state. These are not substitutes for those
system-level failure tests.

Management stop reconciliation accepts a valid authenticated receipt even when
its audit timestamp appears in the future after a wall-clock rollback. It still
requires the exact authority, tenant/project, generation, revision and fence,
and revokes credentials in the same transaction that records the failed phase.
