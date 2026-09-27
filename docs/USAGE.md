# Durable capacity measurements

The worker collects real host capacity once per minute through the authenticated
private host channel. The host reads each recorded project's common ZFS ancestor
and validates its GUID and ownership. It also totals durable runtime memory
reservations, including retained reservations until removal is confirmed.

Each project produces seven observed gauges: allocated bytes, ancestor referenced
bytes, bytes attributed to children, snapshots, the ancestor dataset and
reservations, plus reserved runtime memory. The ancestor's referenced bytes are
not the sum of its descendants' logical database sizes. Reserved memory is an
admission reservation, not resident-set memory or CPU consumption.

A sample records when acquisition started and finished, its Linux boot identity
and elapsed boot-clock nanoseconds. Those timestamps bound measurement work;
they do not mean the gauge stayed constant during that interval or between
samples. No byte-seconds, invoice totals or exact lifecycle durations are inferred.
Clock rollback during acquisition rejects that sample instead of inventing a
positive wall-clock interval.

## Delivery and retries

The host fsyncs one pending batch outside the data datasets before replying.
It retains that exact batch through response loss, worker restart or a management
outage. Sampling pauses while delivery is pending. Gaps therefore remain visible;
they are not filled with zeroes. A batch supports up to 256 projects per host.
Larger inventories require a qualified partitioned collector and fail explicitly.

The worker validates host, authority, project identities and counter bounds.
One short management transaction records an immutable batch hash and all project
measurements. Every measurement has a stable source event key. Concurrent retries
reuse identical records; a changed amount, project list or batch identity fails.
The worker acknowledges the host only after commit. Lost commit or acknowledgement
responses are safe to retry. Old acknowledgements cannot remove a newer batch.
Host calls never execute inside that management transaction.

Database rows cannot be updated or deleted through ordinary roles. Worker grants
allow insertion and reading, while project RLS restricts API reads. A changed
management authority cannot silently adopt an old pending batch; restore requires
explicit accounting reconciliation. Retention/archive tooling remains open.

## Reading history

```sh
pgws usage --limit 100
pgws usage --limit 100 --cursor NEXT_CURSOR
```

The endpoint is `GET /v1/projects/PROJECT/usage`. It accepts `limit` from 1 to 200
and an opaque project-scoped `cursor`, ordering by observation end time and ID,
newest first. `measurement_kind` is `observed_gauge`. Decimal `amount` values are
strings so clients preserve integers larger than JavaScript's safe range.
Dimensions include host, authority, dataset GUID, boot identity, elapsed duration
and batch ID. No row payloads, credentials or transform keys are collected.

Python exposes `client.usage(cursor=..., limit=...)`; TypeScript exposes
`client.usage({cursor, limit, signal})`. Pages are observations available at each
request, not a database snapshot spanning concurrent deliveries. Restart a scan
to see newly delivered historical samples.

SQL/HTTP tests cover missing ACKs, concurrent retries, immutable content,
transaction rollback, project scoping, pagination and decimal precision. Host
outbox tests cover restart replay and stale acknowledgements. The selected Linux
host run passed actual ZFS collection, management commit followed by a lost ACK,
retry without duplicate rows, scoped history and automatic collection by the
separate worker process.

Exact lifecycle intervals, billing integration, scrape/export metrics, historical
retention and production delivery-outage qualification remain separate work.
