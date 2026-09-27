# Private PostgreSQL profile reader

`pgws-discover` now reads aggregate column profiles from one explicit relation
through a private Unix socket. It is an administrator tool inside the trusted
boundary. It cannot register a public discovery finding, approve copying or
publish a sanitized baseline.

```json
{
  "source_dsn": "host=/private/source-socket dbname=application user=discovery sslmode=disable",
  "relation": {
    "source_id": "12345678-1234-1234-1234-123456789abc",
    "source_epoch": 1,
    "schema": "public",
    "table": "people"
  },
  "statement_timeout_ms": 500,
  "job_timeout_ms": 5000
}
```

Save this configuration with mode 0600 and run
`bin/pgws-discover /private/discovery.json`. The result contains the source/epoch,
relation OID, profile-metadata fingerprint, aggregate profiles, row/byte counts,
attempts and incomplete reason. `review_required` is always true. Source identity
is an operator assertion here, not independently verified management authority.
The fingerprint covers the inspected relation/column metadata, not the complete
logical transformation schema. Do not substitute it for a policy schema hash.

The reader owns its connection and uses a read-only transaction. It rejects
superuser, create-role/database, replication and bypass-RLS identities, relation
ownership and write privileges on the selected relation. The discovery role
needs only schema USAGE and table SELECT. RLS, foreign tables, views, inheritance
and partitioned relations are outside this reader's supported scope. Catalogs
are read after acquiring an ACCESS SHARE relation lock. This prevents a type
change between inspection and the bounded SELECT. Catalog metadata is read once
for at most 64 live columns, excluding comments and default expressions.

The SELECT reads eligible fields together with `TABLESAMPLE SYSTEM` and
`LIMIT 64`. A reltuples estimate chooses the rate. One retry at a higher rate is
allowed only when the first attempt returned zero rows, so attempts cannot
duplicate or exceed 64 returned rows. There is no exact count, random sort or
scan per column. Small samples remain partial; even 64 rows do not establish
representativeness or absence of sensitive values.

Only built-in booleans, integers, floats, dates, timestamps, UUIDs and
VARCHAR/CHAR with declared length at most 64 characters are sampled. UTF8 makes
that string limit at most 256 bytes. Generated columns, unlimited text/numeric,
JSON, arrays, domains and custom types get metadata and incomplete/unsupported
evidence without reading values. No substring operation is applied to a large
TOAST value. This conservative type restriction needs separate extension for
ordinary unbounded text fields.

Each statement and lock wait has a maximum 500 ms timeout. The default job
deadline is five seconds, configurable up to 30 seconds. Cancellation closes
the transport; the connection never returns to a pool. Returned values are
checked against 256 bytes each and 8 MiB total. A sampling failure discards
partial values and returns incomplete metadata-only evidence. Failures before
catalog inspection return a generic error. Sampling is time-bounded, not a hard
bound on PostgreSQL pages read or storage latency.

Raw values remain in memory only and never appear in results or errors. The
reader removes pgx tracing and notice callbacks. It rejects some obvious
sensitive identifier forms, including email-like names and common secret
prefixes. This is incomplete detection: identifiers can themselves contain
personal information. Keep the output private and review metadata before
corpus export. No secure memory erasure or automatic anonymization is claimed.

Tests use a disposable PostgreSQL cluster and a separate SELECT-only role.
They cover aggregate-only output, 256-byte UTF8, oversized/opaque/generated
exclusions, role/RLS rejection, literal identifier rejection, empty samples,
metadata drift and connection cleanup after a blocked relation times out.

PostgreSQL references: [TABLESAMPLE semantics](https://www.postgresql.org/docs/18/sql-select.html),
[attribute type modifiers and generated columns](https://www.postgresql.org/docs/18/catalog-pg-attribute.html),
[statement and lock timeouts](https://www.postgresql.org/docs/18/runtime-config-client.html).
