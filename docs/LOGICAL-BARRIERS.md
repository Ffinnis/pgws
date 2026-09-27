# Committed logical barriers

The private logical adapter can now prove a barrier on an idle source. It updates
one service-owned row in the publication, decodes its source COMMIT and stores
the decoded transaction end LSN in the same target transaction as application
rows and the apply checkpoint. A source commit or receiver keepalive alone
cannot complete the request. Source and target WAL positions are never compared.

This is private ingestion machinery. The returned boundary is unsigned and does
not authorize a snapshot, workspace or policy. Public authority signing, policy
revocation and host publication remain separate unfinished gates.

## Source setup and policy

Before discovery, under the onboarding DDL freeze, an operator creates these
objects using a service owner. Existing objects must be reconciled, not adopted
by name. Use a separately managed login for the marker writer:

```sql
CREATE SCHEMA _pgws_barriers;
REVOKE ALL ON SCHEMA _pgws_barriers FROM PUBLIC;
CREATE TABLE _pgws_barriers.marker (
  id bigint PRIMARY KEY,
  token uuid NOT NULL,
  expires_at bigint NOT NULL
);
INSERT INTO _pgws_barriers.marker
VALUES (1, '00000000-0000-0000-0000-000000000000', 0);
REVOKE ALL ON _pgws_barriers.marker FROM PUBLIC;
GRANT USAGE ON SCHEMA _pgws_barriers TO marker_writer;
GRANT SELECT(id), UPDATE(token, expires_at)
ON _pgws_barriers.marker TO marker_writer;
```

The writer cannot insert/delete rows, change the singleton key, or read token
values. The helper rejects owner, superuser and broader table privileges. The
source owner remains a trusted administrator; these grants do not constrain it.
Source retention is one fixed-size row. No cleanup DML or arbitrary payloads are
needed on the source.

Discovery includes the marker relation in the exact published schema. Supply
explicit `copy_original` rules for its three service-metadata columns and set
`marker_relation_oid` in the private CLI configuration to its discovered OID.
The compiler's immutable plan and target contract bind that relation. It cannot
reference application fields or be referenced by them; other relations in the
reserved schema and transformations of marker values are rejected.

Targets with markers use journal format 3. Targets without markers retain
format 2. A candidate must be built with its marker contract from the initial
seed; it cannot acquire markers by changing a running configuration.

## Issuance and retry

Run the normal private `pgws-logical run` consumer. A barrier configuration also
contains `marker_writer_dsn`, a fresh UUID `barrier_id` and an explicit UTC
`barrier_expires_at` no more than one hour ahead. Then run:

```sh
bin/pgws-logical barrier /private/logical.json
```

The result binds marker ID, source lineage, plan hash, decoded source transaction
end LSN and expiry. Keep the same ID and expiry when retrying an uncertain call.
A successful retry returns the original durable boundary. A new desired cut
needs a new UUID. Application transactions must commit before requesting the
barrier; concurrent uncommitted work is not covered.

The target reserves the ID before source mutation, under its checkpoint lock.
At most 4,096 unexpired reservations/receipts are retained. Expired entries are
collected during reservation and apply; expired backlog events cannot recreate
a usable proof. Source apply accepts a live marker only with matching reserved
claims. This prevents callers waiting during CDC lag from overflowing the
receipt budget after writing to the source. A budget failure leaves the source
row unchanged. Reserved but unapplied IDs are not evidence of freshness.

The helper checks source lineage, schema/publication and slot health and waits
at most 30 seconds for durable apply. The writer uses synchronous commit and
five-second statement/lock deadlines. A timeout can leave a committed source
marker, so retry the same identity. No automatic request signing occurs here.

Clone preparation checks the recovered source checkpoint and immutable plan,
then removes both the receipt journal and reserved marker schema in its detach
transaction. A late constraint failure during apply rolls back application
changes, marker receipt and checkpoint together.

## Executed evidence

Pinned PostgreSQL 18.6 tests passed idle-source issuance, a stopped consumer that
cannot satisfy a barrier, retry after apply, exact lost-ACK replay, preceding
application commits, changed-expiry rejection, late-constraint rollback,
pre-mutation quota rejection, expiry cleanup and clone removal. The private CLI
also exercised actual seed, CDC and barrier commands.

`TestLiveLogicalWriterZFS` captured the writer before a source transaction was
committed to the target and after recovery plus marker apply. Independent ZFS
clones recovered the corresponding data/checkpoint/marker receipts. Detach
removed service metadata and both clones accepted independent writes. This is
crash/storage evidence; public sanitized publication remains disabled.
