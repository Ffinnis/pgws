# Approved TCP sources

The host administrator provisions the source endpoint and secret reference pair.
API clients select those references; they cannot submit a hostname, address or
password. A TCP source configuration uses the following fields:

```json
{
  "host": "source.example.internal",
  "port": 5432,
  "approved_addresses": ["10.20.30.40"],
  "root_certificate": "/etc/pgws/source-ca.pem",
  "user": "pgws_source_admin",
  "password_file": "/etc/pgws/source-password",
  "database": "postgres",
  "approved_databases": ["postgres"]
}
```

The password file is private, regular and contains only the password. The CA
file supplies the trusted certificates; omitting it uses the host's trust roots.
The native TLS fixture uses ECDSA/SHA-256. With the pinned pgx 5.11.0 client,
an Ed25519-signed source certificate failed SCRAM channel binding negotiation;
that combination is not supported. Certificate verification remains enabled.
The source role needs the catalog and physical replication privileges required
by inspection, backup and slot management. The narrow supported catalog profile
is unchanged.

`approved_addresses` contains one to eight canonical IP addresses. Neither the
host's SQL inspection nor its replication broker resolves DNS at connection time.
Both connect only to the approved addresses and port, and verify TLS against
`host`. A DNS change therefore requires a separate administrator decision.
TLS 1.2 or later is required. A server refusing TLS cannot receive the startup
packet or credentials. Link-local, multicast, unspecified and known cloud
metadata addresses are rejected. Explicit private and loopback addresses are
supported for self-hosted deployments; administrators must keep management and
other internal services outside the approved source list.

The host starts its own `pgws-host source-broker` child using the current
executable by default. Library callers must set `source_broker_binary` to the
absolute pgws-host executable path. The child has a private root-owned control
socket and a separate Unix replication socket mounted only in the baseline.
Baseline and workspace containers retain `network=none`. Workspaces do not
receive the upstream socket or source passfiles.

The broker permits at most eight physical replication connections under the
configured source username. It rejects ordinary SQL, logical replication,
startup options and cancel packets. PostgreSQL authenticates the forwarded
replication session; the broker does not retain or log the password. The broker
advertises ordinary SCRAM on its local Unix hop because that client cannot bind
authentication to the broker's upstream TLS session. It requires the upstream
SASL offer to include SCRAM-SHA-256 and bounds the authentication prelude. It does
not promise end-to-end SCRAM-PLUS through the broker. Discovery, barriers and
slot management use the host's separately pinned TLS SQL connection and can
negotiate SCRAM-PLUS directly.

The broker configuration is immutable for that source generation. Registration
replay and fresh capture restart a dead broker under its existing identity. The
normal host daemon also checks established sources every five seconds, skips
busy source operations, verifies their dataset/container and restores a dead
broker without waiting for a workspace request. A
durable safety stop prevents restart. Revocation and the independent watchdog
close the broker and remove the baseline runtime before owned-slot cleanup.
Explicit reseeding is described in SOURCE-RESEED.md. TCP reseed passed with separate broker generation/socket identity, preserved
old workspace data and a fresh capture from the new generation. Host reboot
qualification remains open.

Updating the contents of the existing approved password file does not require
reseeding. Maintenance and capture refresh the external passfile through an
atomic rename with the runtime owner and mode 0600 already set. An invalid
replacement leaves the old file intact. Established sessions keep running;
their next connection uses the new secret. Changing the endpoint, username,
secret-reference identifier or file path is not supported by this mechanism.

`python3 scripts/host_lab.py --test-pattern '^TestLiveTCPSource$'` exercises an
actual PostgreSQL 18 native TLS listener. Fixture relays carry opaque bytes into
the source container; PostgreSQL terminates TLS and `pg_stat_ssl` confirms the
negotiated protocol. The test verifies SCRAM, basebackup, WAL replay, password
rotation, idle host-daemon recovery, a fresh clone after a second broker SIGKILL,
and revocation. This is not evidence for cloud routing, host reboot or a stalled
root process. The unit suite separately
checks certificate/name rejection, TLS refusal, address pinning and forbidden
startup packets.
