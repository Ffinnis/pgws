# Local physical service

The development launcher runs a persistent service in the dedicated `pgws-lab`
Lima VM. It creates its own 8 GiB file-backed ZFS pool, a PostgreSQL 18 source with
a `notes` table, a management database, a streaming baseline and a workspace with
a one-hour TTL. This is a disposable development installation.

The VM must already have Docker, OpenZFS, Python 3, OpenSSL and systemd, with the
project mounted at its host path. The launcher builds Linux ARM64 binaries and a
native CLI. It does not install VM dependencies or format physical disks.

```sh
python3 scripts/dev.py up
python3 scripts/dev.py status
python3 scripts/dev.py cli baselines
```

Update an existing installation after changing the code:

```sh
python3 scripts/dev.py upgrade
```

The upgrade verifies the recorded ZFS pool, database container labels and systemd
units. It saves a private management dump, configuration and old binaries under
`/var/lib/pgws-dev/upgrades`, applies migrations as the database owner, replaces
executables atomically and restarts the services. Keys, authority epoch, source,
workspaces and their SQL data are retained. Existing guard processes keep their
running binary until they next restart. The command does not extend credentials,
workspace TTLs or certificates.
Run it during a development maintenance window without concurrent workspace or
source admissions. The launcher lock serializes launcher commands, not API users;
this is not a qualified rolling production upgrade.

Older installations with incompatible guard receipts are rejected before binary
replacement. Retire those legacy workspaces only after exporting any needed data.
The launcher's original project without an allocation record can migrate when
only its recorded streaming baseline remains. This migration verifies baseline
GUID and scope, checks available headroom, sets the configured ancestor quota
and durably records the ancestor GUID. It does not reseed or replace the baseline.

Failed upgrades retain their backup and can be retried. The launcher never
restores a database automatically, because that could revive revoked access.
Use [the authority recovery procedure](MANAGEMENT-RECOVERY.md) for an actual
management restore. These local dumps are not off-host disaster backups.

`python3 scripts/dev_upgrade_check.py` creates its own temporary workspace through
the API, writes SQL over verified TLS, runs the upgrade and checks preserved data,
old and new credentials, capacity history and deletion. It requires native
`psql`, a running development installation and a valid development API token.

`up` prints the baseline and workspace IDs. The API listens on
`http://127.0.0.1:18870`; Lima forwards it and the SQL loopback ports to macOS.
Client secrets are in `.local/dev-client.json`, mode 0600. The SQL trust
certificate is `.local/dev-ca.crt`. Both are excluded from Git. The initial API
token expires after 24 hours, and the development certificate after seven days.
Recreate the disposable installation when either expires. `upgrade` does not
rotate either credential.

After the example workspace expires, create a new example with:

```sh
python3 scripts/dev.py workspace
```

This keeps a current nonterminal workspace, including an intentional pause.
Otherwise it creates a new workspace with a one-hour TTL and updates the example
ID in `status`. It preserves the admission key across interrupted requests.
It does not revive a deleted generation or overwrite its data.

Use the workspace ID from `status`:

```sh
python3 scripts/dev.py cli get --id WORKSPACE_UUID
python3 scripts/dev.py cli credentials --id WORKSPACE_UUID --file credentials.json --key my-credential
```

`credentials.json`:

```json
{"expected_generation":1,"role":"owner","ttl_seconds":900}
```

The credentials command explicitly prints the password. Use its endpoint,
username and password with `sslmode=verify-full` and the absolute path to
`.local/dev-ca.crt`. The clone contains `public.notes`. The owner can run ordinary
application DDL and writes; it cannot assume the imported administrator or run
`COPY TO PROGRAM`. Reader credentials cannot write through tables or procedures.

To work with the Python client without printing secrets:

```python
import json
from pathlib import Path
from pgws import Client

config = json.loads(Path(".local/dev-client.json").read_text())
client = Client(config["url"], config["project_id"], config["token"])
baseline = client.baselines()["items"][0]["id"]
created = client.create(baseline, "my-task", key="my-task", ttl=3600)
client.wait(created["operation"]["id"])
workspace = client.get(created["workspace"]["id"])
```

Run with `PYTHONPATH=sdk/python`. Both Python and TypeScript clients are documented
in [sdk/README.md](../sdk/README.md). For request bodies and lifecycle
preconditions, see [OpenAPI](../contracts/openapi.yaml).

The API and worker run as separate unprivileged system users, `pgwsdev_api` and
`pgwsdev_worker`. Each has a separate SCRAM database login with only its matching
management role. The API receives the encryption key and public verification
key. The worker receives the signing key and private host RPC credential. The
worker group can reach the RPC socket; it cannot read host state or the source
socket. Host and watchdog run as root. SQL containers have no network and no
Docker or management access.

Inspect services inside the VM:

```sh
limactl shell pgws-lab sudo systemctl status pgws-dev-api pgws-dev-worker pgws-dev-host pgws-dev-watchdog
limactl shell pgws-lab sudo journalctl -u pgws-dev-worker -n 30
```

Host and guard process crashes are covered by the live daemon test. The host
reclaims its refused stale socket only after taking its journal lock. A recreated
guard starts closed, binds the same port and needs a new signed serving lease.
VM reboot, source reseeding and recovery from every partial creation stage remain
separate acceptance work. This development launcher does not promise reboot
recovery.

Stop and remove this installation, including its example workspaces:

```sh
python3 scripts/dev.py down
```

Cleanup selects containers by the recorded installation identity and verifies the
pool GUID before destroying it. It removes only `/var/lib/pgws-dev` and the two
local client files. The two locked service accounts remain available for a later
`up`. The VM itself remains running. Repeating `down` is safe.
