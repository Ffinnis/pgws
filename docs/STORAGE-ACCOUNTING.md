# Project allocation and pool pressure

The host provisions each project's common ZFS ancestor before creating its first
baseline or clone. `quota` limits physical allocation below that ancestor,
including descendants and retained snapshots. Baselines and clones remain in the
same project subtree so sharing is counted there once. The host records the
ancestor's GUID and quota outside ZFS data, and checks them on later admission.

The default project allocation limit is 2 GiB; `project_quota_bytes` in the private
host configuration selects another limit for newly provisioned projects. The
initial provisioner treats it as immutable. Changing a configuration value does
not silently enlarge or shrink an existing project. An explicit administrative
migration must update the actual property and durable policy together. Such a
migration command is not implemented yet. Old unlabelled project ancestors are
rejected rather than automatically adopted; a fresh disposable development
installation receives the new layout.

Each generation also has a 2 GiB `refquota` in the current small-data host profile.
That protects referenced bytes, **not incremental writes above an arbitrarily
large shared origin**. The 1 TB-origin/small-growth-allowance profile remains
unqualified. Current seed-size limits also exclude that workload.

Admission requires at least 32 MiB available within the project and the configured
cell floor (`min_pool_available_bytes`, default 256 MiB). The project quota is
enforced by ZFS during writes, independently of API and worker availability.
Accounting properties include metadata and can slightly exceed the nominal quota
at the point an allocation is rejected; the live 128 MiB test observed about
60 KiB of this overhead. A quota is not a byte-exact application payload allowance.

## Read-only inspection

On the dedicated Linux host, an administrator can run this alongside the daemon:

```sh
sudo /path/to/pgws-host capacity /path/to/private-host.json
```

The JSON report checks recorded project GUIDs and includes `used`, `available`,
`quota`, `referenced` and the `usedby*` breakdown at each common ancestor.
`referenced` here describes the ancestor itself; it is not a sum of descendant
logical database sizes. `usedbychildren` includes allocation of descendant
baselines, clones and their snapshots. These are observed gauges, not billing
intervals. The worker now persists deduplicated observations through a durable
host outbox. USAGE.md defines delivery, API access and the limits of these gauges.
Exact lifecycle and billable duration accounting remain separate work.

The inspector only issues read commands and does not acquire the running host's
mutation journal. It cannot change a quota or authorize a workspace.
It also reports reserved runtime memory for the host and each project. A missing
project policy for an active generation is an error, including legacy layouts.

## Independent pressure response

The separate watchdog reads real root-dataset availability every pass. Below the
configured floor it records a terminal `POOL_PRESSURE` stop, closes existing SQL
sessions, removes affected runtimes and releases owned source slots. The source
slot cleanup still verifies source identity. Freeing space does not erase the
stop or republish the old generation; reconciliation is required. Workspace
deletion remains available for cleanup.

After OCI confirms removal of the exact container ID, the watchdog writes a
separate durable memory-release receipt bound to the container specification and
terminal stop. Admission can then reuse that memory reservation. A stop request
alone does not release memory, and an unreadable or mismatched receipt blocks
admission. The watchdog never rewrites the host's lifecycle state. Retained data
still consumes the project's ZFS allocation.

Terminal stops and release receipts publish through exclusive links, so racing
host/watchdog writers cannot replace the first decision. The receipt binds the
exact container and stop; wall-clock timestamps are audit metadata. For an
interrupted source with no recorded container, only the host holding the source
lock can release its reservation after confirming runtime absence. The watchdog
keeps such reservations charged because creation may still be in flight.

The worker independently reads durable host-stop evidence every ten seconds.
It marks the matching workspace generation failed, revokes its credentials, and
removes its endpoint from API responses. A stopped source and baseline become
blocked. These short metadata transactions compare authority, generation,
revision and fence after the host read; stale observations cannot overwrite a
newer lifecycle action. Historical successful operations retain their outcome.

This is a pressure response, not a preallocated cell emergency reservation.
Production qualification still needs the complete stall/partition campaign and a
reserved-space operational policy.

## Observed tests

`scripts/zfs_lab.py` tested a 128 MiB project quota with a 48 MiB incompressible
origin and a clone whose individual refquota was 256 MiB. Creating the clone added
about 50 KiB at the project ancestor. Further clone writes reached the project
quota after 79 MiB; a different project still wrote successfully. Deleting the
clone restored roughly 80 MiB of available project space.

`scripts/host_lab.py` lowers actual pool availability using a temporary sibling
reservation in its own file-backed pool. The independently launched watchdog
closes a live TLS SQL session and releases the baseline's owned source slot.
After the reservation is removed, the stop remains terminal and API deletion
cleans up the workspace. This fixture does not fill a physical disk or touch
user databases.
The same run verifies zero reserved memory after confirmed container removal,
continued nonzero disk allocation, and the resulting failed/blocked API metadata.
