# Source generations

An administrator can reseed a physical source through its existing approved
reference pair. Admission reserves a new source epoch, a new generation and a
new baseline UUID in one management transaction. Old baselines become retired.
Their system identity, timeline, manifests and snapshots are never relabelled.
Existing workspaces retain their own data and lineage.

Read the current epoch, including after a failed attempt:

```sh
pgws source-get --id "$source_id"
```

Submit `source-action` with a JSON file and a stable request key:

```json
{"action":"reseed","expected_source_epoch":1}
```

```sh
pgws source-action --id "$source_id" --file reseed.json --key reseed-request-1
pgws wait --id "$operation_id" --timeout 5m
```

The response includes `source_id`, `source_epoch`, `generation`, `baseline_id`
and the asynchronous operation. A repeated request key returns the same
reservation. A stale epoch or another pending source operation produces a
conflict. Failed and cancelled attempts consume their reserved generation;
the administrator can read the current epoch and submit a new request. The
worker rechecks the administrator grant, reference approval and source generation
before executing and before publishing the result.

The host serializes source work. It records a terminal stop for older generations,
removes their confirmed runtimes and brokers, and drops only confirmed slots
on the original PostgreSQL system. It then creates a separate ZFS baseline,
slot, runtime, control directory and verified backup. Current standby SQL replay
and a real ZFS capture are required before the new baseline becomes ready.
Freshness barriers from previous source epochs cannot authorize new captures.

Storage fences account for captures and collection as well as management jobs.
Collecting old snapshots uses current authority but checks the old generation's
path, GUID and ownership. Referenced snapshots remain protected. After their
references are gone and the one-hour retention has elapsed, collection can remove
even the final snapshot of a retired baseline. The old baseline dataset is then
eligible for nonrecursive deletion after runtime and slot retirement. Actual
snapshots or dependent clones prevent deletion.

The live API test passed a lost completed reseed response, renewed worker fencing,
old workspace write preservation, creation from the new baseline, a new-epoch
barrier, collection of old-generation snapshots and deletion of their final
unreferenced baseline dataset. TCP/TLS reseed passed a separate broker generation
and socket, old workspace preservation and a new-generation capture. Six SIGKILL
cases passed
after removal of the old runtime, old slot cleanup, durable retirement, during
the new backup, after capture and after streaming-state persistence. The capture
retry retained its original source lower bound.

An unconfirmed old slot is never adopted or deleted automatically. A source
whose system identifier changed also requires reconciliation of its old slot
against the original system before this reseed path can proceed. Endpoint and
secret-reference changes, automatic failover, full power-loss qualification and
sanitized policy-generation cutover remain separate work. Password-file content
rotation on the same approved reference does not require reseeding.
