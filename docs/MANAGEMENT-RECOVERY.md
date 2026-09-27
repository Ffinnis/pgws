# Management restore

The implemented procedure performs cold recovery. It revokes restored API
tokens, credentials and policies, cancels queued/running operations, removes
source-reference approvals and quarantines existing generations. Their data and
historical evidence are retained. Operators explicitly issue new grants, approve
source references and onboard fresh sources after recovery completes.

## Operator procedure

Stop API and worker processes before restoring management. Keep their automatic
restarts disabled until sealing completes. A database cannot identify arbitrary
rollback of its own contents while receiving the old external configuration.
This entrypoint and an exhaustive external host inventory are mandatory parts
of the restore procedure. Never restore host journals from a management backup.

1. Restore into an isolated management database and apply migrations as the
   operator. Ordinary API/worker processes remain stopped.
2. Generate the external bundle. This command does not connect to SQL and refuses
   to overwrite an existing directory:

   ```sh
   PGWS_AUTHORITY_EPOCH=CURRENT_EXTERNAL_EPOCH \
   PGWS_AUTHORITY_KEY_FILE=/private/current-authority.key \
   pgwsd recovery-init --directory /private/recovery-2026-09-20 \
     --hosts host-a --operator CURRENT_OPERATOR_ID
   ```

   Output identifies `plan.json`, `signing.key` and `authority.key`. Files have
   mode 0600 in a 0700 directory; private key bytes never enter SQL or stdout.
   For an older backup, pass `--restored-epoch BACKUP_DATABASE_EPOCH`, separate
   from the current external host epoch.
3. Point the operator's `PGWS_DATABASE_URL` at the restored database and run:

   ```sh
   pgwsd recovery-begin /private/recovery-2026-09-20/plan.json
   ```

   A synchronous transaction changes the epoch, pins the new public key and
   closes restored authorizations. Exact retries are safe. Readiness, job claims,
   issuance, approval and serving renewal remain blocked.
4. Stop each host daemon and its automatic restarts. Copy its private config,
   changing only `epoch` and the base64 `authority_key` to the plan values. Run
   on the dedicated Linux host as root:

   ```sh
   pgws-host recover /private/old-host.json /private/new-host.json \
     /private/recovery-2026-09-20/plan.json
   ```

   Recovery exclusively locks both host journals, fsyncs a startup barrier,
   stops exact verified runtimes and verifies retained dataset GUIDs. Unknown
   replacement containers or conflicting GUIDs block completion. It includes
   resources created after the backup. Source slots remain for separate ownership
   reconciliation, with their server WAL cap still in force.
5. Restart host/watchdog with the new config. Install the new epoch and signing/
   public-key files for worker/API. Prepare a 0600 channels file containing every
   host in the plan:

   ```json
   [{"host":"host-a","socket":"/private/host-rpc/host.sock","token_file":"/private/host-rpc.token"}]
   ```

   ```sh
   pgwsd recovery-finish /private/recovery-2026-09-20/plan.json \
     /private/recovery-host-channels.json
   ```

   Authenticated host reads finish before SQL starts. Missing cells, wrong
   plan/epoch/key, unexpected restored hosts or conflicting volume GUIDs keep
   recovery closed. The transaction records reports, raises fences above host
   high-water marks and opens new admission.
6. Start API/worker. Verify current membership outside the restored database
   before issuing new tokens. Source references require explicit new approval;
   policies require new immutable decisions. Old workspace actions stay blocked,
   including deletion and reset. New resources can be provisioned normally.

## Interruption and retained state

Repeat the same host command after interruption. The startup barrier remains
closed even when only one journal has advanced. Epoch advancement preserves all
command records and fences. Old commands cannot complete or create unseen
resources. Reports are archived under `authority-recoveries/<epoch>.json`.

An unacknowledged old usage batch moves to
`usage/recovered-<epoch>-<batch>.json` for audit. It is never relabelled as a new
measurement. New measurements include retained disk allocation and release
memory only after runtime absence is proved.

Quarantined data, source slots and host-only project allocations need separate
reviewed cleanup. Retained-generation reopening and reconciliation of unreadable
journals are not implemented. There is no offline-cell override. Production
backup transport, encryption/key custody, RPO/RTO and power-loss qualification
remain deployment work.

## Executed evidence

`scripts/host_lab.py --test-pattern '^TestLiveAuthority'` passed on Linux ARM64,
PG18.6 and OpenZFS 2.2.2. An actual `pg_dump` predates user/policy revocation and
an additional host-only workspace. Restoration verifies SQL session closure,
failed old-login reconnection, retained GUIDs, rejection of old creates for unseen
resources, operator CLI commands and writable SQL after new grants/source approval.

Six SIGKILL boundaries pass: initial marker, stopped runtimes, command journal,
storage journal, report archive and final marker. The data-bearing restore also
kills recovery between the two journal transitions. These tests do not establish
power-loss or reboot behavior. SQL tests cover exact retries, missing/foreign
acknowledgements, privileges, quarantine, key pinning, reconstructed fences and
host I/O outside transactions.
