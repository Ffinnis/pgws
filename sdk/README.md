# PGWS clients

Both clients require an explicit idempotency key for writes and preserve structured API errors. Reuse the same key after a timeout or OPERATION_PENDING response. A wait timeout does not cancel or remove the workspace. Clients refuse insecure remote HTTP and do not follow redirects with bearer credentials.

## Python

Requires Python 3.10+. The client has no runtime dependencies. Add `sdk/python` to PYTHONPATH, or install that directory as a local package.

```python
from pgws import Client

client = Client(url, project_id, api_token)
created = client.create(baseline_id, "task-42", key="create-task-42", ttl=3600)
client.wait(created["operation"]["id"])
workspace = client.get(created["workspace"]["id"])
credential = client.credentials(workspace["id"], workspace["generation"], key="credential-task-42")
# Pass credential to your PostgreSQL driver. Do not log the password.
client.wait(client.delete(workspace["id"], workspace["generation"], key="delete-task-42")["id"])
```

Call `barrier(source_id, key=...)` only after the source transaction has committed. Pass the returned token as `freshness={"mode":"at_least", "barrier_token":...}`. Explicit snapshot selection uses `{"mode":"snapshot", "snapshot_id":...}`.

Administrators can read `client.source(source_id)` and call
`client.reseed_source(source_id, source["source_epoch"], key="reseed-request-1")`.
Wait for the returned operation before using its new baseline. Existing
workspaces retain their writes. See [source generations](../docs/SOURCE-RESEED.md).

## TypeScript

`sdk/typescript` provides native ESM plus TypeScript declarations. Node.js 22+ supplies fetch and AbortSignal; no build step or runtime dependency is required.

```typescript
import { Client } from "./sdk/typescript/index.mjs";

const client = new Client({url, projectId, token});
const created = await client.create({
  baseline_id: baselineId,
  task_id: "task-42",
  freshness: {mode: "latest"},
  resource_profile: "small",
  ttl_seconds: 3600,
}, "create-task-42");
await client.wait(created.operation.id, {signal: abortController.signal});
const workspace = await client.get(created.workspace.id);
```

For package imports, install the local directory and import `@pgws/client`; its package exports select `index.d.ts` automatically. Credentials contain a password and are returned only by the explicit credentials method.

The corresponding administrator methods are `source(sourceId)` and
`reseedSource(sourceId, source.source_epoch, "reseed-request-1")`.

## Capacity history

`client.usage(cursor=..., limit=...)` in Python and
`client.usage({cursor, limit, signal})` in TypeScript return project-scoped
observed capacity gauges. Amounts remain decimal strings to preserve precision.
These samples are not billable durations. See [usage semantics](../docs/USAGE.md).

## Tests

```sh
python3 -m unittest discover -s sdk/python
npm test --prefix sdk/typescript
make host-lab
```

The SDK unit tests verify terminal error propagation, idempotent retry keys, redirect handling and cancellation. The Linux daemon fixture also runs Python against the real service for barrier/create/wait/credentials/delete.
