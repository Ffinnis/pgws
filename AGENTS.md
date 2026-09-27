# Working on PGWS

Read docs/RFC-0001.md and docs/IMPLEMENTATION.md before changing behavior. Keep implemented scope and acceptance evidence current.

Use Go and the existing PostgreSQL/pgx stack. Keep long-running host/source effects outside management transactions. Preserve tenant/project checks, idempotency, generation checks, host fences and the separation between operation outcome and resource phase.

Never publish readiness from a mock backend, synthetic snapshot metadata or process existence. Unimplemented capabilities return an explicit error. Sanitized mode remains unavailable until its separate acceptance gates pass.

Run go test -race ./... and go vet ./... for Go changes. Run python3 scripts/integration.py for SQL, authorization, API or lifecycle changes. It creates its own disposable management database. Do not use a user's existing database as a test fixture.

The machine running this task may be macOS. Linux/OpenZFS acceptance remains separate; document what was actually executed.
