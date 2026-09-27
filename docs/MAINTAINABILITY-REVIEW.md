# Maintainability review, 20 September 2026

The separate task `PGWS maintainability review` applied
`thermo-nuclear-code-quality-review` and `ponytail-review` to the implementation.
The repository has no commits, so the findings describe current code, not branch
regressions. Before changing code, the implementation task checked each finding
against the callers, tests and RFC safety requirements.

| Finding | Verification and decision |
| --- | --- |
| Three repeated bounded worker pools | Accepted. Serving renewal and observation each use eight workers; the independent host watchdog uses sixteen. All use cancellation-aware submission, wait for admitted work and aggregate errors. `internal/parallel.Run` shares only this scheduling code. Each invocation has its own capacity; timeouts and authorization remain in callers. An item failure does not cancel siblings. The helper uses the standard library already available in Go 1.25. |
| Repeated durable file publication | Accepted for host state, fence journals and ingress state. `internal/atomicfile` shares temporary-file creation, writing, file sync, close, publication and parent-directory sync. `Replace` uses rename; `Create` uses an exclusive hard link. Mode 0600, EEXIST handling, JSON representation, locks, directory preparation and journal poisoning are preserved. Policy permits and streaming secrets retain their separate flows because they perform additional checks or ownership changes before publication. |
| Repeated RPC success handling | Accepted. Five endpoints return concrete response values with identical encoding/error paths. They now encode once after dispatch. Void operations still return an empty 204; JSON operations still return 200. Authentication, strict request decoding and error codes are unchanged. |

The reviewer considered repeated authorization/fence checks and operation
completion paths but did not include them in the final findings. Checks protect
different race boundaries, and completion paths have different step filters and
result handling. These paths were left as they were.

The changes remove 202 production lines and add 124, a net reduction of 78.
Regression tests are counted separately. No dependency was added.

## Validation

- Before changes, 167 tests passed across 31 Go packages.
- After changes, `go test -race ./...` passed 183 tests across 33 packages.
- `go vet ./...` passed.
- `python3 scripts/integration.py` passed 222 tests across 33 packages on an
  isolated PostgreSQL 14.20 cluster, plus CLI/daemon smoke checks.
- New tests cover worker limits, sibling error aggregation, waiting for admitted
  work after cancellation, exclusive publication races, publication failures,
  journal poisoning and restart, and RPC JSON/empty responses and rejections.
- The selected Linux/OpenZFS run passed `TestLiveDaemons` in 83.54 seconds
  and all six `TestLiveAuthorityRecoveryJournalCrashes` interruption cases.
  It exercised separate API/worker/host/guard processes, host/guard SIGKILL,
  lifecycle, SQL revocation and actual pool-pressure cutoff. Evidence is in
  `evidence/host-lab-selection-3938724ad33e.json`.
- The review task compared the final changes against the saved pre-change
  snapshot and found no actionable behavior regressions. It did not rerun the
  live labs performed by the implementation task.

File and directory sync calls are preserved; these unit tests do not qualify
power-loss behavior. The persistent development service is not upgraded by this
source refactor.
