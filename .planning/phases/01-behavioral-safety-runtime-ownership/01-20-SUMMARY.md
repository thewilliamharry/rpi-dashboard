---
phase: 01-behavioral-safety-runtime-ownership
plan: 20
subsystem: runtime-ownership
tags: [sqlite, worker-lease, durable-queue, fencing, apscheduler, playwright]
requires:
  - phase: 01-19
    provides: worker lifecycle ownership and deferred non-blocking scheduler shutdown
provides:
  - opaque worker-owner epochs atomically fence every scan and preview mutation
  - rollback-safe preview result, thumbnail, and event persistence after durable-owner validation
  - lease-loss admission closure and lifecycle-thread draining before Chromium cleanup
affects: [worker, durable-queues, previews, runtime-ownership]
tech-stack:
  added: []
  patterns:
    - transaction-local durable-owner assertion alongside row/revision fencing
    - process-local admission drain that never replaces SQLite authority
key-files:
  created: []
  modified:
    - dashboard/beacon/queues.py
    - dashboard/app.py
    - dashboard/beacon/worker_main.py
    - tests/test_durable_queues.py
    - tests/test_runtime_ownership.py
key-decisions:
  - "Every worker acquisition rotates an opaque owner epoch; worker IDs alone are never durable queue authority."
  - "Lease loss closes local job admission before non-blocking scheduler shutdown, while the lifecycle thread drains work before Chromium cleanup."
patterns-established:
  - "Queue mutation: prove current worker epoch in the same BEGIN IMMEDIATE transaction as the existing row-token or revision predicate."
  - "Lifecycle cleanup: close admission, drain active jobs without scheduler or browser locks, then close Chromium and release the matching epoch."
requirements-completed: [FND-04]
coverage:
  - id: D1
    description: "Stale worker queue operations cannot mutate scan or preview rows after successor takeover."
    requirement: FND-04
    verification:
      - kind: unit
        ref: "tests/test_durable_queues.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "Lease loss stops new work and drains admitted preview work before browser shutdown."
    requirement: FND-04
    verification:
      - kind: unit
        ref: "tests/test_runtime_ownership.py"
        status: pass
    human_judgment: false
duration: 12min
completed: 2026-08-04
status: complete
---

# Phase 01 Plan 20: Durable Worker-Epoch Fencing Summary

**Opaque per-acquisition worker epochs now atomically fence scan and preview writes, while lease loss safely stops admission and drains active work before Chromium cleanup.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-08-04T21:03:53Z
- **Completed:** 2026-08-04T21:15:46Z
- **Tasks:** 3/3
- **Files modified:** 8

## Accomplishments

- Added real-SQLite Worker A/Worker B takeover matrices for every scan and preview mutation, same-ID epoch reuse, and lifecycle drain ordering.
- Added a fresh opaque epoch to each durable worker acquisition and required it in the same SQLite write transaction as every scan/preview row and revision fence.
- Bound worker tokens to scheduled processors and added admission/drain coordination so lease loss cannot admit new work or race active previews with browser cleanup.

## Task Commits

1. **Task 1: Lock the Worker A/Worker B takeover failure into real-SQLite RED tests** — `a327e1e` (test)
2. **Task 2: Fence scan and preview mutations with the current durable owner epoch** — `56ade05` (feat)
3. **Task 3: Stop admission and drain active jobs safely after worker lease loss** — `802a969` (feat)

Supporting integration callers: `46920da` (test).

## Files Created/Modified

- `dashboard/beacon/queues.py` — persists owner epochs and validates them transaction-locally for all queue mutations.
- `dashboard/app.py` — propagates epochs through scan/preview processing and commits preview events with result-side writes.
- `dashboard/beacon/worker_main.py` — owns token propagation, loss admission closure, and deadlock-safe draining.
- `tests/test_durable_queues.py` — covers durable stale-owner rejection matrices.
- `tests/test_runtime_ownership.py` — covers lease-loss admission, drain, cleanup, and normal lifecycle paths.
- `tests/test_api_and_auth.py`, `tests/test_release_contract.py`, `tests/test_ui_safety_integration.py` — use valid durable owners for direct internal processor/queue integration calls.

## Decisions Made

- A queue-row lease is never standalone authority: worker ID plus the fresh durable epoch are proved before its mutation in the same write transaction.
- Owner epochs never appear in logs or exceptions; matching epoch release remains permitted after ordinary expiry but cannot delete a successor.
- The worker-local admission collaborator only coordinates cancellation and joining; SQLite remains the cross-process authority.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated direct integration callers for the new internal worker-token contract**
- **Found during:** Final compatibility verification
- **Issue:** Existing API, release-contract, and UI-safety tests called internal queue processors without the newly required durable owner credentials.
- **Fix:** Acquired a test worker lease and passed its exact ID/token to those internal calls.
- **Files modified:** `tests/test_api_and_auth.py`, `tests/test_release_contract.py`, `tests/test_ui_safety_integration.py`
- **Verification:** Compatibility, UI-safety, and partitioned full-suite tests pass.
- **Committed in:** `46920da`

**Total deviations:** 1 auto-fixed (1 blocking integration update).
**Impact on plan:** Necessary test-call-site alignment only; no public API, UI, schema, dependency, or outbound-policy behavior changed.

## Verification

- Passed: `dashboard/.venv/bin/python -m pytest -q tests/test_durable_queues.py tests/test_runtime_ownership.py -x` — 31 passed, 66 subtests.
- Passed: `dashboard/.venv/bin/python -m pytest -q tests/test_module_boundaries.py tests/test_api_and_auth.py tests/test_release_contract.py -x` — 39 passed, 63 subtests.
- Passed with loopback permission: `tests/test_outbound_policy.py` — 24 passed, 26 subtests; `tests/test_ui_safety_integration.py` — 1 passed; `tests/test_ui_states.py` — 7 passed.
- Passed non-loopback full-suite partition: `dashboard/.venv/bin/python -m pytest -q --ignore=tests/test_outbound_policy.py --ignore=tests/test_ui_safety_integration.py --ignore=tests/test_ui_states.py` — 127 passed, 142 subtests. The monolithic full command was also attempted, but this runner stopped before printing its final line; the passing partitions cover the complete collected suite.

## Known Stubs

None.

## Issues Encountered

- The sandbox initially denied loopback socket binding for proxy and browser tests. Rerunning those tests with the required loopback permission passed without code changes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Phase 1’s remaining FND-04/CR-01 stale-worker mutation gap is closed and its final plan is ready for phase verification.

## Self-Check: PASSED

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-08-04*
