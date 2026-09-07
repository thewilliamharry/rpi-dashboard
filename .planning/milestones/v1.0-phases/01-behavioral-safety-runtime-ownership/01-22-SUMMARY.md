---
phase: 01-behavioral-safety-runtime-ownership
plan: 22
subsystem: runtime-ownership
tags: [sqlite, worker-lease, authority, durable-queues, fencing]
requires:
  - phase: 01-21
    provides: Immutable worker ownership inventory and real-SQLite takeover matrix
provides:
  - Frozen lease-derived worker authority for worker callback execution
  - Authority-aware worker queue, recovery, heartbeat, metrics, probe, cleanup, and preview adapters
  - Green database takeover subset with explicit owner-free web controls
affects: [01-23, worker-runtime, durable-queues, monitoring]
tech-stack:
  added: []
  patterns:
    - Immutable authority is built once from the acquired durable lease
    - Worker queue and recovery transactions assert current epoch after BEGIN IMMEDIATE
key-files:
  created:
    - dashboard/beacon/worker_authority.py
  modified:
    - dashboard/beacon/queues.py
    - dashboard/beacon/worker_main.py
    - dashboard/worker.py
    - dashboard/app.py
    - tests/test_worker_ownership_matrix.py
    - tests/test_durable_queues.py
    - tests/test_runtime_ownership.py
key-decisions:
  - "WorkerServices carries one immutable WorkerAuthority after durable acquisition instead of separate identity strings."
  - "Web metadata, scan enqueue, preview enqueue, rate limiting, and meta-updated writes remain explicitly owner-free."
patterns-established:
  - "Worker adapters take WorkerAuthority; queue variants retain existing row, revision, lease, deadline, and coalescing predicates."
requirements-completed: [FND-04]
coverage:
  - id: D1
    description: Immutable lease-derived authority and same-transaction queue fencing reject stale epochs, including same-ID successor rotations.
    requirement: FND-04
    verification:
      - kind: integration
        ref: "dashboard/.venv/bin/python -m pytest -q tests/test_durable_queues.py tests/test_runtime_ownership.py tests/test_worker_ownership_matrix.py -k 'database_queue or recovery_queue or web_owner_free or wave14 or plan19_authority_shape' -x"
        status: pass
    human_judgment: false
  - id: D2
    description: Database takeover matrix permits current Worker B while owner-free web work remains available without a worker owner row.
    requirement: FND-04
    verification:
      - kind: integration
        ref: "dashboard/.venv/bin/python -m pytest -q tests/test_worker_ownership_matrix.py tests/test_durable_queues.py tests/test_runtime_ownership.py -k 'database or web_owner_free or wave14 or plan19' -x"
        status: pass
    human_judgment: false
duration: 18 min
completed: 2026-08-06
status: complete
---

# Phase 01 Plan 22: Immutable SQLite Worker Authority Summary

**One lease-derived WorkerAuthority now reaches the worker callback graph and fences database takeover paths while preserving owner-free web persistence.**

## Performance

- **Duration:** 18 min
- **Started:** 2026-08-06T19:42:00Z
- **Completed:** 2026-08-06T20:00:36Z
- **Tasks:** 2/2
- **Files modified:** 8

## Accomplishments

- Added frozen, redacted `WorkerAuthority` values constructed once from the exact acquired lease and injected clock.
- Replaced split worker credentials in `WorkerServices`, queue processors, renewal, release, recovery, and preview completion with authority-taking variants.
- Bound the worker shim to authority-aware adapters and retained owner-free metadata, manual scan, and preview enqueue paths.
- Made the database takeover selection green while retaining the Plan 23 admission/effect test as executable RED evidence.

## Task Commits

1. **Task 1: Establish immutable authority and fence the queue/recovery transaction path** — `2962dd3` (test), `0f476aa` (feat)
2. **Task 2: Fence every remaining worker-originated SQLite transaction** — `82e3eaa` (feat)

## Files Created/Modified

- `dashboard/beacon/worker_authority.py` — immutable authority with normalized path, redacted epoch, and injected clock.
- `dashboard/beacon/queues.py` — public authority assertion and worker-only queue/recovery variants.
- `dashboard/beacon/worker_main.py` — acquisition-to-finalization authority propagation.
- `dashboard/app.py` and `dashboard/worker.py` — authority-taking worker adapters and production bindings.
- `tests/test_worker_ownership_matrix.py`, `tests/test_durable_queues.py`, `tests/test_runtime_ownership.py` — authority shape, owner-free, and real-SQLite database takeover evidence.

## Decisions Made

- Worker authority is an immutable value bound to the exact acquisition epoch; logs and representations omit the opaque epoch.
- Existing queue row, revision, lease, deadline, and coalescing fences remain additive to worker epoch authority.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The unfiltered ownership matrix still has its expected Plan 01-23 RED assertion: a stale preview can begin browser capture before takeover. The database-only selection passes; no admission/effect case was deleted, skipped, or reclassified.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan 01-23 can now close scheduler admission and irreversible external-effect boundaries on top of the immutable SQLite authority and green database subset.

## Self-Check: PASSED

- Found `dashboard/beacon/worker_authority.py` and task commits `2962dd3`, `0f476aa`, and `82e3eaa`.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-08-06*
