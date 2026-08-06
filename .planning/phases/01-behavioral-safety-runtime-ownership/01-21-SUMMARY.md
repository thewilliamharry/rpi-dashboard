---
phase: 01-behavioral-safety-runtime-ownership
plan: 21
subsystem: testing
tags: [pytest, sqlite, worker-lease, ownership, regression]
requires:
  - phase: 01-20
    provides: Durable worker epochs and queue-row mutation fencing
provides:
  - Immutable P0/S1-S3/J1-J9/L1 worker ownership inventory
  - Static callback-to-surface closure checks
  - Deterministic real-SQLite RED stale-worker takeover evidence
affects: [01-22, 01-23, worker-runtime, durable-queues]
tech-stack:
  added: []
  patterns:
    - Immutable callback/surface registry shared by follow-on ownership plans
    - Real SQLite A-to-B lease takeover with current-B controls
key-files:
  created:
    - tests/worker_ownership_contract.py
    - tests/test_worker_ownership_matrix.py
  modified: []
key-decisions:
  - "Freeze all worker startup, scheduler, lifecycle, database, and effect boundaries before changing production authority."
  - "Keep filesystem publication explicit with an empty current producer set because preview bytes remain SQLite BLOBs."
patterns-established:
  - "Ownership closure: every post-acquisition callback has stable takeover, transaction, admission, effect, and current-B assertion IDs."
requirements-completed: [FND-04]
coverage:
  - id: D1
    description: Immutable production ownership registry and static callback coverage assertions.
    requirement: FND-04
    verification:
      - kind: unit
        ref: "dashboard/.venv/bin/python -m pytest -q tests/test_worker_ownership_matrix.py -k 'inventory or registry or callback_coverage' -x"
        status: pass
    human_judgment: false
  - id: D2
    description: Real-SQLite stale-A takeover matrix with current-B controls and preview-capture effect evidence.
    requirement: FND-04
    verification:
      - kind: integration
        ref: "! dashboard/.venv/bin/python -m pytest -q tests/test_worker_ownership_matrix.py --maxfail=12"
        status: fail
    human_judgment: true
    rationale: "The failures are deliberate RED evidence to be made green by Plans 01-22 and 01-23."
duration: 9 min
completed: 2026-08-06
status: complete
---

# Phase 01 Plan 21: Worker Ownership Contract Summary

**Immutable P0/S1-S3/J1-J9/L1 ownership registry with real-SQLite stale-worker RED evidence for the remaining system-wide authority, admission, and effect gaps.**

## Performance

- **Duration:** 9 min
- **Started:** 2026-08-06T19:40:00Z
- **Completed:** 2026-08-06T19:49:08Z
- **Tasks:** 2/2
- **Files modified:** 2

## Accomplishments

- Added a frozen production ownership inventory that names every startup, scheduler, and lifecycle callback plus all declared SQL and non-SQL surfaces.
- Added static composition checks for `WorkerOperations`, production bindings, startup stages, scheduler jobs, effect producers, and unclassified fields.
- Added table-driven real-SQLite Worker A-to-B takeover evidence, including a paused preview-capture effect and current-Worker-B controls.

## Task Commits

1. **Task 1: Freeze the production callback, mutation, and effect contract** — `32356b4` (test)
2. **Task 2: Check in the exhaustive real-SQLite RED takeover matrix** — `6949ee5` (test)

## Files Created/Modified

- `tests/worker_ownership_contract.py` — immutable callback, database-surface, effect-surface, and takeover-case registry.
- `tests/test_worker_ownership_matrix.py` — static composition checks plus deterministic RED A-to-B SQLite matrix.

## Decisions Made

- Freeze all worker startup, scheduler, lifecycle, database, and effect boundaries before changing production authority.
- Keep filesystem publication explicit with an empty current producer set because preview bytes remain SQLite BLOBs.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The matrix initially reused Worker B's durable lease between subcases. The planned test harness was corrected to construct a fresh temporary SQLite database per row, leaving only the expected stale-A ownership/admission/effect failures.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plans 01-22 and 01-23 can consume the unchanged registry to make the database, admission, and irreversible-effect subsets green without narrowing any declared row.

## Self-Check: PASSED

- Found: `tests/worker_ownership_contract.py`, `tests/test_worker_ownership_matrix.py`, `32356b4`, and `6949ee5`.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-08-06*
