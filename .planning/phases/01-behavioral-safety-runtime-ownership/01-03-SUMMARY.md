---
phase: 01-behavioral-safety-runtime-ownership
plan: 03
subsystem: runtime
tags: [python, flask, apscheduler, sqlite, playwright, worker]
requires:
  - phase: 01-02
    provides: Side-effect-free settings, repository, and web composition boundaries
provides:
  - Flask-free monitoring and preview operation interfaces
  - A worker-only APScheduler composition root with database preparation gating
  - A compatibility worker CLI shim and lifecycle ownership coverage
affects: [phase-01, monitoring, previews, scheduler, outbound-safety]
tech-stack:
  added: []
  patterns: [explicit collaborator dataclasses, worker-only lifecycle composition, TDD red-green commits]
key-files:
  created: [dashboard/beacon/monitoring.py, dashboard/beacon/previews.py, dashboard/beacon/worker_main.py]
  modified: [dashboard/app.py, dashboard/beacon/db.py, dashboard/worker.py, tests/test_runtime_ownership.py, tests/test_uptime_integration.py]
key-decisions:
  - "Keep dashboard.app as the compatibility edge while worker services receive named operation collaborators."
  - "Gate all scheduled work on explicit database preparation before recovery, heartbeat, signals, or scheduler start."
patterns-established:
  - "Worker composition: build dependencies without side effects, then perform durable lifecycle actions only in worker_main.main."
  - "Compatibility adapters preserve established dashboard and worker call signatures during extraction."
requirements-completed: [FND-01, FND-02, FND-03, FND-04]
coverage:
  - id: D1
    description: Framework-free monitoring and preview operation boundaries retain dashboard compatibility behavior.
    requirement: FND-02
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_uptime_integration.py tests/test_release_contract.py tests/test_security_and_scanning.py -x
        status: pass
    human_judgment: false
  - id: D2
    description: Worker-only scheduler composition is side-effect-free on import and database-gated at startup.
    requirement: FND-04
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py tests/test_release_contract.py -x
        status: pass
    human_judgment: false
duration: 20min
completed: 2026-07-25
status: complete
---

# Phase 01 Plan 03: Worker Runtime Ownership Summary

**Explicit monitoring and preview boundaries with a database-gated APScheduler worker composition root and compatibility-preserving CLI shim.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-07-25T07:22:00Z
- **Completed:** 2026-07-25T07:42:57Z
- **Tasks:** 2/2
- **Files modified:** 8

## Accomplishments

- Added Flask-free monitoring and preview collaborator interfaces while retaining dashboard operation signatures through adapters.
- Centralized scheduler setup, signal registration, browser shutdown, and durable startup ordering in `beacon.worker_main.main()`.
- Added a database preparation gate and lifecycle regression coverage; preserved named job cadence, executor bounds, and Docker Compose validity.

## Task Commits

1. **Task 1: Extract monitoring and preview behavior behind Flask-free interfaces** - `cdfdda5` (TDD RED), `ab0f5b5` (TDD GREEN)
2. **Task 2: Compose all scheduled work exclusively in worker_main** - `78a4c3c` (TDD RED), `38447a4` (TDD GREEN)

## Files Created/Modified

- `dashboard/beacon/monitoring.py` - Explicit, Flask-free monitoring collaborator interface.
- `dashboard/beacon/previews.py` - Explicit, lazy-worker preview collaborator interface.
- `dashboard/beacon/worker_main.py` - Sole scheduler composition root and durable lifecycle order.
- `dashboard/beacon/db.py` - Explicit worker-start database preparation boundary.
- `dashboard/app.py` - Compatibility adapters for extracted operation interfaces.
- `dashboard/worker.py` - Safe import/CLI compatibility shim delegating to `worker_main.main()`.
- `tests/test_runtime_ownership.py` - Runtime construction and ordering coverage.
- `tests/test_uptime_integration.py` - Extraction-boundary coverage.

## Decisions Made

- Kept `dashboard.app` as a compatibility edge so established monitoring and preview callers retain their signatures while dependencies become explicit.
- Made `prepare_database()` the first lifecycle action in `worker_main.main()`; failure prevents recovery, heartbeat, signals, scheduler creation, and browser use.

## Verification

- `dashboard/.venv/bin/python -m pytest -q` — 54 passed.
- `docker compose config -q` — passed.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- The worker has a single explicit composition root ready for later durable queue, migration, and outbound-policy work.
- Monitoring and preview callers retain compatibility adapters while subsequent plans can move implementations behind these interfaces.

## Self-Check: PASSED

- Verified all eight implementation and test files exist.
- Verified task commits `cdfdda5`, `ab0f5b5`, `78a4c3c`, and `38447a4` exist in Git history.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-07-25*
