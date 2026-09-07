---
phase: 01-behavioral-safety-runtime-ownership
plan: 01
subsystem: runtime-ownership
tags: [flask, apscheduler, sqlite, browser-ui, compatibility-tests]
requires: []
provides:
  - Side-effect-free Flask and worker imports with explicit worker lifecycle ownership
  - Persisted worker-heartbeat freshness and monitoring-gap recovery events
  - Compatibility contracts for Beacon's browser-facing routes and payloads
affects: [worker-composition, module-extraction, migrations, dashboard-ui]
tech-stack:
  added: []
  patterns: [explicit-main-entrypoint, persisted-worker-heartbeat, real-sqlite-compatibility-contracts]
key-files:
  created: [tests/test_runtime_ownership.py]
  modified: [dashboard/app.py, dashboard/worker.py, dashboard/app.js, dashboard/style.css, tests/test_api_and_auth.py, tests/test_release_contract.py, tests/helpers.py]
key-decisions:
  - "Only worker.main() owns database preparation, recovery, scheduler construction, signals, and scheduler startup."
  - "Worker freshness is a server-derived, non-blocking dashboard condition distinct from browser/API disconnection."
patterns-established:
  - "Runtime ownership: import modules define routes and jobs only; explicit process entrypoints perform lifecycle I/O."
  - "Compatibility tests seed real temporary SQLite data and assert browser-consumed field names."
requirements-completed: [FND-01, FND-03, FND-04]
coverage:
  - id: D1
    description: "Side-effect-free web and worker imports with an idempotent explicit worker startup path."
    requirement: FND-03
    verification:
      - kind: integration
        ref: "tests/test_runtime_ownership.py#RuntimeOwnershipTests"
        status: pass
    human_judgment: false
  - id: D2
    description: "Persisted worker freshness, recovery-gap events, and a distinct non-blocking dashboard warning."
    requirement: FND-04
    verification:
      - kind: integration
        ref: "tests/test_runtime_ownership.py#test_recovery_records_one_bounded_monitoring_gap"
        status: pass
    human_judgment: false
  - id: D3
    description: "Existing browser routes, payload fields, stored service metadata, previews, uptime, events, and mutation safeguards are pinned before extraction."
    requirement: FND-01
    verification:
      - kind: integration
        ref: "dashboard/.venv/bin/python -m pytest -q"
        status: pass
    human_judgment: false
duration: 6min
completed: 2026-07-25
status: complete
---

# Phase 01 Plan 01: Runtime Ownership Tracer and Compatibility Baseline Summary

**Explicit worker lifecycle ownership with persisted heartbeat freshness, recovery-gap events, a usable stale-monitoring warning, and protected dashboard API contracts.**

## Performance

- **Duration:** 6 min
- **Started:** 2026-07-25T07:21:24Z
- **Completed:** 2026-07-25T07:27:02Z
- **Tasks:** 2/2
- **Files modified:** 8
- **Verification:** 43 focused tests passed; 49 full-suite tests passed.

## Accomplishments

- Removed import-time web and worker lifecycle work; `worker.main()` now exclusively performs runtime initialization, recovery, heartbeat, scheduler setup, signal registration, and startup.
- Added server-derived stale-worker fields to `/api/scan-status`, a bounded durable `monitoring_gap` event on recovery, and a separate live browser warning that preserves dashboard controls.
- Added real-SQLite compatibility coverage for static assets, dashboard APIs, payload field names, thumbnail behavior, health/readiness, optional Prometheus metrics, metadata, scan handling, uptime, events, and security checks.

## Task Commits

1. **Task 1: Trace worker freshness from explicit startup to a usable dashboard warning**
   - `2f79cdc` — `test(01-01): add runtime ownership regressions` (RED)
   - `3878872` — `feat(01-01): make worker ownership explicit` (GREEN)
2. **Task 2: Pin the relied-upon compatibility boundary before extraction**
   - `96feed0` — `test(01-01): pin dashboard compatibility contracts`
   - `a47eadc` — `test(01-01): remove obsolete startup bypass`

## Files Created/Modified

- `dashboard/app.py` — reports persisted worker freshness and records recovery monitoring gaps without import-time runtime I/O.
- `dashboard/worker.py` — exposes an explicit, idempotent `main()` startup boundary and scheduler builder.
- `dashboard/app.js` — separates API connection state from worker staleness and renders recovery feedback/events.
- `dashboard/style.css` — styles the accessible stale-worker warning independently from the connection banner.
- `tests/test_runtime_ownership.py` — covers fresh imports, worker ownership, stale status, recovery gaps, and browser-warning source contract.
- `tests/test_api_and_auth.py`, `tests/test_release_contract.py`, `tests/helpers.py` — pin browser contracts and remove the obsolete import-time startup bypass.

## Decisions Made

- Worker freshness is calculated only from the persisted server-side heartbeat; missing or expired state is stale but does not mark the web process disconnected.
- Recovery writes one `monitoring_gap` record with bounded start/end timestamps before a new heartbeat becomes authoritative.
- The dashboard keeps scan, metadata, links, and theme controls usable while monitoring is stale; the connection alert remains reserved for actual API polling failure.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Test harness bug] Corrected the new runtime test's helper unpacking.**
- **Found during:** Task 1
- **Issue:** `load_app()` returns `(app_module, db_path)`, so the initial test attempted to call `init_db()` on a tuple instead of reaching the intended RED failure.
- **Fix:** Unpacked the helper result and cleaned up its temporary database correctly.
- **Files modified:** `tests/test_runtime_ownership.py`
- **Verification:** The focused RED test then failed only because import-time startup created its sentinel database.
- **Committed in:** `2f79cdc`

**2. [Rule 2 - Missing critical functionality] Preserved the worker's immediate initial metric sample inside `worker.main()`.**
- **Found during:** Task 1
- **Issue:** Moving startup work behind `main()` initially omitted the existing first metric sample, delaying first dashboard statistics after worker startup.
- **Fix:** Kept `sample_metrics()` in the explicit startup sequence and asserted its single invocation.
- **Files modified:** `dashboard/worker.py`, `tests/test_runtime_ownership.py`
- **Verification:** Runtime ownership and complete test suites pass.
- **Committed in:** `3878872`

---

**Total deviations:** 2 auto-fixed (1 Rule 1, 1 Rule 2).
**Impact on plan:** Both corrections preserve the intended tracer behavior and existing dashboard availability without adding scope.

## Issues Encountered

None after the focused test-harness correction.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Later Phase 1 extraction work can rely on an import-safe web surface, a single worker lifecycle owner, persisted worker freshness, and browser/API compatibility tests. No high-severity threat-model mitigation remains unresolved for this plan.

## Self-Check: PASSED

- Required runtime ownership test file exists.
- All four task commits exist in git history.
- Focused and complete pytest suites passed.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-07-25*
