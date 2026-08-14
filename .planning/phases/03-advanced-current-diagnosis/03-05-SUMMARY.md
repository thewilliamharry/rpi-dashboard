---
phase: 03-advanced-current-diagnosis
plan: 05
subsystem: api-ui-testing
tags: [flask, playwright, sqlite, current-diagnosis, safety]
requires:
  - phase: 03-04
    provides: Advanced workspace navigation and current-diagnosis presentation contracts
provides:
  - Truthful independent connection, worker, and recovery safety state
  - Immutable worker-heartbeat freshness and safe service ordering projection
  - Sentinel-bounded gap truncation disclosure with production-route coverage
affects: [advanced-current-diagnosis, phase-03-06]
tech-stack:
  added: []
  patterns: [route-local connection failure state, immutable callback schedule evidence, sentinel-capped SQLite reads]
key-files:
  created: []
  modified: [dashboard/beacon/diagnosis.py, dashboard/beacon/repositories.py, dashboard/advanced.js, tests/test_advanced_diagnosis_api.py, tests/test_advanced_ui.py]
key-decisions:
  - "Connection availability remains memory-only browser evidence; worker and recovery warnings remain server-derived."
  - "Worker freshness derives from J1's immutable five-second heartbeat schedule rather than metric sampling configuration."
  - "Gap truncation is based on a single sentinel row beyond the response cap, not returned-list length."
patterns-established:
  - "Production browser tests serve document assets through Beacon's Flask WSGI routes and fixture-route only the internal JSON endpoint."
requirements-completed: [TEL-06, DIA-01, DIA-03, DIA-08, UX-02]
coverage:
  - id: D1
    description: Independent connection, worker, and recovery warnings through the production advanced bundle
    requirement: DIA-01
    verification:
      - kind: automated_ui
        ref: tests/test_advanced_ui.py#connection_warning-and-production_routes
        status: pass
    human_judgment: false
  - id: D2
    description: Immutable worker freshness, safe service cadence/order, and exact bounded gap disclosure
    requirement: TEL-06
    verification:
      - kind: integration
        ref: tests/test_advanced_diagnosis_api.py#worker_safety-service_cadence-pinned_order-gap_truncation
        status: pass
    human_judgment: false
duration: 14min
completed: 2026-08-14
status: complete
---

# Phase 03 Plan 05: Truthful Current-Diagnosis Gap Closure Summary

**Advanced diagnosis now preserves last successful evidence across connection failures, classifies worker freshness from J1, and truthfully bounds service and gap evidence.**

## Performance

- **Duration:** 14 min
- **Started:** 2026-08-14T15:09:56Z
- **Completed:** 2026-08-14T15:23:44Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added independent browser-owned connection warning state while retaining server-owned worker and recovery warnings through success, failure, and recovery transitions.
- Derived worker safety from the immutable five-second J1 heartbeat cadence and covered Flask-served advanced document, JavaScript, and CSS routes with Playwright.
- Normalized unknown-service cadence and corrupt pinned ordering, and added one-row sentinel evidence for exact gap truncation.

## Task Commits

1. **Task 1: Trace truthful connection and worker safety through production routes**
   - `776f151` — test(03-05): add failing current-diagnosis regressions
   - `c6f350f` — feat(03-05): make current safety evidence truthful
2. **Task 2: Harden current service ordering and exact bounded gap disclosure**
   - `06db5c4` — test(03-05): add failing bounded diagnosis tests
   - `ac32744` — feat(03-05): harden bounded current evidence

## Files Created/Modified

- `dashboard/beacon/diagnosis.py` — J1 worker cadence, worker safety projection, safe pinned ordering, and gap truncation composition.
- `dashboard/beacon/repositories.py` — fixed deterministic gap query with a one-row sentinel.
- `dashboard/advanced.js` — memory-only connection failure state and independent safety-banner rendering.
- `tests/test_advanced_diagnosis_api.py` — worker cadence, service cadence/order, and gap-cardinality regressions.
- `tests/test_advanced_ui.py` — Flask WSGI production-route and safety-transition Playwright coverage.

## Decisions Made

- Kept the closed `1ab5db7` asset repair unchanged; this plan regression-tests its production adapters and image manifest only.
- Kept current diagnosis GET-only and effect-free: corrupt persisted metadata is normalized in projection and never repaired during reads.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Test fixture] Used the schema-valid coverage reason in the exact-cap regression**
- **Found during:** Task 2
- **Issue:** The initial test fixture used an invalid `telemetry_coverage.reason`, violating the existing SQLite check constraint before exercising truncation.
- **Fix:** Replaced it with the allowed `collection_gap` reason.
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Verification:** Focused gap cardinality regression passed for 0/1/48/49 rows.
- **Committed in:** `06db5c4`

**Total deviations:** 1 auto-fixed (Rule 1)

## Issues Encountered

None.

## Verification

- `tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py tests/test_module_boundaries.py -k "worker_safety or connection_warning or safety_combinations or production_routes or production_image_manifest"` — passed (5 tests, 14 subtests).
- `tests/test_advanced_diagnosis_api.py -k "service_cadence or pinned_order or gap_truncation or bounded"` — passed (3 tests, 10 subtests).
- Phase regression (`tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py tests/test_module_boundaries.py`) — passed (38 tests, 49 subtests).
- Full project gate (`pytest -q`) — passed (252 tests, 293 subtests; one existing system-time warning from urllib3).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Automated current-diagnosis truthfulness gaps are closed. Phase 03-06 can perform its ordered Raspberry Pi target-hardware continuity checkpoint.

## Self-Check: PASSED

- Required implementation files exist and all four 03-05 TDD commits are present in git history.
- No production stubs or new threat surface were introduced.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-14*
