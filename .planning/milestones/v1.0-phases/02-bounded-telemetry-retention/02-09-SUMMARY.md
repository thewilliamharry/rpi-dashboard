---
phase: 02-bounded-telemetry-retention
plan: 09
subsystem: telemetry-api
tags: [sqlite, telemetry, retention, rollups, flask]
requires:
  - phase: 02-08
    provides: due-only retry admission and closed-bucket retention behavior
provides:
  - bounded lower-tier fallback reads until completed rollups take ownership
  - durable and derived pending aggregation disclosure for host and service streams
affects: [historical-api, advanced-analytics, telemetry-retention]
tech-stack:
  added: []
  patterns: [fixed SQLite fallback predicates, completed-tier ownership, separate pending disclosure]
key-files:
  created: []
  modified: [dashboard/beacon/repositories.py, dashboard/app.py, tests/test_historical_telemetry_api.py]
key-decisions:
  - "A completed 300-second or hourly aggregate exclusively owns the source intervals it covers."
  - "Pending aggregation remains a separate response disclosure; fallback evidence participates in observed coverage."
patterns-established:
  - "Lower-tier fallback queries are module-owned, parameterized, SQLite-grouped, and sentinel-bounded."
  - "Raw host jobs use the shared host key while hourly host jobs remain metric-specific."
requirements-completed: [TEL-02, TEL-03, TEL-04]
coverage:
  - id: D1
    description: Host telemetry keeps retained raw and five-minute evidence observable until a completed replacement exists.
    requirement: TEL-02
    verification:
      - kind: integration
        ref: tests/test_historical_telemetry_api.py#host fallback and replacement regressions
        status: pass
    human_judgment: false
  - id: D2
    description: Host and service pending or failed compaction work is disclosed without replacing coverage evidence.
    requirement: TEL-03
    verification:
      - kind: integration
        ref: tests/test_historical_telemetry_api.py#pending and failed fallback regressions
        status: pass
    human_judgment: false
  - id: D3
    description: Service fallback preserves duration, latency, checks, and failure-class fields without duplicate replacement evidence.
    requirement: TEL-04
    verification:
      - kind: integration
        ref: tests/test_historical_telemetry_api.py#service fallback and replacement regressions
        status: pass
    human_judgment: false
duration: 25min
completed: 2026-08-11
status: complete
---

# Phase 02 Plan 09: Awaiting-Compaction Evidence Summary

**Bounded, non-duplicating host and service fallback telemetry remains observable until completed rollups atomically take ownership.**

## Performance

- **Duration:** 25 min
- **Completed:** 2026-08-11T06:24:51Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added fixed, parameterized raw and five-minute fallback queries for host and service evidence, guarded by completed replacement existence.
- Combined bounded derived backlog with durable pending/failed rollup jobs, including shared raw-host identity and durable metadata precedence.
- Added host and service regressions for fallback coverage, exact ownership boundaries, replacement suppression, and preserved service aggregates.

## Task Commits

1. **Task 1: Serve non-duplicating host evidence while compaction is awaiting work** — `3a23ed5` (RED tests), `25d55a7` (implementation)
2. **Task 2: Apply the same awaiting-compaction contract to services and close the phase suite** — `668fbd5`

## Files Created/Modified

- `dashboard/beacon/repositories.py` — bounded fallback ownership, derived/durable pending composition, and evidence-only service display buckets.
- `dashboard/app.py` — passes selected display resolution and cutoffs to pending aggregation reads.
- `tests/test_historical_telemetry_api.py` — host and service backlog, failure, replacement, boundary, and field-preservation matrix.

## Decisions Made

- A completed replacement suppresses only lower-tier evidence for the exact half-open interval it owns.
- Preserved source segments remain `observed`; pending aggregation never creates a new coverage state or masks unavailable history.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed empty service display buckets from fallback results**
- **Found during:** Task 2
- **Issue:** The service duration CTE could emit zero-duration buckets before the first fallback observation, falsely presenting them as source evidence.
- **Fix:** Require an actual duration or sample row before returning a service display bucket.
- **Files modified:** `dashboard/beacon/repositories.py`
- **Verification:** Focused service fallback tests and the Phase 2 suites pass.
- **Committed in:** `668fbd5`

**Total deviations:** 1 auto-fixed bug.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py -k "host and (backlog or pending or failed or replacement or boundary or fallback)" -x` — passed (5 tests).
- `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py -k "service and (backlog or pending or failed or replacement or boundary or fallback)" -x` — passed (2 tests).
- `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py` — passed (33 tests, 13 subtests).
- `uv run --project dashboard python -m pytest -q tests/test_migrations.py tests/test_release_contract.py` — passed (35 tests).
- `uv run --project dashboard python -m pytest -q` — passed after allowing the suite's local-only loopback HTTP/proxy/browser fixtures.

## Self-Check: PASSED

- Task commits `3a23ed5`, `25d55a7`, and `668fbd5` exist in local history.
- All three plan-modified files exist and contain the completed implementation and regressions.

## Next Phase Readiness

The historical telemetry API now remains bounded and truthful through backlog, pending, and failed-compaction windows without a schema change.

---
*Phase: 02-bounded-telemetry-retention*
*Completed: 2026-08-11*
