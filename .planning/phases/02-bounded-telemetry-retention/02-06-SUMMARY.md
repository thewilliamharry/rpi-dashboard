---
phase: 02-bounded-telemetry-retention
plan: 06
subsystem: telemetry-api
tags: [sqlite, telemetry, retention, historical-api, coverage]
requires:
  - phase: 02-05
    provides: authority-fenced telemetry observations, retention state, and sparse coverage evidence
provides:
  - Bounded mixed-tier host and service historical reads through fixed SQL shapes
  - Exhaustive D-05 availability coverage and separate pending-aggregation disclosure
  - Exact host/service selector validation and a 2,048-point historical response ceiling
affects: [phase-03-advanced-diagnosis, phase-04-history]
tech-stack:
  added: []
  patterns:
    - Fixed repository query maps with parameter-bound tier and selector values
    - Immutable source segments merged into display buckets without interpolation
    - Explicit coverage partitions independent from pending rollup evidence
key-files:
  created: []
  modified:
    - dashboard/app.py
    - dashboard/beacon/migrations.py
    - dashboard/beacon/repositories.py
    - dashboard/beacon/telemetry.py
    - dashboard/beacon/support_floor.json
    - tests/test_historical_telemetry_api.py
    - tests/test_migrations.py
decisions:
  - "Service rollups retain latency_sample_count so cross-tier latency averages use their real denominator."
  - "Coverage is an exhaustive five-state partition, while pending and failed rollups remain a separate raw-evidence disclosure."
metrics:
  duration: 21min
  completed_date: 2026-08-10
  tasks_completed: 2
  files_modified: 8
status: complete
---

# Phase 02 Plan 06: Bounded Historical Telemetry API Summary

**A bounded host/service history API now merges retained tiers without interpolation, tells callers exactly what coverage is unavailable, and exposes aggregation backlog separately from missing data.**

## Outcomes

- Added fixed, parameterized raw, five-minute, and hourly host/service query shapes, with every tier limited to the response budget plus an overflow sentinel row.
- Composed deterministic display buckets that preserve D-04 aggregates, source resolution disclosure, service durations, failure counts, and weighted latency averages.
- Completed `GET /api/telemetry/history` for exact `host + metric` or `service + port` selectors; invalid, duplicate, mixed, future, oversized, and malformed requests fail before SQLite reads.
- Added an ascending, non-overlapping coverage partition using only `observed`, `collection_gap`, `unknown`, `expired`, and `not_yet_monitored`; pending/failed rollups are returned as `aggregation_pending` without hiding raw evidence.
- Preserved the legacy one-day `/api/history` array route unchanged.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py tests/test_release_contract.py -x` — passed (26 tests, 7 subtests).
- `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py -x` — passed (22 tests, 7 subtests).
- Complete repository suite, run in bounded groups: 199 tests passed, plus 242 subtests.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical functionality] Persisted the latency sample denominator for exact rollup merging**
- **Found during:** Task 1
- **Issue:** Existing service rollups stored an average but not the number of latency-bearing checks, so a cross-tier average could not be weighted exactly.
- **Fix:** Added additive migration 6 and propagated `latency_sample_count` through rollup creation, aggregation, fixed reads, and migration support metadata.
- **Files modified:** `dashboard/beacon/migrations.py`, `dashboard/beacon/telemetry.py`, `dashboard/beacon/repositories.py`, `dashboard/beacon/support_floor.json`, `tests/test_migrations.py`
- **Commit:** `0a058dd`, `6dd5962`

**2. [Rule 1 - Bug] Corrected raw-tier and service display-bucket query details**
- **Found during:** Task 2 verification
- **Issue:** The raw host CTE omitted its timestamp after adding exact cadence evidence, and the service bucket seed was offset by an extra modulo operation.
- **Fix:** Carried the timestamp through the host CTE and aligned service display buckets with the fixed sample query.
- **Files modified:** `dashboard/beacon/repositories.py`
- **Commit:** `ed93f7e`

**3. [Rule 1 - Bug] Updated the validated migration support-floor contract**
- **Found during:** Full-suite verification
- **Issue:** Existing schema tests and both support-floor manifests still declared migration 5 as the final target after migration 6 was added.
- **Fix:** Advanced the expected target and kept the migration-five rollback test scoped to migration 5.
- **Files modified:** `dashboard/beacon/support_floor.json`, `tests/fixtures/legacy/support-floor.json`, `tests/test_migrations.py`
- **Commit:** `6dd5962`

## Known Stubs

None.

## Self-Check: PASSED

- Confirmed all required telemetry API files exist.
- Confirmed task commits `e63ea28`, `0a058dd`, `549f52b`, `ed93f7e`, and `6dd5962` exist in git history.
- Confirmed no tracked files were deleted by this plan.
