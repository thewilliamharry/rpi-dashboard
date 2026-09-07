---
phase: 02-bounded-telemetry-retention
plan: 01
subsystem: telemetry-api
tags: [flask, sqlite, telemetry, retention, pytest]

requires:
  - phase: 01-behavioral-safety-runtime-ownership
    provides: Versioned SQLite migrations, managed database connections, and durable worker authority.
provides:
  - Bounded host telemetry history API with explicit coverage metadata.
  - Deterministic Wave 0 retention, migration, and worker-epoch fixtures.
affects: [02-03-retention, 02-04-rollups, 02-05-worker-epochs, 02-06-analytics-api]

tech-stack:
  added: []
  patterns:
    - Framework-free historical range and coverage policy.
    - Fixed-shape allowlisted SQLite telemetry reads.
    - Injected UTC clocks for deterministic retention and authority tests.

key-files:
  created:
    - dashboard/beacon/telemetry.py
    - tests/test_historical_telemetry_api.py
    - tests/test_telemetry_retention.py
  modified:
    - dashboard/beacon/repositories.py
    - dashboard/app.py
    - tests/test_migrations.py

key-decisions:
  - "Host history preserves the exact requested half-open bounds, returns at most 2,048 points, and exposes coverage rather than interpolating gaps."
  - "Wave 0 retention tests use an injected integer UTC clock and real SQLite worker lease transitions, never wall-clock sleeps."
  - "Migration preservation compares legacy row values as well as row counts for each source table present in a supported fixture."

patterns-established:
  - "Telemetry range path: validate framework-free policy before the repository opens a bounded allowlisted query."
  - "Migration fixtures: snapshot source-table columns before upgrade, then assert the same values after upgrade despite additive schema changes."

requirements-completed: [TEL-04, TEL-05]

metrics:
  duration: 16 min
  completed_date: 2026-08-10
  tasks_completed: 2
  files_changed: 6
status: complete
---

# Phase 02 Plan 01: Bounded host telemetry tracer and Wave 0 fixtures Summary

Bounded raw host telemetry now travels from validated Flask input through a fixed SQLite query to an explicit, non-interpolated historical response, supported by deterministic retention and migration fixtures.

## Accomplishments

- Added a policy module for validated half-open ranges, the 2,048-point resolution ladder, and deterministic coverage coalescing.
- Added `GET /api/telemetry/history` for bounded host CPU, RAM, disk, and temperature history while retaining `/api/history` compatibility.
- Added real-SQLite tracer tests for valid, invalid, empty, and single-sample historical requests.
- Established injected-clock fixtures for exact 7/30/90-day cutoffs, host/service/event rows, coverage, and Worker A-to-B authority takeover.
- Expanded migration preservation coverage to compare representative legacy values and counts for every table present in supported fixtures.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py -x` — passed: 3 tests, 7 subtests.
- `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py tests/test_migrations.py -x` — passed: 21 tests, 7 subtests.
- `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py` — passed: 6 tests, 7 subtests.
- `uv run --project dashboard python -m pytest -q tests/test_migrations.py tests/test_release_contract.py -x` — passed: 32 tests.

## TDD Gate Compliance

- Task 1 RED/GREEN: `33c3d1f` → `40f9794`.
- Task 2 RED/GREEN: `ecf8c73` → `8146b92`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Preserve source fixture columns when comparing migrated rows**
- **Found during:** Task 2 verification
- **Issue:** The first reusable snapshot treated additive migration tables and columns as legacy data, causing a false preservation failure.
- **Fix:** Recorded the source tables and columns in `LegacyRowSnapshot`, then compared only those same columns after migration.
- **Files modified:** `tests/test_migrations.py`
- **Commit:** `8146b92`

## Self-Check: PASSED
