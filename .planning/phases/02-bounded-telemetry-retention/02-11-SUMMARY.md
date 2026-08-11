---
phase: 02-bounded-telemetry-retention
plan: 11
subsystem: telemetry-api
tags: [sqlite, telemetry, retention, flask]
requires:
  - phase: 02-10
    provides: canonical metric history migration
provides:
  - Exact half-open five-minute pending aggregation intervals
  - Equality-only pending interval coalescing
affects: [historical-api, telemetry-retention, phase-02-verification]
tech-stack:
  added: []
  patterns:
    - Fixed five-minute SQL projections use bucket_start plus 300 seconds
    - Pending intervals coalesce only when half-open boundaries exactly touch
key-files:
  created: []
  modified:
    - dashboard/beacon/repositories.py
    - tests/test_historical_telemetry_api.py
key-decisions:
  - "A five-minute source bucket is disclosed as exactly [bucket_start, bucket_start + 300)."
  - "Only exact pending boundary equality coalesces; overlapping or gapped entries remain separate."
requirements-completed: [TEL-04, TEL-05]
metrics:
  duration: 10min
  completed_date: 2026-08-11
  tasks_completed: 1
  files_modified: 2
status: complete
---

# Phase 02 Plan 11: Exact Five-Minute Pending Intervals Summary

**Five-minute host and service aggregation backlog now reports only the exact source intervals that are present.**

## Accomplishments

- Corrected host and service five-minute pending SQL projections from a false 3,600-second end to `bucket_start + 300`.
- Restricted pending coalescing to exactly touching half-open intervals, preserving gaps and overlaps as separate rows.
- Added direct repository and Flask response regressions for host and service exact width, adjacency, durable-failure precedence, empty input, reverse-seeded ordering, and coverage separation.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py -k "five_minute and pending" -x` — passed (3 tests).
- `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py tests/test_migrations.py` — passed (58 tests, 13 subtests).
- `uv run --project dashboard python -m pytest -q` — passed.

## Task Commits

1. **Task 1: Trace exact host and service five-minute backlog through the existing history response** — `42a190b` (RED regressions), `b5cb8c7` (exact projections and strict adjacency).

## Decisions Made

- Derived pending work remains separate from coverage and never expands a five-minute source into an hourly interval.
- Durable pending or failed work still overrides only an exact matching derived interval and retains its retry metadata.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Self-Check: PASSED

- Confirmed `dashboard/beacon/repositories.py` and `tests/test_historical_telemetry_api.py` exist with the completed implementation and regressions.
- Confirmed task commits `42a190b` and `b5cb8c7` exist in local history.
- Confirmed no task commit deleted tracked files.
