---
phase: 02-bounded-telemetry-retention
plan: 08
subsystem: telemetry-retention
tags: [sqlite, telemetry, retention, rollups, retries]

requires:
  - phase: 02-bounded-telemetry-retention
    provides: Settings-backed retention policy, durable rollup jobs, and aggregate-before-delete rollups.
provides:
  - Closed-bucket hourly expiry at the exact configured retention cutoff.
  - Due-only, bounded rollup candidate admission using durable job identities.
affects: [02-09-source-evidence-fallback, historical-telemetry-api]

tech-stack:
  added: []
  patterns:
    - Hourly retention deletes only rows whose half-open bucket end is at or before the cutoff.
    - Each source class limits SQL admission before deterministic global rollup batching.

key-files:
  created:
    - .planning/phases/02-bounded-telemetry-retention/02-08-SUMMARY.md
  modified:
    - dashboard/beacon/telemetry.py
    - tests/test_telemetry_retention.py

key-decisions:
  - "Use bucket_start + bucket_seconds <= cutoff for irreversible hourly expiry while retaining strict event timestamp expiry."
  - "Admit only jobless or due pending/failed rollup work; succeeded and deferred jobs never take batch capacity."

patterns-established:
  - "Retry admission joins each source class to telemetry_rollup_jobs using its exact durable stream and bucket key before applying the per-class cap."

requirements-completed: [TEL-01, TEL-03]

coverage:
  - id: D1
    description: "Hourly host and service rollups retain a bucket crossing a non-hour-aligned retention cutoff and expire closed buckets."
    requirement: TEL-01
    verification:
      - kind: unit
        ref: "tests/test_telemetry_retention.py#test_non_aligned_hourly_expiry_keeps_crossing_host_and_service_buckets"
        status: pass
    human_judgment: false
  - id: D2
    description: "Persisted retry due times govern bounded rollup admission without premature source deletion or duplicate retry effects."
    requirement: TEL-03
    verification:
      - kind: unit
        ref: "tests/test_telemetry_retention.py#test_pre_due_host_and_service_jobs_preserve_sources_until_exact_due_time"
        status: pass
      - kind: unit
        ref: "tests/test_telemetry_retention.py#test_deferred_and_succeeded_jobs_do_not_consume_new_work_batch_capacity"
        status: pass
    human_judgment: false

metrics:
  duration: 3 min
  completed_date: 2026-08-11
  tasks_completed: 2
  files_changed: 3
status: complete
---

# Phase 02 Plan 08: Closed-bucket expiry and due-only retry admission Summary

**Hourly telemetry now expires only after its full bucket closes, while persisted retry deadlines control bounded host and service rollup admission.**

## Performance

- **Duration:** 3 min
- **Started:** 2026-08-11T06:08:34Z
- **Completed:** 2026-08-11T06:12:03Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Replaced start-only hourly host and service expiry with a half-open bucket-end predicate, preserving a bucket that overlaps a non-hour-aligned cutoff.
- Kept the existing strict event timestamp rule so an event exactly at the cutoff remains retained.
- Made raw and five-minute source candidate queries join durable rollup jobs by their exact identities, admitting only new or due pending/failed work.
- Capped each of the four source classes before deduplication and the stable global batch cap, so deferred or succeeded work cannot starve eligible new buckets.

## Task Commits

1. **Task 1: Expire only fully closed hourly host and service buckets**
   - `36db984` — `test(02-08): add failing hourly expiry regression`
   - `c062ac3` — `fix(02-08): expire only closed hourly buckets`
2. **Task 2: Enforce persisted due times before bounded rollup admission**
   - `c1f97d6` — `test(02-08): add failing retry admission regressions`
   - `ebed18e` — `fix(02-08): admit only due rollup retries`

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` — passed: 17 tests, 6 subtests.
- `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py` — passed: 10 tests, 7 subtests.

## Files Created/Modified

- `dashboard/beacon/telemetry.py` — closed-bucket hourly expiry and bounded due-only candidates for raw and hourly rollups.
- `tests/test_telemetry_retention.py` — non-aligned expiry, pre-due/exact-due, success idempotence, and batch-cap regressions.
- `.planning/phases/02-bounded-telemetry-retention/02-08-SUMMARY.md` — execution record and verification evidence.

## Decisions Made

- Preserved the D-02 half-open retention rule without rounding a non-aligned cutoff.
- Kept aggregate verification, savepoint rollback, succeeded markers, and exact source deletion ordering unchanged on every retry path.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan 02-09 can address only the remaining source-evidence query fallback without reopening expiry or durable retry admission behavior.

## Self-Check: PASSED

*Phase: 02-bounded-telemetry-retention*
*Completed: 2026-08-11*
