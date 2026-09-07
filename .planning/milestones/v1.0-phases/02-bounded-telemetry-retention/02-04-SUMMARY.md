---
phase: 02-bounded-telemetry-retention
plan: 04
subsystem: telemetry
tags: [sqlite, retention, rollups, retries, storage-pressure]

requires:
  - phase: 02-bounded-telemetry-retention
    provides: Migration 5 rollup, coverage, and retry tables.
provides:
  - Deterministic raw-to-5-minute and 5-minute-to-hourly SQLite rollups.
  - Aggregate read-back verification before exact source deletion with durable retries.
  - Validated storage-pressure settings and hysteresis decisions for worker integration.
affects: [02-05-worker-retention, 02-06-history-api, phase-04-analytics]

tech-stack:
  added: []
  patterns:
    - Connection-injected retention batches use one SQLite savepoint per ordered bucket.
    - Historical-write permission is a pure pressure decision independent of live monitoring.

key-files:
  created: []
  modified:
    - dashboard/beacon/config.py
    - dashboard/beacon/telemetry.py
    - tests/test_telemetry_retention.py

key-decisions:
  - "Use a host-bucket job identity while preserving one aggregate row per fixed host metric, so deletion occurs only after every observed metric is verified."
  - "Keep pressure policy pure and caller-owned: it can suspend historical persistence but cannot disable safe compaction or live monitoring."

patterns-established:
  - "Aggregate, read back, mark success, then delete the exact source range inside the same bucket savepoint."
  - "Count database, WAL, and SHM bytes together and require both allocation and free-space recovery conditions."

requirements-completed: [TEL-01, TEL-02, TEL-03]
coverage:
  - id: D1
    description: "Raw host and service evidence rolls through complete 5-minute and hourly UTC buckets with deterministic aggregate fields."
    requirement: TEL-01
    verification:
      - kind: integration
        ref: "uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "Verified aggregate read-back precedes exact source deletion; failed buckets retain evidence and retry with bounded backoff."
    requirement: TEL-02
    verification:
      - kind: integration
        ref: "tests/test_telemetry_retention.py#RetentionRollupContractTests"
        status: pass
    human_judgment: false
  - id: D3
    description: "Storage pressure includes DB, WAL, and SHM accounting with reserve exhaustion and two-condition hysteresis recovery."
    requirement: TEL-03
    verification:
      - kind: unit
        ref: "tests/test_telemetry_retention.py#StoragePressureContractTests"
        status: pass
    human_judgment: false

metrics:
  duration: 18 min
  completed_date: 2026-08-10
  tasks_completed: 2
  files_changed: 3
status: complete
---

# Phase 02 Plan 04: Bounded Telemetry Retention Summary

Deterministic, retry-safe SQLite telemetry rollups preserve raw evidence until an exact aggregate read-back succeeds, while pressure policy protects bounded Pi storage without stopping live monitoring.

## Performance

- **Duration:** 18 min
- **Completed:** 2026-08-10
- **Tasks:** 2/2
- **Files modified:** 3

## Accomplishments

- Added canonical UTC bucket handling, host and time-weighted service rollups, exact 7/30/90-day ownership, and strict event expiry.
- Added bounded savepoint processing that writes and verifies aggregates before deleting only their contributing source range; failures retain sources and persist a redacted retry state.
- Added immutable telemetry settings plus DB/WAL/SHM pressure accounting, reserve exhaustion suspension, and non-flapping two-condition recovery.

## Task Commits

1. **Task 1: Roll complete host and service buckets before deleting sources**
   - `aa1a2ce` test(02-04): add failing retention rollup contract
   - `98a8e81` feat(02-04): implement verified telemetry rollups
2. **Task 2: Bound storage pressure with backlog reserve and hysteresis**
   - `1f5dfda` test(02-04): add failing storage pressure contract
   - `1713908` feat(02-04): add telemetry storage pressure policy

## Files Created/Modified

- `dashboard/beacon/telemetry.py` — retention policy, rollup/savepoint engine, retry records, and pressure state machine.
- `dashboard/beacon/config.py` — validated telemetry retention, batch, retry, allocation, and reserve environment settings.
- `tests/test_telemetry_retention.py` — executable rollup, cutoff, failure, retry, event, settings, and pressure evidence.

## Decisions Made

- Host raw rows are deleted only after all observed fixed metrics in their shared bucket are verified, with a single durable host-bucket job identity.
- Storage pressure returns an explicit historical-write decision; later worker wiring owns persistence-state recording and leaves safe rollup compaction available.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected the failed-retry INSERT placeholder count**
- **Found during:** Task 1
- **Issue:** The first retry-state insertion bound one more SQL value than the durable job schema accepts.
- **Fix:** Matched the failed-job insert value list to its nine schema columns before re-running retry preservation tests.
- **Files modified:** `dashboard/beacon/telemetry.py`
- **Verification:** Focused retry test and plan-level telemetry verification pass.
- **Committed in:** `98a8e81`

**Total deviations:** 1 auto-fixed (1 Rule 1 bug)

## Issues Encountered

None.

## User Setup Required

None - all settings have safe environment defaults and no external service configuration is required.

## Next Phase Readiness

Plan 02-05 can inject `RetentionPolicy` from `Settings`, measure the database filesystem, persist pressure/coverage state under worker authority, and schedule `run_retention_batch()` without changing its transactional ordering.

## Self-Check: PASSED

- Confirmed all three implementation/test files exist.
- Confirmed task commits `aa1a2ce`, `98a8e81`, `1f5dfda`, and `1713908` exist.
- Plan-level verification passed: `32 passed, 7 subtests passed`.

---
*Phase: 02-bounded-telemetry-retention*
*Completed: 2026-08-10*
