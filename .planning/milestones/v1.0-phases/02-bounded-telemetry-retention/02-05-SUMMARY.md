---
phase: 02-bounded-telemetry-retention
plan: 05
subsystem: telemetry
tags: [sqlite, retention, worker-authority, apscheduler, coverage]
requires:
  - phase: 02-04
    provides: bounded rollup, retry, and storage-pressure policy primitives
provides:
  - Authority-fenced retention callback and truthful telemetry observations
  - Cadence, unknown, and storage-pressure coverage intervals
  - Frozen worker callback inventory for every telemetry mutation surface
affects: [phase-02-plan-06, phase-03-advanced-diagnosis, phase-04-history]
tech-stack:
  added: []
  patterns:
    - Worker authority is asserted before every retention or observation mutation.
    - Historical suspension preserves current monitoring and records the missing interval explicitly.
key-files:
  created: []
  modified:
    - dashboard/app.py
    - dashboard/beacon/telemetry.py
    - dashboard/beacon/worker_main.py
    - tests/test_telemetry_retention.py
    - tests/worker_ownership_contract.py
key-decisions:
  - "J8 remains the sole coalesced cleanup callback; retention state and rollups are worker-epoch fenced in its transaction."
  - "Storage pressure suspends only new historical rows while explicit collection gaps preserve the unpersisted interval."
  - "True, False, and None service outcomes map respectively to observed online, observed offline, and unknown coverage."
patterns-established:
  - "Telemetry mutations declare their SQLite tables in both production and frozen worker inventories."
requirements-completed: [TEL-01, TEL-03, TEL-04]
coverage:
  - id: D1
    description: Authority-fenced retention, cadence gaps, tri-state service evidence, and 90-day event expiry.
    requirement: TEL-01
    verification:
      - kind: integration
        ref: uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py -x
        status: pass
    human_judgment: false
  - id: D2
    description: Immutable callback inventory covers every telemetry mutation surface while preserving J8 scheduling bounds.
    requirement: TEL-03
    verification:
      - kind: integration
        ref: uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_runtime_ownership.py tests/test_worker_ownership_matrix.py tests/test_durable_queues.py -x
        status: pass
    human_judgment: false
  - id: D3
    description: Missing telemetry is represented as confirmed cadence, unknown, or storage-pressure coverage rather than reconstructed samples.
    requirement: TEL-04
    verification:
      - kind: unit
        ref: tests/test_telemetry_retention.py#WorkerTelemetryObservationContractTests
        status: pass
    human_judgment: false
duration: 10min
completed: 2026-08-10
status: complete
---

# Phase 02 Plan 05: Worker Retention Wiring Summary

**Bounded retention now runs only through Beacon's durable worker epoch, with truthful cadence, unknown, and storage-pressure coverage instead of fabricated history.**

## Performance

- **Duration:** 10 min
- **Started:** 2026-08-10T14:50:00Z
- **Completed:** 2026-08-10T15:00:00Z
- **Tasks:** 2/2
- **Files modified:** 5

## Accomplishments

- Wired the existing J8 cleanup callback to bounded retention, retry processing, 90-day event expiry, scan-rate cleanup, and pressure-state recovery inside one authority-fenced transaction.
- Added stream observation state for exact two-miss cadence gaps, explicit unknown intervals, and persistent storage-pressure gaps without stopping current host or service updates.
- Expanded production and frozen worker mutation inventories so S3/J2/J3/J4/J8 enumerate every telemetry table they can change.

## Task Commits

1. **Task 1: Run retention, cadence gaps, and pressure recovery under WorkerAuthority** - `bb0bf53` (test), `5200050` (feat)
2. **Task 2: Close the production worker mutation inventory over telemetry tables** - `90d20f4` (test), `1cb69b5` (feat)

## Files Created/Modified

- `dashboard/beacon/telemetry.py` - Storage measurement, durable retention state, cadence detection, tri-state observations, and pressure-gap transitions.
- `dashboard/app.py` - Uses validated policy and external storage snapshots for worker retention, host sampling, and service probes.
- `dashboard/beacon/worker_main.py` - Declares telemetry mutation surfaces without changing scheduler ownership or J8 bounds.
- `tests/test_telemetry_retention.py` - Real SQLite TDD coverage for epoch fencing, cadence, and tri-state observations.
- `tests/worker_ownership_contract.py` - Immutable expected callback-to-table inventory.

## Decisions Made

- J8 remains the only retention scheduler callback; no process-local retention owner or startup DDL was introduced.
- Historical suspension leaves `system_stats` and service current-state fields live, while only new history is skipped and marked with `storage_pressure` coverage.
- Service booleans remain semantically explicit: `True` is online, `False` is offline regardless of error text, and only `None` becomes unknown.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Added `runtime_state` to the frozen database-surface universe**
- **Found during:** Task 2 verification
- **Issue:** The expanded callback rows correctly declared `runtime_state`, but the global allowed-surface set omitted it, causing the static bijection gate to fail.
- **Fix:** Added `runtime_state` to `DATABASE_SURFACES`.
- **Files modified:** `tests/worker_ownership_contract.py`
- **Verification:** Worker inventory and wave-end ownership suites pass.
- **Committed in:** `1cb69b5`

**Total deviations:** 1 auto-fixed (Rule 1)

## Known Stubs

None.

## Next Phase Readiness

Phase 2's retention engine now has durable worker ownership and explicit historical availability evidence for the remaining telemetry query work.

## Self-Check: PASSED

- Required production and test files exist.
- Task commits `bb0bf53`, `5200050`, `90d20f4`, and `1cb69b5` exist in git history.
