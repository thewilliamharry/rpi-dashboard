---
phase: 02-bounded-telemetry-retention
plan: 10
subsystem: telemetry-migrations
tags: [sqlite, migrations, telemetry, retention, flask]
requires:
  - phase: 02-09
    provides: canonical metric history reads and pending-compaction evidence
provides:
  - Version 7 transactional conversion of shared host availability evidence
  - Seeded supported version-6 compatibility fixture and API-visible upgrade proof
affects: [phase-02-verification, historical-api, telemetry-retention]
tech-stack:
  added: []
  patterns:
    - Fixed-identity data migrations that expand legacy evidence under one caller-owned transaction
    - Half-open coverage subtraction with canonical evidence taking precedence
key-files:
  created:
    - tests/fixtures/legacy/current-v6.db
  modified:
    - dashboard/beacon/migrations.py
    - dashboard/beacon/support_floor.json
    - tests/fixtures/legacy/support-floor.json
    - tests/test_migrations.py
    - tests/test_historical_telemetry_api.py
key-decisions:
  - "Migration 7 expands host:host availability evidence into cpu, ram, disk, and temp; host:host remains exclusively a raw rollup-job identity."
  - "Existing canonical coverage wins overlap; only uncovered legacy half-open fragments are inserted and equal adjacent fragments coalesce."
requirements-completed: [TEL-04]
coverage:
  - id: D1
    description: Existing version-6 shared-host stream, coverage, and pressure state migrate transactionally and idempotently into canonical metric identities.
    requirement: TEL-04
    verification:
      - kind: integration
        ref: tests/test_migrations.py#test_current_v6_legacy_host_state_migrates_once_without_overlap
        status: pass
      - kind: integration
        ref: tests/test_migrations.py#test_migration_seven_failure_rolls_back_legacy_host_state
        status: pass
    human_judgment: false
  - id: D2
    description: All four real Flask host history endpoints expose migrated collection-gap evidence with exact requested bounds.
    requirement: TEL-04
    verification:
      - kind: integration
        ref: tests/test_historical_telemetry_api.py#test_legacy_host_upgrade_is_visible_to_all_metric_history_endpoints
        status: pass
    human_judgment: false
metrics:
  duration: 25min
  completed_date: 2026-08-11
  tasks_completed: 1
  files_modified: 6
status: complete
---

# Phase 02 Plan 10: Canonical Host Migration Summary

**Version 7 transactionally converts durable shared-host availability evidence into per-metric streams while leaving raw rollup job identity unchanged.**

## Accomplishments

- Added Migration 7 with verified-backup protection, fixed canonical metrics, canonical-over-legacy coverage precedence, and no compatibility read bypass.
- Added a seeded supported version-6 fixture that includes duplicate/adjacent coverage, a conflicting cpu interval, pressure state, unrelated state, and a raw host rollup job.
- Proved one-time upgrade, helper re-entry, runner re-entry, rollback after transformation, malformed-state rejection, and all four production history reads.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_migrations.py tests/test_historical_telemetry_api.py -k "current_v6 or migration_seven or legacy_host_upgrade" -x` — passed (4 tests).
- `uv run --project dashboard python -m pytest -q tests/test_migrations.py tests/test_historical_telemetry_api.py -x` — passed (38 tests, 7 subtests).
- `uv run --project dashboard python -m pytest -q tests/test_release_contract.py tests/test_telemetry_retention.py` — passed (34 tests, 6 subtests).
- `uv run --project dashboard python -m pytest -q` — passed.

## Task Commits

1. **Task 1: Trace a seeded legacy host database through Migration 7 and all four history endpoints** — `2573dc5` (RED tests/fixture), `31045df` (migration implementation), `260ef97` (malformed-state hardening).

## Decisions Made

- The data migration uses only fixed host metric names and the existing runner-owned `BEGIN IMMEDIATE` transaction.
- A malformed retention-state payload or host pressure timestamp fails closed, preserving the verified backup and redacted recovery marker instead of discarding durable evidence.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated the canonical Version 4 migration expectation**
- **Found during:** Task 1 full migration regression.
- **Issue:** The canonical fixture now correctly advances through Migration 7 as well as Versions 5 and 6.
- **Fix:** Updated its exact applied-version assertion to include Version 7.
- **Files modified:** `tests/test_migrations.py`
- **Verification:** Full migration/API suite passes.
- **Committed in:** `31045df`

**2. [Rule 1 - Bug] Made mixed null/string coverage-detail ordering deterministic**
- **Found during:** Task 1 migration hardening.
- **Issue:** Native tuple sorting could compare `None` with a string when equal coverage boundaries used different details.
- **Fix:** Added an explicit deterministic sort key before coalescing coverage segments.
- **Files modified:** `dashboard/beacon/migrations.py`
- **Verification:** Focused and full migration/API suites pass.
- **Committed in:** `260ef97`

## Known Stubs

None.

## Self-Check: PASSED

- Confirmed `tests/fixtures/legacy/current-v6.db` and every listed source/test file exist.
- Confirmed commits `2573dc5`, `31045df`, and `260ef97` exist in local history.
- Confirmed no task commit deleted tracked files.
