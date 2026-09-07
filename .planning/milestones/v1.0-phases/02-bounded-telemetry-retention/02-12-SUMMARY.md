---
phase: 02-bounded-telemetry-retention
plan: 12
subsystem: telemetry-migration
tags: [sqlite, telemetry, migrations, validation]
requires:
  - phase: 02-10
    provides: transactional Migration 7 canonical host evidence conversion
  - phase: 02-11
    provides: final Phase 2 pending-interval corrections
provides:
  - Presence-aware, fail-closed validation for legacy host pressure-gap state
  - Transactional rollback evidence for every malformed legacy JSON pressure value
affects: [telemetry-retention, migration-recovery, phase-02-verification]
tech-stack:
  added: []
  patterns:
    - Persisted JSON validation distinguishes key absence from a present null value.
    - Migration validation occurs before any durable telemetry mutation or version publication.
key-files:
  created: []
  modified:
    - dashboard/beacon/migrations.py
    - tests/test_migrations.py
key-decisions:
  - "Only an absent legacy host:host pressure key is a Migration 7 no-op; every present value must be a non-boolean integer."
  - "Malformed durable pressure values fail inside the existing Migration 7 transaction so version-6 evidence remains exact."
requirements-completed: [TEL-04]
coverage:
  - id: D1
    description: "Migration 7 rejects JSON null, booleans, strings, floats, arrays, and objects without partially publishing canonical telemetry evidence."
    requirement: TEL-04
    verification:
      - kind: integration
        ref: "tests/test_migrations.py#test_migration_seven_rejects_json_null_legacy_pressure_state_without_partial_publication"
        status: pass
      - kind: integration
        ref: "tests/test_migrations.py#test_migration_seven_rejects_remaining_malformed_legacy_pressure_values"
        status: pass
    human_judgment: false
  - id: D2
    description: "Migration 7 keeps absent pressure state as a valid no-op and preserves valid canonical expansion and shared raw rollup-job identity."
    requirement: TEL-04
    verification:
      - kind: integration
        ref: "tests/test_migrations.py#test_migration_seven_absent_legacy_pressure_key_is_a_successful_no_op"
        status: pass
      - kind: integration
        ref: "tests/test_migrations.py#test_current_v6_legacy_host_state_migrates_once_without_overlap"
        status: pass
    human_judgment: false
metrics:
  duration: 8min
  completed_date: 2026-08-11
  tasks_completed: 1
  files_modified: 2
status: complete
---

# Phase 02 Plan 12: Fail-Closed Legacy Pressure State Summary

**Migration 7 now accepts only an absent or non-boolean-integer legacy host pressure timestamp, preserving every version-6 evidence row when persisted state is malformed.**

## Accomplishments

- Added a named JSON-null regression that snapshots streams, coverage, raw retention JSON, rollup jobs, and schema versions before a real migration-runner failure.
- Expanded malformed-value coverage to both booleans, a numeric-looking string, float, array, and object, with exact rollback assertions for each case.
- Made the Migration 7 pressure guard presence-aware before stream, coverage, state, or version mutation; valid integer expansion, absence, re-entry, and raw-host rollup identity remain unchanged.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_migrations.py -k "migration_seven or current_v6_legacy_host_state" -x` — passed (5 tests, 6 subtests).
- `uv run --project dashboard python -m pytest -q` — passed.

## Task Commits

1. **Task 1: Trace malformed legacy pressure state through Migration 7 rollback** — `5510554` (RED regression evidence), `625b4b5` (presence-aware validation).

## Files Created/Modified

- `dashboard/beacon/migrations.py` — distinguishes a missing legacy key from a present malformed value before Migration 7 writes.
- `tests/test_migrations.py` — proves null and malformed rollback, absence behavior, and exact version-6 evidence preservation.

## Decisions Made

- An absent `pressure_gaps['host:host']` entry remains a successful Migration 7 no-op; a present `null` is invalid persisted state.
- Type validation explicitly rejects booleans before accepting integers because Python booleans subclass `int`.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Self-Check: PASSED

- Confirmed `dashboard/beacon/migrations.py` and `tests/test_migrations.py` exist with the completed migration guard and regression evidence.
- Confirmed task commits `5510554` and `625b4b5` exist in local history.
- Confirmed no task commit deleted tracked files.
