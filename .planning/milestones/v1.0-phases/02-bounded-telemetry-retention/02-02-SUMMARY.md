---
phase: 02-bounded-telemetry-retention
plan: 02
subsystem: telemetry-retention-contract
tags: [sqlite, telemetry, retention, migration, decision]

requires:
  - phase: 01-behavioral-safety-runtime-ownership
    provides: Versioned SQLite migrations, legacy-data preservation checks, and durable worker authority.
  - phase: 02-bounded-telemetry-retention
    provides: Bounded historical telemetry tracer and deterministic retention fixtures from Plan 02-01.
provides:
  - Explicit operator approval of the one-way additive telemetry aggregate, coverage, retry, and expiry contract.
  - A narrow authorization boundary for Migration 5 in Plan 02-03.
affects: [02-03-migration, 02-04-rollups, 02-05-worker-retention, 02-06-history-api]

tech-stack:
  added: []
  patterns:
    - Blocking operator approval before migration-backed aggregate storage and source-evidence expiry.
    - Half-open retention cutoffs with aggregate verification before source deletion.

key-files:
  created:
    - .planning/phases/02-bounded-telemetry-retention/02-02-SUMMARY.md
  modified: []

key-decisions:
  - "Approved exact additive telemetry evidence contract: host per metric/bucket, service per service/bucket, sparse coverage ledger, retry keyed by stream/bucket, locked 7/30/90-day boundaries, and verified aggregate-before-delete in one current-worker transaction."

patterns-established:
  - "A one-way storage decision is durably recorded before migration work; approval authorizes only its stated contract."

requirements-completed: [TEL-01, TEL-02, TEL-03]

metrics:
  duration: 4 min
  completed_date: 2026-08-10
  tasks_completed: 1
  files_changed: 1
status: complete
---

# Phase 02 Plan 02: Additive telemetry evidence contract Summary

The operator approved the exact additive SQLite aggregate, coverage, retry, and expiry contract that Migration 5 may implement without weakening the 7/30/90-day evidence guarantees.

## Accomplishments

- Recorded the selected decision exactly as `approve-contract` before any Migration 5 schema or deletion-capable retention work.
- Locked host aggregates to one row per metric and bucket, and service aggregates to one row per service and bucket.
- Locked unavailable intervals to a sparse coverage ledger and retry state to the stream/bucket identity.
- Locked raw retention at and after the 7-day cutoff, 5-minute buckets whose end is after the 30-day cutoff, hourly buckets whose end is after the 90-day cutoff, and events exactly at the 90-day cutoff.
- Locked aggregate-before-delete: a source bucket may be deleted only after its aggregate is written, read back, and verified in the same current-worker transaction.

## Decision Record

**Selected signal:** `approve-contract`

The approval authorizes only the following contract:

- Host aggregates use one row per metric/bucket.
- Service aggregates use one row per service/bucket.
- Unavailable intervals use a sparse coverage ledger.
- Retry state is keyed by stream/bucket.
- Raw rows at and after the 7-day cutoff are retained.
- 5-minute buckets whose end is after the 30-day cutoff are retained.
- Hourly buckets whose end is after the 90-day cutoff are retained.
- Events exactly at the 90-day cutoff are retained.
- A source bucket is deleted only after its aggregate is written, read back, and verified in the same current-worker transaction.

This decision does not authorize any different table shape, cutoff interpretation, public mutation path, or source-deletion behavior. Migration 5 remains exclusively in Plan 02-03.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py tests/test_migrations.py -x` — passed: 18 tests, 7 subtests.

## Acceptance Criteria

- Baseline tracer and Phase 1 migration tests were green before accepting the decision.
- The recorded decision is exactly `approve-contract`.
- `approve-contract` authorizes only this documented contract; selecting revision would have stopped the phase before Plan 02-03.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

The sandbox initially denied access to uv's existing package cache. The required test command was rerun with permission and passed; no repository or production behavior changed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan 02-03 may implement Migration 5 only according to this approved additive contract, while preserving the existing versioned migration and legacy-data preservation gates.

## Self-Check: PASSED

*Phase: 02-bounded-telemetry-retention*
*Completed: 2026-08-10*
