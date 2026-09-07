---
phase: 02-bounded-telemetry-retention
plan: 03
subsystem: database
tags: [sqlite, migrations, telemetry, retention, rollback]

requires:
  - phase: 01-behavioral-safety-runtime-ownership
    provides: Exact-fingerprint migration admission, verified backups, exclusive maintenance, and recovery markers.
  - phase: 02-bounded-telemetry-retention
    provides: Approved additive telemetry evidence contract from Plan 02-02.
provides:
  - Transactional Migration 5 telemetry storage with uniquely keyed aggregate, coverage, and retry state.
  - A populated canonical version-4 fixture and exact support-floor fingerprint for current-schema upgrades.
  - Preservation, no-op, index, and rollback evidence for every supported migration shape.
affects: [02-04-rollups, 02-05-worker-retention, 02-06-history-api]

tech-stack:
  added: []
  patterns:
    - Additive SQLite DDL executes as individual statements inside the migration runner's existing transaction.
    - Canonical current-schema fixtures are generated through historical migrations and admitted by an exact structural fingerprint.

key-files:
  created:
    - tests/fixtures/legacy/current-v4.db
  modified:
    - dashboard/beacon/migrations.py
    - dashboard/beacon/support_floor.json
    - tests/fixtures/legacy/support-floor.json
    - tests/test_migrations.py

key-decisions:
  - "Keep service port as the durable service-rollup stream identity because the confirmed production schema exposes the same port in services and service_checks."
  - "Create Migration 5 DDL with conn.execute statements, never executescript, so a failure rolls back all schema work in the existing transaction."

patterns-established:
  - "Telemetry storage begins empty during migration; later worker-owned retention code must write aggregates and coverage before deleting sources."
  - "The support floor contains the frozen four legacy fingerprints plus only the test-derived canonical Phase 1 v4 fingerprint."

requirements-completed: [TEL-01, TEL-02, TEL-03]
coverage:
  - id: D1
    description: "Every supported legacy schema and the populated canonical v4 fixture upgrades to the empty, indexed Migration 5 telemetry contract without changing legacy rows."
    requirement: TEL-01
    verification:
      - kind: integration
        ref: "uv run --project dashboard python -m pytest -q tests/test_migrations.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "Migration 5 creates bounded rollup, coverage, and retry identities plus range/due indexes without worker or request-path DDL."
    requirement: TEL-02
    verification:
      - kind: integration
        ref: "tests/test_migrations.py#MigrationTests._assert_telemetry_schema"
        status: pass
      - kind: other
        ref: "rg migration DDL scan outside dashboard/beacon/migrations.py"
        status: pass
    human_judgment: false
  - id: D3
    description: "A version-5 failure rolls back telemetry schema and version state while retaining a redacted marker that points to a verified backup."
    requirement: TEL-03
    verification:
      - kind: integration
        ref: "tests/test_migrations.py#MigrationTests.test_migration_five_failure_rolls_back_telemetry_schema_and_keeps_recovery_evidence"
        status: pass
    human_judgment: false

metrics:
  duration: 4 min
  completed_date: 2026-08-10
  tasks_completed: 1
  files_changed: 5
status: complete
---

# Phase 02 Plan 03: Bounded Telemetry Migration Summary

Migration 5 provides transactional, indexed, initially empty telemetry rollup, coverage, and retry storage while preserving every supported legacy record and the Phase 1 recovery path.

## Performance

- **Duration:** 4 min
- **Started:** 2026-08-10T14:32:09Z
- **Completed:** 2026-08-10T14:36:24Z
- **Tasks:** 1/1
- **Files modified:** 5

## Accomplishments

- Added version 5's keyed stream, host/service rollup, sparse coverage, and retry-job tables with strict positive/non-negative/enum constraints and required composite indexes.
- Added a populated canonical Phase 1 v4 fixture, derived its structural fingerprint, and admitted it alongside the four frozen legacy fingerprints with target version 5.
- Proved representative legacy values survive upgrades, current databases rerun without backups, and injected version-5 failures leave no schema/version residue while retaining recovery evidence.

## Task Commits

1. **Task 1: Add migration 5 with preservation and rollback proof** - `33fcf54` (TDD RED), `2f0149a` (TDD GREEN)

## Files Created/Modified

- `dashboard/beacon/migrations.py` - Adds transactional Migration 5 telemetry schema and indexes.
- `dashboard/beacon/support_floor.json` - Preserves four historical entries and adds the exact current-v4 fingerprint.
- `tests/fixtures/legacy/support-floor.json` - Mirrors the packaged support-floor contract.
- `tests/fixtures/legacy/current-v4.db` - Populated canonical database produced through migrations 1–4.
- `tests/test_migrations.py` - Tests exact manifest admission, data preservation, DDL, no-op reruns, and rollback recovery.

## Decisions Made

- Retained port as the durable service stream key after verifying it remains the shared identity in the confirmed production fixture's `services` and `service_checks` tables.
- Kept Migration 5 strictly additive: it creates no aggregate rows, changes no existing rows, and deletes no source telemetry or events.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Prevented partial Migration 5 schema publication on failure.**

- **Found during:** Task 1 rollback verification
- **Issue:** `sqlite3.Connection.executescript()` commits before running its script, allowing telemetry DDL to survive an injected failure.
- **Fix:** Executed each fixed DDL statement with `conn.execute()` inside the runner's existing `BEGIN IMMEDIATE` transaction.
- **Files modified:** `dashboard/beacon/migrations.py`, `tests/test_migrations.py`
- **Verification:** `uv run --project dashboard python -m pytest -q tests/test_migrations.py`
- **Committed in:** `2f0149a`

---

**Total deviations:** 1 auto-fixed (1 bug).
**Impact on plan:** Required to preserve the approved transactional migration and recovery guarantees; no scope expansion.

## Issues Encountered

None after the transactional DDL correction.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 02-04 can populate keyed rollups and retry rows against the version-5 contract without adding tables at worker startup.
- Source deletion remains out of this migration and must continue to follow the approved aggregate-write/read-back verification rule.

## Self-Check: PASSED

- Verified all five migration, manifest, fixture, and test files exist.
- Verified task commits `33fcf54` and `2f0149a` exist in Git history.
- Verified `tests/test_migrations.py` (18 passed) and the Phase 2 quick suite (21 passed, 7 subtests).

---
*Phase: 02-bounded-telemetry-retention*
*Completed: 2026-08-10*
