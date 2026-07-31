---
phase: 01-behavioral-safety-runtime-ownership
plan: 04
subsystem: database
tags: [python, sqlite, migrations, backup, flock, recovery]
requires:
  - phase: 01-03
    provides: Worker lifecycle with database preparation as its first durable gate
provides:
  - Evidence-backed legacy schema support floor including the confirmed operator fingerprint
  - Transactional, process-locked versioned migrations with verified pre-migration snapshots
  - Bounded automatic backup retention and redacted recovery-required markers
affects: [worker-startup, database-compatibility, recovery, phase-01]
tech-stack:
  added: []
  patterns: [immutable migration registry, SQLite online backup verification, fcntl inter-process locking, fingerprint support floor]
key-files:
  created: [dashboard/beacon/migrations.py, dashboard/beacon/support_floor.json, tests/fixtures/legacy/support-floor.json, tests/test_backup_recovery.py]
  modified: [dashboard/app.py, dashboard/beacon/db.py, tests/test_migrations.py]
key-decisions:
  - "Freeze the support floor at three repository-history shapes and the single operator-confirmed production fingerprint."
  - "Treat unmatched non-empty schemas as unsupported before backups or database writes; permit empty paths only for fresh Beacon bootstrap."
  - "Keep recovery action out of the browser: write a redacted durable marker and preserve verified local snapshots."
patterns-established:
  - "Migration runner: take the data-volume flock, re-read durable state, verify a SQLite online backup, then transact one ordered version."
  - "Compatibility initialization delegates to the same migration gate; post-migration state repair preserves the established release contract."
requirements-completed: [FND-05, FND-06]
coverage:
  - id: D1
    description: Evidence-backed schema inventory and frozen support floor cover all history fixtures and the confirmed production fixture.
    requirement: FND-05
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_migrations.py
        status: pass
    human_judgment: false
  - id: D2
    description: Locked ordered migrations preserve representative data, reject unknown shapes, rollback failures, and no-op when current.
    requirement: FND-05
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_migrations.py tests/test_runtime_ownership.py
        status: pass
    human_judgment: false
  - id: D3
    description: Verified online snapshots, recovery markers, unique filenames, and three-file retention protect migration recovery.
    requirement: FND-06
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py
        status: pass
    human_judgment: false
duration: 6min
completed: 2026-07-31
status: complete
---

# Phase 01 Plan 04: Safe Legacy Database Migration Summary

**Evidence-backed legacy upgrades with a locked transactional migration registry, verified SQLite snapshots, three-backup retention, and failure-safe worker preparation.**

## Performance

- **Duration:** 6 min (Task 3 continuation; Task 1 and the operator checkpoint completed earlier)
- **Started:** 2026-07-31T20:33:31Z
- **Completed:** 2026-07-31T20:39:46Z
- **Tasks:** 3/3
- **Files modified:** 9

## Accomplishments

- Froze support to three evidence-backed repository-history schemas plus the operator-confirmed production fingerprint and fixture.
- Added immutable ordered migrations that take a Linux inter-process lock, verify snapshots before schema work, transactionally record versions, and reject unrecognized populated databases without writes.
- Added redacted durable recovery markers, complete-backup-only retention, concurrent contender coverage, and compatibility initialization routed through the same safety gate.

## Task Commits

1. **Task 1: Produce a sanitized deployed-schema inventory and representative fixtures** - `c741c5b` (TDD RED), `c15072b` (TDD GREEN), `4d87e8b` (operator fixture)
2. **Task 2: Confirm the evidence-backed migration support floor** - Operator selected `confirm-complete`: `production.json` fingerprint `6a7215ed74800ba1d4894563334304415c780135d295ced269c561c84b8b0c81` matches `operator/production.db`.
3. **Task 3: Run locked, verified, transactional migrations against the evidence-backed support floor** - `2beaa15` (TDD RED), `85fa893` (TDD GREEN), `6156d54` (compatibility safety fix)

## Files Created/Modified

- `dashboard/beacon/migrations.py` - Immutable migration registry, support-floor validation, locking, snapshots, retention, and recovery markers.
- `dashboard/beacon/support_floor.json` - Production-packaged support manifest for the confirmed four fingerprints.
- `tests/fixtures/legacy/support-floor.json` - Test-visible provenance manifest mirroring the packaged manifest.
- `dashboard/beacon/db.py` and `dashboard/app.py` - One migration preparation boundary for worker and compatibility initialization.
- `tests/test_migrations.py` and `tests/test_backup_recovery.py` - Floor, preservation, no-op, rollback, contender, integrity, marker, uniqueness, and retention coverage.

## Decisions Made

- The support floor includes only the confirmed operator fingerprint and the three schema shapes found in history; unmatched populated databases fail before backup or write.
- A fresh empty database is a safe bootstrap input, while every populated supported schema receives a verified backup immediately before each pending schema-changing version.
- Automatic recovery remains filesystem-only: the durable marker contains no error message or data and no browser restore action was added.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical Functionality] Routed the legacy compatibility initializer through the migration gate.**
- **Found during:** Task 3 final verification
- **Issue:** `dashboard.app.init_db()` still used additive DDL, which could bypass the locked/verified upgrade path during web compatibility startup.
- **Fix:** Delegated compatibility initialization to `prepare_database()` and retained only the existing state-transition repair required by the release contract.
- **Files modified:** `dashboard/app.py`, `dashboard/beacon/migrations.py`, `tests/test_migrations.py`
- **Verification:** `dashboard/.venv/bin/python -m pytest -q` (70 passed)
- **Committed in:** `6156d54`

---

**Total deviations:** 1 auto-fixed (1 missing critical functionality)
**Impact on plan:** Necessary to make the migration boundary universal while preserving existing dashboard behavior; no new user-facing recovery action was introduced.

## Issues Encountered

- The sanitized production fixture omits operational migration rows by design. Exact fingerprint validation therefore supplies its evidence-backed minimum starting version without copying production row values.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Worker startup now stops safely on migration rejection or failure before it can heartbeat, schedule, probe, or use browser resources.
- Operators retain three verified automatic snapshots and a redacted recovery marker for the supported filesystem recovery path.

## Self-Check: PASSED

- Verified all eight implementation, fixture, test, and summary files exist.
- Verified task commits `c741c5b`, `c15072b`, `4d87e8b`, `2beaa15`, `85fa893`, and `6156d54` exist in Git history.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-07-31*
