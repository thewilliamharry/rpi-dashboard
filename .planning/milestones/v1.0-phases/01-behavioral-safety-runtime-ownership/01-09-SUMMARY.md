---
phase: 01-behavioral-safety-runtime-ownership
plan: 09
subsystem: database-maintenance
tags: [sqlite, flock, concurrency, migration, recovery]
requires:
  - phase: 01-05
    provides: verified backup and offline recovery contracts
  - phase: 01-06
    provides: durable web and worker SQLite write paths
provides:
  - Connection-lifetime shared SQLite access leases
  - Bounded exclusive maintenance lease and fixed upgrade-to-maintenance ordering
  - Concurrency regressions for metadata writes and migration entry
affects: [web, worker-queues, migrations, recovery]
tech-stack:
  added: []
  patterns: [fcntl flock connection leases, sibling lock files, upgrade-before-maintenance ordering]
key-files:
  created: []
  modified:
    - dashboard/beacon/db.py
    - dashboard/beacon/queues.py
    - dashboard/beacon/migrations.py
    - dashboard/app.py
    - tests/test_backup_recovery.py
    - tests/test_migrations.py
    - tests/test_module_boundaries.py
key-decisions:
  - "Every ordinary Beacon SQLite connection keeps a shared sibling-lock lease until close."
  - "Schema upgrades acquire the shared upgrade lock before exclusive database maintenance."
  - "Recovery receives shared lock-name/path derivation but will adopt the exclusive maintenance region in Plan 01-10."
metrics:
  duration: 16min
  completed: 2026-08-01
  tasks_completed: 2
  files_modified: 7
status: complete
---

# Phase 01 Plan 09: Database Maintenance Barrier Summary

**Connection-lifetime SQLite leases now block exclusive maintenance during real metadata writes, while migrations take the shared upgrade-to-maintenance lock order before touching database state.**

## Performance

- **Duration:** 16 min
- **Completed:** 2026-08-01T06:07:37Z
- **Tasks:** 2/2
- **Files modified:** 7

## Accomplishments

- Added managed SQLite connections that retain a shared `flock` lease for their lifetime and release it safely after connection close or connection-open failure.
- Routed Flask compatibility access and all queue state-machine connections through the managed connection seam without changing their public return behavior.
- Added a bounded exclusive maintenance context, independent of the SQLite inode, which refuses entry with `MaintenanceBusy` while regular access is active.
- Made migration acquire the established upgrade lock before exclusive maintenance, so it cannot classify, back up, create, alter, or write a recovery marker while ordinary access remains live.
- Exported upgrade and maintenance lock-path contracts for the recovery work scheduled in Plan 01-10.
- Added real Flask metadata-write, connection lease, migration exclusion, lock-order, and source-entrypoint regression coverage.

## Task Commits

1. **Task 1: Prove one active web write excludes database maintenance end to end** — `23cf6ab` (TDD RED), `34ebbfb` (TDD GREEN)
2. **Task 2: Put migration and restore on one deadlock-safe maintenance order** — `79c5f43` (TDD RED), `e5de6ca` (TDD GREEN)

## Verification

- `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py tests/test_migrations.py tests/test_module_boundaries.py` — 29 passed
- `dashboard/.venv/bin/python -m pytest -q tests/test_api_and_auth.py tests/test_durable_queues.py tests/test_runtime_ownership.py` — 28 passed
- Focused barrier and contention contracts — 4 passed
- No package install or schema-push operation was introduced.

## Decisions Made

- Ordinary Beacon SQLite access uses a sibling `.beacon-maintenance.lock` shared lease, conservatively covering reads as well as writers so maintenance cannot retain an old database inode in a live request.
- The upgrade lock is always acquired before the exclusive maintenance lock; both lock paths are owned by `beacon.db` for recovery to reuse.
- Migration reports a redacted `MigrationPreparationError` when maintenance exclusion cannot be acquired within the configured bounded wait.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Self-Check: PASSED

- Verified all seven listed implementation and test files exist.
- Verified task commits `23cf6ab`, `34ebbfb`, `79c5f43`, and `e5de6ca` exist in Git history.
