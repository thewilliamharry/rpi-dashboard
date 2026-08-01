---
phase: 01-behavioral-safety-runtime-ownership
plan: 10
subsystem: database-recovery
tags: [sqlite, wal, recovery, durability, flask, documentation]
requires:
  - phase: 01-09
    provides: managed SQLite connection leases and exclusive maintenance barriers
provides:
  - WAL/SHM-safe catalog restore lifecycle with fsync durability boundaries
  - executable recovery race regressions against a real Flask metadata writer
  - explicit, human-only deployed-database inventory verification procedure
affects: [offline-recovery, migrations, operator-documentation]
tech-stack:
  added: []
  patterns: [upgrade-then-maintenance-lock-order, zero-busy-wal-checkpoint, atomic-replacement]
key-files:
  created:
    - .planning/phases/01-behavioral-safety-runtime-ownership/01-10-SUMMARY.md
  modified:
    - dashboard/beacon/recovery.py
    - tests/test_backup_recovery.py
    - README.md
    - tests/test_ui_contract.py
decisions:
  - "Restore authority is the upgrade lock followed by exclusive database maintenance; worker-heartbeat freshness remains only an additional diagnostic."
  - "The recovery marker is written and fsynced before replacement, then cleared only after read-only validation confirms the replacement and sidecars are absent."
  - "Current and retained Pi inventory remains a human-only, fail-closed check; repository automation must not infer or import external databases."
metrics:
  duration: 21min
  completed: 2026-08-01
  tasks_completed: 2
  files_modified: 4
status: complete
---

# Phase 01 Plan 10: Restore Lifecycle Race Closure Summary

**Catalog recovery now takes full SQLite ownership before replacement, prevents retained WAL/SHM state from replaying over a backup, and verifies the real Flask metadata-writer race.**

## Performance

- **Duration:** 21 min
- **Completed:** 2026-08-01T06:21:34Z
- **Tasks:** 2/2
- **Files modified:** 4

## Accomplishments

- Acquired the established upgrade lock before the Plan 01-09 exclusive maintenance lease, then performed a zero-busy WAL checkpoint before touching the selected target.
- Removed only the exact target `-wal` and `-shm` sidecars, fsyncing stage admission, sidecar cleanup, marker admission, main replacement, and marker cleanup boundaries.
- Wrote a recovery-in-progress marker before replacement; the marker now clears only after read-only integrity/fingerprint validation and sidecar absence checks succeed.
- Added retained-WAL, busy-checkpoint, stage/sidecar failure, repeated-restore, pre/post-replace interruption, and real paused-Flask-writer regression coverage.
- Kept the sole opaque catalog recovery command and documented both maintenance barriers plus the explicit operator-only inventory comparison obligation.

## Task Commits

1. **Task 1: Restore one live-WAL database to the selected backup without replay** — `1ae0431` (TDD RED), `e846bc4` (TDD GREEN)
2. **Task 2: Prove active web metadata cannot overlap restore and document the external inventory check** — `f412d8b` (TDD RED), `09c3e82` (TDD GREEN)

## Verification

- `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py -k "wal or sidecar or repeated or interrupt" -x` — 7 passed.
- `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py tests/test_ui_contract.py -k "metadata_writer or recovery or inventory" -x` — 19 passed.
- `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py tests/test_migrations.py tests/test_api_and_auth.py tests/test_ui_contract.py` — 55 passed.
- `docker compose config -q` — passed.

## Security / Threat Coverage

- **T-01-45 / T-01-47:** The restore lifecycle checkpoint, exact-sidecar removal, durability fsyncs, marker ordering, and retained-WAL/repeatability tests close the WAL/SHM and interruption boundaries.
- **T-01-46:** A real paused `/api/service-meta/<port>` transaction demonstrates that stale worker state cannot let recovery enter maintenance, remove sidecars, or replace the database until the managed web connection closes.

## Decisions Made

- Restore takes the upgrade lock followed by exclusive maintenance; a stale heartbeat never acts as writer exclusion.
- Restore writes an opaque recovery marker before replacement and clears it only after the verified, readable target is the only visible SQLite state.
- The external deployed/retained inventory comparison is intentionally human-only and fail-closed for fingerprints absent from the sanitized support floor.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Self-Check: PASSED

- Verified `dashboard/beacon/recovery.py`, `tests/test_backup_recovery.py`, `README.md`, and `tests/test_ui_contract.py` exist.
- Verified task commits `1ae0431`, `e846bc4`, `f412d8b`, and `09c3e82` exist in Git history.
