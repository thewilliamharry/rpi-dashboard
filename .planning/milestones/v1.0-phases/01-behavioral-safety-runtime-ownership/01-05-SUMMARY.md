---
phase: 01-behavioral-safety-runtime-ownership
plan: 05
subsystem: recovery
tags: [sqlite, docker-compose, offline-recovery, safety]
requires:
  - phase: 01-04
    provides: verified migration backups, support floor, shared upgrade lock, recovery marker
provides:
  - Catalog-constrained offline database recovery CLI
  - Isolated Compose recovery service and independent web startup
  - One documented failed-upgrade restore procedure
affects: [deployment, migrations, runtime-ownership]
tech-stack:
  added: []
  patterns: [opaque backup catalog IDs, stage-verify-fsync-replace recovery]
key-files:
  created: [dashboard/beacon/recovery.py]
  modified: [docker-compose.yml, README.md, tests/test_backup_recovery.py, tests/test_ui_contract.py]
key-decisions:
  - "Recovery accepts opaque automatic-backup catalog IDs only; it never accepts a filesystem path."
  - "Web waits only for data ownership initialization so compatible read surfaces remain available while worker recovery is paused."
patterns-established:
  - "Offline restore: lock, stale-worker check, same-directory staging, integrity/fingerprint validation, fsync, atomic replace."
requirements-completed: [FND-06]
coverage:
  - id: D1
    description: Verified catalog restore is atomic, repeatable, interruption-safe, and excludes concurrent writers.
    requirement: FND-06
    verification:
      - kind: integration
        ref: tests/test_backup_recovery.py#BackupRecoveryTests
        status: pass
    human_judgment: false
  - id: D2
    description: Compose exposes a hardened offline recovery service while web startup no longer depends on worker health.
    requirement: FND-06
    verification:
      - kind: integration
        ref: tests/test_ui_contract.py#UiContractTests; docker compose config -q
        status: pass
    human_judgment: false
duration: 6min
completed: 2026-07-31
status: complete
---

# Phase 01 Plan 05: Safe Offline Recovery Summary

**A catalog-constrained, lock-protected SQLite restore CLI with an isolated Compose recovery service and a single operator recovery command.**

## Performance

- **Duration:** 6 min
- **Started:** 2026-07-31T20:54:38Z
- **Completed:** 2026-07-31T21:00:36Z
- **Tasks:** 2/2
- **Files modified:** 5

## Accomplishments

- Added `beacon.recovery` with safe status/list/restore commands, opaque catalog IDs, stale-worker refusal, shared upgrade locking, staged integrity checks, fsync, and atomic replacement.
- Kept automatic migration snapshots recoverable across support-floor and known pre-migration transition states, including the newest verified snapshot.
- Added a non-root, network-isolated Compose recovery service; web now starts after data ownership initialization instead of waiting on worker health.
- Replaced generic restore guidance with the one supported offline procedure and deterministic recovery/Compose contracts.

## Task Commits

1. **Task 1: Restore a verified backup atomically and repeatably** - `cd39499` (TDD RED), `377a841` (TDD GREEN), `cb870db` (latest-backup RED), `692d533` (transition-backup fix), `2e5c661` (safe staging-error fix)
2. **Task 2: Expose the single offline recovery command through Compose** - `6052605` (TDD RED), `50794e3` (TDD GREEN)

## Files Created/Modified

- `dashboard/beacon/recovery.py` - Safe verified-backup catalog, atomic restore implementation, and offline CLI.
- `docker-compose.yml` - Isolated one-shot recovery service and independent web dependency.
- `README.md` - The sole failed-upgrade restore procedure and its required ordering.
- `tests/test_backup_recovery.py` - Restore selection, idempotency, interruption, lock, stale worker, catalog safety, and CLI coverage.
- `tests/test_ui_contract.py` - Compose hardening, dependency, and documentation contracts.

## Decisions Made

- Recovery selects only opaque, regular, non-symlink catalog entries that pass SQLite integrity and either the frozen support-floor fingerprint or an exact known pre-migration version sequence.
- The recovery container has no network and no restart policy; the operator must stop web and worker before invoking it.
- Browser-based restore, backup deletion, arbitrary backup paths, and migration retry remain intentionally unsupported.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical Functionality] Accepted verified intermediate automatic migration backups.**
- **Found during:** Task 1 verification
- **Issue:** Support-floor-only validation omitted the newest `pre-vN` snapshot produced by a multi-step migration, preventing the documented `restore --latest` path from recovering it.
- **Fix:** Verified known catalog transition versions and ordered recorded migrations in addition to the frozen support floor.
- **Files modified:** `dashboard/beacon/recovery.py`, `tests/test_backup_recovery.py`
- **Verification:** `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py -x`
- **Committed in:** `cb870db`, `692d533`

**2. [Rule 2 - Missing Critical Functionality] Redacted staging I/O failures.**
- **Found during:** Task 1 security review
- **Issue:** A filesystem error during staging could escape the CLI's safe recovery-error boundary.
- **Fix:** Converted staging I/O failures to the fixed `restore did not complete` response while preserving cleanup.
- **Files modified:** `dashboard/beacon/recovery.py`
- **Verification:** `dashboard/.venv/bin/python -m pytest -q`
- **Committed in:** `2e5c661`

---

**Total deviations:** 2 auto-fixed (2 missing critical functionality)
**Impact on plan:** Both fixes are necessary for the documented recovery path and its safe error boundary; no browser restore or arbitrary path support was introduced.

## Issues Encountered

None beyond the automatically corrected recovery safety gaps.

## User Setup Required

None - recovery uses the existing `dashboard-data` volume and Compose image.

## Next Phase Readiness

- Failed upgrades now have a bounded offline recovery procedure that does not require worker startup.
- The web service can expose compatible committed data while monitoring remains paused.

## Self-Check: PASSED

- Verified `dashboard/beacon/recovery.py`, `docker-compose.yml`, `README.md`, `tests/test_backup_recovery.py`, and `tests/test_ui_contract.py` exist.
- Verified commits `cd39499`, `377a841`, `6052605`, `50794e3`, `cb870db`, `692d533`, and `2e5c661` exist in Git history.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-07-31*
