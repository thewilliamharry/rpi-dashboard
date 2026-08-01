---
phase: 01-behavioral-safety-runtime-ownership
plan: 15
subsystem: recovery
tags: [sqlite, migration, recovery, cli, security]
requires:
  - 01-14
provides:
  - marker-authorized catalog-bound recovery selectors
affects:
  - dashboard/beacon/recovery.py
  - tests/test_backup_recovery.py
tech_stack:
  added: []
  patterns:
    - fail-closed regular-file recovery authorization
    - marker-bound CLI selection
key_files:
  created:
    - .planning/phases/01-behavioral-safety-runtime-ownership/01-15-SUMMARY.md
  modified:
    - dashboard/beacon/recovery.py
    - tests/test_backup_recovery.py
decisions:
  - CLI restore selectors resolve only through the validated migration failure marker; --latest never falls back to catalog ordering and --id must match the bound opaque ID.
metrics:
  duration: 19m
  completed: 2026-08-01
  tasks_completed: 2
  files_modified: 2
status: complete
---

# Phase 01 Plan 15: Marker-Bound Recovery CLI Summary

Destructive recovery now requires a valid failed-migration marker and both CLI selectors can restore only its exact verified opaque catalog entry.

## Completed Tasks

1. Refused healthy or malformed-marker restore attempts before lock, catalog, sidecar, staging, or replacement work; preserved the marker across interrupted replacement and consumed it after verified success.
2. Bound `restore --latest` and `restore --id` to the same validated marker authorization, including selector mismatch, missing marker, null-ID, path-like-ID, and repeated-invocation refusals.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_backup_recovery.py` — 22 passed, 13 subtests passed.
- `uv run --project dashboard python -m pytest -q tests/test_migrations.py tests/test_api_and_auth.py tests/test_ui_contract.py` — 39 passed, 31 subtests passed.
- `uv run --project dashboard python -m pytest -q` — passed. The browser/proxy fixtures required an elevated localhost-capable environment because the standard sandbox forbids ephemeral loopback binds.

## Decisions Made

- `--latest` means the marker-authorized catalog record, never the newest arbitrary verified backup.
- `--id` is accepted only when it equals the marker-bound opaque catalog ID; catalog listings remain read-only and cannot authorize replacement.

## Deviations from Plan

### Auto-fixed Issues

1. [Rule 1 - Bug] Corrected recovery test helper compatibility and stale-marker expectations.
- **Found during:** Task 2 RED verification.
- **Issue:** The helper evaluated a missing `BackupRecord.name` fallback and a stale-marker regression expected a refused restore to modify data.
- **Fix:** Accepted both catalog records and paths in the fixture helper, and asserted byte-preserving refusal behavior.
- **Files modified:** `tests/test_backup_recovery.py`
- **Commit:** e01865c

## Known Stubs

None.

## Remaining Human Verification

Before a real Raspberry Pi upgrade, compare every current and retained operator database fingerprint with the documented support floor. This intentionally external-only inventory comparison is unchanged and is not represented by automated fixtures.

## Self-Check: PASSED

- Recovery implementation and regression test files exist.
- Task commits `8c58612`, `777c762`, and `e01865c` exist.
