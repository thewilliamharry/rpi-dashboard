---
phase: 06-workload-resilience-pi-acceptance
plan: 05
subsystem: persistence
tags: [sqlite, wal, concurrency, migrations, backup-recovery, worker-restart, debt-ledger]

# Dependency graph
requires:
  - phase: 06-04
    provides: "The dedicated 'cleanup' executor lane and EXPECTED_EXECUTOR_LANES contract this plan's concurrency test reads worker_main lanes through"
  - phase: 06-01
    provides: "tests/test_workload_resilience.py -- the phase's OPS-01..04 integration suite, extended here with WalModeTests and ConcurrentAccessTests; and migration 10's version-agnostic LINEAGE_FINGERPRINTS contract, reused rather than re-implemented"
provides:
  - "Every Beacon SQLite connection runs in WAL journal mode, set explicitly by connect_db and read back by configured_journal_mode -- not assumed, not left implicit"
  - "A WAL-tolerant schema-inspection fallback (PRAGMA query_only=ON) so a WAL-mode deployment can still be inspected and upgraded"
  - "Pre-migration verified backups are normalized to rollback-journal mode so they carry no -wal/-shm sidecars regardless of the source database's mode"
  - "Automated proof that concurrent web (_db_lock-serialized) and worker SQLite writers under WAL are corruption-free, and that a restarted worker fences its dead epoch correctly"
  - "06-DEBT.md -- the phase's first debt ledger, recording the deliberately-unchanged _db_lock scope (D-01) and the unobserved production starting journal mode"
affects: [06-06 pi acceptance harness, any future _db_lock narrowing evaluation]

actuals:
  tokens: 10100
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "PRAGMA journal_mode set on every connect_db() call and read back via a dedicated configured_journal_mode() accessor, never trusted from the request"
    - "A read-only inspection connection falls back from a mode=ro URI to a normal connection with PRAGMA query_only=ON when the URI path cannot initialize a WAL database's -shm file"
    - "A retained backup artifact is normalized to rollback-journal mode at creation time so its own downstream integrity check and sidecar-free guarantee hold regardless of the live database's journal mode"

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md
  modified:
    - dashboard/beacon/db.py
    - dashboard/beacon/inventory.py
    - dashboard/beacon/migrations.py
    - tests/test_workload_resilience.py
    - tests/test_migrations.py
    - tests/test_backup_recovery.py
    - README.md
    - AGENTS.md
    - .planning/codebase/INTEGRATIONS.md
    - .planning/codebase/CONVENTIONS.md
    - .planning/REQUIREMENTS.md

key-decisions:
  - "D-01 confirmed exactly as researched: WAL only this phase, _db_lock's scope byte-identical at every dashboard/app.py call site, enforced by a git-diff-scoped acceptance criterion rather than left as an unverified intention"
  - "The production database's pre-switch journal_mode was not captured (no reachable Pi/deployed-database copy in this execution environment) and is recorded as unverified in D-DEBT-06-03, not assumed to be either mode -- the rollout logic itself is still proven for both starting modes against synthetic fixtures"
  - "AGENTS.md's Pattern Overview WAL bullet was a stale, pre-existing snapshot that did not match its own generation source (.planning/codebase/ARCHITECTURE.md's current Pattern Overview does not mention WAL at all); corrected the bullet directly rather than touching ARCHITECTURE.md, which carries no claim to fix"

requirements-completed: [OPS-04]

coverage:
  - id: D1
    description: "Every connect_db() connection reports journal_mode=wal when read back, from either a fresh rollback-journal database or one already in WAL"
    requirement: "OPS-04"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#WalModeTests::test_connections_run_in_wal_mode_from_either_starting_mode"
        status: pass
      - kind: unit
        ref: "tests/test_workload_resilience.py#WalModeTests::test_connect_db_releases_flock_and_reraises_when_the_wal_pragma_fails"
        status: pass
    human_judgment: false
  - id: D2
    description: "A WAL-mode deployment with a non-empty -wal sidecar inspects, backs up, and upgrades to the newest migration without raising, and the backup it produces carries no sidecar of its own"
    requirement: "OPS-04"
    verification:
      - kind: integration
        ref: "tests/test_migrations.py#MigrationTests::test_a_wal_mode_deployment_inspects_backs_up_and_upgrades"
        status: pass
      - kind: integration
        ref: "tests/test_migrations.py#InventoryTests::test_cli_inspects_a_wal_mode_database_through_the_query_only_fallback"
        status: pass
      - kind: integration
        ref: "tests/test_backup_recovery.py#BackupRecoveryTests::test_restore_still_removes_wal_and_shm_when_pre_restore_database_is_in_wal_mode"
        status: pass
    human_judgment: false
  - id: D3
    description: "A bounded stress run of eight _db_lock-serialized web writers plus one worker writer completes corruption-free, and a write that did not commit is never reported as having succeeded (PROH-OPS-04-01)"
    requirement: "OPS-04"
    verification:
      - kind: integration
        ref: "tests/test_workload_resilience.py#ConcurrentAccessTests::test_concurrent_web_and_worker_writers_are_corruption_free"
        status: pass
    human_judgment: false
  - id: D4
    description: "A worker restarted mid-job resumes correctly: the new epoch un-claims and completes the dead epoch's row, and the dead epoch's own terminal write is rejected and changes nothing"
    requirement: "OPS-04"
    verification:
      - kind: integration
        ref: "tests/test_workload_resilience.py#ConcurrentAccessTests::test_worker_restart_recovery_fences_the_dead_epoch"
        status: pass
    human_judgment: false
  - id: D5
    description: "_db_lock's scope is byte-identical at every dashboard/app.py call site across this plan's commits"
    requirement: "OPS-04"
    verification:
      - kind: unit
        ref: "git diff 93a279c..HEAD -- dashboard/app.py (zero lines)"
        status: pass
    human_judgment: false

duration: ~70min
completed: 2026-09-01
status: complete
---

# Phase 06 Plan 05: SQLite WAL Concurrency Summary

**Every Beacon connection now runs in WAL with the mode read back from the database rather than assumed, the schema-inspection and backup paths are hardened against WAL sidecars, concurrent web/worker access and worker restart fencing are proven under WAL, and `_db_lock`'s deliberately-unchanged scope is recorded as evidence-backed debt.**

## Performance

- **Duration:** ~70 min
- **Tasks:** 3
- **Files modified:** 11 (3 source + 3 test files + 4 docs + REQUIREMENTS.md), 1 file created (06-DEBT.md)

## Accomplishments

- **WAL enabled with verified read-back (Task 1).** `dashboard/beacon/db.py` gained the `JOURNAL_MODE = 'WAL'` constant, a `PRAGMA journal_mode=WAL` issued on every `connect_db()` call inside the existing `try`/`except` block (so the existing flock-release-and-reraise path covers it with no new error handling), and `configured_journal_mode(conn)` to read back the mode actually in force. `dashboard/beacon/inventory.py`'s `_readonly_connection` now falls back from a `mode=ro` URI connection (which cannot initialize a WAL database's `-shm` file) to a normal connection with `PRAGMA query_only=ON`, so schema inspection — and therefore `_apply_pending_migrations`'s inventory-gated upgrade check — keeps working against a WAL-mode deployment. `dashboard/beacon/migrations.py`'s `create_verified_backup` now normalizes its backup artifact to `journal_mode=DELETE` immediately after the online backup copy, so a retained backup never carries `-wal`/`-shm` sidecars regardless of the live database's mode, keeping the existing post-restore no-sidecar guarantee true by construction.
- **Concurrency and restart-recovery proof (Task 2).** `tests/test_workload_resilience.py` gained `ConcurrentAccessTests`: a bounded stress run of eight `_db_lock`-serialized web-shaped writers plus one worker-shaped `write_transaction` writer, asserting zero unhandled exceptions, `PRAGMA integrity_check == 'ok'`, and every reported-committed write present afterward (PROH-OPS-04-01), plus a companion assertion that an injected `sqlite3.OperationalError` inside a `write_transaction` body rolls back and propagates rather than leaving a partial row. A second test simulates a hard worker restart (a new epoch acquiring the durable lease without the old epoch ever releasing it) and proves `recover_queues_for_worker` un-claims the dead epoch's preview row, the new epoch claims and completes it, the dead epoch's own terminal write is rejected with `LeaseLost` and changes nothing, and `background_job_health` reflects the true `succeeded` outcome.
- **Docs corrected and debt recorded (Task 3).** Added a "SQLite WAL mode and sidecar files" operator subsection to `README.md`. Corrected three documents that asserted WAL as an ambient property before any code in this repository ever set it — `AGENTS.md`'s Pattern Overview bullet, `.planning/codebase/INTEGRATIONS.md`'s PRAGMA settings list, and `.planning/codebase/CONVENTIONS.md`'s database bullet — to each name `connect_db` as the code that establishes the mode. Created `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` with `D-DEBT-06-01` (the deferred `_db_lock` narrowing, evidence-backed by this plan's concurrency and restart tests) and `D-DEBT-06-03` (the production database's pre-switch journal mode was never observed in this execution environment — recorded `unverified`, not assumed).

## Task Commits

1. **Task 1: Enable WAL, and make the rollout correct on a database that already has sidecars** — `78475d2` (feat) — also contains Task 2's `ConcurrentAccessTests` (see Deviations)
2. **Task 3: Record the WAL operations story, correct the docs, and log the deferred `_db_lock` follow-up** — `89ca3b8` (docs)

**Plan metadata:** this commit (docs: complete plan)

## Files Created/Modified

- `dashboard/beacon/db.py` — `JOURNAL_MODE`, `PRAGMA journal_mode=WAL` in `connect_db`, `configured_journal_mode()`
- `dashboard/beacon/inventory.py` — `_readonly_connection` gains a `PRAGMA query_only=ON` fallback via a new `_query_only()` pass-through helper (kept as a `return`-chained call rather than an inline assignment so `tests/test_module_boundaries.py`'s connection-ownership gate sees ownership transferred directly to the caller)
- `dashboard/beacon/migrations.py` — `create_verified_backup` normalizes its backup artifact to `journal_mode=DELETE`
- `tests/test_workload_resilience.py` — `WalModeTests` (two tests) and `ConcurrentAccessTests` (two tests)
- `tests/test_migrations.py` — `test_a_wal_mode_deployment_inspects_backs_up_and_upgrades`, `test_cli_inspects_a_wal_mode_database_through_the_query_only_fallback`, plus fixes to two pre-existing byte-identical assertions and one busy-timeout contention test (see Deviations)
- `tests/test_backup_recovery.py` — `test_restore_still_removes_wal_and_shm_when_pre_restore_database_is_in_wal_mode`
- `README.md` — new WAL sidecar operator subsection
- `AGENTS.md`, `.planning/codebase/INTEGRATIONS.md`, `.planning/codebase/CONVENTIONS.md` — WAL attribution corrections
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — new, `D-DEBT-06-01` and `D-DEBT-06-03`
- `.planning/REQUIREMENTS.md` — OPS-04 marked complete (checkbox and traceability row)

## Decisions Made

- **D-01 confirmed and enforced, not just documented.** WAL only this phase; `_db_lock`'s scope is byte-identical at every `dashboard/app.py` call site, verified by a `git diff` scoped to that file across both of this plan's commits (zero lines).
- **Backup normalization at the artifact, not the source.** `create_verified_backup` normalizes its own copy to rollback-journal mode rather than attempting to read a WAL source with `mode=ro` some other way — a retained backup is a static file with no concurrency requirement, so this is the smaller, more local fix and keeps the existing post-restore no-sidecar assertion true by construction.
- **Production starting-mode evidence recorded honestly as unverified.** No Pi or deployed-database copy was reachable from this execution environment, so the before/after `journal_mode` reading Task 1's `<human-check>` calls for was not captured. This is recorded as `D-DEBT-06-03`, not silently assumed — the rollout logic itself is still proven for both starting modes against synthetic fixtures (`test_connections_run_in_wal_mode_from_either_starting_mode`).
- **`ManagedConnection`, not `sqlite3.Connection`, is the flock-release regression test's patch target.** `sqlite3.Connection` is an immutable C type; `ManagedConnection` (the plain Python subclass `connect_db` actually instantiates via `factory=`) can be monkeypatched, and patching it is also the more precise target since it's the exact class under test.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Two `test_migrations.py` byte-identical assertions broke because enabling WAL makes merely *connecting* a mutating action**
- **Found during:** Task 1's full-suite verification run
- **Issue:** `test_ordinary_access_blocks_migration_before_any_backup_or_marker_write` and `test_exhausted_contention_is_reported_as_contention_and_writes_nothing` each captured a `before = target.read_bytes()` snapshot, then opened an "ordinary access" connection via `connect_db`, then asserted the file was byte-identical after a blocked migration attempt. Once `connect_db` sets `journal_mode=WAL` on every connection, opening that ordinary-access connection itself flips the file header's format-version bytes (SQLite's on-disk WAL/rollback-journal indicator) — before the migration attempt is ever made. The tests were asserting a stronger invariant ("connecting changes nothing") than the one they actually intend to prove ("a *blocked migration* writes nothing further").
- **Fix:** Moved each test's `before = target.read_bytes()` capture to immediately after the ordinary-access `connect_db()` call, so the assertion correctly scopes to "the blocked migration wrote nothing," not "connecting is a no-op" (which WAL makes false by design).
- **Files modified:** `tests/test_migrations.py`
- **Commit:** `78475d2`

**2. [Rule 1 - Bug] A busy-timeout contention test's premise was invalidated because `BEGIN EXCLUSIVE` no longer blocks readers under WAL**
- **Found during:** Task 1's full-suite verification run
- **Issue:** `test_the_pending_work_check_waits_out_a_writer_instead_of_failing` had a writer thread call `connect_db` then `BEGIN EXCLUSIVE`, expecting this to block a separate reader connection's `SELECT` (the scenario the `READ_BUSY_TIMEOUT_SECONDS` tolerance exists for). Under SQLite's WAL mode, `BEGIN EXCLUSIVE` is documented to behave identically to `BEGIN IMMEDIATE` — it excludes other *writers* but does not block *readers* at all, which is WAL's whole point. Once `connect_db` made this writer connection WAL by default, the reader stopped blocking regardless of the patched `READ_BUSY_TIMEOUT_SECONDS`, and the test's "Detector" assertion (`OperationalError not raised`) failed because there was genuinely nothing left to time out on.
- **Fix:** Added `writer.execute('PRAGMA locking_mode=EXCLUSIVE')` before the writer's `BEGIN EXCLUSIVE`, which forces real, file-level exclusivity that does block readers even under WAL (verified empirically before applying), restoring the test's original contention-tolerance coverage under the new WAL-by-default reality.
- **Files modified:** `tests/test_migrations.py`
- **Commit:** `78475d2`

**3. [Rule 1 - Bug] `_readonly_connection`'s new fallback tripped `test_module_boundaries.py`'s connection-ownership gate**
- **Found during:** Full-suite verification run
- **Issue:** The initial fallback implementation assigned the fallback connection to a local variable (`fallback = sqlite3.connect(resolved)`) before returning it. The repo's static connection-ownership gate (`tests/test_module_boundaries.py`) flags any `ast.Assign` binding of a connection-opening call that isn't closed in a `finally` in the same function — it does not special-case "immediately returned."
- **Fix:** Extracted a small `_query_only(conn)` pass-through helper and changed the fallback to `return _query_only(sqlite3.connect(resolved))` — a `return`-chained call with no local binding, matching the existing `mode=ro` URI path immediately above it, which the gate already accepted for the same reason.
- **Files modified:** `dashboard/beacon/inventory.py`
- **Commit:** `78475d2`

None of the three above changed any behavior outside their own test's scope or `_readonly_connection`'s fallback shape — each is a direct, mechanical consequence of turning WAL on everywhere, confined to files already in this plan's `files_modified` list.

### Process note (not a deviation from behavior, but from strict per-task commit granularity)

Task 2's two tests (`ConcurrentAccessTests`) were authored in the same editing pass as Task 1's `WalModeTests` before the first commit checkpoint, so both landed in commit `78475d2` rather than as two separate commits. Each task's own `<verify>` command was still run and confirmed independently before and after that commit (Task 1's `pytest tests/test_workload_resilience.py tests/test_migrations.py tests/test_backup_recovery.py`, and separately Task 2's `pytest tests/test_worker_ownership_matrix.py tests/test_workload_resilience.py -k restart_recovery`), so both tasks' acceptance criteria are independently verified even though the commit boundary does not split cleanly along the task boundary. No code correctness is affected.

## Issues Encountered

None beyond the three auto-fixed items above, all resolved within this plan's scope.

## On the phase's known flaky test

`tests/test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced` was included in this plan's full-suite runs (both the pre-fix run that surfaced the three items above, after they were fixed, and the final 794-test run) and **passed cleanly every time** — no flake observed in this plan's execution. This is consistent with the prior wave's note that it had passed cleanly in the two most recent full runs before this one; it does not by itself prove the test is no longer flaky, only that this plan's WAL change did not visibly provoke it across three consecutive full-suite runs during this plan's own execution.

## Verification

```
uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py tests/test_migrations.py tests/test_backup_recovery.py tests/test_module_boundaries.py
93 passed, 41 subtests passed in 27.24s

uv run --project dashboard python -m pytest -q tests/test_worker_ownership_matrix.py tests/test_workload_resilience.py -k restart_recovery
1 passed, 20 deselected in 0.41s

uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py
10 passed in 12.23s

uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py::ConcurrentAccessTests   (x3 consecutive runs)
2 passed each run -- no flake

uv run --project dashboard python -m pytest -q tests/test_release_contract.py tests/test_ui_contract.py
34 passed in 0.75s

uv run --project dashboard python -m pytest -q   (full suite, twice: once mid-Task-1 with the pre-existing baseline, once final)
794 passed, 561 subtests passed in 224.95s (0:03:44)
```

`git diff 93a279c3dd1789fb3219046be6d29e5eea622f89 HEAD -- dashboard/app.py` is empty (0 lines) — `_db_lock` is confirmed byte-identical.

## Known Stubs

None.

## User Setup Required

None — no external service configuration required. The WAL sidecar files are created and managed automatically by SQLite.

## Next Phase Readiness

Ready. 06-06 (Pi acceptance harness) can build on this plan's `tests/test_workload_resilience.py` additions as part of its own baseline; `06-DEBT.md` is now the phase's first debt ledger and 06-06 should append to it (not replace it) if it produces its own deferred items.

## Self-Check: PASSED

- `dashboard/beacon/db.py` — FOUND, contains `JOURNAL_MODE = 'WAL'` and `def configured_journal_mode(`
- `dashboard/beacon/inventory.py` — FOUND, contains `PRAGMA query_only=ON`
- `dashboard/beacon/migrations.py` — FOUND, contains exactly one `journal_mode=DELETE`
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — FOUND, contains `D-DEBT-06-01` and `_db_lock`
- Commit `78475d2` — FOUND in `git log --oneline`
- Commit `89ca3b8` — FOUND in `git log --oneline`
- `git diff 93a279c3dd1789fb3219046be6d29e5eea622f89 HEAD -- dashboard/app.py` — empty, confirmed
