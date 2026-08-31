---
phase: 06-workload-resilience-pi-acceptance
plan: 01
subsystem: database
tags: [sqlite, migrations, flask, apscheduler, thumbnails, ops-03]

requires:
  - phase: 01-behavioral-safety-runtime-ownership
    provides: versioned migration/recovery machinery, worker-ownership contract, ThumbnailRepository baseline
provides:
  - Migration 10 relocating thumbnail blobs off services into a bounded thumbnails table
  - ThumbnailStoreRepository (sole thumbnail write path) and read_thumbnail() read projection
  - Version-agnostic migration-tail contract (LINEAGE_FINGERPRINTS, no literal tail-version pins)
  - tests/test_workload_resilience.py — the Phase 6 OPS-01..04 integration suite, seeded
  - Measured full-suite pytest runtime (222.82s) recorded in 06-VALIDATION.md
affects: [06-02-preview-retry-and-store-budget, 06-03-bounded-preview-retry, 06-05-wal-and-concurrency]

actuals:
  tokens: 16990
  tasks: 4
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Version-agnostic migration-tail assertions derived from MIGRATIONS[-1].version instead of literal integers"
    - "LINEAGE_FINGERPRINTS[version] map pre-loads the next schema version's lineage fingerprints one plan ahead of the migration that needs them"
    - "Bounded, TTL-expiring satellite table (thumbnails) pattern for relocating large blobs off a primary telemetry table"

key-files:
  created:
    - tests/test_workload_resilience.py
  modified:
    - dashboard/beacon/migrations.py
    - dashboard/beacon/repositories.py
    - dashboard/app.py
    - dashboard/beacon/worker_main.py
    - dashboard/beacon/support_floor.json
    - tests/fixtures/legacy/support-floor.json
    - tests/test_migrations.py
    - tests/test_maintenance_windows.py
    - tests/test_advanced_diagnosis_api.py
    - tests/test_api_and_auth.py
    - tests/test_security_and_scanning.py
    - tests/test_runtime_ownership.py
    - tests/test_module_boundaries.py
    - tests/worker_ownership_contract.py
    - .planning/phases/06-workload-resilience-pi-acceptance/06-VALIDATION.md

key-decisions:
  - "D-OPS-03-01 (Task 1, user decision 'proceed'): migration 10 relocates every captured thumbnail into the new thumbnails table and empties services.thumb_data/thumb_mime in the same transaction, on the live database. Rationale: this satisfies OPS-03 directly and keeps the schema-version bump and the version-agnostic support-floor contract as one indivisible wave-1 change; the one-way-door risk is mitigated by the automatic verified pre-v10 backup (create_verified_backup) and the fact the backfill INSERT and emptying UPDATE share one BEGIN IMMEDIATE transaction, so any failure leaves the original blobs untouched."
  - "Tracer human-verify (Task 3) approved by the user after reviewing the automated evidence: full pytest suite green (780 passed, 552 subtests), tests/test_workload_resilience.py green, the eight realigned test sites green under their original names, and test_module_boundaries.py green with the old ThumbnailRepository still in place pending Task 4."
  - "Falsification-check deviation: the plan's Task 2 acceptance criteria instructed injecting a literal Migration(11, ...) to prove no bookkeeping-unrelated assertion breaks when the next migration ships. Doing so literally skips version 10, creating an artificial gap in MIGRATIONS that broke unrelated contiguous-range assertions (test_current_v4_fixture_is_canonical_and_migrates_preserving_rows etc.) that have nothing to do with support-floor bookkeeping. Used a sequential Migration(10, ...) probe instead -- this is what 'the next migration' means in a codebase with no version gaps -- which produced exactly the intended single failure (the stale target_version assertion) with zero cascading failures, matching the acceptance criterion's actual intent (no applied_versions/MAX(version)/migration_versions/backup-count assertion fails). Reverted immediately after observing the result; not a permanent code change."
  - "Task 3 (tracer, tdd=true in frontmatter) was committed as one atomic commit per the tracer-specific execution protocol ('Execute and commit exactly like type=auto') rather than split into separate RED/GREEN commits -- the tracer protocol takes precedence over the generic per-task TDD cycle for tracer tasks."

patterns-established:
  - "A satellite table (thumbnails) with its own TTL/expiry column, upserted via ON CONFLICT DO UPDATE, is the pattern for relocating a large-blob column off a primary telemetry table without breaking existing read paths -- has_thumb becomes an EXISTS-with-expiry subquery bound with the caller's own now."
  - "LINEAGE_FINGERPRINTS[version] is populated one plan ahead of the migration that needs it (Task 2 pre-loads v9 before Task 3 adds migration 10), so the 'admits every tracked lineage at the previous version' guard is already green before the schema bump lands."

requirements-completed: [OPS-03]

coverage:
  - id: D1
    description: "Migration 10 creates the thumbnails table, backfills every non-NULL services.thumb_data blob into it inside one transaction, and empties services.thumb_data/thumb_mime for those rows"
    requirement: "OPS-03"
    verification:
      - kind: integration
        ref: "tests/test_migrations.py#test_migration_ten_thumbnail_relocation_preserves_every_captured_blob"
        status: pass
      - kind: integration
        ref: "tests/test_workload_resilience.py#ThumbnailMigrationTests.test_migration_ten_moves_existing_blobs_off_services"
        status: pass
    human_judgment: false
  - id: D2
    description: "GET /api/thumbnail/<port> serves stored bytes byte-for-byte from the bounded store with the stored mime, 404s once expires_ts is past, and GET /api/services' has_thumb tracks the same expiry"
    requirement: "OPS-03"
    verification:
      - kind: integration
        ref: "tests/test_workload_resilience.py#ThumbnailRelocationTests.test_thumbnail_is_stored_in_and_served_from_the_bounded_store"
        status: pass
      - kind: integration
        ref: "tests/test_workload_resilience.py#ThumbnailRelocationTests.test_a_failed_capture_records_diagnostics_without_an_orphan_thumbnail_row"
        status: pass
    human_judgment: false
  - id: D3
    description: "The migration-tail contract is version-agnostic (no test pins MIGRATIONS[-1].version as a literal) and the support floor admits every tracked lineage at schema version 9 before migration 10 exists"
    requirement: "OPS-03"
    verification:
      - kind: unit
        ref: "tests/test_migrations.py#test_support_floor_admits_every_tracked_lineage_at_the_previous_version"
        status: pass
      - kind: unit
        ref: "tests/test_migrations.py#test_support_floor_covers_history_and_confirmed_operator_evidence"
        status: pass
      - kind: unit
        ref: "tests/test_maintenance_windows.py#MigrationNineTests.test_migration_nine_adds_the_table_columns_and_index"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_migration_eight_adds_only_job_health_evidence"
        status: pass
    human_judgment: false
  - id: D4
    description: "Exactly one module (repositories.py) writes thumbnail bytes; the old ThumbnailRepository is retired; J6 declares 'thumbnails' as a database surface in both the worker inventory and the ownership contract"
    requirement: "OPS-03"
    verification:
      - kind: unit
        ref: "tests/test_module_boundaries.py#ModuleBoundaryTests.test_thumbnail_sql_stays_in_the_repository_boundary"
        status: pass
      - kind: unit
        ref: "tests/test_worker_ownership_matrix.py"
        status: pass
      - kind: other
        ref: "python -c \"from dashboard.beacon import repositories; assert not hasattr(repositories, 'ThumbnailRepository')\""
        status: pass
    human_judgment: false
  - id: D5
    description: "The phase's measured full-suite pytest runtime (222.82s) is recorded in 06-VALIDATION.md, replacing the TBD placeholder, with the Max feedback latency (full suite) budget reconciled to 240s per the phase's own reconciliation rule"
    verification:
      - kind: other
        ref: "time uv run --project dashboard python -m pytest -q (780 passed, 552 subtests passed, 222.82s)"
        status: pass
    human_judgment: false

duration: 75min
completed: 2026-09-01
status: complete
---

# Phase 6 Plan 1: Thumbnail Relocation Tracer & Version-Agnostic Migration Contract Summary

**Migration 10 relocates thumbnail blobs from `services` into a bounded, TTL-expiring `thumbnails` table via a new `ThumbnailStoreRepository`, proven end-to-end, with the migration-tail contract made version-agnostic first so the schema bump lands on a green suite.**

## Performance

- **Duration:** ~75 min active work (spread across two sessions with a tracer checkpoint pause for human-verify approval)
- **Started:** 2026-08-28T12:24:13+03:00 (first commit after phase plan finalization)
- **Completed:** 2026-09-01T00:45:17+03:00
- **Tasks:** 4 (1 decision checkpoint + 3 executed tasks)
- **Files modified:** 15 (14 modified, 1 created)

## Accomplishments
- Migration 10 (`_migration_10_bounded_thumbnail_store`) creates `thumbnails(port, data, mime, captured_ts, source, expires_ts)`, backfills every existing captured blob into it inside the same transaction that empties `services.thumb_data`/`thumb_mime`, and adds `preview_requests.next_attempt_ts` for 06-03
- `ThumbnailStoreRepository` (repositories.py) is now the sole module that writes thumbnail bytes; the worker write path, `GET /api/thumbnail/<port>`, and all three `has_thumb` projections (discovery, uptime-check re-enqueue, `/api/services`) read/write through the new store
- The migration-tail contract is version-agnostic: `LINEAGE_FINGERPRINTS` maps schema version to lineage fingerprints, five previously tail-pinned assertions now derive from `MIGRATIONS[-1].version`, and the support floor pre-admits every tracked lineage at schema version 9 before migration 10 ever exists
- `tests/test_workload_resilience.py` created as the Phase 6 OPS-01..04 integration suite, seeded with the thumbnail round-trip and migration-path tests
- Eight pre-existing test sites across `test_api_and_auth.py`, `test_security_and_scanning.py`, and `test_runtime_ownership.py` realigned onto the new store without changing their names, docstrings, or subjects
- J6 declares `thumbnails` as a database surface in both `WORKER_CALLBACK_INVENTORY` and `tests/worker_ownership_contract.py`
- Full suite measured once at 222.82s and recorded in `06-VALIDATION.md`, with `Max feedback latency (full suite)` reconciled to 240s

## Task Commits

Each task was committed atomically:

1. **Task 1: Confirm the one-way door — migration 10 empties services.thumb_data in place** - decision only, no commit (option `proceed` selected by the user; pre-resolved by the orchestrator before this plan began execution)
2. **Task 2: Make the migration-tail contract version-agnostic and admit every v9 lineage into the support floor** - `a743e86` (test)
3. **Task 3: Tracer — a captured thumbnail is stored in, and served from, the bounded store** - `c7160f4` (feat)
4. **Task 4: Retire the old write path, declare the new surface, and record the suite's measured runtime** - `21fc4dd` (refactor)

**Plan metadata:** commit follows this summary

## Files Created/Modified
- `dashboard/beacon/migrations.py` - Migration 10 (bounded thumbnail store), `THUMBNAIL_BACKFILL_TTL_SECONDS`
- `dashboard/beacon/repositories.py` - `ThumbnailStoreRepository` (sole write path), `read_thumbnail()`; old `ThumbnailRepository` deleted
- `dashboard/app.py` - `THUMBNAIL_TTL_SECONDS`, `_thumbnail_store()`, relocated `api_thumbnail` and three `has_thumb` projections
- `dashboard/beacon/worker_main.py` - J6 `database_surfaces` gains `'thumbnails'`
- `dashboard/beacon/support_floor.json` / `tests/fixtures/legacy/support-floor.json` - four new v9 lineage entries (Task 2), then every entry's `target_version` moved to 10 (Task 3)
- `tests/test_migrations.py` - `V9_FINGERPRINTS`, `LINEAGE_FINGERPRINTS`, five range-derived tail assertions, new `test_migration_ten_thumbnail_relocation_preserves_every_captured_blob`
- `tests/test_maintenance_windows.py`, `tests/test_advanced_diagnosis_api.py` - literal tail-version pins replaced with applied-migration assertions
- `tests/test_api_and_auth.py`, `tests/test_security_and_scanning.py`, `tests/test_runtime_ownership.py` - eight test sites realigned onto `thumbnails`
- `tests/test_module_boundaries.py` - `test_thumbnail_sql_stays_in_the_repository_boundary` retargeted at the new store's write statement
- `tests/worker_ownership_contract.py` - `'thumbnails'` added to `DATABASE_SURFACES` and the J6 row
- `tests/test_workload_resilience.py` (new) - Phase 6 integration suite; `ThumbnailRelocationTests`, `ThumbnailMigrationTests`
- `.planning/phases/06-workload-resilience-pi-acceptance/06-VALIDATION.md` - measured full-suite runtime and reconciled feedback-latency budget

## Decisions Made
- **D-OPS-03-01 (Task 1, user decision `proceed`):** relocate and empty `services.thumb_data` in migration 10, as planned. Satisfies OPS-03 directly; single migration version keeps the support-floor/fingerprint work in one wave-1 plan; a verified pre-v10 backup is created automatically before the migration touches anything. Accepted one-way-door risk: restoring the pre-phase schema shape on a live deployment requires restoring that backup, since this codebase has no down-migration path.
- **Tracer human-verify approved** by the user after reviewing the automated evidence at the Task 3 checkpoint (full suite green, targeted realigned-test suites green, module-boundary test still green with the old repository class untouched pending Task 4).
- **Falsification-check deviation (Task 2):** see `key-decisions` in frontmatter — used a sequential `Migration(10, ...)` probe instead of the literally-specified `Migration(11, ...)` for the tail-version falsification check, because the literal instruction creates a version gap that breaks unrelated contiguous-range assertions. The sequential probe produces exactly the single intended failure (stale `target_version`) with no cascading failures, matching what the acceptance criterion actually verifies.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - clarification, not a bug] Falsification-check probe number**
- **Found during:** Task 2 acceptance-criteria verification
- **Issue:** The plan's literal instruction ("append a schema-changing no-op `Migration(11, ...)`") creates a version gap at 10 (since the tail was 9 at Task 2's commit), which breaks five range-derived `applied_versions` assertions that have nothing to do with support-floor bookkeeping — contradicting the acceptance criterion's own claim that only the two support-floor tests would fail.
- **Fix:** Ran the falsification check with a sequential `Migration(10, ...)` probe instead (no gap). This produced exactly one failure — the stale `target_version` assertion in `test_support_floor_covers_history_and_confirmed_operator_evidence` — with zero cascading failures, which is what the acceptance criterion's underlying property actually requires. `test_support_floor_admits_every_tracked_lineage_at_the_previous_version` passed cleanly because Task 2 had already pre-loaded the v9 lineage entries, which is the intended effect of this plan's design.
- **Files modified:** none (temporary, in-memory-file patch via a scratch script; reverted immediately with `git checkout -- dashboard/beacon/migrations.py` before continuing)
- **Verification:** Observed exactly 1 failed / 39 passed in `tests/test_migrations.py`; reverted and re-ran to confirm 40 passed / 6 subtests passed (green)
- **Committed in:** not committed (falsification probe, not a permanent change)

---

**Total deviations:** 1 (clarification of an ambiguous acceptance-criterion instruction, not a code bug)
**Impact on plan:** No scope creep; no permanent code change beyond what the plan specified. The falsification check's underlying purpose (prove no bookkeeping-unrelated assertion breaks when the next migration ships) was fully satisfied.

## Issues Encountered
- **Flaky test observed under load (not a regression from this plan):** `tests/test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced` failed twice (subtests `S2`, `J1`) with `AssertionError: False is not true : ... A never reached heartbeat persistence` during one full-suite run (`paused.wait(timeout=2)` timing out). The test passed cleanly in isolation immediately after, and a second full-suite run was 100% green (780 passed, 552 subtests passed). This test is unrelated to any file this plan touched — it exercises worker-lease takeover fencing via a 2-second thread-coordination timeout, which appears sensitive to system load during a ~3.5-minute full-suite run. Recorded here for later phases' awareness; not fixed as part of this plan (out of scope per the scope-boundary rule — pre-existing timing sensitivity in an unrelated file).
- No other issues. Both `git checkout -- <file>` reverts used during falsification testing (Task 2's Migration(11) probe and Task 4's module-boundary marker-move probe) briefly discarded uncommitted Task 4 work-in-progress on `dashboard/beacon/repositories.py` that had not yet been committed; both were re-applied and re-verified before committing.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- OPS-03 is fully implemented and verified for this plan's scope: bounded, TTL-seeded thumbnail store; version-agnostic migration-tail contract; support floor pre-loaded for the next migration.
- `tests/test_workload_resilience.py` exists and is ready for 06-02 (TTL/byte-budget enforcement), 06-03 (bounded preview retry), 06-04 (cadence under contention), 06-05 (WAL/concurrency/restart), and 06-06 (harness self-test) to each append their own tests to it, per its module docstring.
- `preview_requests.next_attempt_ts` (added in migration 10, currently unused) is ready for 06-03 to wire into bounded preview retry.
- No blockers. The flaky `test_worker_ownership_matrix.py` timing sensitivity noted above is worth a quick look if it recurs in a later phase's full-suite runs, but does not block this plan or the next.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-01*
