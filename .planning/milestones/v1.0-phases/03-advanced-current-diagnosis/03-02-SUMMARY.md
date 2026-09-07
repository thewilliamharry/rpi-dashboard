---
phase: 03-advanced-current-diagnosis
plan: 02
subsystem: api-database-worker
tags: [flask, sqlite, apscheduler, telemetry, pytest]
requires:
  - phase: 03-advanced-current-diagnosis
    provides: bounded current-host diagnosis tracer and Flask-free composition seam
provides:
  - approved additive Migration 8 durable background-job outcome evidence
  - authority-fenced callback start, success, and failure recording
  - bounded GET-only current service, pipeline, settings, safety, and exception diagnosis
affects: [03-03-advanced-workspace-ui, phase-4-historical-investigation]
tech-stack:
  added: []
  patterns:
    - current worker epoch assertion and outcome mutation share one BEGIN IMMEDIATE transaction
    - current diagnosis composes fixed, capped SQLite readers before JSON serialization
key-files:
  created: []
  modified:
    - dashboard/beacon/migrations.py
    - dashboard/beacon/repositories.py
    - dashboard/beacon/worker_main.py
    - dashboard/beacon/diagnosis.py
    - dashboard/app.py
    - tests/test_advanced_diagnosis_api.py
key-decisions:
  - "Approved Migration 8 as an additive, restart-safe background-job outcome contract keyed by immutable callback ID."
  - "Publish job evidence only after an exact worker epoch is present and re-proved in the same write transaction."
  - "Keep the advanced snapshot GET-only, parameterless, one-read, and separately typed for availability, freshness, gaps, pressure, and job state."
patterns-established:
  - "Background callback outcomes use running/succeeded/failed transitions and bounded class-only failure evidence."
  - "Advanced pipeline schedule evidence comes from the immutable callback inventory, never a live scheduler."
requirements-completed: [TEL-06, DIA-02, DIA-03, DIA-08]
coverage:
  - id: D1
    description: "Migration 8 and authority-fenced callback outcome evidence preserve real SQLite takeover safety."
    requirement: TEL-06
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py -k 'job_health or migration_eight or callback_outcome or stale_worker'"
        status: pass
      - kind: integration
        ref: "tests/test_migrations.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "Current diagnosis returns services, pipeline, read-only settings, safety, and ordered exceptions from fixed bounded reads."
    requirement: DIA-03
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py -x"
        status: pass
    human_judgment: false
  - id: D3
    description: "Worker callback lifecycle remains compatible with exact-epoch evidence fencing and lease-loss drain semantics."
    requirement: DIA-02
    verification:
      - kind: integration
        ref: "tests/test_runtime_ownership.py -x"
        status: pass
    human_judgment: false
duration: 16min
completed: 2026-08-14
status: complete
---

# Phase 3 Plan 2: Current Service and Pipeline Diagnosis Summary

**Approved Migration 8 durable job evidence and one bounded, GET-only diagnosis snapshot now explain current service, worker, telemetry, settings, safety, and exceptions.**

## Performance

- **Duration:** 16 min
- **Started:** 2026-08-14T10:34:07Z
- **Completed:** 2026-08-14T10:50:30Z
- **Tasks:** 2/2
- **Files modified:** 10

## Accomplishments

- Added the approved additive Migration 8 `background_job_health` contract with state/update diagnostics and bounded class-only failure evidence.
- Fenced callback starts, successes, false results, and exceptions to the exact current worker epoch in one immediate SQLite transaction.
- Expanded `/api/advanced/current` into a parameterless no-store snapshot of current services, pipeline evidence, read-only effective settings, safety facts, and deterministic active exceptions.

## Task Commits

1. **Task 1: Persist authority-fenced worker callback outcomes (RED)** — `03a6c4f` (test)
2. **Task 1: Persist authority-fenced worker callback outcomes (GREEN)** — `7044313` (feat)
3. **Task 2: Expand the one-read snapshot to services, pipeline, settings, and exceptions (RED)** — `acd90fb` (test)
4. **Task 2: Expand the one-read snapshot to services, pipeline, settings, and exceptions (GREEN)** — `911ee75` (feat)
5. **Task 1 compatibility fixes** — `54099b8`, `fa8bf88`, `5c84d26` (fix)

## Files Created/Modified

- `dashboard/beacon/migrations.py` — registers additive, transactional Migration 8.
- `dashboard/beacon/repositories.py` — supplies bounded job, service, and pipeline readers plus caller-owned job transitions.
- `dashboard/beacon/worker_main.py` — records authoritative outcomes without changing lease-loss admission semantics.
- `dashboard/beacon/diagnosis.py` — composes service ordering, pipeline facts, effective settings, safety, and exceptions.
- `dashboard/app.py` — rejects advanced query selectors before SQLite and retains no-store GET output.
- `tests/test_advanced_diagnosis_api.py` — covers migration, job outcomes, stale authority, and expanded snapshot fields.

## Decisions Made

- The operator approved `approve-migration-8`: one current durable row per immutable callback ID, without changing existing service or telemetry rows.
- A job is marked succeeded only for a result other than explicit `False`; errors store only a bounded class name.
- Pipeline facts remain separate: database pressure, worker freshness, stream freshness, gaps, pending aggregation, and job outcomes are never merged into one status.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Compatibility] Updated migration support-floor and fixture expectations for Migration 8.**
- **Found during:** Final full-suite verification
- **Issue:** Existing compatibility tests and support metadata hardcoded schema version 7 and its single-migration backup count.
- **Fix:** Advanced the direct version/backup expectations and retained explicit Migration 7 rollback selection under the now-version-8 registry.
- **Files modified:** `tests/test_migrations.py`, `dashboard/beacon/support_floor.json`, `tests/fixtures/legacy/support-floor.json`
- **Verification:** `tests/test_migrations.py` — 23 passed, 6 subtests passed.
- **Committed in:** `54099b8`

**2. [Rule 1 - Compatibility] Gave the lease-loss lifecycle fixture a real worker epoch.**
- **Found during:** Final full-suite verification
- **Issue:** The fixture expected a J6 callback to start while providing an unleased synthetic authority, which the new required pre-invocation job-health fence correctly rejected.
- **Fix:** Acquired a real short SQLite lease and constructed `WorkerAuthority` from it, retaining the original drain-before-browser-cleanup scenario.
- **Files modified:** `tests/test_runtime_ownership.py`
- **Verification:** `tests/test_runtime_ownership.py -k 'lease_loss_drains_active_jobs_before_browser_cleanup'` — passed.
- **Committed in:** `fa8bf88`

**3. [Rule 1 - Compatibility] Preserved skeletal dispatch collaborators before an epoch exists.**
- **Found during:** Runtime ownership suite
- **Issue:** Existing startup-shape tests intentionally use skeletal collaborators without a durable authority; attempting a health write treated mock clock data as production evidence.
- **Fix:** Keep job-health publication exclusive to real `WorkerAuthority` epochs while retaining compatibility dispatch behavior for no-epoch collaborator tests.
- **Files modified:** `dashboard/beacon/worker_main.py`
- **Verification:** `tests/test_runtime_ownership.py` — 22 passed, 61 subtests passed.
- **Committed in:** `5c84d26`

**Total deviations:** 3 Rule 1 compatibility fixes. All were directly required by the approved Migration 8/evidence fence and introduced no product-scope expansion.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py -k "job_health or migration_eight or callback_outcome or stale_worker" -x` — **4 passed**.
- `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py -x` — **10 passed, 15 subtests passed**.
- `uv run --project dashboard python -m pytest -q tests/test_migrations.py -x` — **23 passed, 6 subtests passed**.
- Full suite completed in execution-window-safe batches: **231 passed, 269 subtests passed** (one pre-existing system-time warning from urllib3 during outbound TLS testing).

## Known Stubs

None.

## Next Phase Readiness

Plan 03-03 can render the complete bounded current-diagnosis contract without introducing worker ownership, history scans, or browser mutation controls.

## Self-Check: PASSED

Confirmed all task commits (`03a6c4f`, `7044313`, `acd90fb`, `911ee75`, `54099b8`, `fa8bf88`, `5c84d26`) exist and the planned implementation files are present.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-14*
