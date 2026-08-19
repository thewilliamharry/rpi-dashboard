---
phase: 03-advanced-current-diagnosis
plan: 12
subsystem: worker
tags: [job-health, bookkeeping, dispatch, gap-closure, durable-evidence]
status: complete

requires:
  - "dashboard/beacon/worker_main.py::dispatch_callback (the sole admission-wrapped callback boundary)"
  - "dashboard/beacon/worker_main.py::_write_job_health_transition (owns its own BEGIN IMMEDIATE transaction and the authority assertion)"
  - "dashboard/beacon/worker_main.py::_job_error_class (the 96-char, message-free failure-class rule)"
  - "dashboard/beacon/diagnosis.py::compose_active_exceptions (promotes any failed job row to a job_failed card)"
  - "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests (services_for harness, direct background_job_health SELECT, _freeze_clock addCleanup discipline)"
  - ".planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md (Gap B, both missing bullets)"
provides:
  - "dashboard/beacon/worker_main.py::JobHealthBookkeepingError — a bookkeeping-write failure as its own named condition"
  - "A dispatch path where the work's outcome is decided in a scope that writes nothing, then recorded once outside it"
  - "Exactly one started write and one outcome write per dispatch — no compensating, retried, or duplicate bookkeeping write"
  - "tests/test_advanced_diagnosis_api.py::test_a_succeeded_callback_never_records_durable_failed_evidence"
  - "tests/test_advanced_diagnosis_api.py::test_outcome_paths_survive_the_bookkeeping_split"
  - "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests::_job_health_row (shared durable-row reader)"
affects:
  - "03-14 (TEL-06 traceability reconciliation, which must wait on phase re-verification)"
  - "Any later plan touching dispatch_callback, worker admission, or the job-health write path"

actuals:
  tokens: 18872
  tasks: 2
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Deciding an outcome and recording it are separate scopes; the recording scope never spans the work"
    - "A bookkeeping failure raises its own named condition rather than converting the verdict it failed to record"
    - "No corrective or retried write on a failed bookkeeping write — one started write, one outcome write, per dispatch"
    - "A raised condition obeys the same message-free discipline as the durable row it failed to write"
    - "Test monkeypatches of module globals are restored through addCleanup, never a bare trailing assignment"

key-files:
  created: []
  modified:
    - dashboard/beacon/worker_main.py
    - tests/test_advanced_diagnosis_api.py

key-decisions:
  - "JobHealthBookkeepingError subclasses RuntimeError and builds its string form only from callback id, transition, and the _job_error_class name — the underlying exception reaches the caller through __cause__ (raise ... from), never through the message"
  - "The started-write failure path runs no work at all and writes no failure record: the work never happened, so there is no work outcome to record"
  - "The retained work exception is re-raised AFTER the outcome write, preserving the old trailing bare `raise` semantics and dispatch_callback's return contract byte-for-byte"
  - "The outcome write's lease-loss branch keeps the existing recording-path log message ('...while recording callback failure') for every outcome, including success — a deliberate, plan-mandated message change for the success path"
  - "TEL-06 was deliberately NOT marked Complete: Gap B closure needs independent re-verification, and 03-14 owns the traceability reconciliation"

patterns-established:
  - "JobHealthBookkeepingError is the named condition for any non-lease-loss durable job-health write failure"
  - "_job_health_row(job_id) is the module's shared durable job-health reader for outcome assertions"

requirements-completed: []

coverage:
  - id: D1
    description: "A callback whose work returned True, whose success bookkeeping write raises a transient sqlite3.OperationalError, never attempts a failure transition, never leaves a durable failed row, and never produces a job_failed exception on the Overview surface; the raised condition names the callback and the error class but not the injected message"
    requirement: "TEL-06"
    verification:
      - kind: automated_test
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_a_succeeded_callback_never_records_durable_failed_evidence"
        status: pass
    human_judgment: false
  - id: D2
    description: "The three outcome paths that were already correct are unmoved: returned-false stays failed with CallbackReturnedFalse and no success timestamp; a raising callback stays failed with its class name and still propagates; a lease loss returns False, closes admission, and writes no failure record; a healthy callback stays succeeded with a success timestamp"
    requirement: "TEL-06"
    verification:
      - kind: automated_test
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_outcome_paths_survive_the_bookkeeping_split"
        status: pass
      - kind: automated_test
        ref: "tests/test_worker_ownership_matrix.py + tests/test_runtime_ownership.py (authority fence and lease-loss dispatch)"
        status: pass
    human_judgment: false
  - id: D3
    description: "The module contains exactly one started write and one outcome write, verified by call-site count rather than by reading the diff"
    requirement: "TEL-06"
    verification:
      - kind: static_gate
        ref: "grep -c '_write_job_health_transition(' dashboard/beacon/worker_main.py == 3"
        status: pass
    human_judgment: false
  - id: D4
    description: "On the target Pi, the Overview safety surface stops showing a job_failed card for a background job that is actually healthy"
    requirement: "TEL-06"
    verification: []
    human_judgment: true
    rationale: "Operator trust in the rendered Overview on real hardware under a real transient SQLite contention cannot be asserted programmatically; collected at the end-of-phase human checkpoint per workflow.human_verify_mode."

duration: 8min
completed: 2026-08-19
---

# Phase 03 Plan 12: Worker Job-Health Bookkeeping Split Summary

**`dispatch_callback` now decides what a callback did in a scope that writes nothing and records that outcome exactly once outside it, so a raising `succeeded` write raises `JobHealthBookkeepingError` instead of durably recording `state='failed'` for a job that succeeded — and the Overview surface stops promoting a `job_failed` card for a healthy job.**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-08-19T05:52:00Z
- **Completed:** 2026-08-19T06:00:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `dashboard/beacon/worker_main.py::JobHealthBookkeepingError`, a `RuntimeError` subclass carrying the callback identifier, the transition that could not be written, and the bounded class name from `_job_error_class`. Its string form is built from those three fields only; the underlying exception reaches the caller through `__cause__` (`raise ... from`), so the message-free discipline that keeps durable rows clean now also holds for the raised condition.
- Restructured `dispatch_callback` into three scopes: a `started` write, a **non-writing** outcome decision around `_invoke_callback`, and a single outcome write. The broad `except Exception` no longer spans any write, which is precisely the anti-pattern the verifier located at `worker_main.py:272-296`.
- Collapsed the module's four job-health call sites (started, returned-false, succeeded, exception-handler failure) into **two** — one started write, one outcome write. The plan's call-site gate (`grep -c '_write_job_health_transition(' == 3`, definition plus two call sites) landed exactly on 3 without adjustment.
- Preserved every construct the plan named: the `ownership_required` early return, the `services.admission.admit` context manager and its `if not admitted` return, the skeletal-collaborator `isinstance` authority fence with its comment, both lease-loss shutdown branches with their distinct log messages, and the return contract (`None` when not admitted, `False` on lease loss and on returned-false, the callback's result otherwise, the work exception re-raised otherwise).
- Added the Gap B fault-injection regression, written failing first: it reproduces the verifier's exact shape (work returns True, `succeeded` write raises `sqlite3.OperationalError('database is locked')`) and asserts the transition sequence is `['started', 'succeeded']` with no failure transition attempted at all, the durable row is not `failed` and carries no error class, `get_current_diagnosis` emits no `job_failed` exception for that job, and the raised condition's string contains `J2` and `OperationalError` but not `database is locked`.
- Added the four-outcome guard regression pinning returned-false, raising, lease-loss, and healthy dispatches to **durable rows** rather than to a recorder — the durable row being what the operator ultimately sees.

## Task Commits

Each task was committed atomically (TDD: test → feat):

1. **Task 1 (tracer): Decide the outcome before recording it, and let a failed recording be its own condition**
   - `a7a7de3` (test) — fault-injection regression, RED with `AttributeError: module 'dashboard.beacon.worker_main' has no attribute 'JobHealthBookkeepingError'`
   - `a4fe2cd` (feat) — `JobHealthBookkeepingError` + the three-scope `dispatch_callback` restructure
2. **Task 2: Prove the three outcome paths that were already correct did not move**
   - `90afdc5` (test) — `_job_health_row` reader + `test_outcome_paths_survive_the_bookkeeping_split` (four subtests, four distinct job ids)

Task 2 is test-only by design (`<files>` names only the test module), so its RED/GREEN cycle is degenerate — there is no production change for it to drive. It is committed as `test(...)`.

## Files Created/Modified

- `dashboard/beacon/worker_main.py` — added `JobHealthBookkeepingError` beside `_job_error_class`; rewrote `dispatch_callback`'s body. `_invoke_callback`, `_job_error_class`, `_write_job_health_transition`, `WorkerAdmission`, `WORKER_CALLBACK_INVENTORY`, `stop_worker`, and every compatibility export are untouched. No schema, column, route, or dependency change.
- `tests/test_advanced_diagnosis_api.py` — added `test_a_succeeded_callback_never_records_durable_failed_evidence`, `_job_health_row`, and `test_outcome_paths_survive_the_bookkeeping_split`. `_freeze_clock`, `ClockIsolationTests`, and all pre-existing tests are unmodified.

## Decisions Made

- **The bookkeeping condition never formats the underlying exception.** `JobHealthBookkeepingError.__init__` takes an already-bounded class *name*, not the exception, so there is no code path by which a message, path, or SQL fragment can reach its string form. The real exception is still fully available to a debugger through `__cause__`, which is what keeps this from trading one lie (a false failure record) for another (a swallowed bookkeeping error).
- **A failed `started` write runs no work.** The work never happened, so no work outcome exists to record and none is written. The alternative — running the work anyway — would produce a dispatch whose durable record is silently missing its start.
- **No corrective write on a failed outcome write.** T-03-77 forbids a compensating or retried bookkeeping write, and a retry would hold the immediate write transaction. The raise is the whole response.
- **Deliberate log-message change on one path.** Previously a lease loss during the `succeeded` write was caught by the outer handler and logged `'Beacon worker lease lost; stopping stale scheduler'`. The unified outcome write uses the plan-mandated recording-path message `'Beacon worker lease lost while recording callback failure'` for all outcomes. Behaviour (close admission, stop worker, return False) is identical; no test asserts on either string.
- **TEL-06 was NOT marked Complete.** `.planning/REQUIREMENTS.md:123` correctly remains `| TEL-06 | Phase 3 | Gaps Found |` and line 25 stays unchecked. This plan closes Gap B's implementation, but 03-VERIFICATION.md's own standing prohibition is that nothing is recorded complete on the strength of an implementation claim — only on independent re-verification. 03-14 owns the reconciliation.

## Deviations from Plan

### 1. [Process] Tracer feedback gate resolved automatically rather than as an interactive checkpoint

- **Found during:** End of Task 1.
- **Issue:** The tracer gate normally emits a `checkpoint:human-verify` in an interactive run.
- **Fix:** The tracer's `<verify>` was re-run end to end and passed (`ONE_STARTED_ONE_OUTCOME_WRITE`, plus the fault-injection test), then execution continued to the expansion task. The plan declares `autonomous: true`, contains no `checkpoint:*` task, and the workspace runs `human_verify_mode: end-of-phase`, so the human judgment for this surface (D4 above) is collected at the phase checkpoint.

### 2. [Judgment — honesty prohibition] TEL-06 left at `Gaps Found`

- **Found during:** State updates after Task 2.
- **Issue:** The standard executor state step marks every requirement in the plan's `requirements:` frontmatter complete. This plan lists `TEL-06`.
- **Fix:** `requirements.mark-complete` was not run; `requirements-completed` is `[]`.
- **Rationale:** 03-VERIFICATION.md's upheld 03-10 prohibition forbids recording a requirement complete on an implementation claim rather than independent verification, and its own required end state lists TEL-06 among the IDs that must stay unchecked. 03-14 reconciles once the phase is re-verified.

**Total deviations:** 2 (1 process, 1 honesty-driven omission). No auto-fixed bugs. No Rule 4 architectural question arose.
**Impact on plan:** None on scope. Every `<action>` instruction was followed literally.

### Plan-pinned counts checked against the live tree

- `_write_job_health_transition(` occurrences **before** the restructure: **5** — exactly as the plan stated (definition + started + returned-false + succeeded + exception-handler failure).
- `_write_job_health_transition(` occurrences **after**: **3** — the plan's pinned value, reached without adjusting the gate.
- The verifier-named anti-pattern (`_write_job_health_transition(..., 'succeeded')` at line 280 inside the `except Exception` at line 287) was present exactly as described.

## Verification Evidence

- `uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py -k succeeded_callback_never_records -q` → **1 passed** (RED first: `AttributeError: ... has no attribute 'JobHealthBookkeepingError'`)
- `test "$(grep -c '_write_job_health_transition(' dashboard/beacon/worker_main.py)" = "3"` → **ONE_STARTED_ONE_OUTCOME_WRITE**
- `grep -c 'class JobHealthBookkeepingError' dashboard/beacon/worker_main.py` → `1`
- `uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py tests/test_runtime_ownership.py tests/test_worker_ownership_matrix.py -q` → **63 passed, 183 subtests passed**
- `uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py -k 'outcome_paths_survive or job_health_transitions_preserve_success or callback_outcome_false_and_exception or stale_worker_cannot_change or a_frozen_clock_never_outlives' -q` → **5 passed, 4 subtests passed** (the three pre-existing job-health regressions pass unmodified; the 03-10 clock-isolation guard is not reopened)
- `uv run --project dashboard python -m pytest -q` → **285 passed, 373 subtests passed** (was 283 / 369 after 03-11 — exactly the two new tests and four new subtests, no regression)

## Issues Encountered

- The first run of `test_outcome_paths_survive_the_bookkeeping_split` failed with `ValueError: unknown worker admission category: scan`. `WorkerCallback`'s positional fields are `(identifier, operation_fields, handler, admission_category, ...)`, so J5's `'scan'` is its **handler**, not its admission category — the category is `'scheduled'`. Fixed in the same task; the corrected assertion confirms lease loss leaves admission closed.

## Known Stubs

None introduced. The pre-existing `'collection_gaps': []` hollow-prop at `dashboard/beacon/diagnosis.py:167` and its `JSON.stringify` render at `dashboard/advanced.js:648` are untouched and remain open — Gap A `missing` bullet 2, owned by plan 03-13.

## Threat Flags

None. No new endpoint, auth path, file access pattern, or schema change. The restructure adds no catch-all: it replaces one broad `except Exception` (which spanned a write) with two narrower ones (neither of which spans the work), and lease loss keeps its own dedicated branch ahead of every general one in all three scopes, per `AGENTS.md` narrow-handling convention (T-03-78). The authority fence inside `_write_job_health_transition` is unchanged and re-asserted by `test_stale_worker_cannot_change_job_health_evidence` and both ownership suites (T-03-76). No dependency was added, removed, or upgraded (T-03-79).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Gap B is closed in implementation and locked by a fault-injection regression that reproduces the verifier's own shape.
- **Still open for Phase 3:** 03-13 (`collection_gaps` server population — Gap A bullet 2), 03-14 (REQUIREMENTS.md reconciliation, which must wait on 03-13 and on re-verification).
- TEL-06 remains `Gaps Found` by design and must not be promoted until the phase is independently re-verified.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*

## Self-Check: PASSED

- Files verified present: `dashboard/beacon/worker_main.py`, `tests/test_advanced_diagnosis_api.py`, `.planning/phases/03-advanced-current-diagnosis/03-12-SUMMARY.md`
- Commits verified in git history: `a7a7de3`, `a4fe2cd`, `90afdc5`
