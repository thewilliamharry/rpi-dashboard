---
phase: 03-advanced-current-diagnosis
plan: 15
subsystem: infra
tags: [python, sqlite, apscheduler, exception-chaining, logging, worker-lifecycle, vanilla-js]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-12's three-scope dispatch split, JobHealthBookkeepingError, the authority-fenced _write_job_health_transition, and the fault-injection recorder harness in tests/test_advanced_diagnosis_api.py"
  - phase: 03-advanced-current-diagnosis
    provides: "03-08's compose_active_exceptions projection, the EXCEPTION_COPY map, and the emitted-kind inventory regression in tests/test_advanced_ui.py"
provides:
  - "A dispatch path where a work failure and the failure to record it are both reported: the bookkeeping condition carries the work's bounded class, chains from the work error, and the work failure is logged at error level before the raise"
  - "A new job_outcome_unrecorded exception kind promoting a durably-running job whose own start is overdue against its own configured cadence onto the Overview safety surface, with operator copy that states the observation and never claims failure"
  - "An explicit worker-startup decision about JobHealthBookkeepingError, so a transient database lock on an S1/S2/S3 bookkeeping write can no longer terminate the worker before the scheduler is built"
  - "tests/test_advanced_diagnosis_api.py owning the worker scheduler global it touches, removing a cross-module teardown dependency"
affects: [advanced-diagnosis, worker-lifecycle, operator-safety-surface, phase-03-reverification]

actuals:
  tokens: 60027
  tasks: 3
  commits: 7

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Adjacent failures are reported as two conditions, not merged and not cancelled: the bookkeeping condition carries the work's bounded class and chains from the work error, leaving the write error reachable as implicit context"
    - "Operator safety promotions are derived only from the promoted row's own durable fields, reusing the module's existing four-times-cadence staleness boundary and strict `type(...) is int` discipline rather than inventing a second convention"
    - "Exception dictionaries on the safety surface are built from explicit keys only, never by spreading a durable row"
    - "A named bookkeeping condition is handled at its one escape point, narrowly, and never widened to catch the lease-loss shutdown path"

key-files:
  created: []
  modified:
    - dashboard/beacon/worker_main.py
    - dashboard/beacon/diagnosis.py
    - dashboard/advanced.js
    - tests/test_advanced_diagnosis_api.py
    - tests/test_advanced_ui.py

key-decisions:
  - "Chain the bookkeeping condition from the work error rather than from the write error: Python has already bound the write error as implicit __context__, so binding the work error as the explicit __cause__ is what makes both reachable — binding the write error to both, as 03-12 did, made only one reachable"
  - "Express the conditional chain as exactly one raise statement whose `from` operand is a conditional expression, keeping the module at exactly two raise sites for the bookkeeping condition as the acceptance gate requires"
  - "Inline the overdue-outcome predicate in the promotion branch rather than extracting a named helper, because the acceptance gate pins `job_outcome_unrecorded` to exactly one occurrence in diagnosis.py — a named helper produced three"
  - "Reuse freshness_state's existing four-times-cadence staleness boundary and its strict `type(...) is int` checks for the new promotion rather than introducing a second staleness convention in the same module"
  - "Introduce RUNNING_JOB_STATE as the single named literal for the state record_background_job_started writes, so the promotion branch reads against the repository's authority rather than the review snippet's `started`"
  - "Build the new exception from explicit keys only, so CF-WR-10's row-spread hazard is neither fixed nor widened by this round"
  - "Correct JobHealthBookkeepingError's docstring to claim the no-message discipline for the condition's own message and arguments, and to state that chaining is a deliberate, separate maintainer channel"
  - "Log the startup bookkeeping condition at warning level and continue, because a failure to record that a startup job began is a fact about the recording and never a verdict on whether Beacon should run"

patterns-established:
  - "Three-channel failure survival: a suppressed failure regains visibility through a bounded attribute on the raised condition, the exception chain, and an error-level log line — all three asserted on the object graph rather than on message strings"
  - "Compound fault injection: a regression drives a work failure and a bookkeeping failure into the same dispatch, so narrowing one condition can never again silently remove the other's last channel"
  - "Test-local ownership of process globals: any test reaching stop_worker registers its own scheduler-global reset via addCleanup instead of borrowing another module's teardown"

requirements-completed: []

coverage:
  - id: D1
    description: "A work failure and the failure of the write that would record it are both reported: the raised bookkeeping condition carries the work's bounded class, the work exception is reachable via __cause__, the write exception stays reachable through the chain, and an error-level log record names the work class without its message — while the durable row is still recorded neither failed nor succeeded"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_a_failed_callback_survives_a_failing_outcome_write"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_a_succeeded_callback_never_records_durable_failed_evidence"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_outcome_paths_survive_the_bookkeeping_split"
        status: pass
      - kind: other
        ref: "grep gates: _write_job_health_transition( == 3, raise JobHealthBookkeepingError == 2, class JobHealthBookkeepingError == 1, 'recording callback failure' outside comments == 0"
        status: pass
    human_judgment: false
  - id: D2
    description: "A durably-running job whose outcome was never recorded and whose own start is overdue against its own configured cadence is promoted to the Overview safety surface as job_outcome_unrecorded, and promotes nothing for a recent start, an unknown state, an absent cadence, or a non-integer start; a failed job still promotes only job_failed"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_a_job_stuck_without_an_outcome_becomes_an_operator_exception"
        status: pass
      - kind: other
        ref: "grep gates: job_outcome_unrecorded == 1 in dashboard/beacon/diagnosis.py, compose_active_exceptions( == 2"
        status: pass
    human_judgment: false
  - id: D3
    description: "The new exception kind renders as operator copy naming the job and stating that no outcome has been recorded since its start, never as a bare machine identifier and never as a claim that the job failed"
    requirement: "TEL-06"
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests::test_every_emitted_exception_kind_renders_operator_copy"
        status: pass
      - kind: other
        ref: "grep gates: job_outcome_unrecorded == 1 in dashboard/advanced.js, '10 active exceptions' == 0 and '11 active exceptions' == 1 in tests/test_advanced_ui.py"
        status: pass
    human_judgment: false
  - id: D4
    description: "A bookkeeping failure raised by any of the three startup dispatches no longer propagates out of run_worker: it is logged with its callback and bounded class, startup continues past it, and the scheduler is built and started — while the lease-loss `is False` early return is unchanged"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests::test_startup_survives_a_bookkeeping_failure"
        status: pass
      - kind: integration
        ref: "uv run --project dashboard python -m pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py -q"
        status: pass
      - kind: other
        ref: "grep gate: except JobHealthBookkeepingError == 1 in dashboard/beacon/worker_main.py"
        status: pass
    human_judgment: false
  - id: D5
    description: "tests/test_advanced_diagnosis_api.py leaves the frozen clock, the job-health write function, and the worker scheduler global exactly as it found them, so its results are reproducible alone and in either module order"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py -q (alone)"
        status: pass
      - kind: integration
        ref: "uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py tests/test_runtime_ownership.py -q"
        status: pass
      - kind: integration
        ref: "uv run --project dashboard python -m pytest tests/test_runtime_ownership.py tests/test_advanced_diagnosis_api.py -q"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#ClockIsolationTests::test_a_frozen_clock_never_outlives_the_test_that_froze_it"
        status: pass
    human_judgment: false
  - id: D6
    description: "On the target Pi, the Overview reads correctly to the operator when a job is genuinely wedged without an outcome and when host evidence is stale — the new card names the job and does not read as a claim that the job failed"
    verification: []
    human_judgment: true
    rationale: "Carried forward from 03-VERIFICATION.md's human_verification block. Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically; the synthetic reproductions establish the server contract and the browser regression establishes the copy exists, but whether the wording reads as an observation rather than a verdict to the person using it is human judgment. Collected at the end-of-phase human checkpoint."

# Metrics
duration: 20min
completed: 2026-08-19
status: complete
---

# Phase 03 Plan 15: Make a genuine background-job failure survive a bookkeeping failure Summary

**A failing callback and the failing write that would record it are now two reported conditions instead of one erasing the other — the work's bounded class rides the raised `JobHealthBookkeepingError`, the work error is the explicit `__cause__`, an error-level log states it, a job wedged without an outcome is promoted to the Overview as `job_outcome_unrecorded`, and a transient lock on a startup bookkeeping write no longer kills the worker.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-08-19T08:44:00Z
- **Completed:** 2026-08-19T09:04:01Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- **The suppressed failure regained three channels.** 03-12 correctly stopped a failing `succeeded` write from being recorded as a work failure, but the same edit moved the work's exception into a local variable and chained the bookkeeping condition from the *write* error — so when the work raised and the `failed` write also failed, the genuine failure was gone from every channel at once. It now survives as `JobHealthBookkeepingError.work_error_class` (a bounded class name), as the condition's explicit `__cause__`, and as an error-level log record emitted before the raise. The compound regression the previous round was missing asserts all three on the object graph, not on a message string.
- **The false positive 03-12 closed stayed closed.** The same regression asserts the durable `background_job_health` row for the dispatched job is recorded neither `failed` nor `succeeded`, and its control case proves `work_error_class` is `None` when the work returned normally — so the new field reports a work failure only when there actually was one.
- **A job wedged without an outcome became actionable.** `compose_active_exceptions` gained a keyword-only `now` and a second job branch emitting `job_outcome_unrecorded`, gated on the row's own `running` literal, a strictly-typed `last_started_ts`, a strictly-typed positive `cadence_seconds`, and an age past the module's existing four-times-cadence boundary. Every input comes from that job's own row. A recent start, an unknown state, an absent cadence, and a non-integer start each promote nothing.
- **Startup stopped dying on a transient lock.** The three startup dispatches are now a loop with one narrow handler for `JobHealthBookkeepingError` that logs and continues, so an `OperationalError` on an S1/S2/S3 bookkeeping write no longer terminates the worker before the scheduler is built. The lease-loss `is False` early return is untouched and still aborts startup.
- **The lease-loss log line stopped contradicting itself.** After 03-12's split, `'Beacon worker lease lost while recording callback failure'` was also reached for a `succeeded` transition, so a callback that completed successfully logged a claim its own transition denied. It now names the callback and the actual transition being written.
- **The job-health test module stands on its own cleanup.** `test_outcome_paths_survive_the_bookkeeping_split`'s lease-loss subtest reaches `stop_worker` and therefore the scheduler module global; it now registers its own reset instead of borrowing `tests/test_runtime_ownership.py`'s teardown. `tests/test_runtime_ownership.py` was not modified.

## Task Commits

Each task was committed atomically. All three tasks were TDD, so each contributed a `test` (RED) commit followed by a `feat` (GREEN) commit. No refactor pass was needed.

1. **Task 1: Let a bookkeeping failure and a work failure both be reported** (tracer)
   - `7331849` (test) — the compound regression, failing with `no logs of level ERROR or higher triggered on beacon.worker`
   - `39bd5d6` (feat) — `work_error_class`, the corrected docstring, the error-level log, the single conditional-chain raise, and the rewritten lease-loss log line
2. **Task 2: Promote a job that never received an outcome onto the surface an operator actually looks at**
   - `2e1d2fe` (test) — the six-subtest promotion regression plus the emitted-kind inventory growth
   - `3a3e0b2` (feat) — the keyword-only `now`, the inline promotion branch, `RUNNING_JOB_STATE`, and the `EXCEPTION_COPY` entry
3. **Task 3: Decide what worker startup does with a bookkeeping failure, and stop a test leaning on another module's cleanup**
   - `055fa27` (test) — the `run_worker` startup regression plus the scheduler-global cleanup
   - `d14d9ca` (feat) — the startup dispatch loop with its one narrow handler

**Plan metadata:** see the trailing `docs(03-15)` commit.

### Tracer feedback gate

Task 1 was `type="tracer"`. Its `<verify>` was re-run end-to-end against the committed slice before any expansion task began, and passed (`BOTH_FAILURES_REPORTED`). No expansion work was poured onto an unproven foundation.

## Files Created/Modified

- `dashboard/beacon/worker_main.py` — `JobHealthBookkeepingError` gained keyword-only `work_error_class` (appended to its own message only when present) and a corrected docstring claiming the no-message discipline for the condition's own message while naming chaining as the deliberate maintainer channel; `dispatch_callback`'s outcome-write failure branch now logs the work failure at error level with bounded class names and raises one conditional-chain statement binding the work error as `__cause__`; the outcome-write lease-loss branch names the callback and transition; `run_worker`'s three startup dispatches became a loop with one `except JobHealthBookkeepingError` handler that logs at warning level and continues.
- `dashboard/beacon/diagnosis.py` — added `RUNNING_JOB_STATE` beside the gap-kind constants; `compose_active_exceptions` gained a keyword-only `now` and a second job branch emitting `job_outcome_unrecorded` from explicit keys, gated inline on the row's own state, start timestamp and cadence; `get_current_diagnosis` passes the `now` it already holds.
- `dashboard/advanced.js` — one new `EXCEPTION_COPY` entry for `job_outcome_unrecorded`, immediately beside `job_failed`, titled "Background job outcome not recorded — {job_id}" with evidence directing the operator to Pipeline for the job's last start, last success and configured cadence.
- `tests/test_advanced_diagnosis_api.py` — added `test_a_failed_callback_survives_a_failing_outcome_write` (compound fault injection with a `reachable` chain walk over both `__cause__` and `__context__`), `test_a_job_stuck_without_an_outcome_becomes_an_operator_exception` (six subtests), `test_startup_survives_a_bookkeeping_failure` (drives `run_worker` with a mocked `build_scheduler` and a fake scheduler that captures the worker globals at `start`), the `_jobs_pipeline` and `_reset_worker_globals` helpers, an `import logging`, a scheduler-global cleanup on `test_outcome_paths_survive_the_bookkeeping_split`, and the `now=` argument on the existing composition call site.
- `tests/test_advanced_ui.py` — `EMITTED_EXCEPTIONS` grew by the new kind, its expected heading was added, and the active-exception count assertion moved from ten to eleven. No other assertion in that test was weakened.

## Decisions Made

Recorded in the `key-decisions` frontmatter. The two that mattered most during execution:

- **Chain direction.** Python already binds the write error as implicit `__context__` inside the `except` block, so binding the *work* error as the explicit `__cause__` is precisely what makes both reachable. 03-12 bound the write error to both, which is why only one survived. Expressed as exactly one `raise` statement whose `from` operand is a conditional expression, because the acceptance gate pins the module at exactly two raise sites for this condition and a per-branch pair would have made three.
- **Inline predicate over named helper.** The first implementation extracted a `job_outcome_unrecorded(job, *, now)` helper for readability. That produced three occurrences of the token in `diagnosis.py` (definition, call, kind literal), failing the acceptance gate of exactly one. The gate exists to guarantee a single emission site and no second definition of the kind, so the predicate was inlined in the `elif` with the reasoning kept as a comment. Reverted and reimplemented rather than negotiated with the gate.

## Deviations from Plan

None — plan executed exactly as written.

The two adjustments worth naming are not deviations: the `RUNNING_JOB_STATE` constant and the inlined predicate are both direct consequences of the plan's own acceptance criteria (the repository is authoritative for the state literal; `job_outcome_unrecorded` must occur exactly once in `diagnosis.py`). No auto-fix rule was invoked, no architectural decision was needed, and no out-of-scope issue was touched. `tests/test_runtime_ownership.py` was left unmodified as instructed, and `.planning/REQUIREMENTS.md` was not touched.

## Issues Encountered

- **The chain walk had to traverse both links.** The first draft of the compound regression walked `cursor.__cause__ or cursor.__context__` from the raised condition. That reaches the work error and stops, because a `raise ... from` sets `__cause__` *and* leaves `__context__` set, and the work error itself has neither. The write error would have been unreachable by that walk, so the assertion that both survive would have been vacuous. Replaced with a `reachable` helper doing a seen-guarded traversal over both `__cause__` and `__context__`, plus direct `assertIsInstance` on `condition.__cause__`.
- **The named promotion helper failed a grep gate.** Described under Decisions Made. Caught by running the gate rather than by inspection, which is the argument for the gate.

## Known Stubs

None. No stub patterns, `TODO`/`FIXME` markers, skipped tests, or unrun `<verify>` blocks were introduced. Every `<verify>` block in the plan was executed and passed.

## Threat Flags

None. No new network endpoint, auth path, file access pattern, or schema change at a trust boundary was introduced. `SCHEMA_VERSION` was deliberately not bumped: the promotion derives from `last_started_ts` and `cadence_seconds`, both already present in the jobs payload, so no payload field was added. No package was installed, added, removed, upgraded, or pinned.

## Verification

- `uv run --project dashboard python -m pytest -q` → **291 passed, 406 subtests passed**. The recorded pre-plan baseline was 288 passed / 395 subtests passed; this plan adds three tests and eleven subtests, and nothing previously green went red. The condition was monotonic, as the plan specifies, not an equality.
- `uv run --project dashboard python -m pytest tests/test_runtime_ownership.py tests/test_worker_ownership_matrix.py -q` → 32 passed, 123 subtests passed. The authority fence and both lease-loss shutdown paths survived the edits to `dispatch_callback` and `run_worker`.
- `tests/test_advanced_diagnosis_api.py` passes alone (37 passed, 85 subtests) and in both module orders against `tests/test_runtime_ownership.py` (59 passed, 146 subtests each way).
- `dashboard/beacon/worker_main.py` holds exactly one `started` write and one outcome write (three `_write_job_health_transition(` occurrences: the definition plus two call sites), exactly two `raise JobHealthBookkeepingError`, exactly one `except JobHealthBookkeepingError`, and exactly one `class JobHealthBookkeepingError`. `'recording callback failure'` occurs zero times outside comments.
- `job_outcome_unrecorded` occurs exactly once in `dashboard/beacon/diagnosis.py` and exactly once in `dashboard/advanced.js`. `compose_active_exceptions(` occurs exactly twice in `diagnosis.py`.
- `'10 active exceptions'` occurs zero times and `'11 active exceptions'` exactly once in `tests/test_advanced_ui.py`.
- No durable job-health row, no raised condition's own message, and no new log line carries an exception message, path, or SQL fragment — asserted positively in both new fault-injection regressions (`assertNotIn` on the injected message text against the condition's string form and against every captured log record).
- `.planning/REQUIREMENTS.md` is byte-unchanged by this plan, and TEL-06 remains open in both halves (`| TEL-06 | Phase 3 | Gaps Found |` and `- [ ] **TEL-06**` each occur exactly once). Only independent re-verification may promote it.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All six `missing` bullets of `03-VERIFICATION.md`'s first gap are implemented, and the 03-08 no-suppression prohibition that flipped to VIOLATED this round has its correction in place with the false positive asserted still closed. The gap is ready for independent re-verification.
- **TEL-06 is deliberately NOT promoted.** This plan closes a TEL-06 gap, and the phase's own carried-forward process prohibition forbids recording a requirement complete on the strength of an implementation claim. `requirements-completed` is empty by design and `.planning/REQUIREMENTS.md` is untouched. Only the next independent re-verification round may promote it.
- Plan 03-16 remains outstanding in this phase; it owns the second verification gap (the `absent` versus `complete`-with-zero conflation in per-service gap evidence) and the `deferred-items.md` records for review findings WR-04, the round-1 carried-forward set, and the out-of-scope `advanced.js` findings.
- One human verification item (D6) is outstanding and is collected at the end-of-phase human checkpoint on the target Pi, per `03-VERIFICATION.md`'s own `human_verification` block.
- `CF-WR-10` (the row-spread hazard at the collection-gap branch of `compose_active_exceptions`) remains open in the carried-forward set. The new promotion branch sits beside it and is built from explicit keys, so it is neither an instance of that hazard nor a second site for it.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*

## Self-Check: PASSED

All five modified source files and the SUMMARY itself exist on disk. All seven commits (`7331849`, `39bd5d6`, `2e1d2fe`, `3a3e0b2`, `055fa27`, `d14d9ca`, `e1cae81`) are present in the repository history. No claimed artifact or commit is missing.
