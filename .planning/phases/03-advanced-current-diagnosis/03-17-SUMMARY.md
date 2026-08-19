---
phase: 03-advanced-current-diagnosis
plan: 17
subsystem: api
tags: [sqlite, apscheduler, background-jobs, telemetry, diagnosis, worker-authority]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-02's durable background_job_health outcome path, 03-12's job evidence payload, 03-15's work_error_class field and job_outcome_unrecorded promotion"
provides:
  - "An empty durable scan/preview queue records a succeeded outcome instead of a fabricated job_failed card"
  - "UNRECORDED_OUTCOME_FLOOR_SECONDS + _unrecorded_outcome_boundary: a floor-clamped, cadence-agnostic promotion boundary"
  - "A run_worker startup catch site that re-raises a compound work-plus-write failure instead of downgrading it to an unnamed warning"
  - "Regressions driven through the real production adapters and the real run_worker rather than synthetic stand-ins"
affects: [03-verification-round-5, advanced-workspace-overview-exceptions, background-job-health]

actuals:
  tokens: 6086
  tasks: 3
  commits: 6

tech-stack:
  added: []
  patterns:
    - "None is the established non-failure sentinel for a callback that did no work; False is reserved for a genuine refusal"
    - "A promotion boundary derived from a plausible-duration floor, never from the job's own poll interval"

key-files:
  created: []
  modified:
    - dashboard/app.py
    - dashboard/beacon/diagnosis.py
    - dashboard/beacon/worker_main.py
    - dashboard/advanced.js
    - tests/test_advanced_diagnosis_api.py
    - .planning/phases/03-advanced-current-diagnosis/deferred-items.md

key-decisions:
  - "An empty durable queue is a completed poll, not a failure: the two production pollers return None so dispatch_callback's unchanged `if result is False:` mapping records succeeded"
  - "The job_outcome_unrecorded boundary is max(UNRECORDED_OUTCOME_FLOOR_SECONDS=900, 4 x cadence) — the LARGER of the two, applied uniformly whether or not a cadence is configured"
  - "run_worker re-raises a startup JobHealthBookkeepingError whose work_error_class is not None; a bookkeeping-only failure still warns and continues"
  - "TEL-06 deliberately NOT promoted in REQUIREMENTS.md — a gap-closure round may not record its own requirement complete"

patterns-established:
  - "Return-value vocabulary: None means 'no work was available', False means 'the work refused', an exception means 'the work failed'"
  - "Regressions for a production defect bind the exact callables dashboard/worker.py wires in, never a synthetic stand-in of the test's own making"

requirements-completed: []  # TEL-06 is this plan's requirement but is deliberately left OPEN — see Decisions Made.

coverage:
  - id: D1
    description: "An idle Pi's J5/J6 queue pollers record a durable succeeded outcome and emit no job_failed exception, driven through the real production adapters against a genuinely empty queue"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_scan_and_preview_pollers_record_an_idle_queue_as_success"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_callback_outcome_false_and_exception_never_claim_success (unmodified non-regression control)"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_outcome_paths_survive_the_bookkeeping_split"
        status: pass
    human_judgment: false
  - id: D2
    description: "The job_outcome_unrecorded promotion boundary is a floor no legitimate run can plausibly exceed, applied uniformly to jobs with and without a configured cadence, strict at the boundary and stable in job_id order"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_job_stuck_without_an_outcome_becomes_an_operator_exception (11 subtests)"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_every_emitted_exception_kind_renders_operator_copy"
        status: pass
    human_judgment: false
  - id: D3
    description: "A compound startup work-plus-write failure escapes run_worker and never reaches build_scheduler; a bookkeeping-only failure still logs a warning and continues startup"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_a_compound_startup_failure_reaches_the_operator_instead_of_continuing"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_startup_survives_a_bookkeeping_failure (unmodified control)"
        status: pass
    human_judgment: false
  - id: D4
    description: "On the target Pi, start the worker and leave the system idle for one minute; /advanced Overview shows no 'Background job failed' card for J5 or J6"
    requirement: "TEL-06"
    verification: []
    human_judgment: true
    rationale: "The round-4 verifier's own confirmation gate for this fix. The regression establishes it on a real SQLite database through the real production adapters; only real hardware confirms the rendered operator surface. Carried to the end-of-phase human checkpoint per config human_verify_mode: end-of-phase."
  - id: D5
    description: "On the target Pi, open /advanced while a real collection gap is active and while host evidence is stale; the workspace shows the open gap and the stale host as real, correctly labelled exceptions and shows no resolved or retention-expired interval as an open actionable gap"
    requirement: "TEL-06"
    verification: []
    human_judgment: true
    rationale: "Carried forward unchanged from all four verification reports and every prior gap-closure plan. Operator trust in the rendered snapshot on real hardware cannot be asserted programmatically."

duration: 20min
completed: 2026-08-19
status: complete
---

# Phase 3 Plan 17: Background-Job Health Gap Closure (Round 5) Summary

**An empty durable queue now records a succeeded outcome instead of two fabricated failure cards, the unrecorded-outcome promotion is measured against a 900-second floor rather than a job's own poll interval, and a compound startup work-plus-write failure is re-raised instead of being downgraded to a warning that names nothing.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-08-19T10:52:00Z (approx — baseline suite run)
- **Completed:** 2026-08-19T11:12:00Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- **An idle Pi stops reporting two failed background jobs.** `worker_process_scan_requests` and `worker_process_preview_requests` return `None` instead of `False` when their durable queue is empty. `dispatch_callback`'s `if result is False:` mapping is untouched — it already treats anything other than a literal `False` as succeeded — so J5/J6 now write `state='succeeded'`, a real `last_success_ts`, and `error_class=None`. The regression that proves it binds `self.appmod.worker_process_scan_requests` / `worker_process_preview_requests`, the exact two callables `dashboard/worker.py:34-35` wires into production, against a genuinely empty `scan_requests`/`preview_requests` table.
- **A legitimately-running job is no longer flagged as stuck.** `UNRECORDED_OUTCOME_FLOOR_SECONDS = 900` and `_unrecorded_outcome_boundary(cadence_seconds)` replace the inline `4 * job['cadence_seconds']` comparison. The boundary is `max(floor, 4 x cadence)` — the **larger** of the two — for a strictly-typed positive `int` cadence, and the floor alone for `None`, a non-`int`, zero or a negative. A 2-second-cadence preview nine seconds into its work and a 5-second heartbeat twenty-five seconds behind `connect_db`'s own thirty-second `flock` wait both promote nothing.
- **A wedged startup job is no longer permanently exempt.** The two cadence-type guards that short-circuited the whole branch for a `None` cadence are gone, so S1/S2/S3/J9 are measured against the same floor as every other job and promote once past it, carrying their own `job_id`.
- **A compound startup failure reaches the operator loudly.** `run_worker`'s existing `except JobHealthBookkeepingError` handler gained a leading `if bookkeeping_error.work_error_class is not None: raise`. The startup work failed **and** the write that would have recorded that failure failed, so nothing has confirmed the state Beacon would carry forward — `build_scheduler` is never called, `_worker_started` stays `False`, and S2/S3 never dispatch.
- **Operator copy no longer asserts a multiplier the code does not use.** The `job_outcome_unrecorded` `evidence` sentence in `EXCEPTION_COPY` now reads "for longer than any run of this job should take" in place of the removed "for longer than its own configured cadence allows".

## Task Commits

Each task was committed atomically, RED then GREEN per its `tdd="true"` marking:

1. **Task 1 (tracer): Give an empty durable queue its own outcome, proven through the real production adapters**
   - `6be0bb4` (test) — RED: the new regression reproduced `[job_failed J5, job_failed J6]` against an empty queue
   - `7100600` (feat) — GREEN: both pollers return `None`; deferred-items row 8 recorded
2. **Task 2: Replace the cadence-multiple threshold with a floor no legitimate run or wedged startup job can dodge**
   - `30fd532` (test) — RED: 11 subtests, 4 failing behaviourally after the inert constant was added
   - `d2423ab` (feat) — GREEN: floor constant, boundary function, rewired branch, corrected operator copy
3. **Task 3: Distinguish a compound startup failure from a bookkeeping-only one at the run_worker catch site**
   - `f36c2d8` (test) — RED: `JobHealthBookkeepingError not raised`, with the captured warning naming only `error_class=OperationalError`
   - `25a176a` (feat) — GREEN: the `work_error_class is not None` re-raise branch

**Plan metadata:** see the final `docs(03-17)` commit.

## Files Created/Modified

- `dashboard/app.py` — `worker_process_scan_requests`'s empty-claim check and `worker_process_preview_requests`'s sole claim check return `None`, each with the mandated comment. The discovery-busy `return False` is untouched; `if not claim:` still occurs 4 times.
- `dashboard/beacon/diagnosis.py` — new `UNRECORDED_OUTCOME_FLOOR_SECONDS` (900) and `_unrecorded_outcome_boundary`; `compose_active_exceptions`'s `job_outcome_unrecorded` branch rewired onto it with the two cadence-type guards removed and the comparison kept strict.
- `dashboard/beacon/worker_main.py` — one conditional `raise` added inside the existing startup `except JobHealthBookkeepingError` handler. `dispatch_callback` is unchanged.
- `dashboard/advanced.js` — one `evidence` string rewritten in the `job_outcome_unrecorded` entry of `EXCEPTION_COPY`. The `title` and the neighbouring `job_failed` entry are unchanged.
- `tests/test_advanced_diagnosis_api.py` — two new tests (38 → 40) and `test_a_job_stuck_without_an_outcome_becomes_an_operator_exception` rewritten in place from 6 to 11 subtests.
- `.planning/phases/03-advanced-current-diagnosis/deferred-items.md` — new row 8; rows 1-7 unchanged.

## Verification Evidence

| Gate | Result |
|---|---|
| Task 1 automated gate | `IDLE_QUEUE_IS_NOT_A_FAILURE` — 3 passed / 6 subtests; grep counts 2 / 4 / 39 all exact; ownership suites 32 passed / 123 subtests |
| Task 2 automated gate | `BOUNDARY_IS_A_FLOOR` — 1 passed / 11 subtests; grep counts 3 / 2 / 0 / 1 / 0 all exact; `every_emitted_exception_kind` 1 passed / 44 subtests |
| Task 3 automated gate | `COMPOUND_FAILURE_IS_LOUD_RECORD_UNTOUCHED` — 2 passed; grep counts 1 / 1 / 40 all exact; both cross-module orders 62 passed / 153 subtests each |
| Full suite | **296 passed / 413 subtests passed** — strictly above the 294/406 baseline measured in this session immediately before execution. Nothing previously green went red. |
| `.planning/REQUIREMENTS.md` | Unchanged — `git status --short` reports nothing for the file; both grep pins (`| TEL-06 | Phase 3 | Gaps Found |` and `- [ ] **TEL-06**`) still return 1. |

**Baseline check:** the pre-execution run of `uv run --project dashboard python -m pytest -q` reported exactly **294 passed / 406 subtests passed**, matching the figure recorded in the plan. No discrepancy to report.

**Non-regression controls kept and re-run unmodified**, per the round-4 verifier's indictment of the prior round's scaffolding: `test_callback_outcome_false_and_exception_never_claim_success` (the synthetic `False -> failed` control — kept, not weakened, not deleted), `test_outcome_paths_survive_the_bookkeeping_split`, and `test_startup_survives_a_bookkeeping_failure`.

## Decisions Made

- **`None`, not a new sentinel type, for "no work available."** `dispatch_callback` already returns `None` in another legitimate context (closed admission, `tests/test_runtime_ownership.py`), so `None` is an established non-failure sentinel in this codebase rather than a convention invented here. No new branch, no new import, and no special case for J5/J6's handler name was needed.
- **`max`, never `min`, at the boundary composition.** A `min` would silently lower every long-cadence job's threshold and ship a new regression of exactly the species round 4 caught. The test states the rule (`max(floor, 4 * cadence)`) independently of the code that computes it, rather than calling `_unrecorded_outcome_boundary` to derive its own expectation.
- **TEL-06 was deliberately NOT promoted.** `.planning/REQUIREMENTS.md` is byte-identical to its pre-execution state, and `requirements-completed` in this summary is empty. `requirements.mark-complete` was intentionally skipped despite the plan's `requirements: [TEL-06]` frontmatter: the 03-10 prohibition holds that a gap-closure round may not record its own requirement complete on the strength of an implementation claim. Only the round-5 verifier may promote it.
- **The tracer feedback gate was satisfied by re-running the tracer's `<verify>` end-to-end rather than by an interactive checkpoint.** The project config sets `workflow.human_verify_mode: end-of-phase`, and the plan itself files both human checks in Task 3's `<human-check>` block, explicitly "collected at the end-of-phase human checkpoint, not automated here." Both are carried into this summary's `coverage:` block as `human_judgment: true` (D4, D5) so neither is lost.

## Deviations from Plan

None — plan executed exactly as written. All three tasks, every mandated comment string, every grep-count acceptance gate, and every named test met the plan's specification without an auto-fix under Rules 1-3 and without an architectural question under Rule 4.

**Total deviations:** 0
**Impact on plan:** None.

## Scope Fences Respected

- `.planning/REQUIREMENTS.md` unchanged; TEL-06 left open in both halves of the record.
- No Phase-4 range-preference control was implemented.
- The two related `return False` sites (`worker_process_scan_requests`'s discovery-busy requeue branch and `_legacy_do_uptime_check` under `_uptime_lock` contention) were recorded as `deferred-items.md` row 8 and left unchanged.
- No new file, route, endpoint, migration, column, table, index, or package. `SCHEMA_VERSION` untouched. No server payload field added.

## Issues Encountered

- **Task 2's first RED was an `AttributeError`, not a behavioural failure.** The rewritten test reads `diagnosis.UNRECORDED_OUTCOME_FLOOR_SECONDS`, which did not yet exist. To get a meaningful RED, the constant and `_unrecorded_outcome_boundary` were added as an inert first step (nothing called the function yet) and the test re-run: 4 subtests then failed behaviourally — `short_cadence_job_nine_seconds_in`, `heartbeat_blocked_behind_the_maintenance_lock`, `absent_cadence_past_the_floor`, and `two_overdue_jobs_promote_in_stable_job_id_order` — reproducing all three defects before the branch was rewired. Both steps landed in the single `d2423ab` GREEN commit.
- **A `sed` while recording decisions relabelled 109 historical `- [Phase ?]:` entries in `STATE.md` to `[Phase 03]`.** Caught immediately by inspecting the diff and fully reverted against `git show HEAD:.planning/STATE.md`; only the 4 decisions this plan added carry the `[Phase 03]` label, and the pre-existing 3 `[Phase 03]` entries and 109 `[Phase ?]` entries are byte-identical to their prior state.

## Known Stubs

None. No hardcoded empty value, placeholder string, TODO, FIXME, or unwired data source was introduced by this plan.

## Threat Flags

None. No file modified by this plan introduces a network endpoint, an auth path, a file-access pattern, or a schema change at a trust boundary. The `_write_job_health_transition` authority fence and the admission/lease fencing are untouched, re-asserted green by `tests/test_runtime_ownership.py` and `tests/test_worker_ownership_matrix.py` after every task.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All seven `missing` bullets of `03-VERIFICATION.md`'s round-4 gap are implemented and covered by regressions that drive real production callables.
- Ready for round-5 independent re-verification. The verifier owns the TEL-06 promotion decision; this plan deliberately left the record open.
- Two human checks (D4, D5 in `coverage:`) remain outstanding for the end-of-phase human checkpoint on real Pi hardware — specifically the idle-Pi Overview check that is the round-4 verifier's own confirmation gate for Task 1.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*
