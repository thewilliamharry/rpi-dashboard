---
phase: 03-advanced-current-diagnosis
plan: 18
subsystem: testing
tags: [background-jobs, worker-dispatch, job-health, sqlite, pytest, telemetry-honesty]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-17's durable background-job health outcome path (dispatch_callback's `if result is False:` mapping, the empty-queue `return None` sites, and the round-5 idle-queue regression this plan mirrors)"
  - phase: 03-advanced-current-diagnosis
    provides: "03-02/03-12/03-15's durable job-health persistence under worker authority (_write_job_health_transition, assert_current_worker_authority) and compose_active_exceptions' job_failed promotion"
provides:
  - "worker_process_scan_requests returns its own computed verdict (`status == 'completed'`) instead of an unconditional True"
  - "worker_process_preview_requests returns `not warning` instead of an unconditional True"
  - "_run_scheduled_discovery and _run_startup_discovery return `outcome != 'failed'` on the work path and an explicit None only on a genuine skip"
  - "The decisive regression five verification rounds lacked: the real production adapters driven against work that genuinely fails, for J5, J6, J7 and J9"
affects: [03-19, background-job-health, worker-dispatch, phase-03-verification]

actuals:
  tokens: 57217
  tasks: 2
  commits: 4

tech-stack:
  added: []
  patterns:
    - "A poller returns the verdict it itself computed and durably recorded, never a constant divorced from it"
    - "None at the worker dispatch boundary means exactly one thing: no work was due"
    - "Outcome regressions force the failure at the collaborator boundary and drive the real production callable, never a stand-in for the function under test"

key-files:
  created: []
  modified:
    - dashboard/app.py
    - dashboard/beacon/worker_main.py
    - tests/test_advanced_diagnosis_api.py

key-decisions:
  - "worker_process_scan_requests/worker_process_preview_requests now return their own computed verdict, so dispatch_callback's unchanged `if result is False:` branch records the same failure it already wrote into the queue table"
  - "`outcome != 'failed'` is typed against run_discovery's documented three-literal contract ('busy' | 'completed' | 'failed'), so 'busy' stays a success and only a genuine failure is False"
  - "_run_startup_discovery's recency-window branch gained an explicit `return None`; it previously fell off the end with no return statement at all, which was the same invisible-None defect in a second place"
  - "New assertions use assertIs(result, False) / assertIsNone rather than assertFalse, because assertFalse cannot distinguish False from the None this plan exists to disambiguate"
  - "TEL-06 deliberately left open in both halves of REQUIREMENTS.md; promotion is the next independent verifier's call, not this plan's"

patterns-established:
  - "Return-value vocabulary at the worker dispatch boundary: None = genuine skip, False = genuine failure, True = genuine success — now true of production for J5, J6, J7 and J9"
  - "Anti-scaffolding regression shape: patch the collaborator (run_discovery, _legacy_refresh_service_preview), bind the function under test to the exact callable dashboard/worker.py wires in, and assert both the durable domain row and the operator-facing exception"

requirements-completed: []

coverage:
  - id: D1
    description: "A queued manual scan whose worker_run_discovery genuinely raises is recorded as a durable failed J5 outcome and a job_failed operator exception, in the same dispatch that durably writes status='failed' into scan_requests"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed (subTest job_id='J5')"
        status: pass
    human_judgment: false
  - id: D2
    description: "A queued preview whose capture genuinely warns is recorded as a durable failed J6 outcome and a job_failed operator exception, in the same dispatch that durably writes status='failed' into preview_requests"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed (subTest job_id='J6')"
        status: pass
    human_judgment: false
  - id: D3
    description: "A scheduled (J7) or startup (J9) discovery whose run_discovery genuinely returns 'failed' is recorded as a durable failed outcome and a job_failed operator exception"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_discovery_dispatch_honours_the_return_value_vocabulary (case='a_genuinely_failed_discovery_is_recorded_as_failed', J7 and J9)"
        status: pass
    human_judgment: false
  - id: D4
    description: "The same two callbacks' genuine skip path still records succeeded, with no fabricated failure and no ambiguous None, and without run_discovery ever being called"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_discovery_dispatch_honours_the_return_value_vocabulary (case='a_genuine_skip_still_records_succeeded', J7 and J9)"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_scan_and_preview_pollers_record_an_idle_queue_as_success"
        status: pass
    human_judgment: false
  - id: D5
    description: "The worker authority fence and lease-fenced J5/J6 dispatch paths survive both edits"
    verification:
      - kind: integration
        ref: "uv run --project dashboard python -m pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py -q"
        status: pass
    human_judgment: false
  - id: D6
    description: "Operator-facing background-job health on the /advanced surface now reflects what the job actually did in both directions (the truth that failed five consecutive verification rounds)"
    verification: []
    human_judgment: true
    rationale: "The code-level halves are proven by D1-D4, but 'the operator can trust the pipeline card' is the ROADMAP truth an independent verifier must judge end-to-end, and 03-19 still owns the compound-startup and transient-contention remainders of the same finding."

# Metrics
duration: 24min
completed: 2026-08-19
status: complete
---

# Phase 03 Plan 18: Background-Job Health Honesty (Fabricated-Success Direction) Summary

**Four background jobs (J5, J6, J7, J9) stopped reporting a genuine, durably-recorded work failure to the operator as `succeeded` — each poller now returns the verdict it itself computed, proven by regressions that force the failure at the collaborator boundary and drive the exact adapters `dashboard/worker.py` wires into production.**

## Performance

- **Duration:** ~24 min
- **Tasks:** 2 (4 commits — TDD RED/GREEN per task)
- **Files modified:** 3
- **Test suite:** 296 passed / 413 subtests (baseline) → **298 passed / 419 subtests** (after)

## Accomplishments

- **Closed the fabricated-success half of the round-5 finding for all four jobs.** `worker_process_scan_requests` returned `True` unconditionally after durably writing `status='failed'` into `scan_requests`; `worker_process_preview_requests` did the same after writing `status='failed'` into `preview_requests`. Both now return their own computed verdict, so `dispatch_callback`'s **unchanged** `if result is False:` branch records `failed` for the same dispatch that wrote the failure.
- **Ended the three-way ambiguity of `None` at the dispatch boundary.** `_run_scheduled_discovery` and `_run_startup_discovery` discarded `run_discovery`'s own `'failed'` return and fell off the end as `None` on *both* the skip path and the work path — so the "None means no work was available" vocabulary `03-17-SUMMARY.md` recorded as established was not true of production. `None` now means exactly one thing: a genuine skip.
- **Broke the test-scaffolding trap that let this survive five rounds.** Both new regressions patch the *collaborator* (`run_discovery` genuinely raises `RuntimeError`; `_legacy_refresh_service_preview` genuinely returns a warning) and drive the real `worker_process_scan_requests` / `worker_process_preview_requests` / `_run_scheduled_discovery` / `_run_startup_discovery`. No stand-in for the function under test exists anywhere in the new coverage.
- **Asserted both halves, never just the durable row.** Each regression checks the durable queue-table row (`scan_requests` / `preview_requests`), the durable `background_job_health` row, *and* that `compose_active_exceptions` emits `job_failed` for the affected job — closing the operator-facing half the verifier flagged as unproven.
- **Found and fixed a second, silent instance of the same defect.** `_run_startup_discovery`'s recency-window branch (a recent `last_discovery` inside the 300-second window) had *no return statement at all*, not even a bare `return`. It now returns `None` explicitly.

## Task Commits

Each task was committed atomically, following the TDD gate sequence (RED test → GREEN fix):

1. **Task 1 (tracer, TDD): Return the poller's own computed verdict instead of a constant**
   - RED: `440c0ac` — `test(03-18): pin a genuine J5/J6 failure to durable failed job health`
   - GREEN: `9005c1a` — `fix(03-18): return each poller's own computed verdict, not a constant`
2. **Task 2 (TDD): Make J7/J9 honour the return-value vocabulary this round declared**
   - RED: `b37f6ac` — `test(03-18): pin J7/J9 to the return-value vocabulary in both directions`
   - GREEN: `f0f90d2` — `fix(03-18): stop J7/J9 discarding a genuine discovery failure as None`

No REFACTOR commit was warranted — both fixes are minimal return-site changes with nothing to clean up.

### RED evidence (the defect was live, and the tests caught it)

- Task 1 RED failed with `AssertionError: True is not False` on both J5 and J6, plus `AssertionError: Lists differ: [] != ['J5', 'J6']` for the operator exceptions — i.e. the durable queue rows already read `failed` while the job-health rows read `succeeded`, exactly the untruth described.
- Task 2 RED failed with `AssertionError: None is not False` on both J7 and J9's failure path. The skip subtests passed at RED, confirming the fix does not fabricate a failure on a genuine skip.

## Files Created/Modified

- `dashboard/app.py` — `worker_process_scan_requests`'s final `return True` → `return status == 'completed'`; `worker_process_preview_requests`'s final `return True` → `return not warning`. Each carries the mandated comment beginning "Return the verdict this function itself just computed and durably recorded". The empty-queue `return None` sites and the discovery-busy `return False` are untouched.
- `dashboard/beacon/worker_main.py` — `_run_scheduled_discovery` and `_run_startup_discovery` now assign `outcome = services.run_discovery(...)` and `return outcome != 'failed'` on the work path, with an explicit `return None` on each genuine skip (three total: J7's scanning/queued guard, J9's scanning/queued guard, J9's recency window). `dispatch_callback`, `_invoke_callback`, the 300-second window, and the skip semantics are unchanged.
- `tests/test_advanced_diagnosis_api.py` — two new tests plus one `_latest_queue_row` helper (40 → 42 `def test_`).

## Decisions Made

- **`assertIs(result, False)` / `assertIsNone(result)` instead of the plan's literal `assertFalse` / `assertFalse`.** `assertFalse(None)` passes, so `assertFalse` cannot distinguish `False` from `None` — the exact ambiguity this plan exists to eliminate. `assertIs` is a strict superset of the plan's stated intent ("assert it returns `False`") and is what makes the regression genuinely decisive. Recorded as a deviation below.
- **Also asserted `error_class == 'CallbackReturnedFalse'` on the durable rows.** This pins the failure to the *return-value* path specifically, distinguishing it from a failure recorded via the exception path — cheap, and it prevents a future refactor from satisfying the test through a different mechanism.
- **`outcome != 'failed'` deliberately treats `'busy'` as success.** `run_discovery`'s contract is exactly `'busy' | 'completed' | 'failed'` (`dashboard/app.py:1580`, `dashboard/beacon/monitoring.py:80`). Contention is not a fault; treating it as one would re-create the fabricated-failure defect round 5 closed.
- **`_latest_queue_row` validates its table argument against a two-item allowlist** before interpolating it into SQL, so the helper cannot become an injection shape if a future test passes a computed name.
- **`.planning/REQUIREMENTS.md` left byte-identical.** Verified with `git diff HEAD -- .planning/REQUIREMENTS.md` (empty). TEL-06 remains `Gaps Found` and unchecked in both halves of the record.

## Deviations from Plan

### Auto-fixed / adjusted

**1. [Rule 2 - Missing Critical] Strengthened the new assertions from `assertFalse` to `assertIs(..., False)`**
- **Found during:** Task 1 (authoring the decisive regression)
- **Issue:** The plan's `<action>` specified `assertFalse` for the `dispatch_callback` return. `assertFalse` is satisfied by `None` as well as `False`. Since this plan's entire subject is that `None` and `False` were being conflated at this exact boundary, an `assertFalse`-based regression would have been satisfiable by a "fix" that returned `None` — a weaker version of the same defect, and precisely the class of scaffolding weakness the plan's own `<why_this_plan_exists>` warns against.
- **Fix:** Used `self.assertIs(worker_main.dispatch_callback(services, job_id), False)` for every failure-path assertion, and `assertIsNone` for every skip-path assertion (the latter already matches the plan's text for Task 2).
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Verification:** Both RED runs failed with the discriminating messages `True is not False` and `None is not False`; both GREEN runs pass. The plan's acceptance criterion ("both `dispatch_callback(...)` return `False`") is satisfied strictly.
- **Committed in:** `440c0ac`, `b37f6ac`

**2. [Rule 2 - Missing Critical] Added an SQL-identifier allowlist to the `_latest_queue_row` test helper**
- **Found during:** Task 1
- **Issue:** The helper needs the table name in the query text (SQLite cannot parameterise identifiers). An unguarded f-string is a bad pattern to leave in a test module even where all callers pass literals.
- **Fix:** `if table not in {'scan_requests', 'preview_requests'}: raise ValueError(...)` before the query.
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Verification:** Both subTests pass; the guard is unreachable for the two literal call sites.
- **Committed in:** `440c0ac`

---

**Total deviations:** 2 (both Rule 2 — correctness/security hardening of new test code)
**Impact on plan:** Both strengthen the regression the plan exists to author. Neither changes any production behaviour, file set, or scope. No scope creep.

## Scope Fences Honoured

- `.planning/REQUIREMENTS.md` **unchanged** — verified empty `git diff`. TEL-06 not promoted.
- No Phase-4 range-preference work.
- **03-19's territory untouched**, despite editing adjacent lines in the same functions:
  - The discovery-busy `return False` inside `worker_process_scan_requests` — untouched.
  - `_legacy_do_uptime_check`'s lock-contention `return False` — untouched.
  - Floor-pinning tests and the compound-startup durable-evidence retry — not attempted.
- `dispatch_callback`'s `if result is False: transition='failed' else: 'succeeded'` mapping — read by both tasks, modified by neither.
- `dashboard/advanced.js`, `advanced.html`, `advanced.css` — untouched; all 36 `03-UI-SPEC.md` rows unaffected.

## Verification Evidence

| Gate | Result |
|---|---|
| `pytest -k 'genuine_failure_as_failed or idle_queue_as_success'` | 2 passed, 4 subtests passed |
| `pytest -k discovery_dispatch_honours_the_return_value_vocabulary` | 1 passed, 4 subtests passed |
| `pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py` | 32 passed, 123 subtests passed |
| Full suite (baseline) | 296 passed, 413 subtests passed |
| **Full suite (after both tasks)** | **298 passed, 419 subtests passed** |
| Module order `advanced_diagnosis` → `runtime_ownership` | 64 passed, 159 subtests passed |
| Module order `runtime_ownership` → `advanced_diagnosis` | 64 passed, 159 subtests passed |
| `grep -c "the verdict this function itself just computed" dashboard/app.py` | 2 (was 0) |
| `grep -c "return status == 'completed'" dashboard/app.py` | 1 (was 0) |
| `grep -c 'return not warning' dashboard/app.py` | 1 (was 0) |
| `grep -c '^    return True$' dashboard/app.py` | 5 (was 7) |
| `grep -c "outcome != 'failed'" dashboard/beacon/worker_main.py` | 2 (was 0) |
| `grep -c 'return None' dashboard/beacon/worker_main.py` | 4 (was 1) |
| `grep -c 'def test_' tests/test_advanced_diagnosis_api.py` | 42 (was 40) |
| `.planning/REQUIREMENTS.md` diff | empty |

The measured baseline (296 passed / 413 subtests) matched the orchestrator's stated floor exactly — no discrepancy to report. The suite grew by +2 tests and +6 subtests, all green.

## Threat Model Dispositions

| Threat ID | Disposition | Evidence |
|---|---|---|
| T-03-107 (Repudiation — poller return) | **mitigated** | Task 1's fix + `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed`, asserting queue-table row and job-health row agree. |
| T-03-108 (Repudiation — discovery outcome) | **mitigated** | Task 2's fix + `test_the_real_discovery_dispatch_honours_the_return_value_vocabulary`, both directions, both jobs. |
| T-03-109 (Tampering — authority fence) | **mitigated** | `_write_job_health_transition` and `assert_current_worker_authority` untouched; ownership suites green (32 passed / 123 subtests) after each task. |
| T-03-110 (DoS — over-broadening to transient paths) | **accepted, boundary held** | Neither the discovery-busy `return False` nor `_legacy_do_uptime_check`'s contention `return False` was touched. |
| T-03-111 (Supply chain) | **n/a** | No dependency added, removed, upgraded, or pinned. No package-manager install ran. |

No durable job-health row, log line, or comment introduced by this plan carries an exception message, path, or SQL fragment. (`fail_scan_for_worker`'s `error` column, which carries the truncated work-error string, is a pre-existing queue-table field this plan neither introduced nor changed.)

## Known Stubs

None. No placeholder value, hardcoded empty collection, `TODO`, `FIXME`, or skipped test was introduced. Both new tests run and assert real durable state.

## Issues Encountered

None. Both RED phases failed for exactly the predicted reason, and both GREEN phases passed on the first attempt. No auto-fix attempt limit was approached.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- **Ready for 03-19 (wave 2).** That plan shares `tests/test_advanced_diagnosis_api.py` and `dashboard/beacon/worker_main.py`; both are in a clean, fully green state. It owns the floor-pinning tests, the compound-startup durable-evidence retry, and the two transient-contention sites — none of which this plan touched.
- **Ready for independent re-verification (round 6) after 03-19 executes.** The truth "Background-job health reported to the operator reflects what the job actually did" now has both polarities closed for J5, J6, J7 and J9, with the anti-scaffolding regression the verifier named as missing across five rounds.
- **TEL-06 remains open by design.** Promotion is the next round's verifier's call. This plan closes half of the completeness-prohibition finding (the J5/J6/J7/J9 fabricated-success half); the compound-startup-failure half is 03-19's.
- **One residual concern for the verifier:** `_run_scheduled_discovery`/`_run_startup_discovery` still call `services.run_discovery` without inspecting whether an unrecognised return literal could appear. `outcome != 'failed'` deliberately treats any non-`'failed'` value as success, per the documented three-literal contract. If that contract ever widens, this site widens with it silently.

---
*Phase: 03-advanced-current-diagnosis*
*Plan: 18*
*Completed: 2026-08-19*

## Self-Check: PASSED

All modified files exist on disk and all four task commits (`440c0ac`, `9005c1a`, `b37f6ac`, `f0f90d2`) are present in git history.
