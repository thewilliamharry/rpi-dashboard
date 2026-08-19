---
phase: 03-advanced-current-diagnosis
plan: 22
subsystem: telemetry
tags: [sqlite, apscheduler, worker-dispatch, job-health, error-classification]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-19/03-20/03-21's job-health return-value discipline and fail-closed discovery vocabulary at J7/J9 (dashboard/beacon/worker_main.py::_discovery_outcome_verdict), which this round extends and completes"
provides:
  - "PreviewCaptureUnavailable -- a distinct exception class raised when the shared preview capture machinery totally fails, kept apart from every per-service preview condition"
  - "Both worker_process_scan_requests and process_scan_requests routed through _discovery_outcome_verdict's membership check before their busy-branch handling"
  - "DISCOVERY_JOB_IDS-scoped, type-guarded job_outcome_unrecorded promotion floor in dashboard/beacon/diagnosis.py"
affects: [03-VERIFICATION.md round 8 re-verification, TEL-06 promotion decision]

# Actuals (#2632)
actuals:
  tokens: 6109
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Fault-class distinction made upstream of blanket except Exception handlers (at the collaborator call site), never re-decided at the return statement"
    - "A sentinel string threaded through an existing return slot survives a blanket exception handler unmodified, avoiding a new raise path through code that cannot distinguish it"
    - "A job-scoped promotion floor gated by frozenset membership, guarding operator-configurable input by type instead of coercing it"

key-files:
  created: []
  modified:
    - dashboard/beacon/previews.py
    - dashboard/app.py
    - dashboard/beacon/diagnosis.py
    - tests/test_advanced_diagnosis_api.py

key-decisions:
  - "The fault-class split for J6 was made at _get_browser() and context.new_page() inside _legacy_screenshot_service -- upstream of both app.py:930 and app.py:982's blanket except Exception handlers -- per the round-7 verifier's own root-cause finding that a return-site-only fix produces an eighth instance of the same defect."
  - "browser.new_context() (dashboard/beacon/previews.py:108, inside browser_proxy_context's generator before yield) remains a known, disclosed residual: it is genuinely unreachable from the with body an inner try/except could wrap, so a failure there still falls through to the per-service classification -- deliberately not closed by this plan."
  - "The job_outcome_unrecorded floor now widens only for job_id in DISCOVERY_JOB_IDS ({'J5','J7','J9'}); every other job's floor stays the constant UNRECORDED_OUTCOME_FLOOR_SECONDS regardless of the operator's configured DISCOVERY_TIMEOUT_SECONDS."
  - "discovery_timeout_seconds is now guarded (type(...) is int and ... > 0) rather than coerced (int(...)), so a malformed value degrades one promotion instead of raising TypeError out of get_current_diagnosis."
  - "TEL-06 stays at Gaps Found in both halves of REQUIREMENTS.md; this plan closes both round-7 gaps in code but does not promote its own requirement -- only independent re-verification may."

patterns-established:
  - "Sentinel-through-existing-return-slot: when two fault classes are merged by a blanket handler, thread a new sentinel through the collaborator's own existing return contract rather than adding a new raise path the blanket handler would re-absorb."

requirements-completed: []  # TEL-06 deliberately NOT promoted -- see key-decisions and gap_coverage in 03-22-PLAN.md; independent re-verification owns promotion.

coverage:
  - id: D1
    description: "A total preview-capture-machinery failure (browser cannot launch, or launches but cannot open a page) durably records J6 as failed with error_class='PreviewCaptureUnavailable', while every per-service preview condition still records J6 succeeded"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests::test_a_broken_capture_machinery_fails_j6s_job_health_while_a_per_service_fault_does_not"
        status: pass
    human_judgment: false
  - id: D2
    description: "worker_process_scan_requests and the legacy process_scan_requests both fail closed on a run_discovery outcome literal outside the documented 'completed'|'busy'|'failed' contract"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests::test_the_real_manual_scan_poller_fails_closed_on_an_unrecognised_discovery_outcome"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests::test_the_legacy_manual_scan_poller_also_fails_closed_on_an_unrecognised_discovery_outcome"
        status: pass
    human_judgment: false
  - id: D3
    description: "The job_outcome_unrecorded promotion floor widens only for DISCOVERY_JOB_IDS and degrades safely (never raises) on a malformed discovery_timeout_seconds"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests::test_a_job_stuck_without_an_outcome_becomes_an_operator_exception (subTest case='the_widened_floor_never_reaches_a_job_that_does_not_run_discovery')"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests::test_a_job_stuck_without_an_outcome_becomes_an_operator_exception (subTest case='a_malformed_discovery_timeout_degrades_one_promotion_instead_of_aborting_the_payload')"
        status: pass
    human_judgment: false
  - id: D4
    description: "Three real-hardware human-verification checks (idle-Pi safety-surface, active-gap/stale-host correctness, and Chromium-unavailable J6 signal) carried forward for the end-of-phase checkpoint"
    verification: []
    human_judgment: true
    rationale: "Requires the target Raspberry Pi hardware and a deliberately broken Chromium install; not automatable in this executor session. Carried forward unchanged from every prior gap-closure round's own human-check block since round 3/4."

# Metrics
duration: 20min
completed: 2026-08-19
status: complete
---

# Phase 03 Plan 22: Round-8 Gap Closure (J6 Machinery Fault, J5 Vocabulary, Floor Scoping) Summary

**Split J6's browser-launch/new-page failure from per-service preview faults at the collaborator boundary (upstream of both blanket exception handlers), routed J5 through the same discovery-outcome membership check J7/J9 already use, and scoped/guarded the job_outcome_unrecorded promotion floor to DISCOVERY_JOB_IDS only.**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-08-19T20:20:00+03:00 (approx, first file read)
- **Completed:** 2026-08-19T20:50:11+03:00
- **Tasks:** 3
- **Files modified:** 4 (dashboard/beacon/previews.py, dashboard/app.py, dashboard/beacon/diagnosis.py, tests/test_advanced_diagnosis_api.py)

## Accomplishments

- J6 (`process_preview_requests`) now durably records a genuine `failed`/`PreviewCaptureUnavailable` job-health row when the shared Chromium capture machinery totally fails (cannot launch, or launches but can no longer open a page), while every per-service preview condition (offline service, missing title, failed capture of a page that did load) still records J6 `succeeded` exactly as the user's round-6 decision established — both directions pinned in one regression driven through the real `dispatch_callback`.
- `worker_process_scan_requests` and its legacy sibling `process_scan_requests` both now call `beacon_worker_main._discovery_outcome_verdict(outcome)` immediately after `run_discovery`/`worker_run_discovery` returns, so an outcome literal outside the documented `'completed'|'busy'|'failed'` contract fails closed and loud at both the J5 job-health row and the `scan_requests` queue row, matching J7/J9's existing behaviour.
- `_unrecorded_outcome_boundary` in `dashboard/beacon/diagnosis.py` now widens its floor only for `job_id in DISCOVERY_JOB_IDS` (`{'J5','J7','J9'}`), and guards `discovery_timeout_seconds` by type instead of coercing it with `int(...)`, so a non-discovery job (J1's 5-second heartbeat, etc.) is never silently exempted by an unrelated operator setting, and a malformed setting degrades one promotion instead of aborting the whole `/advanced` payload.
- Five new regressions added to `tests/test_advanced_diagnosis_api.py` (one test with two subTests for gap 1's primary count, two new tests for gap 1's secondary count, two new subTests inside the existing floor test for gap 2), all proven to fail against the pre-fix tree for the right reason before the corresponding fix landed.

## Task Commits

Each task was committed atomically:

1. **Task 1: Give J6 a job-owned failure signal for a total capture-machinery failure** - `b73ec1e` (feat)
2. **Task 2: Route J5's discovery outcome through the same membership check J7/J9 already use** - `c2aa34c` (feat)
3. **Task 3: Scope the job_outcome_unrecorded floor to the jobs that run discovery, and guard its input** - `e574f72` (fix)

_All three tasks carried `tdd="true"`; each single commit bundles the RED-proof-driven test with its GREEN implementation rather than splitting into separate `test(...)`/`feat(...)` commits, matching this repo's established single-commit-per-task convention for TDD tasks in this phase (see prior 03-* plans' own SUMMARY commit histories)._

## Files Created/Modified

- `dashboard/beacon/previews.py` - Added `PreviewCaptureUnavailable(RuntimeError)`, a distinct exception for total capture-machinery failure, placed after the module docstring/imports and before `ThumbnailResultRepository`.
- `dashboard/app.py` - Added `THUMB_ERROR_BROWSER_UNAVAILABLE` sentinel constant; wrapped `_get_browser()` and `context.new_page()` in `_legacy_screenshot_service` with narrow `try/except` returning the sentinel before any per-service navigation; `worker_process_preview_requests` raises `PreviewCaptureUnavailable` after its transaction commits when the sentinel is present, and its trailing comment was rewritten to state what the code actually guarantees; added `beacon_worker_main` import; `worker_process_scan_requests` and `process_scan_requests` both call `beacon_worker_main._discovery_outcome_verdict(outcome)` before their busy-branch handling.
- `dashboard/beacon/diagnosis.py` - Added `DISCOVERY_JOB_IDS = frozenset({'J5','J7','J9'})`; `_unrecorded_outcome_boundary` gained a `job_id` parameter and now widens the floor only for a job in that set, with `discovery_timeout_seconds` guarded by type instead of coerced; its one call site in `compose_active_exceptions` now passes `job['job_id']`; module comments updated to state the scoped guarantee.
- `tests/test_advanced_diagnosis_api.py` - Added `previews` to the top-level import; added `test_a_broken_capture_machinery_fails_j6s_job_health_while_a_per_service_fault_does_not` (2 subTests), `test_the_real_manual_scan_poller_fails_closed_on_an_unrecognised_discovery_outcome`, `test_the_legacy_manual_scan_poller_also_fails_closed_on_an_unrecognised_discovery_outcome`, and two new subTests inside `test_a_job_stuck_without_an_outcome_becomes_an_operator_exception`.

## Decisions Made

- The fault-class distinction for J6 is made at `_get_browser()` and `context.new_page()` — the exact two call sites named in the plan's `read_first` and `03-VERIFICATION.md` round 7's root-cause finding — never re-decided at either of the two blanket `except Exception` handlers in `dashboard/app.py`, since narrowing the handler at `app.py:982` alone was proven this round NOT to close the gap (the handler at `app.py:930` keeps it fully live).
- `browser.new_context()` (inside `beacon_previews.browser_proxy_context`'s generator, before `yield context`) is confirmed genuinely unreachable from the `with` body an inner `try/except` could wrap, and is left as a known, disclosed residual per the plan's explicit instruction — not silently expanded to claim coverage the code does not have.
- TEL-06 was deliberately left at `Gaps Found` in both halves of `REQUIREMENTS.md`; this plan closes both round-7 gaps in code, but per the standing project rule (a gap-closure round may not record its own requirement complete), promotion is reserved for the next independent verification round.

## Deviations from Plan

None — plan executed exactly as written. All file line numbers, function signatures, and call sites named in the plan's `read_first` blocks matched the live source exactly at execution time (verified against `dashboard/app.py`, `dashboard/beacon/previews.py`, `dashboard/beacon/diagnosis.py`, and `dashboard/beacon/worker_main.py` before each task's implementation).

## RED-Proof Evidence (captured against the pre-fix tree, per plan mandate)

**Task 1** — `test_a_broken_capture_machinery_fails_j6s_job_health_while_a_per_service_fault_does_not`, run with `dashboard/app.py`/`dashboard/beacon/previews.py` reverted to their pre-Task-1 state:

```
>               with self.assertRaises(previews.PreviewCaptureUnavailable):
                                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E               AttributeError: module 'dashboard.beacon.previews' has no attribute 'PreviewCaptureUnavailable'

tests/test_advanced_diagnosis_api.py:508: AttributeError
```

This is exactly the second of the two failure shapes the plan's acceptance criteria named as valid ("... or a `previews.PreviewCaptureUnavailable` `AttributeError` if the class does not yet exist"). (The second subTest, `an_ordinary_probe_fault_still_records_j6_succeeded`, also failed on this run — `'queued' != 'failed'` — as a downstream side effect of subTest 1's `dispatch_callback` call never executing because the `AttributeError` fired before entering the `assertRaises` context, leaving subTest 1's own claimed request unconsumed for subTest 2's `_latest_queue_row` read to pick up instead. This is expected collateral of running a two-subTest regression against a tree where the first subTest's precondition class doesn't exist yet, not a fixture defect: after the real fix landed, both subTests passed independently.)

**Task 2, test 1** — `test_the_real_manual_scan_poller_fails_closed_on_an_unrecognised_discovery_outcome`, run with only Task 2's `dashboard/app.py` changes reverted (Task 1's fix still in place):

```
        with mock.patch.object(
            self.appmod, 'worker_run_discovery',
            return_value='an_unrecognised_discovery_outcome',
        ):
>           self.assertIs(worker_main.dispatch_callback(services, 'J5'), False)
E           AssertionError: True is not False
```

**Task 2, test 2** — `test_the_legacy_manual_scan_poller_also_fails_closed_on_an_unrecognised_discovery_outcome`, same pre-fix state:

```
>       self.assertEqual(row['status'], 'failed')
E       AssertionError: 'completed' != 'failed'
E       - completed
E       + failed
```

**Task 3, subTest 1** — `case='the_widened_floor_never_reaches_a_job_that_does_not_run_discovery'`, run with only Task 3's `dashboard/beacon/diagnosis.py` changes reverted:

```
E           AssertionError: Lists differ: [] != ['J1']
E
E           Second list contains 1 additional elements.
E           First extra element 0:
E           'J1'
```

**Task 3, subTest 2** — `case='a_malformed_discovery_timeout_degrades_one_promotion_instead_of_aborting_the_payload'`, same pre-fix state:

```
>       floor = max(UNRECORDED_OUTCOME_FLOOR_SECONDS, int(discovery_timeout_seconds) + 60)
                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'
```

Every RED-proof failure above matches one of the exact failure shapes the plan's acceptance criteria predicted, confirming each test failed for the intended reason (not a fixture mistake) before its corresponding fix landed.

## Issues Encountered

- The full-suite run (`uv run --project dashboard python -m pytest -q`) intermittently produced two `SUBFAILED` entries in `tests/test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced` (`row_id='S2'`, `row_id='J1'`) on one run, with the message `f'{row_id}: A never reached heartbeat persistence'` — a thread-synchronization timeout (`paused.wait(timeout=2)`) inside a pre-existing threading-based fencing test, unrelated to any file this plan touches. Re-running the same file in isolation passed cleanly (`10 passed, 62 subtests passed`), and re-running the full suite immediately afterward also passed cleanly (`306 passed, 430 subtests passed`), confirming this is a pre-existing timing flake under full-suite thread-scheduling load, not a regression introduced by this plan's changes. Left unfixed per the deviation-rule scope boundary (out-of-scope pre-existing flake, no file this plan touches is implicated); not added to `deferred-items.md` since it self-resolved on retry and the class of flakiness (a 2-second thread-handoff wait under full-suite CPU contention) is a known pattern the project's own test discipline already tolerates elsewhere in this suite.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All three human-verification items from Task 3's `<human-check>` verify block (the recurring active-gap/stale-host correctness check, the recurring idle-Pi safety-surface check, and the new Chromium-unavailable J6-signal check) remain carried forward for the end-of-phase human checkpoint on real Raspberry Pi hardware — not automated in this session, per the plan's own instruction.
- TEL-06 remains `Gaps Found` in `.planning/REQUIREMENTS.md`; both round-7 gaps are now closed in code and pinned by regression, but promotion requires the next independent `/gsd-verify` pass over `03-VERIFICATION.md` round 8.
- `.planning/REQUIREMENTS.md` was not edited by this plan (confirmed by the `TEL-06 | Phase 3 | Gaps Found` and `- [ ] **TEL-06**` gate checks in Task 3's verify block, both passing).

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-19*

## Self-Check: PASSED

All four modified files (`dashboard/beacon/previews.py`, `dashboard/app.py`, `dashboard/beacon/diagnosis.py`, `tests/test_advanced_diagnosis_api.py`) confirmed present on disk. All three task commits (`b73ec1e`, `c2aa34c`, `e574f72`) confirmed present in `git log`.
