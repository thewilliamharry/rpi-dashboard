---
phase: 03-advanced-current-diagnosis
plan: 21
subsystem: background-jobs
tags: [background-jobs, worker-dispatch, discovery, job-health, promotion-floor, pytest, telemetry-honesty]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-18's return-value vocabulary at the worker dispatch boundary (None = genuine skip, False = genuine failure), whose discovery half this plan completes with a fail-closed membership check"
  - phase: 03-advanced-current-diagnosis
    provides: "wave-1 sibling 03-20's J6 semantics -- a job's outcome answers only 'did the poller do its job' -- which this plan's discovery-outcome vocabulary preserves unchanged"
  - phase: 03-advanced-current-diagnosis
    provides: "03-14/03-16's UNRECORDED_OUTCOME_FLOOR_SECONDS promotion floor and its subtest battery, whose arithmetic this plan makes derive from the configured discovery timeout"
provides:
  - "_discovery_outcome_verdict: run_discovery's documented 'completed' | 'busy' | 'failed' contract checked by membership, so an unrecognised literal fails closed and loud instead of succeeding by exclusion"
  - "'busy' pinned as a genuine success at both discovery dispatchers for J7 and J9 -- the one contract literal round 6 found undefended by any test"
  - "An honest uptime-lock-contention comment naming the J3/J4 asymmetry, plus a regression proving the losing full sweep's last_uptime_check is never advanced"
  - "A job_outcome_unrecorded floor that derives from the operator's own configured DISCOVERY_TIMEOUT_SECONDS rather than the hardcoded 900-second constant alone"
affects: [background-job-health, worker-dispatch, discovery, phase-03-verification]

actuals:
  tokens: 3849
  tasks: 3
  commits: 5

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "A documented value contract is enforced by membership, never by exclusion: the default direction for an unrecognised value is a loud failure"
    - "A comment that justifies a non-fault outcome must not overclaim equivalence between two different runs; the narrower true claim is stated and the gap it leaves is pinned by a regression"
    - "A guarantee stated against a configurable setting derives its arithmetic from that setting, never from the setting's default"

key-files:
  created: []
  modified:
    - dashboard/beacon/worker_main.py
    - dashboard/app.py
    - dashboard/beacon/diagnosis.py
    - tests/test_advanced_diagnosis_api.py

key-decisions:
  - "An outcome literal outside run_discovery's documented contract raises ValueError, which dispatch_callback durably records as failed with error_class='ValueError' and surfaces as exactly one job_failed exception -- more visible to the operator, never less"
  - "'busy' remains a genuine success (another discovery already owns the work), consistent with 03-20's J6 semantics: the job answers only whether it did its own job"
  - "The uptime-lock contention branch's return value, lock semantics, and control flow are byte-identical; only the comment's claim and one test assertion changed"
  - "The widened floor is max(900, configured_timeout + 60) -- it grows only with the operator's own budget, so a genuinely wedged job is still promoted (proven by the unmodified overdue/absent-cadence subtests)"
  - "TEL-06 deliberately left open in both halves of REQUIREMENTS.md; promotion is the next independent verifier's call, not this plan's"

patterns-established:
  - "Fail-closed vocabulary enforcement: a collaborator's documented return contract is checked against a positive membership set at the boundary that consumes it, so an undocumented value cannot ride the success path by default"
  - "Honest-comment discipline: when a comment justifies a non-fault, it states the narrowest claim that is actually true and a regression pins the residual gap, so the trade-off is visible to the next reader instead of asserted in prose"
  - "Configurable-invariant derivation: a threshold whose stated guarantee references an operator-configurable setting takes that setting as an argument and computes the guarantee, rather than assuming the default holds"

requirements-completed: [TEL-06]

coverage:
  - id: D1
    description: "_discovery_outcome_verdict maps 'completed'/'busy' to True and 'failed' to False by membership, and raises ValueError naming any literal outside the contract (WR-01)"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_discovery_dispatch_honours_the_return_value_vocabulary"
        status: pass
    human_judgment: false
  - id: D2
    description: "For J7 and J9, an unrecognised discovery outcome raises through dispatch_callback, records a durable state='failed' / error_class='ValueError' row, and emits exactly one job_failed exception; 'busy' records succeeded with no exception"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_discovery_dispatch_honours_the_return_value_vocabulary"
        status: pass
    human_judgment: false
  - id: D3
    description: "A J3 full sweep that yields to a concurrent probe holding _uptime_lock never advances scan_state['last_uptime_check'], so the skipped cycle's coverage gap stays visible on the telemetry-coverage surface (WR-02)"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_an_uptime_lock_collision_is_not_reported_as_a_failure"
        status: pass
    human_judgment: false
  - id: D4
    description: "The job_outcome_unrecorded floor widens to max(900, configured DISCOVERY_TIMEOUT_SECONDS + 60), so a legitimately-running J7/J9 discovery on a deployment configured above 840 is not promoted as a fabricated card (WR-03)"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_job_stuck_without_an_outcome_becomes_an_operator_exception"
        status: pass
    human_judgment: false
  - id: D5
    description: "The three carried-forward operator-facing checks on real Pi hardware (real collection gap + stale host evidence; one idle minute with no fabricated J5/J6 card; a titleless/offline service producing no J6 job_failed card)"
    requirement: "TEL-06"
    verification: []
    human_judgment: true
    rationale: "Each asserts what a human sees on /advanced on real hardware under real timing. Carried into the end-of-phase human checkpoint per config human_verify_mode=end-of-phase; still NOT performed on real hardware through seven rounds."

# Metrics
duration: 7min
completed: 2026-08-19
status: complete
---

# Phase 03 Plan 21: Close Round-6 Warnings WR-01, WR-02 and WR-03 Summary

**An unrecognised discovery outcome now fails closed and loud instead of succeeding by exclusion, the uptime-lock-contention comment stops claiming a down-only probe's work equals a full sweep's, and the `job_outcome_unrecorded` floor derives from the operator's own configured `DISCOVERY_TIMEOUT_SECONDS` rather than the hardcoded 900.**

## Performance

- **Duration:** 7 min
- **Tasks completed:** 3 of 3
- **Commits:** 5 (2 RED, 2 GREEN for the two TDD tasks; 1 for the non-TDD comment task)
- **Files modified:** 4

## Accomplishments

- **WR-01 closed — the discovery vocabulary fails closed.** `dashboard/beacon/worker_main.py` gains `_discovery_outcome_verdict(outcome)` immediately above `_run_scheduled_discovery`. It returns `True` for `'completed'` and `'busy'`, `False` for `'failed'`, and raises `ValueError(f'run_discovery returned an unknown outcome: {outcome!r}')` for anything else. Both dispatchers call it in place of deciding success by exclusion; neither function's `read_scan_state()` call, skip-path `return None`, nor the 300-second recency window was touched. `dispatch_callback` already catches a work exception, writes `('failed', 'ValueError')` durably, and re-raises it — so the new default direction reaches the operator as a genuine `job_failed`, not as silence.
- **`'busy'` is finally defended.** Round 6 found `'busy'` mapping to `succeeded` at both dispatchers with no test anywhere pinning it. It is now pinned for J7 *and* J9 with `assertIs(..., True)`, a durable `state='succeeded'` row, and an empty `job_failed` list. This stays consistent with wave-1 sibling `03-20`'s J6 semantics: the job's outcome answers only whether the poller did its own job, and another discovery already owning the work means this poll did the whole of its.
- **WR-02 closed — the contention comment states the narrower true claim.** `_legacy_do_uptime_check`'s lock-contention comment now says yielding is not a job failure *and* explicitly that this is NOT the same claim as the two runs being equivalent: it names J3 (`only_down=False`, every 5 min) and J4 (`only_down=True`, every 1 min), states they "collide by construction every fifth J4 tick, because 300 is a multiple of 60", and states that a down-only holder never advances `last_uptime_check`, so the loser's cycle is *skipped, not covered*. The `return None`, the `_uptime_lock.acquire(blocking=False)` call, and every other line of the function are byte-identical.
- **The residual coverage gap is pinned, not asserted in prose.** `test_an_uptime_lock_collision_is_not_reported_as_a_failure` now reads `self.appmod._read_scan_state()` after the losing J3 dispatch and asserts `last_uptime_check` is `None`. A future change that silently advanced the loser's coverage clock — claiming as covered a sweep that never ran — fails here.
- **WR-03 closed — the floor derives its own guarantee.** `_unrecorded_outcome_boundary` now takes `discovery_timeout_seconds` and computes `floor = max(UNRECORDED_OUTCOME_FLOOR_SECONDS, int(discovery_timeout_seconds) + 60)` as its first statement; both the `4 * cadence_seconds` comparison and the absent-cadence fallback use that widened value. `compose_active_exceptions` requires it keyword-only and threads it to its one call site; `get_current_diagnosis` supplies `settings.discovery_timeout_seconds`. The module comment above the constant now records that the 180-second figure is a *default*, not the only value in force.
- **The reviewer's own reproduction is now a regression.** The new subTest measures one identically-aged J9 row (1200 seconds old, no cadence) against two configured values: at `discovery_timeout_seconds=1200` the widened floor (1260) covers it and nothing is promoted; at `180` the floor stays 900 and the same row promotes exactly `['J9']`. The floor is therefore proven to derive from the input rather than from the constant alone — a test that could not fail for any value of the constant is exactly how a regressed floor ships green.

## Task Commits

| Task | Gate | Commit | Message |
|------|------|--------|---------|
| 1 | RED | `2728889` | test(03-21): add failing regression for WR-01 fail-open discovery vocabulary |
| 1 | GREEN | `979b081` | fix(03-21): fail closed on an unrecognised discovery outcome literal |
| 2 | — | `fcb22e8` | docs(03-21): state the true J3/J4 asymmetry at the uptime-lock contention site |
| 3 | RED | `6e51a55` | test(03-21): add failing regression for WR-03 hardcoded promotion floor |
| 3 | GREEN | `df6f947` | fix(03-21): derive the outcome-unrecorded floor from the configured discovery timeout |

Both RED gates failed for exactly the right reason before their fix landed:

- Task 1 RED: `AssertionError: ValueError not raised` for both `job_id='J7'` and `job_id='J9'` on `case='an_unrecognised_discovery_outcome_fails_closed_and_loud'`. The `'busy'` subTest passed immediately, as intended — it pins existing correct behaviour that no test defended.
- Task 3 RED: `TypeError: compose_active_exceptions() got an unexpected keyword argument 'discovery_timeout_seconds'` — the setting the floor's own guarantee referenced was not an input to the arithmetic at all.

Task 2 is not TDD: it is a comment correction with zero production behaviour change plus one added assertion, committed as a single `docs` commit.

## Verification Evidence

All three task `<verify>` blocks were run verbatim and emitted their sentinels: `DISCOVERY_OUTCOME_FAILS_CLOSED`, `UPTIME_CONTENTION_ASYMMETRY_DISCLOSED`, and `FLOOR_DERIVES_FROM_CONFIGURED_TIMEOUT`.

Every grep gate landed on its planned count:

| Gate | Plan-time | Now |
|------|-----------|-----|
| `_discovery_outcome_verdict` in `worker_main.py` | 0 | 3 |
| `outcome != 'failed'` in `worker_main.py` | 2 | 0 |
| `a_busy_discovery_lock_is_recorded_as_succeeded` in the test file | 0 | 1 |
| `an_unrecognised_discovery_outcome_fails_closed_and_loud` in the test file | 0 | 1 |
| `collide by construction every fifth J4 tick` in `app.py` | 0 | 1 |
| `Another run already owns this work` in `app.py` | 2 | 2 |
| `WR-02` in the test file | 0 | 1 |
| `discovery_timeout_seconds` in `diagnosis.py` | 1 | 6 |
| `a_configured_discovery_timeout_widens_the_floor_it_used_to_ignore` in the test file | 0 | 1 |
| `def test_` in the test file | 47 | 47 |

Suite results:

- `uv run --project dashboard python -m pytest -q` → **303 passed, 426 subtests passed** (pre-round baseline, before `03-20` and `03-21`: 301 passed, 421 subtests passed). Both halves are strictly greater. The passed count is unchanged from `03-20`'s 303 because this plan adds no new test *method* — it adds five subTests (two per job for J7/J9 in Task 1, one in Task 3), which is exactly `421 → 426`. **Nothing previously green went red.**
- `uv run --project dashboard python -m pytest tests/test_advanced_diagnosis_api.py -q` → 47 passed, 105 subtests passed.
- `uv run --project dashboard python -m pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py -q` → 32 passed, 123 subtests passed. The authority fence and lease-fenced dispatch paths survive all three edits.
- Both cross-module orders against `tests/test_runtime_ownership.py` → 69 passed, 166 subtests passed in each direction. No order dependency introduced: every new collaborator is a fixture-local lambda or an explicit argument, and no `addCleanup` was required.
- `.planning/REQUIREMENTS.md` is unchanged by this plan; `| TEL-06 | Phase 3 | Gaps Found |` and `- [ ] **TEL-06**` each still read exactly once.
- No durable job-health row, raised condition message, log line, or comment introduced by this plan carries an exception message, filesystem path, or SQL fragment. The `ValueError` message names only the unrecognised outcome literal via `!r`.
- Every `compose_active_exceptions` call site in the repo was enumerated (`grep -rn` over `dashboard/` and `tests/`): two production, two test. All four were updated; the third `tests/test_advanced_ui.py` hit is a comment, not a call.

### Wave-1 flake, observed and not chased

The pre-existing intermittent failure in `tests/test_worker_ownership_matrix.py::test_heartbeat_renewal_to_persistence_handoff_is_fenced` (rows S2, J1) did **not** appear in any run during this plan — the ownership matrix passed green on every invocation, including inside the full-suite run. Recorded here only to confirm it was watched for.

## Threat Mitigations Applied

| Threat ID | Disposition | Evidence |
|-----------|-------------|----------|
| T-03-124 | mitigated | `_discovery_outcome_verdict` checks membership against the documented three-literal contract; the new subTests prove `'busy'` records `succeeded` and an unrecognised literal produces a durable `failed` / `ValueError` row plus exactly one `job_failed` exception, for both J7 and J9. |
| T-03-125 | mitigated | The contention comment names the J3/J4 asymmetry and the every-fifth-tick structural collision; the regression proves the losing full sweep's `last_uptime_check` stays `None`. |
| T-03-126 | mitigated | The floor takes the operator's configured value as an argument; the new subTest proves promotion flips in both directions on one identically-aged row at 1200 vs 180. |
| T-03-127 | accepted | The widened floor is `max(900, configured + 60)` and grows only with the operator's own budget. `overdue_running_job_promotes_once` and `absent_cadence_past_the_floor_promotes_once` are unmodified and still prove a genuinely wedged job is promoted. |
| T-03-128 | mitigated | No task touched `_write_job_health_transition`, `assert_current_worker_authority`, or the admission/authority fence; both ownership suites and both cross-module orders are green. |
| T-03-129 | accepted (n/a) | No package-manager install occurred. No dependency added, removed, upgraded, or pinned. |

## Deviations from Plan

Two adjustments were made to satisfy the plan's own grep gates, which the plan's prose would otherwise have contradicted. Both are text-only and neither changes behaviour.

**1. [Rule 3 - Blocking] `_discovery_outcome_verdict`'s docstring could not quote the exclusion comparison verbatim**
- **Found during:** Task 1, running the acceptance criteria
- **Issue:** The docstring explained the defect by quoting `` `outcome != 'failed'` ``, which kept the gate `grep -c "outcome != 'failed'" dashboard/beacon/worker_main.py` at 1 instead of the required 0.
- **Fix:** The docstring now describes the old approach in prose ("treating every value that is not the exact `'failed'` literal as a success") without reproducing the comparison. The explanation is unchanged in substance.
- **Files modified:** `dashboard/beacon/worker_main.py`
- **Commit:** `979b081`

**2. [Rule 3 - Blocking] The two call-site pointer comments could not name the helper**
- **Found during:** Task 1, running the acceptance criteria
- **Issue:** The plan asked for "a one-line pointer to the new helper's own docstring" at each call site, but also required `grep -c '_discovery_outcome_verdict'` to equal exactly 3 (definition + two calls). Comments naming the helper pushed the count to 5.
- **Fix:** Both comments read `# Verdict by membership against the contract; see the helper's docstring.` — a pointer that does not repeat the identifier. Count is 3, and the same-line `return _discovery_outcome_verdict(outcome)` makes the referent unambiguous.
- **Files modified:** `dashboard/beacon/worker_main.py`
- **Commit:** `979b081`

A third, smaller adjustment: `_unrecorded_outcome_boundary`'s new docstring initially referred to `discovery_timeout_seconds` in lowercase, making `grep -c 'discovery_timeout_seconds' dashboard/beacon/diagnosis.py` read 7 rather than the required 6. It now names the setting as `DISCOVERY_TIMEOUT_SECONDS`, which is the operator-facing spelling anyway. Count is 6: the signature, the floor computation, `compose_active_exceptions`' signature, its call to the boundary, `get_current_diagnosis`' argument, and the one pre-existing `_settings_payload` line.

No other deviation rule fired. No auto-fix was needed in any of the four files, and no out-of-scope discovery was logged to `deferred-items.md`.

## Known Stubs

None. No `TODO`, `FIXME`, placeholder, skipped test, or unrun `<verify>` was introduced by any task. `'unrecognised_outcome'` in the new Task 1 subTest is a deliberately-invalid fixture literal supplied at the `run_discovery` collaborator boundary to exercise the fail-closed path — it is the thing under test, not a stand-in for unfinished work. No entry was appended to `.planning/WINDOWS.md` because this plan produced no defect of any recorded kind.

## Requirements Not Promoted (deliberate)

TEL-06 remains open in both halves of `.planning/REQUIREMENTS.md`. Together with wave-1 sibling `03-20`, this round closes CR-01 and all four warnings from `03-19-REVIEW.md`. Per this plan's own `process` prohibition, that is an implementation claim, not independent verification: only the next re-verification pass may promote TEL-06.

## Human Verification Carried Forward

Three operator-facing checks on real Pi hardware remain outstanding for the end-of-phase checkpoint (`human_verify_mode: end-of-phase`), unchanged and not automated away:

1. `/advanced` during a real collection gap with stale host evidence — the open gap and stale host show as real, correctly labelled exceptions, and no resolved or retention-expired interval shows as an open actionable gap. (Carried since round 3.)
2. Worker started, one minute idle, then `/advanced` — no "Background job failed" card for J5 or J6, and no "Background job outcome not recorded" card for a job that is simply working. (Recorded by round 4; still not performed on hardware.)
3. One offline or `<title>`-less monitored service, one normal preview poll cycle, then `/advanced` — the service's own row shows its offline/gap evidence, and no J6 "Background job failed" card appears, proving `03-20`'s CR-01 fix holds on real hardware and not only in the synthetic reproduction.

## Self-Check: PASSED

- `dashboard/beacon/worker_main.py` — FOUND, contains `_discovery_outcome_verdict` at 3 lines.
- `dashboard/app.py` — FOUND, contains the rewritten contention comment.
- `dashboard/beacon/diagnosis.py` — FOUND, `discovery_timeout_seconds` at 6 lines.
- `tests/test_advanced_diagnosis_api.py` — FOUND, 47 test methods, 105 subtests passing.
- `.planning/phases/03-advanced-current-diagnosis/03-21-SUMMARY.md` — FOUND.
- `2728889`, `979b081`, `fcb22e8`, `6e51a55`, `df6f947` — all five commits FOUND in `git log`.
- No file deletions in any of the five commits (`git diff --diff-filter=D` over the range is empty).
