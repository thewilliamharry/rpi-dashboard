---
phase: 03-advanced-current-diagnosis
plan: 19
subsystem: testing
tags: [background-jobs, worker-dispatch, job-health, sqlite, pytest, telemetry-honesty, mutation-testing]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-18's return-value vocabulary at the worker dispatch boundary (None = genuine skip, False = genuine failure) and its two new anti-scaffolding regressions, which this plan's Task 3 extends to the two transient contention sites 03-18 deliberately left untouched"
  - phase: 03-advanced-current-diagnosis
    provides: "03-17's compound-startup re-raise (run_worker's `except JobHealthBookkeepingError` handler and the `work_error_class is not None` branch) that Task 2 extends additively without altering"
  - phase: 03-advanced-current-diagnosis
    provides: "03-02/03-12/03-15's durable job-health persistence under worker authority (_write_job_health_transition, assert_current_worker_authority) and compose_active_exceptions' job_failed promotion"
provides:
  - "UNRECORDED_OUTCOME_FLOOR_SECONDS is pinned against external facts (connect_db's two 30 s lock waits and DISCOVERY_TIMEOUT_SECONDS), proven non-tautological by a mutation-and-restore run"
  - "A compound startup failure leaves durable `failed` evidence the /advanced workspace can read whenever a bounded, best-effort retry of the failed write succeeds"
  - "The compound-startup re-raise remains unconditional and unchanged whether or not the retry succeeds"
  - "A discovery-busy manual scan and a J3/J4 uptime-lock overlap both record `succeeded`, never a fabricated `Background job failed` card"
  - "deferred-items.md row 9 records the closure of row 8's two sites without disturbing row 8"
affects: [background-job-health, worker-dispatch, phase-03-verification]

actuals:
  tokens: 5232
  tasks: 3
  commits: 5

tech-stack:
  added: []
  patterns:
    - "A constant-value gate is pinned against facts external to the constant, never against the constant itself, and is proven able to fail by a one-time mutation-and-restore run"
    - "A best-effort durable-evidence attempt is wrapped in its own try/except and placed before an unconditional re-raise, so it can add an evidence channel but never remove or delay one"
    - "Transient contention (another run already owns this work) maps to the same non-fault outcome as an empty queue, distinct from a genuine failure"

key-files:
  created: []
  modified:
    - tests/test_advanced_diagnosis_api.py
    - dashboard/beacon/worker_main.py
    - dashboard/app.py
    - .planning/phases/03-advanced-current-diagnosis/deferred-items.md

key-decisions:
  - "The mandated Task 2 comment is wrapped so the phrase 'one bounded, best-effort attempt' stays contiguous on one line, satisfying the plan's own grep-based acceptance criterion"
  - "The new compound-startup test asserts exactly three attempted writes, which pins the retry as bounded to exactly one -- a loop would fail the assertion"
  - "Task 3's busy-requeue regression also asserts scan_requests.status='queued' and the uptime regression still yields to the holder, pinning the two contracts deferred-items.md row 8 named as the reason to defer"
  - "TEL-06 deliberately left open in both halves of REQUIREMENTS.md; promotion is the next independent verifier's call, not this plan's"

patterns-established:
  - "Non-tautological constant enforcement: assert the constant against values read from other production modules, then prove the assertion can fail by temporarily regressing the constant and restoring it before commit"
  - "Additive-only failure-path hardening: a new evidence attempt sits inside an existing handler, swallows its own errors, and leaves the surrounding control flow byte-identical"

requirements-completed: []

coverage:
  - id: D1
    description: "The job_outcome_unrecorded promotion floor is enforced against connect_db's own two 30-second lock waits and against DISCOVERY_TIMEOUT_SECONDS, so a regressed floor fails the suite instead of leaving it byte-identical"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_job_stuck_without_an_outcome_becomes_an_operator_exception (subTest case='the_floor_clears_connect_dbs_own_lock_waits')"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_job_stuck_without_an_outcome_becomes_an_operator_exception (subTest case='a_full_discovery_timeout_run_promotes_nothing')"
        status: pass
      - kind: other
        ref: "mutation-and-restore: UNRECORDED_OUTCOME_FLOOR_SECONDS set to 30 -> both new subtests SUBFAILED while all 11 prior subtests still passed; git checkout -- dashboard/beacon/diagnosis.py left the file byte-identical"
        status: pass
    human_judgment: false
  - id: D2
    description: "A compound startup failure (the work failed AND the write recording that failure failed) leaves a durable failed row with the work error's own class, and one job_failed operator card, whenever a bounded best-effort retry of that write succeeds"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_a_compound_startup_failure_leaves_durable_evidence_when_the_retry_succeeds"
        status: pass
    human_judgment: false
  - id: D3
    description: "The raised condition still escapes run_worker exactly as before whether or not the retry succeeds -- build_scheduler is never called, _worker_started stays False, and a retry that also fails changes nothing"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_a_compound_startup_failure_reaches_the_operator_instead_of_continuing"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_startup_survives_a_bookkeeping_failure (the work_error_class is None control, unmodified)"
        status: pass
    human_judgment: false
  - id: D4
    description: "A discovery-busy manual-scan claim records succeeded and no job_failed card, while the claim is genuinely returned to status='queued' for the next poll"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_a_discovery_busy_scan_requeue_is_not_reported_as_a_failure"
        status: pass
      - kind: integration
        ref: "tests/test_release_contract.py#test_manual_scan_stays_queued_when_discovery_is_busy (legacy non-worker path, untouched)"
        status: pass
    human_judgment: false
  - id: D5
    description: "An uptime probe that loses _uptime_lock to a concurrent probe records succeeded and no job_failed card, while still yielding to the holder"
    requirement: "TEL-06"
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_an_uptime_lock_collision_is_not_reported_as_a_failure"
        status: pass
    human_judgment: false
  - id: D6
    description: "The worker authority fence and lease-fenced dispatch paths survive all three edits, and suite greenness does not depend on module execution order"
    verification:
      - kind: integration
        ref: "uv run --project dashboard python -m pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py -q (32 passed / 123 subtests)"
        status: pass
      - kind: integration
        ref: "both cross-module orders against tests/test_runtime_ownership.py (67 passed / 161 subtests each)"
        status: pass
    human_judgment: false
  - id: D7
    description: "On real hardware, the /advanced Overview shows no fabricated Background job failed card and no Background job outcome not recorded card for a job that is simply working"
    verification: []
    human_judgment: true
    rationale: "Both human-verification items from 03-VERIFICATION.md are carried forward unchanged in this plan's Task 3 human-check block. Neither has been performed on the target Pi through six rounds; the operator's own idle Pi is the surface the criterion is written about and no automated reproduction can substitute for it."
  - id: D8
    description: "Background-job health reported to the operator reflects what the job actually did -- the ROADMAP truth that failed five consecutive verification rounds, now closed in both polarities and on all three of round 5's remaining counts by 03-18 plus this plan"
    verification: []
    human_judgment: true
    rationale: "The code-level halves are proven by D1-D6, but whether the truth as a whole is now satisfied is the independent verifier's judgment, not this plan's claim. TEL-06 is deliberately left open for exactly this reason."

# Metrics
duration: 11min
completed: 2026-08-19
status: complete
---

# Phase 03 Plan 19: Background-Job Health Honesty (Floor Enforcement, Compound Startup, Transient Contention) Summary

**The last three counts of round 5's background-job-health finding are closed: the promotion floor is now pinned against connect_db's own lock waits and the discovery timeout and proven able to fail, a compound startup failure leaves durable `failed` evidence whenever a bounded best-effort retry succeeds while still escaping loudly either way, and both transient contention sites record `succeeded` instead of a fabricated `Background job failed` card.**

## Performance

- **Duration:** 11 min
- **Started:** 2026-08-19T13:03:49Z
- **Completed:** 2026-08-19T13:14:36Z
- **Tasks:** 3 (5 commits — TDD RED/GREEN on Tasks 2 and 3)
- **Files modified:** 4
- **Test suite:** 298 passed / 419 subtests (baseline, matching the stated floor exactly) → **301 passed / 421 subtests**

## Accomplishments

- **Made the floor gate able to fail.** Round 5's verifier proved the existing subtests were tautological by setting `UNRECORDED_OUTCOME_FLOOR_SECONDS` to 30 and getting a byte-identical green suite. Two new subtests now read only *external* facts — `assertGreater(floor, 30 + 30)` for `connect_db`'s flock wait plus its SQLite busy timeout, and `assertGreater(floor, self.appmod.DISCOVERY_TIMEOUT_SECONDS)` — plus a J9-shaped row (`cadence_seconds=None`) running a full discovery timeout that must promote nothing. **Reproduced the verifier's own mutation:** with the constant at 30, both new subtests SUBFAILED while all 11 pre-existing subtests still passed, confirming both that the new gate works and that the old ones were exactly as toothless as reported.
- **Gave the compound startup failure an operator-facing channel without weakening the loud one.** `run_worker`'s `except JobHealthBookkeepingError` handler now makes exactly one bounded, best-effort `_write_job_health_transition(..., 'failed', error_class=work_error_class)` attempt on the `work_error_class is not None` branch, wrapped in its own `try` / `except Exception: pass`, immediately before the existing **unconditional** `raise`. When the retry succeeds, the durable `S1` row reads `failed` / `RecoverBlewUp` and `get_current_diagnosis` emits one `job_failed` card — the half five rounds lacked. When the retry also fails, nothing changes at all.
- **Pinned the re-raise in both directions.** The existing `test_a_compound_startup_failure_reaches_the_operator_instead_of_continuing` (whose fixture raises for *every* `('S1','failed')` write) still asserts `build_scheduler.assert_not_called()` and `_worker_started is False`; its `attempted` list now reads three entries, which is what proves the retry is bounded to exactly one — a loop would fail that assertion outright.
- **Closed both transient contention sites rather than merely restating the deferral.** `worker_process_scan_requests`' discovery-busy branch and `_legacy_do_uptime_check`'s `_uptime_lock` branch both `return None` instead of `False`, so `dispatch_callback`'s unchanged `if result is False:` mapping records `succeeded`. The 03-08 honesty prohibition's last two live counts are gone.
- **Pinned the two contracts that made row 8 defer in the first place.** The busy-requeue regression asserts the `scan_requests` row still reads `status='queued'` after the dispatch — the claim is genuinely back on the queue, not dropped — and the uptime regression still requires the losing probe to yield to the holder. `requeue_scan_for_worker`, the `heartbeat.lost` guard, and the lock acquisition itself are untouched. The legacy non-worker `test_manual_scan_stays_queued_when_discovery_is_busy` remains green.

## Task Commits

1. **Task 1: Pin the outcome-unrecorded floor against external facts** — `a08cfef` (test)
2. **Task 2 (TDD): Durable evidence for a compound startup failure**
   - RED: `974ac41` — `test(03-19): pin durable evidence for a compound startup failure`
   - GREEN: `f2a2a4a` — `fix(03-19): leave durable evidence before the compound-startup re-raise`
3. **Task 3 (TDD): Close the two transient contention sites**
   - RED: `2d20ed2` — `test(03-19): pin transient contention as a non-fault outcome`
   - GREEN: `a584814` — `fix(03-19): stop reporting transient contention as a fabricated job failure`

No REFACTOR commit was warranted — both fixes are minimal, local additions.

### RED evidence (the defects were live)

- **Task 2 RED:** both compound-startup tests failed with `Lists differ: [('S1','started'),('S1','failed')] != [('S1','started'),('S1','failed'),('S1','failed')]` — no retry existed.
- **Task 3 RED:** both contention tests failed with `AssertionError: False is not None` — the fabricated failure was live through the real production adapters.
- **Task 1 mutation proof:** with `UNRECORDED_OUTCOME_FLOOR_SECONDS = 30`, `SUBFAILED(case='the_floor_clears_connect_dbs_own_lock_waits')` and `SUBFAILED(case='a_full_discovery_timeout_run_promotes_nothing')`, `2 failed, 1 passed, 11 subtests passed`. `git checkout -- dashboard/beacon/diagnosis.py` then left an empty diff.

## Files Created/Modified

- `tests/test_advanced_diagnosis_api.py` (+229/−2) — two new subtests in `test_a_job_stuck_without_an_outcome_becomes_an_operator_exception` (11 → 13 subtests); three new tests (42 → 45 `def test_`); one `attempted` assertion updated in place.
- `dashboard/beacon/worker_main.py` (+15) — the bounded best-effort retry inside `run_worker`'s existing handler. The `raise`, the `work_error_class is None` branch and its `log.warning`, `dispatch_callback`, `build_scheduler` and the `finally: _finalize_worker_lifecycle` are all unchanged.
- `dashboard/app.py` (+9/−2) — `worker_process_scan_requests`' busy branch and `_legacy_do_uptime_check`'s lock branch each `return None` with the mandated comment. Every other return site in both functions is unchanged.
- `.planning/phases/03-advanced-current-diagnosis/deferred-items.md` (+1/−0) — row 9 appended; rows 1–8 byte-unchanged, verified by `git diff --numstat` showing `1 0`.

## Decisions Made

- **Wrapped Task 2's mandated comment so `one bounded, best-effort attempt` stays on one line.** The plan's own acceptance criterion is `grep -c 'one bounded, best-effort attempt' = 1`, which a natural line break at `bounded,` would have failed. The wording is verbatim; only the line breaks differ. Recorded as a deviation below.
- **Asserted `len(failed_cards) == 1` over the whole exceptions list, not just over `S1`.** This proves the compound failure emits *exactly one* card, not merely that an `S1` card exists among others — stronger than the plan's literal wording and closer to its intent.
- **Registered the new test's `addCleanup` restore *before* the monkeypatch assignment.** `03-17-REVIEW.md` IN-03 recorded the sibling test doing the reverse; the 03-10 prohibition's own restatement asks for restore-before-assignment, so the new test follows the stricter form. Both cross-module orders were re-run as an acceptance criterion (67 passed / 161 subtests each way).
- **`.planning/REQUIREMENTS.md` left byte-identical.** Verified with `git diff HEAD~5 HEAD -- .planning/REQUIREMENTS.md` (empty). TEL-06 remains `Gaps Found` and unchecked in both halves. The standard `requirements mark-complete` state step was **deliberately skipped** — this plan's own process prohibition forbids promoting TEL-06 on an implementation claim.

## Deviations from Plan

### Auto-fixed / adjusted

**1. [Rule 3 - Blocking] Re-wrapped Task 2's mandated comment so the grep phrase stays contiguous**
- **Found during:** Task 2 (GREEN)
- **Issue:** The comment text the plan mandates is longer than one line at 24-space indentation. The natural wrap point falls inside the phrase `one bounded, best-effort attempt`, which made the plan's own acceptance criterion `grep -c 'one bounded, best-effort attempt' = 1` return `0`.
- **Fix:** Re-broke the comment lines so the phrase sits contiguous on a single line. No word was added, removed, or altered.
- **Files modified:** `dashboard/beacon/worker_main.py`
- **Verification:** `grep -c 'one bounded, best-effort attempt'` now returns `1`; all Task 2 gates pass.
- **Committed in:** `f2a2a4a`

**2. [Rule 2 - Missing Critical] Strengthened the compound-failure exception assertion to bound the whole list**
- **Found during:** Task 2 (RED)
- **Issue:** The plan asked that `exceptions` "contains exactly one `job_failed` item whose `job_id` is `'S1'`". Filtering to `S1` first and then asserting length 1 would not catch a second, spurious `job_failed` for a different job.
- **Fix:** Filtered on `kind == 'job_failed'` only, asserted `len == 1`, then asserted `job_id == 'S1'` and `section == 'pipeline'`.
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Verification:** Test passes at GREEN and failed at RED for the intended reason.
- **Committed in:** `974ac41`

**3. [Rule 2 - Missing Critical] Added the requeue/lock contract assertions the deferral reason named**
- **Found during:** Task 3
- **Issue:** `deferred-items.md` row 8's stated reason for deferring was that changing either site "touches its own requeue/retry semantics". Asserting only the new job-health outcome would leave those semantics unpinned — exactly how a gap-closure round ships a new defect.
- **Fix:** The busy-requeue test also asserts `scan_requests.status == 'queued'` and `error IS NULL` after the dispatch; the uptime test acquires `_uptime_lock` in a `try`/`finally` so the holder relationship is real and always released.
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Verification:** Both pass; `tests/test_release_contract.py -k manual_scan_stays_queued_when_discovery_is_busy` (the legacy path) remains green.
- **Committed in:** `2d20ed2`

**4. [Process] Skipped the workflow's `requirements mark-complete` step**
- **Found during:** Close-out
- **Issue:** The plan's `requirements:` frontmatter carries `TEL-06`, and the standard execute-plan close-out marks such IDs complete. This plan's own process prohibition and the orchestrator's scope fence both forbid promoting TEL-06.
- **Fix:** Step skipped; `.planning/REQUIREMENTS.md` left untouched and excluded from the metadata commit.
- **Verification:** `git diff HEAD~5 HEAD -- .planning/REQUIREMENTS.md` is empty; both grep gates on TEL-06's open state pass.

---

**Total deviations:** 4 (1 Rule 3 blocking, 2 Rule 2 hardening of new test code, 1 deliberate process fence)
**Impact on plan:** None weakens the plan; three strengthen the regressions it exists to author and one honours an explicit prohibition. No production behaviour beyond the two mandated `return None` changes and the one mandated retry. No scope creep.

## Scope Fences Honoured

- `.planning/REQUIREMENTS.md` **unchanged** — empty diff across all five commits. TEL-06 not promoted.
- `dashboard/beacon/diagnosis.py` **unchanged** — the mutation-and-restore proof left an empty diff; `UNRECORDED_OUTCOME_FLOOR_SECONDS` is `900` in the tree and in every commit. No mutated constant was ever staged.
- No Phase-4 range-preference work; DIA-08's `range` clause untouched.
- 03-18's returns not revisited: `return status == 'completed'`, `return not warning`, and both `outcome != 'failed'` sites are byte-identical to how 03-18 left them.
- `deferred-items.md` rows 1–8 byte-unchanged (`git diff --numstat` = `1 0`).
- `dashboard/advanced.js`, `advanced.html`, `advanced.css` untouched; all 36 `03-UI-SPEC.md` rows unaffected.
- `dispatch_callback`'s `if result is False:` mapping read by all three tasks, modified by none.

## Verification Evidence

| Gate | Result |
|---|---|
| Full suite (baseline, before this plan) | 298 passed / 419 subtests — matched the stated floor exactly |
| **Full suite (after all three tasks)** | **301 passed / 421 subtests** |
| `pytest -k job_stuck_without_an_outcome` (shipped floor 900) | 1 passed, 13 subtests (was 11) |
| Floor mutated to 30 | 2 failed — both new subtests SUBFAILED, 11 prior subtests still passed |
| `git diff -- dashboard/beacon/diagnosis.py` after restore | empty |
| `pytest -k compound_startup_failure` | 2 passed |
| `pytest -k startup_survives` (bookkeeping-only control) | 1 passed |
| `pytest -k 'discovery_busy_scan_requeue or uptime_lock_collision'` | 2 passed |
| `pytest tests/test_release_contract.py -k manual_scan_stays_queued_when_discovery_is_busy` | 1 passed |
| `pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py` | 32 passed / 123 subtests |
| Module order `runtime_ownership` → `advanced_diagnosis` | 67 passed / 161 subtests |
| Module order `advanced_diagnosis` → `runtime_ownership` | 67 passed / 161 subtests |
| `grep -c 'assertGreater(floor,' tests/...` | 2 (was 0) |
| `grep -c 'a_full_discovery_timeout_run_promotes_nothing' tests/...` | 1 (was 0) |
| `grep -c 'one bounded, best-effort attempt' worker_main.py` | 1 (was 0) |
| `grep -c 'except JobHealthBookkeepingError' worker_main.py` | 1 (unchanged) |
| `grep -c '_write_job_health_transition' worker_main.py` | 4 (was 3) |
| `grep -c 'Another run already owns this work' app.py` | 2 (was 0) |
| `grep -c 'return None$' app.py` | 5 (was 3) |
| `grep -c 'def test_' tests/...` | 45 (was 42) |
| `grep -c '^| 9 |' deferred-items.md` | 1 |
| `grep -c '^| TEL-06 | Phase 3 | Gaps Found |$' REQUIREMENTS.md` | 1 |
| `grep -c '^- \[ \] \*\*TEL-06\*\*' REQUIREMENTS.md` | 1 |

The measured baseline matched the orchestrator's stated floor of 298/419 exactly — no discrepancy to report. The suite grew by +3 tests and +2 subtests; nothing previously green went red.

## Threat Model Dispositions

| Threat ID | Disposition | Evidence |
|---|---|---|
| T-03-112 (Repudiation — unenforced floor) | **mitigated** | Task 1's two external-fact assertions plus the mutation-and-restore run that proved they can fail. |
| T-03-113 (Repudiation — compound row left `running`) | **mitigated** | Task 2's retry + `test_a_compound_startup_failure_leaves_durable_evidence_when_the_retry_succeeds`, asserting the durable row and the operator card. |
| T-03-114 (DoS — retry changing control flow) | **mitigated** | The retry is wrapped in its own `try`/`except Exception: pass`; the `raise` is unconditional and unchanged; the retry-also-fails control test still asserts `build_scheduler.assert_not_called()` and `_worker_started is False`. |
| T-03-115 (Repudiation — contention as `job_failed`) | **mitigated** | Task 3's two `return None` sites + two regressions asserting the durable `succeeded` row and the absence of a `job_failed` card. |
| T-03-116 (DoS — masking a stuck busy-retry loop) | **accepted, bounded** | Both sites remain single-poll-cycle decisions. The busy regression asserts the claim is genuinely back at `status='queued'`, so the next tick re-attempts; a genuine `worker_run_discovery` raise still flows through the unmodified failure path (pinned by 03-18's `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed`, still green). |
| T-03-117 (Tampering — authority fence) | **mitigated** | `_write_job_health_transition`'s `assert_current_worker_authority` untouched; the retry reuses the same authority-fenced function. Ownership suites green (32 passed / 123 subtests) after every task. |
| T-03-118 (Supply chain) | **n/a** | No dependency added, removed, upgraded, or pinned. No package-manager install ran. |

No durable job-health row, log line, or comment introduced by this plan carries an exception message, path, or SQL fragment. The new test asserts `assertNotIn('secret message', str(raised.exception))`, preserving the existing message-boundary contract.

## Known Stubs

None. No placeholder value, hardcoded empty collection, `TODO`, `FIXME`, or skipped test was introduced. All three new tests and both new subtests run and assert real durable state.

## Issues Encountered

- **The mandated comment's grep gate collided with line wrapping** (see deviation 1). Detected by running the acceptance grep rather than assuming it; fixed in one pass.
- No other issue. Both RED phases failed for exactly the predicted reason, both GREEN phases passed first try, and the mutation proof reproduced the verifier's finding precisely. No auto-fix attempt limit was approached.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- **Ready for independent re-verification (round 6).** Round 5's `missing` items 4, 5 and 6 are closed here; items 1, 2 and 3 were closed by wave-1 sibling 03-18. All five carried-forward prohibitions from 03-08/03-09/03-10 are addressed by the combination of the two plans.
- **TEL-06 remains open by design.** Six rounds have correctly declined to promote it; promotion is the independent verifier's call.
- **Both human-verification items remain outstanding on real hardware** and are carried forward verbatim in this plan's Task 3 `<human-check>` block for the end-of-phase checkpoint. Neither has been performed on the target Pi through six rounds — this is the single largest remaining unknown for the phase.
- **One residual note for the verifier:** the two `return None` contention sites now report identically to an empty queue. A *permanently* wedged discovery lock would therefore read as a job that always succeeds. This is bounded by design (the claim returns to `status='queued'` each tick, and `job_outcome_unrecorded` still governs a start that never records an outcome) and is recorded as T-03-116 accepted, but it is the one behaviour this closure trades away.

---
*Phase: 03-advanced-current-diagnosis*
*Plan: 19*
*Completed: 2026-08-19*

## Self-Check: PASSED

All four modified files and the SUMMARY exist on disk, and all five task commits (`a08cfef`, `974ac41`, `f2a2a4a`, `2d20ed2`, `a584814`) plus the metadata commit (`23a99e0`) are present in git history.
