---
phase: 03-advanced-current-diagnosis
plan: 20
subsystem: background-jobs
tags: [background-jobs, worker-dispatch, job-health, lease-ownership, previews, sqlite, pytest, telemetry-honesty]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "03-18's return-value vocabulary at the worker dispatch boundary (None = genuine skip, False = genuine failure), whose J6 half this plan corrects: `return not warning` was the CR-01 defect"
  - phase: 03-advanced-current-diagnosis
    provides: "03-19's genuine-failure regression, whose J6 subTest pinned the CR-01 defect and is corrected in place here, and its busy-requeue regression for the non-lost-lease direction that this plan's WR-04 test complements"
  - phase: 03-advanced-current-diagnosis
    provides: "03-02/03-12/03-15's durable job-health persistence under worker authority (_write_job_health_transition, assert_current_worker_authority) and compose_active_exceptions' job_failed promotion, both untouched by this plan"
provides:
  - "worker_process_preview_requests's job outcome is decoupled from the per-service capture warning: J6 answers 'did the poller do its job', never 'is the previewed service healthy'"
  - "The per-request preview_requests row and J6's job-level row are asymmetric by design in the same dispatch, proven by a regression driving the real production adapter and the real dispatch_callback"
  - "worker_process_scan_requests's discovery-busy branch honours heartbeat.lost exactly like every other terminal path, raising LeaseLost before any requeue is attempted"
  - "A code-verified finding stating that worker_process_scan_requests (J5) does not share CR-01's defect class and is deliberately left unchanged"
affects: [background-job-health, worker-dispatch, previews, phase-03-verification]

actuals:
  tokens: 2595
  tasks: 2
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "A job's own health and the health of the thing it inspects are two distinct signals that never meet at the worker dispatch boundary"
    - "A lost lease is fatal on every terminal path of a function, with no path allowed to return before the guard"
    - "A per-service condition is forced at the collaborator boundary (_fetch_html_response / fetch_thumbnail), never by stubbing the function under test"

key-files:
  created: []
  modified:
    - dashboard/app.py
    - tests/test_advanced_diagnosis_api.py

key-decisions:
  - "J6 succeeds whenever the poll claimed a request, attempted a capture, and durably recorded its own verdict in an authority-asserted transaction -- regardless of what the capture found (the user's decision recorded in 03-19-REVIEW.md CR-01)"
  - "The distinction between 'the job did its job' and 'the job's own machinery failed' is carried in a greppable comment and in a regression, not merely in the `return True` literal"
  - "The per-request preview_requests row's own status='failed' verdict is left completely intact -- nothing about the previewed service's health is suppressed, only J6's job-level verdict is decoupled from it"
  - "worker_process_scan_requests (J5) is verified against live source as NOT sharing CR-01's defect class and is deliberately left unchanged"
  - "TEL-06 deliberately left open in both halves of REQUIREMENTS.md; promotion is the next independent verifier's call, not this plan's"

patterns-established:
  - "Cross-boundary signal isolation: a background job's durable outcome may only be derived from facts the job itself owns (its claim, its transaction), never from a fact about a third-party service it inspected"
  - "Guard completeness: when a function applies a fatal-condition guard on its terminal paths, every branch that returns early must apply it too -- an early return that bypasses the guard is the defect, not the guard's placement"
  - "Asymmetric-by-design assertions: one regression proves two distinct signals disagreeing in the same dispatch, so a future change that collapses them into one fails loudly"

requirements-completed: [TEL-06]

coverage:
  - id: D1
    description: "worker_process_preview_requests returns True once its authority-asserted transaction commits, never derived from the per-service capture warning (CR-01)"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_titleless_service_never_fails_j6s_job_health"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed"
        status: pass
    human_judgment: false
  - id: D2
    description: "The per-request preview_requests row still reads status='failed' with the real warning text for an unhealthy service, coexisting with J6's succeeded job-level outcome in the same dispatch"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_titleless_service_never_fails_j6s_job_health"
        status: pass
    human_judgment: false
  - id: D3
    description: "worker_process_scan_requests's discovery-busy branch raises LeaseLost when the heartbeat confirms the lease is lost, before requeue_scan_for_worker is ever attempted (WR-04)"
    requirement: "TEL-06"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_busy_discovery_lock_with_a_lost_lease_does_not_report_success"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py#test_a_discovery_busy_scan_requeue_is_not_reported_as_a_failure"
        status: pass
    human_judgment: false
  - id: D4
    description: "A code-verified finding stating that worker_process_scan_requests (J5) does not share CR-01's defect class, so it is deliberately left unchanged"
    requirement: "TEL-06"
    verification: []
    human_judgment: true
    rationale: "The finding is an analytical claim about the provenance of scan_state['last_error'] across every exit path of _legacy_do_discovery. No single test can prove the absence of a code path from a downstream service's content into that field; it is established by reading the source and is recorded in 03-20-PLAN.md's own Finding section for a reviewer to re-derive."

# Metrics
duration: 15min
completed: 2026-08-19
status: complete
---

# Phase 03 Plan 20: Decouple J6's Job Health From the Previewed Service's Health Summary

**A monitored service being offline, untitled, or unscreenshottable no longer fabricates a durable J6 `job_failed` card, and a scan lease confirmed lost on the discovery-busy branch is now fatal instead of a fabricated clean poll.**

## Performance

- **Duration:** 15 min
- **Tasks completed:** 2 of 2
- **Commits:** 4 (2 RED, 2 GREEN — both tasks executed TDD)
- **Files modified:** 2

## Accomplishments

- **CR-01 closed.** `worker_process_preview_requests`'s final `return not warning` is now an unconditional `return True`, carried by a comment whose first sentence reads exactly `J6's job outcome answers one question only:`. `warning` describes the previewed service's own health — an offline service, a page with no `<title>`, a failed Chromium capture — and it can no longer decide J6's durable job verdict. Reaching that line means the poller claimed a request, attempted a capture, and durably recorded its own verdict inside an authority-asserted transaction, which is the whole of the job's contract.
- **The two signals are proven asymmetric in the same dispatch.** `test_a_titleless_service_never_fails_j6s_job_health` seeds a real service, enqueues a real preview, and forces a genuinely titleless page **only at the collaborator boundary** (`_fetch_html_response` / `fetch_thumbnail`, plus the `_preview_context.page_title` thread-local pinned falsy) — never by stubbing `_legacy_refresh_service_preview` or the poller itself. The real title-extraction path genuinely finds no title. In one dispatch it asserts J6's job-health row reads `succeeded` with a `None` `error_class`, the `preview_requests` row independently reads `status='failed'` with `error='title not found at configured path'`, and no `job_failed` exception names J6.
- **Round 6's own regression corrected in place.** `test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed`'s J6 subTest asserted the CR-01 defect. Its `dispatch_callback` return is now `True`, its durable row asserts `succeeded` / `None`, and the trailing combined assertion reads `['J5']`. The two `preview_requests` assertions (`status='failed'`, `error='preview capture failed'`) are unchanged — the per-request verdict was never the defect. The docstring now states the asymmetry explicitly so a future reader cannot mistake it for an oversight.
- **WR-04 closed.** `worker_process_scan_requests`'s discovery-busy branch was the one terminal path in the function that returned before reaching `if heartbeat.lost: raise beacon_queues.LeaseLost(...)`. It now raises that same condition, with that same message, as the first statement in the branch — inside the outer `try:` so `finally: heartbeat.stop()` still runs, and before `requeue_scan_for_worker` is ever attempted, since the claim is not ours to return once the lease is gone.
- **The stale empty-claim comment corrected.** Its trailing clause referenced a "busy-retry `return False` below" that no longer exists; it now describes the current `return None` behaviour and points at WR-04.
- **J5 verified as NOT sharing CR-01's defect class.** The plan's Finding section is confirmed against live source: `scan_state['last_error']` is written only by `_legacy_do_discovery`'s own success line (`None`) and its own top-level `except Exception` handler — the discovery job's own execution failing. A single unreachable service during discovery is written to the `services` table's per-row `last_error`, never to `scan_state`. `worker_process_scan_requests` is deliberately left unchanged.

## Task Commits

| Task | Gate | Commit | Message |
|------|------|--------|---------|
| 1 | RED | `dfb3331` | test(03-20): add failing regression for CR-01 J6 job-health conflation |
| 1 | GREEN | `8320366` | fix(03-20): decouple J6's job outcome from the per-service preview warning |
| 2 | RED | `97a5572` | test(03-20): add failing regression for WR-04 lost lease on the busy branch |
| 2 | GREEN | `883dd82` | fix(03-20): raise LeaseLost on the discovery-busy branch when the lease is gone |

Both RED gates failed for exactly the right reason before the fix landed:
- Task 1 RED: `AssertionError: False is not True` — `return not warning` turning a titleless page into a J6 job failure.
- Task 2 RED: `AssertionError: None is not False` — the busy branch returning `None`, which `dispatch_callback` records as `succeeded`.

## Verification Evidence

All acceptance criteria from both tasks pass. Every grep gate landed on its planned count:

| Gate | Plan-time | Now |
|------|-----------|-----|
| `J6's job outcome answers one question only` in `app.py` | 0 | 1 |
| `return not warning` in `app.py` | 1 | 0 |
| `^    return True$` in `app.py` | 5 | 6 |
| `the verdict this function itself just computed` in `app.py` | 2 | 1 |
| `A lost lease is` in `app.py` | 0 | 1 |
| `raise beacon_queues.LeaseLost('worker scan lease was lost')` in `app.py` | 1 | 2 |
| `if heartbeat.lost:` in `app.py` | 3 | 4 |
| `see WR-04 in 03-19-REVIEW.md` in `app.py` | 0 | 1 |
| `def test_` in `tests/test_advanced_diagnosis_api.py` | 45 | 47 |

Both task `<verify>` blocks were run verbatim and emitted their sentinels:
`J6_JOB_HEALTH_NEVER_DERIVED_FROM_SERVICE_CONTENT` and `LOST_LEASE_NEVER_REPORTS_SUCCESS`.

Suite results:

- `uv run --project dashboard python -m pytest -q` → **303 passed, 421 subtests passed** (baseline measured immediately before this plan: 301 passed, 421 subtests passed). Exactly `+2` passed, matching this plan's two new test methods. **Nothing previously green went red.** Note on the plan's "strictly more than 301 passed / 421 subtests passed" criterion: the passed count rose strictly (301 → 303); the subtest count is unchanged at 421 because neither new test uses `subTest`. Recorded as measured rather than restated as a strict increase on both halves.
- `uv run --project dashboard python -m pytest tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py -q` → 32 passed, 123 subtests passed. The authority fence and lease-fenced dispatch paths survive both edits.
- `tests/test_advanced_diagnosis_api.py` alone → 47 passed, 100 subtests passed.
- Both cross-module orders against `tests/test_runtime_ownership.py` → 69 passed, 161 subtests passed in each direction. No order dependency introduced.
- Round 5's empty-queue regression (`idle_queue_as_success`) is unmodified and still green.
- `.planning/REQUIREMENTS.md` is unchanged by this plan; `| TEL-06 | Phase 3 | Gaps Found |` and `- [ ] **TEL-06**` both still read exactly once.
- No durable job-health row, raised condition message, log line, or comment introduced by this plan carries an exception message, filesystem path, or SQL fragment.

## Threat Mitigations Applied

| Threat ID | Disposition | Evidence |
|-----------|-------------|----------|
| T-03-119 | mitigated | `worker_process_preview_requests`'s return is decoupled from `warning`; `test_a_titleless_service_never_fails_j6s_job_health` drives the real, unstubbed collaborator chain and asserts the per-request row and the job-health row disagree by design. |
| T-03-120 | mitigated | The `except beacon_queues.LeaseLost: raise` and every uncaught-exception path inside the transaction are untouched; the unmodified J5 subTest and both ownership suites are green. |
| T-03-121 | mitigated | The busy branch raises `LeaseLost` before any requeue when `heartbeat.lost` is `True`; the regression proves the durable J5 row is left `running`, never fabricated as `succeeded`, and the `scan_requests` row is left `running` with a `None` error. |
| T-03-122 | mitigated | Neither task touches `_write_job_health_transition`'s `assert_current_worker_authority` call or the admission/authority fence; `tests/test_worker_ownership_matrix.py` and `tests/test_runtime_ownership.py` re-run green after both edits. |
| T-03-123 | accepted (n/a) | No package-manager install occurred. No dependency added, removed, upgraded, or pinned. |

## Deviations from Plan

No deviation rule fired against the plan's own scope: both tasks were executed exactly as written, and no auto-fix was needed in `dashboard/app.py` or `tests/test_advanced_diagnosis_api.py`.

One self-inflicted slip occurred during the state-update step and is recorded here rather than left silent:

**1. [Rule 1 - Bug] Over-broad `sed` rewrite of `.planning/STATE.md` decision labels, fully reverted before commit**
- **Found during:** state updates, after Task 2
- **Issue:** `state.add-decision` wrote this plan's four decisions with a `- [Phase ?]:` placeholder label. The correcting `sed 's/^- \[Phase ?\]:/- [Phase 03]:/'` used a BRE where `?` is a literal, so it matched and relabelled **all 109** pre-existing `- [Phase ?]:` decision lines — including Phase 1 and Phase 2 decisions — as Phase 03.
- **Fix:** All 109 lines were restored by diffing the working file against `git show HEAD:.planning/STATE.md` and re-applying the original `- [Phase ?]:` prefix to exactly the lines that carried it in `HEAD`. Verified: the only `- [Phase 03]:` lines remaining are the 14 that already carried that label in `HEAD` plus this plan's own 4.
- **Files modified:** `.planning/STATE.md` (reverted; net change is the intended state update only)
- **Commit:** folded into the final docs commit — the erroneous state never reached a commit.

Additionally, `state.advance-plan` reset the human-readable Current Position block to `Plan: 2 of 21 / Status: Ready to execute` and left `last_activity_desc` pointing at 03-18. Both were corrected to describe 03-20 accurately, since STATE.md is the project's own memory of what is true.

## Known Stubs

None. `b'stub-thumbnail-bytes'` in the new Task 1 regression is a test fixture value supplied at the `fetch_thumbnail` collaborator boundary, not a production stub or placeholder. No `TODO`, `FIXME`, skipped test, or unrun `<verify>` was introduced by either task.

## Requirements Not Promoted (deliberate)

TEL-06 remains open in both halves of `.planning/REQUIREMENTS.md`. This plan closes **CR-01 and WR-04 only**; WR-01, WR-02, and WR-03 are closed by wave-2 sibling `03-21`. Per this plan's own `process` prohibition, only the next independent re-verification — after both 03-20 and 03-21 have executed — may promote TEL-06.

## Self-Check: PASSED

- `dashboard/app.py` — FOUND, contains the new `return True` and the new `LeaseLost` guard.
- `tests/test_advanced_diagnosis_api.py` — FOUND, 47 test methods.
- `dfb3331`, `8320366`, `97a5572`, `883dd82` — all four commits FOUND in `git log`.
- No file deletions in any of the four commits.
