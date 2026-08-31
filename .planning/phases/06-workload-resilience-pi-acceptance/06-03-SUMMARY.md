---
phase: 06-workload-resilience-pi-acceptance
plan: 03
subsystem: backend
tags: [sqlite, apscheduler, playwright, preview-capture, retry-backoff, ops-02]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-01: preview_requests.next_attempt_ts column (migration 10); tests/test_workload_resilience.py seeded as the phase's OPS-01..04 integration suite"
provides:
  - "PREVIEW_STATUS_DEGRADED, preview_retry_decision, schedule_preview_retry_in_transaction and its worker wrapper in queues.py — a bounded, backoff-aware preview retry policy"
  - "Settings.preview_max_attempts/preview_retry_base_seconds/preview_retry_max_seconds (D-02 defaults: 3, 60, 600), env-configurable via the existing _positive_int fallback idiom"
  - "worker_process_preview_requests branches a per-service capture failure into a real-backoff retry or, once the budget is exhausted, the degraded terminal status — never blocking J1-J4"
  - "api_thumbnail_status.thumb_state (degraded/ok/pending/empty) and a distinct, theme-parity-safe degraded preview badge/copy in app.js/style.css"
affects: [06-04-cadence-under-contention, 06-05-wal-and-concurrency, 06-06-harness-self-test]

actuals:
  tokens: 8535
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "preview_retry_decision: a pure, DB-free doubling-with-cap function (same shape as Settings.telemetry_retry_base_seconds/_max_seconds) that returns None once attempt_count reaches the configured budget"
    - "schedule_preview_retry_in_transaction copies finish_preview_in_transaction's exact guard sequence (current-owner assertion, row-exists check, newer-revision supersession check) so a retry can never be scheduled against a row this worker no longer owns"
    - "claim_preview's candidate SELECT and conditional UPDATE both gained the same 'next_attempt_ts IS NULL OR next_attempt_ts <= now' predicate, keeping the claim atomic against a concurrent writer exactly like every other claim guard in this file"

key-files:
  created: []
  modified:
    - dashboard/beacon/queues.py
    - dashboard/beacon/config.py
    - dashboard/app.py
    - dashboard/app.js
    - dashboard/style.css
    - docker-compose.yml
    - tests/test_durable_queues.py
    - tests/test_workload_resilience.py
    - tests/test_ui_states.py
    - tests/test_advanced_diagnosis_api.py

key-decisions:
  - "D-02 (inherited, implemented here): PREVIEW_MAX_ATTEMPTS=3, PREVIEW_RETRY_BASE_SECONDS=60, PREVIEW_RETRY_MAX_SECONDS=600, doubling per attempt with a cap. Rationale recorded in both config.py comments and queues.py's preview_retry_decision docstring, not only in the plan: 3 attempts bound one request's worst-case browser occupancy at ~81s against its own 1800s deadline_ts; 60/600 mirrors the existing telemetry_retry_* exponential-with-cap shape, scaled down because a preview is cheaper and more operator-visible than a telemetry rollup."
  - "Realigned four pre-existing test assertions in tests/test_advanced_diagnosis_api.py (Rule 1 - not a bug, but a direct, necessary consequence of the intended OPS-02 behavior change) from expecting an immediately-terminal 'failed' preview_requests row on the first capture fault to expecting a bounded-retry-pending 'queued' row with a future next_attempt_ts — the row's error text and every other assertion in each test (job-health state, PreviewCaptureUnavailable propagation, event error_class) were left unchanged, and no test's name, docstring, or subject was altered, following the exact realignment precedent 06-01 set for its own thumbnail-relocation test-site updates."
  - "attempt_count is left untouched by schedule_preview_retry_in_transaction — claim_preview already incremented it on the failed claim, and incrementing again in the retry-scheduling path would halve the effective retry budget."

patterns-established:
  - "A worker poller's per-item failure branches through a pure retry-decision function before choosing between 'defer with backoff' and 'write the bounded terminal status' — reusable for any other durable queue that needs the same bounded-retry-then-degrade shape."

requirements-completed: [OPS-02]

coverage:
  - id: D1
    description: "The durable preview queue can defer a failed attempt by a computed, real-elapsed backoff, refuses to hand the row back before that backoff elapses, and exposes a pure decision function that says when the retry budget is exhausted"
    requirement: "OPS-02"
    verification:
      - kind: unit
        ref: "tests/test_durable_queues.py#DurableQueueTests.test_preview_retry_decision_is_bounded_and_capped"
        status: pass
      - kind: integration
        ref: "tests/test_durable_queues.py#DurableQueueTests.test_preview_retry_reschedules_with_backoff_and_is_not_claimable_early"
        status: pass
    human_judgment: false
  - id: D2
    description: "A repeatedly-failing preview exhausts a bounded budget, lands on a distinct durable 'degraded' terminal state visible via /api/services and /api/thumbnail-status, and never blocks J1-J4's own background_job_health rows while it does so; a browser-unavailable machinery fault still raises PreviewCaptureUnavailable on every attempt"
    requirement: "OPS-02"
    verification:
      - kind: integration
        ref: "tests/test_workload_resilience.py#PreviewRetryTests.test_preview_retry_bounded_reaches_degraded_without_blocking_essential_jobs"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#AdvancedDiagnosisApiTests.test_a_broken_capture_machinery_fails_j6s_job_health_while_a_per_service_fault_does_not"
        status: pass
    human_judgment: false
  - id: D3
    description: "The dashboard renders a distinct, theme-parity-safe copy and fallback badge for a degraded preview versus a never-captured one, attributing the failure to Beacon's own capture machinery rather than the monitored service, and the degraded fallback carries no border (never boxed, per the six-state contract)"
    requirement: "OPS-02"
    verification:
      - kind: unit
        ref: "tests/test_ui_states.py#UiStateTests.test_degraded_preview_copy_is_distinct_from_never_captured_and_unboxed"
        status: pass
    human_judgment: false

duration: 22min
completed: 2026-08-31
status: complete
---

# Phase 6 Plan 3: Bounded Preview Retry & Degraded State Summary

**Preview capture failures now retry with real elapsed backoff (60s, 120s, capped at 600s) for up to 3 attempts before landing on a distinct `degraded` terminal status, surfaced in the dashboard as `◈ Preview capture failing — retries exhausted` in both themes, without ever blocking J1-J4's essential scheduler lanes.**

## Performance

- **Duration:** ~22 min active work
- **Started:** 2026-08-31T22:10:43Z (first commit after base merge)
- **Completed:** 2026-08-31T22:32:58Z
- **Tasks:** 2
- **Files modified:** 10 (0 created)

## Accomplishments
- `preview_retry_decision(attempt_count, max_attempts, base_seconds, max_seconds)` is a pure, unit-testable doubling-with-cap function that returns `None` once the retry budget is exhausted
- `schedule_preview_retry_in_transaction` / `schedule_preview_retry_for_worker_in_transaction` defer a failed capture back to `'queued'` with `next_attempt_ts` set, copying `finish_preview_in_transaction`'s exact ownership/supersession guard sequence
- `claim_preview`'s candidate SELECT and conditional UPDATE both honor `next_attempt_ts`, so a retry-pending row is genuinely unclaimable until its backoff elapses — proven with a real clock-advance test, not a mocked one
- `Settings.preview_max_attempts` / `preview_retry_base_seconds` / `preview_retry_max_seconds` (defaults 3/60/600, D-02) load through the existing `_positive_int` fallback idiom and are exposed in `docker-compose.yml`'s shared `beacon-environment` anchor
- `worker_process_preview_requests` branches every per-service capture failure through `preview_retry_decision`: below budget it schedules a real-backoff retry; at budget it writes `PREVIEW_STATUS_DEGRADED`; the trailing `PreviewCaptureUnavailable` raise for a genuine browser-unavailable machinery fault is untouched on every path
- `GET /api/services` (via the existing `preview_status` projection) and the new `GET /api/thumbnail-status` `thumb_state` key both report `degraded` for an exhausted port, and `thumb_state` distinguishes `ok`/`pending`/`empty` from stored facts only
- `app.js` renders `◈ Preview capture failing — retries exhausted` in `.svc-preview-status` (inside `.svc-meta`, which the light theme never hides) and a `PREVIEW UNAVAILABLE` dark-mode fallback badge distinct from `NO PREVIEW`; `style.css` adds `.svc-preview-fallback.degraded` with no border, matching the six-state contract's Degraded row
- Realigned four pre-existing preview-capture test assertions in `tests/test_advanced_diagnosis_api.py` onto the new bounded-retry-pending first-attempt behavior (see Deviations)

## Task Commits

Each task was committed atomically:

1. **Task 1: Bounded retry with backoff in the durable preview queue** - `6140e4a` (feat)
2. **Task 2: The worker exhausts the budget, and the operator sees a distinct degraded state** - `c0d7216` (feat)

**Plan metadata:** commit follows this summary

## Files Created/Modified
- `dashboard/beacon/queues.py` - `PREVIEW_STATUS_DEGRADED`, `QueueRequest.attempt_count`, `preview_retry_decision`, `schedule_preview_retry_in_transaction`, `schedule_preview_retry_for_worker_in_transaction`, `next_attempt_ts`-aware `claim_preview`
- `dashboard/beacon/config.py` - `preview_max_attempts`/`preview_retry_base_seconds`/`preview_retry_max_seconds` fields and their `_positive_int`-backed loading, with D-02 rationale in comments
- `dashboard/app.py` - `PREVIEW_MAX_ATTEMPTS`/`PREVIEW_RETRY_BASE_SECONDS`/`PREVIEW_RETRY_MAX_SECONDS` constants, retry-aware `worker_process_preview_requests`, `thumb_state` in `api_thumbnail_status`
- `dashboard/app.js` - `degraded` entry in `previewCopy`, `previewDegraded`-branched fallback badge/text
- `dashboard/style.css` - `.svc-preview-fallback.degraded` (unboxed, dark-mode only)
- `docker-compose.yml` - three preview-retry env vars added to the shared `beacon-environment` anchor
- `tests/test_durable_queues.py` - `test_preview_retry_decision_is_bounded_and_capped`, `test_preview_retry_reschedules_with_backoff_and_is_not_claimable_early`
- `tests/test_workload_resilience.py` - `PreviewRetryTests.test_preview_retry_bounded_reaches_degraded_without_blocking_essential_jobs`
- `tests/test_ui_states.py` - `test_degraded_preview_copy_is_distinct_from_never_captured_and_unboxed`
- `tests/test_advanced_diagnosis_api.py` - four assertion sites realigned onto the new bounded-retry-pending first attempt (see Deviations)

## Decisions Made
- **D-02 implemented as specified**: 3 attempts, 60/600s doubling backoff, all three knobs env-configurable with documented fallback, rationale recorded in code comments per the phase context's obligation.
- **`attempt_count` left untouched by the retry-scheduling path** — `claim_preview` already incremented it on the failed claim; incrementing again would halve the effective budget.
- **Test realignment over duplicate assertions**: rather than adding parallel tests for the new bounded-retry-pending first-attempt shape, the four existing sites that directly exercised this exact code path were updated in place (names/docstrings/subjects unchanged), following the 06-01 precedent for handling behavior changes that ripple into pre-existing regression coverage.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - direct consequence of intended behavior change] Realigned four pre-existing preview-capture test assertions**
- **Found during:** Task 2 full-suite verification
- **Issue:** `tests/test_advanced_diagnosis_api.py` had four sites (`test_the_real_scan_and_preview_pollers_record_a_genuine_failure_as_failed`, `test_a_titleless_service_never_fails_j6s_job_health`, and two subtests in `test_a_broken_capture_machinery_fails_j6s_job_health_while_a_per_service_fault_does_not`) asserting `preview_requests.status == 'failed'` after a first, single per-service capture fault. That assertion described the pre-06-03 behavior (a single failure was immediately terminal); 06-03's entire purpose is to make a single failure land bounded-retry-pending (`'queued'` with a future `next_attempt_ts`) instead, so these four assertions became stale by design, not by accident.
- **Fix:** Updated each site's status assertion from `'failed'` to `'queued'`, added a one-line comment citing 06-03/OPS-02, and left every other assertion in each test (job-health state, `error` text, `PreviewCaptureUnavailable` propagation, `event_row['error_class']`, the diagnosis-exceptions projection) completely unchanged. No test name, docstring, or documented subject was altered, matching the realignment precedent 06-01 set when its own storage-relocation change rippled into eight pre-existing test sites.
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Verification:** `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py` — 0 failures after the fix (was 4 subtest/test failures before); full suite green at 785 passed / 552 subtests passed.
- **Committed in:** `c0d7216` (Task 2 commit)

---

**Total deviations:** 1 (test realignment necessitated directly by this plan's own intended behavior change, not a defect)
**Impact on plan:** No scope creep — the realigned file was not in the plan's `files_modified` list, but leaving it unfixed would have left the full suite red for a reason entirely internal to this plan's own change. All four sites are now correct with respect to the shipped OPS-02 behavior.

## Issues Encountered
None beyond the deviation above. The full suite measured green twice during this plan: 783 passed / 552 subtests after Task 1 (baseline 781 + Task 1's 2 new queue tests), 785 passed / 552 subtests after Task 2 (+2: the new `PreviewRetryTests` integration test and the new `test_ui_states.py` source-contract test). The 552 subtest count matches the pre-existing baseline exactly across both runs, confirming no existing subtest regressed. The `test_worker_ownership_matrix.py` flaky timing sensitivity noted in 06-01/06-02 was not observed during this plan's runs.

## User Setup Required

None - no external service configuration required. Operators who want a non-default retry budget or backoff can set `PREVIEW_MAX_ATTEMPTS` / `PREVIEW_RETRY_BASE_SECONDS` / `PREVIEW_RETRY_MAX_SECONDS` in their environment or `docker-compose.yml` overrides; the shipped defaults (3, 60, 600) require no action.

## Next Phase Readiness
- OPS-02 is fully implemented and verified for this plan's scope: bounded backoff-aware retry in the durable queue, worker-side exhaustion into a distinct `degraded` terminal state, and operator-visible, theme-parity-safe copy naming the capture (not the service) as the failing thing.
- `tests/test_workload_resilience.py` now also carries `PreviewRetryTests`, ready alongside the existing `ThumbnailRelocationTests`/`ThumbnailMigrationTests`/`ThumbnailBudgetTests` for 06-04 (cadence under contention), 06-05 (WAL/concurrency/restart), and 06-06 (harness self-test) to append their own coverage per the module's docstring.
- No blockers.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-08-31*
