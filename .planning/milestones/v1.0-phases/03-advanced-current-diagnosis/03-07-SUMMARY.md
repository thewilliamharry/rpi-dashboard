---
phase: 03-advanced-current-diagnosis
plan: 07
subsystem: api
tags: [flask, sqlite, playwright, telemetry, diagnosis, truthful-evidence]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis (plans 01-06)
    provides: the bounded parameterless GET-only current-diagnosis endpoint, its typed pipeline evidence, and the advanced browser workspace that renders it
  - phase: 02-bounded-telemetry-retention
    provides: telemetry_streams.open_gap_start_ts, telemetry_coverage, and telemetry_rollup_jobs durable evidence
provides:
  - Open telemetry_streams gaps synthesized into pipeline.gaps and promoted to exceptions (CR-01)
  - A distinct host_freshness exception for stale/unknown host evidence (CR-02)
  - Sentinel-measured pending_truncated, correct at exactly the cap (CR-03)
  - Sentinel-measured streams_truncated plus active-gap/stale-first stream ordering and UI disclosure (CR-04)
  - A monotonic browser refresh-generation guard discarding superseded responses and errors (WR-01)
affects: [03.1-planned-maintenance-recognition, 04-historical-analytics, advanced-workspace, telemetry-evidence]

actuals:
  tokens: 8599
  tasks: 3
  commits: 6

tech-stack:
  added: []
  patterns:
    - "Sentinel-measured truncation (fetch cap+1, slice to cap, return the boolean) applied uniformly to gaps, streams, and pending reads"
    - "Priority ORDER BY that ranks active-gap then stale rows ahead of quiet ones so a cap never silently drops actionable evidence"
    - "Monotonic in-memory request-generation guard on both the success and failure branches of a browser refresh"

key-files:
  created: []
  modified:
    - dashboard/beacon/diagnosis.py
    - dashboard/beacon/repositories.py
    - dashboard/advanced.js
    - tests/test_advanced_diagnosis_api.py
    - tests/test_advanced_ui.py

key-decisions:
  - "An open telemetry_streams gap is durable active-gap evidence in its own right and is synthesized into exactly one open, actionable pipeline.gaps item, appended after coverage-derived items so existing ordering is untouched."
  - "Truncation is measured with a sentinel row beyond the cap, never inferred from returned-list length; the flawed len(list) >= cap derivation was fully replaced rather than kept alongside."
  - "Stale or unknown host evidence is its own host_freshness exception kind at the worker-freshness priority tier, never merged with worker_freshness or recovery_required."
  - "Bounded stream reads rank open-gap then stale streams ahead of quiet ones so the 64-row cap can never hide actionable collection evidence."
  - "Refresh ordering is enforced with a memory-only monotonic generation counter rather than AbortController, leaving the single fetch call per refresh unchanged."

patterns-established:
  - "Sentinel truncation: every capped read returns an explicit measured boolean, and the composer consumes that boolean instead of re-deriving it"
  - "Truthful-normality: the Overview 'reporting normally' copy is reachable only when host, service, and pipeline evidence all produce zero exceptions"
  - "Reverse-order network regressions are exercised in Playwright by test-owned fetch instrumentation that holds the first in-flight request"

requirements-completed: [TEL-06, DIA-02, DIA-03, DIA-08]

coverage:
  - id: D1
    description: "An active telemetry_streams gap with no telemetry_coverage row is synthesized into exactly one open, actionable pipeline.gaps item and promoted into the exceptions list; a NULL open_gap_start_ts still yields no gap"
    requirement: TEL-06
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_open_stream_gap_is_synthesized_merged_and_promoted"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_open_stream_gap_is_reported_per_stream_without_borrowing_evidence"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_open_stream_gap_renders_as_pipeline_and_overview_evidence"
        status: pass
    human_judgment: false
  - id: D2
    description: "Missing or stale host evidence always produces a distinct host_freshness exception, and the Overview 'reporting normally' copy never renders while any exception is present"
    requirement: DIA-02
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_host_freshness_becomes_an_active_exception_when_evidence_is_not_fresh"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_stream_truncation_and_host_exception_replace_the_normal_claim"
        status: pass
    human_judgment: false
  - id: D3
    description: "Pending-aggregation truncation is sentinel-measured: false at 0/31/32 rows, true only at 33+, always capped at 32 returned items"
    requirement: TEL-06
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_pending_truncation_uses_one_sentinel_beyond_the_response_cap"
        status: pass
    human_judgment: false
  - id: D4
    description: "Stream truncation is sentinel-measured (false at 0/64, true at 65) with open-gap and stale streams surviving the cap ahead of quiet ones, and the UI discloses the count/truncated state"
    requirement: DIA-03
    verification:
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_stream_truncation_uses_a_sentinel_and_keeps_active_evidence"
        status: pass
      - kind: integration
        ref: "tests/test_advanced_diagnosis_api.py#test_stream_truncation_ranks_stale_evidence_ahead_of_quiet_streams"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_pipeline_and_settings_render_independent_truthful_regions"
        status: pass
    human_judgment: false
  - id: D5
    description: "A slower older refresh response or error can never be applied after a faster newer response has already been applied"
    requirement: DIA-08
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_reverse_order_refresh_success_never_regresses_newer_evidence"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_reverse_order_refresh_failure_never_raises_a_superseded_warning"
        status: pass
      - kind: unit
        ref: "tests/test_advanced_ui.py#test_refresh_generation_guard_is_declared_in_the_advanced_controller"
        status: pass
    human_judgment: false
  - id: D6
    description: "Operator-facing confirmation on the target Pi that the advanced workspace now shows an open collection gap and a stale host as real exceptions rather than a normal summary"
    verification: []
    human_judgment: true
    rationale: "The value of this plan is whether an operator's trust in the snapshot is restored; that judgment cannot be made by an assertion, only by a person reading the workspace during a real gap."

duration: 21min
completed: 2026-08-18
status: complete
---

# Phase 03 Plan 07: Gap Closure (CR-01..CR-04, WR-01) Summary

**Open stream gaps are now synthesized and promoted, stale hosts raise their own exception, pending/stream truncation is sentinel-measured instead of length-inferred, and a superseded refresh response can no longer regress newer browser evidence.**

## Performance

- **Duration:** 21 min
- **Started:** 2026-08-18T19:04:00+03:00
- **Completed:** 2026-08-18T19:25:08+03:00
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- `compose_pipeline_diagnosis` gained a second synthesis pass that emits exactly one open, actionable gap item per stream carrying `open_gap_start_ts`, merged after (never in place of) coverage-derived evidence, so the existing exception-promotion loop surfaces it with no new logic.
- `compose_active_exceptions` gained `host` as a required first argument and a distinct `host_freshness` exception kind, closing the path where a missing or stale `system_stats` row could still be summarised as "reporting normally".
- `read_pipeline_evidence` now returns `streams_truncated` and `pending_truncated` measured from one sentinel row past each cap, replacing the `len(evidence['pending']) >= 32` inference that mislabelled exactly 32 rows as truncated and the streams read that had no truncation signal at all.
- The streams query ranks open-gap rows first, then rows stale relative to the bound `now` and their own cadence, then `stream_kind`/`stream_key`, so the 64-row cap can never drop actionable evidence in favour of quiet streams.
- `pipeline.streams` became `{items, count, truncated}` (matching `gaps`/`aggregation_pending`) and `advanced.js` renders the count/truncated disclosure instead of treating a capped list as complete.
- `refreshCurrentDiagnosis` captures a per-call id from a new monotonic `state.requestGeneration` and discards any response or error from a superseded generation on both branches.

## Task Commits

Each task was committed atomically (TDD: test → feat):

1. **Task 1 (tracer): Open collection gap end-to-end without a coverage row (CR-01)** - `ccc8755` (test), `1f3a986` (feat)
2. **Task 2: Host-freshness exception and sentinel-measured truncation (CR-02, CR-03, CR-04)** - `40bcc1b` (test), `54df711` (feat)
3. **Task 3: Refresh generation guard against reverse-order completion (WR-01)** - `2543a2c` (test), `087ded1` (feat)

## Files Created/Modified

- `dashboard/beacon/diagnosis.py` - Open-stream gap synthesis pass, `host_freshness` exception branch and new `host` parameter, `streams` returned as `{items, count, truncated}`, `aggregation_pending.truncated` sourced from the sentinel.
- `dashboard/beacon/repositories.py` - Normalized stream/pending limits, sentinel `cap+1` fetches with slice-back, new `streams_truncated`/`pending_truncated` keys, and the active-gap/stale-first stream `ORDER BY` bound to `now`.
- `dashboard/advanced.js` - `state.requestGeneration` counter, generation guards on both refresh branches, `pipeline.streams.items` read, and the `Streams (N streams, truncated)` heading disclosure.
- `tests/test_advanced_diagnosis_api.py` - `_seed_stream` helper plus open-gap synthesis/merge/isolation regressions, the missing/stale/fresh host matrix, and the 0/31/32/33 pending and 0/64/65 stream boundary regressions including stale-first ordering.
- `tests/test_advanced_ui.py` - Open-gap Pipeline/Overview rendering guard, streams-shape and truncation-disclosure coverage, the stale-host normal-copy regression, and the reverse-order success/failure regressions with a test-owned fetch-holding harness.

## Decisions Made

- **Open-gap synthesis is additive and appended, never sorted in.** `test_gap_truncation_uses_one_sentinel_beyond_the_response_cap` asserts an exact order over pure coverage fixtures; synthesized items go after that block in `stream_records` order, so the existing determinism is untouched.
- **The inferred truncation boolean was replaced, not supplemented.** Keeping `len(list) >= cap` alongside a sentinel would leave a provably wrong signal in the payload; the plan's assumption-delta decision to promote the sentinel was followed exactly.
- **`host_freshness` sits at priority 1 next to `worker_freshness` but is its own kind** (D-09), reuses the existing four-state vocabulary unchanged (D-10), and reports only the observed `state` with no inferred cause (D-11).
- **Reverse-order ordering was tested with test-owned `window.fetch` instrumentation** rather than by changing `advanced.js` or introducing an `AbortController`. The harness holds only the first in-flight request and releases it after a newer one has applied, which is the exact WR-01 hazard; the production controller still issues exactly one `fetch('/api/advanced/current', ...)` per refresh (asserted).

## Deviations from Plan

None - plan executed exactly as written. No deviation rule was triggered; no auto-fix, package install, or architectural change was required.

## Issues Encountered

- **The Task 1 Playwright test was green on arrival.** The plan called for it "RED first", but `addCollectionRegion`'s existing generic gap renderer already handled `open`/`actionable` items correctly, exactly as the plan's own `read_first` note predicted. It is therefore a regression guard rather than a driving test; the genuine RED for CR-01 came from the three API subtests (`0 != 1` on the synthesized item). No code was weakened to manufacture a failure.
- **Deferring the tracer's interactive human-verify gate.** `workflow.auto_advance` is `false`, which would normally stop the run for human verification of the tracer slice. The plan is marked `autonomous: true` and the project runs `human_verify_mode: end-of-phase`, so verification is collected at phase level rather than mid-plan. The tracer's automated `<verify>` and the full phase regression both passed end-to-end before any expansion task began, which is the substance the gate protects.
- **A closed historical coverage row on a stream that also has an open gap is still flagged `open: true`.** This is pre-existing behaviour of the coverage loop (`open_gap = bool(stream and stream.get('open_gap_start_ts') is not None)`), unchanged and explicitly out of scope for this plan, which only required the closed item's `start_ts`/`end_ts`/`reason`/`detail` to be preserved byte-identically. Recorded here so the next reviewer does not read it as introduced by this change.

## Known Stubs

None. No hardcoded empty collection, placeholder string, or unwired data source was introduced; every new payload field is populated from durable SQLite evidence and covered by a boundary-pinned test.

## Threat Flags

None. No new network endpoint, auth path, file access pattern, or schema object was introduced. All new SQL is fixed, module-owned, fully parameterized text (`now` and the limit are the only bound values), the endpoint remains GET-only, parameterless, `no-store`, and effect-free, and all new browser rendering continues to use `.textContent`/`.replaceChildren` only.

## Verification

- Task 1: `pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py -k "open_stream_gap or open_collection_gap or gap_truncation" -x` — 4 passed, 7 subtests passed.
- Task 2: `pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py -k "host_freshness or pending_truncation or stream_truncation or pipeline_and_settings" -x` — 8 passed, 18 subtests passed.
- Task 3: `pytest -q tests/test_advanced_ui.py -k "reverse_order or generation_guard" -x` — 3 passed.
- Phase regression: `pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py tests/test_module_boundaries.py` — 46 passed, 62 subtests passed.
- Full project gate: `pytest -q` — 263 passed, 306 subtests passed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All five open Phase 3 verification findings (CR-01, CR-02, CR-03, CR-04, WR-01) are closed with deterministic, boundary-pinned regressions; `TEL-06` and `DIA-08` are ready to move from BLOCKED to SATISFIED on re-verification, and `DIA-02`/`DIA-03` are strengthened rather than regressed.
- **Contract change for downstream consumers:** `pipeline.streams` is no longer a bare array. Any future reader must use `pipeline.streams.items`; the plan's single browser consumer was updated, and no other consumer exists in the repository.
- No blockers. The endpoint remains parameterless, GET-only, `no-store`, bounded, and effect-free, and no package, route, migration, column, table, or index was added.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-18*

## Self-Check: PASSED

All five modified source/test files and the SUMMARY exist on disk; all six task commits (`ccc8755`, `1f3a986`, `40bcc1b`, `54df711`, `2543a2c`, `087ded1`) are present in git history.
