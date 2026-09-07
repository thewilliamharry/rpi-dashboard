---
phase: 03-advanced-current-diagnosis
plan: 08
subsystem: advanced-current-diagnosis
tags: [diagnosis, telemetry-coverage, exceptions, truncation, gap-closure]
status: complete

requires:
  - "dashboard/beacon/repositories.py::read_pipeline_evidence (bounded pipeline read)"
  - "dashboard/beacon/migrations.py telemetry_coverage / telemetry_streams DDL"
  - ".planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md (three BLOCKER gaps)"
provides:
  - "Per-row gap openness: coverage-derived items are never open"
  - "GAP_REASON_EXCEPTION_KINDS / gap_exception_kind reason-to-kind mapping"
  - "coverage_unknown operator-facing exception kind"
  - "read_pipeline_evidence gaps_limit + open_gap_streams_truncated disclosure keys"
  - "pipeline.gaps.count and pipeline.gaps.truncated over one bounded population"
  - "SCHEMA_VERSION 2"
affects:
  - "dashboard/advanced.js (renders the new coverage_unknown kind as a raw identifier until 03-09 gives it copy)"
  - "plans 03-09 and 03-10 build on this payload"

tech-stack:
  added: []
  patterns:
    - "Service/read-model assembler (diagnosis.py) owns presentation meaning; repository owns bounds"
    - "Sentinel-measured truncation booleans derived beside the ORDER BY that makes them sound"
    - "Stable priority sort preserves the durable read order between equal-priority items"

key-files:
  created: []
  modified:
    - dashboard/beacon/diagnosis.py
    - dashboard/beacon/repositories.py
    - tests/test_advanced_diagnosis_api.py
    - tests/test_advanced_ui.py

key-decisions:
  - "Coverage-derived gap items report open=false unconditionally; only the telemetry_streams synthesis pass may emit open=true"
  - "Each telemetry_coverage reason maps to exactly one outcome; an unrecognised reason surfaces as coverage_unknown"
  - "The gaps disclosure consumes the narrow open_gap_streams_truncated predicate, never the broad streams_truncated"
  - "The combined coverage+synthesized list is bounded to the durable read's own gaps_limit rather than being split into a second typed field"

requirements-completed: []
requirements-declared: [TEL-06, DIA-08]

coverage:
  - deliverable: "A persisted coverage row is never labelled open, regardless of its stream's open_gap_start_ts"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_persisted_coverage_rows_are_never_open_regardless_of_stream_state"
        status: pass
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_open_stream_gap_is_synthesized_merged_and_promoted"
        status: pass
  - deliverable: "Resolved and retention-expired intervals stay visible as Pipeline history and stop inflating Active Exceptions"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_resolved_history_never_renders_as_an_open_collection_gap"
        status: pass
  - deliverable: "Recent-window actionability boundary is exact"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_persisted_coverage_actionability_boundary_is_the_recent_window"
        status: pass
  - deliverable: "Each durable coverage reason maps to its own exception kind or to no exception"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_coverage_reason_maps_to_its_own_exception_kind"
        status: pass
  - deliverable: "An out-of-enum reason surfaces as coverage_unknown, never dropped nor reported as a collection failure"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_coverage_reason_outside_the_durable_enum_surfaces_as_indeterminate"
        status: pass
  - deliverable: "gaps.count and gaps.truncated describe one bounded population, in both directions"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_gap_count_and_truncated_describe_the_same_population"
        status: pass
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_gap_truncation_uses_one_sentinel_beyond_the_response_cap"
        status: pass
  - deliverable: "Gap items sort open-first then actionable-first, stably"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_gap_ordering_puts_open_and_actionable_evidence_first"
        status: pass
  - deliverable: "The API advertises the contract version it actually is (schema_version 2)"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_host_tracer_returns_one_current_snapshot_with_server_freshness"
        status: pass
  - deliverable: "On the target Pi, a real open gap and a stale host read as correctly labelled exceptions while no resolved or expired interval reads as an open actionable gap"
    human_judgment: true
    rationale: "Carried forward from 03-VERIFICATION.md human_verification item 1; operator trust in the rendered snapshot on real hardware cannot be asserted programmatically. Collected at phase level (human_verify_mode: end-of-phase)."

metrics:
  duration: "12 min"
  completed: 2026-08-18
  tasks: 3
  files_modified: 4

actuals:
  tokens: 9800
  tasks: 3
  commits: 6
---

# Phase 03 Plan 08: Per-Row Gap Truthfulness and Same-Population Bounding Summary

Every `open`, `actionable`, and `kind` label on `pipeline.gaps` is now derivable from the durable row it describes, and the gaps disclosure is bounded so its completeness claim is true in both directions.

## Accomplishments

- **Blocker 1 closed** — `compose_pipeline_diagnosis`'s coverage loop no longer borrows the stream's `open_gap_start_ts`. A persisted `telemetry_coverage` row is a closed interval by construction (its DDL enforces `end_ts > start_ts` and rows are written only once bounded), so coverage-derived items now report `open: False` unconditionally and `actionable` from their own recency alone. The 03-07 synthesis pass over `telemetry_streams` remains the sole producer of `open: True`.
- **Blocker 1b closed (WR-06)** — the test at `tests/test_advanced_diagnosis_api.py` that asserted the defect was corrected rather than preserved: the historical-row assertion now also asserts `open is False` and `actionable is False`, and the exception-count assertion moved from `1 + len(coverage)` to `1`.
- **Blocker 2 closed** — `GAP_REASON_EXCEPTION_KINDS`, `UNMAPPED_GAP_EXCEPTION_KIND`, and `gap_exception_kind(reason)` replace the hard-coded `'collection_gap'` promotion kind. `collection_gap` promotes as itself, `unknown` promotes as the new `coverage_unknown` kind, `expired` and `not_yet_monitored` are lifecycle evidence that is never actionable and never promoted, and a reason outside the migrations CHECK enum surfaces as `coverage_unknown`.
- **Blocker 3 closed (with WR-02 and WR-04)** — `read_pipeline_evidence` now returns `gaps_limit` and the narrow `open_gap_streams_truncated`; the composer stably sorts the combined list open-first then actionable-first, slices it to `gaps_limit`, reports `count` over the slice, and ORs three truthful truncation facts. `SCHEMA_VERSION` is now `2`.
- **The mirror defect (T-03-47) is prevented, not just the original** — the gaps disclosure consumes `open_gap_streams_truncated`, never the broad `streams_truncated`, so 65 streams of which only two carry an open gap plus 5 coverage rows returns all 7 items with `truncated: false`, while `pipeline.streams.truncated` still correctly reports `true`.

## Task Commits

| Task | Gate | Commit | Message |
|------|------|--------|---------|
| 1 | RED | `0ce577c` | test(03-08): add failing per-row gap truthfulness regressions |
| 1 | GREEN | `eb353af` | feat(03-08): derive gap openness per coverage row, never from the stream |
| 2 | RED | `6640f9a` | test(03-08): add failing coverage-reason exception-kind regressions |
| 2 | GREEN | `99f6983` | feat(03-08): map each coverage reason to its own exception kind |
| 3 | RED | `9e39289` | test(03-08): add failing same-population gap bounding and ordering regressions |
| 3 | GREEN | `601fbab` | feat(03-08): bound gaps.count and gaps.truncated to one population |

No REFACTOR commit was needed — each GREEN change was already minimal and in its final shape.

## Verification Results

| Command | Result |
|---------|--------|
| Task 1 tracer (`-k "open_stream_gap or persisted_coverage or gap_truncation or open_collection_gap"`) | 7 passed, 11 subtests passed |
| Task 2 (`-k "coverage_reason or persisted_coverage or open_stream_gap"`) | 6 passed, 11 subtests passed |
| Task 3 (`-k "same_population or gap_truncation or open_stream_gap or gap_ordering or tracer"`) | 11 passed, 18 subtests passed |
| Phase regression (`test_advanced_diagnosis_api.py test_advanced_ui.py test_module_boundaries.py`) | 54 passed, 70 subtests passed |
| Full project gate (`pytest -q`) | **270 passed, 318 subtests passed** |

The verifier's own reproduction shapes are reproduced as regressions, not proxies:

- One open-gap stream + a `collection_gap` row resolved 30 days ago + a retention-expired row on the same stream → exactly one `open: true` item and exactly one `collection_gap` exception (was three open + three exceptions).
- 65 open-gap streams, zero coverage rows → `truncated: true`, `count` ≤ 48 (was `truncated: false`, `count: 64`).
- 64 open-gap streams + 60 coverage rows → `count` ≤ 48 with every returned item `open: true` (was `count: 112`).

## Deviations from Plan

None - plan executed exactly as written.

## TDD Gate Compliance

All three tasks followed RED → GREEN with the RED gate proven by a real failure before implementation:

- Task 1 RED failed with `AssertionError: 3 != 1` (three items reported `open`) plus the corrected subtest failing.
- Task 2 RED failed with `AttributeError: module 'dashboard.beacon.diagnosis' has no attribute 'gap_exception_kind'` plus three failing reason subtests.
- Task 3 RED failed on both verifier reproduction shapes, the ordering regression, and the `schema_version` assertion.

Two tests specified in the plan's `<behavior>` blocks were **contract locks rather than RED drivers** and passed on arrival, which is expected and is how the plan classified them (they are written as `Boundary:` / renderer assertions, not `RED first:`):

- `test_persisted_coverage_actionability_boundary_is_the_recent_window` guards the existing `recent_window` edge, which Task 1 deliberately preserved.
- `test_resolved_history_never_renders_as_an_open_collection_gap` drives a fixed fixture payload through Playwright, so it exercises `advanced.js`'s already-correct generic gap renderer. Its value is locking the operator-facing copy (`Open actionable gap.` vs `Resolved historical gap.`) against future renderer drift, and proving end-to-end that the corrected server flags produce the right DOM.

## Authentication Gates

None encountered.

## Issues Encountered

None.

## Known Stubs

None. No placeholder, TODO, or hardcoded-empty value was introduced; a grep for stub markers over both modified source files returns nothing.

## Threat Flags

None. No new network endpoint, auth path, file access pattern, or schema change at a trust boundary was introduced. The plan's three high-severity threats each have executable mitigations:

| Threat | Mitigation evidence |
|--------|---------------------|
| T-03-41 (Tampering — stream fact overwriting a row fact) | `test_persisted_coverage_rows_are_never_open_regardless_of_stream_state` + the Playwright render regression |
| T-03-42 (Spoofing — a lifecycle reason reported as a collection failure) | `test_coverage_reason_maps_to_its_own_exception_kind` + the out-of-enum unit regression |
| T-03-43 (Information Disclosure — false completeness claim) | `test_gap_count_and_truncated_describe_the_same_population` (both verifier shapes) |
| T-03-47 (Spoofing — false *incompleteness* claim) | The `sixty_five_streams_with_only_two_open_gaps` subtest asserts all 7 items returned with `truncated: false` |

## Follow-ups for Later Plans

- `coverage_unknown` currently renders in the Overview exception list as the raw identifier, exactly as `collection_gap` already did. Plan 03-09 owns the operator copy for both (this is the plan's own stated sequencing, not an omission here).
- `TEL-06` and `DIA-08` remain unmarked in REQUIREMENTS.md: `requirements.ready-ids` reports `0/2 ready` because plans 03-09 and 03-10 also declare both IDs and have no SUMMARY yet. They become eligible when the last declaring plan finishes.
- The carried-forward human verification (open gap + stale host on the target Pi) is collected at phase level per `workflow.human_verify_mode: end-of-phase`.

## Next

Ready for 03-09.

## Self-Check: PASSED

- Modified files verified present on disk: `dashboard/beacon/diagnosis.py`, `dashboard/beacon/repositories.py`, `tests/test_advanced_diagnosis_api.py`, `tests/test_advanced_ui.py`.
- All six task commits verified present in `git log`: `0ce577c`, `eb353af`, `6640f9a`, `99f6983`, `9e39289`, `601fbab`.
- Required artifact strings verified: `coverage_unknown` in `diagnosis.py` and `test_advanced_diagnosis_api.py`; `gaps_limit` in `repositories.py`; `Resolved` in `test_advanced_ui.py`.
- `dashboard/advanced.js` confirmed unmodified; no migration, column, table, index, route, query parameter, or package was added.
- All task `<acceptance_criteria>` re-run and passing; full project gate green at 270 passed.
