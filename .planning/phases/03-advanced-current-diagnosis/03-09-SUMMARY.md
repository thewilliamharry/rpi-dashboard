---
phase: 03-advanced-current-diagnosis
plan: 09
subsystem: advanced-current-diagnosis
tags: [ui, diagnosis, exceptions, operator-copy, sort-persistence, gap-closure]
status: complete

requires:
  - "dashboard/beacon/diagnosis.py::compose_active_exceptions (the ten emitted kinds, as left by 03-08)"
  - "dashboard/beacon/diagnosis.py::gap_exception_kind / coverage_unknown (03-08)"
  - ".planning/phases/03-advanced-current-diagnosis/03-REVIEW.md WR-03, WR-08 client half, WR-09, WR-10"
provides:
  - "dashboard/advanced.js::EXCEPTION_COPY — kind-to-copy map covering all ten emitted kinds"
  - "dashboard/advanced.js::exceptionCopy(item) — {title, evidence} with an explicit unrecognised-kind branch"
  - "dashboard/advanced.js::renderRefreshError(reason) — contracted copy plus a server-supplied reason"
  - "dashboard/advanced.js::serverSuppliedReason(error) — only apiFetch's own thrown Error reaches the operator"
  - "A service sort that survives automatic polling and Refresh now"
  - "A guarded selectSection that validates the heading before any visibility mutation"
affects:
  - "plan 03-10 supplies the 503 maintenance body that now renders its own reason"
  - "03-UI-SPEC.md Service diagnosis sort-persistence sentence reconciled with shipped behaviour"

tech-stack:
  added: []
  patterns:
    - "Kind-to-copy projection held in a Map so a server kind can never resolve through Object.prototype"
    - "Server-supplied strings are composed into copy and written only through textContent"
    - "Validate-before-mutate: resolve the target element first, return early, then mutate visibility"
    - "Operator intent (sort, filters, expansion) is memory-only state a render pass must not overwrite"

key-files:
  created:
    - .planning/phases/03-advanced-current-diagnosis/deferred-items.md
  modified:
    - dashboard/advanced.js
    - tests/test_advanced_ui.py
    - .planning/phases/03-advanced-current-diagnosis/03-UI-SPEC.md

key-decisions:
  - "EXCEPTION_COPY is the sole source of exception card text; item.label and item.evidence are deleted, and an unrecognised kind renders an explicit counted card rather than being dropped"
  - "EXCEPTION_COPY is a Map rather than an object literal so a kind such as 'constructor' cannot resolve through Object.prototype to a truthy non-builder"
  - "The service sort survives every refresh and is cleared only by Reset operational order or Clear all filters; it stays session-local because D-14 does not list it among the persisted preferences"
  - "Only a reason apiFetch itself threw (a plain Error) is appended to the contracted refresh-error copy; browser-raised TypeError/SyntaxError failures are never surfaced"
  - "The UI-SPEC refresh clause was amended rather than left contradicting the shipped and verified behaviour"

requirements-completed: []
requirements-declared: [TEL-06, DIA-03, DIA-08]

coverage:
  - deliverable: "Every emitted exception kind renders operator copy naming its host, service, stream or job"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_every_emitted_exception_kind_renders_operator_copy"
        status: pass
  - deliverable: "coverage_unknown states that coverage could not be determined and is never worded as a collection failure"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_indeterminate_coverage_exception_is_never_worded_as_a_failure"
        status: pass
  - deliverable: "An unrecognised kind renders a visible card, is counted, and does not suppress the other cards"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_unrecognised_exception_kind_still_renders_and_is_counted"
        status: pass
  - deliverable: "With zero exceptions the contracted empty copy renders verbatim, and never renders while an exception is present"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_workspace_sections_overview_and_host_states"
        status: pass
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_open_stream_gap_renders_as_pipeline_and_overview_evidence"
        status: pass
  - deliverable: "A non-ok JSON body carrying an error field names that reason beside the contracted retained-data copy"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_refresh_error_names_the_server_supplied_reason"
        status: pass
  - deliverable: "A chosen service sort survives an automatic poll and Refresh now, with aria-sort and the reset control consistent"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_service_sort_survives_automatic_poll_and_manual_refresh"
        status: pass
  - deliverable: "Both deliberate clearing paths still clear the sort, and no sort key enters the persisted preferences"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_deliberate_controls_still_clear_the_service_sort"
        status: pass
  - deliverable: "An unrecognised section value neither hides every section nor raises, while a valid one still focuses its heading"
    human_judgment: false
    verification:
      - kind: browser
        ref: "tests/test_advanced_ui.py#test_unknown_section_value_never_blanks_the_workspace"
        status: pass
  - deliverable: "The bundle stays same-origin, GET-only and textContent-only after the new copy is added"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_ui.py#test_advanced_controller_tracer_is_same_origin_get_only_and_text_safe"
        status: pass
      - kind: test
        ref: "tests/test_advanced_ui.py#test_refresh_generation_guard_is_declared_in_the_advanced_controller"
        status: pass
  - deliverable: "On the target Pi, exception cards read as sentences and a chosen sort is still applied after two poll cycles"
    human_judgment: true
    rationale: "Carried forward from 03-VERIFICATION.md human_verification item 1; operator trust in the rendered snapshot on real hardware cannot be asserted programmatically. Collected at phase level (human_verify_mode: end-of-phase)."

metrics:
  duration: "10 min"
  completed: 2026-08-18
  tasks: 2
  files_modified: 3

actuals:
  tokens: 7500
  tasks: 2
  commits: 4
---

# Phase 03 Plan 09: Operator-Readable Exceptions and Durable Operator State Summary

The Overview exception list now reads as sentences about the operator's Pi instead of raw kind identifiers over an `Unknown evidence` placeholder, and the workspace no longer discards the operator's chosen sort or blanks itself on an unrecognised section value.

## Accomplishments

- **WR-09 closed** — `EXCEPTION_COPY` (a `Map`) plus `exceptionCopy(item)` project each of the ten kinds `compose_active_exceptions` emits into a `{title, evidence}` pair built only from the fields that kind actually carries. The two dead fallback reads (`item.label`, `item.evidence`) are deleted; neither string appears anywhere in `dashboard/advanced.js` any more.
- **`coverage_unknown` is legible and is not a fault claim** — plan 03-08's new kind renders as `Coverage could not be determined — host: ram` with evidence stating that coverage could not be determined for the interval and that this is recorded coverage evidence, not a confirmed fault. A regression asserts the card text contains none of `gap`, `fail`, `lost`, or `missing`, so the wording cannot drift into asserting a cause (D-11).
- **An unknown kind is visible, not silent** — an exception whose `kind` is absent from the map renders `Unrecognised exception — {kind}`, names the kind, points at the owning section, and is included in the `N active exceptions` count. A `Map` is used deliberately: with an object literal, a kind of `constructor` or `toString` would have resolved to a truthy non-builder through `Object.prototype`.
- **WR-03 closed** — the `state.serviceSort = null` statement is gone from the success path of `refreshCurrentDiagnosis`. The two deliberate clearing controls (`reset-service-order`, `clear-service-filters`) are the only remaining paths, and the sort stays memory-only: `beacon-advanced-preferences-v1` keeps exactly its prior key set.
- **WR-10 closed** — `selectSection` resolves `{section}-heading` and returns before `state.activeSection`, any `aria-selected`, or any `hidden` mutation. The regression drives a server-supplied `section` of `nowhere`, asserts zero page errors, and asserts the workspace stays rendered with Overview still selected — before proving a valid section still hides the others and focuses its heading.
- **WR-08 client half closed** — `renderRefreshError(reason)` appends `Server reported: {reason}` after the contracted retained-data sentence. `serverSuppliedReason` admits only a plain `Error` (what `apiFetch` itself throws, carrying the server's structured `error` field or its bounded status line); a browser-raised `TypeError` from the network or `SyntaxError` from an unparseable body is discarded, satisfying T-03-55 without touching `apiFetch`.
- **The UI-SPEC no longer contradicts the shipped behaviour** — the one "Service diagnosis" bullet that listed "the table is refreshed" as a sort-superseding event now reads that a user sort persists until filters are cleared or `Reset operational order` is chosen, and that neither an automatic poll nor `Refresh now` clears it. Exactly one bullet changed (1 insertion, 1 deletion).

## Task Commits

| Task | Gate | Commit | Message |
|------|------|--------|---------|
| 1 | RED | `9f6d1fa` | test(03-09): add failing operator-copy and refresh-reason regressions |
| 1 | GREEN | `c2d8af5` | feat(03-09): give every exception kind operator copy and name refresh causes |
| 2 | RED | `46d402a` | test(03-09): add failing sort-survival and unknown-section regressions |
| 2 | GREEN | `fe474fd` | feat(03-09): preserve the operator sort across refresh and guard selectSection |

No REFACTOR commit was needed — both GREEN changes were minimal and in their final shape.

## Verification Results

| Command | Result |
|---------|--------|
| Task 1 (`-k "exception or overview or refresh_error or text_safe"`) | 9 passed, 44 subtests passed |
| Task 2 (`-k "sort or section or filters or reverse_order"`) | 7 passed |
| Phase regression (`test_advanced_diagnosis_api.py test_advanced_ui.py test_module_boundaries.py`) | 63 passed, 118 subtests passed |
| Full project gate (`pytest -q`) | **277 passed, 362 subtests passed** (270 before this plan) |

RED gates were proven by real failures, not by absence:

- Task 1 RED: 7 test methods failed, including 20 subtest failures where every card heading was still the bare kind identifier (`recovery_required`, `host_freshness`, … `database_pressure`).
- Task 2 RED: the sort regression failed immediately after the automatic poll (`':80' not found`), and the section regression failed with the exact WR-10 defect — `Cannot read properties of null (reading 'focus')` raised as an uncaught page error.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] A third existing regression depended on the dead `label` field**

- **Found during:** Task 1
- **Issue:** `test_workspace_loading_and_partial_overview_use_truthful_evidence` (line ~249) drove a fixture with `{'kind': 'service', 'label': 'Critical web service down'}` and `{'kind': 'stream', 'label': ...}` — kinds and a field the server never emits — and asserted the `label` text appeared in the Overview. The plan's `<read_first>` named only the two regressions at lines 540-580 and 585-630, so this one would have blocked the acceptance criterion "`item.label` … no longer read anywhere".
- **Fix:** the fixture now uses two real emitted kinds (`critical_service_offline` and an open `collection_gap` whose `stream_key` is the same long overflow string), and the assertions check the corresponding operator copy. The test's original purpose — 2 exceptions, long-text overflow at 360px, `Unknown` summaries, and the partial-data copy — is preserved intact.
- **Files modified:** `tests/test_advanced_ui.py`
- **Commit:** `9f6d1fa`

**2. [Rule 2 - Correctness] `EXCEPTION_COPY` is a `Map`, not the object literal the plan's wording implied**

- **Found during:** Task 1
- **Issue:** With an object literal, `EXCEPTION_COPY[item.kind]` for a server-supplied kind of `constructor`, `toString`, or `valueOf` resolves through `Object.prototype` to a truthy function that is not a copy builder, producing a card with `undefined` title and evidence instead of the intended unrecognised-exception card.
- **Fix:** the map is a `Map` and lookup is `EXCEPTION_COPY.get(kind)`, which has no prototype chain. The artifact string `EXCEPTION_COPY` required by the plan's `must_haves` is unchanged.
- **Files modified:** `dashboard/advanced.js`
- **Commit:** `c2d8af5`

### Adjustments within plan scope

- **Task 2 fixture column.** The sort-survival regressions were first written against the latency column and were switched to `duration`, because the fixture's offline service carries `latency_ms: null` and `Number(null)` is `0`, which sorted it first ascending and made the assertion unable to distinguish operational order from sorted order. The `duration` column exercises the identical code path (`stableServiceSort`, `syncServiceSortControls`, `#reset-service-order`) with a fixture whose sorted order genuinely differs from operational order. The pre-existing latency assertion in `test_services_filters_sort_and_multi_disclosure_contract` was left untouched.
- **Section-link locators.** The new section regression's `a:has-text("View host")` locator matched both the exception card link and the Host summary card link, so it is scoped to `#overview-content > section a` — the exception region only.

## Deferred Issues

Logged to `.planning/phases/03-advanced-current-diagnosis/deferred-items.md`, not fixed:

- A service whose `latency_ms` is `null` renders as `0 ms` and sorts as the fastest service, because `Number(null)` is `0` and passes `Number.isFinite`. Pre-existing behaviour in `renderServices` and `stableServiceSort`'s latency branch; outside the file regions this gap-closure plan touches, and it belongs with the service-table presentation work from 03-02/03-04.

## Authentication Gates

None encountered.

## Issues Encountered

None beyond the deviations recorded above.

## Known Stubs

None. No placeholder, TODO, FIXME, hardcoded-empty value, or unwired data source was introduced. Every new string is composed from a field the server actually supplies, and the only remaining `Unknown` renderings come from the pre-existing `displayValue`/`displayTimestamp` helpers reporting genuinely absent evidence.

## Threat Flags

None. No new endpoint, route, request, storage key, auth path, file access pattern, or schema change was introduced. The plan's mitigate dispositions each have executable evidence:

| Threat | Mitigation evidence |
|--------|---------------------|
| T-03-51 (Spoofing — raw identifier as safety evidence) | `test_every_emitted_exception_kind_renders_operator_copy` (10 kinds, per-kind subtests) + `test_unrecognised_exception_kind_still_renders_and_is_counted` |
| T-03-52 (Denial of Service — unguarded section dereference) | `test_unknown_section_value_never_blanks_the_workspace` asserts zero page errors and a still-rendered workspace |
| T-03-53 (Tampering — per-poll reset of operator sort) | `test_service_sort_survives_automatic_poll_and_manual_refresh` + `test_deliberate_controls_still_clear_the_service_sort` |
| T-03-54 (XSS via rendered server strings) | `test_advanced_controller_tracer_is_same_origin_get_only_and_text_safe` still passes; every new write is `textContent` and no `innerHTML` path exists |
| T-03-55 (Information Disclosure via error reason) | `serverSuppliedReason` admits only a plain `Error` from `apiFetch`; `TypeError`/`SyntaxError` are discarded |
| T-03-56 (Supply chain) | No dependency added, removed, or upgraded; the bundle is still dependency-free vanilla JavaScript |

## Follow-ups for Later Plans

- Plan 03-10 supplies the 503 maintenance body whose `error` field this plan's refresh-error region now renders.
- `TEL-06`, `DIA-03` and `DIA-08` remain unmarked in REQUIREMENTS.md: plan 03-10 also declares all three and has no SUMMARY yet, so they become eligible only when the last declaring plan finishes.
- The carried-forward human verification (real gap plus stale host plus a chosen sort held across two poll cycles on the target Pi) is collected at phase level per `workflow.human_verify_mode: end-of-phase`.

## Next

Ready for 03-10.

## Self-Check: PASSED

- Modified files verified present on disk: `dashboard/advanced.js`, `tests/test_advanced_ui.py`, `.planning/phases/03-advanced-current-diagnosis/03-UI-SPEC.md`; created `deferred-items.md` present.
- All four task commits verified present in `git log`: `9f6d1fa`, `c2d8af5`, `46d402a`, `fe474fd`.
- Required artifact strings verified: `EXCEPTION_COPY` in `dashboard/advanced.js`, `EXCEPTION` in `tests/test_advanced_ui.py`, `Reset operational order` in `03-UI-SPEC.md`.
- `grep -n "item.label\|item.evidence" dashboard/advanced.js` returns nothing; `state.serviceSort = null` remains at exactly the two deliberate control handlers.
- `node --check dashboard/advanced.js` passes; all task `<acceptance_criteria>` re-run and passing; full project gate green at 277 passed.
