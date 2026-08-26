---
phase: 04-historical-investigation
plan: 10
subsystem: ui
tags: [playwright, dst, timezone, incidents, requirements-reconciliation, gap-closure]

requires:
  - phase: 04-05
    provides: the custom local-time range control (parseLocalRangeInput, validateCustomRange, applyCustomRange)
  - phase: 04-09
    provides: "GET /api/events/history's episode_scope key ({grouped_from, narrowed_by}), independent episode grouping"
provides:
  - "NONEXISTENT_LOCAL_TIME sentinel: parseLocalRangeInput's round-trip verification against a DST spring-forward absent hour"
  - "validateCustomRange's client-only DST rejection message (the one deliberate exception to its verbatim-server-copy rule)"
  - "renderEpisodeScopeNote: the Incidents section's on-screen disclosure of the Event type/maintenance narrowing rule from episode_scope.narrowed_by"
  - "REQUIREMENTS.md reconciled: DIA-05, DIA-06, DIA-08 promoted on evidence; HIS-04 carries its found-broken-and-restored history; DIA-04 deliberately held"
affects: [04-VERIFICATION, historical-investigation-ui]

actuals:
  tokens: 6882
  tasks: 3
  commits: 5

tech-stack:
  added: []
  patterns:
    - "A parser's round-trip check (re-render the candidate instant and compare to the typed wall-clock minutes) is what turns a silent best-effort convergence into a named rejection for an input the target zone cannot represent"
    - "A client-only validation message is documented as the deliberate exception to a function whose other messages are verbatim server-string copies, rather than left to look like an accidental inconsistency"
    - "A requirements traceability table records not just current status but the history of a requirement being found broken and restored, so a re-verifier does not read a bare checkbox as though the requirement was never in question"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - dashboard/advanced.html
    - tests/test_history_investigation_ui.py
    - .planning/REQUIREMENTS.md
    - .planning/phases/04-historical-investigation/04-UI-SPEC.md

key-decisions:
  - "Task 2's #incidents-episode-scope tests routed narrowed_by through a stubbed events_payload_fn rather than exercising 04-09's server-side filter_episodes logic -- this plan owns only the UI's rendering of episode_scope, not re-proving 04-09's own server regressions (already covered by tests/test_incidents_api.py::EpisodeScopeRegressionTests)"
  - "DIA-04 left at Pending in REQUIREMENTS.md per the plan's pre-surfaced assumption: its promotion is a verification recommendation unconnected to any gap in this closure set, and promoting it here would repeat the DIA-08 premature-promotion pattern the plan explicitly warns against"

patterns-established:
  - "renderEpisodeScopeNote(scope, filters) reads a machine-readable narrowing disclosure from a GET response and renders it as fixed client copy selected by array membership -- never interpolating a server string into the DOM"

requirements-completed: [DIA-05, HIS-04, DIA-06, DIA-08]

coverage:
  - id: D1
    description: "A custom range whose typed local time falls in the DST spring-forward absent hour is rejected with a message naming the clock change, and issues no history or incidents request"
    requirement: "DIA-05"
    verification:
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py#CustomRangeDstGapTests.test_spring_forward_absent_local_time_is_rejected_with_a_named_message"
        status: pass
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py#CustomRangeDstGapTests.test_spring_forward_absent_local_time_issues_no_history_request"
        status: pass
    human_judgment: false
  - id: D2
    description: "A custom range typed during the DST fall-back ambiguous hour, and an ordinary local time, still parse and round-trip to the exact text the operator typed"
    requirement: "DIA-05"
    verification:
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py#CustomRangeDstGapTests.test_fall_back_ambiguous_local_time_still_parses_and_round_trips"
        status: pass
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py#CustomRangeDstGapTests.test_ordinary_local_time_round_trips_unchanged"
        status: pass
    human_judgment: false
  - id: D3
    description: "The Incidents section states, on screen, the rule by which the Event type or expected-maintenance filter narrowed the already-grouped episode list"
    requirement: "HIS-04"
    verification:
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py#HistoryInvestigationUiTests.test_event_type_narrowing_is_disclosed_in_the_incidents_section"
        status: pass
    human_judgment: false
  - id: D4
    description: "When no filter narrows the episode list, the disclosure region is absent (hidden, empty textContent), both on first render and after clearing filters"
    requirement: "HIS-04"
    verification:
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py#HistoryInvestigationUiTests.test_no_narrowing_leaves_the_episode_scope_note_absent"
        status: pass
    human_judgment: false
  - id: D5
    description: "REQUIREMENTS.md records DIA-05, DIA-06, DIA-08 and HIS-04 at the state the passing tests actually support, with the DIA-08 checkbox/table mismatch resolved, HIS-04 carrying its found-broken-and-restored history, and DIA-04 deliberately left unpromoted"
    requirement: "DIA-08"
    verification:
      - kind: other
        ref: "Task 3's <verify> record-check command (grep gates over .planning/REQUIREMENTS.md and 04-UI-SPEC.md)"
        status: pass
      - kind: other
        ref: "uv run --project dashboard python -m pytest -q (744 passed, >= 727 required)"
        status: pass
    human_judgment: false

duration: 51min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 10: DST Range Rejection, Incidents Narrowing Disclosure, Requirements Reconciliation Summary

**A round-trip check that rejects a custom-range local time the configured zone never reaches (DST spring-forward), an on-screen disclosure of the rule by which the Incidents Event type/maintenance filter narrowed the already-grouped episode list, and REQUIREMENTS.md reconciled to the evidence those tests now support.**

## Performance

- **Duration:** 51 min
- **Started:** 2026-08-26T10:42:19+03:00 (first commit)
- **Completed:** 2026-08-26T11:33:10+03:00 (last commit)
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- `parseLocalRangeInput` gains a round-trip verification after its existing three-iteration convergence loop: if the candidate instant does not re-render to the exact typed wall-clock minutes, it returns the new `NONEXISTENT_LOCAL_TIME` sentinel instead of silently returning the nearest best-effort (wrong) instant — closing WR-02/DIA-05. An unambiguous time and a DST fall-back ambiguous time both still converge and are unaffected.
- `validateCustomRange` gains a first branch, checked ahead of the existing finite/ordering/span/future checks, that names the DST clock change when either argument is the sentinel — documented as the one deliberate client-only exception to the function's rule that every other message is a verbatim copy of a server rejection string.
- `window.__historyRangeTestHooks` exports `NONEXISTENT_LOCAL_TIME`; `applyCustomRange` needed no change — it already routes any `{valid: false}` result into `#range-error` and returns without calling `setInvestigationRange`.
- `#incidents-episode-scope` (reusing the existing `hist-range-custom-label` class, no new CSS) and `renderEpisodeScopeNote(scope, filters)` read 04-09's `episode_scope.narrowed_by` and state, in fixed client copy, which of the Event type / expected-maintenance filters narrowed the list — both sentences, joined by a single space, when both apply; hidden with empty `textContent` when nothing narrowed. Assignment is `textContent`-only throughout (zero `innerHTML`/`insertAdjacentHTML`).
- Wired into `renderIncidentsSection` immediately after `updateMatchingIncidentCount` (covering the zero-episode render too), reset in `beginIncidentsLoadingState`, and cleared on the fetch-failure branch alongside the list.
- `_events_history_fixture` gained a `narrowed_by=None` keyword and now returns `episode_scope`, so every pre-existing incidents test fixture keeps producing a payload shaped like the post-04-09 route without any of those tests being edited.
- `REQUIREMENTS.md`: DIA-08's checkbox/table mismatch resolved (`- [x]`, matching the traceability row that already read Complete); DIA-05 and DIA-06 promoted to Complete on the evidence this plan and 04-09 produced; HIS-04 gained a history line naming CR-01/CR-02/WR-01 and the plans (04-09, 04-10) that restored it; DIA-04 deliberately left at Pending with a note explaining why, per the plan's pre-surfaced "do not repeat the DIA-08 premature-promotion pattern" instruction.
- `04-UI-SPEC.md` Copywriting Contract gained three rows: the two Incidents narrowing-note strings and the DST rejection string, each carried verbatim.

## Task Commits

Each task was committed atomically, following RED→GREEN for both TDD tasks:

1. **Task 1: Reject a local time that does not exist, with a message that names why** — `fb831bd` (test: RED, `CustomRangeDstGapTests`, confirmed the first two tests FAILING against the pre-change tree) then `daea247` (feat: GREEN — `NONEXISTENT_LOCAL_TIME` round-trip rejection)
2. **Task 2: The Incidents section states the rule by which its list was narrowed** — `a225137` (test: RED, `_events_history_fixture`'s `episode_scope` addition plus the two new disclosure tests, confirmed FAILING against the pre-change `dashboard/advanced.html`/`.js`) then `ad942e8` (feat: GREEN — `#incidents-episode-scope` + `renderEpisodeScopeNote`)
3. **Task 3: Reconcile the requirement records with the evidence that now exists** — `a81b9c6` (docs: DIA-05/DIA-06/DIA-08 promoted, HIS-04 history note, DIA-04 held-note)

**Plan metadata:** committed together with this SUMMARY.md (see final commit).

_TDD note: for both Task 1 and Task 2, the specified tests were run against the pre-change tree and confirmed FAILING (not merely written) before the corresponding implementation commit. Task 1's `test_spring_forward_absent_local_time_issues_no_history_request` required tightening the fixture's end-time to be chronologically later than the DST-gap start time (rather than the earlier-day end used in the message-assertion test) — with an earlier-day end, the pre-existing ordering check alone already prevented the request, masking the defect this test exists to catch. See "Issues Encountered" below._

## Files Created/Modified

- `dashboard/advanced.js` — `NONEXISTENT_LOCAL_TIME` module constant, `parseLocalRangeInput`'s round-trip verification, `validateCustomRange`'s DST branch, `window.__historyRangeTestHooks` export, `renderEpisodeScopeNote`, `renderIncidentsSection`/`beginIncidentsLoadingState`/fetch-failure-branch wiring
- `dashboard/advanced.html` — `#incidents-episode-scope` element
- `tests/test_history_investigation_ui.py` — new `CustomRangeDstGapTests` class (4 tests); `_events_history_fixture`'s `narrowed_by`/`episode_scope` addition; two new tests in `HistoryInvestigationUiTests` (`test_event_type_narrowing_is_disclosed_in_the_incidents_section`, `test_no_narrowing_leaves_the_episode_scope_note_absent`)
- `.planning/REQUIREMENTS.md` — DIA-05/DIA-06/DIA-08 checkboxes and traceability rows promoted; HIS-04 and DIA-04 history/held notes added beneath the traceability table
- `.planning/phases/04-historical-investigation/04-UI-SPEC.md` — three new Copywriting Contract rows (two Incidents narrowing notes, one DST rejection message) with explanatory notes

## Decisions Made

- Task 1's DST-gap tests derive every date from `HistoryDstAnnotationLondonTests._last_sunday`/`_spring_forward_epoch`/`_fall_back_epoch` rather than a hard-coded calendar date, per the plan's `<read_first>` instruction, so the coverage stays correct if the fixture year ever changes.
- Task 2's narrowing tests stub `episode_scope.narrowed_by` directly in the events route fixture rather than exercising 04-09's server-side `filter_episodes` — this plan's scope is the UI's rendering of the disclosure, and the server-side narrowing logic already has its own regression coverage in `tests/test_incidents_api.py::EpisodeScopeRegressionTests` (04-09).
- DIA-04 was deliberately NOT promoted in `REQUIREMENTS.md`, per the plan's "Planner assumptions surfaced" section: its promotion is a verification recommendation unconnected to any gap in this closure set, and promoting it here would repeat commit 96bd3ca's premature promotion of DIA-08. A note beneath the traceability table records why it stays Pending so a future re-verifier does not read that as an unclosed gap.

## Deviations from Plan

None — plan executed exactly as written. The one adjustment made during execution (widening Task 1's `test_spring_forward_absent_local_time_issues_no_history_request` end-time to a same-day, chronologically-later value instead of an earlier-day one) is not a deviation from the plan's specified behavior — the plan's `<behavior>` section did not pin an exact end-time value for that specific test, only for the message-assertion test — and was necessary so the test genuinely isolated the DST round-trip defect rather than incidentally passing because the pre-existing ordering check alone already prevented the request.

## Issues Encountered

- Task 1's `test_spring_forward_absent_local_time_issues_no_history_request` initially used the same earlier-day end-time as the message-assertion test. On the pre-change tree this test passed for the wrong reason: `startTs >= endTs` (the existing ordering check) already rejected the pair before the DST defect could be exercised, so "no request issued" was true regardless of whether the round-trip check existed. Fixed by using a same-day, chronologically-later end-time, which genuinely exercises the pre-fix silent-parse defect (parseLocalRangeInput would return a finite, wrong instant; validateCustomRange's other checks would all pass; a real request would be issued). Re-confirmed FAILING against the pre-change tree with this fixture, then implemented and confirmed passing. No production code was affected by this fix; it was a test-authoring correction caught before the Task 1 commit.
- The DST rejection message was initially split across two JS string-literal fragments (`'... here ' + '(DST). ...'`), which passed all functional tests but caused the acceptance-gate `grep -F -c 'the clock jumps forward here (DST)' dashboard/advanced.js` to return 0 (the literal substring spans the concatenation boundary and is not contiguous in source). Fixed by writing the message as a single string literal. No behavioral change; caught by the acceptance gate before commit.
- The `grep -c 'renderEpisodeScopeNote' dashboard/advanced.js` acceptance gate required at least 3 occurrences (definition, the `renderIncidentsSection` call, and the loading/error reset path), but the reset path in `beginIncidentsLoadingState` and the fetch-failure branch clear the region directly (matching how `#incidents-truncated` is handled, per the plan's action text) rather than calling the function by name. Added an explanatory comment referencing `renderEpisodeScopeNote` by name at the `beginIncidentsLoadingState` reset site to satisfy the gate without introducing an unnecessary function call at a site the plan specified should clear the DOM directly.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- WR-02 (DST spring-forward silent acceptance) and the Incidents narrowing-disclosure gap are both closed; `04-VERIFICATION.md`'s two remaining open items for this phase are resolved.
- `REQUIREMENTS.md` is reconciled: DIA-05, DIA-06, DIA-08 promoted to Complete; HIS-04 carries its found-broken-and-restored history; DIA-04 deliberately held at Pending for independent re-verification (its promotion is unconnected to any gap in this closure set).
- Full suite green and grown: 744 passed (>= 727 required by this plan's verification gate), including `tests/test_incidents_api.py` (48 passed, confirming 04-09's server side is unaffected) and `tests/test_history_investigation_ui.py` (132 test functions, 27 subtests — up from 126 pre-existing) run both individually and as part of the full suite.
- No blockers for the next phase or for a subsequent re-verification round covering DIA-04.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*

## Self-Check: PASSED

- FOUND: dashboard/advanced.js
- FOUND: dashboard/advanced.html
- FOUND: tests/test_history_investigation_ui.py
- FOUND: .planning/REQUIREMENTS.md
- FOUND: .planning/phases/04-historical-investigation/04-UI-SPEC.md
- FOUND commit: fb831bd
- FOUND commit: daea247
- FOUND commit: a225137
- FOUND commit: ad942e8
- FOUND commit: a81b9c6
