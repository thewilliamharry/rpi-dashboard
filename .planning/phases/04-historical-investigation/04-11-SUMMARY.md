---
phase: 04-historical-investigation
plan: 11
subsystem: ui
tags: [gap-closure, incidents, candour, requirements-reconciliation]

requires:
  - phase: 04-07
    provides: "renderIncidentsSection, updateMatchingIncidentCount, the Incidents section's filtered/baseline parallel-fetch shape"
  - phase: 04-09
    provides: "episode_scope disclosure and independent episode-grouping this plan's tests build fixtures on"
provides:
  - "updateMatchingIncidentCount(matching, total): total: number | null, with null rendering the unknown-total state and never colliding with a real 0 count"
  - "renderIncidentsSection's explicit totalKnown flag, replacing the silent filtered-count fallback"
  - "the 04-REVIEW.md IN-01 regression plus its recovery case"
  - "the Copywriting Contract row and E4 UI Considerations clause for the unknown-total state"
  - "DIA-04 promoted to Complete on 04-VERIFICATION.md's cited evidence; HIS-04's note names WR-01 (new) and its closure"
affects: [04-VERIFICATION, historical-investigation-ui]

actuals:
  tokens: 5086
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns:
    - "A null total (never a sentinel number or 0) is what keeps an absent value type-distinguishable from a real, meaningful zero count in the same UI element"
    - "Both branches of a two-state render write both the text and the state attribute on every call, so a previous render's state can never survive into a later one"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - tests/test_history_investigation_ui.py
    - .planning/phases/04-historical-investigation/04-UI-SPEC.md
    - .planning/REQUIREMENTS.md

key-decisions:
  - "No retry on a failed baseline fetch (04-REVIEW.md's alternative suggestion) — a retry adds load against an already-degraded server and a second failure still needs an honest render; disclosure is the whole fix (plan's own pre-surfaced assumption 4)"
  - "data-total-known is a DOM state attribute, not just changed copy — gives the regression a state assertion independent of exact wording and gives Phase 5 a styling hook without a new DOM element"

patterns-established:
  - "updateMatchingIncidentCount(matching, total: number | null) — null means 'Beacon does not have this number', never zero; both render branches write text and dataset.totalKnown together so no partial-state render is possible"

requirements-completed: [HIS-04, DIA-04]

coverage:
  - id: D1
    description: "A failed unfiltered baseline request with an active incident filter renders '{N} of ? incidents (total unavailable)' and data-total-known=\"false\" instead of the misleading '{N} of {N} incidents'; the filtered list still renders in full with no error banner"
    requirement: "HIS-04"
    verification:
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total"
        status: pass
    human_judgment: false
  - id: D2
    description: "A recovered baseline fetch restores a known total and data-total-known=\"true\"; the unknown-total state is per-render, never persistent"
    requirement: "HIS-04"
    verification:
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_recovered_baseline_fetch_restores_a_known_total"
        status: pass
    human_judgment: false
  - id: D3
    description: "Both requests succeeding still renders the unchanged '{N} of {M} incidents' — the fix adds no standing caveat on the ordinary path"
    requirement: "HIS-04"
    verification:
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_incident_criticality_filter_issues_request_and_narrows_count"
        status: pass
      - kind: automated_ui
        ref: "tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_zero_match_incidents_renders_empty_copy_and_matching_count"
        status: pass
    human_judgment: false
  - id: D4
    description: "04-UI-SPEC.md's Copywriting Contract carries the unknown-total copy verbatim and E4's partial category names the failed-baseline state"
    verification:
      - kind: other
        ref: "Task 2's <verify> record-check command (grep gates over 04-UI-SPEC.md)"
        status: pass
    human_judgment: false
  - id: D5
    description: "REQUIREMENTS.md records DIA-04 Complete with its hold discharged and evidence cited, and HIS-04's note names the WR-01 (new) finding, its closure, and the pinning regression test"
    requirement: "DIA-04"
    verification:
      - kind: other
        ref: "Task 3's <verify> record-check command (grep gates over REQUIREMENTS.md)"
        status: pass
      - kind: other
        ref: "uv run --project dashboard python -m pytest -q (746 passed, 499 subtests passed, >= 746 required)"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 11: Baseline-Fetch-Failure Candour, Copywriting Contract, Requirements Reconciliation Summary

**An explicit `totalKnown` flag replaces `renderIncidentsSection`'s silent filtered-count fallback so a failed unfiltered baseline read renders `"N of ? incidents (total unavailable)"` instead of a misleading `"N of N incidents"`, closing 04-VERIFICATION.md's one remaining gap and promoting DIA-04 on its cited evidence.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-08-26T17:53:14+03:00 (first commit)
- **Completed:** 2026-08-26T18:01:14+03:00 (last commit)
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- `updateMatchingIncidentCount(matching, total)` now accepts `total: number | null`. `null` renders `"{matching} of ? incidents (total unavailable)"` and sets `dataset.totalKnown = 'false'`; any other value keeps the unchanged `"{matching} of {total} incidents"` and sets `dataset.totalKnown = 'true'`. Both branches always write both the text and the attribute, so a previous render's uncertainty can never survive into a later successful one, and `0` (a real matched count) never collapses into the absent-value state.
- `renderIncidentsSection` derives `total` from an explicit `totalKnown` const (the baseline outcome being `fulfilled` with an array `episodes` list) instead of falling back to the filtered list's own length — the exact silent substitution 04-REVIEW.md's WR-01 (new) and 04-VERIFICATION.md's single open gap identified.
- `_incidents_route`'s new `events_failure_fn` keyword lets a test fail one of the two parallel `/api/events/history` requests (filtered vs. unfiltered baseline) independently of the other via a predicate over the parsed query dict — every pre-existing caller omits it and is unaffected.
- Two new regressions on `HistoryInvestigationUiTests`: `test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total` (04-REVIEW.md IN-01) and `test_recovered_baseline_fetch_restores_a_known_total`.
- `04-UI-SPEC.md`'s Copywriting Contract gained the `Incidents matching-count — unfiltered total unavailable` row, and the E4 UI Considerations row now names the failed-baseline read as the `partial` category's covered case.
- `REQUIREMENTS.md`: DIA-04 promoted to Complete (checkbox + traceability row), its 04-10 hold rewritten to record the discharge with 04-VERIFICATION.md's cited evidence; HIS-04's note appended (not overwritten) to name the WR-01 (new) finding, its closure by this plan, and the pinning regression test.

## Task Commits

Each task was committed atomically, following RED->GREEN for the TDD tracer task:

1. **Task 1: A failed unfiltered baseline can no longer be rendered as a known total** — `a7436c8` (test: RED, confirmed FAILING against the pre-change tree — observed count text `'1 of 1 incidents'`) then `09a3b50` (feat: GREEN — `totalKnown` flag, unknown-total render)
2. **Task 2: Record the unknown-total state in the design contract** — `579dadf` (docs)
3. **Task 3: Promote DIA-04 on cited evidence and refresh HIS-04's note** — `9a40f32` (docs, gated on both `tests/test_history_investigation_ui.py -q` and the full suite passing beforehand)

**Plan metadata:** committed together with this SUMMARY.md (see final commit).

_TDD note: `test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total` was run against the pre-change tree and confirmed FAILING with `AssertionError: '1 of 1 incidents' != '1 of ? incidents (total unavailable)'` before the implementation commit — the exact misleading count the gap identified._

## Files Created/Modified

- `dashboard/advanced.js` — `updateMatchingIncidentCount`'s `null`-total branch and `dataset.totalKnown`; `renderIncidentsSection`'s `totalKnown`-derived `total`; updated function comment citing D-06/D-12 and the `#correlation-unavailable` precedent
- `tests/test_history_investigation_ui.py` — `_incidents_route`'s `events_failure_fn` keyword; `test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total`; `test_recovered_baseline_fetch_restores_a_known_total`
- `.planning/phases/04-historical-investigation/04-UI-SPEC.md` — one Copywriting Contract row, one note sentence, one E4 UI Considerations clause
- `.planning/REQUIREMENTS.md` — DIA-04 checkbox/traceability row promoted and its note rewritten to record the discharged hold; HIS-04's note extended with the WR-01 (new) closure

## Decisions Made

- No retry on a failed baseline fetch, per the plan's pre-surfaced assumption: a retry adds request load against an already-degraded server and a second failure still needs an honest render — disclosure is the whole fix.
- `data-total-known` added as a DOM state attribute rather than relying on copy wording alone, giving the regression a state assertion independent of exact text and giving Phase 5 a styling hook without introducing a new element.

## Deviations from Plan

None — plan executed exactly as written. `renderMarkerSingle`'s `role="img"`/`role="button"` mismatch (04-REVIEW.md WR-02 new) was left untouched for Phase 5 per the plan's scope fence; confirmed by `grep -c "setAttribute('role', 'img')" dashboard/advanced.js` still returning `3` and no added diff line touching any ARIA role.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `04-VERIFICATION.md`'s single open gap (5/6 must-haves) is closed: the Incidents matching-count region no longer claims parity it does not have on a partial baseline-fetch failure.
- `REQUIREMENTS.md` is fully reconciled for this round: DIA-04 promoted to Complete; HIS-04 carries both its found-broken-and-restored (CR-01/CR-02/WR-01 original) history and its WR-01 (new) closure.
- Full suite green and grown: 746 passed, 499 subtests passed (>= 746 required by this plan's verification gate), including `tests/test_incidents_api.py` (48 passed, confirming the server side remains unaffected) and `tests/test_history_investigation_ui.py` (134 test functions) both individually and as part of the full suite.
- `renderMarkerSingle`'s accessibility Warning remains recorded in `04-VERIFICATION.md`'s Anti-Patterns for Phase 5 to inherit — not touched here.
- No blockers for the next re-verification round or for Phase 5.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*

## Self-Check: PASSED

- FOUND: dashboard/advanced.js
- FOUND: tests/test_history_investigation_ui.py
- FOUND: .planning/phases/04-historical-investigation/04-UI-SPEC.md
- FOUND: .planning/REQUIREMENTS.md
- FOUND commit: a7436c8
- FOUND commit: 09a3b50
- FOUND commit: 579dadf
- FOUND commit: 9a40f32
