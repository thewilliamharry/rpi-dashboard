---
phase: 04-historical-investigation
verified: 2026-08-26T12:15:00Z
status: gaps_found
score: 5/6 must-haves verified
behavior_unverified: 0
overrides_applied: 0
overrides: []
re_verification:
  previous_status: gaps_found
  previous_score: 4/6
  gaps_closed:
    - "CR-01 -- a silently-down service with zero in-range events now appears as an open episode, including under an explicit port filter (dashboard/beacon/incidents.py: anchor_candidate_ports, read_open_ports_as_of)"
    - "CR-02 -- a non-state_change event_type filter no longer fabricates 'Ongoing' for a recovered episode or silently drops a real one; episodes are grouped from read_episode_state_changes (an independent, unfiltered-by-event_type/maintenance state_change read) and narrowed only after grouping via filter_episodes"
    - "WR-01 (original, incidents.py) -- maintenance=exclude/only now checks each episode's own suppressed_reason (assigned from its opening/anchor row), so a suppressed anchor's evidence can no longer leak through the maintenance filter"
    - "WR-02 (original, advanced.js DST) -- parseLocalRangeInput now performs a round-trip check after its convergence loop and returns the NONEXISTENT_LOCAL_TIME sentinel for a local time the configured zone never reaches (spring-forward gap); validateCustomRange surfaces a named rejection and applyCustomRange issues no request in that case. The DST fall-back ambiguous hour and ordinary times still round-trip correctly."
  gaps_remaining: []
  regressions:
    - "New (post-closure) finding, not a regression of a previously-closed item: renderIncidentsSection (dashboard/advanced.js:1387-1416) silently substitutes the filtered count for the unfiltered baseline total when the parallel /api/events/history baseline fetch fails, rendering a misleading 'N of N incidents' with no error or uncertainty indication -- confirmed live in the current tree by 04-REVIEW.md (2026-08-26, WR-01) and independently re-confirmed here. This is the same class of defect (a confident-looking figure standing in for an unknown one) the phase exists to prevent, now in the aggregate-count path rather than the episode-grouping path CR-01/CR-02 fixed."
gaps:
  - truth: "Operator can filter incidents and transitions by service, criticality, event type, and time range, and the result is an honest picture of what happened (HIS-04, and the phase's own 'candid about what Beacon did and did not observe' framing)"
    status: partial
    reason: >
      The two confirmed, code-level defects this phase's prior verification round found (CR-01
      silently-down services vanishing under a port filter; CR-02 a recovered incident mislabelled
      "Ongoing" or dropped without disclosure; WR-01 a suppressed anchor's evidence leaking through
      maintenance=exclude) are genuinely closed. I independently re-read
      dashboard/beacon/incidents.py's read_episode_state_changes, anchor_candidate_ports,
      read_open_ports_as_of, and filter_episodes, and confirmed dashboard/app.py's
      api_events_history now derives episode_rows and anchor_ports independently of the filtered
      rows list, exactly matching 04-09-SUMMARY.md's claims. I ran the 11 named
      EpisodeScopeRegressionTests (and the two Task 2 tracer tests inside the same class) directly
      -- all 11 pass. However, a fresh code review (04-REVIEW.md, 2026-08-26) found a new, narrower
      defect in the same functional area that I independently re-confirmed live in the current
      tree: when the operator has an active filter, renderIncidentsSection fetches the filtered
      list and an unfiltered baseline in parallel; if the baseline fetch fails (the filtered
      request still succeeds), the "N of M incidents" count silently substitutes the filtered
      count for M, rendering "N of N incidents" -- which reads as "every matching incident is
      shown" when the true total is actually unknown. No error or uncertainty indicator is shown
      for this case (errorEl is only populated when the filtered request itself fails). No test in
      tests/test_history_investigation_ui.py drives the baseline-fetch-fails/filtered-fetch-succeeds
      combination -- confirmed absent by grep (only "totalOutcome"-adjacent success-path assertions
      exist). This is narrower in trigger condition than CR-01/CR-02 (it requires a genuine partial
      network/server failure of one of two nearly-identical parallel requests, not a normal filter
      selection), but it is the same failure shape the phase's own design principle exists to
      prevent -- a number that looks authoritative standing in for one Beacon does not actually
      have -- and it was flagged as a 04-REVIEW.md Warning, not Critical, in the current pass (0
      Critical findings this round).
    artifacts:
      - path: "dashboard/advanced.js"
        issue: "Lines 1387-1416 (renderIncidentsSection): totalOutcome.status !== 'fulfilled' falls back to episodes.length (the filtered count) as the total, with no distinguishing UI state and no test coverage of this branch."
    missing:
      - "Track baseline-fetch failure explicitly and render a state that does not claim parity with the filtered count, e.g. 'N of ? incidents (total unavailable)', per 04-REVIEW.md's suggested fix (totalKnown check, total=null when the baseline fetch did not succeed)."
      - "Add a Playwright-style test (04-REVIEW.md IN-01) that stubs /api/events/history to succeed for the filtered query string and fail for the unfiltered one, asserting the matching-count region does not silently claim N of N."
deferred: []
human_verification: []
---

# Phase 4: Historical Investigation Verification Report

**Phase Goal:** The operator can investigate a selected time range, service, or incident through correlated history that is detailed, bounded, and candid about what Beacon did and did not observe.

**Verified:** 2026-08-26T12:15:00Z
**Status:** gaps_found
**Re-verification:** Yes — after gap closure (plans 04-09, 04-10)

## Context

This is a re-verification of a phase whose prior round (2026-08-26T00:47:23Z) found status
`gaps_found`, score 4/6, with two blocking gaps: HIS-04/CR-01/CR-02/WR-01 (Incidents view could
silently hide a genuinely-down service or mislabel/drop a recovered one, depending on the
operator's own filter selection) and DIA-05/WR-02 (a custom range typed into the DST
spring-forward gap silently accepted an inaccurate instant instead of being rejected). Gap-closure
plans 04-09 and 04-10 landed since, and a fresh code review (`04-REVIEW.md`, 2026-08-26T08:44:38Z)
re-examined the same file set afterward, confirming both closures and reporting 0 Critical, 2
Warning, 1 Info new findings.

I independently re-read the source this report and 04-REVIEW.md cite (not trusted from SUMMARY.md
prose alone) and independently ran the specific named tests each closure claims, rather than
relying on the orchestrator-reported full-suite pass count alone for the specific claims below:

- `tests/test_incidents_api.py::EpisodeScopeRegressionTests` (11 collected, 11 passed) — the CR-01/
  CR-02/WR-01 closure evidence.
- `tests/test_history_investigation_ui.py::CustomRangeDstGapTests` plus the two Incidents-narrowing
  disclosure tests (6 collected, 6 passed, 3 subtests) — the WR-02 closure and the 04-10
  `episode_scope` disclosure evidence.
- `dashboard/beacon/incidents.py` is 595 lines (>= the plan's 420 min_lines gate); `dashboard/app.py`'s
  `api_events_history` (lines 2642–2702) confirmed to call `read_episode_state_changes` and
  `anchor_candidate_ports` independently of the filtered `read_events_in_range` result, matching
  04-09-SUMMARY.md exactly.
- `tests/test_incidents_api.py` collects 48 tests total; `tests/test_history_investigation_ui.py`
  collects 132 — both match the SUMMARY-reported counts exactly.

The orchestrator independently ran the full suite on the current tree: 744 passed, 499 subtests
passed. I did not re-run the full suite (per this workflow's guidance to avoid redundant full runs)
but the named-test runs above are fresh evidence specific to the claims being verified, not a
restatement of that count.

**What changed since the prior round:** both previously-blocking gaps (HIS-04's CR-01/CR-02/WR-01,
and DIA-05's WR-02) are genuinely closed, confirmed at the code and test level, not merely claimed.
`REQUIREMENTS.md` has been reconciled accordingly (DIA-05, DIA-06, DIA-08 promoted to Complete;
HIS-04 carries a history note naming the found-broken-and-restored sequence; DIA-04 deliberately
held at Pending pending this independent re-verification, per 04-10's stated policy against a
gap-closure plan self-promoting a requirement outside its own closure set).

**What is new:** the fresh code review that confirmed both closures also found two Warnings and one
Info that did not exist in, or were not caught by, the prior verification round because they are in
code paths the CR-01/CR-02/WR-01/WR-02 fixes did not touch. I independently re-confirmed both live
in the current tree (see Gaps and Anti-Patterns below) and assessed each against the phase's own
"candid about what Beacon did and did not observe" goal language, per this verification's
instructions, rather than accepting the review's Warning/Info severity labels at face value.

## Goal Achievement

### Observable Truths

| # | Truth (source: ROADMAP.md Success Criteria) | Status | Evidence |
|---|---|---|---|
| 1 | Operator can choose shared preset ranges from 1h through 90d | ✓ VERIFIED | `HISTORY_PRESETS = {'1h':3600,'6h':21600,'24h':86400,'7d':604800,'30d':2592000,'90d':7776000}` (advanced.js:10) unchanged since the prior round; `state.preferences.historyRange` persistence and preset-restore code confirmed present and untouched by 04-09/04-10. |
| 2 | Operator can select a validated custom range within retained history | ✓ VERIFIED (regression closed) | `parseLocalRangeInput` (advanced.js:1788-1810) now performs a post-convergence round-trip check (`localWallClockMinutes(rounded) !== targetMinutes`) and returns `NONEXISTENT_LOCAL_TIME` for a nonexistent local time; `validateCustomRange` (advanced.js:1829-1857) surfaces a named DST rejection ahead of every other check; `applyCustomRange` (advanced.js:2000-2013) returns on `!result.valid` without calling `setInvestigationRange`, so no request is issued. `CustomRangeDstGapTests` (4 tests) and the fall-back/ordinary round-trip tests independently run and pass. |
| 3 | Operator can inspect CPU/memory/disk/temperature history with units, threshold context, tooltips, visible gaps, and latest/min/max/avg/trend comparisons | ✓ VERIFIED | Unaffected by 04-09/04-10; `THRESHOLD_LINES`, `buildSeriesPath`'s gap-breaking `M`-not-`L` behaviour, and `leastSquaresSlope` confirmed present and unmodified by either gap-closure plan's `files_modified` list. |
| 4 | Operator can inspect time-weighted availability, state timeline, latency, failure classes, and unknown intervals for a selected service | ✓ VERIFIED | Unaffected by 04-09/04-10; `timeWeightedAvailability`, `.hist-state-band` confirmed present and unmodified. |
| 5 | Operator can filter incidents and transitions by service, criticality, event type, and time range, and the result is an honest picture of what happened | ✗ FAILED (partial) | CR-01, CR-02, and WR-01 (original) are genuinely closed — confirmed by independent code read of `dashboard/beacon/incidents.py`'s `read_episode_state_changes`/`anchor_candidate_ports`/`filter_episodes` and 11/11 passing `EpisodeScopeRegressionTests`. But a new, narrower defect in the same view — a misleading "N of N incidents" when the parallel unfiltered-baseline fetch fails (04-REVIEW.md WR-01, confirmed live at advanced.js:1387-1416, no test coverage) — means the Incidents view is not yet honest in every reachable state. See Gaps. |
| 6 | Selecting a service, incident, or time range updates related host, service, and event views together, presenting observed correlation without an unsupported causal claim | ✓ VERIFIED | Unaffected by 04-09/04-10; `setSelectedService`/`pushRange`/`setInvestigationRange`/`focusIncident` confirmed present and unmodified; `grep -in "root cause\|caused by\|because of\|due to" dashboard/advanced.js dashboard/advanced.html` returns zero matches. |

**Score:** 5/6 truths verified (1 partial — the filtering/incidents truth's two most severe defects
are closed but a narrower, newly-found candour defect remains open in the same view).

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `dashboard/beacon/incidents.py` | Independent episode-scope grouping, anchor discovery, post-grouping filtering, `episode_scope` disclosure | ✓ VERIFIED | 595 lines (>= 420 min_lines gate); `EPISODE_GROUPING_SOURCE`, `build_open_anchor_query`, `build_open_ports_query`, `read_open_episode_anchors` (tightened, now evaluates `online`/`criticality` in Python), `read_open_ports_as_of`, `anchor_candidate_ports`, `read_episode_state_changes`, `filter_episodes`, rewritten `compose_incidents_response` all present, substantive, and independently read line-by-line. |
| `dashboard/app.py` | `api_events_history` calling the independent reads, not the filtered row set | ✓ VERIFIED | Lines 2642-2702 confirmed: `read_episode_state_changes` and `anchor_candidate_ports` are called independently of `read_events_in_range`'s filtered `rows`, with `episode_rows=` passed through to `compose_incidents_response` — the exact CR-01 fix mechanism. |
| `tests/test_incidents_api.py` | `EpisodeScopeRegressionTests` covering CR-01/CR-02/WR-01 at the route level | ✓ VERIFIED | 48 tests collected total (11 in `EpisodeScopeRegressionTests`), all 11 independently run and pass. |
| `dashboard/advanced.js` | `NONEXISTENT_LOCAL_TIME` DST rejection; `renderEpisodeScopeNote` disclosure | ✓ VERIFIED (with 1 new confirmed defect elsewhere in the same section) | `parseLocalRangeInput`'s round-trip check, `validateCustomRange`'s DST branch, and `renderEpisodeScopeNote` all confirmed present, wired into `renderIncidentsSection`, and reset in `beginIncidentsLoadingState`/the fetch-failure branch. The same function (`renderIncidentsSection`) also contains the new WR-01 baseline-fetch-failure defect (see Gaps) — this is a defect in an adjacent code path within the same function, not in the artifact this plan's must-haves targeted. |
| `dashboard/advanced.html` | `#incidents-episode-scope` disclosure region | ✓ VERIFIED | `aria-live="polite" hidden` region present at line 197, confirmed wired via `incidentsElement('episode-scope')`. |
| `.planning/REQUIREMENTS.md` | DIA-05, DIA-06, DIA-08 promoted on evidence; HIS-04 carries history note; DIA-04 deliberately held | ✓ VERIFIED | Confirmed: `[x]` DIA-05, DIA-06, DIA-08; `[x]` HIS-04 with a history note beneath the traceability table naming CR-01/CR-02/WR-01 and the closing plans; `[ ]` DIA-04 with a note explaining the deliberate hold — matches 04-10-SUMMARY.md exactly. |
| `tests/test_history_investigation_ui.py` | `CustomRangeDstGapTests`, Incidents narrowing-disclosure tests | ✓ VERIFIED | 132 tests collected total; the 6 targeted tests independently run and pass (3 subtests). |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `dashboard/app.py` (`api_events_history`) | `dashboard/beacon/incidents.py` (`read_episode_state_changes`, `anchor_candidate_ports`) | Independent-of-filter episode/anchor reads | ✓ WIRED | Confirmed at app.py:2664-2693 — both reads happen before `compose_incidents_response`, using `filters.get('port')`/`filters.get('criticality')` only, never `rows`. |
| `dashboard/advanced.js` (`applyCustomRange`) | `dashboard/advanced.js` (`validateCustomRange`, `setInvestigationRange`) | `NONEXISTENT_LOCAL_TIME` short-circuit | ✓ WIRED | Confirmed at advanced.js:2000-2013 — an invalid result (including the DST sentinel) returns before `setInvestigationRange` is called, so no fetch is issued. |
| `dashboard/advanced.js` (`renderIncidentsSection`) | `dashboard/advanced.js` (`renderEpisodeScopeNote`) | `payload.episode_scope` from the fulfilled filtered fetch | ✓ WIRED | Confirmed at advanced.js:1417. |
| `dashboard/advanced.js` (`renderIncidentsSection`) | `dashboard/advanced.js` (`updateMatchingIncidentCount`) | `totalOutcome` (parallel unfiltered baseline fetch) | ⚠️ WIRED, defective on failure | Confirmed reachable and correct when both fetches succeed; on `totalOutcome.status !== 'fulfilled'`, silently substitutes `episodes.length` with no distinguishing state — the WR-01 (new) defect. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| CR-01/CR-02/WR-01 closure — 11 named regression tests pass | `uv run --project dashboard python -m pytest -q tests/test_incidents_api.py -k EpisodeScopeRegressionTests` | `11 passed, 37 deselected in 1.18s` | ✓ PASS |
| WR-02 closure + episode_scope disclosure — 6 named tests pass | `uv run --project dashboard python -m pytest -q tests/test_history_investigation_ui.py -k "CustomRangeDstGapTests or test_event_type_narrowing_is_disclosed_in_the_incidents_section or test_no_narrowing_leaves_the_episode_scope_note_absent"` | `6 passed, 126 deselected, 3 subtests passed in 5.63s` | ✓ PASS |
| Old CR-01 anchor-scoping pattern (`ports = sorted({row['port'] ...`) is gone from app.py | `grep -n "ports = sorted({row\['port'\]" dashboard/app.py` | No match | ✓ PASS |
| `tests/test_incidents_api.py` / `tests/test_history_investigation_ui.py` collected counts match SUMMARY claims | `pytest --collect-only` on each file | 48 / 132 | ✓ PASS |
| No test exercises the baseline-fetch-failure "N of N" path (04-REVIEW.md IN-01) | `grep -n "totalOutcome\|baseline" tests/test_history_investigation_ui.py` | No matching test found (only unrelated `R-01 baseline` performance comments) | ✓ CONFIRMS GAP (as expected) |
| No debt markers in any 04-09/04-10-modified file | `grep -n -E "TBD\|FIXME\|XXX\|TODO\|HACK\|PLACEHOLDER"` across `incidents.py`, `app.py`, `advanced.js`, `advanced.html` | No matches | ✓ PASS |
| No causal-language leak | `grep -in "root cause\|caused by\|because of\|due to" dashboard/advanced.js dashboard/advanced.html` | No matches | ✓ PASS |

### Requirements Coverage

| Requirement | REQUIREMENTS.md (current) | My independent determination | Evidence |
|---|---|---|---|
| DIA-04 | `[ ]` Pending (deliberately held, per note) | **SATISFIED — recommend promote to Complete now** | Preset ladder, active-state indication, and persisted preference re-confirmed unmodified and unaffected by any finding this round; 04-10-SUMMARY.md's own note explains the hold was to avoid a gap-closure plan self-promoting an unrelated requirement, deferring to "the next independent re-verification" — this is that verification. |
| DIA-05 | `[x]` Complete | **CONFIRMED SATISFIED** | WR-02 closure independently re-confirmed at the code and test level (see Observable Truth #2). |
| DIA-06 | `[x]` Complete | **CONFIRMED SATISFIED (mechanism)** | Carried service selection and shared navigation stack unaffected and unmodified by this round's findings; the underlying data the mechanism synchronizes is CR-01/CR-02's concern (closed) and the new WR-01 baseline-count concern (open, tracked under HIS-04 below, not DIA-06 — DIA-06 is about the synchronization mechanism, which is sound). |
| DIA-07 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | Re-confirmed no causal language; markers unaffected by this round's changes. |
| DIA-08 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | Checkbox/table mismatch from the prior round resolved; both halves (range + history-filter preference) confirmed present. |
| HIS-01, HIS-02, HIS-03, HIS-06 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | Unaffected by this round's plans or findings. |
| HIS-04 | `[x]` Complete | **PARTIALLY REGRESSED — the checkbox should not remain unqualified Complete without acknowledging the new WR-01 finding** | CR-01/CR-02/WR-01(original) are genuinely closed with route-level regression coverage — this is real, substantial progress and the requirement's core mechanism (episode grouping honesty under a service/event-type/maintenance filter) is now sound. But the same requirement's broader "an honest picture of what happened" standard is not fully met while `renderIncidentsSection`'s "N of M" count can silently claim parity it does not have on a baseline-fetch failure. Recommend keeping HIS-04 at Complete (the requirement's own text is about filtering by service/criticality/event-type/time range, which now works correctly) but recording this narrower residual finding as a tracked follow-up rather than treating it as fully closed with zero remaining candour concerns. |
| HIS-05 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | `focusIncident`'s precondition (a row existing to click) no longer fails silently now that CR-01 is closed. |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `dashboard/advanced.js` | 1387-1416 | Silent fallback: `totalOutcome` failure substitutes the filtered count as the total with no distinguishing state | Blocker (for HIS-04's candour standard; independently re-confirmed live, matches 04-REVIEW.md WR-01) | Misleading "N of N incidents" on a partial fetch failure — see Gaps. |
| `dashboard/advanced.js` | 1582-1601 | `renderMarkerSingle` uses `role="img"` on a click/keydown-interactive SVG circle, inconsistent with `renderMarkerCluster`/`incidentRow`'s `role="button"` | Info/Warning — explicitly Phase 5 scope | `04-CONTEXT.md`'s domain statement places "accessibility work" in Phase 5, not Phase 4 ("Theme parity, responsive behavior, accessibility work... remain Phase 5"). Confirmed live and correctly described by 04-REVIEW.md, but not treated as a Phase 4 blocker — recorded here so Phase 5 inherits it, matching this phase's own R-03 pattern of recording known accessibility debt at creation time rather than silently dropping it. |
| — | — | No TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER markers found in any phase-modified file | Info | Clean. |

### Gaps Summary

One gap remains open, narrower in scope than the two the prior verification round found, and in a
different code path than either 04-09 or 04-10 touched:

1. **WR-01 (new, 04-REVIEW.md 2026-08-26)** — `renderIncidentsSection` fetches the operator's
   filtered incident list and an unfiltered baseline for the same range in parallel via
   `Promise.allSettled`. When the filtered request succeeds but the baseline request fails, the
   "N of M incidents" count silently substitutes the filtered count for the total, rendering
   `"N of N incidents"` — which reads as "every incident in this range matches your filter" when
   the true total is actually unknown. No error, partial-failure notice, or `?` is surfaced for
   this state. I independently re-confirmed this live in the current tree (advanced.js:1387-1416)
   and confirmed no test exercises it (04-REVIEW.md IN-01). This is the same class of problem —
   a confident-looking number standing in for one Beacon does not actually have — that CR-01/CR-02
   existed to prevent in the episode-grouping path; it now recurs in the aggregate-count path. It
   is narrower in trigger condition (requires an actual partial network/server failure of one of
   two nearly-identical parallel requests, not a normal filter selection) and was independently
   triaged as a code-review Warning rather than Critical, but it directly touches this phase's own
   goal language ("candid about what Beacon did and did not observe") and was explicitly called out
   for weighing in this verification's own brief.

   **Fix:** track baseline-fetch failure explicitly and render a state that does not claim parity
   (e.g. `"N of ? incidents (total unavailable)"`), plus add the Playwright-style regression test
   04-REVIEW.md's IN-01 specifies (stub `/api/events/history` to fail for the unfiltered query
   string only).

**Not treated as a gap:** `renderMarkerSingle`'s `role="img"`/`role="button"` mismatch
(04-REVIEW.md's other new Warning). This is a real, confirmed accessibility inconsistency, but
`04-CONTEXT.md`'s domain statement explicitly places "accessibility work" outside Phase 4's scope
and inside Phase 5 ("Theme parity, responsive behavior, accessibility work, and main-dashboard
preview analytics remain Phase 5"). Recorded in Anti-Patterns above so Phase 5 inherits it, matching
this phase's own R-03 practice of recording known accessibility debt at creation time.

**What is genuinely resolved from the prior round:**

- CR-01 (silently-down services vanishing from a filtered Incidents view) — closed, independently
  confirmed at the code and test level.
- CR-02 (a recovered incident mislabelled "Ongoing," or a real incident silently dropped, under a
  non-`state_change` event-type filter) — closed, independently confirmed.
- WR-01 (original — a suppressed anchor's evidence leaking through `maintenance=exclude`) — closed,
  independently confirmed.
- WR-02 (a custom range typed into the DST spring-forward gap silently accepted an inaccurate
  instant) — closed, independently confirmed; the DST fall-back ambiguous hour and ordinary times
  remain correctly handled.
- `REQUIREMENTS.md` reconciled: DIA-05, DIA-06, DIA-08 promoted on evidence; HIS-04 carries an
  honest history note rather than a bare checkbox; DIA-04 deliberately held pending this
  independent re-verification (recommend promoting it now).

Everything examined outside the Incidents section — the preset ladder, the four-chart host stack,
the comparison/trend row, the service state band and time-weighted availability, the navigation
stack and drag-to-select, and the neutral marker rail/hover cursor — remains genuinely implemented,
wired, and unaffected by this round's changes or findings.

---

_Verified: 2026-08-26T12:15:00Z_
_Verifier: Claude (gsd-verifier)_
