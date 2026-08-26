---
phase: 04-historical-investigation
verified: 2026-08-26T00:47:23Z
status: gaps_found
score: 4/6 must-haves verified
behavior_unverified: 0
overrides_applied: 0
overrides: []
gaps:
  - truth: "Operator can filter incidents and transitions by service, criticality, event type, and time range, and the result is an honest picture of what happened (HIS-04, DIA-06's investigation-context data, and the phase's own 'candid about what Beacon did and did not observe' framing)"
    status: failed
    reason: >
      Confirmed by independent code reading (matches 04-REVIEW.md CR-01/CR-02/WR-01, treated as
      established facts per this verification's brief). Two critical, currently-untested defects
      in dashboard/beacon/incidents.py and its dashboard/app.py caller make the Incidents view
      dishonest in exactly the way this phase exists to prevent:
      (1) CR-01 -- api_events_history derives the set of ports eligible for an "open episode"
      anchor lookup only from the filtered, range-bounded rows already returned
      (`ports = sorted({row['port'] for row in rows})`, app.py:2676-2679). A service that went
      down before start_ts and produced no other event inside the window (the normal case for a
      long-silent outage) has zero in-range rows, so its port never reaches
      read_open_episode_anchors and the still-open outage is completely absent from `episodes` --
      not disclosed as a gap, simply missing. The same path is reachable through the shipped
      per-service filter (dashboard/advanced.js incidentQueryParams sets `port=<selected>`),
      so investigating one specific silently-down service can render "No incidents match this
      range and these filters" for that exact service.
      (2) CR-02 -- read_open_episode_anchors (incidents.py:154-176) hardcodes
      `event_type = 'state_change'` and applies no maintenance predicate, while
      read_events_in_range applies the operator's event_type/maintenance filter in SQL before
      grouping. Selecting any Incidents "Event type" filter other than "State change" (the
      shipped dropdown offers six others, dashboard/advanced.html:184-190) can (a) fabricate a
      false "Ongoing -- not yet recovered" badge for an already-fully-recovered incident, because
      the anchor's down row is the only state_change row group_episodes still sees once the real
      closing row is filtered out, or (b) silently drop a real, fully-in-range incident from the
      episodes list and the "N of M incidents" count entirely.
      (3) WR-01 -- the same anchor query in (1)/(2) has no suppressed_reason predicate, so a
      maintenance-exclude filter can still surface a suppressed anchor's evidence, the opposite
      of what "hide expected maintenance" asked for.
      No test in tests/test_incidents_api.py (37 tests, all read) combines a non-default
      event_type or maintenance filter with a route-level anchor + in-range-recovery scenario --
      test_maintenance_suppressed_row_present_by_default_and_excludable only asserts against the
      flat `events` list, never `episodes`. The full 727-pass / 496-subtest suite is therefore not
      evidence against these defects.
    artifacts:
      - path: "dashboard/app.py"
        issue: "Lines 2664-2679: `ports` (the anchor lookup's candidate set) is computed from the filtered row set, not independently of it."
      - path: "dashboard/beacon/incidents.py"
        issue: "Lines 154-176 (read_open_episode_anchors): hardcodes event_type='state_change' and applies no maintenance predicate, inconsistent with the caller's own event_type/maintenance filter applied at incidents.py's read_events_in_range."
      - path: "dashboard/advanced.js"
        issue: "Lines 1056-1069 (incidentQueryParams) and dashboard/advanced.html:184-190 make both CR-01 (via port) and CR-02 (via event_type) reachable from the shipped UI, not just direct API calls."
    missing:
      - "Compute the anchor candidate port set independently of what happened to match inside the window -- e.g. always resolve the anchor for the filter's explicit `port` when one is supplied, and otherwise query every port with a currently-open state_change as of start_ts, not just the ports present in `rows`."
      - "Stop grouping `episodes` from a row set already narrowed by event_type/maintenance. Either group from an unfiltered-by-event-type, unfiltered-by-maintenance state_change read and filter/annotate episodes after grouping, or explicitly return `episodes: []` when event_type is set to a non-state_change value rather than grouping a row set that cannot represent the real state machine."
      - "Apply the same maintenance predicate to the anchor query as to the range read (WR-01), or explicitly document and test that anchor suppression is authoritative regardless of the maintenance filter."
      - "Add the route-level regression test 04-REVIEW.md's IN-01 and its own CR-01/CR-02 fix sections specify: event_type=alert_sent (or similar) against a port with a fully-recovered in-range episode must not report `open: true`; a port with an out-of-window-only anchor and zero in-range rows must still appear as an open episode."
  - truth: "A custom range entered as explicit local start/end text is validated -- an entry that cannot actually exist is rejected rather than silently accepted (DIA-05)"
    status: failed
    reason: >
      Confirmed by independent code reading (matches 04-REVIEW.md WR-02). parseLocalRangeInput's
      convergence loop (dashboard/advanced.js:1726-1745) iteratively nudges a candidate UTC
      instant until localWallClockMinutes(candidate) matches the typed wall-clock minutes. For an
      unambiguous time or the DST "fall back" ambiguous hour this converges correctly, but for a
      wall-clock time that never occurs at all (the "spring forward" gap, e.g. typing 02:30 on the
      day a zone jumps 02:00->03:00) no candidate ts satisfies the target, deltaMinutes never
      reaches 0, and the loop still exits after exactly 3 iterations, returning a value that does
      not round-trip to the text the operator entered. validateCustomRange only checks
      ordering/span/future-ness, never round-trip fidelity, so no error is ever surfaced --
      exactly the "silently accepting an inaccurate instant" failure mode this phase's own
      DST-tick detector (dstAnnotations) was built elsewhere to avoid.
    artifacts:
      - path: "dashboard/advanced.js"
        issue: "Lines 1726-1745 (parseLocalRangeInput): no post-loop check that localWallClockMinutes(candidate) === targetMinutes; a nonexistent local time silently returns an inaccurate ts instead of null."
    missing:
      - "After the convergence loop, verify localWallClockMinutes(candidate) === targetMinutes; if not, return null (or a sentinel validateCustomRange turns into a visible 'that local time does not exist because of a clock change' message) instead of accepting the inaccurate instant."
deferred: []
human_verification: []
---

# Phase 4: Historical Investigation Verification Report

**Phase Goal:** The operator can investigate a selected time range, service, or incident through correlated history that is detailed, bounded, and candid about what Beacon did and did not observe.

**Verified:** 2026-08-26T00:47:23Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Context

All 8 plans (04-01 through 04-08) executed and merged to `main` across 7 waves. I independently
ran the full test suite myself (not trusted from SUMMARY.md or the execution state note):
**727 passed, 496 subtests passed in 183.21s, exit code 0** — this exactly matches the reported
regression-gate figure, confirming no environment drift. I also independently read the source
lines `04-REVIEW.md` cites for CR-01, CR-02, WR-01, and WR-02 and confirm all four are real,
present in the current tree exactly as described — these are treated as established facts per
this verification's brief, not re-litigated, but their consequences for goal achievement and for
the specific requirements they touch (HIS-04, DIA-05, DIA-06's data, HIS-05's precondition) are
assessed fresh below.

**The core problem:** this phase's own goal statement uses the word "candid" and its own design
decisions (D-12: "Grouping is a view over durable rows"; the incidents.py module docstring: "An
episode with no observed recovery stays open... it is never backfilled with the query's end_ts
or the current time") repeatedly promise that the Incidents view will never fabricate or hide a
service's true state. CR-01 (silent disappearance of a genuinely ongoing, event-quiet outage) and
CR-02 (a fully-recovered incident relabeled "Ongoing," or a real incident dropped from the count)
are the exact failure modes the phase was built to prevent, both reachable from the shipped UI's
own filter controls, both confirmed present in the current codebase, and both currently
untested.

## Goal Achievement

### Observable Truths

| # | Truth (source: ROADMAP.md Success Criteria) | Status | Evidence |
|---|---|---|---|
| 1 | Operator can choose shared preset ranges from 1h through 90d | ✓ VERIFIED | `HISTORY_PRESETS = {'1h':3600,'6h':21600,'24h':86400,'7d':604800,'30d':2592000,'90d':7776000}` (advanced.js:10); active-preset indication and `beacon-advanced-preferences-v1` persistence confirmed by reading `historyRange` prefs schema and `validHistoryFilters`/preference-restore code; 96bd3ca's dedicated preset-ladder test suite passes in the full run. |
| 2 | Operator can select a validated custom range within retained history | ✗ FAILED (partial) | Core validation (start<end, reverse order, blank/non-decimal rejection, server-side HistoricalRange re-validation) is real and works. But `parseLocalRangeInput`'s DST convergence loop (advanced.js:1726-1745) silently accepts an inaccurate instant for a nonexistent local time (spring-forward gap) with no round-trip check and no surfaced error — confirmed WR-02. See Gaps. |
| 3 | Operator can inspect CPU/memory/disk/temperature history with units, threshold context, tooltips, visible gaps, and latest/min/max/avg/trend comparisons | ✓ VERIFIED | `THRESHOLD_LINES = {temp:[80,85], disk:[100]}` (advanced.js:30, CPU/memory carry none, matching the plan); `buildSeriesPath` breaks the path (`M` not `L`) across any interval not fully covered (advanced.js:2131-2143); `leastSquaresSlope`/`usableTrendPoints` present (advanced.js:2432+); coverage-strip vocabulary and `.hist-comparison`/`.hist-threshold` CSS present; `dashboard/advanced.html` carries `chart-temp`, `comparison-cpu`, and per-metric loading/empty/error regions for all four metrics. |
| 4 | Operator can inspect time-weighted availability, state timeline, latency, failure classes, and unknown intervals for a selected service | ✓ VERIFIED | `timeWeightedAvailability` computes `online/(online+offline)` over observed seconds only, returns `null` (Unknown) at zero observed seconds (advanced.js:828-844); `.hist-state-band`/`.incident-row` CSS and `service-state-band` HTML id present; latency chart reuses `buildSeriesPath`/coverage-strip verbatim per 04-06-SUMMARY.md and code read. |
| 5 | Operator can filter incidents and transitions by service, criticality, event type, and time range; choosing an incident focuses the related service and time window | ✗ FAILED | CR-01 and CR-02 (see Gaps) make the service and event-type filters actively dishonest, not merely incomplete: filtering by service can hide the exact ongoing outage under investigation, and filtering by event type can relabel a recovered incident "Ongoing" or drop a real incident from the count. The focus mechanism itself (`focusIncident` → `setSelectedService` + `setInvestigationRange`, advanced.js:1428-1434) is correct once a row exists to click, but a row hidden by CR-01 can never be selected in the first place. |
| 6 | Selecting a service, incident, or time range updates related host, service, and event views together, presenting observed correlation without an unsupported causal claim | ✓ VERIFIED | `setSelectedService`/`clearSelectedService` (advanced.js:515,534) is the one carried, read-only entry point; `pushRange`/`popRange`/`setInvestigationRange` (advanced.js:1796-1899) is the one navigation-stack entry point every gesture (drag, preset, custom apply, incident focus) shares; `grep -in "root cause\|caused by\|because of\|due to"` across advanced.js/advanced.html returns zero matches outside comments/tests; the marker rail (`clusterMarkers`, advanced.js:1457+) always fetches the unfiltered baseline so a marker's presence never depends on the operator's own Incidents filter. |

**Score:** 4/6 truths verified (2 present-and-partially-working but confirmed defective; not counted as human-verification items because both defects were independently confirmed at the code level, not merely suspected).

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `dashboard/advanced.html` | History/Incidents nav entries, four-chart stack, comparison rows, custom range/back controls, service band, incident rows, marker rail | ✓ VERIFIED | `data-section="history"`, `data-section="incidents"`, `chart-temp`, `comparison-cpu`, `service-state-band`, `incident-marker-rail` all present; six event-type filter options plus two maintenance-visibility options confirmed at lines 184-190. |
| `dashboard/advanced.js` | Range state, gap-breaking series, coverage strips, comparison row/trend, custom range parsing, navigation stack, carried service selection, incident fetch/filter/focus, marker rail, hover cursor | ✓ VERIFIED (with 2 confirmed defects) | All required functions/constants present and wired: `HISTORY_PRESETS`, `buildSeriesPath`, `THRESHOLD_LINES`, `leastSquaresSlope`, `pushRange`/`setInvestigationRange`, `setSelectedService`, `timeWeightedAvailability`, `incidentQueryParams`/`fetchIncidents`, `focusIncident`, `clusterMarkers`, `moveTimeCursor`. `parseLocalRangeInput` has the confirmed WR-02 defect. |
| `dashboard/advanced.css` | Chart/coverage-strip/comparison/drag-select/state-band/incident-row/cursor styling | ✓ VERIFIED | `.hist-coverage-strip`, `.hist-threshold`, `.hist-comparison`, `.hist-drag-select`, `.hist-state-band`, `.incident-row`, `.hist-cursor` all present. |
| `dashboard/beacon/incidents.py` | Range-and-filter event read, anchor lookup, episode grouping, overrun split, flapping classification | ⚠️ VERIFIED-WITH-DEFECT | `EVENT_TYPES`, `CRITICALITY_VALUES`, `MAINTENANCE_MODES`, `INCIDENT_ROW_BUDGET`, `read_events_in_range`, `read_open_episode_anchors`, `group_episodes`, `classify_flapping`, `compose_incidents_response` all present, substantive, and wired from `dashboard/app.py`. `read_open_episode_anchors` (lines 154-176) is the confirmed source of CR-01/CR-02/WR-01. |
| `dashboard/app.py` | `GET /api/telemetry/history`, `GET /api/events/history` routes | ✓ VERIFIED (route wiring) / ✗ defective (anchor scope) | `api_events_history` (line 2642+) confirmed to call `read_events_in_range` then derive `ports` from the filtered `rows` before calling `read_open_episode_anchors` — the exact CR-01 mechanism. |
| `tests/test_incidents_api.py` | Grouping, filtering, validation, budget, query-plan coverage | ✓ EXISTS, min_lines met (487 lines, 37 tests) | Confirmed no test combines a non-default `event_type`/`maintenance` filter with an anchor + in-range-recovery scenario (`test_maintenance_suppressed_row_present_by_default_and_excludable` only inspects the flat `events` list, never `episodes`) — matches IN-01. |
| `tests/test_history_investigation_ui.py` | Playwright end-to-end coverage of the History/Incidents tracer paths | ✓ EXISTS (4399 lines, 126 tests) | Present, substantive; part of the full green suite run below. |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `dashboard/advanced.js` | `dashboard/app.py` | `GET /api/telemetry/history?kind=host\|service` | ✓ WIRED | Confirmed via `fetchIncidents`/history-fetch call sites and `THRESHOLD_LINES`/comparison consumers of the returned points. |
| `dashboard/advanced.js` | `dashboard/app.py` | `GET /api/events/history` (`incidentQueryParams`/`fetchIncidents`) | ✓ WIRED, ⚠️ semantically defective | The call reaches the route, but the route's own anchor logic (CR-01/CR-02) means the wiring correctly transports incorrect data for filtered requests. |
| `dashboard/app.py` | `dashboard/beacon/incidents.py` | `api_events_history` calls `read_events_in_range` then `read_open_episode_anchors`/`compose_incidents_response` | ✓ WIRED | Confirmed at app.py:2664-2679. |
| `dashboard/advanced.js` (focusIncident) | `dashboard/advanced.js` (setSelectedService/setInvestigationRange) | Shared carried-selection and navigation-stack entry points | ✓ WIRED | Confirmed at advanced.js:1428-1434. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Full regression suite is genuinely green (not just SUMMARY-claimed) | `python -m pytest -q` (run once, in `dashboard/.venv`) | `727 passed, 496 subtests passed in 183.21s`, exit code 0 | ✓ PASS |
| `test_incidents_api.py` has no route-level test crossing event_type/maintenance filters with anchor+recovery scenarios (IN-01) | `grep -n "def test_" tests/test_incidents_api.py` (37 results reviewed) | No matching test name/body found; `test_maintenance_suppressed_row_present_by_default_and_excludable` only asserts against `events`, not `episodes` | ✓ CONFIRMS GAP (as expected) |
| No causal-language leak in shipped UI copy | `grep -in "root cause\|caused by\|because of\|due to" dashboard/advanced.js dashboard/advanced.html` | No matches | ✓ PASS |
| No debt markers (TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER) in phase-modified files | `grep -n -E "TBD\|FIXME\|XXX\|TODO\|HACK\|PLACEHOLDER"` across app.py, incidents.py, advanced.js/html/css | No matches | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | REQUIREMENTS.md (before) | My independent determination | Evidence |
|---|---|---|---|---|
| DIA-04 | 04-01 | `[ ]` Pending | **SATISFIED — recommend promote to Complete** | Six-preset ladder, active-state indication, and validated persisted preference all confirmed working; not touched by any confirmed defect. |
| DIA-05 | 04-02 (server), 04-05 (UI) | `[ ]` Pending | **NOT YET SATISFIED — keep Pending, gap recorded** | Custom-range entry, parsing, and server-side re-validation work for the overwhelming majority of inputs, but WR-02 is a confirmed, reproducible defect in the exact "validated" contract this requirement names (a nonexistent local time silently produces an inaccurate range rather than a rejection). Promoting to Complete would misrepresent an unresolved, code-confirmed bug as done. |
| DIA-06 | 04-05, 04-06, 04-07 | `[ ]` Pending | **SATISFIED (mechanism) — recommend promote to Complete, with a recorded caveat** | The synchronization mechanism itself — carried service selection, shared navigation stack, incident focus pushing both a range and a service — is correctly implemented and independently confirmed at the code level (`setSelectedService`, `pushRange`/`setInvestigationRange`, `focusIncident`). DIA-06's own wording concerns view synchronization, not the correctness of the underlying event data; that correctness problem is HIS-04's, tracked as a gap there. Promoting DIA-06 should be read together with the HIS-04 gap below — a synchronized view can still synchronize wrong data until that gap is closed. |
| DIA-07 | 04-08 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | No causal language in shipped copy; markers are neutral (no severity colour/size); correlation is presented as shared-axis markers plus a hover cursor only. |
| DIA-08 | 04-01, 04-07 | `[ ]` checkbox / `Complete` in traceability table (inconsistent — see below) | **CONFIRMED SATISFIED functionally — recommend fixing the checkbox/table mismatch** | Both halves Phase 4 owns are real: the range preference (04-01) and the history-filter preference (04-07, `historyFilters` persisted under `beacon-advanced-preferences-v1`, validated via `validHistoryFilters`). The line-item checkbox at `REQUIREMENTS.md` line 43 still reads `[ ]` while the traceability table already reads `Complete` (promoted prematurely by commit 96bd3ca in wave 1, before the filtering half even shipped in wave 6) — a documentation inconsistency, not a functional gap, but worth a reconciling edit now that the functional claim is actually true. |
| HIS-01, HIS-02, HIS-03, HIS-06 | 04-01/03/04/06 | `[x]` Complete | **CONFIRMED SATISFIED — no change** | Spot-checked as described in Observable Truths #3 and #4 above. |
| HIS-04 | 04-02, 04-07 | `[x]` Complete | **REGRESSION — this requirement is NOT actually satisfied; should NOT remain marked Complete without a gap-closure plan** | CR-01 and CR-02 are confirmed, code-level violations of exactly this requirement's own text ("filter incidents... by service, criticality, event type, and time range"): filtering by service can hide the incident being investigated, and filtering by event type can fabricate or erase incident status. This is the most important finding in this report — a requirement previously recorded Complete is demonstrably broken by two of its own four filter dimensions. |
| HIS-05 | 04-07 | `[x]` Complete | **SATISFIED at the mechanism level, with a noted dependency on HIS-04's gap** | `focusIncident` itself is correct; its precondition (an incident row existing to click) can fail to hold when CR-01 hides the row entirely. Not reverting this checkbox, but flagging the dependency so the HIS-04 gap-closure plan is understood to also restore HIS-05's practical reliability. |

### Anti-Patterns Found

None. No TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER markers in any phase-modified file; no `innerHTML`/`insertAdjacentHTML` usage (independently spot-checked, matching 04-REVIEW.md); no stub returns or hardcoded-empty render paths found in the functions read for this verification.

### Gaps Summary

Two confirmed, code-level defects block full goal achievement, both centered on
`dashboard/beacon/incidents.py`'s anchor-lookup mechanism and its interaction with the filtered
row set the caller derives it from:

1. **CR-01 + CR-02 + WR-01 (one root cause, three symptoms)** — the open-episode anchor lookup is
   scoped to ports/rows that already survived the range-and-filter read, instead of being resolved
   independently for the filter's own explicit `port`, or for every genuinely-open port as of
   `start_ts`. This makes the shipped Incidents "Service" filter (CR-01) and "Event type" filter
   (CR-02) actively dishonest — a silently-down service can vanish from the exact filtered view
   built to find it, and a fully-recovered incident can be relabeled "Ongoing" or dropped
   entirely. WR-01 is the same root cause narrowed to the `maintenance` filter's effect on a
   suppressed anchor. This is the single largest gap and should be closed before this phase is
   considered done — it directly contradicts the phase's own "candid about what Beacon did and
   did not observe" goal language and the HIS-04 requirement text.

2. **WR-02** — the custom local-time range parser silently accepts an inaccurate instant for a
   local time that does not exist (the DST spring-forward gap), with no round-trip verification
   and no surfaced error, undermining the "validated" half of DIA-05.

Both gaps are narrow in scope (one function each: `read_open_episode_anchors` in
`incidents.py`, and `parseLocalRangeInput` in `advanced.js`) and both were shipped without
regression coverage for the exact scenarios they break — closing them should also include the
route-level and DST-gap tests 04-REVIEW.md's fix sections specify, so the next full-suite run is
actual evidence against a recurrence.

Everything else examined for this phase — the preset ladder, the four-chart host stack with
gap-breaking series and coverage strips, the comparison/trend row, the service state band and
time-weighted availability, the navigation stack and drag-to-select, the incident row anatomy and
flapping banner, the neutral marker rail and shared hover cursor, and the DIA-08 preference
persistence — is genuinely implemented, wired, and passing 727 tests with no debt markers or stub
patterns found.

---

_Verified: 2026-08-26T00:47:23Z_
_Verifier: Claude (gsd-verifier)_
