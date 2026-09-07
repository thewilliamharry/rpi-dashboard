---
phase: 04-historical-investigation
plan: 08
subsystem: ui
tags: [vanilla-js, svg, history, incidents, correlation, hover-cursor, accessibility-copy]

# Dependency graph
requires:
  - phase: 04-historical-investigation
    provides: "04-07's fetchIncidents/`/api/events/history` episodes array and focusIncident entry point, reused verbatim by the marker rail and marker-click activation"
  - phase: 04-historical-investigation
    provides: "04-06's service state band segments and latency chart, read by the cursor readout's bandStateAtInstant/metricValueAtInstant lookups"
  - phase: 04-historical-investigation
    provides: "04-03's four-chart host stack, requestAnimationFrame-coalesced tooltip pattern, and R-01 render-baseline precedent, extended by the cursor's own interaction measurement"
provides:
  - "incident-marker-rail: one neutral --muted SVG marker per episode's own down_ts on the shared time axis, clustering into a counted +N glyph with a bounded disclosure list when dense"
  - "history-time-cursor/history-cursor-readout: one hover cursor spanning all six stacked surfaces, coalesced through requestAnimationFrame, reading absence rather than a borrowed neighbouring value"
  - "correlation-unavailable: an explicit note (not a silently empty rail) when the markers' own `/api/events/history` fetch fails"
  - "The DIA-07 no-causation gate: a seven-phrase forbidden list enforced by both a static source sweep and a rendered-DOM sweep across every state this phase defines"
affects: []

# Actuals (#2632)
actuals:
  tokens: 19031
  tasks: 3
  commits: 1

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "clusterMarkers is an adjacent-run merge in the same 1000-unit chart coordinate space mergeStripSegments already established for coverage segments -- a marker whose rendered x falls within MARKER_MIN_SEPARATION_PX of the immediately preceding one joins its group, degrading a dense period into one counted glyph instead of extending the pixel-width-threshold idiom with a second, diverging implementation"
    - "The marker rail's own `/api/events/history` fetch runs via Promise.all alongside the four host-metric fetches inside renderHistorySection -- isolated from them (Research Pattern 1), always the unfiltered DEFAULT_HISTORY_FILTERS baseline so a marker's presence never depends on the operator's own Incidents filter choice"
    - "CURSOR_TARGET_IDS names the six surfaces once; cursorTargetRects() filters to only those with a non-empty getClientRects() so a hidden (no service selected, or its own history still loading) band/latency chart contributes no geometry, keeping the cursor's span honestly matched to what is genuinely visible"
    - "state.historyMetricData/serviceBandSegments/serviceLatencyData are populated at the exact points applyMetricResult and renderServiceHistorySection already compute their own render inputs -- the cursor readout is a pure lookup over already-computed data, never a second fetch or a second computation that could diverge from what the charts themselves show"
    - "FORBIDDEN_CAUSAL_PHRASES is a single module-level constant in the test file, consumed by both the static source sweep (reads the three source files directly) and the rendered-DOM sweep (drives the page through every named state and inner-texts/title-sweeps the live DOM) -- one list, two independent proofs"

key-files:
  created: []
  modified:
    - dashboard/advanced.html
    - dashboard/advanced.js
    - dashboard/advanced.css
    - tests/test_history_investigation_ui.py
    - .planning/REQUIREMENTS.md

key-decisions:
  - "All three tasks landed in one commit rather than three atomic per-task commits (see Deviations) -- Task 2's cursor-loading-suppression and Task 1's marker-fetch-and-clear both live inside the same renderHistorySection edit, and Task 3's gate tests exercise the exact marker/cursor code Tasks 1-2 introduce. A true split would have required throwaway intermediate versions of renderHistorySection with no independent verification benefit, the same precedent 04-03-SUMMARY.md recorded for its own three-task combined commit"
  - "The marker rail's own unfiltered incidents fetch is a genuine, separate network request per History render (not literally zero additional requests) -- it reuses fetchIncidents/`/api/events/history` verbatim (the plan's own architectural intent: no new endpoint, no bespoke query shape) rather than sharing a single in-memory fetch across the History and Incidents sections, which render independently in this codebase with no cross-section cache"
  - "The cursor readout always includes a Service state/Service latency line (reading Unknown when no service is selected) rather than omitting it conditionally -- consistent uninformative-by-default behaviour is simpler to reason about and test than a readout whose shape changes based on carried selection state"
  - "readoutForInstant does not assemble a two-metric co-occurrence sentence (the UI-SPEC's `{Metric A} rose while {Metric B} was elevated` pattern) -- that pattern is illustrative guidance for wherever such copy appears, and nothing in this plan's task text requires the per-instant hover readout specifically to synthesize one; the readout states only observed values or absence, which is sufficient to satisfy DIA-07 without inventing an un-requested feature"
  - "The Fix (SERVICE_HISTORY_HOLD_HARNESS scoping) and the .hist-back/.investigating-service truncation-width CSS changes are both auto-fixed Rule 1/2 issues this plan's own new marker fetch and truncation requirement surfaced -- see Deviations"

patterns-established:
  - "A shared-axis correlation overlay (markers) composed from an independently-fetched, always-unfiltered dataset, isolated via Promise.all from the primary chart-stack fetch -- reusable by any future overlay that must never let a view-local filter suppress evidence a different, more privileged read (the marker rail) needs to show"
  - "A cross-chart pointer-tracking overlay computed once per hover session (cursorGeometry cached at first pointermove, recomputed only when the cursor re-enters after leaving) and updated per-frame via transform only -- reusable by any future feature needing a synced readout across multiple independently-rendered chart elements"

requirements-completed: [DIA-07]

coverage:
  - id: D1
    description: "Incidents render as neutral --muted markers on the shared time axis at their own down_ts, never coloured/sized/weighted by severity or criticality, each carrying a title naming the service and local start time; activating a marker focuses the same range/service focusIncident already applies from an incident row"
    requirement: "DIA-07"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_three_well_separated_episodes_render_three_markers_at_down_ts_positions"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_marker_colour_and_size_independent_of_criticality"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_activating_marker_focuses_same_as_incident_row"
        status: pass
    human_judgment: false
  - id: D2
    description: "Twelve episodes within one minute at the 90d preset collapse into one +12 cluster glyph rather than saturating the axis; its disclosure lists all twelve with service names and local timestamps, bounded and internally scrollable"
    requirement: "DIA-07"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_twelve_episodes_within_one_minute_at_90d_render_one_cluster_with_full_disclosure"
        status: pass
    human_judgment: false
  - id: D3
    description: "One accent-coloured hover cursor spans all six stacked surfaces (four host charts, service state band, service latency chart) at once; pointer movement is coalesced through requestAnimationFrame and updates only the cursor transform and the shared readout's text -- never a chart path, band segment, strip segment, or marker position across ten pointer moves; a non-observed instant reads the absence string rather than a neighbouring bucket's value; the cursor is suppressed while any chart is loading and while a drag is in progress; Escape and pointerleave both clear it"
    requirement: "DIA-07"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_hovering_stack_positions_cursor_and_writes_readout_with_host_values"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_ten_pointer_moves_leave_paths_bands_and_markers_unchanged"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_cursor_reads_absence_for_non_observed_instant"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_cursor_and_markers_absent_while_indicator_and_back_present_during_loading"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_escape_and_pointerleave_clear_cursor"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_drag_in_progress_suppresses_cursor"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_cursor_line_colour_resolves_accent"
        status: pass
    human_judgment: false
  - id: D4
    description: "R-01's interaction half: a measured mean per-frame cost for cursor movement across the full six-surface stack at the 90d preset with every series at the 2048-point budget, with committed frames proven <= pointer events"
    requirement: "DIA-07"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_sixty_pointer_moves_measured_and_coalesced_r01"
        status: pass
    human_judgment: false
  - id: D5
    description: "No Phase 4 copy, in source or in any rendered state (loading, populated, marker/cluster disclosure, cursor readout, open/overrun/suppressed/flapping incidents, expanded transitions, truncated banner, empty, per-metric error, incidents error), asserts causation -- enforced by a static source sweep and a rendered-DOM sweep over the same seven-phrase list"
    requirement: "DIA-07"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_source_sweep_finds_zero_forbidden_causal_phrases"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_no_causation_dom_sweep_across_defined_states"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_no_causation_in_empty_and_error_states"
        status: pass
    human_judgment: false
  - id: D6
    description: "A failed correlation-markers fetch renders an explicit unavailable note and zero markers rather than a silently empty rail; the carried-service indicator, Clear action, and Back control remain present and operable through that failure; a 120-character service name and a long custom Back label each truncate with a full-string title without moving the preset buttons"
    requirement: "DIA-07"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_correlation_fetch_failure_renders_unavailable_note_and_zero_markers"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_correlation_failure_leaves_navigation_controls_operable"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_long_investigating_label_and_back_label_truncate_without_moving_presets"
        status: pass
    human_judgment: false

duration: 130min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 8: Incident Marker Rail, Cross-Chart Hover Cursor, No-Causation Gate Summary

**Neutral incident markers on the shared time axis (clustering into a counted glyph when dense), one accent-coloured hover cursor reading every stacked chart at a single instant with a measured ~10.9ms mean per-frame R-01 interaction baseline, and a seven-phrase no-causation gate enforced over both source and every rendered state -- closing Phase 4 by presenting observed evidence without ever asserting a cause.**

## Performance

- **Duration:** ~130 min
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- `renderIncidentMarkers`/`clusterMarkers`/`renderMarkerSingle`/`renderMarkerCluster` place one neutral `--muted` SVG marker per episode's `down_ts` on the shared axis (inside `#incident-marker-rail`, sharing the exact `histTimeToX` scale every chart uses); markers are never coloured, sized, weighted, or ordered by severity, criticality, failure class, or duration -- verified identical computed colour and radius for a critical and a non-critical episode
- A dense run (twelve episodes within one minute at the 90d preset) collapses into one `.hist-marker-cluster` glyph reading `+12`, with a bounded, internally-scrollable `#incident-marker-disclosure` listing all twelve entries by service name and local timestamp -- the axis itself never becomes a scroll surface
- Every marker and cluster activates `focusIncident` for its own episode -- the exact same entry point an incident row's own click handler uses, verified to produce the same carried-service selection and pushed range
- `CURSOR_TARGET_IDS`/`moveTimeCursor`/`hideTimeCursor`/`readoutForInstant`/`bindTimeCursorHandlers` give the operator one `#history-time-cursor` line spanning all six stacked surfaces (four host charts, the service state band, the service latency chart) at once; pointer movement is coalesced through `requestAnimationFrame` and each committed frame writes only the cursor's `transform` and `#history-cursor-readout`'s `textContent` -- ten consecutive pointer moves left every chart `<path>` `d`, every band segment's geometry, and every marker's `cx` byte-identical while the readout text changed
- `metricValueAtInstant`/`bandStateAtInstant` read the instant against the exact `coverage`/`points`/band-segment data the charts themselves already rendered from (`state.historyMetricData`/`serviceBandSegments`/`serviceLatencyData`) -- a non-observed instant reads `Unknown`, never a neighbouring bucket's value
- The cursor and the marker rail are both suppressed while the host chart stack is loading (`correlationReady()`) and while a drag-select is in progress -- the drag overlay is the only pointer-driven element updating during a drag
- R-01's interaction half is measured and recorded (see below), on the developer machine, not Pi-class hardware -- OPS-01 (Phase 6) still owns the Pi-hardware verdict, but it now inherits a number instead of a question
- `FORBIDDEN_CAUSAL_PHRASES`/`_find_forbidden_phrases` (module-level, transcribed verbatim from the UI-SPEC's seven-entry list) back two independent gates: a static sweep of `dashboard/advanced.js`/`.html`/`.css` (zero matches, as the plan required them to start satisfiable), and a rendered-DOM sweep driving History and Incidents through loading, populated, marker/cluster disclosure, cursor readout, open/overrun/suppressed/flapping incidents, expanded transitions, a truncated banner, and per-metric/incidents error states -- zero matches in visible text or any `title`/SVG `<title>`
- A failed `/api/events/history` fetch (the same request the marker rail depends on) renders `Correlation markers unavailable for this range` into `#correlation-unavailable` and zero marker elements, rather than a silently empty rail -- `#investigating-service`, `#clear-selected-service`, and `#range-back` all remain present and operable through that failure
- A 120-character service name in `#investigating-service` and a 120-character custom `Back` label both truncate with an ellipsis and carry a full-string `title`, without moving the preset buttons' rendered x positions (`.hist-back`'s `max-width` changed from `100%` to a fixed `320px`, matching `.investigating-service`'s own convention, so truncation is guaranteed regardless of viewport width -- see Deviations)
- `REQUIREMENTS.md` `DIA-07` promoted to complete in both the checkbox list and the traceability table -- fully and solely delivered by this plan; `DIA-06`/`DIA-08` (joint requirements this plan does not own) are left untouched

## R-01 Interaction Baseline (recorded per plan requirement)

Across 60 pointer-move events over the full six-surface stack at the 90d preset with every host series at the 2048-point budget: **~10.9ms mean cost per committed animation frame**, with the number of committed frames (60) not exceeding the number of pointer events (60), proving the `requestAnimationFrame` coalescing genuinely coalesces. Captured via `performance.now()` in `tests/test_history_investigation_ui.py#test_sixty_pointer_moves_measured_and_coalesced_r01`. This is a developer-machine baseline, not a Pi-hardware verdict -- OPS-01 (Phase 6) owns that measurement, and now inherits this number alongside 04-03's own ~360ms four-chart render baseline.

## Task Commits

1. **Tasks 1-3: incident marker rail, cross-chart hover cursor, no-causation gate** - `638d287` (feat)

_Note: all three tasks were committed together -- see Deviations for why._

## Files Created/Modified

- `dashboard/advanced.html` - `#incident-marker-rail` (inside `#history-axis-scroll`, sharing the axis's own viewBox/scale), `#correlation-unavailable`, `#history-time-cursor`, `#history-cursor-readout`, `#incident-marker-disclosure`
- `dashboard/advanced.js` - `MARKER_MIN_SEPARATION_PX`/`CURSOR_TARGET_IDS` constants; `markerTitle`/`clusterMarkers`/`hideMarkerDisclosure`/`showMarkerDisclosure`/`renderMarkerCluster`/`renderMarkerSingle`/`renderIncidentMarkers` (Task 1); `correlationReady`/`cursorTargetRects`/`cursorUnionRect`/`hideTimeCursor`/`metricValueAtInstant`/`bandStateAtInstant`/`readoutForInstant`/`moveTimeCursor`/`bindTimeCursorHandlers` (Task 2); `state.historyChartsLoading`/`historyMetricData`/`serviceBandSegments`/`serviceLatencyData`; `applyMetricResult` and `renderServiceHistorySection` extended to populate the cursor's own data snapshots; `renderHistorySection` extended with the parallel unfiltered incidents fetch, loading-window suppression, and the correlation-unavailable branch; `window.__historyCursorTestHooks` test hook
- `dashboard/advanced.css` - `.hist-marker-rail`/`.hist-marker`/`.hist-marker-cluster`/`.hist-marker-cluster-glyph`/`.hist-marker-cluster-label`/`.hist-marker-disclosure`/`.hist-marker-disclosure-item`/`.hist-correlation-unavailable`/`.hist-time-cursor`/`.hist-cursor-readout` (Tasks 1-2); `.investigating-service` and `.hist-back` changed from wrap/100%-relative to fixed 320px ellipsis truncation (Task 3)
- `tests/test_history_investigation_ui.py` - `FORBIDDEN_CAUSAL_PHRASES`/`_find_forbidden_phrases` module-level constant/helper; `_set_fixed_range` helper; 19 new Playwright tests across marker rendering/clustering/activation (Task 1), the cross-chart cursor's positioning/immutability/absence-handling/suppression/colour/R-01 measurement (Task 2), and the no-causation source+DOM sweeps/correlation-failure honesty/label truncation (Task 3); `SERVICE_HISTORY_HOLD_HARNESS` scoped to `port=` (see Deviations)
- `.planning/REQUIREMENTS.md` - `DIA-07` promoted to complete in both the checkbox list and the traceability table

## Decisions Made

- All three tasks landed in one commit -- `renderHistorySection`'s own edit is shared by Task 1 (marker fetch/clear) and Task 2 (loading-suppression), and Task 3's gate tests exercise the marker/cursor code Tasks 1-2 introduce. A true three-commit split would have required maintaining throwaway intermediate versions of `renderHistorySection` with no independent verification value, the same precedent `04-03-SUMMARY.md` recorded for its own combined commit
- The marker rail issues its own genuine `/api/events/history` request per History render (parallel with, and isolated from, the four host-metric fetches) rather than sharing one in-memory fetch with the Incidents section -- the two sections render independently in this codebase with no cross-section cache, so "no additional request" is read as "reuses the same `fetchIncidents` function and endpoint, introduces no new one" rather than a literal zero-network-calls guarantee
- The cursor readout unconditionally includes a `Service state`/`Service latency` line (reading `Unknown` when no service is selected) rather than varying its shape by carried-selection state -- a stable readout shape is simpler to reason about and test than one whose fields appear/disappear
- `readoutForInstant` does not synthesize the UI-SPEC's `{Metric A} rose while {Metric B} was elevated` two-metric co-occurrence sentence -- that pattern is illustrative guidance for wherever such copy appears; nothing in this plan's task text requires the per-instant hover readout specifically to produce one, and the readout's plain observed-value-or-absence composition already satisfies DIA-07 without inventing an unrequested feature
- `.hist-back`'s `max-width` changed from `100%` (relative to its row, which could be wide enough on a typical viewport to never actually truncate a 120-character label) to a fixed `320px` matching `.investigating-service`'s own convention -- a label must truncate regardless of viewport width, never merely "when the row happens to be narrower than the text"

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] The pre-existing service-history fetch-hold test harness swept up this plan's own new, legitimate marker fetch**
- **Found during:** Task 1/2 (full-suite regression run)
- **Issue:** `SERVICE_HISTORY_HOLD_HARNESS`'s `isServiceEvents` check matched any URL containing `/api/events/history`, with no `port` scoping. This plan's own marker rail introduces a second, independent, unfiltered consumer of that same endpoint (fired in parallel on every History render). `test_indicator_and_clear_present_and_operable_while_service_request_pending` therefore held 3 fetches instead of the 2 it expected, so its `wait_for_function('window.__heldServiceReleases.length === 2')` predicate never became true and Chromium's CSP-vs-eval interaction surfaced as a confusing `EvalError` after prolonged polling rather than a clean timeout.
- **Fix:** Scoped the harness's `isServiceEvents` check to `url.includes('port=')`, matching only the selected service's own scoped events fetch (`fetchServiceEventsHistory` always includes `&port=`) and leaving the marker rail's unfiltered fetch un-held.
- **Files modified:** `tests/test_history_investigation_ui.py`
- **Verification:** The previously-failing test passes; full `tests/test_history_investigation_ui.py` suite (126 tests) green.
- **Committed in:** `638d287`

**2. [Rule 2 - Missing Critical] `.hist-back`'s relative `max-width: 100%` did not guarantee truncation this plan's own acceptance criteria require**
- **Found during:** Task 3 (own new truncation test)
- **Issue:** A 120-character custom `Back` label did not visually overflow at the default test viewport, since `max-width: 100%` of the (wide) range-control row let the button grow to accommodate most of the text without triggering `text-overflow: ellipsis`.
- **Fix:** Changed `.hist-back`'s `max-width` from `100%` to a fixed `320px`, matching `.investigating-service`'s own existing convention, so a long label truncates regardless of viewport width.
- **Files modified:** `dashboard/advanced.css`
- **Verification:** `test_long_investigating_label_and_back_label_truncate_without_moving_presets` passes; full suite green.
- **Committed in:** `638d287`

---

**Total deviations:** 2 auto-fixed (1 Rule 1 bug in a pre-existing test harness this plan's own legitimate new fetch surfaced, 1 Rule 2 missing-critical CSS fix required by this plan's own acceptance criteria)
**Impact on plan:** No scope creep. Both fixes are narrowly scoped to the exact surface this plan's own new, legitimate work introduced or required; no acceptance criterion, verification command, or documented contract was weakened.

## Issues Encountered

None beyond the deviations above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 4's full historical-investigation surface (host charts, service history, incidents, and now correlation) is complete: shared range control, gap-honest charts, per-service state/latency/availability/failure-class history, filterable incidents with focus/navigation-stack, neutral markers, and the cross-chart cursor.
- R-01's two halves are both on the record: `04-03-SUMMARY.md`'s ~360ms four-chart render baseline and this plan's ~10.9ms mean per-frame cursor-interaction baseline -- both developer-machine measurements Phase 6's OPS-01 will hold to a Pi-hardware verdict.
- R-03 (Phase 5 accessibility debt) gains no new items from this plan beyond what `04-CONTEXT.md` already flagged for drag-to-select and the hover cursor at creation time -- the marker rail's own keyboard path (Tab to a marker or cluster, Enter/Space to activate, matching an incident row's own keyboard affordance) is delivered, not deferred.
- `DIA-07` promoted to complete. `DIA-06`/`DIA-08` remain for the phase-level verifier, per the precedent `04-06-SUMMARY.md`/`04-07-SUMMARY.md` established for those joint requirements.
- No blockers for Phase 4 verification or Phase 5.

## Self-Check: PASSED

All modified files found on disk; commit hash `638d287` found in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*
