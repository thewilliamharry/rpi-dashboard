---
phase: 04-historical-investigation
plan: 06
subsystem: ui
tags: [vanilla-js, svg, history, service-selection, state-band, availability, failure-classes]

# Dependency graph
requires:
  - phase: 04-historical-investigation
    provides: "04-05's range stack, drag-select, and Pi-local-time range fields the service view's own re-render piggybacks on"
  - phase: 04-historical-investigation
    provides: "04-02's GET /api/events/history (episode grouping, overrun grace/fault split) supplying the band's maintenance-suppressed spans"
  - phase: 04-historical-investigation
    provides: "04-03's mergeStripSegments/coverage-strip machinery and renderCoverageStrip, reused verbatim by the latency chart"
provides:
  - "setSelectedService/clearSelectedService: the single carried, read-only service-selection entry point published by a Services-table row control and the History service picker alike, with no change to the parameterless /api/advanced/current request"
  - "deriveBandSegments/mergeBandSegments/renderServiceStateBand: the four-state (online/offline/unknown/maintenance) horizontal band, proportionally split per bucket and reclassified against maintenance-suppressed/overrun-grace spans"
  - "renderLatencyChart/latencyValueDomain: the service latency chart and its own coverage strip (#strip-service-latency), reusing buildSeriesPath/renderCoverageStrip verbatim with no state shading in the plot"
  - "timeWeightedAvailability/renderAvailability/maintenanceAttributedSeconds: the time-weighted availability headline (observed-seconds-only, Unknown on zero observation) and its expandable exact-second detail, never adjusted for maintenance"
  - "aggregateFailureClasses/renderFailureClassChips: the sorted, wrapping failure-class chip list beside the band"
affects: [04-07, 04-08]

# Actuals (#2632)
actuals:
  tokens: 23279
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "The investigate toggle on each Services-table row is `position: absolute` and explicitly sized/specificity-scoped (#services-table .service-investigate-toggle), taking it entirely out of the identity <th>'s CSS Grid row/column sizing -- three in-flow placements were each found to distort the row's fixed 44px height or the existing .service-details-toggle's own spanned area before this one proved stable"
    - "renderServiceHistorySection is a dedicated staleness-guard generation (state.serviceHistoryRequestGeneration) independent of the host stack's own state.historyRequestGeneration, and its fetch runs unawaited from renderHistorySection so a slow or failed service-history request never delays or blanks the host chart stack above it"
    - "maintenanceSuppressedSpans (built once, from episodes) is reused by both the band's per-segment reclassification (Task 2) and the availability detail's maintenance-attributed-seconds figure (Task 3), so the two can never quietly disagree about which seconds are maintenance-covered"
    - "The latency chart and its coverage strip reuse the host stack's own histTimeToX/histValueToY/buildSeriesPath/renderCoverageStrip functions verbatim by keying #strip-service-latency off the metric string 'service-latency' -- no new chart-rendering vocabulary was introduced"

key-files:
  created: []
  modified:
    - dashboard/advanced.html
    - dashboard/advanced.js
    - dashboard/advanced.css
    - tests/test_history_investigation_ui.py
    - tests/test_advanced_ui.py

key-decisions:
  - "fetchServiceHistory (Task 2's own named function per the plan's action text) was implemented in full -- including the Promise.allSettled composition of both /api/telemetry/history?kind=service and /api/events/history -- as part of Task 1's own commit, since Task 1's own acceptance criteria require the request to fire and the loading/error states to work correctly the moment a selection exists. Task 2's commit therefore builds the band/latency rendering on top of an already-working fetch pipeline, mirroring the exact precedent 04-05-SUMMARY.md recorded for its own Task 1/Task 2 split"
  - "Unknown and gap seconds are folded into one 'unknown' band sub-segment (never a fifth band state) -- both mean 'we did not observe a definite online/offline state' to an operator reading the four-state band, and the band's own wire vocabulary carries no 'gap' literal"
  - "A segment born from a bucket carrying both online and offline seconds (mixedWith) never merges with a neighbour in either direction -- its exact per-bucket second counts and below-resolution-ordering caveat would otherwise be silently absorbed into a neighbour's plain duration label"
  - "The availability detail's observed/unknown/gap/maintenance-attributed rows use a dedicated exactSecondsLabel formatter, not the existing formatSpan largest-unit formatter -- the plan's own must-have text requires disclosing '500 unknown seconds' verbatim, and formatSpan would have rounded that to '8 minutes'"
  - "The failure-class chip count copy ('1 failure class' / '{N} failure classes') is its own inline pluralization rule, not the existing generic countLabel helper -- countLabel's bare-'s' pluralization would have rendered 'classs'"

patterns-established:
  - "A carried selection (state.preferences.selectedService) is validated with the same null-or-bounded-integer discipline as historyRange's own validator, persisted under the same versioned beacon-advanced-preferences-v1 key, and consumed read-only by a second section without that section ever writing back into the first section's own request contract -- reusable by 04-07/04-08 if either introduces its own carried, cross-section value"
  - "scheduleBandTooltipUpdate reuses the exact shared #history-chart-tooltip element and requestAnimationFrame-coalescing the host chart's point tooltips (schedulePointTooltipUpdate) already established, generalized to plain text rather than a (metric, point) pair -- reusable by any future SVG element needing hover-and-keyboard-focus disclosure through the same shared tooltip"

requirements-completed: [HIS-02, HIS-03]

coverage:
  - id: D1
    description: "A service selected in the Services table becomes the History section's own selection and vice versa, read-only in both directions, with no change to the parameterless /api/advanced/current request; hostile stored values resolve to no selection; the indicator and its Clear action stay usable through loading and a failed fetch"
    requirement: "DIA-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_selecting_service_in_table_sets_indicator_and_carries_to_history_picker"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_selecting_service_in_history_picker_shows_selected_in_services_table"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_advanced_current_request_byte_identical_before_and_after_selection"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_clear_selected_service_leaves_range_fields_unchanged"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_hostile_stored_selected_service_values_resolve_to_no_selection"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_no_selection_renders_placeholder_and_issues_no_service_request"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_indicator_and_clear_present_and_operable_while_service_request_pending"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_indicator_and_clear_present_and_operable_after_service_request_fails"
        status: pass
    human_judgment: false
  - id: D2
    description: "The selected service's history renders as a four-state horizontal band on the shared time axis: one uninterrupted state spans the full width with one duration label, a zero-observation bucket renders unknown rather than blank, same-state adjacent buckets merge, different states never merge even sub-pixel, and an offline span overlapping a maintenance-suppressed or overrun-grace episode renders as maintenance"
    requirement: "HIS-03"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_one_uninterrupted_online_range_renders_one_full_width_segment"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_zero_online_and_zero_offline_bucket_renders_unknown_not_blank"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_three_consecutive_same_state_buckets_merge_into_one_segment"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_alternating_subpixel_states_never_merge"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_offline_overlapping_maintenance_suppressed_episode_renders_maintenance"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_mixed_bucket_segment_title_discloses_exact_counts_and_ordering_caveat"
        status: pass
    human_judgment: false
  - id: D3
    description: "The latency chart sits beneath the band on the identical time axis, breaking its path at non-observed coverage intervals and rendering one coverage-strip segment per non-observed interval, with no state shading in the plot itself"
    requirement: "HIS-03"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_latency_chart_breaks_at_non_observed_coverage_and_strip_renders_two_segments"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_latency_plot_background_matches_plain_plot_background_in_both_themes"
        status: pass
      - kind: other
        ref: "grep -q 'strip-service-latency' dashboard/advanced.html"
        status: pass
    human_judgment: false
  - id: D4
    description: "Time-weighted availability sums online/offline seconds only, is invariant to bucket order, renders Unknown (never 0% or 100%) on zero observation, and is never adjusted for maintenance -- attribution appears only in the expandable exact-second detail"
    requirement: "HIS-02"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_900_online_100_offline_renders_90_percent"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_adding_unknown_seconds_leaves_availability_unchanged_and_discloses_in_detail"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_zero_online_and_zero_offline_renders_unknown_never_0_or_100_percent"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_reversed_bucket_order_produces_identical_availability"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_maintenance_suppressed_downtime_still_counts_in_headline"
        status: pass
    human_judgment: false
  - id: D5
    description: "Failure classes render as a stable, complete, wrapping chip list beside the band: sorted by descending count then ascending class name, an explicit 'N failure classes' count including zero, wrapping to a second line at narrow widths"
    requirement: "HIS-03"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_two_equal_count_failure_classes_render_in_ascending_name_order"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_no_failures_renders_zero_failure_classes"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_failure_class_chip_list_wraps_at_narrow_viewport"
        status: pass
    human_judgment: false

duration: 100min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 6: Selected-Service History Summary

**One carried, read-only service selection between the Phase 3 Services table and the History section, rendering the selected service as a four-state (online/offline/unknown/maintenance) band with its latency chart beneath it, a time-weighted availability figure, and a sorted failure-class chip list -- all on the shared time axis.**

## Performance

- **Duration:** ~100 min
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- `setSelectedService`/`clearSelectedService` is the single entry point a Services-table row control (`#service-investigate-{port}`) and the History section's `#history-service-picker` both call; the selection is validated (`null` or an integer port 1..65535), persisted under the existing `beacon-advanced-preferences-v1` key, and never adds a parameter to `/api/advanced/current` -- verified byte-identical before and after a selection, and the full Phase 3 `test_advanced_ui.py`/`test_advanced_diagnosis_api.py` suites re-run green as a task gate
- `Investigating: {name}` (`#investigating-service`) and its `Clear` action (`#clear-selected-service`) render from client-side state alone, requiring no fetch, and stay visible and operable while a service-history request is pending and after it fails
- `fetchServiceHistory` composes `/api/telemetry/history?kind=service` and `/api/events/history` in parallel via `Promise.allSettled`; a failed events fetch still renders the band and latency chart from telemetry alone (with a disclosed note that maintenance reclassification is unavailable) rather than blanking the whole service view
- `deriveBandSegments`/`mergeBandSegments`/`renderServiceStateBand` render the selected service's four-state band: proportional online/offline/unknown sub-segments per bucket, unknown+gap seconds folded into one honest `unknown` sub-segment, same-state adjacent segments merged into one duration label, different states never merged even sub-pixel, and an offline sub-segment overlapping a maintenance-suppressed or overrun-grace episode span reclassified to `maintenance`
- `renderLatencyChart` sits beneath the band on the identical time axis, reusing `buildSeriesPath`/`renderCoverageStrip` verbatim (`#strip-service-latency`) -- no state shading ever applied to the latency plot
- `timeWeightedAvailability`/`renderAvailability` write a 28px headline percentage (or `Unknown`, never `0%`/`100%`) beside the range bounds, with an expandable detail disclosing exact observed/unknown/gap/maintenance-attributed second counts; the headline is never adjusted for maintenance (03.1 D-09)
- `aggregateFailureClasses`/`renderFailureClassChips` sum the server's own failure-class vocabulary verbatim into `{class}: {count}` chips, sorted by descending count then ascending class name, preceded by an explicit `N failure classes` count
- `REQUIREMENTS.md` HIS-02 and HIS-03 promoted to complete; DIA-06 deliberately left pending -- this plan delivers only the service-selection half of "selecting a service, incident, or time range updates related views," the incident half is 04-07's own scope, matching the precedent 04-05-SUMMARY.md recorded for the same requirement

## Task Commits

1. **Task 1: One service selection, carried read-only across every section** - `6bf55b1` (feat) -- includes `fetchServiceHistory`/`renderServiceHistorySection` in full (see Decisions Made)
2. **Task 2: The state band — merged where honest, never merged where it would lie** - `20c9ef5` (feat)
3. **Task 3: Time-weighted availability and failure classes for the range** - `d02dafe` (feat)

**Plan metadata:** committed by the orchestrator after this SUMMARY

## Files Created/Modified

- `dashboard/advanced.html` - `#investigating-service-row` (picker/indicator/clear), `#service-history-group` with its loading/empty/error triplet, `#service-history-content` wrapping `#service-state-band`, the availability headline/detail, `#failure-class-chips`, and the `#service-latency-chart`/`#strip-service-latency` pair
- `dashboard/advanced.js` - `validSelectedService`, `setSelectedService`, `clearSelectedService`, `renderInvestigatingIndicator`, `renderHistoryServicePicker`, `fetchServiceHistory`, `renderServiceHistorySection` (Task 1); `SERVICE_BAND_STATES`, `MIN_BAND_SEGMENT_PX`, `maintenanceSuppressedSpans`, `deriveBandSegments`, `mergeBandSegments`, `renderServiceStateBand`, `bandSegmentTooltipText`, `scheduleBandTooltipUpdate`, `latencyValueDomain`, `renderLatencyChart` (Task 2); `timeWeightedAvailability`, `maintenanceAttributedSeconds`, `exactSecondsLabel`, `renderAvailability`, `aggregateFailureClasses`, `renderFailureClassChips` (Task 3); `state.preferences.selectedService`/`state.serviceHistoryRequestGeneration`; the Services-table row's `.service-investigate-toggle` control (`renderServices` extended in place)
- `dashboard/advanced.css` - `.service-primary`/`.service-investigate-toggle` (identity-cell layout, see Deviations), `.hist-investigating-row`/`.investigating-service`/`.hist-clear-service`, `.hist-service-group`/`.hist-service-content`, `.hist-state-band`/`.hist-band-segment`/`.hist-band-{online,offline,unknown,maintenance}`, `.hist-band-header`/`.hist-availability-headline`/`.hist-availability-detail`, `.hist-failure-chips`/`.hist-failure-chip-count`/`.hist-failure-chip-list`/`.hist-failure-chip`
- `tests/test_history_investigation_ui.py` - `_service`/`_service_point`/`_episode`/`_service_history_fixture`/`_events_history_fixture` fixture helpers, 24 new Playwright tests across selection carry-through, band derivation/merging/reclassification, the latency chart, availability, and failure-class chips; two pre-existing 04-03 assertions scoped to `#history-content` (see Deviations)
- `tests/test_advanced_ui.py` - the pinned preference-key allowlist in `test_refresh_pause_and_allowlisted_preferences_are_local_and_defensive` extended to include `selectedService`

## Decisions Made

- `fetchServiceHistory`'s full `Promise.allSettled` composition of both endpoints was implemented in Task 1's own commit (not deferred to Task 2, where the plan's action text formally introduces it), because Task 1's own acceptance criteria ("selecting a service ... drives the service request", "present and operable while pending and after it fails") require a real, working request/loading/error pipeline to exist already. Task 2's commit builds `deriveBandSegments`/`renderServiceStateBand` on top of that already-fetched data -- the same precedent 04-05-SUMMARY.md recorded for its own `setInvestigationRange` split
- Unknown and gap seconds are folded into one `unknown` band sub-segment rather than a fifth state, since the band's wire vocabulary is exactly the four current-diagnosis literals (`online`/`offline`/`unknown`/`maintenance`) and both mean "no definite online/offline observation" to an operator
- A `mixedWith`-flagged segment (a bucket split into both online and offline) never merges with a neighbour, preserving its exact per-bucket disclosure rather than letting it be silently absorbed into an adjacent duration label
- The availability detail's second counts use a dedicated `exactSecondsLabel` formatter (not the existing `formatSpan` largest-unit formatter), since the plan's own must-have text requires disclosing the literal second count (e.g. "500 unknown seconds"), which `formatSpan` would round to "8 minutes"
- The failure-class chip count uses its own inline pluralization ("1 failure class" / "{N} failure classes") rather than the existing generic `countLabel` helper, whose bare-`s` pluralization would render "classs"

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] The Services-table investigate control intercepted the existing Show-details button's clicks/hover across three consecutive layout attempts**
- **Found during:** Task 1 (full-suite regression run)
- **Issue:** Adding a second interactive control to the identity `<th>` (already a two-row CSS Grid packing name/port beside a row-spanning "Show details" button, all within the row's fixed 44px total height) broke `.service-details-toggle`'s own geometry three different ways in sequence: (a) a stacked third grid row overflowed the 44px budget and visually covered the *next* row's button; (b) an inline flex sibling of the name text distorted `.service-details-toggle`'s spanned-row height to ~88px, again covering the next row; (c) once repositioned as `position: absolute` to remove it from grid flow entirely, an absolutely-positioned grid child with no explicit `grid-column`/`grid-row` was found to default its containing block to the *whole* grid area and stretch to fill it (Chromium's grid-absolute-positioning default), silently covering `.service-details-toggle` in column 2 and intercepting its own hover/click; and even after constraining `top`/`left`/an explicit `width`/`height`, the existing `#services-table th button { width: 100%; }` rule (an ID selector, undefeated by a bare class) still overrode the fixed size.
- **Fix:** A single-glyph (`☆`/`★`) `position: absolute` toggle, explicitly sized (`18px × 18px`) and scoped with an ID-qualified selector (`#services-table .service-investigate-toggle`) to out-specificity the pre-existing `#services-table th button` rules, anchored to the identity cell's own `position: relative` top-left corner with the name text's own left padding reserving its gutter.
- **Files modified:** `dashboard/advanced.css`, `dashboard/advanced.js`
- **Verification:** Full `tests/test_advanced_ui.py` (118/118), `tests/test_advanced_diagnosis_api.py`, and `tests/test_history_investigation_ui.py` suites green; full project suite (689 tests) green.
- **Committed in:** `6bf55b1` (Task 1 commit)

**2. [Rule 1 - Bug] Two pre-existing 04-03 regression assertions enumerated a fifth `.hist-plot`/`.hist-coverage-strip` element once the latency chart existed**
- **Found during:** Task 2 (full-suite regression run)
- **Issue:** `test_four_charts_render_in_fixed_order_with_independent_coverage_strips` queried the bare `.hist-plot`/`.hist-coverage-strip` classes across the whole document and asserted exactly the four host-chart IDs; `#service-latency-chart`/`#strip-service-latency` legitimately reuse those same classes verbatim (per the plan's own action text) and live in the DOM (inside a `hidden` sibling container) even when no service is selected.
- **Fix:** Scoped both selectors to `#history-content` (the host stack's own container, which `#service-history-group` sits outside of as a sibling) rather than the whole document -- no assertion content changed, only the query's scope.
- **Files modified:** `tests/test_history_investigation_ui.py`
- **Verification:** `test_four_charts_render_in_fixed_order_with_independent_coverage_strips` passes; full `tests/test_history_investigation_ui.py` suite green.
- **Committed in:** `20c9ef5` (Task 2 commit)

**3. [Rule 1 - Bug] The pinned preference-key allowlist test needed the new `selectedService` key**
- **Found during:** Task 1 (full-suite regression run)
- **Issue:** `test_refresh_pause_and_allowlisted_preferences_are_local_and_defensive` asserts the exact set of keys `savePreferences` writes to `localStorage`; adding the required `selectedService` key (per the plan's own action text) is a legitimate, plan-mandated addition to that set, exactly as 04-01 previously added `historyRange` to the same pinned assertion.
- **Fix:** Extended the expected key set to include `selectedService`.
- **Files modified:** `tests/test_advanced_ui.py`
- **Verification:** `test_refresh_pause_and_allowlisted_preferences_are_local_and_defensive` passes; full `tests/test_advanced_ui.py` suite green.
- **Committed in:** `6bf55b1` (Task 1 commit)

**4. [Rule 1 - Bug] The generic `countLabel` helper mispluralized "failure class"**
- **Found during:** Task 3 (own new test run)
- **Issue:** `countLabel(0, 'failure class')`'s bare-`s` pluralization rule produced "0 failure classs" instead of "0 failure classes".
- **Fix:** Wrote the failure-class chip count as its own inline pluralization rule rather than reusing `countLabel`, which remains unchanged for its existing callers (gaps/streams/jobs).
- **Files modified:** `dashboard/advanced.js`
- **Verification:** `test_no_failures_renders_zero_failure_classes` passes.
- **Committed in:** `d02dafe` (Task 3 commit)

---

**Total deviations:** 4 auto-fixed (all Rule 1 -- three are layout/assertion adjustments forced by this plan's own legitimate new surface, one is a genuine copy bug caught by this plan's own new test)
**Impact on plan:** No scope creep. Every fix is either a correctness fix contained to the new control's own layout, or a narrow-scope adjustment to a pre-existing test whose assumption this plan's own explicit deliverables surpass. No acceptance criterion, verification command, or documented contract was weakened.

## Issues Encountered

None beyond the deviations above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `setSelectedService`/`clearSelectedService`/`window` state (`state.preferences.selectedService`) is ready for 04-07's Incidents section to read and filter by, without new plumbing -- selecting an incident row's own service could call the identical entry point.
- `maintenanceSuppressedSpans` is a pure function over episodes, reusable by 04-07's own incident-row rendering (e.g. an `Expected` chip) without modification.
- `deriveBandSegments`/`mergeBandSegments`/`renderServiceStateBand` and `renderLatencyChart` are complete and independently verified; 04-08's cross-chart hover cursor (D-17) can extend the same shared `#history-chart-tooltip`/`requestAnimationFrame`-coalescing pattern this plan's `scheduleBandTooltipUpdate` already establishes.
- `HIS-02`/`HIS-03` promoted to complete in `REQUIREMENTS.md`. `DIA-06` deliberately left pending -- 04-07 owns its incident-selection half; only once both plans' evidence exists should a verifier promote it.
- No blockers for 04-07 or 04-08.

## Self-Check: PASSED

All modified files found on disk; all three commit hashes (`6bf55b1`, `20c9ef5`, `d02dafe`) found in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*
