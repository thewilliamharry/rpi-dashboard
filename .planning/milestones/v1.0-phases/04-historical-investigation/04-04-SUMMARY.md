---
phase: 04-historical-investigation
plan: 04
subsystem: ui
tags: [vanilla-js, svg, flask, history, telemetry, trend, dst]

# Dependency graph
requires:
  - phase: 04-historical-investigation
    provides: "04-03's four-chart host stack (CPU/memory/disk/temperature) on one shared time axis, each with its own coverage strip and point tooltips"
  - phase: 04-historical-investigation
    provides: "04-01's shared range control, per-metric render entry point, and Pi-local-time shared axis (formatLocalTimestamp, state.timezone)"
provides:
  - "leastSquaresSlope/trendDisplay: a least-squares slope over observed points only, withheld under 3 points, low-confidence-qualified from 3-9, unqualified at 10+, flat-banded to 'steady', expressed per-hour for spans <=24h and per-day beyond -- never a projection"
  - "rangeAggregate/formatComparisonValue/renderComparisonRow: the per-chart HIS-06 comparison row (latest/minimum/maximum/average/trend), all describing the same selected-range window, with latest always carrying its own exact local timestamp"
  - "dstAnnotations/localWallClockMinutes: DST fall-back and spring-forward detection on the shared time axis, derived entirely from Intl.DateTimeFormat's own local labels for the configured zone -- no manual UTC-offset arithmetic or transition table"
affects: [04-05, 04-06, 04-07, 04-08]

# Actuals (#2632)
actuals:
  tokens: 10433
  tasks: 3
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "usableTrendPoints: the single observed-points filter shared by leastSquaresSlope and trendDisplay -- finiteMeasurement's absence discipline plus a ts-ascending sort, so the slope is provably invariant to caller order"
    - "window.__historyTrendTestHooks: a test-only global exposing leastSquaresSlope/trendDisplay for Playwright, matching the existing window.__historyStackRenderMs pattern for functions the IIFE otherwise keeps private"
    - "localWallClockMinutes/dstAnnotations: a signed 60-minute mismatch between a tick's local-label delta and its fixed epoch delta is sufficient to detect and classify a DST transition, independent of tick spacing and requiring no transition-date table"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - dashboard/advanced.html
    - dashboard/advanced.css
    - tests/test_history_investigation_ui.py
    - .planning/REQUIREMENTS.md

key-decisions:
  - "trendDisplay's metric label is HOST_METRIC_LABELS[metric].toLowerCase() (cpu/memory/disk/temperature), not the capitalized chart-header label -- matching the UI-SPEC's own lower-cased copy example ('disk +0.4%/day ↑') rather than the capitalized HOST_METRIC_LABELS used elsewhere in the file"
  - "DST detection compares a 'naive' local wall-clock minute index (built from Intl.DateTimeFormat's own year/month/day/hour/minute parts via Date.UTC) against the fixed epoch interval between adjacent ticks, rather than literal string-equality on rendered labels -- this generalizes correctly to any tick spacing, not just an exact 1-hour spacing, while still deriving every comparison from Intl output and never from manual offset arithmetic"
  - "HistoryDstAnnotationLondonTests/HistoryDstAnnotationUtcTests are new, separate TestCase classes (own app/server per TZ) rather than reusing HistoryInvestigationUiTests -- that class's app is loaded once for Australia/Sydney via load_app()'s module-level importlib.reload(), and a second reload mid-class would silently rewrite the shared dashboard.app module namespace every already-bound route handler on that class's still-running server reads its SETTINGS from"
  - "renderComparisonRow is called for every fulfilled per-metric outcome, including an empty-points response -- rangeAggregate's null-safe reduction already renders the documented 'Unknown'/'Not enough data for a trend' copy for that case, so no additional branch was needed in applyMetricResult"

patterns-established:
  - "leastSquaresSlope/trendDisplay/rangeAggregate/formatComparisonValue/renderComparisonRow are pure-then-render pairs over the same points array renderHistoryChart already fetched -- no second request is issued, reusable verbatim by the service latency chart in a later plan"
  - "dstAnnotations(tickTimestamps) is a pure function over an array of tick epoch seconds, returning one nullable annotation per tick -- reusable by any future axis (e.g. a per-service history axis) without modification"

requirements-completed: [HIS-06]

coverage:
  - id: D1
    description: "Each host chart's comparison row shows latest, minimum, maximum, average and trend for the selected range; latest always carries its own exact local timestamp"
    requirement: "HIS-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_comparison_row_ids_present_for_all_four_metrics"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_comparison_row_reports_known_minimum_maximum_and_weighted_average"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_comparison_row_latest_never_reads_as_current_for_past_ending_range"
        status: pass
    human_judgment: false
  - id: D2
    description: "An empty range renders Unknown for latest/minimum/maximum/average and the withheld trend string, never a fabricated 0; equal minimum and maximum still render all four values with a steady trend"
    requirement: "HIS-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_comparison_row_empty_range_renders_unknown_not_zero"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_comparison_row_equal_min_max_still_renders_all_values_with_steady_trend"
        status: pass
    human_judgment: false
  - id: D3
    description: "leastSquaresSlope returns the exact gradient of a linear series, zero for a flat series, and is unaffected by null avg_value points; trendDisplay withholds under 3 usable points, qualifies 3-9 as low confidence, is unqualified at 10+, flat-bands to steady with no sign or arrow, switches from per-hour to per-day at spans beyond 86400s, and never emits projection wording"
    requirement: "HIS-06"
    verification:
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_least_squares_slope_over_exact_gradient_returns_that_gradient"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_least_squares_slope_over_flat_series_returns_zero"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_least_squares_slope_skips_null_avg_value_points"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_trend_display_withheld_below_three_usable_points_regardless_of_slope"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_trend_display_low_confidence_at_three_and_nine_points"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_trend_display_no_qualifier_at_ten_points"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_trend_display_steady_band_has_no_sign_or_arrow"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_trend_display_uses_hourly_unit_at_24h_and_daily_unit_just_beyond"
        status: pass
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_trend_display_never_contains_a_projection"
        status: pass
    human_judgment: false
  - id: D4
    description: "A range straddling a spring-forward instant under a DST-observing zone annotates exactly the tick after the skip with '⚠ DST transition' and a <title> naming the absent hour; a range straddling a fall-back instant annotates precisely the two ticks whose local labels are identical; the same two ranges under UTC never annotate any tick"
    requirement: "HIS-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#HistoryDstAnnotationLondonTests.test_spring_forward_annotates_exactly_one_tick_naming_absent_hour"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#HistoryDstAnnotationLondonTests.test_fall_back_annotates_the_two_identical_local_label_ticks"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#HistoryDstAnnotationUtcTests.test_spring_forward_range_under_utc_has_no_annotation"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#HistoryDstAnnotationUtcTests.test_fall_back_range_under_utc_has_no_annotation"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-08-25
status: complete
---

# Phase 4 Plan 4: Trend, Comparison Row, and DST Axis Honesty Summary

**Every host chart now carries a comparison row (latest/minimum/maximum/average/trend) computed
over the same selected-range window, with a least-squares slope that is withheld under three
points, low-confidence-qualified under ten, flat-banded to "steady", and never extrapolated into a
projection -- and the shared time axis explicitly labels the one ambiguous and one absent hour a
DST-observing zone produces each year instead of silently rendering a compressed or duplicate
tick.**

## Performance

- **Duration:** ~25 min
- **Tasks:** 3
- **Files modified:** 5 (4 code/test + 1 requirements doc)

## Accomplishments

- `leastSquaresSlope(points)` computes the closed-form least-squares gradient of `avg_value`
  against `ts` over only the points whose `avg_value` is a finite measurement (per
  `finiteMeasurement`'s existing absence discipline), sorted ascending by `ts` so the result is
  provably invariant to caller order; fewer than two usable points returns `null`
- `trendDisplay(metric, points, spanSeconds)` turns that slope into the exact contracted copy:
  withheld (`Not enough data for a trend`) under 3 usable points, low-confidence-qualified
  (`{metric} {sign}{value}{unit}/{hour|day} {arrow} (low confidence — {N} points)`) from 3-9,
  unqualified at 10+, flat-banded to `{metric} steady` (no sign, no arrow) when the rounded
  one-decimal magnitude is zero, and switching from a per-hour to a per-day unit at spans beyond
  86400 seconds -- the predicted-change quantity used internally to decide the flat band is never
  rendered, and no output ever names a projected date, a remaining-time quantity, or a "will reach"
  claim
- `rangeAggregate(points)` reduces the fetched points array to minimum (smallest `min_value`),
  maximum (largest `max_value`), a `sample_count`-weighted average of `avg_value` matching the
  server's own `_compose_host_bucket` weighting, and the `latest_value` of the latest point that
  has one, together with that point's `ts`; a range with zero usable points reports every value as
  `null`, which `formatComparisonValue` renders as `Unknown` -- never a fabricated `0`
- `renderComparisonRow(metric, points, spanSeconds)` writes `Latest: {value} (as of {exact local
  timestamp})`, `Minimum`, `Maximum`, `Average`, and the trend into each chart's new
  `comparison-{metric}` element, reusing the points array `renderHistoryChart` already fetched (no
  second request) and formatting the latest value's timestamp through the existing
  `formatLocalTimestamp` so a range ending in the past can never be read as a current reading
- `dstAnnotations(tickTimestamps)` and its `localWallClockMinutes` helper detect DST transitions on
  the shared axis by comparing a naive local wall-clock minute index (built entirely from
  `Intl.DateTimeFormat`'s own parts for the configured zone) against the fixed epoch interval
  between adjacent ticks -- a signed 60-minute mismatch is a DST transition regardless of tick
  spacing, with no manual UTC-offset arithmetic and no hard-coded transition date. A fall-back
  annotates both of the two ticks whose local labels are now identical; a spring-forward annotates
  only the tick after the skipped hour; under `UTC` (including the config fail-closed case) no
  annotation can ever fire, verified directly rather than special-cased
- `REQUIREMENTS.md` HIS-06 promoted to complete

## Task Commits

1. **Task 1 RED: failing trend tests** - `4aedf6c` (test)
2. **Task 1 GREEN: least-squares trend with three confidence tiers** - `a3f2f14` (feat)
3. **Task 2: per-chart range comparison row** - `29e8ede` (feat)
4. **Task 3: DST transitions labelled on the shared axis** - `5e03497` (feat)

## Files Created/Modified

- `dashboard/advanced.js` - `TREND_MIN_POINTS`/`TREND_CONFIDENT_POINTS`/`TREND_HOURLY_MAX_SPAN_SECONDS`,
  `usableTrendPoints`, `leastSquaresSlope`, `trendDisplay`, `window.__historyTrendTestHooks`,
  `rangeAggregate`, `formatComparisonValue`, `renderComparisonRow`, `localWallClockMinutes`,
  `dstAnnotations`; `applyMetricResult` now calls `renderComparisonRow` for every fulfilled outcome,
  `beginMetricLoadingState` clears the comparison row alongside the chart/strip, and
  `renderSharedTimeAxis` renders annotated ticks with the `hist-dst-tick` class and a `<title>`
  instead of the normal timestamp label
- `dashboard/advanced.html` - `comparison-{cpu,ram,disk,temp}` markup added immediately beneath each
  chart's coverage strip
- `dashboard/advanced.css` - `.hist-comparison`/`.hist-comparison-value`/`.hist-trend` (reusing the
  `.evidence-row` visual language at 14px body/mono) and `.hist-dst-tick` (`--accent2`, text+glyph,
  never colour alone)
- `tests/test_history_investigation_ui.py` - 9 trend unit tests via `window.__historyTrendTestHooks`,
  5 comparison-row end-to-end tests, and two new `TestCase` classes
  (`HistoryDstAnnotationLondonTests`/`HistoryDstAnnotationUtcTests`) covering spring-forward,
  fall-back, and the UTC no-annotation case
- `.planning/REQUIREMENTS.md` - HIS-06 marked complete (checkbox + traceability row)

## Decisions Made

- `trendDisplay`'s metric label is the lower-cased `HOST_METRIC_LABELS` value (`cpu`, `memory`,
  `disk`, `temperature`), matching the UI-SPEC's own lower-cased copy example (`disk +0.4%/day ↑`)
  rather than the capitalized labels used for chart headers elsewhere in the file
- DST detection compares a naive local wall-clock minute index against the fixed epoch interval
  between adjacent ticks, rather than literal string-equality on rendered labels — this correctly
  generalizes to any tick spacing (not only an exact 1-hour spacing) while still deriving every
  comparison from `Intl.DateTimeFormat` output, never from manual offset arithmetic
- The two new DST test classes each load their own app/server instance per timezone rather than
  reusing `HistoryInvestigationUiTests` — that class's app is loaded once for `Australia/Sydney` via
  `load_app()`'s module-level `importlib.reload()`, and a second reload mid-class would rewrite the
  shared `dashboard.app` module namespace every already-bound route handler on that class's
  still-running server reads its `SETTINGS` from
- `renderComparisonRow` is invoked for every fulfilled per-metric outcome, including an
  empty-points response — `rangeAggregate`'s null-safe reduction already produces the documented
  `Unknown`/`Not enough data for a trend` copy for that case, so no additional branch was needed in
  `applyMetricResult`

## Deviations from Plan

None — plan executed exactly as written. Task 1 followed the TDD RED→GREEN flow (a `test` commit
followed by a `feat` commit); Tasks 2 and 3 were not marked `tdd="true"` in the plan and were
committed as single `feat` commits including their own tests, per the plan's own action text for
each.

One in-flight self-correction during Task 1's GREEN commit: an early draft of a code comment
literally contained the phrase `will reach` (inside a negation, e.g. `no "will reach"`), which
tripped the plan's own forbidden-phrase grep gate against `dashboard/advanced.js`. Reworded the
comment to describe the same constraint without using any of the five forbidden phrases; no
behavioral code changed. This is a same-task authoring correction, not a deviation from the plan's
intent.

## Issues Encountered

- Playwright's `.text_content()` on an SVG `<text>` element that has a `<title>` child concatenates
  the title's text into the result. Two DST assertions were adjusted from exact equality to
  `startswith('⚠ DST transition')` to isolate the tick's own visible label from its `<title>`
  disclosure text — the rendered DOM and the underlying `dstAnnotations` logic were already correct;
  only the test's read of `text_content()` needed the fix.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `leastSquaresSlope`/`trendDisplay`/`rangeAggregate`/`formatComparisonValue`/`renderComparisonRow`
  are pure-then-render pairs over an already-fetched points array, ready for reuse by the service
  latency chart in 04-05/04-06 without modification.
- `dstAnnotations(tickTimestamps)` is a pure function over an array of tick epoch seconds, ready for
  reuse by any future shared axis (e.g. a per-service history axis) without modification.
- HIS-06 is promoted to complete in `REQUIREMENTS.md`. DIA-04 through DIA-07 and HIS-02 through
  HIS-05 remain correctly pending for later plans in this phase.
- No blockers for 04-05 through 04-08.

## Self-Check: PASSED

All modified files found on disk; all four commit hashes (4aedf6c, a3f2f14, 29e8ede, 5e03497) found
in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-25*
