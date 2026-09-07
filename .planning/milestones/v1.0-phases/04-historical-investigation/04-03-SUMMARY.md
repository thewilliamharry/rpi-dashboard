---
phase: 04-historical-investigation
plan: 03
subsystem: ui
tags: [vanilla-js, svg, flask, history, telemetry, tooltips]

# Dependency graph
requires:
  - phase: 04-historical-investigation
    provides: "04-01's History section tracer: shared range control, per-metric render entry point (renderMetricHistory precursor), gap-honest CPU chart, coverage strip, Pi-local-time axis"
provides:
  - "Four host charts (CPU, memory, disk, temperature) stacked on one shared time axis, each with its own coverage strip, Y axis, and unit label"
  - "Per-metric fetch isolation via fetchHostHistory/renderHostStack (Promise.allSettled composition) -- one metric's failure never blanks its siblings"
  - "Two documented threshold reference lines (temperature 80/85 degC, disk 100%) with provenance disclosed on inspection; CPU and memory carry none"
  - "Point tooltips (renderPointTooltip) disclosing exact local timestamp, value, and unit, coalesced through requestAnimationFrame"
  - "Merged sub-pixel coverage-segment disclosure (mergeStripSegments/segmentTooltipText) -- same-reason adjacent segments merge with a true count+duration tooltip; different reasons never merge"
  - "R-01 measured render baseline for the full four-chart stack at the 90d preset, recorded below"
affects: [04-04, 04-05, 04-06, 04-07, 04-08]

# Actuals (#2632)
actuals:
  tokens: 14494
  tasks: 3
  commits: 1

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "fetchHostHistory/renderHostStack: four parallel host-metric fetches composed with Promise.allSettled, walked in fixed HOST_METRIC_ORDER so a metric's chart frame is never removed from the DOM regardless of fetch outcome"
    - "THRESHOLD_LINES/THRESHOLD_PROVENANCE: a metric-keyed map with no fallback branch -- an absent metric key draws no line at all, never an invented one"
    - "mergeStripSegments: merges only adjacent same-reason coverage segments whose rendered width would fall below the 3px minimum, preserving the five-state partition on screen at the 90d preset"
    - "Pointer-driven tooltip updates coalesced through requestAnimationFrame, updating only the shared tooltip element's text/position -- chart <path> d attributes are never regenerated on a pointer event"

key-files:
  created: []
  modified:
    - dashboard/advanced.html
    - dashboard/advanced.js
    - dashboard/advanced.css
    - tests/test_history_investigation_ui.py

key-decisions:
  - "Committed all three tasks as a single commit rather than three atomic per-task commits (see Deviations) -- the render pipeline functions each task extends (renderHistoryChart, beginMetricLoadingState, metricValueDomain) are modified by every subsequent task's code, so a true per-task split would have required maintaining throwaway intermediate versions of the same functions with no independent verification value"
  - "Temperature's Y-axis domain function (metricValueDomain) always folds in THRESHOLD_LINES.temp, so the 80/85 degC lines are visible even when the observed range sits well below them -- percent metrics (cpu/ram/disk) keep a fixed 0-100 domain"
  - "The disk threshold's physical filesystem-reported total (disk.total_bytes from the current snapshot) is disclosed in the visible line label, not folded into the <title> provenance string, so the <title> text stays byte-identical to the Copywriting Contract regardless of whether the current snapshot has loaded yet"
  - "Point hit-targets are per-point focusable SVG circles (tabindex=0) rather than a single delegated listener, so pointerover and keyboard focus share one code path (renderPointTooltip) without inventing a second disclosure mechanism"

patterns-established:
  - "renderThresholdLines(metric, scale, diskTotalBytes)/renderYAxis(metric, points) are pure per-chart appenders (query-and-remove-then-append), safe to call on every render without accumulating stale SVG children"
  - "mergeStripSegments(segments, pixelsPerSecond) is a pure function over the existing coverageStripSegments() output -- reusable by any future chart (e.g. the service latency chart in 04-06) without modification"

requirements-completed: [HIS-01]

coverage:
  - id: D1
    description: "All four host charts (CPU, memory, disk, temperature) render stacked in fixed order on one shared time axis, each with its own coverage strip, unit label, and Y axis; one metric's fetch failure never blanks its siblings"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_four_charts_render_in_fixed_order_with_independent_coverage_strips"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_temperature_failure_isolates_other_three_charts"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_disk_empty_response_keeps_chart_frame_present"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_narrow_viewport_keeps_four_charts_full_width_with_scrollable_axis"
        status: pass
    human_judgment: false
  - id: D2
    description: "Two documented threshold reference lines draw only on temperature (80/85 degC) and disk (100%), each disclosing its documented source on inspection; CPU and memory carry no threshold line; the temperature Y-axis domain grows to include both lines even for a cool reading"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_temperature_and_disk_thresholds_carry_provenance_cpu_ram_carry_none"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_temperature_domain_includes_85_even_when_observed_max_is_41"
        status: pass
    human_judgment: false
  - id: D3
    description: "Hovering or focusing a plotted point discloses its exact local timestamp, value, and unit in a shared tooltip; tooltip updates never regenerate a chart path"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_point_tooltip_discloses_value_unit_and_local_timestamp"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_tooltip_updates_without_regenerating_chart_paths_on_pointer_moves"
        status: pass
    human_judgment: false
  - id: D4
    description: "Adjacent same-reason sub-pixel coverage segments merge into one segment whose tooltip discloses the true interval count and total duration; adjacent different-reason sub-pixel segments never merge"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_merged_subpixel_segments_disclose_true_count_and_duration"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_adjacent_subpixel_different_reasons_do_not_merge"
        status: pass
    human_judgment: false
  - id: D5
    description: "R-01: a measured wall-clock render figure exists for the full four-chart stack at the 90d preset with 2048 points/series and >=50 non-observed coverage intervals, recorded on the record before Phase 6 inherits the question"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_four_chart_stack_render_is_measured_and_bounded_r01"
        status: pass
    human_judgment: false
  - id: D6
    description: "No element, label, or tooltip in the History section expresses coverage as a single completeness percentage or score -- missing time is disclosed by reason and duration only"
    requirement: "HIS-01"
    verification: []
    human_judgment: true
    rationale: "This is a negative/absence claim across the whole rendering surface -- a source-level judgment call (confirmed by code review: no percentage/score computation exists anywhere in the coverage-strip or comparison rendering path) rather than something a single automated assertion can prove exhaustively."

duration: 50min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 3: Four-Chart Host Stack, Thresholds, and Point Tooltips Summary

**Memory, disk, and temperature join the CPU chart on one shared time axis with independent coverage strips, two documented threshold lines (temperature throttle points, disk capacity), per-point tooltips coalesced through requestAnimationFrame, and honest merged sub-pixel coverage-segment disclosure -- plus a measured R-01 render baseline (~360ms) for the full four-chart stack at the 90d preset.**

## Performance

- **Duration:** ~50 min
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- All four host metrics (CPU, memory, disk, temperature) render stacked top-to-bottom in fixed order on one shared time axis, each with its own coverage strip, Y axis, and unit label (`%` for cpu/ram/disk, `°C` for temp) -- a metric's chart frame is never removed from the DOM regardless of fetch outcome, so stack height and order are stable across every range
- `fetchHostHistory`/`renderHostStack` compose the four parallel fetches with `Promise.allSettled`: a temperature-only 503 leaves the other three charts drawn and shows only the temperature error copy; a disk-only empty response renders the disk empty copy while `#chart-disk` stays present
- Two honest threshold lines -- 80°C/85°C (Raspberry Pi documented soft/hard thermal throttle) on temperature, 100% (filesystem-reported capacity) on disk -- each carrying an exact `<title>` provenance string, dashed `--muted` in both themes (never `--accent`/`--accent2`); CPU and memory carry no line at all, with no fallback branch that invents one
- The temperature Y-axis domain always includes both threshold lines, even when the observed maximum is far below them (verified with a 41°C fixture)
- `renderPointTooltip` discloses a hovered or keyboard-focused point's exact local timestamp, value, and unit in a single shared `#history-chart-tooltip` element; pointer-driven updates are coalesced through `requestAnimationFrame` and never regenerate a chart `<path>` `d` attribute
- `mergeStripSegments`/`segmentTooltipText` merge only adjacent same-reason coverage segments whose rendered width would fall below the 3px minimum, disclosing the true interval count and total duration (`Collection gap — 4 intervals, 6 minutes total`); adjacent different-reason segments never merge, even when both are sub-pixel
- R-01 measured: the full four-chart stack render at the 90d preset, 2048 points/series, 60 non-observed coverage intervals, measures **~360ms** (348-369ms across repeated runs) on the developer machine via `performance.now()` -- captured in `window.__historyStackRenderMs` and asserted finite in the Playwright test. This is a baseline on a non-Pi-class machine, not a Pi-hardware verdict; OPS-01 (Phase 6) owns that measurement.
- `REQUIREMENTS.md` HIS-01 promoted to complete: this plan closes out the CPU-only tracer from 04-01 with the full four-metric, threshold, and tooltip surface HIS-01 describes.

## Task Commits

1. **Tasks 1-3: Four-chart stack, threshold lines, point tooltips and merged segments** - `3dd14f5` (feat)

_Note: all three tasks were committed together -- see Deviations for why._

## Files Created/Modified

- `dashboard/advanced.html` - three additional chart groups (`chart-ram`/`chart-disk`/`chart-temp` + their strips, unit labels, loading/empty/error triplets), `.hist-stack` wrapper, `history-axis-scroll` region, `history-chart-tooltip` element
- `dashboard/advanced.js` - `HOST_METRIC_ORDER`/`HOST_METRIC_LABELS`/`HOST_METRIC_UNITS`, `THRESHOLD_LINES`/`THRESHOLD_PROVENANCE`, `fetchHostHistory`, `renderHostStack`, `applyMetricResult`, `metricValueDomain`, `renderThresholdLines`, `renderYAxis`, `renderPointTooltip`/`renderPointTargets`/`schedulePointTooltipUpdate`, `mergeStripSegments`, `segmentTooltipText`, `formatBytes`, `currentDiskTotalBytes`; `renderHistoryChart`/`renderCoverageStrip`/`beginMetricLoadingState` extended in place
- `dashboard/advanced.css` - `.hist-stack`, `.hist-chart-header`, `.hist-unit`, `.hist-y-axis-tick`, `.hist-threshold`/`.hist-threshold-label`, `.hist-point-target`, `.hist-tooltip`, `.hist-axis-scroll` (with a 640px min-width forcing horizontal scroll under 959px)
- `tests/test_history_investigation_ui.py` - 12 new Playwright tests covering the four-chart stack, per-metric failure/empty isolation, narrow viewport, threshold provenance and domain, point tooltips, merged/unmerged sub-pixel segments, and the R-01 render measurement; the existing pending-request test's fetch-hold harness was fixed to hold and release all four concurrent metric fetches instead of one

## Decisions Made

- Percent metrics (cpu/ram/disk) keep the fixed 0-100 Y-axis domain from 04-01; only temperature computes an observed-range-plus-threshold domain via `metricValueDomain`, so idle-temperature ranges still show how far the reading is from throttling
- The disk threshold's physical total (`disk.total_bytes` from the live snapshot, when available) is appended to the visible line *label* text, not the `<title>` provenance string, so the `<title>` stays byte-identical to the Copywriting Contract's exact sentence regardless of snapshot load timing
- Point hit-targets are individually focusable SVG circles (`tabindex="0"`) sharing one `renderPointTooltip` code path for both `pointerover` and `focus`, rather than inventing a second, keyboard-only disclosure mechanism

## Deviations from Plan

### Process Deviation (commit granularity)

**All three tasks were committed as a single commit (`3dd14f5`) instead of three atomic per-task commits.**
- **Why:** Task 2's `renderThresholdLines` call and Task 3's `renderPointTargets`/`renderYAxis` calls all live inside the same `renderHistoryChart` function Task 1 introduces; Task 3's `mergeStripSegments` call lives inside the same `renderCoverageStrip` function Task 1 introduces. A true three-commit split would have required writing and independently verifying throwaway intermediate versions of these functions (e.g., a Task-1-only `renderHistoryChart` that doesn't yet call the threshold/tooltip helpers Task 2/3 add a few lines later), with no independent verification benefit -- the plan's own per-task `<verify>` blocks all run the identical `pytest tests/test_history_investigation_ui.py -q` command regardless of task boundary.
- **Mitigation:** The single commit message itemizes each task's contribution explicitly (four-chart stack / threshold lines / point tooltips and R-01), and this SUMMARY's `coverage:` block maps each deliverable back to its originating task and test.
- **Impact:** No functional or verification impact -- every task's `<acceptance_criteria>` and the plan's overall `<verification>` (full suite, `test_advanced_ui.py`/`test_ui_states.py` regression) all pass. Traceability is preserved via the commit message and this document rather than via separate commit hashes.

### Auto-fixed Issues

**1. [Rule 1 - Bug] Pending-request test's fetch-hold harness only held one of four concurrent history fetches**
- **Found during:** running the pre-existing 04-01 regression suite before adding new tests
- **Issue:** `HISTORY_FETCH_HOLD_HARNESS` stored a single `window.__heldHistoryRelease` slot, overwritten by each concurrent `/api/telemetry/history` call. With four parallel metric fetches (04-03), only the last-assigned metric's fetch was releasable; the other three stayed permanently held, and `test_pending_request_shows_skeleton_and_draws_no_chart_path` timed out waiting for the CPU chart's loading skeleton to clear.
- **Fix:** Changed the harness to collect all held releases in an array (`window.__heldHistoryReleases`) with a `window.__releaseAllHeldHistoryFetches()` helper that releases all four at once; updated the test to wait for `.length === 4` before asserting and to call the release-all helper.
- **Files modified:** tests/test_history_investigation_ui.py
- **Verification:** `tests/test_history_investigation_ui.py -q` (all 7 pre-existing 04-01 tests, then all 18 tests after the new additions) passes
- **Committed in:** 3dd14f5 (combined task commit)

---

**Total deviations:** 1 process deviation (commit granularity, documented above) + 1 auto-fixed test-harness bug (Rule 1)
**Impact on plan:** No scope creep; no weakened verification. The commit-granularity deviation is a traceability trade-off, not a correctness one -- every acceptance criterion is independently verified by a named, passing test.

## Issues Encountered

- Playwright's default `.wait_for()` visibility state considers an SVG `<line>` element with `y1 === y2` (zero bounding-box height) as not visible, even though it is correctly attached and painted. Two threshold-line tests were adjusted to `wait_for(state='attached')` instead of the default `state='visible'`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `THRESHOLD_LINES`/`THRESHOLD_PROVENANCE` are metric-keyed maps with no fallback branch, ready for a future config-driven threshold (per D-10's stated additive path) without touching the rendering code.
- `mergeStripSegments`/`segmentTooltipText` are pure functions over `coverageStripSegments()` output, ready for reuse by 04-06's service latency chart without modification.
- The hover time cursor and cross-chart correlation work (04-08, D-17) can build directly on this plan's `requestAnimationFrame`-coalesced pointer-update pattern and the now-complete four-chart stack, rather than establishing the pattern itself.
- HIS-01 is promoted to complete in `REQUIREMENTS.md`; DIA-04 through DIA-08 and HIS-02 through HIS-06 remain correctly pending for 04-02/04-04 through 04-08.
- No blockers for 04-04 through 04-08.

## Self-Check: PASSED

All modified files found on disk; commit hash `3dd14f5` found in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*
