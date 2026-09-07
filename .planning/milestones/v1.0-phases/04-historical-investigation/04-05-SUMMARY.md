---
phase: 04-historical-investigation
plan: 05
subsystem: ui
tags: [vanilla-js, svg, history, range-control, navigation-stack, drag-select]

# Dependency graph
requires:
  - phase: 04-historical-investigation
    provides: "04-01's shared six-preset range control, historyRange preference schema, and Pi-local-time formatting infrastructure (state.timezone, formatLocalTimestamp)"
  - phase: 04-historical-investigation
    provides: "04-03's four-chart host stack (CPU/memory/disk/temperature) sharing one time axis, which drag-to-select narrows"
provides:
  - "parseLocalRangeInput/formatLocalRangeInput/validateCustomRange: explicit local-time custom-range entry, interpreted in the Pi's configured timezone and validated against exactly the server's own HistoricalRange/api_telemetry_history bounds"
  - "setInvestigationRange/pushRange/popRange/clearRangeStack: the single entry point and in-memory navigation stack every narrowing gesture (preset, custom apply, drag -- and plan 04-07's incident focus) shares, bounded by RANGE_STACK_LIMIT and never persisted or URL-visible"
  - "renderRangeFields/renderBackControl: the fields as the authoritative, statable representation of the current range from every source, and a Back control created/removed from the DOM (never merely hidden) only while the stack is non-empty"
  - "beginDragSelect/updateDragSelect/commitDragSelect/cancelDragSelect: drag-to-select across any host chart, rAF-coalesced, touching only the single reused #history-drag-overlay rectangle and never a chart <path>"
  - "INCIDENT_PAD_FRACTION (0.15) / INCIDENT_PAD_FLOOR_SECONDS (300): the incident-window padding rule plan 04-07 applies when it pushes an incident focus onto this stack"
affects: [04-07, 04-08]

# Actuals (#2632)
actuals:
  tokens: 16905
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "parseLocalRangeInput reuses the existing DST-aware localWallClockMinutes technique (naive local-minutes vs. a candidate instant, corrected iteratively) rather than manual UTC-offset arithmetic, so custom-range entry and axis DST detection share one timezone-correction primitive"
    - "setInvestigationRange(next) is the single state-mutation entry point for range changes -- origin: 'manual' clears the stack, origin: 'drag'|'incident' pushes the range being left unless the resulting bounds are a no-op -- so every future narrowing gesture (04-07's incident focus) plugs into the same contract without new stack logic"
    - "The Back control is created/removed from the DOM by JS rather than toggled via the `hidden` attribute, so an empty stack leaves it genuinely absent (unreachable), not present-and-disabled"
    - "The drag overlay is one reused, position:fixed element (matching the existing .hist-tooltip precedent) geometrically driven from the specific chart's own bounding rect, never regenerated chart paths -- window.__historyRangeTestHooks exposes the range/stack primitives for direct Playwright-driven stack testing, independent of which gesture triggers a push"

key-files:
  created: []
  modified:
    - dashboard/advanced.html
    - dashboard/advanced.js
    - dashboard/advanced.css
    - tests/test_history_investigation_ui.py

key-decisions:
  - "setInvestigationRange (D-15's single entry point) was implemented in full -- including the navigation stack -- as part of Task 1's own commit, since Task 1's custom-range apply already routes through it per the plan's own action text ('routes through the single setInvestigationRange(...) entry point that Task 2 introduces'). Task 2's commit is therefore test-only (its own stack-specific Playwright coverage), following the exact precedent 04-01-SUMMARY.md recorded for its own Task 2"
  - "The historyRange preference descriptor is either {preset} or {custom: {start_ts, end_ts}}; resolveRangeBounds recomputes a preset's bounds from Date.now() on every call (so a live preset stays live) but returns a custom descriptor's two integers unchanged"
  - "The custom-range text fields use a plain YYYY-MM-DD HH:MM format (regex-parsed), not the native <input type=datetime-local>, because a datetime-local input's value is interpreted and displayed in the browser's own timezone with no way to force the Pi's configured zone -- exactly the D-05 violation the UI-SPEC and RESEARCH.md Pitfall 1/Anti-Pattern flag"
  - "The drag overlay maps pixels to time using the specific chart SVG's own bounding rect captured at pointerdown, not the container's rect, so a drag over any one chart lands on exactly that chart's own rendered span with no cross-element padding offset"
  - "Renamed a Task 1 constant from CUSTOM_RANGE_INPUT_PATTERN to CUSTOM_RANGE_TEXT_PATTERN after discovering its 'PUT' substring tripped test_advanced_ui.py's existing forbidden-mutation-verb source scan (Rule 1 fix, folded into the Task 2 commit)"

patterns-established:
  - "A caller-supplied `label` argument to setInvestigationRange names the range being left (computed by the caller via currentRangeLabel() before the change), so the Back control's 'Back to {label}' text is accurate regardless of which gesture triggered the push"
  - "window.__historyRangeTestHooks exposes parseLocalRangeInput/formatLocalRangeInput/validateCustomRange/setInvestigationRange/pushRange/popRange/clearRangeStack/resolveRangeBounds/RANGE_STACK_LIMIT, matching the existing window.__historyTrendTestHooks pattern -- reusable by 04-07's incident-focus tests without new plumbing"

requirements-completed: []

coverage:
  - id: D1
    description: "A custom local-time start/end range can be entered and applied, validated against exactly the server's own bounds (blank/whitespace, reversed/equal, over-90-day span, future-ending) before any request is issued, with every rejection string matching the server's own wording"
    requirement: "DIA-05"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_blank_start_field_renders_message_and_issues_zero_requests"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_equal_start_and_end_renders_server_message_and_issues_zero_requests"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_reversed_start_and_end_rejected_values_not_swapped"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_span_over_90_days_renders_server_message_and_issues_zero_requests"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_future_end_renders_server_message_and_issues_zero_requests"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_valid_custom_range_issues_request_with_parsed_bounds_in_configured_timezone"
        status: pass
    human_judgment: false
  - id: D2
    description: "The start/end fields always state the currently governing range -- after a preset click, after a custom apply, and after a reload with a stored custom range -- and a hostile stored custom range (strings, nulls, an inverted pair) falls back to the 24h default with no request built from it"
    requirement: "DIA-05"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_fields_populated_after_preset_click_custom_apply_and_reload_with_stored_custom"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_fields_populated_after_reload_with_stored_custom_range"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_hostile_stored_custom_range_yields_24h_default"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_apply_button_disabled_while_in_flight_fields_stay_visible"
        status: pass
    human_judgment: false
  - id: D3
    description: "One shared navigation stack serves drag and (later) incident focus: Back is absent from the DOM with an empty stack, three pushes followed by three pops restore the original range exactly in LIFO order, a no-op push (identical bounds) creates no entry, a manual preset/custom-apply change clears the stack, and the stack never exceeds RANGE_STACK_LIMIT"
    requirement: "DIA-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_range_back_absent_when_stack_empty_present_after_one_push"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_three_pushes_and_three_backs_restore_original_range_exactly"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_push_of_identical_range_creates_no_entry"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_preset_after_pushes_clears_stack_and_adopts_preset"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_custom_apply_after_pushes_clears_stack"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_stack_never_exceeds_range_stack_limit"
        status: pass
      - kind: other
        ref: "tests/test_history_investigation_ui.py#test_range_stack_never_reaches_the_url_or_browser_history_api"
        status: pass
    human_judgment: false
  - id: D4
    description: "Dragging across any host chart narrows the range through the same setInvestigationRange entry point as the fields/presets -- left-to-right and right-to-left drags of the same span produce identical ranges, a click without movement applies nothing, Escape cancels cleanly, and no chart <path> is regenerated during the gesture while the overlay geometry visibly changes"
    requirement: "DIA-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_drag_across_chart_applies_fraction_of_rendered_span"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_right_to_left_drag_produces_identical_range_to_left_to_right"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_click_without_movement_applies_no_range_and_leaves_back_absent"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_escape_during_drag_cancels_no_range_change_and_overlay_hidden"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_five_pointer_moves_leave_chart_paths_unchanged_while_overlay_moves"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_drag_overlay_border_resolves_accent_and_fill_is_not_solid"
        status: pass
      - kind: other
        ref: "tests/test_history_investigation_ui.py#test_drag_entry_point_documents_missing_keyboard_equivalent_as_phase5_debt"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 5: Custom Range Entry, Navigation Stack, and Drag-to-Select Summary

**Explicit local-time start/end fields as the canonical, always-current range representation; one shared in-memory navigation stack (`pushRange`/`popRange`/`Back`) that drag-to-select narrows into and a manual range change clears; and rAF-throttled drag-select across any host chart that never regenerates a chart path.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Operator can type an explicit local-time start and end into `#range-start`/`#range-end` and click `Apply custom range`; the text is interpreted in the Pi's configured timezone (never the browser's) via `parseLocalRangeInput`, which reuses the same DST-aware naive-local-minutes correction the shared axis already uses for DST tick detection
- `validateCustomRange` applies exactly the server's own `HistoricalRange`/`api_telemetry_history` bounds and surfaces the server's own rejection wording verbatim for blank/whitespace, reversed, equal, over-90-day, and future-ending input -- zero requests are ever issued on an invalid submission, and the previously rendered charts are left untouched
- `setInvestigationRange` is the single entry point every range change (preset, custom apply, drag) flows through; it owns an in-memory, browser-local navigation stack bounded by `RANGE_STACK_LIMIT` (20), pushing the range being left on a drag/incident-origin change (skipping a no-op push when the resulting bounds are unchanged) and clearing the stack entirely on a manual preset/custom-apply change
- The `Back` control (`#range-back`) is created and removed from the DOM by JS -- never merely hidden -- so an empty stack leaves it genuinely unreachable; its text and `title` read `Back to {label}`, naming the range a pop restores
- `#range-start`/`#range-end` are re-rendered after every range change from any source (preset, custom apply, drag, `Back`, and once the Pi's timezone loads), keeping them the authoritative, statable representation of the current range at all times; a stored custom range with a string, null, or inverted pair falls back to the documented 24h default with no request built from it
- Dragging across any of the four host charts (`beginDragSelect`/`updateDragSelect`/`commitDragSelect`) narrows the range through the identical `setInvestigationRange` entry point; a right-to-left drag produces the same range as left-to-right, a click without movement or an Escape press cancels cleanly, and pointer-driven updates touch only the single reused `#history-drag-overlay` rectangle -- verified directly that every chart `<path>` `d` attribute is unchanged across five pointer moves during a live drag
- `INCIDENT_PAD_FRACTION` (0.15) and `INCIDENT_PAD_FLOOR_SECONDS` (300) declared for plan 04-07's incident-window padding rule

## Task Commits

1. **Task 1: Custom local-time range entry, validated before anything is fetched** - `8f57cf0` (feat) -- includes `setInvestigationRange`/`pushRange`/`popRange`/`clearRangeStack` in full, since Task 1's own custom-apply path routes through that entry point per the plan's action text
2. **Task 2: One navigation stack for every narrowing gesture** - `dae6bca` (test) -- the stack's own code was already generic from Task 1; this commit's delta is the stack-specific Playwright coverage plus a Rule 1 constant-rename fix
3. **Task 3: Drag-to-select across any chart, without redrawing a single series** - `3a5a884` (feat)

**Plan metadata:** committed by the orchestrator after this SUMMARY

## Files Created/Modified

- `dashboard/advanced.html` - `range-back-row`, `hist-range-fields` (with `range-start`/`range-end`/`apply-custom-range`), `range-custom-label`, `history-drag-overlay` markup added to the shared range control and chart stack
- `dashboard/advanced.js` - `boundsForPreset`, `parseLocalRangeInput`, `formatLocalRangeInput`, `validateCustomRange`, `currentRangeLabel`, `pushRange`, `popRange`, `clearRangeStack`, `renderRangeFields`, `renderBackControl`, `applyRangeAndRender`, `setInvestigationRange`, `applyCustomRange` (Tasks 1-2); `RANGE_STACK_LIMIT`, `INCIDENT_PAD_FRACTION`, `INCIDENT_PAD_FLOOR_SECONDS`, `state.rangeStack`, `state.historyBounds` constants/state; `beginDragSelect`, `updateDragSelect`, `commitDragSelect`, `cancelDragSelect`, `clientXToTs`, `updateDragOverlayGeometry` (Task 3); `resolveRangeBounds`/`selectRangePreset`/`validHistoryRange`/`renderHistorySection`/`fetchRuntimeConfig` extended to compose with the above; `window.__historyRangeTestHooks` test-only hook
- `dashboard/advanced.css` - `.hist-range-fields`, `.hist-range-active`, `#apply-custom-range`, `.hist-range-custom-label`, `.hist-back-row`, `.hist-back`, `.hist-drag-select` styling; `.hist-range-error` class added alongside the existing `#range-error` id
- `tests/test_history_investigation_ui.py` - 30 new tests across custom-range validation/persistence, navigation-stack contract, and drag-to-select gesture coverage

## Decisions Made

- `setInvestigationRange` (D-15's shared entry point) was fully implemented -- stack included -- in the Task 1 commit rather than stubbed, because Task 1's own custom-range apply path explicitly routes through it per the plan text. Task 2's commit is therefore `test`-only, mirroring the exact precedent 04-01-SUMMARY.md recorded for its own Task 2 (code already generic from an earlier task; the task's delta is its own tests)
- Custom-range text fields use a plain `YYYY-MM-DD HH:MM` format, not `<input type="datetime-local">`, because that native control is interpreted and displayed in the browser's own timezone with no way to force the Pi's configured zone -- exactly the violation RESEARCH.md Pitfall 1 and the UI-SPEC's D-05 warn against
- The drag overlay maps pixels to time using the specific chart SVG's own bounding rect captured at `pointerdown` (not the container's), so a drag over any one chart lands on exactly that chart's own rendered span
- Renamed `CUSTOM_RANGE_INPUT_PATTERN` to `CUSTOM_RANGE_TEXT_PATTERN` (Rule 1 fix) after its `PUT` substring tripped `test_advanced_ui.py`'s existing forbidden-mutation-verb source scan

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Renamed a Task 1 constant whose substring tripped an existing regression test**
- **Found during:** Task 1 (full-suite regression run)
- **Issue:** `CUSTOM_RANGE_INPUT_PATTERN` contains the substring `PUT`, which `test_advanced_ui.py`'s existing forbidden-mutation-verb source scan (`POST`/`PUT`/`PATCH`/`DELETE`/...) flags against `dashboard/advanced.js` -- an incidental substring collision, not an actual mutation verb
- **Fix:** Renamed to `CUSTOM_RANGE_TEXT_PATTERN`; no behavioral change
- **Files modified:** dashboard/advanced.js
- **Verification:** Full suite green (665 passed / 486 subtests) after the rename
- **Committed in:** `dae6bca` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 -- incidental forbidden-substring collision, no behavioral change)
**Impact on plan:** No scope creep; the fix is a pure identifier rename.

## Issues Encountered

- `color-mix(in srgb, var(--accent) 18%, transparent)` serializes in this Chromium build as `color(srgb r g b / a)` rather than `rgba(...)`. The drag-overlay fill test was adjusted to read the real alpha channel back via a 1x1 canvas (`fillStyle` + `getImageData`) instead of pattern-matching a specific CSS serialization string -- the underlying CSS and the rendered fill were already correct; only the test's read of the computed style needed the fix.
- `tests/test_worker_ownership_matrix.py::test_heartbeat_renewal_to_persistence_handoff_is_fenced` failed twice under full-suite load (a `threading.Event.wait(timeout=2)` race unrelated to this plan's files) but passed cleanly both times it was run in isolation and passed on the final full-suite run reported above. Not fixed here -- out of this plan's scope (no file in `<files>` touches worker ownership) per the SCOPE BOUNDARY rule; flagged for awareness, not remediation.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `setInvestigationRange`/`pushRange`/`popRange`/`window.__historyRangeTestHooks` are ready for 04-07's incident-focus feature to reuse verbatim: an incident row's `Show transitions` action need only call `setInvestigationRange({start_ts, end_ts, origin: 'incident', label})` with the padded window `INCIDENT_PAD_FRACTION`/`INCIDENT_PAD_FLOOR_SECONDS` already declare the rule for.
- `currentRangeLabel()` is reusable as-is for naming the range an incident focus leaves.
- No blockers for 04-06, 04-07, or 04-08.
- `requirements-completed` is deliberately left `[]`: DIA-05 (custom range) is functionally complete by this plan alone, but DIA-06 ("Selecting a service, incident, or time range updates related host, service, and event views as one investigation context") is only partially delivered here -- the time-range/navigation-stack half, not the service/incident-selection half 04-06/04-07 add. This mirrors 04-01-SUMMARY.md's own precedent of leaving DIA-04 pending despite delivering its core mechanics: promotion is left to the phase-level verifier once every contributing plan has landed, not claimed by the plan that happens to land first.

## Self-Check: PASSED

All modified files found on disk; all three commit hashes (8f57cf0, dae6bca, 3a5a884) found in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*
