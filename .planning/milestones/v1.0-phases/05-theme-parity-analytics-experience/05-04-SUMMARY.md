---
phase: 05-theme-parity-analytics-experience
plan: 04
subsystem: ui
tags: [aria, keyboard-accessibility, playwright, svg, dual-theme]

# Dependency graph
requires:
  - phase: 05-02
    provides: "FRESHNESS_PRESENTATION and the .freshness-* class family this plan reads alongside (unmodified) while extending the same file's marker/coverage-strip/point-target ARIA and keyboard surfaces"
  - phase: 04-historical-investigation
    provides: "04-REVIEW.md WR-02 (the diagnosed renderMarkerSingle role defect) and 04-CONTEXT.md R-03 (the deferred keyboard-accessibility debt this plan closes)"
provides:
  - "The pinned actionable-vs-disclosure-only ARIA role convention across every focusable SVG element in the History section (A-19): renderMarkerSingle corrected to role=button with an Investigate-prefixed aria-label; renderServiceStateBand and renderPointTargets confirmed unchanged at role=img"
  - "uptimeStrip segments on the main dashboard carry role=img and an aria-label equal to their existing title text, computed once so the two can never drift (A-18)"
  - "Coverage-strip segments (renderCoverageStrip) are keyboard-reachable: tabindex, role=img, an aria-label matching their <title>, and focus/blur wired through the state band's existing scheduleBandTooltipUpdate/hidePointTooltip -- no second tooltip mechanism"
  - "Focusing a chart point target drives the shared cross-chart time cursor (moveTimeCursor) through the identical function the pointer path drives; blur clears it via hideTimeCursor"
  - "applySelectedRange(tsA, tsB) -- the single range-apply function both the mouse drag and a new keyboard range-anchor gesture (beginKeyboardRangeAnchor/completeKeyboardRange/cancelKeyboardRangeAnchor, Shift+Enter/Enter/Escape) call, closing 04-CONTEXT.md R-03's drag-to-select keyboard-equivalent debt"
affects: [05-05, 05-06]

# Actuals (#2632)
actuals:
  tokens: 8595
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Actionable-vs-disclosure-only ARIA convention, pinned by a source-derived test: a focusable element with a click/keydown action carries role=button; a focusable, disclosure-only element carries role=img; no third role appears on any focusable SVG element in the History section without an explicit decision"
    - "Keyboard-focus reuses the exact same shared tooltip/cursor functions the pointer path already drives (scheduleBandTooltipUpdate, hidePointTooltip, moveTimeCursor, hideTimeCursor) -- never a second, parallel mechanism"
    - "One range-apply function is the sole caller of a range-setting entry point for a given gesture family; two input methods (mouse, keyboard) both route through it so they can never diverge (T-05-14)"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - dashboard/app.js
    - dashboard/advanced.css
    - tests/test_history_investigation_ui.py
    - tests/test_ui_states.py

key-decisions:
  - "The History-section role-convention enumeration scopes to SVG elements only (namespaceURI check), deliberately excluding #history-axis-scroll's and #services-table-scroll's pre-existing role=region/tabindex=0 scrollable-landmark pattern -- an orthogonal WCAG 2.1.1 scroll-region convention unrelated to A-19's actionable-vs-disclosure taxonomy, not one of the SVG chart elements this plan's must_haves describe"
  - "The keyboard range-anchor gesture stores the anchored point's own server-supplied ts directly (not a pixel-derived approximation reconstructed from the anchor's client x), since the exact timestamp is already in hand -- more precise than round-tripping through clientXToTs, and empirically produces byte-identical #range-start/#range-end values to the equivalent mouse drag in the new regression"
  - "completeKeyboardRange always calls cancelKeyboardRangeAnchor() after applySelectedRange, regardless of whether a range was actually applied, so anchoring and completing on the same point leaves the current range untouched and the overlay hidden -- matching a zero-width mouse drag's behaviour exactly"
  - "requirements-completed records this plan's own contribution only; UX-06 and OPS-06 stay unmarked in REQUIREMENTS.md per the phase's established convention (05-01/05-02/05-03) -- 05-05 and 05-06 also declare OPS-06 and have not yet executed"

patterns-established:
  - "A focusable SVG element's role is decided once by whether it is click/keydown-actionable (role=button) or disclosure-only (role=img) -- never a third role, pinned by an enumeration test scoped to the SVG namespace"

requirements-completed: [UX-06, OPS-06]

coverage:
  - id: D1
    description: "renderMarkerSingle announces role=button with an Investigate-prefixed aria-label, matching renderMarkerCluster's confirmed-correct pattern (04-REVIEW.md WR-02); the nested <title> keeps its unprefixed text; activating the marker with the keyboard still focuses its incident"
    requirement: "UX-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_actionable_svg_elements_announce_as_buttons_and_disclosure_only_as_images"
        status: pass
    human_judgment: false
  - id: D2
    description: "The role convention is pinned across every focusable SVG element in the History section: the set of distinct roles among tabindex=0 SVG elements is a subset of {button, img}, sized at most 2"
    requirement: "UX-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_actionable_svg_elements_announce_as_buttons_and_disclosure_only_as_images"
        status: pass
    human_judgment: false
  - id: D3
    description: "Each main-dashboard uptime-strip segment carries role=img and a non-empty aria-label equal to its existing title text in both themes"
    requirement: "UX-06"
    verification:
      - kind: e2e
        ref: "tests/test_ui_states.py#test_shared_dashboard_capability_is_present_and_displayed_in_both_themes"
        status: pass
    human_judgment: false
  - id: D4
    description: "Every coverage-strip segment is keyboard-reachable (tabindex=0, role=img), carries an aria-label equal to its hover <title> text (including a segment whose reason carries no observed count), and discloses that same text via the shared tooltip on focus, clearing on blur"
    requirement: "UX-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_coverage_strip_segment_is_keyboard_reachable_and_discloses_on_focus"
        status: pass
    human_judgment: false
  - id: D5
    description: "Tabbing to a chart's point target moves the shared cross-chart time cursor and updates the readout exactly as pointer hover does, driven by the identical moveTimeCursor function; blurring hides both"
    requirement: "UX-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_focusing_a_point_target_moves_the_shared_time_cursor"
        status: pass
    human_judgment: false
  - id: D6
    description: "A keyboard user can select a chart sub-range (Shift+Enter to anchor, Enter on another point to complete) and the applied range is produced by the identical applySelectedRange function the mouse drag calls, in either point-visit order; a pending anchor can be abandoned via Escape without applying anything, including anchor-and-complete on the same single point; an empty-points chart offers no anchor and applies no range"
    requirement: "UX-06"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_keyboard_range_selection_applies_the_same_range_as_the_mouse_drag"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_pending_range_anchor_is_abandoned_without_applying_anything"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_empty_points_fixture_renders_no_point_targets_and_no_key_applies_a_range"
        status: pass
    human_judgment: false
  - id: D7
    description: "The stale R-03 'no keyboard equivalent' debt comment above beginDragSelect is replaced by one naming the equivalent that now exists -- the debt marker is gone from the source, not left beside the code that closes it"
    requirement: "OPS-06"
    verification:
      - kind: unit
        ref: "tests/test_history_investigation_ui.py#test_drag_entry_point_documents_the_keyboard_equivalent_that_closed_the_debt"
        status: pass
    human_judgment: false

duration: 26min
completed: 2026-08-27
status: complete
---

# Phase 5 Plan 04: Keyboard-Accessible Status and Chart Interactions Summary

**The one actionable SVG element (the incident marker) now announces itself correctly, the coverage strip and cross-chart cursor are keyboard-reachable through the pointer path's own shared tooltip/cursor mechanisms, and a new keyboard range-anchor gesture applies chart sub-ranges through the exact same function the mouse drag calls -- closing 04-CONTEXT.md R-03 and 04-REVIEW.md WR-02.**

## Performance

- **Duration:** 26 min
- **Started:** 2026-08-27T14:25:51Z
- **Completed:** 2026-08-27T14:51:42Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments
- `renderMarkerSingle` (dashboard/advanced.js) fixed per 04-REVIEW.md WR-02: `role="img"` → `role="button"`, and its `aria-label` gains an `Investigate ` prefix over the existing marker-title text, matching `renderMarkerCluster`'s already-correct pattern; the nested `<title>` keeps the unprefixed text for hover
- The actionable-vs-disclosure-only role convention (A-19) is pinned by a new regression enumerating every focusable SVG element in the History section — the set of distinct roles is asserted to be a subset of `{button, img}`, so a sixth role can never appear silently
- `uptimeStrip` segments on the main dashboard (dashboard/app.js) gain `role="img"` and an `aria-label` computed once alongside the existing `title` text so the two attributes can never drift (A-18); no `tabindex` is added
- `renderCoverageStrip` segments gain `tabindex`, `role="img"`, and an `aria-label` matching their `<title>`; focus/blur reuse `scheduleBandTooltipUpdate`/`hidePointTooltip` verbatim — the state band's own shared tooltip mechanism, with a matching `.hist-coverage-segment:focus-visible` ring in advanced.css
- `renderPointTargets`'s focus handler now also calls `moveTimeCursor`, so tabbing across a chart's point targets moves the same shared cross-chart cursor the pointer path drives; blur clears it via `hideTimeCursor`
- `applySelectedRange(tsA, tsB)` extracted from `commitDragSelect`'s tail as the single range-apply function; a new keyboard range-anchor gesture (`beginKeyboardRangeAnchor`/`completeKeyboardRange`/`cancelKeyboardRangeAnchor`, driven by Shift+Enter/Enter/Escape on point targets) calls the identical function, closing R-03's drag-to-select keyboard-equivalent debt
- The stale "no keyboard equivalent" comment above `beginDragSelect` is replaced with one naming the equivalent that now exists

## Task Commits

Each task was committed atomically:

1. **Task 1: Roles that tell the truth — the marker fix, the strip's accessible name, and the convention pinned** - `10d4460` (feat)
2. **Task 2: Focus reaches the coverage strip, and moves the shared time cursor** - `a4a633f` (feat)
3. **Task 3: One range-apply function, two gestures** - `f58f065` (feat)

## Files Created/Modified
- `dashboard/advanced.js` - `renderMarkerSingle` role/aria-label fix; `renderCoverageStrip` keyboard reachability; `renderPointTargets` focus-driven cursor and keyboard range-anchor keydown handler; `applySelectedRange`, `beginKeyboardRangeAnchor`, `completeKeyboardRange`, `cancelKeyboardRangeAnchor`, `pendingRangeAnchor`; window Escape listener extended; R-03 comment replaced
- `dashboard/app.js` - `uptimeStrip` segment `role`/`aria-label`
- `dashboard/advanced.css` - `.hist-coverage-segment:focus-visible`
- `tests/test_history_investigation_ui.py` - `test_actionable_svg_elements_announce_as_buttons_and_disclosure_only_as_images`, `test_coverage_strip_segment_is_keyboard_reachable_and_discloses_on_focus`, `test_focusing_a_point_target_moves_the_shared_time_cursor`, `test_keyboard_range_selection_applies_the_same_range_as_the_mouse_drag`, `test_pending_range_anchor_is_abandoned_without_applying_anything`, `test_empty_points_fixture_renders_no_point_targets_and_no_key_applies_a_range`; renamed/rewrote the stale debt-marker test
- `tests/test_ui_states.py` - added the uptime-strip `aria-label`/`title` pairing assertion to the existing dual-theme shared-capability test

## Decisions Made
- The History-section role-convention enumeration scopes to SVG elements only (checked via `namespaceURI`), deliberately excluding the pre-existing `#history-axis-scroll`/`#services-table-scroll` `role="region"`/`tabindex="0"` scrollable-landmark pattern — an orthogonal WCAG 2.1.1 convention unrelated to A-19's actionable-vs-disclosure taxonomy, and not one of the SVG chart elements the plan's own must_haves and read_first files describe. A literal reading of "every tabindex=0 element" would have made this pre-existing, unrelated pattern fail a test this plan never intended to cover
- The keyboard range-anchor gesture stores the anchored point's own server-supplied `ts` directly rather than reconstructing an approximate timestamp from the anchor's screen x position — more precise than a pixel round-trip, and it produces field values identical to the equivalent mouse drag in practice (both converge to the same integer after `applySelectedRange`'s rounding)
- `completeKeyboardRange` always calls `cancelKeyboardRangeAnchor()` after `applySelectedRange`, regardless of whether a range was actually applied, so anchoring and completing on the same single point leaves the current range untouched and the overlay hidden — identical to a zero-width mouse drag
- `requirements-completed` records only this plan's own contribution; `UX-06` and `OPS-06` stay unmarked in `REQUIREMENTS.md`, per the phase's established convention (05-01/05-02/05-03) — `05-05` and `05-06` also declare `OPS-06` and have not yet executed

## Deviations from Plan

### Auto-fixed Issues

None — Rules 1-4 were not triggered by any production-code correctness gap. The one adjustment made was to the plan's own literal test-scope wording, not a deviation from a `<verify>`/acceptance criterion:

**1. [Test-design clarification] Scoped the History-section role-convention enumeration to SVG elements**
- **Found during:** Task 1, first run of `test_actionable_svg_elements_announce_as_buttons_and_disclosure_only_as_images`
- **Issue:** A literal `#history-section [tabindex="0"]` query (matching the plan's action text almost verbatim) also matched `#history-axis-scroll`, a pre-existing, unrelated `role="region"`/`tabindex="0"` scrollable-landmark div (a distinct WCAG 2.1.1 convention, not one of the SVG marker/band/point-target/coverage-strip elements A-19 and this plan's read_first files describe). The unscoped assertion would have failed on day one against code this plan never touches and was never asked to touch
- **Fix:** Filtered the enumeration to nodes whose `namespaceURI` is the SVG namespace before collecting roles, so the assertion covers exactly the actionable-vs-disclosure-only SVG convention the plan establishes, without either loosening the invariant for the elements it actually governs or failing on an orthogonal, already-decided accessibility pattern
- **Files modified:** tests/test_history_investigation_ui.py
- **Verification:** Test passes with the fix; without it, the assertion fails with `{'button', 'img', 'region'}`, confirming the scroll-region div is what triggered it, not a marker/band/point-target/coverage-strip regression
- **Committed in:** `10d4460` (Task 1 commit)

---

**Total deviations:** 0 auto-fixed bugs/missing-critical/blocking issues. 1 test-scoping clarification, resolved within the same task before its commit.
**Impact on plan:** None on production-code behaviour or on any stated acceptance criterion — every acceptance criterion and `<verify>` command in the plan passed as specified. No scope creep.

## Issues Encountered
None beyond the test-scoping clarification above.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The actionable-vs-disclosure-only ARIA role convention is now pinned across every focusable SVG element in the History section; a future plan adding a sixth such element will get an immediate, readable test failure rather than a silent role drift
- `applySelectedRange` is now the single, extractable range-apply function for chart-selected ranges — any future gesture needing to apply a chart sub-range should call it rather than re-deriving `setInvestigationRange`'s bounds/origin/label composition
- `UX-06` and `OPS-06` are **NOT** marked complete in `REQUIREMENTS.md` — `05-05` and `05-06` also declare `OPS-06` and have not yet executed; this plan's `requirements-completed` frontmatter records its own contribution only
- No blockers for the remaining Phase 5 plans (05-05, 05-06)

## Self-Check: PASSED

All created/modified files and all commit hashes referenced above verified present:
- `dashboard/advanced.js`, `dashboard/app.js`, `dashboard/advanced.css`, `tests/test_history_investigation_ui.py`, `tests/test_ui_states.py` — found
- Commits `10d4460`, `a4a633f`, `f58f065` — found in `git log --oneline`

---
*Phase: 05-theme-parity-analytics-experience*
*Completed: 2026-08-27*
