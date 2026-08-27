---
phase: 05-theme-parity-analytics-experience
plan: 06
subsystem: testing
tags: [playwright, css, responsive, theme-parity, ui-contract, cross-surface]

# Dependency graph
requires:
  - phase: 05-04
    provides: "focus-visible/keyboard-affordance styling in dashboard/advanced.css, extended (not modified) by this plan's Task 1"
provides:
  - "One shared narrow layout boundary (720px) across dashboard/style.css and dashboard/advanced.css, pinned at source level"
  - "tests/test_theme_parity_ui.py — the phase's dedicated cross-surface dual-theme UI-contract module: NarrowBoundaryPinTests (breakpoint agreement) and ThemeParityUiTests (boundary-from-both-sides on both documents, and every at-risk narrow layout proven to scroll rather than hide, in both themes)"
affects: []

# Actuals (#2632)
actuals:
  tokens: 8350
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Source-derived breakpoint pin: a regex extracts every @media max-width value from both stylesheets at test time and asserts the shared boundary is present with no near-neighbour within 10px, so an off-by-one reintroduction fails loudly rather than passing a bare membership check"
    - "Cross-surface dual-theme harness: one _route_all(fixture) stubs every endpoint both / and /advanced call, and _open(theme, path, width, fixture) opens a page at a given viewport/theme against the real Flask app, reused by every test in the module"
    - "Boundary-from-both-sides assertion: every narrow-layout claim is paired with a NARROW_BOUNDARY_PX + 1 assertion that the wide layout applies, so a stylesheet narrowed at every width cannot pass"
    - "Counter-based superset check (Python 3.10+ Counter <=) proves the boundary's displayed-control collection is a strict superset of the desktop collection, with both asserted non-empty — closes both the 'lost one, gained one' gap and the empty-vs-empty vacuous-pass gap that a subset/count check would leave open"

key-files:
  created:
    - tests/test_theme_parity_ui.py
  modified:
    - dashboard/advanced.css

key-decisions:
  - "Reconciled the advanced workspace's narrow boundary (719px) up to the main dashboard's existing value (720px), per A-30 — the main dashboard's boundary is older and more widely tested, so moving the smaller/newer surface touches less"
  - "Pin uses a 10px near-neighbour exclusion, not a bare membership check (T-05-23) — a stylesheet that kept 719px alongside a newly-added 720px would pass membership but fail the near-neighbour assertion, which is what actually catches an off-by-one reintroduction"
  - "Chose .metrics-row (main dashboard) and .summary-grid (advanced workspace) as the boundary-crossing grids to assert against — both resolve a real track-count change (3 to 1) at the boundary, satisfying the plan's requirement to assert against a property the narrow query genuinely changes rather than a container with no tracks"
  - "Measured filter-group boundary-vs-desktop comparisons by resizing one already-loaded page's viewport in place (page.set_viewport_size) rather than opening two separate page instances, since the DOM is identical and only CSS reflow differs — simpler and equally valid for this comparison"
  - "Performed the 'nothing hidden to fit' descriptor-superset check while the Services section was active (not a blanket whole-document check) — that is where the plan's at-risk-layout narrative concentrates (table + filters), and is the natural point in the existing test flow to capture both descriptor collections"
  - "Did not deduplicate the descriptor-rule helper with plan 05-05's identical rule, per the plan's own explicit instruction (A-32-adjacent): 05-05 runs in the same wave and its helper is not guaranteed to exist when this executes"

patterns-established:
  - "Cross-surface dual-theme UI-contract module: any future phase needing 'the same viewport width applied to both documents in both themes' gets its own module in this shape, rather than being split across two single-document test files where the shared boundary would be invisible"

requirements-completed: [UX-05, OPS-06]

coverage:
  - id: D1
    description: "dashboard/style.css and dashboard/advanced.css narrow at the same shared 720px boundary, pinned against an off-by-one reintroduction (verified failing against a temporarily restored 719px value, byte-for-byte restored afterward)"
    requirement: "UX-05"
    verification:
      - kind: unit
        ref: "tests/test_theme_parity_ui.py::NarrowBoundaryPinTests::test_both_stylesheets_declare_the_same_narrow_boundary"
        status: pass
    human_judgment: false
  - id: D2
    description: "The shared 720px boundary produces the narrow layout on both / and /advanced, in both dark and light themes, and the wide layout one pixel wider — asserted against a grid property the narrow query genuinely changes, with a harness guard proving the light theme genuinely applied"
    requirement: "UX-05"
    verification:
      - kind: e2e
        ref: "tests/test_theme_parity_ui.py::ThemeParityUiTests::test_the_shared_boundary_produces_the_narrow_layout_on_both_documents_in_both_themes"
        status: pass
    human_judgment: false
  - id: D3
    description: "Every at-risk narrow layout (four-chart host stack, marker rail inheriting the shared axis scroll container, services table scroll with unchanged header count and sticky identity column, both filter groups keeping 44px hit targets and wrapping without overflow, and a superset-proven 'nothing hidden' control census) scrolls rather than hides content at the boundary, in both themes"
    requirement: "OPS-06"
    verification:
      - kind: e2e
        ref: "tests/test_theme_parity_ui.py::ThemeParityUiTests::test_at_risk_narrow_layouts_scroll_rather_than_hide_in_both_themes"
        status: pass
    human_judgment: false
  - id: D4
    description: "OPS-06's coverage is delivered entirely as DOM/computed-style/geometry contract assertions, with zero screenshot-API usage anywhere in the test directory"
    requirement: "OPS-06"
    verification:
      - kind: unit
        ref: "grep -rho 'to_have_screenshot|page.screenshot' tests/ | grep -c '' == 0"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-27
status: complete
---

# Phase 5 Plan 06: Theme-Parity Analytics Experience Summary

**Reconciled the main dashboard's and advanced workspace's narrow breakpoints to one shared 720px value, pinned the agreement at source level against off-by-one drift, and added a dedicated cross-surface dual-theme test module proving the shared boundary and every at-risk narrow layout (host chart stack, marker rail, services table, both filter groups, and a superset-proven "nothing hidden" control census) behave identically on both documents in both themes.**

## Performance

- **Duration:** ~55 min
- **Started:** 2026-08-27T14:25:00Z (approx.)
- **Completed:** 2026-08-27T15:20:00Z
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- `dashboard/advanced.css`'s narrow media query moved from `max-width: 719px` to `max-width: 720px`, matching `dashboard/style.css` exactly; the declaration block inside the query is byte-identical to its pre-change contents
- `tests/test_theme_parity_ui.py::NarrowBoundaryPinTests` extracts every `@media (max-width: Npx)` value from both stylesheets by regex and asserts `NARROW_BOUNDARY_PX` (720) is present in both, with no other declared max-width within 10px of it — verified to genuinely fail (not just theoretically) when the boundary was temporarily restored to 719px, then verified byte-for-byte restored (SHA-256 identical) and passing again
- `ThemeParityUiTests` establishes the module's harness (`load_app` + `werkzeug` + Playwright, mirroring `tests/test_advanced_ui.py`'s shape) and asserts, for all four combinations of `(dark, light) x (/, /advanced)`, that `.metrics-row`/`.summary-grid` resolve exactly one grid track at the boundary and more than one at `boundary + 1`, guarded by a resolved-body-colour check proving the light theme genuinely applied
- `test_at_risk_narrow_layouts_scroll_rather_than_hide_in_both_themes` closes the regression risk on every layout `05-UI-SPEC.md`'s Responsive Contract names at-risk: the four-chart host stack (stacked, non-zero width, scrollable shared axis), the marker rail (displayed, structurally confirmed inside the shared axis's own scroll container — E11, no new CSS), the services table (overflows/scrolls, unchanged header count, sticky identity column), both filter groups (every control at least 44px tall, never overflowing its own group, wrapping to strictly more rows at the boundary for `#service-filters` and at least as many for `#incident-filters`), and a `Counter`-based superset census proving no displayed control present at desktop width disappears at the boundary
- Zero `to_have_screenshot`/`page.screenshot` calls anywhere in `tests/` — OPS-06's coverage is delivered entirely as DOM/computed-style/geometry assertions

## Task Commits

Each task was committed atomically:

1. **Task 1: One narrow boundary, shared and pinned** - `be2f366` (test)
2. **Task 2: The boundary behaves identically on both documents, in both themes** - `e5e2957` (test)
3. **Task 3: At the narrow boundary, content scrolls — it never disappears** - `496738f` (test)

_Note: No TDD tasks in this plan; each commit is the complete test/CSS addition for its task, matching plan 05-03's precedent for this phase._

## Files Created/Modified

- `dashboard/advanced.css` — one media-query boundary value changed (719px → 720px); no other line touched
- `tests/test_theme_parity_ui.py` (new) — `NarrowBoundaryPinTests` and `ThemeParityUiTests`, three tests total

## Decisions Made

See `key-decisions` in frontmatter. Most notable: the descriptor-rule helper for the "nothing hidden" census is deliberately duplicated rather than shared with plan 05-05's identical rule, per the plan's own explicit instruction, since both plans execute in the same wave.

## Deviations from Plan

### Auto-fixed Issues

None — Rules 1–4 were not triggered for this plan's own declared files. All three tasks executed exactly as specified, with every test passing on first implementation and the full task-by-task verification loop (breakpoint pin, off-by-one regression check, byte-identical restoration) matching the plan's acceptance criteria exactly.

### Cross-Plan Scope Conflict (reported, not fixed — outside declared scope)

**1. `tests/test_advanced_ui.py::AdvancedUiTests::test_breakpoint_boundary_and_accessibility_contract` and `test_precision_and_accessible_service_source_contract` now fail**

- **Found during:** Task 1's own `<verify>` step (`uv run --project dashboard python -m pytest tests/test_advanced_ui.py tests/test_history_investigation_ui.py -q`) and reconfirmed in the plan's final full-suite verification
- **Root cause:** `tests/test_advanced_ui.py` (owned by the parallel wave-4 plan 05-05, explicitly out of this plan's declared scope: `dashboard/advanced.css`, `tests/test_theme_parity_ui.py`) contains two assertions hardcoded to the **old** 719px boundary that this plan's Task 1 was explicitly instructed to change:
  - Line ~2037: `for width, expected_columns in ((720, 3), (719, 1)):` — asserted the OLD boundary semantics (720px was still "wide"/3-column, 719px was "narrow"/1-column). After the reconciliation, 720px is the narrow boundary (1 column) and 721px is the first wide width, so `(720, 3)` now fails (`AssertionError: 1 != 3`).
  - Line ~2056: `self.assertIn('@media (max-width: 719px)', css)` — a literal string match against the now-superseded value; the string no longer exists in `dashboard/advanced.css` after Task 1's change.
- **Why not fixed here:** Both lines live in `tests/test_advanced_ui.py`, which the parallel plan 05-05 explicitly owns in this wave. The orchestrator's scope instructions are explicit: an out-of-scope edit in a parallel wave becomes a merge conflict, and the correct action is to report rather than silently widen scope. This plan's own declared verification (Task 1's `<verify>`, and the plan's overall `<verification>` block) both assumed `tests/test_advanced_ui.py` would remain green after the CSS change; that assumption did not hold, and is recorded here rather than papered over.
- **Confirmed scope of impact:** the full suite (`uv run --project dashboard python -m pytest -q`) was run at this plan's final commit and shows **exactly** these two failures — `765 passed, 546 subtests passed, 2 failed` — with no other regressions of any kind. Both failures are demonstrated to stem directly from the literal 719px value, not from any logic bug this plan introduced.
- **Exact fix needed (for whoever reconciles — likely plan 05-05's worktree or a small follow-up merge commit touching only `tests/test_advanced_ui.py`):**
  ```python
  # line ~2037, was:
  for width, expected_columns in ((720, 3), (719, 1)):
  # should become (any pair straddling the new 720px boundary from both sides), e.g.:
  for width, expected_columns in ((NARROW_BOUNDARY_PX + 1, 3), (NARROW_BOUNDARY_PX, 1)):
  # (or the literal (721, 3), (720, 1) if the file does not import the constant)

  # line ~2056, was:
  self.assertIn('@media (max-width: 719px)', css)
  # should become:
  self.assertIn('@media (max-width: 720px)', css)
  ```
- **Verification of the diagnosis:** confirmed by direct inspection of the failure output (`AssertionError: 1 != 3` at the exact `(720, 3)` case, and `AssertionError: '@media (max-width: 719px)' not found in '...'` quoting the full, correctly-720px-containing stylesheet) — not inferred from "the file isn't in my declared list."
- **Logged to:** `.planning/WINDOWS.md` (deviation entry, kind `deviation`)

---

**Total deviations:** 0 auto-fixed. 1 cross-plan scope conflict reported (not fixed, per explicit scope boundary and orchestrator instructions).
**Impact on plan:** None on this plan's own three declared deliverables — all task-level `<verify>`/`<acceptance_criteria>` passed cleanly on `dashboard/advanced.css` and `tests/test_theme_parity_ui.py`. The full suite is **not** fully green at this plan's final commit; it is green except for the two known, precisely-diagnosed, out-of-scope lines above, which require a two-line follow-up fix in `tests/test_advanced_ui.py` during wave-4 merge reconciliation.

## Issues Encountered

None beyond the cross-plan scope conflict documented above.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Both stylesheets now narrow at one shared, source-pinned boundary; any future off-by-one drift fails `NarrowBoundaryPinTests` immediately
- `tests/test_theme_parity_ui.py` is the phase's cross-surface dual-theme contract module; any future work touching both `/` and `/advanced` responsive behavior should extend this module rather than duplicating single-document coverage
- **Blocker for merge (not for this plan's own completion):** the two `tests/test_advanced_ui.py` assertions documented above must be updated to the new 720px boundary before or during wave-4 merge — otherwise the merged tree's full suite will show 2 failures that are trivial to fix but currently outside any single wave-4 plan's declared scope intersection
- `UX-05` and `OPS-06` are not independently promoted in `REQUIREMENTS.md` by this plan alone if any sibling 05-xx plan also declares them and has not yet completed — following this phase's established convention (see prior 05-xx SUMMARYs' identical notes)

## Self-Check: PASSED

All created/modified files and all commit hashes referenced above verified present:
- `dashboard/advanced.css`, `tests/test_theme_parity_ui.py` — found
- Commits `be2f366`, `e5e2957`, `496738f` — found in `git log --oneline --all`

---
*Phase: 05-theme-parity-analytics-experience*
*Completed: 2026-08-27*
