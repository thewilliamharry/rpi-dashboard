---
phase: 03-advanced-current-diagnosis
plan: 23
subsystem: ui
tags: [css, playwright, accessibility, hover-affordance]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: the /advanced workspace (advanced.html/advanced.js/advanced.css) built across plans 03-01..03-22
provides:
  - Mouse affordance (cursor: pointer + hover feedback) for every interactive control in the /advanced workspace, in both themes
  - #advanced-refresh carrying the accent/primary-action treatment 03-UI-SPEC.md:76 reserves for it
  - A real-browser regression (test_every_interactive_control_reads_as_interactive_in_both_themes) pinning cursor, hover deltas, and the accent reservation both positively and negatively
affects: []

actuals:
  tokens: 2856
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Theme-scoped hover pairs (html:not(.light) X:hover / html.light X:hover) reusing style.css's existing tint/border-darken vocabulary rather than inventing new values"
    - "Grouped low-specificity affordance rules placed below a higher-specificity ID rule so hover cannot strip an already-earned accent (#advanced-refresh, aria-selected nav tab)"

key-files:
  created: []
  modified:
    - dashboard/advanced.css
    - tests/test_advanced_ui.py

key-decisions:
  - "Task 1's #advanced-refresh accent treatment accepted as-is by the user at the tracer checkpoint; no changes made to it in Task 2"
  - "Included .service-filters select and .settings-grid select in the pointer rule even though the gap's literal 'missing' list didn't name them, because the gap's truth (every interactive control reads as interactive) is broader than its missing-list enumeration"
  - "Deliberately did not add an a:hover rule, a :disabled rule, or any transition — matching dashboard/style.css's existing convention rather than inventing a new visual language for one page"
  - "Nav tab hover rules set no color property, specifically so hover cannot grant or strip the accent that only aria-selected=true owns"

patterns-established:
  - "Interactive-affordance CSS block convention for /advanced: one grouped cursor rule + theme-scoped hover pairs, inserted above the trailing @media blocks, values borrowed verbatim from style.css"

requirements-completed: [UX-02]

coverage:
  - id: D1
    description: "Every interactive control in /advanced computes cursor: pointer in both themes; #service-search deliberately does not"
    requirement: "UX-02"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_every_interactive_control_reads_as_interactive_in_both_themes"
        status: pass
    human_judgment: false
  - id: D2
    description: "Hovering any control produces a visible computed-style change in both themes, using style.css's existing hover vocabulary"
    requirement: "UX-02"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_every_interactive_control_reads_as_interactive_in_both_themes"
        status: pass
    human_judgment: false
  - id: D3
    description: "#advanced-refresh carries the accent/primary-action treatment 03-UI-SPEC.md:76 reserves for it, proven by equality against the Dashboard link and inequality against Pause updates"
    requirement: "UX-02"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_every_interactive_control_reads_as_interactive_in_both_themes"
        status: pass
    human_judgment: false
  - id: D4
    description: "Accent reservation pinned negatively: #pause-updates, an unselected nav tab at rest, and that same tab while hovered never compute the accent, while the aria-selected tab always does"
    requirement: "UX-02"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_every_interactive_control_reads_as_interactive_in_both_themes"
        status: pass
    human_judgment: false
  - id: D5
    description: "On the real Pi, in both themes, Refresh now reads to a human operator as the primary action of the header (the original G-03-4 complaint)"
    human_judgment: true
    rationale: "Perception cannot be proven by a computed-style delta alone; collected as human-check item 1 at the end-of-phase checkpoint per workflow.human_verify_mode: end-of-phase"
    verification: []
  - id: D6
    description: "On the real Pi, in both themes, hover feedback across every control is perceptible at the display's actual brightness and viewing angle"
    human_judgment: true
    rationale: "Perceptibility of an 8-12% alpha tint and a border-color shift on real hardware cannot be proven by getComputedStyle; collected as human-check item 2 at the end-of-phase checkpoint"
    verification: []

duration: 9min (Task 2 continuation; Task 1's duration from the interrupted session is not separately recorded)
completed: 2026-08-20
status: complete
---

# Phase 3 Plan 23: Advanced Workspace Interactive Affordance Summary

**Nine-line CSS block gives every /advanced control a pointer cursor and theme-scoped hover feedback, with Refresh now carrying the accent primary-action treatment 03-UI-SPEC.md:76 reserves for it — closing G-03-4, the last open Phase 3 UAT gap.**

## Performance

- **Duration:** ~9 min for this continuation (Task 2 only; Task 1 ran in a prior, interrupted session)
- **Completed:** 2026-08-20T19:43:40Z
- **Tasks:** 2 (both complete)
- **Files modified:** 2 (`dashboard/advanced.css`, `tests/test_advanced_ui.py`)

## Accomplishments
- `#advanced-refresh` now computes `cursor: pointer`, accent text/border, 600 weight, and a hover-induced background change — in both themes — proven by equality against the Dashboard return link's colour and inequality against `Pause updates`'s (Task 1).
- Every remaining click target in the workspace (`Pause updates`, the refresh-interval select, all five nav tabs, the three filter buttons, four filter selects, the settings selects, every dynamically-created service-details toggle, and all six sort buttons) now computes `cursor: pointer` and answers hover with a theme-scoped border/background/text change, while `#service-search` deliberately keeps its native text-input cursor (Task 2).
- The accent reservation is pinned negatively as well as positively: `#pause-updates` and an unselected nav tab never compute the accent, at rest or while hovered, while the `aria-selected="true"` tab always does — so the fix cannot silently widen what 03-UI-SPEC.md:76 grants accent to.
- One real-Chromium regression test, extended (not duplicated) across both tasks, drives both themes and asserts 24 subTest-level checks: cursor sweep, hover deltas, accent equality/inequality, and the 44px hit-target non-regression.
- Zero regressions: the full 307-test suite (454 subtests) passes, including the two pre-existing responsive/breakpoint tests and the two source-contract tests that read this same stylesheet.

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end "Refresh now reads and answers as the primary action"** - `2b12c4b` (feat) — completed in a prior session, verified intact before Task 2 began
2. **Task 2: Expand the same affordance to every remaining interactive control, and pin the accent reservation negatively** - `07ac39c` (feat)

**Plan metadata:** committed alongside STATE.md/ROADMAP.md/REQUIREMENTS.md updates in this closing commit.

## Files Created/Modified
- `dashboard/advanced.css` - Gained a nine-line interactive-affordance block: one comment, five general rules (Task 2: grouped pointer rule, two neutral-hover theme pairs, two nav-hover theme pairs), and three `#advanced-refresh`-specific rules (Task 1: accent treatment plus two hover tints)
- `tests/test_advanced_ui.py` - `test_every_interactive_control_reads_as_interactive_in_both_themes` extended from Task 1's 7-assertion tracer into a 24-subtest sweep covering pointer, hover deltas, and the accent reservation (positive and negative) across both themes

## Decisions Made
- Task 1's approach (ID-scoped accent rule, no `background` change at rest, values borrowed verbatim from `style.css`) was accepted as-is by the user at the tracer checkpoint ("refresh now is looking good now") — no changes made to it in this continuation.
- Included `.service-filters select` and `.settings-grid select` in the pointer rule beyond the gap's literal `missing` list, per the plan's recorded scope decision, so the workspace's affordance is internally consistent.
- No `a:hover`, `:disabled`, or `transition` rule added — matches `dashboard/style.css`'s existing convention rather than inventing new visual language for one page.

## Deviations from Plan

None - plan executed exactly as written. All acceptance-criteria grep counts (`cursor: pointer` = 2, both header hover pairs = 1 each, both nav hover pairs = 1 each, `.service-filters input` = 1, `min-height: 44px` = 6, `focus-visible` = 1, `font-weight: 600` = 4 with exactly one on `#advanced-refresh`, both `@media` blocks last, test method count = 36) and both automated `<verify>` commands passed on the first attempt.

## Issues Encountered
None. The prior session's tracer checkpoint work (`2b12c4b`) was confirmed intact — the `#advanced-refresh` accent block and both its hover rules were present, and the test method existed as expected — before Task 2's edits began.

## User Setup Required
None - no external service configuration required.

## Known Stubs
None. This is a presentation-only stylesheet change with no data wiring, mock props, or placeholder text.

## Next Phase Readiness
- G-03-4 is closed in code; the two new perception items (human-check 1 and 2) plus the three carried-forward hardware-verification items (human-check 3, 4, 5) are queued for the end-of-phase human checkpoint per `workflow.human_verify_mode: end-of-phase`. They are not automated away and this plan does not claim closure on their behalf.
- Phase 3's `03-UAT.md` gap list should now be empty pending that human checkpoint's confirmation of items 1 and 2.
- No blockers for Phase 4.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-20*

## Self-Check: PASSED
