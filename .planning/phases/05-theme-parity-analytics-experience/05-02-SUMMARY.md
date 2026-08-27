---
phase: 05-theme-parity-analytics-experience
plan: 02
subsystem: ui
tags: [flask, playwright, freshness, wcag-contrast, dual-theme]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: freshness_state() four-tier classifier and serviceFreshness's existing fail-closed allowlist
  - phase: 05-01
    provides: the worker_degraded fact and the .degraded-warning non-hue disambiguation pattern this plan extends to the services table
provides:
  - "FRESHNESS_PRESENTATION, freshnessPresentation(state) and freshnessBadge(state) in dashboard/advanced.js — one glyph/word/class table every freshness reading in the workspace now routes through"
  - "The services table's freshness cell, the Overview Host card, the Host/Pipeline-worker/expanded-service evidence rows, and the Pipeline streams list all render the same vocabulary instead of a raw lowercase wire literal"
  - "A degraded evidence sentence for pipeline streams, mirroring the existing stale sentence without its worker-comparison paragraph"
  - ".freshness-badge/.freshness-fresh/.freshness-degraded/.freshness-stale/.freshness-unknown in dashboard/advanced.css — inline, unbordered, token-only colour, distinguished from the bordered .advanced-error box by shape"
  - "serviceFreshness is now case-sensitive (T-05-06 fix) — an unrecognised or wrong-cased literal fails closed to Unknown instead of silently matching a valid state"
  - "test_six_states_are_distinct_in_both_themes and test_freshness_filter_and_sort_still_use_the_server_wire_literals — dual-theme regression pinning all six current-diagnosis states apart by glyph, word, shape and WCAG contrast"
affects: [05-05]

# Actuals (#2632)
actuals:
  tokens: 6108
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns:
    - "One presentation lookup table (a Map, matching this file's existing EXCEPTION_COPY discipline) mapping every wire literal to {glyph, word, className}, with a single fail-closed accessor every renderer calls instead of interpolating the literal directly"
    - "Container-shape disambiguation for a shared accent color: .freshness-degraded is inline with no border, .advanced-error is a bordered box — the same non-hue technique 05-01 established for .degraded-warning vs .recovery-warning"
    - "Module-level WCAG contrast-ratio helper, self-checked against a known literal pair before being trusted for live getComputedStyle assertions"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - dashboard/advanced.html
    - dashboard/advanced.css
    - tests/test_advanced_ui.py

key-decisions:
  - "FRESHNESS_PRESENTATION built as a Map (glyph/word/className per literal), matching the file's existing EXCEPTION_COPY pattern, rather than a plain object"
  - "freshnessWord extended (not replaced) so 'aging' returns lowercase 'degraded' for the pre-existing mid-sentence active-exception copy, keeping badge copy and sentence copy from drifting apart"
  - ".freshness-stale/.freshness-unknown resolve --text (not --muted): --muted fails WCAG AA 4.5:1 in both themes on this table's surface, --text clears it by a wide margin in both; .freshness-fresh's light-mode --green gap (3.30:1) is deliberately left unfixed per A-34/05-DEBT.md — an app-wide token decision outside this plan's scope"
  - "serviceFreshness's .toLowerCase() removed: the plan's own T-05-06 threat register and Task 1 acceptance criteria require an 'AGING'-literal service to render Unknown, but the pre-existing case-insensitive match let it masquerade as 'aging' — fixed as a Rule 1 bug, scoped to serviceFreshness only (serviceAvailability's case handling is untouched, out of this plan's scope)"
  - "requirements-completed records this plan's own contribution only; UX-07/UX-06/OPS-06 stay unmarked in REQUIREMENTS.md per 05-01's established convention, since sibling plans in this phase also declare them"

patterns-established:
  - "Every freshness-reading surface in the workspace speaks one vocabulary: FRESHNESS_PRESENTATION is the single source, and no renderer interpolates the raw server literal directly"

requirements-completed: [UX-07, UX-06, OPS-06]

coverage:
  - id: D1
    description: "One presentation table (glyph, word, class) drives the services table's freshness column, the Overview Host card, Host/Pipeline-worker/expanded-service evidence rows, and the Pipeline streams list — every freshness reading in the workspace reads the same vocabulary instead of a raw wire literal"
    requirement: "UX-07"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_six_states_are_distinct_in_both_themes"
        status: pass
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_workspace_sections_overview_and_host_states"
        status: pass
    human_judgment: false
  - id: D2
    description: "Shape, not hue, separates a degraded reading (inline, unbordered .freshness-degraded) from an error (bordered .advanced-error box), pinned independently in both themes"
    requirement: "UX-07"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_six_states_are_distinct_in_both_themes"
        status: pass
    human_judgment: false
  - id: D3
    description: "The degraded, stale and unknown freshness badges each clear WCAG AA 4.5:1 contrast against the body surface in both themes, proven with a self-checked contrast helper; the fresh badge's known light-mode --green gap is deliberately left unasserted per A-34"
    requirement: "OPS-06"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_six_states_are_distinct_in_both_themes"
        status: pass
    human_judgment: false
  - id: D4
    description: "The Freshness filter's third option is relabelled Degraded while its value and the sort/filter comparisons keep the server's four wire literals unchanged"
    requirement: "UX-07"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_freshness_filter_and_sort_still_use_the_server_wire_literals"
        status: pass
    human_judgment: false
  - id: D5
    description: "An unrecognised, wrong-typed, wrong-cased, or absent freshness literal fails closed to Unknown, and a pending or empty read renders zero freshness badges — a pending read never renders as a known state"
    requirement: "UX-07"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_an_unrecognised_or_absent_freshness_literal_renders_unknown"
        status: pass
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_six_states_are_distinct_in_both_themes"
        status: pass
    human_judgment: false

duration: 38min
completed: 2026-08-27
status: complete
---

# Phase 5 Plan 02: Freshness Vocabulary — Glyph, Word, Shape Summary

**One `FRESHNESS_PRESENTATION` table now drives every freshness reading in the advanced workspace with a glyph, a capitalized word and a shape (never hue alone), a case-sensitive fail-closed accessor caught and fixed a real T-05-06 defect, and a new dual-theme WCAG-contrast test pins all six current-diagnosis states apart in both themes.**

## Performance

- **Duration:** 38 min
- **Started:** 2026-08-27T13:38:36Z (approx.)
- **Completed:** 2026-08-27T14:16:10Z
- **Tasks:** 3 (plus one Rule 1 fix commit)
- **Files modified:** 4

## Accomplishments
- `FRESHNESS_PRESENTATION` (a `Map`, matching the file's existing `EXCEPTION_COPY` discipline) maps each of the server's four wire literals to `{glyph, word, className}`; `freshnessPresentation`/`freshnessBadge` route the services table's freshness cell through it, fail-closed to Unknown for anything else
- Every other freshness reading in the workspace — the Overview Host card, the Host section's evidence row, the Pipeline worker row, the expanded per-service evidence row, and the Pipeline streams list — now reads `freshnessPresentation(...).word` instead of a raw lowercase wire literal, via one shared `formatFreshnessEvidence` change
- The Pipeline streams list gained a degraded evidence sentence beside the existing stale one, mirroring its shape but stating its own "not yet stale" condition rather than the stale branch's worker-comparison claim
- `.freshness-badge`/`.freshness-fresh`/`.freshness-degraded`/`.freshness-stale`/`.freshness-unknown` in `dashboard/advanced.css`: inline text, zero border, `--text` (not `--muted`) for stale/unknown to clear WCAG AA 4.5:1 in both themes — the same non-hue shape discipline 05-01 established for `.degraded-warning` vs `.recovery-warning`
- Found and fixed a real fail-closed defect: `serviceFreshness`'s pre-existing `.toLowerCase()` let an `'AGING'`-literal service match the `'aging'` allowlist entry and render as Degraded, when this plan's own T-05-06 threat register and Task 1 acceptance criteria require it to render Unknown
- `test_six_states_are_distinct_in_both_themes` (dual-theme) and `test_freshness_filter_and_sort_still_use_the_server_wire_literals` pin glyph distinctness, WCAG contrast (via a self-checked module-level helper), the degraded/error shape distinction, empty/loading zero-badge behavior, and per-theme token re-resolution

## Task Commits

Each task was committed atomically:

1. **Task 1: One freshness vocabulary — glyph, word, class — and the services table** - `17c267e` (feat)
2. **Task 2: The same vocabulary everywhere else a freshness reading appears** - `e516edf` (feat)
3. **Task 3: Pin the six states apart, per theme** - `e023dd3` (test)
4. **Rule 1 fix: serviceFreshness case-sensitivity (T-05-06)** - `1064d1b` (fix)

## Files Created/Modified
- `dashboard/advanced.js` - `FRESHNESS_PRESENTATION`, `freshnessPresentation`, `freshnessBadge`; extended `freshnessWord`; the services table freshness `<td>`, `formatFreshnessEvidence`, the Overview Host card, and the Pipeline streams list all route through the shared vocabulary; `serviceFreshness` made case-sensitive
- `dashboard/advanced.html` - the Freshness filter's `aging` option relabelled `Degraded` (`value="aging"` unchanged)
- `dashboard/advanced.css` - `.freshness-badge`/`.freshness-fresh`/`.freshness-degraded`/`.freshness-stale`/`.freshness-unknown`
- `tests/test_advanced_ui.py` - `test_six_states_are_distinct_in_both_themes`, `test_freshness_filter_and_sort_still_use_the_server_wire_literals`, `test_an_unrecognised_or_absent_freshness_literal_renders_unknown`, a module-level WCAG contrast helper, and one pre-existing assertion updated for the new capitalized `Fresh` word

## Decisions Made
- `FRESHNESS_PRESENTATION` built as a `Map`, following the file's existing `EXCEPTION_COPY` lookup-table discipline
- `.freshness-stale`/`.freshness-unknown` resolve `--text`, not `--muted`, per the plan's own AA-contrast requirement; `.freshness-fresh`'s light-mode `--green` gap (3.30:1) is deliberately left unfixed and unasserted, per A-34/`05-DEBT.md` — an app-wide token decision outside this plan's scope
- `requirements-completed` records only this plan's contribution; `UX-07`/`UX-06`/`OPS-06` remain unmarked in `REQUIREMENTS.md`, consistent with 05-01's established convention, since sibling plans in this phase also declare them and have not all produced their own `*-SUMMARY.md` yet

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `serviceFreshness` case-insensitivity let an unrecognised literal masquerade as a valid one**
- **Found during:** Task 3, while manually verifying Task 1's stated acceptance criterion ("a service whose `freshness.state` is `'AGING'`... renders `○ Unknown —` in every case")
- **Issue:** `serviceFreshness` called `.toLowerCase()` on the state literal before checking it against the four-item allowlist. This is pre-existing, unmodified-by-this-plan code, but it meant `freshness.state === 'AGING'` normalized to `'aging'` and matched the allowlist, rendering `◈ Degraded` instead of the `○ Unknown` this plan's own T-05-06 threat register requires (a high-severity spoofing mitigation: "any literal outside the server's four resolves to Unknown"). The server never emits a case-varied literal, so tolerating one here only widens the attack surface the mitigation exists to close.
- **Fix:** Removed the `.toLowerCase()` call; `serviceFreshness` now does an exact, case-sensitive match against `['fresh', 'aging', 'stale', 'unknown']`. `serviceAvailability`'s own separate case handling is untouched — out of this plan's scope.
- **Files modified:** dashboard/advanced.js, tests/test_advanced_ui.py
- **Verification:** Added `test_an_unrecognised_or_absent_freshness_literal_renders_unknown`, pinning `'AGING'`, `null`, `42`, `{}` and an absent `freshness` key all render `○ Unknown — `; confirmed no existing test relied on the case-insensitive behavior; full suite green before and after.
- **Committed in:** `1064d1b`

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary to satisfy this plan's own stated Task 1 acceptance criterion and T-05-06 threat mitigation. Scoped exactly to `serviceFreshness`'s case handling; `serviceAvailability` and every other allowlist in the file are untouched. No scope creep.

## Issues Encountered
None beyond the deviation above.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `FRESHNESS_PRESENTATION`/`freshnessPresentation`/`freshnessBadge` and the `.freshness-*` class family are now the single vocabulary every freshness reading in the advanced workspace routes through; any later plan needing a freshness reading (05-05 declares UX-07 too) should call these rather than re-deriving glyph/word/class.
- `UX-07`, `UX-06` and `OPS-06` are **NOT** marked complete in `REQUIREMENTS.md` — sibling plans in this phase also declare these IDs and have not all produced their own `*-SUMMARY.md` yet. This plan's `requirements-completed` frontmatter records its own contribution only; the checkbox flips once the last declaring plan finishes.
- A-34 (light-mode `--green` fails AA for `.freshness-fresh`, tracked in `05-DEBT.md` D-DEBT-01) remains open, awaiting a human decision; this plan did not touch `--green` and does not assert `.freshness-fresh`'s contrast, per the plan's own explicit exemption.
- No blockers for the remaining Phase 5 plans.

## Self-Check: PASSED

All created/modified files and all commit hashes referenced above verified present:
- `dashboard/advanced.js`, `dashboard/advanced.html`, `dashboard/advanced.css`, `tests/test_advanced_ui.py` — found
- Commits `17c267e`, `e516edf`, `e023dd3`, `1064d1b` — found in `git log --oneline --all`

---
*Phase: 05-theme-parity-analytics-experience*
*Completed: 2026-08-27*
