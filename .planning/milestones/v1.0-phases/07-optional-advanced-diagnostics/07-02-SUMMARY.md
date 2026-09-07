---
phase: 07-optional-advanced-diagnostics
plan: 02
subsystem: api
tags: [flask, feature-flag, regex, playwright]

# Dependency graph
requires:
  - phase: 07-optional-advanced-diagnostics
    provides: "07-01's ENABLE_ADVANCED_DIAGNOSTICS toggle, handler-first-statement 404 gate shape (D-07-02), and DatabaseWorkCounter/_counting_connections measurement harness"
provides:
  - "The remaining three advanced routes (/advanced, /advanced.css, /advanced.js) gated behind ENABLE_ADVANCED_DIAGNOSTICS, mirroring api_advanced_current's gate exactly"
  - "dashboard/beacon/frontpage.py's without_advanced_entry_point -- a pure, raise-on-ambiguity string transform that excises the front page's advanced-diagnosis anchor and its trailing separator"
  - "dashboard/app.py's _index_document_without_advanced_entry_point process-local cache and index()'s disabled branch, serving a front page that never carried the entry point while leaving the enabled send_file call textually untouched (D-07-03)"
  - "dashboard/app.js guards at both advanced-diagnosis-link lookup sites (DOMContentLoaded's click-listener registration and restoreDashboardScroll's focus call), so the front page boots with or without the anchor"
affects: [07-optional-advanced-diagnostics]

# Actuals (#2632) — pairs with the plan's estimate to calibrate future estimates.
# Same estimateTokens scale (chars/4 over the realized diff), never a harness token count.
actuals:
  tokens: 7076
  tasks: 3
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Handler-first-statement 404 gate replicated three more times (D-07-02), never generalized into a decorator -- matches 07-01's established shape exactly"
    - "Process-local computed-once cache for a pure server-side document transform, mirroring the module-level None-until-first-call idiom, gated so the enabled path never reaches it"
    - "Raise-on-ambiguity pure transform (AdvancedEntryPointNotFound on 0 or 2+ matches) as the safety net for a regex coupled to specific markup, backed by a 'markup invariant' tripwire test that is explicitly labeled non-behavioural"
    - "Optional-element guard at a script boot site: resolve into a local, branch on truthiness, comment states the consequence (what breaks if unguarded) not just the mechanism"

key-files:
  created:
    - dashboard/beacon/frontpage.py
  modified:
    - dashboard/app.py
    - dashboard/app.js
    - tests/test_optional_advanced_diagnostics.py
    - .planning/WINDOWS.md

key-decisions:
  - "D-07-05 (from the plan objective, implemented here): the front page's entry point is removed server-side, once per process, on the disabled branch only -- never via a client-side config fetch (adds a boot round-trip and still ships the link) and never via a toggled wrapper in index.html (moves the enabled bytes criterion 4 protects)."
  - "The transform never no-ops: exactly one regex match is required, zero or two-plus both raise AdvancedEntryPointNotFound -- a silent no-op would serve the link on a deployment that turned the feature off."
  - "Both dashboard/app.js lookup sites are guarded independently (not consolidated into one check) because they fail differently: site 772's throw is synchronous and kills the rest of DOMContentLoaded; site 762's throw is async, reachable only when a scroll position is seeded, and was invisible to an ordinary Playwright load until the seeded-scroll subtest was added."

patterns-established:
  - "A pure string-to-string transform module under dashboard/beacon/ with no I/O and no import of dashboard.app, satisfying test_module_boundaries.py's AST rule by construction rather than by exception."

requirements-completed: []  # DIA-09 spans all three plans in this phase; 07-02 is Task 1+2 of 3 -- see scope fence "Do not promote DIA-09"

coverage:
  - id: D1
    description: "With the toggle off, /advanced, /advanced.css and /advanced.js each answer 404 with an empty body; the front page's own assets (/, /style.css, /app.js) are never gated."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedAssetTests::test_the_disabled_toggle_gates_only_the_advanced_bundle"
        status: pass
    human_judgment: false
  - id: D2
    description: "With the toggle on, all four advanced surfaces and / return bytes equal to their file on disk (an invariant, not a frozen digest), and the four asset digests still match 07-01's fixture."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedAssetTests::test_enabled_advanced_surfaces_are_byte_identical_to_disk"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedAssetTests::test_the_enabled_asset_digests_still_match_07_01s_fixture"
        status: pass
    human_judgment: false
  - id: D3
    description: "without_advanced_entry_point excises exactly one anchor-plus-separator span and raises AdvancedEntryPointNotFound on zero or duplicate matches; dashboard/index.html's real markup yields exactly one match today (tripwire, not evidence)."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageEntryPointTests::test_the_markup_invariant_dashboard_index_html_has_exactly_one_entry_point"
        status: pass
    human_judgment: false
  - id: D4
    description: "With the toggle off, GET / serves a body containing none of the entry point's id/href/label while still containing the services grid and theme toggle ids; with the toggle on, GET / is byte-identical to index.html and the transform is never invoked."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageEntryPointTests::test_disabled_body_omits_the_entry_point_and_keeps_the_rest_of_the_page"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageEntryPointTests::test_enabled_body_is_byte_identical_to_index_html_and_the_transform_is_unreached"
        status: pass
    human_judgment: false
  - id: D5
    description: "The transform runs at most once per process across five disabled GET / requests, and a transform failure propagates out of the route rather than being served as a 200 page carrying the entry point."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageEntryPointTests::test_the_transform_runs_at_most_once_per_process_across_five_disabled_requests"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageEntryPointTests::test_a_transform_failure_propagates_out_of_the_route_rather_than_serving_a_page"
        status: pass
    human_judgment: false
  - id: D6
    description: "With the toggle off, in real Chromium (dark and light), the services front page boots and renders seeded service content with no uncaught page error, on both an ordinary load and a load with DASHBOARD_SCROLL_KEY seeded -- the only condition reaching restoreDashboardScroll's guarded focus call -- and the advanced link locator resolves to zero elements."
    requirement: "DIA-09"
    verification:
      - kind: e2e
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageBootWithoutAdvancedTests::test_ordinary_load_boots_and_renders_seeded_services_with_no_page_error"
        status: pass
      - kind: e2e
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageBootWithoutAdvancedTests::test_seeded_scroll_position_reaches_restore_dashboard_scrolls_focus_call_with_no_page_error"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-09-04
status: complete
---

# Phase 7 Plan 02: The Remaining Advanced Routes and a Front Page That Survives Losing Its Link Summary

**The three remaining advanced routes gated behind ENABLE_ADVANCED_DIAGNOSTICS, and the front page's advanced-diagnosis entry point excised server-side (dashboard/beacon/frontpage.py) with the boot script's two unguarded element lookups fixed so the services page still renders in real Chromium once the link is gone.**

## Performance

- **Duration:** 20 min (commit span; excludes upfront file reading)
- **Started:** 2026-09-04T12:17:47+03:00
- **Completed:** 2026-09-04T12:37:28+03:00
- **Tasks:** 3
- **Files modified:** 5 (1 created, 4 modified)

## Accomplishments
- `advanced_index`, `serve_advanced_css`, `serve_advanced_js` gated by the identical handler-first-statement 404 shape 07-01 established on `api_advanced_current` (D-07-02) -- no fourth gate shape invented.
- `dashboard/beacon/frontpage.py`'s `without_advanced_entry_point`: a pure, I/O-free, `dashboard.app`-independent regex transform that excises the anchor-plus-separator span and raises `AdvancedEntryPointNotFound` on anything other than exactly one match -- never a silent no-op.
- `dashboard/app.py`'s `index()` disabled branch serves that transformed document through a process-local cache computed at most once; the enabled branch's `send_file` call stays textually untouched, so criterion 4's byte-identity is a property of the code shape (D-07-03), not only of a test.
- Both of `dashboard/app.js`'s unguarded `advanced-diagnosis-link` lookups (the `DOMContentLoaded` click-listener registration and `restoreDashboardScroll`'s focus call) are now guarded, each covered by its own real-Chromium subtest in both themes -- an ordinary load for the first, a seeded-`sessionStorage` load for the second, which no ordinary load reaches.
- Every guard mutation-verified with observed failure values recorded below (11 mutations total across the three tasks).

## Task Commits

Each task was committed atomically:

1. **Task 1: The three remaining routes answer 404 off, and serve their file unchanged on** - `c882e1f` (feat)
2. **Task 2: The entry point leaves the served document, once per process, or the server refuses** - `10d699f` (feat)
3. **Task 3: The services front page still works without its advanced link — proven in a real browser** - `95a96b6` (fix)

**Plan metadata (deviations):** `b2c47d3` (docs: WINDOWS.md entries #22/#23)

## Files Created/Modified
- `dashboard/beacon/frontpage.py` - New module: `AdvancedEntryPointNotFound`, `ADVANCED_ENTRY_POINT_ID`, `without_advanced_entry_point` -- pure string-to-string, no I/O, no import of `dashboard.app`.
- `dashboard/app.py` - Three route gates (`advanced_index`, `serve_advanced_css`, `serve_advanced_js`); `beacon_frontpage` import (both branches); `_index_document_without_advanced_entry_point` cache function; `index()`'s disabled branch.
- `dashboard/app.js` - Guarded both `advanced-diagnosis-link` lookup sites (`DOMContentLoaded` registration, `restoreDashboardScroll`'s focus call).
- `tests/test_optional_advanced_diagnostics.py` - `DisabledAdvancedAssetTests`, `FrontPageEntryPointTests`, `FrontPageBootWithoutAdvancedTests` (real-Chromium, `make_server`+`sync_playwright`), plus the `beacon_frontpage`/`threading`/`playwright`/`werkzeug` imports these classes need.
- `.planning/WINDOWS.md` - Entries #22 (lock-audit line-shift, compounds #21) and #23 (a confirmed-flaky, confirmed-unrelated browser test failure observed during whole-suite verification).

## Decisions Made
- **D-07-05** (server-side, once-per-process removal on the disabled branch only): the plan objective's three rejected alternatives (client-side fetch-then-remove, a toggled wrapper in `index.html`, a second front-page file) each fail a different criterion; this plan implements the chosen mechanism.
- The transform's raise-on-ambiguity contract (zero or 2+ matches both raise) is the safety net for a regex deliberately coupled to specific markup; the "markup invariant" test is explicitly documented as a tripwire, not behavioural evidence, so a future reader cannot mistake it for proof the feature works.
- Both `dashboard/app.js` guard sites are fixed independently rather than with one consolidated check, because they fail on different code paths reached under different conditions (see Sensitivity Demonstrations below) -- consolidating them would have hidden the asymmetry the plan's own acceptance criteria required proving.

## Deviations from Plan

### Auto-fixed Issues

None - all three tasks executed exactly as planned; no bugs, missing functionality, or blocking issues required an unplanned fix.

### Recorded, not fixed — out of scope

**1. [WINDOWS.md #22] tests/test_lock_profile.py::LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit re-fails**
- **Found during:** the plan's whole-suite `<verification>` run.
- **Issue:** this plan's mandated `dashboard/app.py` edits (three route gates, the cache function, the `beacon_frontpage` import) shift every `_db_lock` call site's line number further below each insertion point, on top of 07-01's already-recorded shift (`WINDOWS.md` #21). Confirmed a pure line-number desync: same 28 sites, same 26 functions; `LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock` (structural, not line-based) still passes.
- **Why not fixed:** `06-LOCK-AUDIT.md` is a `.planning/phases/06-*` artifact; this plan's scope fence explicitly forbids touching it. No smaller edit satisfying this plan's own acceptance criteria (mirroring `api_advanced_current`'s exact gate shape, adding the cache function above `index()`) would avoid the shift.
- **Recorded:** `.planning/WINDOWS.md` entry #22 (kind: deviation, phase 07, open), compounding entry #21.
- **Impact:** the phase-wide full-suite floor is exceeded (958 passed / 587 subtests vs. the stated floor of 950/573), and this is one of the two failures — a recorded, understood, non-functional line-number desync, not a new behavioral regression.

**2. [WINDOWS.md #23] tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_advanced_current_request_byte_identical_before_and_after_selection failed once under whole-suite load**
- **Found during:** the plan's whole-suite `<verification>` run.
- **Issue:** `IndexError: list index out of range` at `recorded[-1]` — a Playwright request-recording race under full-suite Chromium contention (many browser-driving test modules running in the same pytest session).
- **Confirmed unrelated to 07-02:** passes in isolation (`1 passed in 2.31s`) and passes when the whole module is re-run alone (`144 passed, 27 subtests passed`). The file is not in 07-02's declared scope (`dashboard/app.py`, `dashboard/app.js`, `dashboard/beacon/frontpage.py`, `tests/test_optional_advanced_diagnostics.py`), and no code this test's flow depends on was touched.
- **Recorded:** `.planning/WINDOWS.md` entry #23 (kind: deviation, phase 07, open).
- **Impact:** flaky, not a regression; the plan's own three tasks' individual `<verify>` runs (which don't include this file) never observed it.

---

**Total deviations:** 0 auto-fixed, 2 recorded-not-fixed (one out-of-scope Phase-6 artifact line-shift, one confirmed-flaky unrelated test).
**Impact on plan:** Neither recorded item is a functional or security regression in this plan's own code. The full suite otherwise passed clean at 958/587, comfortably above the plan's stated floor.

## Sensitivity Demonstrations (observed values)

All mutations below were applied, run, observed, and reverted (confirmed byte-identical to a pre-mutation backup) before the corresponding commit.

### Task 1 — the three route gates

| # | Mutation | Test | Observed failure |
|---|----------|------|-------------------|
| 1 | Removed `advanced_index`'s early return | `DisabledAdvancedAssetTests::test_the_disabled_toggle_gates_only_the_advanced_bundle` | `AssertionError: 200 != 404 : /advanced answered 200, expected 404` |
| 2 | Removed `serve_advanced_css`'s early return | same test | `AssertionError: 200 != 404 : /advanced.css answered 200, expected 404` |
| 3 | Removed `serve_advanced_js`'s early return | same test | `AssertionError: 200 != 404 : /advanced.js answered 200, expected 404` |

### Task 2 — the front-page transform

| # | Mutation | Test | Observed failure |
|---|----------|------|-------------------|
| 4 | `without_advanced_entry_point` returns its input unchanged (no-op) instead of excising the match | `FrontPageEntryPointTests::test_disabled_body_omits_the_entry_point_and_keeps_the_rest_of_the_page` | `AssertionError: 'id="advanced-diagnosis-link"' unexpectedly found in <body>` (named which of the three strings was found) |
| 5 | Removed the document cache in `_index_document_without_advanced_entry_point` (always recompute) | `FrontPageEntryPointTests::test_the_transform_runs_at_most_once_per_process_across_five_disabled_requests` | `AssertionError: 5 != 1 : expected exactly 1 transform invocation across 5 disabled GET / requests, observed 5` — the exact `1` vs `5` pair the plan named |
| 6 | Fed the transform a document with the anchor duplicated | direct call to `without_advanced_entry_point` (pure-function probe, mirrors the pinned duplicate-match unit behavior) | `AdvancedEntryPointNotFound: expected exactly one advanced-diagnosis entry point span (id='advanced-diagnosis-link'), found 2` |

### Task 3 — the two script guard sites, independently

| # | Mutation | Subtest | Observed failure |
|---|----------|---------|-------------------|
| 7 | Reverted **only** the `DOMContentLoaded` guard (site 772) | `test_ordinary_load_boots_and_renders_seeded_services_with_no_page_error` (both themes) | Collected `pageerror`: `"Cannot read properties of null (reading 'addEventListener')"`; services grid stayed at `<div class="svc-empty">waiting for worker…</div>` |
| 8 | Same mutation as #7 | `test_seeded_scroll_position_reaches_restore_dashboard_scrolls_focus_call_with_no_page_error` (both themes) | Also failed (site 772's throw is synchronous and precedes site 762's async callback regardless of scroll seeding) — expected; the plan's asymmetry requirement is about mutation (b), not (a) |
| 9 | Reverted **only** the `restoreDashboardScroll` guard (site 762), leaving the `DOMContentLoaded` guard in place | `test_seeded_scroll_position_reaches_restore_dashboard_scrolls_focus_call_with_no_page_error` (both themes) | Collected `pageerror`: `"Cannot read properties of null (reading 'focus')"` |
| 10 | Same mutation as #9 | `test_ordinary_load_boots_and_renders_seeded_services_with_no_page_error` (both themes) | **Kept passing** (2 passed) — the required asymmetry: mutation (b) breaks only the seeded-scroll subtest, proving the two subtests cover different code rather than the same site twice |

Mutation count: 3 (Task 1) + 3 (Task 2, one of which — #6 — is a pure-function probe rather than a full pytest run, matching how the pinned duplicate-match assertion is itself verified) + 4 (Task 3, covering both required directions of the asymmetry) = 10 recorded mutation observations.

## Issues Encountered
None beyond the two recorded-not-fixed deviations above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- 07-03 can proceed: the front page's cost-equality and reversibility measurements this plan's predecessor summary flagged as depending on "07-02's front-page conditional branch" now have that branch in place (`dashboard/app.py::index`'s disabled/enabled split).
- `dashboard/beacon/frontpage.py` and its `without_advanced_entry_point`/`ADVANCED_ENTRY_POINT_ID`/`AdvancedEntryPointNotFound` exports are available for 07-03 to reuse if its reversibility measurement needs to reference the transform directly.
- `_index_document_without_advanced_entry_point`'s process-local cache (`dashboard/app.py`) is a fresh `None` per process reload (`importlib.reload` in `load_app`), so 07-03's own tests needing a clean cache state should reset `appmod._index_document_without_advanced_entry_point_cache = None` after `load_app`, exactly as `FrontPageEntryPointTests` does.
- Open item for whoever next works Phase 6: `.planning/WINDOWS.md` #21 and #22 both need the same mechanical line-number refresh of `06-LOCK-AUDIT.md`'s table once Phase 6 is unsealed — #22 should be resolved together with #21, not separately, since both point at the same table.
- DIA-09 remains **not** promoted (scope fence honored) — 07-01 (tracer) and 07-02 (this plan, Tasks covering the remaining routes and the front page) are complete; 07-03 remains.

---
*Phase: 07-optional-advanced-diagnostics*
*Completed: 2026-09-04*

## Self-Check: PASSED

All 4 files listed in Files Created/Modified (plus `.planning/WINDOWS.md` and this SUMMARY) confirmed present on disk. All 4 commit hashes (`c882e1f`, `10d699f`, `95a96b6`, `b2c47d3`) confirmed present in `git log --oneline --all`.
