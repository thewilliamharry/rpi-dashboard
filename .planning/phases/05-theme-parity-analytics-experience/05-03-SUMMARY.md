---
phase: 05-theme-parity-analytics-experience
plan: 03
subsystem: testing
tags: [playwright, css, theme-parity, ui-contract, dual-theme]

# Dependency graph
requires:
  - phase: 05-01
    provides: "worker_degraded field on /api/scan-status, consumed here (set false) so the fixture is wire-shape-complete"
provides:
  - "THEME_HIDDEN_RULES and extract_theme_gated_hidden_selectors() in tests/test_ui_contract.py — the exhaustive, regex-derived theme-gated visibility inventory, classified deliberate-calm/decorative, capped at 8 keys"
  - "test_advanced_workspace_hides_nothing_by_theme — proves dashboard/advanced.css has zero theme-gated display:none rules"
  - "test_decorative_theme_gated_rules_are_dead_and_render_nothing — pins .corner/.offline-badge as dead rules, confirms .arc-unit still renders"
  - "test_shared_dashboard_capability_is_present_and_displayed_in_both_themes in tests/test_ui_states.py — dual-theme, first-render proof that every contract-shared main-dashboard element is present and displayed"
  - "test_deliberate_light_mode_calm_is_hidden_not_absent_and_has_a_named_substitute — proves the five deliberate-calm rules are CSS-reversible, not missing, with a named light-mode substitute or the one accepted exception"
affects: [05-05, 05-06]

# Actuals (#2632)
actuals:
  tokens: 4577
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns:
    - "Source-derived contract test: a regex over the stylesheet extracts the theme-gated visibility surface at test time and compares it to a recorded classification table via assertEqual on sets, so a ninth rule fails loudly instead of drifting silently"
    - "Dual-theme first-render assertion via page.add_init_script('localStorage.setItem(...)') before goto, reusing tests/test_advanced_ui.py's established idiom rather than a mid-test toggle, when the claim is about first render"
    - "Harness guard pattern: a resolved-colour comparison between theme runs proves the light theme genuinely applied, kept strictly separate from the capability assertions themselves (which read DOM presence/display/text, never colour alone)"

key-files:
  created: []
  modified:
    - tests/test_ui_contract.py
    - tests/test_ui_states.py

key-decisions:
  - "THEME_HIDDEN_RULES classifies all 8 known html.light display:none rules exactly as 05-PATTERNS.md's audit and this plan's explicit assumptions record: 4 deliberate-calm (sparkline, temp-row, svc-preview, uptime-labels) plus svc-uptime-pct extended to deliberate-calm by A-13, and 3 decorative (arc-unit, corner, offline-badge), with corner/offline-badge additionally pinned dead by A-14"
  - "The extraction regex matches on normalized-whitespace selector prefix (html.light / html:not(.light)) plus a display:none declaration found anywhere in the block — tolerant of formatting variation, verified via a live probe-rule injection into both style.css and advanced.css (checksum-verified restored byte-for-byte afterward) rather than trusted on inspection alone"
  - "Task 2's fixture seeds preview_status='queued' on exactly one of three services (the other two have the key removed entirely, not set to a falsy value) so Task 3's .svc-preview-status assertion depends on a real fixture fact, matching dashboard/app.js:286-292's queued/running/failed/expired-only emission"
  - "Per assumption A-17, every accessible-name assertion in Task 3 reads the uptime segment's title attribution only, not aria-label — that pairing lands one wave later in 05-04"

patterns-established:
  - "Regex-derived, self-maintaining CSS contract inventories (05-RESEARCH.md Pitfall 1's fix): any future audit of a scattered stylesheet override surface should extract-and-classify rather than hand-transcribe"

requirements-completed: [UX-01, UX-03, OPS-06]

coverage:
  - id: D1
    description: "Every theme-gated visibility rule in the project is enumerated, classified (deliberate-calm/decorative) and capped at exactly 8, derived from dashboard/style.css by regex rather than transcribed — a ninth rule fails the test until classified"
    requirement: "UX-03"
    verification:
      - kind: unit
        ref: "tests/test_ui_contract.py#test_every_theme_gated_visibility_rule_is_enumerated_and_classified"
        status: pass
    human_judgment: false
  - id: D2
    description: "The advanced workspace has zero theme-gated visibility rules (proven empty by the same regex against advanced.css), and .corner/.offline-badge are pinned as dead rules that render nowhere while .arc-unit is confirmed still live"
    requirement: "UX-03"
    verification:
      - kind: unit
        ref: "tests/test_ui_contract.py#test_advanced_workspace_hides_nothing_by_theme"
        status: pass
      - kind: unit
        ref: "tests/test_ui_contract.py#test_decorative_theme_gated_rules_are_dead_and_render_nothing"
        status: pass
    human_judgment: false
  - id: D3
    description: "Every element the theme-parity contract calls shared (arc gauges, numeric readouts, host identity, sample time, per-service status text, uptime strip, events panel, scan label, theme toggle with correct aria-pressed, all four safety banners) is present and computed-displayed on the main dashboard in both dark and light themes, from first render, with a harness colour guard proving the light theme genuinely applied"
    requirement: "UX-01"
    verification:
      - kind: e2e
        ref: "tests/test_ui_states.py#test_shared_dashboard_capability_is_present_and_displayed_in_both_themes"
        status: pass
    human_judgment: false
  - id: D4
    description: "The five deliberate-calm omissions (sparkline, temp-row, svc-preview, svc-uptime-pct, uptime-labels) are present in the DOM and CSS-hidden in light mode (not absent), with dark mode confirming the same elements are not display:none there; each has a named light-mode substitute (numeric readouts + advanced-workspace link, the uptime strip itself, each segment's title attribute) except the one accepted exception (the preview thumbnail), whose capture-state text (.svc-preview-status) stays visible in both themes instead"
    requirement: "UX-01"
    verification:
      - kind: e2e
        ref: "tests/test_ui_states.py#test_deliberate_light_mode_calm_is_hidden_not_absent_and_has_a_named_substitute"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-08-27
status: complete
---

# Phase 5 Plan 03: Theme-Parity Contract Summary

**A regex-derived, self-maintaining test inventory turns "theme parity" from a claim into an exhaustive, classified contract — one source-level test caps the project's theme-gated visibility surface at exactly 8 known rules and proves the advanced workspace has none, and two browser tests prove the main dashboard's shared capability displays in both themes while every deliberately-calm omission is CSS-hidden (not absent) with a recorded substitute.**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-08-27T13:33:00Z (approx.)
- **Completed:** 2026-08-27T14:17:01Z
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments
- `THEME_HIDDEN_RULES` classifies all 8 known `html.light` display:none rules in `dashboard/style.css` as `deliberate-calm` or `decorative`, derived at test time by `extract_theme_gated_hidden_selectors()` rather than hand-transcribed, so a ninth rule anywhere fails the test until classified
- `test_advanced_workspace_hides_nothing_by_theme` proves the same regex applied to `dashboard/advanced.css` extracts an empty set — the advanced workspace renders from one DOM tree in both themes
- `test_decorative_theme_gated_rules_are_dead_and_render_nothing` pins `.corner`/`.offline-badge` as dead rules (absent from every document and script) while confirming `.arc-unit` is still genuinely rendered, keeping the two decorative sub-categories distinguishable
- `test_shared_dashboard_capability_is_present_and_displayed_in_both_themes` proves, from first render in each theme, that every element the theme-parity contract calls reachable-and-visible (gauges, readouts, host identity, sample time, per-service ONLINE/OFFLINE text, uptime strip, events, scan label, theme toggle with correct `aria-pressed`, all four safety banners) is present and computed-displayed — with a resolved body-colour comparison guarding against a light theme that silently failed to apply
- `test_deliberate_light_mode_calm_is_hidden_not_absent_and_has_a_named_substitute` proves the five deliberate-calm rules stay present in the DOM and are CSS-`display:none` only in light mode, then asserts each omission's named light-mode substitute (or the one accepted exception, the preview thumbnail, whose `.svc-preview-status` capture-state text stays visible in both themes)
- The inventory's regex tolerance was verified live, not just inspected: a probe rule was injected into the end of both `dashboard/style.css` and `dashboard/advanced.css`, confirmed to fail the corresponding test with a nine-/one-element extracted set, then removed with the file's SHA-256 checksum confirmed byte-for-byte identical to the pre-injection state

## Task Commits

Each task was committed atomically:

1. **Task 1: The exhaustive, self-maintaining visibility inventory** - `a5752c3` (test)
2. **Task 2: Everything the contract calls shared is displayed in both themes** - `9edf8ff` (test)
3. **Task 3: Deliberate calm is hidden, not absent — and has a named substitute** - `200b3fb` (test)

**Investigation/ledger update (not a plan task):** `dd3172c` (docs) — logs an out-of-scope full-suite-load flake found during Task 3's full-suite verify step; see Deviations below.

_Note: No TDD tasks in this plan; each commit is the complete test addition for its task._

## Files Created/Modified
- `tests/test_ui_contract.py` — `THEME_HIDDEN_RULES`, `DEAD_THEME_HIDDEN_SELECTORS`, `extract_theme_gated_hidden_selectors()`, and three new tests enumerating/classifying/pinning the theme-gated visibility surface
- `tests/test_ui_states.py` — `_theme_parity_dashboard_fixture()`/`_theme_parity_route_api()` helpers plus two new dual-theme Playwright tests proving shared-capability display and deliberate-calm hide-not-absent behavior

## Decisions Made
- Classified `.svc-uptime-pct` as `deliberate-calm` by extension of D-03's identical rationale (assumption A-13), since it is not itself named in `05-CONTEXT.md` D-03
- Pinned `.corner` and `.offline-badge` as dead rules rather than deleting them (assumption A-14) — a future phase that starts rendering either class must re-classify it before its markup can land
- Recorded `.svc-preview` as the one accepted exception with no light-mode substitute (assumption A-15); `.svc-preview-status`, a separate class, is asserted as the substitute for preview *capture state* (not the thumbnail itself)
- Read only `title` (never `aria-label`) for uptime-strip segment accessible text, per assumption A-17 — the `aria-label` pairing is added by plan 05-04 in wave 3, after this plan's wave-2 execution
- Task 2's fixture deliberately removes the `preview_status` key entirely (rather than setting it to `None`/empty string) on two of three services, so the `.svc-preview-status` count-of-1 assertion in Task 3 depends on a genuine fixture fact rather than an accidental falsy-value pass

## Deviations from Plan

### Auto-fixed Issues

None — Rules 1–4 were not triggered. All three tasks executed exactly as specified in the plan, with the tests passing on first implementation.

### Out-of-Scope Discovery (logged, not fixed)

**1. Full-suite-load intermittent flake in an untouched file**
- **Found during:** Task 3's second `<verify>` step (`uv run --project dashboard python -m pytest -q`)
- **Issue:** `tests/test_ui_safety_integration.py::UiSafetyIntegrationTests::test_stale_to_fresh_page_persists_actions_and_records_recovery` failed once (Playwright `TimeoutError` waiting 18s for "Monitoring gap recorded" text) in a full-suite run that also included this plan's two new browser tests
- **Investigation:** This test lives in a file entirely outside this plan's declared scope (`tests/test_ui_contract.py`, `tests/test_ui_states.py`). Applying the corrected-diagnosis rigor recorded in `deferred-items.md` Entry 1 (a prior "flake" in this same phase turned out to be a real deterministic `os.environ` leak from `load_app`), both modified files were grepped for `load_app`/`os.environ`/`import os` — zero matches; this plan's new tests use a static file server plus fully-stubbed `page.route()`, never the real Flask app the failing test depends on. The failing test passed in isolation, and two subsequent full-suite runs (with the complete 05-03 diff present) both passed clean at 755/755 with 0 failures
- **Root cause (of the flaky test, not of this plan):** the failing test captures `self.now = int(time.time())` at `setUp` and performs several real SQLite worker-lease operations before polling the browser for text within an 18s timeout — a wall-clock/resource-contention-sensitive design, matching the same flake class already documented in this phase (05-01's heartbeat-drift deviation, a different specific test)
- **Fix:** None applied — out of scope. Logged to `.planning/phases/05-theme-parity-analytics-experience/deferred-items.md` (Entry 2) and `.planning/WINDOWS.md` (entry 18, kind `deviation`)
- **Verification:** Full suite green on 2 of 3 runs (755 passed, 534 subtests, 0 failures); isolated run of the flaking test passed
- **Committed in:** `dd3172c` (separate docs commit, not part of any task's deliverable)

---

**Total deviations:** 0 auto-fixed. 1 out-of-scope discovery logged (not fixed, per scope boundary).
**Impact on plan:** None on this plan's deliverables — all three tasks' own `<verify>` and `<acceptance_criteria>` passed cleanly, and the plan's own two files have zero involvement in the flaking test's mechanism.

## Issues Encountered
- The probe-injection verification for Task 1's acceptance criteria (append a synthetic `html.light .theme-parity-probe`/`.advanced-parity-probe` rule, confirm the test fails, then restore) required manual SHA-256 checksum comparison before and after, since the plan's acceptance criteria explicitly required byte-for-byte restoration proof — both checksums matched exactly (`style.css`: `924280ed...`, `advanced.css`: `f09b3cc9...`)

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The theme-gated visibility surface is now capped, classified, and self-maintaining; plans 05-05 and 05-06 (and any future UI work) that touch `dashboard/style.css` or `dashboard/advanced.css` will get an immediate, readable test failure if they introduce a new undeclared `html.light`/`html:not(.light)` display:none rule
- `UX-01`, `UX-03`, and `OPS-06` are NOT independently promoted in `REQUIREMENTS.md` by this plan alone — other sibling 05-xx plans also declare these IDs; the checkbox flips only once every declaring plan's `*-SUMMARY.md` exists (per the established phase-05 convention, see 05-01-SUMMARY.md's identical note)
- Assumption A-17's read of `title`-only accessible text on uptime-strip segments is deliberately time-bound to this wave-2 execution; plan 05-04 (wave 3) adds the `role`/`aria-label` pairing next to the identical string, and any future test extending Task 3's segment assertions should read both attributes once 05-04 lands
- No blockers for the remaining Phase 5 plans

## Self-Check: PASSED

All created/modified files and all commit hashes referenced above verified present:
- `tests/test_ui_contract.py`, `tests/test_ui_states.py`, `.planning/phases/05-theme-parity-analytics-experience/deferred-items.md`, `.planning/WINDOWS.md` — found
- Commits `a5752c3`, `9edf8ff`, `200b3fb`, `dd3172c` — found in `git log --oneline --all`

---
*Phase: 05-theme-parity-analytics-experience*
*Completed: 2026-08-27*
