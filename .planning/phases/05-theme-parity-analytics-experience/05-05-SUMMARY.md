---
phase: 05-theme-parity-analytics-experience
plan: 05
subsystem: ui
tags: [density, progressive-disclosure, playwright, dual-theme, accessibility]

# Dependency graph
requires:
  - phase: 05-04
    provides: "The keyboard-accessible incident marker, coverage strip, point targets, and range selection this plan's edits to dashboard/advanced.js sit alongside without touching"
  - phase: 03-advanced-current-diagnosis
    provides: "The existing density-comfortable/density-compact body class mechanism (03-CONTEXT.md D-16) this plan extends rather than forks"
provides:
  - "densityDisclosureDefault() -- the single boolean input (reading only the existing density body class, never the theme class) that drives the default open state of the availability detail and each incident row's transitions toggle"
  - "Per-instance operator overrides (availabilityDetailOverride, incidentTransitionsOverrides) that survive re-renders and are pruned to the episodes currently on screen (A-25)"
  - "applyDisclosureDefaults() -- clears overrides and re-applies the density default on an explicit Settings density change only, never on an ordinary re-render"
  - "A directly-asserted D-02 reachability invariant: the set of interactive controls in the workspace, enumerated by an id-or-(tag,class,index) descriptor, is proven identical (multiplicity and enabled-state included) between dark and light"
  - "clearMatchingIncidentCount() closing the Phase 4 tracked-debt gap: a failed filtered incidents fetch can no longer leave a previous render's populated count standing beside its own error banner"
affects: [05-06]

# Actuals (#2632)
actuals:
  tokens: 10063
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Density-driven disclosure default: one boolean (densityDisclosureDefault) read from the existing density body class governs the initial open/expanded state of exactly two named surfaces, with a per-instance override record kept out of persisted preferences -- the same shape as the pre-existing expandedPorts precedent"
    - "id-or-(tag,class,index-among-parent) control descriptor for asserting DOM-shape parity across themes via a Counter (not a set), so a missing control and a changed multiplicity both fail with a readable diff"
    - "Dataset-flag state distinctness (data-matching-known alongside the existing data-total-known) so three distinct count readings never require parsing rendered text"

key-files:
  created: []
  modified:
    - dashboard/advanced.js
    - tests/test_advanced_ui.py
    - tests/test_history_investigation_ui.py

key-decisions:
  - "densityDisclosureDefault() reads only the density body class applyDensity already toggles, never the theme class -- so a light theme explicitly set to compact behaves exactly like a dark theme set to compact (D-02's two-way independence requirement)"
  - "The native <details> 'toggle' event listener is bound exactly once at module init (alongside every other one-time control binding), not inside renderAvailability which runs on every render -- a re-render only ever sets .open from the current override/default, never re-registers a listener"
  - "applyDisclosureDefaults() is deliberately not called from applyDensity() itself, since applyDensity also runs at startup and on theme application; calling it there would make an ordinary re-render clobber an operator's own override (A-24)"
  - "The reachability-invariant fixture (Task 2) deliberately uses exactly one service and one incident episode -- never two of the same repeatable row/marker/segment shape -- so the id-or-(tag,class,index) descriptor can never collide with itself inside a single theme; host metrics are given zero points and an 'observed' coverage interval (which draws no segment) so the four structurally-identical host charts contribute zero id-less elements that would otherwise collide with each other"
  - "Fixed a pre-existing test (test_transitions_toggle_flips_aria_expanded_and_reveals_fixture_rows) that implicitly assumed the transitions toggle always starts collapsed -- a direct, correct consequence of Task 1's density-driven default (dark theme's default density is now compact, which defaults to expanded). The test now pins comfortable density explicitly via localStorage, decoupling its toggle-mechanics assertion from the new density-driven default it does not intend to test"
  - "requirements-completed left unmarked in REQUIREMENTS.md, per the phase's established convention (05-01 through 05-04): UX-03/UX-04/UX-07/OPS-06 are shared with other Phase 5 plans (05-06 also declares OPS-06 and had not both executed at authoring time), and a single plan's own execution may not promote a requirement -- only independent re-verification may"

patterns-established:
  - "A density-driven disclosure default is implemented as one function read at render time by every consuming surface, with per-instance override state kept off the persisted-preferences path entirely -- never a per-density or per-theme render-function pair"

requirements-completed: []

coverage:
  - id: D1
    description: "densityDisclosureDefault() drives the default open state of the availability detail (<details id=\"service-availability-detail\">) and each incident row's transitions toggle; density, not theme, is the input, and either theme can be set to either density with identical results"
    requirement: "UX-04"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_density_drives_disclosure_defaults_and_theme_only_supplies_the_default_density"
        status: pass
    human_judgment: false
  - id: D2
    description: "An operator's own toggle of the availability detail or an incident row's transitions overrides the density default for that instance and survives every subsequent re-render; a render whose episodes no longer include an overridden key prunes it rather than accumulating it"
    requirement: "UX-04"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_an_operator_toggle_survives_re_render_and_other_rows_keep_the_density_default"
        status: pass
    human_judgment: false
  - id: D3
    description: "The D-02 reachability invariant is asserted, not assumed: the set of interactive controls (button/select/input/summary/[tabindex=0]) present and operable across the whole advanced workspace is identical, multiplicity and enabled-state included, in both themes"
    requirement: "UX-03"
    verification:
      - kind: e2e
        ref: "tests/test_advanced_ui.py#test_every_advanced_control_is_present_and_operable_in_both_themes"
        status: pass
    human_judgment: false
  - id: D4
    description: "A failed filtered incidents fetch clears #matching-incident-count to an explicit 'Incident count unavailable' reading with both data-total-known and data-matching-known flags false, distinguishable from a known zero and from a known-matching/unknown-total reading; a subsequent successful fetch restores a known reading"
    requirement: "UX-07"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_failed_filtered_incidents_fetch_clears_the_matching_incident_count"
        status: pass
    human_judgment: false

duration: 32min
completed: 2026-08-27
status: complete
---

# Phase 5 Plan 05: Density-Driven Disclosure and the Reachability Invariant Summary

**Extended the existing density body class into a single-input default for two named disclosure surfaces (availability detail, incident transitions), proved the D-02 reachability invariant with a direct DOM-shape-parity assertion across both themes, and closed a Phase 4 tracked-debt gap where a failed filtered incidents fetch could leave a stale count beside its own error banner.**

## Performance

- **Duration:** 32 min
- **Started:** 2026-08-27T18:00:00+03:00 (approx.)
- **Completed:** 2026-08-27T18:32:00+03:00
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- `densityDisclosureDefault()` (dashboard/advanced.js) reads the existing `density-compact`/`density-comfortable` body class as the single input to the default open state of the availability `<details>` and each incident row's transitions toggle -- never reads the theme class directly, so density and theme are independently settable with identical visible results
- `availabilityDetailOverride` and `incidentTransitionsOverrides` (a `Map` keyed by `incidentEpisodeKey`, port+down_ts) record an operator's own disclosure choice in-memory only, surviving every re-render (refresh poll, range change, service change) and pruned to the episodes currently on screen after every incidents render (A-25)
- `applyDisclosureDefaults()` clears both override records and re-applies the density default, called only from the Settings density `<select>` change handler -- never from `applyDensity()` itself, so an ordinary re-render can never clobber an operator's override
- `test_every_advanced_control_is_present_and_operable_in_both_themes` (tests/test_advanced_ui.py) asserts the D-02 reachability invariant directly: every interactive control across Overview, Host, Services, History (with a selected service), Incidents, Pipeline, and Settings is enumerated via an id-or-(tag,class,index-among-parent) descriptor, collected into a `Counter`, and proven identical -- multiplicity and enabled-state included -- between dark and light, with zero descriptor collisions in either theme
- `test_density_drives_disclosure_defaults_and_theme_only_supplies_the_default_density` proves theme supplies only density's own default: light/no-preference starts both surfaces closed, dark/no-preference starts both open, one keyboard-operable activation in light reveals content byte-identical to dark's default, and an explicit Settings density change flips both defaults regardless of which theme is active
- `clearMatchingIncidentCount()` (dashboard/advanced.js) closes the Phase 4 tracked-debt gap (04-VERIFICATION.md Anti-Patterns / 04-11-REVIEW.md Info finding): the early-return path in `renderIncidentsSection` taken when the filtered fetch fails now writes an explicit `Incident count unavailable` reading and sets both `data-total-known` and `data-matching-known` dataset flags `false`, so a previous render's populated count can never stand beside the error banner
- `updateMatchingIncidentCount`'s two existing branches now also set `data-matching-known` `true`, leaving both existing text strings byte-identical -- the three readings (known/known, known/unknown-total, neither known) are now distinguishable in the DOM without parsing text

## Task Commits

Each task was committed atomically:

1. **Task 1: Density drives the default open state of exactly two containers** - `fddc3a3` (feat)
2. **Task 2: Prove the invariant -- same controls, both themes; closed is one activation from open** - `beca0ec` (test)
3. **Task 3: Overrides survive re-renders, and a failed read never leaves a stale count** - `ba5a677` (fix)

## Files Created/Modified
- `dashboard/advanced.js` - `densityDisclosureDefault`, `applyDisclosureDefaults`, `incidentEpisodeKey`, `applyIncidentTransitionsState`, `state.availabilityDetailOverride`/`state.incidentTransitionsOverrides`, `renderAvailability`'s `<details>` open-state wiring, `incidentRow`'s override-aware initial expanded state, `renderIncidents`'s override-map pruning, the module-init `toggle` listener binding, the Settings density `<select>` handler's `applyDisclosureDefaults()` call, `clearMatchingIncidentCount`, `updateMatchingIncidentCount`'s new `data-matching-known` flag, and `renderIncidentsSection`'s early-return `clearMatchingIncidentCount()` call
- `tests/test_advanced_ui.py` - `test_every_advanced_control_is_present_and_operable_in_both_themes`, `test_density_drives_disclosure_defaults_and_theme_only_supplies_the_default_density`, and the fixture builders they share (`config_fixture`, `host_metric_fixture`, `service_history_fixture`, `incident_episode`, `events_history_fixture`, `build_investigation_route`, `CONTROL_ENUMERATION_SCRIPT`)
- `tests/test_history_investigation_ui.py` - `test_failed_filtered_incidents_fetch_clears_the_matching_incident_count`, `test_an_operator_toggle_survives_re_render_and_other_rows_keep_the_density_default`, and a scoping fix to the pre-existing `test_transitions_toggle_flips_aria_expanded_and_reveals_fixture_rows`

## Decisions Made
- `densityDisclosureDefault()` reads only the density body class, never the theme class directly, per D-02's two-way independence requirement
- The native `<details>` `toggle` listener is bound exactly once at module init (matching every other one-time control binding in this file), not inside `renderAvailability` -- a re-render only ever sets `.open`, never re-registers a listener
- `applyDisclosureDefaults()` is deliberately not called from `applyDensity()` itself, since `applyDensity` also runs at startup and on theme application; calling it there would let an ordinary re-render clobber an operator's own override (A-24)
- The reachability-invariant fixture uses exactly one service and one incident episode, and gives host metrics zero points with an `observed` coverage interval, so the id-or-(tag,class,index) descriptor scheme used to prove the invariant can never produce a false collision between the four structurally-identical host charts
- `requirements-completed` left empty in this SUMMARY's frontmatter, per the phase's established convention (05-01 through 05-04): all four of this plan's declared requirements (UX-03, UX-04, UX-07, OPS-06) are shared with other Phase 5 plans, and a single plan's own execution does not promote a requirement -- only independent re-verification may

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Test-design correction] Decoupled a pre-existing test from the new density-driven default it did not intend to test**
- **Found during:** Task 1, first run of `tests/test_history_investigation_ui.py`
- **Issue:** `test_transitions_toggle_flips_aria_expanded_and_reveals_fixture_rows` asserted the transitions toggle always starts collapsed (`Show transitions`/`aria-expanded="false"`). This was a correct assumption before Task 1, but Task 1's own change makes the default depend on density -- and the test's page loads with the default (dark) theme, whose default density is now `compact`, which defaults the toggle to *expanded*. The test failed with `'Hide transitions' != 'Show transitions'`.
- **Fix:** Seeded `density: 'comfortable'` via the existing `localStorage`-init-script idiom before navigation, so the test's starting point (collapsed) is pinned explicitly and independent of the page's default theme/density -- decoupling its toggle-flip-mechanics assertion from the density default, which is separately and directly covered by this plan's own new tests
- **Files modified:** tests/test_history_investigation_ui.py
- **Verification:** `uv run --project dashboard python -m pytest tests/test_advanced_ui.py tests/test_history_investigation_ui.py -q` exits 0 with the fix; failed without it
- **Committed in:** `fddc3a3` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 test-design correction, Rule 1). No production-code bugs, missing-critical functionality, or blocking issues beyond the plan's own stated actions.
**Impact on plan:** None on any stated acceptance criterion or `<verify>` command -- every one passed as specified once the pre-existing test was corrected. No scope creep: the fix touches only the one test whose own assumption the plan's change directly invalidated.

## Issues Encountered
None beyond the test-design correction above.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `densityDisclosureDefault()` and `applyDisclosureDefaults()` are now the established, single-source-of-truth pattern for any future density-driven presentation choice; a third disclosure surface would extend the same two functions rather than adding a new mechanism (A-29 keeps this plan's own scope to exactly two surfaces)
- The `CONTROL_ENUMERATION_SCRIPT` id-or-(tag,class,index) descriptor and its Counter-based comparison in `tests/test_advanced_ui.py` is now available as a reusable pattern for any future dual-theme parity assertion across the workspace
- `data-matching-known` joins `data-total-known` on `#matching-incident-count` as an established convention: any future count-bearing element facing a similar "may not have been produced" state should carry the same two-flag distinctness pattern rather than inferring state from rendered text
- `UX-03`, `UX-04`, `UX-07`, and `OPS-06` are **NOT** marked complete in `REQUIREMENTS.md` -- `05-06` also declares `OPS-06` and may not yet have executed; per the phase's established convention, only independent re-verification may promote a Phase 5 requirement
- No blockers for `05-06` or for a subsequent Phase 5 verification round

## Self-Check: PASSED

All created/modified files and all commit hashes referenced above verified present:
- `dashboard/advanced.js`, `tests/test_advanced_ui.py`, `tests/test_history_investigation_ui.py` -- found
- Commits `fddc3a3`, `beca0ec`, `ba5a677` -- found in `git log --oneline`

---
*Phase: 05-theme-parity-analytics-experience*
*Completed: 2026-08-27*
