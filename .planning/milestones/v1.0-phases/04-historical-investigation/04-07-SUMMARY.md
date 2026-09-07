---
phase: 04-historical-investigation
plan: 07
subsystem: ui
tags: [vanilla-js, incidents, filtering, grouping, navigation-stack, maintenance]

# Dependency graph
requires:
  - phase: 04-historical-investigation
    provides: "04-02's GET /api/events/history (episode grouping, overrun grace/fault split, flapping_groups) as the sole data source this plan renders"
  - phase: 04-historical-investigation
    provides: "04-05's setInvestigationRange/pushRange/popRange navigation stack and INCIDENT_PAD_FRACTION/INCIDENT_PAD_FLOOR_SECONDS constants, reused verbatim by focusIncident"
  - phase: 04-historical-investigation
    provides: "04-06's setSelectedService/clearSelectedService carried-selection entry point, extended (not replaced) to keep the Incidents service filter in sync"
provides:
  - "The Incidents nav entry and section: filter form (service/criticality/event-type+maintenance-visibility), matching count, loading/empty/error/truncated states"
  - "investigation-header: the shared range control relocated out of history-section so one control governs both History and Incidents (D-16), toggled by one added hook in selectSection"
  - "incidentRow/incidentDurationBar/renderFlappingBanner: the full row anatomy -- open badge, overrun duration-bar split at grace expiry, Expected chip, flapping banner, transitions disclosure"
  - "focusIncident/incidentFocusWindow: clicking a row sets the carried service selection and pushes a padded window onto the shared navigation stack, moving host charts, service views and the incident list together"
  - "historyFilters: the filtering half of the DIA-08 range/filter preference remainder (D-04), persisted under the existing beacon-advanced-preferences-v1 key"
affects: [04-08]

# Actuals (#2632)
actuals:
  tokens: 19588
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "investigation-header is a plain <div> (not a <section>), inserted as the first child of .advanced-detail rather than a new grid column -- selectSection's existing `.advanced-detail > section` query already ignores it, so exactly one added hook toggles its `hidden` attribute for history/incidents without touching the five Phase 3 sections' own visibility logic"
    - "The Incidents service filter is never an independent second fact: validHistoryFilters derives `service` from the one carried selectedService value on every load/save, and setSelectedService is the only place historyFilters.service is ever written, so the filter select and the carried selection can never disagree (D-16)"
    - "renderIncidentsSection fetches the filtered list and an unfiltered baseline for the same range in parallel via Promise.allSettled -- 'N of M incidents' needs the baseline because M is deliberately never narrowed by the operator's own filter choice, mirroring the exact two-independent-reads composition 04-06's fetchServiceHistory already established"
    - "The event-type filter is one <select> combining two disjoint parameter namespaces in a single prefixed string value ('event_type:<member>' vs 'maintenance:<mode>'), since the UI-SPEC treats EVENT_TYPES and the two maintenance-visibility options as one filter dimension on one control rather than two"

key-files:
  created: []
  modified:
    - dashboard/advanced.html
    - dashboard/advanced.js
    - dashboard/advanced.css
    - tests/test_history_investigation_ui.py
    - tests/test_advanced_ui.py
    - .planning/REQUIREMENTS.md

key-decisions:
  - "Task 2's full incidentRow anatomy (open badge, overrun duration bar, Expected chip, flapping banner, transitions disclosure) and Task 3's focusIncident/incidentFocusWindow were implemented in the same commit as Task 1's filter/matching-count/state machinery, because Task 1's own acceptance criteria (a populated list renders real rows; a zero-match response renders the documented empty copy; a 503 leaves filters operable) require a real, working row renderer to observe -- mirroring the exact precedent 04-05/04-06-SUMMARY.md recorded for their own Task 1/Task 2 splits. Task 2's and Task 3's own commits are therefore test-only, proving out each task's own contract against the already-working implementation"
  - "incidentDurationBar renders every closed episode uniformly (grace_seconds/fault_seconds sub-segments sized proportionally) rather than special-casing the common non-overrun incident -- the server's own split_overrun_span already returns grace_seconds=0/fault_seconds=full-span for a plain incident, so the bar degenerates to a single red segment without a second code path that could drift from the overrun path's own math"
  - "An open episode renders no 'End:' line at all (not 'End: Ongoing') -- so 'the row contains no end timestamp' (D-12/Pitfall 4) is literal, not merely undated text in an End slot"
  - "DIA-06 and DIA-08 are deliberately NOT marked complete despite being listed in this plan's own requirements frontmatter -- both are joint requirements 04-01/04-05/04-06 already declined to promote (\"promotion is left to the phase-level verifier once every contributing plan has landed, not claimed by the plan that happens to land first\", 04-05-SUMMARY.md), and DIA-08's checkbox was explicitly left for the phase verifier by 04-01-SUMMARY.md even after that plan closed the traceability-row wording. Only HIS-04 and HIS-05 -- fully and solely delivered by this plan -- are promoted"
  - "Clear all filters also clears the carried service selection (via setSelectedService(null)), not just criticality/event-type -- the UI-SPEC's own Filters section lists service as one of the four AND-combined filters this control resets; only the shared range (the investigation context itself, D-16) is left untouched"

patterns-established:
  - "A single <select> mapping onto two disjoint server query parameters via a prefixed string value ('event_type:x' / 'maintenance:y') -- reusable wherever a future filter UI needs one control to span two independently-validated server parameters without a second control"

requirements-completed: [HIS-04, HIS-05]

coverage:
  - id: D1
    description: "The Incidents section is reachable from nav and governed by one shared range control (never duplicated per section); four filters (service, criticality, event type, maintenance-visibility mapped onto event type) combine with AND semantics, each issuing a request carrying the mapped parameter"
    requirement: "HIS-04"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_incidents_nav_reveals_section_and_shares_one_range_header"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_incident_criticality_filter_issues_request_and_narrows_count"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_maintenance_visibility_options_issue_maintenance_param_and_default_shows_suppressed"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_combining_criticality_and_event_type_filters_issues_one_request_with_both"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_clear_all_incident_filters_resets_and_leaves_range_unchanged"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_incident_filters_persist_across_reload_and_hostile_stored_value_falls_back"
        status: pass
    human_judgment: false
  - id: D2
    description: "Honest empty, loading, error and truncated states: zero matches render the documented copy and 'N of M incidents'; a failed fetch renders the documented error and leaves filters operable; a truncated response discloses it; no affordance on the surface implies a remote action"
    requirement: "HIS-04"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_zero_match_incidents_renders_empty_copy_and_matching_count"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_incidents_fetch_failure_renders_error_and_keeps_filters_enabled"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_truncated_incidents_response_renders_disclosure"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_incidents_section_has_no_action_affordances"
        status: pass
    human_judgment: false
  - id: D3
    description: "One row is one grouped down-to-recovered episode: an open episode renders Ongoing with no synthesized end timestamp and sorts first; an overrun episode renders a two-segment duration bar and two separate Down since/Raised at lines; an open overrun omits the fault segment; a suppressed row is tagged Expected by default; three-plus episodes in 15 minutes gain one shared flapping banner over still-separate rows; a transitions disclosure reveals the raw fixture rows; a long service name wraps rather than truncating"
    requirement: "HIS-04"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_open_episode_renders_ongoing_badge_no_end_timestamp_and_sorts_first"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_overrun_episode_renders_two_duration_segments_and_two_timestamp_lines"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_open_overrun_renders_ongoing_and_no_fault_segment"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_expected_chip_renders_for_suppressed_row_by_default"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_flapping_group_renders_one_banner_above_three_separate_rows"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_transitions_toggle_flips_aria_expanded_and_reveals_fixture_rows"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_long_service_name_wraps_within_row"
        status: pass
    human_judgment: false
  - id: D4
    description: "Choosing an incident sets the carried service selection and pushes its padded window (15% per side, 300s floor) onto the shared navigation stack, driving the host charts, service views and incident list together; an open episode's pushed window never exceeds the current range's own end_ts; Back appears and restores the prior range"
    requirement: "HIS-05"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_clicking_incident_row_focuses_service_and_pushes_padded_range"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_focus_padding_floor_applies_for_a_short_episode"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_open_incident_focus_caps_end_at_current_range_end"
        status: pass
    human_judgment: false

duration: 95min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 7: Incidents Section Summary

**A filterable Incidents list under the same shared range control as History -- one row is one grouped down-to-recovered episode, unresolved outages say `Ongoing` rather than being closed against a clock nobody observed, overrun outages carry both durable timestamps split at grace expiry, and choosing a row moves the whole investigation (service, range, and every dependent view) together.**

## Performance

- **Duration:** ~95 min
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- The `Incidents` nav entry and section exist between `History` and `Pipeline`, sharing one relocated `investigation-header`/`investigation-range` control with `History` (`id="investigation-range"` appears exactly once in the DOM, verified visible for `history`/`incidents` and hidden for every current-state section) -- `selectSection` gained exactly one added hook and is otherwise byte-identical to Phase 3's behavior
- Four AND-combined filters (`incident-service-filter`, `incident-criticality-filter`, and one combined `incident-event-type-filter` spanning `EVENT_TYPES` plus the two maintenance-visibility options) each issue a `GET /api/events/history` request carrying the mapped parameter; the default request carries no `maintenance` parameter and suppressed rows are visible by default (D-13), the opposite of the main dashboard's hidden-by-default feed
- `matching-incident-count` reads `{N} of {M} incidents` at all times: `renderIncidentsSection` fetches the filtered list and an unfiltered baseline for the same range in parallel, so `M` is never narrowed by the operator's own filter choice
- `historyFilters` (service/criticality/eventType) is validated against the exact server allowlists (`CRITICALITY_VALUES`, `EVENT_TYPES`, `MAINTENANCE_MODES`, and the same bounded-port rule `validSelectedService` already applies) before ever reaching a request URL, and persists under the existing `beacon-advanced-preferences-v1` key -- surviving a reload and falling back to the documented default on a hostile stored value
- `incidentRow` renders every episode shape honestly: an open episode shows `▶ Ongoing — not yet recovered` with no end-timestamp line at all and sorts first (server-ordered); an overrun episode's duration bar splits into a grace-covered (Maintenance colour) and post-grace unplanned-fault (Offline/red) sub-segment sized by the server's own `grace_seconds`/`fault_seconds`, beside `Down since`/`Raised at` as two permanently separate lines; a suppressed row carries an `Expected` chip; a `flapping_groups` entry renders one `Flapping — {N} episodes in {span}` banner above still-separate rows; each row's `Show transitions` disclosure reveals the raw fixture rows behind `aria-expanded`
- `focusIncident`/`incidentFocusWindow` do exactly two things in order: `setSelectedService(episode.port)` then `setInvestigationRange({...paddedWindow, origin: 'incident'})`, reusing 04-05's navigation stack and 04-06's carried selection verbatim -- an open episode's pushed window is capped at the current shared range's own `end_ts` and the padded window is additionally clamped to the 90-day retention bound
- No affordance anywhere in `#incidents-section` implies Beacon can act on a service -- verified by an accessible-name scan for restart/stop/retry/fix/remediate across every button, link, input and select in the section
- `REQUIREMENTS.md` `HIS-04` and `HIS-05` promoted to complete; `DIA-06` and `DIA-08` deliberately left pending for the phase verifier (see Decisions Made)

## Task Commits

1. **Task 1: The Incidents section, the shared range header, and four narrowing filters** - `3a6bdbf` (feat) -- includes Task 2's full row anatomy and Task 3's `focusIncident` in full (see Decisions Made)
2. **Task 2: Incident row anatomy — open, overrun, expected, flapping** - `0aff3e9` (test) -- the row anatomy was already generic from Task 1's own commit; this commit's delta is its own Playwright coverage
3. **Task 3: Choosing an incident focuses the whole investigation** - `e476e0f` (test) -- `focusIncident`/`incidentFocusWindow` were already working from Task 1's own commit; this commit's delta is its own Playwright coverage

**Plan metadata:** committed by the orchestrator after this SUMMARY

## Files Created/Modified

- `dashboard/advanced.html` - nav button `data-section="incidents"`; `investigation-header` wrapping the relocated `investigation-range` container as the first child of `.advanced-detail`; `incidents-section` with `incident-filters`, `matching-incident-count`, `incidents-loading`/`incidents-error`/`incidents-truncated`/`incidents-empty`/`incidents-list`
- `dashboard/advanced.js` - `DEFAULT_HISTORY_FILTERS`, `INCIDENT_EVENT_TYPES`/`INCIDENT_CRITICALITY_VALUES`/`INCIDENT_MAINTENANCE_MODES`, `validHistoryFilters`, `state.incidentsRequestGeneration`; `incidentQueryParams`, `fetchIncidents`, `beginIncidentsLoadingState`, `updateMatchingIncidentCount`, `populateIncidentServiceFilterOptions`, `syncIncidentServiceFilterControl`, `syncIncidentFilterControls`, `renderIncidentsSection` (Task 1); `incidentDurationBar`, `incidentRow`, `renderFlappingBanner`, `renderIncidents` (Task 2); `incidentFocusWindow`, `focusIncident` (Task 3); `selectSection` extended with the one `investigation-header` visibility hook; `setSelectedService` extended to keep `historyFilters.service` and the Incidents filter control in sync; `applyRangeAndRender` extended to also re-render Incidents on every range change; filter-control/clear-button/nav-button wiring and `window.__incidentTestHooks` added at the bottom of the IIFE
- `dashboard/advanced.css` - `#investigation-header`, `.incident-filters`, `.incidents-list`, `.incidents-empty`, `.incident-row`, `.incident-row-header`, `.incident-service`, `.incident-chip-expected`, `.incident-badge-open`, `.incident-timestamps`, `.incident-duration-bar`/`.incident-duration-grace`/`.incident-duration-fault`, `.incident-meta`, `.incident-transitions-toggle`/`.incident-transitions`, `.incident-flapping-banner`
- `tests/test_history_investigation_ui.py` - `_incidents_route`/`_goto_incidents` fixture helpers plus 20 new Playwright tests across filters/matching-count/states/no-action-affordance (Task 1), row anatomy (Task 2), and focus/navigation-stack (Task 3)
- `tests/test_advanced_ui.py` - the pinned nav-label list extended to include `Incidents`; the pinned preference-key allowlist extended to include `historyFilters`
- `.planning/REQUIREMENTS.md` - `HIS-04`/`HIS-05` promoted to complete in both the checkbox list and the traceability table

## Decisions Made

- Task 2's full `incidentRow` anatomy and Task 3's `focusIncident`/`incidentFocusWindow` were implemented in the same commit as Task 1's own filter/state machinery, since Task 1's own acceptance criteria (a populated list renders real rows; a zero-match response renders the documented empty copy; a 503 leaves filters operable) require a real, working row renderer to observe against -- the exact precedent 04-05-SUMMARY.md and 04-06-SUMMARY.md both recorded for their own Task 1/Task 2 splits. Task 2's and Task 3's own commits are therefore test-only, proving out each task's own contract against the already-working implementation
- `incidentDurationBar` renders every closed episode through one uniform code path (grace_seconds/fault_seconds sub-segments sized proportionally) rather than special-casing the common non-overrun incident -- the server's `split_overrun_span` already returns `grace_seconds=0`/`fault_seconds=<full span>` for a plain incident, so the bar degenerates to one red segment without a second, possibly-diverging math path
- An open episode renders no `End:` line at all (not `End: Ongoing`) -- "the row contains no end timestamp" (D-12/Pitfall 4) is therefore literal, not merely undated text occupying an End slot
- The Incidents service filter is never an independent second fact: `validHistoryFilters` always re-derives its `service` field from the one carried `selectedService` value on load/save, and `setSelectedService` is the only place that ever writes it, so the filter control and the carried selection can never disagree (D-16)
- `Clear all filters` also clears the carried service selection via `setSelectedService(null)`, not just criticality/event-type -- the UI-SPEC's own Filters section lists service as one of the four AND-combined filters this control resets; only the shared range (the investigation context itself, per D-16) is left untouched
- `DIA-06` and `DIA-08` are deliberately **not** marked complete despite being listed in this plan's own `requirements` frontmatter. Both are joint requirements that 04-01, 04-05 and 04-06 already declined to promote on their own: 04-05-SUMMARY.md records "promotion is left to the phase-level verifier once every contributing plan has landed, not claimed by the plan that happens to land first," and 04-01-SUMMARY.md left `DIA-08`'s checkbox unchecked "for the phase verifier" even after closing its traceability-row wording. This plan is the last one whose frontmatter lists `DIA-06`, but "last" is not "phase verifier" -- only `HIS-04` and `HIS-05`, fully and solely delivered by this plan, are promoted here
- `renderIncidentsSection` fetches the filtered list and an unfiltered baseline for the same range in parallel via `Promise.allSettled` -- `N of M incidents` needs both numbers, and `M` is deliberately never narrowed by the operator's own filter selection, mirroring the exact two-independent-reads composition 04-06's `fetchServiceHistory` already established for telemetry+events

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Two pre-existing regression tests pinned the exact section-nav label list and preference-key allowlist**
- **Found during:** Task 1 (full-suite regression run)
- **Issue:** `test_workspace_sections_overview_and_host_states` asserted the exact six-label nav list (`Overview, Host, Services, History, Pipeline, Settings`); `test_refresh_pause_and_allowlisted_preferences_are_local_and_defensive` asserted the exact seven-key `localStorage` preference set. Adding the plan-mandated `Incidents` nav entry and `historyFilters` preference key are legitimate, plan-mandated additions to both sets, exactly as 04-01/04-06 previously extended the same two pinned assertions for their own new surfaces.
- **Fix:** Extended both expected sets to include the new entry/key.
- **Files modified:** `tests/test_advanced_ui.py`
- **Verification:** Both tests pass; full `tests/test_advanced_ui.py` suite green (139/139).
- **Committed in:** `3a6bdbf` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 -- two narrow-scope adjustments to pre-existing tests whose assumptions this plan's own legitimate new surface surpasses; no acceptance criterion or documented contract was weakened)
**Impact on plan:** No scope creep.

## Issues Encountered

None beyond the deviation above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `focusIncident`/`incidentFocusWindow` are the last consumer of 04-05's navigation stack and 04-06's carried selection this phase introduces -- both are now exercised from three independent entry points (drag, preset/Back, and incident focus) with no additional stack logic needed.
- `DIA-06` and `DIA-08` are ready for the phase verifier to promote: every contributing plan (04-01, 04-05, 04-06, 04-07) has now landed its own half of each requirement.
- 04-08 (correlation: shared time axis, incident markers, hover cursor) can read `episode.down_ts`/`episode.recovered_ts`/`episode.critical` directly from the same `/api/events/history` response this plan already fetches for the Incidents list, without new plumbing.
- No blockers for 04-08.

## Self-Check: PASSED

All modified files found on disk; all three commit hashes (`3a6bdbf`, `0aff3e9`, `e476e0f`) found in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*
