---
phase: 03-advanced-current-diagnosis
plan: 04
subsystem: ui
tags: [vanilla-javascript, playwright, accessibility, responsive-design, localstorage]
requires:
  - phase: 03-03
    provides: Route-local snapshot state, refresh owner, workspace shell, and presentation preferences.
provides:
  - Local-only service filtering, operational sorting, and multi-row diagnostic disclosure.
  - Same-tab dashboard/advanced navigation with shared theme and one-shot scroll restoration.
  - Locked responsive service-table boundaries and mechanical UI consideration coverage.
affects: [phase-3-verification, advanced-workspace, dashboard-navigation]
tech-stack:
  added: []
  patterns:
    - Service interactions consume the already-bounded current snapshot without fetches or mutations.
    - Dashboard return context uses validated, consumed-once tab-local session storage.
key-files:
  created: []
  modified:
    - dashboard/advanced.html
    - dashboard/advanced.js
    - dashboard/advanced.css
    - dashboard/index.html
    - dashboard/app.js
    - tests/test_advanced_ui.py
key-decisions:
  - "Keep service filters and details entirely route-local; persist only validated filter values."
  - "Use ordinary same-tab links, the existing beacon-theme key, and a one-shot session scroll offset for dashboard return context."
  - "Lock narrow behavior below 960px and summary stacking below 720px so boundary behavior is mechanically testable."
patterns-established:
  - "A service table always retains semantic headers and detail rows, including loading and empty states."
  - "User sorting uses raw server evidence with stable input-order ties, while successful snapshots restore operational ordering."
requirements-completed: [DIA-01, DIA-03, DIA-08, UX-02]
coverage:
  - id: D1
    description: "Every current service can be searched, filtered, operationally sorted, and compared through expandable diagnostic rows without remote actions."
    requirement: DIA-03
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_services_filters_sort_and_multi_disclosure_contract"
        status: pass
    human_judgment: false
  - id: D2
    description: "Dashboard and Advanced diagnosis use same-tab navigation while preserving theme and consuming a valid tab-local scroll offset once."
    requirement: UX-02
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_theme_or_return_round_trip_preserves_theme_and_consumes_scroll_once"
        status: pass
    human_judgment: false
  - id: D3
    description: "The approved UI consideration inventory, exact viewport boundaries, sticky identity, and 44px targets are enforced in Chromium."
    requirement: DIA-08
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_ui_consideration_inventory_is_complete_and_unique"
        status: pass
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#test_breakpoint_boundary_and_accessibility_contract"
        status: pass
    human_judgment: false
metrics:
  duration: 10min
  completed: 2026-08-14
status: complete
---

# Phase 3 Plan 4: Services Diagnosis and Navigation Continuity Summary

**A local-only, accessible all-service diagnosis table now supports comparison without losing evidence, and dashboard/advanced round trips retain theme plus one-shot scroll context.**

## Performance

- **Duration:** 10 min
- **Started:** 2026-08-14T11:15:12Z
- **Completed:** 2026-08-14T11:24:49Z
- **Tasks:** 3/3
- **Files modified:** 6

## Accomplishments

- Built the semantic Services table with local combinable filters, truthful `N of M services` counts, stable operational/user sorting, and multiple accessible detail disclosures.
- Kept availability, freshness, TLS posture, failure, cadence, exact timestamp, and collection-gap evidence distinct in expanded diagnostics, with sticky narrow identity and no card fallback.
- Added ordinary same-tab dashboard/advanced navigation that keeps `beacon-theme` unchanged and safely restores a validated dashboard scroll offset exactly once.
- Locked 959/960 and 719/720 responsive behavior and added a complete UI-01 through UI-36 inventory with browser accessibility assertions.

## Task Commits

1. **Task 1: Implement the sortable, filterable, multi-expand service diagnosis table (RED)** — `4f9aa23` (test)
2. **Task 1: Implement the sortable, filterable, multi-expand service diagnosis table (GREEN)** — `2f506ea` (feat)
3. **Task 2: Wire the same-tab dashboard round trip with theme and scroll continuity (RED)** — `fa973f6` (test)
4. **Task 2: Wire the same-tab dashboard round trip with theme and scroll continuity (GREEN)** — `f589a93` (feat)
5. **Task 3: Close breakpoint, precision, accessibility, and 36-consideration parity (RED)** — `b54003f` (test)
6. **Task 3: Close breakpoint, precision, accessibility, and 36-consideration parity (GREEN)** — `5d22367` (feat)

## Files Created/Modified

- `dashboard/advanced.html` — Adds labelled filters, count/actions, responsive table semantics, skeleton rows, and empty-state copy.
- `dashboard/advanced.js` — Owns local filtering, deterministic sorting, detail disclosure, evidence rendering, and preference projection.
- `dashboard/advanced.css` — Styles fixed diagnostic columns, narrow sticky identity, focus states, 44px controls/rows, and exact breakpoints.
- `dashboard/index.html` and `dashboard/app.js` — Add the ordinary Advanced diagnosis link and safe tab-local scroll round trip.
- `tests/test_advanced_ui.py` — Covers services, navigation continuity, responsive/accessibility boundaries, and the UI-01–UI-36 inventory.

## Decisions Made

- Keep all service interactions browser-local over the existing snapshot; no service filter, sort, disclosure, or reset calls an API or creates a monitoring action.
- Reset user sorting only on a successful snapshot refresh, filter-clear, or explicit operational-order reset; keep expanded detail ports memory-only.
- Consume the scroll key before restoration so malformed, stale, or cross-load values cannot repeatedly affect dashboard navigation.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py -x` — **24 passed, 15 subtests passed**.
- `uv run --project dashboard python -m pytest -q tests/test_ui_contract.py tests/test_ui_states.py tests/test_ui_safety_integration.py -x` — **17 passed**.
- Full project suite completed in bounded verification batches — **243 passed, 269 subtests passed**.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Manual Capacity Check Pending

The Raspberry Pi-class 15-minute refresh/load observation from `03-VALIDATION.md` remains a manual environment check. It requires representative monitored services and cannot be reproduced by the deterministic browser fixture suite.

## Next Phase Readiness

Phase 3’s current-diagnosis workspace is complete with service comparison, navigation continuity, and responsive/accessibility coverage. The remaining capacity observation should be performed during Phase 3 UAT on target hardware.

## Self-Check: PASSED

- Verified all six RED/GREEN task commits exist and all six planned source/test artifacts are present.
- Verified no task commit deleted a tracked file.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-14*
