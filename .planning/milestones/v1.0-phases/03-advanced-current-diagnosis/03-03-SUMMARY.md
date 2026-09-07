---
phase: 03-advanced-current-diagnosis
plan: 03
subsystem: ui
tags: [vanilla-javascript, flask, playwright, localstorage, diagnostics]
requires:
  - phase: 03-02
    provides: One stable, effect-free advanced current-diagnosis snapshot.
provides:
  - Exception-first advanced Overview and complete current Host evidence.
  - Separate Pipeline and Settings diagnosis regions with truthful empty and partial states.
  - Bounded local refresh and allowlisted presentation preferences.
affects: [03-04-services-diagnosis, advanced-workspace, ui]
tech-stack:
  added: []
  patterns: [Route-local snapshot renderer, one-owner refresh timer, defensive localStorage projection]
key-files:
  created: [dashboard/advanced.css]
  modified: [dashboard/advanced.html, dashboard/advanced.js, tests/test_advanced_ui.py]
key-decisions:
  - "Advanced UI renders server-classified freshness and typed pipeline evidence without recomputing it."
  - "Only validated presentation preferences are persisted under beacon-advanced-preferences-v1."
patterns-established:
  - "Advanced sections keep stable semantic regions and replace their content through textContent-based DOM construction."
  - "Refresh failures retain the last successful snapshot and timestamp while scheduled polling remains single-owner."
requirements-completed: [TEL-06, DIA-01, DIA-02, DIA-08]
coverage:
  - id: D1
    description: Exception-first Overview and current Host workspace across responsive navigation states.
    requirement: DIA-01
    verification:
      - kind: automated_ui
        ref: tests/test_advanced_ui.py#workspace-overview-host
        status: pass
    human_judgment: false
  - id: D2
    description: Pipeline and Settings evidence with explicit empty, unknown, and local-only states.
    requirement: TEL-06
    verification:
      - kind: automated_ui
        ref: tests/test_advanced_ui.py#pipeline-and-settings
        status: pass
    human_judgment: false
  - id: D3
    description: Predictable refresh, pause, density defaults, and allowlisted browser preferences.
    requirement: DIA-08
    verification:
      - kind: automated_ui
        ref: tests/test_advanced_ui.py#refresh-pause-preferences
        status: pass
    human_judgment: false
metrics:
  duration: 18min
  completed: 2026-08-14
status: complete
---

# Phase 03 Plan 03: Advanced Current Workspace Summary

**A responsive exception-first advanced diagnosis workspace with current Host, Pipeline, and Settings evidence, plus truthful refresh retention and local presentation preferences.**

## Performance

- **Duration:** 18min
- **Completed:** 2026-08-14T11:08:57Z
- **Tasks:** 3/3
- **Files modified:** 4

## Accomplishments

- Added the persistent five-section workspace, safety-warning ordering, responsive rail/tabs, exception-first Overview, and complete current Host evidence.
- Rendered independent retention, pressure, worker, stream, gap, pending aggregation, job, effective-setting, and local-presentation regions without operational controls.
- Added one bounded refresh owner with safe failure retention, pause/resume, exact valid intervals, theme-aware density defaults, and defensive preference persistence.

## Task Commits

1. **Task 1: Build the persistent workspace shell, exception-first Overview, and Host diagnosis** — `78d4b3d` (feat)
2. **Task 2: Render complete Pipeline evidence and read-only Settings** — `3e1876f` (feat)
3. **Task 3: Add predictable refresh and allowlisted presentation preferences** — `530d33f` (feat)

## Files Created/Modified

- `dashboard/advanced.html` — Semantic workspace shell, safety cluster, refresh controls, and section regions.
- `dashboard/advanced.js` — Snapshot renderers, refresh controller, safety states, and preference projection.
- `dashboard/advanced.css` — Token-based responsive rail/tab layout, density variants, and long-content containment.
- `tests/test_advanced_ui.py` — Deterministic browser coverage for workspace, Overview, Host, Pipeline, Settings, refresh, and preferences.

## Decisions Made

- Rendered server-provided freshness and independent pipeline facts as text evidence; the browser does not infer causes or reclassify states.
- Kept all advanced controls browser-local and persisted only the approved allowlisted values.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k "not services" -x` — passed (7 tests)
- `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py -x` — passed (17 tests, 15 subtests)
- `uv run --project dashboard python -m pytest -q` — passed

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Self-Check: PASSED

- Verified all four implementation/test artifacts and the summary exist.
- Verified commits `78d4b3d`, `3e1876f`, and `530d33f` exist in Git history.

## Next Phase Readiness

The non-service advanced workspace is ready for Plan 03-04 to add the dense Services table and its local filters without adding another data source or refresh loop.
