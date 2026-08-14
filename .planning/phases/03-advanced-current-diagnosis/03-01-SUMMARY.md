---
phase: 03-advanced-current-diagnosis
plan: 01
subsystem: api-ui-database
tags: [flask, sqlite, vanilla-javascript, pytest, playwright]
requires:
  - phase: 02-bounded-telemetry-retention
    provides: managed SQLite reads and current system-stat evidence
provides:
  - bounded GET-only current-host diagnosis snapshot at /api/advanced/current
  - direct /advanced document and controller route with truthful freshness rendering
  - reusable Flask-free diagnosis and repository seams for later Phase 3 payload expansion
affects: [03-02-service-pipeline-diagnosis, 03-03-advanced-workspace-ui, phase-4-historical-investigation]
tech-stack:
  added: []
  patterns:
    - Flask-free diagnosis composition backed by one managed SQLite read transaction
    - same-origin cache-disabled GET with DOM textContent rendering and failed-refresh retention
key-files:
  created:
    - dashboard/beacon/diagnosis.py
    - dashboard/advanced.html
    - dashboard/advanced.js
    - tests/test_advanced_diagnosis_api.py
    - tests/test_advanced_ui.py
  modified:
    - dashboard/app.py
    - dashboard/beacon/repositories.py
key-decisions:
  - "Classify current-host freshness server-side from sample timestamp and configured cadence, returning unknown rather than inventing health."
  - "Keep the advanced snapshot endpoint GET-only and effect-free; the browser preserves the last successful evidence after a refresh failure."
patterns-established:
  - "Advanced route adapter: document, script, reserved stylesheet, and bounded API route remain thin Flask edges."
  - "Current diagnosis reads one primary-key system_stats row through repositories.read_current_host inside read_transaction."
requirements-completed: [DIA-01, DIA-02]
coverage:
  - id: D1
    description: "Direct advanced workspace route and GET-only current-host snapshot expose a bounded, trusted-host-protected diagnosis path."
    requirement: DIA-01
    verification:
      - kind: integration
        ref: "uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py -k 'tracer or host or direct_route' -x"
        status: pass
    human_judgment: false
  - id: D2
    description: "Advanced workspace renders current host identity and metrics with server-derived freshness, including truthful failed-refresh retention."
    requirement: DIA-02
    verification:
      - kind: automated_ui
        ref: "tests/test_advanced_ui.py#AdvancedUiTests"
        status: pass
    human_judgment: false
duration: 3min
completed: 2026-08-14
status: complete
---

# Phase 3 Plan 1: Current-Host Diagnosis Tracer Summary

**A direct, GET-only advanced workspace now renders one current Raspberry Pi snapshot from a bounded SQLite read with truthful server-side freshness.**

## Performance

- **Duration:** 3 min implementation window; resumed after operator checkpoint approval
- **Started:** 2026-08-13T06:39:29Z
- **Completed:** 2026-08-14T10:17:59Z
- **Tasks:** 1/1
- **Files modified:** 7

## Accomplishments

- Added `/advanced`, `/advanced.js`, reserved `/advanced.css`, and bounded `/api/advanced/current` Flask adapters protected by existing middleware.
- Composed a versioned current-host payload from one managed SQLite read and classified freshness without worker, scheduler, history, thumbnail, or network effects.
- Added deterministic API and browser tracer coverage for freshness boundaries, direct-route behavior, text-safe rendering, and retention of the last successful snapshot on refresh failure.

## Task Commits

1. **Task 1: Trace one current-host diagnosis from SQLite to /advanced (RED)** — `2aa7b65` (test)
2. **Task 1: Trace one current-host diagnosis from SQLite to /advanced (GREEN)** — `19bacc7` (feat)

## Files Created/Modified

- `dashboard/beacon/diagnosis.py` — Flask-free current diagnosis composition and freshness classification.
- `dashboard/beacon/repositories.py` — fixed primary-key reader for current host evidence.
- `dashboard/app.py` — thin advanced document/static/GET API adapters.
- `dashboard/advanced.html` and `dashboard/advanced.js` — semantic advanced shell and text-safe host snapshot renderer.
- `tests/test_advanced_diagnosis_api.py` and `tests/test_advanced_ui.py` — deterministic tracer contracts.

## Decisions Made

- Freshness is a server-derived state (`fresh`, `aging`, `stale`, or `unknown`), with future samples clamped to zero age and invalid evidence reported as unknown.
- A failed browser refresh leaves the previous successful host evidence and timestamp visible instead of claiming new data.

## Checkpoint Approval

The operator approved the completed human-verification checkpoint for Task 1. Prior commits `2aa7b65` and `19bacc7` were verified before continuation; no task work was repeated.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py -k "tracer or host or direct_route" -x` — **6 passed, 15 subtests passed**.
- `uv run --project dashboard python -m pytest -q` — **passed** after rerunning outside the sandbox, whose default policy blocks local loopback sockets required by browser/proxy tests.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

The sandbox prevented the test suite from binding ephemeral `127.0.0.1` ports. The unchanged test command passed when rerun with local loopback permission; this was an environment constraint, not a product defect.

`state.advance-plan` could not parse the pre-existing `Plan: Not started` placeholder in `STATE.md`. The equivalent supported state patch set the next position to `Plan: 2 of 4`; all other state handlers completed normally.

## Known Stubs

None.

## Threat Flags

None - the implementation adds only the planned GET-only route and bounded SQLite read surface.

## Next Phase Readiness

Plan 03-02 can extend the stable current-diagnosis root with services, pipeline, settings, and exception evidence without replacing the bounded host route, service boundary, or browser refresh contract.

## Self-Check: PASSED

Confirmed the summary and all seven task files exist, and both RED/GREEN task commits (`2aa7b65`, `19bacc7`) are present in git history.

---
*Phase: 03-advanced-current-diagnosis*
*Completed: 2026-08-14*
