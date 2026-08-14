---
phase: quick
plan: 260814-kfc
subsystem: ui
tags: [vanilla-js, playwright, accessibility, tls]
requires:
  - phase: 01-behavioral-safety-runtime-ownership
    provides: Independent trusted-LAN TLS posture and service-card metadata editor behavior
provides:
  - Compact TLS posture and edit labels with preserved accessible descriptions
affects: [dashboard-ui, service-tls-posture]
tech-stack:
  added: []
  patterns:
    - Keep compact visible service-card controls paired with descriptive ARIA labels
key-files:
  created: []
  modified:
    - dashboard/app.js
    - tests/test_ui_contract.py
    - tests/test_ui_states.py
key-decisions:
  - "TLS posture remains conditionally rendered and separate from service availability."
  - "The Edit button's compact visual label retains Edit service as its explicit accessible name."
requirements-completed: [FND-07]
coverage:
  - id: D1
    description: Compact trusted-LAN TLS badge and service edit control preserve their descriptive accessibility semantics.
    requirement: FND-07
    verification:
      - kind: automated_ui
        ref: "uv run --project dashboard python -m pytest -q tests/test_ui_contract.py tests/test_ui_states.py -x"
        status: pass
    human_judgment: false
metrics:
  duration: 2m
  completed: 2026-08-14
  tasks_completed: 1
  files_changed: 3
status: complete
---

# Quick Task 260814-kfc: Compact Service-Card Copy Summary

**Service cards now show compact `TLS` and `Edit` labels while retaining the full trusted-LAN certificate warning and `Edit service` accessible name.**

## Accomplishments

- Shortened only the TLS badge's visible text; its condition, CSS hook, title, and ARIA warning remain unchanged.
- Shortened only the edit button's visible text and added an explicit `Edit service` ARIA label.
- Extended static and Playwright contracts to prove visible copy, descriptions, and the existing metadata-editor click path.

## Task Commits

1. **Task 1: Compact service-card copy while preserving accessible meaning** - `37d6622` (test), `003d3af` (feat)

## Files Created/Modified

- `dashboard/app.js` - compact service-card copy with preserved TLS and editor semantics.
- `tests/test_ui_contract.py` - static accessible-copy contract.
- `tests/test_ui_states.py` - browser-visible copy, accessibility, and edit-activation coverage.

## Verification

- RED: `uv run --project dashboard python -m pytest -q tests/test_ui_contract.py tests/test_ui_states.py -x` failed as expected on the old `TLS unverified` source copy.
- GREEN: `uv run --project dashboard python -m pytest -q tests/test_ui_contract.py tests/test_ui_states.py -x` — 16 passed.
- Diff inspection confirmed changes are limited to the three planned files; Phase 3 verification gaps remain untouched.

## Decisions Made

- Preserve the existing full TLS title and ARIA text rather than reducing assistive information with the visual label.
- Use an explicit button ARIA label so `Edit` remains compact without weakening the control's accessible name.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Self-Check

PASSED - confirmed the summary and all three planned files exist; verified commits `37d6622` and `003d3af` are present in Git history.
