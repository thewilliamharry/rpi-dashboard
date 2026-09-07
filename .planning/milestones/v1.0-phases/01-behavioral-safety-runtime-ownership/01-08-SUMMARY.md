---
phase: 01-behavioral-safety-runtime-ownership
plan: 08
subsystem: ui
tags: [vanilla-js, flask, playwright, accessibility, responsive-design, monitoring]
requires:
  - phase: 01-05
    provides: Worker freshness and migration recovery state for web-safe dashboard reads
  - phase: 01-06
    provides: Durable scan and preview queue status with metadata updates during worker outages
  - phase: 01-07
    provides: Persisted trusted-LAN TLS posture and redacted outbound-policy failures
provides:
  - Ordered, accessible browser, worker, and recovery safety warnings
  - Truthful durable scan and preview status with stale-worker metadata feedback
  - Independent TLS posture badges and safe inline error behavior
  - Chromium-backed zero/one/many UI coverage in both themes and supported widths
affects: [dashboard, monitoring, service-metadata, previews, phase-02]
tech-stack:
  added: []
  patterns:
    - Render server-owned availability, worker, recovery, queue, and TLS state as separate labels
    - Keep stale operational data interactive while announcing bounded recovery changes through a polite live region
key-files:
  created:
    - tests/test_ui_states.py
  modified:
    - dashboard/index.html
    - dashboard/app.js
    - dashboard/style.css
    - dashboard/app.py
    - tests/test_ui_contract.py
key-decisions:
  - "Safety warnings occupy one stable cluster below the topbar in connection, worker, then recovery order."
  - "TLS trust posture is a non-interactive badge separate from ONLINE/OFFLINE and uptime."
  - "Metadata failures always use one safe browser message and retain entered values for retry."
patterns-established:
  - "Use deterministic local API fixtures and Chromium to cover dashboard DOM state without external services."
  - "Use explicit text labels alongside warning, availability, and queue colors in both themes."
requirements-completed: [FND-01, FND-04, FND-07, OPS-05]
coverage:
  - id: D1
    description: Ordered monitoring, recovery, scan, preview, and metadata-outage presentation
    requirement: FND-01
    verification:
      - kind: automated_ui
        ref: tests/test_ui_states.py
        status: pass
    human_judgment: false
  - id: D2
    description: Independent trusted-LAN TLS posture, safe failure copy, and responsive accessible controls
    requirement: FND-07
    verification:
      - kind: automated_ui
        ref: tests/test_ui_states.py tests/test_ui_contract.py
        status: pass
    human_judgment: false
  - id: D3
    description: Durable queue and stale-worker dashboard semantics remain compatible with runtime ownership and outbound policy
    requirement: OPS-05
    verification:
      - kind: integration
        ref: tests/test_runtime_ownership.py tests/test_durable_queues.py tests/test_outbound_policy.py
        status: pass
    human_judgment: false
duration: 14min
completed: 2026-07-31
status: complete
---

# Phase 01 Plan 08: Behavioral Safety UI Summary

**The dashboard now keeps stale monitoring interactive while clearly separating browser connectivity, worker freshness, migration recovery, durable queue work, service availability, and trusted-LAN TLS posture.**

## Performance

- **Duration:** 14 min
- **Started:** 2026-07-31T21:16:00Z
- **Completed:** 2026-07-31T21:29:59Z
- **Tasks:** 2/2
- **Files modified:** 6

## Accomplishments

- Added the ordered `#safety-warning-cluster`, truthful scan/preview queue copy, recovery feedback, and a stale-worker metadata flow that saves immediately and restores edit focus.
- Rendered persistent accessible `TLS unverified` badges independently from ONLINE/OFFLINE, added safe policy-error rendering, and renamed the existing control to `Edit service`.
- Added deterministic Chromium coverage for zero, one, and several services and events across dark/light desktop and 720px layouts, including narrow modal action size and monitoring-gap rendering.

## Task Commits

1. **Task 1: Render ordered monitoring, recovery, scan, and preview states** - `87f09bf` (test), `534a2d0` (feat)
2. **Task 2: Show TLS posture and prove all UI consideration states in both themes** - `41558a5` (test), `5ad7487` (feat), `6f2fcd0` (test)
3. **Verification correction: separate migration recovery presentation** - `f523655` (fix)

## Files Created/Modified

- `dashboard/index.html` - stable warning cluster and accessible metadata warning/error regions.
- `dashboard/app.js` - independent worker, recovery, scan, preview, TLS, event, feedback, and safe-error rendering.
- `dashboard/style.css` - warning, badge, preview-status, wrapping, theme-parity, and 720px action styles.
- `dashboard/app.py` - additive current preview status and migration-marker status for browser state.
- `tests/test_ui_states.py` - source contracts plus deterministic Playwright zero/one/many UI harness.
- `tests/test_ui_contract.py` - TLS accessibility and safe-error source contract.

## Decisions Made

- Put static warning regions in markup rather than creating them dynamically, so their order and live-region behavior stay stable.
- Preserve current readable cards and controls during worker staleness; only the scan button is disabled while submitting or actively running.
- Treat a recovery marker as a distinct warning condition while retaining the established stale-worker compatibility field for API consumers.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Kept migration recovery distinct from ordinary worker staleness in the browser.**
- **Found during:** Task 2 verification
- **Issue:** The legacy `recovery_required` API compatibility field reported stale heartbeats, which would make a migration-recovery warning ambiguous.
- **Fix:** Added the marker-backed recovery condition while retaining the stale-heartbeat compatibility value; the browser displays the recovery warning only for the distinct marker condition.
- **Files modified:** `dashboard/app.py`, `tests/test_ui_states.py`
- **Verification:** Focused Phase 1 suite and full pytest suite pass.
- **Committed in:** `f523655`

---

**Total deviations:** 1 auto-fixed Rule 1 bug.
**Impact on plan:** The correction preserves API compatibility and makes the required warning hierarchy truthful without expanding Phase 1 scope.

## Known Stubs

None.

## User Setup Required

None - Playwright Chromium was installed locally for test execution only; the deployed dashboard retains its existing container-managed browser runtime.

## Next Phase Readiness

- The main dashboard now has a tested safety-state seam for later analytics work without introducing advanced-workspace navigation or destructive recovery controls.
- Future browser changes should retain the separate labels for connection, worker freshness, recovery, queue work, availability, and TLS posture.

## Self-Check: PASSED

- Confirmed all six planned UI and test files exist.
- Confirmed task and correction commits `87f09bf`, `534a2d0`, `41558a5`, `5ad7487`, `f523655`, and `6f2fcd0` exist in Git history.
- Verified the focused Phase 1 UI/runtime/security suite passes with 50 tests and 4 subtests, and the full suite passes with 101 tests and 4 subtests.
