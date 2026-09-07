---
phase: 01-behavioral-safety-runtime-ownership
plan: 18
subsystem: outbound-security
tags: [playwright, chromium, websocket, wss, tls, policy-proxy]
requires:
  - phase: 01-16
    provides: GET/HEAD-only preview routing and pinned HTTPS proxy transport
  - phase: 01-17
    provides: validated Phase 1 gap-closure baseline
provides:
  - Browser contexts that install HTTP and WebSocket transport gates before page creation
  - Zero-handshake and zero-frame proof for hostile TLS WSS preview attempts
  - Refreshed strict TLS fixture for deterministic outbound verification
affects: [previews, outbound-policy, screenshot-capture, service-monitoring, security]
tech-stack:
  added: []
  patterns: [mandatory-browser-context-policy, fail-closed-websocket-routing, real-tls-origin-regression]
key-files:
  created: []
  modified:
    - dashboard/beacon/previews.py
    - dashboard/app.py
    - tests/test_outbound_policy.py
    - tests/fixtures/tls/beacon-test-cert.pem
key-decisions:
  - "Every preview context receives both route gates before callers can create a page."
  - "WSS is closed in Chromium before proxy CONNECT can become an opaque duplex channel."
  - "Approved HTTPS GET/HEAD retrieval continues to use the pinned loopback proxy unchanged."
patterns-established:
  - "Browser transport controls belong in context construction, not at individual page callers."
  - "Hostile-preview transport claims require a real TLS origin that records both Upgrade attempts and decoded frames."
requirements-completed: [FND-07, OPS-05]
coverage:
  - id: D1
    description: "Hostile HTTPS preview JavaScript cannot establish a WSS origin connection or send an opaque mutation frame."
    requirement: FND-07
    verification:
      - kind: e2e
        ref: "tests/test_outbound_policy.py#test_hostile_https_preview_cannot_open_wss_or_deliver_mutation_frame"
        status: pass
    human_judgment: false
  - id: D2
    description: "Preview contexts install HTTP and WebSocket gates before page creation while approved HTTPS retrieval retains its Host and SNI identity."
    requirement: OPS-05
    verification:
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_browser_proxy_context_passes_only_loopback_proxy_and_closes_once"
        status: pass
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_chromium_connect_tunnel_preserves_original_sni_at_pinned_origin"
        status: pass
    human_judgment: false
metrics:
  duration: 12min
  completed: 2026-08-04
  tasks_completed: 1
  files_modified: 4
status: complete
---

# Phase 01 Plan 18: Block Hostile WSS While Preserving HTTPS Retrieval Summary

**Chromium preview contexts now reject every WebSocket before origin connection while ordinary approved HTTPS rendering remains pinned, Host/SNI-preserving retrieval.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-08-04T15:43:19Z
- **Completed:** 2026-08-04T15:54:47Z
- **Tasks:** 1/1
- **Files modified:** 4

## Accomplishments

- Added a mandatory context policy installer that registers both retrieval routing and a catch-all WebSocket close before contexts are yielded.
- Removed the redundant caller-side HTTP registration from screenshot capture, so every production page is created only after both gates exist.
- Added a real TLS hostile-preview regression which proves JavaScript and HTTPS subresources work while the WSS target records neither an Upgrade handshake nor a mutation frame.
- Preserved the selected loopback destination, original Host/SNI identity, trusted-LAN TLS posture, and GET/HEAD proxy behavior.

## Task Commits

1. **Task 1: Block hostile WSS before CONNECT while preserving real HTTPS retrieval** - `ce3d4af` (test), `df1bbbe` (feat)

## Files Created/Modified

- `dashboard/beacon/previews.py` - Installs HTTP and WebSocket context gates and closes routed sockets before an origin can be connected.
- `dashboard/app.py` - Relies on the mandatory context policy before creating the screenshot page.
- `tests/test_outbound_policy.py` - Adds the TLS/WebSocket mutation fixture, zero-handshake/frame regression, and registration ordering checks.
- `tests/fixtures/tls/beacon-test-cert.pem` - Refreshes the local strict-verification certificate while retaining its test identity.

## Decisions Made

- Kept CONNECT available as the carrier for approved HTTPS document and GET/HEAD subresource retrieval; blocked WSS at Chromium's pre-CONNECT context boundary.
- Registered transport policy inside `browser_proxy_context()` to make omission impossible for production callers.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Avoided the Playwright 1.61 sync route-close deadlock**
- **Found during:** Task 1
- **Issue:** Calling the sync `WebSocketRoute.close()` wrapper from its own route callback blocked the Playwright dispatcher indefinitely.
- **Fix:** Returned the route's non-blocking close awaitable when running under Playwright while retaining the direct public close path for test doubles.
- **Files modified:** `dashboard/beacon/previews.py`
- **Verification:** Real hostile TLS/WSS regression completed in 3.05 seconds with zero handshakes and frames.
- **Committed in:** `df1bbbe`

**2. [Rule 3 - Blocking] Refreshed expired local TLS verification fixture**
- **Found during:** Task 1 verification
- **Issue:** The checked-in `alerts.example.test` certificate expired on 2026-08-03, preventing the pre-existing strict TLS/SNI test from reaching its assertion.
- **Fix:** Regenerated only the local certificate with its existing private key, subject, and SAN, valid through 2036-08-01.
- **Files modified:** `tests/fixtures/tls/beacon-test-cert.pem`
- **Verification:** Full outbound-policy suite passed, including strict TLS/SNI validation.
- **Committed in:** `df1bbbe`

**Total deviations:** 2 auto-fixed (1 Rule 1, 1 Rule 3).

## Issues Encountered

- Local loopback fixtures require the approved test environment because the default sandbox prohibits port binding.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The encrypted WSS mutation gap is closed with direct hostile-origin evidence.
- The remaining Phase 1 worker-lease gap closure can proceed independently.

## Self-Check: PASSED

- Found all four modified task files and both task commits (`ce3d4af`, `df1bbbe`).
- Selected safety tests passed (3), outbound-policy tests passed (24 plus 26 subtests), and the complete suite passed in bounded groups (133 non-UI and 17 UI tests).
