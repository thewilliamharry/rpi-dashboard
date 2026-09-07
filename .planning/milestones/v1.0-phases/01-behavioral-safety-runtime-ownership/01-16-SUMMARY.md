---
phase: 01-behavioral-safety-runtime-ownership
plan: 16
subsystem: outbound-security
tags: [playwright, chromium, http-proxy, retrieval-only, socket-cleanup]
requires:
  - phase: 01-12
    provides: numeric-address-pinned Chromium policy proxy with route interception
provides:
  - GET/HEAD-only browser route and plain-proxy enforcement
  - Hostile Chromium zero-mutation evidence across allowed origins
  - Exactly-once pre-relay socket and semaphore cleanup
affects: [previews, outbound-policy, service-monitoring, security]
tech-stack:
  added: []
  patterns: [shared-retrieval-method-allowlist, explicit-proxy-ownership-transfer]
key-files:
  created: []
  modified:
    - dashboard/beacon/outbound.py
    - dashboard/beacon/previews.py
    - tests/test_outbound_policy.py
key-decisions:
  - "Browser previews are retrieval-only: only GET and HEAD may cross either the route gate or plain-proxy boundary."
  - "An acquired origin remains handler-owned until transfer to _relay(), whose existing cleanup is the sole post-transfer owner."
patterns-established:
  - "Untrusted browser requests are method-gated before URL policy planning and network continuation."
  - "Pre-relay resources use an explicit ownership transfer so each socket slot has exactly one cleanup owner."
requirements-completed: [FND-07, OPS-05]
coverage:
  - id: D1
    description: "Browser previews retrieve GET/HEAD resources but cannot send unsafe methods through Playwright routing or the plain HTTP proxy."
    requirement: FND-07
    verification:
      - kind: e2e
        ref: "tests/test_outbound_policy.py#test_hostile_chromium_preview_cannot_mutate_second_allowed_origin"
        status: pass
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_route_rejects_every_non_retrieval_method_before_policy_planning"
        status: pass
    human_judgment: false
  - id: D2
    description: "Pre-relay proxy failures close origins and release bounded capacity exactly once."
    requirement: OPS-05
    verification:
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_pre_relay_failures_close_origin_and_release_each_slot_once"
        status: pass
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_repeated_pre_relay_failures_leave_capacity_for_a_real_proxy_get"
        status: pass
    human_judgment: false
metrics:
  duration: 12min
  completed: 2026-08-01
  tasks_completed: 2
  files_modified: 3
status: complete
---

# Phase 01 Plan 16: Retrieval-Only Preview Safety Summary

**Chromium previews now allow only GET/HEAD retrieval and retain full proxy capacity after every pre-relay failure.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-08-01T08:57:51Z
- **Completed:** 2026-08-01T09:09:00Z
- **Tasks:** 2/2
- **Files modified:** 3

## Accomplishments

- Added one shared retrieval-method predicate, used by the Playwright route gate before policy planning and by the plain HTTP proxy before origin connection.
- Added an explicit `405 Method Not Allowed` response with `Allow: GET, HEAD` for unsafe plain proxy methods, without reading or forwarding their request bodies.
- Proved a real local hostile Chromium page cannot mutate a second allowed HTTP or HTTPS origin while normal GET subresources still load.
- Made handler-owned pre-relay origins close and release their bounded semaphore slots exactly once on CONNECT-response, tunneled-remainder, header-format, and plain-forwarding failures.

## Task Commits

Each TDD task was committed atomically:

1. **Task 1: Prove a hostile preview cannot mutate a second allowed origin** - `49494bd` (test), `3931d02` (feat)
2. **Task 2: Release every origin socket and proxy slot before relay transfer** - `0073ca3` (test), `aa14b63` (fix)

## Files Created/Modified

- `dashboard/beacon/outbound.py` - Shared GET/HEAD predicate, method rejection, and handler-owned pre-relay cleanup.
- `dashboard/beacon/previews.py` - Abort-before-plan browser route enforcement for every non-retrieval method.
- `tests/test_outbound_policy.py` - Isolated local-origin method recording, real hostile Chromium proof, and deterministic failure/capacity regressions.

## Decisions Made

- Kept CONNECT available only as Chromium's HTTPS transport; Playwright rejects unsafe HTTPS request methods before a tunnel can be used.
- Preserved numeric destination pinning, original Host/SNI identity, TLS posture, redirect/rebinding policy, and relay-owned cleanup behavior.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The execution sandbox blocks loopback port binding, so local HTTP/TLS origin and Chromium verification ran under the approved local-test permission only; no external traffic was used.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Preview content has retrieval authority only at both enforceable boundaries.
- Proxy capacity remains reusable after all tested pre-relay failure paths.

## Self-Check: PASSED

- Found modified outbound and preview modules plus the outbound-policy test suite.
- Found task commits `49494bd`, `3931d02`, `0073ca3`, and `aa14b63`.
- Final verification passed: outbound policy (22 passed, 26 subtests), security/release suites (25 passed), and full pytest suite.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-08-01*
