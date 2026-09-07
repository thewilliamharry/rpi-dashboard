---
phase: 01-behavioral-safety-runtime-ownership
plan: 07
subsystem: security
tags: [outbound-policy, ssrf, dns, redirects, tls, webhook, playwright]
requires:
  - phase: 01-03
    provides: Explicit Beacon module boundaries with a compatibility application adapter
provides:
  - Immutable purpose-specific outbound request plans
  - DNS-aware redirect and TLS policy for service, browser, and webhook traffic
  - Policy-before-persistence metadata validation and redacted webhook failures
affects: [monitoring, previews, service-metadata, alerting, phase-01-plan-08]
tech-stack:
  added: []
  patterns:
    - Immutable RequestPlan/TlsPosture values for per-request transport decisions
    - Redirect-owning transport that validates each candidate before access
    - Browser route gate that aborts disallowed subresources before continuation
key-files:
  created:
    - dashboard/beacon/outbound.py
    - tests/test_outbound_policy.py
  modified:
    - dashboard/beacon/config.py
    - dashboard/app.py
    - dashboard/beacon/previews.py
    - dashboard/beacon/repositories.py
    - tests/test_security_and_scanning.py
    - tests/test_release_contract.py
key-decisions:
  - "Outbound service targets use dedicated host/network allowlists, not inbound Host/Origin trust lists."
  - "The trusted-LAN TLS exception is an immutable service request posture; webhook plans are always HTTPS, verified, and redirect-free."
  - "Compatibility handlers retain the active I/O integration until their staged extraction is complete."
patterns-established:
  - "Request every outbound purpose through OutboundPolicy before transport or browser continuation."
  - "Persist TLS trust posture separately from reachability, status transitions, and uptime history."
requirements-completed: [FND-07, OPS-05]
coverage:
  - id: D1
    description: "Purpose-specific immutable outbound target, DNS, redirect, and TLS policy"
    requirement: FND-07
    verification:
      - kind: unit
        ref: "tests/test_outbound_policy.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "Strict webhook delivery, protected metadata mutation, and browser request gating"
    requirement: OPS-05
    verification:
      - kind: integration
        ref: "tests/test_outbound_policy.py tests/test_security_and_scanning.py tests/test_release_contract.py"
        status: pass
    human_judgment: false
duration: 16min
completed: 2026-07-31
status: complete
---

# Phase 01 Plan 07: Outbound Safety Policy Summary

**Immutable per-purpose outbound plans now enforce DNS-aware service, browser, and webhook boundaries without treating the trusted-LAN TLS exception as downtime.**

## Performance

- **Duration:** 16 min
- **Started:** 2026-07-31T20:34:52Z
- **Completed:** 2026-07-31T20:50:52Z
- **Tasks:** 3/3
- **Files modified:** 8

## Accomplishments

- Added a dedicated outbound policy with safe rejection classes, full A/AAAA validation, bounded service redirects, and strict exact-destination webhooks.
- Routed requests and Chromium resource continuations through immutable plans; persisted TLS trust posture independently of availability and uptime data.
- Made webhook errors redacted and metadata URL changes policy-gated before persistence, with concurrency-focused TLS isolation coverage.

## Task Commits

1. **Task 1: Decide target, redirect, and TLS posture before connection** - `442b2bb` (test), `a28b6e3` (feat)
2. **Task 2: Route requests and Chromium through the common policy** - `01bd8cd` (test), `0117291` (feat)
3. **Task 3: Keep webhooks and mutations strict under overlapping work** - `2d03256` (test), `ae53032` (feat)

## Files Created/Modified

- `dashboard/beacon/outbound.py` - immutable target/DNS/TLS plans and no-follow transport.
- `dashboard/beacon/config.py` - dedicated outbound service host and network allowlists.
- `dashboard/app.py` - compatibility I/O integration, strict alert delivery, and metadata policy enforcement.
- `dashboard/beacon/previews.py` - browser-route guard for main-frame and subresource requests.
- `dashboard/beacon/repositories.py` - separate durable TLS trust-posture state.
- `tests/test_outbound_policy.py` - table-driven policy, redirect, browser, and concurrent-plan checks.

## Decisions Made

- Kept browser Host/Origin trust configuration separate from outbound allowlists to prevent inbound trust from becoming an SSRF permit.
- Webhooks must match the configured HTTPS URL exactly, resolve to globally routable addresses, use verified TLS, and reject all redirects.
- Kept intentional unverified TLS confined to configured service targets and persisted it separately so it cannot affect online state or uptime buckets.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Critical safety integration] Routed the active compatibility adapter through the policy**
- **Found during:** Task 2
- **Issue:** The staged module extraction still leaves actual requests, Playwright lifecycle, webhook delivery, and metadata routes in `dashboard/app.py`; changing only the listed thin modules would leave live network paths outside the policy.
- **Fix:** Integrated the shared policy at the compatibility edge while retaining the planned framework-free module boundaries.
- **Files modified:** `dashboard/app.py`
- **Verification:** Focused security suites and the complete pytest suite pass.
- **Committed in:** `0117291`, `ae53032`

---

**Total deviations:** 1 auto-fixed (Rule 2)
**Impact on plan:** Necessary safety integration only; no change to public route contracts or availability semantics.

## Issues Encountered

- Existing metadata paths retain URL fragments for browser navigation. The policy now strips those fragments from the network request while preserving the stored UI path, and continues to reject webhook fragments.

## Known Stubs

None.

## User Setup Required

None - existing deployments can optionally configure `SERVICE_TARGET_HOSTS` and `SERVICE_TARGET_NETWORKS`; defaults preserve local/LAN service behavior.

## Next Phase Readiness

- Plan 08 can display the single safe policy error class returned by mutation routes.
- All outgoing network paths have a shared policy seam for further monitoring and UI work.

## Self-Check: PASSED

- Confirmed `dashboard/beacon/outbound.py` and `tests/test_outbound_policy.py` exist.
- Confirmed all six task commits are present in Git history.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-07-31*
