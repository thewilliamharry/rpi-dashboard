---
phase: 01-behavioral-safety-runtime-ownership
plan: 12
subsystem: outbound-security
tags: [urllib3, dns-rebinding, chromium, proxy, tls, ssrf]
requires:
  - phase: 01-11
    provides: durable worker execution and fenced preview queue ownership
provides:
  - Numeric-address-pinned HTTP and HTTPS transport
  - Loopback-only policy proxy for Chromium HTTP and CONNECT traffic
  - Real-origin destination, Host, TLS SNI, redirect, and rebinding evidence
affects: [service-monitoring, previews, webhooks, outbound-policy]
tech-stack:
  added: []
  patterns: [validated-plan-to-numeric-socket, authority-preserving-tls, per-capture-browser-proxy]
key-files:
  created:
    - tests/fixtures/tls/beacon-test-cert.pem
    - tests/fixtures/tls/beacon-test-key.pem
  modified:
    - dashboard/beacon/outbound.py
    - dashboard/beacon/previews.py
    - dashboard/app.py
    - tests/test_outbound_policy.py
    - tests/test_security_and_scanning.py
    - tests/test_release_contract.py
key-decisions:
  - "HTTP and HTTPS pools connect only to RequestPlan.selected_address, while Host, TLS SNI, and strict certificate hostname checks retain the original authority."
  - "Chromium uses a short-lived loopback proxy for every preview context; route interception remains an early policy gate, not the socket enforcement boundary."
  - "Trusted-LAN service TLS remains unverified only for service purposes; webhook delivery stays strict, pinned, and redirect-free."
patterns-established:
  - "A validated request plan owns both the authority identity and one immutable numeric socket destination."
  - "Browser proxy tests use deterministic local origins and assert observed destinations rather than only policy-plan calls."
requirements-completed: [FND-07, OPS-05]
coverage:
  - id: D1
    description: "HTTP and HTTPS outbound traffic pins its numeric socket destination while preserving Host, TLS SNI, and certificate-hostname identity."
    requirement: FND-07
    verification:
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_socket_destination_and_host_header_are_pinned"
        status: pass
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_tls_sni_and_certificate_hostname_survive_pinned_socket"
        status: pass
    human_judgment: false
  - id: D2
    description: "Redirects and DNS rebinding attempts are replanned or rejected before any forbidden origin connection."
    requirement: OPS-05
    verification:
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_redirect_hop_replans_before_opening_its_selected_socket"
        status: pass
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_rebinding_after_planning_never_resolves_or_connects_by_hostname"
        status: pass
      - kind: integration
        ref: "tests/test_outbound_policy.py#test_proxy_rebinding_blocks_before_any_forbidden_origin_connection"
        status: pass
    human_judgment: false
  - id: D3
    description: "Chromium preview main frames, subresources, and HTTPS CONNECT tunnels traverse the policy proxy and retain their original service authority."
    requirement: FND-07
    verification:
      - kind: e2e
        ref: "tests/test_outbound_policy.py#test_chromium_main_frame_and_subresource_use_loopback_policy_proxy"
        status: pass
      - kind: e2e
        ref: "tests/test_outbound_policy.py#test_chromium_connect_tunnel_preserves_original_sni_at_pinned_origin"
        status: pass
    human_judgment: false
metrics:
  duration: 14min
  completed: 2026-08-01
  tasks_completed: 3
  files_modified: 8
status: complete
---

# Phase 01 Plan 12: DNS-Rebinding Socket Enforcement Summary

**Beacon now pins every approved HTTP and Chromium origin socket to a numeric address while preserving original HTTP authority, TLS SNI, and certificate identity.**

## Performance

- **Duration:** 14 min
- **Started:** 2026-08-01T06:30:25Z
- **Completed:** 2026-08-01T06:44:31Z
- **Tasks:** 3/3
- **Files modified:** 8

## Accomplishments

- Replaced hostname-opening outbound requests with urllib3 pools that open `RequestPlan.selected_address`, set the original `Host`, and preserve original TLS server-name and verification identity.
- Added a bounded, loopback-only HTTP/CONNECT proxy for Chromium preview contexts, with per-request planning, numeric origin sockets, idle limits, relay-slot accounting, and deterministic cleanup.
- Proved probes, title fetches, webhooks, redirects, browser main frames, HTTP subresources, and HTTPS CONNECT traffic cannot bypass the outbound policy; preview failures now return stable, destination-free error categories.

## Task Commits

Each TDD task was committed atomically:

1. **Task 1: Pin one HTTP and HTTPS request to the policy-approved address** - `019d651` (test), `c1b2516` (feat)
2. **Task 2: Route Chromium sockets through a bounded policy proxy** - `ce45c30` (test), `210e913` (feat)
3. **Task 3: Wire preview capture and guard every outbound call site** - `a724b10` (test), `d67f400` (fix)
4. **High-severity browser-boundary evidence** - `29c70e2` (test), `7a17bf5` (test)

## Files Created/Modified

- `dashboard/beacon/outbound.py` - Immutable selected-address plans, urllib3 pinned transport, and bounded loopback proxy.
- `dashboard/beacon/previews.py` - Context manager that owns one policy proxy per Chromium context.
- `dashboard/app.py` - Pins service/webhook callers and constructs preview contexts through the enforcing proxy with safe errors.
- `tests/test_outbound_policy.py` - Local real-origin tests for destination, Host, SNI, redirects, rebinding, raw proxy paths, and real Chromium paths.
- `tests/test_security_and_scanning.py` - Production redirect seam and destination-free preview error coverage.
- `tests/test_release_contract.py` - Strict webhook transport seam coverage.
- `tests/fixtures/tls/beacon-test-cert.pem` - Deterministic local TLS identity fixture.
- `tests/fixtures/tls/beacon-test-key.pem` - Matching deterministic local TLS test key.

## Decisions Made

- Kept the trusted-LAN service-only TLS exception by setting `CERT_NONE` solely for eligible service plans; the strict webhook plan still uses original-host certificate validation.
- Opened fresh pools and browser origin sockets only by `selected_address`; no connection layer invokes hostname DNS after policy planning.
- Used a short-lived per-preview proxy so shutdown closes relay state with its browser context instead of creating a global browser-side network bypass.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added real Chromium browser-boundary assertions**
- **Found during:** Final high-severity verification
- **Issue:** Raw proxy tests proved the proxy implementation but did not independently prove Chromium main-frame/subresource and CONNECT traffic reached the browser socket boundary.
- **Fix:** Added deterministic local Chromium HTTP-subresource and HTTPS CONNECT/SNI tests through the loopback proxy.
- **Files modified:** `tests/test_outbound_policy.py`
- **Verification:** Browser proxy suite passed with local origins only.
- **Committed in:** `29c70e2`, `7a17bf5`

---

**Total deviations:** 1 auto-fixed (1 missing critical test boundary).
**Impact on plan:** Required for the high-severity completion invariant; no product-scope expansion.

## Issues Encountered

- The sandbox blocks loopback port binding, so deterministic local-origin tests ran under the approved local-test permission; no external network was used.

## Known Stubs

None.

## Security Decisions

- DNS answers are validated once per request hop, then the resulting immutable numeric address is the only socket destination.
- Browser route callbacks remain an early rejection/event point, while the proxy owns final socket enforcement for redirects and subresources.
- Transport and preview responses expose stable categories only; addresses and raw exception strings are not reflected.

## Next Phase Readiness

- The outbound safety gap is closed with real socket-level evidence for requests and Chromium.
- Subsequent work can rely on the validated-plan-to-numeric-socket boundary for service monitoring and preview behavior.

## Self-Check: PASSED

- Found all created TLS fixtures and modified outbound/proxy modules.
- Found task commits `019d651`, `c1b2516`, `ce45c30`, `210e913`, `a724b10`, `d67f400`, `29c70e2`, and `7a17bf5`.
- Final verification: `dashboard/.venv/bin/python -m pytest -q` — 128 passed, 4 subtests passed.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-08-01*
