---
phase: 01-behavioral-safety-runtime-ownership
reviewed: 2026-08-01T09:17:32Z
depth: standard
files_reviewed: 29
files_reviewed_list:
  - dashboard/app.js
  - dashboard/app.py
  - dashboard/beacon/config.py
  - dashboard/beacon/db.py
  - dashboard/beacon/migrations.py
  - dashboard/beacon/outbound.py
  - dashboard/beacon/previews.py
  - dashboard/beacon/queues.py
  - dashboard/beacon/recovery.py
  - dashboard/beacon/repositories.py
  - dashboard/beacon/worker_main.py
  - dashboard/index.html
  - dashboard/style.css
  - dashboard/worker.py
  - tests/fixtures/tls/beacon-test-cert.pem
  - tests/fixtures/tls/beacon-test-key.pem
  - tests/test_api_and_auth.py
  - tests/test_backup_recovery.py
  - tests/test_durable_queues.py
  - tests/test_migrations.py
  - tests/test_module_boundaries.py
  - tests/test_outbound_policy.py
  - tests/test_release_contract.py
  - tests/test_runtime_ownership.py
  - tests/test_security_and_scanning.py
  - tests/test_ui_contract.py
  - tests/test_ui_safety_integration.py
  - tests/test_ui_states.py
findings:
  critical: 1
  warning: 1
  info: 0
  total: 2
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-01T09:17:32Z
**Depth:** standard
**Files Reviewed:** 29
**Status:** issues_found

## Summary

Reviewed the Phase 1 application, worker, persistence/recovery, outbound-policy, browser-preview, UI, TLS fixture, and test changes. Marker validation and queue terminal transitions are carefully guarded, and the metadata endpoint rejects non-exact JSON primitive types. However, the browser-preview egress boundary is still bypassable through an encrypted tunnel, and worker ownership is not released for ordinary scheduler exits or failures after acquisition.

## Critical Issues

### CR-01: BLOCKER — HTTPS browser tunnels bypass GET/HEAD-only enforcement

**File:** `dashboard/beacon/outbound.py:293`
**Issue:** `CONNECT` is unconditionally accepted and then handed to the bidirectional opaque relay at lines 297–303 and 448–480. A hostile HTTPS preview can open a `wss://` WebSocket (the upgrade begins as an allowed `GET`) and send arbitrary state-changing WebSocket frames after the tunnel is established. Neither `route_browser_request()` nor the proxy can inspect or block those frames, so the claimed GET/HEAD-only browser boundary does not hold for allowed HTTPS services.

**Fix:** Treat WebSockets and other long-lived upgraded/tunnel protocols as disallowed in the preview context. For example, disable JavaScript for untrusted preview pages if static rendering is acceptable, or add a Chromium/CDP request policy that rejects WebSocket creation before `CONNECT` is opened; retain a proxy-side restriction that only permits the narrowly required HTTPS navigation flow. Add an integration test where an HTTPS preview page attempts `new WebSocket(...)` and verify the target receives no mutation frame.

## Warnings

### WR-01: WARNING — Worker lease is leaked on normal scheduler exit and startup failures

**File:** `dashboard/beacon/worker_main.py:210-235`
**Issue:** The worker acquires its durable lease at line 211, but the `finally` block only shuts down Chromium. It does not release the lease. Any exception after acquisition (for example recovery, initial metrics, scheduler construction, or signal setup) and any scheduler exit not routed through `stop_worker()` leaves `worker_owner` valid until it expires. A replacement process started in that interval refuses to schedule monitoring, unnecessarily extending an outage.

**Fix:** Put lease release in the `finally` block immediately around the post-acquisition lifecycle, guarded by a `lease_acquired` flag and swallowing only `LeaseLost`. Also clear the active-worker globals there so a controlled in-process restart is possible.

```python
lease_acquired = False
try:
    services.acquire_worker_lease(services.settings.db_path, worker_id)
    lease_acquired = True
    # recovery, initial jobs, and scheduler lifecycle
finally:
    services.shutdown_browser()
    if lease_acquired:
        try:
            services.release_worker_lease(services.settings.db_path, worker_id)
        except queues.LeaseLost:
            pass
```

---

_Reviewed: 2026-08-01T09:17:32Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
