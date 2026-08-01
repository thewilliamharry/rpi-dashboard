---
phase: 01-behavioral-safety-runtime-ownership
reviewed: 2026-08-01T07:22:28Z
depth: standard
files_reviewed: 29
files_reviewed_list:
  - README.md
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
  critical: 2
  warning: 2
  info: 0
  total: 4
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-01T07:22:28Z
**Depth:** standard
**Files Reviewed:** 29
**Status:** issues_found

## Summary

The gap closures do address the previously reported mechanics: normal Beacon connections use the maintenance lease, scan work renews its lease, the worker package no longer imports the legacy app edge, malformed scalar metadata is rejected, and the requests transport pins a selected numeric address. However, recovery remains capable of destructive rollback outside a recovery state, and the Chromium proxy allows preview content to issue state-changing requests to every policy-approved LAN service. The existing tests do not exercise either boundary.

## Critical Issues

### CR-01: Recovery command can silently roll a healthy database back to an old snapshot

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/recovery.py:266`

**Issue:** `restore_backup()` accepts any catalog entry and overwrites `dashboard.db` even when `recovery-required.json` is absent. The CLI exposes this through both `restore --latest` and `restore --id` (lines 347-363). Thus an accidental or automated invocation against a healthy deployment replaces current services, metadata, monitoring history, and queues with an older pre-migration backup. The function writes and later removes a marker (lines 305 and 322), but never requires a pre-existing failure marker before the destructive operation.

**Fix:** Require and validate the existing recovery marker before selecting/copying a backup; ensure its catalog ID matches the requested backup (or make `--latest` resolve only the marker's catalog ID). Return a safe refusal when recovery is not required, and add a test that a healthy database is byte-for-byte unchanged when restore is invoked without the marker.

### CR-02: Preview pages can use the browser proxy to mutate other allowed services

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/outbound.py:294`

**Issue:** The proxy accepts the browser-supplied HTTP method, then forwards it and the request body unchanged to any `BROWSER_PREVIEW` target (lines 294-299). `route_browser_request()` only validates URL policy and then continues every method (lines 71-79 in `previews.py`). A compromised or hostile page being screenshotted can therefore use a form, fetch, or navigation to send `POST`, `PUT`, `PATCH`, or `DELETE` requests to other configured/LAN-approved services. The product requirement limits outbound fetching and mutation boundaries; a screenshot needs safe retrieval, not the authority to cause state changes on monitored services.

**Fix:** Reject non-safe browser requests before they reach the proxy, e.g. permit only `GET` and `HEAD` in `route_browser_request` and return a 405 from the plain-HTTP proxy for other methods. For HTTPS CONNECT tunnels, enforce the same method policy in the Playwright route callback before allowing the tunnel. Add browser tests proving an HTML form/fetch POST to a second allowed origin never reaches that origin.

## Warnings

### WR-01: Proxy connection slots leak when forwarding fails before relay setup

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/outbound.py:294`

**Issue:** `_connect()` acquires one of four semaphore slots and returns an open origin socket (lines 400-411). In both the CONNECT branch and ordinary HTTP branch, an exception from `client.sendall()`, `_format_headers()`, or `origin.sendall()` is caught by `handle()` (line 300) before `_relay()` is entered. Only `_relay()` closes the origin and releases the slot (lines 439-445). Four client disconnects or refused writes at that point permanently exhaust the per-preview proxy until the process restarts, preventing all later previews.

**Fix:** Make `_connect()` a context-managed resource or close/release `origin` in `handle()` whenever ownership has not moved to `_relay()`. Add failure-injection tests for each send path asserting `active_relays == 0` and that all four slots remain reusable.

### WR-02: Metadata booleans are coerced instead of validated

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:1864`

**Issue:** The endpoint validates string fields but never validates `critical`; it stores `int(bool(payload.get('critical')))`. Consequently JSON such as `{"critical": "false"}`, `{"critical": []}`, or `{"critical": 2}` is accepted and coerced, with the non-empty string and non-zero number incorrectly making a service critical. `pinned_order` similarly accepts JSON booleans because `int(True)` is valid (line 1867). This leaves the mutation contract ambiguous and can alter alert behaviour contrary to the caller's request.

**Fix:** Require `type(payload['critical']) is bool` when present, and reject booleans explicitly before parsing `pinned_order` (then apply an appropriate integer range). Extend `test_service_metadata_rejects_scalar_json_and_invalid_string_fields` with invalid `critical` and `pinned_order` values.

---

_Reviewed: 2026-08-01T07:22:28Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
