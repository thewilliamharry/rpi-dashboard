---
phase: 01-behavioral-safety-runtime-ownership
reviewed: 2026-08-04T16:28:05Z
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
  warning: 0
  info: 0
  total: 1
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-04T16:28:05Z
**Depth:** standard
**Files Reviewed:** 29
**Status:** issues_found

## Summary

Reviewed the Phase 1 application, worker, persistence/recovery, outbound-policy, browser-preview, UI, refreshed TLS fixture, and tests. The previous HTTPS/WSS mutation blocker is closed: Chromium now rejects non-GET/HEAD routes and closes every WebSocket before its handshake; the real-browser HTTPS/WSS test covers the opaque-frame attempt. The refreshed certificate is valid from 2026-08-04 through 2036-08-01 and has the required `alerts.example.test` SAN; strict pinned-SNI delivery passes.

The prior ordinary-exit worker-release warning is also closed. However, durable worker ownership is still not a fencing condition for in-flight jobs, so a worker that has lost ownership can resume and commit after its successor acquires the worker lease.

## Critical Issues

### CR-01: BLOCKER — A stale worker can commit a job after a successor owns the worker lease

**File:** `dashboard/app.py:1467-1516`, `dashboard/app.py:1519-1557`, `dashboard/beacon/queues.py:396-405`, `dashboard/beacon/queues.py:602-623`, `dashboard/beacon/worker_main.py:87-96`
**Issue:** The worker lease is renewed only by `heartbeat()`. When renewal raises `LeaseLost`, it calls `scheduler.shutdown(wait=False)`, which does not cancel already-running scan or preview jobs. Those jobs are fenced solely by their own row leases: a scan uses a unique `lease_owner` token and a preview uses the worker ID. Neither terminal update verifies that `runtime_state.worker_owner` is still the same worker.

Consequently, a paused Worker A can lose its 15-second worker lease, Worker B can acquire it, and Worker A can resume and complete a scan whose 60-second row lease is still valid. The same applies to preview persistence. An isolated reproduction with the submitted queue code produced `completed` for Worker A's scan after Worker B acquired the durable worker lease. This permits stale monitoring data and side effects after ownership transfer, and can also prevent the new worker from processing the still-leased row.

**Fix:** Fence every worker-owned queue operation with the durable worker lease, not just the queue-row lease. Pass a worker ownership epoch/token into the job claim and require the matching current `worker_owner` in `renew_*`, `finish_*`, `fail_*`, and requeue updates. On `LeaseLost`, prevent new jobs and wait for/cancel active jobs before lifecycle finalization. Add an integration test that:

```python
# Worker A has a long row lease but loses the shorter worker lease.
claim = claim_scan(db_path, worker_a_id, lease_seconds=60, now=t0)
acquire_worker_lease(db_path, worker_b_id, now=t0 + 16, lease_seconds=15)

# Must fail: A is no longer the durable worker owner.
with pytest.raises(LeaseLost):
    finish_scan(db_path, claim.request_id, claim.lease_owner, now=t0 + 16)
```

---

_Reviewed: 2026-08-04T16:28:05Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
