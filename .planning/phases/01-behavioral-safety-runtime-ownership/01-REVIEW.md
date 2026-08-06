---
phase: 01-behavioral-safety-runtime-ownership
reviewed: 2026-08-06T20:25:14Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - dashboard/app.py
  - dashboard/beacon/outbound.py
  - dashboard/beacon/queues.py
  - dashboard/beacon/worker_authority.py
  - dashboard/beacon/worker_main.py
  - dashboard/worker.py
  - tests/test_durable_queues.py
  - tests/test_runtime_ownership.py
  - tests/test_worker_ownership_matrix.py
  - tests/worker_ownership_contract.py
findings:
  critical: 2
  warning: 1
  info: 0
  total: 3
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-06T20:25:14Z
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

The callback inventory, queue-row fencing, preview publication transaction, and strict webhook request path are explicit. However, the primary Phase 01 closure invariant is still violated: most worker adapters validate the epoch only once, then invoke legacy helpers which commit later without an authority assertion. A takeover in that interval permits stale writes.

The focused ownership, runtime, and durable-queue suite passes (`44` tests, `131` subtests), but its matrix tests an already-invalid authority rather than the required valid-A-to-B takeover interval. A direct reproduction confirmed that `worker_collect_system_stats()` writes `system_stats` after its authority check is completed and Worker B has acquired the durable lease.

## Critical Issues

### CR-01: BLOCKER — Legacy worker callbacks still commit after a successor takes ownership

**File:** `dashboard/app.py:1600-1637`

**Issue:** `worker_collect_system_stats`, `worker_cleanup_history`, `worker_run_discovery`, and `worker_do_uptime_check` call `_assert_worker_callback_authority()` only at entry, then delegate to legacy operations. Those operations open their own connections and commit without `WorkerAuthority`: metrics at `dashboard/app.py:1041-1062`, cleanup at `dashboard/app.py:1068-1075`, discovery (including scan-state/event/service/check/preview writes) at `dashboard/app.py:1083-1251`, and uptime writes at `dashboard/app.py:1329-1359` and `1380`.

Once the entry transaction commits, Worker A can be paused for longer than its lease, Worker B can acquire the epoch, and A will still commit those later transactions. J5 inherits the same flaw through `worker_process_scan_requests()` calling `worker_run_discovery()` (`dashboard/app.py:1646-1691`). The ContextVar at `dashboard/app.py:1621-1625` only routes transition webhooks; it does not fence the legacy SQLite writes.

**Fix:** Replace the delegation with authority-taking worker implementations (or inject authority-aware persistence callbacks) so every individual mutation starts `BEGIN IMMEDIATE`, calls `assert_current_worker_authority(conn, authority)` on that same connection, writes, and commits. Preserve the legacy helpers only for explicitly owner-free web operations. Add A-current → pause-before-each-commit → B-acquires tests for metrics, cleanup, uptime, discovery, and scan-nested discovery.

### CR-02: BLOCKER — Lease loss returned as `False` does not revoke the stale scheduler

**File:** `dashboard/app.py:241-280`, `dashboard/app.py:1600-1637`, `dashboard/beacon/worker_main.py:203-247`, `dashboard/beacon/worker_main.py:371-385`

**Issue:** The authority-taking adapters catch `LeaseLost` and return `False`, while `dispatch_callback()` revokes admission and calls `stop_worker()` only for a raised `LeaseLost`. `_invoke_callback()` returns these falsey results unchanged for all non-heartbeat jobs; heartbeat additionally discards the result of `update_worker_heartbeat()` and always returns `True` (`dashboard/beacon/worker_main.py:209-213`). Consequently, a callback that loses authority at a later guarded boundary does not close admission or stop the scheduler. Startup also ignores the S1 and S3 results (`dashboard/beacon/worker_main.py:373-377`); after an S3 loss it builds and starts a scheduler whose callbacks are no longer authorized.

This leaves a stale process executing scheduled work and retaining browser/process resources after durable ownership has moved, contrary to the lifecycle and drain contract.

**Fix:** Let `LeaseLost` propagate from worker adapters to `dispatch_callback()` (preferred), or return a distinct loss result that dispatch treats as lease loss. Propagate the heartbeat write result instead of unconditionally returning `True`, and abort startup when any post-acquisition startup callback signals or raises lease loss:

```python
if not dispatch_callback(services, 'S1'):
    return
if not dispatch_callback(services, 'S2'):
    return
if not dispatch_callback(services, 'S3'):
    return
```

Add coverage for loss during each startup callback and after renewal-but-before-heartbeat persistence, asserting admission closes and no scheduler is started.

## Warnings

### WR-01: Takeover matrix misses the check-to-write race it claims to close

**File:** `tests/test_worker_ownership_matrix.py:202-214`, `tests/test_worker_ownership_matrix.py:295-314`

**Issue:** `_run_after_takeover()` acquires Worker B before invoking the stale callback. Each stale case then constructs an artificial authority using the literal token `'stale'`. This can only prove rejection at the adapter's first authority check; it cannot expose a real Worker A that was current at callback admission and becomes stale before a later transaction. That is why CR-01 passes the green matrix. J6 has one paused browser test, but no equivalent pause before metrics, cleanup, discovery, uptime, or scan-nested commits.

**Fix:** For each callback/subtransaction, acquire a real A lease, enter and pause the actual production callback after its initial assertion, advance the injected clock and acquire B, then release A and compare every declared surface. Keep the existing B-success control, but assert both no late-A delta and that dispatch closes admission on the resulting `LeaseLost`.

---

_Reviewed: 2026-08-06T20:25:14Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
