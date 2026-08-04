---
phase: 01-behavioral-safety-runtime-ownership
reviewed: 2026-08-04T21:23:47Z
depth: standard
files_reviewed: 8
files_reviewed_list:
  - dashboard/beacon/queues.py
  - dashboard/app.py
  - dashboard/beacon/worker_main.py
  - tests/test_durable_queues.py
  - tests/test_runtime_ownership.py
  - tests/test_api_and_auth.py
  - tests/test_release_contract.py
  - tests/test_ui_safety_integration.py
findings:
  critical: 1
  warning: 0
  info: 0
  total: 1
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-04T21:23:47Z
**Depth:** standard
**Files Reviewed:** 8
**Status:** issues_found

## Summary

Reviewed the Wave 14 worker-epoch implementation, all changed integration tests, and the Plan 01-20 lifecycle contract. Queue claim, renewal, requeue, and terminal preview-result writes now perform their row/revision and durable-owner checks in one SQLite transaction. The focused durable-queue/runtime suite also passes (31 tests, 66 subtests).

However, ownership fencing and admission closure stop at the two explicit queue processors. A worker that has lost its durable lease can still run already-submitted discovery, uptime, recovery, and worker-originated preview-enqueue work and commit shared monitoring data after its successor takes ownership. This leaves the phase's sole-active-worker invariant unachieved.

## Critical Issues

### CR-01: BLOCKER — Lease loss does not fence other mutating scheduler jobs

**File:** `dashboard/beacon/worker_main.py:138-169`, `dashboard/beacon/worker_main.py:205-225`, `dashboard/app.py:182-185`, `dashboard/app.py:1105-1176`, `dashboard/app.py:1191-1195`, `dashboard/app.py:1274-1304`

**Issue:** `heartbeat()` closes `WorkerAdmission` only after losing the owner epoch, but that admission guard is used solely by `process_scans()` and `process_previews()` (lines 142-153). The scheduler invokes uptime probes and cleanup directly, and invokes both scheduled discovery variants without an admission guard (lines 205-225). None of `recover_worker_state`, `run_discovery`, or `do_uptime_check` receives the worker ID/epoch or validates it in the transactions that update `services`, `service_checks`, runtime state, or enqueue preview rows.

`scheduler.shutdown(wait=False)` does not cancel submitted/running jobs. Therefore, Worker A can be in (or begin from an already-submitted job) `scheduled_discovery()` or `do_uptime_check()`, lose its 15-second durable lease, and then commit the writes at `app.py:1105-1176` or `1274-1304` after Worker B acquires the lease. Discovery also creates preview requests at `app.py:1193` without any owner proof. This is the same stale-worker mutation class Wave 14 was intended to eliminate, now affecting service health, checks, events/transitions, scan state, and preview queue state rather than only terminal queue rows.

**Fix:** Carry `worker_id` and `owner_token` into every worker-only mutating operation. Guard all scheduler entries with the same admission/drain mechanism, and assert the epoch in the same `BEGIN IMMEDIATE` transaction as each worker-originated write. Web-originated metadata and scan enqueue paths may remain owner-free; worker-originated enqueue/recovery must use an owner-fenced variant. For example:

```python
def scheduled_discovery(services):
    with services.admission.admit('discovery') as admitted:
        if not admitted:
            return None
        return services.run_discovery(
            source='scheduled',
            worker_id=services.worker_id,
            worker_owner_token=services.owner_token,
        )

# Within every worker-owned BEGIN IMMEDIATE transaction:
queues.assert_current_worker_owner(
    conn, worker_id, worker_owner_token, now,
)
```

Add Worker A/Worker B takeover tests that hold scheduled discovery and uptime work across expiry, then assert that A cannot commit service/check/preview-enqueue changes and that finalization drains those jobs before releasing ownership.

---

_Reviewed: 2026-08-04T21:23:47Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
