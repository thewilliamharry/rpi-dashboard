---
phase: 01-behavioral-safety-runtime-ownership
plan: 06
subsystem: runtime-ownership
tags: [python, sqlite, durable-queue, worker-lease, concurrency]
requires:
  - phase: 01-03
    provides: Side-effect-free web/worker composition roots and compatibility adapters
  - phase: 01-04
    provides: Locked, versioned SQLite migration preparation
provides:
  - Persisted single-worker ownership leases with conditional renewal and stale-owner rejection
  - Durable scan and preview queues with deadlines, row leases, expiry, restart recovery, and latest-preview revisions
  - Atomic metadata-plus-preview persistence that remains available while the worker is absent
affects: [worker-startup, scan-status, service-metadata, previews, monitoring-recovery]
tech-stack:
  added: []
  patterns: [SQLite BEGIN IMMEDIATE claims, conditional lease completion, revision-gated preview writes]
key-files:
  created: [dashboard/beacon/queues.py, tests/test_durable_queues.py]
  modified: [dashboard/beacon/migrations.py, dashboard/beacon/repositories.py, dashboard/beacon/worker_main.py, dashboard/app.py, tests/test_runtime_ownership.py]
key-decisions:
  - "SQLite runtime state is the authoritative worker-owner lease; process-local locks do not establish ownership."
  - "Manual scans expire after 15 minutes and previews after 30 minutes; recovery replays only current, unexpired work."
  - "Metadata persistence and latest preview enqueue share one transaction, and preview completion must match both its lease and current revision."
patterns-established:
  - "Queue mutation pattern: short BEGIN IMMEDIATE transaction, conditional state transition, then terminal status only for the matching claimant."
  - "Preview pattern: new queued revisions supersede older queued work and stale running results cannot write service state."
requirements-completed: [FND-01, FND-04]
coverage:
  - id: D1
    description: Persisted worker ownership prevents concurrent scheduler startup and rejects stale lease renewal.
    requirement: FND-04
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py
        status: pass
    human_judgment: false
  - id: D2
    description: Manual scan work is durable, coalescing, expiring, and atomically claimable.
    requirement: FND-01
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_durable_queues.py tests/test_api_and_auth.py
        status: pass
    human_judgment: false
  - id: D3
    description: Metadata writes atomically enqueue only the latest 30-minute preview revision during worker outages.
    requirement: FND-01
    verification:
      - kind: integration
        ref: dashboard/.venv/bin/python -m pytest -q tests/test_durable_queues.py tests/test_api_and_auth.py
        status: pass
    human_judgment: false
duration: 31min
completed: 2026-07-31
status: complete
---

# Phase 01 Plan 06: Durable Worker Ownership and Queues Summary

**SQLite-backed worker ownership, 15-minute coalescing scan work, and 30-minute revision-safe previews that keep metadata saves durable during worker outages.**

## Performance

- **Duration:** 31 min
- **Completed:** 2026-07-31T21:14:43Z
- **Tasks:** 3/3
- **Files modified:** 9

## Accomplishments

- Added migration 4 for owner leases, queue deadlines, claimant leases, terminal state, and preview revisions while preserving legacy queued work.
- Made worker ownership atomic and durable; only the active owner can renew its heartbeat or construct scheduled work.
- Made manual scans durable/coalescing and preview updates revision-safe, with bounded expiry and restart recovery.
- Kept service metadata writes immediately transactional and available with no worker lease or heartbeat.

## Task Commits

1. **Task 1: Gate scheduler startup on a persisted worker lease** — `e7fc6a8` (TDD RED), `139ac9b` (TDD GREEN)
2. **Task 2: Carry manual scans through a coalescing, expiring durable queue** — `b1b7357` (TDD RED), `ea50842` (TDD GREEN)
3. **Task 3: Couple metadata persistence to latest-revision preview work** — `21f1398` (TDD RED), `0e3c637` (TDD GREEN)
4. **Lease-loss safety correction** — `a6080c9` (fix)

## Files Created/Modified

- `dashboard/beacon/queues.py` — worker-owner, scan, and preview durable state machines.
- `dashboard/beacon/migrations.py` — migration 4 adds queue deadlines, leases, terminals, and revision records.
- `dashboard/beacon/repositories.py` and `dashboard/app.py` — atomic metadata enqueue, durable API status, and compatibility adapters.
- `dashboard/beacon/worker_main.py` — owner gate and owner-ID queue consumers.
- `tests/test_runtime_ownership.py` and `tests/test_durable_queues.py` — lease, contention, expiry, restart, and stale-revision coverage.

## Decisions Made

- SQLite rows, not process-local locks, are the authoritative ownership and queue coordination mechanism.
- Scan and preview results commit only when the worker still owns the specific row lease; preview results additionally require the current service revision.
- Worker absence remains a monitoring condition, not a reason to reject validated metadata writes.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated migration support-floor and concurrent migration expectations for migration 4.**
- **Found during:** Task 1 verification
- **Issue:** Existing migration contracts still described schema version 3 after the planned durable queue migration was added.
- **Fix:** Updated support manifests and migration expectations to the new current version.
- **Files modified:** `dashboard/beacon/support_floor.json`, `tests/fixtures/legacy/support-floor.json`, `tests/test_migrations.py`
- **Verification:** `dashboard/.venv/bin/python -m pytest -q tests/test_migrations.py`
- **Committed in:** `139ac9b`

**2. [Rule 1 - Bug] Routed legacy discovery and uptime preview enqueue paths through the revision queue.**
- **Found during:** Task 3 full-suite verification
- **Issue:** Existing `ON CONFLICT(port)` inserts no longer matched the revision-capable preview table and broke discovery/uptime processing.
- **Fix:** Reused the queue transaction helper for every compatibility preview enqueue path.
- **Files modified:** `dashboard/app.py`
- **Verification:** `dashboard/.venv/bin/python -m pytest -q`
- **Committed in:** `0e3c637`

**3. [Rule 1 - Bug] Halted startup after heartbeat lease renewal fails.**
- **Found during:** Final lease-safety review
- **Issue:** A worker that lost its lease during startup could continue toward scheduler construction.
- **Fix:** Exit worker startup immediately when the conditional lease renewal reports loss.
- **Files modified:** `dashboard/beacon/worker_main.py`
- **Verification:** `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py -x`
- **Committed in:** `a6080c9`

---

**Total deviations:** 3 auto-fixed Rule 1 bugs.
**Impact on plan:** All corrections preserve the intended durable-queue design and compatibility; no additional product scope was introduced.

## Issues Encountered

None beyond the automatically corrected migration, compatibility, and stale-lease paths documented above.

## User Setup Required

None - the durable queues use the existing local SQLite volume and require no new service configuration.

## Next Phase Readiness

- Worker scheduling and persisted work now have a safe cross-process ownership boundary.
- Dashboard metadata remains available during monitoring outages while only current preview work is executed after recovery.

## Self-Check: PASSED

- Verified `dashboard/beacon/queues.py`, durable migration/adapters, and both queue/ownership test modules exist.
- Verified commits `e7fc6a8`, `139ac9b`, `b1b7357`, `ea50842`, `21f1398`, `0e3c637`, and `a6080c9` exist in Git history.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-07-31*
