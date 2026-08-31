---
phase: 06-workload-resilience-pi-acceptance
plan: 02
subsystem: database
tags: [sqlite, thumbnails, ttl, storage-budget, apscheduler, ops-03]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-01: bounded thumbnails table (migration 10), ThumbnailStoreRepository as the sole write path, read_thumbnail() projection, tests/test_workload_resilience.py seeded with the relocation tracer"
provides:
  - "THUMBNAIL_TTL_DAYS / THUMBNAIL_STORE_MAX_BYTES settings (D-02 defaults: 7 days, 64 MiB) with fail-closed fallback on bad env values"
  - "delete_expired_thumbnails, evict_thumbnails_over_budget, thumbnail_store_bytes repository functions"
  - "J8's hourly cleanup transaction now reaps expired thumbnails and enforces the byte budget, and declares 'thumbnails' as a database surface it writes"
affects: [06-03-bounded-preview-retry, 06-04-cadence-under-contention, 06-05-wal-and-concurrency, 06-06-harness-self-test]

actuals:
  tokens: 5000
  tasks: 1
  commits: 1

tech-stack:
  added: []
  patterns:
    - "Bounded eviction walk: a module constant caps rows scanned per call (THUMBNAIL_EVICTION_SCAN_LIMIT=512, clamped 1-4096), deletes oldest-key-first via one parameterized IN(...), and is designed to converge across repeated hourly calls rather than complete in one unbounded pass"
    - "Settings-derived TTL/budget bounds follow the existing telemetry_* precedent: _positive_int(source, ENV_KEY, default) falls back to the documented default on non-positive or unparseable values, never to 'no limit'"

key-files:
  created: []
  modified:
    - dashboard/beacon/config.py
    - dashboard/beacon/repositories.py
    - dashboard/app.py
    - dashboard/beacon/worker_main.py
    - tests/worker_ownership_contract.py
    - tests/test_workload_resilience.py
    - docker-compose.yml

key-decisions:
  - "D-02 values recorded in code comments, not only in the plan: THUMBNAIL_TTL_DAYS=7 survives six missed daily refresh cycles (THUMB_REFRESH_DAYS=1) and never outlives a service's own 7-day visibility window (EXPIRE_DAYS); THUMBNAIL_STORE_MAX_BYTES=64 MiB matches the existing telemetry_backlog_reserve_bytes reserve and stays an order of magnitude below the 512 MiB telemetry_db_max_bytes ceiling it shares a disk with."
  - "THUMBNAIL_EVICTION_SCAN_LIMIT=512 chosen as a ceiling between the store's natural key population (~85 discovered ports today) and the theoretical worst case (65535 ports) -- the same bounded/clamped `limit` idiom as read_background_job_health's max(1, min(int(limit), 128))."
  - "evict_thumbnails_over_budget deliberately does not guarantee reaching the budget in one call when the store is pathologically oversized; it deletes what its bounded scan selected and returns, relying on J8's hourly cadence for convergence across passes rather than an unbounded single-pass scan."

patterns-established:
  - "A single parameterized `DELETE ... WHERE port IN (?,?,...)` built from placeholder lists (never string-interpolated row values) is the pattern for batch-deleting a bounded eviction selection."

requirements-completed: [OPS-03]

coverage:
  - id: D1
    description: "THUMBNAIL_TTL_DAYS and THUMBNAIL_STORE_MAX_BYTES are readable from the environment with documented defaults of 7 days and 67108864 bytes, and fall back to those defaults on a non-positive or unparseable value"
    requirement: "OPS-03"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#ThumbnailBudgetTests.test_thumbnail_store_stays_within_ttl_and_byte_budget"
        status: pass
    human_judgment: false
  - id: D2
    description: "delete_expired_thumbnails removes exactly the rows whose expires_ts has passed; rows with NULL or future expires_ts survive"
    requirement: "OPS-03"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#ThumbnailBudgetTests.test_thumbnail_store_stays_within_ttl_and_byte_budget"
        status: pass
    human_judgment: false
  - id: D3
    description: "evict_thumbnails_over_budget is a no-op when the store is at or below the budget, deletes oldest-captured_ts-first when over budget, and its bounded scan_limit converges across repeated calls rather than scanning unbounded in one pass"
    requirement: "OPS-03"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#ThumbnailBudgetTests.test_thumbnail_store_stays_within_ttl_and_byte_budget"
        status: pass
    human_judgment: false
  - id: D4
    description: "A J8 cleanup pass deletes expired rows and enforces the byte budget inside its existing transaction, evicting an over-budget-but-unexpired row even when nothing has expired (the two bounds interact independently), and GET /api/services reports has_thumb falsy for the evicted port on the very next read"
    requirement: "OPS-03"
    verification:
      - kind: integration
        ref: "tests/test_workload_resilience.py#ThumbnailBudgetTests.test_thumbnail_store_stays_within_ttl_and_byte_budget"
        status: pass
    human_judgment: false
  - id: D5
    description: "J8 declares 'thumbnails' as a database surface it writes in both the worker callback inventory and the ownership contract test"
    requirement: "OPS-03"
    verification:
      - kind: unit
        ref: "tests/test_worker_ownership_matrix.py"
        status: pass
    human_judgment: false

duration: 35min
completed: 2026-09-01
status: complete
---

# Phase 6 Plan 2: Bound the Thumbnail Store — TTL, Byte Budget, and the Hourly Reap Summary

**The relocated thumbnail store (06-01) now has a configurable 7-day TTL and a configurable 64 MiB total-byte budget, both enforced hourly by J8's existing cleanup transaction, with malformed environment values falling back to the documented default rather than disabling the bound.**

## Performance

- **Duration:** ~35 min active work
- **Started:** 2026-08-31T21:55:00Z (approx, first read of plan)
- **Completed:** 2026-09-01T22:05:00Z
- **Tasks:** 1
- **Files modified:** 7

## Accomplishments
- `Settings.thumbnail_ttl_days` (default 7) and `Settings.thumbnail_store_max_bytes` (default 67,108,864) load from `THUMBNAIL_TTL_DAYS` / `THUMBNAIL_STORE_MAX_BYTES` via the existing `_positive_int` helper, which already guarantees a non-positive or unparseable value falls back to the documented default (PROH-OPS-03-04)
- `dashboard/beacon/repositories.py` gains `thumbnail_store_bytes`, `delete_expired_thumbnails`, and `evict_thumbnails_over_budget` (module constant `THUMBNAIL_EVICTION_SCAN_LIMIT = 512`), all using `?`-parameterized SQL with no string-interpolated values
- `evict_thumbnails_over_budget` is a no-op when the store is already within budget, otherwise walks a bounded `ORDER BY captured_ts ASC, port ASC LIMIT ?` selection and deletes it via one parameterized `IN (...)` — bounded per call, convergent across J8's hourly cadence
- `dashboard/app.py`'s `THUMBNAIL_TTL_SECONDS` now derives from `SETTINGS.thumbnail_ttl_days` instead of 06-01's hardcoded `7 * 86400`; `worker_cleanup_history` (J8) calls `delete_expired_thumbnails` then `evict_thumbnails_over_budget` inside its existing `_worker_write_transaction`, with no second transaction or connection
- `dashboard/beacon/worker_main.py` and `tests/worker_ownership_contract.py` both declare `'thumbnails'` in J8's `database_surfaces` tuple
- `docker-compose.yml`'s shared `beacon-environment` anchor gains `THUMBNAIL_TTL_DAYS: "7"` and `THUMBNAIL_STORE_MAX_BYTES: "67108864"`, added inside the anchor above `services:` so the load-bearing service-ordering tests are unaffected
- `tests/test_workload_resilience.py` gains `ThumbnailBudgetTests.test_thumbnail_store_stays_within_ttl_and_byte_budget`, covering TTL expiry, byte summation, no-op-under-budget, oldest-first eviction, bounded `scan_limit` convergence across repeated calls, config fallback, and a full J8 pass proving the two bounds interact independently (an unexpired-but-over-budget row is still evicted) and that `has_thumb` flips false the moment the row is gone

## Task Commits

Each task was committed atomically:

1. **Task 1: Bound the store — configurable TTL, byte budget, and the hourly reap** - `657f1a8` (feat)

**Plan metadata:** commit follows this summary

## Files Created/Modified
- `dashboard/beacon/config.py` - `thumbnail_ttl_days`, `thumbnail_store_max_bytes` fields and their `_positive_int`-backed loading, with D-02 rationale recorded as comments
- `dashboard/beacon/repositories.py` - `THUMBNAIL_EVICTION_SCAN_LIMIT`, `thumbnail_store_bytes`, `delete_expired_thumbnails`, `evict_thumbnails_over_budget`
- `dashboard/app.py` - `THUMBNAIL_TTL_SECONDS` now Settings-derived, new `THUMBNAIL_STORE_MAX_BYTES` constant, `worker_cleanup_history` calls both new sweeps
- `dashboard/beacon/worker_main.py` - J8's `database_surfaces` tuple gains `'thumbnails'`
- `tests/worker_ownership_contract.py` - J8's `_row` database_surfaces gains `'thumbnails'` to match
- `docker-compose.yml` - `THUMBNAIL_TTL_DAYS` / `THUMBNAIL_STORE_MAX_BYTES` added to the shared `beacon-environment` anchor
- `tests/test_workload_resilience.py` - `ThumbnailBudgetTests` with the comprehensive TTL/byte-budget test

## Decisions Made
- **D-02 rationale committed to code comments** (see `key-decisions` in frontmatter): the 7-day TTL and 64 MiB budget are derived from concrete existing constants (`THUMB_REFRESH_DAYS`, `EXPIRE_DAYS`, `telemetry_backlog_reserve_bytes`, `telemetry_db_max_bytes`) rather than picked arbitrarily, and that derivation is now visible to a future reader in `config.py`, not only in the plan.
- **Bounded, convergent eviction over guaranteed single-pass completion**: `evict_thumbnails_over_budget` explicitly may not reach the budget in one call against a pathologically oversized store. This is documented in the function's docstring as intentional — the alternative (an unbounded scan) is the exact failure mode OPS-03 exists to prevent, and J8's hourly cadence provides convergence.

## Deviations from Plan

None - plan executed exactly as written. The plan's own framing that the schema/support-floor half of migration 10 landed entirely in 06-01 was honored: no new migration was added in this plan.

## Issues Encountered

None. The full suite was measured green both before (780 passed, from 06-01) and after this plan's change (781 passed — the +1 is the new test method added here; 552 subtests passed matches the prior baseline exactly, confirming no existing subtest count regressed). The flaky `test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced` timing sensitivity noted in 06-01's summary was not observed during this plan's runs.

## User Setup Required

None - no external service configuration required. Operators who want a non-default TTL or byte budget can set `THUMBNAIL_TTL_DAYS` / `THUMBNAIL_STORE_MAX_BYTES` in their environment or `docker-compose.yml` overrides; the shipped defaults (7 days, 64 MiB) require no action.

## Next Phase Readiness
- OPS-03 is now fully bounded end-to-end: relocated storage (06-01) plus enforced TTL and byte budget (06-02), both reaped by J8's existing hourly transaction.
- `tests/test_workload_resilience.py` now carries both the 06-01 relocation tracer and this plan's `ThumbnailBudgetTests`, ready for 06-03 (bounded preview retry), 06-04 (cadence under contention), 06-05 (WAL/concurrency/restart), and 06-06 (harness self-test) to each append their own tests per the module's docstring.
- `preview_requests.next_attempt_ts` (added in migration 10, still unused) remains ready for 06-03 to wire into bounded preview retry.
- No blockers.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-01*

## Self-Check: PASSED

All modified files confirmed present on disk (`dashboard/beacon/config.py`, `dashboard/beacon/repositories.py`,
`dashboard/app.py`, `dashboard/beacon/worker_main.py`, `tests/worker_ownership_contract.py`,
`tests/test_workload_resilience.py`, `docker-compose.yml`). Commit `657f1a8` confirmed present in
`git log --oneline --all`.
