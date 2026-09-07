---
phase: 06-workload-resilience-pi-acceptance
plan: 08
subsystem: api
tags: [sqlite, flask, sweep-algorithm, n+1, uptime, performance]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-UAT.md's hardware-measured root cause: an O(buckets x checks) nested loop in the /api/services uptime bucket computation, plus a secondary per-service offline-interval N+1 in the same route"
provides:
  - "_legacy_uptime_summary computes identical 7-day uptime and 168-bucket output at cost linear in stored check count, via a forward-advancing sweep instead of a per-bucket rescan"
  - "read_service_offline_intervals_by_port: one bulk read of offline intervals for a whole port list, mirroring read_maintenance_windows_by_port"
  - "api_services issues a query count independent of the number of returned services, pinned by a regression test"
affects: [06-workload-resilience-pi-acceptance, pi-acceptance-uat]

# Actuals (#2632)
actuals:
  tokens: 7752
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Forward-advancing sweep over a sorted, contiguous interval list (a permanent head index plus a per-bucket scan pointer) instead of rescanning every interval for every output bucket"
    - "Shared reconstruction helper (_offline_intervals_from_points) called by both the single-key and bulk-by-key repository readers, so the two can never drift"
    - "SQLite window function (ROW_NUMBER() OVER (PARTITION BY ...)) for a deterministic per-key boundary selection in one bulk query, mirroring the existing read_maintenance_windows_by_port bulk-read shape"
    - "sqlite3.Connection.set_trace_callback as a connection-level statement counter for query-count regression guards, instead of mocking route internals"

key-files:
  created:
    - tests/test_services_route_scaling.py
  modified:
    - dashboard/app.py
    - dashboard/beacon/repositories.py

key-decisions:
  - "The plan's 'boundary tie' concern (two samples sharing a timestamp) is schema-impossible for a single port: service_checks carries PRIMARY KEY (ts, port). The bulk boundary read still resolves each port's boundary deterministically via a per-port ROW_NUMBER() window function, and a dedicated test proves the schema invariant (duplicate insert raises) plus correct selection among closely-spaced pre-window samples."
  - "Bounded the new bulk read with _OFFLINE_INTERVALS_BULK_ROW_LIMIT (20000), mirroring _MAINTENANCE_WINDOWS_BULK_ROW_LIMIT's reasoning and at-limit behavior (silently drops the tail of in-window rows for the highest-numbered port(s) in the request)."

patterns-established:
  - "Pin a pre-optimization algorithm verbatim in the test file as an equivalence oracle, with a comment forbidding it from ever being edited to match the implementation under test."

requirements-completed: [OPS-07, OPS-01]

coverage:
  - id: D1
    description: "_legacy_uptime_summary's bucket accumulation is a linear-cost sweep, byte-for-byte identical in output to the previous nested-loop implementation for every input"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeSummaryDifferentialTests::test_randomized_histories_match_the_reference"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeSummaryScalingTests::test_a_20000_interval_history_computes_well_inside_budget"
        status: pass
      - kind: unit
        ref: "tests/test_release_contract.py::ReleaseContractTests::test_time_weighted_uptime_preserves_boundary_and_fractional_bucket"
        status: pass
      - kind: unit
        ref: "tests/test_release_contract.py::ReleaseContractTests::test_tiny_outage_never_rounds_to_exact_100"
        status: pass
    human_judgment: false
  - id: D2
    description: "Offline intervals are read once per /api/services request across the whole port list, not once per service, and the bulk reader is proven equivalent to the single-port reader"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::OfflineIntervalsBulkReadTests::test_the_bulk_result_matches_the_single_port_result_per_port"
        status: pass
      - kind: unit
        ref: "tests/test_maintenance_windows.py"
        status: pass
    human_judgment: false
  - id: D3
    description: "The route's SQL statement count is independent of the number of services returned, guarded by a regression test proven to discriminate"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::ServiceCountQueryGuardTests::test_query_count_is_independent_of_service_count"
        status: pass
    human_judgment: false
  - id: D4
    description: "OPS-07's declared 500ms /api/services budget on Pi-class hardware under load"
    requirement: OPS-07
    verification: []
    human_judgment: true
    rationale: "This plan removes the identified CPU cost on commodity hardware and pins the algorithmic/scaling properties responsible for it, but confirming the route now meets its 500ms budget under representative concurrent load on the actual Raspberry Pi is a backstop-verification item per the plan's must_haves, requiring a real hardware run rather than local test execution."

duration: ~25min
completed: 2026-09-01
status: complete
---

# Phase 06 Plan 08: Linear-Cost Uptime Buckets and Batched Offline-Interval Reads Summary

**Replaced /api/services's O(buckets x checks) nested bucket rescan with a linear sweep and hoisted its per-service offline-interval read into one bulk query, closing the hardware-measured 2.5s CPU cost with pinned differential, scaling, and query-count regression tests.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-09-01T10:02:23+03:00
- **Tasks:** 3
- **Files modified:** 3 (2 modified, 1 created)

## Accomplishments

- `_legacy_uptime_summary` in `dashboard/app.py` now sweeps its precomputed bucket boundaries once, with a permanent forward-only index into the sorted interval list, instead of rescanning every interval for every one of the 168 hourly buckets. Output (uptime percentage, bucket array, `-1` sentinel, `99.999` clamp, fractional-final-bucket handling) is unchanged.
- `read_service_offline_intervals_by_port` added to `dashboard/beacon/repositories.py`: one window-function query resolving every requested port's boundary sample plus one bulk query for in-window rows, replacing a per-service call inside `api_services`'s result loop. The reconstruction logic is now shared (`_offline_intervals_from_points`) between the single-port and bulk readers so the two cannot drift.
- `tests/test_services_route_scaling.py` (new, 464 lines) pins all three properties: a seeded differential test against a verbatim pre-optimization reference algorithm, a 20,000-interval scaling guard, a bulk-vs-single-port offline-interval equivalence suite, and a connection-level query-count guard proving `/api/services`'s statement count does not grow with service count.
- Manually confirmed the query-count guard discriminates: temporarily reverting the Task 2 hoist moved the statement count from 9 to 23 and failed the test (not committed).

## Task Commits

Each task was committed atomically:

1. **Task 1: Replace the per-bucket interval rescan with a single ordered sweep** - `5df6590` (feat)
2. **Task 2: Read offline intervals once for the whole port list** - `2c6b56e` (feat)
3. **Task 3: Pin that /api/services query count does not grow with service count** - `d2d33a3` (test)

**Plan metadata:** committed separately after this summary is written.

## Files Created/Modified

- `dashboard/app.py` - `_legacy_uptime_summary`'s bucket loop rewritten as a sweep; `api_services` hoists offline-interval reads into a bulk call alongside the existing maintenance-window bulk read
- `dashboard/beacon/repositories.py` - added `_offline_intervals_from_points` (shared helper), `read_service_offline_intervals_by_port`, and `_OFFLINE_INTERVALS_BULK_ROW_LIMIT`; `read_service_offline_intervals` now delegates to the shared helper
- `tests/test_services_route_scaling.py` (new) - pinned reference algorithm, differential/edge-case/scaling tests for the sweep, bulk-vs-single-port equivalence tests for offline intervals, and the query-count regression guard

## Decisions Made

- **Boundary-tie handling reconsidered against the actual schema.** The plan's Task 2 text assumed a same-port boundary timestamp tie was a live ambiguity to resolve and test. `service_checks` carries `PRIMARY KEY (ts, port)`, so two rows for the same port can never share a `ts` — verified directly (`test_the_schema_makes_a_true_same_port_boundary_tie_impossible` asserts the duplicate insert raises). The bulk boundary query still resolves each port's boundary deterministically via `ROW_NUMBER() OVER (PARTITION BY port ORDER BY ts DESC)`, matching the single-port query's semantics exactly, and a dedicated test (`port_near_boundary`) pins correct selection among closely-spaced pre-window samples for one port. This is a factual correction to the plan's stated concern, not a scope change — the equivalence property the plan asked to prove is proven, on grounds specific to this schema.
- **Row limit constant named `_OFFLINE_INTERVALS_BULK_ROW_LIMIT = 20000`**, mirroring `_MAINTENANCE_WINDOWS_BULK_ROW_LIMIT`'s reasoning and documented at-limit behavior (silently drops the tail of in-window rows for the highest-numbered port(s), ordered `port ASC, ts ASC`).

## Deviations from Plan

None requiring Rule 1-4 handling. The boundary-tie note above is a factual correction discovered while implementing Task 2's stated concern, not an unplanned addition, bug fix, or architectural change — it is documented here for traceability since the plan's task text described the concern as live.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `/api/services`'s uptime bucket computation and offline-interval reads are both now linear/bounded in cost, with permanent regression coverage (differential, scaling, equivalence, and query-count guards) in `tests/test_services_route_scaling.py`.
- `_db_lock`'s scope is untouched, confirmed by `git diff 8c2fc48..HEAD -- dashboard/app.py` showing no added or removed line mentioning it — narrowing its scope remains a separate, deliberately deferred decision under `06-10`.
- OPS-07's declared 500ms `/api/services` budget on actual Raspberry Pi hardware under representative concurrent load is a `backstop` verification item (D4 above) that still requires a real hardware acceptance run — this plan removes the identified CPU cost and pins its absence in code, but does not itself constitute that hardware measurement.
- Full test suite (`uv run --project dashboard python -m pytest -q`) passes in full: 810 passed, 561 subtests passed, with no pre-existing test modified.

## Self-Check: PASSED

- FOUND: `tests/test_services_route_scaling.py`
- FOUND: `dashboard/app.py`
- FOUND: `dashboard/beacon/repositories.py`
- FOUND commit: `5df6590`
- FOUND commit: `2c6b56e`
- FOUND commit: `d2d33a3`

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-01*
