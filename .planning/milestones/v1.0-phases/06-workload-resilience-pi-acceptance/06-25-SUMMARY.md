---
phase: 06-workload-resilience-pi-acceptance
plan: 25
subsystem: database
tags: [sqlite, uptime, performance, gap-closure, ops-07]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-PREMISE-C.md's three verified shape mismatches, 06-PROFILE-2.md's 43.727% uptime_sweep attribution, and D-DEBT-06-21's option-C decision"
provides:
  - "beacon_repositories.read_uptime_strips_by_port: one bulk all-ports SQL aggregation replacing the per-service Python uptime sweep in /api/services"
  - "UptimeStripSqlDifferentialTests and UptimeStripBoundednessTests: the agreement and boundedness invariants PROH-OPS-07-16/17/22 require"
  - "A realigned 06-LOCK-AUDIT.md and scope pin naming the new producer, with the lock's contained scope unchanged"
affects: [06-26, 06-27, 06-28]

actuals:
  tokens: 12400
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Bulk all-ports SQL aggregation with a synthetic boundary point merged into a single ordered point stream via UNION ALL + LEAD(), replacing a per-entity Python sweep"
    - "Rounding kept strictly in Python over integer SQL totals to avoid SQLite ROUND()'s half-away-from-zero vs Python's half-to-even divergence"

key-files:
  created: []
  modified:
    - dashboard/beacon/repositories.py
    - dashboard/app.py
    - tests/test_services_route_scaling.py
    - tests/test_lock_profile.py
    - .planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md

key-decisions:
  - "The reader truncates a float `now` via int(now), matching _legacy_uptime_summary's own int(now) truncation, rather than raising ValueError -- pinned by test_float_now_matches_int_now_truncation"
  - "A single admitted CTE floored at retention_seconds feeds both the boundary sub-select and the in-window scan, so the retention floor cannot be applied to one but not the other by omission"
  - "The plan's literal acceptance-criteria example for the divisibility guard (window_seconds=604800, bucket_count=100) does not actually demonstrate non-divisibility -- 604800 % 100 == 0 -- so the ValueError test uses bucket_count=1000 instead (Rule 1 fix to the plan's own test data, not to shipped behavior)"

requirements-completed: []

coverage:
  - id: D1
    description: "/api/services computes every service's uptime pair from one bulk SQL aggregation (read_uptime_strips_by_port) instead of a per-service Python sweep, called once inside the existing _db_lock block"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::ApiServicesOutputEquivalenceTests::test_narrowed_route_reproduces_the_pre_narrowing_response_bytes"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripSqlDifferentialTests::test_randomized_histories_agree_with_the_legacy_sweep_on_the_route_subset"
        status: pass
    human_judgment: false
  - id: D2
    description: "The retention floor (CHECK_RETENTION_SECONDS) is applied to both the boundary lookup and the in-window scan, so a check older than retention establishes no boundary and still renders -1"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripSqlDifferentialTests::test_beyond_retention_sole_row_renders_the_pre_change_sentinel"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripSqlDifferentialTests::test_beyond_retention_plus_mid_window_rows_establishes_no_boundary"
        status: pass
    human_judgment: false
  - id: D3
    description: "The bulk reader is bounded by construction (one query per request, len(ports) * UPTIME_BUCKETS materialized rows), never truncating the strip regardless of stored check volume"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripBoundednessTests::test_one_query_regardless_of_port_count"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripBoundednessTests::test_materialized_row_count_is_independent_of_stored_check_volume"
        status: pass
    human_judgment: false
  - id: D4
    description: "The _db_lock scope pin and 06-LOCK-AUDIT.md are realigned to the new producer without narrowing or loosening the lock's contained scope"
    requirement: OPS-04
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::LockScopePreservationTests::test_api_services_lock_scope_containment_and_termination"
        status: pass
      - kind: unit
        ref: "tests/test_lock_profile.py::LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit"
        status: pass
    human_judgment: false

duration: 30min
completed: 2026-09-05
status: complete
---

# Phase 6 Plan 25: Bulk SQL Uptime Strip Aggregation Summary

**Replaced `/api/services`' per-service Python uptime sweep with one bulk all-ports SQL aggregation (`read_uptime_strips_by_port`), proved the rendered 168-value strip did not move via a 1,824-case randomized+enumerated differential against both existing producers, and realigned the `_db_lock` scope pin and audit for the new producer.**

## Performance

- **Duration:** ~30 min
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- `dashboard/beacon/repositories.py` gained `UPTIME_STRIP_QUERY` and `read_uptime_strips_by_port(conn, *, ports, now, window_seconds, bucket_count, retention_seconds)`: one bulk SQL statement computing every requested port's `(uptime_pct, 168-bucket strip)` pair, floored at `retention_seconds` on both the boundary lookup and the in-window scan, with no `LIMIT` and no `_checked_rows` point budget.
- `dashboard/app.py`'s `api_services` now calls the new reader once inside the existing `with _db_lock, database_access(DB_PATH) as conn:` block, in place of the per-service `_uptime_summary(checks, now)` call; the dead `checks_by_port` accumulation is gone (`points_by_port`, feeding offline-interval reconstruction, is unaffected).
- `tests/test_services_route_scaling.py` gained `UptimeStripSqlDifferentialTests` (400 randomized trials -- 1,824 total per-port histories, 1,384 of which crossed the retention floor -- plus 9 enumerated edge cases) and `UptimeStripBoundednessTests` (query-count and materialized-row-count independence, an over-cap case).
- `tests/test_lock_profile.py`'s scope pin and `06-LOCK-AUDIT.md`'s per-site table are realigned to the new producer and the +4 line shift Task 1 caused from `api_events` onward; the lock's contained scope itself is unchanged.
- The three golden fixtures (`api_services_pre_narrowing_golden.json`, `..._over_cap_golden.json`, `..._empty_golden.json`) byte-match unregenerated throughout.

## Task Commits

1. **Task 1: End-to-end -- one bulk SQL aggregation produces every service's strip, and the golden bytes do not move** - `87fa3ae` (feat)
2. **Task 2: The differential oracle -- the two producers agree, and the guard is mutation-verified** - `d127158` (test)
3. **Task 3: Rewrite the scope pin that fails by design, and realign the lock audit** - `aef7b50` (fix)

## Files Created/Modified

- `dashboard/beacon/repositories.py` - `UPTIME_STRIP_QUERY` constant and `read_uptime_strips_by_port` reader
- `dashboard/app.py` - `api_services` wired to the new reader; `checks_by_port` accumulator removed
- `tests/test_services_route_scaling.py` - `UptimeStripSqlDifferentialTests`, `UptimeStripBoundednessTests`
- `tests/test_lock_profile.py` - scope pin's `required_calls` and class docstring updated
- `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md` - 9 rows realigned (+4 lines each), preamble records the third realignment

## Decisions Made

- **Float-`now` truncation.** `/api/services` always passes `int(time.time())`, but `_legacy_calc_uptime_pct` passes an unrounded float, so the reader defines behaviour for it: `now = int(now)` inside `read_uptime_strips_by_port`, matching `_legacy_uptime_summary`'s own `int(now)` truncation rather than raising. Pinned by `test_float_now_matches_int_now_truncation`.
- **Retention floor applied through one shared CTE.** Both the boundary sub-select and the in-window scan draw from a single `admitted` CTE floored at `retention_floor = now - retention_seconds`, so the floor cannot be applied to the in-window scan while silently missing the boundary lookup (the specific failure mode `PROH-OPS-07-22` names).
- **NULL `online` refuses via a per-port count carried alongside every bucket row**, rather than a second query -- `null_counts` is left-joined onto the final result and checked in Python before any bucket value is trusted, so the reader and `_legacy_uptime_summary` fail on the same input.
- **`(ts, online)` segment ordering kept as a defensive tiebreak** even though `PRIMARY KEY (ts, port)` makes a genuine tie between two real rows unreachable; it resolves the one REACHABLE tie -- a real check landing exactly at `start`, colliding with the synthetic boundary point's position there -- by sorting the boundary point first (`sort_key` 0 vs 1), reproducing `_legacy_uptime_summary`'s own zero-width-interval skip.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug in the plan's own test data] The stated divisibility-guard example does not discriminate**

- **Found during:** Task 1, writing the `window_seconds % bucket_count` acceptance check
- **Issue:** The plan's acceptance criteria specify "assert it with `bucket_count=100` against `window_seconds=604800`" to prove the reader raises `ValueError` for non-divisible values. `604800 % 100 == 0` (`604800 = 6048 * 100`), so that exact pair evenly divides and cannot demonstrate the guard.
- **Fix:** Verified the arithmetic (`604800 % 100 == 0`, confirmed in `/private/tmp/.../scratchpad/more_checks.py`) and used `bucket_count=1000` instead (`604800 % 1000 == 800`), which genuinely raises. The `ValueError` guard itself (`window_seconds % bucket_count != 0`) is implemented exactly as specified; only the manual verification's chosen numbers changed.
- **Files modified:** none (verification-only; no test asserting the literal `100` value was committed)
- **Verification:** `read_uptime_strips_by_port(..., window_seconds=604800, bucket_count=1000, ...)` raises `ValueError`; `604800 % 100 == 0` confirmed directly.
- **Committed in:** n/a (ad hoc verification, not a shipped test)

---

**Total deviations:** 1 auto-fixed (1 bug in plan's own test data)
**Impact on plan:** No shipped behavior or test changed; only which numbers a manual verification step used to demonstrate an already-correctly-implemented guard.

## Mutation Verification (Task 2, required by plan)

Each mutation was applied by hand to a working copy, the relevant test(s) run, the failure observed and recorded below, then reverted before committing. `git diff --stat` confirmed zero residual diff before each commit.

**(a) Dropped the `retention_floor` bound from the reader's boundary sub-select** (widened `admitted`'s `ts >= ?` filter to admit rows without a lower bound). Both beyond-retention tests failed:
- `test_beyond_retention_sole_row_renders_the_pre_change_sentinel`: `(100.0, [1.0, ...]) != (None, [-1, -1, ...])`
- `test_beyond_retention_plus_mid_window_rows_establishes_no_boundary`: `(99.983, [-1,-1,0.0,...]) != (99.961, [-1,-1,...,1.0])` (later diverges further at the buckets-before-first-in-window-check assertion)

This is the mutation that proves `PROH-OPS-07-22`'s guard is real.

**(b) Filtered the joined result to drop zero-observation buckets** (added a `HAVING online_seconds + offline_seconds > 0` clause to `bucket_totals`). Two failures, one expected and one unexpected side effect:
- `test_materialized_row_count_is_independent_of_stored_check_volume`: `6 != 504` -- the row-count guard, not the gap test, is what actually detects this mutation, because the Python side pre-fills every bucket index with `-1` before processing SQL rows, so a *missing* SQL row for an already-`-1` bucket is invisible to any strip-content assertion.
- `test_null_online_makes_both_producers_raise`: `ValueError not raised` -- an unexpected finding worth recording verbatim: a NULL-only port's sole row contributes 0 to both `online_seconds` and `offline_seconds`, so `HAVING` drops every one of its bucket rows, the `null_counts` left join is therefore never read for that port, and the NULL guard is silently defeated as a side effect of a mutation aimed at something else entirely. This demonstrates that `HAVING`-based row-dropping is doubly dangerous: it breaks boundedness AND silently disables an unrelated correctness guard.

**(c) Moved the division and rounding into SQL** (added `ROUND(1.0 * online_seconds / (online_seconds + offline_seconds), 3) AS bucket_fraction` to the query and consumed it directly in Python instead of `round(online_seconds / observed, 3)`). The 400-trial randomized differential caught it at trial 33, port 40331: bucket value `0.063` (SQLite `ROUND()`, half-away-from-zero) versus the correct `0.062` (Python `round()`, half-to-even) for a ratio near `1/16 = 0.0625`. Confirmed independently: `round(1/16, 3) == 0.062` in Python, `SELECT ROUND(1.0*1/16, 3)` returns `0.063` in SQLite.

**(d) Applied `LIMIT 20` to the reader's final `SELECT`.** The over-cap test failed directly: `None != 68.0` for `uptime_pct`. Six further tests failed as side effects (differential, row-count, several enumerated cases) since the truncated row set silently produced incomplete or wrong strips for every port after the 20-row cutoff.

**(e) Changed `_route_input_rows` to return the full inserted set** (removed its `ts >= now - CHECK_RETENTION_SECONDS` filter), with mutation (a) still applied. Concrete demonstration that a superset-fed oracle proves nothing: in `test_beyond_retention_plus_mid_window_rows_establishes_no_boundary`, the oracle-equality assertion (`self.assertEqual(actual[port], expected)`) **passed** -- both the mutated reader and the now-superset-fed oracle agreed at `(99.983, [1.0, 1.0, ...])`, because both were "wrong" identically (both saw the out-of-retention row as establishing a boundary). The test as a whole still failed, but only because of its *separate*, literal, non-oracle-derived assertion (`buckets[:first_in_window_bucket] == [-1] * first_in_window_bucket`) three lines later. `test_beyond_retention_sole_row_renders_the_pre_change_sentinel` never calls the oracle at all and continued to fail correctly regardless. This is exactly `PROH-OPS-07-22`'s warning realized concretely: an oracle-only equality check would have gone green under mutations (a)+(e) combined, and only the literal structural assertions caught the regression.

## Scope Pin Mutation Verification (Task 3, required by plan)

Reverting `required_calls` in `test_api_services_lock_scope_containment_and_termination` from `beacon_repositories.read_uptime_strips_by_port` back to `_uptime_summary` reproduces the exact failure the pin exists to catch: `AssertionError: {'_uptime_summary'} is not false : _db_lock's SCOPE changed: ['_uptime_summary'] no longer execute inside api_services' _db_lock with-block`. Reverted before commit.

## Vacuity Guard (T-06-97)

`_db_lock_owning_functions` matched **26** functions (28 `_db_lock` sites across those 26 functions -- `process_preview_requests` and `api_service_meta` each own two). Confirms the AST walk in `test_no_database_access_escapes_the_db_lock` matched real sites rather than passing vacuously.

## Retention-Floor Randomized Pressure

Of 400 randomized trials (1-8 ports each, 1,824 total per-port histories), **1,384** contained at least one check older than `CHECK_RETENTION_SECONDS` -- well above the plan's 100-history minimum, and considerably higher than the ~25% base rate because ports frequently also acquire an out-of-retention row incidentally from the generator's wide initial-timestamp range.

## Production Writer Evidence (Task 1 acceptance criteria)

Both production writers of `service_checks.online` bind an integer, never `None`, confirming the reader's NULL-refusal path is schema-permitted but currently unreachable through either writer:

- `dashboard/app.py:1468-1469`: `"INSERT OR REPLACE INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)"` / `(now, port, online, latency, error_class)`, where `online` is set to `1` or `0` by the branch immediately above (`app.py:1454-1466`).
- `dashboard/app.py:1665-1666`: `"INSERT OR REPLACE INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)"` / `(now, port, online_int, latency_ms, error_class)`, where `online_int = 1 if online else 0` (`app.py:1597`).

## Issues Encountered

- An early draft of `test_a_24_hour_observation_gap` asserted a mid-window `-1` gap, which this algorithm cannot produce (once a boundary or first in-window check establishes state, coverage is contiguous through to `now` -- there is no mid-stream "unknown" concept, only an unobserved prefix before the first established state). Caught by running the test against both oracles before committing; rewritten to assert a start-of-window gap instead, which both oracles agree matches the SQL reader.
- `sqlite3.Cursor.fetchall` cannot be monkeypatched per-instance (C-extension read-only attribute) for the materialized-row-count test; worked around with a thin `_CountingCursor` proxy wrapping the real cursor.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The correctness proof is complete: one bulk SQL producer, proven equivalent to both existing Python producers on the route's exact retention-floored input, with the rendered strip provably unmoved.
- The cost verdict is deliberately NOT claimed here. `06-26` re-profiles `/api/services` on this host with the new producer; `06-27` profiles on Pi hardware and runs the concurrency-3 acceptance gate. `06-PROFILE-2.md`'s 43.727% `uptime_sweep` attribution is a floor on the improvement, not a guarantee -- the true post-change latency is bounded below by `382.2ms` and above only by "no improvement at all," per this plan's objective.
- `.planning/REQUIREMENTS.md` is unedited: OPS-07 stays Pending pending an independent verification round (`PROH-OPS-07-08`).
- `06-28` inherits: the `(function, ordinal)` vs `(function, line)` audit-pinning decision this plan deferred, and `T-06-24`'s register re-closure once `06-26`/`06-27` land.

## Self-Check: PASSED

All modified files confirmed present on disk; all four commit hashes (`87fa3ae`, `d127158`, `aef7b50`, `c01be24`) confirmed in `git log`.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-05*
