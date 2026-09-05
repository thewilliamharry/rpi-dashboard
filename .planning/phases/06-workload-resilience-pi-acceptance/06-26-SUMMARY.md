---
phase: 06-workload-resilience-pi-acceptance
plan: 26
subsystem: testing
tags: [cprofile, sqlite, performance, gap-closure, ops-07]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-25's bulk SQL uptime-strip reader (read_uptime_strips_by_port) and its correctness proof; 06-PROFILE-2.md's 43.727% uptime_sweep attribution and 58.533ms wall_ms_unprofiled baseline"
provides:
  - "06-PROFILE-3.md: a same-host, same-seed, same-shape before/after wall_ms_unprofiled measurement of 06-25, with a REFUTED verdict and its arithmetic"
  - "tests/services_route_profile.py's uptime_strip_sql profiler bucket, keyed on read_uptime_strips_by_port, documented as measuring only the Python wrapper"
  - "UptimeStripCostModelTests: the relational, mutation-verified guard pinning the true cost-model claim -- Python-side materialized row count and statement count are independent of stored check volume, not that SQLite stopped scanning rows"
  - "A root-cause observation (recorded in 06-PROFILE-3.md, not fixed here): UPTIME_STRIP_QUERY's bucket_totals CTE joins on a range predicate SQLite cannot index-seek, so its cost scales with buckets x ports x segments_per_port"
affects: [06-27, 06-28]

actuals:
  tokens: 5348
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Detached git worktree (not stash, not history rewrite) used to measure a prior commit's code without disturbing this worktree's own branch state"
    - "Relational, same-run cost-model guard (two measurements taken inside one test method, compared to each other) rather than an absolute-band prediction calibrated to today's dataset size (D-DEBT-06-14's lesson)"

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-3.md
  modified:
    - tests/services_route_profile.py
    - tests/test_services_route_scaling.py

key-decisions:
  - "The before/after measurement was taken via a detached `git worktree add` checkout of the pre-06-25 parent commit, never `git stash` or a rewrite of this worktree's own HEAD -- the destructive-git prohibitions this executor operates under exclude stash entirely, and a worktree is the sanctioned way to inspect another commit's code without touching the current branch."
  - "The mutation-verification target for Task 2 was the query's final SELECT (reading straight from `admitted` instead of the aggregated `bucket_totals`), not `bucket_totals`'s own SUM/CASE removal -- the first attempt (removing only the aggregation inside bucket_totals) produced a TypeError on NULL online/offline_seconds for buckets with no overlapping segment, which is a real failure but not the row-count assertion failure the plan specified; the final-SELECT mutation cleanly demonstrates the literal 'one row per stored check' failure mode with the real ratio in the message."

requirements-completed: []

coverage:
  - id: D1
    description: "06-PROFILE-3.md states, at the identical 8-service/8-day/seed-20260902 shape and host as 06-PROFILE-2.md, the before (79e051e) and after (9da5e5e) wall_ms_unprofiled means with spread, the delta, and a REFUTED verdict with its arithmetic shown"
    verification:
      - kind: other
        ref: "grep -n 'Verdict: \\*\\*REFUTED\\*\\*' .planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-3.md"
        status: pass
    human_judgment: true
    rationale: "The report is a prose artifact whose honesty (no share-table-only claim, no Pi-latency claim, arithmetic shown before the verdict) requires human review beyond keyword presence."
  - id: D2
    description: "A uptime_strip_sql profiler bucket is registered keyed on read_uptime_strips_by_port, documented as capturing only the Python wrapper; HONESTY_CAVEAT and PI_CONTROL_PASS_P50_MS remain unedited; ServicesRouteProfilerGuardTests still passes"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::ServicesRouteProfilerGuardTests"
        status: pass
    human_judgment: false
  - id: D3
    description: "UptimeStripCostModelTests pins the relational, mutation-verified claim that read_uptime_strips_by_port's Python-side row count and statement count are independent of stored check volume"
    requirement: OPS-04
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripCostModelTests::test_python_side_row_and_statement_counts_are_independent_of_stored_check_volume"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-09-05
status: complete
---

# Phase 6 Plan 26: Local Before/After Guard on 06-25 -- REFUTED Summary

**Re-profiled `/api/services` before/after `06-25` on this host at a fixed shape and seed: `06-25`'s bulk SQL uptime aggregation measured 236.265ms mean vs 56.820ms mean before it -- a 315.8% regression, not an improvement -- recorded as REFUTED in `06-PROFILE-3.md`, with `06-27` stopped rather than run against this build.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 2
- **Files modified:** 3 (1 created)

## Accomplishments

- **The verdict: REFUTED.** `wall_ms_unprofiled` measured 56.820ms mean (three repetitions, spread 0.230ms) at the pre-`06-25` parent commit (`79e051e`) and 236.265ms mean (three repetitions, spread 2.902ms) at `06-25`'s HEAD (`9da5e5e`) -- identical host, seed `20260902`, 8 services, 8 days. Delta: **+179.446ms absolute, +315.8%**, roughly 780x the before-run's own spread and roughly 4x the Pi's own 44ms run-to-run variance floor. `06-25`'s bulk SQL aggregation did not make the route cheaper on this host -- it made it more than four times slower.
- **Root cause identified, not fixed (out of this plan's scope):** `UPTIME_STRIP_QUERY`'s `bucket_totals` CTE joins `requested_ports CROSS JOIN buckets` (1,344 rows at this shape) to `ordered_points` on a range predicate (`sg.effective_ts < bucket_start + bucket_seconds AND sg.end_ts > bucket_start`) that SQLite cannot resolve with an index seek, so the join's cost scales with `buckets x ports x segments_per_port` rather than the old sweep's effective `services x buckets` bound. `sql_execute`'s tottime grew from 3.386ms to 1018.995ms (mean) across the same 5 profiled repeats -- more than four times what the `uptime_sweep` bucket it replaced cost.
- **`uptime_sweep`'s collapse is attributed, not celebrated** (`PROH-OPS-07-19`): the bucket is entirely absent from the after run (zero calls), and `06-PROFILE-3.md` states explicitly that its cost moved into `sql_execute`, which grew far more than `uptime_sweep` shrank.
- **`row_grouping`'s predicted partial fall confirmed:** calls fell 226,848 -> 100,409 (-55.7%), tottime fell 89.711ms -> 50.433ms (-43.8%) -- a real, substantial, but partial fall, exactly as predicted from `checks_by_port` being removed while `points_by_port` remains.
- **The true cost-model claim pinned relationally:** `UptimeStripCostModelTests` proves `read_uptime_strips_by_port` always materializes `len(ports) * UPTIME_BUCKETS` Python-side rows and issues exactly one SQL statement, measured at both a 2-day and an 8-day check history over the same three ports inside one test run, regardless of the 4.000x measured growth in stored `service_checks` rows. The docstring states plainly that SQLite still scans the admitted rows -- this guard is about the Python-side count only.
- **Attribution instrument unaffected:** `attributed_pct` stayed at 98.639% mean (after run), comfortably above the profiler's 90.0% contract; `HONESTY_CAVEAT` and `PI_CONTROL_PASS_P50_MS` remain byte-identical (`git diff` confirms no edit).

## Task Commits

1. **Task 1: Re-profile at a fixed shape, and write the before/after that can say REFUTED** - `f94daf2` (docs)
2. **Task 2: Pin the cost-model claim that is actually true** - `4a0bd74` (test)

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-3.md` - the before/after report: provenance, headline delta, REFUTED verdict with arithmetic, where `uptime_sweep`'s cost went, `row_grouping`'s measured partial fall, honesty block, stop condition
- `tests/services_route_profile.py` - `uptime_strip_sql` bucket added to `PROFILE_PHASES`, adjacent to `uptime_sweep`, with a comment documenting that it captures only the Python wrapper and the SQL cost lands in `sql_execute`
- `tests/test_services_route_scaling.py` - `UptimeStripCostModelTests` added

## Decisions Made

- **Measurement method:** a detached `git worktree add --detach <path> 79e051e` checkout for the before build, cleaned up with `git worktree remove --force` after both measurement sessions completed, rather than `git stash` (prohibited in this executor's worktree-isolation rules) or rewriting this worktree's own HEAD. This worktree's branch (`worktree-agent-a23d7a0b1aee87c77`) and base commit were never touched by the before-run measurement.
- **Mutation target for Task 2** was the query's final `SELECT` (reading directly from the `admitted` CTE instead of the aggregated `bucket_totals`), chosen after a first attempt -- removing only `bucket_totals`'s `SUM`/`CASE`/`GROUP BY` -- produced a `TypeError` on `NULL online_seconds`/`offline_seconds` for a bucket with no overlapping segment, a real failure but not the row-count assertion failure the plan asked to observe. The final-SELECT mutation demonstrates the literal claim ("one row per stored check instead of one per bucket") cleanly: `small_rows` came back exactly equal to `small_stored` (1,728) and `large_rows` exactly equal to `large_stored` (6,912).
- **Report presents this plan's own fresh before-run**, not `06-PROFILE-2.md`'s older numbers, as the authoritative "before" figure for the delta arithmetic (`PROH-OPS-07-18` -- never compare a share or a wall-time figure across two different measurement sessions as if they were the same run). `06-PROFILE-2.md`'s 58.533ms is cited only as a corroborating cross-check (this plan's fresh 56.820ms mean sits within this host's observed variance of it), never as an input to the delta calculation itself.

## Deviations from Plan

None - plan executed exactly as written. The REFUTED verdict is the plan's own explicitly-anticipated branch, not a deviation from it -- the plan required the REFUTED wording to be written before the measurement was taken, and it was.

## Mutation Verification (Task 2, required by plan)

Mutated `dashboard/beacon/repositories.py`'s `UPTIME_STRIP_QUERY` final `SELECT` from:

```sql
SELECT bt.port, bt.idx, bt.online_seconds, bt.offline_seconds, COALESCE(nc.null_count, 0) AS null_count
FROM bucket_totals bt LEFT JOIN null_counts nc ON nc.port = bt.port
ORDER BY bt.port ASC, bt.idx ASC
```

to:

```sql
SELECT port, 0 AS idx, COALESCE(online, 0) AS online_seconds, 0 AS offline_seconds, 0 AS null_count
FROM admitted
ORDER BY port ASC, ts ASC
```

Ran `UptimeStripCostModelTests` against the mutated code. Observed failure, verbatim:

```
AssertionError: 1728 != 6912 : Python-side materialized row count moved with stored check volume
(measured 4.000x growth in stored service_checks rows: small_stored=1728, large_stored=6912) --
small_rows=1728, large_rows=6912. read_uptime_strips_by_port must materialize exactly
len(ports) * UPTIME_BUCKETS rows regardless of how many rows are stored; SQLite itself still
scans the stored rows to build the aggregation -- only the Python-side count is claimed to be
bounded here.
```

`small_rows == small_stored` and `large_rows == large_stored` exactly -- the mutation produced literally one materialized row per stored (retention-floored, in-window) check, confirming the guard fails precisely the way the plan specified. Reverted before commit; `git diff -- dashboard/beacon/repositories.py` confirmed clean before staging Task 2's commit.

## Issues Encountered

- The first mutation attempt (removing `bucket_totals`'s `SUM(CASE ...)` wrapping and its `GROUP BY`, keeping the range join) produced a `TypeError: unsupported operand type(s) for +: 'NoneType' and 'NoneType'` at `read_uptime_strips_by_port`'s `observed = online_seconds + offline_seconds` line, because a bucket with no overlapping segment now gets a `NULL` join result with no `SUM`/`ELSE 0` to coalesce it. This is a real defect the guard's own crash would have caught (an unhandled exception is at least as loud as an assertion failure), but it does not produce "the row-count assertion fail with the real ratio in its message" the plan specifically asked to observe and record, so the final-SELECT mutation was used instead. Reverted cleanly before moving to the second mutation attempt (confirmed via `git diff --stat` showing no residual diff).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- **`06-27` must not run against this build.** The verdict is REFUTED: `06-25`'s bulk SQL aggregation is measurably worse on this host, not better, and the regression is attributable to a specific, named query-structure defect (`UPTIME_STRIP_QUERY`'s unindexed range join), not to noise or to this host being unrepresentative in some unnamed way. Running `06-27`'s Pi hardware round against `9da5e5e` as it stands would spend a sixth hardware round measuring a change this plan's cheap local guard already caught.
- **What the next planning round inherits:** a specific, falsifiable root-cause finding (`06-PROFILE-3.md`'s "Root cause" section) naming the exact join structure responsible, rather than a vague "option C didn't work." Whoever scopes the next round can choose to fix the join (e.g., restructure to avoid the range predicate, or fall back toward a bounded per-port approach) or reconsider option C's viability entirely -- both are live options this report does not foreclose.
- **This finding is a blocker-level fact for Phase 6's overall direction** and belongs in `STATE.md`'s Blockers/Concerns once the orchestrator's post-wave update runs (this plan does not edit `STATE.md` per its worktree-isolation contract): `06-25`, though correctness-verified, made `/api/services` measurably slower on this host, and `06-27` should not proceed against `9da5e5e` without either fixing the identified join defect or re-scoping.
- `.planning/REQUIREMENTS.md` is unedited: OPS-07 and OPS-04 stay exactly as they were before this plan (`requirements-completed: []`) -- this plan is a measurement-and-guard round, not a requirement-closing round, and its own verification section says so explicitly.

## Self-Check: PASSED

All modified/created files confirmed present on disk:
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-3.md`
- FOUND: `tests/services_route_profile.py` (diff confirmed: `uptime_strip_sql` bucket present, `HONESTY_CAVEAT`/`PI_CONTROL_PASS_P50_MS` unedited)
- FOUND: `tests/test_services_route_scaling.py` (diff confirmed: `UptimeStripCostModelTests` present)

Both commit hashes confirmed in `git log`:
- FOUND: `f94daf2`
- FOUND: `4a0bd74`

Full suite (`uv run --project dashboard python -m pytest tests/ -q`): **982 passed, 593 subtests passed, 0 failed** (run after both tasks were committed, including the new `UptimeStripCostModelTests`) -- no new failures, and neither of `D-DEBT-06-13`'s two known-flaky tests manifested in this run.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-05*
