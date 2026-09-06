---
phase: 06-workload-resilience-pi-acceptance
plan: 29
subsystem: database
tags: [sqlite, uptime, performance, gap-closure, ops-07, recursive-cte]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-PROFILE-3.md's root-cause finding (bucket_totals' unindexed range join scaling as buckets x ports x segments_per_port) and 06-26's stop condition blocking 06-27"
provides:
  - "UPTIME_STRIP_QUERY's bucket_totals CTE reshaped into index-arithmetic (clamped/spans) plus recursive expansion (expanded/bucket_sums), replacing the range join, with the 168-bucket scaffold's LEFT JOIN reduced to an equality predicate"
  - "UptimeStripSqlTextGuardTests: the narrowed rounding guard 06-25 specified but never shipped (PROH-OPS-07-23)"
  - "UptimeStripRowEmissionTests: mutation (b)'s NULL-guard side-effect finding, pinned as a standing test (PROH-OPS-07-25)"
  - "06-PROFILE-4.md: FAIL-BUT-IMPROVED verdict against the pre-06-25 baseline, with the planner's pre-registered ~70ms projection confirmed"
affects: [06-27, 06-30]

actuals:
  tokens: 8704
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns:
    - "Invert a range-join aggregation by computing each row's overlapping target range arithmetically (integer division on bucket-index boundaries), then expanding only that range through a recursive CTE, so the join back to the fixed-shape scaffold becomes an equality predicate SQLite can serve"
    - "Mutation-verify a narrowed guard against the exact mutations the original guard was built for, in the same commit that narrows it, so the narrowing's justification is provable rather than asserted"
    - "Pre-register a cost fix's pass bar, projection, and all outcome-branch wordings to disk (and commit them) before running the measurement that will settle them"

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-4.md
  modified:
    - dashboard/beacon/repositories.py
    - tests/test_services_route_scaling.py

key-decisions:
  - "The 168-bucket scaffold (requested_ports CROSS JOIN buckets LEFT JOIN bucket_sums) stays in SQL rather than reconstructing the fixed array in Python from only non-empty buckets, even though the alternative measured ~4ms cheaper in the planner's pre-planning bench -- moving it would make the materialized row count a function of window coverage (breaking two passing boundedness/cost-model guards) and would silently reopen mutation (b)'s NULL-guard defeat (PROH-OPS-07-24)."
  - "The rounding guard is narrowed from 'no division character anywhere in the query text' to 'no SQL rounding call, and every division belongs to an enumerated (first_idx, last_idx) pair' -- narrowed because the original proxy was wrong about what it protected (it forbids bucket-index arithmetic on values never rendered), never because the reshaped code could not meet the original criterion (PROH-OPS-07-23)."
  - "06-PROFILE-4.md's pass bar, projection, and all three outcome branches were written to disk and committed (0b06e24) BEFORE running the three profiler invocations, so the verdict's wording could not be adjusted after the number arrived (PROH-OPS-07-26)."

requirements-completed: []

coverage:
  - id: D1
    description: "UPTIME_STRIP_QUERY's bucket_totals CTE reshaped to compute each segment's overlapping bucket range by integer-division arithmetic and expand only those buckets via a recursive CTE, joining back to the 168-bucket scaffold by equality instead of a range predicate -- proven output-identical by every pre-existing correctness guard, unmodified"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripSqlDifferentialTests::test_randomized_histories_agree_with_the_legacy_sweep_on_the_route_subset"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripBoundednessTests::test_materialized_row_count_is_independent_of_stored_check_volume"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripCostModelTests::test_python_side_row_and_statement_counts_are_independent_of_stored_check_volume"
        status: pass
    human_judgment: false
  - id: D2
    description: "The reshaped query is measurably cheaper than the shape it replaces AS A QUERY, demonstrated by an A/B of both shapes against one seeded database in a single run before any route-level number was quoted"
    requirement: OPS-07
    verification:
      - kind: other
        ref: "scratchpad ab_bench.py (not committed, per plan instruction): old shape min 208.3ms, new shape min 38.9ms, 1,344/1,344 tuples tuple-identical"
        status: pass
    human_judgment: false
  - id: D3
    description: "The narrowed rounding guard (no SQL rounding call, division allowlist) and the per-port row-emission tally exist, are mutation-verified against the exact hazards they replace/pin, and 06-25's existing guards are untouched"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripSqlTextGuardTests"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripRowEmissionTests"
        status: pass
    human_judgment: false
  - id: D4
    description: "06-PROFILE-4.md states its pass condition and pre-registered projection before measuring, then records a verdict against the pre-06-25 56.820ms baseline (never against 06-25's 236.265ms regression)"
    requirement: OPS-07
    verification:
      - kind: other
        ref: "grep -n '^## Verdict:' .planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-4.md"
        status: pass
    human_judgment: true
    rationale: "The report is a prose artifact whose honesty (bar stated before 236.265, FAILURE stated as the headline, no re-basing) requires human review beyond keyword presence."

duration: 51min
completed: 2026-09-06
status: complete
---

# Phase 6 Plan 29: Invert the Range Join, Measure Against the Bar That Matters Summary

**Replaced `UPTIME_STRIP_QUERY`'s unindexed range-join `bucket_totals` with index-arithmetic plus recursive bucket expansion (5.4x faster as an isolated query, 208.3ms to 38.9ms), shipped the rounding guard `06-25` specified but never built, and measured the reshape at the route level: 236.265ms down to 69.191ms (70.71% better than `06-25`'s regression) but still short of the 56.820ms pre-`06-25` baseline this fix had to clear — recorded as FAIL-BUT-IMPROVED, confirming the planner's own pre-registered ~70ms projection almost exactly.**

## Performance

- **Duration:** ~51 min
- **Tasks:** 3
- **Files modified:** 3 (1 created)

## Accomplishments

- **The reshape.** `UPTIME_STRIP_QUERY`'s `bucket_totals` CTE — previously a `requested_ports CROSS JOIN buckets` (1,344 rows) `LEFT JOIN` onto `ordered_points` on a range predicate SQLite could not index-seek — is replaced by four CTEs (`clamped`, `spans`, `expanded`, `bucket_sums`) that compute each segment's overlapping bucket range once, arithmetically (integer division on bucket-index boundaries, proven non-negative and therefore safe under SQLite's truncate-toward-zero semantics), and expand only those buckets through a recursive CTE. The scaffold's join to the aggregate is now equality on `(port, idx)`.
- **Query-level A/B (Task 1, before any route-level number was quoted):** on the profiled 8-service/8-day seeded database, the old shape measured a minimum of 208.3ms over 3 runs; the reshaped shape measured a minimum of 38.9ms — **5.4x**, with all 1,344 result tuples tuple-identical between the two shapes. Expanded intermediate row count measured at 22,247 against a bound of 23,583 (`segment_count + len(ports) * (UPTIME_BUCKETS - 1)`).
- **Every pre-existing correctness guard passes unmodified.** `UptimeStripSqlDifferentialTests` (400 randomized trials + 9 enumerated cases), `UptimeStripBoundednessTests`, `UptimeStripCostModelTests`, `ApiServicesOutputEquivalenceTests` — all green, `git diff --stat -- tests/` empty on Task 1's commit. The three golden fixtures byte-match unregenerated.
- **The rounding guard 06-25 specified but never shipped now exists, narrowed and mutation-proven.** `UptimeStripSqlTextGuardTests` asserts no SQL rounding call, an enumerated division allowlist (`first_idx`/`last_idx` only), a live-execution column-name pin, and integer-only value types. `UptimeStripRowEmissionTests` pins mutation (b)'s finding — a row-drop silently disables the unrelated NULL guard — via a per-port tally against a sparse four-port fixture (dense, NULL-only, zero-row, sparse).
- **The route-level verdict: FAIL-BUT-IMPROVED.** Three invocations of `tests/services_route_profile.py` at the identical shape/seed/host as `06-PROFILE-3.md` measured `wall_ms_unprofiled` at 70.301ms / 68.048ms / 69.224ms, mean **69.191ms**. This is *not* below the 56.820ms pass bar (pre-`06-25` baseline) — a stated FAILURE per `PROH-OPS-07-26` — though it is a 70.71% reduction from `06-25`'s 236.265ms regression. The planner's pre-registered projection (`~70ms`, band 55-90ms, projected FAIL) is **confirmed**, not refuted.
- **Cost attribution, not celebration (`PROH-OPS-07-19`):** `sql_execute`'s tottime fell from 1018.995ms (`06-25`, after) to a measured mean of 189.200ms — a 5.386x fall, consistent with the isolated 5.4x query-level A/B. Every other bucket's absolute tottime is flat; their *share* rose only because the shrinking total made their unchanged absolute cost a larger fraction of it.

## Task Commits

1. **Task 1: End-to-end — invert the join, and let the tests nobody edited prove the strip did not move** - `8a84139` (feat)
2. **Task 2: Narrow the guard that was never built — and prove the narrowed form still catches what the original was for** - `46d8315` (test)
3. **Task 3a: Write 06-PROFILE-4's pass condition and projection before measuring** - `0b06e24` (docs)
4. **Task 3b: Record the reshape's verdict — FAIL-BUT-IMPROVED** - `6e8e3bf` (docs)

_Note: Task 3 produced two commits — the pre-registered skeleton (pass bar, projection, all three outcome branches) written and committed BEFORE the measurement, then the completed report with results and verdict, per the plan's own discipline requirement (PROH-OPS-07-26)._

## Files Created/Modified

- `dashboard/beacon/repositories.py` - `UPTIME_STRIP_QUERY`'s `bucket_totals` CTE reshaped (four new CTEs, reduced `bucket_totals`); `read_uptime_strips_by_port`'s `params` tuple updated to match. Signature, docstring semantics, validation, and Python post-processing untouched.
- `tests/test_services_route_scaling.py` - `UptimeStripSqlTextGuardTests` (narrowed rounding guard) and `UptimeStripRowEmissionTests` (row-emission tally) added; no pre-existing class modified.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-4.md` - created: pass condition, pre-registered projection, all three outcome branches, provenance, headline table, verdict, attribution table, honesty block, stop condition.

## Decisions Made

- **The 168-bucket scaffold stays in SQL** (`requested_ports CROSS JOIN buckets LEFT JOIN bucket_sums`) rather than reconstructing the fixed array in Python from only non-empty buckets, even though the Python-side alternative measured ~4.2ms cheaper in the planner's pre-planning bench. Moving it would make the materialized row count a function of window coverage — breaking `UptimeStripBoundednessTests::test_materialized_row_count_is_independent_of_stored_check_volume` and `UptimeStripCostModelTests::test_python_side_row_and_statement_counts_are_independent_of_stored_check_volume` — and would silently reopen `06-25`'s mutation (b) NULL-guard defeat (`PROH-OPS-07-24`).
- **The rounding guard is narrowed** from "no division character anywhere in the query text" to "no SQL rounding call, and every division belongs to an enumerated `(first_idx, last_idx)` pair" (`PROH-OPS-07-23`) — narrowed because the original proxy was wrong about what it protected (it forbids bucket-index arithmetic on values that select an array position and are never rendered), never because the reshaped code could not meet the original criterion. Proven by re-running mutations (c), (c-prime), (c-double-prime) against the narrowed form (see Mutation Verification below).
- **The measurement discipline was followed literally**: `06-PROFILE-4.md`'s pass bar, projection, and all three outcome-branch wordings were written to disk and committed (`0b06e24`) before the three profiler invocations ran, so the verdict's wording could not be adjusted once the number arrived.

## Deviations from Plan

None — plan executed exactly as written, including the FAIL-BUT-IMPROVED verdict, which is the plan's own explicitly pre-registered likely branch, not a deviation from it. The plan itself stated: "the same bench says this fix probably does not clear the bar." It did not; that is the plan working as designed, not a departure from it.

## Mutation Verification (Task 2, required by plan)

Each mutation was applied by hand directly to `dashboard/beacon/repositories.py`, the relevant test(s) run, the failure observed and recorded below, then reverted via `git checkout --` before the next mutation. `git diff --stat` confirmed zero residual diff before Task 2's commit.

**(c) Rounded ratio column added to the final SELECT** (`ROUND(1.0 * bt.online_seconds / (bt.online_seconds + bt.offline_seconds + 1), 3) AS bucket_fraction`). Three independent failures, verbatim:

```
AssertionError: 3 != 2 : a division character exists in UPTIME_STRIP_QUERY outside the enumerated
first_idx/last_idx bucket-index pair -- a division added anywhere else (a projected column, a CASE
arm, a join predicate) must fail this assertion
```
```
AssertionError: <re.Match object; span=(2246, 2252), match='ROUND('> is not None : UPTIME_STRIP_QUERY
must contain no SQL rounding call -- rounding happens only in Python, over the integer second totals
this query returns (SQLite ROUND() rounds half away from zero; Python round() rounds half to even,
PROH-OPS-07-15/07-23)
```
```
AssertionError: Lists differ: ['port', 'idx', 'online_seconds', 'offline_seconds', 'null_count',
'bucket_fraction'] != ['port', 'idx', 'online_seconds', 'offline_seconds', 'null_count'] : the
projected column set must be exactly the five the reader consumes
```

**(c-prime) Same column, no ROUND()** (`1.0 * bt.online_seconds / (bt.online_seconds + bt.offline_seconds + 1) AS bucket_fraction`). Fails the division-allowlist and column-name assertions, **passes** the rounding-call test — the asymmetry the plan asked to confirm, proving the allowlist earns its place independent of the rounding check:

```
AssertionError: 3 != 2 : a division character exists in UPTIME_STRIP_QUERY outside the enumerated
first_idx/last_idx bucket-index pair -- ...
```
```
AssertionError: Lists differ: [..., 'bucket_fraction'] != ['port', 'idx', 'online_seconds',
'offline_seconds', 'null_count'] : the projected column set must be exactly the five the reader
consumes
```

**(c-double-prime) Division on an existing total, same alias, no new column** (`bt.online_seconds / 1 AS online_seconds`). Fails **only** the division-allowlist test — proof the narrowing left no hole a rounding-only ban would have opened:

```
AssertionError: 3 != 2 : a division character exists in UPTIME_STRIP_QUERY outside the enumerated
first_idx/last_idx bucket-index pair -- ...
```
(rounding-call, column-name, and value-type assertions all pass unchanged.)

**(b) Scaffold LEFT JOIN to `bucket_sums` changed to INNER JOIN.** Against the sparse four-port fixture (dense/NULL-only/zero-row/sparse), fails the per-port emission assertion:

```
AssertionError: 150 != 168 : port 71001 emitted 150 rows, expected exactly 168 -- a per-port tally
is required because a mutation can drop one port while another still supplies the total
```

Full per-port breakdown under the mutation (measured separately, not asserted in the committed test): `{dense: 150, null_only: 1, zero_row: 0, sparse: 3}` — total 154 of an expected 672, with the **zero-row port vanishing entirely** (0 rows). Confirmed the same mutation is **invisible** against a dense 8-day/8-port fixture: 1,344 rows both mutated and unmutated (no difference), because every `(port, idx)` pair already has an aggregate row on a dense dataset. This is exactly `PROH-OPS-07-25`'s cited hazard: a row-drop mutation of this shape is undetectable except against a fixture whose window is mostly unobserved.

## Issues Encountered

None beyond the expected measurement mechanics. The A/B benchmark script initially mis-sliced the CTE prefix text when measuring the recursive expansion's intermediate row count (an off-by-comma error in the truncated query text); corrected by counting `?` placeholders in the sliced prefix rather than assuming a fixed offset, confirmed against the reshaped query's own text before trusting the measured 22,247/23,583 figures.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- **`06-27` stays blocked.** `06-PROFILE-4.md`'s verdict is FAIL-BUT-IMPROVED: the reshape does not meet its own pass condition (beat 56.820ms), so option C — even in its best measured version — remains refuted against the baseline that matters, per `PROH-OPS-07-26`.
- **What `06-30` inherits:** a route-level number (69.191ms mean) that confirms rather than refutes the planner's own pre-registered projection, built entirely from this same host's prior attribution data before the reshape existed. `06-30`'s checkpoint decides between keeping the reshape (a real, attributed, substantial improvement over `06-25`'s regression, even though insufficient alone) and reverting the route wiring entirely. The `ordered_points` restructure (measured ~10ms saving, held in reserve per the plan's objective) remains an untaken option for that checkpoint to weigh.
- `.planning/REQUIREMENTS.md` is unedited by this plan: `OPS-07` and `OPS-04` stay exactly as they were (`requirements-completed: []`) — `PROH-OPS-07-08` forbids a gap-closure round from recording its own requirement complete.
- Full suite (`uv run --project dashboard python -m pytest tests/ -q`): **988 passed, 593 subtests passed, 0 failed** — 6 more than `06-26`'s 982 (exactly the 6 new tests this plan added: 4 in `UptimeStripSqlTextGuardTests`, 2 in `UptimeStripRowEmissionTests`). No new failures.

## Self-Check: PASSED

All modified/created files confirmed present on disk:
- FOUND: `dashboard/beacon/repositories.py` (diff confirmed: reshaped `UPTIME_STRIP_QUERY`, updated `params` tuple)
- FOUND: `tests/test_services_route_scaling.py` (diff confirmed: `UptimeStripSqlTextGuardTests`, `UptimeStripRowEmissionTests` present, additions-only)
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE-4.md`

All four commit hashes confirmed in `git log`:
- FOUND: `8a84139`
- FOUND: `46d8315`
- FOUND: `0b06e24`
- FOUND: `6e8e3bf`

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-06*
