---
phase: 06-workload-resilience-pi-acceptance
kind: profile-report
created: 2026-09-05
build_before: 79e051e4b2e14130f8c962f06945bafcdaae1cf2 (pre-06-25, immediate parent of 87fa3ae -- production code identical to 06-PROFILE-2.md's ca28683 build; no route change between them)
build_after: 9da5e5e47f024d842a76833cbc6460157e81de44 (06-25 landed) plus this plan's own instrumentation-only diff to tests/services_route_profile.py (the new uptime_strip_sql bucket registration; zero production code changed by this plan)
supersedes: nothing. 06-PROFILE.md and 06-PROFILE-2.md are both retained unedited, per this phase's convention of never deleting a measurement.
does_not_supersede: 06-PROFILE-2.md's 43.727% uptime_sweep share at this same shape/seed/host -- this report's own before-run reproduces it (43.942% mean across three repetitions) and treats that agreement as confirmation, not revision.
---

# `/api/services` before/after `06-25`, same host, same seed, same shape

**Purpose:** establish whether `06-25`'s bulk SQL uptime aggregation actually made `/api/services`
cheaper on this host, before any Pi time is spent on `06-27`. This is not Pi latency evidence
(`PROH-OPS-07-09`) and does not claim OPS-07 passes or fails -- see "What this may not conclude"
below.

## Provenance

| | |
|---|---|
| Host | `arm64` / `Williams-MacBook-Pro-635.local` -- a development laptop, **not Pi latency evidence** |
| Before build | `79e051e` -- immediate parent of `06-25` Task 1's commit (`87fa3ae`) |
| After build | `9da5e5e` (`06-25` fully landed) + this plan's own profiler-instrumentation-only diff (no production module touched) |
| Seed | `20260902` (default -- identical to `06-PROFILE-2.md`) |
| Services | 8 |
| Days | 8 |
| Repeats per invocation | 5 |
| Invocations per build | 3, run back-to-back on this host via a detached `git worktree` checkout for the before build (never rewriting this worktree's own history) |

Invocation (identical both builds):

```
uv run --project dashboard python tests/services_route_profile.py \
    --services 8 --days 8 --repeats 5 --output <json> --min-attributed 0
```

## Headline: `wall_ms_unprofiled`, before vs after

| | run 1 | run 2 | run 3 | mean | spread (max-min) |
|---|---|---|---|---|---|
| Before (`79e051e`) | 56.931ms | 56.827ms | 56.701ms | **56.820ms** | 0.230ms |
| After (`9da5e5e`) | 238.005ms | 235.688ms | 235.103ms | **236.265ms** | 2.902ms |

**Delta: +179.446ms absolute, +315.8% of the before mean.** Both builds' own run-to-run spreads
(0.230ms before, 2.902ms after) are two orders of magnitude smaller than the delta -- this is not
noise, and `06-ACCEPTANCE-C3-RUN2.md`'s 44ms Pi run-to-run variance (the plan's stated floor for a
"result smaller than spread is not a result") is itself an order of magnitude smaller than this
delta. The before mean (56.820ms) is consistent with `06-PROFILE-2.md`'s independently-measured
58.533ms at the identical build lineage, seed and shape (both builds share identical route code;
`79e051e` sits after `06-PROFILE-2.md`'s `ca28683` in history but no production module changed
between them) -- the ~1.7ms difference between the two measurement sessions is itself inside this
host's observed variance, corroborating rather than contradicting the fresh before-run.

`wall_ms_profiled` (after): 260.538ms / 254.490ms / 254.933ms, mean **256.654ms**.
`attributed_pct` (after): 98.662% / 98.617% / 98.637%, mean **98.639%** -- comfortably above the
profiler's 90.0% contract; the bucket table below is not an artifact of poor attribution coverage.

## Verdict: **REFUTED**

```
before_mean = 56.820ms
after_mean  = 236.265ms
delta       = after_mean - before_mean = +179.446ms
delta_pct   = delta / before_mean * 100 = +315.8%
```

`06-25`'s bulk SQL aggregation did not make `/api/services` cheaper on this host -- it made it
**more than four times slower** (236.265ms vs 56.820ms). This is the REFUTED branch the plan
required to be written before the measurement was taken: option C's premise -- that moving
`uptime_sweep`'s ~43.7%-share Python work into a SQLite aggregation would reduce total cost -- does
not hold here. The delta is not merely "not an improvement"; it is a substantial regression, of the
same character (a landed, correctness-verified change that measured decisively worse) as round 5's
Pi run that this plan exists to catch before a sixth repetition of that exact failure mode.

## Where `uptime_sweep`'s cost went (not a saving -- `PROH-OPS-07-19`)

| bucket | before share_pct | before tottime_ms | after share_pct | after tottime_ms | cost went to |
|---|---|---|---|---|---|
| `uptime_sweep` | 43.942% | 240.059 | -- (absent, 0 calls) | -- | route no longer calls `_legacy_uptime_summary` at all |
| `sql_execute` | 0.620% | 3.386 | **79.370%** | **1018.995** | the SQL aggregation itself -- see below |
| `uptime_strip_sql` | -- | -- | 0.381% | 4.890 | the reader's Python wrapper only (expected small, by design -- see the bucket's own comment in `tests/services_route_profile.py`) |
| `row_grouping` | 16.417% | 89.711 | 3.928% | 50.433 | partial fall -- see next section |
| `sql_fetch` | 13.529% | 73.894 | 5.825% | 74.789 | flat in absolute ms; share fell only because the total grew |
| `offline_intervals_read` | 7.389% | 40.365 | 3.735% | 47.949 | roughly flat |
| `attributed_downtime` | 6.812% | 37.211 | 2.271% | 29.147 | roughly flat |
| `maintenance_coverage` | 5.533% | 30.227 | 2.370% | 30.420 | flat |
| `other` | 3.580% | 19.560 | 1.361% | 17.474 | flat |
| `covering_boundaries` | 1.602% | 8.750 | 0.684% | 8.778 | flat |
| `monitoring_operations_binding` | 0.394% | 2.155 | -- (absent) | -- | no longer called (the reader replaces this call path too) |
| `json_serialization` | 0.171% | 0.934 | 0.073% | 0.934 | flat |
| `maintenance_windows_read` | 0.010% | 0.056 | 0.004% | 0.051 | flat |

**`uptime_sweep`'s collapse is not the story -- `sql_execute`'s growth is.** `uptime_sweep` cost
~240ms of tottime (accumulated cProfile self-time across 5 profiled repeats) before; `sql_execute`
alone now costs ~1019ms of tottime across the same 5 repeats -- more than four times what the
bucket it replaced cost, not a wash and not a saving. Per this module's own documented bias
(cProfile inflates Python-heavy buckets and under-measures SQL-bound ones), if anything this
understates how much the SQL side grew relative to the Python-heavy bucket it replaced, because the
comparison here is tottime-to-tottime, both under the same instrument.

**Root cause, read from `dashboard/beacon/repositories.py`'s `UPTIME_STRIP_QUERY`
(`read_uptime_strips_by_port`), stated as an observation about the query's structure, not as a fix
this plan is scoped to make:** the `bucket_totals` CTE performs
`requested_ports CROSS JOIN buckets` (8 ports x 168 buckets = 1,344 rows) `LEFT JOIN ordered_points
sg ON sg.port = rp.port AND sg.effective_ts < bk.bucket_start + ? AND sg.end_ts > bk.bucket_start`.
The join predicate against `ordered_points` is a range condition (`<` / `>`), not an equality
SQLite can resolve with an index seek -- for every one of the 1,344 bucket-port rows, SQLite must
scan `ordered_points` for that port looking for overlapping segments. At this seeded shape (8-day
retention, 300s/60s check cadence per `_J3_INTERVAL_SECONDS`/`_J4_INTERVAL_SECONDS`) each port
carries on the order of several thousand admitted segments, so the join's real cost scales with
`buckets x ports x segments_per_port` rather than `services x buckets` as the old per-service sweep
effectively bounded it. This is an observation for whoever scopes the next round, not a mitigation
performed here -- this plan's mandate is measurement and a relational cost-model guard, not a query
rewrite.

## `row_grouping`: the predicted partial fall, measured

`06-25` removed the `checks_by_port` half of `api_services`'s result-grouping loop but left the
`points_by_port` half (still feeding offline-interval reconstruction). The prediction was a partial
fall, not a collapse:

- calls: 226,848 (mean, before) -> 100,409 (after) -- **-55.7%**
- tottime: 89.711ms (mean, before) -> 50.433ms (after) -- **-43.8%**

The measurement bears out the prediction: a real, substantial fall, well short of the ~56% call
reduction implying an equivalent tottime reduction (tottime fell proportionally less than calls,
consistent with `points_by_port`'s share of the loop's per-call cost being larger than its share of
calls) but nowhere near zero. This is the one bucket in this report that moved exactly as `06-25`'s
plan predicted.

## Honesty block (`PROH-OPS-07-09`)

Every millisecond in this report -- `wall_ms_unprofiled`, `wall_ms_profiled`, every bucket's
`tottime_ms` -- was measured on `host_machine=arm64` / `host_node=Williams-MacBook-Pro-635.local`,
a development laptop. None of it is Raspberry Pi latency evidence. The sole authority on absolute
`/api/services` cost on target hardware remains the 289.0ms p50 measured on the Pi control pass at
concurrency 1 (`PI_CONTROL_PASS_P50_MS` in `tests/services_route_profile.py`, unedited by this
plan -- confirmed by `grep -n "HONESTY_CAVEAT\|PI_CONTROL_PASS_P50_MS"` matching both symbols and
`git diff` showing no edit to either). Only the proportional attribution and the directional
before/after delta measured here may inform a decision; neither this report's milliseconds nor
06-PROFILE.md's stale section 4 growth ratios may be quoted as Pi-class evidence.

## What this report may not conclude

Nothing about Pi latency and nothing about whether OPS-07 passes or fails. A REFUTED dev-host
wall-time delta is a directional signal that option C's premise, as implemented, does not hold on
this host's SQLite query planner -- it is not a prediction of concurrency-3 p95 behavior on a Pi 5,
and it does not by itself prove the Pi would show the same regression (a different SQLite version,
page cache behavior, or storage medium could in principle behave differently). What it does
establish, on the falsifiable terms this plan set before measuring: **the cheap local guard did its
job.** Running `06-27` against this build would spend a sixth hardware round measuring a change
that already failed its own local, same-host, same-seed, same-shape check.

## Stop condition

**The verdict is REFUTED. Per this plan's explicit instruction, `06-27` must not be run as written
against this build.** Option C's premise -- that removing `uptime_sweep`'s Python cost via a bulk
SQL aggregation would reduce `/api/services`'s total cost -- did not hold on this host. The
regression is attributable to the new query's unindexed range-join cost scaling with
`buckets x ports x segments_per_port`, a cost dimension the Python sweep did not have at this
shape. This plan stops here with that finding recorded, rather than proceeding to spend hardware
time on a build that already measured decisively worse locally.
