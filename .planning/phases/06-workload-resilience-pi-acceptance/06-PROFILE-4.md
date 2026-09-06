---
phase: 06-workload-resilience-pi-acceptance
kind: profile-report
created: 2026-09-06
build_before: 79e051e4b2e14130f8c962f06945bafcdaae1cf2 (pre-06-25, 56.820ms reference build, per 06-PROFILE-3.md); 9da5e5e47f024d842a76833cbc6460157e81de44 (06-25 landed, 236.265ms reference build, per 06-PROFILE-3.md)
build_after: this plan's Task 1 commit, 8a84139 (the CTE reshape of UPTIME_STRIP_QUERY's bucket_totals)
supersedes: nothing. 06-PROFILE.md, 06-PROFILE-2.md and 06-PROFILE-3.md are all retained unedited, per this phase's convention of never deleting a measurement.
---

# Does the CTE reshape beat the bar it actually has to clear?

**Purpose:** measure Task 1's reshaped `UPTIME_STRIP_QUERY` (index arithmetic plus recursive bucket
expansion, replacing the unindexed range join `06-PROFILE-3.md` identified as the cause of `06-25`'s
315.8% regression) against the bar this fix must clear -- the **pre-`06-25` baseline**, never
`06-25`'s own regression -- under a pass condition and a projection both written down before the
measurement (`PROH-OPS-07-26`). This is not Pi latency evidence (`PROH-OPS-07-09`) and does not
claim OPS-07 passes or fails -- see "What this report may not conclude" below.

## Pass condition (written before the run)

Mean `wall_ms_unprofiled` across three invocations must be **strictly below 56.820ms** -- the
pre-`06-25` baseline `06-PROFILE-3.md` measured on this host, at this seed, at this shape. **Not**
below 236.265ms (`06-25`'s own regression). A result that beats 236.265ms but not 56.820ms is a
FAILURE of this fix, per `PROH-OPS-07-26`.

## Pre-registered projection (written before the run)

**~70ms, band 55-90ms. Projected verdict: FAIL.**

Arithmetic, as `06-29-PLAN.md`'s objective states it: `236.265 - ~204 + ~38 ≈ 70ms`, where `~204ms`
is the current (pre-reshape) query's measured per-request cost implied by `06-PROFILE-3.md`'s
`sql_execute` attribution (1018.995ms tottime across 5 profiled repeats ≈ 204ms/repeat), and `~38ms`
is the reshaped query's projected per-request cost at roughly 18.6% of that (`06-29-PLAN.md`'s own
pre-planning bench measured the reshaped query at 47.4ms against the old shape's 254.4ms on a
synthetic database at this profiled shape -- 47.4 / 254.4 ≈ 18.6%, applied to the ~204ms route-level
figure).

**This projection is the planner's, not a measurement.** A result under 56.820ms REFUTES it, and
that must be recorded as a refutation, not quietly dropped. A result at or above 56.820ms CONFIRMS
it, within the stated band or not.

## The three outcome branches (written before the run)

**PASS** -- mean below 56.820ms. The reshape closes `06-25`'s regression and beats the pre-`06-25`
baseline. The planner's ~70ms projection is refuted; that refutation is stated as such, not
absorbed silently. `06-27`'s local stop condition is lifted, subject to `06-30`'s checkpoint and to
`06-27` itself needing its build SHAs amended before it can run.

**FAIL-BUT-IMPROVED** -- mean at or above 56.820ms and below 236.265ms. **This is recorded as a
FAILURE of this fix against its stated pass condition.** The headline sentence is the failure. The
improvement over `06-25`'s 236.265ms is a subordinate fact, stated after the failure sentence, with
its own arithmetic, and is never presented as the result. Option C remains refuted against the
baseline that matters. `06-27` stays blocked.

**FAIL-NO-IMPROVEMENT** -- mean at or above 236.265ms. The reshape did not help at route level
despite helping at query level (Task 1's A/B: 208.3ms -> 38.9ms, 5.4x, tuple-identical); that gap
between query-level and route-level improvement is itself the finding and must be attributed, not
hand-waved. `06-27` stays blocked and reverting the reshape becomes the recommendation into `06-30`.

**This skeleton -- pass condition, projection and all three branches -- was written to disk and
committed BEFORE the measurement below was run** (commit `0b06e24`), per this task's own discipline
requirement: five rounds of this phase have produced numbers whose interpretation was settled after
they arrived.

## Provenance

| | |
|---|---|
| Host | `arm64` / `Williams-MacBook-Pro-635.local` -- a development laptop, **not Pi latency evidence** |
| Reshape commit | `8a84139` (this plan's Task 1 -- `UPTIME_STRIP_QUERY`'s `bucket_totals` reshape) |
| Reference builds | `79e051e` (pre-`06-25`, 56.820ms) and `9da5e5e` (`06-25` landed, 236.265ms), both per `06-PROFILE-3.md` |
| Seed | `20260902` (default -- identical to `06-PROFILE-3.md`) |
| Services | 8 |
| Days | 8 |
| Repeats per invocation | 5 |
| Invocations | 3, run back-to-back on this host |

Invocation (identical to `06-PROFILE-3.md`'s in every argument):

```
uv run --project dashboard python tests/services_route_profile.py \
    --services 8 --days 8 --repeats 5 --output <json> --min-attributed 0
```

## Headline: `wall_ms_unprofiled`, this run vs both references

| | run 1 | run 2 | run 3 | mean | spread (max-min) |
|---|---|---|---|---|---|
| This run (`8a84139`) | 70.301ms | 68.048ms | 69.224ms | **69.191ms** | 2.253ms |
| Pre-`06-25` (`79e051e`, `06-PROFILE-3.md`) | 56.931ms | 56.827ms | 56.701ms | 56.820ms | 0.230ms |
| `06-25` (`9da5e5e`, `06-PROFILE-3.md`) | 238.005ms | 235.688ms | 235.103ms | 236.265ms | 2.902ms |

**Delta against the pass bar (56.820ms) first, per `PROH-OPS-07-26`:**

```
this_mean    = 69.191ms
pass_bar     = 56.820ms
delta        = this_mean - pass_bar = +12.371ms
delta_pct    = delta / pass_bar * 100 = +21.78%
```

**Delta against `06-25`'s regression (236.265ms) second, subordinate to the failure above:**

```
regression_mean = 236.265ms
delta           = regression_mean - this_mean = +167.074ms improvement
delta_pct       = delta / regression_mean * 100 = -70.71%
```

`wall_ms_profiled` (this run): 89.384ms / 88.967ms / 87.661ms, mean **88.671ms**.
`attributed_pct` (this run): 96.552% / 96.273% / 96.427%, mean **96.417%** -- comfortably above the
profiler's 90.0% contract; the bucket table below is not an artifact of poor attribution coverage.

## Verdict: **FAIL-BUT-IMPROVED**

**FAILURE**: the reshape does not meet this fix's stated pass condition -- 69.191ms mean is not below
56.820ms, the pre-`06-25` baseline this fix must beat. Option C, even in its best measured version,
remains refuted against the baseline that matters (`PROH-OPS-07-26`) -- this is the headline, stated
first.

Subordinately: the reshape improves substantially on `06-25`'s own regression -- 236.265ms down to
69.191ms, a 70.71% reduction, roughly 3.4x faster than `06-25`'s HEAD. This improvement is real and
attributable (see the share table below), but it is not the result; a result that beats 236.265ms but
not 56.820ms is a FAILURE of this fix, per `PROH-OPS-07-26`, and is recorded as one.

**The planner's pre-registered projection (`06-29-PLAN.md`'s objective, `~70ms`, band `55-90ms`,
projected verdict FAIL) is CONFIRMED, not refuted.** The measured mean, 69.191ms, sits almost exactly
on the projected point estimate and inside the projected band. `06-27` stays blocked.

## Task 1's query-level A/B, quoted for context (kept distinct from the route-level figure above)

From `06-29-SUMMARY.md` (Task 1, this plan): on the same profiled 8-service/8-day seeded database,
the old range-join shape measured a **minimum of 208.3ms** over 3 runs and the reshaped
index-arithmetic shape measured a **minimum of 38.9ms** -- a **5.4x** query-level improvement, with
all 1,344 result tuples tuple-identical between the two shapes. The query-level improvement (5.4x)
is real and demonstrated in isolation; the route-level improvement (3.4x, `236.265ms -> 69.191ms`) is
smaller because other route-level costs (`sql_fetch`, `row_grouping`, `offline_intervals_read`,
`maintenance_coverage`, `attributed_downtime`) do not shrink with this change -- they are unaffected
by it, so as `sql_execute` falls, their share of the (now-smaller) total necessarily grows even
though their own absolute cost is flat.

## Where cost moved (`sql_execute`'s fall is attributed, not just reported -- `PROH-OPS-07-19`)

| bucket | `06-PROFILE-3.md` after-`06-25` share_pct | after-`06-25` tottime_ms | this run's mean share_pct | this run's mean tottime_ms | cost went to |
|---|---|---|---|---|---|
| `sql_execute` | 79.370% | 1018.995 | **42.623%** | **189.200** | the reshaped query itself -- 1018.995ms -> 189.200ms tottime, a **5.386x** fall (consistent with Task 1's own 5.4x query-level A/B, both measured independently) |
| `sql_fetch` | 5.825% | 74.789 | 15.820% | 70.218 | roughly flat in absolute ms (74.789 -> 70.218); share rose only because `sql_execute`'s fall shrank the total |
| `row_grouping` | 3.928% | 50.433 | 10.926% | 48.499 | flat in absolute ms; share rose for the same reason |
| `offline_intervals_read` | 3.735% | 47.949 | 10.539% | 46.782 | flat in absolute ms; share rose for the same reason |
| `maintenance_coverage` | 2.370% | 30.420 | 6.912% | 30.682 | flat |
| `attributed_downtime` | 2.271% | 29.147 | 6.291% | 27.922 | flat |
| `other` | 1.361% | 17.474 | 3.583% | 15.902 | flat |
| `covering_boundaries` | 0.684% | 8.778 | 2.030% | 9.010 | flat |
| `uptime_strip_sql` | 0.381% | 4.890 | 1.080% | 4.793 | flat (the reader's Python wrapper only, as documented at its registration) |
| `json_serialization` | 0.073% | 0.934 | 0.189% | 0.838 | flat |
| `maintenance_windows_read` | 0.004% | 0.051 | 0.009% | 0.038 | flat |

**`sql_execute`'s fall is the entire story here, and it is real, not a share-table illusion**: every
other bucket's absolute `tottime_ms` is within measurement noise of `06-PROFILE-3.md`'s after-`06-25`
figures; only `sql_execute` moved, and it moved by the same ~5.4x the isolated query-level A/B
measured independently. Nothing here contradicts the pre-registered projection's own arithmetic,
which explicitly built in that the reshape only touches `sql_execute`'s cost and nothing else.

## Honesty block (`PROH-OPS-07-09`)

Every millisecond in this report -- `wall_ms_unprofiled`, `wall_ms_profiled`, every bucket's
`tottime_ms` -- was measured on `host_machine=arm64` / `host_node=Williams-MacBook-Pro-635.local`, a
development laptop. None of it is Raspberry Pi latency evidence. The sole authority on absolute
`/api/services` cost on target hardware remains the 289.0ms p50 measured on the Pi control pass at
concurrency 1 (`PI_CONTROL_PASS_P50_MS` in `tests/services_route_profile.py`, unedited by this plan
-- confirmed by `git diff --stat -- tests/services_route_profile.py` showing no change and
`grep -c "HONESTY_CAVEAT\|PI_CONTROL_PASS_P50_MS" tests/services_route_profile.py` still matching
both symbols). Only the proportional attribution and the directional before/after delta measured
here may inform a decision; neither this report's milliseconds nor `06-PROFILE.md`'s stale section 4
growth ratios may be quoted as Pi-class evidence.

## What this report may not conclude

Nothing about Pi latency and nothing about whether OPS-07 passes or fails. A FAIL-BUT-IMPROVED
dev-host wall-time result is a directional signal that the reshape, while a real and substantial
improvement over `06-25`'s regression, does not on this host's SQLite query planner recover to the
pre-`06-25` baseline -- it is not a prediction of concurrency-3 p95 behavior on a Pi 5, and it does
not by itself prove the Pi would show the same shortfall (a different SQLite version, page cache
behavior, or storage medium could in principle behave differently). What it does establish, on the
falsifiable terms this plan set before measuring: the cheap local guard did its job again, and the
planner's own pre-registered projection -- built from this same host's `06-PROFILE-3.md` attribution,
before the reshape existed -- predicted this outcome almost exactly.

## Stop condition

**The verdict is FAIL-BUT-IMPROVED. `06-27` must not be run as written against this build.** The
reshape's own pass condition -- beat 56.820ms -- is not met; it beats 236.265ms substantially but
that was never the bar. `.planning/REQUIREMENTS.md` is unedited by this plan: `OPS-07` stays Pending
(`PROH-OPS-07-08`) -- confirmed by `git status -- .planning/REQUIREMENTS.md` showing no change. Even
on a hypothetical future PASS, `06-27` would still need its build SHAs amended before it could run;
that amendment, like the keep-or-revert decision this FAIL-BUT-IMPROVED verdict poses, belongs to
`06-30`'s checkpoint, not to this report.
