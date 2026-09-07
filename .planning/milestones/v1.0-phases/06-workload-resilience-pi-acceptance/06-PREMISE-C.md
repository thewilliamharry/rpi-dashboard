---
phase: 06-workload-resilience-pi-acceptance
kind: premise-verification
subject: D-DEBT-06-21 option C
verified: 2026-09-05
build: fd4a736
verdict: SUPPORTED WITH CORRECTIONS — payoff overstated, shape is not a drop-in
---

# Option C's premise, verified before decomposition

Option C as recorded: "Move the 168-bucket computation into SQL via the existing
`SERVICE_QUERY_SHAPES['raw']` — no new infrastructure, no schema change; targets ~35% of the
profiled residual." Verified against source rather than inherited, per the rule D-DEBT-06-21 earned.

## What holds

The uptime bucket computation **is already expressed in SQL** in this codebase.
`SERVICE_QUERY_SHAPES['raw']` (`dashboard/beacon/repositories.py:269`) builds buckets with a
recursive generator, constructs segments with `LEAD(ts, 1, ?) OVER (ORDER BY ts)`, and clips
intervals per bucket into `online_seconds` / `offline_seconds` / `unknown_seconds`. The approach is
not speculative — a working precedent sits in the same file.

## Three mismatches — the shape is not a drop-in

**1. Bucket origin differs.** The SQL generator is `? - (? % ?)` bound as
`tier_start - (tier_start % display_bucket_seconds)` (`repositories.py:513`) — aligned down to an
absolute epoch multiple. `_legacy_uptime_summary` anchors at `start = now - UPTIME_WINDOW_SECONDS`
(`app.py:1183`), a sliding unaligned origin, and stretches the final bucket to `now`
(`app.py:1225-1226`). The two produce **different bucket boundaries and a different last-bucket
width**. Reusing the shape unchanged alters the rendered 168-value availability strip — a
behavioural change, not an optimization. Needs either a parameterized origin or an accepted
rendering change, decided explicitly.

**2. Sentinel and unknown semantics differ.** Python `intervals` carry binary state only; time with
no observation is *absent* from intervals, so `observed = online + offline`, and a bucket with
`bucket_observed == 0` renders the `-1` sentinel (`app.py:1262`). There is no unknown state at all —
`1 if int(online) else 0` (`app.py:1184`) would raise on a NULL. The SQL shape emits a separate
`unknown_seconds` for `online IS NULL`, hardcodes `gap_seconds` to 0, and its closing `WHERE`
**drops** zero-observation buckets rather than emitting them. Reconstituting a fixed-length 168
array with `-1` sentinels is added work the estimate did not carry.

**3. The shape is per-port; the route's read is bulk.** `get_service_telemetry` takes `port` and
binds `port=?` (`repositories.py:502`). `/api/services` deliberately issues **one** bulk read for
all ports (`app.py:2921-2926`, unbounded by design per D-DEBT-06-10) and loops in Python. Adopting
the shape as-is means N recursive-CTE queries per request, **all inside `_db_lock`** — the route
holds it across the whole block (`app.py:2874`). Round 5 already measured worse on hardware after
moving work across this lock/GIL boundary. A bulk formulation over all ports is a precondition, not
a refinement.

## The payoff is overstated: ~30%, not ~35%

The estimate sums `uptime_sweep` (29.975%) + `row_grouping` (5.083%). But `row_grouping` is the
single loop at `app.py:2933-2940` that builds `checks_by_port` **and** `points_by_port` together,
and the offline-interval reconstruction still consumes those rows — 06 deliberately de-duplicated
that read rather than issuing a second one. Moving uptime into SQL removes neither `row_grouping`
nor `sql_fetch`. Realistic target: **`uptime_sweep` alone, ~30%**, and only if the SQL path is
genuinely cheaper than the swept Python it replaces.

## The larger point C does not address

`06-PROFILE.md` records `maintenance_coverage` at **29.649%** — effectively tied with
`uptime_sweep` for the largest bucket — with a growth ratio of **7.564**, the fastest-growing
bucket measured, exceeding the check-row ratio. C leaves it untouched.

The route is over by 27% (635.6ms vs a 500ms budget). Removing ~30% of self time lands near the
budget **with no margin**, measured against a baseline whose confound is still unresolved. That is
the case for option D landing before C's result is read as attributable.

## What this changes for planning

C remains worth doing. It should be planned as: a **bulk, all-ports** SQL formulation with an
explicitly chosen bucket origin and sentinel reconstruction — not as reuse of an existing
per-port shape. The acceptance evidence must compare against the option-D baseline, not the
2026-09-04 confounded run.
