---
phase: 06-workload-resilience-pi-acceptance
kind: profile-report
created: 2026-09-05
supersedes_shares_in: 06-PROFILE.md
build: ca28683 (docs-only ahead of a33af15; no code change since)
---

# `/api/services` cost attribution, re-measured

`06-PROFILE.md` (2026-09-02) profiled a build that predates **06-13**'s
`maintenance_occurrence_cache` memo (`4352198`), which targeted one of its two largest buckets and
is still in HEAD. Its shares could not size an optimization round. This run replaces them.

Same instrument, same invocation, same default seed (`20260902`), same shape — 8 services, 8 days,
5 repeats — so the two are directly comparable:

```
uv run --project dashboard python tests/services_route_profile.py \
    --services 8 --days 8 --repeats 5 --output <json> --markdown <md>
```

Host `arm64` / `Williams-MacBook-Pro-635.local` — a development laptop, **not Pi latency evidence**
(`PROH-OPS-07-09`). Only share percentages carry forward. `attributed_pct` **96.376%**, above the
profiler's 90.0 contract. `wall_ms_unprofiled` 58.533ms vs `wall_ms_profiled` 111.616ms.

## Shares, then and now

| bucket | 2026-09-02 | 2026-09-05 | |
|---|---|---|---|
| `uptime_sweep` | 29.975% | **43.727%** | ← now the dominant cost |
| `row_grouping` | 5.083% | **16.083%** | tripled |
| `sql_fetch` | 15.620% | 14.246% | |
| `offline_intervals_read` | 10.266% | 7.415% | |
| `attributed_downtime` | 4.238% | 6.629% | |
| `maintenance_coverage` | 29.649% | **5.479%** | ← 06-13's memo banked |
| `covering_boundaries` | — | 1.591% | |

**Two findings, both decision-grade.**

1. **06-13's memo worked.** `maintenance_coverage` fell from 29.649% to 5.479%. Nothing else in the
   record confirmed this; it was assumed. Re-attacking that bucket would have been re-fixing a
   solved problem.
2. **`uptime_sweep` is now 43.727%**, not the 29.975% the stale report showed — it did not get more
   expensive, the total got smaller around it. Option C targets a substantially larger share of the
   current cost than the withdrawn arithmetic assumed.

## What this means for option C's sufficiency

Against run 2's measured **679.3ms p95**, removing `uptime_sweep` entirely projects to ~382ms —
inside the 500ms budget with ~118ms of margin, against a run-to-run variance of 44ms.

**That projection is optimistic and must not be planned against as a point estimate.** The profiler
states its own bias: cProfile inflates Python-heavy buckets relative to SQL-bound ones, and
`uptime_sweep` is the most Python-heavy bucket in the table (1,131,112 calls). Overall instrument
inflation here is ~1.9x (58.533ms → 111.616ms). `uptime_sweep`'s real share is therefore **below**
43.727%, by an amount this instrument cannot quantify.

The honest range: C alone lands somewhere between ~382ms and the ~475ms the previous, lower share
implied. Both are inside budget. **C alone is now plausibly sufficient** — which the withdrawn
"~60% scoping" reasoning got right by accident and for the wrong reason.

## What C still cannot remove

`row_grouping`, now 16.083%, builds `checks_by_port` **and** `points_by_port` in one loop
(`dashboard/app.py:2933-2940`); the offline-interval path consumes the latter regardless of where
uptime is computed. Its call count rose from 126,811 to 226,837 at an identical dataset shape,
consistent with that loop having taken on the de-duplicated second consumer. `06-PREMISE-C.md`'s
finding stands: C removes `uptime_sweep`, not `row_grouping`.

## Not re-measured

The growth ratios in `06-PROFILE.md` §4 are equally stale — `maintenance_coverage`'s 7.564 was the
headline there and that bucket has since collapsed. A `--growth` run was not made here. Growth is
not needed to size C, but no growth figure from the old report may be quoted.
