---
phase: 06-workload-resilience-pi-acceptance
plan: 12
kind: profile-report
created: 2026-09-02
---

# `/api/services` cost attribution — where the residual 289.0ms goes

> Input to `06-13`'s blocking fix-path decision. This report names cost centres and measures
> growth ratios; it does not choose a fix. `06-13` Task 1 makes that decision against this
> evidence.

## 1. What this is and is not

Every absolute millisecond figure in this report — `wall_ms_unprofiled`, `wall_ms_profiled`, and
every bucket's `tottime_ms` — was measured on **this run's own host**, named below via
`platform.machine()` / `platform.node()`. These figures are **not** Raspberry Pi latency
evidence (`PROH-OPS-07-09`). The **289.0ms p50** the operator measured on the real Pi control pass
at concurrency 1, zero contention (`06-DEBT.md` `D-DEBT-06-01`, `06-VERIFICATION.md`) **remains the
sole authority on absolute per-request `/api/services` cost.** What this report contributes, and
what may be carried into `06-13`'s decision, is:

- the **proportional attribution** (`share_pct` / `attributed_pct`) of that residual cost to named
  sub-computations, and
- the **measured growth ratios** of each sub-computation against a measured stored-check-row
  ratio.

`cProfile` itself adds real per-call instrumentation overhead, and that overhead is **not** evenly
distributed: it inflates Python-heavy buckets (loops, comprehensions, dataclass construction, the
window-occurrence walk) relative to SQL-bound buckets, where most wall time is spent inside the
C-level `sqlite3` driver, outside cProfile's per-line accounting. `wall_ms_unprofiled` is reported
alongside `wall_ms_profiled` in every run below precisely so a reader can see how much the
instrument itself perturbed the measured total, rather than reading `wall_ms_profiled` as this
route's real-world cost on this host, let alone on a Pi.

**Host this report was measured on** (emitted in both JSON reports as `host_machine` /
`host_node`): `arm64` / `Williams-MacBook-Pro-635.local` — an Apple Silicon development laptop,
not the `aarch64` Raspberry Pi target the 289.0ms figure was measured on. Absolute numbers below (e.g. "252ms") describe this laptop's CPU, storage and SQLite build.
They are not comparable to Pi timings even though both report `aarch64`/`arm64`-family
architectures; a Pi 4/5-class SBC's single-thread CPU performance is a fraction of a current-model
Apple Silicon laptop's. Only the share percentages and growth ratios below carry forward.

## 2. How it was measured

Profiler module: `tests/services_route_profile.py` (this plan's Task 1/2 deliverable). It drives
the real route through `appmod.app.test_client().get('/api/services')` — never re-implemented or
partially called — under `cProfile.Profile()`, discards the first request of each run as a
warm-up (so connection setup and import-time cost are never attributed to a per-request bucket),
and classifies every `pstats` self-time ("tot") entry into one of the eleven `PROFILE_PHASES`
buckets declared in that module, redistributing an unmatched builtin/leaf entry's cost to its
caller's bucket (`_classify_with_call_graph`) so that generator expressions, comprehensions,
`datetime` arithmetic, and small undeclared helper calls a matched function makes are not
misattributed to `other`.

**Attribution run** (the plan's real deployment shape — the one this section's `attributed_pct`
figure is asserted against, at the profiler's default `--min-attributed 90.0`):

```
uv run --project dashboard python tests/services_route_profile.py \
    --services 8 --days 8 --repeats 5 --output /tmp/beacon-profile-full.json
```

**Growth run** (2-versus-8 days across the same 8 services):

```
uv run --project dashboard python tests/services_route_profile.py --growth \
    --small-days 2 --large-days 8 --services 8 --repeats 3 --output /tmp/beacon-growth-full.json
```

Both commands exited 0 on this run, regenerating both JSON reports fresh rather than reading stale
files (`T-06-60`'s mitigation).

**Seed and dataset shape.** `--seed` was left at the profiler's default, `20260902`, in both runs,
so the dataset is exactly reproducible. `seed_pi_representative_dataset` sizes the seeded
`service_checks` volume against the deployment's real cadence (`dashboard/beacon/worker_main.py`
J3: every 300s per service; J4: down-only every 60s during a deterministic ~10%-of-window offline
fraction), not an invented row count, and seeds one enabled `maintenance_windows` row on the
first port (`port 20000`) so the maintenance-attribution buckets are exercised on a real,
non-trivial window set rather than only their empty-window fast path.

- **Attribution run** (8 services, 8 days): read back with `SELECT COUNT(*) FROM service_checks`
  at the same seed/shape → **25,278** stored check rows.
- **Growth run, small side** (8 services, 2 days): **5,949** rows.
- **Growth run, large side** (8 services, 8 days): **25,278** rows (same shape as the attribution
  run, same seed → identical row count, confirming the seeding is deterministic).
- **Measured `check_row_ratio`** (large / small, read back, not assumed from the `--days`
  arguments): **4.249**.

**Warm-up-discard rule and the profiling-overhead caveat** are both implemented in
`profile_services_route` and repeated in the module's own docstring and CLI `--markdown` output —
see §1 above.

## 3. The attribution table

Attribution run: 8 services, 8 days, 5 repeats, seed `20260902`. `wall_ms_unprofiled` **90.995ms**
(mean of 5 unprofiled requests), `wall_ms_profiled` **169.717ms** (mean of 5 requests under
`cProfile` — nearly 2x the unprofiled figure, illustrating the profiling-overhead caveat above:
read the share percentages, not either absolute figure, as the transferable evidence).

**`attributed_pct`: 98.653** — clears the profiler's 90.0 default (`--min-attributed`) on its own
exit code; both commands in §2 exited 0.

| bucket | tottime_ms | calls | share_pct |
| --- | ---: | ---: | ---: |
| uptime_sweep | 252.160 | 1,131,142 | 29.975 |
| maintenance_coverage | 249.416 | 813,090 | 29.649 |
| sql_fetch | 131.402 | 35 | 15.620 |
| offline_intervals_read | 86.364 | 430,126 | 10.266 |
| row_grouping | 42.757 | 126,811 | 5.083 |
| attributed_downtime | 35.655 | 30,025 | 4.238 |
| sql_execute | 19.665 | 50 | 2.338 |
| **other** | 11.334 | 9,706 | 1.347 |
| covering_boundaries | 9.635 | 16,860 | 1.145 |
| monitoring_operations_binding | 1.960 | 120 | 0.233 |
| json_serialization | 0.851 | 85 | 0.101 |
| maintenance_windows_read | 0.032 | 25 | 0.004 |

Shares sum to 100.0 by construction (every `pstats` entry lands in exactly one bucket, including
`other`); `attributed_pct` is 100 minus `other`'s share.

## 4. The growth table

Growth run: 8 services, small=2 days (5,949 rows) vs. large=8 days (25,278 rows), 3 repeats,
seed `20260902`. **Measured `check_row_ratio`: 4.249.** Small-side `attributed_pct`: 95.633;
large-side: 98.212 — both individually clear 90.0 too.

Interpretation rule (declared in `tests/services_route_profile.py` and applied mechanically, not
by eye): a bucket whose `growth_ratio` is at or above half the `check_row_ratio` (≥ 2.125 here) is
classified `proportional_to_check_count`; below that, `not_proportional_to_check_count`.

| bucket | small_tottime_ms | large_tottime_ms | growth_ratio | classification |
| --- | ---: | ---: | ---: | --- |
| covering_boundaries | 0.749 | 5.790 | 7.730 | proportional |
| maintenance_coverage | 19.784 | 149.637 | 7.564 | proportional |
| row_grouping | 5.399 | 28.172 | 5.218 | proportional |
| attributed_downtime | 5.236 | 21.757 | 4.155 | proportional |
| uptime_sweep | 38.420 | 150.176 | 3.909 | proportional |
| offline_intervals_read | 14.998 | 56.692 | 3.780 | proportional |
| monitoring_operations_binding | 0.369 | 1.387 | 3.759 | proportional |
| sql_fetch | 20.369 | 69.141 | 3.394 | proportional |
| sql_execute | 4.177 | 12.360 | 2.959 | proportional |
| **other** | 5.023 | 9.023 | 1.796 | not proportional |
| maintenance_windows_read | 0.019 | 0.028 | 1.474 | not proportional |
| json_serialization | 0.470 | 0.571 | 1.215 | not proportional |

Every bucket that measures a computation walking stored check rows (`uptime_sweep`,
`offline_intervals_read`, `attributed_downtime`, `sql_fetch`, `sql_execute`, `row_grouping`) grows
close to or above the check-row ratio, as expected. Two results are worth naming explicitly
because they are not obvious from the bucket names alone:

- **`maintenance_coverage` and `covering_boundaries` are themselves proportional to stored check
  count**, even though the maintenance-window *table* itself never grew across the two runs (still
  one row, on one port). Their cost is driven by the number of **offline intervals** the port with
  a window accumulates — which itself scales with the check-row volume — not by window-table size.
  This is the discriminating evidence the interpretation rule exists to produce: it is not simply
  "more days, everything grows equally."
- **`maintenance_windows_read` stays flat (1.474, well below half of 4.249)**, confirming by
  measurement — not by argument — that the one bulk-per-port-list window read `06-08` already
  added is genuinely check-count-independent, exactly as its own docstring claims.

## 5. The named finding

**06-VERIFICATION.md's recorded expectation is PARTIALLY CONFIRMED.** It named "the per-service
`_uptime_summary` sweep plus the `attributed_downtime_seconds`/offline-interval computation" as the
likely residual. Summing the buckets that expectation names — `uptime_sweep` (29.975%) +
`attributed_downtime` (4.238%) + `offline_intervals_read` (10.266%) — accounts for **44.479%** of
the measured self time. That is real and substantial: `uptime_sweep` alone is the single largest
bucket. But it is **not the majority**, and a comparably large cost the prediction did not name at
all — **`maintenance_coverage`, at 29.649%, effectively tied with `uptime_sweep` for the largest
single bucket** — is measured here for the first time.

**What `maintenance_coverage` actually is.** Direct instrumentation (not shown as its own
`PROFILE_PHASES` bucket boundary, measured separately while writing this report) found
`beacon_maintenance.coverage()` is called **29,985 times across the 5-repeat attribution run** —
roughly **5,997 times per single `/api/services` request** — even though only **one** of the 8
seeded services (`port 20000`, the one port carrying the seeded maintenance window) has any
maintenance window to evaluate; the other 7 ports' `attributed_downtime_seconds` calls iterate an
empty `windows` list and return near-instantly. `attributed_downtime_seconds`
(`dashboard/beacon/maintenance.py`) splits each offline interval into segments at every maintenance
occurrence's boundary and calls `coverage()` once per resulting segment; `coverage()` in turn calls
`_local_occurrence_epochs` — a fresh walk of `MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS + 1` (= 3)
calendar days of fold-aware `datetime` construction — on **every single call**, with no memoization
across the thousands of calls one request makes for the same window. `_local_occurrence_epochs`
alone measured 44,960 calls / 204.6ms cumulative time across the 5-repeat run (≈41ms/request) — the
single most expensive leaf this report found. **This means the maintenance-attribution cost this
plan measured is not proportional to "one service has a maintenance window" in a fixed sense — it
is proportional to how many offline intervals that one service has accumulated**, which the
growth table (§4) confirms directly: `maintenance_coverage`'s growth ratio (7.564) *exceeds* the
check-row ratio (4.249), because more retained days means both more check rows and more
(independently re-walked) offline-interval segments for that one service.

**The second unnamed-by-the-prediction cost, tested directly per this plan's instruction: the
duplicate full-window `service_checks` scan.** `api_services` (`dashboard/app.py:2806-2809`)
issues one `SELECT ts, port, online FROM service_checks WHERE port IN (...) AND ts >= ? ORDER BY ts
ASC` covering the whole `CHECK_RETENTION_SECONDS` window into `checks_by_port`.
`read_service_offline_intervals_by_port` (`dashboard/beacon/repositories.py:1148-1153`) then issues
its own `in_window_rows` query over the *same* `port IN (...) AND ts >= ? AND ts <= ?` bounds. A
direct row-count check at this report's seeded 8-service/8-day shape (25,278 total rows) confirms
both hypotheses the plan asked this report to test:

- **The rows genuinely overlap.** `api_services`'s own read returns all 25,278 rows.
  `read_service_offline_intervals_by_port`'s second read of the identical bounds returns
  **20,000** rows — **79.1%** of the same data, re-fetched.
- **That second read is already hitting its own row cap at this realistic scale.** 20,000 is
  exactly `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` (`dashboard/beacon/repositories.py:1104`). At 8
  services with 8 days of J3/J4-cadence checks, the bulk offline-interval read is **already
  silently dropping ~21% (5,278 rows) of in-window data** for the highest-numbered port(s), per
  that constant's own documented at-limit behavior. This was not something `06-VERIFICATION.md` or
  `06-DEBT.md` predicted, and it is a correctness-adjacent finding, not only a performance one: a
  production deployment at or above this scale may already be reconstructing incomplete offline
  intervals for its highest-numbered service(s), silently. This report does not fix it
  (`PROH-OPS-07-01`, this plan's own scope fence) — it is named here as a fact this measurement
  surfaced, for `06-13` or a follow-up to weigh.
- Attributing `sql_fetch`'s 131.402ms by caller (a direct-instrumentation check, not part of the
  committed profiler's bucket table): of `fetchall`'s total cost, `api_services`'s own three
  `fetchall()` calls account for ~69.2ms, `read_service_offline_intervals_by_port`'s two
  `fetchall()` calls (one boundary query returning 0 rows in this seeded shape, one 20,000-row
  in-window query) account for ~46.1ms, and `read_maintenance_windows_by_port`'s one call accounts
  for ~23.1ms. The duplicate-scan query is a real, separately measurable fraction of the largest
  single bucket after the two named-and-confirmed ones.

**Verdict: partially confirmed, with a materially incomplete original prediction.** The named
computations are real contributors and the single largest bucket (`uptime_sweep`) is exactly what
was predicted. But treating "the sweep plus attributed-downtime/offline-interval computation" as
*the* residual understates the picture: `maintenance_coverage`'s uncached, per-segment
window-occurrence re-walk and the duplicate full-window `service_checks` read are comparably large
(29.649% and a material share of `sql_fetch`'s 15.620% respectively) and were not named at all.

## 6. What this does not establish

- **Host difference.** This profile ran on `arm64` / `Williams-MacBook-Pro-635.local`, a
  development laptop, not the Pi target. CPU microarchitecture, storage medium, and the exact
  SQLite build differ. Only the proportional shares and growth ratios transfer; the milliseconds do
  not (`PROH-OPS-07-09`).
- **GIL contention.** Self-time attribution from a single-threaded `test_client()` run cannot
  separate GIL contention effects, which appear only under concurrent multi-threaded load
  (`--workers 1 --threads 8` in `dashboard/Dockerfile`) and are not exercised here. `D-DEBT-06-01`'s
  evidence about GIL-driven degradation under concurrency-8 load remains a separate line of
  evidence this report does not extend or contradict.
- **Deployment topology.** This profile says nothing about `dashboard/Dockerfile`'s worker/thread
  topology (`--workers 1 --threads 8`). `06-13` must weigh that on `D-DEBT-06-01`'s existing
  evidence, not on this report.
- **Representativeness of the maintenance-window finding.** This report's dominant new finding
  (`maintenance_coverage` at 29.649%) depends on the seeded dataset having *one* service with both
  an enabled maintenance window and a meaningful history of offline intervals. A deployment with no
  maintenance windows configured (a common case — the feature is operator-opt-in, added in Phase
  3.1) would not pay this cost at all; a deployment with more services carrying windows and more
  offline history would pay proportionally more. The growth table's `maintenance_coverage` ratio
  (7.564, exceeding the check-row ratio) shows this cost scales *faster* than raw check-row count
  when it is present, but does not establish how common "present" is across real deployments.
- **The row-cap finding's severity.** This report establishes that
  `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` is reached at 8 services / 8 days in a seeded dataset with a
  10% offline fraction. It does not establish what fraction of real deployments reach that volume,
  nor what the practical impact of the resulting silently-incomplete offline-interval
  reconstruction is on the `maintenance_attributed_seconds` value operators see.

## 7. Candidate fix paths, unranked

No sentence below selects a fix — `06-13` Task 1 is the user's blocking decision, made against
this evidence, not this report's conclusion.

- **Memoize `_local_occurrence_epochs` (or `coverage()`'s output) per `(window, day)` within a
  single `/api/services` request.** `attributed_downtime_seconds` currently re-walks the same
  window's occurrences from scratch on every one of ~750 `coverage()` calls per offline-window-
  carrying service, per request. A request-scoped cache keyed on the window's identity and the
  segment's calendar day could collapse thousands of redundant walks into a handful. Cost: new
  per-request state threading through `attributed_downtime_seconds`/`coverage()`; must preserve
  exact segment-boundary and grace-period semantics (`D-05`'s longest-grace-wins rule).
- **Avoid the duplicate `service_checks` scan.** `api_services` already holds every service's
  checks in `checks_by_port` after its own `all_checks` query; `read_service_offline_intervals_by_port`
  re-reads the same rows a second time. Reconstructing offline intervals from the already-fetched
  `checks_by_port` data (in Python) instead of re-querying SQLite would remove one of the two full
  bulk reads and the row-cap truncation risk with it. Cost: `_offline_intervals_from_points`
  currently operates on rows read with its own boundary/in-window query shape; reusing
  `checks_by_port` would need a compatible boundary-sample derivation and careful equivalence
  proof against the existing `OfflineIntervalsBulkReadTests` oracle.
- **Raise or eliminate `_OFFLINE_INTERVALS_BULK_ROW_LIMIT`.** Independent of the duplicate-scan
  question, the 20,000-row cap is already reached at this report's realistic 8-service/8-day
  shape. Raising it defers the same truncation to a larger deployment; removing it re-opens the
  unbounded-read concern the constant exists to prevent. Cost: needs its own sizing decision against
  real fleet-scale check volume, independent of this plan's scope.
- **Leave `uptime_sweep` as-is.** `06-08` already reduced it from an O(buckets × intervals) rescan
  to a linear sweep; this report's growth measurement (3.909, close to the 4.249 check-row ratio)
  shows it now scales linearly, as designed. Further reduction here would need a genuinely
  different algorithm (e.g. incremental/cached bucket state across requests), a larger change than
  a hot-path fix.
- **Do nothing to `/api/services` itself; address the residual via deployment topology instead.**
  `D-DEBT-06-01` already frames `--workers 1 --threads 8` and the GIL as a live suspect separate
  from any single route's algorithmic cost. This report's findings do not rule that path out —
  they only establish that `/api/services`'s own single-threaded cost is real, attributable, and
  larger than the original prediction described, independent of thread contention.
