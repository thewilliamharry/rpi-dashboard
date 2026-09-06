---
phase: 06-workload-resilience-pi-acceptance
kind: acceptance-evidence
build: a7c3ef1 (06-31's revert-plus-reduction; actually deployed at a31d3ba, code-identical -- see 06-PI-PROFILE-C.md Provenance)
measured: 2026-09-06
criterion: amended (concurrency 3, D-DEBT-06-20)
outcome: failed — one route
pairs_with: 06-ACCEPTANCE-C3.md (run 1), 06-ACCEPTANCE-C3-RUN2.md (run 2). Supersedes neither; this phase's convention is that no measurement is superseded, only added to.
---

# OPS-07 third gating run — the revert-plus-reduction, measured under load

Segment B of `06-27-PLAN.md`, run only because segment A (`06-PI-PROFILE-C.md`) returned IMPROVED:
a Pi-class cheap predictor showed `/api/services`' per-request cost fell 45.07% before this ten-minute
run was spent, per `PROH-OPS-07-20`.

## Admissibility

| Property | Value |
|---|---|
| `run_kind` | `acceptance` |
| `lock_profile` | `{}` (empty) |
| `self_test` | `false` |
| `concurrency` | `3` |
| `duration_seconds` | `600` (601s elapsed: `finished_at_epoch - started_at_epoch = 1788708625 - 1788708024`) |
| Diagnostic endpoint pre-run | `404` (confirmed uninstrumented before spending ten minutes) |
| Host | `aarch64` / `raspi` |
| Build | `a7c3ef1` (06-31's revert-plus-reduction: `83f9ce5` + `bcfc73f`), deployed at `a31d3ba`, code-identical per `06-PI-PROFILE-C.md`'s `git diff --stat` check |

All four gating properties (`run_kind`, `lock_profile`, `concurrency`, `duration`) are as declared,
together with `self_test: false` — this run is admissible OPS-07 evidence, `PROH-OPS-07-11`'s
condition for treating it as such.

`service_checks`: **66,005 → 66,035** (before → after, +30 rows over the run's 601s window).
`services`: **7** — the same shape as run 2 (also 7) and one fewer than run 1 (8).

## Result: `overall_passed` FALSE — one route, missing by 162.3ms

cadence PASSED | resources PASSED | response_times FAILED
`failure_reasons`: `/api/services: p95 662.3ms exceeds budget 500ms`

| route | p50 | p95 | max | count | budget | result |
|---|---:|---:|---:|---:|---:|---|
| `/api/services` | 530.1 | **662.3** | 717.9 | 1381 | 500 | **FAIL (+32.5%)** |
| `/api/advanced/current` | 508.2 | 549.6 | 627.0 | 1380 | 2000 | pass |
| `/api/scan-status` | 8.1 | 192.1 | 283.1 | 1380 | 500 | pass |
| `/api/thumbnail/<port>` | 7.8 | 204.8 | 371.5 | 9646 | 1500 | pass |
| `/api/history` | 17.6 | 38.4 | 219.0 | 1380 | 2000 | pass |
| `/api/thumbnail-status` | 8.5 | 11.8 | 194.1 | 1380 | 750 | pass |

`assertions.cadence`: `{"passed": true, "failures": []}` — OPS-01's clause holds. All 12
`background_job_health` rows read `state: succeeded`, no `error_class`. All four `freshness_by_job`
states (`J1`-`J4`) read `fresh` (ages 0s, 0s, 200s, 20s).

## The three-run `/api/services` comparison, each with its own row count

| run | measured | p95 | vs budget | count | dataset shape |
|---|---|---:|---:|---:|---|
| run 1 (`06-ACCEPTANCE-C3.md`, 2026-09-04) | build `a33af15` | 635.6ms | +27.1% | 1355 | 61,387 → 61,502 `service_checks`; 8 services; confounded by a Chromium job (worker peak_cpu 71.0%, peak_rss 786.9 MB) |
| run 2 (`06-ACCEPTANCE-C3-RUN2.md`, 2026-09-05) | build `82801cb` (docs-only ahead of `a33af15`) | 679.3ms | +35.9% | 1278 | 7 services; confound resolved (worker peak_cpu 9.9%, peak_rss 513.0 MB flat) |
| run 3 (this report, 2026-09-06) | build `a7c3ef1`/`06-31`'s revert-plus-reduction | **662.3ms** | **+32.5%** | 1381 | 66,005 → 66,035 `service_checks`; 7 services |

No absolute figure above is read across a changed dataset without its own row count alongside it —
`D-DEBT-06-14`'s lesson. Run 1 and run 2 both predate `06-25`; they measure the pre-optimization Python
producer under the same load shape this run measures the reduced producer under. This run's build is
the first of the three carrying `06-31`'s state-change-only reduction, independently measured at
-45.07% on this same Pi's per-request cost in isolation (`06-PI-PROFILE-C.md`).

**The route did not clear the budget, and it did not clear run 1's figure either.** 662.3ms sits
between run 1's 635.6ms and run 2's 679.3ms — worse than the first independent measurement of this
route's ancestor build, better than the second. Read plainly: **removing 45% of this route's
per-request cost (segment A's own delta) moved the concurrency-3 p95 by 2.5%** (679.3ms → 662.3ms
against run 2, the cleaner of the two prior runs). That gap between the two percentages is this
round's most important number.

## Resources

| role | mean CPU | peak CPU | mean RSS | peak RSS | limit | passed |
|---|---:|---:|---:|---:|---:|---|
| web | 150.2% | 168.2% | 115.6 MB | 117.1 MB | 256 MiB | yes |
| worker | 0.74% | 9.9% | 552.9 MB | 553.6 MB | 1 GiB | yes |

**A fourth distinct worker-memory reading, noted so no single one of the four is treated as the
baseline.** `06-ACCEPTANCE-C3-RUN2.md` recorded three states: run 1's 786.9 MB peak with 71.0% CPU (an
active Chromium preview job mid-run); run 2's 513.0 MB peak, flat against its own mean (a resident
Chromium held alive between jobs, no active render); and rounds 3-5's 54.9 MB (no browser resident at
all). This run's worker RSS — 552.9 MB mean, 553.6 MB peak, essentially flat — sits closest to run 2's
"resident but idle" state, not to run 1's active-job spike or to the no-browser baseline. It passed the
1 GiB limit comfortably and nothing gated on it. Recorded as a fourth data point in the same family as
run 2's reading, not as evidence of a new mechanism.

Web-tier CPU (150.2% mean, 168.2% peak across 594 samples, `sampled_set_changed: false`, 2 PIDs — a
gunicorn master plus one worker) is consistent with `06-ACCEPTANCE-C3-RUN2.md`'s own reading (143.5%
mean) and that report's own resolution: this is a container-wide aggregate across all six route
families, dominated by the single worker process's GIL-released C work (SQLite BLOB reads for
`/api/thumbnail/<port>`'s 9,646 requests this run), not attributable to `/api/services` specifically.

## A finding this run's own shape produces: selective, not uniform, inflation

Segment A measured `/api/services`' single-threaded, uncontended per-request cost at **77.1ms** on
this same Pi (`06-PI-PROFILE-C.md`). Under this run's concurrency-3 load, the same route's p50 is
**530.1ms** — a **6.9x inflation** (530.1 / 77.081 = 6.88) over what the request itself computes.

**The inflation is selective, not uniform across the six exercised routes.** Two routes sit near
500ms p50 under this load — `/api/services` (530.1ms) and `/api/advanced/current` (508.2ms) — while
four sit two orders of magnitude faster and evidently unaffected: `/api/history` (17.6ms),
`/api/thumbnail-status` (8.5ms), `/api/scan-status` (8.1ms), and `/api/thumbnail/<port>` (7.8ms,
despite carrying 7x the request volume of any other route this run).

**What that shape rules out, and what it is consistent with — stated as a hypothesis, not a
diagnosis.** Four routes unaffected, two inflated by comparable amounts, `cadence` and `resources`
both PASSED, worker CPU near zero (0.74% mean) with every background job `succeeded` and every
freshness state `fresh` — that pattern is not consistent with a per-request computation bottleneck
(segment A already measured this route's own computation collapsing 45% on this hardware, and the
p95 barely moved), not consistent with resource exhaustion (both CPU and memory assertions passed
comfortably under their limits), and not consistent with worker starvation or failed background work
(worker CPU is idle, every job succeeded, every freshness state is fresh). It is consistent with
contention on a shared serialization point that specifically affects `/api/services` and
`/api/advanced/current` and not the other four routes — which is exactly the shape round 5's `_db_lock`
instrumentation (`06-LOCK-DIAGNOSTIC.md`, `06-LOCK-DIAGNOSTIC-R5A.md`, `06-LOCK-DIAGNOSTIC-R5B.md`) was
built to measure directly, before `06-18`'s `fix-now` decision redirected the next seven rounds into
narrowing that lock's scope and then into per-request cost attribution instead.

**This run carries no lock instrumentation and cannot attribute the inflation.** `lock_profile: {}` is
precisely what makes this run admissible as OPS-07 acceptance evidence (`PROH-OPS-07-11`); an
instrumented pass is diagnostic evidence only. This report therefore states what the shape is
consistent with, not what caused it. Confirming or refuting the hypothesis would need an instrumented
concurrency-3 pass — the same `BEACON_LOCK_PROFILE=1` methodology round 4 and round 5 used at
concurrency 8, run instead at the concurrency this criterion actually gates on, reported separately
from any acceptance evidence per `PROH-OPS-07-11`. This report proposes that measurement as a
candidate for round 8; it does not schedule or scope it.

**The transferable lesson, stated plainly.** `uptime_sweep` genuinely was 43.727% of `/api/services`'
own profiled self time (`06-PROFILE-2.md`, independently re-measured and confirmed, not the stale
29.975% an earlier profile showed). That attribution was correct. Self time was simply never what this
route's concurrency-3 p95 was made of. Removing 45.07% of per-request cost (segment A's own Pi-class
delta) moved the p95 by 2.5% (679.3ms → 662.3ms, against run 2). A profiler measuring a single
uncontended request cannot see a serialization cost that only exists when other requests are in
flight — and four rounds of this phase's attention went to the quantity the profiler could see.

## OPS-07 disposition — a decision for the operator, not this plan

`/api/services` has now missed its 500ms p95 budget on three independent hardware runs — 635.6ms,
679.3ms, 662.3ms — after a remedy that cut its own per-request cost by 45% on this hardware moved the
concurrency-3 figure by only 2.5%. The operator has questioned whether this budget is worth continuing
to chase, and asked that the disposition be recorded as an explicit decision rather than settled by
another round. This section lays out the options and the evidence behind each, neutrally. **No option
below is recommended, selected, or acted on by this plan. OPS-07 stays Pending regardless of which the
operator eventually chooses (`PROH-OPS-07-08`).**

**Why the budget's own load model is worth re-examining, and why that is a different question from
"the code can't meet it."** `tests/pi_load_acceptance.py`'s own written reasoning for
`ROUTE_BUDGETS_MS['/api/services']` (lines 90-102, verified against source) states: `/api/services`
and `/api/scan-status` are "polled by the dashboard on an interactive cadence (app.js's own poll
loop), so a slow response here is a slow-feeling UI -- tightest budget." The budget exists to protect
a specific, named thing: how the route feels to an operator watching the dashboard update. `dashboard/
app.js` (line 797, verified against source) polls `loadServices` via `setInterval(..., 15000)` — once
every 15 seconds, or **0.067 requests/second** for one operator with one open tab. This run drove
`/api/services` at **1,381 requests in 600 seconds = 2.30 req/s** — inside a total offered load across
all six routes of **16,547 requests / 600s ≈ 27.6 req/s** (9,646 of those, 58%, are thumbnail
fetches). The route-specific ratio is **2.30 / 0.067 ≈ 34.5x** the rate `app.js` actually generates,
driven closed-loop with zero think time — a harness client fires its next request the instant the
prior one returns, which no human operator does.

At the rate the deployment actually serves — one operator, one tab, 0.067 req/s — this route's own
measured cost is segment A's **77.1ms** single-threaded figure, comfortably inside the 500ms budget
with wide margin.

`PROH-OPS-07-01` and `PROH-OPS-07-10` forbid amending a budget **because code could not meet it** —
that prohibition stands, unweakened, and nothing in this section proposes moving
`ROUTE_BUDGETS_MS['/api/services']`. What those prohibitions do not forbid, and what this phase's own
prior amendment already establishes as a legitimate distinct category, is re-deriving a *load model*
that is shown to be wrong about the deployment it purports to represent — the justification is usage,
never difficulty, and `D-DEBT-06-20`'s own concurrency-8-to-3 amendment is the precedent: it was
accepted specifically because the operator stated, and `app.js` confirmed, that 8 concurrent
closed-loop clients did not describe a single-operator dashboard. The 34.5x figure above is offered as
the same category of evidence about the same load model, not as a request to relitigate the criterion
here.

**Three options, each with its evidence, cost and risk. None chosen.**

| | Option | What it does | Evidence for it | Cost | Risk |
|---|---|---|---|---|
| (a) | Accept the deviation and close OPS-07 as a recorded, reasoned exception | Records that this route misses the budget under a synthetic 34.5x-of-real-usage load, and that the operator accepts this given the real usage rate is comfortably inside budget | Segment A's 77.1ms at the real 0.067 req/s rate; three independent hardware runs all missing only under the harness's closed-loop load | Cheapest — no further engineering or measurement | Leaves a permanently-failing acceptance gate in the suite; a future genuine regression at real usage rates could hide behind an already-accepted exception unless the record is read carefully |
| (b) | Re-derive the gate's load model on realistic usage (e.g., a think-time-bearing client shape, or a lower closed-loop concurrency/duration pairing calibrated against `app.js`'s actual polling rate) | Produces a criterion that tests what the deployment actually experiences, rather than a synthetic worst case | `D-DEBT-06-20`'s own precedent (concurrency 8→3, accepted on identical usage-not-difficulty grounds); the 34.5x ratio computed above | Moderate — requires redesigning the harness's request-generation shape, not just a constant, and re-running acceptance evidence against the new model | The precedent this option leans on and the forbidden move (`PROH-OPS-07-01`/`-10`) look identical from outside; the justification must be documented at least as carefully as `D-DEBT-06-20`'s was, or a later reader cannot distinguish this from tuning a budget to pass |
| (c) | A round 8 investigating the contention this report's finding names as a hypothesis | Directly tests whether a shared serialization point (the leading candidate per `_db_lock`'s prior measured history) explains the selective inflation, using the same instrumented methodology round 4/5 already built, at concurrency 3 instead of 8 | The selective-inflation shape above (two routes near 500ms, four unaffected, resources/cadence both clean) and round 5's own prior `_db_lock` measurements at concurrency 8 | Moderate-to-high — an instrumented Pi session plus analysis, and no guarantee the mechanism is fixable without another architectural change | Four of this phase's prior seven rounds already chased a hypothesis that did not fully explain the measured result (`D-DEBT-06-09`, `D-DEBT-06-15`); this could be a fifth if the contention hypothesis also does not fully account for the gap |

## What this run does not do

`git diff -- tests/ dashboard/` is empty at the end of this task: nothing was tuned in response to
this measurement. `git diff -- .planning/REQUIREMENTS.md` is empty: **OPS-07 is NOT promoted by this
round** — the checkbox at line 73 and the traceability row at line 157 both stay `Pending`,
per `PROH-OPS-07-08`. This is the third consecutive independent hardware run in which
`/api/services` misses its budget; none of the three is superseded, softened, or reframed by another.

**No rollup-backed remedy is proposed here, and none should be inferred from this section's options.**
`D-DEBT-06-21`'s round-7 addendum re-refuted `service_rollups` independently and upgraded the
rejection from "not currently populated" to "not reconstructible" — the rollup ladder's fixed
hour-aligned grid cannot losslessly render this strip's sliding-window boundaries at any retention
setting (168/168 rendered buckets straddle an epoch hour, worst error 0.461 on a 3-decimal fraction).
`PROH-OPS-07-29` requires that finding to be read and re-verified against source before any
rollup-backed remedy is proposed a third time; this report does not propose one, and option (c) above
names lock contention, not a rollup rebuild, as its subject.

The deployment ends this run on HEAD, uninstrumented, and running.
