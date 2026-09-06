---
phase: 06-workload-resilience-pi-acceptance
kind: profile-report
created: 2026-09-06
measured: 2026-09-06
build_before: 79e051e4b2e14130f8c962f06945bafcdaae1cf2 (pre-06-25, verified as `9da5e5e^`, the 56.820ms dev-host reference build per 06-PROFILE-3.md)
build_after: a7c3ef1 (06-31's revert-plus-reduction, commits 83f9ce5 + bcfc73f; actually profiled at a31d3ba, code-identical -- see Provenance)
verdict: IMPROVED
supersedes: nothing. 06-PROFILE.md through 06-PROFILE-5.md are all retained unedited, per this phase's convention of never deleting a measurement. This is the first Pi-class figure for this comparison; 06-PROFILE-5.md's PASS is dev-host evidence for the same build.
---

# Segment A — does the revert-plus-reduction's dev-host win reproduce on the Pi it actually has to run on?

**Purpose.** `06-PROFILE-5.md` measured `06-31`'s revert-plus-reduction build on a development laptop
at 34.927ms against a 56.820ms bar -- a PASS, but explicitly not Pi latency evidence
(`PROH-OPS-07-09`). This segment repeats the same before/after comparison, same shape, same seed, on
the Raspberry Pi that gates OPS-07, per `PROH-OPS-07-20`: an acceptance run is never spent on a build
whose own cheap predictor measured worse, and this predictor must itself be run where the acceptance
run will be spent.

**What this report may and may not conclude, stated first.** This is a `cProfile`-instrumented,
in-process measurement of `/api/services` alone. It is diagnostic evidence about per-request cost,
never OPS-07 acceptance evidence (`PROH-OPS-07-11`) -- that is segment B's role, reported separately in
`06-ACCEPTANCE-C3-RUN3.md`. Unlike `06-PROFILE-5.md`, however, this run's absolute milliseconds and
`host_machine`/`host_node` fields ARE Pi-class: `platform.machine()` reads `aarch64` and
`platform.node()` reads `raspi` in every one of the six reports below, so this run's proportional
attribution AND its Pi-class percentage delta may be read as target-hardware evidence, which
`06-PROFILE-5.md`'s dev-host figures never were. The absolute milliseconds themselves remain bounded
by the same caveat every report from this profiler carries: `cProfile` overhead is not evenly
distributed across buckets, and the sole authority on absolute `/api/services` cost on target hardware
is the 289.0ms p50 measured on the Pi control pass at concurrency 1 (`PI_CONTROL_PASS_P50_MS`,
unchanged, unedited by this plan). What is carried into the gate decision below is the **relative
delta between the two builds, measured identically, on the same host, in the same session** -- a ratio,
never an absolute-latency prediction.

## Provenance

| | |
|---|---|
| Host | `aarch64` / `raspi` -- the Raspberry Pi this deployment actually runs on |
| Build profiled (after) | Working tree synced to `origin/main` at commit `a31d3ba`. **Pinned build:** `a7c3ef1` (the merge landing `06-31`'s production commits `83f9ce5` and `bcfc73f`). `git diff --stat a7c3ef1 <tip> -- dashboard/ tests/` was checked against whatever `main` pointed at when the Pi was synced and was **empty** -- every commit since `a7c3ef1` touches only `.planning/`, so `a31d3ba` and `a7c3ef1` are code-identical and the profiler cannot tell them apart. The pin (`a7c3ef1`) is recorded as the build under test, per the plan's own instruction to prefer the pin over the branch tip when the two are shown code-identical. |
| Build profiled (before) | `79e051e` -- the parent of `06-25`'s first production commit. Verified rather than trusted: `git rev-parse 9da5e5e^` was run and printed `79e051e...`, confirming the before-build is the same commit `06-PROFILE-3.md` and `06-PROFILE-5.md` both measure against. |
| Seed / shape | `--services 8 --days 8 --repeats 5`, identical to every prior profile report this phase, unchanged between the two builds |
| Repetitions per build | 3 independent invocations, each internally averaging 5 repeats (`repeats: 5` in each JSON) |
| HEAD before and after | Confirmed matching: the deployment returned to `main` HEAD after profiling the before-build, per the plan's step 5 |

**Methodological note, disclosed rather than smoothed over.** The three after-build invocations were
not taken as one uninterrupted three-run sweep. The operator's first three invocations at the current
build all wrote to the same `-1` output filename and overwrote one another; only the third of those
survives as `beacon-pi-profile-after-1.json`. A further two invocations were then taken separately into
`-2` and `-3`. All three surviving figures are genuine independent invocations of the identical
command against the identical build -- nothing here is fabricated or interpolated -- but they were not
captured back-to-back in one session the way `06-PROFILE-5.md`'s clean re-run was. This is recorded so
a later reader does not assume a tighter methodological guarantee than what was actually taken. The
spread across the three surviving after-figures (1.302ms, 1.7% of their own mean) is tight enough that
this disclosure does not itself cast doubt on the result, but the gap between what was intended (three
back-to-back runs) and what happened (one overwritten pair plus a recovered third, then two more) is
stated here rather than left for a later reader to discover by noticing the file-naming gap.

## Headline: `wall_ms_unprofiled`, six figures, two builds

| | run 1 | run 2 | run 3 | median | mean | spread (max-min) |
|---|---|---|---|---|---|---|
| After (`a7c3ef1`, Pi) | 77.081ms | 76.685ms | 77.987ms | **77.081ms** | 77.251ms | 1.302ms |
| Before (`79e051e`, Pi) | 140.323ms | 142.699ms | 139.074ms | **140.323ms** | 140.699ms | 3.625ms |

`host_machine: aarch64`, `host_node: raspi` in all six of the above -- confirmed in every JSON
(`beacon-pi-profile-after-{1,2,3}.json`, `beacon-pi-profile-before-{1,2,3}.json`).

## The gate, per `PROH-OPS-07-20`

```
after_median   = 77.081ms
before_median  = 140.323ms
delta          = after_median - before_median = -63.242ms
delta_pct      = delta / before_median * 100  = -45.07%
larger_spread  = max(1.302, 3.625) = 3.625ms
delta / spread = 63.242 / 3.625 = 17.4x
```

The delta is 17.4x the larger of the two spreads -- not a marginal call. Per the pre-registered
three-branch decision:

**Verdict: IMPROVED.** The after-build's per-request cost fell by 45.07%, comfortably outside the
observed measurement noise on either build. Task 2 (segment B, the gating acceptance run) proceeds.

## Pi-class delta, stated next to the dev-host figure, as ratios only (`PROH-OPS-07-09`)

| | reduction |
|---|---|
| Dev-host (`06-PROFILE-5.md`, laptop, `34.927ms` vs `56.820ms`) | **-38.53%** |
| Pi-class (this report, `77.081ms` vs `140.323ms`) | **-45.07%** |

`06-PROFILE-5.md`'s dev-host PASS **reproduced on Pi-class hardware, and the Pi-class reduction is
LARGER, not smaller** -- 45.07% against 38.53%, a 6.54-percentage-point wider margin on the hardware
that gates OPS-07 than on the laptop that predicted it. This is stated as a ratio comparison only; no
absolute millisecond figure from either host is compared to the other's, per `PROH-OPS-07-09`.

## Where cost moved, Pi-class (secondary attribution, condensed)

Mean `tottime_ms` and `share_pct` across each build's three invocations, for the buckets that moved
materially:

| bucket | before mean tottime | before mean share | after mean tottime | after mean share | reading |
|---|---|---|---|---|---|
| `uptime_sweep` | 606.259ms | 45.783% | 26.934ms | 4.081% | **22.5x fall** (606.259 / 26.934) -- the state-change-only reduction to `checks_by_port`, same mechanism `06-PROFILE-5.md` measured at 19.59x on the dev host. The Pi shows a larger fall, consistent with the Pi-class wall-clock delta also being larger. |
| `sql_execute` | 5.879ms | 0.444% | 5.980ms | 0.906% | Flat, small, in both builds -- neither build calls the bulk-SQL uptime reader (`read_uptime_strips_by_port`); both use the Python producer `_uptime_summary`. This is the SQL-execute cost of ordinary per-service point fetches, not the SQL reshape option C measured and this segment does not re-litigate. |
| `row_grouping` | 271.543ms | 20.506% | 211.242ms | 32.010% | Absolute cost fell modestly; share rose because the total collapsed around it -- the two-consumer loop (`checks_by_port` and `points_by_port`) is unchanged between these two builds, so this bucket's cost tracks raw row count in both, not the reduction. |
| `attributed_pct` (instrument coverage) | 96.159% mean | -- | 94.186% mean | -- | Both comfortably above the profiler's 90% contract; the bucket table above is not an artifact of poor attribution coverage on either build. |

This table is supplementary attribution, not a re-derivation of the gate: the gate above is decided on
`wall_ms_unprofiled`, per `PROH-OPS-07-20`'s own text, and stands regardless of how the sub-buckets are
read.

## Honesty block (`PROH-OPS-07-09`, `PROH-OPS-07-11`)

This is a `cProfile`-instrumented, in-process measurement of `/api/services` alone, run via
`tests/services_route_profile.py`. It is **diagnostic evidence only and is never OPS-07 acceptance
evidence** -- segment B's uninstrumented, concurrency-3, `run_kind acceptance` pass
(`06-ACCEPTANCE-C3-RUN3.md`) is the acceptance-evidence species, and the two are reported separately
per `PROH-OPS-07-11`. Unlike `06-PROFILE-5.md`, this run's `host_machine`/`host_node` genuinely read
`aarch64`/`raspi`, so its proportional attribution and relative delta are Pi-class evidence in a way
the dev-host report's figures never were -- but the absolute milliseconds are still not a prediction of
concurrency-3 p95 behavior under load; `cProfile` measures a single in-process request with no
concurrent contention, no gunicorn worker/thread topology, and no `_db_lock` interaction. The sole
authority on absolute `/api/services` cost on target hardware under real request-serving conditions
remains the 289.0ms p50 measured on the Pi control pass at concurrency 1
(`PI_CONTROL_PASS_P50_MS`, unedited: `git diff --stat -- tests/services_route_profile.py` shows no
change). `git diff -- tests/` is empty at the end of this task -- no budget, threshold or limit was
touched in response to this measurement.

## What this report may not conclude

Nothing about concurrency-3 acceptance behavior. A cheap, uncontended, single-request measurement
improving by 45% is the evidence that justifies spending ten minutes of Pi time on segment B
(`PROH-OPS-07-20`'s own purpose) -- it is not a prediction of what that ten minutes will show, and
segment B's own result (`06-ACCEPTANCE-C3-RUN3.md`) should be read as independent evidence, not as an
expected confirmation of this report's percentage.

## Stop condition

**The verdict is IMPROVED.** Segment B (Task 2) proceeds. `.planning/REQUIREMENTS.md` is unedited by
this task: OPS-07 stays Pending (`PROH-OPS-07-08`) -- confirmed by `git diff --quiet --
.planning/REQUIREMENTS.md`.
