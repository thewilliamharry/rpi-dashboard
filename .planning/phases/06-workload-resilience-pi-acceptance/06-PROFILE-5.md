---
phase: 06-workload-resilience-pi-acceptance
kind: profile-report
created: 2026-09-06
build_before: 79e051e4b2e14130f8c962f06945bafcdaae1cf2 (pre-06-25, 56.820ms reference build, per 06-PROFILE-3.md); 9da5e5e47f024d842a76833cbc6460157e81de44 (06-25 landed, 236.265ms reference build, per 06-PROFILE-3.md); 8a84139 (06-29's reshape, 69.191ms reference build, per 06-PROFILE-4.md)
build_after: 06-31's production commit(s) -- the single-commit revert-plus-reduction (83f9ce5) and its guard commit (bcfc73f), landed at HEAD as of this report's committing SHA (see Provenance)
supersedes: nothing. 06-PROFILE.md, 06-PROFILE-2.md, 06-PROFILE-3.md and 06-PROFILE-4.md are all retained unedited, per this phase's convention of never deleting a measurement.
---

# Does the revert-plus-reduction beat the bar it actually has to clear?

**Purpose:** measure `06-31`'s build -- the revert of `06-25`'s SQL wiring back to the Python
producer `_uptime_summary`, fed a state-change-only reduction of `checks_by_port` in the same
commit -- against the bar this round must clear: the **pre-`06-25` baseline**, never `06-25`'s own
236.265ms regression and never `06-29`'s 69.191ms reshape figure, under a pass condition and a
projection both written down before the measurement (`PROH-OPS-07-26`). This is not Pi latency
evidence (`PROH-OPS-07-09`) and does not claim OPS-07 passes or fails -- see "What this report may
not conclude" below.

## Pass condition (written before the run)

Mean `wall_ms_unprofiled` across three invocations must be **strictly below 56.820ms** -- the
pre-`06-25` baseline `06-PROFILE-3.md` measured on this host, at this seed, at this shape. **Not**
below 236.265ms (`06-25`'s own regression) and **not** below 69.191ms (`06-29`'s reshape). A result
that beats either of those later figures but not 56.820ms is a FAILURE of this round, per
`PROH-OPS-07-26`.

## Pre-registered projection (written before the run)

**~37ms, band 34-42ms. Projected verdict: PASS.**

This projection is unlike rounds 1-6's own pre-registered projections: it is a *reproduction of a
measurement the planner already took on the exact shipping shape* (`06-31-PLAN.md`'s objective) --
a worktree at HEAD with option C's route wiring reverted and the state-change-only reduction
applied -- which measured **36.943ms** mean over three invocations, spread 1.222ms. The same bench
reproduced the `79e051e` baseline at **57.012ms** against `06-PROFILE-3.md`'s **56.820ms**, a 0.34%
agreement, so the host and harness are consistent with the reference this report measures against.
A result above the 34-42ms band is therefore news about the executor's implementation diverging
from the benched one, not noise, and the FAIL branch below is written to be executed rather than
argued around.

## The three outcome branches (written before the run)

**PASS** -- mean strictly below 56.820ms. The reduction closes `06-25`'s regression AND beats the
pre-`06-25` baseline, which no round of this phase has previously done. The projection is
confirmed. `06-27`'s local stop condition under `PROH-OPS-07-20` is lifted; `06-27` still cannot
run as written, because its build SHAs describe a build that no longer exists -- `D-DEBT-06-26`
enumerates that amendment. OPS-07 is NOT promoted (`PROH-OPS-07-08`).

**PASS-PROJECTION-REFUTED** -- mean strictly below 56.820ms but outside the 34-42ms band. The fix
passes and the planner's projection is REFUTED; the refutation is recorded as a refutation, in its
own sentence, and the gap is attributed before the pass is treated as settled. `PROH-OPS-07-19`: a
bucket's disappearance from a profile is never reported as a saving until the cost it moved to has
been measured.

**FAIL** -- mean at or above 56.820ms. This is a failure of the fix, stated as the headline
sentence, whatever it beats. The stop-and-revert branch executes: revert `06-31`'s production
commit, confirm the suite returns green at the reverted state, record the revert and the measured
number in this report and in `06-DEBT.md`, and leave `06-27` blocked under `PROH-OPS-07-20`. The
bar, the harness, the seed, the shape and the repeat count are not adjusted in response
(`PROH-OPS-07-01`, `PROH-OPS-07-10`, `PROH-OPS-07-26`). No fourth branch is opened for a near-miss.

**This skeleton -- pass condition, projection and all three branches -- was written to disk and
committed BEFORE the measurement below was run**, per this task's own discipline requirement: six
rounds of this phase have produced numbers whose interpretation was settled after they arrived.
This skeleton was committed as `304cde5`; that commit predates every measured figure in this
report, exactly as `06-PROFILE-4.md`'s skeleton was committed as `0b06e24` before its own
measurement was run.

## Provenance

| | |
|---|---|
| Host | `arm64` / `Williams-MacBook-Pro-635.local` -- a development laptop, **not Pi latency evidence** |
| Build measured | `HEAD` at commit `a7c3ef1` (the merge landing `06-31`'s production commits `83f9ce5` (feat: revert + reduction) and `bcfc73f` (test: mutation guards)), full suite green at `993 passed, 593 subtests passed` immediately before this measurement (precondition) |
| Reference builds | `79e051e` (pre-`06-25`, 56.820ms, `06-PROFILE-3.md`); `9da5e5e` (`06-25` landed, 236.265ms, `06-PROFILE-3.md`); `8a84139` (`06-29`'s reshape, 69.191ms, `06-PROFILE-4.md`) |
| Seed | `20260902` (default -- identical to every prior profile report this phase) |
| Services | 8 |
| Days | 8 |
| Repeats per invocation | 5 |
| Invocations | 3, run back-to-back on this host |

Invocation (identical to `06-PROFILE-3.md`'s and `06-PROFILE-4.md`'s in every argument):

```
uv run --project dashboard python tests/services_route_profile.py \
    --services 8 --days 8 --repeats 5 --output <json> --min-attributed 0
```

**Same-session baseline recheck, run for attribution below, not as a fourth invocation of the
build under test.** To distinguish an ordinary host-session speed difference from a genuine
implementation difference, the pre-`06-25` reference build (`79e051e`) was re-profiled once, in
the same session, via a detached `git worktree add --detach` checkout outside this worktree
(never rewriting this worktree's own history, identical method to `06-PROFILE-2.md`'s
before/after comparison), then removed with `git worktree remove --force` immediately after.
Result: **53.287ms** `wall_ms_unprofiled` (single invocation) against `06-PROFILE-3.md`'s
three-invocation mean of **56.820ms** for the same build -- a **-6.22%** session-level difference,
used only in the attribution section below, never substituted for the frozen 56.820ms pass bar.

## Headline: `wall_ms_unprofiled`, this run vs all three references

| | run 1 | run 2 | run 3 | mean | spread (max-min) |
|---|---|---|---|---|---|
| This run (HEAD, `06-31`'s build) | 31.512ms | 32.670ms | 32.016ms | **32.066ms** | 1.158ms |
| Pre-`06-25` (`79e051e`, `06-PROFILE-3.md`) | 56.931ms | 56.827ms | 56.701ms | 56.820ms | 0.230ms |
| `06-25` (`9da5e5e`, `06-PROFILE-3.md`) | 238.005ms | 235.688ms | 235.103ms | 236.265ms | 2.902ms |
| `06-29` reshape (`8a84139`, `06-PROFILE-4.md`) | 70.301ms | 68.048ms | 69.224ms | 69.191ms | 2.253ms |

**Delta against the pass bar (56.820ms) first, per `PROH-OPS-07-26`:**

```
this_mean    = 32.066ms
pass_bar     = 56.820ms
delta        = this_mean - pass_bar = -24.754ms
delta_pct    = delta / pass_bar * 100 = -43.57%
```

**Deltas against the two later, non-bar reference figures, subordinate to the above:**

```
vs 06-29's reshape (69.191ms): delta = -37.125ms (-53.65%)
vs 06-25's regression (236.265ms): delta = -204.199ms (-86.43%)
```

`wall_ms_profiled` (this run): 56.349ms / 56.727ms / 56.231ms, mean **56.436ms**.
`attributed_pct` (this run): 94.540% / 94.662% / 94.718%, mean **94.640%** -- comfortably above the
profiler's 90.0% contract; the bucket table below is not an artifact of poor attribution coverage.

## Verdict: **PASS-PROJECTION-REFUTED**

**PASS**: 32.066ms is strictly below the 56.820ms pass bar (`PROH-OPS-07-26`) -- the reduction
closes `06-25`'s regression AND beats the pre-`06-25` baseline, which no round of this phase has
previously done. This is the headline, stated first, per the delta above.

**The planner's pre-registered projection (~37ms, band 34-42ms) is REFUTED, not confirmed --
stated as a refutation in its own sentence, not silently absorbed into the PASS.** The measured
mean, 32.066ms, sits **below the bottom of the projected band** (1.934ms under the 34ms floor,
13.20% under the 36.943ms point estimate the planner's own pre-planning bench measured on this
exact shipping shape). A result below a narrow, reproduction-sourced band is exactly the kind of
divergence this report's own pre-registered text said to treat as news, not noise -- attributed
below rather than waved through as unqualified upside (`PROH-OPS-07-19`).

**Attribution of the gap between the projection and this measurement.** The same-session baseline
recheck above (`79e051e` re-profiled in this session at 53.287ms against `06-PROFILE-3.md`'s
56.820ms, a -6.22% session-level difference) shows this session runs measurably faster end-to-end
than the sessions that produced `06-PROFILE-3.md`'s and `06-PROFILE-4.md`'s reference figures --
consistent with `06-PROFILE.md`/`06-PROFILE-2.md`'s own precedent of a ~1.7ms (~3%) session-to-session
drift on this same host, scaled up here in relative terms only because the absolute figure being
measured (~32-37ms) is roughly a sixth the size of that earlier pair's (~56-58ms) baseline, so the
same order of absolute host variance reads as a larger percentage. Applying this session's own
-6.22% scaling factor to the planner's 36.943ms projection predicts **34.646ms** -- inside the
band's lower edge. That accounts for **roughly two-thirds of the gap** between the projection and
the actual 32.066ms result (36.943ms -> 34.646ms is a 2.297ms move; the total gap is 4.877ms). **The
remaining ~2.580ms (7.45% of the session-scaled projection) is NOT accounted for by host-session
variance and is recorded as an open, unattributed residual** rather than rounded away or assigned a
mechanism this report has no evidence for -- candidates not distinguished by this measurement
include a difference between the planner's specific pre-planning invocation and this profiler
harness's own default seeded database state, or genuine additional headroom in the shipped
reduction beyond what the calibration bench measured. Per `PROH-OPS-07-19`, no bucket's
disappearance or shrinkage is claimed as a saving beyond what is attributed above.

`06-27`'s local stop condition under `PROH-OPS-07-20` is lifted by this PASS -- `06-27` still
cannot run as written, because its build SHAs describe a build (`8a84139`/`9da5e5e`) that no longer
exists at HEAD; `D-DEBT-06-26` enumerates that amendment. OPS-07 is NOT promoted by this report
(`PROH-OPS-07-08`) -- see the Stop Condition below for the check that proves
`.planning/REQUIREMENTS.md` was not touched.

## Where cost moved (`uptime_sweep`'s fall is attributed, not just reported -- `PROH-OPS-07-19`)

Mean tottime_ms across the three invocations above, compared against `06-PROFILE-4.md`'s
(`06-29`'s reshape, the immediately preceding report) after-figures:

| bucket | `06-PROFILE-4.md` (06-29 reshape) share_pct | 06-29 tottime_ms | this run's mean share_pct | this run's mean tottime_ms | cost went to |
|---|---|---|---|---|---|
| `sql_execute` | 42.623% | 189.200 | **1.042%** | **2.945** | the bulk SQL aggregation is no longer called at all -- `api_services` no longer invokes `beacon_repositories.read_uptime_strips_by_port`; `sql_execute`'s residual 2.945ms is ordinary per-service point-fetch SQL, close to `06-PROFILE-3.md`'s own pre-`06-25` figure (3.386ms) |
| `uptime_sweep` | -- (absent, 0 calls) | -- | **4.254%** | **12.023** | the reduced Python producer reappears -- `_uptime_summary` executes again, but fed a state-change-only subset of `checks_by_port` rather than every raw row. Against the pre-`06-25` full-sweep figure this same bucket measured before any of this round's changes (`06-PROFILE-3.md`: 43.942% share, **240.059ms** tottime), this run's 12.023ms is a **19.97x fall** (240.059 / 12.023), consistent with `06-31-SUMMARY.md`'s own differently-seeded differential measuring a 19.3x fall on its own fixture -- the reduction, not a vanished computation, is what shrank this bucket |
| `uptime_strip_sql` | 1.080% | 4.793 | -- (absent, 0 calls) | -- | the reader's Python wrapper is no longer called (the bulk SQL path left the request path entirely) |
| `row_grouping` | 10.926% | 48.499 | **26.210%** | **74.087** | grew in absolute ms (48.499 -> 74.087) because the two-consumer loop (`checks_by_port` AND `points_by_port`) is restored inside `api_services`, matching `06-25`'s own before-figure call count almost exactly (this run: 227,238 calls; `06-PROFILE-2.md`'s pre-`06-25` figure: 226,848 calls, a 0.17% difference consistent with ordinary seeded-database session variance) -- the reduction trims what is STORED into `checks_by_port`, not what is ITERATED over building it, so this bucket's cost tracks raw row count, not the reduced output |
| `sql_fetch` | 15.820% | 70.218 | 24.800% | 70.100 | flat in absolute ms (70.218 -> 70.100); share rose only because `sql_execute`'s fall shrank the total, the identical pattern `06-PROFILE-3.md`/`06-PROFILE-4.md` already documented for this bucket |
| `offline_intervals_read` | 10.539% | 46.782 | 14.406% | 40.721 | roughly flat, slightly down |
| `maintenance_coverage` | 6.912% | 30.682 | 10.378% | 29.333 | flat |
| `attributed_downtime` | 6.291% | 27.922 | 10.065% | 28.448 | flat |
| `other` | 3.583% | 15.902 | 5.360% | 15.150 | flat |
| `covering_boundaries` | 2.030% | 9.010 | 3.108% | 8.785 | flat |
| `json_serialization` | 0.189% | 0.838 | 0.302% | 0.854 | flat |
| `maintenance_windows_read` | 0.009% | 0.038 | 0.0147% | 0.0417 | flat |

**`sql_execute`'s collapse and `uptime_sweep`'s reappearance are two sides of the same revert, and
both are attributed above, not merely reported as a net win.** `row_grouping`'s growth is the
measured cost the two-consumer loop's restoration reintroduced -- real, attributed, and smaller
than the pre-`06-25` two-consumer figure it approximately reproduces, not a new regression.

## Honesty block (`PROH-OPS-07-09`)

Every millisecond in this report -- `wall_ms_unprofiled`, `wall_ms_profiled`, every bucket's
`tottime_ms`, and the same-session baseline recheck -- was measured on `host_machine=arm64` /
`host_node=Williams-MacBook-Pro-635.local`, a development laptop. None of it is Raspberry Pi
latency evidence. The sole authority on absolute `/api/services` cost on target hardware remains
the 289.0ms p50 measured on the Pi control pass at concurrency 1 (`PI_CONTROL_PASS_P50_MS` in
`tests/services_route_profile.py`, unedited by this plan -- confirmed by `git diff --stat --
tests/services_route_profile.py` showing no change and
`grep -c "HONESTY_CAVEAT\|PI_CONTROL_PASS_P50_MS" tests/services_route_profile.py` still matching
both symbols). Only the proportional attribution and the directional before/after delta measured
here may inform a decision; neither this report's milliseconds nor any stale prior report's growth
ratios may be quoted as Pi-class evidence.

## What this report may not conclude

Nothing about Pi latency and nothing about whether OPS-07 passes or fails. A PASS-PROJECTION-REFUTED
dev-host wall-time result is a directional signal that the revert-plus-reduction genuinely and
substantially improves on `06-25`'s regression and on the pre-`06-25` baseline itself, on this
host's SQLite query planner and this host's session -- it is not a prediction of concurrency-3 p95
behavior on a Pi 5, and it does not by itself prove the Pi would show the same magnitude of
improvement (a different SQLite version, page cache behavior, storage medium, or CPU architecture
could in principle behave differently, and the ~2.58ms unattributed residual above is exactly the
kind of gap a Pi run could resolve differently). What it does establish, on the falsifiable terms
this report set before measuring: the cheap local guard did its job, the fix beats the bar it
actually had to clear, and the planner's own pre-registered projection -- itself sourced from a
reproduction of this same build's own measured behavior -- was numerically wrong in a way this
report attributes rather than absorbs.

## Stop condition

**The verdict is PASS-PROJECTION-REFUTED, which is a PASS against this report's own pass condition.**
No stop-and-revert branch executes. `.planning/REQUIREMENTS.md` is unedited by this task: `OPS-07`
stays Pending (`PROH-OPS-07-08`) -- confirmed by `git status --short .planning/REQUIREMENTS.md`
printing nothing. `06-27`'s `PROH-OPS-07-20` stop condition is lifted by this PASS, but `06-27`
still cannot run as written against a build description that no longer matches HEAD -- its build
SHAs, its decision-gate reference, and its `PROH-OPS-07-20` resolution all need amendment, which
`D-DEBT-06-26` enumerates rather than editing `06-27-PLAN.md` directly, per the append contract.
