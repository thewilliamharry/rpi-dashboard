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
committed BEFORE the measurement below was run**, per this task's own discipline requirement: five
rounds of this phase have produced numbers whose interpretation was settled after they arrived.
