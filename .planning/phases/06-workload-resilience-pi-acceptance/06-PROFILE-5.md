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
This skeleton was committed as `<SKELETON_COMMIT_PENDING>`; that commit predates every measured
figure in this report, exactly as `06-PROFILE-4.md`'s skeleton was committed as `0b06e24` before its
own measurement was run.

## Provenance

`<PENDING -- filled in after the measurement, not before>`

## Headline: `wall_ms_unprofiled`, this run vs all three references

`<PENDING>`

## Verdict

`<PENDING>`

## Where cost moved (`uptime_sweep`'s fall is attributed, not just reported -- `PROH-OPS-07-19`)

`<PENDING>`

## Honesty block (`PROH-OPS-07-09`)

`<PENDING -- carried verbatim from 06-PROFILE-4.md's form once the measurement lands>`

## What this report may not conclude

`<PENDING -- nothing about Pi latency, nothing about whether OPS-07 passes>`

## Stop condition

`<PENDING>`
