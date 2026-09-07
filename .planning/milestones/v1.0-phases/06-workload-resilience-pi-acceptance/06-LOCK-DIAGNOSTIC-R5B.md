---
phase: 06-workload-resilience-pi-acceptance
kind: hardware-diagnostic
round: 5b
build: 311a6df
measured: 2026-09-03
outcome: reverted
---

# Round 5b — attribution point two, the acceptance run, and the revert

**Build `311a6df` for all three runs** (segment A and B SHAs verified identical). Host `aarch64`/`raspi`,
Raspberry Pi 5 Model B, `nproc` 4. Dataset 59,772 → 59,914 rows across the session.

This is the record the `ea8689e` revert rests on. It supersedes nothing; `06-LOCK-DIAGNOSTIC-R5A.md`
remains the record of attribution point one.

## Admissibility of the acceptance run

Segment B1's pre-run `curl` printed `000` — the container was mid-restart — not the required `404`.
The plan says stop on anything but `404`, and that step was not satisfied as written. Verified after
the fact instead, with nothing rebuilt in between: the endpoint returned `404`, `BEACON_LOCK_PROFILE`
was `None` in the `beacon-web` container environment, and the report carries no `lock_profile` block.
On that evidence the acceptance run was uninstrumented and is OPS-07-admissible (`PROH-OPS-07-11`).
Recorded here rather than glossed, because the check that was specified is not the check that was run.

## A: r5b-c1 (instrumented, 120s) — overall_passed TRUE, cadence TRUE, resources TRUE
utilisation 0.4050 | clamped_off_cpu 1
services shares: connect .001 sql .681 py .317
latency p50/p95: services 300.1/317.9 | advanced/current 105.8/138.6 | scan-status 3.4/4.5
narrowing_outcome: REFUTED — python_share 0.3174 vs 0.2 refutation threshold
attribution: INCONCLUSIVE (no slow scan-status at c1)
advanced/current: n 258 wall 28,605.9 cpu 28,447.0 lock_wait 0.0 other 158.9

## B: r5b-c8 (instrumented, 600s) — overall_passed FALSE, cadence TRUE, resources TRUE
utilisation 0.9740 (r5a 0.9692, round4 0.9639) | clamped_off_cpu 28
services shares: connect .046 sql .849 py .105
failures: services p95 3045.9 | scan-status p95 1891.2 | advanced/current p95 3249.1
narrowing_outcome: INCONCLUSIVE (python_share .1048 below .2 refutation, above .1 confirmation;
  sql_share .8492 below .85; utilisation .9740 above .85)
attribution: **CONFIRMED** (round 4 was 4/5 held; r5a was 5/5; now a full confirmation)
requests (totals ms):
  advanced/current n 750 wall 1,675,346.5 cpu 584,354.5 lock_wait 0.0 other 1,090,992.1
  services         n 753 wall 1,428,330.1 cpu 324,546.5 lock_wait 838,025.0 other 265,758.6
  scan-status      n 750 wall   521,320.8 cpu   1,473.6 lock_wait 518,305.1 other   1,542.1
  thumbnail/<port> n 5960 wall  927,118.8 cpu  11,221.0 lock_wait 887,018.8 other  28,879.5
  history          n 750 wall   147,871.2 cpu  29,847.0 lock_wait  89,162.6 other  28,861.6

## C: ACCEPTANCE (UNINSTRUMENTED, 600s) — overall_passed FALSE, cadence TRUE, resources TRUE
lock_profile: {} (empty — admissible)
failures: services p95 2917.3 vs 500 | scan-status p95 1892.8 vs 500 | advanced/current p95 3291.9 vs 2000
latency p50/p95: services 1489.4/2917.3 | advanced/current 2532.1/3291.9 | scan-status 636.9/1892.8
  history 105.1/827.5 | thumbnail-status 23.3/34.3 | thumbnail/<port> 22.9/1284.4

## THE FINDING: round 5's production changes made the system materially WORSE

Uninstrumented acceptance, round 3 -> round 5, same scenario (c8/600s), +5.4% data:
  /api/services         p95 1732.3 -> 2917.3   (+68.4%)
  /api/scan-status      p95  656.5 -> 1892.8   (+188.3%)
  /api/advanced/current p95 2382.2 -> 3291.9   (+38.2%)

/api/advanced/current non-lock off-CPU across the three measurements:
  round 4 (pre-narrowing)   550,980ms
  round 5a (post-narrowing) 1,007,408ms
  round 5b (post-memo)      1,090,992ms
T-C did not recover the regression; it deepened.

Round 5's only production changes are 06-20 (narrowing, commit 1a4db68) and 06-22 (memo, afff388).
06-19 was test-only. USER DECISION: revert both. Keep all test infrastructure.
