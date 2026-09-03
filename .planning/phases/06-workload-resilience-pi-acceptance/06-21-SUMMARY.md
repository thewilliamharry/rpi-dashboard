---
phase: 06-workload-resilience-pi-acceptance
plan: 21
subsystem: infra
tags: [lock-profile, sqlite, db-lock, hardware-evidence, gil-contention, load-testing]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-20's narrowed api_services _db_lock critical section, evaluate_narrowing_outcome/NARROWING_OUTCOME_PREDICTIONS from 06-19, and the 0.745-0.82 estimate range D-DEBT-06-15 recorded"
provides:
  - "06-LOCK-DIAGNOSTIC-R5A.md -- the narrowing's measured effect on real Raspberry Pi hardware, post-fix: worked mechanically (Python share collapsed as designed), regressed under load (utilisation, total hold and three routes' p95 all moved the wrong direction)"
  - "narrowing_outcome verdict transcribed verbatim -- REFUTED at concurrency 1, INCONCLUSIVE under load -- and evaluate_lock_attribution's post-fix re-read (5/5 HELD, up from 4/5 pre-fix)"
  - "D-DEBT-06-01, D-DEBT-06-09, D-DEBT-06-15 updated with the measured result; new D-DEBT-06-18 recording the regression, its GIL-contention mechanism, the revert option held in reserve, and the user's direction for 06-22's remedy"
affects: [06-22-topology-fix, 06-23-post-remedy-acceptance, 06-24-secure-phase-rerun]

actuals:
  tokens: 11926
  tasks: 2
  commits: 1

tech-stack:
  added: []
  patterns:
    - "Same-run derived figures (a route's hold median back-calculated from two directly-reported fields, e.g. a ratio check times a hold-median check) presented as arithmetic over named fields, never as a third field pretending to be directly reported"

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC-R5A.md
  modified:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "The measured regression is recorded plainly, not softened or explained away, per the task's explicit instruction: narrowing_outcome reads REFUTED (concurrency 1) and INCONCLUSIVE (concurrency 8), and evaluate_lock_attribution reads MORE strongly confirmed post-fix (5/5) than pre-fix (4/5) -- the opposite of what a working fix would show. Both verdicts are transcribed verbatim from the harness, not composed in prose."
  - "The regression is not read as grounds to revert 06-20 on its own -- the concurrency-1 control pass shows the narrowing produced a genuine 34.8% utilisation reduction with no queue to reabsorb the freed time into; the mechanism is specifically an interaction with the still-unaddressed GIL-bound /api/advanced/current route, which 06-22 has not yet remedied. New D-DEBT-06-18 names the revert option in reserve, gated on 06-23's post-remedy re-measurement."
  - "A third full-suite-load-sensitive test (HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing, first flagged as a one-off in 06-20-SUMMARY.md) was observed failing on 2 of 2 full-suite runs this plan's own verification performed, always passing cleanly in isolation. Recorded as a D-DEBT-06-13 addendum rather than fixed -- this plan is explicitly code-free (git diff --quiet holds for dashboard/ and tests/)."

patterns-established: []

requirements-completed: []

coverage:
  - id: D1
    description: "The narrowing's post-fix effect measured on real Raspberry Pi hardware, in isolation from 06-22's still-pending second change, and recorded as a measured verdict (REFUTED/INCONCLUSIVE) with its full checks table, whichever way it fell"
    verification:
      - kind: other
        ref: ".planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC-R5A.md Section 5 (narrowing_outcome and attribution verdicts transcribed verbatim from beacon-r5a-c1.json / beacon-r5a-c8.json)"
        status: pass
    human_judgment: false
  - id: D2
    description: "The measured utilisation (0.9692) compared against the 0.745-0.82 estimate with arithmetic shown, and the gap attributed to the estimate's two stated assumptions -- both shown falsified by the same GIL-contention mechanism"
    verification:
      - kind: other
        ref: ".planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC-R5A.md Section 2"
        status: pass
    human_judgment: false
  - id: D3
    description: "D-DEBT-06-01, D-DEBT-06-09, D-DEBT-06-15 updated with the measured post-narrowing figures; new D-DEBT-06-18 records the regression, its mechanism, and the revert option held in reserve; none is marked closed while /gsd-secure-phase 06 and 06-23's re-measurement remain outstanding"
    verification:
      - kind: other
        ref: ".planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md D-DEBT-06-01/-09/-15/-18 sections"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-09-03
status: complete
---

# Phase 06 Plan 21: The narrowing's post-fix hardware measurement — worked mechanically, regressed under load Summary

**`06-20`'s `_db_lock` narrowing moved `/api/services`' Python-side work out of the critical section exactly as designed (held-region Python share `.250 -> .112` under load), and the deployment got measurably worse under real concurrency-8 load anyway — utilisation `0.9639 -> 0.9692` (not the estimated 0.745-0.82), total lock hold up 0.81%, and three of four previously-failing routes' p95 up 26.2-83.3%, because the work released from the lock now competes for the GIL instead of queueing behind it.**

## Performance

- **Duration:** ~25 min (Task 2 documentation + full-suite verification; Task 1's hardware run was operator-executed outside this session)
- **Tasks:** 2 of 2 complete (Task 1: operator-performed blocking checkpoint, pre-verified before this session; Task 2: this session)
- **Files modified:** 2 (1 created, 1 modified)

## Accomplishments

- **`06-LOCK-DIAGNOSTIC-R5A.md` written** — the durable, field-cited record of both post-narrowing hardware passes (concurrency-1 control, concurrency-8/600s loaded), covering Provenance, the in-situ overhead check, the held-region composition (Section 1), hold and utilisation with the estimate comparison (Section 2), the queueing consequence on `/api/scan-status` (Section 3), what the narrowing could not touch on `/api/advanced/current` (Section 4), the narrowing-outcome and attribution verdicts transcribed verbatim (Section 5), and OPS-01/resources (Section 6).
- **The narrowing worked mechanically.** `/api/services`' held-region Python share fell `.576 -> .353` at concurrency 1 (38.7% relative reduction) and `.250 -> .112` under load (55.2% relative reduction), `clamped_python_count` 0 on both passes — trustworthy readings. At concurrency 1, with no queue to reabsorb the freed time, utilisation genuinely fell `0.6653 -> 0.4339` (34.8% reduction).
- **The system regressed under load, on every aggregate that matters.** Utilisation rose `0.9639 -> 0.9692`; total lock hold rose `578,783,964,515ns -> 583,472,152,134ns` (+0.81%, the opposite of the 0.745-0.82 estimate's predicted ~15% cut); `/api/services` p95 +38.6% (2138.5ms -> 2962.9ms), `/api/scan-status` p95 +83.3% (853.0ms -> 1563.9ms), `/api/advanced/current` p95 +26.2% (2217.6ms -> 2799.3ms, on a route this narrowing does not touch); `/api/services`' own throughput fell 11.1% (882 -> 784 completions).
- **The mechanism measured directly.** `/api/advanced/current` — no lock, unmodified by `06-20` — saw its `other_off_cpu_ns_total` nearly double in the same pass (550,980.5ms -> 1,007,408.3ms, +82.9%). `/api/services`' own hold (derived from two directly-reported fields) rose ~3.5% despite its Python share collapsing, because its `sql_share` rose `.748 -> .844` — the SQL still inside the lock got absolutely slower. Total requested CPU across all routes stayed essentially flat (~1.57 -> ~1.575 core-equivalents) while wall-clock and off-CPU time exploded. **Lock contention was converted into GIL contention on this single-interpreter deployment.**
- **One genuine improvement.** `/api/thumbnail/<port>` dropped out of the failure list entirely (p95 1695.6ms -> 1023.0ms against a 1500ms budget), its lock-wait total halving (2,021,760.3ms -> 984,592.1ms). Round 4 had four failing routes; round 5 has three.
- **Verdicts stated as measured, not softened.** `narrowing_outcome`: REFUTED at concurrency 1 (python_share 0.3532 >= 0.2 refutation threshold), INCONCLUSIVE under load (refutation held at 0.1118, all three confirmation checks failed, including the decisive utilisation check at 0.9692 vs 0.85). `evaluate_lock_attribution`: 5/5 checks HELD post-fix, up from 4/5 pre-fix — the lock-serialization attribution reads *more* strongly confirmed after the narrowing, not less, because `/api/services`' hold did not shrink.
- **`D-DEBT-06-01`, `D-DEBT-06-09`, `D-DEBT-06-15` updated** with the measured result, each by scoped addition (no wholesale rewrite). New `D-DEBT-06-18` files the regression's own entry: what was measured, the mechanism, why it is not by itself grounds to revert `06-20`, the revert option held in reserve gated on `06-23`'s post-remedy re-measurement, and the user's already-stated direction for `06-22` — the reversible T-C memo option (`dashboard/beacon/diagnosis.py`'s `get_current_diagnosis`, mirroring `06-13`'s proven memo), not the one-way T-A worker-count door.

## Task Commits

1. **Task 1: Two instrumented passes on real hardware, post-narrowing** — performed by the operator on real Pi hardware before this session (`checkpoint:human-verify`, blocking gate). Results supplied as `06-21-hardware-data.md` and consumed verbatim into `06-LOCK-DIAGNOSTIC-R5A.md`. No commit in this session (no files changed by that step).
2. **Task 2: Write `06-LOCK-DIAGNOSTIC-R5A.md` and update `06-DEBT.md`** — `0327076` (docs)

**Plan metadata:** this SUMMARY's own commit (below).

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC-R5A.md` — new. The durable, field-cited hardware evidence artifact for round 5's first attribution point.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — `D-DEBT-06-01` Status field and new "`06-21` measured" subsection; `D-DEBT-06-09` Status field and new "RE-READ POST-FIX — round 5" subsection; `D-DEBT-06-15` Status field and new "`06-21` measured" subsection; new `D-DEBT-06-18` entry; a short addendum to `D-DEBT-06-13` recording a third full-suite-load-sensitive test observed this session.

## Decisions Made

- **The measured regression is recorded plainly, not softened.** Per the task's explicit instruction, both harness verdicts (`narrowing_outcome`, `evaluate_lock_attribution`) are transcribed verbatim from the two hardware reports, including the checks tables. No prose upgrades a FAILED check or an INCONCLUSIVE verdict, and the regression is stated as measured, not "partially successful."
- **The regression does not by itself imply `06-20` should be reverted.** The concurrency-1 control pass shows the narrowing genuinely reduced utilisation (34.8%) with no queue to reabsorb the freed time into — the mechanism is specifically an *interaction* between the narrowing and the still-unaddressed GIL-bound `/api/advanced/current` route (`D-DEBT-06-15`), not evidence the narrowing is unsound in isolation. `D-DEBT-06-18` names the revert option in reserve rather than exercising it now, gated on `06-23`'s post-`06-22` re-measurement.
- **The already-known full-suite-load-sensitivity pattern (`D-DEBT-06-13`) was observed on a third test** (`HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing`) during this plan's own required-verify step, failing on 2 of 2 full-suite runs (python_share measured 0.6239, then 0.5792, against the 0.5 ceiling) while passing cleanly in isolation both times (2 passed in 0.51s). Recorded as a `D-DEBT-06-13` addendum, not fixed — this plan's own scope forbids touching `dashboard/` or `tests/`, and neither file was touched (`git diff --quiet` holds for both throughout this session).

## Deviations from Plan

### Auto-fixed Issues

None — this plan is documentation-only by design and no code was touched. The one non-trivial judgment call (how to treat the reproducing `HeldRegionCompositionTests` failure against the plan's "no NEW failures outside `D-DEBT-06-13`'s known-flaky set" acceptance criterion) is not a deviation requiring a fix — it is documented above under Decisions Made and in the `D-DEBT-06-13` addendum, per the rule that only issues directly caused by this plan's own changes are in scope for auto-fix, and this plan made no code changes.

---

**Total deviations:** 0 auto-fixed.
**Impact on plan:** None. The plan executed exactly as written for Task 2; Task 1 was the operator's pre-supplied hardware run.

## Issues Encountered

**`HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing` failed on both full-suite verification runs this session performed** (required by Task 2's `<verify>`), each time passing cleanly in isolation. This is the same test `06-20-SUMMARY.md` already flagged as a one-off transient full-suite-load flake; this session's 2-of-2 reproduction is a stronger signal than `06-20` saw. Per this plan's explicit scope (`Do NOT touch dashboard/ or tests/` — an unambiguous instruction from the objective, and this plan's own acceptance criteria require `git diff --quiet -- dashboard/` to hold), the test was not modified. It is recorded as a `D-DEBT-06-13` addendum instead. The full suite otherwise shows **no other failures**: `937 passed, 564 subtests passed, 1 failed` on both runs, the one failure being this already-documented pattern.

**Reading this against the plan's acceptance criterion, stated honestly rather than asserted cleanly.** `06-21-PLAN.md` Task 2's acceptance criteria require "The full suite shows no NEW failures outside `D-DEBT-06-13`'s known-flaky set." This failing test is not literally inside `D-DEBT-06-13`'s originally-named two-test set, but it is the identical *pattern* that entry diagnoses (a small, load-sensitive quantity assertion failing only under whole-suite contention), first observed transiently on this same test by `06-20`, one plan prior. This is recorded as what it is — a third instance of a pre-existing, already-diagnosed-but-unfixed pattern, not a new kind of defect and not caused by any change this plan made (this plan changed zero lines of `dashboard/` or `tests/`) — rather than either silently waved through or misreported as a clean pass.

## User Setup Required

None — no external service configuration required. Task 1's hardware setup (instrumented Pi deployment, both load-test passes, restore to uninstrumented) was performed by the operator before this session began, per the plan's `user_setup` block.

## Next Phase Readiness

- **`06-22`** has the evidence it needs to execute its blocking `checkpoint:decision`: `06-LOCK-DIAGNOSTIC-R5A.md` Section 4's full `/api/advanced/current` request accounting, and `D-DEBT-06-18`'s record of the user's already-stated direction (the reversible T-C memo option). `06-22`'s Task 1 checkpoint still executes formally in that plan's own session — this plan does not preempt it, only records the evidence and context it will be decided against.
- **`06-23`** inherits the closure condition for the new `D-DEBT-06-18`: re-measure on real hardware after `06-22`'s remedy ships, and either confirm the regression recovered (closing `D-DEBT-06-18` on that evidence) or trigger the revert option held in reserve.
- **`06-24`** inherits the still-outstanding `/gsd-secure-phase 06` formal re-run (`PROH-OPS-04-05` prerequisite 4) — unchanged by this plan, which touches no code.
- **`D-DEBT-06-13`** now carries a third data point (this session's 2-of-2 reproduction) that a future round closing that entry should account for when deciding whether to widen its named set or adopt the "measurement-sensitive, excluded from the floor" branch.
- **Guardrails held throughout:** `git diff --quiet -- .planning/REQUIREMENTS.md` (OPS-07 stays Pending, `PROH-OPS-07-08`), `git diff --quiet -- dashboard/`, `git diff --quiet -- tests/` — all confirmed clean at every check in this session.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-03*

## Self-Check: PASSED

- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-DIAGNOSTIC-R5A.md`
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md`
- FOUND commit `0327076` (Task 2)
- Confirmed: `git diff --quiet -- .planning/REQUIREMENTS.md` held throughout this session
- Confirmed: `git diff --quiet -- dashboard/` held throughout this session
- Confirmed: `git diff --quiet -- tests/` held throughout this session
- Confirmed: full suite run twice, `937 passed, 564 subtests passed, 1 failed` both times — the one failure is `HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing`, reproduced 2/2 in full-suite context, passing cleanly in isolation both times (2 passed in 0.51s), pre-existing per `06-20-SUMMARY.md` and documented, not fixed, in `D-DEBT-06-13`
