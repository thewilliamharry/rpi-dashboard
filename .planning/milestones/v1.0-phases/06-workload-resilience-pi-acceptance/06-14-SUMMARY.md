---
phase: 06-workload-resilience-pi-acceptance
plan: 14
subsystem: testing
tags: [raspberry-pi, load-testing, cpu-sampling, debt-tracking, ops-07]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-11's CPU sampling fix, 06-12's cost profile, and 06-13's reduce-request-cost implementation, all of which this round's hardware run tested"
provides:
  - "A third real Raspberry Pi acceptance run's results recorded against the debt entries they bear on: D-DEBT-06-06 discharged on a working CPU reading, D-DEBT-06-02's revisit trigger evaluated for the first time (NOT TRIGGERED), D-DEBT-06-01 updated with what 06-13's fix achieved on hardware and confirmation that its second reopening test did not fire"
  - "06-ACCEPTANCE-ROUND3.md, a durable record of both hardware reports' key figures"
  - "Two new debt entries: D-DEBT-06-08 (OPS-07 deliberately not promoted this round, following the TEL-06/03-17 precedent) and D-DEBT-06-09 (the failure mechanism is measured to be serialization but not yet attributed to a cause)"
affects: []

# Actuals (#2632)
actuals:
  tokens: 8416
  tasks: 1
  commits: 1

# Tech tracking
tech-stack:
  added: []
  patterns: []

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-ACCEPTANCE-ROUND3.md
  modified:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "The third real Pi acceptance run's overall_passed is false — recorded as failing, not written around, per PROH-OPS-07-01."
  - "D-DEBT-06-01's second named reopening test (unlocked /api/advanced/current recovering while locked routes stay over budget) was evaluated against round-3 hardware and did NOT fire — /api/advanced/current improved only 13.1% and remains over its own budget — so _db_lock is not newly implicated by this round."
  - "D-DEBT-06-02's revisit trigger (sustained CPU percent that starves the host) was evaluated for the first time on a working CPU reading and read NOT TRIGGERED — mean_cpu_percent 165.504 of 400% available leaves roughly 2.3 of 4 cores idle."
  - "D-DEBT-06-06 discharged: 06-11's per-tick psutil.Process caching fix is confirmed on real hardware, producing genuine non-zero CPU figures for both roles."
  - "OPS-07 is deliberately NOT promoted in REQUIREMENTS.md by this round, following the project's own TEL-06/03-17 precedent recorded in STATE.md (a gap-closure round may not certify its own requirement); a new D-DEBT-06-08 entry records this."
  - "A new D-DEBT-06-09 entry records the round's central open finding: the failure is measured to be serialization (a 3.281ms route degrading 74x under concurrency 8 while roughly 2.3 of 4 cores sit idle), but the specific mechanism is not yet attributed. The user's explicit choice for the next round is a diagnostic pass, not a third inferred fix."
patterns-established: []

requirements-completed: []

coverage:
  - id: D1
    description: "06-DEBT.md updated to reflect the third hardware run's actual results across D-DEBT-06-01, D-DEBT-06-02, and D-DEBT-06-06, with D-DEBT-06-03 and D-DEBT-06-05 left unchanged"
    verification:
      - kind: other
        ref: "gsd-tools verify script embedded in 06-14-PLAN.md Task 2 (grep-based presence + REQUIREMENTS.md byte-identity check), executed manually and printed ROUND3_RECORD_OK"
        status: pass
    human_judgment: false
  - id: D2
    description: "REQUIREMENTS.md left byte-identical, OPS-07 still unchecked and still Pending"
    verification:
      - kind: other
        ref: "git diff --quiet -- .planning/REQUIREMENTS.md"
        status: pass
    human_judgment: false
  - id: D3
    description: "06-ACCEPTANCE-ROUND3.md created as a durable record of both round-3 hardware reports' key figures"
    verification: []
    human_judgment: true
    rationale: "The content is a transcription of operator-supplied hardware evidence (Task 1's checkpoint result); a human should confirm the figures were carried through faithfully rather than an automated check re-deriving them from the source JSON reports, which are not present in this repository."

# Metrics
duration: ~15min
completed: 2026-09-02
status: complete
---

# Phase 06 Plan 14: Third Pi acceptance run — recorded as failing Summary

**Third real Raspberry Pi acceptance run recorded FAILED (`overall_passed: false`); D-DEBT-06-06 discharged on a now-working CPU reading, D-DEBT-06-02's starvation trigger evaluated for the first time and read NOT TRIGGERED, D-DEBT-06-01's `_db_lock` reopening test did NOT fire, and a new debt entry records that the failure is measured to be serialization but not yet attributed to a cause — OPS-07 stays Pending.**

## Performance

- **Duration:** ~15 min (Task 2 only; Task 1 was a blocking human-verify checkpoint performed by the operator on real hardware, outside this execution)
- **Tasks:** 1 of 1 in this execution (Task 2 of 2 in the plan; Task 1 was resolved before this agent was spawned)
- **Files modified:** 2 (1 modified, 1 created)

## Accomplishments

- Recorded the third real Pi acceptance run's results in `06-DEBT.md` against every entry the plan named:
  - **`D-DEBT-06-06` discharged.** `06-11`'s per-tick `psutil.Process` caching fix is confirmed on hardware: web role `cpu_sampling.all_samples_zero: false`, `mean_cpu_percent: 165.504`, `peak_cpu_percent: 233.6`; worker role `all_samples_zero: false`, `mean_cpu_percent: 0.698`, genuine cadence-driven idleness (309 non-zero samples, 285 zero samples). This is the first working CPU measurement this phase has produced.
  - **`D-DEBT-06-02`'s revisit trigger evaluated for the first time.** "Sustained CPU percent that starves the host" read **NOT TRIGGERED** — 165.504% mean leaves roughly 2.3 of 4 cores idle on this Raspberry Pi 5, confirming the original no-`cpus:`-cap rationale by measurement rather than by argument.
  - **`D-DEBT-06-01` updated.** `06-13`'s `reduce-request-cost` fix is confirmed to cut `/api/services`'s control-pass p50 27.6% (289.0ms → 209.355ms) and acceptance-pass p95 29.7% (2465.9ms → 1732.3ms) on real hardware — but the acceptance run still fails, with `/api/services`, `/api/scan-status`, and `/api/advanced/current` all over budget. The entry's own second named reopening test (the unlocked `/api/advanced/current` route recovering while locked routes stay over budget) was evaluated for the first time and **did not fire**: that route improved only 13.1% and remains 12.6x over its own control p50 under load. `_db_lock` is not newly implicated.
  - **`D-DEBT-06-07` updated** with the finding that `mem_limit` is declared in `docker-compose.yml` but not kernel-enforced on this Pi host (the kernel lacks cgroup memory-limit support), which tightens rather than loosens the constraint `PROH-OPS-04-05` places on any future worker-count increase.
  - **`D-DEBT-06-03` and `D-DEBT-06-05` left unchanged**, as instructed — no journal-mode reading was captured this round, and the flaky ownership-fencing test is not this round's work.
- Added **`D-DEBT-06-08`** — a new Deferred entry recording that OPS-07's evidence now exists but this round deliberately does not promote it, naming the `TEL-06`/`03-17` precedent from `.planning/STATE.md` and stating that only an independent verification round may promote it.
- Added **`D-DEBT-06-09`** — a new Deferred entry recording the round's central open finding: the acceptance failure is now measured to be a serialization mechanism (a 3.281ms route degrading 74x under concurrency 8 while roughly 2.3 of 4 cores sit idle), explicitly not attributed to `_db_lock` or confirmed as GIL saturation, with the user's chosen next step being a diagnostic round rather than a third inferred fix.
- Created **`06-ACCEPTANCE-ROUND3.md`**, a durable, committed record of both hardware reports' key tables (control pass, acceptance pass, degradation factors, cadence, resources, `cpu_sampling`, `resource_targets`, `scenario`, and the `mem_limit`-not-enforced finding) so a later reader is not dependent on chat history.

## Task Commits

Task 1 (the blocking `checkpoint:human-verify`) was performed by the operator on real hardware outside this execution and produced no code or documentation commit of its own — its result was supplied verbatim to this execution.

1. **Task 2: Record what the third run established, and leave OPS-07 alone** — `e428df8` (docs)

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — `D-DEBT-06-06` moved to Discharged; `D-DEBT-06-01`, `D-DEBT-06-02`, `D-DEBT-06-07` updated with round-3 findings; two new Deferred entries (`D-DEBT-06-08`, `D-DEBT-06-09`) added. `D-DEBT-06-03` and `D-DEBT-06-05` unchanged.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-ACCEPTANCE-ROUND3.md` — new durable record of the round-3 hardware evidence.

## Decisions Made

See `key-decisions` in the frontmatter. The most consequential one for a future reader: the acceptance run still fails, but the failure mode has shifted from "per-request cost" (round 2's diagnosis, now measurably improved by `06-13`) to "serialization under concurrency, mechanism unattributed" (round 3's new finding, recorded in `D-DEBT-06-09`). `_db_lock` is explicitly not implicated by this round's evidence — the entry's own reopening test was run and did not fire.

## Deviations from Plan

None — plan executed exactly as written. Task 1's result was supplied verbatim by the operator and recorded as failing, per the plan's own instruction that "a failing run is a valid outcome of this task and feeds Task 2, which records it as failing rather than writing around it." Task 2's action block was followed entry-by-entry against `06-DEBT.md`'s existing three-section structure and per-entry table format, with no new shape introduced.

## Issues Encountered

None.

## User Setup Required

None.

## Next Phase Readiness

`D-DEBT-06-09` is the load-bearing open item for whatever comes next: the acceptance failure's mechanism is measured (serialization under concurrency-8 load, not per-request cost, not confirmed GIL saturation, not `_db_lock` per the reopening test) but not attributed to a specific cause. The user's explicit choice is a diagnostic round — direct instrumentation of the serialization point under the same concurrency-8 load — rather than a third inferred fix, since two prior single-cause hypotheses (`_db_lock`, then `/api/services`'s per-request cost) have each been proposed and then not confirmed by the following round's hardware evidence. `OPS-07` remains `Pending` in `.planning/REQUIREMENTS.md`, unchanged by this round, per `D-DEBT-06-08` and `PROH-OPS-07-08`.

## Self-Check: PASSED

- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — FOUND (modified)
- `.planning/phases/06-workload-resilience-pi-acceptance/06-ACCEPTANCE-ROUND3.md` — FOUND (created)
- Commit `e428df8` — FOUND in `git log --oneline --all`
- `06-14-PLAN.md` Task 2's embedded verify script printed `ROUND3_RECORD_OK`
- `git diff --quiet -- .planning/REQUIREMENTS.md` confirmed clean
- `git diff --quiet -- dashboard/ tests/` confirmed clean (no code changed)

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-02*
