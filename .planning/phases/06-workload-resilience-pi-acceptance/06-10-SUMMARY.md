---
phase: 06-workload-resilience-pi-acceptance
plan: 10
subsystem: testing
tags: [raspberry-pi, acceptance-testing, resource-monitoring, sqlite, gil, debt-tracking]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance (06-07, 06-08, 06-09)
    provides: corrected resource-sampling oracle, /api/services 8.7x speedup, closed code-review warnings
provides:
  - A real Pi acceptance run (two attempts) with trustworthy resource-provenance evidence
  - A user decision, made on measured hardware evidence, to keep _db_lock unnarrowed
  - 06-DEBT.md updated to match what hardware actually established, including two new entries
affects: [06-secure-phase, future-phase-that-revisits-db_lock-or-cpu-sampling]

actuals:
  tokens: 7363
  tasks: 1
  commits: 1

tech-stack:
  added: []
  patterns: ["debt-ledger sections: Deferred / Decided / Discharged, with per-entry Field/Value table + narrative"]

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-10-SUMMARY.md
  modified:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "Task 2 (user, checkpoint:decision): defer-again — _db_lock stays unnarrowed. The unlocked /api/advanced/current route degraded 29x under load despite never acquiring the lock, which establishes the lock is not sufficient to explain the acceptance run's failure, so narrow-now's precondition ('routes still over budget with /api/services now fast') never held."
  - "D-DEBT-06-04 discharged on execution, not on a passing result — the real Pi run happened across two attempts and its evidence is now trustworthy; overall_passed on the re-run is still false."
  - "New entry D-DEBT-06-06 filed for the acceptance harness reporting 0.0 CPU percent for both roles on both runs despite verified-correct PID resolution — this is the second consecutive round D-DEBT-06-02's revisit trigger could not be evaluated."

requirements-completed: []

coverage:
  - id: D1
    description: "06-DEBT.md updated to reflect the real Pi hardware run: D-DEBT-06-04 discharged, D-DEBT-06-01 re-decided on measured evidence, D-DEBT-06-02's untestable trigger documented, new flaky-test entry (D-DEBT-06-05) and new CPU-sampling-defect entry (D-DEBT-06-06) added, D-DEBT-06-03 left untouched."
    verification:
      - kind: other
        ref: "grep -q D-DEBT-06-05 && grep -q test_heartbeat_renewal_to_persistence_handoff_is_fenced && grep -qi discharged && grep -q D-DEBT-06-03 (plan's automated verify)"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-09-02
status: complete
---

# Phase 06 Plan 10: Pi Acceptance Re-run and Debt Reconciliation Summary

**Real Pi acceptance run FAILED (`overall_passed: false`) with three routes still over budget; the user decided to keep `_db_lock` unnarrowed on that evidence, and `06-DEBT.md` now matches what hardware actually established, including two new debt entries.**

## Performance

- **Duration:** 12 min (Task 3 execution only; Tasks 1-2 were resolved by the user/operator before this continuation was spawned)
- **Tasks:** 1 of 3 executed by this agent (Task 3); Tasks 1 and 2 resolved externally per the resume instructions
- **Files modified:** 1 (`06-DEBT.md`) + this SUMMARY.md

## Accomplishments

- **Task 1 (resolved by operator on real Pi hardware, `aarch64`/`raspi`):** Two hardware runs against this
  round's build (commit `e46a044` and later). Control pass (concurrency 1, 120s): `/api/services` p50
  dropped from a pre-fix 2504.6ms to **289.0ms** — an 8.7x improvement, but short of the plan's predicted
  "tens of milliseconds," still consuming 58% of that route's own 500ms budget at zero contention.
  Acceptance pass (concurrency 8, 600s): **`overall_passed: false`**, with `/api/services` (p95
  2465.9ms vs 500ms budget), `/api/scan-status` (p95 1797.4ms vs 500ms budget), and
  `/api/advanced/current` (p95 2742.1ms vs 2000ms budget) all over budget. **OPS-07's success
  criterion (a passing hardware acceptance run) is therefore NOT satisfied by this round, and Phase 06
  cannot seal on this run.** Cadence passed cleanly (J1-J4 never stale, both runs). `06-07`'s
  resource-targeting fix is confirmed earned on hardware: every sampled PID (web `1745069`/`1745146`,
  worker `1745076`) was independently cross-checked by the operator against `docker inspect
  --format '{{.State.Pid}}' beacon-web beacon-worker` and matched exactly, with no PID tracing to the
  unrelated `/opt/offline-portal` process that corrupted the previous round's resource figures. A new
  harness defect surfaced: `peak_cpu_percent`/`mean_cpu_percent` read exactly `0.0` for both roles on
  both runs despite plausible, load-correlated RSS figures — implausible under load and recorded as a
  broken measurement, not a confirming one.
- **Task 2 (resolved by user, checkpoint:decision): `defer-again`.** `_db_lock`'s scope stays exactly
  as it is; no line touching it changes in this plan. The decisive evidence: `/api/advanced/current`
  does not take `_db_lock` at all (`dashboard/beacon/diagnosis.py` has no lock; this is the pre-existing
  `AR-03-01` accepted-risk route) yet still degraded 80.7ms &rarr; 2344.0ms p50 (29x) under load — a
  lock cannot do that to a caller that never acquires it, which means `_db_lock` is not *sufficient* to
  explain the acceptance run's failure. The evidence instead points at `--workers 1 --threads 8`
  (single-interpreter GIL contention) combined with `/api/services`'s residual Python-side cost.
  Because `defer-again` was chosen: **`T-06-24`'s closure evidence in `06-SECURITY.md` remains valid,
  and `/gsd-secure-phase 06` does NOT need to re-run.**
- **Task 3 (this agent): `06-DEBT.md` updated to match what hardware established.**
  - `D-DEBT-06-04` discharged — but on execution having happened (across two attempts, the first of
    which found the two real defects `06-07`/`06-08` exist to fix), not on the re-run passing.
  - `D-DEBT-06-01` re-decided: recorded the `defer-again` decision, the full evidence chain (control
    numbers, acceptance failures, the unlocked-route 29x regression, a closed-loop arithmetic model,
    and its honest limits), and a sharpened reopening condition — a route whose own service time
    saturates the serialized path again, or a run where the unlocked route recovers while locked
    routes stay over budget (which would newly implicate the lock specifically).
  - `D-DEBT-06-02`'s stated revisit trigger ("sustained CPU percent that starves the host") still could
    not be evaluated — the corrected oracle now samples the right PIDs but the CPU column itself
    returns 0.0 regardless of load, so the trigger has never actually been tested on usable evidence.
  - `D-DEBT-06-03` left unchanged — no journal-mode reading was captured this deployment.
  - New entry `D-DEBT-06-05`: the pre-existing flaky ownership-fencing test
    (`test_heartbeat_renewal_to_persistence_handoff_is_fenced`, ~1-in-20 failure rate, measured
    identical before and after this phase), filed as decided/not-a-regression per `06-UAT.md`.
  - New entry `D-DEBT-06-06`: the harness's 0.0 CPU-percent reading, filed as awaiting a decision since
    nothing this round fixes it, and noted as the reason `D-DEBT-06-02`'s trigger remains untestable.
  - No entry added for work this round actually fixed (`06-07`, `06-08`, `06-09`'s closures).

## Task Commits

Tasks 1 and 2 were checkpoints resolved by the user/operator outside this agent's execution (no commits
from this agent for those tasks).

3. **Task 3: Record what hardware established** - `32781e5` (docs)

_No plan-metadata commit was made by this agent — per this plan's explicit instruction, STATE.md and
ROADMAP.md updates are owned by the orchestrator, not this executor._

## Files Created/Modified
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` - Reorganized into three sections
  (Deferred / Decided / Discharged); `D-DEBT-06-04` moved to Discharged with the two-attempt narrative;
  `D-DEBT-06-01` moved to Decided with the full re-examination evidence and reopening condition;
  `D-DEBT-06-02` updated with this round's failed trigger-evaluation attempt; new entries
  `D-DEBT-06-05` (flaky test) and `D-DEBT-06-06` (harness CPU-sampling defect) added; `D-DEBT-06-03`
  left untouched.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-10-SUMMARY.md` - this file.

## Decisions Made
- **`defer-again` for `_db_lock`** (Task 2, the user): see key-decisions above and the full evidence
  chain recorded in `D-DEBT-06-01`.
- **Section restructuring in `06-DEBT.md`** (this agent, Task 3): added a third section, "Discharged —
  closed this round," to hold `D-DEBT-06-04` distinctly from entries still awaiting a decision
  (Section 1) and entries decided with no further action (Section 2). The plan's instruction to "match
  its per-entry table format... do not introduce a second shape" was read as preserving the
  Field/Value table and narrative convention per entry, not as forbidding a third top-level section;
  a fully-closed entry does not fit either existing section header's semantics ("awaiting a decision"
  or "decided, no further action" implying an ongoing judgment call), so a distinct "Discharged"
  section keeps the ledger's status vocabulary honest.

## Deviations from Plan

None - Task 3 executed exactly as written. The section restructuring described above is a formatting
choice within the plan's own instruction ("match its per-entry table format... do not introduce a
second shape"), not a deviation from the plan's required content.

## Issues Encountered

None during Task 3's execution. Tasks 1 and 2 (resolved externally, before this continuation) surfaced
two substantive findings that are now the phase's central open questions, both fully carried into
`06-DEBT.md`:
1. The acceptance run still fails on real hardware after this round's fixes (`/api/services`,
   `/api/scan-status`, `/api/advanced/current` all over budget at concurrency 8) — OPS-07 is not yet
   satisfied.
2. The acceptance harness's CPU sampling is broken (reads 0.0 under real load), which is itself now
   blocking `D-DEBT-06-02`'s trigger from ever being evaluated.

## User Setup Required

None - no external service configuration required by Task 3. (Tasks 1-2's `user_setup` block, covering
the Pi deployment and load-test execution, was already carried out by the operator before this
continuation began.)

## Next Phase Readiness

**Phase 06 cannot seal on this round's evidence.** The acceptance run's `overall_passed: false` means
OPS-07's success criterion (a passing hardware acceptance run) is not met. What is now known and
recorded:
- `06-07`'s resource-targeting fix is real and independently confirmed on hardware.
- `06-08`'s `/api/services` fix is real but incomplete relative to its own prediction (289ms vs. "tens
  of milliseconds").
- The remaining over-budget routes point at GIL contention under `--workers 1 --threads 8` combined
  with `/api/services`'s residual per-request cost, not at `_db_lock` — per the unlocked
  `/api/advanced/current` route's own 29x regression.
- The acceptance harness's CPU sampling needs its own fix (`D-DEBT-06-06`) before `D-DEBT-06-02`'s
  trigger can ever be meaningfully tested.
- **The two raw JSON reports (`beacon-control-c1.json`, `beacon-acceptance.json`) currently exist only
  on the Pi host at `~/projects/rpi-dashboard/` and are NOT committed to this repository** — this
  plan's `files_modified` covered only `06-DEBT.md`, so no plan branch attempted to commit them. A
  future plan that continues this investigation should pull those reports into the repo as evidence if
  they are still needed after this write-up.

## Self-Check: PASSED

- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — FOUND (modified, committed)
- `.planning/phases/06-workload-resilience-pi-acceptance/06-10-SUMMARY.md` — FOUND (this file)
- Commit `32781e5` — FOUND in `git log --oneline`
- Automated verify (`DEBT_RECORD_OK`) — PASSED

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-02*
