---
phase: 06-workload-resilience-pi-acceptance
plan: 04
subsystem: infra
tags: [apscheduler, threadpool, scheduler-lanes, worker, cadence, sqlite]

# Dependency graph
requires:
  - phase: 06-02
    provides: "The thumbnail TTL/byte-budget reap that J8's cleanup_history now also runs, making J8 measurably heavier than when the lane contention was first identified"
  - phase: 06-01
    provides: "tests/test_workload_resilience.py — the phase's OPS-01..04 integration suite, extended here with CadenceUnderContentionTests"
provides:
  - "A dedicated single-thread 'cleanup' executor lane in the worker scheduler"
  - "J8 (hourly retention/reap) moved off the shared 'metrics' lane onto 'cleanup'"
  - "EXPECTED_EXECUTOR_LANES — a declared, test-pinned source of truth for every scheduled callback's lane"
  - "test_essential_cadence_under_contention — proves J1/J2 hold cadence while every best-effort job runs"
affects: [06-06 pi acceptance harness, future scheduler lane changes]

actuals:
  tokens: 8600
  tasks: 2
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Executor lane ownership declared in a test-pinned map, not only in the scheduler construction"

key-files:
  created: []
  modified:
    - dashboard/beacon/worker_main.py
    - tests/test_worker_ownership_matrix.py
    - tests/test_workload_resilience.py
    - .planning/REQUIREMENTS.md

key-decisions:
  - "J8 gets its own single-thread 'cleanup' lane rather than being moved onto the existing 'probes' pool — a slow reap must not displace service checks either, and a dedicated lane keeps the failure mode isolated to cleanup"
  - "The 'metrics' lane is now reserved for J1 (heartbeat) and J2 (metric sampling) alone, and that reservation is asserted, so a future job quietly parked on it fails a contract test instead of only showing up as a timing symptom under load"

patterns-established:
  - "EXPECTED_EXECUTOR_LANES: lane assignments live in a single declared map that must move in the same commit as the code, or the ownership contract goes red"

requirements-completed: [OPS-01]

coverage:
  - id: D1
    description: "J8's hourly cleanup runs on a dedicated 'cleanup' executor lane, so it can never sit in front of heartbeat or metric sampling on a shared thread"
    requirement: "OPS-01"
    verification:
      - kind: unit
        ref: "tests/test_worker_ownership_matrix.py#test_every_scheduled_callback_declares_its_expected_executor_lane"
        status: pass
    human_judgment: false
  - id: D2
    description: "Essential sampling holds its cadence while every best-effort job runs, judged by the product's own freshness classifier"
    requirement: "OPS-01"
    verification:
      - kind: integration
        ref: "tests/test_workload_resilience.py#CadenceUnderContentionTests::test_essential_cadence_under_contention"
        status: pass
    human_judgment: false

duration: ~25min
completed: 2026-09-01
status: complete
---

# Phase 06 Plan 04: Cleanup Lane Isolation Summary

**The hourly retention/reap pass no longer shares a single thread with the heartbeat and metric sampling every freshness surface in the product depends on — and the cadence guarantee is now asserted, not assumed.**

## Performance

- **Duration:** ~25 min
- **Tasks:** 2
- **Files modified:** 4 (3 source/test + REQUIREMENTS.md)

## Accomplishments

- Added a dedicated `'cleanup'` `ThreadPoolExecutor(1)` lane to `build_scheduler` and moved J8's `executor` from `'metrics'` to `'cleanup'`. The `'metrics'` lane now carries J1 (heartbeat, 5s) and J2 (metric sampling, 5s) only. This closes the one concrete, verified contention risk `06-RESEARCH.md` identified for OPS-01 — and it mattered more by the time it landed, because 06-02 had just added the thumbnail reap to J8's workload.
- Introduced `EXPECTED_EXECUTOR_LANES` in `tests/test_worker_ownership_matrix.py` as the single declared source of lane truth, with `test_every_scheduled_callback_declares_its_expected_executor_lane` asserting every scheduled callback's lane and that the built scheduler actually registers each declared lane. A future regression — parking another job on the essential lane, or dropping the `'cleanup'` lane — fails loudly at contract level rather than surfacing only as an intermittent timing symptom under load.
- Added `CadenceUnderContentionTests::test_essential_cadence_under_contention` to the phase's OPS-01..04 integration suite (+173 lines), using the product's own freshness classifier as the pass/fail oracle rather than a hand-rolled timing threshold.

## Task Commits

1. **Task 1: Give cleanup its own lane and pin every lane assignment under test** — `8cfac52` (feat)
2. **Task 2: Prove essential cadence holds while every best-effort job runs** — `ef3d728` (test)

**Plan metadata:** this commit (docs: complete plan)

## Files Created/Modified

- `dashboard/beacon/worker_main.py` — J8's `executor` changed `'metrics'` → `'cleanup'`; `build_scheduler` gains the `'cleanup'` pool plus a comment documenting what each lane carries and why
- `tests/test_worker_ownership_matrix.py` — `EXPECTED_EXECUTOR_LANES` map + lane contract test
- `tests/test_workload_resilience.py` — `CadenceUnderContentionTests`
- `.planning/REQUIREMENTS.md` — OPS-01 marked complete (checkbox and traceability row)

## Decisions Made

- **Dedicated lane over reusing `'probes'`.** Moving J8 to the existing 2-thread `'probes'` pool would have removed the heartbeat contention but introduced service-check contention in its place. A dedicated single-thread lane keeps a slow reap's blast radius confined to cleanup itself.
- **Lane truth is declared and asserted.** The lane assignment could have been left implicit in `WORKER_CALLBACK_INVENTORY`. Pinning it in a test-visible map makes the OPS-01 guarantee a contract a future change has to consciously break.

## Deviations from Plan

None — plan executed as written.

## Issues Encountered

**The executor process was terminated twice by a host-level API error** (`Your computer went to sleep mid-response`), the first time immediately before it wrote this SUMMARY, the second during the resume attempt that was meant to write it. Both task commits (`8cfac52`, `ef3d728`) had already landed intact and were verified complete against the plan's two tasks before recovery proceeded.

**This SUMMARY was therefore written by the phase orchestrator, not by the executor agent.** That distinction matters for how much weight to give it: the Accomplishments, Files, and Decisions sections are reconstructed from the committed diffs, which are authoritative; the Decisions rationale is inferred from the code comments the executor left in `build_scheduler` and `EXPECTED_EXECUTOR_LANES`, which state the reasoning explicitly, but was not confirmed with the executor. The executor's own account of its intent is lost.

**Verification below was run by the orchestrator, not carried over from an executor self-check.** No executor self-check for this plan was ever observed, so none is claimed.

## Verification

Run by the orchestrator in this worktree at plan close-out:

```
uv run --project dashboard python -m pytest -q \
  tests/test_workload_resilience.py tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py
39 passed, 132 subtests passed in 21.72s
```

**On the phase's known flaky test:** `test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced` has intermittently failed under full-suite load throughout this phase. It is included in the run above and passed. That is evidence but not proof — this run was not under full-suite load, which is the condition that provokes it. The question of whether moving J8 off the `'metrics'` lane affects heartbeat timing was never evaluated by the executor before it was cut off. Reasoning from the diff: the change removes a source of delay from the heartbeat's lane and adds none, so it should reduce rather than increase heartbeat timing pressure — but this is orchestrator inference, not a measurement, and the full-suite result at the phase gate is the real check.

## User Setup Required

None — no external service configuration required. The `'cleanup'` lane is internal to the worker scheduler and needs no new environment variables.

## Next Phase Readiness

Ready. 06-05 (SQLite WAL) touches `db.py`/`inventory.py`/`migrations.py` and does not overlap the scheduler lane work here. The cadence test added here becomes part of the baseline 06-06's Pi acceptance harness runs against.

## Self-Check: NOT PERFORMED BY EXECUTOR

The executor was terminated before any self-check step. The targeted verification above was run by the orchestrator as a substitute and passed, but it is narrower than a full-suite self-check. The authoritative check for this plan is the orchestrator's post-merge full-suite gate.
