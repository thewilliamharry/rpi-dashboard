---
phase: 06-workload-resilience-pi-acceptance
plan: 15
subsystem: diagnostics
tags: [lock-instrumentation, db-lock, diagnostics, measurement, ast-guard]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-14's third hardware run and D-DEBT-06-09's attribution of the concurrency failure to _db_lock's 155-line critical section"
provides:
  - "dashboard/beacon/lockprofile.py: a default-off InstrumentedLock wrapping _db_lock, recording wait and hold nanoseconds per Flask route"
  - "GET /api/diagnostics/lock-profile: per-route wait/hold snapshot, 404 when disabled"
  - "instrument_cost_ns_per_acquisition, derived and reported — the error bar every hold figure must carry"
  - "An AST scope pin proving _db_lock's scope is unchanged, mutation-verified against the round-5 narrowing shape"
affects: ["06-16", "06-17", "06-18"]

actuals:
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "A diagnostic that is inert by default and proves its inertness by a zero call count on its own timer, not by a type check"
    - "Recording outside the instrumented lock's critical section so the collector's own lock is never nested inside it (T-06-77b)"

key-files:
  created:
    - dashboard/beacon/lockprofile.py
    - tests/test_lock_profile.py
  modified:
    - dashboard/app.py
    - dashboard/beacon/config.py
    - docker-compose.yml

key-decisions:
  - "The raw release happens BEFORE the collector records, so the collector's lock is never held inside _db_lock's critical section (T-06-77b). Recording under the lock would both inflate hold and add real contention to the thing being measured."
  - "The microsecond-scale overhead arm asserts NO ratio, by design. At tens-of-microseconds a fixed per-acquisition cost is inherently a large relative inflation, so a ratio gate would be either vacuous or noise-driven. It derives instrument_cost_ns_per_acquisition instead and gates only a generous 328us ceiling."
  - "Mutual-exclusion workers are daemon threads. This is load-bearing, not hygiene — see Issues Encountered."

patterns-established:
  - "A mutation test must FAIL, not HANG. A hang reads as infrastructure trouble rather than a red build, and costs far more than a red test."
---

# Plan 06-15: default-off `_db_lock` instrumentation

**Status:** Complete. Rescued and closed out by the orchestrator after the executor stalled — see
*Issues Encountered*.

## The deliverable that matters downstream

```
instrument_cost_ns_per_acquisition = 1469.1 ns
  (bare=14,872,610ns  instrumented=15,607,160ns  over 500 acquisitions)
  developer-machine evidence — PROH-OPS-07-09; the Pi's figure will be larger
```

`06-18` §1 must quote this beside **every** reported hold figure. It is negligible against
`/api/services`' ~209ms hold and potentially decisive against `/api/scan-status`' predicted near-zero
hold — which is exactly why the round predicts a near-zero hold there. If scan-status's measured hold
is not distinguishable from the instrument, the required honest reading is *"hold is at or below the
instrument's resolution"*, not *"hold is zero"*.

## What was built

`dashboard/beacon/lockprofile.py` wraps `_db_lock` only when `BEACON_LOCK_PROFILE` is set, recording
wait and hold nanoseconds per Flask route and exposing them at `/api/diagnostics/lock-profile`
(404 when disabled). 17 tests in `tests/test_lock_profile.py`.

## `_db_lock`'s scope is unchanged — the evidence

| Check | Result |
|---|---|
| `with _db_lock` statement count | **28**, unchanged (3 bare, 25 combined) |
| `api_services` body shape | `[Assign, Assign, With(2785–2938), Return(2940)]` — unchanged |
| Diff against base | **55 insertions, 0 deletions** — a conditional rebinding at the declaration only |
| Four computations still inside the `with` | `offline_intervals_from_points_by_port`, `_uptime_summary`, `coverage`, `attributed_downtime_seconds` |

`test_api_services_lock_scope_containment_and_termination` is **mutation-verified against the
round-5 narrowing shape**: removing `_uptime_summary` from inside the `with` fails it with
`{'_uptime_summary'} is not false : _db_lock's SCOPE changed: ... D-01 and PROH-OPS-04-02 fence
exactly this scope.` That mutation is the precise edit a future round would make to narrow the lock,
and the pin catches it.

This is the replacement evidence retiring `T-06-24`'s diff-based closure. It asserts 28
`with _db_lock` statements plus the critical section still enclosing the four computations — **not**
that the call sites are byte-identical to their prior text. Stated at that strength deliberately.

## Verification

| Check | Result |
|---|---|
| Lock-profile tests | 17 passed in 2.30s |
| Full suite, quiet tree | **876 passed, 561 subtests, 0 failed** (up from 859 — this plan adds 17) |
| Scope pin vs. the narrowing mutation | FAILS as designed, message names D-01 / PROH-OPS-04-02 |
| Mutual exclusion vs. release-skipping mutation | FAILS `acquisitions 1 != 2400`, terminates in 120s |

## Issues Encountered

**The executor stalled with all its work uncommitted.** While mutation-verifying
`test_mutual_exclusion_survives_instrumentation` — deliberately breaking the lock to prove the test
catches it — the release-skipping mutation deadlocked the interpreter for ~8 minutes. The executor
had completed the implementation and all 17 tests but had made **zero commits**, despite the plan
requiring a commit per task.

Orchestrator recovery: preserved every uncommitted file before touching the worktree, killed the
deadlocked pytest process tree, confirmed the executor's own mutation revert had landed, verified
the scope pin and the full suite independently, and committed the work in three commits with this
SUMMARY.

**The deadlock was itself a finding, and it is now fixed.** `join(10)` already bounds the *wait*, so
a lock that loses mutual exclusion still reaches the assertions. But the workers were **non-daemon**,
so a thread blocked forever on a never-released lock prevents the *interpreter* from exiting: pytest
prints its result and then hangs. `daemon=True` fixes it, verified — with the mutation applied the
test now fails `acquisitions 1 != 2400` and terminates in 120.12s.

Worth noting which assertion caught it: `max_occupancy` stayed at 1, because with the release skipped
only one thread ever enters. The catch came from the acquisitions count. Two assertions, and the
second one earned its place.

## What this does not establish

Nothing about the Pi. Every figure here is developer-machine evidence (`PROH-OPS-07-09`), including
the instrument cost, which will be larger on the Pi's slower CPU. This plan builds the instrument;
`06-16` decomposes what it records, `06-17` turns it into a verdict, and only `06-18` puts it on real
hardware. And nothing here bears on whether the `_db_lock` attribution is correct — that is precisely
what the instrument exists to confirm or refute.
