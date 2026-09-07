---
phase: 06-workload-resilience-pi-acceptance
plan: 31
subsystem: database
tags: [sqlite, uptime, performance, gap-closure, ops-07, guard-decision-revision]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-GUARD-DECISION.md §8's rollup re-scope, D-DEBT-06-21's original refutation of service_rollups' population, and 06-PROFILE-4.md's FAIL-BUT-IMPROVED verdict against the pre-06-25 baseline"
provides:
  - "api_services reverted to calling _uptime_summary (the Python producer) instead of beacon_repositories.read_uptime_strips_by_port, with checks_by_port reduced to state-change points only inside the route's existing all_checks loop"
  - "UptimeStripCoalescingDifferentialTests: 1,813 randomized transition-dense cases (86 carrying a NULL row) proving the reduction is output-identical to _legacy_uptime_summary over the raw route-input subset, plus a route-driven mirror-agreement test"
  - "UptimeStripInputReductionGuardTests: pins the strip producer's input count to state transitions, not stored volume, on both a dense fixture and a mostly-unobserved-window fixture (PROH-OPS-07-25); confirmed to fail when the reduction is removed"
  - "LockScopePreservationTests and 06-LOCK-AUDIT.md realigned a fourth time to the reverted producer and the +42 net line shift"
affects: [06-32]

actuals:
  tokens: 9589
  tasks: 3
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Reduce a Python sweep's input to state-change points only when interval overlap is additive over a contiguous partition -- merging adjacent same-state points is exactly equal, not approximately, and is proven so by a differential over the exact case space the pre-existing correctness oracle uses"
    - "Pin an input reduction's PRESENCE with a dedicated guard (input count vs. stored volume), never rely on a correctness differential alone -- a differential proves a reduction is correct but cannot prove it exists, since unreduced input trivially agrees with itself (measured: 0/1,813 divergences when the reduction is removed)"
    - "When an inline (non-importable) code block is the thing under test, mirror it in the test file with a companion test that drives the real route through a real database and asserts the mirror's output equals what the route actually computed -- proving the mirror stayed faithful to the production code, not merely to itself"

key-files:
  created: []
  modified:
    - dashboard/app.py
    - tests/test_lock_profile.py
    - tests/test_services_route_scaling.py
    - .planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md

key-decisions:
  - "Task 1's blocking checkpoint:decision was pre-resolved by the operator to `reduce-producer-input`, per the prompt's own recorded reasoning: the rollup mechanism is refuted on evidence (D-DEBT-06-21, PROH-OPS-07-29) and cannot render the strip's sliding boundaries even if populated (PROH-OPS-07-15); input reduction is exact by a partition-additivity argument and was measured at 36.943ms against a 56.820ms bar on the shipping shape."
  - "The revert (06-25's SQL wiring) and the reduction (state-change-only input) landed in ONE commit, per the plan's explicit instruction, so the lock-scope pin and 06-LOCK-AUDIT.md realign exactly once rather than twice."
  - "A NULL online row resets last_state_by_port to None (a value no real 0/1 state can equal), guaranteeing the row immediately following a NULL is also always appended -- this is what prevents the measured 39-of-1,813-case (this run's seed; planner reported 39/1,802 on a different seed) divergence a naive null-as-falsy reduction would introduce."
  - "The reduction rule is mirrored (not imported) in tests/test_services_route_scaling.py because Task 2 left it inline in api_services' loop body; a dedicated companion test drives the real route through a real database and asserts the mirror agrees with what api_services actually handed _uptime_summary, so the mirror cannot silently drift from production behavior."

requirements-completed: []

coverage:
  - id: D1
    description: "api_services reverted to the Python producer (_uptime_summary), fed a reduced state-change-only subset of checks_by_port, inside the same, unwidened _db_lock block -- proven output-identical to HEAD's rendered strip"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::ApiServicesOutputEquivalenceTests::test_narrowed_route_reproduces_the_pre_narrowing_response_bytes"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripCoalescingDifferentialTests::test_randomized_histories_agree_between_reduced_and_raw_route_input"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripCoalescingDifferentialTests::test_mirror_agrees_with_the_route_on_its_own_loop"
        status: pass
    human_judgment: false
  - id: D2
    description: "A NULL online row is never coalesced away by the reduction -- the producer refuses the same inputs it refuses at HEAD, with the same exception type"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripCoalescingDifferentialTests::test_null_after_a_same_state_run_is_never_coalesced_away"
        status: pass
    human_judgment: false
  - id: D3
    description: "The strip producer's input count is a function of state transitions, not stored check volume, pinned by a guard that fails when the reduction is removed"
    requirement: OPS-07
    verification:
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripInputReductionGuardTests::test_reduced_input_count_tracks_transitions_not_stored_volume"
        status: pass
      - kind: unit
        ref: "tests/test_services_route_scaling.py::UptimeStripInputReductionGuardTests::test_reduced_input_count_holds_on_a_mostly_unobserved_window"
        status: pass
      - kind: other
        ref: "manual mutation: reduction removed from dashboard/app.py, both guard tests observed to fail, then restored -- git diff --stat dashboard/app.py empty afterward"
        status: pass
    human_judgment: false
  - id: D4
    description: "The _db_lock scope pin and 06-LOCK-AUDIT.md are realigned to the reverted producer, exactly once, without narrowing or loosening the lock's contained scope"
    requirement: OPS-04
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::LockScopePreservationTests::test_api_services_lock_scope_containment_and_termination"
        status: pass
      - kind: unit
        ref: "tests/test_lock_profile.py::LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit"
        status: pass
    human_judgment: false

duration: 65min
completed: 2026-09-06
status: complete
---

# Phase 6 Plan 31: Revert the Rollup Re-scope, Reduce the Producer's Input Summary

**Reverted `06-25`'s bulk-SQL uptime strip wiring back to the Python producer `_uptime_summary`, and in the same commit fed it a state-change-only subset of `checks_by_port` (25,278 candidate points reducing to a handful of transitions in the profiled shape) — output-identical by a partition-additivity argument, proven on 1,813 randomized transition-dense cases plus a route-driven mirror check, never coalescing a NULL row, and proven detectable-by-absence by a dedicated input-count guard a correctness differential alone cannot substitute for.**

## Performance

- **Duration:** ~65 min
- **Tasks:** 3 (Task 1: operator decision, pre-resolved; Task 2: revert + reduction; Task 3: guards)
- **Files modified:** 4

## Accomplishments

- **Task 1 (blocking checkpoint) recorded as decided, not re-prompted.** The operator's prompt context supplied the resolution (`reduce-producer-input`) and its reasoning verbatim; no code moved until that was recorded.
- **One commit reverts `06-25`'s SQL wiring and adds the input reduction.** `api_services` no longer calls `beacon_repositories.read_uptime_strips_by_port`; it restores the pre-`06-25` `checks_by_port` two-consumer read and calls `_uptime_summary(checks, now)` once per service, inside the unwidened `with _db_lock` block. `dashboard/beacon/repositories.py` is untouched — `read_uptime_strips_by_port`, `UPTIME_STRIP_QUERY`, and every `06-29` guard over them (including the narrowed division allowlist) stay in the tree, unedited, and pass.
- **The reduction: `checks_by_port` retains only state-change points.** Inside the `for row in all_checks` loop, a per-port `last_state_by_port` dict tracks the last appended state; a row is appended only when its derived state differs from the port's last (or unconditionally on a NULL `online`, which also resets the tracked state to `None` — a value no real `0`/`1` state can equal — so the row immediately following a NULL is always appended too). `points_by_port` (the offline-interval consumer) is untouched and still sees the full, uncoalesced stream with its original `offline_points_budget` accounting.
- **The reduction is proven output-identical, not asserted.** `UptimeStripCoalescingDifferentialTests` ran 1,813 randomized transition-dense per-port histories (own seed `20260931`, reusing `UptimeStripSqlDifferentialTests`' `_route_input_rows` retention-floor contract) — 86 of which carried a NULL row after a same-state run — asserting `_legacy_uptime_summary` returns the identical tuple (or raises the identical `TypeError`) whether fed the reduced or the raw route-input subset. 27,801 raw points reduced to 14,718. Zero divergences.
- **A companion test proves the test file's mirror matches production, not merely itself.** Because Task 2 left the reduction inline in `api_services`' loop body (nothing importable to call), `test_mirror_agrees_with_the_route_on_its_own_loop` drives the real route through a real seeded database, spies on `_uptime_summary`, and asserts the `checks` list the route actually passed equals this file's `_reduce_to_state_changes` applied to the same seeded rows.
- **A second, independent guard closes the gap a differential cannot see.** `UptimeStripInputReductionGuardTests` pins the strip producer's input count to state transitions, never stored volume — on a dense fixture (2,016 stored rows, 6 retained, transitions-tracked) and, per `PROH-OPS-07-25`, on a fixture whose 7-day window is mostly unobserved (3 stored rows in the final 300 seconds, 2 retained). Both assertions are **confirmed to fail** when the reduction is manually reverted from `dashboard/app.py` (restored afterward, zero residual diff).
- **The two predicted mechanical failures, and only those, were fixed.** `LockScopePreservationTests`' `required_calls` renamed back to `_uptime_summary` (docstring records both the `06-25` and `06-31` renames rather than overwriting history), and `06-LOCK-AUDIT.md` rows 20-28 realigned by the actual +42 net line delta this implementation produced (row 19 and rows 1-19 untouched), recorded as the **fourth** realignment.

## Task Commits

1. **Task 1: The scoped remedy rests on a refuted premise — choose the path before any code moves** — *no commit* (blocking `checkpoint:decision`, pre-resolved by the operator; `reduce-producer-input` selected per the prompt's own recorded reasoning, not re-prompted)
2. **Task 2: One commit — the strip reads state changes, option C leaves the request path, and the pins realign once** - `83f9ce5` (feat)
3. **Task 3: Guards — prove the reduction is exact, prove it refuses what it must, and prove its absence is detectable** - `bcfc73f` (test)

## Files Created/Modified

- `dashboard/app.py` - `api_services` reverted to `_uptime_summary` with `checks_by_port` fed a state-change-only reduction; `beacon_repositories.read_uptime_strips_by_port` no longer called
- `tests/test_lock_profile.py` - `LockScopePreservationTests`' `required_calls` and docstrings renamed back to `_uptime_summary`, recording both renames' history
- `tests/test_services_route_scaling.py` - `UptimeStripCoalescingDifferentialTests` and `UptimeStripInputReductionGuardTests` added (additive only, no existing assertion modified)
- `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md` - rows 20-28 realigned by +42 lines; fourth-realignment note added

## Decisions Made

- **`reduce-producer-input` selected over `build-hot-rollup` and `revert-only`** at Task 1's blocking checkpoint, per the operator's pre-recorded reasoning: the rollup mechanism is refuted on evidence (`D-DEBT-06-21`, `PROH-OPS-07-29`) and cannot render the strip's sliding boundaries even if populated (`PROH-OPS-07-15`); input reduction is exact by a partition-additivity argument, planner-measured at 36.943ms against a 56.820ms bar.
- **The revert and the reduction landed in one commit**, per the plan's explicit instruction, so the lock-scope pin and `06-LOCK-AUDIT.md` realign exactly once.
- **`last_state_by_port` resets to `None` on every NULL row** rather than leaving the prior real state in place, so the row immediately following a NULL is always appended too — the specific hazard the plan named (a naive null-as-falsy reduction silently drops a NULL following an offline run, turning a refusal into a rendered number).
- **The reduction rule is mirrored, not imported, in the test file**, with a route-driven companion test proving the mirror agrees with production — because Task 2 left the reduction inline in `api_services`' loop body rather than as a separate callable.

## Deviations from Plan

### Auto-fixed Issues

None — no bugs, missing functionality, or blocking issues were found beyond what the plan's own predicted failures already anticipated (see below).

### Notes on the plan's own acceptance-criteria wording (not deviations in the implementation)

**1. The literal `grep -c "_uptime_summary(checks, now)" dashboard/app.py` command is unsatisfiable by any correct implementation, including the plan's own pre-registered benchmark shape.** The plan's Task 2 acceptance criteria state this command "returns exactly 1, inside `api_services`." Confirmed by direct measurement against `79e051e` (the pre-`06-25` baseline this plan reverts to, which the plan itself describes as "the exact shape this plan ships"): the same literal grep already returns **4** at that commit, because `_legacy_uptime_summary(checks, now):`, `_uptime_summary(checks, now):` (the def line), and `_uptime_summary(checks, now)[1]` (an unrelated pre-existing caller at line 1271) all contain the searched substring in addition to the one call site inside `api_services`. This implementation reproduces that exact baseline shape and therefore also returns 4 on the literal grep. Verified by the actual intent instead: an AST walk restricted to `api_services`' function body counts exactly **1** call to `_uptime_summary`, matching the criterion's stated purpose. Recorded here rather than silently satisfied-by-reinterpretation, per this plan's own self-audit instruction.

**2. Task 2's acceptance criteria state `git show --stat HEAD lists exactly the four files in this task's files`, but Task 2's own `<files>` element names three files** (`dashboard/app.py`, `tests/test_lock_profile.py`, `.planning/.../06-LOCK-AUDIT.md`). Commit `83f9ce5` touches exactly those three files and no others — matching the task's own file scope. The "four" in the acceptance criteria appears to be a wording slip in the plan text, not a missed file; recorded rather than silently reinterpreted.

---

**Total deviations:** 0 auto-fixed. Two pre-existing plan-text wording issues noted above (neither affected implementation correctness; both verified against the plan's own stated intent and against the reverted baseline's actual shape).

## Mutation Verification (Task 3, required by plan)

Measured on this run's own generator (seed `20260931`, 1,813 total per-port histories, 86 carrying a NULL row — comparable order of magnitude to the planner's pre-registered 1,802/39/1,331/0 on a different seed), against `_reduce_to_state_changes` (this file's mirror, proven faithful to `dashboard/app.py`'s inline reduction by the companion test above):

| mutation | description | divergences (this run) | planner's pre-registered figure |
|---|---|---|---|
| m1 | `online is None` treated as merely falsy — a NULL following an offline run is dropped | **29 / 1,813** | 39 / 1,802 |
| m2 | keep the LAST point of each run rather than the first | **1,293 / 1,813** | 1,331 / 1,802 |
| m3 | remove the reduction entirely (raw input compared to itself) | **0 / 1,813** | 0 / 1,802 |

**m3 is the reason `UptimeStripInputReductionGuardTests` exists as a second, independent class, not a footnote.** A differential can prove a reduction is correct (m1, m2 both caught) but cannot prove it is present — unreduced input trivially agrees with itself, hence 0 divergences for m3 on the differential. `UptimeStripInputReductionGuardTests` is the guard that actually catches m3: it pins the strip producer's Python input count to state transitions, and both of its test methods were directly confirmed to fail (`AssertionError: 0 != 1` / count-tracks-volume assertions failing) when the reduction was manually removed from `dashboard/app.py` (temporarily, then restored — `git diff --stat dashboard/app.py` empty afterward, confirmed).

Mutations m1 and m2 were applied to a standalone script reproducing the exact case-generation and comparison logic (not committed — scratchpad-only, consistent with `06-25`'s and `06-29`'s own mutation-verification method of applying by hand and reverting). m3 was verified two ways: against the standalone script (0/1,813) and directly against `dashboard/app.py` by manually reverting the reduction in the shipped route and confirming `UptimeStripInputReductionGuardTests` fails.

## Issues Encountered

- **A pre-existing, unrelated, load-sensitive test failed once in a full-suite run, then passed on immediate re-run and in isolation.** `tests/test_lock_profile.py::LockProfileInertnessTests::test_millisecond_scale_overhead_ratio` (an instrumentation-overhead timing ratio assertion, unrelated to `dashboard/app.py`'s uptime logic or any file this plan touches) failed once (`1.0544x` against a `1.02x` ceiling) in the first post-Task-3 full-suite run, then passed cleanly on an immediate second full-suite run (`993 passed, 0 failed`) and in isolation. This matches the documented pattern in `06-DEBT.md`'s `D-DEBT-06-13` ("the full suite has become intermittently flaky under load") exactly — a small, load-sensitive quantity assertion sensitive to full-suite scheduler contention, not a regression this plan introduced. Not fixed here (out of this plan's scope per the scope-boundary rule: pre-existing, unrelated file, already tracked phase-wide); no new entry added to `06-DEBT.md` since `D-DEBT-06-13` already names this exact failure class.
- Immediately after Task 2's commit, the full suite ran clean at **988 passed, 593 subtests passed, 0 failed** — exactly the plan's predicted post-fix figure, confirming only the two predicted mechanical failures (the lock-scope pin and the lock audit) needed fixing and nothing else moved.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `/api/services` is back on the Python producer, proven output-identical to HEAD by the existing golden-fixture equivalence tests, the new coalescing differential, and the route-driven mirror check. `dashboard/beacon/repositories.py` (the `06-25`/`06-29` bulk-SQL path) is retained, unreferenced by production, per the operator's `06-GUARD-DECISION.md` §8 decision — `06-32` is where that debt is recorded, not this plan.
- **`06-32` inherits:** the projection this plan's objective made (`~37ms, band 34-42ms, projected verdict PASS`) is a dev-host reproduction of a measurement already taken on the shipping shape, not an extrapolation — `06-32`'s job is to measure it, not assume it. `06-32` also owns writing the round-7 re-refutation of the rollup path next to `D-DEBT-06-21`'s original (`PROH-OPS-07-29`), and recording `read_uptime_strips_by_port`'s retained-but-unreferenced status as debt (per `artifacts_this_phase_produces`), and the fourth-realignment note this plan added to `06-LOCK-AUDIT.md` pointing at `06-28`'s still-open `(function, ordinal)` re-pinning decision as the way to make a fifth realignment unnecessary.
- `.planning/REQUIREMENTS.md` is unedited by this plan: `OPS-07` and `OPS-04` stay exactly as they were (`requirements-completed: []`) — `PROH-OPS-07-08` forbids a gap-closure round from recording its own requirement complete.
- Full suite (`uv run --project dashboard python -m pytest tests/ -q`), second run: **993 passed, 593 subtests passed, 0 failed** — 5 more than `06-29`'s 988 (exactly this plan's 5 new tests: 3 in `UptimeStripCoalescingDifferentialTests`, 2 in `UptimeStripInputReductionGuardTests`). No new failures beyond the two predicted-and-fixed ones and the one documented, unrelated, pre-existing flake.

## Self-Check: PASSED

All modified files confirmed present on disk and containing the expected changes:
- FOUND: `dashboard/app.py` (diff confirmed: `checks_by_port` restored, `read_uptime_strips_by_port` call removed, reduction loop present)
- FOUND: `tests/test_lock_profile.py` (diff confirmed: `required_calls` renamed to `_uptime_summary`, docstrings record both renames)
- FOUND: `tests/test_services_route_scaling.py` (diff confirmed: `UptimeStripCoalescingDifferentialTests`, `UptimeStripInputReductionGuardTests` present, additive-only diff — 385 insertions, 0 deletions)
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md` (diff confirmed: rows 20-28 realigned to +42, fourth-realignment note added)

Both commit hashes confirmed in `git log`:
- FOUND: `83f9ce5`
- FOUND: `bcfc73f`

Test collection confirmed: `pytest --collect-only` reports both new classes and all 5 new test methods collected. All acceptance criteria walked individually against the actual tree (not assumed): the two plan-text wording issues documented above under Deviations were the only discrepancies found between the plan's literal acceptance-criteria commands and the verified-correct implementation.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-06*
