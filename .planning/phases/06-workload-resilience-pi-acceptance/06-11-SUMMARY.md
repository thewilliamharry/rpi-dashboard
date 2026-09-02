---
phase: 06-workload-resilience-pi-acceptance
plan: 11
subsystem: testing
tags: [psutil, pytest, tdd, acceptance-harness, resource-sampling]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-10's re-verified Pi acceptance run and debt reconciliation, which root-caused D-DEBT-06-06 (the harness's CPU column was a structural 0.0)"
provides:
  - "A run-lifetime per-PID psutil.Process handle cache on ResourceTarget so cpu_percent(interval=None) has a real prior-tick baseline instead of a structural 0.0"
  - "_cached_handle: reuses a cached process object when create_time() confirms identity, replaces and re-primes it on PID recycle, prunes to the live PID set every tick"
  - "cpu_sampling provenance block in the acceptance report's per-role resource summary, stating whether the run's CPU column is a measurement or a structural zero"
  - "Eight new regressions in PiLoadAcceptanceHarnessTests pinning the cache's identity, accounting, pruning, and provenance properties"
affects: ["06-14 hardware acceptance checkpoint", "06-13"]

# Actuals (#2632)
actuals:
  tokens: 5533
  tasks: 3
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Object-identity caching keyed by create_time() to distinguish a stable PID from a recycled one, without ever caching the enumerated *set* itself"

key-files:
  created: []
  modified:
    - tests/pi_load_acceptance.py
    - tests/test_workload_resilience.py

key-decisions:
  - "Removed _prime_cpu_percent's own explicit cpu_percent() call (Rule 1 bug fix) because it double-counted against _cached_handle's insert-time priming call, violating Task 1's own 'never re-primed' behavior contract"
  - "cpu_sampling.all_samples_zero is reader-facing provenance only -- never appended to failure_reasons, never affects assertions.resources.passed (D-DEBT-06-02, PROH-OPS-07-01)"

patterns-established:
  - "A handle cache that caches *objects* but always re-derives the enumerated *set* fresh every tick, so a mid-run process respawn is still sampled without inheriting stale identity"

requirements-completed: []  # OPS-07 intentionally NOT promoted -- stays Pending until a passing hardware run exists (PROH-OPS-07-08)

coverage:
  - id: D1
    description: "_live_role_processes hands out one psutil.Process object per PID for a run's lifetime (object identity, not equality), proven by an assertion that fails against the pre-fix shape"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_the_same_process_handle_is_reused_across_sampling_ticks"
        status: pass
    human_judgment: false
  - id: D2
    description: "The process SET is still re-derived from the container on every tick (not cached), so a mid-run respawn is sampled and the two pre-existing PROH-OPS-07-06 respawn-guard tests pass unmodified"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_mid_run_respawn_is_sampled_and_recorded_as_a_changed_set"
        status: pass
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_sample_tick_aggregates_parent_and_busy_child_not_parent_alone"
        status: pass
    human_judgment: false
  - id: D3
    description: "cpu_percent(interval=None) is called exactly once for priming plus exactly once per tick on the held handle -- never re-primed, never doubled per tick"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_cpu_percent_is_primed_once_and_read_once_per_tick"
        status: pass
    human_judgment: false
  - id: D4
    description: "A recycled PID (same PID, different create_time) never inherits the outgoing process's CPU baseline"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_a_recycled_pid_does_not_inherit_the_previous_process_cpu_baseline"
        status: pass
    human_judgment: false
  - id: D5
    description: "A disappeared child is pruned from the handle cache on the next tick, and the cache never exceeds the live process count across a mid-run respawn"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_a_disappeared_child_is_pruned_from_the_handle_cache"
        status: pass
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_the_handle_cache_never_exceeds_the_live_process_count"
        status: pass
    human_judgment: false
  - id: D6
    description: "A busy child's real CPU reading reaches the role's recorded sample after the handle survives across ticks"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_a_busy_child_reaches_the_recorded_role_cpu_after_the_first_tick"
        status: pass
    human_judgment: false
  - id: D7
    description: "The acceptance report carries a cpu_sampling provenance block (handle_cache, primed_pid_count, zero_sample_count, nonzero_sample_count, all_samples_zero) for every role on every run, including a --self-test smoke run"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_the_report_carries_cpu_sampling_provenance_for_every_role"
        status: pass
      - kind: other
        ref: "uv run --project dashboard python tests/pi_load_acceptance.py --self-test --output /tmp/beacon-smoke-06-11.json (prints CPU_PROVENANCE_OK)"
        status: pass
    human_judgment: false
  - id: D8
    description: "The cpu_sampling provenance block never changes the resource verdict -- an all-zero-CPU role with in-budget RSS still passes, with no CPU-mentioning failure reason"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#test_cpu_sampling_provenance_never_changes_the_resource_verdict"
        status: pass
    human_judgment: false

# Metrics
duration: 55min
completed: 2026-09-02
status: complete
---

# Phase 06 Plan 11: Per-PID CPU Handle Cache Summary

**Run-lifetime psutil.Process handle cache (keyed by PID, identity-checked via create_time) makes the acceptance harness's CPU column an actual measurement instead of a structural 0.0, plus a self-reporting `cpu_sampling` provenance block so a future reader can tell the difference without re-reading the source.**

## Performance

- **Duration:** ~55 min
- **Started:** 2026-09-02 (session start)
- **Completed:** 2026-09-02T14:10:00Z
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- `_live_role_processes` now hands out one `psutil.Process` object per PID for a run's lifetime via a new `_cached_handle` helper and a `handles` field on `ResourceTarget`, so `cpu_percent(interval=None)` has a real prior-tick baseline instead of the structural `0.0` that `06-VERIFICATION.md` root-caused as `D-DEBT-06-06`.
- The process *set* is still fully re-derived from the container on every tick (only the objects are cached) — the two pre-existing respawn-guard tests (`test_sample_tick_aggregates_parent_and_busy_child_not_parent_alone`, `test_mid_run_respawn_is_sampled_and_recorded_as_a_changed_set`) pass unmodified, proving `PROH-OPS-07-06` still holds.
- A recycled PID (same PID, new process, different `create_time()`) is detected and never inherits the outgoing process's CPU baseline; the handle cache is pruned to the live PID set every tick so it cannot grow unbounded across a long run.
- The acceptance report now carries a `cpu_sampling` provenance block (`handle_cache`, `primed_pid_count`, `zero_sample_count`, `nonzero_sample_count`, `all_samples_zero`) in every role's `assertions.resources.summary` entry, on every run — making an untrue CPU column self-announcing instead of silently indistinguishable from a genuinely idle deployment.
- Eight new regressions in `PiLoadAcceptanceHarnessTests`, every one confirmed to fail against the pre-fix shape before the corresponding implementation was written.

## Task Commits

Each task was committed atomically (Task 1 followed RED/GREEN TDD; the Rule-1 bug found while writing Task 2 was folded into Task 2's commit since it corrects Task 1's own already-committed behavior):

1. **Task 1 RED: failing regression for per-PID handle reuse** - `6382726` (test)
2. **Task 1 GREEN: reuse one psutil.Process per PID** - `87bb934` (feat)
3. **Task 2: pin cache accounting properties + fix double-primed baseline** - `3455434` (test, includes Rule-1 bug fix)
4. **Task 3: report whether the CPU column is trustworthy** - `aa354c2` (feat)

_Note: Task 1 (`tdd="true"`, `type="tracer"`) used the RED/GREEN cycle: the failing test was committed first, confirmed to fail against the pre-fix implementation, then the implementation was committed separately._

## Files Created/Modified

- `tests/pi_load_acceptance.py` - Added `ResourceTarget.handles` (run-lifetime PID→`psutil.Process` cache), `_cached_handle` helper, rewrote `_live_role_processes` to cache objects while re-deriving the set every tick, fixed `_prime_cpu_percent`'s double-priming bug, added the `cpu_sampling` provenance block to `run_acceptance`'s per-role summary
- `tests/test_workload_resilience.py` - Added 8 new tests to `PiLoadAcceptanceHarnessTests`: `test_the_same_process_handle_is_reused_across_sampling_ticks`, `test_cpu_percent_is_primed_once_and_read_once_per_tick`, `test_a_recycled_pid_does_not_inherit_the_previous_process_cpu_baseline`, `test_a_disappeared_child_is_pruned_from_the_handle_cache`, `test_the_handle_cache_never_exceeds_the_live_process_count`, `test_a_busy_child_reaches_the_recorded_role_cpu_after_the_first_tick`, `test_the_report_carries_cpu_sampling_provenance_for_every_role`, `test_cpu_sampling_provenance_never_changes_the_resource_verdict`

## Decisions Made

- **Removed `_prime_cpu_percent`'s own explicit `cpu_percent()` call.** The plan's Task 1 text said to leave `_prime_cpu_percent`'s body unchanged, on the theory that priming through `_live_role_processes` alone would suffice. Empirically this produced 2 calls at priming time (one from `_cached_handle`'s insert-time baseline call, one from `_prime_cpu_percent`'s own loop) instead of 1 — violating Task 1's own explicit behavior contract ("`cpu_percent(interval=None)` is called exactly once for priming plus exactly once per tick — never twice per tick, and never re-primed"). Verified via a standalone probe script before and after: pre-fix showed `1,2,3,4,5` growing by 1 per call (i.e. 2 at prime, +1 per tick); post-fix showed the correct `1,2,3,4` (1 at prime, +1 per tick). No existing test depended on the old double-call behavior.
- **`cpu_sampling.all_samples_zero` is reader-facing only.** Per `PROH-OPS-07-01` and `D-DEBT-06-02`, it is never appended to `failure_reasons` and never affects `assertions.resources.passed` — confirmed by a dedicated regression (`test_cpu_sampling_provenance_never_changes_the_resource_verdict`) that forces an all-zero-CPU reading through the real `run_acceptance` path and asserts the verdict stays `True`.
- **Two of the five Task 2 tests were redesigned mid-implementation.** My first draft of `test_cpu_percent_is_primed_once_and_read_once_per_tick` and `test_a_busy_child_reaches_the_recorded_role_cpu_after_the_first_tick` patched `psutil.Process` with `return_value=<one stable mock>`, which accidentally passed against the pre-fix implementation too (the mock's own object stability substituted for the cache's, giving a false-positive regression). Redesigned both to patch with `side_effect=[<distinct mock per call>]`, mirroring the pre-fix code's real re-instantiation-per-tick behavior, and re-verified all five Task 2 tests genuinely fail against a pre-fix copy of the source before committing.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `_prime_cpu_percent` double-counted its priming call**
- **Found during:** Task 2 (writing `test_cpu_percent_is_primed_once_and_read_once_per_tick`)
- **Issue:** `_prime_cpu_percent`'s unchanged explicit `proc.cpu_percent(interval=None)` loop, combined with `_cached_handle`'s new insert-time baseline call (both introduced/required by Task 1), produced 2 calls at priming time instead of the 1 the plan's own behavior contract requires ("never re-primed").
- **Fix:** Removed the explicit loop body; `_prime_cpu_percent` now only calls `_live_role_processes(target)` per target, which triggers `_cached_handle`'s insert-time priming as a side effect. Docstring updated to explain why.
- **Files modified:** `tests/pi_load_acceptance.py`
- **Verification:** Standalone probe script confirmed call counts went from `1,2,3,4,5` (wrong) to `1,2,3,4` (correct: N+1 for N ticks) after the fix; `PiLoadAcceptanceHarnessTests` remained green throughout.
- **Committed in:** `3455434` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Necessary correction to make Task 1's already-committed implementation satisfy its own stated behavior contract; no scope creep, no production code touched.

## Issues Encountered

**Concurrent sibling-agent test load caused intermittent full-suite failures unrelated to this plan's scope.** A sibling worktree agent executing plan `06-12` in parallel ran heavy Playwright/Chromium-based UI test suites concurrently on the same machine (observed 15-35 concurrent chromium/pytest processes, system load average 5-10). Multiple `uv run --project dashboard python -m pytest -q` full-suite runs during this session showed 15-16 failures, **every single one** in `tests/test_advanced_ui.py`, `tests/test_history_investigation_ui.py`, or `tests/test_ui_states.py` — files this plan does not touch and has no code path into. Every failing test, when re-run in isolation, passed. One failure did briefly appear inside this plan's own scope (`test_run_acceptance_fails_when_one_role_unresolved_but_other_resolves`, an `HTTPConnection... Errno 49 Can't assign requested address` — ephemeral port exhaustion under system load); re-run alone, it passed immediately.

The cleanest evidence the floor holds: immediately after Task 1's commit (before the sibling agent's load ramped up), a full run produced **838 passed, 561 subtests passed, 0 failures** (837 baseline + the 1 new test from Task 1). After Tasks 2 and 3, `PiLoadAcceptanceHarnessTests` (this plan's own scope) was run in isolation five times across the session and passed 100% every time (24 → 29 → 31 tests as each task's tests were added), and Task 3's exact `<verify>` command (self-test smoke run + JSON assertion) printed `CPU_PROVENANCE_OK` on the first attempt. `git diff -- dashboard/` is empty across all four commits — no production code touched, consistent with `06-CONTEXT.md` `D-01`.

I did not keep re-running the full suite hoping the contention would resolve (deviation-rules scope boundary): after five full-suite attempts spanning ~25 minutes, with the sibling agent's process count still rising (15 → 23 → 35), I stopped retrying and am documenting this instead. **This is not logged to `.planning/WINDOWS.md`** — it is not a stub, skipped test, or unrun `<verify>`; every `<verify>` in this plan was run and passed. It is environmental flakiness in unrelated files under a documented, external, concurrent-load condition, evidenced above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The harness's CPU column is now a real measurement; `06-14`'s hardware acceptance checkpoint can read `cpu_sampling.all_samples_zero` per role to distinguish a genuine low-CPU deployment from a broken measurement.
- `OPS-07` intentionally remains `Pending` in `REQUIREMENTS.md` — this plan does not promote it (`PROH-OPS-07-08`); only a passing hardware run at `06-14` may do that.
- `06-13` (the sibling plan touching `dashboard/app.py`, `dashboard/Dockerfile`, `docker-compose.yml`) can proceed independently; this plan touched none of those files.
- No blockers for downstream plans.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-02*
