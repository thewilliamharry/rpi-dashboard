---
phase: 06-workload-resilience-pi-acceptance
plan: 07
subsystem: testing
tags: [acceptance-harness, docker, psutil, subprocess, resource-monitoring, ops-07]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: the Pi-class load acceptance harness (tests/pi_load_acceptance.py) and its resource-oracle self-test coverage, built in earlier 06-0x plans
provides:
  - Container-derived resource-target resolution (resolve_container_process_tree, _container_root_pid) replacing host-wide command-line matching
  - Per-role honest failure for an unresolvable role or a resolved-but-empty sample set (_resource_unavailable_reason)
  - In-report provenance (assertions.resources.resource_targets) naming the container, method, root PID, sampled-PID union, and mid-run-change flag per role
  - Regression coverage pinning the co-tenant mis-targeting defect, the smoke-fallback boundary, tree aggregation, and mid-run respawn as permanent
affects: [06-08, 06-09, 06-10, any later plan that consumes a Pi acceptance report as evidence]

# Actuals (#2632)
actuals:
  tokens: 10762
  tasks: 3
  commits: 5

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Validated, injectable subprocess seam (runner=subprocess.run default) for docker inspect, argv list only, never shell=True"
    - "Per-tick re-derivation of a role's live process set from a held root PID, rather than a set fixed at run start"
    - "In-report resolution provenance (container/method/root_pid/sampled_pids/changed flag) so a resource pass is falsifiable from the report alone"

key-files:
  created: []
  modified:
    - tests/pi_load_acceptance.py
    - tests/test_workload_resilience.py

key-decisions:
  - "Deleted _find_process_by_cmdline outright rather than keeping it as a fallback -- its one caller is replaced, and leaving a host-wide substring matcher in the file invites its reuse"
  - "Tasks 1 and 2 were implemented as a single coherent rewrite of run_acceptance's resource path -- the old all(proc is None ...) guard depended on the old {role: process} mapping shape, which no longer exists after Task 1's {role: ResourceTarget} rewrite, so there was no safe intermediate state to split them at"
  - "Extracted _resource_unavailable_reason as a standalone, directly-testable primitive rather than leaving the per-role guard inlined in run_acceptance, enabling focused unit tests for Task 2 without needing to drive the full HTTP+DB harness"
  - "RSS is summed across a role's live process set (parent + children), documented as a deliberate upper bound: it over-counts copy-on-write shared pages, but for a ceiling assertion an upper bound can produce a false failure but never a false pass"

patterns-established:
  - "docker inspect via argv list + bounded timeout + injectable runner seam for any future container-derived resolution in this harness"
  - "Per-tick process-tree re-derivation (not fixed at run start) as the pattern for any resource oracle sampling a process whose children can respawn"

requirements-completed: [OPS-07, OPS-01]

coverage:
  - id: D1
    description: "Acceptance runs resolve worker/web resource-sampling targets from the beacon-worker/beacon-web containers via docker inspect, including the request-serving child process, instead of host-wide command-line matching"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_resource_targets_acceptance_resolves_from_containers"
        status: pass
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_resolve_container_process_tree_returns_root_and_children"
        status: pass
      - kind: e2e
        ref: "python tests/pi_load_acceptance.py --self-test"
        status: pass
    human_judgment: false
  - id: D2
    description: "A role whose container cannot be resolved, or that resolves but samples nothing, fails the run with a named reason -- never a silent pass"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_resource_unavailable_reason_names_role_and_cause_when_unresolved"
        status: pass
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_run_acceptance_fails_when_one_role_unresolved_but_other_resolves"
        status: pass
    human_judgment: false
  - id: D3
    description: "The co-tenant mis-targeting defect (06-UAT.md 'Second defect'), the smoke-fallback boundary, tree aggregation, and mid-run respawn are pinned as regressions"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_co_tenant_process_is_never_selected_by_acceptance_resolution"
        status: pass
      - kind: unit
        ref: "tests/test_workload_resilience.py#PiLoadAcceptanceHarnessTests::test_mid_run_respawn_is_sampled_and_recorded_as_a_changed_set"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-09-01
status: complete
---

# Phase 06 Plan 07: Container-Derived Resource-Target Resolution Summary

**Rewrote the Pi acceptance harness's resource oracle to sample the Beacon containers' own process trees via `docker inspect`, replacing the host-wide `gunicorn`/`worker.py` substring matcher that sampled an unrelated co-tenant application's process on real hardware.**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-09-01T09:57Z (first RED test commit)
- **Completed:** 2026-09-01T10:05Z (final regression-coverage commit)
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- `resolve_container_process_tree` / `_container_root_pid` resolve each role's Beacon container root PID via a validated, injectable `docker inspect` seam (argv list, bounded timeout, never a shell string), expanding to the root's full recursive child set so the request-serving child is never left out
- `_resource_targets` no longer scans the host process table at all — for `self_test=False` it resolves strictly from `beacon-worker`/`beacon-web`, returning a named-reason `ResourceTarget` per role on failure; `self_test=True` still resolves both roles to the current process, with no structural path from the acceptance branch to that fallback
- `_sample_resources_tick` re-derives each role's live process set from its held root PID on every tick (not once at run start), so a gunicorn worker respawn mid-run is picked up rather than leaving the role silently degraded to the surviving master
- `_resource_unavailable_reason` makes an unresolvable role, or a resolved role with zero samples, an honest per-role run failure — replacing the old `all(proc is None ...)` guard that required *both* roles to fail before firing
- `assertions.resources.resource_targets` records, per role, the resolved container, method, root PID, the union of every sampled PID, and whether that set changed mid-run, so a reader can audit the resource evidence rather than trust it
- 23 new regression tests pin the co-tenant mis-targeting scenario, the smoke-fallback boundary (both directions), tree aggregation (idle master + busy child), and mid-run respawn (sampled CPU reflects the new child, not the old master)

## Task Commits

Each task was committed atomically, following RED→GREEN for Tasks 1 and 2 (Task 3 is test-only, per its plan-declared reversibility):

1. **Task 1: Resolve each role's sampled processes from the Beacon containers, end to end**
   - `ed6b982` (test) — 12 failing tests for the docker-inspect seam and container-derived `_resource_targets`
   - `5e29ab3` (feat) — the resolution/sampling rewrite; all 23 tests pass, `--self-test` exits 0 with `run_kind: "smoke"`
2. **Task 2: Make an unresolvable role an honest, run-failing outcome**
   - `763636d` (test) — 5 tests for `_resource_unavailable_reason` and the per-role guard
   - `82cee26` (feat) — extracted `_resource_unavailable_reason`, replacing the `all(proc is None ...)` guard; 28 tests pass
3. **Task 3: Regression coverage for the mis-targeting failure mode**
   - `c807b48` (test) — 5 tests pinning co-tenant exclusion, fallback containment, tree aggregation, and mid-run respawn; 33 tests pass, no pre-existing test modified

**Plan metadata:** committed alongside this SUMMARY (worktree mode — STATE.md/ROADMAP.md updates deferred to the orchestrator).

## Files Created/Modified

- `tests/pi_load_acceptance.py` — `_container_root_pid`, `resolve_container_process_tree`, `ResourceTarget`, rewritten `_resource_targets`/`_sample_resources`/`_sample_resources_tick`, `_resource_unavailable_reason`, `--worker-container`/`--web-container` CLI knobs, `resource_targets` report provenance; `_find_process_by_cmdline` deleted
- `tests/test_workload_resilience.py` — 22 new tests appended to `PiLoadAcceptanceHarnessTests`

## Decisions Made

- Deleted `_find_process_by_cmdline` outright (its one caller is replaced) rather than retaining it as dead code — leaving a host-wide substring matcher in the file invites its reuse
- Implemented Tasks 1 and 2 as a single coherent code rewrite of `run_acceptance`'s resource path: the old `all(proc is None ...)` guard operated on the pre-Task-1 `{role: process}` mapping shape, which Task 1's `{role: ResourceTarget}` rewrite necessarily replaces, so there was no safe intermediate commit point that preserved the old guard's exact shape. Task 2's own commit still isolates its distinct contribution — extracting `_resource_unavailable_reason` as a standalone, unit-testable function — with its own RED→GREEN cycle
- Chose to patch `resolve_container_process_tree` (not `subprocess.run`) in tests that exercise `run_acceptance` end-to-end, because `_container_root_pid`'s `runner=subprocess.run` default is bound at function-definition time; patching the `subprocess` module attribute afterward does not reach calls made through that already-bound default (confirmed empirically: the test environment has a real `docker` binary, and the unpatched default invoked it for real, producing genuine `docker inspect` failures instead of the intended stub behavior)
- RSS is summed across a role's live process set (parent + children) as a documented upper bound (over-counts copy-on-write shared pages) — correct direction to bias for a ceiling assertion this phase has already been burned by trusting too far the other way

## Deviations from Plan

None in the implementation — plan executed as written, with one process note: Tasks 1 and 2's production-code changes landed as a single coupled rewrite (see Decisions Made above) rather than as two independently revertable diffs, because Task 2's guard is structurally dependent on Task 1's new `ResourceTarget` return shape. Both tasks retained their own distinct RED→GREEN test/feat commit pairs; the coupling is in the implementation dependency, not in the commit discipline.

**Requirements traceability deviation:** The plan's frontmatter lists `requirements: [OPS-07, OPS-01]`, and the standard executor protocol is to mark both complete in `REQUIREMENTS.md`. This plan deliberately did **not** do that for OPS-07. This is a `gap_closure: true` plan (`gap_ids: [G-06-1]`) whose objective is fixing the acceptance harness's resource oracle — it is not itself the hardware re-run that OPS-07 requires ("A Raspberry Pi-class acceptance run verifies responsiveness, resource budgets, recovery, and sampling continuity under representative load"). This project has an extensively documented policy, recorded repeatedly in `STATE.md`'s decision log (e.g. Phase 3: "a gap-closure round may not record its own requirement complete; only independent re-verification may", and "03-14: requirements mark-complete was invoked with only DIA-01/DIA-02/UX-02... The workflow default would have re-promoted the three requirements this plan exists to keep open"), against exactly this promotion pattern. OPS-07 remains `Pending` in `REQUIREMENTS.md`; it should be promoted only after an independent hardware acceptance run confirms the fixed harness reports earned evidence. OPS-01 was already `Complete` prior to this plan (established in an earlier 06-0x plan) and needed no action.

## Issues Encountered

- Initial `test_run_acceptance_fails_when_one_role_unresolved_but_other_resolves` test attempted to inject a stub via `mock.patch.object(subprocess, 'run', ...)`, which silently invoked the real `docker` binary present in the CI/dev environment instead of the stub, because `_container_root_pid`'s `runner=subprocess.run` default argument was already bound to the real function at import time. Fixed by patching `pi_load_acceptance.resolve_container_process_tree` directly (looked up by name at call time, so the patch takes effect), and documented the pitfall in a code comment on the test.

## User Setup Required

None — no external service configuration required. (`docker`, when present, is used read-only via `docker inspect`; no new dependency was introduced.)

## Next Phase Readiness

- The harness's resource oracle now samples Beacon's own containers exclusively; the byte-for-byte unrelated-process match from the hardware run (06-UAT.md "Second defect") cannot recur without a code change that would break the new regression suite
- `06-08`/`06-09`/`06-10` (or whichever later plans reference a Pi acceptance report) can now trust `assertions.resources.passed` as earned evidence, and can audit `assertions.resources.resource_targets` to see exactly which containers/PIDs produced each figure
- No blockers. The harness has not yet been re-run on real Pi hardware against this change — that remains the job of the hardware-acceptance plan later in this gap-closure round (previously `06-10`), not this plan.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-01*
