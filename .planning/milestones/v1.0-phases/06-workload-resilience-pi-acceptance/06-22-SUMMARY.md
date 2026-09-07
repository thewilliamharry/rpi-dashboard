---
phase: 06-workload-resilience-pi-acceptance
plan: 22
subsystem: api
tags: [maintenance-attribution, memoization, lock-profile, golden-fixture, mutation-testing]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-21's post-narrowing hardware regression measurement (06-LOCK-DIAGNOSTIC-R5A.md section 4: /api/advanced/current's off-CPU time nearly doubled), 06-13's request-scoped occurrence-memo pattern already proven on /api/services, and D-DEBT-06-15/D-DEBT-06-18's user-directed T-C decision"
provides:
  - "dashboard/beacon/diagnosis.py's get_current_diagnosis threads a request-scoped maintenance_occurrence_cache through attributed_downtime_seconds and compose_service_diagnosis/_maintenance_disclosure, mirroring api_services' identical 06-13 memo -- cache=None default leaves every other caller unaffected"
  - "PROH-OPS-07-14 (minted this plan): /api/advanced/current's payload must be byte-identical for the same input on any cost or topology change -- enforced by a golden captured from the pre-memo code, mutation-verified sensitive to a dropped composed field"
  - "test_occurrence_walks_do_not_scale_with_port_count -- a relational, mutation-verified guard proving the memo's mechanism (walk count collapses to distinct (window, date, tz) triples, not port count): 1 walk at 4 ports and 1 walk at 8 ports post-fix, 16 and 48 respectively with cache= stripped"
  - "D-DEBT-06-15 closure branch recorded (separate remedy shipped, sufficiency unmeasured until 06-23), D-DEBT-06-17 (new, the residual: excluded batching candidate and T-A held in reserve), D-DEBT-06-18's formal decision record (option, reversibility, planner recommendation, user's choice, measurement), 06-SECURITY.md's T-06-112 and explicit PROH-OPS-04-05-not-engaged statement"
affects: [06-23-post-remedy-acceptance, 06-24-secure-phase-rerun]

actuals:
  tokens: 10858
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Request-scoped occurrence-walk memo threaded through a second call site (get_current_diagnosis), reusing the identical cache= contract 06-13 established on maintenance.coverage/attributed_downtime_seconds rather than inventing a second one"
    - "A cache-aware call-count guard that distinguishes a genuine walk (cache miss) from a mere function entry (cache hit still enters the function) by re-deriving the callee's own cache key in the counting wrapper before calling through -- a naive per-call counter cannot discriminate memoized from unmemoized code, per 06-13-SUMMARY.md's own finding that _local_occurrence_epochs's call count is unchanged by caching"

key-files:
  created:
    - tests/fixtures/advanced_current_pre_remedy_golden.json
  modified:
    - dashboard/beacon/diagnosis.py
    - tests/test_advanced_diagnosis_api.py
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md
    - .planning/phases/06-workload-resilience-pi-acceptance/06-SECURITY.md

key-decisions:
  - "Task 1's blocking checkpoint:decision was already resolved by the user before this session: T-C (t-c-reduce-cost), the reversible occurrence memo -- matching the planner's own recommendation. T-A (--workers N>1), T-B (--threads reduction), and T-D (accept-and-scope) were not implemented; dashboard/Dockerfile and docker-compose.yml were not touched."
  - "The call-count guard's fixture shares one literal maintenance window row (same id/port/schedule fields) and one literal fixed offline interval across every port in both arms (4 ports, then 8), via a patched read_maintenance_windows_by_port/read_service_offline_intervals rather than per-port real DB windows -- this is what makes cross-port cache collision genuine (Window is a value-equal frozen dataclass, so structurally-identical rows collide in _local_occurrence_epochs's cache regardless of literal object identity) and is what the plan's own W5 finding required: a shared window alone is not sufficient if the two arms' intervals touch different local dates, so both arms use the identical interval epochs, pinned to Monday 2026-01-05 02:30:00Z-04:00:00Z UTC (both instants fall on the same calendar date under UTC, which is what the fixture explicitly pins rather than inheriting SETTINGS.timezone)."
  - "The golden fixture was captured from the code exactly as it stood before this plan's production edit -- verified by reverting dashboard/beacon/diagnosis.py to HEAD (git checkout --) before running the capture script, then restoring the edited version and confirming a second capture run produced byte-identical output."

patterns-established: []

requirements-completed: [OPS-07, OPS-04, OPS-02]

coverage:
  - id: D1
    description: "get_current_diagnosis's occurrence walk memoized via a request-scoped cache, threaded through attributed_downtime_seconds and compose_service_diagnosis/_maintenance_disclosure, mirroring 06-13's identical /api/services fix"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedCurrentCostTests::test_occurrence_walks_do_not_scale_with_port_count"
        status: pass
    human_judgment: false
  - id: D2
    description: "PROH-OPS-07-14 minted and enforced: /api/advanced/current's payload stays byte-identical for the same input across the memo, proven against a golden captured from the pre-edit code and mutation-verified sensitive to a dropped composed field"
    requirement: "OPS-02"
    verification:
      - kind: unit
        ref: "tests/test_advanced_diagnosis_api.py::AdvancedCurrentCostTests::test_payload_is_unchanged_by_the_round_5_remedy"
        status: pass
    human_judgment: false
  - id: D3
    description: "The decision, its closure, and its residual recorded in 06-DEBT.md (D-DEBT-06-15, D-DEBT-06-17 new, D-DEBT-06-18) and 06-SECURITY.md (T-06-112, PROH-OPS-04-05-not-engaged stated explicitly), in the same form the phase's prior two one-way-door decisions use"
    requirement: "OPS-04"
    verification:
      - kind: other
        ref: ".planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md D-DEBT-06-15/-17/-18 sections; 06-SECURITY.md T-06-112 row and '06-22' audit-trail entry"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-09-03
status: complete
---

# Phase 06 Plan 22: T-C -- the reversible occurrence memo for `/api/advanced/current` Summary

**`get_current_diagnosis` now threads a request-scoped occurrence-walk memo through `attributed_downtime_seconds` and `_maintenance_disclosure`, mirroring `06-13`'s identical `/api/services` fix -- proven byte-identical against a pre-memo golden and mutation-verified to collapse the walk count from scaling with port count (16 walks at 4 ports, 48 at 8) to a small constant independent of it (1 walk at both 4 and 8 ports).**

## Performance

- **Duration:** ~45 min
- **Tasks:** 2 of 3 complete this session (Task 1's blocking `checkpoint:decision` was already resolved by the user before this session started, per the objective's `<resolved_decision>`; Task 2 and Task 3 executed here)
- **Files modified:** 5 (1 fixture created, 4 modified)

## Accomplishments

- **`dashboard/beacon/diagnosis.py`'s `get_current_diagnosis` now creates one `maintenance_occurrence_cache` dict per request and threads it to `maintenance.attributed_downtime_seconds` (per-port) and to `compose_service_diagnosis`, which forwards it to `_maintenance_disclosure`'s two `maintenance.coverage` call sites. `cache=None` default preserves every caller that does not opt in, exactly as `06-13` established for `/api/services`.
- **`PROH-OPS-07-14` minted and enforced.** `test_payload_is_unchanged_by_the_round_5_remedy` compares `get_current_diagnosis`'s serialized output against `tests/fixtures/advanced_current_pre_remedy_golden.json`, captured from the code exactly as it stood before this plan's production edit (verified by reverting `diagnosis.py` to HEAD via `git checkout --`, capturing, then restoring the edit and reproducing byte-identical output). Mutation-verified: dropping the `'settings'` field from the returned dict was observed to FAIL the test (11,270 identical chars, then a 592-char divergence); reverted.
- **`test_occurrence_walks_do_not_scale_with_port_count`: a relational, mutation-verified call-count guard.** Post-fix (cache threaded): 1 walk at 4 ports, 1 walk at 8 ports -- N-independent. Mutation (cache= stripped, hand-applied and reverted): 16 walks at 4 ports, 48 walks at 8 ports -- both scale with port count. The guard's counting shim distinguishes a genuine walk (cache miss) from a mere function entry (cache hit still enters `_local_occurrence_epochs`), which is necessary because `06-13-SUMMARY.md` recorded that a naive per-call counter does not discriminate memoized from unmemoized code for this function.
- **`git diff -- dashboard/beacon/diagnosis.py` adds only an optional `cache=None` parameter (three call sites: `_maintenance_disclosure`, `compose_service_diagnosis`, `get_current_diagnosis`), its threading, and one comment above the cache's creation** -- no SQL, no constant, no ordering change.
- **The decision recorded verbatim in `06-DEBT.md`**, in the same form the phase's prior two one-way-door decisions use (`D-DEBT-06-01`'s "Round 4 reopening", `D-DEBT-06-09`'s decision record): option selected (`t-c-reduce-cost`), reversibility rating (reversible -- only `t-a-add-workers` carries the one-way rating), planner recommendation (T-C, matched), whether the user followed it (yes), and the measurement it was made against (`06-LOCK-DIAGNOSTIC-R5A.md` section 4).
- **New `D-DEBT-06-17`** files the residual: the `read_service_offline_intervals_by_port` batching candidate T-C's own `<action>` deliberately excludes (its combined-across-ports row cap, `D-DEBT-06-11`, would change this route's output), and T-A held in reserve if `06-23` measures T-C insufficient.
- **`06-SECURITY.md`'s `T-06-112`** (Tampering -- the payload changing under a cost change) added, closed on `PROH-OPS-07-14` and its mutation-verified guard. A new `06-22` audit-trail entry states explicitly that **`PROH-OPS-04-05` is NOT engaged** by this branch -- no topology change, no new database-access boundary, `T-06-24`'s closure evidence untouched, `git diff --quiet` holds for `dashboard/Dockerfile` and `docker-compose.yml`.

## Task Commits

1. **Task 1: Choose the remedy for `/api/advanced/current`** -- already resolved by the user before this session (blocking `checkpoint:decision`, per the objective's `<resolved_decision>`). No commit this session (a decision produces no file changes on its own; its formal record is Task 3's `afff388`/`13203e0`).
2. **Task 2: Implement the selected remedy (T-C), without moving the payload** -- `afff388` (feat)
3. **Task 3: Record the decision, what it forecloses, and what it leaves open** -- `13203e0` (docs)

**Plan metadata:** this SUMMARY's own commit (below).

## Files Created/Modified

- `dashboard/beacon/diagnosis.py` -- `_maintenance_disclosure`, `compose_service_diagnosis`, and `get_current_diagnosis` gain an optional `cache=None` parameter and its threading, plus one comment above the cache dict's creation.
- `tests/test_advanced_diagnosis_api.py` -- new `AdvancedCurrentCostTests` class: `test_payload_is_unchanged_by_the_round_5_remedy` (golden equivalence guard) and `test_occurrence_walks_do_not_scale_with_port_count` (relational call-count guard).
- `tests/fixtures/advanced_current_pre_remedy_golden.json` -- new. The payload golden captured from the pre-memo code, 3 services (one online, one offline+maintenance-covered with `maintenance_attributed_seconds=5400`, one offline with no window and real unattributed downtime).
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` -- `D-DEBT-06-15` Status field and new "`06-22` measured" section; new `D-DEBT-06-17` entry; `D-DEBT-06-18` Status field and new "`06-22`'s formal decision, recorded verbatim" section.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-SECURITY.md` -- new `T-06-112` register row; new "`06-22`" Security Audit Trail entry.

## Decisions Made

- **Task 1's blocking `checkpoint:decision` was already resolved by the user before this session: T-C.** Per the objective's `<resolved_decision>` block, this was not re-raised or re-litigated. T-A (`--workers N>1`), T-B (`--threads` reduction), and T-D (accept-and-scope) were not implemented; `dashboard/Dockerfile` and `docker-compose.yml` were not touched (`git diff --quiet` holds for both).
- **The call-count guard's fixture shares one literal window and one literal interval across every port, via patched repository functions rather than per-port real DB writes.** `Window` is a value-equal frozen dataclass (`@dataclass(frozen=True)`, default `eq`/`hash`), so `_local_occurrence_epochs`'s `(window, date, tz)` cache key collides across ports whose window rows are structurally identical, regardless of literal object identity -- this is what makes cross-port collapse genuine and testable without needing the DB schema's real one-row-per-port `maintenance_windows` constraint to somehow produce a shared row. Per the plan's own W5 finding, a shared window alone is not sufficient if the two arms' offline intervals touch different local dates; both arms here use the identical interval epochs (2026-01-05T02:30:00Z through 2026-01-05T04:00:00Z, both on the same Monday under an explicitly pinned UTC clock, not `SETTINGS.timezone`), so the equality asserted follows from the memo, not from the fixture's dates happening to coincide.
- **The golden fixture's capture-then-restore process, verified rather than assumed.** `dashboard/beacon/diagnosis.py` was reverted to HEAD (`git checkout --`, the sanctioned single-file restore) before running the capture script, so the golden reflects the code exactly as it stood before this plan's production edit; the edited version was then restored from a scratchpad backup and a second capture run confirmed byte-identical output (`diff` reported no difference).

## Deviations from Plan

### Auto-fixed Issues

None -- plan executed exactly as written for the T-C branch. The one non-trivial engineering judgment (how to construct a call-count guard that discriminates memoized from unmemoized behavior given `06-13-SUMMARY.md`'s own finding that raw call counts do not) is not a deviation from the plan's instructions -- it directly implements the plan's own W5 finding and its instruction to seed both arms' offline intervals to span the same local dates under an explicitly pinned timezone, and is documented above under Decisions Made and in the test's own docstring.

---

**Total deviations:** 0 auto-fixed.
**Impact on plan:** None. Both tasks executed exactly as specified for the T-C branch.

## Issues Encountered

**The known full-suite-load-sensitive test flake reproduced once, as documented by `D-DEBT-06-13`.** The plan's Task 2 `<verify>` (targeted: `tests/test_advanced_diagnosis_api.py tests/test_module_boundaries.py tests/test_maintenance_windows.py tests/test_workload_resilience.py`) passed cleanly: 268 passed, 136 subtests passed, 0 failed. A subsequent full-suite run (`uv run --project dashboard python -m pytest -q`, performed to check the phase's stated suite floor) showed `939 passed, 564 subtests passed, 1 failed` -- the failure was `HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing`, which `D-DEBT-06-13`'s own addendum already names as reproducing under whole-suite load contention while passing cleanly in isolation. Re-run in isolation immediately after: `2 passed in 0.56s`. This is not caused by this plan's change -- this plan touches only `dashboard/beacon/diagnosis.py` and its own test file, neither of which this failing test exercises -- and per the plan's own instruction ("Suite floor... judge by 'no NEW failures outside the known-flaky set'... that set now includes `test_heartbeat_renewal_to_persistence_handoff_is_fenced` and `test_a_check_count_independent_bucket_does_not_track_the_check_row_ratio`" and separately notes the held-region composition guard now uses a same-run relational comparator, which is exactly the guard that failed here under load), this is read as the known pattern, not a new defect. Suite total (939 passed + 1 failed = 940) matches the expected floor plus this plan's 2 new tests (938 + 2 = 940), confirming neither new test failed.

## User Setup Required

None -- no external service configuration required.

## Next Phase Readiness

- **`06-23`** inherits the closure condition for `D-DEBT-06-18` and the open question `D-DEBT-06-15`/`D-DEBT-06-17` both name honestly: whether T-C's memo is sufficient to bring `/api/advanced/current` under its 2000ms budget is a hardware measurement this plan does not and cannot make. If `06-23` measures the route still over budget, `D-DEBT-06-17` names the two untaken candidates (the excluded batching, and T-A held in reserve with round 5's own `mem_limit` sizing data).
- **`06-24`** inherits the still-outstanding `/gsd-secure-phase 06` formal re-run (`PROH-OPS-04-05` prerequisite 4) -- unaffected by this plan, since `PROH-OPS-04-05` was explicitly not engaged (no topology change).
- **Guardrails held throughout:** `git diff --quiet -- .planning/REQUIREMENTS.md` (OPS-07 stays not-promoted, `PROH-OPS-07-08`), `git diff --quiet -- dashboard/Dockerfile`, `git diff --quiet -- docker-compose.yml`, `git diff -- tests/pi_load_acceptance.py` empty -- all confirmed clean throughout this session.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-03*

## Self-Check: PASSED

- FOUND: `dashboard/beacon/diagnosis.py`
- FOUND: `tests/test_advanced_diagnosis_api.py`
- FOUND: `tests/fixtures/advanced_current_pre_remedy_golden.json`
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md`
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-SECURITY.md`
- FOUND commit `afff388` (Task 2)
- FOUND commit `13203e0` (Task 3)
- Confirmed: `git diff --quiet -- .planning/REQUIREMENTS.md` held throughout this session
- Confirmed: `git diff --quiet -- dashboard/Dockerfile` and `git diff --quiet -- docker-compose.yml` held throughout
- Confirmed: targeted verify (`tests/test_advanced_diagnosis_api.py tests/test_module_boundaries.py tests/test_maintenance_windows.py tests/test_workload_resilience.py`) -- 268 passed, 136 subtests passed, 0 failed
- Confirmed: full suite -- 939 passed, 564 subtests passed, 1 failed (the known `D-DEBT-06-13` full-suite-load flake, reproducing cleanly in isolation: 2 passed in 0.56s)
