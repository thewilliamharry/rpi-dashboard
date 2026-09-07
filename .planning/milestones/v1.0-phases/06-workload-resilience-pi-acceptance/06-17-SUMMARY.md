---
phase: 06-workload-resilience-pi-acceptance
plan: 17
subsystem: diagnostics
tags: [lock-instrumentation, acceptance-harness, verdict-logic, three-valued-verdict, ast-guard]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-15's default-off InstrumentedLock (wait/hold per route) and 06-16's held-region/request-wall-time decomposition, both readable from dashboard/beacon/lockprofile.py's snapshot()"
provides:
  - "tests/pi_load_acceptance.py: fetch_lock_profile/percentile_from_histogram/diff_lock_profile/summarize_lock_profile deriving windowed per-route wait/hold percentiles, hold-decomposition shares, and utilisation from a snapshot pair taken around exactly the load window"
  - "tests/pi_load_acceptance.py: LOCK_ATTRIBUTION_PREDICTIONS + evaluate_lock_attribution -- a pure, three-valued CONFIRMED/REFUTED/INCONCLUSIVE verdict against 06-VERIFICATION.md Truth 5's own falsifiable predictions, refutation evaluated before confirmation"
  - "tests/pi_load_acceptance.py: AcceptanceReport.lock_profile, LoadScenario.collect_lock_profile/observer, --lock-profile CLI flag, run_self_test(collect_lock_profile=...) -- the collection block never touches overall_passed or failure_reasons (PROH-OPS-07-12)"
  - "tests/test_lock_profile.py: LockProfileCollectionTests (13), LockAttributionVerdictTests (8), HarnessRehearsalTests (4) -- 25 new tests, all four mutations named in the plan run and recorded below"
affects: ["06-18"]

actuals:
  tokens: 16478
  tasks: 3
  commits: 2

tech-stack:
  added: []
  patterns:
    - "A three-valued verdict (CONFIRMED/REFUTED/INCONCLUSIVE) with the refutation branch evaluated BEFORE the confirmation branch -- a function that checks its hypothesis first and only falls through to refutation is the shape that produced two wrong rounds this phase (D-DEBT-06-09, D-DEBT-06-10)"
    - "A diagnostic collection block proven inert to the verdict by TWO independent arms: a deterministic single-run before/after observer capture (proves the block cannot move overall_passed/failure_reasons within one run) plus an ast structural scan (proves no expression contributing to either references the diagnostic's own field) -- two nondeterministic live runs merely agreeing is explicitly demoted to a smoke-level cross-check, not primary evidence"
    - "Percentiles read off a fixed-edge histogram are reported as a (lower_edge, upper_edge) bound pair, never a single number -- a bucketed estimate presented as exact would be the same shape-over-substance defect the round is guarding against"

key-files:
  created: []
  modified:
    - tests/pi_load_acceptance.py
    - tests/test_lock_profile.py

key-decisions:
  - "The deterministic arm's observer fires immediately before/after the collection block, which sits AFTER the load window but BEFORE the database-oracle read that appends the seeded failure -- so both captured (failure_reasons, overall_passed) pairs are legitimately empty/False at that point. Per the orchestrator's correction in the plan, the test additionally asserts the run's FINAL failure_reasons is non-empty, proving the seeded failing oracle genuinely fired and this was not a vacuous empty-list comparison."
  - "HarnessRehearsalTests wraps run_self_test in a narrow _run_self_test_reliably retry (bounded to 5 attempts, only for two named transient conditions: an early 'target unreachable' before accept() is serviced, and errno 49 'Can't assign requested address' from local ephemeral-port pressure). Discovered empirically while running the full suite repeatedly -- the same full-suite-only flakiness shape D-DEBT-06-13 documents elsewhere. Any other collected:False reason (404, schema mismatch, etc.) is never retried."
  - "LOCK_PROFILE_SCHEMA_VERSION is a literal constant (2), not bound to dashboard/beacon/lockprofile.SNAPSHOT_SCHEMA_VERSION by import -- a future bump to that module should not silently widen what this harness claims to understand without a person choosing to update this constant too."

patterns-established:
  - "RED/GREEN split by dependency shape, not literal task boundary: Task 2's evaluate_lock_attribution is called from inside Task 1's _collect_lock_profile, so the two were implemented and committed as one coupled RED (all new tests, revert-and-restore to prove collection failure) / one GREEN (full implementation) pair rather than three separate per-task cycles. Documented as a deviation below."

requirements-completed: [OPS-07]

coverage:
  - id: D1
    description: "The harness collects the lock-profile snapshot pair around exactly its own load window and embeds the derived per-route wait/hold percentiles, hold-decomposition shares, utilisation, and CONFIRMED/REFUTED/INCONCLUSIVE verdict in the same JSON report as the latencies"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::LockProfileCollectionTests::test_reachable_collection_produces_a_populated_block"
        status: pass
      - kind: unit
        ref: "tests/test_lock_profile.py::LockProfileCollectionTests::test_utilisation_matches_a_known_held_fraction"
        status: pass
    human_judgment: false
  - id: D2
    description: "evaluate_lock_attribution reaches REFUTED on a world built from the hardware run's own figures (06-ACCEPTANCE-ROUND3.md) with the lock-wait component removed -- the diagnostic can refute, not only confirm"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::LockAttributionVerdictTests::test_attribution_fails_world_yields_refuted"
        status: pass
    human_judgment: false
  - id: D3
    description: "Requesting lock-profile collection can never change a run's overall_passed or failure_reasons, proven by a deterministic single-run observer capture, an ast structural scan, and four failure-arm cross-checks (404, schema mismatch, timeout, no-collection-requested)"
    requirement: "OPS-07"
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::LockProfileCollectionTests::test_deterministic_arm_the_collection_block_never_moves_the_verdict"
        status: pass
      - kind: unit
        ref: "tests/test_lock_profile.py::LockProfileCollectionTests::test_structural_arm_lock_profile_never_feeds_the_verdict"
        status: pass
    human_judgment: false
  - id: D4
    description: "The operator's exact `ENABLE_LOCK_PROFILE=1 ... --self-test --lock-profile --output ...` command path was rehearsed end to end on the developer machine, producing a populated, byte-size-known report"
    requirement: "OPS-07"
    verification:
      - kind: manual_procedural
        ref: "hand-run: ENABLE_LOCK_PROFILE=1 uv run --project dashboard python tests/pi_load_acceptance.py --self-test --lock-profile --output /tmp/beacon-rehearsal.json (see Developer-Machine Evidence below)"
        status: pass
    human_judgment: false

duration: 95min
completed: 2026-09-03
status: complete
---

# Phase 6 Plan 17: Lock-profile collection, three-valued verdict, and rehearsal Summary

**The acceptance harness now collects the `_db_lock` wait/hold snapshot pair around its own load window and reaches an explicit CONFIRMED/REFUTED/INCONCLUSIVE verdict — proven capable of REFUTED against a counterfactual built from 06-ACCEPTANCE-ROUND3.md's own hardware figures — without ever moving the run's pass/fail verdict.**

## Performance

- **Duration:** ~95 min
- **Started:** 2026-09-03T12:14Z
- **Completed:** 2026-09-03T13:00Z
- **Tasks:** 3 (implemented as one coupled RED/GREEN cycle — see Deviations)
- **Files modified:** 2 (`tests/pi_load_acceptance.py`, `tests/test_lock_profile.py`)

## Accomplishments

- `tests/pi_load_acceptance.py` gains `fetch_lock_profile`, `percentile_from_histogram`, `diff_lock_profile`, and `summarize_lock_profile`: a `before`/`after` snapshot pair taken immediately before `resource_thread.start()` and immediately after its join is turned into windowed per-route wait/hold percentile bounds (never a single false-precision number), hold-decomposition shares (connect/SQL/Python), per-route request wall/CPU/lock-wait/other-off-CPU figures, and global utilisation.
- `LOCK_ATTRIBUTION_PREDICTIONS` + `evaluate_lock_attribution`: a pure, three-valued verdict against `06-VERIFICATION.md` Truth 5's own stated predictions. The refutation condition (measured lock-wait share of a genuinely slow route's wall time) is evaluated **before** the confirmation conditions — the ordering the plan's own review called out as the fix for the shape that produced two wrong rounds this phase.
- `AcceptanceReport.lock_profile`, `LoadScenario.collect_lock_profile`/`observer`, and the `--lock-profile` CLI flag wire the whole thing into one command. The collection block is proven inert to the verdict by two independent arms (deterministic single-run observer capture + `ast` structural scan), not merely by two live runs happening to agree.
- `evaluate_lock_attribution` was driven to **REFUTED** by a synthetic world built directly from `06-ACCEPTANCE-ROUND3.md`'s own hardware numbers (`/api/scan-status` 242.614ms acceptance p50) with the lock-wait component set to a negligible share — the concrete counterfactual `D-DEBT-06-10`'s review required.
- The operator's exact command was rehearsed by hand on the developer machine (see Developer-Machine Evidence below): it ran to completion, produced a 131KB report, and reached `attribution.verdict: INCONCLUSIVE` (the self-test's 4-thread, 5-second load does not reproduce a slow enough `/api/scan-status` to test the hypothesis either way — an honest, correctly-behaving result, not a defect).
- Full suite: **919 passed, 561 subtests, 0 failed** (up from 894/561 before this plan — +25 new tests). `tests/test_lock_profile.py` alone run twice back-to-back after the retry fix: 60 passed both times.

## Task Commits

Both tasks 1 and 2 share one RED/GREEN cycle (see Deviations for why); Task 3 (rehearsal) is covered by the same GREEN commit since its only code change (the `collect_lock_profile` parameter and CLI flag) was already part of the coupled implementation.

1. **RED** — `37b31df` — `test(06-17): add failing tests for lock-profile collection, verdict, and rehearsal`
2. **GREEN** — `60f9fe5` — `feat(06-17): collect the lock-profile snapshot pair and reach a verdict`

**Plan metadata:** this commit (below)

## Files Created/Modified

- `tests/pi_load_acceptance.py` — `LOCK_PROFILE_PATH`, `LOCK_PROFILE_SCHEMA_VERSION`, `LOCK_PROFILE_FETCH_TIMEOUT_SECONDS`, `fetch_lock_profile`, `percentile_from_histogram`, `diff_lock_profile`/`LockProfileCounterWentBackwardsError`, `summarize_lock_profile`, `LOCK_ATTRIBUTION_PREDICTIONS`, `evaluate_lock_attribution`, `_collect_lock_profile`, `AcceptanceReport.lock_profile`, `LoadScenario.collect_lock_profile`/`observer`, `run_acceptance`'s before/after collection around the load window, `run_self_test(collect_lock_profile=...)`, `--lock-profile` CLI flag.
- `tests/test_lock_profile.py` — `LockProfileCollectionTests` (13 tests: reachable collection, deterministic arm, structural arm, 404/schema-mismatch/timeout cross-checks, no-collection-requested, and 7 pure-function unit tests over literal synthetic snapshots), `LockAttributionVerdictTests` (8 tests: CONFIRMED/REFUTED/INCONCLUSIVE worlds, route-overflow, collected:false, missing-route, threshold provenance, purity), `HarnessRehearsalTests` (4 tests: populated block, disabled-matches-enabled, JSON round-trip, T-06-29 information-disclosure).

## Decisions Made

See `key-decisions` in frontmatter. In prose: the most consequential decision was ordering `evaluate_lock_attribution`'s refutation check before its confirmation checks — this is the single line that determines whether the round is a diagnostic or a confirmation exercise, and it was mutation-verified (see below) to actually matter: removing it changes the same REFUTED-world input to INCONCLUSIVE, not to CONFIRMED, which is itself informative — the confirmation predictions in that world partially hold (services' hold sits in the predicted band) even though the refutation should fire first.

## Deviations from Plan

### Process deviation (documented, not a Rule 1-4 auto-fix)

**RED/GREEN commit granularity collapsed from three task-level cycles to one plan-level cycle.** The plan's three tasks (`tdd="true"` each) describe separate RED/GREEN pairs, but Task 2's `evaluate_lock_attribution` is called directly from inside Task 1's `_collect_lock_profile` (`report.lock_profile['attribution'] = evaluate_lock_attribution(summary)`), and Task 3 adds no new implementation beyond wiring already covered by Task 1's changes (`run_self_test`'s `collect_lock_profile` parameter, the CLI flag). Splitting per-task would have required either committing intermediate broken states or artificially staging/unstaging file regions with no real behavioral boundary between them. Instead: the whole `tests/pi_load_acceptance.py` implementation diff was reverted (`git checkout --`), the full new test suite was run to confirm a genuine `AttributeError` collection failure (RED — recorded verbatim below), the RED-only test commit was made, the implementation was restored via `git apply` of the saved patch, and the full suite was re-run to confirm GREEN before the second commit. Both commits are genuine, verified RED and GREEN states, not simulated.

**RED gate evidence (verbatim collection error, `pytest -q tests/test_lock_profile.py -k "LockProfileCollection or LockAttributionVerdict or HarnessRehearsal"` against `tests/test_lock_profile.py` alone with `tests/pi_load_acceptance.py` reverted):**
```
ERROR collecting tests/test_lock_profile.py
tests/test_lock_profile.py:1502: in <module>
    schema_version=harness.LOCK_PROFILE_SCHEMA_VERSION,
AttributeError: module 'tests.pi_load_acceptance' has no attribute 'LOCK_PROFILE_SCHEMA_VERSION'
```

### Auto-fixed Issues

**1. [Rule 1 - Bug] `HarnessRehearsalTests` was flaky under full-suite load, not in isolation**
- **Found during:** running the full `tests/test_lock_profile.py` suite repeatedly after the GREEN commit, per this round's commit discipline (commit the unmutated state before mutation-verifying).
- **Issue:** `test_profile_enabled_self_test_returns_a_populated_diagnostic_block` and `test_report_round_trips_through_to_json_and_json_loads` failed intermittently only when run as part of the full 60-test module, never in isolation. Root cause, confirmed by a 15-iteration stress script: two distinct transient, environment-level failures — an honest `run_acceptance` early return (`target unreachable`, empty `lock_profile`) before the werkzeug server's `accept()` backlog was serviced, and (once, in the full-suite run) `errno 49 Can't assign requested address` from local ephemeral-port pressure across many short-lived `127.0.0.1` connections accumulated by the suite's other real-server tests. Both are the same full-suite-only flakiness shape `D-DEBT-06-13` documents elsewhere in this suite (two different pre-existing tests, unrelated to this plan, that fail differently across consecutive full-suite runs and pass reliably in isolation).
- **Fix:** Added `_run_self_test_reliably`, a narrow retry wrapper (bounded to 5 attempts) that retries `run_self_test` ONLY when it observes one of these two named transient conditions. Any other `collected: False` reason (a genuine 404, schema mismatch, etc.) is never retried, so a real regression still fails immediately.
- **Files modified:** `tests/test_lock_profile.py` only — no harness/application code touched.
- **Verification:** `tests/test_lock_profile.py` run twice back-to-back after the fix: 60 passed both times. Full project suite: 919 passed, 561 subtests, 0 failed.
- **Committed in:** `60f9fe5` (part of the GREEN commit — discovered and fixed before that commit landed, not as a follow-up).

---

**Total deviations:** 1 process deviation (RED/GREEN granularity, documented above) + 1 auto-fixed issue (Rule 1 — test-file-only flakiness fix, scoped entirely to `tests/test_lock_profile.py`).
**Impact on plan:** No scope creep. No application code (`dashboard/`) touched at any point — confirmed by `git diff -- dashboard/` returning empty across the whole plan. No budget, assertion function, or scenario default touched — confirmed by `git diff` review below.

## Mutation Verification (all run against the actual source via Edit, not monkeypatches; all reverted, confirmed via `git diff --stat` returning empty after each)

| # | Task | Mutation | Observed failure |
|---|---|---|---|
| 1 | 1 | Collection-failure path in `run_acceptance` changed to also append the failure reason to `report.failure_reasons` | `test_deterministic_arm_...` fails: `captures[0]=([], False)` != `captures[1]=(['before-snapshot fetch failed: 404 Client Error: NOT FOUND for url: http://127.0.0.1:59657/api/diagnostics/lock-profile'], False)`. `test_structural_arm_...` fails independently: `ast` finds `[('failure_reasons mutation', 1349)] != []` |
| 2 | 1 | `before` lock-profile snapshot moved to the very top of `run_acceptance`, before port discovery, with a 0.6s sleep inserted between that early capture and the true load start (simulating the real-world discovery latency a local self-test's own sub-millisecond discovery call cannot exercise) | `test_reachable_collection_produces_a_populated_block` fails: `window_ns 2632629333 not within 25% of 2000000000` (632.6ms over the 500ms tolerance band) |
| 3 | 2 | `evaluate_lock_attribution`'s refutation branch (`if lock_wait_share < min_share:`) disabled (`if False:`) | `test_attribution_fails_world_yields_refuted` fails: `'INCONCLUSIVE' != 'REFUTED'` on the exact same REFUTED-world input — informative in itself: the confirmation checks partially hold in that world (services' hold sits in the predicted band) even though the refutation should have fired first |
| 4 | 2 | `LOCK_ATTRIBUTION_PREDICTIONS['utilisation_superlinear_threshold']` loosened from `0.85` to `0.5` | `test_predictions_match_the_verification_reports_own_stated_figures` fails: `0.5 != 0.85` |

## Developer-Machine Evidence (PROH-OPS-07-09 / PROH-OPS-07-11 — never Pi evidence, never OPS-07 evidence)

Hand-run exactly as the Pi operator will, outside the test suite:
```
ENABLE_LOCK_PROFILE=1 uv run --project dashboard python tests/pi_load_acceptance.py \
    --self-test --lock-profile --output /tmp/beacon-rehearsal.json
```
Exit code `0`. Four concurrent threads over five seconds against a seeded temp SQLite database — nothing about this is Pi evidence, and the verdict it reaches carries no weight.

```
run_kind=smoke   overall_passed=True   output file size=131028 bytes
lock_profile: collected=True   instrumented=True   window_ns=5040908000   utilisation=0.9127
attribution: verdict=INCONCLUSIVE
  reason="this run did not reproduce a slow /api/scan-status (median wall 3356477ns
          < 50000000ns threshold) -- nothing to explain either way."

/api/services     acquisitions=758  wait p50=[1623777,3359818]ns  wait p95=[1623777,3359818]ns
                   hold p50=[784760,1623777]ns  hold p95=[1623777,3359818]ns
                   connect_share=0.3349  sql_share=0.5184  python_share=0.1467
/api/scan-status  acquisitions=757  wait p50=[1623777,3359818]ns  wait p95=[1623777,3359818]ns
                   hold p50=[784760,1623777]ns  hold p95=[1623777,3359818]ns
```

`instrument_cost_ns_per_acquisition = 1469.1 ns` (06-15) remains the error bar every hold figure above must be read against — the `/api/services` hold p50 lower bound (784,760ns) is roughly 500x that cost, comfortably above the instrument's own resolution. The `INCONCLUSIVE` verdict here is the CORRECT reading for this run, not a defect: the self-test's low thread count and short duration do not reproduce hardware round 3's 74x `/api/scan-status` degradation, so the run has nothing to confirm or refute either way — exactly the third branch this round exists to make possible. `06-18`'s real hardware run, at concurrency 8 for 600s, is where a genuine CONFIRMED or REFUTED verdict becomes possible.

**Friction found and fixed before the hardware run meets it:** none beyond the flaky-rehearsal-under-full-suite-load issue documented above (a test-infrastructure concern, not an operator-facing one — the command path itself, its flags, and its output shape all worked correctly on the first hand-run).

## Constraint Compliance

- `git diff -- dashboard/` — empty across the whole plan (confirmed after both commits).
- `git diff -- dashboard/pyproject.toml dashboard/uv.lock dashboard/Dockerfile` — empty.
- `git diff` review of `tests/pi_load_acceptance.py`: `ROUTE_BUDGETS_MS`, `assert_response_times`, `assert_resource_budget`, `assert_cadence`, the `--duration` 600 default, the `--concurrency` 8 default, `_routes_for_ports`, and `_load_worker` do not appear anywhere in the diff at all (`PROH-OPS-07-01`, `PROH-OPS-07-10`).
- `PROH-OPS-07-12`: enforced by the deterministic arm + the `ast` structural scan (both mutation-verified above), not merely asserted.
- `PROH-OPS-07-11` / `T-06-26`: `run_self_test`'s `run_kind` stays `'smoke'`, computed the same way it always was — untouched by this plan.
- `PROH-OPS-07-08`: OPS-07 not promoted — this plan is collection and analysis only; the hardware run is `06-18`.

## Known Stubs

None.

## User Setup Required

None — no external service configuration required. (The Pi operator's own `ENABLE_LOCK_PROFILE=1` environment step for `06-18`'s hardware run is that plan's concern, not this one's.)

## Next Phase Readiness

`06-18` can now run `--self-test --lock-profile` (or a real `--lock-profile` acceptance run) against the Pi and get back one JSON report carrying both the route latencies and the `lock_profile` block — including a CONFIRMED/REFUTED/INCONCLUSIVE verdict — with zero risk that requesting the diagnostic changes whether the run passes. The `INCONCLUSIVE` verdict observed on this developer machine is expected and correct for a low-concurrency, short-duration rehearsal; `06-18`'s concurrency-8, 600-second hardware run is the first invocation with a realistic chance of reaching `CONFIRMED` or `REFUTED`.

## Self-Check: PASSED

- `tests/pi_load_acceptance.py` — FOUND
- `tests/test_lock_profile.py` — FOUND
- Commit `37b31df` — FOUND
- Commit `60f9fe5` — FOUND

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-03*
