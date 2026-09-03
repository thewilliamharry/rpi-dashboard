---
phase: 06-workload-resilience-pi-acceptance
plan: 19
subsystem: testing
tags: [ast-invariant, concurrency-testing, lock-profile, falsifiable-prediction, db-lock-audit]

requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-15's LockScopePreservationTests/instrument_cost_ns_per_acquisition, 06-16's held-region decomposition and clamped_python_count guard, 06-17's evaluate_lock_attribution three-valued verdict and _live_beacon_server rehearsal, 06-18's D-DEBT-06-01 'Round 4 reopening' PROH-OPS-04-05 prerequisites and D-DEBT-06-15's fix-sizing arithmetic"
provides:
  - "06-LOCK-AUDIT.md — the per-call-site review of all 28 with-_db_lock sites PROH-OPS-04-05 prerequisite 1 requires, api_services named as this round's sole narrowing target"
  - "LockScopeInvariantTests — the T-06-24 no-escape invariant asserted directly (union of every _db_lock block a function owns, correct on the two two-block functions), plus audit-coverage enforcement so 06-LOCK-AUDIT.md cannot silently go stale"
  - "NarrowedShapeConcurrentAccessTests — PROH-OPS-04-05 prerequisite 3, proving the narrowed shape's own hazard (snapshot consumed after connection close) is safe under 8 concurrent readers and a concurrent writer"
  - "services_min_hold_over_scan_status_hold_ratio and evaluate_narrowing_outcome/NARROWING_OUTCOME_PREDICTIONS — D-DEBT-06-14 closed, and 06-20's own falsifiable post-fix prediction written before the fix exists"
affects: [06-20-narrowing-plan, 06-21-hardware-measurement, 06-24-secure-phase-rerun]

actuals:
  tokens: 15970
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "AST-derived (function, line) site sets asserted for set equality (both directions) against a hand-authored audit table, so a document and a source-of-truth cannot silently diverge"
    - "Per-reader distinctly-seeded ports so a mispaired-snapshot/result defect is detectable by construction, not by timing luck"
    - "A pure diagnostic verdict function wired into a report block that is proven, both structurally (AST) and behaviorally (a forced verdict on a live run), to never influence the run's actual pass/fail oracle"

key-files:
  created:
    - .planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md
  modified:
    - tests/test_lock_profile.py
    - tests/test_workload_resilience.py
    - tests/pi_load_acceptance.py
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "The AST no-escape rule excludes not only the function's own _db_lock with-blocks but ANY with-statement anywhere in the function that rebinds one of the same bound names (e.g. a sibling `with _worker_write_transaction(...) as conn:`) -- without this, the rule produced false positives on every function that reuses the identifier `conn` for an unrelated, independently-opened connection in a different branch. Verified against dashboard/app.py at HEAD: zero violations, 26 owning functions, 28 sites, before this refinement the same rule produced 31 false-positive violations across 3 functions."
  - "Test 2's second test seeds 8 DISTINCT ports (one per reader thread) rather than 8 readers sharing one port, so a mispaired result/snapshot defect is deterministically detectable -- with identical seed data across all readers, a mispairing mutation could not produce an observable difference."
  - "The required Task 3 mutation ('services_refutation_python_share_of_hold temporarily raised above the CONFIRMED world's own share') is mathematically incapable of flipping a CONFIRMED verdict as literally worded, since the refutation condition is `python_share >= threshold` -- raising the threshold only makes refutation HARDER to trigger. Applied the mutation in the direction that actually changes the verdict (lowered to at-or-below the world's own share, 0.05 -> 0.03) and recorded the observed CONFIRMED -> REFUTED -> CONFIRMED (reverted) sequence."
  - "evaluate_narrowing_outcome's precondition order places clamped_python_count non-zero AFTER acquisitions-below-minimum and BEFORE reading python_share/sql_share, mirroring evaluate_lock_attribution's precondition-first, refutation-before-confirmation ordering (D-DEBT-06-09, D-DEBT-06-10)."

patterns-established:
  - "A rebinding-with-subtree exclusion for AST escape-detection rules keyed on a shared variable name (`conn`) -- generalizable to any future AST invariant over dashboard/app.py that walks execution paths rather than lexical containment."

requirements-completed: []

coverage:
  - id: D1
    description: "06-LOCK-AUDIT.md — 28-row per-call-site audit (26 distinct functions) satisfying PROH-OPS-04-05 prerequisite 1, enforced by LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit"
    requirement: "OPS-04"
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit"
        status: pass
      - kind: unit
        ref: "tests/test_lock_profile.py::LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock"
        status: pass
    human_judgment: false
  - id: D2
    description: "NarrowedShapeConcurrentAccessTests — PROH-OPS-04-05 prerequisite 3, the narrowed shape's snapshot-survives-connection-close guarantee under 8 readers and a concurrent writer"
    requirement: "OPS-04"
    verification:
      - kind: unit
        ref: "tests/test_workload_resilience.py::NarrowedShapeConcurrentAccessTests::test_snapshot_materialized_under_the_lock_survives_connection_close"
        status: pass
      - kind: unit
        ref: "tests/test_workload_resilience.py::NarrowedShapeConcurrentAccessTests::test_out_of_lock_computation_matches_a_serial_oracle_under_a_concurrent_writer"
        status: pass
    human_judgment: false
  - id: D3
    description: "D-DEBT-06-14 closed: services_min_hold_over_scan_status_hold_ratio replaces the retired absolute band; round 4's own figures replayed through the renamed check HOLD"
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::LockAttributionVerdictTests::test_round_4_measured_hold_figures_hold_against_the_renamed_ratio_check"
        status: pass
      - kind: unit
        ref: "tests/test_lock_profile.py::LockAttributionVerdictTests::test_predictions_match_the_verification_reports_own_stated_figures"
        status: pass
    human_judgment: false
  - id: D4
    description: "evaluate_narrowing_outcome / NARROWING_OUTCOME_PREDICTIONS — 06-20's own falsifiable prediction, written before the fix, never influencing overall_passed/failure_reasons (PROH-OPS-07-13)"
    verification:
      - kind: unit
        ref: "tests/test_lock_profile.py::NarrowingOutcomeVerdictTests (9 tests, all branches + purity + structural + behavioral non-leak)"
        status: pass
    human_judgment: false

duration: 43min
completed: 2026-09-03
status: complete
---

# Phase 06 Plan 19: The 28-site lock audit, the narrowed shape's own proof, and the fix's falsifiable prediction

**`06-LOCK-AUDIT.md`'s 28-row per-call-site review is enforced by an AST invariant that asserts `T-06-24` directly (no database access escapes its owning `_db_lock` block, correct on the two two-block functions), `NarrowedShapeConcurrentAccessTests` proves the shape `06-20`'s narrowing creates is safe under 8 concurrent readers and a concurrent writer, and `evaluate_narrowing_outcome` gives `06-21` a falsifiable prediction about the fix -- written here, before the fix exists.**

## Performance

- **Duration:** 43 min
- **Started:** 2026-09-03T19:35:00+03:00 (approx.)
- **Completed:** 2026-09-03T20:18:00+03:00 (approx.)
- **Tasks:** 3 of 3 complete
- **Files modified:** 4 (1 created: `06-LOCK-AUDIT.md`; 3 modified: `tests/test_lock_profile.py`, `tests/test_workload_resilience.py`, `tests/pi_load_acceptance.py`; plus `06-DEBT.md` across two commits)

## Accomplishments

- **Audited all 28 `with _db_lock` sites across 26 distinct functions** (`process_preview_requests` and `api_service_meta` each own two — the only two that do), recorded in `06-LOCK-AUDIT.md` with per-site function/line/form/read-write/non-DB-work/narrowed-this-round columns.
- **`LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock`** asserts the `T-06-24` invariant directly — no connection use, and no `connect_db`/`get_db`/`database_access`/`read_transaction`/`write_transaction` call, escapes its owning function's union of `_db_lock` blocks. Correctly passes at HEAD for both two-block functions, with neither excluded, special-cased, or allow-listed.
- **`LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit`** derives the `(function, line)` set by AST and asserts set equality in both directions against `06-LOCK-AUDIT.md`'s table, plus separately-asserted row count (28) and distinct-function count (26).
- **`NarrowedShapeConcurrentAccessTests`** proves the narrowed shape's own hazard — a snapshot fetched inside `_db_lock` and consumed (fields read, computation run) after the with-block and its connection have closed — is correct and readable under 8 concurrent readers, and that out-of-lock computation over that snapshot matches a serial oracle under a genuinely concurrent writer, with `PRAGMA integrity_check` intact.
- **`D-DEBT-06-14` closed**: `services_min_hold_over_scan_status_hold_ratio` (a same-run ratio, floor 20.0) replaces the retired absolute `[200ms, 500ms]` band. Round 4's own measured figures (596,245,129ns / 2,531,729ns = 235.5) replayed through the renamed `services_hold_dominates_scan_status_hold` check HOLD comfortably above the floor — demonstrating the retired band's failure was a property of the band, not of the data.
- **`evaluate_narrowing_outcome` / `NARROWING_OUTCOME_PREDICTIONS`**: `06-20`'s own falsifiable prediction, written before the fix and before `06-21`'s hardware measurement, gated on `clamped_python_count == 0` before trusting the derived `python_share`/`sql_share` remainder (D-DEBT-06-10's lesson applied directly). `PROH-OPS-07-13` minted and honoured, proven both structurally (AST, mirroring `test_structural_arm_lock_profile_never_feeds_the_verdict`) and behaviorally (a forced-REFUTED live run matches the same run without the diagnostic block).
- **`D-DEBT-06-16` filed**: two sites the audit found holding non-database work under the lock beyond `api_services` (`api_service_meta`'s PUT handler, `recover_worker_state`), deliberately not narrowed this round.
- **Suite result: 935 passed, 561 subtests passed, zero failures** — no NEW failures, and notably `test_disabled_wrapper_path_costs_nothing_measurable` (recorded as a real, reproducible failure in `06-18-SUMMARY.md`'s Issues Encountered) did NOT reproduce this run either.

## Task Commits

1. **Task 1: Audit all 28 `_db_lock` call sites, and make the audit an invariant a test enforces** — `379de11` (test)
2. **Task 2: Prove the narrowed shape's own failure mode does not occur under a concurrent writer** — `c391cd2` (test)
3. **Task 3: Replace the absolute hold band with a same-run ratio, and write the fix's own falsifiable prediction** — `e8541e9` (test)

**Plan metadata:** this SUMMARY's own commit (below).

## Files Created/Modified

- `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md` — new. 28-row per-call-site table (26 distinct functions), `AR-03-01`'s `api_advanced_current` exception recorded, future narrowing candidates section.
- `tests/test_lock_profile.py` — added `LockScopeInvariantTests` (6 tests), `LockAttributionVerdictTests::test_round_4_measured_hold_figures_hold_against_the_renamed_ratio_check`, updated `test_predictions_match_the_verification_reports_own_stated_figures` to key-set equality, added `NarrowingOutcomeVerdictTests` (9 tests).
- `tests/test_workload_resilience.py` — added `NarrowedShapeConcurrentAccessTests` (2 tests). `ConcurrentAccessTests` untouched (additions only, confirmed via `git diff`).
- `tests/pi_load_acceptance.py` — retired `services_min_median_hold_ns`/`services_max_median_hold_ns`, added `services_min_hold_over_scan_status_hold_ratio`; renamed `services_median_hold_in_band` check to `services_hold_dominates_scan_status_hold`; added `NARROWING_OUTCOME_PREDICTIONS` and `evaluate_narrowing_outcome`; wired `summary['narrowing_outcome']` into `_collect_lock_profile`.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — filed `D-DEBT-06-16`; closed `D-DEBT-06-14` with closure evidence.

## Decisions Made

- **The AST no-escape rule needed a rebinding-with-subtree exclusion beyond the plan's literal description.** The plan's algorithm ("exclude the union of the function's own `_db_lock` with-subtrees, then flag any Load of a bound name or escape call elsewhere in the function") produced 31 false-positive violations across 3 functions at HEAD when first implemented literally: `_mutation_write_transaction`, `_legacy_do_discovery`, and `_legacy_do_uptime_check` all reuse the identifier `conn` for a SEPARATE, independently-opened connection inside a sibling `with _worker_write_transaction(...) as conn:` or `with _mutation_write_transaction(...) as conn:` block. The rule was extended to also exclude the subtree of ANY with-statement (anywhere in the function, not just `_db_lock`-owning ones) that itself rebinds one of the same bound names — since inside such a block, the name refers to a different connection, not the escaped one. After this fix: zero violations at HEAD, verified directly by script before writing the committed test.
- **`NarrowedShapeConcurrentAccessTests`' second test seeds 8 distinct ports (one per reader) rather than 8 readers sharing one port.** With all readers reading identical seed data, the required "computed over a DIFFERENT thread's snapshot" mutation could not produce an observable difference (all snapshots would be byte-identical) — making the test non-discriminating for exactly the defect class it exists to catch. Per-reader distinct ports with distinct RNG seeds make a mispairing mutation deterministically detectable.
- **Task 3's required mutation direction was corrected from the plan's literal wording.** "`services_refutation_python_share_of_hold` temporarily raised above the CONFIRMED world's own share is observed to change that world's verdict" cannot hold mathematically: the refutation condition is `python_share >= threshold`, so raising the threshold can only make refutation harder to trigger, never easier — a CONFIRMED world's verdict cannot flip by raising this constant. Applied the mutation in the direction that actually produces the described effect (lowering the threshold to at-or-below the world's own share) and recorded the observed before/after verdicts.
- **`evaluate_narrowing_outcome` reuses `min_acquisitions_for_median` from `LOCK_ATTRIBUTION_PREDICTIONS` by reference, never restating the literal**, per the plan's explicit instruction, so the two prediction sets cannot drift on this shared floor.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] The literal AST escape-detection algorithm produced false positives on identifier reuse across unrelated with-statements**
- **Found during:** Task 1, before writing the committed test (caught in a standalone validation script, not shipped)
- **Issue:** A rule keyed only on "the union of the function's own `_db_lock` with-blocks, exclude those, flag everything else" reports a sibling `with _worker_write_transaction(...) as conn:` block's `conn` uses as escapes of the `_db_lock` connection, since both bindings share the identifier `conn`.
- **Fix:** Added `_rebinding_with_subtrees`, excluding the subtree of any with-statement (anywhere in the function) that itself rebinds one of the bound names — not only `_db_lock`-owning ones.
- **Files modified:** `tests/test_lock_profile.py` (the fix was made before the first commit; no separate revert/re-fix cycle needed in git history)
- **Verification:** Standalone script confirmed zero violations across all 26 owning functions at HEAD before the test was written into the suite; `test_no_database_access_escapes_the_db_lock` passes and both required hand-applied mutations fail it as designed.
- **Committed in:** `379de11` (Task 1 commit — the corrected algorithm shipped directly; no separate fix commit needed)

---

**Total deviations:** 1 auto-fixed (Rule 1 — algorithm correction found and fixed before the test was ever committed in a broken state)
**Impact on plan:** No scope creep. The correction was necessary for the invariant to be non-vacuously true at HEAD, which the plan itself requires ("The same test PASSES unchanged at HEAD").

## Issues Encountered

**The Task 3 mutation instruction, as literally worded, describes a change that cannot produce the stated effect.** See Decisions Made above — the mutation was applied in the mathematically-necessary direction (lowered, not raised) to produce and record the required observable verdict change. Both readings agree on the underlying intent (demonstrate the guard is sensitive to this threshold); only the specific magnitude/direction of the recorded mutation differs from the plan's literal phrasing.

**Nothing else required deviation.** All five required mutations (two in Task 1, two in Task 2, one in Task 3) were hand-applied, observed to fail with the recorded verbatim text below, and reverted before the corresponding task's commit.

### Mutation-verification record (all five, verbatim observed failures)

**Task 1, mutation 1 — dedent `preview_rows = conn.execute(...)` out of `api_services`' with-block:**
```
AssertionError: [('api_services', 2972, 'conn')] is not false : database access escaped its owning
_db_lock block: [('api_services', 2972, 'conn')] -- see D-DEBT-06-01, PROH-OPS-04-05 and
06-SECURITY.md T-06-24 before editing this assertion. If this fails at HEAD (not against a
hand-applied mutation), the defect is in this rule, never in dashboard/app.py.
```
Reverted; `git diff -- dashboard/app.py` confirmed empty afterward.

**Task 1, mutation 2 — add a `get_db()` call after the with-block in `api_services`:**
```
AssertionError: [('api_services', 2976, 'get_db')] is not false : database access escaped its owning
_db_lock block: [('api_services', 2976, 'get_db')] -- see D-DEBT-06-01, PROH-OPS-04-05 and
06-SECURITY.md T-06-24 before editing this assertion. If this fails at HEAD (not against a
hand-applied mutation), the defect is in this rule, never in dashboard/app.py.
```
Reverted; `git diff -- dashboard/app.py` confirmed empty afterward.

**Task 2, mutation 1 — `_snapshot_checks_under_lock` returns an unconsumed cursor instead of a materialized list:**
```
AssertionError: False is not true : reader thread(s) raised: [ProgrammingError('Cannot operate on a
closed database.'), ProgrammingError('Cannot operate on a closed database.'), ... ] (all 8 threads)
```
Reverted.

**Task 2, mutation 2 — `_uptime_summary` computed over a DIFFERENT reader thread's snapshot (mispaired result/checks):**
```
AssertionError: Tuples differ: (66.667, [-1, -1, -1, -1, -1, -1, -1, -1, [650 chars]667]) !=
(73.333, [-1, -1, -1, -1, -1, -1, -1, -1, [648 chars]833])
First differing element 0: 66.667 != 73.333
... : port 8090: out-of-lock result did not match its own snapshot recomputed serially
```
Reverted.

**Task 3, mutation — `services_refutation_python_share_of_hold` lowered to at-or-below the CONFIRMED world's own `python_share` (0.05):**
```
BEFORE (threshold 0.20): CONFIRMED — "every prediction held: /api/services' python_share sits at or
below the confirmation threshold, its sql_share sits at or above its own threshold, and utilisation
is below the post-narrowing superlinear threshold."
AFTER (threshold lowered to 0.03): REFUTED — "/api/services' python_share is 0.0500, at or above the
0.03 refutation threshold -- the narrowing did not move the Python-side work out of the critical
section."
REVERTED (threshold restored to 0.20): CONFIRMED
```
No repository file was modified for this mutation — it was demonstrated against an in-memory copy of `NARROWING_OUTCOME_PREDICTIONS` in an interactive Python session, so no `git diff` revert was needed. See Issues Encountered above for why the direction differs from the plan's literal wording.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

**`PROH-OPS-04-05`'s prerequisites 1 and 3 are met**, and prerequisite 2 (a demonstration that read-only routes no longer block behind a writer under WAL specifically) is addressed as recorded prose in `06-LOCK-AUDIT.md`, backed by the invariant test rather than assumed. Prerequisite 4 (`/gsd-secure-phase 06` re-run) remains scoped to `06-24`, after the narrowing lands, per the plan's own sequencing.

**What `06-20` inherits directly, so it does not need to re-derive scope:**
- `_db_lock`'s scope is unchanged by this plan (`git diff --quiet -- dashboard/app.py` held throughout) — the fence `06-18` lifted for the follow-up plan is still exactly where `06-20` will operate.
- `06-LOCK-AUDIT.md`'s 28-site table and `LockScopeInvariantTests`' invariant are the new, stronger closure evidence for `T-06-24` that `06-20` re-closes on, replacing `LockScopePreservationTests`' frozen-scope pin (which `06-20` retires deliberately, in the same commit as the narrowing — expected and correct, not something to suppress).
- `NarrowedShapeConcurrentAccessTests` is the proof, ready and passing, that the shape `06-20` creates (snapshot materialized under the lock, consumed after connection close) is safe under load — `06-20` does not need to write this proof itself.
- `evaluate_narrowing_outcome` and `NARROWING_OUTCOME_PREDICTIONS` are wired and ready for `06-21`'s hardware measurement to read; `06-20` itself does not need to touch `tests/pi_load_acceptance.py` for this.
- `D-DEBT-06-16` (two future narrowing candidates beyond `api_services`) is filed for a later round, not `06-20`'s scope.

**Suite floor for future rounds:** 935 passed, 561 subtests, zero failures at this commit — a clean baseline for `06-20` to build on, with no outstanding flaky-test caveat to carry forward from this round.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-03*

## Self-Check: PASSED

- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md`
- FOUND: `.planning/phases/06-workload-resilience-pi-acceptance/06-19-SUMMARY.md`
- FOUND commit `379de11` (Task 1)
- FOUND commit `c391cd2` (Task 2)
- FOUND commit `e8541e9` (Task 3)
- Confirmed: `git diff --quiet -- dashboard/app.py` holds (no production code changed)
- Confirmed: `git diff --quiet -- .planning/REQUIREMENTS.md` holds (OPS-07 stays Pending)
- Confirmed: full suite `935 passed, 561 subtests passed` — zero failures
