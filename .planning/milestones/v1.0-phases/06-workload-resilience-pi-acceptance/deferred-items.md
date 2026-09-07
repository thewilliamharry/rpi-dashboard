# Phase 06 — Deferred Items

Out-of-scope discoveries found while executing this phase. Logged, not fixed.

## Entry 1 — 06-12: pre-existing, deterministic UI browser-test failure, confirmed unrelated to this plan's diff

| # | Found during | File | Issue | Why deferred |
|---|--------------|------|-------|--------------|
| 1 | 06-12 full-suite verification (Task 1) | `tests/test_ui_states.py::UiStateBrowserTests::test_safety_matrix_keeps_recovery_tls_errors_and_narrow_controls_distinct` | Fails at `self.assertTrue(page.locator('#meta-error').is_visible())` (`tests/test_ui_states.py:1005`) after submitting `#meta-form` with `form.requestSubmit()`: the expected client-side validation error banner never becomes visible. | 06-12's declared `files_modified` are `tests/services_route_profile.py` (new), `tests/test_services_route_scaling.py`, and `.planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE.md` — this plan writes no line of `dashboard/app.py`, `dashboard/app.js`, or `tests/test_ui_states.py`. |

**Evidence this is not caused by 06-12's diff.** `git diff f672832ec46725060db3a8a82e6fb981e9fcd3a5 HEAD -- tests/test_ui_states.py` and `git diff f672832ec46725060db3a8a82e6fb981e9fcd3a5 HEAD -- dashboard/` are both empty (0 lines) at the point this failure was first observed — the file containing the failing test and every server/client file it exercises are byte-identical to the pre-plan baseline. The test also fails in complete isolation (`pytest tests/test_ui_states.py::UiStateBrowserTests::test_safety_matrix_keeps_recovery_tls_errors_and_narrow_controls_distinct`, no other test file loaded), so it is not cross-test-isolation contamination from anything this plan added either.

**Not the same as the known D-DEBT-06-05 flake.** `06-DEBT.md`'s recorded flaky test is `tests/test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced`, measured at roughly 1-in-20 and *intermittent*. This is a different test, in a different file, testing a different surface (client-side form-validation UI, not worker ownership fencing).

**What was actually established, applying the corrected-diagnosis rigor from `05-deferred-items.md` Entry 1 (a prior misdiagnosis there turned out to be a real regression) — this one held up under the same scrutiny:**
- Fails deterministically: 4/4 runs in isolation (`1 failed` every time, not intermittent).
- Not caused by 06-12's diff: confirmed by empty `git diff` against the pre-plan baseline for both the test file and the entire `dashboard/` tree.
- Full suite otherwise green at 839 passed / 561 subtests passed (837 baseline + 4 new `ServicesRouteProfilerGuardTests` tests, all passing) with only this one pre-existing failure plus one now-fixed flake in this plan's own new test (see below).

**Open question for phase verification (unresolved by this entry, same caveat 05's Entry 2 left open):** whether this test also fails at the phase-06 pre-round baseline, or whether it is specific to this execution environment (e.g. an installed Playwright/Chromium version drift since it was last verified green). Establishing that requires running it against an earlier commit in a comparable environment, which this plan's scope (a read-only `/api/services` profiler) does not include. Not fixed here.

Also logged to `.planning/WINDOWS.md` (kind: deviation).

## Entry 2 — 06-12: new-test flake, fixed within this plan's own scope (not deferred, recorded for the record)

`tests/test_services_route_scaling.py::ServicesRouteProfilerGuardTests::test_a_check_count_independent_bucket_does_not_track_the_check_row_ratio` (a test this plan's Task 2 added) flaked (~1 run in 5) at its original `repeats=2` fixture: `maintenance_windows_read`'s accumulated cost per run (under 0.02ms) was close enough to timer-resolution noise that its measured growth ratio occasionally crossed the discrimination threshold by chance. Diagnosed by direct repetition (`pytest -q` in a loop) before it ever reached a merge gate. Fixed by raising the fixture's `repeats` to 20, which keeps the bucket's accumulated tottime an order of magnitude further from the noise floor while the test still completes in low single-digit seconds; confirmed stable across 15 additional isolated repeats and one full-suite run after the fix, both clean. This is Rule 1 (auto-fix a bug in code this task itself just wrote), not a deferred item — included here only so the investigation is on the record next to Entry 1's.
