# Phase 05 — Deferred Items

Out-of-scope discoveries found while executing this phase. Logged, not fixed.

| # | Found during | File | Issue | Why deferred |
|---|--------------|------|-------|--------------|
| 1 | 05-01 post-merge gate | `tests/helpers.py` (`load_app`) | `load_app` writes every `extra_env` key into `os.environ` and never restores it, so any test that passes `extra_env` silently changes the environment for every later test module that reloads `dashboard.app`. This already caused one real regression (see below); the same hazard remains latent for `METRIC_SAMPLE_SECONDS`, `EXPIRE_DAYS`, `ALERT_*` and the rest. | Fixing the helper itself changes shared behaviour for the whole suite — some existing tests may be depending on the leak. Wants its own scoped change with a full-suite run, not a fix smuggled into a phase-05 UI plan. The concrete regression it caused **was** fixed (below). |

## Corrected record — the entry that used to live here was wrong

The original entry claimed `tests/test_runtime_ownership.py::RuntimeOwnershipTests::test_lease_takeover_records_one_monitoring_gap`
was a **pre-existing cross-test-isolation flake, unrelated to 05-01**. That was a misdiagnosis, and it was
deferred on a false premise.

What was actually true:

- The pre-phase baseline `515eee8` runs the full suite fully green (746 passed, 0 failures).
- After 05-01 the failure reproduced in **2/2** full-suite runs — deterministic, not intermittent.
- Minimal reproduction, 0.28s:
  `pytest tests/test_api_and_auth.py::ApiAndAuthTests::test_scan_status_never_reports_degraded_and_stale_together tests/test_runtime_ownership.py::RuntimeOwnershipTests::test_lease_takeover_records_one_monitoring_gap`

Mechanism: 05-01's new `test_scan_status_never_reports_degraded_and_stale_together` calls
`load_app({'WORKER_READY_SECONDS': '10', 'METRIC_SAMPLE_SECONDS': '5'})`. `load_app` never restores
`os.environ`, so `WORKER_READY_SECONDS=10` leaked into every later module. `test_runtime_ownership`
derives `recovered = started + WORKER_READY_SECONDS + 9`, so the simulated gap fell from 29s to 19s —
at or below the `ready_seconds=20` default in `queues.acquire_worker_lease`, so `_record_gap` recorded
nothing and the assertion saw 0 rows instead of 1.

The same leak also explains the intermittent `test_degraded_banner_reads_identically_in_both_themes_on_both_documents`
subtest failure (`theme='dark', path='/'`): with the leaked values the aging window narrows to 20s and
`worker_stale` flips at age 11s, so one second of real drift between seeding and the browser request
made the server report `worker_stale` instead of `worker_degraded` and the banner correctly stayed hidden.

Fix applied: the new test now restores `WORKER_READY_SECONDS` and `METRIC_SAMPLE_SECONDS` via
`addCleanup`. Full suite after the fix: 750 passed, 530 subtests passed, 0 failures.

## Entry 2 — 05-03: intermittent full-suite-load flake, confirmed not caused by this plan

| # | Found during | File | Issue | Why deferred |
|---|--------------|------|-------|--------------|
| 2 | 05-03 full-suite verification | `tests/test_ui_safety_integration.py::UiSafetyIntegrationTests::test_stale_to_fresh_page_persists_actions_and_records_recovery` | Real-wall-clock (`self.now = int(time.time())`), real Flask app, real SQLite worker-lease claim/finish sequence, then a Playwright `wait_for(timeout=18_000)` for "Monitoring gap recorded" text. Under full-suite resource contention this occasionally exceeds the 18s timeout. | 05-03 declares only `tests/test_ui_contract.py` and `tests/test_ui_states.py`; this file and test were never touched. Applying the corrected-diagnosis rigor from Entry 1 (a prior misdiagnosis here turned out to be a real deterministic env leak): confirmed this is **not** the same class of bug — grepped both files 05-03 modified for `load_app`/`os.environ`/`import os` (zero matches; the new tests never touch process environment, and use a static file server + fully-stubbed `page.route()`, not the real Flask app this failing test depends on). Ran `pytest -q` (full suite) three times against the complete 05-03 diff: run 1 failed only this test (754 passed); runs 2 and 3 both passed clean (755 passed, 0 failures, twice). The failing test also passes reliably in isolation. This is intermittent under load, not deterministic, and the mechanism (wall-clock worker-heartbeat aging + browser polling timeout) matches the same flake class already known in this phase (05-01's heartbeat-drift deviation), just a different test instance. Not fixed — out of scope for 05-03's declared files. |

Also logged to `.planning/WINDOWS.md` (kind: deviation).
