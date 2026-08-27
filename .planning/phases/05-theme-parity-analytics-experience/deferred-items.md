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
