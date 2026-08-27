# Phase 05 — Deferred Items

Out-of-scope discoveries found while executing this phase. Logged, not fixed.

| # | Found during | File | Issue | Why deferred |
|---|--------------|------|-------|--------------|
| 1 | 05-01 Task 3 | `tests/test_runtime_ownership.py::RuntimeOwnershipTests::test_lease_takeover_records_one_monitoring_gap` | Fails intermittently when run as part of the full `pytest -q` suite (`AssertionError: 0 != 1`, expecting one `monitoring_gap` event row) but passes reliably in isolation. Not caused by, and not in a file touched by, plan 05-01 — this test exercises `beacon_queues.acquire_worker_lease`/`renew_worker_lease` and has no dependency on `diagnosis.py`'s `worker_freshness`/`worker_degraded` or any file this plan modified. | Pre-existing cross-test-isolation flake surfaced by running the full suite twice during this plan's verification. Fixing it means diagnosing whatever shared/global state (timing, a leaked thread, or a shared SQLite lock) leaks across test classes — scope this plan does not own. Recorded here so the next executor/verifier who sees a red full-suite run for this test knows it is not a regression from 05-01. |
