---
phase: 6
slug: workload-resilience-pi-acceptance
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
status: planned
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-28
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded by `/gsd-plan-phase 6` from `06-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest `>=9.0.2,<10` [VERIFIED: dashboard/pyproject.toml] |
| **Config file** | `dashboard/pyproject.toml` `[tool.pytest.ini_options]` — `pythonpath = [".."]`, `testpaths = ["../tests"]` |
| **Quick run command** | `uv run --project dashboard python -m pytest -q -k <module_or_test>` |
| **Full suite command** | `uv run --project dashboard python -m pytest -q` |
| **Quick command runtime** | Sub-second to a few seconds per module; well inside the 120s budget below |
| **Full suite runtime** | *Not yet measured.* **06-01 Task 4 (wave 1) measures it once with `time uv run --project dashboard python -m pytest -q` and replaces this cell with the observed wall-clock duration and the date measured.** It is measured against a green suite: 06-01 Tasks 2 and 3 each carry a full-suite-exits-0 acceptance criterion, so by Task 4 the repository is green and the number is a real runtime rather than a failing run's. Nine tasks across this phase assert on an unscoped full-suite run, so this number is the contract they are budgeted against — it must be a measurement, not an estimate. |

---

## Sampling Rate

- **After every task commit:** Run `uv run --project dashboard python -m pytest -q -k <touched module>`
- **After every plan wave:** Run `uv run --project dashboard python -m pytest -q`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency (quick command):** 120 seconds for `pytest -q -k <touched module>`. This budget is fixed and does not move.
- **Max feedback latency (full suite):** provisionally 120 seconds, pending the measurement 06-01 Task 3 records above. Reconciliation rule, so the contract is never left violated: if the measured full-suite runtime is at or under 120 seconds, this line stands unchanged. If it exceeds 120 seconds, 06-01 Task 3 replaces this line with the measured value rounded up to the next 30 seconds, annotated as measured rather than assumed. The quick-command budget above is not weakened in either case — the two commands carry separate budgets because they answer different questions.
- **Why the distinction:** nine tasks in this phase verify with the unscoped full suite (06-01 T2/T3, 06-02 T2, 06-04 T2, 06-05 T1/T2/T3, 06-06 T1/T2). Holding an unmeasured suite to a quick-command budget is a contract that cannot be evaluated; measuring it once in wave 1 makes every later wave's assertion checkable.
- **Phase gate addendum:** OPS-07's Pi-class harness run is additionally required as human-gated evidence if no live Pi is reachable from the automated environment (see `06-RESEARCH.md` § Environment Availability).

---

## Per-Task Verification Map

> Task rows are filled once PLAN.md files exist. The requirement-level map below is the
> contract each task row must trace back to.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 06-01-T2 | 06-01 | 1 | OPS-03 | T-06-08, T-06-09 | Every tracked lineage at the previous schema version is admitted by the support floor; no test pins the tail migration version as a literal, so the next migration cannot lock deployments out silently | contract + migration | `uv run --project dashboard python -m pytest -q` | ✅ (extends existing) | ⬜ pending |
| 06-01-T3 | 06-01 | 1 | OPS-03 | T-06-01, T-06-02, T-06-03, T-06-08 | Thumbnail blobs live only in the bounded store; the migration never destroys the only copy; migrated blobs are preserved byte-for-byte; the support floor moves to target_version 10 in the same commit that makes 10 the tail; the tracer commits against a green suite | integration (tracer) + migration | `uv run --project dashboard python -m pytest -q` | ❌ W0 (this task creates `tests/test_workload_resilience.py`; the `thumbnail_relocation` guard extends existing `tests/test_migrations.py`) | ⬜ pending |
| 06-01-T4 | 06-01 | 1 | OPS-03 | T-06-02 | One module owns the thumbnail write; the worker-ownership contract declares the new database surface; the full-suite runtime is measured and recorded against a green suite | contract + measurement | `uv run --project dashboard python -m pytest -q` | ✅ | ⬜ pending |
| 06-02-T1 | 06-02 | 2 | OPS-03 | T-06-06, T-06-07, T-06-10 | TTL and total-byte budget enforced hourly; bad config falls back to the documented default | unit + integration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py tests/test_startup_ordering.py tests/test_worker_ownership_matrix.py` | ✅ | ⬜ pending |
| 06-03-T1 | 06-03 | 3 | OPS-02 | T-06-11, T-06-15 | Retry is bounded and deferred by real elapsed backoff; superseded revisions still fence | unit + integration | `uv run --project dashboard python -m pytest -q tests/test_durable_queues.py` | ✅ | ⬜ pending |
| 06-03-T2 | 06-03 | 3 | OPS-02 | T-06-12, T-06-13, T-06-14 | Exhausted retries reach a distinct degraded terminal state, visible in both themes, without blocking J1-J4 | integration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py -k preview_retry_bounded` | ✅ | ⬜ pending |
| 06-04-T1 | 06-04 | 4 | OPS-01 | T-06-16 | The essential lane is claimed by J1 and J2 alone, enforced by a static contract | contract | `uv run --project dashboard python -m pytest -q tests/test_worker_ownership_matrix.py` | ✅ | ⬜ pending |
| 06-04-T2 | 06-04 | 4 | OPS-01 | T-06-17, T-06-18, T-06-19 | Essential sampling stays within cadence under contention, judged by `freshness_state` | integration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py -k cadence_under_contention` | ✅ | ⬜ pending |
| 06-05-T1 | 06-05 | 5 | OPS-04 | T-06-21, T-06-22, T-06-24 | WAL is in force and read back; inspection, backup and upgrade all work with sidecars present; both starting modes converge without needing a Pi | integration + migration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py tests/test_migrations.py tests/test_backup_recovery.py` | ✅ | ⬜ pending |
| 06-05-T2 | 06-05 | 5 | OPS-04 | T-06-20, T-06-23, T-06-25 | Concurrent web/worker access is corruption-free; a restarted worker fences the dead epoch | integration | `uv run --project dashboard python -m pytest -q tests/test_worker_ownership_matrix.py tests/test_workload_resilience.py -k restart_recovery` | ✅ | ⬜ pending |
| 06-05-T3 | 06-05 | 5 | OPS-04 | T-06-24 | The `_db_lock` boundary is documented as deferred rather than silently unchanged (D-01); the docs stop asserting WAL as an ambient property and name the code that sets it | doc + contract | `uv run --project dashboard python -m pytest -q tests/test_release_contract.py tests/test_ui_contract.py` | ✅ | ⬜ pending |
| 06-06-T1 | 06-06 | 6 | OPS-07 | T-06-27, T-06-28, T-06-30 | The harness judges cadence with the product's own oracle and fails honestly on missing evidence | e2e / acceptance | `python tests/pi_load_acceptance.py --self-test && uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py` | ❌ W0 (this task creates it) | ⬜ pending |
| 06-06-T2 | 06-06 | 6 | OPS-07 | T-06-26, T-06-29 | A Pi-class run is labelled `acceptance`; a non-Pi run is labelled `smoke` and never counted as acceptance | e2e / acceptance | `uv run --project dashboard python -m pytest -q && python tests/pi_load_acceptance.py --self-test` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Phase Requirements → Behavior Map

| Req ID | Behavior under test |
|--------|---------------------|
| OPS-01 | J1/J2 (essential) freshness stays `fresh`/`aging` (never `stale`, per `freshness_state`) while J5/J6/J7/J8 fire concurrently under synthetic load |
| OPS-02 | A forced repeated preview capture failure exhausts a bounded retry count, reaches a distinct terminal "degraded" state, and never blocks J1/J2/J3/J4 dispatch |
| OPS-03 | After migration, `services.thumb_data` is NULL for all rows and the new thumbnail table holds the migrated blobs, size-capped and TTL-expiring |
| OPS-04 | Concurrent web (`_db_lock`-serialized, 8 threads) and worker writers against a shared SQLite file under WAL produce no corruption/lock errors across a bounded stress run; worker restart mid-job correctly resumes/fences per `background_job_health` |
| OPS-07 | A checked-in load harness runs a representative-load scenario and asserts response-time, RSS/CPU-vs-`mem_limit`, `freshness_state`, and `background_job_health` bounds |

---

## Wave 0 Requirements

- [ ] `tests/test_workload_resilience.py` — new file covering OPS-01 (cadence under contention), OPS-02 (bounded preview retry), OPS-04 (restart + concurrent access stress)
- [ ] `tests/pi_load_acceptance.py` (or `scripts/pi_load_acceptance.py`) — new, checked-in, repeatable load harness covering OPS-07, built on `requests`/`threading`/`psutil` (no new dependency)
- [ ] Extension to `tests/test_migrations.py` — new migration test for the thumbnail-table relocation and `services.thumb_data` emptying, following the existing preservation-snapshot pattern (snapshot source fixture columns and values before asserting the same data after additive upgrades)
- [ ] Framework install: none — pytest, psutil, and requests are already pinned dependencies

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Representative-load acceptance run on real Raspberry Pi-class hardware | OPS-07 | The automated execution environment cannot be confirmed to have physical/target Pi access; the success criterion explicitly names Pi-class hardware. Consistent with how `03-UAT.md` / `03.1-UAT.md` handled real-Pi hardware tests for this project. | Deploy the phase build to the target Pi, run `python tests/pi_load_acceptance.py --duration 600` against it, and attach the harness's asserted output (response times, RSS/CPU vs `mem_limit`, `freshness_state` timeline, `background_job_health` rows) as evidence. A run without a Pi is labelled `smoke` and never counted as acceptance (06-06 Task 2). |
| Production starting `journal_mode` reading from the deployed database | OPS-04 | Requires access to the deployed `/data/dashboard.db` (or a copy). Evidence only — the WAL rollout itself is proven for both starting modes by automated tests against synthetic fixtures, so this is not a gate. | Before deploying the phase build, run `python -m beacon.inventory --db /data/dashboard.db --output beacon-journal-mode-before.json`; deploy; run it again to `-after.json`; attach both. If unreachable, 06-05 Task 3 records the starting mode as `unverified` in `06-DEBT.md` as `D-DEBT-06-03` and the item stays open — it is never recorded as observed. |

*The harness itself must still be built, checked in, and automated — only its execution on real hardware is human-gated.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
