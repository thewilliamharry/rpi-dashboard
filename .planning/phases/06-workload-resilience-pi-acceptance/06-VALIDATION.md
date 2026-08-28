---
phase: 6
slug: workload-resilience-pi-acceptance
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
status: draft
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
| **Estimated runtime** | ~TBD (measure at Wave 0; full suite is the repo `workflow.test_command`) |

---

## Sampling Rate

- **After every task commit:** Run `uv run --project dashboard python -m pytest -q -k <touched module>`
- **After every plan wave:** Run `uv run --project dashboard python -m pytest -q`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 120 seconds for the quick command
- **Phase gate addendum:** OPS-07's Pi-class harness run is additionally required as human-gated evidence if no live Pi is reachable from the automated environment (see `06-RESEARCH.md` § Environment Availability).

---

## Per-Task Verification Map

> Task rows are filled once PLAN.md files exist. The requirement-level map below is the
> contract each task row must trace back to.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| _pending planner_ | — | — | OPS-01 | — | Essential sampling stays within cadence under contention | integration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py -k cadence_under_contention` | ❌ W0 | ⬜ pending |
| _pending planner_ | — | — | OPS-02 | — | Bounded preview retry reaches a terminal degraded state, never blocks core jobs | integration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py -k preview_retry_bounded` | ❌ W0 | ⬜ pending |
| _pending planner_ | — | — | OPS-03 | — | Thumbnail blobs off the primary telemetry path, size-capped and TTL-expiring | migration + unit | `uv run --project dashboard python -m pytest -q tests/test_migrations.py -k thumbnail_relocation` | ❌ W0 | ⬜ pending |
| _pending planner_ | — | — | OPS-04 | — | Concurrent web/worker SQLite access and restart recovery are corruption-free and fenced | integration | `uv run --project dashboard python -m pytest -q tests/test_worker_ownership_matrix.py tests/test_workload_resilience.py -k restart_recovery` | ❌ W0 | ⬜ pending |
| _pending planner_ | — | — | OPS-07 | — | Representative-load run meets response-time, resource-budget, freshness and job-health bounds | e2e / acceptance | `python tests/pi_load_acceptance.py --duration 600` | ❌ W0 | ⬜ pending |

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
| Representative-load acceptance run on real Raspberry Pi-class hardware | OPS-07 | The automated execution environment cannot be confirmed to have physical/target Pi access; the success criterion explicitly names Pi-class hardware. Consistent with how `03-UAT.md` / `03.1-UAT.md` handled real-Pi hardware tests for this project. | Deploy the phase build to the target Pi, run `python tests/pi_load_acceptance.py --duration 600` against it, and attach the harness's asserted output (response times, RSS/CPU vs `mem_limit`, `freshness_state` timeline, `background_job_health` rows) as evidence. |

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
