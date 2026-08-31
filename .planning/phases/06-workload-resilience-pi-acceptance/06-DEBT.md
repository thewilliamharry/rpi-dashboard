---
phase: 6
slug: workload-resilience-pi-acceptance
kind: debt-and-dispositions
created: 2026-09-01
---

# Phase 6 — Tracked Debt & Revision Dispositions

> A later verifier must read this before re-litigating anything in this phase: what was deliberately
> **not** done, why, and what evidence this phase already produced for the next evaluation to start from.

---

## 1. Deferred — awaiting a human decision

### D-DEBT-06-01 — narrow `_db_lock`'s scope now that WAL is in force

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Open Question 3, `PROJECT.md`'s `AR-03-01` accepted-risk note |
| **Status** | **Deferred — awaiting a human decision.** Not touched in Phase 6. |
| **Recorded in the plan** | `06-05-PLAN.md` decision D-01, `PROH-OPS-04-02`, and Task 1's `git diff`-scoped acceptance criterion |

**What was not done and why.** `_db_lock`'s scope in `dashboard/app.py` is unchanged at every one of its
25+ call sites. D-01 locked this boundary for Phase 6 explicitly: WAL only, `_db_lock` untouched.
`06-RESEARCH.md` Pitfall 4 is the reason this is a boundary and not an oversight: WAL governs
reader/writer blocking *across connections*, while `_db_lock` serializes access from *multiple threads
inside one gunicorn process* (`--workers 1 --threads 8`). Enabling WAL does not make `_db_lock`'s
serialization redundant — the two solve different problems, and relaxing the second is not a free
consequence of enabling the first. `PROH-OPS-04-02` forbids any route or job gaining unserialized
database access as a side effect of the journal-mode change; the scoped `git diff` against
`dashboard/app.py` in Task 1's acceptance criteria confirms zero change to any `_db_lock` occurrence in
this plan's commits.

**The evidence this phase produced that a future evaluation should start from:**

- The starting-mode evidence outcome for the production database is recorded below (see D-DEBT-06-03)
  — the production reading itself was not captured this phase, but the rollout logic is proven for
  both starting modes by `tests/test_workload_resilience.py::WalModeTests::test_connections_run_in_wal_mode_from_either_starting_mode`.
- `tests/test_workload_resilience.py::ConcurrentAccessTests::test_concurrent_web_and_worker_writers_are_corruption_free`
  proves a bounded stress run of eight `_db_lock`-serialized web-shaped writers plus one worker-shaped
  writer completes with zero unhandled exceptions, `PRAGMA integrity_check` returning `ok`, and every
  reported-committed write present afterward (PROH-OPS-04-01), all under WAL and with `_db_lock` in
  its current, unnarrowed form.
- `tests/test_workload_resilience.py::ConcurrentAccessTests::test_worker_restart_recovery_fences_the_dead_epoch`
  proves a worker restart correctly fences the dead epoch's claim, and that the dead epoch's terminal
  write is rejected with `LeaseLost` and changes nothing.
- The pre-existing `AR-03-01` accepted-risk note for `api_advanced_current` (`.planning/PROJECT.md`),
  the one route already outside `_db_lock` — its reasoning (a 30s maintenance-flock wait inside a
  process-global lock would stall every DB route behind a 5-second poll) is the baseline a `_db_lock`
  narrowing evaluation must reconcile with, not relitigate from scratch.

**What would need to be true to proceed.** A per-call-site audit of all `_db_lock` uses; a demonstration
that read-only routes no longer block behind a writer under WAL specifically (not merely an assumption
that WAL implies it); and a regression that fails if any route regains unserialized access it should
not have. None of that audit exists yet — this phase deliberately produced WAL-mode concurrency
evidence without touching the lock, per D-01.

**Explicitly not a bug.** `_db_lock` is correct as it stands today. This is an optimization opportunity,
not a defect; removing or narrowing it without the audit above would reintroduce the exact race it was
added to prevent.

---

### D-DEBT-06-03 — production starting journal mode never read

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Open Question 1, `06-05-PLAN.md` Task 1's `<human-check>` |
| **Status** | **Deferred — awaiting the next Pi deployment.** Not blocking; not a defect. |
| **Recorded in the plan** | `06-05-PLAN.md` Task 1 `<human-check>` (non-blocking evidence capture) and Task 3's acceptance criteria |

**What was not done and why.** This execution environment has no reachable Raspberry Pi and no copy of
a deployed `/data/dashboard.db` to run `python -m beacon.inventory --db /data/dashboard.db --output
<report.json>` against before this build lands. The deployed database's pre-switch `journal_mode` was
therefore **not observed** — it is recorded here as `unverified`, not silently assumed to be either
mode.

**Why this does not block the rollout.** The rollout does not depend on knowing the starting mode:
`connect_db` issues `PRAGMA journal_mode=WAL` unconditionally on every connection, and
`configured_journal_mode` reads back the mode actually in force. Both starting-mode paths converge on
the same end state and are proven against synthetic fixtures by
`tests/test_workload_resilience.py::WalModeTests::test_connections_run_in_wal_mode_from_either_starting_mode`
(one fixture left at SQLite's default rollback journal, one pre-set to WAL before `connect_db` ever
sees it) and by `tests/test_migrations.py::MigrationTests::test_a_wal_mode_deployment_inspects_backs_up_and_upgrades`
(a tracked lineage already carrying a non-empty `-wal` sidecar inspects, backs up, and upgrades
end-to-end). What is missing is the *production reading*, not the rollout's correctness.

**What would need to be true to proceed / close this entry.** On the next Pi deployment, run
`python -m beacon.inventory --db /data/dashboard.db --output /tmp/beacon-journal-mode-before.json`
before deploying this build, deploy, then run it again to
`/tmp/beacon-journal-mode-after.json`. Confirm `journal_mode` reads `wal` in the after-report (and note
whether the before-report already showed `wal`, in which case the deployment was a no-op confirmation
rather than a first-time conversion). Attach both reports as phase evidence and close this entry.
