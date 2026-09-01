---
status: testing
phase: 06-workload-resilience-pi-acceptance
source: [06-VERIFICATION.md]
started: 2026-09-01T00:00:00Z
updated: 2026-09-01T00:00:00Z
---

## Current Test

number: 1
name: Real Raspberry Pi-class acceptance run (OPS-07)
expected: |
  On a confirmed Raspberry Pi-class target with the Phase 6 build deployed, the checked-in
  acceptance harness completes a representative-load run and reports:

    - `run_kind: "acceptance"` (NOT `"smoke"` — smoke means it did not run against Pi-class hardware)
    - the host correctly detected as Pi-class
    - `overall_passed: true`
    - no failed job-health rows
    - J1-J4 never observed `stale` for the duration of the run
    - resource budgets within limits
    - route p95 latencies within limits

  Command:

    python tests/pi_load_acceptance.py --duration 600 \
      --base-url http://127.0.0.1 --db /data/dashboard.db \
      --output beacon-acceptance.json
awaiting: user response

## Tests

### 1. Real Raspberry Pi-class acceptance run (OPS-07)
expected: Harness reports `run_kind: "acceptance"`, Pi-class host, `overall_passed: true`, no failed job-health rows, J1-J4 never `stale`, resource budgets and route p95s within limits.
result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps

Four of the five Phase 6 success criteria were verified automatically against the codebase and
are not part of this UAT:

1. Cadence isolation under contention (OPS-01) — verified
2. Bounded preview retry and visible degraded state (OPS-02) — verified
3. Bounded thumbnail store off the telemetry path (OPS-03) — verified
4. Restart / concurrency / failed-job recovery coverage (OPS-04) — verified

Only criterion 5 (OPS-07) requires hardware unreachable from the execution environment. The
harness that produces this evidence is complete and was independently confirmed working via its
smoke path; only the hardware execution is outstanding. Tracked as `D-DEBT-06-04` in `06-DEBT.md`.

### Carried-forward items for decision (not blocking this UAT)

- **WR-01** (`dashboard/beacon/inventory.py:41-56`, code-review Warning, independently reproduced
  by the verifier): the WAL read-only-inspection fallback requires filesystem write access to
  create the `-shm` sidecar, so inspecting a WAL database on read-only media fails. This is a real
  regression against the copy-then-lock-down workflow the phase's own README section recommends,
  and no test covers a non-writable source directory.
- **WR-02** (`dashboard/app.py:3054-3062`, code-review Warning): `thumb_state` checks `degraded`
  before `has_thumb` and can report `"degraded"` while a valid thumbnail is still served. Scoped
  to an API field with zero frontend consumers — the dashboard's degraded-state UI correctly uses
  `preview_status` — so it does not affect the shipped UI.
- **Flaky test**: `tests/test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced`
  fails ~1 run in 20, measured at an identical rate before and after this phase's changes. Not a
  Phase 6 regression; flagged for separate follow-up.
