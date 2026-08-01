---
phase: 01-behavioral-safety-runtime-ownership
plan: 11
subsystem: durable-queue-ownership
tags: [sqlite, queues, leases, heartbeat, fencing, discovery]
requires:
  - phase: 01-09
    provides: managed SQLite connections and concurrent writer safety
provides:
  - Heartbeated scan execution with immutable owner tokens
  - Claim-time recovery of abandoned scans and deadline expiry
  - Deterministic takeover and stale-worker fencing coverage
affects: [worker-queues, discovery, runtime-ownership]
tech-stack:
  added: []
  patterns: [scan lease heartbeat, token-fenced terminal writes, recover-before-claim transaction]
key-files:
  created:
    - .planning/phases/01-behavioral-safety-runtime-ownership/01-11-SUMMARY.md
  modified:
    - dashboard/beacon/queues.py
    - dashboard/app.py
    - tests/test_durable_queues.py
key-decisions:
  - "Every scan claim receives a new opaque owner token, which all renewal and terminal transitions must present."
  - "Scan polling recovers expired leases and expires missed deadlines before selecting the next request in the same SQLite write transaction."
  - "Discovery starts a bounded half-lease heartbeat and skips terminal writes after authority is lost."
patterns-established:
  - "Lease fencing: ownership tokens, state, unexpired lease, and live request deadline are predicates for renewal and terminal writes."
  - "Deterministic queue concurrency tests drive injected timestamps instead of wall-clock sleeps."
requirements-completed: [FND-04]
coverage:
  - id: D1
    description: "Long-running discovery keeps its scan lease alive beyond 30 seconds and completes under the original token."
    requirement: FND-04
    verification:
      - kind: integration
        ref: "tests/test_durable_queues.py#test_long_scan_heartbeat_renews_before_expiry_and_completes"
        status: pass
    human_judgment: false
  - id: D2
    description: "Normal claim polling recovers abandoned running scans or expires requests past their deadline."
    requirement: FND-04
    verification:
      - kind: integration
        ref: "tests/test_durable_queues.py#test_claim_recovers_expired_running_scan_and_takes_it_over_same_poll"
        status: pass
      - kind: integration
        ref: "tests/test_durable_queues.py#test_claim_expires_past_deadline_running_scan_instead_of_reclaiming_it"
        status: pass
    human_judgment: false
  - id: D3
    description: "A former scan owner cannot renew, complete, or fail work after takeover, while the successor records one terminal outcome."
    requirement: FND-04
    verification:
      - kind: integration
        ref: "tests/test_durable_queues.py#test_scan_takeover_fencing_allows_only_current_token_terminal_write"
        status: pass
      - kind: integration
        ref: "tests/test_durable_queues.py#test_lost_ownership_suppresses_late_terminal_writes"
        status: pass
    human_judgment: false
metrics:
  duration: 3min
  completed: 2026-08-01
  tasks_completed: 2
  files_modified: 3
status: complete
---

# Phase 01 Plan 11: Scan Lease Renewal, Recovery, and Fencing Summary

**Discovery scans now keep a live lease with a bounded heartbeat, recover abandoned work during ordinary claim polling, and fence stale workers from every terminal transition.**

## Performance

- **Duration:** 3 min
- **Started:** 2026-08-01T06:26:16Z
- **Completed:** 2026-08-01T06:29:15Z
- **Tasks:** 2/2
- **Files modified:** 3

## Accomplishments

- Tokenized each scan claim, then required the token, `running` state, live lease, and live deadline for renewal, completion, and failure writes.
- Added a lease heartbeat that starts before discovery, renews at a bounded interval below the 30-second lease, joins before the terminal transition, and suppresses results after authority loss.
- Added one in-transaction recovery helper used both at startup and at the beginning of every scan claim; live abandoned rows requeue and past-deadline rows become terminal `expired` records.
- Proved long scans, same-poll takeover, deadline expiration, token fencing, and single terminal outcomes with deterministic injected timestamps and no wall-clock sleeps.

## Task Commits

1. **Task 1: Carry one scan beyond its lease with an active heartbeat** — `1158be7` (TDD RED), `e286df9` (TDD GREEN)
2. **Task 2: Recover abandoned scans during each claim transaction** — `4be8590` (TDD RED), `6c05f6d` (TDD GREEN)

## Verification

- `dashboard/.venv/bin/python -m pytest -q tests/test_durable_queues.py` — 10 passed.
- `dashboard/.venv/bin/python -m pytest -q tests/test_release_contract.py -k scan` — 2 passed, 15 deselected.
- Focused heartbeat/lost-ownership and recovery/deadline/fencing selections passed before their GREEN commits.

## Files Created/Modified

- `dashboard/beacon/queues.py` — Scan owner-token generation, injectable lease heartbeat, and claim-time lease recovery.
- `dashboard/app.py` — Discovery execution owns a heartbeat and respects loss of scan authority.
- `tests/test_durable_queues.py` — Deterministic long-scan, takeover, expiry, and fenced-terminal regression coverage.

## Decisions Made

- Every scan claim gets a fresh opaque owner token so a restarted or competing worker cannot reuse a worker label to write a stale result.
- Recovery happens inside each claim transaction, eliminating the worker-restart dependency and preventing an interleaving worker from claiming before cleanup completes.
- The heartbeat records lease loss without logging the token, then prevents all remaining terminal writes by that former owner.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None.

## Threat Coverage

- **T-01-48 (high):** Renewal and terminal updates require the request, token, `running` status, live lease, and live deadline; multi-worker tests block stale-owner completion and failure.
- **T-01-49 (high):** Each claim transaction requeues live abandoned scans and terminally expires requests past their deadline, with deterministic same-poll tests.
- **T-01-50 (medium):** Lease loss is logged with the request identity only; token values remain excluded and unauthorized terminal writes are suppressed.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

The durable scan queue has explicit ownership and reclaim semantics for downstream worker and outbound-policy work. No blockers identified.

## Self-Check: PASSED

- Verified `dashboard/beacon/queues.py`, `dashboard/app.py`, `tests/test_durable_queues.py`, and this summary exist.
- Verified task commits `1158be7`, `e286df9`, `4be8590`, and `6c05f6d` exist in Git history.
