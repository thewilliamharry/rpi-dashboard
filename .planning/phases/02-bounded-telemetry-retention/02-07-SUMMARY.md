---
phase: 02-bounded-telemetry-retention
plan: 07
subsystem: telemetry
tags: [sqlite, telemetry, retention, flask, worker-authority]
requires:
  - phase: 02-06
    provides: bounded historical telemetry API and explicit coverage responses
provides:
  - Canonical metric-specific host stream identities across worker writes, rollups, and history reads
  - One Settings-backed immutable retention policy for worker cleanup and API response limits
affects: [02-08, 02-09, phase-03-advanced-diagnosis, phase-04-history]
tech-stack:
  added: []
  patterns:
    - Fixed host metric allowlist shared by worker, rollup, and API coverage paths
    - RetentionPolicy composed only from validated Settings at the application boundary
key-files:
  created: []
  modified:
    - dashboard/app.py
    - dashboard/beacon/telemetry.py
    - tests/test_telemetry_retention.py
    - tests/test_historical_telemetry_api.py
key-decisions:
  - "Host coverage is metric-specific (cpu, ram, disk, temp); host:host remains only the shared raw-rollup job identity."
  - "The historical API uses the same Settings-derived RetentionPolicy as worker cleanup, including its point budget."
requirements-completed: [TEL-02, TEL-04, TEL-05]
coverage:
  - id: D1
    description: Real worker samples and pressure recovery create readable metric-specific host history evidence.
    requirement: TEL-04
    verification:
      - kind: integration
        ref: tests/test_telemetry_retention.py#test_real_worker_samples_use_metric_streams_and_close_pressure_gaps
        status: pass
    human_judgment: false
  - id: D2
    description: Deployed retention days and point budget drive both worker cleanup and the historical API.
    requirement: TEL-05
    verification:
      - kind: integration
        ref: tests/test_historical_telemetry_api.py#test_configured_policy_controls_worker_and_history_route
        status: pass
    human_judgment: false
metrics:
  duration: 6min
  completed_date: 2026-08-11
  tasks_completed: 2
  files_modified: 4
status: complete
---

# Phase 02 Plan 07: Canonical Host Streams and Policy Parity Summary

**Worker-written host telemetry now uses the same per-metric stream identity and validated retention policy that the historical API reads.**

## Outcomes

- Added a strict four-metric host stream contract shared by sampling, pressure-gap persistence, rollups, and API selector/coverage lookup.
- Made pressure recovery preserve one exact `storage_pressure` gap for each host metric, and represent explicit null samples as `unknown`, while retaining the single shared raw-rollup job key.
- Composed `RetentionPolicy` directly from validated `Settings`, then used that one value for worker cleanup and every history route cutoff, sentinel limit, overflow check, and serialized budget.
- Added production-path regressions for worker-to-Flask history reads, storage pressure, stale worker rejection, non-default tier days, and response budgets.

## Verification

- `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py` — passed (24 tests, 11 subtests).
- `uv run --project dashboard python -m pytest -q tests/test_runtime_ownership.py tests/test_worker_ownership_matrix.py -k "worker or authority or telemetry"` — passed (21 tests, 73 subtests).

## Task Commits

1. **Task 1: Trace all four real worker host metrics through canonical stream evidence** — `08091e2` (RED), `36b0054` (GREEN), `8894dd2` (null-sample correction)
2. **Task 2: Route worker and API through one deployed retention policy** — `1145e19` (RED), `3d9b05a` (GREEN)

## Files Created/Modified

- `dashboard/beacon/telemetry.py` — canonical host keys, pressure-state composition support, and Settings policy factory.
- `dashboard/app.py` — metric-specific worker evidence and settings-backed history budget/cutoffs.
- `tests/test_telemetry_retention.py` — real worker writer-to-reader and pressure-gap regression.
- `tests/test_historical_telemetry_api.py` — non-default deployment-policy and bounded-read regression.

## Decisions Made

- Host stream keys are metric names under the `host` stream kind; `host:host` remains internal to the atomic shared-row rollup job only.
- Production policy is composed once through `RetentionPolicy.from_settings(SETTINGS)`; no history-route default can diverge from deployed settings.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Suppressed duplicate generic gaps after a declared pressure gap**
- **Found during:** Task 1
- **Issue:** Recovering a per-metric pressure gap also triggered cadence-gap detection, producing an overlapping coverage interval.
- **Fix:** Marked the declared pressure interval when recording recovery observations so the stream timestamp advances without inventing a second generic gap.
- **Files modified:** `dashboard/beacon/telemetry.py`, `dashboard/app.py`
- **Verification:** Real worker pressure recovery regression passes for all four metrics.
- **Committed in:** `36b0054`

**2. [Rule 3 - Blocking issue] Stabilized an existing wall-clock-dependent display-bucket assertion**
- **Found during:** Task 2 focused verification
- **Issue:** A pre-existing repository test assumed two samples were in the same hourly display bucket, but its dynamic cutoff could place them in adjacent buckets.
- **Fix:** Chose a deterministic intra-hour cutoff for that test's stated same-bucket scenario.
- **Files modified:** `tests/test_historical_telemetry_api.py`
- **Verification:** Focused configured policy suite passes.
- **Committed in:** `3d9b05a`

**3. [Rule 1 - Bug] Recorded explicit null host metric samples as unknown coverage**
- **Found during:** Final task self-check
- **Issue:** The per-metric loop converted a null value into a false observation instead of the required unknown state.
- **Fix:** Passed `None` into the tri-state observation contract and added null-temperature coverage to the production worker regression.
- **Files modified:** `dashboard/app.py`, `tests/test_telemetry_retention.py`
- **Verification:** Focused worker regression and both required suites pass.
- **Committed in:** `8894dd2`

**Total deviations:** 3 auto-fixed (2 Rule 1, 1 Rule 3).

## Known Stubs

None.

## Issues Encountered

None.

## Next Phase Readiness

Plan 02-08 can repair closed-bucket expiry and retry-due enforcement on top of canonical host coverage and policy parity.

## Self-Check: PASSED

- Confirmed all four implementation/test files exist.
- Confirmed task commits `08091e2`, `36b0054`, `8894dd2`, `1145e19`, and `3d9b05a` exist in git history.
- Confirmed this plan deleted no tracked files.
