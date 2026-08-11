---
phase: 02-bounded-telemetry-retention
reviewed: 2026-08-11T00:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - dashboard/app.py
  - dashboard/beacon/telemetry.py
  - dashboard/beacon/repositories.py
  - tests/test_telemetry_retention.py
  - tests/test_historical_telemetry_api.py
findings:
  critical: 2
  warning: 0
  info: 0
  total: 2
status: issues_found
---

# Phase 02: Code Review Report

**Reviewed:** 2026-08-11T00:00:00Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

The repaired production paths correctly use metric-specific host stream keys for new samples, one Settings-derived retention policy, closed-hour expiry, due-only retry admission, and lower-tier fallback reads. The original five defects are therefore resolved for newly written data.

Two blockers remain. The host-key conversion does not migrate already-persisted shared `host:host` coverage/state, and the derived pending query reports each unaggregated five-minute bucket as a full hour. Both defects cause the history API to make false claims about retained telemetry.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Canonical host-key upgrade strands existing coverage and pressure state

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:1729-1741`, `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/repositories.py:385-404`

**Issue:** Before this repair, the worker wrote host stream/coverage/pressure-gap state under `host:host`; the new writer and history reader use only `host:cpu`, `host:ram`, `host:disk`, and `host:temp`. No migration or read compatibility path copies the existing `telemetry_streams` and `telemetry_coverage` rows to those keys, or translates an existing `telemetry_retention_state.pressure_gaps["host:host"]`. After upgrade, the API therefore ignores a persisted historical `collection_gap`, and the old pressure-gap entry can never be closed by the new per-metric loop. This violates the phase's stored-data compatibility and makes the API report unknown/not-yet-monitored where it has durable gap evidence.

**Fix:** Add an idempotent schema/data migration (or a one-time transaction guarded by a migration version) that expands legacy `host:host` stream metadata and each coverage interval to the four canonical metric keys, translating the legacy pressure-gap key into the four per-metric keys. Preserve `host:host` only in `telemetry_rollup_jobs`, where it intentionally remains the shared raw-row job identity. Add an upgrade test seeded with legacy stream, coverage, and runtime-state rows that verifies each metric endpoint retains the historical coverage after initialization.

### CR-02: Derived five-minute backlog is disclosed as a 3,600-second pending interval

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/repositories.py:425-435`, `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/repositories.py:447-457`

**Issue:** Both `five_query` statements select a 300-second rollup (`bucket_seconds=300`) but calculate `end_ts` as `bucket_start + 3600`. A single unaggregated five-minute row is thus returned in `aggregation_pending` as one full hour of work. Adjacent rows are coalesced based on this exaggerated interval, so the endpoint can claim pending aggregation over timestamps for which no source row exists. A direct in-memory SQLite reproduction with one host `bucket_seconds=300` row at `0` returns `{'start_ts': 0, 'end_ts': 3600, 'state': 'pending', ...}`.

**Fix:** Change both projections to `bucket_start + 300 AS end_ts`, keeping the durable hourly-job rows at `bucket_start + bucket_seconds`. Add host and service regression cases with one 300-second fallback row and assert that the derived pending interval is exactly `[bucket_start, bucket_start + 300)` before testing coalescing of truly adjacent buckets.

---

_Reviewed: 2026-08-11T00:00:00Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
