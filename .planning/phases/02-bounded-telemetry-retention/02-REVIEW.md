---
phase: 02-bounded-telemetry-retention
reviewed: 2026-08-10T15:31:16Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - dashboard/app.py
  - dashboard/beacon/config.py
  - dashboard/beacon/migrations.py
  - dashboard/beacon/repositories.py
  - dashboard/beacon/support_floor.json
  - dashboard/beacon/telemetry.py
  - dashboard/beacon/worker_main.py
  - tests/fixtures/legacy/current-v4.db
  - tests/fixtures/legacy/support-floor.json
  - tests/test_historical_telemetry_api.py
  - tests/test_migrations.py
  - tests/test_telemetry_retention.py
  - tests/worker_ownership_contract.py
findings:
  critical: 4
  warning: 1
  info: 0
  total: 5
status: issues_found
---

# Phase 02: Code Review Report

**Reviewed:** 2026-08-10T15:31:16Z
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues_found

## Summary

The migration and focused contract tests are present and the focused Phase 2 suite passes (40 tests, 7 subtests). However, production paths do not preserve the stated truthfulness and retention guarantees: host coverage uses a different stream identity from the API, configured tier boundaries are ignored by the API, and expiry can delete a partial hourly bucket. Preserved raw evidence is also omitted from history until an asynchronous rollup has completed.

## Critical Issues

### CR-01: Worker records host coverage under a key the host API never reads

**Classification:** BLOCKER

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:1743`

**Issue:** The worker creates the host stream and pressure gaps as `host:host` (lines 1743-1747), while the endpoint uses the requested metric such as `host:cpu` as its stream key (line 2202). The rollup path also reads host coverage by metric in `telemetry.py:824`. Consequently normal worker-produced host data has no matching stream/coverage at the API: `partition_coverage()` marks intervals `not_yet_monitored`, and storage-pressure gaps never affect the corresponding host rollups or API response. The API tests manually insert `host:cpu`, so they do not cover the production writer-to-reader contract.

**Fix:** Choose one canonical host stream identity and use it consistently. Since queries and rollups are metric-specific, record the stream, cadence, and pressure gaps for each metric (`cpu`, `ram`, `disk`, `temp`) and pass that metric key to `close_storage_pressure_gap()`, `open_storage_pressure_gap()`, and `record_observation()`.

### CR-02: The history API uses default retention tiers instead of the deployed policy

**Classification:** BLOCKER

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:2197`

**Issue:** The worker rolls and expires data with `_telemetry_policy()`, which is built from validated environment settings. The API instead constructs a default `RetentionPolicy()` and a fixed point budget. If any `TELEMETRY_RAW_DAYS`, `TELEMETRY_FIVE_MINUTE_DAYS`, or retention setting differs from defaults, the API looks in the wrong table tier and returns missing/unknown history for retained observations (or omits available rollups). This makes the configured storage policy and returned history disagree.

**Fix:** Build the endpoint's policy from the same settings-backed factory used by the worker, then derive both tier cutoffs and response budget from that policy (subject to any intentional immutable server cap).

### CR-03: Expiry deletes hourly buckets that still overlap the retention window

**Classification:** BLOCKER

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/telemetry.py:962`

**Issue:** Hourly records are deleted when `bucket_start < expiry_cutoff`. When the cutoff is not aligned to an hour, that removes the bucket containing observations from `expiry_cutoff` through `bucket_start + 3600`, even though those observations are still inside the requested 90-day window. This is irreversible data loss and violates the phase's half-open bucket ownership rule. The same defect exists for service rollups on line 964.

**Fix:** Delete only a closed bucket: `WHERE bucket_seconds=3600 AND bucket_start + bucket_seconds <= ?` for both rollup tables. Add tests with a deliberately non-hour-aligned `now` value.

### CR-04: Retained but not-yet-compacted evidence disappears from history reads

**Classification:** BLOCKER

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/repositories.py:157`

**Issue:** `_tier_ranges()` assigns data older than the raw cutoff exclusively to the five-minute/hourly tables. Until the hourly cleanup job has compacted that evidence, the raw rows remain safely preserved but neither `get_host_telemetry()` nor `get_service_telemetry()` reads them. This happens for up to a scheduler interval in steady state and can last far longer for the bounded migration/backlog batches. No pending job is created before the first failed attempt, so the API also reports the interval as ordinary `unknown` rather than pending aggregation. The operator is therefore told history is missing while the source observations still exist.

**Fix:** Include unaggregated source rows as a bounded fallback for tiers awaiting compaction, or create/query explicit pending jobs before deferring source data. Ensure the coverage response distinguishes that state from unknown and keeps the aggregate/source ranges non-overlapping.

## Warnings

### WR-01: Rollup retry backoff is persisted but never enforced

**Classification:** WARNING

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/telemetry.py:780`

**Issue:** `_mark_failed()` writes `next_retry_ts`, but candidate selection only scans source/rollup rows and `run_retention_batch()` attempts every candidate immediately (lines 928-958). It never consults the job state or due timestamp. Thus a failed bucket is retried on every cleanup invocation regardless of its configured exponential-backoff deadline, defeating the bounded retry contract.

**Fix:** Pass `now` into candidate selection and exclude failed jobs whose `next_retry_ts` is in the future; explicitly select only due pending/failed jobs. Add a test that invokes the batch before `next_retry_ts` and verifies both the source rows and `attempt_count` remain unchanged.

---

_Reviewed: 2026-08-10T15:31:16Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
