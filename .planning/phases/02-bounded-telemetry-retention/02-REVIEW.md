---
phase: 02-bounded-telemetry-retention
reviewed: 2026-08-11T00:00:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - dashboard/beacon/migrations.py
  - dashboard/beacon/support_floor.json
  - tests/fixtures/legacy/support-floor.json
  - tests/fixtures/legacy/current-v6.db
  - tests/test_migrations.py
  - dashboard/beacon/repositories.py
  - tests/test_historical_telemetry_api.py
findings:
  critical: 1
  warning: 0
  info: 0
  total: 1
status: issues_found
---

# Phase 02: Code Review Report

**Reviewed:** 2026-08-11T00:00:00Z
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

The final repairs correctly add a versioned, caller-transactional Migration 7; migrate normal legacy `host:host` stream and coverage data to canonical host metrics; preserve the approved shared rollup-job identity; and correct host/service five-minute derived pending intervals to `[bucket_start, bucket_start + 300)`. The focused regression suite passed: `7 passed, 34 deselected`.

The previous seven Phase 2 review gaps were traced again. The five original repairs remain present (canonical new writes, deployed policy parity, closed-bucket expiry, source fallback, and retry due-time admission). Normal legacy-host state and the five-minute width/coalescing defects are also repaired. One malformed persisted pressure-state value is still silently accepted, leaving the obsolete `host:host` key behind after Migration 7 reports success.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: A JSON-null legacy pressure gap bypasses validation and survives the migration

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/migrations.py:387-391`, `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/migrations.py:451-468`

**Issue:** The migration reads the legacy entry with `pressure_gaps.get('host:host')` and treats `None` as if the key were absent. A persisted state such as `{"state":"pressure","pressure_gaps":{"host:host":null}}` therefore passes the malformed-state guard, skips the expansion and `pop`, then successfully deletes the legacy stream/coverage rows and publishes version 7. The invalid obsolete pressure key is left in `telemetry_retention_state`, contrary to the migration contract that malformed legacy timestamps fail closed and that no `host:host` pressure identity remains after success. This can strand corrupt historical pressure state behind a completed, non-repeatable migration.

**Fix:** Test key presence separately from its value, reject every present value that is not a non-boolean integer, and remove the legacy key only after a valid expansion. For example:

```python
has_legacy_pressure = 'host:host' in pressure_gaps
legacy_pressure_start = pressure_gaps.get('host:host')
if has_legacy_pressure and (
    isinstance(legacy_pressure_start, bool)
    or not isinstance(legacy_pressure_start, int)
):
    raise ValueError('invalid legacy host pressure gap')
if has_legacy_pressure:
    # expand to canonical keys, then pressure_gaps.pop('host:host')
```

Add a Migration 7 rollback regression with `"host:host": null` and assert the database remains at version 6 with all legacy rows intact.

---

_Reviewed: 2026-08-11T00:00:00Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
