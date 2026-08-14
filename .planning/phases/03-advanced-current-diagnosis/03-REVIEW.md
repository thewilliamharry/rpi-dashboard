---
phase: 03-advanced-current-diagnosis
reviewed: 2026-08-14T11:32:26Z
depth: standard
files_reviewed: 16
files_reviewed_list:
  - dashboard/advanced.css
  - dashboard/advanced.html
  - dashboard/advanced.js
  - dashboard/app.js
  - dashboard/app.py
  - dashboard/beacon/diagnosis.py
  - dashboard/beacon/migrations.py
  - dashboard/beacon/repositories.py
  - dashboard/beacon/support_floor.json
  - dashboard/beacon/worker_main.py
  - dashboard/index.html
  - tests/fixtures/legacy/support-floor.json
  - tests/test_advanced_diagnosis_api.py
  - tests/test_advanced_ui.py
  - tests/test_migrations.py
  - tests/test_runtime_ownership.py
findings:
  critical: 3
  warning: 4
  info: 0
  total: 7
status: issues_found
---

# Phase 03: Code Review Report

**Reviewed:** 2026-08-14T11:32:26Z
**Depth:** standard
**Files Reviewed:** 16
**Status:** issues_found

## Summary

The Phase 3 API, worker, and browser implementation has several integration defects that make the production advanced workspace misleading or unusable despite the focused suites passing. The most serious problems are an empty stylesheet response, unwired safety warnings, and worker-health freshness derived from the wrong cadence.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Production route serves an empty advanced stylesheet

**Classification:** BLOCKER

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py:2106`

**Issue:** The `/advanced.css` route returns a zero-length response instead of `dashboard/advanced.css`. The new document requests that URL, so production never receives the responsive workspace, table containment, density, or accessibility styles that were added in this phase. Browser tests do not reveal this because their fixture server bypasses Flask and serves the file directly.

**Fix:** Serve the asset through the existing static adapter:

```python
@app.route('/advanced.css')
def serve_advanced_css():
    return send_file('advanced.css', mimetype='text/css')
```

### CR-02: Connection and worker safety warnings are never driven by real state

**Classification:** BLOCKER

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/advanced.js:113`

**Issue:** `renderSafety()` reads `snapshot.safety.connection` and `snapshot.safety.worker_stale`, but the real snapshot only supplies `safety.recovery_required`; connection is deliberately browser-derived and worker freshness is supplied under `pipeline.worker`. On failed fetches, `refreshCurrentDiagnosis()` only displays an error that tells the operator to check the connection warning, while leaving that warning hidden. The worker warning is likewise permanently hidden. This violates the required independent connection/worker/recovery safety cluster and can conceal an unavailable API or stopped worker.

**Fix:** Track bounded consecutive fetch failures locally (as the main dashboard does) and update the connection banner from that state. Derive the worker warning from the server's worker freshness (or add an explicit server-computed `worker_stale` field), without clearing recovery state.

### CR-03: Worker freshness uses the metric sampling interval instead of the heartbeat schedule

**Classification:** BLOCKER

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/diagnosis.py:183`

**Issue:** The worker heartbeat job is fixed at five seconds (`J1` in `worker_main.py`), and the established worker-ready threshold is configured separately (`WORKER_READY_SECONDS`). This projection instead classifies worker freshness using `metric_sample_seconds`. Any deployment that increases metric sampling, for example to 60 seconds, reports a dead worker as merely aging/fresh for up to four minutes even though the scheduler has stopped heartbeating every five seconds and the main dashboard declares it stale after its readiness threshold.

**Fix:** Derive worker cadence from the immutable `J1` callback (five seconds), or expose/use the same worker-readiness threshold as the established safety API; add a non-default metric-sampling regression test.

## Warnings

### WR-01: Unknown service evidence is assigned the down-service cadence

**Classification:** WARNING

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/diagnosis.py:117`

**Issue:** The code assigns a 60-second cadence to every non-online service, including `unknown`. Unknown services are not confirmed down and should follow the five-minute full-probe cadence. A malformed or indeterminate probe value with a timestamp therefore gets overstated freshness/staleness evidence and an incorrect displayed expected cadence.

**Fix:** Make the short cadence exclusive to confirmed offline services:

```python
cadence = 60 if availability == 'offline' else 300
```

### WR-02: Malformed persisted pinned order can turn a read-only diagnosis into HTTP 500

**Classification:** WARNING

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/diagnosis.py:136`

**Issue:** `int(row.get('pinned_order') or 0)` raises `ValueError` for a legacy or manually-corrupted nonnumeric `service_meta.pinned_order`. The Phase 3 threat model explicitly requires malformed persisted evidence to remain a truthful bounded diagnosis, but this one field aborts the entire snapshot rather than falling back to a deterministic default.

**Fix:** Parse this field defensively (reject booleans and catch `TypeError`/`ValueError`), using `0` or the service port as the stable fallback; add a route-level regression test with malformed metadata.

### WR-03: Truncation metadata claims omitted evidence when a result exactly reaches the cap

**Classification:** WARNING

**File:** `/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/diagnosis.py:243`

**Issue:** The queries fetch at most 48 gaps / 32 pending rows, then set `truncated` when `len(items) >= limit`. Exactly 48 complete rows are falsely reported as truncated, while `count` is merely the returned count rather than the total. The Pipeline UI consequently claims evidence was omitted when it was not.

**Fix:** Query `limit + 1`, set `truncated` only when the sentinel exists, return only `limit` items, and report a count semantics that distinguishes returned and total/at-least-total values.

### WR-04: Tests bypass the Flask asset route and assert only the CSS MIME type

**Classification:** WARNING

**File:** `/Users/william/Documents/devproj/rpi-dashboard/tests/test_advanced_ui.py:15`

**Issue:** The Playwright suite's `SimpleHTTPRequestHandler` serves `dashboard/advanced.css` directly, while the API route test checks only `/advanced.css` status and MIME type. This allowed the production zero-byte CSS response to pass all 69 tests and leaves the real document/Flask/static-asset integration untested.

**Fix:** Add a Flask test asserting `/advanced.css` has the expected nonempty stylesheet content (or hash), and run the browser flow against a real Flask/Gunicorn test server for at least one production asset-loading check.

---

_Reviewed: 2026-08-14T11:32:26Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
