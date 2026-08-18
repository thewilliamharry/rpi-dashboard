---
phase: 03-advanced-current-diagnosis
reviewed: 2026-08-18T16:51:42Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - dashboard/advanced.css
  - dashboard/advanced.html
  - dashboard/advanced.js
  - dashboard/app.js
  - dashboard/app.py
  - dashboard/beacon/diagnosis.py
  - dashboard/beacon/migrations.py
  - dashboard/beacon/repositories.py
  - dashboard/beacon/worker_main.py
  - dashboard/index.html
  - tests/test_advanced_diagnosis_api.py
  - tests/test_advanced_ui.py
findings:
  critical: 2
  warning: 10
  info: 5
  total: 17
status: issues_found
---

# Phase 3: Code Review Report

**Reviewed:** 2026-08-18T16:51:42Z
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

The five 03-07 gap-closure fixes were re-verified against the boundaries they claim, and **four of the five hold**:

- **CR-03 / CR-04 (sentinel truncation) — holds.** `read_pipeline_evidence` fetches `cap + 1` and slices back for streams, gaps, and pending. Verified through the production HTTP route at 0/31/32/33 pending (`truncated` flips only at 33) and 0/64/65 streams (`truncated` flips only at 65). The `ORDER BY` that ranks open-gap then stale streams ahead of quiet ones is correct and keeps the open-gap stream inside the cap.
- **CR-02 (`host_freshness`) — holds** for the host branch: missing `system_stats` yields `unknown`, stale yields `stale`, fresh yields no exception.
- **WR-01 (`state.requestGeneration`) — holds.** The counter is incremented before the await and checked on both the success and failure branches; a superseded older response cannot overwrite newer evidence or raise a stale connection warning.
- **CR-01 (open-stream gap synthesis) — holds for the synthesized item, but the surrounding gap projection it plugs into is broken.** The synthetic item itself is correct. The pre-existing `open`/`actionable` derivation that CR-01 wired itself into mislabels *every other* coverage interval belonging to the same stream, and the `reason` field is discarded when gaps are promoted to exceptions. Both were reproduced end-to-end through `GET /api/advanced/current`.

Two BLOCKERs follow from that last point: the "Active exceptions" list — the single operator-facing safety surface of this phase — reports 30-day-old *resolved* gaps and *retention-deleted* intervals as open, actionable collection gaps, and labels indeterminate (`unknown`) evidence as a collection gap. The phase's own test locks the first behavior in as expected. Beyond the gap projection, the test suite globally and permanently patches `time.time`, which undermines the evidence base for the whole phase.

There are no injection, XSS, secret-leak, or authz findings: all DOM writes go through `textContent`, all SQL is parameterized, and `_settings_payload` correctly reduces `alert_webhook_url` to a boolean.

## Critical Issues

### CR-01: Any unrelated open gap marks every historical interval on that stream as open and actionable

**File:** `dashboard/beacon/diagnosis.py:205-217` (and the promotion at `dashboard/beacon/diagnosis.py:308-310`)

**Issue:** `open_gap` is derived from the *stream's* `open_gap_start_ts`, not from the gap row being processed:

```python
open_gap = bool(stream and stream.get('open_gap_start_ts') is not None)
item = {**gap, 'open': open_gap, 'actionable': open_gap or gap['end_ts'] >= now - recent_window}
```

Every durable `telemetry_coverage` row for that stream — including intervals resolved months ago and intervals whose `reason` is `expired` (data deleted by retention) — inherits `open: True` and therefore `actionable: True`, and each one is then promoted into a separate `collection_gap` exception.

Reproduced through the production route (`GET /api/advanced/current`) with one stream carrying an open gap plus two unrelated historical rows:

```
GAP retention-deleted     reason=expired         open=True actionable=True
GAP resolved-30-days-ago  reason=collection_gap  open=True actionable=True
GAP (synthesized)         reason=collection_gap  open=True actionable=True
EXCEPTIONS: host_freshness, worker_freshness, collection_gap x3
```

Impact: the operator's exception list inflates with historical noise the moment a single real gap opens; the UI literally renders "Open actionable gap" for a gap that closed a month ago (`dashboard/advanced.js:280`). This is exactly the causal-inference the module docstring forbids. It also means a stream can never return to a clean gap view without its whole coverage history aging out.

**Fix:** decide `open` per row, not per stream. The synthesized item (lines 218-233) already carries `open: True` explicitly, so durable rows should always be closed:

```python
for gap in evidence['gaps']:
    stream = stream_index.get((gap['stream_kind'], str(gap['stream_key'])))
    cadence = stream.get('cadence_seconds') if stream else None
    recent_window = max(3600, 4 * cadence) if isinstance(cadence, int) and cadence > 0 else 3600
    item = {
        **gap,
        # A persisted coverage row is, by construction, a closed interval:
        # telemetry.record_observation only writes it once the gap ends.
        'open': False,
        'actionable': gap['end_ts'] >= now - recent_window,
    }
```

Then update `tests/test_advanced_diagnosis_api.py::test_open_stream_gap_is_synthesized_merged_and_promoted` (see WR-06) — it currently asserts the defect.

### CR-02: Non-gap coverage reasons are promoted as `collection_gap` exceptions

**File:** `dashboard/beacon/diagnosis.py:308-310`

**Issue:** `compose_active_exceptions` hard-codes the kind and discards `gap['reason']`:

```python
for gap in pipeline['gaps']['items']:
    if gap['actionable']:
        exceptions.append({'kind': 'collection_gap', 'section': 'pipeline', 'priority': 5, **gap})
```

`telemetry_coverage.reason` is a constrained enum of `collection_gap | unknown | expired | not_yet_monitored` (`dashboard/beacon/migrations.py:260-262`). `unknown` intervals are written by `record_observation(..., state=None)` for every sample where a metric is unavailable (`dashboard/app.py:1739-1743` passes `state=True if sample[metric] is not None else None`), and `record_coverage_interval` coalesces consecutive ones into a single interval whose `end_ts` keeps advancing to `ts + cadence`. On any host where a metric is permanently unreadable (for example no thermal sensor, so `temp` is `None`), that interval's `end_ts` is always within `recent_window`, so it is permanently `actionable`.

Reproduced through the production route with a single `reason='unknown'` interval and **no** open gap on the stream:

```
GAP reason=unknown open=False actionable=True
EXCEPTION KINDS: ['host_freshness', 'worker_freshness', 'collection_gap']
```

Impact: an indeterminate observation is reported to the operator as a collection gap, and the workspace can never legitimately display "No active exceptions / reporting normally" on such a host. Retention-`expired` intervals get the same mislabel via CR-01.

**Fix:** carry the reason into the exception kind, and stop promoting reasons that are not collection failures:

```python
GAP_EXCEPTION_KINDS = {
    'collection_gap': 'collection_gap',
    'unknown': 'indeterminate_evidence',
    # 'expired' and 'not_yet_monitored' are expected retention/lifecycle
    # evidence, not active exceptions.
}
for gap in pipeline['gaps']['items']:
    kind = GAP_EXCEPTION_KINDS.get(gap['reason'])
    if gap['actionable'] and kind is not None:
        exceptions.append({'kind': kind, 'section': 'pipeline', 'priority': 5, **gap})
```

Add coverage asserting each `reason` value maps to its own kind (or to no exception at all).

## Warnings

### WR-01: `gaps.truncated` reports `false` while synthesized open gaps are silently dropped

**File:** `dashboard/beacon/diagnosis.py:218-233, 273-277`

**Issue:** Open gaps are synthesized only from `stream_records`, which is already capped at 64. `gaps.truncated` is sourced solely from `evidence['gaps_truncated']`, which measures the `telemetry_coverage` read. With 65 streams all carrying an open gap and no coverage rows, the API returns:

```
gaps.count = 64  gaps.truncated = False   (65 open gaps exist)
streams.truncated = True
```

This is the same false-completeness claim CR-04 was raised to eliminate, just relocated to the `gaps` collection. The operator only learns something is missing by cross-referencing a different section.

**Fix:** propagate stream truncation into the gaps disclosure:

```python
'truncated': bool(
    evidence.get('gaps_truncated', False)
    or evidence.get('streams_truncated', False)
),
```

### WR-02: `gaps.count` can exceed its documented 48-row cap and no longer matches the bounded read

**File:** `dashboard/beacon/diagnosis.py:273-277`

**Issue:** Synthesized open gaps are appended *after* `read_pipeline_evidence` truncated the durable read to `gap_limit` (48). `count` is `len(gaps)`, so the payload can carry up to 48 + 64 = 112 gap items while `truncated` still describes only the 48-row durable slice. The `count`/`truncated` pair therefore describes two different populations.

**Fix:** either bound the combined list explicitly after synthesis (slice to `gap_limit`, setting `truncated` when synthesis overflows), or return the synthesized set as a separately typed field (e.g. `open_gaps`) with its own count/truncated pair, matching the phase's "separately typed" convention.

### WR-03: Auto-refresh discards the operator's chosen service sort every cycle

**File:** `dashboard/advanced.js:628`

**Issue:** `refreshCurrentDiagnosis` unconditionally executes `state.serviceSort = null;` on every successful poll. With the default 15-second interval (and a supported 5-second interval), any sort the operator selects via the column-header buttons is silently reverted within seconds, the "Reset operational order" button re-hides itself, and the `aria-sort` attributes reset — while `state.filters` and `state.expandedPorts` are correctly preserved. There is no test covering sort persistence across a refresh, so this is invisible to the suite.

**Fix:** remove the reset from the refresh path. If a snapshot must invalidate the sort, do it only when the sorted field is no longer present:

```javascript
state.connectionUnavailable = false;
state.snapshot = snapshot;
state.lastSuccessLabel = displayTimestamp(snapshot.generated_ts);
```

### WR-04: Breaking payload shape change shipped without bumping `SCHEMA_VERSION`

**File:** `dashboard/beacon/diagnosis.py:15, 268-272`

**Issue:** `pipeline.streams` changed from a bare array to `{items, count, truncated}`, but `SCHEMA_VERSION` remains `1` and the response still advertises `schema_version: 1`. Any cached client, bookmarked response, or future consumer written against the old shape cannot detect the change from the payload itself. The phase summary explicitly labels this a "contract change for downstream consumers".

**Fix:** bump `SCHEMA_VERSION = 2` and assert the new value in `tests/test_advanced_diagnosis_api.py` (currently `self.assertEqual(payload['schema_version'], 1)` at line 45).

### WR-05: Tests permanently replace the process-global `time.time`, leaking a frozen clock into every later test

**File:** `tests/test_advanced_diagnosis_api.py:18-19, 39, 61, 111, 298, 335, 376, 400, 447, 522, 549, 585, 614, 641`

**Issue:** `self.appmod.time.time = lambda: ...` mutates the **`time` module object**, not the app module — `appmod.time` *is* `sys.modules['time']`. `tearDown` only calls `cleanup_db`, and `importlib.reload(dashboard.app)` in `tests/helpers.load_app` does not restore it. The patch therefore survives for the remainder of the pytest process. Demonstrated with a two-test file:

```
LEAKED time.time() = 1700000005
AssertionError: GLOBAL CLOCK LEAKED FROM PREVIOUS TEST
  where 1700000005 = <function A.test_a_patch.<locals>.<lambda>> = time.time
```

Impact: every test module that runs after `test_advanced_diagnosis_api.py` sees a frozen November-2023 wall clock. Retention cutoffs, lease expiry, `expire_days` filtering, and rate-limit windows in other suites are all computed from `time.time()`. Results become order-dependent, and real regressions can be masked.

**Fix:** use `unittest.mock.patch` with automatic teardown, and patch the boundary the code calls rather than the stdlib module:

```python
def setUp(self):
    ...
    self._clock = {'now': 1_700_000_005}
    patcher = unittest.mock.patch('time.time', lambda: self._clock['now'])
    patcher.start()
    self.addCleanup(patcher.stop)
```

### WR-06: The phase's own test asserts the CR-01 defect as expected behavior

**File:** `tests/test_advanced_diagnosis_api.py:487-506`

**Issue:** The `open_gap_merged_with_closed_historical_coverage` case seeds a gap that closed at `now - 4000` (well outside the 3600-second `recent_window`) and then asserts `len(collection_gaps) == 1 + len(coverage)` — i.e. it requires the resolved historical gap to appear as an active exception. It also asserts only `start_ts`/`end_ts`/`reason`/`detail` for the historical row, deliberately omitting `open` and `actionable`, so the mislabel is unasserted. Fixing CR-01 will fail this test, which is the correct signal but means the test currently protects the bug.

**Fix:** assert the full historical item, including the corrected flags:

```python
self.assertEqual(historical[0]['open'], False)
self.assertEqual(historical[0]['actionable'], False)
self.assertEqual(len(collection_gaps), 1)
```

### WR-07: `test_refresh_generation_guard_is_declared_in_the_advanced_controller` asserts source text, not behavior

**File:** `tests/test_advanced_ui.py:754-761`

**Issue:** The test greps `advanced.js` for exact literals (`'requestGeneration: 0'`, `'const requestId = ++state.requestGeneration;'`, a count of `2` for the guard line) and asserts `assertNotIn('AbortController', js)`. It verifies nothing about ordering behavior — the two adjacent Playwright regressions already do that properly — and it actively forbids replacing the counter with `AbortController`, which is the standard fix for this class of race. A whitespace change or a refactor into a helper breaks the test without changing behavior.

**Fix:** delete this test. The behavioral coverage in `test_reverse_order_refresh_success_never_regresses_newer_evidence` and `..._failure_never_raises_a_superseded_warning` is sufficient and implementation-agnostic.

### WR-08: `/api/advanced/current` has no error handling and bypasses the app's `_db_lock`

**File:** `dashboard/app.py:2121-2132`

**Issue:** Two problems in one handler:

1. No exception handling. `get_current_diagnosis` opens its own connection via `read_transaction`; `connect_db` blocks up to 30 s on the maintenance flock and then raises `MaintenanceBusy` (`dashboard/beacon/db.py:56-88`). `sqlite3.OperationalError` is equally reachable. Either escapes as a Flask 500 with an HTML body, which `apiFetch` cannot parse (`dashboard/advanced.js:59-63`), so the operator sees "Check the connection warning, then try again" for what is actually a scheduled maintenance window.
2. Every other read route (`/api/history`, `/api/telemetry/history`, `/api/stats`) serializes on `_db_lock` before touching SQLite. This handler does not, so it is the only route that can hold a SQLite read outside the app's connection discipline — on a page that polls as fast as every 5 seconds, from up to 8 Gunicorn threads. `journal_mode` is never set to WAL anywhere in the codebase, so readers and the worker's writers contend directly.

**Fix:** model the maintenance case explicitly and match the surrounding lock discipline:

```python
@app.route('/api/advanced/current')
def api_advanced_current():
    if request.args:
        return jsonify({'error': 'unexpected query parameters'}), 400
    try:
        with _db_lock:
            payload = beacon_diagnosis.get_current_diagnosis(DB_PATH, SETTINGS, int(time.time()))
    except MaintenanceBusy:
        return jsonify({'error': 'database maintenance in progress'}), 503
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'no-store'
    return response
```

and surface the 503 body in `renderRefreshError` so the copy names the real cause.

### WR-09: Overview exception cards render raw machine identifiers through dead fallback fields

**File:** `dashboard/advanced.js:138`

**Issue:**

```javascript
addCard(exceptionRegion, item.label || item.kind || 'Unknown exception',
        item.evidence || item.detail || 'Unknown evidence', item.section);
```

`compose_active_exceptions` never emits `label` or `evidence` — both branches are dead. Every card therefore falls through to `item.kind` and, for most kinds, to `'Unknown evidence'`. The operator's primary safety surface reads `host_freshness`, `critical_service_offline`, `worker_freshness` with "Unknown evidence" beneath. `tests/test_advanced_ui.py:626` cements this by asserting `assertIn('host_freshness', overview)`.

**Fix:** either add `label`/`evidence` to the server projection (the server already holds `state`, `port`, `name`, `job_id`, and the gap timestamps needed to compose them), or map kind → operator copy in the client. Then remove whichever fallback becomes dead.

### WR-10: `selectSection` dereferences a server-supplied section id with no guard

**File:** `dashboard/advanced.js:602-612`

**Issue:** `addCard` passes `item.section` straight from the API into `selectSection`, which does `document.querySelectorAll('.advanced-detail > section').forEach((node) => { node.hidden = node.id !== `${section}-section`; })` and then `$(`${section}-heading`).focus()`. If the server ever emits a `section` value with no matching element — a new exception category, a schema skew between a cached page and an upgraded backend — every section is hidden **and then** `heading.focus()` throws on `null`, leaving a blank workspace with an uncaught `TypeError`. The hide loop runs before the null dereference, so the failure is not atomic.

**Fix:** validate before mutating:

```javascript
function selectSection(section) {
  const heading = $(`${section}-heading`);
  if (!heading) return;
  state.activeSection = section;
  ...
}
```

## Info

### IN-01: Every poll rebuilds the whole DOM, destroying focus and open selects

**File:** `dashboard/advanced.js:571-578, 456-469`

`renderSnapshot` calls `replaceChildren` on the overview, host, services table body, pipeline section, and settings section on every successful refresh, and `syncServiceFilterControls` calls `tagControl.replaceChildren(...)` plus reassigns `control.value` for all five filter inputs. At the default 15-second cadence (5 seconds is selectable) this drops keyboard focus from any "Show details" toggle or sort button and closes an open tag dropdown. Consider diffing the service rows by port, or skipping the rebuild when `document.activeElement` is inside the region being replaced.

### IN-02: Client and server duplicate the D-06 ordering rule with divergent `pinned_order` fallbacks

**File:** `dashboard/advanced.js:385-399` vs `dashboard/beacon/diagnosis.py:90-101, 110-114`

The server falls back to `port` for an invalid or missing `pinned_order` (`_safe_pinned_order(value, fallback=row['port'])`); the client falls back to `0` (`Number(left.pinned_order) || 0`). With a mix of set and unset `pinned_order` values, the client's "default operational order" differs from the order the API already sorted. Since the client re-sorts an already-sorted list, the simplest fix is to trust the server order when `state.serviceSort` is null.

### IN-03: A service with `unknown` availability but fresh probe evidence produces no exception

**File:** `dashboard/beacon/diagnosis.py:296-307`

`operational_service_key` ranks `availability == 'unknown'` into notable group 2, but `compose_active_exceptions` only emits for `offline` or for stale/unknown *freshness*. A service whose availability is unknown while its probe timestamp is fresh yields no exception, so the workspace can claim "reporting normally". This is the same truthfulness gap class that CR-02 closed for the host; low reachability today because `_legacy_probe_http` only returns `True`/`False`.

### IN-04: `restoreDashboardScroll` consumes a sessionStorage key that can outlive its navigation

**File:** `dashboard/app.js:420-435`

`captureDashboardScroll` fires on any click of the advanced link, including middle-click and ctrl-click (where the user stays on the dashboard), and `restoreDashboardScroll` only runs on `DOMContentLoaded` — which bfcache back-navigation skips. In both cases the key survives, so a later unrelated dashboard load scroll-jumps and steals focus to the advanced link. Consider clearing the key on `pagehide`, or storing a navigation nonce alongside the offset.

### IN-05: Dead and always-null job/settings fields

**Files:** `dashboard/beacon/diagnosis.py:172, 173`, `dashboard/advanced.js:324`

- `callback_schedule_evidence` always returns `'next_expected_ts': None`; nothing populates it and the UI never reads it.
- `'not_scheduled': callback.scheduler_id is None` is `True` for `P0`, `S1`, `S2`, `S3`, and `L1` — startup and lifecycle callbacks that do run — so the Background jobs region labels them "Not scheduled".
- `addSettingsGroup(root, 'Effective pressure', settings.pressure, ['alert_webhook_url'])` passes an `optionalKeys` entry that is not a key of the pressure group (`_settings_payload` puts alerting in its own group as a boolean). The argument has no effect.

---

_Reviewed: 2026-08-18T16:51:42Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
