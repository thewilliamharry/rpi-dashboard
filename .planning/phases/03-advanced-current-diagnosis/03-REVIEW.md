---
phase: 03-advanced-current-diagnosis
reviewed: 2026-08-18T22:40:00Z
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
  critical: 3
  warning: 10
  info: 8
  total: 21
status: issues_found
---

# Phase 3: Code Review Report

**Reviewed:** 2026-08-18T22:40:00Z
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

This review replaces the pre-gap-closure `03-REVIEW.md` at this path and describes the code as it stands after plans 03-08, 03-09 and 03-10.

The gap-closure round did land its stated fixes. Verified as genuinely closed by reading the current code (not the SUMMARYs): per-row gap openness (`open: false` on every persisted `telemetry_coverage` row, `diagnosis.py:236`), per-reason exception kinds (`GAP_REASON_EXCEPTION_KINDS` + `gap_exception_kind`, `diagnosis.py:20-37`), one-population gap bounding (`diagnosis.py:264-273` + `open_gap_streams_truncated`, `repositories.py:140-142`), operator copy for every emitted exception kind (`EXCEPTION_COPY`, `advanced.js:131-183`), sort survival across refresh, the `selectSection` guard (`advanced.js:685-699`), the `SCHEMA_VERSION` bump to 2, and the leaked test clock (`_freeze_clock` with `addCleanup`). `tests/test_advanced_diagnosis_api.py` passes locally (30 tests, 60 subtests, 1.01 s).

What the round did not close, and what it introduced, is the substance of this report.

The dominant theme is unchanged from the last review and is the phase's own stated contract — **the workspace still displays fabricated evidence where the server said "unknown"**:

- Every service's expanded detail row claims there is no collection-gap evidence, because the server hardcodes `collection_gaps: []` while `service:<port>` telemetry streams demonstrably do accumulate coverage rows and open gaps (CR-01).
- Every offline service renders `0 ms` latency and never shows its failure class, because `latency_ms` is `None` by construction for all non-online services and `Number(null) === 0` passes `Number.isFinite` (CR-02). This is item 1 of `deferred-items.md`, but its recorded scope ("a service whose `latency_ms` is null") understates it: this is not an edge case, it is every offline and every unknown service — precisely the rows the operator opened the page for. The failure-class fallback at `advanced.js:630` is unreachable from any real server payload.
- The same coercion bug reaches `state_duration_seconds` (WR-06), which the deferred item does not cover.

New in the gap-closure and phase-03 worker changes: `dispatch_callback` can write durable `failed` job evidence for a callback that actually succeeded (CR-03), and the API route's new `sqlite3.OperationalError` handler discards the very detail its comment promises to log (WR-02).

Two known items are deliberately not re-argued here: `DIA-01`'s traceability/checklist mismatch (documentation, not source), and the `latency_ms` deferral, which is reported only because my own reading enlarges its scope.

## Structural Findings (fallow)

No `<structural_findings>` block was supplied with this review. All findings below are narrative.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Per-service collection-gap evidence is hardcoded empty and reads as "no gaps"

**File:** `dashboard/beacon/diagnosis.py:172`, `dashboard/advanced.js:648`

**Issue:** `compose_service_diagnosis` builds every service row with a literal empty list:

```python
'collection_gaps': [],
```

Nothing ever populates it — `get_current_diagnosis` (`diagnosis.py:386-409`) composes `services` and `pipeline` independently and never joins them. The client then renders that literal as evidence:

```javascript
addEvidence(evidence, 'Collection-gap evidence', JSON.stringify(service.collection_gaps || service.collection_gap || 'No gap evidence'));
```

`[]` is truthy in JavaScript, so the `'No gap evidence'` fallback never fires and the row always prints `[]`.

Service streams are real: `dashboard/app.py:1406-1410` calls `record_observation(conn, 'service', str(port), ..., cadence_seconds=300)` on every probe, `telemetry.py:661` opens and closes `telemetry_coverage` rows for those streams, and `compose_pipeline_diagnosis` already attaches those very gaps to the matching stream record (`diagnosis.py:244`, `diagnosis.py:260`). So a port can simultaneously carry an open collection gap in the Pipeline section and a service detail row asserting `[]`. `03-UI-SPEC.md:119` and `03-02-PLAN.md:171` both require this field to carry real evidence.

This is the exact class of defect CR-01/CR-02 of the previous round closed for the pipeline: asserting a fact the durable evidence does not support.

**Fix:** join the already-computed stream gaps onto the service rows, and make the client's empty case explicit rather than JSON-dumping a container:

```python
# diagnosis.py, inside get_current_diagnosis after pipeline is composed
gaps_by_port = {}
for stream in pipeline['streams']['items']:
    if stream['stream_kind'] == 'service':
        gaps_by_port[str(stream['stream_key'])] = stream['gaps']
for service in services:
    service['collection_gaps'] = gaps_by_port.get(str(service['port']), [])
```

```javascript
const gaps = Array.isArray(service.collection_gaps) ? service.collection_gaps : null;
addEvidence(evidence, 'Collection-gap evidence',
  gaps === null ? 'Unknown'
  : gaps.length === 0 ? 'No collection-gap evidence for this service'
  : gaps.map((gap) => `${gap.open ? 'Open' : 'Resolved'} ${gapInterval(gap)}`).join(' '));
```

If populating the field is out of scope for this phase, the honest interim is to remove the field from the payload and render `Unknown` — never `[]`.

### CR-02: Every offline service renders "0 ms" latency and its failure class is unreachable

**File:** `dashboard/beacon/diagnosis.py:154`, `dashboard/advanced.js:629-630`, `dashboard/advanced.js:499-502`

**Issue:** Known and recorded as `deferred-items.md` item 1; reported here because my reading **enlarges its scope from an edge case to the default path**, which changes its severity.

The server sets latency to `None` for *every* non-online service by construction:

```python
'latency_ms': row.get('probe_latency_ms') if availability == 'online' else None,
```

The client then does:

```javascript
const latencyValue = Number(service.latency_ms);
latency.textContent = Number.isFinite(latencyValue) ? `${latencyValue} ms` : displayValue(service.failure_class || service.last_error, '');
```

`Number(null)` is `0` and `Number.isFinite(0)` is `true` (verified in node). So the "Latency / failure" column shows **`0 ms` for every offline and every unknown service**, and the `failure_class` / `last_error` branch is dead for any payload this server can emit (it can only fire if the key is absent entirely, yielding `NaN`).

Consequences: the failure class — the single most useful cell for a down service — is never shown in the collapsed table; `0 ms` is fabricated evidence that reads as "fastest service"; and `stableServiceSort`'s latency branch (`advanced.js:499-502`) sorts every down service ahead of every healthy one, with its `Number.POSITIVE_INFINITY` guard equally unreachable.

The deferred rationale ("pre-existing behaviour... belongs with 03-02/03-04") is a scheduling argument, not a severity argument. The phase's requirement is a truthful current diagnosis; this defeats it on the rows that matter most.

**Fix:** stop coercing null. One helper, used by both the cell and the sort:

```javascript
function serviceLatency(service) {
  const value = service.latency_ms;
  if (value === null || value === undefined) return null;
  const latency = Number(value);
  return Number.isFinite(latency) ? latency : null;
}
// cell
const latency = serviceLatency(service);
latencyCell.textContent = latency === null
  ? displayValue(service.failure_class || service.last_error)
  : `${latency} ms`;
// sort
if (sort.field === 'latency') return serviceLatency(service) ?? Number.POSITIVE_INFINITY;
```

Add a regression fixture with `latency_ms: null` + a non-null `failure_class` asserting the cell shows the failure class and never the string `0 ms` — `SORTABLE_SERVICES` in `tests/test_advanced_ui.py` already carries such a row and currently asserts nothing about its latency cell.

### CR-03: A callback that succeeded can be recorded as `failed` and re-raised

**File:** `dashboard/beacon/worker_main.py:272-297`

**Issue:**

```python
try:
    _write_job_health_transition(services, callback_id, 'started')
    result = _invoke_callback(services, callback)
    if result is False:
        ...
    _write_job_health_transition(services, callback_id, 'succeeded')   # <-- can raise
    return result
except queues.LeaseLost:
    ...
except Exception as exc:
    _write_job_health_transition(services, callback_id, 'failed', error_class=_job_error_class(exc))
    raise
```

The success bookkeeping write is inside the same `try` as the real work. `_write_job_health_transition` opens its own connection through `write_transaction` → `connect_db`, which blocks up to 30 s on the maintenance flock and then raises `MaintenanceBusy`, and can raise `sqlite3.OperationalError` on `BEGIN IMMEDIATE` after the 30 s busy timeout (`dashboard/beacon/db.py:56-89`). When that happens **after** `_invoke_callback` has already completed its durable work, the broad `except Exception` writes `state='failed'` with `error_class='MaintenanceBusy'` (or `OperationalError`) for a callback that succeeded, and then re-raises into APScheduler so the scheduler log also records a failure.

That false row is not inert: `read_background_job_health` feeds `compose_pipeline_diagnosis`, and `compose_active_exceptions` (`diagnosis.py:355-357`) promotes any `state == 'failed'` into an operator-facing `job_failed` exception rendered as "Background job failed — J2". The durable record also loses the true `last_success_ts` for that run.

Second-order effect from the same block: if the **`started`** write fails, the callback's real work is skipped entirely (metrics, probes, cleanup) because bookkeeping now runs first and aborts the dispatch.

**Fix:** scope the failure record to failures of the work itself, and never let bookkeeping failure rewrite a known-good outcome:

```python
try:
    _write_job_health_transition(services, callback_id, 'started')
except queues.LeaseLost:
    raise
except Exception:
    log.warning('could not record start of %s; running it anyway', callback_id)

try:
    result = _invoke_callback(services, callback)
except queues.LeaseLost:
    ...
except Exception as exc:
    _record_outcome(services, callback_id, 'failed', error_class=_job_error_class(exc))
    raise

_record_outcome(services, callback_id, 'failed' if result is False else 'succeeded',
                error_class='CallbackReturnedFalse' if result is False else None)
return result
```

where `_record_outcome` swallows and logs non-`LeaseLost` bookkeeping errors. Add a test that makes only the `succeeded` write raise `MaintenanceBusy` and asserts the durable row is not `failed` and no `job_failed` exception reaches `/api/advanced/current`.

## Warnings

### WR-01: `/api/advanced/current` still bypasses `_db_lock`, and no journal mode is ever set

**File:** `dashboard/app.py:2121-2141`

**Issue:** Reported in the previous review as part of WR-08; 03-10 fixed only the error-handling half. Every other read route in `app.py` serializes on `_db_lock` (`app.py:131, 187, 2156, 2301, 2452, ...` — 27 call sites). This handler still does not, so it remains the only route that holds a SQLite read outside the app's connection discipline, on a page that polls as fast as every 5 s from up to 8 Gunicorn threads. `grep -rn journal_mode dashboard/` finds only `inventory.py` *reading* the pragma — WAL is never enabled anywhere, so these readers contend directly with the worker's `BEGIN IMMEDIATE` writers, which CR-03's change just made three times more frequent per callback.

**Fix:** either wrap the call in `with _db_lock:` to match the surrounding discipline, or set `PRAGMA journal_mode=WAL` in `connect_db` and document the deliberate divergence. Do not leave it undecided.

### WR-02: The 503 handler discards the detail its own comment promises to log, and mislabels permanent failures

**File:** `dashboard/app.py:2135-2138`

**Issue:**

```python
except sqlite3.OperationalError as exc:
    # The detail belongs in the server log, never in the response body.
    log.warning('advanced diagnosis read unavailable (%s)', exc.__class__.__name__)
    return jsonify({'error': 'diagnosis database is temporarily unavailable'}), 503
```

The comment says the detail goes to the log; the code logs only `exc.__class__.__name__`, which is always the constant string `OperationalError`. The message — `no such table: telemetry_streams`, `database is locked`, `attempt to write a readonly database` — is discarded at both ends, so an operator has no way to distinguish a transient lock from a broken schema. `tests/test_advanced_diagnosis_api.py` asserts only that the message does not reach the *response*; nothing asserts it reaches the log, which is why the omission survived.

Related: `sqlite3.OperationalError` also covers permanent conditions (missing table after a partial migration, read-only filesystem). Reporting those as "temporarily unavailable" tells the operator to wait for a state that will never arrive, and the UI has no retry ceiling.

**Fix:**

```python
except sqlite3.OperationalError as exc:
    log.warning('advanced diagnosis read unavailable: %s', exc)   # server-side only
    return jsonify({'error': 'diagnosis database is temporarily unavailable'}), 503
```

and assert the log record in the test with `assertLogs`. Consider `Retry-After` on the 503, and consider narrowing the "temporarily" claim (e.g. treat `no such table` / `readonly database` as 500-class configuration faults).

### WR-03: Polling has no in-flight guard or abort, and a test forbids adding one

**File:** `dashboard/advanced.js:57-65, 672-676, 709-726`; `tests/test_advanced_ui.py:1146`

**Issue:** `scheduleRefresh` installs `setInterval(refreshCurrentDiagnosis, refreshSeconds * 1000)` and `refreshCurrentDiagnosis` neither checks for a pending request nor carries an `AbortSignal` or timeout. `state.requestGeneration` only discards a stale *render*; the HTTP request itself continues.

Server-side, a single request can legitimately hang ~30 s (`_acquire_lock(..., timeout_seconds=30)`) plus a 30 s SQLite busy timeout before it returns 503. At the 5 s cadence the workspace offers, that is up to a dozen stacked requests per tab, each pinned to one of the 8 Gunicorn threads, and each consuming one of the browser's ~6 connections per origin — which also stalls the main dashboard in another tab. During a recovery or maintenance window, i.e. exactly when the operator needs the page, the page and the API can starve each other.

Compounding this, `test_refresh_generation_guard_is_declared_in_the_advanced_controller` asserts `self.assertNotIn('AbortController', js)` — the test suite actively forbids the standard fix.

**Fix:** skip or supersede an in-flight request and bound it:

```javascript
let inFlight = null;
async function refreshCurrentDiagnosis() {
  if (inFlight) inFlight.abort();
  const controller = new AbortController();
  inFlight = controller;
  const timer = setTimeout(() => controller.abort(), Math.max(4000, state.preferences.refreshSeconds * 1000 - 500));
  try { /* fetch with {signal: controller.signal} */ }
  finally { clearTimeout(timer); if (inFlight === controller) inFlight = null; }
}
```

and delete the `assertNotIn('AbortController', js)` assertion — a test must not prohibit a mechanism.

### WR-04: An unwritable `localStorage` kills the whole workspace at load

**File:** `dashboard/advanced.js:36-45, 731`

**Issue:** `loadPreferences` guards its read with `try/catch`, but `savePreferences` calls `localStorage.setItem(...)` bare, and the module-level bootstrap calls it unconditionally at `advanced.js:731` — **before** any event listener is bound and before `scheduleRefresh()` / the first `refreshCurrentDiagnosis()`. In any context where `setItem` throws (Safari private browsing, quota exhausted, storage blocked by policy), the IIFE aborts and the operator is left with the static loading skeleton forever: no refresh, no nav, no error message, and the page looks like a hung backend. The same throw path exists on every filter keystroke, density change and pause toggle.

**Fix:**

```javascript
function savePreferences() {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify({...}));
  } catch (_) { /* presentation preferences are best-effort browser-local state */ }
}
```

### WR-05: `streams.items[].gaps` is a second, differently-bounded copy of the gap population

**File:** `dashboard/beacon/diagnosis.py:218-273, 308-317`

**Issue:** Plan 03-08's goal was that `gaps.count` and `gaps.truncated` describe exactly one population. They now do — but the same items are also pushed into `stream['gaps']` (`diagnosis.py:244, 260`) **before** the priority sort and the `gaps[:gaps_limit]` slice, and `stream_records` is emitted verbatim as `streams.items`. So:

1. A gap dropped from `gaps.items` by the cap is still present, in full, under `streams.items[].gaps` — the response simultaneously claims truncation and ships the truncated item.
2. `streams.items[].gaps` is bounded by the *stream* limit and the coverage read, not by `gaps_limit`, so it is a second population with no disclosure of its own.
3. Every gap is serialized twice (they are the same dict object in memory, but JSON has no aliasing), inflating a payload polled every 5 s.
4. Nothing consumes it: neither `advanced.js` nor any test reads `streams.items[].gaps`.

**Fix:** drop the per-stream copy and let the Pipeline gap region be the single disclosure, or populate it from `bounded_gaps` after the slice and give it its own `truncated` flag. Dropping it is preferable — CR-01 needs a *service*-keyed join, not a per-stream duplicate.

### WR-06: `state_duration_seconds: null` renders as "0 seconds" and sorts as most-recent

**File:** `dashboard/advanced.js:452-455, 503, 631`

**Issue:** Same root cause as CR-02, not covered by `deferred-items.md`. The server deliberately emits `None` when it cannot establish a state transition timestamp:

```python
'state_duration_seconds': (max(0, now - row['state_since']) if isinstance(row.get('state_since'), int) else None),
```

The client coerces it back to a number:

```javascript
const seconds = Number(service.state_duration_seconds);   // Number(null) === 0
return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
```

So an unknown duration prints "0 seconds" — which an operator reads as "this service just changed state right now" — and sorts ahead of every real duration, while `formatDuration`'s `'Unknown duration'` branch and the `?? Number.POSITIVE_INFINITY` sort guard are both unreachable. Reachability is lower than CR-02 (`state_since` is backfilled by migration and set on insert), which is why this is a warning rather than a blocker, but the client must not contradict an explicit server `null`.

**Fix:** null-check before coercion, exactly as in CR-02:

```javascript
function serviceDuration(service) {
  const value = service.state_duration_seconds;
  if (value === null || value === undefined) return null;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}
```

### WR-07: `aria-selected` on plain buttons gives assistive technology no section state

**File:** `dashboard/advanced.html:32-38`, `dashboard/advanced.js:692-695`

**Issue:** The section navigation is a `<nav>` of plain `<button>` elements carrying `aria-selected="true|false"`. `aria-selected` is only defined for `role="tab" | option | row | gridcell | treeitem | columnheader | rowheader`; on an implicit `role="button"` it is invalid and ignored. The selected section is therefore conveyed **only** by CSS (`.section-navigation button[aria-selected="true"]` sets colour and background), so a screen-reader user gets no indication of which of the five sections is active. `tests/test_advanced_ui.py` asserts the invalid attribute, cementing it.

**Fix:** either adopt the tab pattern properly (`role="tablist"` on the nav, `role="tab"` + `aria-selected` + roving `tabindex` on the buttons, `role="tabpanel"` + `aria-labelledby` on the sections), or keep plain buttons and use `aria-current="true"` (valid on any element) plus `aria-expanded`. Update the assertions to the chosen valid attribute.

### WR-08: Tautological and source-text tests give coverage credit for nothing

**File:** `tests/test_advanced_ui.py:1149-1152, 1140-1147, 196-209, 481-499, 1198-1207`

**Issue:** Several tests assert properties of the test file or of source *text* rather than behavior, so they cannot fail on a regression:

- `test_ui_consideration_inventory_is_complete_and_unique` (1149-1152) asserts that `UI_CONSIDERATIONS` — a module constant built by `tuple(f'UI-{n:02d}' for n in range(1, 37))` at line 13 — has 36 unique members and equals the identical comprehension. It is a tautology; it can never fail, and it asserts nothing about the product. It reads in a coverage roll-up as if UI-01..UI-36 were verified.
- `test_precision_and_accessible_service_source_contract` (1198-1207) and `test_services_source_contract_...` (481-499) grep the shipped files for `'position: sticky'`, `'aria-expanded'`, `'state_duration_seconds'`, `f'function {name}'`. A rule can be deleted from the matching selector, or a function renamed at its call sites, without failing.
- `test_advanced_controller_tracer_...` (196-209) bans the bare substrings `'history'` and `'POST'` in `advanced.js`. Brittle: any future identifier containing "history" fails the suite for no behavioral reason.

Real behavioral coverage does exist elsewhere in this file (the `getComputedStyle` breakpoint checks, the exception-copy tests), which makes the grep tests pure noise.

**Fix:** delete the tautology, and replace each source grep with the browser assertion it was standing in for (e.g. assert `getComputedStyle(identity).position === 'sticky'` — already done at line 1181 — and assert the toggle's `aria-expanded` flips on click rather than that the string exists).

### WR-09: `next(...)` over the callback inventory raises `StopIteration` into the request path

**File:** `dashboard/beacon/diagnosis.py:213-216`

**Issue:**

```python
heartbeat_callback = next(
    callback for callback in WORKER_CALLBACK_INVENTORY if callback.identifier == 'J1'
)
```

If `J1` is ever renamed or removed from the inventory, this raises a bare `StopIteration` from inside a web request. The route catches only `MaintenanceBusy` and `sqlite3.OperationalError`, so the operator gets an unparseable HTML 500 — the exact failure mode plan 03-10 set out to eliminate. `worker_main.py` already maintains `_CALLBACKS_BY_ID` for precisely this lookup, and `diagnosis.py` already imports from that module.

**Fix:**

```python
from .worker_main import WORKER_CALLBACK_INVENTORY, _CALLBACKS_BY_ID  # or a public accessor
heartbeat_callback = _CALLBACKS_BY_ID.get('J1')
worker_cadence = (
    callback_schedule_evidence(heartbeat_callback, settings)['cadence_seconds']
    if heartbeat_callback is not None else None
)
```

`freshness_state` already degrades a `None` cadence to `{'state': 'unknown'}`, which is the truthful outcome.

### WR-10: Exception dicts are spread from a database row, so a new column can silently rewrite the classification

**File:** `dashboard/beacon/diagnosis.py:354, 360`

**Issue:**

```python
exceptions.append({'kind': kind, 'section': 'pipeline', 'priority': 5, **gap})
```

`gap` is built from `SELECT ... FROM telemetry_coverage` (`repositories.py:143-147`) plus the composer's own keys. Because `**gap` is spread **last**, any future `telemetry_coverage` column named `kind`, `section` or `priority` silently overrides the classification this line just computed. The sort key immediately below (`item['priority'], item['kind'], item.get('port', -1), item.get('job_id', '')`) will then either mis-order or raise a `TypeError` comparing a str priority to an int. The fix is one character of ordering and costs nothing.

**Fix:**

```python
exceptions.append({**gap, 'kind': kind, 'section': 'pipeline', 'priority': 5})
```

Apply the same ordering discipline wherever server rows are spread into composed payloads.

## Info

### IN-01: Every successful poll rebuilds the entire DOM

**File:** `dashboard/advanced.js:654-661, 539-552`

Unchanged from the previous review. `renderSnapshot` calls `replaceChildren` on the overview, host, services table body, pipeline section and settings section; `syncServiceFilterControls` rebuilds the tag `<select>` and reassigns all five filter inputs. At the default 15 s cadence (5 s selectable) this drops keyboard focus from any Show details / sort button and closes an open dropdown. Consider skipping the rebuild while `document.activeElement` is inside the region, or diffing service rows by port.

### IN-02: The D-06 ordering rule is implemented twice

**File:** `dashboard/advanced.js:468-482` vs `dashboard/beacon/diagnosis.py:112-123`

The client re-sorts a list the server already sorted, using a parallel implementation. The previously reported `pinned_order` fallback divergence is **not** currently reachable — `_safe_pinned_order` guarantees an int in `0..65535`, and `Number(0) || 0` is `0` — so the two agree today. It remains a maintenance hazard: any change to one side silently desynchronizes the operator's "default operational order". Simplest resolution is to trust the server order when `state.serviceSort` is null.

### IN-03: `unknown` availability with fresh probe evidence yields no exception

**File:** `dashboard/beacon/diagnosis.py:336-347`

Unchanged. `operational_service_key` ranks `availability == 'unknown'` into notable group 2, but `compose_active_exceptions` only emits for `offline` or for stale/unknown *freshness*. A service whose availability is unknown while its probe timestamp is fresh produces no exception, so the overview can still claim "Host, services, and collection pipeline are reporting normally."

### IN-04: The dashboard scroll key can outlive its navigation

**File:** `dashboard/app.js:421-437`

Unchanged. `captureDashboardScroll` fires on any click of the advanced link (including middle-click and ctrl-click, where the user stays put), and `restoreDashboardScroll` runs only on `DOMContentLoaded`, which bfcache back-navigation skips. The key survives, so a later unrelated dashboard load scroll-jumps and steals focus to the advanced link. Clear it on `pagehide`, or store a navigation nonce alongside the offset.

### IN-05: Dead and always-constant fields

**Files:** `dashboard/beacon/diagnosis.py:194-195`, `dashboard/advanced.js:407`, `dashboard/beacon/worker_main.py:237`

- `callback_schedule_evidence` always returns `'next_expected_ts': None`; nothing populates it and the UI never reads it.
- `'not_scheduled': callback.scheduler_id is None` is `True` for `P0`, `S1`, `S2`, `S3` and `L1` — startup and lifecycle callbacks that do run — so the Background jobs region labels five real callbacks "Not scheduled".
- `addSettingsGroup(root, 'Effective pressure', settings.pressure, ['alert_webhook_url'])` passes an `optionalKeys` entry that is not a key of the pressure group; the argument has no effect.
- `_job_error_class` ends with `type(error).__name__[:96] or 'CallbackFailed'`; `__name__` is never empty, so the fallback is dead (and `repositories._safe_job_error_class` already provides one).

### IN-06: Three duplicated element-id maps and two freshness allow-lists

**File:** `dashboard/advanced.js:540-543, 591-594, 741-744, 761-764, 113-117, 447-450`

The filter-control map is built twice (`syncServiceFilterControls`, bootstrap) and the sort-button map twice (`renderServices`, bootstrap), with the ids repeated verbatim in each — a rename in `advanced.html` must be mirrored in four places, and a miss throws only at click time. Separately, the freshness allow-list exists as both `FRESHNESS_WORDS` (a `Set`) and an inline array in `serviceFreshness`. Hoist each to a single module constant.

### IN-07: A collection region can print "0 gaps" above the word "Unknown"

**File:** `dashboard/advanced.js:263-288, 360`

`countLabel` maps a missing count to `0`, while `addCollectionRegion` renders `Unknown` when the collection is not an array. With `pipeline.gaps` absent the heading reads "Collection gaps (0 gaps)" over a body reading "Unknown" — two different claims about the same evidence. Make `countLabel` return `Unknown` for a non-finite count.

### IN-08: `schedule_kind` reports the admission category

**File:** `dashboard/beacon/diagnosis.py:191`

`'schedule_kind': callback.admission_category` emits `'scheduled'`, `'startup'`, `'pre_epoch_preparation'`, `'lifecycle_finalization'`. The value is defensible but the name implies the trigger kind (which is reported separately as `trigger`), and nothing in the UI reads the field. Either rename it or drop it from the payload.

---

_Reviewed: 2026-08-18T22:40:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
