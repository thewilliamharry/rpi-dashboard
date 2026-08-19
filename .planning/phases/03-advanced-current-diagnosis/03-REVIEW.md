---
phase: 03-advanced-current-diagnosis
reviewed: 2026-08-19T00:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - dashboard/advanced.js
  - dashboard/beacon/diagnosis.py
  - dashboard/beacon/worker_main.py
  - tests/test_advanced_diagnosis_api.py
  - tests/test_advanced_ui.py
findings:
  critical: 1
  warning: 16
  info: 16
  total: 33
status: issues_found
---

# Phase 3: Code Review Report — gap-closure round 3

**Reviewed:** 2026-08-19T00:00:00Z
**Depth:** standard
**Files Reviewed:** 5 (diff range `74fe5f2..HEAD`)
**Status:** issues_found

## Summary

This report **replaces** the 18 Aug `03-REVIEW.md`, which covered plans 03-01…03-10. It is scoped to
the five source files changed by plans 03-11…03-14, and it carries forward, without re-arguing, every
round-1 finding that this round's changes did not resolve.

**Round-1 findings this round genuinely closed** (verified by reading the current code, not the SUMMARYs):

| Round-1 ID | Status | Evidence |
|---|---|---|
| CR-01 — `collection_gaps: []` hardcoded | **Closed** | `diagnosis.py:360-393` joins each service to its own `('service', str(port))` stream; `advanced.js:679` renders operator copy, no `JSON.stringify` |
| CR-02 — `0 ms` for every offline service | **Closed** | `advanced.js:660` routes through `finiteMeasurement`; `test_advanced_ui.py` asserts `ConnectionRefused` / `Unknown` and that a real `0` still renders `0 ms` |
| CR-03 — a succeeded callback recorded as `failed` | **Closed (main claim)** | `worker_main.py:305-328` decides `(transition, error_class)` in a non-writing scope; a write failure now raises instead of rewriting the verdict. The second-order half is **not** closed — see WR-04 |
| WR-06 — `state_duration_seconds: null` → `0 seconds` | **Closed** | `advanced.js:483-486` |

**What I verified is actually sound in the new code**, because it was the highest-risk claim:

- The per-service `count` / `open_count` / `items` all derive from one object (`stream['gaps']`,
  `diagnosis.py:381-386`) — no Gap-3 recurrence within the service block.
- The `complete` state cannot under-report: `gap_evidence_truncated` is `evidence['gaps_truncated']`,
  which is `len(gap_rows) > 48` over a `LIMIT 49` read of the whole `telemetry_coverage` table
  (`repositories.py:142-148`). If it is `False`, every coverage row was read.
- `open_gap_streams_truncated` is correctly *not* folded into `gap_evidence_truncated`: a service's open
  gap is derived from its own stream row's `open_gap_start_ts`, so a matched stream always carries its
  open gap, and an unmatched one resolves to `not_established`. Keeping the two flags separate is right.
- A missing or non-boolean truncation flag resolves to `not_established`, never `absent`
  (`diagnosis.py:343-357`) — only a literal `False` produces `absent`. Confirmed.
- The join key cannot mismatch on type: both sides are `str(...)` (`diagnosis.py:225, 380`).
- No XSS. `addEvidence` (`advanced.js:89-98`) uses `textContent` exclusively; `detailId` is built from
  `Number(service.port)` and `applyServiceFilters` drops non-finite ports.
- `JobHealthBookkeepingError`'s own message leaks nothing: callback id from a fixed inventory, a literal
  transition, and `type(exc).__name__[:96]`. No message, path or SQL. Confirmed.
- Test scaffolding restores what it mutates: `_freeze_clock` uses `mock.patch` + `addCleanup`; the
  `_write_job_health_transition` monkeypatch has a matching `addCleanup`. Each test gets a fresh DB.

**What this round introduced or left standing** is the substance below. The one blocker is in
`worker_main.py`: while narrowing the false positive (bookkeeping failure recorded as work failure),
the new code created a path that erases a **genuine** work failure entirely — no durable row, no
chained exception, no log — which is standing prohibition 4 in this phase's own threat model.

Counts: **this round** — 1 Critical, 7 Warning, 8 Info. **Carried forward from round 1** — 0 Critical,
9 Warning, 8 Info.

## Structural Findings (fallow)

No `<structural_findings>` block was supplied with this review. All findings below are narrative.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01 (round 3): A genuine callback failure is erased when the outcome write also fails

**File:** `dashboard/beacon/worker_main.py:307, 316-318, 335-341`

**Issue:** When `_invoke_callback` raises, the exception is stashed in `work_error` and the outcome is
decided as `('failed', _job_error_class(exc))`. If the outcome write then fails for a non-lease reason,
control enters:

```python
except Exception as exc:
    raise JobHealthBookkeepingError(
        callback_id, transition, _job_error_class(exc),
    ) from exc
```

`work_error` is never raised (line 341 is unreachable from this branch), never chained, and never
logged. Because the write failed, no durable row was written either. The genuine failure therefore
disappears from **every** channel simultaneously:

- durable evidence: `background_job_health` still holds the pre-run row (or `started`), so
  `compose_active_exceptions` emits no `job_failed` (`diagnosis.py:421`);
- exception chain: `__cause__` is the *write* error; `work_error` was already handled, so it is not in
  `__context__` either;
- log: nothing logs `work_error`.

The operator's only signal is `background job health write failed: callback=J8 transition=failed
error_class=OperationalError` — which names the class of the **write** failure, not of the work.

This is the phase's own standing prohibition: *"MUST NOT suppress a genuine collection failure while
narrowing false positives."* The round narrowed the false positive and, in the same edit, created the
suppression.

**Reproduce:**

```python
def recording_write(s, cid, transition, *, error_class=None):
    if transition == 'failed':
        raise sqlite3.OperationalError('database is locked')
    return real_write(s, cid, transition, error_class=error_class)

worker_main._write_job_health_transition = recording_write
services.cleanup_history = raiser(DeliberateOutcomeFailure('the real cause'))
with self.assertRaises(worker_main.JobHealthBookkeepingError) as raised:
    worker_main.dispatch_callback(services, 'J8')
# Both of these currently pass — they should not:
self.assertNotIn('DeliberateOutcomeFailure', repr(raised.exception.__cause__))
self.assertNotEqual(self._job_health_row('J8')['error_class'], 'DeliberateOutcomeFailure')
```

Note the existing test `test_outcome_paths_survive_the_bookkeeping_split` covers the `raised` outcome
and the `succeeded`-write-fails outcome, but never both at once, which is why this survived.

**Fix:** carry the work's error class in the raised condition and log it before raising. It costs
nothing and preserves the no-message discipline:

```python
except Exception as exc:
    if work_error is not None:
        log.error(
            'callback %s failed and its outcome could not be recorded (work=%s, write=%s)',
            callback_id, _job_error_class(work_error), _job_error_class(exc),
        )
    raise JobHealthBookkeepingError(
        callback_id, transition, _job_error_class(exc),
        work_error_class=_job_error_class(work_error) if work_error is not None else None,
    ) from (work_error or exc)
```

Chaining `from work_error` when it exists keeps the real cause in the traceback while the *message*
still contains only bounded class names.

## Warnings

### WR-01 (round 3): The UI collapses `absent` and `complete` into one identical "No gap evidence" string

**File:** `dashboard/advanced.js:266`; `dashboard/beacon/diagnosis.py:346-349`

**Issue:** The server deliberately derives four distinct literals, and `absent` means something quite
specific: the stream list is *complete* and it contains no `('service', port)` stream at all — i.e.
the telemetry pipeline has no record of ever observing this service (`app.py` calls
`record_observation(conn, 'service', str(port), …)` on every probe, so a service with no stream row is
one the pipeline is not collecting). The client throws that distinction away:

```javascript
if (state === 'absent' || (state === 'complete' && count === 0)) return 'No gap evidence';
```

An unmonitored service and a fully-collected clean service produce byte-identical operator copy. The
new browser test pins this in place — `9002` (`absent`) and `9003` (`complete`) both assert
`'No gap evidence'` (`tests/test_advanced_ui.py`, `expected` map).

This is the "fixed *no gaps* string" case the phase's standing prohibitions name explicitly: it
presents an absence of collection as a clean bill of health.

**Fix:**

```javascript
if (state === 'absent') return 'No collection stream established for this service';
if (state === 'complete' && count === 0) return 'No gap evidence';
```

and split the two assertions in the browser test.

### WR-02 (round 3): `JobHealthBookkeepingError` has no handler anywhere, and at startup it kills the worker

**File:** `dashboard/beacon/worker_main.py:240-256, 301, 337`; `dashboard/beacon/worker_main.py:466-479`

**Issue:** `grep -rn JobHealthBookkeepingError --include=*.py dashboard` finds three sites: the class,
and two `raise`s. Nothing in `dashboard/` ever catches it. Its own docstring says the condition is
*"a fact about the recording, never a verdict on the work"* — but the code lets it become a verdict on
whether the worker runs at all:

```python
try:
    if dispatch_callback(services, 'S1') is False:
        return
    if dispatch_callback(services, 'S2') is False:
        return
    if dispatch_callback(services, 'S3') is False:
        return
    scheduler = build_scheduler(services)
    ...
except (KeyboardInterrupt, SystemExit):
    pass
finally:
    if lease_acquired:
        _finalize_worker_lifecycle(services)
```

`JobHealthBookkeepingError` is not `KeyboardInterrupt` or `SystemExit`, so a transient
`sqlite3.OperationalError('database is locked')` or `MaintenanceBusy` on the S1/S2/S3 bookkeeping write
propagates out of `run_worker` and terminates the worker process before the scheduler is ever built.
(P0 is unaffected — it runs before `authority` is a `WorkerAuthority`, so the guard at line 288 skips
bookkeeping entirely.) For scheduled callbacks APScheduler logs and continues, so the worker survives
there, but the outcome is never recorded (see WR-03).

This is not a regression — the pre-03-12 code raised the raw exception the same way — but the round
introduced a *named, documented* condition and then gave it no handler.

**Fix:** decide explicitly at the one place the design says it matters:

```python
for startup_id in ('S1', 'S2', 'S3'):
    try:
        if dispatch_callback(services, startup_id) is False:
            return
    except JobHealthBookkeepingError as exc:
        log.warning(
            'could not record %s job health (%s); startup continues',
            exc.callback_id, exc.error_class,
        )
```

### WR-03 (round 3): A job that never receives an outcome is invisible to the operator

**File:** `dashboard/beacon/worker_main.py:297-341`; `dashboard/beacon/diagnosis.py:420-422`

**Issue:** Four paths now leave `background_job_health` at `started` with no outcome ever written:

1. `LeaseLost` during the work (`worker_main.py:311-315` → `return False`);
2. `LeaseLost` during the outcome write (`worker_main.py:329-334` → `return False`);
3. a non-lease outcome-write failure (`worker_main.py:335-339` → raise);
4. a `started`-write failure, where the work is skipped entirely (`worker_main.py:297-302`).

`compose_active_exceptions` promotes only `job['state'] == 'failed'`:

```python
for job in pipeline['jobs']:
    if job['state'] == 'failed':
        exceptions.append({'kind': 'job_failed', ...})
```

So a job wedged at `started` produces no operator exception at all, while its `last_success_ts` silently
ages. Before this round the broad `except Exception` at least *attempted* a `failed` write, so a
repeated bookkeeping failure was (wrongly, but visibly) surfaced; the correct narrowing has made it
silent.

**Fix:** promote the wedged state on its own evidence, from the durable row rather than from inference:

```python
if job['state'] == 'started' and isinstance(job['last_started_ts'], int) \
        and isinstance(job['cadence_seconds'], int) \
        and now - job['last_started_ts'] > 4 * job['cadence_seconds']:
    exceptions.append({'kind': 'job_outcome_unrecorded', 'section': 'pipeline',
                       'priority': 6, 'job_id': job['job_id']})
```

and add the matching `EXCEPTION_COPY` entry in `advanced.js`.

### WR-04 (round 3): The `started` write still gates the work — a bookkeeping failure skips the callback

**File:** `dashboard/beacon/worker_main.py:296-302`

**Issue:** Carried from round 1's CR-03 second-order effect. This round did not fix it; it enshrined it
with a comment:

```python
except Exception as exc:
    # The work never ran, so there is no work outcome to record.
    raise JobHealthBookkeepingError(callback_id, 'started', _job_error_class(exc)) from exc
```

The comment is a description of the consequence, not a justification. A failure to *record* that a job
started now prevents J1 (heartbeat and worker-lease renewal), J2 (metrics), J3/J4 (probes), J8 (cleanup)
and J9 from running at all. `_write_job_health_transition` → `write_transaction` → `connect_db` blocks
up to 30 s on the maintenance flock and then raises `MaintenanceBusy` (`db.py:56-89`), and can raise
`sqlite3.OperationalError` on `BEGIN IMMEDIATE` after a 30 s busy timeout. Under sustained web/worker
write contention, bookkeeping alone can starve the heartbeat that keeps the lease alive.

**Fix:** as proposed in round 1 — log and proceed, so bookkeeping can never veto work:

```python
try:
    _write_job_health_transition(services, callback_id, 'started')
except queues.LeaseLost:
    ...  # unchanged
except Exception as exc:
    log.warning('could not record start of %s (%s); running it anyway',
                callback_id, _job_error_class(exc))
```

### WR-05 (round 3): The lease-loss log line asserts a failure that may have been a success

**File:** `dashboard/beacon/worker_main.py:330`

**Issue:** The message was written when this branch could only be reached while recording a *failure*.
After the split it is reached for `succeeded` and `CallbackReturnedFalse` alike:

```python
except queues.LeaseLost:
    log.error('Beacon worker lease lost while recording callback failure')
```

A callback that completed successfully now logs "while recording callback failure". That is an
operator-facing claim contradicted by the transition the code was actually writing — the same class of
defect this phase exists to eliminate, one layer down.

**Fix:**

```python
log.error('Beacon worker lease lost while recording %s outcome %s', callback_id, transition)
```

### WR-06 (round 3): `finiteMeasurement` turns several non-numeric values into a real measurement of `0`

**File:** `dashboard/advanced.js:71-75`

**Issue:** Verified in node against the shipped implementation:

| input | result | |
|---|---|---|
| `0`, `'0'` | `0` | correct — a real zero survives |
| `''`, `null`, `undefined` | `null` | correct |
| `'abc'`, `{}`, `'Infinity'` | `null` | correct |
| `' '`, `'  '` | **`0`** | a whitespace string becomes a measurement |
| `[]` | **`0`** | an empty container becomes a measurement |
| `false` | **`0`**, `true` → **`1`** | a boolean becomes a measurement |
| `[5]` | **`5`** | a single-element array becomes a measurement |

The helper is now the phase's single "absent value" rule and the **only** thing standing between a
server value and the fabricated `0 ms` / `0 seconds` copy this round was created to eliminate — and it
also guards `block.count` and `block.open_count` in `formatServiceGapEvidence`, where a `[]` would
render "0 gaps (0 open)". It is `''`-aware but not `'  '`-aware, which is the tell that the emptiness
check was written for a specific observed value rather than for a rule.

Not currently reachable from this server (`latency_ms`, `state_duration_seconds`, `count` and
`open_count` are all `int` or `None`), which is why this is a Warning and not a blocker.

**Fix:** make the rule the rule, not a list of observed values:

```javascript
function finiteMeasurement(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string' || value.trim() === '') return null;
  const measurement = Number(value);
  return Number.isFinite(measurement) ? measurement : null;
}
```

### WR-07 (round 3): `attach_service_collection_gaps` normalises every container except the items themselves

**File:** `dashboard/beacon/diagnosis.py:372-386`

**Issue:** The function is written as a defensive normalising boundary — `isinstance` guards on
`streams_block`, on `stream_items`, on each `stream`, and on `items` — and then drops the discipline on
the last hop:

```python
'open_count': sum(1 for item in items if item.get('open') is True),
```

A non-dict element in `items` raises `AttributeError` inside the `/api/advanced/current` request path.
The route catches only `MaintenanceBusy` and `sqlite3.OperationalError` (`app.py:2130-2137`), so the
operator gets an unparseable HTML 500 — the exact failure mode plan 03-10 set out to eliminate. The
function is a module-level public name and is unit-tested directly with hand-built dicts
(`test_advanced_diagnosis_api.py`, `attach(services, {'streams': …})`), so its contract is "normalise
untrusted shape", and it half-honours that contract.

**Fix:**

```python
'open_count': sum(1 for item in items if isinstance(item, dict) and item.get('open') is True),
```

## Info

### IN-01 (round 3): `'not_established'` is listed in the allow-list and then immediately rejected

**File:** `dashboard/advanced.js:255, 260-262`

`SERVICE_GAP_EVIDENCE_STATES` contains all four literals, and the very next statement excludes
`not_established` again. Its membership in the array is therefore dead. Either drop it from the array
and let the `includes` check reject it, or keep the array as the wire vocabulary and comment why one
member is handled separately — currently a reader must hold both rules at once to see they cancel.

### IN-02 (round 3): The formatter trusts declared counts over the items it renders beside them

**File:** `dashboard/advanced.js:263-272`

`count` prefers `block.count` over `items.length`, and `openCount` prefers `block.open_count` over the
derived count, with no cross-check. If the server ever disagreed with itself, the client would print the
declared number over a visibly different list — the same shape as the Gap-3 defect, one layer out.
Today the server derives all three from one list (`diagnosis.py:381-386`), so this is latent. Consider
asserting agreement and falling back to the derived value on mismatch.

### IN-03 (round 3): The four completeness literals are declared twice with no contract test

**File:** `dashboard/beacon/diagnosis.py:333-337` vs `dashboard/advanced.js:255`

The server defines `SERVICE_GAP_EVIDENCE_*` constants and the client re-declares the same four strings
as a JS array. Both sides are tested independently; nothing asserts the two vocabularies agree. A
rename on the server silently degrades every service row to "Gap evidence unavailable" with a green
suite. A source-level assertion (the repo already greps `advanced.js` from Python tests elsewhere) would
catch it.

### IN-04 (round 3): `attach_service_collection_gaps` both mutates and returns; the call site ignores the return

**File:** `dashboard/beacon/diagnosis.py:360, 393, 461`

The docstring describes in-place semantics, the body mutates in place, the function returns `services`
anyway, and `get_current_diagnosis` discards the return value. Pick one shape.

### IN-05 (round 3): The no-message claim in the docstring does not cover the exception chain

**File:** `dashboard/beacon/worker_main.py:240-256, 301-303, 337-339`

The docstring says the class "carries … the bounded class name of the underlying error only, so the
no-message discipline `_job_error_class` enforces for durable rows also holds for this raised
condition." That holds for `args`, but `raise … from exc` attaches the original exception, whose message
(e.g. `attempt to write a readonly database: /data/dashboard.db`) is rendered by every traceback
formatter, including APScheduler's job logger (`exc_info=True`). Chaining is the right call for
debuggability; the docstring should say the discipline holds for the *message*, not for the condition.

### IN-06 (round 3): Per-service gap items are a third alias of the same rows

**File:** `dashboard/beacon/diagnosis.py:381-386`

`service['collection_gaps']['items']` is the *same list object* as
`pipeline['streams']['items'][i]['gaps']`, which is itself the pre-slice population that
`pipeline['gaps']['items']` was cut from. Each gap row is therefore serialized up to three times in a
payload polled as often as every 5 s, and `services[].collection_gaps.count` is bounded by nothing while
`pipeline.gaps.count` is capped at 48. This is bounded overall (≤48 coverage rows + ≤64 synthetic open
gaps) and self-consistent, so it is not a Gap-3 recurrence — but round-1 WR-05 remains true: nothing in
`advanced.js` reads `streams.items[].gaps`, so that copy is now pure wire weight whose only purpose is
to be re-read server-side by `attach_service_collection_gaps`. Passing `evidence` directly to the join
would remove it from the payload.

### IN-07 (round 3): The new `lease_lost` subtest depends on a process global it neither sets nor asserts

**File:** `tests/test_advanced_diagnosis_api.py` (`test_outcome_paths_survive_the_bookkeeping_split`,
`lease_lost` subtest)

`dispatch_callback` on `LeaseLost` calls `stop_worker()`, which reads the module global
`worker_main.scheduler` and calls `.shutdown(wait=False)` on it if it is not `None`.
`AdvancedDiagnosisApiTests` neither sets nor resets that global. The subtest passes only because
`RuntimeOwnershipTests` resets `worker_main.scheduler` in its `tearDown` — i.e. suite greenness here
depends on another module's cleanup discipline, which is the shape (if not yet the effect) of the
phase's execution-order prohibition. Add `self.addCleanup(setattr, worker_main, 'scheduler', None)` or
assert `worker_main.scheduler is None` before the subtest.

### IN-08 (round 3): Unmeasured latency is ranked as an extreme in both directions, and ties survive on a `NaN` accident

**File:** `dashboard/advanced.js:529-544`

`POSITIVE_INFINITY` for an absent latency means a *descending* sort puts every unmeasured service above
the genuinely slowest measured one. That is defensible (the cell shows the failure class, not a number,
and down services arguably belong at the top) and is now pinned by
`test_unmeasured_latency_and_duration_never_rank_or_read_as_zero`. Worth recording that it is a choice,
not a consequence. Separately, two unmeasured services compare as `Infinity - Infinity === NaN`, and
stability is preserved only because `NaN || (left.index - right.index)` falls through to the index —
correct today, but an accidental dependency on `NaN` being falsy. `Number.isNaN(result) ? 0 : result`
would make it deliberate.

---

## Carried forward from round 1 (still open, not re-argued)

Verified still present in the current tree. Full argument and fix for each is in git history for this
file (commit prior to this review) or reproducible from the cited lines.

| ID | Sev | File:line | One-line |
|---|---|---|---|
| CF-WR-01 | Warning | `dashboard/app.py:2120-2141` | `/api/advanced/current` is the only read route that bypasses `_db_lock`; `journal_mode=WAL` is still never set anywhere |
| CF-WR-02 | Warning | `dashboard/app.py:2135-2137` | The 503 handler logs `exc.__class__.__name__` (always the constant `OperationalError`) and discards the message its own comment promises to log; permanent faults are labelled "temporarily unavailable" |
| CF-WR-03 | Warning | `dashboard/advanced.js:57-65`; `tests/test_advanced_ui.py:1448` | Polling has no in-flight guard, no `AbortSignal`, no timeout; `assertNotIn('AbortController', js)` still forbids the standard fix |
| CF-WR-04 | Warning | `dashboard/advanced.js:36-45` | `savePreferences` calls `localStorage.setItem` bare and runs at bootstrap; an unwritable store aborts the whole IIFE and leaves a permanent loading skeleton |
| CF-WR-05 | Warning | `dashboard/beacon/diagnosis.py:308-317` | `streams.items[].gaps` is still shipped and still read by no client code — see IN-06 above, which extends it |
| CF-WR-07 | Warning | `dashboard/advanced.html:33-38` | `aria-selected` on plain `<button>` elements is invalid and ignored; section state reaches assistive tech only through CSS |
| CF-WR-08 | Warning | `tests/test_advanced_ui.py` | `test_ui_consideration_inventory_is_complete_and_unique` is still a tautology over a module constant; the source-grep contract tests still cannot fail on a behavioral regression |
| CF-WR-09 | Warning | `dashboard/beacon/diagnosis.py:212-214` | `next(callback for … if callback.identifier == 'J1')` raises bare `StopIteration` into the request path if `J1` is ever renamed; the route does not catch it |
| CF-WR-10 | Warning | `dashboard/beacon/diagnosis.py:419` | `{'kind': …, 'priority': 5, **gap}` spreads the DB row **last**, so a future `telemetry_coverage` column named `kind`/`section`/`priority` silently overrides the classification and can `TypeError` the sort |
| CF-IN-01 | Info | `dashboard/advanced.js` | Every successful poll rebuilds the entire DOM and drops keyboard focus |
| CF-IN-02 | Info | `dashboard/advanced.js:499-513` vs `dashboard/beacon/diagnosis.py:112-123` | The D-06 ordering rule is implemented twice; currently agreeing, permanently a desync hazard |
| CF-IN-03 | Info | `dashboard/beacon/diagnosis.py:401-412` | `availability == 'unknown'` with fresh probe evidence still yields no exception |
| CF-IN-04 | Info | `dashboard/app.js:421-437` | The dashboard scroll key can outlive its navigation (middle-click, bfcache) |
| CF-IN-05 | Info | `diagnosis.py:193-195`, `advanced.js:438`, `worker_main.py:237` | `next_expected_ts` always `None`; `not_scheduled` labels five real callbacks "Not scheduled"; the `'alert_webhook_url'` optional key is not a key of the pressure group; `_job_error_class`'s `or 'CallbackFailed'` fallback is dead |
| CF-IN-06 | Info | `dashboard/advanced.js` | Three duplicated element-id maps and two freshness allow-lists |
| CF-IN-07 | Info | `dashboard/advanced.js:294-296, 391` | `countLabel` maps a missing count to `0`, so a region can print "Collection gaps (0 gaps)" above a body reading "Unknown" |
| CF-IN-08 | Info | `dashboard/beacon/diagnosis.py:190` | `schedule_kind` reports the admission category, not the trigger kind, and nothing reads it |

Round-1 `DIA-01` (traceability/checklist mismatch) remains a documentation item and is out of scope for
code review. The 03-13 executor's report that the `grep -c 'gap_evidence_truncated' == 1` acceptance
criterion is arithmetically unsatisfiable is accepted as a plan defect and is not counted here; the
code is correct as written (one producer at `diagnosis.py:316`, one consumer at `diagnosis.py:352`).

---

_Reviewed: 2026-08-19T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
