---
phase: 03-advanced-current-diagnosis
round: 7 (plans 03-20 + 03-21)
reviewed: 2026-08-19T00:00:00Z
depth: standard
diff_base: 1b3c72a
files_reviewed: 4
files_reviewed_list:
  - dashboard/app.py
  - dashboard/beacon/worker_main.py
  - dashboard/beacon/diagnosis.py
  - tests/test_advanced_diagnosis_api.py
findings:
  critical: 1
  warning: 5
  info: 6
  total: 12
status: issues_found
---

# Phase 03 round 7: Code Review Report

**Reviewed:** 2026-08-19
**Depth:** standard (adversarial, scoped to `git diff 1b3c72a..HEAD -- dashboard/ tests/`)
**Files Reviewed:** 4 source files
**Status:** issues_found

## Summary

Four of round 6's five findings are genuinely closed at the sites they name, and
three of them are closed correctly:

- **WR-04 is closed exactly as specified.** The `raise
  beacon_queues.LeaseLost('worker scan lease was lost')` at `app.py:1831` is the
  first statement in the busy branch, sits inside the outer `try:` (so
  `finally: heartbeat.stop()` at `app.py:1850` still runs), and precedes
  `requeue_scan_for_worker` at `app.py:1834-1836`. The enclosing `except
  beacon_queues.LeaseLost: raise` at `app.py:1845-1846` re-raises without
  swallowing. Verified by reading the whole function and by the new regression,
  which observes `dispatch_callback` returning `False`, the J5 row left at
  `running`, and `scan_requests` left at `running` with a `NULL` error.
- **WR-02 is byte-identical in control flow.** `git diff 1b3c72a..HEAD --
  dashboard/app.py` at that site touches only comment lines: the non-blocking
  `_uptime_lock.acquire(blocking=False)`, the `return None`, and the
  `finally: _uptime_lock.release()` at `app.py:1463-1464` are unchanged. The
  comment's new claim is also substantiated: `record_observation` skips both
  `last_observed_ts` and gap detection when `expected_cadence` is falsy
  (`telemetry.py:718-738`), so a J4-only cycle really does leave the online
  services' streams unadvanced (but see WR-05 for how narrow that disclosure is).
- **CR-01's `return not warning` is gone** and the per-request verdict is intact:
  `finish_preview_for_worker_in_transaction` still receives `status='failed' if
  warning else 'completed'` with `error=warning` (`app.py:2011-2014`), and the
  `preview_complete` event still carries `success: not bool(warning)`
  (`app.py:2019-2023`). The new regression proves the two rows disagreeing in one
  dispatch.
- **WR-01's `ValueError` surfaces as exactly one durable `job_failed`.** J9 is a
  scheduler job (`WorkerCallback('J9', ..., trigger='date')`), *not* one of the
  `S1/S2/S3` startup callbacks, so the raise cannot abort worker startup. Inside
  `dispatch_callback` it is bound to `work_error`, written as
  `('failed', 'ValueError')`, and only then re-raised
  (`worker_main.py:359-363`, `worker_main.py:398-399`), where APScheduler logs it.
  No listener intercepts it (`grep add_listener` over `dashboard/` is empty).

Full suite green: `303 passed, 426 subtests passed`.

Where round 7 fails is again the mirror image of the finding it closed. Closing
CR-01 by making `worker_process_preview_requests` return `True` unconditionally
removed the *only* J6 job-health signal for a total failure of the capture
subsystem J6 itself owns — because `_legacy_refresh_service_preview`'s blanket
`except Exception:` at `app.py:982` converts every browser-machinery fault into
`warning`, which the new code discards. A Playwright browser that is not
installed at all now records J6 `succeeded` on every 2-second poll, forever
(CR-01, reproduced below).

WR-01 is closed at two of the *three* consumers of `run_discovery`'s contract:
`worker_process_scan_requests` (J5) still decides by exclusion at
`app.py:1829/1844`, and an unrecognised literal there fabricates both a
`succeeded` J5 row *and* a `completed` manual-scan queue row (WR-01, reproduced).
WR-03's widened floor is applied globally, so an operator's discovery timeout now
silently delays wedge detection for J1/J2/J5/J6 as well (WR-02). Two further
warnings concern the new `LeaseLost` escalating a request-level condition into a
whole-worker shutdown, and the type discipline of the new floor input.

## Critical Issues

### CR-01: `return True` leaves J6 with no job-health signal at all for a total failure of its own capture machinery

**File:** `dashboard/app.py:2038` (with `dashboard/app.py:982`)

**Issue:** The new comment at `app.py:2028-2037` justifies the unconditional
`return True` by asserting that "A genuine J6 job fault -- the claim or the
transaction itself failing -- already propagates as LeaseLost above or as an
uncaught exception dispatch_callback converts to a real failed row."

That is true for the claim and the transaction. It is false for everything
between them, because `_legacy_refresh_service_preview` wraps the *entire*
capture in a blanket handler:

```python
    except Exception:
        warnings.append("title refresh failed (exception)")
        warnings.append("thumbnail refresh skipped")
```

(`dashboard/app.py:982-984`). No exception raised anywhere in the capture path —
Playwright failing to launch, Chromium OOM-killed, `/dev/shm` exhausted, an
`ImportError` on the browser binding — can reach `worker_process_preview_requests`
as an exception. All of it arrives as `warning`, which this change now discards.

J6 owns that machinery: it declares `browser_resource_lifecycle` in its
`effect_surfaces` and it is the sole occupant of the `screenshots` executor
(`worker_main.py` inventory, `worker_main.py:461`). A permanently broken browser
is a fault of the job, not of a monitored service — exactly the distinction the
round-6 fix asked for ("derive it from something the job owns, e.g. the browser
context failing to start at all").

Reproduced against the real `worker_process_preview_requests`, the real
`dispatch_callback` and the real `_legacy_refresh_service_preview`, forcing only
the `fetch_thumbnail` collaborator to raise the error Playwright raises when the
browser is not installed:

```
J6 dispatch result       -> True
J6 durable job health    -> {'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}
preview_requests row     -> {'status': 'failed',
                             'error': 'title refresh failed (exception); thumbnail refresh skipped'}
operator exceptions      -> [host_freshness, worker_freshness]   # nothing names J6
```

Before this diff the same input produced a (over-broad, but present) J6
`job_failed`. After it, the capture subsystem can fail totally and permanently
and J6's durable health reads `succeeded` at 0.5 Hz. The remaining reachable
`failed` transitions for J6 are a SQLite error inside `_worker_write_transaction`
or `claim_preview_for_worker` — nothing else. That is a fabricated success of the
same class TEL-06 exists to remove, relocated rather than removed.

The per-service surfaces do carry the evidence, which is what makes this a
tolerable *interim* state rather than a silent loss. But the comment states a
safety property the code does not have, and the plan's `provides` claims J6
"answers 'did the poller do its job'" while the code cannot observe the answer.

**Fix:** Keep `return True` for per-service conditions, and derive a job-owned
fault from a fact the poller owns, so the capture-machinery class is not merged
into `warning`. The narrow version needs no new plumbing — `_legacy_fetch_thumbnail`
already separates the two at `app.py:947-954`:

```python
    # A per-service capture verdict never decides this return value (CR-01).  A
    # failure of the capture machinery this job owns is a different fact and is
    # not reported by warning, because _legacy_refresh_service_preview's blanket
    # handler (app.py:982) erases it.  Surface it explicitly.
    if warning and 'title refresh failed (exception)' in warning:
        # The capture path raised: that is J6's own machinery, not the service.
        raise PreviewCaptureUnavailable(...)   # dispatch_callback names the class
    return True
```

or, less invasively, narrow `app.py:982` from `except Exception` to the
`requests`/`OutboundPolicyError` classes that genuinely describe the monitored
service, and let everything else propagate. Either way, add a regression that
drives `fetch_thumbnail` raising and asserts J6's durable row is `failed`, so the
distinction the comment asserts is enforced rather than described.

## Warnings

### WR-01: `_discovery_outcome_verdict` covers two of the three consumers of `run_discovery`'s contract — J5 still fails open

**File:** `dashboard/app.py:1829`, `dashboard/app.py:1844` (and `dashboard/app.py:1896`, `dashboard/app.py:1906`)

**Issue:** Plan 03-21 states the vocabulary is enforced "at both discovery
dispatchers". There are three consumers of the same
`'busy' | 'completed' | 'failed'` contract. `worker_process_scan_requests` — the
J5 path that runs the *operator's own manual scan* — was not converted and still
decides by exclusion:

```python
        if outcome == 'busy':          # app.py:1829
            ...
        status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'
```

(`app.py:1844`; the legacy `process_scan_requests` repeats it verbatim at
`app.py:1896/1906`). Every literal outside the contract therefore takes the
`'completed'` branch. Reproduced against the real poller and the real
`dispatch_callback`, with `run_discovery` returning `'an_unrecognised_literal'`:

```
J5 dispatch result     -> True
J5 durable job health  -> {'state': 'succeeded', 'last_success_ts': 100, 'error_class': None}
scan_requests row      -> {'status': 'completed', 'error': None}
```

This is strictly worse than the J7/J9 case round 6 named: the fabricated success
lands on *two* durable surfaces, and the operator's manual scan is reported as
completed having done nothing. The new test's `for job_id in ('J7', 'J9')` loop
cannot catch it because J5 is outside the loop.

**Fix:** Route J5 through the same membership check, or move the helper somewhere
both modules can import it:

```python
        outcome = worker_run_discovery(authority, source=f'manual:{claim.request_id}')
        if outcome not in ('completed', 'busy', 'failed'):
            raise ValueError(f'run_discovery returned an unknown outcome: {type(outcome).__name__}')
        if outcome == 'busy':
            ...
```

and extend `test_the_real_discovery_dispatch_honours_the_return_value_vocabulary`
(or the J5 sibling at `tests/test_advanced_diagnosis_api.py:591`) with a J5
unknown-literal subtest asserting `scan_requests.status == 'failed'`.

### WR-02: the widened floor is global, so `DISCOVERY_TIMEOUT_SECONDS` now delays wedge detection for every job, including the heartbeat

**File:** `dashboard/beacon/diagnosis.py:56`

**Issue:** `floor = max(UNRECORDED_OUTCOME_FLOOR_SECONDS, int(discovery_timeout_seconds) + 60)`
is computed once and applied to *every* job in `pipeline['jobs']`, not only to the
discovery jobs that actually run under that budget. `DISCOVERY_TIMEOUT_SECONDS` is
`_positive_int(..., 180)` with no upper bound (`config.py:205`), and the docstring
itself invites large values ("a Pi sweeping a wide port range"). Measured directly
against the live function:

```
cadence=5   (J1 heartbeat)  timeout=180   -> 900
cadence=5   (J1 heartbeat)  timeout=3600  -> 3660
cadence=2   (J5/J6 pollers) timeout=3600  -> 3660
cadence=None(J9)            timeout=1200  -> 1260
```

So an operator who raises the *discovery* timeout to an hour silently extends the
blind window for a wedged heartbeat job (J1, 5 s cadence) from 15 minutes to 61
minutes, and likewise for J2/J5/J6. Round 6's IN-05 established that
`job_outcome_unrecorded` is the *only* remaining signal for a permanently wedged
`_scan_lock`/`_uptime_lock`; this change lengthens that signal's latency by a knob
whose name has nothing to do with those jobs. The new subtests only exercise J9,
so nothing detects the collateral.

**Fix:** Apply the widened floor to the jobs that run discovery, and leave the
rest on the constant:

```python
DISCOVERY_JOB_IDS = frozenset({'J5', 'J7', 'J9'})

def _unrecorded_outcome_boundary(cadence_seconds, discovery_timeout_seconds, job_id):
    floor = UNRECORDED_OUTCOME_FLOOR_SECONDS
    if job_id in DISCOVERY_JOB_IDS:
        # Only a job that actually runs under the operator's discovery budget may
        # be measured against it; widening every job's floor would let a discovery
        # knob hide a wedged heartbeat.
        floor = max(floor, int(discovery_timeout_seconds) + 60)
    ...
```

and add a subtest asserting a J1 row aged past 900 s still promotes at
`discovery_timeout_seconds=3600`.

### WR-03: the new busy-branch `LeaseLost` escalates a per-request condition into a full worker shutdown

**File:** `dashboard/app.py:1831`

**Issue:** `heartbeat.lost` is set by `WorkerScanLeaseHeartbeat.renew_once`
(`queues.py:129-140`) from `renew_scan_lease`, whose `UPDATE ... WHERE ...
lease_until > ? AND deadline_ts > ?` (`queues.py:464-466`) fails on *request*-level
loss — an expired 900 s request deadline, or another owner taking the row — while
the worker epoch is entirely valid. Round 6 established this and used it to argue
the fabricated `succeeded` row would actually be written.

The remedy carries the same conflation into a new consequence.
`dispatch_callback` treats any `queues.LeaseLost` from the work as *worker* lease
loss (`worker_main.py:353-357`): it logs "Beacon worker lease lost; stopping stale
scheduler", calls `services.admission.close_admission()` and `stop_worker()`, and
returns `False`. So a manual scan request whose deadline expires while discovery
is busy now tears down the entire worker process — metrics, heartbeat, uptime
probes and previews included — on a healthy epoch. Before this diff that path
returned `None`.

The new test demonstrates the shutdown rather than guarding against it: it needs
`self.addCleanup(self._reset_worker_globals)` at
`tests/test_advanced_diagnosis_api.py:656` precisely because `stop_worker` mutates
the scheduler module globals, and the comment there frames it as test hygiene.

Reachability is the same as round 6 assessed (sub-millisecond busy return vs. a
≥1 s first renewal), so this is unlikely rather than impossible — but it is a new
failure mode on a path that previously could not stop the worker.

**Fix:** Distinguish the two conditions rather than reusing one class, e.g. raise a
`ScanClaimLost` that `dispatch_callback` records as a real `failed` outcome for J5
without `stop_worker()`; or, minimally, keep the raise but assert the epoch first
so only a genuine epoch loss reaches the shutdown handler:

```python
            if heartbeat.lost:
                # A lost lease is a lost lease on this path too, but only an epoch
                # loss may stop the worker: a request-level deadline expiry is one
                # request's fault, not the process's.
                raise beacon_queues.ScanClaimLost('worker scan claim was lost')
```

and pin it with a subtest asserting `worker_main._worker_started` and the
scheduler globals are untouched after a request-level loss.

### WR-04: `int(discovery_timeout_seconds)` breaks `diagnosis.py`'s own strict-type discipline and can abort the whole diagnosis payload

**File:** `dashboard/beacon/diagnosis.py:56`

**Issue:** Every other numeric input in `compose_active_exceptions` is guarded
rather than coerced — `type(job.get('last_started_ts')) is int`, `type(now) is int`
(`diagnosis.py:478-480`), and the sibling line 57 in this very function uses
`type(cadence_seconds) is int`. The comment at line 58-61 calls that "strict-integer
discipline, reused rather than a second convention." The new line introduces a
second convention that both coerces and can raise. Measured:

```
_unrecorded_outcome_boundary(5, None)   -> TypeError: int() argument must be ... not 'NoneType'
_unrecorded_outcome_boundary(5, 900.9)  -> 960     # silently truncated
_unrecorded_outcome_boundary(5, True)   -> 900     # bool accepted as 1
```

The `TypeError` is raised inside `compose_active_exceptions`, i.e. inside
`get_current_diagnosis`, so a single malformed setting takes out the *entire*
`/advanced` diagnosis payload — including `recovery_required`, host freshness and
every unrelated exception — rather than degrading one promotion. Production
`Settings` always yields an int (`_positive_int` falls back to its default on
`TypeError`/`ValueError`), so today this is a robustness and consistency defect
rather than a live crash; but this module is explicitly documented as a
"safety-first deterministic exception projection", and this is now its only input
that can abort it.

**Fix:** Guard, do not coerce, and pick the safe direction on malformed input:

```python
    floor = UNRECORDED_OUTCOME_FLOOR_SECONDS
    if type(discovery_timeout_seconds) is int and discovery_timeout_seconds > 0:
        floor = max(floor, discovery_timeout_seconds + 60)
```

### WR-05: the compensating disclosure the new uptime comment relies on needs an exact 600-second boundary a single skipped J3 tick barely reaches

**File:** `dashboard/app.py:1334-1343`

**Issue:** The rewritten comment moves the honesty burden onto one specific
surface: "the telemetry-coverage surface is what must disclose a real gap, never
this return value." That surface is `detect_collection_gaps`, which confirms a gap
only when `int(now) >= int(last) + 2 * cadence` (`telemetry.py:683`), and service
streams are recorded with `cadence_seconds=300` (`app.py:1416`).

One skipped J3 tick therefore produces a delta of *exactly* `2 * 300` in the ideal
case, and the check is `>=`, so it passes only if the later run's wall-clock
`now = int(time.time())` (taken after the lock acquire, `app.py:1344`) is not
closer to the earlier one. J3 runs on the shared 2-thread `probes` executor with
J4/J5/J7/J9 and `misfire_grace_time=60` (`worker_main.py:434`,
`worker_main.py` inventory). If the *earlier* successful J3 was dispatched, say,
30 s late under executor contention and the next one is on time, the delta is 570
and no gap is recorded at all — the skipped cycle is silently covered, which is
the exact outcome the comment promises cannot happen.

The new test does not exercise this: it asserts only that the yielding dispatch
leaves `last_uptime_check` unadvanced, never that any coverage gap is produced.

**Fix:** Either state the narrower true claim in the comment ("a *single* skipped
full sweep is disclosed only when the next sweep lands at or after two cadences;
sustained loss is disclosed reliably"), or make the disclosure independent of
scheduler jitter by recording the skip explicitly at the yield site:

```python
    if not _uptime_lock.acquire(blocking=False):
        if not only_down:
            log.info('Full uptime sweep yielded to a concurrent down-only probe')
        return None
```

paired with a coverage interval or event the diagnosis surface can read, and a
regression asserting a J3 yield followed by a J3 sweep at `last + 570` still
discloses the gap.

## Info

### IN-01: two new test methods have no blank line before their `def`

**File:** `tests/test_advanced_diagnosis_api.py:389`, `tests/test_advanced_diagnosis_api.py:639`
**Issue:** Both new methods start on the line immediately after the previous
method's closing `)` (PEP 8 E301). Every other method in the 1900-line file is
separated by one blank line, so this is a local inconsistency introduced by both
plans independently.
**Fix:** Insert one blank line before each `def test_a_titleless_service_...` and
`def test_a_busy_discovery_lock_with_a_lost_lease_...`.

### IN-02: `error_class='ValueError'` cannot be distinguished from three other `ValueError`s the same dispatcher raises

**File:** `dashboard/beacon/worker_main.py:206`
**Issue:** The durable evidence for an unrecognised discovery outcome is the bare
class name `'ValueError'` (`_job_error_class`, `worker_main.py:266-268`). The same
durable value is produced by `_invoke_callback`'s `callback ... cannot be
dispatched` (`worker_main.py:263`), `_write_job_health_transition`'s `unknown
background job transition` (`worker_main.py:317`), and `WorkerAdmission.admit`'s
`unknown worker admission category`. On a surface whose entire purpose is
operator-legible durable evidence, the four are indistinguishable.
**Fix:** Define `class UnknownDiscoveryOutcome(ValueError)` in `worker_main.py` and
raise that, so the durable row reads `UnknownDiscoveryOutcome`; the new test's
`assertRaises(ValueError)` continues to pass unchanged.

### IN-03: the new raised message embeds an unbounded value while every neighbouring string is length-capped

**File:** `dashboard/beacon/worker_main.py:206`
**Issue:** `f'run_discovery returned an unknown outcome: {outcome!r}'` interpolates
an arbitrary collaborator return value with no cap, next to `_job_error_class`'s
`[:96]`, `JobHealthBookkeepingError`'s documented "bounded class names only", and
`str(exc)[:240]` at `app.py:1846`. 03-20-SUMMARY.md's own verification asserts "No
... raised condition message ... carries an exception message, filesystem path, or
SQL fragment"; that holds today only because `run_discovery` returns short literals.
**Fix:** `f'run_discovery returned an unknown outcome: {type(outcome).__name__}'`,
or cap it: `{repr(outcome)[:96]}`.

### IN-04: two of the round's new assertions are characterization tests that pass against the pre-fix code

**File:** `tests/test_advanced_diagnosis_api.py:555-570`, `tests/test_advanced_diagnosis_api.py:746`
**Issue:** The `a_busy_discovery_lock_is_recorded_as_succeeded` subtest passes
identically under the old `return outcome != 'failed'` (`'busy' != 'failed'` is
`True`), and the new `last_uptime_check` assertion accompanies a comment-only
change, so it too passes on both sides of the diff. Both are legitimate
contract pins — round 6 asked for exactly the `'busy'` one — but neither is a
regression for this round's fixes. The genuine regressions are the
unknown-outcome subtest, the titleless-service test, the lost-lease test, and the
widened-floor subtest, all four of which fail against the pre-fix tree (the last
by `TypeError` on the new required keyword).
**Fix:** None required; recorded so the round's regression coverage is not
overcounted at 5 new pins when it is 4.

### IN-05: the WR-02 assertion pins a fresh-database default rather than an unadvanced value

**File:** `tests/test_advanced_diagnosis_api.py:746`
**Issue:** `self.assertIsNone(state['last_uptime_check'])` asserts the value a
never-probed database already has. A regression that *cleared* `last_uptime_check`
on the yield path would pass; only a regression that *set* it is caught.
**Fix:** Seed a distinctive prior value before the dispatch and assert it survives:
`self.appmod._update_scan_state(last_uptime_check=42)` … `self.assertEqual(state['last_uptime_check'], 42)`.

### IN-06: round 6's five Info findings are all still open

**File:** `dashboard/beacon/worker_main.py:550-551`, `dashboard/beacon/worker_main.py:547`, `dashboard/app.py:1871`
**Issue:** Neither plan scoped them, and each is confirmed unchanged in the diff:
IN-02's silent `except Exception: pass` on the best-effort startup retry, IN-03's
hardcoded `'failed'` transition literal, IN-04's `CallbackReturnedFalse` masking
the real discovery error class on J5, IN-01's loose floor pin (which this round's
new `discovery_timeout_seconds=180` subtest partially tightens), and IN-05's
unpinned permanent-wedge bound (which WR-02 above now makes more consequential,
since the bound is no longer a constant).
**Fix:** Carry into deferred-items.md explicitly rather than letting them lapse
between rounds.

---

_Reviewed: 2026-08-19_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard, adversarial, diff `1b3c72a..HEAD`_
