---
phase: 03-advanced-current-diagnosis
round: 6 (plans 03-18 + 03-19)
reviewed: 2026-08-19T00:00:00Z
depth: standard
diff_base: e42dd4e
files_reviewed: 3
files_reviewed_list:
  - dashboard/app.py
  - dashboard/beacon/worker_main.py
  - tests/test_advanced_diagnosis_api.py
findings:
  critical: 1
  warning: 4
  info: 5
  total: 10
status: issues_found
---

# Phase 03 round 6: Code Review Report

**Reviewed:** 2026-08-19
**Depth:** standard (adversarial, scoped to `git diff e42dd4e..HEAD`)
**Files Reviewed:** 3 source files
**Status:** issues_found

## Summary

Round 6 does close the two things it set out to close, and the mechanics are sound
where it matters most:

- **Requeue and lock semantics are untouched.** The only edits at both contention
  sites are the returned value. `requeue_scan_for_worker` is still called under the
  same `if not heartbeat.lost:` guard with the same arguments (`app.py:1826-1828`),
  and `_uptime_lock`'s non-blocking acquire and its `finally: release()` are
  byte-identical (`app.py:1333`, `app.py:1458`). No retry or backoff timing changed.
  Verified empirically: the busy scan still reads `status='queued'` with `error IS
  NULL` afterwards.
- **The compound-startup re-raise is not weakened.** The retry at
  `worker_main.py:525-531` sits strictly before the unchanged unconditional `raise`,
  makes exactly one attempt (no loop, no recursion), is entered only when
  `work_error_class is not None`, and its `except Exception` cannot catch
  `KeyboardInterrupt`/`SystemExit`. The bookkeeping-only path (`work_error_class is
  None`) still only warns and continues. Pinned in both directions by the sibling
  tests at `tests/test_advanced_diagnosis_api.py:996` and the updated assertion at
  line 983.
- **The floor pin is genuinely external, not tautological.** Verified without
  mutating the tree by injecting `diagnosis.UNRECORDED_OUTCOME_FLOOR_SECONDS` at
  runtime: floor=900 passes, 181 passes, 180 fails (1), 60 fails (2), 30 fails (2).
  The executor's non-tautology claim holds.
- **The permanent-wedge trade-off (priority 2) is adjudicated SOUND.** `_scan_lock`
  and `_uptime_lock` are only ever acquired inside `_legacy_run_discovery` /
  `_legacy_do_uptime_check`, which in the worker process are only reachable through
  a dispatched callback that has already written a `started` row. APScheduler
  `max_instances=1` means the wedged job cannot re-enter and therefore never records
  an outcome, so `job_outcome_unrecorded` fires against it after
  `max(900, 4*cadence)`. The yielding job's fabricated "always succeeds" reading is
  therefore always accompanied by a promoted card on the job that is actually stuck.
  Separately, the requeued manual scan is not infinite: `deadline_ts = requested_ts +
  900` and the sweeper at `queues.py:334-338` moves it to `status='expired'`. The
  bound is real. It is, however, pinned by no test (IN-05).

Where the round fails is the mirror image of the round-4 finding it was written to
avoid: while closing two low-frequency fabricated *failures*, plan 03-18 opened a
**new, high-frequency fabricated failure at `worker_process_preview_requests`**
(CR-01), reachable every time a monitored service is offline or serves a page with
no `<title>`. Four further warnings concern a fail-open comparison, a justification
that does not hold at the uptime site, an invariant the code does not enforce against
an operator-configurable value, and a lease-loss path that now reports success.

`dashboard/beacon/diagnosis.py` is confirmed clean: `git diff e42dd4e..HEAD --
dashboard/beacon/diagnosis.py` is empty and `git status` shows no working-tree
modification. The test-validity mutation was fully restored.

Full suite: `301 passed, 421 subtests passed`.

## Critical Issues

### CR-01: `return not warning` turns a routine per-service preview outcome into a fabricated J6 *job* failure

**File:** `dashboard/app.py:2021`

**Issue:** `worker_process_preview_requests` now returns `not warning`, where `warning`
is the sixth element of `_legacy_refresh_service_preview`'s tuple
(`dashboard/app.py:957-986`). That value is a *per-service capture* verdict, not a
worker verdict. It is non-`None` in all of these entirely routine cases:

- the monitored service is offline or unreachable at capture time →
  `"title refresh failed (probe_failed); thumbnail refresh skipped"` (`app.py:980-981`);
- the page renders and the thumbnail succeeds but the page has no `<title>` →
  `"title not found at configured path"` (`app.py:976`);
- Chromium fails one screenshot (OOM/timeout on a Pi) → `"thumbnail refresh failed"`
  (`app.py:978`).

Each of those now makes `dispatch_callback` take its `if result is False:` branch and
write a durable `('failed', 'CallbackReturnedFalse')` job-health row for **J6**, which
surfaces to the operator as a `job_failed` card in `/advanced`.

Triggering state and observable wrong behaviour, reproduced against the real adapter
and the real `dispatch_callback` (service seeded online, preview enqueued,
`_fetch_html_response` returning `(False, 'connect_error', None, None)` — i.e. the
service simply went down between the uptime probe that enqueued the preview and the
capture):

```
dispatch result -> False
operator job_failed cards -> [{'kind': 'job_failed', 'section': 'pipeline',
                               'priority': 6, 'job_id': 'J6'}]
```

The preview poller did its job correctly in that run: it claimed the request, captured
what was available, and durably recorded `preview_requests.status='failed'` with the
warning plus a `preview_complete` event carrying `success: false`. The per-service
truth is already published on the per-service surfaces. Reporting it a second time as a
*background job* failure is exactly the 03-08 honesty violation this phase exists to
remove — and it fires far more often than the two contention sites this round closed
(J6 polls every 2 s; one offline or title-less service is enough to keep the card
permanently lit and drown genuine J6 faults).

Note the asymmetry with the J5 sibling, which is defensible: J5's `status='failed'`
comes from `outcome == 'failed'`, i.e. `do_discovery` itself raised — a genuine worker
fault. J6's comes from the content of a third-party service.

**Fix:** Do not let a per-service capture warning become the job's verdict. The job
failed only if the claim/transaction handling failed — which already propagates as
`LeaseLost` or an exception that `dispatch_callback` converts to a real
`('failed', <real class>)` row.

```python
    except beacon_queues.LeaseLost:
        raise
    # The per-service capture verdict is already durable on preview_requests.status
    # and on the preview_complete event.  A service that is offline, or a page with
    # no <title>, is not a fault of the preview poller: reaching this line means the
    # claim was honoured and its outcome was recorded in an authority-asserted
    # transaction, which is the whole of this job's contract.
    return True
```

If a genuine J6 *job* fault signal is wanted later, derive it from something the job
owns (e.g. the browser context failing to start at all), never from `warning`.
`tests/test_advanced_diagnosis_api.py:307`'s J6 subtest asserts the current behaviour
and must be re-pointed at a real job fault at the same time.

## Warnings

### WR-01: `outcome != 'failed'` fails open — any unrecognised return value is reported as success

**File:** `dashboard/beacon/worker_main.py:199`, `dashboard/beacon/worker_main.py:210`

**Issue:** Both discovery dispatchers decide success by *exclusion*. Every value that
is not the exact literal `'failed'` — `'busy'`, `'completed'`, `None`, `''`, `0`, or
any literal a future `_legacy_run_discovery` adds — maps to `True` → `succeeded`. The
adjacent comment asserts "run_discovery's contract is exactly `'busy' | 'completed' |
'failed'`", but nothing enforces that contract: `services.run_discovery` is an
injected collaborator (`worker.py:32`), `beacon/monitoring.py:80-81` passes the value
straight through, and only one test anywhere pins the `'busy'` literal
(`tests/test_release_contract.py:249`). In a phase whose entire subject is fabricated
success, the default direction of an unknown value should be failure, not success.

Confirmed for `'busy'` specifically: it maps to `succeeded`, which is the intended
result and is consistent with this round's philosophy — but it is pinned by no test in
either `_run_scheduled_discovery` or `_run_startup_discovery`, so the intent is
undefended.

**Fix:** Use a positive whitelist so an unrecognised value fails closed and loudly:

```python
    outcome = services.run_discovery(services.authority, source='scheduled')
    if outcome in ('completed', 'busy'):
        return True
    if outcome == 'failed':
        return False
    raise ValueError(f'run_discovery returned an unknown outcome: {outcome!r}')
```

and add the `'busy'` case to
`test_the_real_discovery_dispatch_honours_the_return_value_vocabulary`
(`tests/test_advanced_diagnosis_api.py:395`), which today drives only `'failed'` and
the two skip paths.

### WR-02: the uptime-contention justification does not hold when J3 loses to J4 — and they collide by construction every 5 minutes

**File:** `dashboard/app.py:1334-1336`

**Issue:** The new comment justifies `return None` with "Another run already owns this
work ... It self-clears on the next scheduled tick." That is true when the two probes
do the same work; J3 and J4 do not. J3 is `only_down=False` (probe every service), J4
is `only_down=True` (probe only services already offline), and they share both
`_uptime_lock` and `ThreadPoolExecutor(2)` (`worker_main.py:86-87`, `worker_main.py:434`).

The collision is not rare: J3's interval is 5 minutes and J4's is 1 minute, so 300 is
an exact multiple of 60 and the two triggers fire on the same instant every fifth J4
tick, both dispatched concurrently on a 2-thread executor. Whichever loses the
non-blocking acquire returns immediately.

When the loser is **J3**, the winner (J4) probes only offline services, records no
`expected_cadence` observations (`app.py:1409-1412` passes
`expected_cadence=not only_down`), and does not advance `last_uptime_check` — only
`last_down_check` (`app.py:1449-1452`). So no online service is checked that cycle,
J3's own coverage is not refreshed, and J3's durable job health now reads `succeeded`.
Previously it read `failed`: wrong label, but visible. The round replaced a mislabelled
signal with no signal at a path that executes routinely.

The new test at `tests/test_advanced_diagnosis_api.py:517` does not distinguish the
two directions — it takes the lock from the test thread and asserts only that J3
returns `None` and records `succeeded`. It never asserts "the probe was not dropped",
which is the half of the deferred row-8 contract that actually needed pinning.

**Fix:** Either make the skip conditional on the holder doing at least the loser's
work, or record it as an explicit skip rather than a success. A minimal, honest option
is to keep the non-fault reporting but stop claiming equivalence, and add the direction
the comment asserts:

```python
def _legacy_do_uptime_check(only_down=False):
    if not _uptime_lock.acquire(blocking=False):
        # Another uptime probe owns the lock.  A down-only holder does NOT perform a
        # full sweep, so an all-services run that yields here is skipped, not covered;
        # telemetry coverage (expected_cadence) remains the surface that reports it.
        log.info('Uptime check yielded to a concurrent probe (only_down=%s)', only_down)
        return None
```

and extend the test to assert that a J3 which yields to a J4 leaves
`scan_state['last_uptime_check']` unadvanced, so the trade-off is visible to the next
reader rather than asserted in prose.

### WR-03: the 900 s floor is hardcoded while `DISCOVERY_TIMEOUT_SECONDS` is operator-configurable and unbounded

**File:** `tests/test_advanced_diagnosis_api.py:1624`, `tests/test_advanced_diagnosis_api.py:1626-1636`

**Issue:** The new subtests assert a relationship the code does not enforce:
`UNRECORDED_OUTCOME_FLOOR_SECONDS` is the literal `900`
(`dashboard/beacon/diagnosis.py:40`), while `DISCOVERY_TIMEOUT_SECONDS` comes from
`_positive_int(source, 'DISCOVERY_TIMEOUT_SECONDS', 180)`
(`dashboard/beacon/config.py:205`), which accepts any positive integer with no upper
bound. For any deployment configured above 900 — plausible on a Pi sweeping a wide
port range — a J7/J9 discovery that is *legitimately still running* is promoted to a
`job_outcome_unrecorded` operator card at 900 s. That is a fabricated fault, and it is
the exact class of defect the floor exists to avoid.

The test half is environment-dependent for the same reason: `tests/helpers.py:52-64`
sets only six env keys and leaves the rest of `os.environ` intact, so an ambient
`DISCOVERY_TIMEOUT_SECONDS` leaks into the reloaded module. Demonstrated:

```
$ DISCOVERY_TIMEOUT_SECONDS=1200 ... -k stuck_without_an_outcome
SUBFAILED(case='the_floor_clears_connect_dbs_own_lock_waits')
SUBFAILED(case='a_full_discovery_timeout_run_promotes_nothing')
    + []
    - [{'job_id': 'J9', 'kind': 'job_outcome_unrecorded', 'priority': 6,
        'section': 'pipeline'}]
```

The second failure is not a test artefact — it is the production defect the test is
correctly detecting.

**Fix:** Make the boundary derive the invariant rather than assume it, in
`_unrecorded_outcome_boundary`:

```python
    floor = max(UNRECORDED_OUTCOME_FLOOR_SECONDS, settings.discovery_timeout_seconds + 60)
```

(threading the setting through, or exposing a resolved floor the tests read), and pin
the test's environment with `load_app({'METRIC_SAMPLE_SECONDS': '5',
'DISCOVERY_TIMEOUT_SECONDS': '180'})` so an ambient value cannot change the verdict.

### WR-04: the busy branch is the one path that bypasses the `heartbeat.lost` guard, and it now reports success

**File:** `dashboard/app.py:1826-1831`

**Issue:** Every other terminal path in `worker_process_scan_requests` treats a lost
lease as fatal — `if heartbeat.lost: raise beacon_queues.LeaseLost(...)` at
`app.py:1843-1844`. The busy branch returns before reaching it. So when
`heartbeat.lost` is `True`:

- `requeue_scan_for_worker` is skipped (`app.py:1826`), leaving the claim at
  `status='running'` with a dead lease;
- no `fail_scan_for_worker` is written;
- the function returns `None`, which this round changed from `False`, so
  `dispatch_callback` now records J5 as **succeeded** instead of failed.

`renew_scan_lease` raises `LeaseLost` on request-level loss too, not only epoch loss —
`AND lease_until > ? AND deadline_ts > ?` at `queues.py:464-466` — so an expired
request deadline sets `heartbeat.lost` while the worker epoch is entirely valid, which
means `_write_job_health_transition`'s `assert_current_worker_authority` will *not*
intercept and the fabricated `succeeded` row is actually written.

Reachability is low: the heartbeat's first renewal is at least 1 s after `start()`
(`queues.py:77`, `queues.py:98`) while the busy return is sub-millisecond (a
non-blocking `acquire` that fails). It is nonetheless the only path in this function
that can drop a claim and call it success, and no test covers it — the new test at
`tests/test_advanced_diagnosis_api.py:468` exercises only `heartbeat.lost == False`.

**Fix:** Apply the same guard the rest of the function uses, before deciding the
outcome:

```python
        if outcome == 'busy':
            if heartbeat.lost:
                # A lost lease is a lost lease on this path too: do not requeue a
                # claim we no longer own, and do not report the poll as clean.
                raise beacon_queues.LeaseLost('worker scan lease was lost')
            beacon_queues.requeue_scan_for_worker(
                authority, claim.request_id, claim.lease_owner, now=int(now_fn()),
            )
            return None
```

(the `raise` must come from inside the `try` so the `finally: heartbeat.stop()` still
runs), and add a subtest driving a `'busy'` outcome with a heartbeat stub whose `lost`
is `True`.

## Info

### IN-01: the floor pin only defends down to 181 seconds

**File:** `tests/test_advanced_diagnosis_api.py:1616-1636`
**Issue:** Measured sensitivity (constant injected at runtime, tree untouched):
900 pass, 181 pass, 180 fail, 60 fail, 30 fail. The two comparisons together only
force `floor > DISCOVERY_TIMEOUT_SECONDS` (180); a regression from 900 to 181 ships
green, and the `assertGreater(floor, 30 + 30)` line is fully subsumed by the other.
The pin is genuinely external — it is just loose.
**Fix:** Pin the *margin* the comment claims, not merely the ordering, e.g.
`self.assertGreaterEqual(floor, self.appmod.DISCOVERY_TIMEOUT_SECONDS * 2)` alongside
the connect_db comparison, so the stated headroom is the thing under test.

### IN-02: the retry's `except Exception: pass` is silent and can delay the loud raise by up to ~60 s

**File:** `dashboard/beacon/worker_main.py:530-531`
**Issue:** Nothing distinguishes "the retry succeeded" from "the retry also failed" in
the logs, and the retry re-enters `write_transaction` → `connect_db`, which waits up
to 30 s on the maintenance flock (`db.py:76`) plus up to 30 s on SQLite's busy timeout
(`db.py:79`, `db.py:83`). Worst case that doubles the time `run_worker` blocks while
holding `_worker_start_lock`, before `signal.signal` has installed the SIGTERM/SIGINT
handlers (`worker_main.py:548-549`). The raise is never suppressed and never looped —
only bounded-delayed — and the retry-failed case still leaves an unresolved `running`
row that `job_outcome_unrecorded` will eventually promote, so evidence exists either
way.
**Fix:** `except Exception as retry_error: log.warning('Best-effort retry of a
compound startup failure write also failed: callback=%s error_class=%s',
startup_callback_id, _job_error_class(retry_error))` — keeps the swallow, ends the
silence.

### IN-03: the retry hardcodes the `'failed'` transition instead of reading it off the condition

**File:** `dashboard/beacon/worker_main.py:527`
**Issue:** `bookkeeping_error.transition` is available and is guaranteed `'failed'`
whenever `work_error_class is not None` (`worker_main.py:340-341, 369-372`), so the
literal is correct today. It is coupled to that invariant by nothing but this comment.
**Fix:** `_write_job_health_transition(services, startup_callback_id,
bookkeeping_error.transition, error_class=bookkeeping_error.work_error_class)`.

### IN-04: a genuinely raised discovery error reaches durable job health as `CallbackReturnedFalse`

**File:** `dashboard/app.py:1860`
**Issue:** The new boolean return means J5's durable `error_class` is always the
generic `'CallbackReturnedFalse'` even when `run_discovery` raised a specific class —
asserted as such by the new test at `tests/test_advanced_diagnosis_api.py:344`. The
real class survives only as free text in `scan_requests.error`. The operator's job-health
surface therefore cannot distinguish a network error from a database error.
**Fix:** Out of scope for a return-value change, but worth recording: propagating the
exception (and letting `dispatch_callback`'s `_job_error_class` name it) would carry the
real class without changing the queue-row contract.

### IN-05: nothing pins the permanent-wedge bound the trade-off relies on

**File:** `dashboard/app.py:1831`, `dashboard/app.py:1336`
**Issue:** The reasoning that a permanently wedged lock still surfaces (because the
wedged job's own `started` row never receives an outcome and is promoted to
`job_outcome_unrecorded`) is correct — verified against `max_instances=1`
(`worker_main.py:445`), the single acquire sites (`app.py:1324`, `app.py:1333`), and
the 900 s scan deadline sweeper (`queues.py:334-338`). But no test asserts it, so a
future change to the promotion boundary or to `max_instances` would silently remove the
only remaining signal for a wedge.
**Fix:** Add one subtest: a J7 row left `running` past the boundary while J5 records
repeated `succeeded` rows still yields exactly one `job_outcome_unrecorded` card for J7.

---

_Reviewed: 2026-08-19_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard, adversarial, diff `e42dd4e..HEAD`_
