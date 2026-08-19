---
phase: 03-advanced-current-diagnosis
plan: 17
reviewed: 2026-08-19T00:00:00Z
depth: standard
diff_base: e12cada
files_reviewed: 5
files_reviewed_list:
  - dashboard/advanced.js
  - dashboard/app.py
  - dashboard/beacon/diagnosis.py
  - dashboard/beacon/worker_main.py
  - tests/test_advanced_diagnosis_api.py
findings:
  critical: 0
  warning: 5
  info: 5
  total: 10
status: issues_found
---

# Phase 03 Plan 17: Code Review Report (gap-closure round 5)

**Reviewed:** 2026-08-19
**Depth:** standard (with executable adversarial probes)
**Diff range:** `e12cada..HEAD` (8 commits)
**Files Reviewed:** 5
**Status:** issues_found — 0 Critical, 5 Warning, 5 Info

## Summary

All three defects named in the round-4 gap are genuinely closed, and I verified this
rather than taking the summary's word for it. Three independent probes were run
against throwaway copies of the tree (never against the working tree):

| Probe | Method | Result |
|---|---|---|
| Are the new tests real regressions? | HEAD's `tests/` grafted onto `e12cada`'s `dashboard/beacon/diagnosis.py`, `worker_main.py`, `app.py`, `advanced.js` | **5 failures** — all three new/rewritten tests fail against the old implementation. Not tautological. |
| Is `max` actually pinned (vs `min`)? | `max(...)` → `min(...)` in `_unrecorded_outcome_boundary` | **3 subtests fail** (`exactly_at_the_boundary`, `short_cadence_job_nine_seconds_in`, `heartbeat_blocked_behind_the_maintenance_lock`). Pinned. |
| Is the strict comparison pinned? | `>` → `>=` at `diagnosis.py:468` | **1 subtest fails** (`exactly_at_the_boundary_promotes_nothing`). Pinned. |
| Is the narrow re-raise pinned (vs over-broad)? | `work_error_class is not None` → `True` | **`test_startup_survives_a_bookkeeping_failure` fails.** The bookkeeping-only path is genuinely protected. |
| Does the re-raise strand worker state? | Ran the compound path and inspected the DB and module globals afterwards | **No strand.** `calls == ['prepare','recover','shutdown_browser']`, the `worker_owner` runtime row is gone (lease released), and `scheduler`/`_worker_started`/`_active_services`/`_active_worker_id` are all reset. The re-raise sits inside the outer `try`, so the `finally: _finalize_worker_lifecycle(services)` still runs. |
| Sentinel change — every consumer traced | `grep` of the whole tree for `dispatch_callback`, `process_scans`, `process_previews`, `worker_process_scan_requests`, `worker_process_preview_requests` | **Safe.** Only three consumers of `dispatch_callback`'s return exist in `dashboard/`: `build_scheduler`'s `partial` (return discarded by APScheduler), the `P0` call (return discarded), and `run_worker`'s `is False` startup test — which is identity-based, not truthiness-based, and is never reached by J5/J6. No `if result:` / `if not result:` site exists anywhere that could now conflate `None` with `False`. |
| Full suite | `uv run --project dashboard python -m pytest -q` | 296 passed / 413 subtests, matching the summary. |

Boundary arithmetic is correct: `max`, not `min` (`diagnosis.py:50`); the `None` /
non-`int` / `<= 0` path returns the floor and can never fall below it
(`diagnosis.py:52-54`); `type(x) is int` correctly excludes `bool`; `max(0, now - ts)`
guards a negative elapsed; the comparison is strictly greater-than.

What follows are the defects the change did not close, plus test-quality gaps that
would let a plausible future change reinstate one of the three defects while the
suite stays green.

## Warnings

### WR-01: No test pins the floor's value — the suite stays green with a 30-second floor

**File:** `dashboard/beacon/diagnosis.py:40`, `tests/test_advanced_diagnosis_api.py:1222`, `1289-1305`

**Issue:** The must-have truth is that the boundary is "a floor no legitimate run can
plausibly exceed". Nothing tests that. `tests/test_advanced_diagnosis_api.py:1222` reads
`floor = diagnosis.UNRECORDED_OUTCOME_FLOOR_SECONDS` and then derives every
absent-cadence expectation from it (`last_started_ts=now - floor + 1` and
`now - floor - 1`, lines 1295 and 1303). Those assertions are self-referential with
respect to the constant and cannot fail for *any* value of it. The only subtests that
constrain the floor at all are the two using absolute figures — `cadence=2` at 9 s and
`cadence=5` at 25 s — which together only require `floor >= 25`.

**Proved, not asserted.** I set `UNRECORDED_OUTCOME_FLOOR_SECONDS = 30` in a throwaway
copy of HEAD and ran the entire suite: **296 passed / 413 subtests passed**, unchanged.
A 30-second floor is *below* `connect_db`'s own 30-second `flock` wait and 30-second
`busy_timeout` and far below `DISCOVERY_TIMEOUT_SECONDS: "180"` (`docker-compose.yml`).
That is the exact false-positive class this plan exists to remove — a J9 startup
discovery legitimately running for 101 s would be promoted as a fault under a 100-second
floor, with a fully green suite. The constant's stated rationale (its own comment, lines
35-39) is entirely unverified.

**Fix:** Add a subtest that pins the floor against the two real values its comment cites,
rather than against itself:

```python
with self.subTest(case='the_floor_clears_connect_dbs_own_lock_waits'):
    # connect_db allows a 30 s flock wait and a 30 s busy_timeout; discovery is
    # allowed 180 s. A run inside any of those is legitimate work, not a fault.
    self.assertGreater(floor, 30 + 30)
    self.assertGreater(floor, self.appmod.DISCOVERY_TIMEOUT_SECONDS)

with self.subTest(case='a_discovery_length_run_promotes_nothing'):
    self.assertEqual(
        compose(job_row(job_id='J9', cadence_seconds=None,
                        last_started_ts=now - 180)),
        [],
    )
```

### WR-02: A startup callback that *returns* `False` while its outcome write fails is misclassified as "bookkeeping-only" and startup continues

**File:** `dashboard/beacon/worker_main.py:502-521` (with `dispatch_callback` at `328-330` and `352-358`)

**Issue:** The new branch splits `JobHealthBookkeepingError` into exactly two classes,
using `work_error_class is not None` as the discriminator. But `dispatch_callback`
produces a *third* condition it does not account for. At `worker_main.py:328-330`, a
callback that returns literal `False` sets `transition, error_class = 'failed',
'CallbackReturnedFalse'` while leaving `work_error = None`. If the outcome write then
fails, `worker_main.py:352-354` computes `work_error_class = None` (because
`work_error is None`) and raises `JobHealthBookkeepingError` with `work_error_class=None`.

Observable wrong behaviour: a startup callback that *refused* (`False`) and whose refusal
could not be recorded falls into the `log.warning(...)` branch and **startup continues** —
whereas the very same refusal, recorded successfully, hits
`if dispatch_callback(...) is False: return` at line 502 and **aborts startup**. Whether
Beacon starts is decided by whether an unrelated SQLite write succeeded.

This is currently unreachable: `worker_recover_worker_state` (app.py:296), 
`worker_update_worker_heartbeat` (app.py:307) and `worker_collect_system_stats`
(app.py:1754) all return truthy. It becomes live the moment any startup handler grows a
refusal path — which is exactly what `worker_process_scan_requests`'s busy branch already
does for a scheduled job. The new code introduces the classification, so it owns the
third case.

**Fix:** Discriminate on the recorded transition too, not just on `work_error_class`:

```python
except JobHealthBookkeepingError as bookkeeping_error:
    if (
        bookkeeping_error.work_error_class is not None
        or bookkeeping_error.transition == 'failed'
    ):
        # Either the work failed, or the work refused; in both cases the outcome
        # that decides whether Beacon should run went unrecorded.
        raise
    log.warning(...)
```

### WR-03: The compound startup failure still never reaches the /advanced operator surface

**File:** `dashboard/beacon/worker_main.py:505-512`, `dashboard/beacon/diagnosis.py:40`

**Issue:** The plan's objective is that "a compound startup failure reaches the operator
loudly". The re-raise delivers that on the log/process-exit channel only. I ran the
compound path and read the durable table afterwards:

```
JOB HEALTH: [{'job_id': 'S1', 'state': 'running', 'last_started_ts': ..., 'error_class': None}]
```

`state` is `'running'`, not `'failed'` — so `compose_active_exceptions` emits no
`job_failed` for S1. The only route to the operator surface is the new
`job_outcome_unrecorded`, which cannot fire for at least `UNRECORDED_OUTCOME_FLOOR_SECONDS`
= 900 s. Meanwhile the worker container runs under `restart: unless-stopped`
(`docker-compose.yml:4`), so each restart re-dispatches S1 and rewrites `started`,
refreshing `last_started_ts`. While the restart interval stays under 900 s the promotion
never fires at all, and the operator sees no exception naming S1 — only the generic
`worker_freshness` exception that any dead worker produces. Compare the non-compound
case, where the `failed` write succeeds and the operator gets a `job_failed` card naming
the job.

This is an improvement over the pre-change behaviour (previously the worker continued and
nothing at all surfaced), but the round's own completeness claim — that the genuine
startup failure now reaches the operator — is met only on the journal, not on the
workspace the phase is about. It should be recorded as still open rather than closed.

**Fix:** Before re-raising, make one bounded best-effort attempt to leave durable evidence
the operator surface can read, and let that attempt's own failure be non-fatal:

```python
if bookkeeping_error.work_error_class is not None:
    try:
        _write_job_health_transition(
            services, startup_callback_id, 'failed',
            error_class=bookkeeping_error.work_error_class,
        )
    except Exception:
        # The operator surface stays silent; the raised condition and the ERROR
        # log remain the evidence channel.
        pass
    raise
```
Alternatively, record this explicitly as a remaining gap so round-5 verification does not
credit the operator-surface half of the truth.

### WR-04: The operator copy directs the reader to a "configured cadence" that does not exist for the jobs this change newly made promotable

**File:** `dashboard/advanced.js:184` (with `dashboard/beacon/diagnosis.py:464-468` and `dashboard/advanced.js:433`)

**Issue:** Task 2 did two things at once: it removed the cadence-type guards so
cadence-less jobs (S1, S2, S3, J9) can now be promoted as `job_outcome_unrecorded`, and it
rewrote that kind's `evidence` sentence — but left the sentence's trailing clause "See
Pipeline for its last start, last success, and **configured cadence**." For exactly the
newly-promotable jobs there is no configured cadence: `callback_schedule_evidence`
(`diagnosis.py:216`) yields `cadence_seconds: None` for every non-interval trigger, and the
Pipeline renderer at `advanced.js:433` shows `Not scheduled` for S1/S2/S3
(`not_scheduled` is true when `scheduler_id is None`) and `expected every —` for J9
(`trigger='date'`, `scheduler_id='startup_discovery'`, so `not_scheduled` is false and
`displayValue(null)` renders the placeholder). The operator is sent to a field that reads
as a placeholder, which is what prohibition 03-09 (integrity) exists to prevent.

**Fix:** Drop the cadence pointer from the sentence, since the boundary no longer derives
from cadence anyway:

```js
evidence: `The background job ${displayValue(item.job_id)} recorded a start and no outcome has been recorded since, for longer than any run of this job should take. See Pipeline for its last start and last success.`,
```

### WR-05: Both pollers still report `succeeded` for a genuinely failed scan or preview (adjacent, pre-existing)

**File:** `dashboard/app.py:1847`, `dashboard/app.py:2004`

**Issue:** Flagging this because it directly bounds the round's central truth and lives in
the two functions this diff edits. `worker_process_scan_requests` computes
`status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'`
(app.py:1825), calls `fail_scan_for_worker` on that path (app.py:1841-1844), and then
returns `True` unconditionally at line 1847. `worker_process_preview_requests` does the
same: `status='failed' if warning else 'completed'` (app.py:1985) then `return True` at
line 2004. `dispatch_callback` maps anything that is not literal `False` to
`succeeded`, so a manual scan that failed and a preview that failed both record
`state='succeeded'`, `error_class=None` on their J5/J6 job-health rows.

So after this round, `False` still means "refused", `None` means "no work", exceptions mean
"failed" — but a *recorded* work failure means "succeeded". The truth "background-job health
reported to the operator reflects what the job actually did" remains false for J5/J6 in the
failure direction, and no test in this round covers it. `git blame` dates both lines to
`82e3eaa2` (2026-08-06), so this is pre-existing, not a regression from this diff.

**Fix:** Return the outcome instead of a constant, and let the existing mapping do its job:

```python
    return status == 'completed'   # worker_process_scan_requests
    return not warning             # worker_process_preview_requests
```
If that is out of scope for this round, record it in `deferred-items.md` alongside row 8 so
the next verifier does not credit the truth as whole.

## Info

### IN-01: The new comment overstates what the guarded return actually covers

**File:** `dashboard/app.py:1803-1810`, `dashboard/app.py:1966-1968`

**Issue:** The comment asserts "An empty durable queue is a completed poll", but
`claim_scan` (`queues.py:415-450`) returns `None` on three distinct conditions: no queued
row (line 428), a lost conditional-UPDATE race with a concurrent claimer (line 439), and
after its own expiry sweep has retired the only queued row. `claim_preview`
(`queues.py:631-666`) is the same, and additionally marks past-deadline rows `expired`
before selecting. The `succeeded` outcome is defensible for all three, but the comment
describes only the first and will mislead the next reader triaging a claim race.

**Fix:** Say "no claim was available" rather than "the queue is empty".

### IN-02: Production source comment points at a planning artifact that is not shipped

**File:** `dashboard/app.py:1808-1809`

**Issue:** `-- see deferred-items.md` refers to
`.planning/phases/03-advanced-current-diagnosis/deferred-items.md`. The Dockerfile copies
only `app.py`, `worker.py`, `runtime_smoke.py`, the static assets and `beacon/`, so a
maintainer reading the source inside the container has no way to resolve the reference.

**Fix:** State the reason inline ("the busy-retry `return False` below is a transient,
self-clearing condition and is deliberately unchanged") instead of deferring to a path.

### IN-03: The new monkeypatch registers its `addCleanup` after the assignment, contrary to the plan's own prohibition

**File:** `tests/test_advanced_diagnosis_api.py:706-709`

**Issue:** Prohibition 03-10 as restated in `03-17-PLAN.md` requires that "every new
monkeypatch this plan's tests install ... is paired with an `addCleanup` registered
**before** the assignment". The code assigns `worker_main._write_job_health_transition =
recording_write` at line 706 and only then registers the restore at 707-709. The practical
risk is nil (no statement between them can raise) and it matches the module's existing
style at line 617, but `03-17-SUMMARY.md`'s "Total deviations: 0 / plan executed exactly as
written" is inaccurate on this point.

**Fix:** Either move the `addCleanup` above the assignment in both places, or amend the
summary's deviation count.

### IN-04: Two assertions in the compound-failure test are vacuous, and the cleanup it depends on is untested

**File:** `tests/test_advanced_diagnosis_api.py:726`

**Issue:** `self.assertFalse(worker_main._worker_started)` cannot fail: `_reset_worker_globals`
runs as cleanup, `_worker_started` is only set at `worker_main.py:527` (after
`build_scheduler`), and the preceding line already asserts `build_scheduler` was never
called. Separately, the test asserts nothing about the `finally:
_finalize_worker_lifecycle(services)` path the re-raise depends on — I confirmed manually
that the lease is released and `shutdown_browser` is called, but a regression that made the
re-raise escape before `lease_acquired = True` (leaving a held lease that blocks every
restart with `LeaseHeld`) would pass this test.

**Fix:** Replace the vacuous line with a strand check that would actually fail:

```python
self.assertIn('shutdown_browser', calls)   # _finalize_worker_lifecycle ran
with sqlite3.connect(self.db_path) as conn:
    owner = conn.execute(
        "SELECT 1 FROM runtime_state WHERE key='worker_owner'"
    ).fetchone()
self.assertIsNone(owner, 'the lease must not survive a compound startup failure')
```

### IN-05: The newly declared return-value vocabulary is not uniform across the inventory

**File:** `dashboard/beacon/worker_main.py:188-202`

**Issue:** `03-17-SUMMARY.md` records the pattern "None means 'no work was available',
False means 'the work refused', an exception means 'the work failed'". Two existing
handlers contradict it: `_run_scheduled_discovery` (J7) and `_run_startup_discovery` (J9)
return `None` implicitly on *both* their skip path (lines 191-192 / 198-199) and their
work path — including when `services.run_discovery(...)` returned the string `'failed'`,
whose value is discarded. So `None` already carries at least three meanings on the
dispatch boundary. Nothing is broken by this diff, but the pattern should not be recorded
as established until the discovery handlers follow it.

**Fix:** Have both handlers return the discovery outcome (`return outcome != 'failed'`) on
the work path and `None` only on the genuine skip path, or narrow the recorded pattern to
the two queue pollers it actually holds for.

---

_Reviewed: 2026-08-19_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Scope: `git diff e12cada..HEAD` over 5 source files_
