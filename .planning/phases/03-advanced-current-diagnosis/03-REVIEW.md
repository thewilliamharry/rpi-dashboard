---
phase: 03-advanced-current-diagnosis
reviewed: 2026-08-19T09:51:17Z
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
  warning: 6
  info: 6
  total: 15
status: issues_found
---

# Phase 3: Code Review Report — round 4

**Reviewed:** 2026-08-19T09:51:17Z
**Depth:** standard
**Files Reviewed:** 12 (SUMMARY-derived scope; no reliable diff base — see scope note)
**Status:** issues_found

## Summary

This report **replaces** the round-3 `03-REVIEW.md`. It is scoped to the twelve source files the phase
touched and reviews the tree as it now stands, after plans 03-15 and 03-16 landed.

`.planning/phases/03-advanced-current-diagnosis/deferred-items.md` was read first. Nothing recorded
there as a deliberate exclusion is re-argued below. Two findings sit adjacent to deferred rows and say
so explicitly (`CR-03` next to row 2, `WR-01` next to row 2).

**What round 3's fixes actually closed** — verified by reading the current code, not the summaries:

- Round-3 `CR-01` (a genuine work failure erased when its outcome write also fails) is **closed**.
  `worker_main.py:335-361` now carries `work_error_class` on the raised condition, chains
  `from work_error`, and logs the work failure at error level before raising. The three channels are
  asserted on the object graph, not on strings, by `test_a_failed_callback_survives_a_failing_outcome_write`.
- Round-3 `WR-01` (`absent` and `complete` collapsed into one string) is **closed**.
  `advanced.js:264-271` gives an unestablished stream its own sentence, and
  `test_service_detail_gap_evidence_reads_as_operator_copy` pins the two as unequal by port.
- Round-3 `WR-02` (`JobHealthBookkeepingError` unhandled, killing the worker at startup) is **partly
  closed** — a handler now exists at `worker_main.py:499-514`. What it decides is wrong; see `CR-03`.
- Round-3 `WR-05` (lease-loss log line asserting a failure that may have been a success) is **closed**
  (`worker_main.py:329-334`).
- Round-3 `WR-06` (`finiteMeasurement` turning `' '`, `[]`, `false` into a measurement of `0`) is
  **closed** — `advanced.js:78-83` is now a type rule, pinned by
  `test_non_numeric_server_values_never_become_a_measurement`.
- Round-3 `WR-07` (unguarded element in the open-count derivation) is **closed** (`diagnosis.py:386-388`).
- Round-3 `IN-01`, `IN-03`, `IN-05`, `IN-07` are **closed** (justifying comment on the wire vocabulary,
  a real cross-language contract test at `test_advanced_ui.py:1390`, a corrected docstring, and
  `_reset_worker_globals` owning the scheduler global).

**What I verified is sound**, because it was the highest-risk claim in the new code:

- No XSS anywhere in `advanced.js`. Every insertion is `textContent`; the only `href` is a literal
  `#`-prefixed fragment whose click handler `preventDefault()`s and revalidates through
  `selectSection`, which fails closed on an unknown section.
- `JobHealthBookkeepingError`'s own message still leaks nothing — bounded class names, a fixed callback
  id and a literal transition. Chaining is deliberate and now correctly documented as a separate channel.
- `_safe_job_error_class` (`repositories.py:18-22`) strips to `[A-Za-z0-9_.]` and truncates at 96, so a
  message can never reach `background_job_health.error_class`.
- `job_outcome_unrecorded` is built from explicit keys, so `CF-WR-10`'s row-spread hazard is neither
  fixed nor widened.
- The service/stream join key cannot mismatch on type: both sides are `str(...)`
  (`diagnosis.py:225, 380`).
- `absent` is a truthful claim: nothing in the codebase deletes a `('service', port)` row from
  `telemetry_streams`, so a missing stream in a complete stream list really is a service the pipeline
  has never recorded.

**The three blockers below are all new, all reachable on a healthy idle Pi, and all land on the one
surface this phase exists to make truthful.** Two are reproduced against the shipped code, not inferred:

- `CR-01` — the Overview "Active exceptions" region shows two permanent, fabricated
  `Background job failed` cards within two seconds of worker start, because the two queue-polling
  callbacks return `False` as their *normal idle* result and `dispatch_callback` records `False` as a
  durable failure.
- `CR-02` — the brand-new `job_outcome_unrecorded` promotion fires on legitimately in-progress work: its
  threshold is 8 seconds for J5/J6 and 20 seconds for J1, the latter shorter than the 30-second
  maintenance-lock wait `connect_db` is allowed to block for.
- `CR-03` — the new startup handler swallows a *compound* failure (startup work failed **and** its
  outcome write failed), discards the `work_error_class` that 03-15 added specifically to carry it, and
  the startup callbacks it swallows can never be promoted by `job_outcome_unrecorded` because their
  `cadence_seconds` is `None`.

## Structural Findings (fallow)

No `<structural_findings>` block was supplied with this review. All findings below are narrative.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: An idle Pi permanently reports two background jobs as failed

**Severity:** BLOCKER

**Files:** `dashboard/beacon/worker_main.py:324-327`; `dashboard/app.py:1803-1804, 1959-1960`;
`dashboard/beacon/repositories.py:51-63`; `dashboard/beacon/diagnosis.py:419-420`;
`dashboard/advanced.js:178-181`

**Issue:** `dispatch_callback` treats a `False` return as a work failure:

```python
if result is False:
    transition, error_class = 'failed', 'CallbackReturnedFalse'
```

Two production callbacks return `False` as their **normal, expected, idle** result — it means "the
durable queue was empty", not "something went wrong":

```python
# app.py:1803-1804  worker_process_scan_requests  (J5, every 2 seconds)
if not claim:
    return False

# app.py:1959-1960  worker_process_preview_requests  (J6, every 2 seconds)
if not claim:
    return False
```

Every J5 and J6 tick on an idle system therefore writes `state='failed'`,
`error_class='CallbackReturnedFalse'`, `last_success_ts=NULL` to `background_job_health`, which
`compose_active_exceptions` promotes unconditionally:

```python
for job in pipeline['jobs']:
    if job['state'] == 'failed':
        exceptions.append({'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, ...})
```

and `advanced.js` renders as `Background job failed — J5` / `— J6`. Because J5/J6 never return
anything other than `False` while idle, the two cards **never clear**, `last_success_ts` stays `NULL`
forever, and the Overview count is permanently inflated by two. `_legacy_do_uptime_check` adds a third
reachable case: it returns `False` when `_uptime_lock` is already held, and J3 (5 min) and J4 (1 min)
share `ThreadPoolExecutor(2)`, so they can overlap.

This is the phase's own standing prohibition — an operator-facing claim of failure that the evidence
does not support — on the highest-priority surface the phase built.

**Reproduced** against the shipped code (apscheduler stubbed only to satisfy the import):

```
DURABLE ROWS: {'J5': ('failed', 'CallbackReturnedFalse', None),
               'J6': ('failed', 'CallbackReturnedFalse', None)}
OPERATOR EXCEPTIONS: [{'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, 'job_id': 'J5'},
                      {'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, 'job_id': 'J6'}]
```

Note the existing test `test_callback_outcome_false_and_exception_never_claim_success` *pins* the
`False → failed` mapping, which is why this survived: the mapping was verified in isolation against a
synthetic callback, never against what the two real queue pollers actually return.

**Fix:** `False` from a queue poller is "no work was available", which is a successful poll. Give the
"nothing to do" outcome its own vocabulary rather than overloading `False`, and stop inferring a verdict
from a return value that already means something else:

```python
# worker_main.py — a callback reports its own outcome; absence of work is not failure
NO_WORK_AVAILABLE = False   # what claim-based pollers return when the queue is empty

...
else:
    if result is False and callback.handler in ('scan', 'preview'):
        # An empty durable queue is a completed poll, not a failed job.
        transition, error_class = 'succeeded', None
    elif result is False:
        transition, error_class = 'failed', 'CallbackReturnedFalse'
    else:
        transition, error_class = 'succeeded', None
```

Cleaner still, and preferable if the churn is acceptable: have `worker_process_scan_requests` and
`worker_process_preview_requests` return `None` (or a `PollResult` sentinel) on an empty queue and
reserve `False` for a genuine refusal, then delete the special case. Either way add a regression that
drives the **real** adapters with an empty queue and asserts `compose_active_exceptions` emits no
`job_failed`.

### CR-02: The new `job_outcome_unrecorded` promotion fires on work that is simply still running

**Severity:** BLOCKER

**Files:** `dashboard/beacon/diagnosis.py:425-443`; `dashboard/beacon/worker_main.py:83-85`;
`dashboard/beacon/db.py:76`; `dashboard/advanced.js:182-186`

**Issue:** The promotion added by 03-15 uses `freshness_state`'s four-times-cadence boundary as a
stand-in for "this job should have finished by now":

```python
and max(0, now - job['last_started_ts']) > 4 * job['cadence_seconds']
```

That premise only holds when a callback's cadence is a proxy for its duration. For the queue pollers it
is the opposite — they are polled *fast precisely because each run is short-lived when idle*, and a run
that finds work is unboundedly longer than the poll interval. Resolved thresholds, printed from the
shipped inventory:

| callback | trigger | cadence | promotion threshold |
|---|---|---|---|
| J1 heartbeat | interval | 5 s | **20 s** |
| J5 scan requests | interval | 2 s | **8 s** |
| J6 preview requests | interval | 2 s | **8 s** |
| J2 metrics | interval | 60 s | 240 s |
| J4 uptime (down) | interval | 60 s | 240 s |
| J3 uptime (all) | interval | 300 s | 1200 s |
| J8 cleanup | interval | 3600 s | 4 h |
| S1 / S2 / S3 / J9 | none / date | `None` | **never promoted** |

The `started` transition commits before the work runs (`_write_job_health_transition` opens and closes
its own `write_transaction`), so the durable row genuinely reads `running` for the whole duration. Three
reachable false positives:

1. **J6** drives Chromium through `_refresh_service_preview` to screenshot a service. Exceeding 8 s on
   Raspberry Pi hardware is routine, not exceptional.
2. **J5** runs a claimed manual discovery scan end to end. Discovery is a multi-second-to-minutes
   operation; it will exceed 8 s essentially every time it finds work.
3. **J1** is a 20 s threshold, but `connect_db` holds a shared `flock` wait of **30 s** and a
   `busy_timeout` of 30 s (`db.py:76-81`). Any maintenance or backup window longer than 20 s therefore
   promotes the heartbeat as "outcome not recorded" while it is simply waiting for the lock.

**Reproduced:** a J6 row with `state='running'`, `cadence_seconds=2`, `last_started_ts=now-9` yields
`[{'kind': 'job_outcome_unrecorded', 'section': 'pipeline', 'priority': 6, 'job_id': 'J6'}]`.

The existing test asserts only `running_inside_its_cadence_window_promotes_nothing` with
`cadence=60`; no case uses a cadence smaller than the work it gates, which is why this survived.

**Fix:** stop deriving an expected *duration* from a poll *interval*. Use a floor that no legitimate run
can plausibly exceed, and clamp against the lock waits the callback itself may block on:

```python
# diagnosis.py — the boundary is "no outcome for far longer than any run could take",
# never "longer than the poll interval". 30 s is connect_db's own flock/busy wait, so a
# job merely queued behind maintenance can never be promoted.
UNRECORDED_OUTCOME_FLOOR_SECONDS = 900

...
and max(0, now - job['last_started_ts'])
    > max(UNRECORDED_OUTCOME_FLOOR_SECONDS, 4 * job['cadence_seconds'])
```

Add subtests for `cadence_seconds=2` with a nine-second-old start (must promote nothing) and for a
heartbeat blocked 25 s behind the maintenance lock (must promote nothing).

Separately, the copy overstates the rule it applied — see `WR-06`.

### CR-03: Worker startup swallows a genuine startup work failure and continues

**Severity:** BLOCKER

**Files:** `dashboard/beacon/worker_main.py:499-514, 335-361`; `dashboard/beacon/diagnosis.py:425-443`

**Issue:** The new startup handler is documented as narrow — "a failure to record that a startup job
began is a fact about the recording, never a verdict on whether Beacon should run":

```python
except JobHealthBookkeepingError as bookkeeping_error:
    log.warning(
        'Beacon worker could not record a startup job; continuing '
        'startup: callback=%s error_class=%s',
        startup_callback_id, bookkeeping_error.error_class,
    )
```

But `JobHealthBookkeepingError` is raised from **two** places, and the second one is not about the
recording alone. When an S1/S2/S3 callback's *work* fails and the outcome write then also fails, the
condition carries `work_error_class` and chains `from work_error` — and this handler catches it,
logs only `bookkeeping_error.error_class` (the **write** error's class, never the work's), and proceeds
as though the startup job had succeeded. Concretely: `recover_worker_state` failing to reclaim stale
scan/preview requests and log the monitoring gap is downgraded to a warning that does not even name it.

`work_error_class` was added by this very round specifically so the work failure would remain
recoverable at the catch site, and the one handler that catches the condition ignores it.

The failure then has no durable channel either. The row is left at `running` (or absent, if the
`started` write was the one that failed), and `job_outcome_unrecorded` **cannot** promote a startup
callback: `callback_schedule_evidence` returns `cadence_seconds=None` for every non-`interval` trigger,
so `type(job.get('cadence_seconds')) is int` is `False` for S1, S2, S3 and J9 — verified against the
shipped inventory. `test_a_job_stuck_without_an_outcome_becomes_an_operator_exception` pins this as
`absent_cadence_promotes_nothing` without recording that it makes exactly the swallowed paths invisible.

`test_startup_survives_a_bookkeeping_failure` covers only the `started`-write failure, where the work is
skipped; the compound case is untested.

*(Adjacent to `deferred-items.md` row 2, which defers whether the `started` write should gate the work.
This finding is about what `run_worker` now decides when the condition escapes, and about the promotion
gap, neither of which row 2 covers.)*

**Fix:** distinguish the two conditions at the catch site, and give startup callbacks a promotable
cadence so a wedged startup job is visible:

```python
# worker_main.py
except JobHealthBookkeepingError as bookkeeping_error:
    if bookkeeping_error.work_error_class is not None:
        # Not a bookkeeping-only condition: the startup work itself failed. Its
        # outcome could not be recorded, so continuing would run Beacon on state
        # nothing has confirmed. Fail loudly, as an unrecorded work failure must.
        raise
    log.warning(
        'Beacon worker could not record a startup job; continuing startup: '
        'callback=%s error_class=%s',
        startup_callback_id, bookkeeping_error.error_class,
    )
```

```python
# diagnosis.py — a startup callback has no interval, so give the promotion an
# explicit floor rather than letting a None cadence silently exempt it.
cadence = job.get('cadence_seconds')
boundary = 4 * cadence if type(cadence) is int and cadence > 0 else UNRECORDED_OUTCOME_FLOOR_SECONDS
```

Add a compound regression: drive an S1 whose work raises **and** whose `failed` write raises, and assert
`run_worker` does not build the scheduler.

## Warnings

### WR-01: A job that never starts still reads as succeeded, and promotes nothing

**Severity:** WARNING

**Files:** `dashboard/beacon/worker_main.py:296-302`; `dashboard/beacon/repositories.py:25-35`;
`dashboard/beacon/diagnosis.py:418-443`

**Issue:** Round 3's `WR-03` listed four paths that leave a job without an outcome. The new
`job_outcome_unrecorded` promotion covers three of them, because all three leave the row at `running`.
It does not cover the fourth. When the `started` write fails, `record_background_job_started` never
executes, so the row keeps its **previous** state — normally `succeeded` from the last good run:

```python
except Exception as exc:
    # The work never ran, so there is no work outcome to record.
    raise JobHealthBookkeepingError(callback_id, 'started', _job_error_class(exc)) from exc
```

`compose_active_exceptions` promotes only `failed` and `running`, so a job that is failing to start on
every tick — and therefore never running at all — reads `succeeded` on the Pipeline surface indefinitely
while `last_success_ts` silently ages. For scheduled callbacks APScheduler logs the raised condition and
continues, so nothing else surfaces it either.

*(`deferred-items.md` row 2 defers whether the `started` write should gate the work. This is the
separate question of whether the resulting wedge is visible, which the round-3 finding claimed the
promotion closed.)*

**Fix:** promote on the row's own aging success rather than only on its state, using the same durable
fields:

```python
elif (
    type(job.get('last_success_ts')) is int
    and type(job.get('cadence_seconds')) is int
    and job['cadence_seconds'] > 0
    and max(0, now - job['last_success_ts'])
        > max(UNRECORDED_OUTCOME_FLOOR_SECONDS, 4 * job['cadence_seconds'])
):
    exceptions.append({'kind': 'job_outcome_unrecorded', 'section': 'pipeline',
                       'priority': 6, 'job_id': job['job_id']})
```

### WR-02: One noisy stream can starve every other service's gap evidence

**Severity:** WARNING

**Files:** `dashboard/beacon/repositories.py:142-148`; `dashboard/beacon/diagnosis.py:339-357, 372-393`

**Issue:** The per-service gap block is derived from a **global**, unscoped read of the coverage table:

```sql
SELECT stream_kind, stream_key, start_ts, end_ts, reason, detail FROM telemetry_coverage
ORDER BY end_ts DESC, start_ts DESC LIMIT ?          -- 49, for the whole table
```

Nothing partitions that budget by stream. A single chatty stream with 49 recent coverage rows consumes
the entire read, so:

- every other service resolves to `possibly_incomplete` (`gap_evidence_truncated` is `True`) and reads
  `0 gaps (0 open); more gap evidence may exist`, and
- a service whose gaps *were* partly read reports a `count` that is an artifact of the global budget,
  not its own gap population, presented beside a specific number.

The truncation is disclosed, so this is not an untruth — but the number the operator reads next to the
disclosure is the wrong quantity, and one stream's noise silently degrades every other service's
evidence to unusable.

**Fix:** scope the read so each stream gets its own budget, or query per service on the join:

```sql
SELECT stream_kind, stream_key, start_ts, end_ts, reason, detail FROM telemetry_coverage
WHERE stream_kind = 'service'
ORDER BY stream_key ASC, end_ts DESC, start_ts DESC
```

and cap per `stream_key` in Python, setting a per-service `truncated` flag instead of reusing the global
one. `_service_gap_evidence_state` should then read that per-service flag.

### WR-03: The Flask process imports the worker composition root to read one tuple

**Severity:** WARNING

**Files:** `dashboard/beacon/diagnosis.py:12`; `dashboard/beacon/worker_main.py:12-13, 22-23, 411-415`;
`dashboard/app.py:25`

**Issue:** `diagnosis.py` — a module whose docstring is "Read-only current-diagnosis composition" —
imports from the worker's executable composition root:

```python
from .worker_main import WORKER_CALLBACK_INVENTORY
```

`app.py` imports `diagnosis`, so the **web** process now transitively imports APScheduler
(`BlockingScheduler`, `ThreadPoolExecutor`), executes `logging.getLogger('apscheduler').setLevel(...)`
as an import-time global side effect, and carries `worker_main`'s mutable process globals
(`scheduler`, `_worker_started`, `_active_services`, `_active_worker_id`) plus `stop_worker`,
`build_scheduler` and `run_worker` in its address space — all to read an immutable tuple of dataclasses.
An APScheduler import problem now takes down the read-only API, and the worker's signal-handling entry
point is reachable from a request handler's module graph. AGENTS.md's stated constraint is "explicit
module boundaries and testable interfaces".

**Fix:** move the inventory and its dataclasses into a dependency-free module both sides import:

```python
# dashboard/beacon/worker_inventory.py — no apscheduler, no globals, no side effects
@dataclass(frozen=True)
class WorkerCallback: ...
WORKER_CALLBACK_INVENTORY = (...)
```

```python
# worker_main.py
from .worker_inventory import WORKER_CALLBACK_INVENTORY, WorkerCallback   # re-export for compatibility
# diagnosis.py
from .worker_inventory import WORKER_CALLBACK_INVENTORY
```

Then add a source-level assertion that `dashboard/beacon/diagnosis.py` does not import `worker_main`.

### WR-04: Migration 8 is the only migration that tolerates a pre-existing object

**Severity:** WARNING

**File:** `dashboard/beacon/migrations.py:479-504`

**Issue:** Every other migration creates new objects with plain `CREATE TABLE` / `CREATE INDEX`
(`migrations.py:254, 265, 282`). Migration 8 alone uses `IF NOT EXISTS` for its table and both indexes.
Migrations already run exactly once, ordered and recorded in `schema_migrations`, so the guard buys
nothing — while costing the one protection the plain form provides. If a `background_job_health` table
already exists with a different shape (a rolled-back newer version, a hand-repaired database, a restored
backup from a divergent branch), migration 8 records version 8 as applied against a schema it never
verified, and the first `INSERT` fails at runtime inside a worker transaction instead of at migration
time where the backup/rollback machinery can act.

**Fix:**

```python
conn.execute(
    "CREATE TABLE background_job_health ("
    ...
)
conn.execute(
    'CREATE INDEX idx_background_job_health_state_updated '
    'ON background_job_health(state, updated_ts DESC)'
)
```

(See also `IN-02`: neither index is used by any query and both should probably just be dropped.)

### WR-05: The dashboard's TLS badge now reads as reassurance

**Severity:** WARNING

**File:** `dashboard/app.js:229-233`

**Issue:** The badge shown when a service's TLS certificate is **not** verified reads, visibly, `TLS`:

```javascript
const tls = Object.assign(document.createElement('span'), {className: 'svc-tls-unverified', textContent: 'TLS'});
tls.title = 'TLS certificate is not verified for this trusted local service.';
tls.setAttribute('aria-label', 'TLS certificate is not verified for this trusted local service.');
```

A bare `TLS` chip is read by essentially every operator as "this service uses TLS" — a positive
property. The actual meaning is the inverse. The truth exists only in `title` and `aria-label`, so a
screen-reader user is told the truth and a sighted user is told the opposite; the warning colour
(`--accent2`) is the only visual hint and colour alone is not a label. On a page whose whole purpose is
that the operator can trust what they read, this is a semantic inversion, and
`tests/test_ui_states.py:143` now pins the shortened text in place.

*(Not introduced by phase 03 — `git log -S` attributes it to `003d3af feat(quick-260814-kfc): compact
service-card labels`. Reported because `dashboard/app.js` is in the reviewed scope and the defect is in
the same truthfulness class the phase is enforcing.)*

**Fix:** keep the label short without inverting it, and update the two source-contract assertions:

```javascript
const tls = Object.assign(document.createElement('span'),
  {className: 'svc-tls-unverified', textContent: 'TLS unverified'});
```

If horizontal space is the constraint, `TLS ⚠` or `unverified TLS` both preserve the polarity;
`.svc-tls-unverified` already sets `overflow-wrap: anywhere` and `max-width: 100%` at narrow widths.

### WR-06: The `job_outcome_unrecorded` copy misstates the rule the code applied

**Severity:** WARNING

**File:** `dashboard/advanced.js:182-186`; `dashboard/beacon/diagnosis.py:437`

**Issue:** The operator copy says:

> ...no outcome has been recorded since, for longer than **its own configured cadence** allows. See
> Pipeline for its last start, last success, and configured cadence.

and then directs the operator to the Pipeline region, which prints `expected every N seconds` — the
1× cadence. The code's boundary is `4 * job['cadence_seconds']`. An operator who follows the card's own
instruction computes a threshold four times smaller than the one that fired, and will conclude either
that the card is wrong or that the job is four times more overdue than it is. This phase's standard is
that copy states exactly what was observed.

**Fix:** state the multiple, so the sentence and the cited evidence agree:

```javascript
evidence: `The background job ${displayValue(item.job_id)} recorded a start and no outcome has been recorded since, for more than four times its own configured cadence. See Pipeline for its last start, last success, and configured cadence.`,
```

If `CR-02`'s absolute floor is adopted, word it as "for longer than any run of this job should take
(at least fifteen minutes, and always more than four times its configured cadence)".

## Info

### IN-01: Unused import

**File:** `dashboard/beacon/diagnosis.py:3`

`import json` is never used — no `json.` reference exists in the module. Remove it.

### IN-02: Both `background_job_health` indexes are dead

**File:** `dashboard/beacon/migrations.py:497-504`

The only read of the table is `read_background_job_health`, which is
`... FROM background_job_health ORDER BY job_id ASC LIMIT ?` — served by the primary key. The three
writers all resolve by `job_id` through the same primary key. Neither
`idx_background_job_health_state_updated` nor `idx_background_job_health_updated` can be used by any
query in the tree, so both are pure write amplification on a table written every two seconds by J5/J6.
Drop them, or add the query that justifies them.

### IN-03: Columns are read and then discarded

**File:** `dashboard/beacon/repositories.py:87-88`

`read_current_services` selects `s.last_latency_ms` and `s.first_seen`. Neither is projected by
`compose_service_diagnosis` nor read by `advanced.js`. (`s.last_seen` is used, but only in the `WHERE`
clause, so it need not be in the select list either.) Drop them from the projection so the read states
what it actually uses.

### IN-04: `state.expandedPorts` is never pruned

**File:** `dashboard/advanced.js:8, 620-627, 659`

Ports are added on expand and removed only on explicit collapse. When a service disappears from a later
poll — expired, removed, filtered out at source — its port stays in the set forever. The visible
consequence is that `$('collapse-service-details').hidden = state.expandedPorts.size === 0` keeps the
"Collapse all details" button showing when nothing is expanded, and clicking it announces "All service
details collapsed" with no visible change. Intersect the set with the ports present in the current
snapshot inside `renderServices`.

### IN-05: A sort or filter click before the first poll reports "no matching services"

**File:** `dashboard/advanced.js:637-644, 800-825`

The sort and filter handlers are wired at bootstrap, before `refreshCurrentDiagnosis()` resolves.
Clicking a column header at that moment calls `renderServices()` with `state.snapshot === null`, and
because `partial.hidden = Array.isArray(source)` and `empty.hidden = services.length !== 0`, the page
replaces its loading skeleton with both "Some current-state evidence is unavailable" and "No services
match these filters" — telling the operator that evidence is missing and that filters excluded
everything, when the page has simply not loaded yet. Guard the render (`if (!state.snapshot) return;`)
or leave the skeleton in place until the first snapshot arrives.

### IN-06: Database corruption is classified as an unmodelled defect

**File:** `dashboard/app.py:2130-2137`

`api_advanced_current` catches `MaintenanceBusy` and `sqlite3.OperationalError`. SQLite raises
`sqlite3.DatabaseError` — the parent class, not caught here — for `database disk image is malformed`,
which is the one condition Beacon maintains a `RECOVERY_MARKER` and a documented recovery command for.
It therefore reaches the operator as an HTML 500 whose only copy is
`Beacon could not refresh current diagnosis... Server reported: HTTP 500`. That is deliberate per
`test_unexpected_failure_stays_loud_instead_of_becoming_a_service_unavailable`, and the client degrades
gracefully, so this is recorded rather than argued: a corrupted database is a *modelled* condition
everywhere else in this codebase and arguably deserves its own named 503 alongside the maintenance case.

---

## Carried forward (still open, not re-argued)

The seventeen round-1 findings recorded as `CF-*` in `deferred-items.md` row 7 were spot-checked and
remain present. They are not restated here; the row-7 entry and the round-3 review in git history hold
the full argument for each. The five round-3 exclusions in `deferred-items.md` rows 2-6
(`WR-04`, `IN-02`, `IN-04`, `IN-06`, `IN-08`) were verified as still-accurate descriptions of the
current code and are **not** re-reported.

Two of them are now load-bearing for findings above and are noted for the fixer's benefit:

- row 2 (the `started` write gates the work) is the precondition for `WR-01`'s wedge.
- row 6 (`POSITIVE_INFINITY` latency ranking) is unaffected by anything in this round.

---

_Reviewed: 2026-08-19T09:51:17Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
