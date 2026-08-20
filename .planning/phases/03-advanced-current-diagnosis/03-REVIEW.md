---
phase: 03-advanced-current-diagnosis
reviewed: 2026-08-20T00:00:00Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - dashboard/advanced.css
  - dashboard/advanced.html
  - dashboard/advanced.js
  - dashboard/app.js
  - dashboard/app.py
  - dashboard/beacon/diagnosis.py
  - dashboard/beacon/migrations.py
  - dashboard/beacon/previews.py
  - dashboard/beacon/repositories.py
  - dashboard/beacon/worker_main.py
  - dashboard/index.html
  - tests/test_advanced_diagnosis_api.py
  - tests/test_advanced_ui.py
findings:
  critical: 0
  warning: 4
  info: 6
  total: 10
status: issues_found
---

# Phase 3: Code Review Report — round 5

**Reviewed:** 2026-08-20T00:00:00Z
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues_found

## Summary

This report **replaces** round 4's `03-REVIEW.md`. It is scoped to the thirteen files the workflow
listed, which is the phase's whole `/advanced` surface plus the `dashboard/app.py` / `app.js` /
`index.html` files it touches, re-read against the tree as it now stands after plans 03-17 through
03-23 (the last of which is the interactive-affordance gap closure for `advanced.css` and
`test_advanced_ui.py` the task note called out).

**Verified closed since round 4** (read directly against the current code, not inferred from
commit messages):

- Round-4 `CR-01` (J5/J6 idle-poll `False` fabricating two permanent `job_failed` cards) is
  **closed**. `worker_process_scan_requests` and `worker_process_preview_requests`
  (`app.py:1838-1846, 2031-2033`) both return `None` on an empty claim, and `dispatch_callback`'s
  `if result is False:` branch only matches the literal.
- Round-4 `CR-02` (the `job_outcome_unrecorded` floor derived from a poll interval, promoting
  legitimately running J1/J5/J6) is **closed**. `diagnosis.py:58-83`'s
  `_unrecorded_outcome_boundary` now uses a 900-second floor, widened only for
  `DISCOVERY_JOB_IDS = {'J5', 'J7', 'J9'}` — J6 and J1 are excluded from the widening and sit at the
  900s floor.
- Round-4 `CR-03` (a compound startup work-failure-and-write-failure silently continuing) is
  **closed**. `worker_main.py:535-558` now branches on `bookkeeping_error.work_error_class is not
  None` and re-raises rather than logging and continuing.
- Round-4 `WR-06` (operator copy citing "its own configured cadence" for a rule that is actually
  4×cadence-or-floor) is **closed**. `advanced.js:184` now reads "longer than any run of this job
  should take" instead of naming a specific multiple that disagreed with the code.

**Still open, reverified against the current code** (not re-argued at length; see round 4's
`03-REVIEW.md` in git history for the original analysis — cited here only where the current line
numbers or text changed):

- Round-4 `WR-01`, `WR-02`, `WR-03`, `WR-05` — see Warnings below.
- Round-4 `IN-01`, `IN-03`, `IN-04`, `IN-05`, `IN-06` — see Info below.

The round-3 exclusions already recorded in `deferred-items.md` (`WR-04`, `IN-02`, `IN-04` [dup id,
round-3's own], `IN-06` [dup id, round-3's own], `IN-08`) are not re-reported, per that file's own
argument.

**New in this pass:**

- One dead function in `dashboard/app.py` (`_table_columns`) builds SQL with an f-string against a
  caller-supplied table name and is never called from anywhere in the tree — see `IN-07`.

**Verified sound in the 03-23 diff** (the only new source lines since round 4): the interactive
affordance CSS added to `advanced.css:57-66` and the cursor/hover assertions added to
`test_advanced_ui.py` match each other exactly — every selector the test's `pointer_selectors` tuple
checks is covered by the new `cursor: pointer` rule, the negative check (`#service-search` must not
be a pointer) has no matching rule, and the accent-reservation assertion (`#advanced-refresh`'s
`color: var(--accent)` from its own `#advanced-refresh` ID rule) survives the new
`html.light .advanced-header-controls button:hover` class rule's `color: #0f172a` on specificity
(`(1,0,0)` beats `(0,3,2)`), so hovering the refresh button in light mode does not strip its accent
color as the class rule alone would suggest. No defect found in this diff.

## Structural Findings (fallow)

No `<structural_findings>` block was supplied with this review. All findings below are narrative.

## Narrative Findings (AI reviewer)

## Warnings

### WR-01: A job whose start was never durably recorded reads as permanently healthy

**File:** `dashboard/beacon/diagnosis.py:482-508`

**Issue:** `compose_active_exceptions` only promotes a job on two conditions:

```python
for job in pipeline['jobs']:
    if job['state'] == 'failed':
        exceptions.append({'kind': 'job_failed', ...})
    elif (
        job['state'] == RUNNING_JOB_STATE
        and ...
    ):
        exceptions.append({'kind': 'job_outcome_unrecorded', ...})
```

Neither branch reads `last_success_ts`. When `record_background_job_started` fails to write (a
transient lock, a full disk, a maintenance window), `_write_job_health_transition` raises before the
row changes, so `background_job_health.state` keeps its **previous** value — normally `succeeded`
from the last good run. `worker_main.py:335-346` already carries this exact condition as
`JobHealthBookkeepingError` for every non-startup callback and simply raises it without recording
anything (the same `started`-write branch that gates `S1`/`S2`/`S3` in `run_worker`). A scheduled
callback stuck in this state forever after — never starting, never running, never failing — reads
`succeeded` on the Pipeline surface and is invisible to the Overview exception list indefinitely
while `last_success_ts` ages unbounded. Confirmed by grep: `last_success_ts` is read once in the
whole module, only to populate the display field at `diagnosis.py:336`, never in the promotion logic.
No regression test in `tests/test_advanced_diagnosis_api.py` drives a `started`-write failure through
to `compose_active_exceptions` and asserts a promotion — the gap is untested as well as unfixed.

**Fix:** promote on the row's own aging success as well as on `running`/`failed`:

```python
elif (
    type(job.get('last_success_ts')) is int
    and type(job.get('cadence_seconds')) is int
    and job['cadence_seconds'] > 0
    and max(0, now - job['last_success_ts'])
        > _unrecorded_outcome_boundary(job.get('cadence_seconds'), discovery_timeout_seconds, job['job_id'])
):
    exceptions.append({'kind': 'job_outcome_unrecorded', 'section': 'pipeline', 'priority': 6, 'job_id': job['job_id']})
```

Add a regression that drives a `started`-write failure (or directly seeds a `background_job_health`
row at `state='succeeded'` with a stale `last_success_ts` and no later start) and asserts
`compose_active_exceptions` emits `job_outcome_unrecorded`.

### WR-02: A single noisy telemetry stream can starve every other service's gap evidence

**File:** `dashboard/beacon/repositories.py:143-149`; `dashboard/beacon/diagnosis.py:396-410`

**Issue:** The per-service gap block the Services detail row renders (`formatServiceGapEvidence` in
`advanced.js`) is derived from one **global, unscoped** read:

```python
gap_rows = [dict(row) for row in conn.execute(
    'SELECT stream_kind, stream_key, start_ts, end_ts, reason, detail FROM telemetry_coverage '
    'ORDER BY end_ts DESC, start_ts DESC LIMIT ?',
    (normalized_gap_limit + 1,),
)]
```

`normalized_gap_limit` (48 by default) bounds the *whole table's* most recent rows, not each
service's own rows. A single chatty stream with 48+ recent coverage rows consumes the entire budget:
every other service's stream then resolves to `possibly_incomplete`
(`gap_evidence_truncated=True`, `diagnosis.py:405-410`) and its detail row reads `0 gaps (0 open);
more gap evidence may exist` — truthfully disclosed as possibly incomplete, but the `0` beside it is
an artifact of the global budget being consumed elsewhere, not a fact about that service's own gap
history. The truncation flag makes this technically not a fabricated claim, but the number an
operator reads next to "no gap evidence may exist" is the wrong quantity, and one stream's noise
silently degrades every other service's evidence surface to unusable on a page whose whole purpose
is truthful per-service diagnosis.

**Fix:** scope the read per stream (`WHERE stream_kind='service'`, ordered by `stream_key`, capped
per key in Python with a per-service truncation flag) rather than one global `LIMIT`, and have
`_service_gap_evidence_state` read the per-service flag instead of the pipeline-wide one.

### WR-03: The read-only Flask process transitively imports the worker's scheduler machinery

**File:** `dashboard/beacon/diagnosis.py:12`; `dashboard/beacon/worker_main.py:12-13, 22-23`

**Issue:** `diagnosis.py` — documented as "Read-only current-diagnosis composition" — still imports
from the worker's executable composition root to read one tuple:

```python
from .worker_main import WORKER_CALLBACK_INVENTORY
```

`app.py` imports `diagnosis` at module load (`app.py:25`), so every request to `/api/advanced/current`
runs in a process whose import graph already pulled in `apscheduler.executors.pool.ThreadPoolExecutor`
and `apscheduler.schedulers.blocking.BlockingScheduler`, executed
`logging.getLogger('apscheduler').setLevel(logging.WARNING)` as an import-time side effect, and now
carries `worker_main`'s mutable process globals (`scheduler`, `_worker_started`, `_active_services`,
`_active_worker_id`) plus `stop_worker` / `build_scheduler` / `run_worker` in the web process's
address space — all to read an immutable tuple of dataclasses that has no dependency on any of that.
An `apscheduler` import failure now takes down the read-only diagnosis API alongside the worker, and
the worker's `SIGTERM`/`SIGINT` signal-handling entry point (`run_worker`) is importable from a
request handler's module graph. No test in the reviewed scope asserts `diagnosis.py`'s import graph
excludes `apscheduler` or `worker_main`.

**Fix:** move `WorkerCallback` and `WORKER_CALLBACK_INVENTORY` into a dependency-free module
(`worker_inventory.py`) that both `diagnosis.py` and `worker_main.py` import, with `worker_main.py`
re-exporting for compatibility. Add a source-level test asserting `dashboard/beacon/diagnosis.py`'s
own text never contains `worker_main` or `apscheduler`.

### WR-05: The dashboard's TLS badge reads as reassurance, not warning

**File:** `dashboard/app.js:232-236`

**Issue:** The badge shown when a service's TLS certificate is **not** verified still reads, to a
sighted user, simply `TLS`:

```javascript
const tls = Object.assign(document.createElement('span'), {className: 'svc-tls-unverified', textContent: 'TLS'});
tls.title = 'TLS certificate is not verified for this trusted local service.';
tls.setAttribute('aria-label', 'TLS certificate is not verified for this trusted local service.');
```

A bare `TLS` chip on a service card is read by almost every operator as "this service uses TLS" — a
positive property. The actual meaning (certificate verification is disabled) is the inverse, and it
exists only in `title` (hover-only) and `aria-label` (screen-reader-only). A sighted mouse user gets
the opposite of the truth from the one glanceable signal; the warning color (`--accent2` via
`.svc-tls-unverified`) is the only visual hint, and color alone is not a label. This is the same
truthfulness standard the `/advanced` workspace this phase built holds itself to (D-11 in
`diagnosis.py`'s own comments: state the observation, never assert the opposite of it), and this
badge sits on the dashboard page reviewed alongside it.

**Fix:** keep the label short without inverting its polarity, e.g. `TLS unverified` (or `TLS ⚠`);
`.svc-tls-unverified` already sets `overflow-wrap: anywhere` for narrow widths, so the longer string
is safe to render.

## Info

### IN-01: Unused import

**File:** `dashboard/beacon/diagnosis.py:3`

`import json` is never referenced anywhere in the module (`grep -n "json\."` returns nothing). Remove
it.

### IN-03: Columns are read from the database and then never used

**File:** `dashboard/beacon/repositories.py:87-88`

`read_current_services` selects `s.last_latency_ms` and `s.first_seen` (line 87). Neither is read by
`compose_service_diagnosis` in `diagnosis.py` (which uses `probe_latency_ms` for latency and never
references `first_seen`) nor by `advanced.js`. Drop both from the projection so the read states only
what the composition actually consumes.

### IN-04: `state.expandedPorts` is never pruned against the current snapshot

**File:** `dashboard/advanced.js:8, 619-627, 659, 664`

Ports are added to `state.expandedPorts` on expand and removed only on explicit collapse
(`toggleServiceDetails`, `collapseAllDetails`). When a service disappears from a later poll (expired
past `expire_days`, or simply absent from a later snapshot), its port stays in the set forever. The
visible effect: `$('collapse-service-details').hidden = state.expandedPorts.size === 0` continues
showing "Collapse all details" after every currently-visible row is already collapsed, and clicking
it announces "All service details collapsed" with no visible change. Intersect the set with the
ports present in the current snapshot inside `renderServices`.

### IN-05: Interacting with sort/filter controls before the first poll resolves shows two contradictory messages

**File:** `dashboard/advanced.js:637-648, 798-825`

Sort, filter, and clear-filter handlers are wired at bootstrap (bottom of the IIFE), before
`refreshCurrentDiagnosis()`'s first `await` resolves. A click in that window calls `renderServices()`
with `state.snapshot === null`, so `source` is `undefined`:

```javascript
partial.hidden = Array.isArray(source);          // false -> "Some current-state evidence is unavailable" shows
empty.hidden = services.length !== 0;             // true services.length is 0 -> "No services match these filters" shows
```

The loading skeleton (`<tbody id="services-table-body">`'s two `.service-skeleton` rows from
`advanced.html`) is replaced by both messages simultaneously, telling the operator evidence is
missing *and* that their filters excluded every service, when the page has simply not completed its
first load. Guard with `if (!state.snapshot) return;` at the top of `renderServices`, or otherwise
leave the skeleton rows in place until `state.snapshot` is set.

### IN-06: `sqlite3.DatabaseError` (corruption) is not distinguished from an ordinary operational error

**File:** `dashboard/app.py:2214-2234`

`api_advanced_current` catches `MaintenanceBusy` and `sqlite3.OperationalError`. SQLite raises the
broader `sqlite3.DatabaseError` (which `OperationalError` is one subclass of) for conditions such as
`database disk image is malformed` — the one condition this codebase maintains a durable
`RECOVERY_MARKER` and a documented recovery command for elsewhere. That specific error therefore
falls through to an unhandled 500 with no `error` body field, reaching the operator only as
`advanced.js`'s generic "Server reported: HTTP 500". Every other place in this codebase that reasons
about corruption treats it as a modelled condition; this endpoint is the exception. Not urgent (the
client still degrades to its bounded error copy rather than crashing), but worth its own explicit 503
alongside the maintenance case for consistency with the rest of the recovery-marker machinery.

### IN-07: Dead function builds SQL with an f-string against an unvalidated table name

**File:** `dashboard/app.py:127-128`

```python
def _table_columns(conn, table_name):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
```

`_table_columns` has no callers anywhere in the tree (`grep -rn "_table_columns"` matches only its
own definition). It is dead code, and the pattern it uses — an f-string interpolating `table_name`
directly into a `PRAGMA` statement rather than the module's own established
`'"{}"'.format(table.replace('"', '""'))` quoting convention used identically for the same purpose in
`migrations.py:52-53` (`_column_names`) — is a latent SQL-injection shape that only isn't reachable
today because nothing calls it. Remove the function, or if it is needed, delegate to
`migrations.py`'s already-quoted `_column_names` instead of re-implementing the same query unsafely.

---

## Carried forward (still open, not re-argued)

The round-3 findings recorded as deferred in `deferred-items.md` rows 2–6 (`WR-04`, and round-3's own
`IN-02`, `IN-04`, `IN-06`, `IN-08`) and the seventeen round-1 `CF-*` findings in that file's row 7
were spot-checked against the current tree and remain accurate. They are not restated here;
`deferred-items.md` and the round-1 `03-REVIEW.md` (in git history) hold the full argument for each.

---

_Reviewed: 2026-08-20T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
