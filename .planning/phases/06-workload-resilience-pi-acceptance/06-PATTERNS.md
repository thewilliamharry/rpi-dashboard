# Phase 6: Workload Resilience & Pi Acceptance - Pattern Map

**Mapped:** 2026-08-28
**Files analyzed:** 9 (5 modified, 4 new)
**Analogs found:** 9 / 9 (all are same-file self-extension or in-repo precedent)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|-----------------|---------------|
| `dashboard/beacon/worker_main.py` (executor/lane edit) | config (scheduler wiring) | event-driven | same file, `build_scheduler`/`WORKER_CALLBACK_INVENTORY` (self) | exact — extend existing dict/tuple, no new pattern |
| `dashboard/beacon/queues.py` (preview retry/backoff) | service (queue state machine) | CRUD (state-machine transitions) | same file, `claim_preview`/`finish_preview_in_transaction` (self) | exact — same file, same optimistic-concurrency idiom |
| `dashboard/beacon/db.py` (WAL PRAGMA) | config (connection setup) | request-response (per-connection init) | same file, `connect_db` (self) | exact — one more `conn.execute('PRAGMA ...')` line |
| `dashboard/beacon/migrations.py` (new thumbnail-table migration) | migration | batch (one-time backfill) | same file, `_migration_3_metadata_and_state` (migrations.py:161-172) | exact — identical "add table + backfill + empty old column" shape |
| `dashboard/beacon/repositories.py` (new `ThumbnailStoreRepository`) | model/repository | CRUD | same file, `ThumbnailResultRepository.store_thumbnail_result` (repositories.py:712-727) + `read_background_job_health` (repositories.py:66-73) | exact — parameterized write + bounded read projection |
| `dashboard/app.py` (thumbnail-degraded read route) | controller/route | request-response | same file, `api_thumbnail` route + existing `/api/thumbnail-status` (app.py:2973-3012) | exact — extend existing endpoint's response shape |
| `dashboard/app.js` (degraded-state thumbnail rendering) | component | request-response (DOM render from fetched JSON) | same file, `buildServiceCard` fallback block (app.js:217-244) | exact — extend existing `has_thumb`/fallback branch |
| `tests/test_workload_resilience.py` (new) | test | event-driven / integration | `tests/test_worker_ownership_matrix.py` (dynamic RED-matrix pattern) + `tests/test_migrations.py` (fixture/snapshot pattern) | role-match — new integration suite combining both idioms |
| `tests/pi_load_acceptance.py` (new) | utility (standalone load harness) | batch / request-response (HTTP load generation + polling) | `dashboard/beacon/repositories.py` `read_background_job_health` (evidence reader) + `dashboard/beacon/diagnosis.py` `freshness_state` (oracle) | partial — no existing load-harness analog in repo; built from these two evidence-reading primitives |

## Pattern Assignments

### `dashboard/beacon/worker_main.py` (config, event-driven) — executor lane split

**Analog:** same file, `WORKER_CALLBACK_INVENTORY` and `build_scheduler` (self-extension)

**Current registry entries to edit** [worker_main.py:79, 85]:
```python
WorkerCallback('J1', ('update_worker_heartbeat', 'renew_worker_lease'), 'heartbeat', 'scheduled',
    ('worker_owner', 'worker_heartbeat'), ('browser_resource_lifecycle',), scheduler_id='heartbeat',
    trigger='interval', trigger_kwargs=(('seconds', 5),), executor='metrics'),
WorkerCallback('J8', ('cleanup_history',), 'cleanup', 'scheduled', (...), (),
    scheduler_id='cleanup', trigger='interval', trigger_kwargs=(('hours', 1),),
    executor='metrics', misfire_grace_time=300),
```
Change J8's `executor='metrics'` to `executor='cleanup'` (new lane). Leave J1/J2 on `'metrics'`.

**Core pattern — executor dict** [worker_main.py:457-462]:
```python
def build_scheduler(services):
    """Create the bounded UTC scheduler without starting it."""
    executors = {
        'default': ThreadPoolExecutor(1),
        'metrics': ThreadPoolExecutor(1),
        'probes': ThreadPoolExecutor(2),
        'screenshots': ThreadPoolExecutor(1),
    }
```
Add `'cleanup': ThreadPoolExecutor(1),` to this dict — this is the entire change needed to give J8 an isolated lane. `WorkerCallback.executor` is already read generically at `built_scheduler.add_job(..., executor=callback.executor, ...)` (worker_main.py:474-483), so no dispatch-path code changes are required, only data.

**Also verify:** `SCHEDULER_JOB_IDS` map in `tests/test_worker_ownership_matrix.py:33-36` enumerates `'cleanup': 'J8'` already by scheduler_id (not executor), so that mapping does not need editing — only `build_scheduler`'s executors dict and J8's `executor=` kwarg change.

---

### `dashboard/beacon/queues.py` (service, CRUD state machine) — bounded preview retry/backoff

**Analog:** same file, `claim_preview` (queues.py:630-670) and `finish_preview_in_transaction` (queues.py:697-725)

**Existing claim pattern to extend** [queues.py:630-668, quoted]:
```python
def claim_preview(db_path, worker_id, *, worker_owner_token, now=None, lease_seconds=60):
    """Claim the latest non-expired preview revision, if any."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        _assert_current_worker_owner(conn, worker_id, worker_owner_token, now)
        conn.execute(
            "UPDATE preview_requests SET status='expired', terminal_ts=?, completed_ts=?, error='expired' "
            "WHERE status='queued' AND deadline_ts <= ?", (now, now, now),
        )
        row = conn.execute("""
            SELECT p.id FROM preview_requests p
             WHERE p.status='queued' AND p.deadline_ts > ?
               AND NOT EXISTS (...)
             ORDER BY p.requested_ts, p.id LIMIT 1
        """, (now,)).fetchone()
        ...
        changed = conn.execute(
            "UPDATE preview_requests SET status='running', started_ts=?, lease_owner=?, lease_until=?, "
            "attempt_count=attempt_count + 1, error=NULL WHERE id=? AND status='queued' AND deadline_ts > ?",
            (now, str(worker_id), now + int(lease_seconds), request_id, now),
        ).rowcount
```
**Existing terminal-write pattern to extend** [queues.py:697-722, quoted]:
```python
def finish_preview_in_transaction(
    conn, request_id, worker_id, *, worker_owner_token, revision,
    status='completed', error=None, result=None, now=None,
):
    """Finish only a current revision while the caller holds its write transaction."""
    now = _now(now)
    _assert_current_worker_owner(conn, worker_id, worker_owner_token, now)
    row = conn.execute(
        'SELECT port FROM preview_requests WHERE id=? AND revision=?', (request_id, revision),
    ).fetchone()
    ...
    changed = conn.execute(
        "UPDATE preview_requests SET status=?, completed_ts=?, terminal_ts=?, error=?, result=?, "
        "lease_owner=NULL, lease_until=NULL WHERE id=? AND revision=? AND status='running' "
        "AND lease_owner=? AND lease_until > ? AND deadline_ts > ?",
        (status, now, now, error, result, request_id, revision, str(worker_id), now, now),
    ).rowcount
```
**Pitfall this codebase itself flags (RESEARCH.md Pitfall 2):** `attempt_count` is already incremented on every `claim_preview` call (queues.py:657) but nothing reads it as a cap — this is bookkeeping only today. The new bounded-retry logic must be added as an explicit read-and-branch, e.g. in the caller of `finish_preview_in_transaction` (worker-side `worker_process_preview_requests` in `app.py:2227-2281`, which already distinguishes machinery failure `PreviewCaptureUnavailable` from a per-service `thumb_error`): before calling `finish_preview_in_transaction(status='failed', ...)`, read the current `attempt_count` (already selected alongside `status`/`port` in the claimed row) and if it is below a bounded max, re-enqueue via the same `enqueue_preview_in_transaction` pattern already imported into `repositories.py:12` with a short backoff `deadline_ts`; once the max is reached, write a new terminal status distinct from `'failed'` (e.g. `'degraded'`) so app.js/`/api/thumbnail-status` can distinguish it from an ordinary in-flight failure.

**Backoff/enqueue analog** — `enqueue_preview_in_transaction` (same file, imported at `repositories.py:12`) is the existing insert-path to copy for re-enqueuing with a delayed `deadline_ts`; read it directly next to `claim_preview` in `queues.py` (same module) before authoring the retry branch.

---

### `dashboard/beacon/db.py` (config, request-response) — WAL PRAGMA

**Analog:** same file, `connect_db` (self-extension)

**Current connection setup** [db.py:74-88, quoted]:
```python
def connect_db(settings_or_path):
    """Open a configured SQLite connection while holding a shared access lease."""
    handle = _acquire_lock(maintenance_lock_path(settings_or_path), fcntl.LOCK_SH, 30)
    try:
        conn = sqlite3.connect(
            _db_path(settings_or_path), timeout=30, factory=ManagedConnection,
        )
        conn._set_maintenance_handle(handle)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn
    except Exception:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
        raise
```
**Change:** add `conn.execute('PRAGMA journal_mode=WAL')` immediately after the existing `busy_timeout`/`foreign_keys` PRAGMAs, in the same try block, following the exact same fail-closed pattern (any exception before `return conn` still releases the `flock` handle via the existing `except Exception` branch — no new error handling needed since it reuses the same block).

**Guard rail (RESEARCH.md Pitfall 4):** do not touch `_db_lock` (`dashboard/app.py:115`) in the same change. `_db_lock` is a separate in-process thread-serialization concern; WAL only affects cross-connection reader/writer blocking. Keep these as two independently-tested changes.

---

### `dashboard/beacon/migrations.py` (migration, batch) — bounded/TTL'd thumbnail table

**Analog:** same file, `_migration_3_metadata_and_state` (migrations.py:161-172, quoted verbatim)

```python
def _migration_3_metadata_and_state(conn):
    _add_column(conn, 'service_meta', "healthy_statuses TEXT DEFAULT '200-399'")
    conn.execute(
        "UPDATE services SET thumb_data=NULL, thumb_mime='image/jpeg', thumb_ts=NULL, thumb_source=NULL "
        "WHERE thumb_source='fallback'"
    )
    conn.execute(
        "INSERT OR IGNORE INTO service_meta (port, url, critical, pinned_order, tags, healthy_statuses) "
        "SELECT port, 'http://127.0.0.1:' || port, 0, port, '', '200-399' FROM services"
    )
```
This is the exact precedent to follow for the new migration: (1) `CREATE TABLE IF NOT EXISTS thumbnails (port INTEGER PRIMARY KEY, data BLOB, mime TEXT, captured_ts INTEGER, source TEXT, expires_ts INTEGER)` using the same `conn.executescript(...)` idiom seen at migrations.py:141-149 for index/table DDL; (2) `INSERT INTO thumbnails (...) SELECT port, thumb_data, thumb_mime, thumb_ts, thumb_source, ? FROM services WHERE thumb_data IS NOT NULL` to backfill; (3) `UPDATE services SET thumb_data=NULL, thumb_mime=NULL WHERE thumb_data IS NOT NULL` to empty the primary table — same statement shape as the existing `UPDATE services SET thumb_data=NULL, ...` cleanup line quoted above.

**Column-add helper already available** [migrations.py:152-158, quoted]:
```python
def _migration_2_service_diagnostics(conn):
    for column in (
        'thumb_data BLOB', 'thumb_mime TEXT DEFAULT \'image/jpeg\'', 'thumb_ts INTEGER',
        'thumb_source TEXT', 'thumb_attempt_ts INTEGER', 'thumb_error TEXT',
        'last_latency_ms REAL', 'last_error TEXT', 'state_since INTEGER',
    ):
        _add_column(conn, 'services', column)
```
Use `_add_column(conn, ...)` (imported/defined in this module) only if adding columns to an existing table; the new `thumbnails` table itself should use `CREATE TABLE IF NOT EXISTS` inside a `conn.executescript` block matching the DDL style at migrations.py:141-149, not `_add_column`.

**Registration:** new migration function must be added to the `MIGRATIONS` tuple in this file (see `_migration_7_canonical_host_streams`/`_migration_9_planned_maintenance` import names used by `tests/test_migrations.py:20-27` — the test file imports migration functions by name directly, so the new function needs a discoverable name following the `_migration_N_<description>` convention, e.g. `_migration_10_thumbnail_relocation`).

---

### `dashboard/beacon/repositories.py` (model, CRUD) — new thumbnail-store repository

**Analog A — write pattern:** `ThumbnailResultRepository.store_thumbnail_result` (repositories.py:712-727, quoted verbatim):
```python
def store_thumbnail_result(
    self, conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts=None,
):
    timestamp = int(time.time()) if ts is None else int(ts)
    if thumb_data and thumb_source == 'screenshot':
        conn.execute(
            "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=?, thumb_source=?, "
            "thumb_attempt_ts=?, thumb_error=NULL WHERE port=?",
            (thumb_data, thumb_mime, timestamp, thumb_source, timestamp, port),
        )
        return
    conn.execute(
        "UPDATE services SET thumb_data=NULL, thumb_mime='image/jpeg', thumb_ts=NULL, thumb_source=NULL, "
        "thumb_attempt_ts=?, thumb_error=? WHERE port=?",
        (timestamp, (thumb_error or 'screenshot failed')[:240], port),
    )
```
The new repository's write method should follow the same shape but target the new `thumbnails` table with an `INSERT ... ON CONFLICT(port) DO UPDATE SET ...` (upsert, since `port` is the natural key) plus an `expires_ts` computed as `timestamp + ttl_seconds` — mirror the `INSERT ... ON CONFLICT(job_id) DO UPDATE SET` upsert idiom already used in `record_background_job_started`/`record_background_job_succeeded` below.

**Analog B — bounded read/eviction pattern:** `read_background_job_health` (repositories.py:66-73, quoted verbatim):
```python
def read_background_job_health(conn, *, limit=32):
    """Return a deterministic, bounded projection of durable job outcomes."""
    return [dict(row) for row in conn.execute(
        'SELECT job_id, last_started_ts, last_finished_ts, last_success_ts, '
        'state, error_class, updated_ts FROM background_job_health '
        'ORDER BY job_id ASC LIMIT ?',
        (max(1, min(int(limit), 128)),),
    )]
```
Use this exact clamped-`limit` + `dict(row)` list-comprehension shape for a `read_thumbnail(conn, port)` accessor. For TTL eviction, add a `delete_expired_thumbnails(conn, *, now)` function using `conn.execute('DELETE FROM thumbnails WHERE expires_ts <= ?', (now,))` — this is the reap step J8 (`cleanup_history`, moved to the new `'cleanup'` executor) should call alongside its existing retention sweeps.

**Upsert idiom to copy** [repositories.py:27-35, quoted]:
```python
def record_background_job_started(conn, job_id, *, now):
    conn.execute(
        'INSERT INTO background_job_health('
        'job_id, last_started_ts, last_finished_ts, last_success_ts, state, error_class, updated_ts'
        ') VALUES(?,?,NULL,NULL,\'running\',NULL,?) '
        'ON CONFLICT(job_id) DO UPDATE SET '
        'last_started_ts=excluded.last_started_ts, state=excluded.state, '
        'error_class=NULL, updated_ts=excluded.updated_ts',
        (str(job_id), int(now), int(now)),
    )
```

---

### `dashboard/app.py` (controller, request-response) — degraded-preview read route

**Analog:** existing `/api/thumbnail-status` endpoint (app.py:2990-3012) and module constants block (app.py:65-73, quoted verbatim):
```python
THUMB_MAX_BYTES = 2 * 1024 * 1024
PREVIEW_SETTLE_MS = 5_000
PREVIEW_BROWSER_BUDGET_MS = 27_000
THUMB_ERROR_BROWSER_UNAVAILABLE = 'browser_unavailable'
```
```python
_screenshot_sem = threading.Semaphore(1)
_browser_lock = threading.Lock()
```
`api_thumbnail` (reads `thumb_data`/`thumb_mime` off `services`) will need to read from the new `thumbnails` table (via the new repository) instead once OPS-03 relocates storage — same route shape, new data source. The existing `/api/thumbnail-status` route already exposes `thumb_error`/`thumb_attempt_ts` per-service; extend its response payload (or the new repository's read) to also expose the retry-exhausted `'degraded'` terminal state added in `queues.py`, so `app.js` has something distinct to render.

**Guard rail:** keep `_db_lock` usage exactly as-is at every one of its 25+ existing call sites (`app.py:115`) — do not narrow/remove it as part of this route change (RESEARCH.md Pitfall 4/Anti-Pattern 3).

---

### `dashboard/app.js` (component, request-response) — degraded thumbnail rendering

**Analog:** same file, `buildServiceCard` fallback block (app.js:217-244, quoted verbatim):
```javascript
const fallback = document.createElement('div');
fallback.className = 'svc-preview-fallback';
fallback.style.display = service.has_thumb ? 'none' : 'flex';
const fallbackPort = document.createElement('span');
fallbackPort.className = 'fallback-port';
fallbackPort.textContent = `:${service.port}`;
fallback.append(fallbackPort, Object.assign(document.createElement('span'), {textContent: 'NO PREVIEW'}));
if (service.has_thumb) {
  const image = document.createElement('img');
  image.className = 'svc-thumb';
  image.alt = '';
  image.src = `/api/thumbnail/${service.port}?v=${service.last_seen || 0}`;
  image.addEventListener('error', () => { image.remove(); fallback.style.display = 'flex'; });
  preview.appendChild(image);
}
```
**Recommended change:** branch this same fallback block on a new field (e.g. `service.thumb_state === 'degraded'`) surfaced from the extended `/api/thumbnail-status`/service payload, rendering a distinct label (e.g. `'PREVIEW UNAVAILABLE'`) instead of always `'NO PREVIEW'` — reuse Phase 5's established six-state visibility vocabulary (loading/empty/stale/unknown/degraded/error) referenced in RESEARCH.md Pattern 2, rather than inventing new CSS states. Locate Phase 5's degraded-state CSS/JS convention (search `app.js`/`app.css` for `degraded` class names used by the worker-freshness banner) and mirror its class-naming scheme for the new per-thumbnail degraded badge.

---

### `tests/test_workload_resilience.py` (new test, integration)

**Analog A — dynamic contract-matrix pattern:** `tests/test_worker_ownership_matrix.py:1-36` (imports, `EXPECTED_CALLBACK_IDS`, `SCHEDULER_JOB_IDS` tuples/dicts asserting scheduler structure directly against `dashboard.beacon.worker_main`).

**Analog B — fixture/harness pattern:** `tests/test_migrations.py:1-30` (imports `connect_db`/`prepare_database` from `dashboard.beacon.db`, uses `tempfile`, `multiprocessing`, `threading`, `subprocess` for concurrency/process-level scenarios — directly reusable for OPS-04's "worker restart mid-job" and "concurrent web/worker writer" cases).

**Pattern to copy for cadence-under-contention (OPS-01):** build a scheduler via `build_scheduler(services)` (worker_main.py) against a real/temp SQLite DB, fire J5/J6/J7/J8-equivalent work concurrently (or call the underlying callback functions directly via `dispatch_callback`), then assert `read_background_job_health(conn, limit=...)` (repositories.py:66-73) entries for `'J1'`/`'J2'` have `state='succeeded'` and, using `freshness_state(now, last_success_ts, cadence_seconds)` (diagnosis.py:101-118), assert `state` is `'fresh'` or `'aging'`, never `'stale'`.

**Pattern to copy for bounded preview retry (OPS-02):** use `queues.claim_preview`/`finish_preview_in_transaction` directly (as `tests/test_migrations.py` and `test_worker_ownership_matrix.py` already import `queues` and call worker-layer functions directly rather than through HTTP), force repeated `status='failed'` outcomes, and assert the request reaches the new bounded terminal state after the configured max attempts without blocking J1-J4 (assert their `background_job_health` rows are untouched/still succeeding during the same window).

---

### `tests/pi_load_acceptance.py` (new, standalone harness)

**No direct existing analog** (first load-harness file in the repo) — build from these two existing evidence primitives, both already read this session:

**Oracle 1 — freshness classification** (diagnosis.py:101-118, quoted verbatim above under Pattern Assignments db.py section) — call directly against sampled `last_success_ts` values pulled from `background_job_health`.

**Oracle 2 — durable job health projection** (repositories.py:66-73, quoted above) — poll this throughout the load run via a direct `sqlite3`/`connect_db` connection (reuse `dashboard.beacon.db.connect_db` the same way `tests/test_migrations.py` does) rather than scraping logs.

**Resource ceilings to assert against** — read from `docker-compose.yml` directly (not quoted here since it is YAML config, not code to copy-pattern from): `worker: mem_limit: 1g`, `web: mem_limit: 256m` — use `psutil.Process(...).memory_info().rss` (already a pinned dependency, used elsewhere for `collect_system_stats`) to sample and assert against these ceilings.

**Load generation:** use `requests` (already pinned, used throughout `app.py` for outbound checks) in worker threads (`threading`, already used throughout the worker) to generate concurrent HTTP load against `/api/history/*`, `/api/advanced/*`, and thumbnail routes — no new dependency, per RESEARCH.md "Don't Hand-Roll."

## Shared Patterns

### Parameterized SQL / no string-interpolated queries
**Source:** every quoted excerpt above (`queues.py`, `repositories.py`, `migrations.py`) uses `?`-placeholder parameterized `conn.execute(sql, (values...))` — never f-string/`.format()` SQL.
**Apply to:** the new `ThumbnailStoreRepository` methods and any new migration DML.

### Transaction discipline (commit/rollback in `finally`/`except`)
**Source:** `dashboard/beacon/db.py:121-129` `write_transaction` context manager (quoted):
```python
@contextmanager
def write_transaction(settings_or_path):
    with database_access(settings_or_path) as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
```
**Apply to:** any new migration function and any new worker-side thumbnail-write call site — always go through `write_transaction`/`database_access`, never a bare unmanaged `sqlite3.connect`.

### Bounded/clamped `limit` parameters on read projections
**Source:** `read_background_job_health(conn, *, limit=32)` clamp: `max(1, min(int(limit), 128))` (repositories.py:70).
**Apply to:** any new `read_thumbnail`/thumbnail-listing repository function and the load harness's own polling queries.

### `WorkerCallback`/`WORKER_CALLBACK_INVENTORY` as the single source of truth for lane/scheduler identity
**Source:** `dashboard/beacon/worker_main.py:79-95` tuple, consumed generically by `build_scheduler` (worker_main.py:474-483) and asserted against directly by `tests/test_worker_ownership_matrix.py:29-36` (`EXPECTED_CALLBACK_IDS`, `SCHEDULER_JOB_IDS`).
**Apply to:** the J8 lane reassignment — change only the tuple entry and the executors dict; do not add a parallel lane-configuration mechanism.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `tests/pi_load_acceptance.py` | utility (load harness) | batch / request-response | First load-generation harness in the repo; composed from existing evidence-reader primitives (`freshness_state`, `read_background_job_health`) rather than an existing analog file — see RESEARCH.md "Don't Hand-Roll" table |

## Metadata

**Analog search scope:** `dashboard/beacon/` (worker_main.py, queues.py, db.py, migrations.py, repositories.py, diagnosis.py), `dashboard/app.py`, `dashboard/app.js`, `tests/` (test_migrations.py, test_worker_ownership_matrix.py)
**Files scanned:** 9 source files read directly this session (non-overlapping targeted ranges), plus 2 existing test files for structural precedent
**Pattern extraction date:** 2026-08-28
