# Phase 2: Bounded Telemetry & Retention - Pattern Map

**Mapped:** 2026-08-10  
**Files analyzed:** 10  
**Analogs found:** 10 / 10

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dashboard/beacon/telemetry.py` | utility/service | transform | `dashboard/beacon/monitoring.py` | role-match |
| `dashboard/beacon/migrations.py` | migration | batch | `dashboard/beacon/migrations.py` | exact |
| `dashboard/beacon/repositories.py` | repository/service | request-response | `dashboard/beacon/repositories.py` | exact |
| `dashboard/beacon/monitoring.py` | service adapter | event-driven | `dashboard/beacon/monitoring.py` | exact |
| `dashboard/beacon/worker_main.py` | worker/scheduler | event-driven | `dashboard/beacon/worker_main.py` | exact |
| `dashboard/beacon/config.py` | config | transform | `dashboard/beacon/config.py` | exact |
| `dashboard/app.py` | controller/compatibility adapter | request-response | `dashboard/app.py` | exact |
| `tests/test_telemetry_retention.py` | test | batch | `tests/test_migrations.py` | role-match |
| `tests/test_historical_telemetry_api.py` | test | request-response | `tests/test_runtime_ownership.py` | role-match |
| `tests/test_migrations.py` | test | migration | `tests/test_migrations.py` | exact |

## Pattern Assignments

### `dashboard/beacon/telemetry.py` (utility/service, transform)

**Analog:** `dashboard/beacon/monitoring.py`

Keep policy code Flask-, scheduler-, and connection-lifetime-free. It should take an already-open SQLite connection and worker authority from adapters, following the operation-seam style rather than importing `app`.

**Imports and adapter seam** — `dashboard/beacon/monitoring.py:1-29`:

```python
"""Framework-free monitoring operation interfaces.

The worker owns composition.  This module only receives callables for persistence,
network transport, and clocks, which keeps it importable by jobs and unit tests
without creating Flask, schedulers, or browser processes.
"""

from dataclasses import dataclass
from typing import Callable

@dataclass(frozen=True)
class MonitoringOperations:
    """Explicit monitoring collaborators supplied by a composition root."""
```

**Thin delegation pattern** — `dashboard/beacon/monitoring.py:68-85`:

```python
def collect_system_stats(operations, now=None, persist_history=None):
    return operations.collect_system_stats(now, persist_history)

def cleanup_history(operations, now=None):
    return operations.cleanup_history(now)
```

Use pure functions/data classes for UTC bucket selection, coverage coalescing, point-budget resolution selection, and storage calculations; the worker-facing operation performs transactional persistence.

---

### `dashboard/beacon/migrations.py` (migration, batch)

**Analog:** `dashboard/beacon/migrations.py`

Add one additive versioned migration for rollups, coverage, job state/failure, and indexes. Append to `MIGRATIONS`; do not create tables at job startup.

**Schema migration convention** — `dashboard/beacon/migrations.py:45-112`:

```python
def _migration_1_baseline(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, applied_ts INTEGER NOT NULL
        );
        ...
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    """)
```

**Idempotent column migration convention** — `dashboard/beacon/migrations.py:35-43, 122-126`:

```python
def _add_column(conn, table, column_sql):
    column_name = column_sql.split()[0]
    if column_name not in _column_names(conn, table):
        conn.execute('ALTER TABLE {} ADD COLUMN {}'.format(table, column_sql))

_add_column(conn, 'service_checks', 'latency_ms REAL')
_add_column(conn, 'service_checks', 'error_class TEXT')
```

**Registration and transactional application** — `dashboard/beacon/migrations.py:183-188, 337-365`:

```python
MIGRATIONS = (
    Migration(1, 'baseline_schema', True, _migration_1_baseline),
    ...
)

with sqlite3.connect(database, timeout=30) as conn:
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('BEGIN IMMEDIATE')
    migration.apply(conn)
    conn.execute(
        'INSERT INTO schema_migrations(version, applied_ts) VALUES(?, ?)',
        (migration.version, int(clock())),
    )
    conn.commit()
```

---

### `dashboard/beacon/repositories.py` (repository/service, request-response)

**Analog:** `dashboard/beacon/repositories.py`

Implement bounded raw/aggregate reads and coverage reads here. Receive an open connection, use fixed query shapes and placeholders, and return rows or dictionaries; do not open connections or access Flask request state.

**Module contract and parameterization** — `dashboard/beacon/repositories.py:1-10, 34-45`:

```python
"""Parameterized SQLite queries used by thin Beacon adapters.

Repository functions receive an already-open connection.  They deliberately do
not own Flask request state, network clients, browsers, or connection lifetime.
"""

def get_service_metadata(conn, port):
    row = conn.execute(
        "SELECT ... WHERE s.port = ?",
        (port,),
    ).fetchone()
    return dict(row) if row else None
```

**Upsert and runtime-state conventions** — `dashboard/beacon/repositories.py:61-74, 77-92`:

```python
conn.execute(
    "INSERT INTO service_meta (...) VALUES(?,?,?,?,?,?,?) "
    "ON CONFLICT(port) DO UPDATE SET ...",
    (...),
)

row = conn.execute('SELECT value FROM runtime_state WHERE key=?', (key,)).fetchone()
...
conn.execute(
    "INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) "
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts",
    (key, json.dumps(value, separators=(',', ':')), updated_ts),
)
```

**Bounded query convention** — `dashboard/beacon/repositories.py:108-121`:

```python
if since_ts is None:
    return conn.execute(query + 'ORDER BY e.ts DESC, e.id DESC LIMIT ?', (limit,)).fetchall()
return conn.execute(
    query + 'WHERE e.ts > ? ORDER BY e.ts DESC, e.id DESC LIMIT ?',
    (since_ts, limit),
).fetchall()
```

---

### `dashboard/beacon/monitoring.py` (service adapter, event-driven)

**Analog:** `dashboard/beacon/monitoring.py`

Extend the explicit operation registry only if observation writers need a telemetry-registration seam. Preserve its framework-free forwarding behavior.

**Operation registration/delegation** — `dashboard/beacon/monitoring.py:12-29, 68-85`:

```python
@dataclass(frozen=True)
class MonitoringOperations:
    ...
    collect_system_stats: Callable
    cleanup_history: Callable
    do_uptime_check: Callable

def do_uptime_check(operations, only_down=False):
    return operations.do_uptime_check(only_down)
```

---

### `dashboard/beacon/worker_main.py` (worker/scheduler, event-driven)

**Analog:** `dashboard/beacon/worker_main.py`

Keep a single worker-owned retention callback. Add its operation field to both immutable service data classes, declare it in `WORKER_CALLBACK_INVENTORY`, dispatch it through `_invoke_callback`, and use the existing bounded APScheduler configuration.

**Declarative callback inventory** — `dashboard/beacon/worker_main.py:24-42, 75-92`:

```python
@dataclass(frozen=True)
class WorkerOperations:
    ...
    cleanup_history: object

WorkerCallback(
    'J8', ('cleanup_history',), 'cleanup', 'scheduled',
    ('stats_history', 'service_checks', 'events', 'scan_rate_hits'), (),
    scheduler_id='cleanup', trigger='interval', trigger_kwargs=(('hours', 1),),
    executor='metrics', misfire_grace_time=300,
)
```

**Dispatch and lease-loss boundary** — `dashboard/beacon/worker_main.py:203-247`:

```python
if callback.handler == 'cleanup':
    return services.cleanup_history(services.authority)
...
try:
    return _invoke_callback(services, callback)
except queues.LeaseLost:
    log.error('Beacon worker lease lost; stopping stale scheduler')
    services.admission.close_admission()
    stop_worker()
    return False
```

**Scheduling bounds** — `dashboard/beacon/worker_main.py:297-324`:

```python
job_defaults = {
    'coalesce': True,
    'max_instances': 1,
    'misfire_grace_time': 15,
}
built_scheduler = BlockingScheduler(executors=executors, job_defaults=job_defaults, timezone='UTC')
```

---

### `dashboard/beacon/config.py` (config, transform)

**Analog:** `dashboard/beacon/config.py`

Add validated immutable retention, pressure, reserve, retry, and historical-point-budget settings with environment overrides. Use positive-integer parsing and retain defaults on invalid input.

**Settings and validation pattern** — `dashboard/beacon/config.py:24-48, 89-136`:

```python
@dataclass(frozen=True)
class Settings:
    db_path: str = '/data/dashboard.db'
    metric_history_seconds: int = 60
    ...

def _positive_int(environ, key, default):
    try:
        value = int(environ.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default

return Settings(
    db_path=source.get('DB_PATH', '/data/dashboard.db'),
    metric_history_seconds=_positive_int(source, 'METRIC_HISTORY_SECONDS', 60),
)
```

---

### `dashboard/app.py` (controller/compatibility adapter, request-response)

**Analog:** `dashboard/app.py`

Use the legacy app only as the compatibility composition point: invoke telemetry through the worker-authority transaction and add the new bounded historical route without changing `/api/history`'s existing one-day array contract.

**Authority-fenced transaction** — `dashboard/app.py:226-239`:

```python
@contextmanager
def _worker_write_transaction(authority, *, now=None):
    conn = connect_db(authority.db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        beacon_queues.assert_current_worker_authority(conn, authority, now)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
```

**Collection then atomic publish** — `dashboard/app.py:1643-1677`:

```python
def worker_collect_system_stats(authority, now=None, persist_history=None):
    """Collect outside SQLite, then publish under the current worker epoch."""
    ...
    with _worker_write_transaction(authority) as conn:
        conn.execute("INSERT INTO system_stats(...) VALUES(...) ON CONFLICT(id) DO UPDATE SET ...", (...))
        if persist_history:
            conn.execute('INSERT OR REPLACE INTO stats_history(ts,cpu,ram,disk,temp) VALUES(?,?,?,?,?)', (...))
```

**Existing compatibility history route** — `dashboard/app.py:2051-2061`:

```python
@app.route("/api/history")
def api_history():
    now = int(time.time())
    with _db_lock:
        conn = get_db()
        rows = conn.execute(
            "SELECT ts, cpu, ram, disk, temp FROM stats_history WHERE ts >= ? ORDER BY ts ASC",
            (now - 86400,),
        ).fetchall()
        conn.close()
    return jsonify([dict(r) for r in rows])
```

Replace `worker_cleanup_history`'s age-only telemetry deletes with the telemetry retention operation but leave scan-rate cleanup in the same authority transaction.

---

### `tests/test_telemetry_retention.py` (test, batch)

**Analog:** `tests/test_migrations.py` and `tests/test_runtime_ownership.py`

Use temporary databases and direct `Settings`/migration calls for deterministic tier and retry tests; verify state after every failure path rather than only final successful output.

**Temporary fixture and direct migration pattern** — `tests/test_migrations.py:50-105`:

```python
class MigrationTests(unittest.TestCase):
    def _copied_fixture(self, directory, filename):
        target = Path(directory) / filename
        copy2(FIXTURE_DIR / filename, target)
        return target

    def test_current_rerun_is_a_no_op_without_a_new_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            settings = Settings(db_path=str(target))
            run_migrations(settings)
            result = run_migrations(settings)
            self.assertEqual(result.applied_versions, ())
```

**Real lease test-double pattern** — `tests/test_runtime_ownership.py:37-71`:

```python
def acquire_worker_lease(db_path, worker_id):
    calls.append(('acquire', worker_id))
    return queues.acquire_worker_lease(db_path, worker_id)

def renew_worker_lease(authority):
    calls.append(('renew', authority.worker_id))
    return queues.renew_worker_authority(authority)
```

Cover raw/5-minute/hourly/expired boundaries, rollup-write verification before source deletion, retry/backoff, pressure gaps/recovery, and stale-lease failure.

---

### `tests/test_historical_telemetry_api.py` (test, request-response)

**Analog:** `tests/helpers.py` and `tests/test_runtime_ownership.py`

Load a fresh legacy compatibility app per test and use its Flask test client. Assert requested bounds, bounded resolution, points, and complete coverage partition exactly.

**App fixture and cleanup pattern** — `tests/helpers.py:51-81, 84-100`:

```python
def load_app(extra_env=None):
    ...
    db_dir = tempfile.mkdtemp(prefix='beacon-test-')
    db_path = os.path.join(db_dir, 'dashboard.db')
    import dashboard.app as appmod
    appmod = importlib.reload(appmod)
    appmod.DB_PATH = db_path
    appmod.init_db()
    return appmod, db_path
```

**Test lifecycle pattern** — `tests/test_runtime_ownership.py:20-29`:

```python
def setUp(self):
    self.tmpdir = tempfile.TemporaryDirectory()
    self.appmod, self.db_path = load_app()
    self.client = self.appmod.app.test_client()

def tearDown(self):
    self._reset_worker_globals()
    cleanup_db(self.db_path)
    self.tmpdir.cleanup()
```

---

### `tests/test_migrations.py` (test, migration)

**Analog:** `tests/test_migrations.py`

Extend existing legacy-fixture tests to check the new migration version/tables/indexes while confirming legacy rows survive, migration reruns are no-ops, and a migration failure rolls back.

**Preservation assertion** — `tests/test_migrations.py:71-93`:

```python
result = run_migrations(Settings(db_path=str(target)))
self.assertTrue(result.applied_versions)
with sqlite3.connect(target) as conn:
    self.assertEqual(conn.execute('SELECT COUNT(*) FROM services').fetchone()[0], service_rows)
    self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], event_rows)
    self.assertEqual(
        conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0],
        MIGRATIONS[-1].version,
    )
```

## Shared Patterns

### Durable worker authority and write transactions

**Sources:** `dashboard/app.py:226-239`, `dashboard/beacon/worker_main.py:233-247`  
**Apply to:** Rollups, retention deletion, coverage persistence, retry/failure state, pressure-mode changes.

Every worker mutation begins `BEGIN IMMEDIATE`, asserts the current durable worker epoch, and commits/rolls back within one short transaction. A `LeaseLost` raised by the operation must stop stale scheduled work.

### SQLite migration safety

**Source:** `dashboard/beacon/migrations.py:294-369`  
**Apply to:** All telemetry schema changes.

Use the migration gate with its existing backup, support-floor, exclusive-maintenance, transaction, and recovery-marker behavior. Do not hand-create schema from a retention callback.

### Bounded and parameterized reads

**Source:** `dashboard/beacon/repositories.py:108-121`  
**Apply to:** New historical API queries.

Use selector allowlists to choose fixed SQL and bind all values. Cap rows/resolution before materializing a response; close the request connection at the route boundary.

### Compatibility boundary

**Source:** `dashboard/app.py:2051-2061`  
**Apply to:** Existing dashboard preview and new historical endpoint.

Do not alter the return shape or one-day semantics of `/api/history`; add the coverage-aware range contract as a separate endpoint/adapter.

### Test isolation

**Source:** `tests/helpers.py:69-100`  
**Apply to:** Both new test modules.

Use one temporary database directory per test and clean database, WAL, SHM, and lock files through `cleanup_db`.

## No Analog Found

No file lacks a usable project analog. The new `telemetry.py` policy module is a role-match extension of the framework-free `monitoring.py` seam; its retention-specific algorithms should follow `02-RESEARCH.md`.

## Metadata

**Analog search scope:** `dashboard/beacon/`, `dashboard/app.py`, `tests/`  
**Files scanned:** 12  
**Pattern extraction date:** 2026-08-10
