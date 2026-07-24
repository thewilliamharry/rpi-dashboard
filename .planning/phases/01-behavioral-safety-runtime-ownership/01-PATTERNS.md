# Phase 1: Behavioral Safety & Runtime Ownership - Pattern Map

**Mapped:** 2026-07-24  
**Files analyzed:** 21 planned new/modified files  
**Analogs found:** 18 / 21

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dashboard/beacon/config.py` | config | transform | `dashboard/app.py` | role-match |
| `dashboard/beacon/db.py` | service | CRUD | `dashboard/app.py` | role-match |
| `dashboard/beacon/migrations.py` | migration | transform | `dashboard/app.py` | partial |
| `dashboard/beacon/repositories.py` | service | CRUD | `dashboard/app.py` | role-match |
| `dashboard/beacon/queues.py` | service | event-driven | `dashboard/app.py` | role-match |
| `dashboard/beacon/outbound.py` | service | request-response | `dashboard/app.py` | role-match |
| `dashboard/beacon/monitoring.py` | service | event-driven | `dashboard/app.py` | exact-domain |
| `dashboard/beacon/previews.py` | service | file-I/O | `dashboard/app.py` | exact-domain |
| `dashboard/beacon/web.py` | controller | request-response | `dashboard/app.py` | exact-domain |
| `dashboard/beacon/worker_main.py` | controller | event-driven | `dashboard/worker.py` | exact |
| `dashboard/app.py` | compatibility shim | request-response | `dashboard/app.py` | self-modification |
| `dashboard/worker.py` | compatibility shim | event-driven | `dashboard/worker.py` | self-modification |
| `docker-compose.yml` | config | batch | `docker-compose.yml` | self-modification |
| `tests/fixtures/legacy/*.db` | fixture | file-I/O | none | no analog |
| `tests/test_migrations.py` | test | transform | `tests/test_release_contract.py` | partial |
| `tests/test_backup_recovery.py` | test | file-I/O | `tests/helpers.py` | partial |
| `tests/test_runtime_ownership.py` | test | event-driven | `tests/test_release_contract.py` | role-match |
| `tests/test_durable_queues.py` | test | event-driven | `tests/test_release_contract.py` | role-match |
| `tests/test_outbound_policy.py` | test | request-response | `tests/test_security_and_scanning.py` | role-match |
| `tests/test_api_and_auth.py` | test | request-response | self | self-modification |
| `tests/test_release_contract.py` | test | request-response | self | self-modification |

`tests/test_uptime_integration.py` and `tests/test_ui_contract.py` are contract analogs to expand only if their behavior changes.

## Pattern Assignments

### `dashboard/beacon/config.py` (config, transform)

**Analog:** `dashboard/app.py`

**Config parsing pattern** (lines 28-41, 49-83):

```python
DB_PATH = os.environ.get("DB_PATH", "/data/dashboard.db")
METRIC_SAMPLE_SECONDS = int(os.environ.get("METRIC_SAMPLE_SECONDS", 5))

for _port_text in os.environ.get("EXTRA_SCAN_PORTS", "8100").split(','):
    try:
        _extra_port = int(_port_text.strip())
        if 1 <= _extra_port <= 65535:
            EXTRA_SCAN_PORTS.add(_extra_port)
    except (TypeError, ValueError):
        pass
```

Move parsing out of `app.py`; use validated settings as the module interface, not mutable globals.

---

### `dashboard/beacon/db.py`, `migrations.py`, and `repositories.py` (service/migration/CRUD)

**Analogs:** `dashboard/app.py` lines 105-110, 117-125, 330-353, and 1908-1916.

**Connection pattern** (lines 105-110):

```python
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn
```

**Parameterised write pattern** (lines 1908-1916):

```python
conn.execute(
    "INSERT INTO service_meta (...) VALUES (...) "
    "ON CONFLICT(port) DO UPDATE SET ...",
    (...),
)
conn.commit()
conn.close()
```

No safe migration-registry analog exists. Retain these SQLite conventions, but replace additive startup DDL with an ordered immutable registry, one transaction per version, verified SQLite online backup before each schema-changing migration, and a worker-start gate. Keep SQL in repositories rather than routes/jobs.

---

### `dashboard/beacon/queues.py` (service, event-driven)

**Analog:** `dashboard/app.py` lines 1475-1578 and 1920-1924.

**Enqueue/claim pattern:**

```python
cur = conn.execute(
    "INSERT INTO scan_requests(requested_ts, requested_by, status) VALUES(?,?,'queued')",
    (now, str(client_key)[:120]),
)
request_id = cur.lastrowid
conn.commit()

row = conn.execute(
    "SELECT id FROM scan_requests WHERE status='queued' ORDER BY requested_ts, id LIMIT 1"
).fetchone()
conn.execute(
    "UPDATE scan_requests SET status='running', started_ts=? WHERE id=? AND status='queued'",
    (now, request_id),
)
```

Keep short transactional claims and status rows, but replace process-local lock ownership with persisted worker and row leases, expiry, attempts, and terminal `expired` status. Preserve latest-preview upsert behavior.

---

### `dashboard/beacon/outbound.py` (service, request-response)

**Analog:** `dashboard/app.py` lines 441-470, 578-617, and 625-660.

**URL validation pattern** (lines 441-463):

```python
parsed = urlparse(raw if '://' in raw else f"http://{raw}")
if parsed.scheme not in ("http", "https"):
    raise ValueError("URL must use http:// or https://")
if not parsed.hostname:
    raise ValueError("URL must include a host")
if parsed.username is not None or parsed.password is not None:
    raise ValueError("URL must not include user information")
```

**Redirect/error mapping pattern** (lines 585-617):

```python
resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
if 300 <= resp.status_code < 400:
    location = resp.headers.get('Location')
    if location:
        redirect_url = urljoin(url, location)
        # validate redirect before a further request
```

Keep stable `ValueError`/error-class contracts. Replace host-string-only checks and blanket `verify=False` with a purpose-aware plan that parses, resolves, and validates every address at every hop. The webhook must stay strict; its existing regression pattern is in `tests/test_release_contract.py` lines 254-264.

---

### `dashboard/beacon/monitoring.py` and `previews.py` (service, event-driven/file-I/O)

**Analog:** `dashboard/app.py` lines 1360-1473, 955 onward, and 1544-1578.

**Transition pattern** (lines 1446-1470):

```python
if previous_online != online_int:
    transitions.append({...})

for transition in transitions:
    _handle_state_transition(**transition)

_update_scan_state(**state_changes)
log.info("Uptime check complete (%s): %d services checked", ..., len(rows))
```

Keep monitoring/preview code Flask-free. All HTTP, HTML, and browser navigation must go through `outbound.py`; persist TLS posture separately from reachability.

---

### `dashboard/beacon/web.py` and `dashboard/app.py` (controller/compatibility shim, request-response)

**Analog:** `dashboard/app.py` lines 1631-1678 and 1841-2009.

**Mutation guard pattern** (lines 1657-1665):

```python
if not _is_trusted_request_host(_request_host()):
    return jsonify({'error': 'untrusted host'}), 400
if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
    if request.headers.get('X-Beacon-UI') != '1':
        return jsonify({'error': 'missing Beacon UI header'}), 403
    if not _origin_is_same_host():
        return jsonify({'error': 'unexpected origin'}), 403
```

**Route pattern:** Follow `api_service_meta` at lines 1841-1933: allowlisted input fields, explicit 400/404 responses, metadata commit before preview enqueue, and legacy response fields (`refresh_warning`, `preview_queued`).

`web.py` should provide a side-effect-free `create_app(settings)`. Keep `app.py` as the WSGI/legacy-import adapter but remove its import-time lifecycle at lines 1620-1628 and 2057-2063.

---

### `dashboard/beacon/worker_main.py` and `dashboard/worker.py` (controller/compatibility shim, event-driven)

**Analog:** `dashboard/worker.py` lines 19-111.

**Scheduler composition pattern** (lines 53-97):

```python
executors = {'metrics': ThreadPoolExecutor(1), 'probes': ThreadPoolExecutor(2)}
job_defaults = {'coalesce': True, 'max_instances': 1, 'misfire_grace_time': 15}
scheduler = BlockingScheduler(executors=executors, job_defaults=job_defaults, timezone='UTC')
scheduler.add_job(heartbeat, 'interval', seconds=5, executor='metrics', id='heartbeat')
```

Keep job IDs, pool bounds, coalescing, and cleanup signals (lines 43-45, 100-111). Move all startup execution from lines 48-98 into `main()`: migration preflight, durable owner-lease acquisition, recovery/gap record, scheduler composition, then start. `worker.py` becomes the CLI compatibility shim.

---

### `docker-compose.yml` (config, batch)

**Analog:** same file lines 1-28 and 48-81.

```yaml
user: "10001:10001"
read_only: true
volumes:
  - dashboard-data:/data
```

Keep the least-privilege and writable-volume contract. Change only the dependency/recovery wiring needed for web to stay reachable after a failed worker migration and one named offline recovery command.

---

### Tests and legacy fixtures

**Harness analog:** `tests/helpers.py` lines 51-78.

```python
fd, db_path = tempfile.mkstemp(prefix='beacon-test-', suffix='.db')
os.close(fd)
import dashboard.app as appmod
appmod = importlib.reload(appmod)
appmod.DB_PATH = db_path
appmod.init_db()
return appmod, db_path
```

**API contract:** `tests/test_api_and_auth.py` lines 14-24, 45-58, 83-102 — temporary real SQLite DB, `app.test_client()`, UI header, exact status/JSON-field assertions.

**Security seam:** `tests/test_security_and_scanning.py` lines 21-61 — substitute a tiny response/transport double, restore in `finally`, assert stable error classes.

**Durable state:** `tests/test_release_contract.py` lines 151-176 and 178 onward — seed real rows, run a domain operation, query SQLite, assert observable state.

Create `tests/fixtures/legacy/*.db` only after schema inventory; no existing fixture analog exists. Use the exact research-map test filenames.

## Shared Patterns

### SQLite durability and parameterization

**Source:** `dashboard/app.py` lines 105-110, 1475-1513, 1908-1916.  
**Apply to:** db, repositories, migrations, queues, monitoring, previews.

Use `sqlite3.Row`, busy timeout, foreign keys, parameterized values, short commits, and explicit close. Process-local locks can serialize worker threads but cannot establish cross-container ownership.

### Flask mutation boundary

**Source:** `dashboard/app.py` lines 1631-1678; `tests/test_release_contract.py` lines 113-129.  
**Apply to:** every mutation compatibility route.

Preserve trusted Host, same-origin, and `X-Beacon-UI: 1` checks before delegation.

### Stable errors and compatibility JSON

**Source:** `dashboard/app.py` lines 1848-1906 and 1999-2009.  
**Apply to:** web adapters and policy errors.

Return explicit `{"error": ...}` 400/403/404 responses and established 202/409/429 queue responses; do not expose raw exceptions.

### Worker-only lifecycle

**Source:** `dashboard/worker.py` lines 48-98; `dashboard/app.py` lines 1620-1628 and 2057-2063.  
**Apply to:** worker main/shim and web/app adapters.

The current app import initializes runtime and is the anti-pattern to remove. Only worker main may migrate, own work, start scheduling, create a browser, or do background I/O.

## No Analog Found

| File/capability | Role | Data Flow | Reason |
|---|---|---|---|
| verified backup/restore migration registry | migration | transform/file-I/O | Current initialization lacks ordered per-version transactional migrations and SQLite online backup verification. |
| `tests/fixtures/legacy/*.db` | fixture | file-I/O | No legacy/deployed SQLite fixture is tracked; support floor is explicitly pending inventory. |
| durable cross-process worker owner lease | service | event-driven | Existing queue states/process-local locks do not provide distributed lease semantics. |

## Metadata

**Analog search scope:** `dashboard/`, `tests/`, `docker-compose.yml`, git history  
**Files scanned:** 9 primary source/test/config files, plus phase context and research  
**Pattern extraction date:** 2026-07-24

