# Phase 3: Advanced Current Diagnosis - Pattern Map

**Mapped:** 2026-08-12  
**Files analyzed:** 12 planned new or modified files  
**Analogs found:** 12 / 12

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dashboard/app.py` | route/controller | request-response | `dashboard/app.py` `/api/telemetry/history`, `/api/services` | exact |
| `dashboard/advanced.html` | component/document shell | request-response | `dashboard/index.html` | role-match |
| `dashboard/advanced.js` | component/client controller | request-response | `dashboard/app.js` | role-match |
| `dashboard/advanced.css` | component styling | transform | `dashboard/style.css` | role-match |
| `dashboard/index.html` | component/document shell | event-driven | `dashboard/index.html` top bar | exact |
| `dashboard/app.js` | component/client controller | event-driven | `dashboard/app.js` theme initialization | exact |
| `dashboard/beacon/diagnosis.py` | service/read-model assembler | transform | `dashboard/beacon/telemetry.py` + `dashboard/beacon/repositories.py` | partial-match |
| `dashboard/beacon/repositories.py` | repository/service | CRUD | `dashboard/beacon/repositories.py` metadata/runtime helpers | exact |
| `dashboard/beacon/migrations.py` | migration | CRUD | `dashboard/beacon/migrations.py` migration 5 | exact |
| `dashboard/beacon/worker_main.py` | service/worker dispatcher | event-driven | `dashboard/beacon/worker_main.py::dispatch_callback` | exact |
| `tests/test_advanced_diagnosis_api.py` | test | request-response | `tests/test_api_and_auth.py` | exact |
| `tests/test_advanced_ui.py` | test | event-driven | `tests/test_ui_states.py` | exact |

## Pattern Assignments

### `dashboard/app.py` (route/controller, request-response)

**Analog:** existing static document adapters at `dashboard/app.py:2089-2101`, bounded read API at `dashboard/app.py:2175-2253`, and service projection at `dashboard/app.py:2256-2328`.

**Import / package fallback pattern** (`dashboard/app.py:20-43`): add `beacon.diagnosis` in both the package and Gunicorn fallback import branches; do not introduce a second app object.

**Route and JSON pattern** (`dashboard/app.py:2089-2101`, `2114-2124`):

```python
@app.route("/")
def index():
    return send_file("index.html", mimetype="text/html")

@app.route("/api/stats")
def api_stats():
    with _db_lock:
        conn = get_db()
        row = conn.execute("SELECT * FROM system_stats WHERE id=1").fetchone()
        conn.close()
    if row is None:
        return jsonify({'error': 'metrics not yet sampled'}), 503
    payload = dict(row)
    payload.pop('id', None)
    return jsonify(payload)
```

Add `/advanced`, `/advanced.js`, and `/advanced.css` static adapters beside the existing ones, then make `GET /api/advanced/current` call the diagnosis service once with `DB_PATH`, `SETTINGS`, and `int(time.time())`. Keep it GET-only.

**Validation/error boundary** (`dashboard/app.py:2175-2253`): validate any future query parameters before opening SQLite, return `{'error': str(exc)}`, 400 for `ValueError`, and retain `no-store` response behavior if copied from the telemetry route. The Phase 3 endpoint itself should need no mutating UI header because it is read-only.

**Security pattern** (`dashboard/app.py:2065-2086`): use the existing app-wide trusted-host middleware and after-request CSP headers; do not add page-local security exceptions.

---

### `dashboard/advanced.html` (component/document shell, request-response)

**Analog:** `dashboard/index.html:1-35`.

**Head/assets and safety-cluster pattern:**

```html
<link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script>

<div id="safety-warning-cluster" class="safety-warning-cluster" aria-label="Monitoring status">
  <div class="connection-banner safety-warning" id="connection-banner" role="alert" hidden>...</div>
  <div class="worker-warning safety-warning" id="worker-warning" role="status" aria-live="polite" hidden>...</div>
  <div class="recovery-warning safety-warning" id="recovery-warning" role="alert" hidden>...</div>
</div>
```

Copy the warning IDs and locked order exactly, then load `/advanced.js` and `/advanced.css`. Use semantic `header`, `nav`, `main`, section headings, native links/buttons/selects, a polite live region, and a real `table`/`thead`/`tbody` for Services. Never add inline scripts or remote assets.

---

### `dashboard/advanced.js` (component/client controller, request-response)

**Analog:** API/error helper at `dashboard/app.js:64-72`; accessible feedback and warning state at `79-107`; theme/poll bootstrapping at `413-438`.

**Fetch error pattern:**

```javascript
async function apiFetch(path, options = {}) {
  const response = await fetch(path, {cache: 'no-store', ...options});
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try { message = (await response.json()).error || message; } catch (_) { /* ignore */ }
    throw new Error(message);
  }
  return response.json();
}
```

**Theme pattern** (`dashboard/app.js:413-422`): preserve the `beacon-theme` key and same `.light` class contract:

```javascript
function applyTheme(light) {
  document.documentElement.classList.toggle('light', light);
  $('toggle').setAttribute('aria-pressed', String(light));
  localStorage.setItem('beacon-theme', light ? 'light' : 'dark');
}
```

Use a route-local state object for snapshot, poll timer, selected section, filters, sort, and expanded service ports. Store only explicit preferences under `beacon-advanced-preferences-v1`; keep expanded rows, errors, and live data memory-only. On a failed refresh, retain the last rendered snapshot and show the specified error copy—do not overwrite `lastSuccessTs`.

**DOM rendering pattern** (`dashboard/app.js:272-287`): build dynamic rows with `document.createElement`, `.textContent`, `.replaceChildren()`, and event listeners rather than string HTML. Use `Set` for multi-expanded rows, buttons with `aria-expanded` for details, and buttons with `aria-sort` plus the existing polite status-region approach for sorting announcements.

---

### `dashboard/advanced.css` (component styling, transform)

**Analog:** design tokens at `dashboard/style.css:1-41`, safety styling at `59-74`, and narrow breakpoint structure at `944-1039`.

**Token and dual-theme pattern:**

```css
html {
  --bg: #010a14; --bg2: #030f1e; --bg3: #041525;
  --accent: #00d4ff; --accent2: #ffab00; --green: #00ff88; --red: #ff3d3d;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}
html.light { --bg: #ffffff; --bg3: #f7f7f7; --accent: #0066cc; --green: #16a34a; --red: #dc2626; }
```

Layer only advanced selectors on these variables. Implement the UI contract’s `960px` rail-to-horizontal-tabs breakpoint and `720px` summary stack; preserve 44px minimum controls, `overflow-wrap:anywhere`, horizontal table scrolling, and a sticky Name + port cell below desktop width.

---

### `dashboard/index.html` and `dashboard/app.js` (existing dashboard navigation, event-driven)

**Analog:** topbar at `dashboard/index.html:18-27`; theme initialization at `dashboard/app.js:413-438`.

Insert an ordinary same-tab `<a href="/advanced">Advanced diagnosis</a>` in the existing topbar, and add a narrowly scoped click handler only if needed to store dashboard scroll position in `sessionStorage`. Do not alter the dashboard polling, warning markup/order, or `beacon-theme` behavior.

---

### `dashboard/beacon/diagnosis.py` (service/read-model assembler, transform)

**Analog:** bounded repository ownership statement at `dashboard/beacon/repositories.py:1-5`, transaction context at `dashboard/beacon/db.py:115-129`, and telemetry policy/read helpers in `dashboard/beacon/telemetry.py`.

**Transaction composition pattern:**

```python
with read_transaction(db_path) as conn:
    host = read_current_host(conn)
    services = read_service_diagnoses(conn, now=now)
    pipeline = read_pipeline_diagnosis(conn, policy=policy, now=now)
    jobs = read_background_job_health(conn)
```

Keep this module pure from Flask, scheduler, browser, and connection lifetime. It should normalize timestamps/cadences and return one stable `{generated_ts, host, services, pipeline, settings, exceptions}` snapshot. Derive `fresh`/`aging`/`stale`/`unknown` on the server using cadence evidence, without attributing stale data to a failure cause.

---

### `dashboard/beacon/repositories.py` (repository/service, CRUD)

**Analog:** parameterized metadata upsert at `dashboard/beacon/repositories.py:586-599`, runtime JSON state at `602-625`, and latest-event bounded query at `633-646`.

**Parameterized upsert pattern:**

```python
conn.execute(
    "INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) "
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts",
    (key, json.dumps(value, separators=(',', ':')), updated_ts),
)
```

New diagnosis readers receive an open `conn`, use fixed SQL shapes and bound values, and return rows/data without committing. Add job-outcome writers here for worker use, keyed by immutable callback identifier; writers must be called inside the worker’s authority-fenced transaction seam, never from web routes.

---

### `dashboard/beacon/migrations.py` (migration, CRUD)

**Analog:** grouped schema/index migration at `dashboard/beacon/migrations.py:212-288`; ordered registry at `479-486`; atomic runner at `564-635`.

Add one new monotonically numbered migration for `background_job_health` and its diagnosis indexes. Keep DDL in a migration helper, add its `Migration(version, name, True, helper)` entry to `MIGRATIONS`, and rely on the existing backup, `BEGIN IMMEDIATE`, rollback/recovery-marker flow rather than ad-hoc `CREATE TABLE` calls in app or worker code.

---

### `dashboard/beacon/worker_main.py` (service/worker dispatcher, event-driven)

**Analog:** immutable callback inventory at `dashboard/beacon/worker_main.py:75-93`, `WorkerServices` dependency binding at `140-184`, and dispatch authority handling at `233-247`.

**Authority/error pattern:**

```python
with services.admission.admit(callback.admission_category) as admitted:
    if not admitted:
        return None
    try:
        return _invoke_callback(services, callback)
    except queues.LeaseLost:
        log.error('Beacon worker lease lost; stopping stale scheduler')
        services.admission.close_admission()
        stop_worker()
        return False
```

Record job start/success/failure around `_invoke_callback` only after admission succeeds and under the existing worker authority. Preserve the special `LeaseLost` behavior exactly: never swallow it, never mark it a success, and never permit web-owned writing. Derive schedule/cadence from `WORKER_CALLBACK_INVENTORY` and the existing `build_scheduler` mapping (`297-325`) rather than duplicating it.

---

### `tests/test_advanced_diagnosis_api.py` (test, request-response)

**Analog:** `tests/test_api_and_auth.py:16-45`.

```python
def setUp(self):
    self.appmod, self.db_path = load_app({...})
    self.client = self.appmod.app.test_client()

def tearDown(self):
    cleanup_db(self.db_path)
```

Seed deterministic SQLite evidence using `_db_lock`, `get_db()`, parameterized inserts, commit, and close. Assert exact snapshot fields and stale-boundary semantics, GET-only behavior, read-only operation, job failure/no-false-success evidence, and distinct gap/pending/expired/unknown vocabulary.

---

### `tests/test_advanced_ui.py` (test, event-driven)

**Analog:** source contracts at `tests/test_ui_states.py:14-83` and fixture-routed Playwright harness at `85-161`.

**Playwright fixture pattern:**

```python
page.route('**/api/**', route_api)
page.goto(self.base_url, wait_until='networkidle')
```

Read advanced HTML/JS/CSS source for stable DOM hooks and absence of mutation controls. Use deterministic `/api/advanced/current` fixtures for desktop/narrow, light/dark theme continuity, warning order, error retention, filters, keyboard sorting, multi-row disclosure, and scroll-return behavior.

## Shared Patterns

### Request security

**Source:** `dashboard/app.py:2065-2086`  
**Apply to:** `/advanced` asset and API routes through existing Flask hooks.

The trusted-host check and global CSP/security headers already protect all route responses. Advanced diagnosis must remain GET-only, so it must not create a special mutation or UI-header pathway.

### SQLite transaction ownership

**Source:** `dashboard/beacon/db.py:115-129`  
**Apply to:** diagnosis assembly, repository writes, and migrations.

```python
@contextmanager
def read_transaction(settings_or_path):
    with database_access(settings_or_path) as conn:
        yield conn

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

### Safety warnings and theme continuity

**Source:** `dashboard/index.html:29-33`, `dashboard/app.js:90-107`, `dashboard/app.js:413-422`  
**Apply to:** dashboard link and advanced document.

Keep connection, worker, then recovery as independent warnings. Keep `beacon-theme` untouched; advanced-specific preferences use a different versioned storage key.

### Parameterized, bounded SQL

**Source:** `dashboard/beacon/repositories.py:559-570`, `633-646`  
**Apply to:** diagnosis service/readers.

Use `?` parameters, fixed SQL identifiers, `ORDER BY` and `LIMIT` for current evidence. Do not call legacy `/api/services` or load its seven-day check bucket history on every advanced refresh.

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `dashboard/beacon/diagnosis.py` | service/read-model assembler | transform | No existing single snapshot composer; compose existing repositories, telemetry, and transaction boundaries. |
| `dashboard/advanced.js` | component/client controller | request-response | No separate route-local SPA module; copy the dependency-free dashboard helper/rendering conventions. |

## Metadata

**Analog search scope:** `dashboard/`, `dashboard/beacon/`, and `tests/`  
**Files scanned:** 18 source and test files  
**Pattern extraction date:** 2026-08-12
