# Phase 4: Historical Investigation - Pattern Map

**Mapped:** 2026-08-25
**Files analyzed:** 8 (5 modified, 3 new)
**Analogs found:** 8 / 8

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|----------------|
| `dashboard/beacon/incidents.py` (NEW) | service | CRUD (read/group) | `dashboard/beacon/telemetry.py` (composition) + `dashboard/beacon/repositories.py` (query) | role-match |
| `dashboard/app.py` — `GET /api/events/history` (NEW route) | route/controller | request-response | `dashboard/app.py:2508` `api_telemetry_history` | exact |
| `dashboard/app.py` — `/api/config` extension (`timezone`) | route/controller | request-response | `dashboard/app.py:2441` `api_config` | exact |
| `dashboard/advanced.html` — History/Incidents sections + nav entries | component (markup) | request-response | `dashboard/advanced.html:32-78` section-navigation + `services-section` | exact |
| `dashboard/advanced.js` — range/investigation state module | store/provider | event-driven | `dashboard/advanced.js:1-45` preferences state + `dashboard/advanced.js:832-850` `selectSection` | exact |
| `dashboard/advanced.js` — chart/coverage-strip renderer | component | transform | `dashboard/app.js:132-141` `updateHistory` sparkline | role-match (must be extended, not copied as-is) |
| `dashboard/advanced.js` — Incidents filter/list renderer | component | CRUD (read) | `dashboard/advanced.js:895-919` service-filters wiring + `dashboard/advanced.js:~700-800` `renderServices` row builder | exact |
| `dashboard/advanced.css` — chart/coverage-strip/state-band/incident-row styles | config/styling | n/a | `dashboard/advanced.css` `.evidence-row`/`.diagnosis-card`/`.service-filters` classes | role-match |

## Pattern Assignments

### `dashboard/beacon/incidents.py` (NEW — service, CRUD/grouping)

**Analog:** `dashboard/beacon/telemetry.py` (module shape, docstring convention) composed with the query pattern already used for events in `dashboard/app.py:2687-2724` (`api_events`).

**Query pattern to extend** (`dashboard/app.py:2705-2724`, verbatim column set — reuse exactly, add `WHERE ts BETWEEN ? AND ?` plus `port`/`event_type`/criticality filters):
```python
rows = conn.execute(
    "SELECT e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
    "e.latency_ms, e.error_class, e.alert_status, e.details, "
    "e.suppressed_reason, e.maintenance_grace_until, e.down_since_ts, "
    "COALESCE(m.display_name, s.title, ':' || e.port) AS service_name "
    "FROM events e "
    "LEFT JOIN services s ON s.port = e.port "
    "LEFT JOIN service_meta m ON m.port = e.port "
    "WHERE e.ts > ? "
    "ORDER BY e.ts DESC, e.id DESC LIMIT ?",
    (since_ts, limit),
).fetchall()
```

**Grouping function shape** (server classifies, per `dashboard/beacon/diagnosis.py`'s established split — server classifies, UI renders). Write `group_episodes(rows)` in the new module following this shape (from RESEARCH.md Pattern 4, verified against the events schema at `dashboard/beacon/migrations.py:115-146,540-571`):
```python
def group_episodes(rows):
    """rows: state_change events ordered by ts ASC for one port.
    Returns closed episodes (down_ts, recovered_ts, ...) plus at most one open
    episode (down_ts set, recovered_ts=None) if the service is still down —
    never a synthesized 'end' timestamp (D-12 Pitfall 4)."""
    episodes = []
    open_episode = None
    for row in rows:
        if row['online'] == 0:
            open_episode = {'down_ts': row['down_since_ts'] or row['ts'], 'recovered_ts': None, 'events': [row]}
        elif open_episode is not None:
            open_episode['recovered_ts'] = row['ts']
            open_episode['events'].append(row)
            episodes.append(open_episode)
            open_episode = None
    if open_episode is not None:
        episodes.append(open_episode)
    return episodes
```

**Validation pattern to reuse** — `HistoricalRange` (`dashboard/beacon/telemetry.py:29-42`) already rejects inverted/>90-day ranges; call it from the new route rather than writing new bounds logic.

---

### `dashboard/app.py` — `GET /api/events/history` (NEW route)

**Analog:** `dashboard/app.py:2472-2580` (`_parse_history_timestamp`, `_history_selector`, `api_telemetry_history`)

**Imports/validation pattern** (lines 2472-2503, reuse verbatim structure for `start_ts`/`end_ts`; extend with an `event_type`/`criticality` allowlist check the same way `_history_selector` validates `kind`):
```python
def _parse_history_timestamp(name):
    values = request.args.getlist(name)
    if len(values) != 1:
        raise ValueError(f'{name} must be supplied exactly once')
    value = values[0]
    if value is None or not value.isascii() or not value.isdecimal():
        raise ValueError(f'{name} must be a decimal integer')
    return int(value)
```

**Route/error-handling pattern** (lines 2508-2534, two-phase try/except — validation errors return 400 before any DB access, DB-touching errors return 400 after):
```python
@app.route('/api/telemetry/history')
def api_telemetry_history():
    try:
        kind, metric, port = _history_selector()
        requested = beacon_telemetry.HistoricalRange(
            _parse_history_timestamp('start_ts'),
            _parse_history_timestamp('end_ts'),
        )
        now = int(time.time())
        if requested.end_ts > now:
            raise ValueError('end_ts must not be in the future')
        ...
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    try:
        with _db_lock, database_access(DB_PATH) as conn:
            ...
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({...})
```

**`_db_lock` pattern:** every DB-touching route in this file takes `with _db_lock, database_access(DB_PATH) as conn:` (37 call sites, e.g. `dashboard/app.py:2534,2589,2702`). The new `/api/events/history` route must follow this — AR-03-01's exception for `api_advanced_current` does not extend to new routes (per RESEARCH.md Security Domain).

---

### `dashboard/app.py` — `/api/config` extension

**Analog:** `dashboard/app.py:2440-2447` (`api_config`) — additive, parameterless GET, no DB access:
```python
@app.route("/api/config")
def api_config():
    return jsonify({
        "alerting_enabled": bool(ALERT_WEBHOOK_URL),
        "uptime_buckets": UPTIME_BUCKETS,
        "trigger_rate_limit": TRIGGER_SCAN_RATE_LIMIT,
        "trigger_rate_window_seconds": TRIGGER_SCAN_WINDOW_SECONDS,
    })
```
Add `"timezone": SETTINGS.timezone` to this dict (per D-05/Research Pitfall 1) — the minimal, additive change; no other structure changes.

---

### `dashboard/advanced.html` — History/Incidents sections + nav entries

**Analog:** `dashboard/advanced.html:32-78` (nav rail + section shell)

**Nav pattern** (lines 32-37, insert two new `<button>` entries between `services` and `pipeline`, exact attribute shape):
```html
<nav id="section-navigation" class="section-navigation" aria-label="Advanced diagnosis sections">
  <button type="button" data-section="overview" aria-controls="overview-section" aria-selected="true">Overview</button>
  <button type="button" data-section="host" aria-controls="host-section" aria-selected="false">Host</button>
  <button type="button" data-section="services" aria-controls="services-section" aria-selected="false">Services</button>
  <!-- NEW: history, incidents inserted here per UI-SPEC nav ordering -->
  <button type="button" data-section="pipeline" aria-controls="pipeline-section" aria-selected="false">Pipeline</button>
  <button type="button" data-section="settings" aria-controls="settings-section" aria-selected="false">Settings</button>
</nav>
```

**Section shell pattern** (line 44, `hidden` attribute toggled by `selectSection`, `aria-labelledby` + focusable `h2`):
```html
<section id="host-section" aria-labelledby="host-heading" hidden>
  <h2 id="host-heading" tabindex="-1">Host</h2>
  ...
</section>
```
New `history-section` and `incidents-section` must follow this exact `hidden` + `aria-labelledby` + focusable-heading shape so `selectSection` (advanced.js) works unmodified.

**Filter form pattern** (`dashboard/advanced.html:51-57`, `service-filters` — copy this shape for the Incidents filter form):
```html
<form id="service-filters" class="service-filters" aria-label="Filter current service diagnosis">
  ...
  <button type="button" id="clear-service-filters">Clear all filters</button>
</form>
```

---

### `dashboard/advanced.js` — range/investigation state module

**Analog:** `dashboard/advanced.js:1-45` (preferences load/save/validate) + `dashboard/advanced.js:832-850` (`selectSection`)

**Preference schema + validation pattern** (lines 2-3, 17-33 — extend `DEFAULT_PREFERENCES` and `loadPreferences`/`savePreferences` with new validated keys, never trust stored values without a whitelist check):
```javascript
const PREFS_KEY = 'beacon-advanced-preferences-v1';
const DEFAULT_PREFERENCES = {refreshSeconds: 15, paused: false, density: null, range: '24h', filters: {}};
// Phase 4 additions (validated the same way as refreshSeconds/density above):
//   historyRange: {preset: '1h'|'6h'|'24h'|'7d'|'30d'|'90d'} | {custom: {start_ts, end_ts}}
//   historyFilters: {service, criticality, eventType, ...} — validated against an allowlist like validFilters()
//   selectedService: port|null

function loadPreferences() {
  let stored = {};
  try {
    const candidate = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}');
    stored = candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate : {};
  } catch (_) { /* malformed browser-local data uses documented defaults */ }
  const refreshSeconds = REFRESH_CHOICES.has(stored.refreshSeconds) ? stored.refreshSeconds : DEFAULT_PREFERENCES.refreshSeconds;
  state.preferences = { refreshSeconds, /* ...validated fields... */ };
  return state.preferences;
}
```

**Section-switch pattern** (lines 832-846 — reuse this exact function for `History`/`Incidents` nav entries, no modification needed since it's already generic over `data-section`/`{section}-heading`/`{section}-section`):
```javascript
function selectSection(section) {
  const heading = $(`${section}-heading`);
  if (!heading) return;
  state.activeSection = section;
  document.querySelectorAll('#section-navigation button').forEach((button) => {
    button.setAttribute('aria-selected', String(button.dataset.section === section));
  });
  document.querySelectorAll('.advanced-detail > section').forEach((node) => { node.hidden = node.id !== `${section}-section`; });
  heading.focus();
  $('advanced-status').textContent = `${heading.textContent} selected`;
}
```

**Fetch + error-partial-isolation pattern** (`dashboard/advanced.js`'s `apiFetch`/`refreshCurrentDiagnosis`, lines ~55-820 — reuse the try/catch + `requestGeneration` staleness-guard idiom for the four parallel host-metric fetches, per RESEARCH.md Pattern 1's `Promise.allSettled` composition):
```javascript
async function apiFetch() {
  const response = await fetch('/api/advanced/current', {cache: 'no-store'});
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    // ...error text extraction, thrown as Error(message)
  }
  return response.json();
}
```
Extend this per-metric (own try/catch per `fetch('/api/telemetry/history?...')` call) so one metric's failure never blocks the other three (RESEARCH.md Pattern 1, Copywriting Contract "Error state (chart fetch failed)").

---

### `dashboard/advanced.js` — chart/coverage-strip renderer (NEW logic, extends sparkline precedent)

**Analog:** `dashboard/app.js:132-141` (`updateHistory`) — **this is the ONLY existing chart precedent; it must be extended with gap-awareness, not copied as-is** (RESEARCH.md "State of the Art": the sparkline's always-connect-every-point behavior is explicitly superseded for Phase 4).

**What to copy — the inline-SVG-path-construction idiom:**
```javascript
function updateHistory(rows) {
  for (const key of ['cpu', 'ram', 'disk']) {
    const values = rows.slice(-80).map((row) => Math.max(0, Math.min(100, Number(row[key] || 0))));
    if (!values.length) continue;
    const points = values.map((value, i) => `${(i / Math.max(1, values.length - 1)) * 200},${40 - value * 0.4}`).join(' ');
    const linePoints = points.replaceAll(' ', ' L');
    $(`${key}-sparkline`).setAttribute('d', `M${linePoints}`);
    $(`${key}-sparkfill`).setAttribute('d', `M0,40 L${linePoints} L200,40 Z`);
  }
}
```

**What must NOT be copied — the missing gap-break logic.** Per D-06/RESEARCH.md Pattern 3, replace the single `M...L...L...` path build with a pen-up/pen-down loop gated on `coverage[i].state === 'observed'`:
```javascript
function buildPath(points, coverageIntervals) {
  const isObserved = (ts) => coverageIntervals.some((c) => c.start_ts <= ts && ts < c.end_ts && c.state === 'observed');
  let d = '';
  let penDown = false;
  for (const p of points) {
    const cmd = penDown && isObserved(p.bucket_start) ? 'L' : 'M';
    d += `${cmd}${xFor(p.bucket_start)},${yFor(p.value)} `;
    penDown = true;
  }
  return d.trim();
}
```

**Coverage-strip segment classification** (branches on `(state, detail)` together per D-06/UI-SPEC Chart Contract table):
```javascript
function stripSegmentFor(interval) {
  if (interval.state === 'collection_gap' && interval.detail === 'storage_pressure') {
    return { pattern: 'diagonal-hatch', label: 'Storage pressure (no persistence)' };
  }
  if (interval.state === 'collection_gap') return { pattern: 'dots', label: 'Collection gap' };
  if (interval.state === 'unknown') return { pattern: 'dashed', label: 'Unknown' };
  if (interval.state === 'expired') return { pattern: 'diagonal-thin', label: 'Expired (outside retention)' };
  if (interval.state === 'not_yet_monitored') return { pattern: 'solid-muted', label: 'Not yet monitored' };
  return null; // 'observed' — no strip segment, chart line drawn
}
```

**Hover cursor / pointer-throttle pattern (no existing analog — new, per RESEARCH.md Pitfall 3):** update only cursor/tooltip DOM node attributes inside a `requestAnimationFrame` callback coalescing `pointermove` events; never regenerate chart `<path>` `d` attributes on hover or drag.

---

### `dashboard/advanced.js` — Incidents filter/list renderer

**Analog:** `dashboard/advanced.js:895-919` (filter-control wiring) + row-builder pattern at `dashboard/advanced.js:~700-800` (`renderServices`/`addEvidence`)

**Filter wiring pattern** (lines 895-919 — reuse verbatim shape, swap the filter key set for `{service, criticality, eventType, time}`):
```javascript
const filterControls = {
  query: $('service-search'), status: $('service-status-filter'), criticality: $('service-criticality-filter'),
  freshness: $('service-freshness-filter'), tags: $('service-tag-filter'),
};
Object.entries(filterControls).forEach(([key, control]) => control.addEventListener(key === 'query' ? 'input' : 'change', () => {
  state.filters = {...state.filters, [key]: control.value};
  if (!control.value) delete state.filters[key];
  savePreferences();
  renderServices();
}));
$('clear-service-filters').addEventListener('click', () => {
  state.filters = {};
  savePreferences();
  renderServices();
  $('advanced-status').textContent = 'All service filters cleared; operational order restored';
});
```

**Evidence-row / expand-on-click pattern** (`addEvidence` calls at `dashboard/advanced.js:775-796`, `detailRow.hidden = !expanded` toggle) — reuse for the incident row's `Show transitions` disclosure (`aria-expanded`, per UI-SPEC Incidents Contract):
```javascript
addEvidence(evidence, 'Maintenance', formatMaintenanceEvidence(service.maintenance));
const overrun = service.overrun && typeof service.overrun === 'object' ? service.overrun : null;
if (overrun) {
  addEvidence(evidence, 'Down since', displayTimestamp(overrun.down_since_ts));
  addEvidence(evidence, 'Raised at', displayTimestamp(overrun.raised_at_ts));
}
```
This is also the exact D-14 overrun-row precedent — the two-timestamp, never-merged-into-one-string pattern the Incidents row must reuse.

---

### `dashboard/advanced.css` — chart/coverage-strip/state-band/incident-row styles

**Analog:** existing `.evidence-row`, `.diagnosis-card`, `.service-filters` class families in `dashboard/advanced.css`.

**Pattern:** new class names extend these families rather than starting a competing vocabulary (per UI-SPEC Design System) — e.g. `.hist-chart`, `.hist-coverage-strip`, `.incident-row` should reuse the existing custom properties (`--bg`, `--bg2`, `--bg3`, `--accent`, `--accent3`, `--green`, `--red`, `--muted`, `--border2`, `--font-mono`) declared in `dashboard/style.css:5-21,24-37` — no new CSS custom property is introduced.

---

## Shared Patterns

### `_db_lock` + `database_access(DB_PATH)` — every new DB read
**Source:** `dashboard/app.py` (37 existing call sites, e.g. lines 2534, 2589, 2702, 2894)
**Apply to:** `/api/events/history` (new route), any DB access inside `beacon/incidents.py` callers in `app.py`.
```python
with _db_lock, database_access(DB_PATH) as conn:
    ...
```
AR-03-01's exception for `api_advanced_current` (accepted risk, not taking `_db_lock`) does NOT extend to new routes per RESEARCH.md Security Domain — new routes take the lock unless a documented reason argues otherwise.

### Two-phase try/except: validate-before-DB, then DB-errors-separately
**Source:** `dashboard/app.py:2510-2534` (`api_telemetry_history`)
**Apply to:** `/api/events/history` — validation `ValueError`s return 400 before opening SQLite; a second try/except wraps the DB-touching block and also returns 400 on `ValueError`.

### Validated browser-local preferences, versioned key
**Source:** `dashboard/advanced.js:1-33` (`PREFS_KEY`, `DEFAULT_PREFERENCES`, `loadPreferences`)
**Apply to:** History range/filter/selected-service persistence (D-04, D-18) — every new preference field must have an explicit allowlist/type check in `loadPreferences`, mirroring `REFRESH_CHOICES.has(...)` and `validFilters(...)`.

### Section shell + nav wiring (generic, no change needed)
**Source:** `dashboard/advanced.js:832-846` (`selectSection`), `dashboard/advanced.html:32-78`
**Apply to:** `History` and `Incidents` nav entries and sections — the existing function is already generic over `data-section`/`{section}-heading`/`{section}-section`; only markup needs to be added, not JS logic.

### Server classifies, UI renders (no client-side recomputation)
**Source:** `dashboard/beacon/diagnosis.py` (established split, referenced in RESEARCH.md Architectural Responsibility Map)
**Apply to:** `beacon/incidents.py`'s `group_episodes` — grouping, open/flapping classification happen server-side; `advanced.js` only renders the returned `episodes[]`/`events[]`.

### Bare `toLocaleString()` — explicit anti-pattern, do not copy
**Source:** `dashboard/advanced.js:87`, `dashboard/app.js:34` (both render in browser-local time, not the Pi's configured timezone)
**Apply to:** every Phase 4 timestamp display — use `Intl.DateTimeFormat(undefined, { timeZone: cfg.timezone, ... })` once `/api/config` exposes `timezone` instead.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| Drag-to-select handler (advanced.js) | component | event-driven | No existing pointer/drag interaction anywhere in the codebase; must be built from RESEARCH.md Pitfall 3 guidance (rAF-throttled, selection-rectangle-only updates) with no in-repo precedent |
| Navigation stack (push/pop for incident focus + drag-select, D-15) | store | event-driven | No existing "stack of prior states" pattern in `advanced.js`; closest conceptual analog is the preferences object but it has no history/undo semantics — build fresh per D-15's spec |
| Hover time cursor synced across stacked charts (D-17) | component | event-driven | No existing multi-chart cross-hair/cursor pattern; the only prior interactive chart (`app.js:139` sparkline) has no hover behavior at all |
| Least-squares trend slope computation (D-08) | utility | transform | No existing statistical/slope computation anywhere in `dashboard/app.js` or `advanced.js`; a ~10-line closed-form function must be written fresh per RESEARCH.md "Don't Hand-Roll" guidance |

## Metadata

**Analog search scope:** `dashboard/app.py`, `dashboard/advanced.js`, `dashboard/advanced.html`, `dashboard/advanced.css`, `dashboard/app.js`, `dashboard/beacon/telemetry.py`, `dashboard/beacon/repositories.py`, `dashboard/beacon/diagnosis.py`, `dashboard/beacon/migrations.py`
**Files scanned:** 9
**Pattern extraction date:** 2026-08-25
