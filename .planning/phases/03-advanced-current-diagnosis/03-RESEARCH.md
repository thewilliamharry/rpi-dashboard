# Phase 3: Advanced Current Diagnosis - Research

**Researched:** 2026-08-12
**Domain:** Read-only current-state monitoring workspace on Flask, SQLite WAL, APScheduler, and dependency-free browser JavaScript
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

<!-- DATA_Q7m2Lp9V_START -->
### Locked Decisions

## Implementation Decisions

### Workspace Structure

- **D-01:** Use an overview-first workspace with drill-down sections for Overview, Host, Services, Pipeline, and Settings.
- **D-02:** Lead the overview with active exceptions and degraded components, followed by compact Host, Services, and Collection Health summaries.
- **D-03:** Keep persistent section navigation visible while the selected section replaces the main detail area.
- **D-04:** Open the advanced workspace in the same tab at `/advanced`, provide a clear Dashboard return, preserve theme and explicit advanced preferences, and restore the dashboard's prior scroll position when practical.

### Service Diagnosis

- **D-05:** Present every service in one compact, sortable table with expandable diagnostic rows rather than reusing the main dashboard's preview-card grid.
- **D-06:** Default to operational-priority ordering: critical failures, other failures, stale or unknown services, then healthy services. Preserve configured pinned order within each group.
- **D-07:** Keep name and port, status, latency or failure class, state duration, criticality, and freshness visible in the collapsed row. Put tags and the full effective health rule in expanded detail.
- **D-08:** Allow multiple service rows to remain expanded for comparison and provide a collapse-all action.

### Freshness and Warning Priority

- **D-09:** Keep simultaneous safety, freshness, and pipeline conditions distinct. Preserve the established connection, worker, and recovery safety-warning cluster, then summarize other active exceptions globally with details in the affected section.
- **D-10:** Describe host and service freshness as `fresh`, `aging`, `stale`, or `unknown`, show relative age, and expose the exact sample timestamp and expected cadence in detail.
- **D-11:** Do not infer a failed cause from stale data alone. When a stream is stale but the worker heartbeat is fresh, report both observations and expose cadence and background-job evidence for diagnosis.
- **D-12:** Promote collection gaps to the global exception summary only while they are actionable: open gaps or recent gaps that indicate an ongoing problem. Keep resolved older gaps available in Pipeline detail.

### Preferences and Controls

- **D-13:** Use predictable auto-refresh with a visible, selectable fixed interval, Pause, Refresh now, and a clear last-updated time.
- **D-14:** Persist explicit preferences in browser-local storage: theme, refresh interval, presentation density, range, and filters. Do not restore expanded rows or transient warning selections.
- **D-15:** Provide search by service name, port, or tag plus combinable status, criticality, freshness, and tag filters. Always show the matching count and a clear-all action.
- **D-16:** Use theme-aware density defaults: comfortable in light mode and compact in dark mode. Either theme may override density without losing any capability.

### the Agent's Discretion

- Choose exact refresh-interval choices and freshness thresholds, grounded in the configured sampling and probe cadences.
- Choose responsive behavior for the persistent navigation and service table at narrow widths while preserving access to all fields.
- Choose the internal frontend and API module boundaries, accessibility mechanics, and browser-storage key/versioning scheme.
- Choose the exact visual styling and wording within the locked hierarchy and the existing calm-light/dense-dark product direction.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
<!-- DATA_Q7m2Lp9V_END -->
</user_constraints>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TEL-06 | See effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health. | One bounded pipeline read model combines `RetentionPolicy`, durable pressure/coverage/stream evidence, and durable per-job outcomes. |
| DIA-01 | Open a dedicated advanced analytics and monitoring page from either theme. | Add `/advanced` with separate static assets; use the existing `beacon-theme` key unchanged. |
| DIA-02 | Inspect current host metrics, identity, sample time, and freshness. | Read `system_stats` and derive freshness from server time plus `METRIC_SAMPLE_SECONDS`. |
| DIA-03 | Inspect every service's current diagnostic fields. | One bounded services query plus latest probe/stream evidence produces table and expanded-detail fields. |
| DIA-08 | See settings and change supported local presentation preferences without remote control. | Read-only effective-settings payload; browser-only versioned preferences; no POST/PUT controls in advanced assets. |
| UX-02 | Move between dashboard and advanced analytics without losing theme choice. | Same-tab links, existing theme key, and one-shot dashboard scroll restoration. |

## Project Constraints (from AGENTS.md)

- Keep Beacon self-contained on a 64-bit Raspberry Pi using Docker Compose. [VERIFIED: AGENTS.md]
- Restrict monitoring to the host Pi and configured/discovered trusted LAN or web services; do not add fleet management. [VERIFIED: AGENTS.md]
- Keep outbound fetching and mutation endpoints narrowly testable even on the trusted LAN. [VERIFIED: AGENTS.md]
- Preserve 90-day bounded telemetry retention, theme parity of existing compact previews, stored-data compatibility, and Pi responsiveness. [VERIFIED: AGENTS.md]
- Use explicit, testable module boundaries instead of enlarging the existing monolith. [VERIFIED: AGENTS.md]
- Use readable PEP 8 Python, lowercase snake-case modules/functions, narrow expected-error handling, Flask JSON status responses, and pytest's current temporary-SQLite/test-client patterns. [VERIFIED: AGENTS.md]
- Do not introduce direct repository edits outside the GSD workflow; this research artifact is produced through the active planning workflow. [VERIFIED: AGENTS.md]

## Summary

Phase 3 is a read-model and workspace phase, not a monitoring rewrite. Beacon already persists the current host sample, service state/probe result, worker heartbeat, retention pressure, telemetry stream cadence, coverage intervals, and worker callback schedule. The missing implementation is a stable, bounded diagnosis projection that joins these facts without issuing a probe, starting a scheduler, loading preview bytes, or scanning retained history. [VERIFIED: codebase grep]

Use a dedicated `GET /api/advanced/current` endpoint that opens one short SQLite read, builds a versioned payload, and closes the connection before JSON serialization. The page may poll that endpoint at the chosen browser cadence; it must never call the mutation routes or ask the worker to perform work. WAL permits concurrent reading/writing, but a reader sees a snapshot and an overlong reader can hold checkpoint progress, making small bounded queries essential on Pi hardware. [CITED: https://www.sqlite.org/wal.html]

The one material data gap is background-job health: the scheduler inventory declares cadence and job identity, but job success/failure/last-run evidence is not currently durable. Add a small, worker-owned `background_job_health` persistence seam, updated around the existing callback dispatch, then expose it only through the diagnosis read model. Do not read a process-local APScheduler object from the web container: the web and worker are deliberately separate processes. [VERIFIED: dashboard/beacon/worker_main.py]

**Primary recommendation:** Build a new, versioned, GET-only current-diagnosis read model backed by one bounded SQLite snapshot and durable job-health rows; add `/advanced` as an independently testable vanilla-JS page that reuses the existing theme and safety-warning contract.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| `/advanced` document, section state, filtering, sorting, disclosures, preferences | Browser / Client | Frontend Server | These are presentation-only interactions; filters/sorts act on the already bounded payload and preferences stay local. [VERIFIED: UI-SPEC.md] |
| Route and diagnosis snapshot projection | API / Backend | Database / Storage | Flask owns same-origin route/security middleware; SQL/read-model helpers own durable facts and no worker effects. [VERIFIED: dashboard/app.py] |
| Current host/service, retention, stream/gap, pressure evidence | Database / Storage | API / Backend | `system_stats`, `services`, `telemetry_*`, and `runtime_state` are the durable source of truth across web and worker processes. [VERIFIED: dashboard/beacon/migrations.py] |
| Heartbeat, probes, retention cleanup, and durable job result updates | API / Backend | Database / Storage | The worker owns scheduled callbacks and writes them under durable authority; browser/API reads must not take ownership. [VERIFIED: dashboard/beacon/worker_main.py] |
| Dashboard-to-advanced navigation and scroll restoration | Browser / Client | — | Same-tab navigation, `sessionStorage`, focus, and existing local theme key are browser concerns. [VERIFIED: UI-SPEC.md] |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Flask | 3.1.3 (project pin) | Existing document/static and JSON route server | Flask routes and JSON response behavior already define Beacon's HTTP boundary. [VERIFIED: dashboard/pyproject.toml] |
| Python `sqlite3` + existing Beacon repositories | stdlib + project source | Short durable current-diagnosis reads | Existing SQLite WAL database is shared by web and worker; do not add an ORM or external database. [VERIFIED: dashboard/beacon/db.py] |
| APScheduler | 3.11.3 (project pin) | Existing worker callback schedule | Reuse the immutable callback inventory rather than introduce a second schedule/owner. [VERIFIED: dashboard/pyproject.toml] |
| Vanilla HTML/CSS/JavaScript | project source | Advanced route, accessible table, local preferences | The approved UI contract explicitly forbids a build step, component package, icon package, or registry. [VERIFIED: 03-UI-SPEC.md] |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pytest | >=9,<10 (project pin) | API/read-model, browser-source, and worker persistence tests | Extend the current test-client and temporary-SQLite harness. [VERIFIED: dashboard/pyproject.toml] |
| Playwright | 1.61.0 (project pin) | Deterministic browser interaction/layout smoke coverage | Use existing fixture-routed browser tests for both themes and narrow/desktop states. [VERIFIED: dashboard/pyproject.toml] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| One purpose-built diagnosis endpoint | Client fan-out to `/api/stats`, `/api/services`, `/api/scan-status`, and telemetry endpoints | Fan-out produces inconsistent cross-table snapshots and repeats expensive service/history work; use a server-composed bounded snapshot. [VERIFIED: dashboard/app.py] |
| Durable job-health rows | Inspect `scheduler.get_jobs()` from the web process | APScheduler can list scheduled jobs, but the scheduler exists only in the worker process and currently does not persist outcome evidence. [CITED: https://apscheduler.readthedocs.io/en/3.x/modules/schedulers/base.html] |
| Separate advanced document/assets | Add conditional advanced state to `dashboard/app.js` | Separate files make the read-only workspace testable without making the current dashboard monolith larger. [VERIFIED: AGENTS.md] |

**Installation:** No package installation. [VERIFIED: 03-UI-SPEC.md]

## Architecture Patterns

### System Architecture Diagram

```text
Dashboard page                         Advanced page (/advanced)
  | capture scroll position                | GET /api/advanced/current (poll/manual)
  | link, existing beacon-theme key         v
  +------------------------------------> Flask route + diagnosis service
                                           | one short SQLite read snapshot
                                           v
  system_stats / services + meta / runtime_state / telemetry_streams
  telemetry_coverage / telemetry_rollup_jobs / background_job_health
                                           |
                                           v
                    versioned current-diagnosis JSON (read-only)

Worker scheduler --> existing callback dispatch --> durable job-health update
      |                     |                        |
      +--> heartbeat/probes/metrics/cleanup ----------> shared SQLite
```

The advanced request flow must stop at the read-model boundary: no outgoing HTTP, Playwright, queue mutation, scheduling, discovery, or telemetry compaction may be reached from this route. [VERIFIED: Phase 3 CONTEXT.md]

### Recommended Project Structure

```text
dashboard/
├── app.py                         # thin /advanced and /api/advanced/current route adapters
├── advanced.html                  # advanced document shell; no inline scripts
├── advanced.js                    # state, renderers, polling, accessibility, local preferences
├── advanced.css                   # advanced layout layered on existing CSS custom properties
└── beacon/
    ├── diagnosis.py               # pure current-diagnosis assembly and freshness helpers
    ├── repositories.py            # bounded diagnosis SQL and job-health read/write helpers
    └── worker_main.py             # worker-owned callback outcome recording seam
tests/
├── test_advanced_diagnosis_api.py # payload/semantics/read-only route contracts
└── test_advanced_ui.py            # source and Playwright interaction/layout contracts
```

### Pattern 1: One bounded read model

**What:** Read all dashboard-wide diagnosis facts in one short read transaction, normalize timestamps/cadences at the server boundary, and return a stable `{generated_ts, host, services, pipeline, settings, exceptions}` payload.

**When to use:** Every automatic or manual advanced refresh. Keep client sorting/filtering local to that payload; request another snapshot only on the selected cadence or explicit refresh.

**Example:**

```python
# Source: existing route/repository transaction pattern [VERIFIED: dashboard/app.py]
def get_current_diagnosis(db_path, settings, now):
    policy = RetentionPolicy.from_settings(settings)
    with read_transaction(db_path) as conn:
        host = read_current_host(conn)
        services = read_service_diagnoses(conn, now=now)
        pipeline = read_pipeline_diagnosis(conn, policy=policy, now=now)
        jobs = read_background_job_health(conn)
    return compose_current_diagnosis(
        generated_ts=now, host=host, services=services,
        pipeline=pipeline, jobs=jobs, policy=policy,
    )
```

Use an explicit bounded service list (`EXPIRE_DAYS`-compatible current rows) and `MAX`/grouped SQL for latest probe evidence. Do not reuse `/api/services` unchanged because it loads up to eight days of `service_checks` to calculate dashboard uptime strips, which Phase 3 does not need. [VERIFIED: dashboard/app.py]

### Pattern 2: Server-derived freshness with evidence, never causal inference

**What:** The server returns `freshness`, `age_seconds`, `sample_ts`, and `expected_cadence_seconds`; UI only formats it. Treat no parseable timestamp/cadence as `unknown`.

**When to use:** Host sample, service probe, worker heartbeat, and every telemetry stream shown in Pipeline.

```python
# Source: locked Phase 3 UI threshold contract [VERIFIED: 03-UI-SPEC.md]
def freshness(now, sample_ts, cadence_seconds):
    if sample_ts is None or not cadence_seconds or cadence_seconds <= 0:
        return {'state': 'unknown', 'age_seconds': None}
    age = max(0, int(now) - int(sample_ts))
    state = 'fresh' if age <= cadence_seconds else (
        'aging' if age <= 4 * cadence_seconds else 'stale'
    )
    return {'state': state, 'age_seconds': age}
```

Host freshness uses `METRIC_SAMPLE_SECONDS` (default 5 seconds), worker freshness uses the heartbeat cadence (5 seconds), and pipeline stream freshness uses the persisted `telemetry_streams.cadence_seconds`; therefore the default host and worker threshold becomes stale after 20 seconds. Service payloads must expose the regular full-probe cadence (5 minutes) and, when currently down, the distinct one-minute down-recheck cadence; select and expose the cadence used for the freshness label. [VERIFIED: dashboard/app.py] [VERIFIED: dashboard/beacon/worker_main.py]

### Pattern 3: Durable job outcome evidence at worker dispatch

**What:** Wrap the existing inventory-driven callback dispatch with a narrow worker-owned record of `job_id`, `last_started_ts`, `last_finished_ts`, `last_success_ts`, `state`, `error_class`, and scheduler cadence/next-expected evidence.

**When to use:** Each scheduled worker callback only. Startup/lifecycle callbacks may be represented as `on_startup`/`not_scheduled`, but scheduled `J1`–`J9` must have visible outcome evidence.

```python
# Source: existing immutable callback dispatch boundary [VERIFIED: dashboard/beacon/worker_main.py]
def dispatch_callback(services, callback_id):
    callback = CALLBACKS_BY_ID[callback_id]
    with services.admission.admit(callback.admission_category) as admitted:
        if not admitted:
            return None
        started = int(services.clock())
        write_job_started(services.authority, callback, started)
        try:
            result = invoke_callback(services, callback)
        except Exception as exc:
            write_job_failed(services.authority, callback, started, exc)
            raise
        write_job_succeeded(services.authority, callback, started, int(services.clock()))
        return result
```

Implement the writer beneath the existing worker authority/transaction helpers. Do not swallow `LeaseLost`, do not write from the web process, and avoid recording a false success when a callback returns an explicit failure result. [VERIFIED: dashboard/app.py]

### Pattern 4: Route-local frontend state with one presentation-preferences schema

**What:** `advanced.js` owns active section, poll timer, last successful snapshot, temporary expansions, local sort, filter state, and the live-region announcer. A versioned preferences object persists only explicit preferences.

**When to use:** On `/advanced`; main dashboard keeps its existing behavior except for navigation/scroll capture.

```javascript
// Source: existing Beacon local-storage and polling pattern [VERIFIED: dashboard/app.js]
const PREFS_KEY = 'beacon-advanced-preferences-v1';
const DEFAULTS = {refresh_seconds: 15, paused: false, density: null,
  range: '24h', filters: {query: '', status: [], criticality: [], freshness: [], tags: []}};

function loadPreferences() {
  try { return {...DEFAULTS, ...JSON.parse(localStorage.getItem(PREFS_KEY) || '{}')}; }
  catch (_) { return {...DEFAULTS}; }
}
```

Keep `beacon-theme` unchanged. Do not persist expanded rows, selected exception links, fetch errors, or live data. The `range` preference can drive only displayed-resolution explanation until Phase 4 introduces historical investigation; it must not imply a current-history chart exists. [VERIFIED: 03-UI-SPEC.md]

### Responsive and accessibility implementation

- At `>=960px`, render the 224px persistent section rail; below it, render the same destinations as a horizontally scrollable tab list. Keep the selected tab visible and move focus to the selected section heading. [VERIFIED: 03-UI-SPEC.md]
- Keep the service table semantic (`table`, `thead`, `tbody`); make the containing region horizontally scrollable below 960px and freeze the Name + port cell using CSS `position: sticky`. Do not replace it with cards. [VERIFIED: 03-UI-SPEC.md]
- Implement sorting with native `<button>` elements and `aria-sort`; update a polite live region with field/direction. Implement disclosure using buttons with `aria-expanded` and stable detail-row IDs; permit a `Set` of expanded ports. [VERIFIED: 03-UI-SPEC.md]
- Maintain 44px minimum hit targets, non-colour textual markers, native focus indicators, `overflow-wrap:anywhere` for error evidence, and the existing warning order (connection, worker, recovery). [VERIFIED: 03-UI-SPEC.md]
- Preserve the last successful screen on refresh failure; update neither `last_success_ts` nor displayed-data freshness as if a failed response were current. [VERIFIED: 03-UI-SPEC.md]

### Anti-Patterns to Avoid

- **Web-owned monitoring:** Do not probe services or sample host metrics in the advanced endpoint; worker ownership and current-state correctness would regress. [VERIFIED: dashboard/beacon/worker_main.py]
- **Client fan-out / mixed snapshots:** Do not poll multiple existing endpoints and stitch them in JavaScript. It creates skew between exception summary, host, services, and pipeline state. [VERIFIED: dashboard/app.py]
- **Full retention scans per refresh:** Do not query 7–90 day telemetry or calculate historical uptime for the 5/15-second UI poll. [VERIFIED: dashboard/app.py]
- **Process-local job status:** Do not expose APScheduler instances, thread counters, or mutable in-memory status to Flask; it would be absent after a process restart and inaccessible to the separate web container. [VERIFIED: dashboard/worker.py]
- **Conflating evidence:** Do not make stale equal failed, unverified TLS equal unavailable, pending aggregation equal a collection gap, or worker freshness prove a stream is fresh. [VERIFIED: 03-UI-SPEC.md]
- **Advanced controls as operations:** Do not render Scan, edit metadata, trigger cleanup, reconfigure monitoring, or any remote-control action in the advanced page. [VERIFIED: 03-UI-SPEC.md]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Database concurrency | New cross-process lock or shared in-memory status | Existing SQLite WAL, existing DB helpers, short read transactions | Web and worker are already separate processes; WAL supports concurrent readers/writers but long readers harm checkpointing. [CITED: https://www.sqlite.org/wal.html] |
| Scheduler lifecycle | A second scheduler or browser interval that drives monitoring | Existing `WORKER_CALLBACK_INVENTORY` and worker process | The sole worker owns scheduled work and durable authority. [VERIFIED: dashboard/beacon/worker_main.py] |
| Health-rule parsing | New client-side status-range parser | Persisted validated `healthy_statuses` as the effective rule text | The metadata route already validates this policy; diagnosis only displays the effective rule. [VERIFIED: dashboard/app.py] |
| Freshness consistency | Separate browser thresholds per component | One server helper with explicit timestamp/cadence evidence | Browser clocks and copied thresholds can drift; server controls configuration. [VERIFIED: 03-UI-SPEC.md] |
| Service filtering/sorting | Server-side query mutation API | Pure local array filtering/sorting after bounded snapshot | Required filters are presentation preferences and must not mutate monitoring. [VERIFIED: 03-CONTEXT.md] |

**Key insight:** The advanced page needs composition and evidence presentation, not a new monitoring subsystem. The only new persistent write is durable job-outcome evidence, owned by the existing worker so diagnosis remains truthful across restarts. [VERIFIED: dashboard/beacon/worker_main.py]

## Common Pitfalls

### Pitfall 1: Treating `last_seen` as the last probe

**What goes wrong:** A down service looks stale even though its down-recheck is running, because `services.last_seen` is updated for successful service observations rather than every failed probe. [VERIFIED: dashboard/app.py]

**How to avoid:** Read latest `service_checks.ts` separately; expose regular and down-recheck cadence explicitly, and use the cadence selected by the diagnosis projection for the freshness label.

**Warning signs:** A worker-fresh page reports a stale service while recent failed `service_checks` exist.

### Pitfall 2: Making background job health process-local

**What goes wrong:** Web cannot reliably observe the worker's APScheduler object, and any in-memory last-run value disappears on restart. [VERIFIED: dashboard/worker.py]

**How to avoid:** Persist job start/success/failure rows under worker authority and derive next expected run from a known schedule/cadence plus the durable timestamp.

**Warning signs:** Job evidence changes merely because the web container restarted, or job rows lack an error after an exception.

### Pitfall 3: Polling a costly legacy services response

**What goes wrong:** Reusing `/api/services` reads a long window of check rows to build seven-day uptime buckets that are not required by the advanced diagnosis table. [VERIFIED: dashboard/app.py]

**How to avoid:** Add a diagnosis-specific grouped/latest-probe query and return no thumbnails or historical buckets.

**Warning signs:** The five-second advanced refresh produces large row counts, slow Pi response, or sampling gaps.

### Pitfall 4: Losing truthful stale/unknown semantics

**What goes wrong:** UI infers an outage cause from a stale timestamp, or merges collection gap, retention expiry, pending aggregation, and unknown evidence into one red state. [VERIFIED: 03-UI-SPEC.md]

**How to avoid:** Keep all evidence types separately typed in the API and render the locked vocabulary verbatim; show fresh worker + stale stream together when both are true.

**Warning signs:** A stale stream automatically changes service availability, or pipeline shows blank collections/empty setting values.

### Pitfall 5: Regressing theme or warning compatibility

**What goes wrong:** New page writes a competing theme preference or collapses the three safety warnings into one general exception banner. [VERIFIED: dashboard/app.js] [VERIFIED: 03-UI-SPEC.md]

**How to avoid:** Reuse `beacon-theme`; render the existing safety warning cluster first in the exact order, then show non-safety exceptions in Overview.

**Warning signs:** Navigating back changes theme, or recovery becomes invisible while worker warning is active.

## Code Examples

### Flask read-only route adapter

```python
# Source: Flask route + JSON response pattern [VERIFIED: dashboard/app.py]
@app.route('/advanced')
def advanced_index():
    return send_file('advanced.html', mimetype='text/html')

@app.route('/api/advanced/current')
def api_advanced_current():
    now = int(time.time())
    return jsonify(beacon_diagnosis.get_current_diagnosis(DB_PATH, SETTINGS, now))
```

Flask supports route-registered view functions and JSON responses; retain Beacon's existing request-security middleware and static-file response conventions. [CITED: https://flask.palletsprojects.com/en/stable/api/]

### Client refresh that preserves the last successful snapshot

```javascript
async function refreshCurrentDiagnosis() {
  try {
    const snapshot = await apiFetch('/api/advanced/current');
    state.snapshot = snapshot;
    state.lastSuccessTs = Date.now();
    render(snapshot);
    announce('Current diagnosis updated.');
  } catch (_) {
    renderRefreshError(state.lastSuccessTs);
  }
}
```

This aligns manual/automatic refresh with the locked requirement to retain old evidence after an error rather than show invented healthy/zero values. [VERIFIED: 03-UI-SPEC.md]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Main dashboard polls independent stats, scan, service, event, and history endpoints | Phase 3 needs one bounded diagnosis snapshot for coherent cross-component evidence | Phase 3 recommendation | Avoids inconsistent UI state and unnecessary retained-history reads. [VERIFIED: dashboard/app.js] |
| Historical pipeline health absent from UI | Phase 2 persists telemetry streams, coverage, rollup jobs, and retention state | Phase 2 complete | Phase 3 can expose actual collection/pressure evidence without new telemetry collection. [VERIFIED: dashboard/beacon/migrations.py] |
| Callback schedule exists only as immutable inventory | Persist outcome evidence at dispatch for diagnosis | Phase 3 recommendation | Satisfies job health across web/worker process separation and restarts. [VERIFIED: dashboard/beacon/worker_main.py] |

**Deprecated/outdated:** Do not use the legacy `/api/history` endpoint for advanced diagnosis; it always loads 24 hours of host points and cannot describe Phase 2 coverage, retention, or job health. [VERIFIED: dashboard/app.py]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | A default local `range: '24h'` is appropriate as a persisted Phase 3 presentation preference before Phase 4 charts exist. | Architecture Patterns | Low; choose a different UI default if product preference differs. |

All other implementation facts were verified against the codebase or official documentation in this session.

## Open Questions (RESOLVED)

1. **RESOLVED — How should a non-periodic startup callback appear in job health?**
   - What we know: `J9` is date-triggered and other callback inventory entries are lifecycle/startup-only. [VERIFIED: dashboard/beacon/worker_main.py]
   - Selected answer: Include every inventory item with `schedule_kind: scheduled | startup | lifecycle`; startup and lifecycle callbacks use `next_expected_ts: null` and render `Not scheduled` rather than a fabricated cadence.

2. **RESOLVED — What exact default range preference should Settings show before Phase 4 history?**
   - What we know: The approved contract requires storing a range preference but prohibits history charts in this phase. [VERIFIED: 03-UI-SPEC.md]
   - Selected answer: Default to a browser-local 24-hour presentation preference until Phase 4 implements history; label it as a local investigation preference and use it only to explain the effective future display resolution; see A1.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| Python | Flask/read-model tests | ✓ | 3.11.15 | Project supports 3.11–3.12. [VERIFIED: local command] |
| uv | Locked test execution | ✓ | 0.11.32 | — [VERIFIED: local command] |
| Node.js | Browser-source helper tests | ✓ | v22.14.0 | — [VERIFIED: local command] |
| Playwright CLI | Browser smoke tests | ✓ | installed at `/opt/homebrew/bin/playwright` | Existing project-pinned Python Playwright remains test dependency. [VERIFIED: local command] |
| Docker Compose | Pi deployment verification | ✓ | v5.3.1 | — [VERIFIED: local command] |

**Missing dependencies with no fallback:** None. [VERIFIED: local command]

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest >=9,<10, with existing `unittest`-style suites [VERIFIED: dashboard/pyproject.toml] |
| Config file | `dashboard/pyproject.toml` [VERIFIED: dashboard/pyproject.toml] |
| Quick run command | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py` |
| Full suite command | `uv run --project dashboard python -m pytest -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEL-06 | Pipeline contains retention tiers, pressure, worker freshness, stream/gap evidence, and durable job state/error/next expectation; pending aggregation remains distinct. | API + worker integration | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py -k pipeline` | ❌ Wave 0 |
| DIA-01 | `/advanced` and its static assets return expected types; dashboard link works in either saved theme. | Route + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k navigation` | ❌ Wave 0 |
| DIA-02 | Host snapshot reports metrics, hostname, exact sample timestamp/cadence, and fresh/aging/stale/unknown boundaries. | API unit | `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py -k host` | ❌ Wave 0 |
| DIA-03 | All services expose effective fields, operational ordering, local filters/sorts, multi-expand, and failure/TLS/freshness separation. | API + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k services` | ❌ Wave 0 |
| DIA-08 | Settings shows effective values/local controls only; advanced JS contains no mutation/remote action and persists only approved preferences. | Source contract + Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k settings` | ❌ Wave 0 |
| UX-02 | Theme survives round trip; scroll restoration and return-link focus work when browser permits it. | Playwright | `uv run --project dashboard python -m pytest -q tests/test_advanced_ui.py -k theme_or_return` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `uv run --project dashboard python -m pytest -q tests/test_advanced_diagnosis_api.py tests/test_advanced_ui.py`
- **Per wave merge:** `uv run --project dashboard python -m pytest -q`
- **Phase gate:** Full suite green plus Playwright desktop/narrow and dark/light fixture flows before `$gsd-verify-work`.

### Wave 0 Gaps

- [ ] `tests/test_advanced_diagnosis_api.py` — deterministic temporary-SQLite seeds for host/service freshness, gaps, pressure, settings, job success/failure, and GET-only route contract.
- [ ] `tests/test_advanced_ui.py` — fixture-routed Playwright tests for navigation, theme/scroll, refresh pause/error retention, keyboard sorting/disclosure, filters, screen-width behavior, and text-labelled states.
- [ ] Worker callback test coverage — assert durable job health is authority-fenced, records failure without a false success, and cannot cause duplicate scheduled work.

The project already has suitable reusable patterns: Flask test client/temporary SQLite in `tests/helpers.py`, browser fixture routing in `tests/test_ui_states.py`, and worker ownership tests. [VERIFIED: tests/helpers.py] [VERIFIED: tests/test_ui_states.py]

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Trusted-LAN product scope; retain existing host/origin request checks. [VERIFIED: AGENTS.md] |
| V3 Session Management | no | No login/session state introduced. [VERIFIED: Phase 3 CONTEXT.md] |
| V4 Access Control | yes | Advanced endpoint is GET-only and remains behind existing same-host request middleware. [VERIFIED: dashboard/app.py] |
| V5 Input Validation | yes | No advanced API query parameters; browser preferences are parsed defensively with defaults and never sent as mutation input. [VERIFIED: 03-UI-SPEC.md] |
| V6 Cryptography | no | No cryptographic feature is introduced. [VERIFIED: Phase 3 CONTEXT.md] |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Accidental monitoring mutation from advanced controls | Tampering | Route only GET snapshot/static assets; no scan/edit/config action controls or `fetch` mutation calls in advanced JS. [VERIFIED: 03-UI-SPEC.md] |
| Web process starts worker-like work | Elevation of Privilege | Read only SQLite; preserve separate worker ownership and no APScheduler startup in web. [VERIFIED: dashboard/worker.py] |
| Unbounded read starves storage/checkpointing | Denial of Service | One short query, no history/thumbnail BLOBs, bounded service rows, close read before response construction. [CITED: https://www.sqlite.org/wal.html] |
| Misleading security/availability state | Spoofing | Render TLS posture, availability, freshness, worker state, gaps, and recovery as separate typed facts. [VERIFIED: 03-UI-SPEC.md] |

## Sources

### Primary (HIGH confidence)

- [Project Phase 3 context](/Users/william/Documents/devproj/rpi-dashboard/.planning/phases/03-advanced-current-diagnosis/03-CONTEXT.md) - locked scope, route, data, freshness, and interaction decisions.
- [Phase 3 UI contract](/Users/william/Documents/devproj/rpi-dashboard/.planning/phases/03-advanced-current-diagnosis/03-UI-SPEC.md) - approved responsive/accessibility/refresh/freshness contract.
- [Current Flask integration](/Users/william/Documents/devproj/rpi-dashboard/dashboard/app.py) - routes, existing service payload cost, current facts, and worker-owned writes.
- [Worker callback inventory](/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/worker_main.py) - schedule/cadence/ownership evidence.
- [Telemetry policy and persistence](/Users/william/Documents/devproj/rpi-dashboard/dashboard/beacon/telemetry.py) - retention, pressure, gaps, and cadence semantics.

### Secondary (MEDIUM confidence)

- [Flask API documentation](https://flask.palletsprojects.com/en/stable/api/) - routes, response conversion, and test client.
- [APScheduler BaseScheduler documentation](https://apscheduler.readthedocs.io/en/3.x/modules/schedulers/base.html) - scheduled job inspection semantics.
- [SQLite WAL documentation](https://www.sqlite.org/wal.html) - concurrent reader/writer behavior, snapshot reads, and checkpoint caveats.

### Tertiary (LOW confidence)

- None.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — no new package is required; all components are pinned in the project and locked by the approved UI contract. [VERIFIED: dashboard/pyproject.toml]
- Architecture: HIGH — source code directly proves worker/web separation, current durable evidence, scheduler inventory, and costly legacy response paths. [VERIFIED: dashboard/app.py]
- Pitfalls: HIGH — derived from current code paths and the approved freshness/compatibility contract, with SQLite WAL operational caveats documented officially. [CITED: https://www.sqlite.org/wal.html]

**Research date:** 2026-08-12
**Valid until:** 2026-09-11 (codebase findings); reconfirm framework documentation if dependencies change.
