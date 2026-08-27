<!-- refreshed: 2026-08-27 -->
# Architecture

**Analysis Date:** 2026-08-27

## System Overview

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                          Frontend Presentation                            │
├──────────────────────┬──────────────────────┬────────────────────────────┤
│  Everyday Dashboard  │   Advanced Workspace │    HTTP API Routes         │
│  `dashboard/         │  `dashboard/         │   `dashboard/app.py       │
│   index.html`        │   advanced.html`     │    @app.route(...)`       │
│  `dashboard/app.js`  │  `dashboard/         │                            │
│                      │   advanced.js`       │ /                          │
│                      │                      │ /advanced                  │
│                      │                      │ /api/stats                 │
│                      │                      │ /api/history               │
│                      │                      │ /api/services              │
│                      │                      │ /api/events                │
│                      │                      │ /api/scan-status           │
│                      │                      │ /api/advanced/current      │
│                      │                      │ /api/telemetry/history     │
└──────────────┬───────┴──────────────────────┴──────────────┬─────────────┘
               │                                              │
               │              /api/stats                      │ /api/advanced/current
               │              /api/services                   │ (complete diagnosis snapshot)
               │              /api/history                    │
               │              /api/events                     │
               ▼                                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    Diagnosis Composition Layer                            │
│                  `dashboard/beacon/diagnosis.py`                          │
│         get_current_diagnosis() → versioned snapshot                      │
│         ├─ Host metrics state (cpu, ram, disk, temp)                      │
│         ├─ Services with availability & TLS posture                       │
│         ├─ Pipeline evidence (worker health, job health)                  │
│         ├─ Maintenance window attribution                                 │
│         └─ Safety classification (worker stale/degraded/fresh)            │
└──────────────────────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                   Data Access & Persistence Layer                         │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │         Repository Functions  `beacon/repositories.py`              │  │
│  │  • read_current_services()     • read_maintenance_windows_by_port()  │  │
│  │  • read_current_host()         • read_pipeline_evidence()           │  │
│  │  • record_background_job_*()   • read_service_offline_intervals()   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │      Database Access  `beacon/db.py`                                │  │
│  │  • connect_db() — shared-lease connection with locking              │  │
│  │  • read_transaction() / write_transaction() — explicit boundaries   │  │
│  │  • ManagedConnection — maintains fcntl-based maintenance lease      │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      SQLite Persistence                                   │
│              (beacon.db — shared state between web/worker)               │
│  Tables:   services, service_checks, service_meta, service_tls_posture   │
│            system_stats, stats_history                                   │
│            background_job_health, worker_owner, worker_heartbeat         │
│            maintenance_windows, events, scan_requests, preview_requests  │
│            telemetry_streams, telemetry_coverage, telemetry_rollup_jobs  │
│            runtime_state, scan_rate_hits, service_rollups,               │
│            host_metric_rollups                                           │
└──────────────────────────────────────────────────────────────────────────┘
               ▲
               │
               │ (write via jobs)
               │
┌──────────────────────────────────────────────────────────────────────────┐
│                   Background Worker Process                              │
│                    `dashboard/worker.py` entry point                      │
│                   `dashboard/beacon/worker_main.py`                       │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │        Scheduled Job Composition (APScheduler)                      │  │
│  │  WORKER_CALLBACK_INVENTORY defines job lifecycle:                   │  │
│  │  P0: Pre-epoch preparation                                          │  │
│  │  S1-S3: Startup callbacks (recover state, heartbeat, metrics)       │  │
│  │  J1: Heartbeat (every 5s) — updates worker_heartbeat                │  │
│  │  J2: Metrics (configured cadence) — collects & stores system stats  │  │
│  │  J3-J4: Uptime checks (5min & 1min intervals) — service probing     │  │
│  │  J5: Manual scan processing (every 2s)                              │  │
│  │  J6: Preview/thumbnail processing (every 2s)                        │  │
│  │  J7: Scheduled discovery (daily)                                    │  │
│  │  J8: History cleanup (hourly)                                       │  │
│  │  J9: Startup discovery (once at startup)                            │  │
│  │  L1: Lifecycle finalization                                         │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │     Core Worker Operations  `beacon/monitoring.py`                  │  │
│  │  • probe_http() — HTTP service health checks                        │  │
│  │  • collect_system_stats() — psutil metrics collection               │  │
│  │  • do_discovery() — network service discovery                       │  │
│  │  • do_uptime_check() — state transition & alert logic               │  │
│  │  • cleanup_history() — retention policy enforcement                 │  │
│  │  • process_scan_requests() — handle user-triggered scans            │  │
│  │  • process_preview_requests() — browser-based thumbnails            │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| Flask app | HTTP routing, request validation, API responses | `dashboard/app.py` |
| Everyday dashboard | Real-time system monitoring, service status, quick actions | `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css` |
| Advanced workspace | Historical analysis, diagnosis deep-dive, settings | `dashboard/advanced.html`, `dashboard/advanced.js`, `dashboard/advanced.css` |
| Diagnosis pipeline | Versioned state snapshots, availability classification, exceptions | `dashboard/beacon/diagnosis.py` |
| Repositories | Parameterized SQL queries, data projections | `dashboard/beacon/repositories.py` |
| Database access | Connection management, transaction boundaries, locking | `dashboard/beacon/db.py` |
| Worker orchestrator | Job scheduling, callback dispatch, lifecycle management | `dashboard/beacon/worker_main.py` |
| Monitoring operations | HTTP probing, metrics collection, discovery, cleanup | `dashboard/beacon/monitoring.py` |
| Telemetry | Retention policy, rollup strategy, coverage tracking | `dashboard/beacon/telemetry.py` |
| Maintenance | Window detection, downtime attribution, suggestions | `dashboard/beacon/maintenance.py` |
| Incidents | Event recording, filtering, historical queries | `dashboard/beacon/incidents.py` |
| Outbound | Alert webhooks, policy enforcement | `dashboard/beacon/outbound.py` |

## Pattern Overview

**Overall:** Layered, decoupled composition with explicit data flow — Flask web layer consumes read-only snapshots from a diagnosis pipeline; background worker writes state via scheduled jobs; both share SQLite as the single source of truth.

**Key Characteristics:**
- **Async job ownership**: Worker acquires exclusive lease before running; all writes go through transaction boundaries
- **Server-side classification**: Worker freshness state (fresh/aging/stale) computed once in diagnosis, consumed by both frontends
- **Stateless repositories**: SQL queries are pure functions of connection and parameters; no lifecycle side effects
- **Explicit boundaries**: Database access wrapped in read_transaction/write_transaction; Flask routes acquire _db_lock before persistence
- **Versioned snapshots**: Advanced workspace consumes complete diagnosis with schema version; everyday dashboard polls separate endpoints

## Layers

**Web/Presentation:**
- Purpose: HTTP server, routing, static assets, REST API responses
- Location: `dashboard/app.py`, `dashboard/*.html`, `dashboard/*.js`, `dashboard/*.css`
- Contains: Flask route handlers, HTML templates, client-side UI logic
- Depends on: Diagnosis pipeline, repositories, database access, worker state
- Used by: Web browsers, mobile clients

**Diagnosis Composition:**
- Purpose: Build versioned state snapshots from durable evidence; classify worker health; resolve service availability
- Location: `dashboard/beacon/diagnosis.py`
- Contains: `get_current_diagnosis()`, `compose_service_diagnosis()`, `compose_pipeline_diagnosis()`, `compose_active_exceptions()`
- Depends on: Repositories, database, maintenance module, telemetry policy
- Used by: `/api/advanced/current` endpoint, everyday dashboard API handlers

**Data Access:**
- Purpose: Parameterized SQL queries, row projections, transaction boundaries
- Location: `dashboard/beacon/repositories.py`, `dashboard/beacon/db.py`
- Contains: `read_current_services()`, `read_current_host()`, `connect_db()`, `read_transaction()`, `write_transaction()`
- Depends on: SQLite, configuration
- Used by: Diagnosis pipeline, job handlers, API endpoints

**Worker Orchestration:**
- Purpose: Schedule jobs, manage lifecycle, dispatch callbacks, handle state recovery
- Location: `dashboard/beacon/worker_main.py`
- Contains: `WorkerCallback`, `WorkerOperations`, `WORKER_CALLBACK_INVENTORY`, job dispatch
- Depends on: APScheduler, configuration, persistence layer
- Used by: `worker.py` entry point, Gunicorn/production runner

**Job Operations:**
- Purpose: Implement scheduled work — probing, metrics, discovery, cleanup
- Location: `dashboard/beacon/monitoring.py`, per-job handlers in `dashboard/app.py`
- Contains: HTTP probing, stats collection, uptime calculation, history cleanup
- Depends on: Repositories, database, HTTP client (psutil, requests)
- Used by: Worker callbacks

**Support Modules:**
- `config.py`: Settings loading and defaults
- `maintenance.py`: Maintenance window detection, downtime attribution
- `incidents.py`: Event recording and filtering
- `telemetry.py`: Retention policy, rollup strategy
- `outbound.py`: Webhook policies
- `previews.py`: Browser-based thumbnail capture
- `queues.py`: Scan/preview request queues
- `recovery.py`: Upgrade recovery procedures
- `migrations.py`: Schema versioning and migrations
- `worker_authority.py`: Worker lease and ownership tracking

## Data Flow

### Primary Request Path (Everyday Dashboard)

1. Browser loads `/` → `index.html` + `app.js` + `style.css` (`dashboard/app.py` serves static files)
2. App polls `/api/stats` → `api_stats()` reads `system_stats` table (current metrics snapshot)
3. App polls `/api/services` → `api_services()` reads services with current state, latest probe, TLS posture
4. App polls `/api/history` → `api_history()` reads `stats_history` for past 24 hours
5. App polls `/api/events` → `api_events()` reads recent events with type filtering
6. App renders safety banners: `worker_stale` (heartbeat > 5s cutoff), `worker_degraded` (freshness="aging"), `recovery_required`
7. On user action (scan, service settings) → `/api/trigger-scan` or `/api/service-meta/<port>` → writes to `scan_requests` or `service_meta`

**State updates flow:**
- Worker J1 (heartbeat, 5s interval) → updates `worker_heartbeat` table
- Worker J2 (metrics, configurable cadence) → inserts to `system_stats`, `stats_history`
- Worker J3/J4 (uptime checks, 5min/1min) → updates `services`, inserts to `service_checks`, records `events`
- Worker J8 (cleanup, 1hr) → purges expired `stats_history`, `service_checks`, `events`

### Advanced Workspace Request Path

1. Browser loads `/advanced` → `advanced.html` + `advanced.js` + `advanced.css`
2. App calls `/api/advanced/current` → `api_advanced_current()` → `beacon_diagnosis.get_current_diagnosis()`
3. Diagnosis composes:
   - Host metrics state from `system_stats` + historical trend
   - Services from `services` + `service_meta` + latest `service_checks` + `service_tls_posture`
   - Pipeline evidence (worker heartbeat age, job health) from `worker_heartbeat`, `background_job_health`
   - Maintenance windows from `maintenance_windows`
   - Availability classification (online/offline/maintenance/unknown) per service
   - Worker freshness state (fresh/aging/stale) via `worker_freshness()`
   - Active exceptions (collection gaps, discovery issues, maintenance overruns)
4. Response includes complete snapshot with schema version for versioning
5. Advanced workspace renders diagnosis sections (Overview, Host, Services, History, Incidents, Pipeline, Settings)

**Historical investigation:**
- User selects service + time range on History section
- App calls `/api/telemetry/history?kind=service&port=8080&start_ts=X&end_ts=Y`
- Server validates range (max 90 days), retrieves `telemetry_streams` + coverage intervals
- Response includes data points at adaptive resolution (60s, 300s, ..., 86400s) based on POINT_BUDGET
- App renders historical state band + latency chart with coverage annotations

### Worker Startup & Lifecycle

1. `worker.py main()` → `worker_main.run_worker(operations)`
2. `WorkerAdmission` gates job execution
3. `build_scheduler()` registers callbacks from `WORKER_CALLBACK_INVENTORY`
4. Startup phase:
   - P0: `prepare_database()` runs migrations
   - S1: `recover_worker_state()` — clears stale scan/preview requests
   - S2: `update_worker_heartbeat()` — records initial lease
   - S3: `collect_system_stats()` — collects initial metrics
   - J9: `startup_discovery()` runs once
5. Scheduled phase begins:
   - J1 fires every 5s → renews `worker_heartbeat` (acquired exclusive DB access via `acquire_worker_lease`)
   - J2 fires at configured interval → collects stats, inserts to `system_stats` + `stats_history`
   - J3/J4 fire on intervals → probe services, update state, fire alerts if enabled
   - J5/J6 fire every 2s → process queued requests
   - J7 fires daily → discovery
   - J8 fires hourly → cleanup
6. Shutdown:
   - `close_admission()` prevents new job starts
   - `drain()` waits for in-flight jobs
   - L1: `shutdown_browser()`, `release_worker_lease()`

### Safety Banner State Machine (Both Frontends)

**Classification happens server-side in `diagnosis.py:worker_freshness()`:**

1. **Input:** Current timestamp, last heartbeat timestamp, settings (WORKER_READY_SECONDS, METRIC_SAMPLE_SECONDS)
2. **Logic:**
   - If heartbeat is null or > WORKER_READY_SECONDS → state = "stale", freshness_seconds = ∞
   - Elif heartbeat is 0–4×cadence → state = "fresh", freshness_seconds = age
   - Elif heartbeat is 4×cadence–WORKER_READY_SECONDS → state = "aging", freshness_seconds = age
3. **Output:** `{'state': 'fresh'|'aging'|'stale', 'freshness_seconds': int}`

**Banners rendered by both frontends:**
- `#recovery-warning`: Shown if `recovery_required` = true (`.beacon-recovery-marker` exists)
- `#degraded-warning`: Shown if `worker_freshness['state']` = "aging" AND NOT worker_stale
- `#worker-warning`: Shown if `worker_stale` = true (heartbeat age > cutoff)
- `#connection-banner`: Shown if fetch fails (poll_failures exceeds threshold)

## Key Abstractions

**WorkerCallback:**
- Purpose: Immutable descriptor of one scheduled job or lifecycle callback
- Examples: `J1` (heartbeat), `J2` (metrics), `J5` (scan processing)
- Pattern: Dataclass with `identifier`, `operation_fields` (tuple of required operations), `handler` (job function name), `database_surfaces` (read/written tables), `effect_surfaces` (side effects like webhooks), `scheduler_metadata`
- Used by: Dispatcher to validate preconditions, build scheduler

**WorkerOperations:**
- Purpose: Explicit bundle of operations supplied by composition root to worker
- Examples: `prepare_database`, `update_worker_heartbeat`, `collect_system_stats`, `do_uptime_check`
- Pattern: Dataclass with callable fields; decouples worker from Flask/browser concerns
- Used by: Scheduler, job handlers

**CoverageInterval:**
- Purpose: Represent one half-open telemetry span with known availability state
- Examples: `[1693000000, 1693003600, 'observed', None]` or `[1693003600, 1693007200, 'collection_gap', 'J2 failed']`
- Pattern: Frozen dataclass with validation; `as_dict()` for JSON serialization
- Used by: Telemetry layer, historical diagnosis

**SourceSegment:**
- Purpose: One tier of aggregated telemetry from retention rollup
- Pattern: Resolution in seconds + tuple of display-ready points
- Used by: Advanced workspace history rendering

**ManagedConnection:**
- Purpose: SQLite connection that owns fcntl-based maintenance lease
- Pattern: Subclass of sqlite3.Connection; `_set_maintenance_handle()` stores lock, `close()` releases
- Used by: `connect_db()`, ensures no connection can outlive its lease

## Entry Points

**Web Application:**
- Location: `dashboard/app.py`
- Triggers: Gunicorn or development server starts Flask app
- Responsibilities: Configure logging, load settings, register routes, initialize browser pool
- Key exports: `app` (Flask instance), `init_db()` (migration entry point)

**Background Worker:**
- Location: `dashboard/worker.py`
- Triggers: Separate process (not same as web process)
- Responsibilities: Build worker operations, create scheduler, run main loop
- Key exports: `build_worker_operations()`, `main(settings=None)`

**CLI/Admin:**
- Location: `dashboard/beacon/migrate.py`
- Triggers: Manual execution for schema upgrades
- Responsibilities: Run versioned migrations with exclusive lock

## Architectural Constraints

- **Single SQLite file**: All processes (web + worker) share one database; contention resolved via fcntl-based lease + 30-second timeouts
- **Worker ownership**: Only one worker process should hold lease at a time; enforced by `worker_authority.py` and `queues.py`
- **Synchronous HTTP**: Flask routes are synchronous; long operations (discovery, browser capture) have explicit timeouts
- **No global state in web**: Flask routes do not maintain process-level state across requests; all state in SQLite
- **Stateless repositories**: Repository functions are pure queries; no caching or side effects
- **Browser resource management**: Only one Playwright browser instance per worker; shared across J6 jobs via semaphore
- **Discovery budget**: Network discovery has operator-configurable timeout (DISCOVERY_TIMEOUT_SECONDS); jobs J5, J7, J9 use this budget

## Anti-Patterns

### Stale Diagnosis in Everyday Dashboard

**What happens:** Everyday dashboard polls `/api/stats`, `/api/services`, `/api/history` separately on different intervals; if one endpoint fails or lags, displayed state is inconsistent (CPU from 1s ago, services from 3s ago).

**Why it's wrong:** Operator may see degraded service state alongside fresh metrics, making it harder to correlate problems. Maintenance windows may apply to one view but not another.

**Do this instead:** Everyday dashboard should also call `/api/advanced/current` (single versioned snapshot) for safety-critical state (recovery_required, worker_stale, worker_degraded). Keep separate endpoints for high-frequency polling (stats) but use diagnosis snapshot as authoritative state.

### Job Identity Duplication

**What happens:** Same job logic defined multiple times — once in `WORKER_CALLBACK_INVENTORY`, once in route handler, once in test fixture.

**Why it's wrong:** Changes to cadence, database surfaces, or preconditions get missed in one location; tests diverge from production job definitions.

**Do this instead:** All job metadata lives in `WORKER_CALLBACK_INVENTORY` (`dashboard/beacon/worker_main.py`). Route handlers reference callback by ID, not by reimplementing logic.

### Implicit Database Transactions

**What happens:** Repositories call `conn.execute()` directly without wrapping in explicit `read_transaction()` or `write_transaction()`.

**Why it's wrong:** Caller may leak connections, hold locks across network I/O, or race with maintenance windows.

**Do this instead:** Always use context managers: `with read_transaction(db_path) as conn:` or `with write_transaction(db_path) as conn:`. Never pass bare connection objects across function boundaries.

---

*Architecture analysis: 2026-08-27*
