<!-- refreshed: 2026-07-24 -->
# Architecture

**Analysis Date:** 2026-07-24

## System Overview

```text
Browser (`dashboard/index.html`, `dashboard/app.js`)
          │ HTTP JSON/static requests
          ▼
Flask web process (`dashboard/app.py`, Gunicorn :8080)
          │ shared SQLite database `/data/dashboard.db`
          ▼
Background scheduler (`dashboard/worker.py`, APScheduler)
          ├─ discovery/probes and uptime checks
          ├─ metric sampling and retention cleanup
          └─ thumbnail/preview jobs (Playwright)
          ▼
Network services, Raspberry Pi system (`psutil`), optional webhook
```

## Component Responsibilities

| Component | Responsibility | File |
|---|---|---|
| Flask API/static server | Security middleware, health endpoints, CRUD-like service metadata, metrics/history/events responses | `dashboard/app.py` |
| Persistence layer | SQLite schema, migrations, runtime/scan state, event and service history | `dashboard/app.py` (`init_db`, `get_db`) |
| Discovery/probing | Port discovery, HTTP checks, transitions, alerts, thumbnails | `dashboard/app.py` (`run_discovery`, `do_uptime_check`, `fetch_thumbnail`) |
| Worker scheduler | Isolated periodic jobs and startup recovery | `dashboard/worker.py` |
| Browser UI | Polls APIs, renders system/service/event dashboard, submits scan and metadata actions | `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css` |

## Pattern Overview

**Overall:** Two-process Flask + worker architecture with a shared SQLite state store and polling single-page frontend.

**Key Characteristics:**
- `dashboard/app.py` contains both HTTP handlers and domain/data operations; worker imports it as a module.
- APScheduler uses bounded thread pools for metrics, probes, screenshots, and default jobs (`dashboard/worker.py`).
- SQLite WAL mode, explicit locks, and runtime state rows coordinate processes.
- Frontend is dependency-free vanilla JavaScript; all dynamic data comes from `/api/*` polling endpoints.

## Layers

**Presentation/API:**
- Purpose: Serve static assets and JSON endpoints; enforce host/origin and security headers.
- Location: `dashboard/app.py` route functions; assets in `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css`.
- Depends on: persistence/domain functions in same module.

**Domain/operations:**
- Purpose: Discover services, probe health, calculate uptime, collect system metrics, create events/alerts, render thumbnails.
- Location: `dashboard/app.py` functions `run_discovery`, `do_uptime_check`, `collect_system_stats`, `_handle_state_transition`.
- Depends on: `requests`, `psutil`, BeautifulSoup, Playwright, SQLite.

**Scheduling:**
- Purpose: Trigger operations periodically and recover worker state.
- Location: `dashboard/worker.py`.
- Depends on: exported operations/constants from `dashboard/app.py`.

**Storage:**
- Purpose: Persist services, metadata, checks, events, metrics, queue requests, and runtime state.
- Location: SQLite initialized by `init_db()` in `dashboard/app.py`; volume defined in `docker-compose.yml`.

## Data Flow

### Primary Request Path

1. Browser loads `/` and static assets from Flask (`dashboard/app.py:index`, `dashboard/index.html`).
2. `dashboard/app.js` polls `/api/config`, `/api/stats`, `/api/history`, `/api/services`, `/api/events`, and scan status.
3. Route handlers open SQLite connections via `get_db()`, query persisted rows, and return JSON.
4. UI updates cards, sparklines, service tiles, and incident list in the DOM.

### Background Monitoring Flow

1. `dashboard/worker.py` initializes/recover state, then APScheduler starts jobs.
2. Discovery and uptime jobs probe local network services using `_probe_http` and write `services`, `service_checks`, and `events`.
3. Metric jobs sample `psutil` values into `system_stats`/`stats_history`; cleanup enforces retention.
4. Queued scan/preview requests are consumed by worker jobs; browser previews use a serialized Playwright instance.

**State Management:** SQLite is the source of truth. `_db_lock`, `_scan_lock`, `_uptime_lock`, and related locks protect concurrent operations; `runtime_state` records heartbeat and scan progress.

## Key Abstractions

**Service metadata and health records:** `services` stores observed state while `service_meta` stores operator overrides (name, URL, tags, criticality). Use `api_service_meta` for edits.

**Runtime queues:** `scan_requests` and `preview_requests` provide durable, polling queues between web and worker processes.

**Security helpers:** `_is_trusted_request_host`, `_safe_service_url`, `_origin_is_same_host`, and `enforce_request_security` constrain SSRF and browser-origin access.

## Entry Points

**Web container:** Gunicorn invokes Flask `app` from `dashboard/app.py` (container command in `dashboard/Dockerfile`).

**Worker container:** `python worker.py` executes module initialization and `scheduler.start()` in `dashboard/worker.py`.

**Frontend:** Browser entry is `dashboard/index.html`; deferred script `dashboard/app.js` drives polling/rendering.

## Architectural Constraints

- **Concurrency:** Web and worker are separate processes sharing SQLite; writes must retain explicit transactions/locks.
- **Global state:** Module-level Flask app, locks, browser singleton, and configuration in `dashboard/app.py`.
- **Deployment:** Containers run as UID 10001 with read-only filesystems; only `/data` volume is writable (`docker-compose.yml`).
- **Network:** Worker uses host networking for LAN discovery; web exposes port 80 mapped to 8080.

## Anti-Patterns

### Mixing web and domain concerns
**What happens:** API handlers and substantial probe/storage logic coexist in `dashboard/app.py`.
**Why it's wrong:** Changes can affect both request latency and scheduled jobs.
**Do this instead:** Keep route handlers thin and reuse existing operation helpers; isolate new domain code into modules only with worker import compatibility.

### Direct cross-process in-memory coordination
**What happens:** Locks/global variables are process-local.
**Why it's wrong:** They cannot coordinate web and worker processes.
**Do this instead:** Persist coordination in SQLite `runtime_state` and queue tables.

## Error Handling

**Strategy:** Catch network/browser exceptions, classify probe errors, persist event/error fields, and return JSON HTTP errors from routes. Worker jobs continue after individual failures.

## Cross-Cutting Concerns

**Logging:** Python `logging` configured in `dashboard/app.py` and `dashboard/worker.py`.
**Validation:** URL/host/status/tag validation helpers in `dashboard/app.py`.
**Authentication:** No user login; trusted-host/origin checks and `X-Beacon-UI` request conventions protect mutating UI calls.

---

*Architecture analysis: 2026-07-24*
