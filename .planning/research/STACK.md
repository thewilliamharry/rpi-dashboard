# Technology Stack

**Project:** Beacon — local Raspberry Pi operations dashboard
**Researched:** 2026-07-24
**Confidence:** MEDIUM — recommendations are cross-checked against official Flask, SQLite and Chart.js documentation and current project registries. The research-cache confidence seam assigns MEDIUM to the verified web fallback used because Context7/`ctx7` was unavailable in this agent runtime.

## Recommendation

Preserve Beacon's two-container Python deployment and SQLite database. It already matches a single trusted-LAN Raspberry Pi: the worker collects and writes data; Gunicorn only serves reads and short mutations. The milestone should make that architecture explicit, add bounded SQLite rollups, and introduce exactly one locally shipped browser library for analytics charts. Do **not** turn a one-Pi dashboard into a multi-service observability stack.

The existing `stats_history` one-minute sampling cadence would produce 129,600 rows over 90 days, which SQLite can store comfortably. The API must nevertheless query precomputed range rollups, not send all raw rows to the browser. Retain short-lived high-resolution samples for diagnosis, and use UTC bucket tables for the 90-day views.

## Recommended Stack

### Core Framework

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| Python | 3.12.x | Web, worker, persistence and operations code | Already deployed in the pinned `python:3.12-slim-bookworm` image; no runtime or language migration is justified for this milestone. |
| Flask | `3.1.3` | HTTP API and static-file delivery | Keep the proven small WSGI server. Convert the global `app` to `create_app(config)` and register focused blueprints; Flask documents factories as enabling injected test configuration and multiple instances, while blueprints provide application-level modularity. [MEDIUM] |
| Gunicorn | `26.0.0` | Production WSGI server | Retain one worker and bounded threads. The dashboard is local and its expensive work belongs in the separate worker, not inside request threads. |
| APScheduler | `3.11.3` | In-process interval scheduling in the sole worker container | Retain it with current bounded executors, `max_instances=1`, coalescing, and explicit misfire policies. Version 3.11.3 is the stable current line; APScheduler 4 is still pre-release, so do not couple this restructuring to a scheduler migration. [MEDIUM] |

### Database

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| Python stdlib `sqlite3` / SQLite | Python 3.12 bundled SQLite; retain WAL | Local source of truth | Keep it. One Pi, one worker writer, and one web reader process are precisely the workload SQLite WAL supports. WAL improves reader/writer overlap but still permits only one writer, so all writes must be short transactions. [MEDIUM] |
| Explicit migration registry | New internal module; no package | Durable, testable schema evolution | Extract the existing inline `ALTER TABLE` code into ordered, idempotent migration functions recorded in `schema_migrations`. This keeps the existing database and avoids adding an ORM solely to obtain migrations. |
| UTC rollup tables | New schema; no package | Bounded 90-day analytical queries | Store `bucket_start`, bucket width, count, min, max, and average for CPU/RAM/disk/temp; store per-service probe count, online count, latency min/max/avg, and error count. Use unique `(bucket_start, bucket_seconds[, service_id])` keys and idempotent upserts. |

### Infrastructure

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| Docker Compose | Existing | Local two-process deployment | Preserve `data-init`, `worker`, and `web`, read-only roots, non-root UID, tmpfs, health checks, and the named `/data` volume. Do not add Redis or a broker. |
| uv | `0.11.28` | Locked Python dependency installation | Preserve the existing frozen lockfile workflow and update it only when a deliberately chosen pinned dependency changes. |
| Playwright + Chromium | `1.61.0` | Isolated service thumbnails | Retain only for preview jobs, serialized in its own worker executor. It is not part of analytics and must never run in the web process. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `psutil` | `7.2.2` | Host CPU, memory, filesystem, temperature, load and network measurements | Retain as the sole Pi telemetry collector. Its maintained system-monitoring API already covers the required host metrics. [MEDIUM] |
| `requests` + `urllib3` | `2.34.2` / `2.7.0` | HTTP probes and outbound alert delivery | Retain behind a `probe_service` adapter so probing policy, timeouts and error classification stay out of routes and scheduler code. |
| Chart.js | `4.5.1` | Canvas charts on the advanced analytics page | Add as a locally committed, pinned UMD asset, not a CDN import. Use line charts with `parsing: false`, animations disabled for dense charts, and the built-in `min-max` decimation option for peak-preserving telemetry. Chart.js supports decimation on linear/time X axes. [MEDIUM] |
| Browser-native `Date` / `Intl` | Browser built-in | UTC timestamp labels/tooltips | Use a **linear** milliseconds-since-epoch X axis plus local tooltip/tick formatters. This avoids adding a Chart.js time adapter and another JavaScript dependency. |
| `pytest` | `>=9,<10` (lock a selected patch) | Contract, migration and retention tests | Keep pytest; add deterministic clock fixtures and temporary SQLite databases to test migrations, bucketing, rollups, retention and API response bounds. |

## Data Retention and Aggregation Design

| Data tier | Retention | Storage / query rule | Rationale |
|-----------|-----------|----------------------|-----------|
| Current host state | Latest only | Continue the one-row `system_stats` table, updated at the existing 5-second cadence. | Preserves immediate diagnosis without historic write amplification. |
| Recent host samples | 7 days | Persist one-minute raw samples. Query only a bounded window for current diagnostics. | Enables short-window detail and keeps writes low (10,080 rows). |
| 90-day host analytics | 90 days | Persist 15-minute rollups with count/min/max/avg. Generate/update them transactionally from raw samples; serve these to 7–90 day charts. | Gives 8,640 chart points per series at most before response downsampling. |
| Service probes | 14 days raw; 90 days aggregate | Retain raw five-minute checks for diagnosis, then materialize hourly availability/latency rollups for history endpoints. | Raw checks preserve recent incident drill-down; hourly rollups cap 90-day multi-service reads at 2,160 points/service. |
| Events | 90 days | Keep state-change and diagnostic events separately, with indexed timestamp and service key. | Events are sparse and must not be reconstructed from coarse aggregates. |
| Cleanup | Every hour, after rollup completion | In one short transaction: materialize closed buckets, delete expired raw rows, delete expired aggregates/events, then commit. | Prevents a cleanup race from deleting data before aggregation and bounds volume/flash writes. |

Use integer UTC epoch seconds throughout, as the existing schema already does. SQLite documents Unix timestamps as a supported time-value representation; create composite indexes that follow every endpoint's range predicate (for example `(ts)` for host data and `(port, ts)` / `(bucket_start, port)` for service analytics). Validate query plans with `EXPLAIN QUERY PLAN`; SQLite specifically exposes whether a query becomes a full scan or uses an index. [MEDIUM]

Each analytics endpoint must accept a fixed whitelist of ranges/resolutions and return no more than the visual budget (target: 800–1,200 points/series). The server selects the appropriate rollup and returns `{bucket_start, min, max, avg, count}` rather than asking Chart.js to compensate for an unbounded API response. Client-side decimation is a final rendering guard, not the retention strategy.

## Module Boundaries

Use a small package refactor; do not introduce a framework-wide repository pattern or dependency injection container.

```text
dashboard/beacon/
  __init__.py              # create_app(), shared config, blueprint registration
  web/                     # thin Flask blueprints: dashboard, services, analytics, admin
  domain/                  # typed records and pure uptime/diagnostic/bucketing calculations
  persistence/             # connection factory, migrations, repositories, transactions
  operations/              # telemetry, probes, discovery, previews, alerts
  analytics/               # rollup writer, retention policy, bounded query service
  worker.py                # scheduler wiring only; imports use-case functions
  static/vendor/           # checked-in Chart.js 4.5.1 UMD asset and license
```

Routes validate request input and call a use-case/service; services depend on repository interfaces/functions and not on Flask request globals; repositories own SQL and transactions; the worker owns only schedule registration and process lifecycle. Preserve SQLite queue tables (`scan_requests`, `preview_requests`) for cross-process coordination — Python locks remain process-local and are not a coordination mechanism between web and worker containers.

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Persistence | SQLite + stdlib `sqlite3` | PostgreSQL/TimescaleDB | Adds a database service, memory, backups and operational failure modes for a one-device, bounded 90-day workload. Revisit only for multiple writers/devices or materially larger retention. |
| Migrations/data access | Explicit SQL migrations and repositories | SQLAlchemy + Alembic | Helpful for larger relational applications, but would create a broad migration and dual data-access rewrite with no required capability. Keep SQL visible for the small analytical schema. |
| Scheduling | APScheduler 3.11.3 in one worker | Celery + Redis/RabbitMQ | Durable distributed task execution is unnecessary; it adds at least two processes and an external queue to a local appliance. |
| Metrics platform | SQLite rollups | Prometheus + Grafana | Excellent for fleet/operations monitoring, but too heavy and changes Beacon's local self-contained UI/product boundary. It also duplicates current collection and persistence responsibilities. |
| Frontend | Vanilla JS + Chart.js | React/Vue/Vite SPA | The existing single-page UI is dependency-free. A build system and framework rewrite would consume the milestone without improving local analytics enough to justify it. |
| Charting | Locally bundled Chart.js | CDN Chart.js / hosted analytics | Beacon must work without Internet access and should not leak local operational metadata to third parties. |
| Chart time handling | Linear UTC milliseconds + native formatters | Chart.js time scale plus date adapter | A time scale requires an adapter; the linear scale meets this dashboard's needs with one fewer dependency. |

## Installation

No new Python production package is required for the architecture and data work. Keep the locked Python environment, then vendor one pinned browser asset into the application source and include its license notice.

```bash
# Existing runtime remains locked and container-installed.
uv sync --frozen --project dashboard

# Add the audited Chart.js 4.5.1 UMD distribution to dashboard/static/vendor/
# (or the equivalent current static-asset directory), commit the exact file and license.
# Do not load it from a CDN and do not introduce npm/Vite for this one asset.
```

When a dependency update is chosen, pin the exact version in `pyproject.toml`, refresh `uv.lock`, run `pip-audit`, build the ARM64 image, and run the existing smoke tests plus analytics/migration tests. Do not update Flask, APScheduler, Playwright, and Chromium as an incidental side effect of the refactor.

## Sources

- [Flask application factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/) and [blueprints](https://flask.palletsprojects.com/en/stable/blueprints/) — official documentation; **MEDIUM** (verified web fallback).
- [Flask 3.1.3 release record](https://pypi.org/project/Flask/) — project registry; **MEDIUM**.
- [APScheduler package releases](https://pypi.org/project/APScheduler/) and [scheduler concepts](https://apscheduler.readthedocs.io/en/master/userguide.html) — official project sources; **MEDIUM**.
- [SQLite WAL](https://www.sqlite.org/wal.html), [date/time values](https://www.sqlite.org/lang_datefunc.html), and [query planning](https://sqlite.org/eqp.html) — official SQLite documentation; **MEDIUM**.
- [Chart.js 4.5.1 package record](https://www.npmjs.com/package/chart.js), [performance guidance](https://www.chartjs.org/docs/latest/general/performance.html), and [decimation](https://www.chartjs.org/docs/latest/configuration/decimation.html) — official project sources; **MEDIUM**.
- [psutil 7.2.2 package record](https://pypi.org/project/psutil/) — project registry; **MEDIUM**.

## What Not to Use in This Milestone

- Do not migrate to PostgreSQL, TimescaleDB, Redis, Celery, Prometheus, Grafana, InfluxDB, or a hosted telemetry product.
- Do not introduce an ORM, SQLAlchemy job store, or APScheduler 4 while extracting the monolith.
- Do not keep a 90-day chart endpoint that selects every raw sample/check and relies on the browser to absorb it.
- Do not run telemetry collection, probes, discovery, Playwright, or retention cleanup in Flask/Gunicorn request handlers.
- Do not use a CDN or send telemetry to an external service; Beacon's local-only deployment is a product constraint.
