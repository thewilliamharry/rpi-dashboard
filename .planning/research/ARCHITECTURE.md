# Architecture Patterns

**Domain:** Local-only Raspberry Pi operations dashboard
**Researched:** 2026-07-24
**Evidence confidence:** MEDIUM — current implementation was inspected directly; architecture recommendations are cross-checked against current official SQLite, Flask, and APScheduler documentation.

## Recommended Architecture

Keep the two deployable processes—Flask/Gunicorn web and the APScheduler worker—but make them consumers of a small, side-effect-free application package. Do not introduce a network database, message broker, frontend framework, or a third process: they add operational surface without solving Beacon's single-host problem. SQLite remains the local source of truth, with the worker as the sole owner of scheduled collection, rollup, retention, durable-job claiming, and WAL maintenance.

```text
Browser: light dashboard / dark dashboard / advanced analytics
     │  polling JSON; mutations carry existing trusted-LAN safeguards
     ▼
Flask composition root → API blueprints → query + command services
     │                               │
     │                         SQLite read transactions
     │                               ▼
     └──── durable command rows ◀── SQLite database (/data)
                                      │
                                      ▼
Worker composition root → scheduler → collectors / aggregates / queue consumers
                                      │
                 psutil + host state │ HTTP probe │ Playwright preview (isolated lane)
                                      ▼
                      Pi host and explicitly permitted LAN services
```

The direct codebase evidence is that `dashboard/app.py` currently combines schema changes, HTTP routes, all collectors, queues, browser lifecycle, and import-time worker startup. The target must therefore be an *extract-and-adapt* refactor with compatibility tests, not a rewrite of monitoring behavior. Use an application factory for the web composition root: Flask documents that factories support isolated configurations and test instances, while avoiding global construction that becomes difficult as an application grows ([Flask application factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/), MEDIUM). The worker must construct the same configuration and repository/services explicitly, but it must never import a module that starts a scheduler.

### Component Boundaries

| Component | Responsibility | Communicates With |
|---|---|---|
| `beacon.config` | Parse, validate, and expose immutable configuration: paths, sample intervals, retention, allowed service network/ports, feature flags. | Both composition roots |
| `beacon.db` | Open short-lived SQLite connections, set per-connection pragmas, run explicit transaction helpers, schema-version migrations, backup/checkpoint observability. No domain SQL elsewhere. | Repositories, migration runner |
| `beacon.repositories` | SQL-only persistence ports for current state, raw observations, rollups, events, services, metadata, preview metadata, and durable work items. | Domain services / query services |
| `beacon.monitoring` | Collect host metrics, probe services, classify errors, detect transitions, and write observations/events in short transactions. No Flask imports or scheduler calls. | `psutil`, HTTP adapter, repositories |
| `beacon.discovery` | Discover permitted candidates, reconcile service inventory, enqueue preview work. It is a slow operation and never executes in a request handler. | Network adapter, repositories |
| `beacon.previews` | Own Playwright lifecycle and screenshot files; process one durable preview task at a time. Failure is non-fatal to service monitoring. | Filesystem thumbnail store, repositories |
| `beacon.analytics` | Select resolution by requested range, read current/rollup series, calculate availability and bounded trend summaries. It does not mutate telemetry. | Repositories |
| `beacon.jobs` | Define APScheduler job wrappers, durations/outcomes, coalescing/misfire policy, queue claim/retry, and process lifecycle. | Monitoring, discovery, previews, retention |
| `beacon.web` | Flask factory, request security, blueprints, JSON request/response contracts, and static-file delivery. Route functions are adapters only. | Query/command services |
| Browser `dashboard` | Shared API client, lightweight view modules, current dashboard previews, and a dedicated analytics page route/view. Themes share data and controls; only layout/density differs. | `/api/v1/*` |

### Data Model and Retention Pipeline

Use distinct tables for identity/current state, immutable observations, derived rollups, and operational work. Do **not** overload `services` or `system_stats` with historical-analytics duties.

| Data group | Recommended shape | Retention / access rule |
|---|---|---|
| Service identity | `services(service_id, stable_key, first_seen_ts, last_seen_ts, current_state...)` and `service_meta(service_id, display_name, url, critical, tags...)` | Long-lived; prefer a generated `service_id` over port as identity so changing a URL/port does not sever history. Keep a compatibility mapping while migrating old port-keyed rows. |
| Current host state | One `host_current` row containing the latest full diagnostic sample. | Overwrite every sample; dashboard polls it. |
| Raw host observations | `host_samples(ts, cpu_pct, ram_pct, disk_pct, temp_c, load_1m, ... )`; primary key `(ts)` or `(bucket_ts, sequence)` after collision policy. | Keep 24 hours at 60-second grain (1,440 rows/day). The five-second collector updates `host_current`; it must not create 1.56m 90-day rows. |
| Raw service observations | `service_checks(ts, service_id, online, latency_ms, error_class)` with primary key `(service_id, ts)` and indexes `(ts)` and `(service_id, ts)`. | Keep 7 days of five-minute probe data; preserve state transitions as events. |
| Aggregate buckets | `host_rollups(resolution, bucket_ts, sample_count, cpu_min, cpu_avg, cpu_max, ... )`; `service_rollups(resolution, service_id, bucket_ts, observed_seconds, online_seconds, check_count, latency_avg, latency_max, failure_count)`. | Hourly buckets for day 2–90; daily buckets are optional only if a future range exceeds 90 days. Uniqueness keys make rollup reruns idempotent. |
| Events/incidents | Existing `events`, extended with stable `service_id` and structured details/error class; optional incident span record for a down→up interval. | Retain 90 days; incident/event history is much smaller and explains charts. |
| Work/runtime | `work_items` (or evolved `scan_requests` / `preview_requests`) with type, payload JSON, status, attempts, lease expiry, error, timestamps; `runtime_state` for heartbeat and last successful maintenance. | Delete completed operational tasks quickly; retain failures long enough to diagnose. Persisted state coordinates processes—never Python locks. |
| Thumbnail assets | Files under a managed `/data/previews/` directory named by service ID/content version; database stores relative path, MIME type, byte size, hash, timestamps, status. | One current preview plus bounded stale/orphan cleanup. Do not retain 2 MiB BLOBs in the telemetry database/WAL. |

The worker must collect current state, append raw observations only at their configured grain, then atomically upsert completed buckets. A safe hourly maintenance run is:

1. Determine the last finalized hourly bucket from `maintenance_state`; do not aggregate the open current hour.
2. Recompute any incomplete/finalizable hourly buckets from the retained raw rows using `MIN`, `AVG`, `MAX`, counts, and service online-duration logic; `INSERT ... ON CONFLICT DO UPDATE` makes reruns safe after restart.
3. Verify rollup coverage and record the last successfully finalized bucket in the same transaction.
4. Delete raw rows only after their rollup is present and after a small overlap window; then delete rollups/events older than 90 days.
5. Run a bounded `PRAGMA wal_checkpoint(PASSIVE)` and record returned frame counts/elapsed time; never make an API request wait for it.

This is deliberately rollup-before-delete. It prevents a restart, late job, or partially completed maintenance pass from silently creating holes in 90-day analytics. SQLite WAL allows readers alongside a writer but allows only one writer; open/long read transactions can stop checkpoint completion and allow WAL growth, so all API queries must fetch/serialize promptly outside the transaction and workers must keep write transactions short ([SQLite WAL documentation](https://www.sqlite.org/wal.html), MEDIUM; [checkpoint pragma](https://www.sqlite.org/pragma.html#pragma_wal_checkpoint), MEDIUM).

### API and Analytics-UI Contract

Keep the existing endpoints working during the migration. Add versioned read models rather than having the advanced page orchestrate several low-level tables in JavaScript.

| Endpoint family | Contract | Caller |
|---|---|---|
| Existing `/api/stats`, `/api/history`, `/api/services`, `/api/events` | Compatibility adapters backed by the new query services; preserve JSON fields/current previews until all UI callers move. | Existing dashboard |
| `GET /api/v1/diagnostics/current` | Host sample freshness, collection health, disk/WAL/preview-queue status, and concise per-service current diagnosis. | Both themes, advanced current-state section |
| `GET /api/v1/analytics/host?range=24h|7d|30d|90d` | Server selects `raw` or `hourly` resolution and returns `{resolution, coverage, points, gaps}`. Points include bucket start/end and min/avg/max. | Advanced charts; compact previews use a bounded subset |
| `GET /api/v1/analytics/services?range=...&service_id=...` | Per-service availability, latency, observed seconds, failures, events, and resolution/coverage metadata. | Advanced service drill-down |
| `GET /api/v1/incidents?range=...&service_id=...` | Paginated transition/incident timeline with stable cursor, never unbounded event loads. | Advanced event view |
| `POST /api/v1/commands/scan` and preview/meta mutation adapters | Enqueue durable command, return `202` plus ID/status URL; retain existing origin/host validation and rate limits. | Both themes |

The response must say what is unknown: `sample_count`, `coverage`, `gaps`, `state=unknown`, and collection freshness are first-class fields. The UI must not draw a zero line for an unobserved period. Client charts should receive no more than roughly 180–360 points per selected series; range/resolution selection belongs in the analytics service, not the browser. The main page keeps its current compact sparklines and polls current state at the existing cadence; the advanced page refreshes current diagnostics independently and reloads historical series on range/service changes or a slower cadence. Both themes share one semantic view model/API; CSS tokens and component density differ, not capabilities.

## Patterns to Follow

### Pattern 1: Side-effect-free composition roots

**What:** `create_app(config=None)` builds Flask, registers security and blueprints, then injects service instances. `worker_main()` builds the same container, runs migrations before scheduling, and owns shutdown. Modules define functions/classes but perform no I/O, scheduler start, browser start, or schema migration on import.

**When:** Always—especially during the refactor that removes `dashboard/app.py` import-time `_ensure_runtime_started()` behavior.

**Example:**

```python
# beacon/web/factory.py
def create_app(config: Settings | None = None) -> Flask:
    settings = config or load_settings()
    services = build_services(settings)
    app = Flask(__name__)
    register_security(app, services.request_policy)
    app.register_blueprint(api_v1(services))
    app.register_blueprint(compat_api(services))
    return app

# beacon/worker/main.py
def main() -> None:
    services = build_services(load_settings())
    services.migrator.upgrade()
    run_scheduler(services)  # the only place scheduler.start() occurs
```

Flask’s factory pattern is explicitly intended to make configuration/test instances independent ([official documentation](https://flask.palletsprojects.com/en/stable/patterns/appfactories/), MEDIUM).

### Pattern 2: One scheduled writer with short transactions and durable claims

**What:** The single worker claims queue rows with a conditional update/lease, does network/browser work outside a transaction, then commits the outcome in a short transaction. The web process only reads or creates a durable command.

**When:** Scan, preview, alert, retry, retention, and rollup work; never coordinate cross-container work using `_db_lock` or module globals.

**Example:**

```python
def claim_next_preview(conn, now: int) -> WorkItem | None:
    row = conn.execute(
        "SELECT id FROM work_items WHERE kind='preview' AND status='queued' "
        "ORDER BY requested_ts LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    changed = conn.execute(
        "UPDATE work_items SET status='running', lease_until=? "
        "WHERE id=? AND status='queued'", (now + 180, row['id'])
    ).rowcount
    return load_work_item(conn, row['id']) if changed else None
```

SQLite WAL improves concurrent reader/writer behavior, but it is still a single-writer store; this pattern avoids a web response and long screenshot/probe competing inside one write transaction ([SQLite WAL documentation](https://www.sqlite.org/wal.html), MEDIUM).

### Pattern 3: Query-specific read models and range-aware resolution

**What:** Analytics queries are API-facing read services that choose raw or hourly tables and return a stable chart DTO with coverage. They do not expose schema rows or compute time-series aggregation in the browser.

**When:** Every chart/table in the advanced page. Use raw data for 24h, hourly rollups for 7–90d; return a fixed point budget.

**Example:**

```python
def host_series(range_: TimeRange) -> HostSeries:
    source = "host_samples" if range_.seconds <= 24 * 3600 else "host_rollups"
    points = repo.read_host_series(source, range_, max_points=360)
    return HostSeries(resolution=source, points=points,
                      coverage=coverage(points, range_))
```

### Pattern 4: Observable scheduling with deliberate overload policy

**What:** Keep named executors: a short metrics/maintenance lane, a bounded probe lane, and one preview lane. Assign every job a recorded last-start, last-success, duration, exception class, `max_instances=1`, appropriate grace time, and coalescing policy.

**When:** The existing worker already has executor lanes; preserve this resource isolation while moving wrappers out of `worker.py`.

APScheduler states that `max_instances` caps overlapping executions, missed invocations are evaluated using `misfire_grace_time`, and coalescing can collapse multiple missed runs into one ([APScheduler user guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html), MEDIUM). Metrics and rollups should coalesce; a preview queue needs no catch-up run because work is durable; service checks should report staleness rather than run a burst after an outage.

## Anti-Patterns to Avoid

### Anti-Pattern 1: Extending the monolithic `app.py`

**What:** Add analytics routes, schema changes, collection, and chart transforms to the existing 2,000+ line module.

**Why bad:** Imports can start background work; web latency, migration risk, and monitoring correctness remain entangled. Analytics increases SQLite load precisely where the current shared locks and BLOBs are most fragile.

**Instead:** First establish modules/ports and compatibility adapters. Move behavior one bounded domain at a time with contract tests.

### Anti-Pattern 2: Retain 90 days of high-frequency raw samples

**What:** Change the current one-day cleanup to 90 days at five-second host sampling and one-minute/five-minute service checks.

**Why bad:** It turns a local status dashboard into an unnecessary write-amplification and WAL-growth workload. At five seconds, host data alone reaches 1,555,200 rows in 90 days before indexes and service checks.

**Instead:** Keep latest diagnostics separately, raw history only for short investigation windows, and one idempotent hourly rollup for 90-day views.

### Anti-Pattern 3: A single “analytics” endpoint that loads all history

**What:** Return all metrics, checks, and events for 90 days and let vanilla JS group/filter them.

**Why bad:** It creates slow responses, long-lived reads that interfere with WAL checkpoints, high Pi memory use, and duplicated aggregation rules across UI sections.

**Instead:** Bounded range endpoints with point limits, pagination/cursors, server-side aggregation, and explicit coverage/gap fields.

### Anti-Pattern 4: Cross-process Python locks and implicit queue state

**What:** Rely on `_db_lock`, `_scan_lock`, globals, or APScheduler memory to coordinate Flask and the worker.

**Why bad:** Container/process-local locks do not protect the other process and a restart loses queue ownership.

**Instead:** Persist status, lease/attempt information, idempotency keys, and completion state in SQLite; recover expired leases at worker startup.

### Anti-Pattern 5: Make Playwright a prerequisite for monitoring or analytics

**What:** Run browser previews on the same critical lane as probes/rollups or fail service monitoring if Chromium is unavailable.

**Why bad:** Browser start/restart has the largest memory and latency footprint on a Pi, and previews do not establish availability.

**Instead:** Keep previews an optional, single-concurrency work type with health/status exposed to the UI; core host/service telemetry must continue when it is degraded.

## Dependency-Driven Build Order

1. **Protect the behavioral baseline and migration seam.** Add snapshot/upgrade fixtures for representative current databases; characterize current API JSON, worker heartbeat, scan/preview recovery, and main-page preview behavior. Introduce `schema_migrations` versioned transactional migrations before changing retention or keys.
2. **Create side-effect-free composition roots and ports.** Add settings, connection/transaction factory, repository interfaces, Flask factory/blueprints, and worker main. Move current behavior behind compatibility endpoints without changing SQL semantics. Remove import-time scheduler startup only after web and worker entrypoint tests prove ownership.
3. **Stabilize current-state collection and durable work.** Extract host collection, probe/transition logic, discovery, preview worker, queues, and scheduler wrappers. Add job freshness/outcome metrics; replace BLOB writes with the managed preview file store and migration fallback. This phase protects monitoring before historical load is introduced.
4. **Introduce the analytics schema and 90-day pipeline.** Add stable service IDs/mapping, raw observation metadata, hourly rollups, maintenance state, indexes, bounded cleanup, and passive checkpoint reporting. Backfill only data that actually exists; label unavailable earlier periods as gaps rather than inventing history.
5. **Ship query services and advanced analytics UI.** Build range-aware diagnostics/analytics/incident endpoints, then the advanced page/view modules. Preserve dashboard sparklines through the compatibility/read-model APIs. Implement both themes from shared controls/data, then tune dark density and calm light presentation.
6. **Exercise production-like recovery and resource contracts.** Test two-container SQLite behavior, migration upgrades/rollback plan, restart while a job lease is active, missed scheduler jobs, long chart reads, WAL boundedness, degraded Playwright, and 90-day query payload/time budgets on Pi-class hardware.

**Ordering rationale:** Analytics is downstream of stable identity, collection timing, schema migration, and retention semantics. The analytics UI is downstream of bounded query DTOs. Refactoring only becomes safe when legacy behavior remains reachable through compatibility tests; new rollups must prove data coverage before cleanup discards raw evidence.

## Scalability Considerations

The product is intentionally a one-Pi/one-operator deployment. “10K” and “1M” here mean data/query volume, not a recommendation to turn Beacon into a fleet platform.

| Concern | At 100 users | At 10K users | At 1M users |
|---|---|---|---|
| Concurrent UI reads | One Gunicorn process plus short SQLite reads is sufficient; poll current state and bound charts. | Outside product scope; do not add web replicas over the same SQLite file. | Outside product scope; requires a different, multi-tenant architecture. |
| Telemetry volume | Short raw window + hourly rollups easily fits local storage; observe database/WAL size. | If interpreted as 10K points, use rollups/pagination and keep API payloads capped. | Do not retain/query this volume in SQLite on a Pi; export or redesign only if product scope changes. |
| SQLite writes | Single worker serializes writes; short transactions and passive checkpoints. | Maintain one writer; batch rollups/cleanup. Queue/migrate only if measured contention cannot be fixed by bounded work. | Not supported by the local-only constraint. |
| Discovery/previews | Bounded probe executor plus one preview worker; backoff failures. | Reduce scan scope and preserve service inventory; no full-network scan per request. | Not applicable—fleet/distributed discovery is explicitly out of scope. |

## Sources

- [SQLite Write-Ahead Logging](https://www.sqlite.org/wal.html) — primary source, MEDIUM confidence via verified web retrieval; concurrency, checkpoint, and WAL-growth guidance.
- [SQLite PRAGMA documentation: `wal_checkpoint`](https://www.sqlite.org/pragma.html#pragma_wal_checkpoint) — primary source, MEDIUM confidence via verified web retrieval; checkpoint behavior/status.
- [Flask Application Factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/) — primary source, MEDIUM confidence via verified web retrieval; factory/module-boundary pattern.
- [APScheduler 3.x User Guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html) — official project documentation, MEDIUM confidence via verified web retrieval; coalescing, misfire, and concurrency semantics.
- `.planning/PROJECT.md`, `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/STRUCTURE.md`, and `.planning/codebase/CONCERNS.md` — direct codebase evidence, HIGH confidence.
