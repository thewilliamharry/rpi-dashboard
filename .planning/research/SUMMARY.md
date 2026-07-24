# Project Research Summary

**Project:** Beacon
**Domain:** Self-contained, local Raspberry Pi operations dashboard
**Researched:** 2026-07-24
**Confidence:** MEDIUM

## Executive Summary

Beacon should remain a deliberately small, local appliance: Flask/Gunicorn serves a browser dashboard while one APScheduler worker collects Pi metrics, probes approved services, and owns durable maintenance. The right milestone is an extract-and-adapt refactor, not a platform rewrite. Keep Python 3.12, Flask, SQLite WAL, Docker Compose, and the two-container deployment; introduce an explicit application factory, focused modules, versioned SQL migrations, a designated worker writer, and local Chart.js for the new analytics views. Do not add a broker, ORM, hosted telemetry, Prometheus/Grafana, or a frontend build stack.

The advanced workspace should answer two questions reliably: what is wrong now, and what happened during the last 90 days? That requires a bounded data contract before chart work: fresh current state, short-lived raw diagnostic data, idempotent UTC rollups, time-weighted service availability, explicit unknown/gap states, and range-aware APIs with bounded payloads. The existing main dashboard stays glanceable in both themes; the advanced page adds detailed current diagnosis, host and service history, incident investigation, and monitoring-pipeline health. Light and dark modes must expose the same capabilities while differing only in presentation density.

The main risks are data loss during a live SQLite migration, treating WAL as multi-writer scalability, retention that exhausts Pi storage or produces misleading history, low-priority Chromium/discovery work starving collection, and outbound fetch paths bypassing security policy. Mitigate them before analytics: verified online backups and idempotent migrations, one scheduled writer with short transactions, rollup-before-delete retention, isolated best-effort preview work, and one reusable allowlisted outbound-target policy. Prove the design with compatibility, Compose concurrency, migration/restart, security, visual-parity, and Pi-class soak tests.

## Key Findings

### Recommended Stack

Preserve the existing lightweight deployment and pin only deliberate upgrades. Python 3.12.x, Flask 3.1.3, Gunicorn 26.0.0, APScheduler 3.11.3, stdlib SQLite in WAL mode, Docker Compose, uv, psutil, and requests/urllib3 fit Beacon's one-Pi constraint. The web process must only serve reads and short command mutations; the worker owns collection, events, rollups, retention, queue claims, and checkpoint maintenance. APScheduler 4, PostgreSQL/Timescale, Redis/Celery, an ORM, Prometheus/Grafana, and a SPA rewrite are unjustified scope and operational overhead.

**Core technologies:**
- **Flask application factory + blueprints** — separates web composition from domain operations and makes test configurations isolated.
- **SQLite WAL with explicit migrations** — keeps a suitable local source of truth while enforcing short transactions and a single write owner.
- **UTC raw observations and idempotent rollups** — keeps recent diagnostic fidelity while making 90-day queries/storage bounded.
- **APScheduler in the sole worker** — preserves simple local scheduling with `max_instances=1`, coalescing, and explicit misfire policy.
- **Chart.js 4.5.1, vendored locally** — renders efficient analytics charts without a CDN, npm, time adapter, or frontend framework.
- **Playwright/Chromium in a serialized preview lane** — retains previews as optional best-effort work, never a web or monitoring dependency.
- **pytest with deterministic clocks and temporary SQLite databases** — validates migrations, retention, range APIs, and contracts.

Recommended retention contract: latest host state at five-second cadence; one-minute raw host samples for seven days; 15-minute host rollups for 90 days; raw service probes for 14 days plus hourly service aggregates for 90 days; events for 90 days. All timestamps are UTC epoch seconds. Cleanup runs after rollup completion in short, idempotent transactions, and server APIs cap returned points rather than depending on browser-side decimation.

### Expected Features

**Must have (table stakes):**
- Advanced-page navigation from both themes while retaining main-dashboard previews.
- Freshness-aware current host diagnosis: CPU, memory, disk, temperature, hostname, timestamp, and visible stale/unknown state.
- Current service inventory with status, latency/failure class, state-since, criticality, tags, and existing service actions/links.
- Shared bounded time ranges (1h, 24h, 7d, 30d, 90d and validated custom range).
- 90-day host charts with units, threshold context, tooltips, and honest gaps.
- Per-service time-weighted availability, state timeline, latency/error history, and transition events.
- Filterable incident timeline that can focus a service and time window.
- Explicit retention and collection-quality/freshness visibility.
- Responsive, accessible, full-capability light and dark modes.

**Should have (differentiators):**
- Shared investigation context across selected service, event, and time range.
- A pipeline-health panel: worker heartbeat, last successful jobs, collection gaps, queue state, WAL/database/retention pressure.
- Range-aware resolution disclosure plus recent/detail versus historical/aggregate views.
- Explainable baseline comparisons (current, min/max/average, trend) rather than opaque anomaly scoring.
- Critical-service-first filtering and intentionally denser dark versus calmer light presentation.

**Defer (v2+):**
- Remote control, restarts, shell/container actions, and other mutations.
- Fleet/multi-Pi support, users/RBAC, tenancy, hosted telemetry, and remote write.
- Arbitrary dashboards, query language, plugins, alert routing/collaboration workflows, unbounded logs/screenshots/telemetry, browser journeys, and AI root-cause claims.

### Architecture Approach

Create a small, side-effect-free `beacon` package with separate configuration, database/transaction/migration code, repositories, monitoring/probing, discovery, previews, analytics, jobs, and web blueprints. The web factory registers compatibility and versioned API routes but starts no scheduler or I/O on import. `worker_main()` builds the same services, runs migrations, and is the only scheduler owner. Persisted durable work rows and leases—not Python locks—coordinate web commands and worker execution. Keep existing endpoints operating through compatibility adapters while moving one behavioral domain at a time.

**Major components:**
1. **Config, database, and migrations** — validated immutable settings, short-lived SQLite connections, schema versions, backups/checkpoint observation.
2. **Repositories and domain/query services** — SQL ownership, pure bucketing/uptime calculations, stable read models and bounded range queries.
3. **Monitoring and jobs** — host sampling, service probes, state transitions, rollups, cleanup, queue claiming, scheduler outcomes and freshness.
4. **Discovery and previews** — slow network/browser work with durable queues, single-concurrency Chromium, cleanup, and non-fatal degradation.
5. **Web and browser dashboard** — thin adapters, request security, shared API/view contracts, compact dashboard previews, and a separate analytics page.

Key patterns: query-specific API DTOs with `coverage`, `gaps`, and resolution; raw-or-rollup server selection with a point budget; time-weighted availability over known intervals; immutable service IDs with migration mapping from legacy port keys; a managed preview file store rather than large SQLite BLOBs; and named critical/probe/preview job lanes with observable overload behavior.

### Critical Pitfalls

1. **Un-upgradeable or lost live SQLite data** — establish `schema_migrations`, transactional idempotent upgrades, verified online logical backups, compatibility fixtures, and two-step backfill/validate/switch migrations before destructive changes.
2. **WAL contention from multiple writers or long reads** — give the worker exclusive telemetry/event write ownership, keep transactions/read lifetimes short, use durable leases, instrument busy retries/WAL/checkpoints, and prove bounded behavior with concurrent Compose tests.
3. **Ninety-day retention that is inaccurate or grows without bound** — define UTC/cutoff/gap semantics, roll up before deletion, batch cleanup, index range predicates, track watermarks and storage budgets, and calculate availability by elapsed known state rather than pass percentage.
4. **Diagnostics starving the monitoring they diagnose** — separate critical collection/probes from best-effort discovery/previews/compaction, serialize Chromium, enforce deadlines/backoff, clean browser resources in `finally`, and run constrained-Pi soak testing.
5. **SSRF or unsafe outbound paths** — route requests, HTML fetches, screenshots, and webhooks through one policy that permits only explicit HTTP(S) host/port targets, validates A/AAAA resolution at connection time, revalidates/blocks redirects, keeps TLS verification on, and has table-driven regression tests.

## Implications for Roadmap

### Phase 1: Behavioral Safety, Persistence, and Process Ownership

**Rationale:** Every later change depends on preserving useful behavior and data while removing import-time lifecycle coupling. Analytics cannot safely sit on an unversioned schema, ambiguous scheduler ownership, process-local locks, or fragmented outbound policy.

**Delivers:** Baseline API/UI/persistence contract tests; online backup and restore verification; forward-only idempotent migration registry; side-effect-free Flask factory and worker entrypoint; focused package/repository boundaries; compatibility endpoints; worker-only scheduler/writer ownership; durable command/lease semantics; unified outbound-target policy; and initial job/WAL/freshness instrumentation.

**Addresses:** Existing main-dashboard behavior, service metadata and editing, scans/previews, safe trusted-LAN operations, and the foundation for advanced navigation in both themes.

**Avoids:** Database-loss/rollback failures, duplicate schedulers/events, import-time side effects, process-local coordination bugs, and security-policy bypasses.

### Phase 2: Bounded Telemetry, Service History, and Retention

**Rationale:** The advanced page needs correct historical truth before it needs visualization. This phase converts the 90-day requirement into explicit data semantics and operational limits.

**Delivers:** Stable service identity mapping; current-state/raw/rollup/event/runtime tables; UTC time and gap contract; raw-to-rollup pipeline; time-weighted service availability; bounded cleanup and passive checkpoint reporting; indexes and query-plan tests; storage/freshness/WAL metrics; versioned host/service/event range-query services with capped payloads and coverage metadata.

**Addresses:** 90-day host history, availability/latency/event history, visible retention, adaptive resolution, and monitoring-pipeline health inputs.

**Avoids:** Raw-data explosion, false zeroes/continuity, corrupted availability, retention races, excessive flash/WAL pressure, and long chart reads.

### Phase 3: Advanced Diagnostics and Theme-Parity UI

**Rationale:** Once bounded APIs provide trustworthy state and history, the product can present a coherent investigation workspace without duplicating aggregation logic in JavaScript.

**Delivers:** Dedicated advanced route from both themes; vendored Chart.js; shared time/service/event selection state; current host and service diagnosis with freshness; host metric charts; service inventory/drill-down; time-weighted availability, latency, incident timeline, correlations, baseline summaries, critical-service focus, pipeline-health panel, responsive/accessibility states, and retained compact main-dashboard previews.

**Addresses:** All core advanced monitoring features, shared investigation context, and intentional density parity between light and dark modes.

**Avoids:** Dark-only functionality, replacing the everyday dashboard, inaccessible chart-only diagnosis, and causal/AI claims the data cannot support.

### Phase 4: Preview/Discovery Resilience and Pi-Class Acceptance

**Rationale:** Preview/discovery work has the largest resource footprint and should be hardened only after core monitoring and analytics are isolated and observable.

**Delivers:** Dedicated best-effort discovery/preview queue lanes, single-concurrency Playwright lifecycle ownership, target failures/backoff/degraded states, managed thumbnail-file lifecycle, container resource budgets, Compose recovery tests, and constrained-Pi smoke/24-hour soak acceptance.

**Addresses:** Existing service previews/discovery without weakening telemetry reliability.

**Avoids:** Chromium leaks, OOM/retry loops, dashboard stalls, sampling gaps, unbounded thumbnails, and recovery failures under slow/disconnected services.

### Phase Ordering Rationale

- Compatibility, migration, process ownership, and request security are non-negotiable gates for every schema and module move.
- The retention/rollup pipeline must precede historical API/UI work so charts never invent history or pressure the Pi with raw scans.
- Query services precede the advanced page so resolution, availability, gaps, and payload limits have one tested source of truth.
- Preview hardening follows core monitoring because it is optional work and must prove it cannot starve essential collection.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 1:** Validate the exact current database migration/rollback path, production Compose ownership behavior, and all existing outbound callers against the unified policy.
- **Phase 2:** Confirm legacy data shapes, service identity migration strategy, precise bucket/availability semantics, capacity limits, and query plans on target storage.
- **Phase 3:** Research only implementation-local UI constraints: existing DOM/theme patterns, narrow viewport behavior, and Chart.js vendoring/licensing integration.
- **Phase 4:** Measure actual Raspberry Pi resource limits, Chromium behavior, Compose enforcement, and representative slow/rebinding endpoint test harnesses.

Phases with standard patterns (skip broad research-phase):
- **Factory/blueprint extraction and pytest contract coverage:** established Flask/Python patterns; focus on codebase-specific compatibility.
- **SQLite migration registry, short transactions, range indexes, and idempotent upserts:** well-documented SQLite patterns; validate against Beacon's data rather than reselecting technology.
- **Basic Chart.js line charts:** well-documented once the project's static asset and API DTO are chosen.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Official docs support the retained stack; exact pins and target-Pi behavior still need project validation. |
| Features | MEDIUM | Existing capabilities/constraints are high-confidence codebase evidence; prioritization is product judgement. |
| Architecture | MEDIUM | Direct inspection strongly supports the extraction/ownership recommendation; migration details need local verification. |
| Pitfalls | MEDIUM | Official SQLite, Docker, Playwright, and OWASP guidance is strong; real resource/concurrency thresholds require measurement. |

**Overall confidence:** MEDIUM

### Gaps to Address

- **Current production database variants and data volume:** Inventory schemas, metadata, previews, event history, WAL state, and backup/restore outcomes before finalizing migrations.
- **Target Pi performance budget:** Measure database/WAL size, checkpoint duration, write latency, chart query/payload time, worker RSS/CPU, and Chromium behavior under representative load.
- **Retention resolution choice:** Validate 15-minute host/hourly service aggregates against actual diagnostic needs; document any final change from the proposed 7/14-day raw windows.
- **Network policy compatibility:** Reconcile the strict explicit allowlist/redirect/TLS policy with every valid existing service and any approved certificate exception before rollout.
- **UI acceptance contract:** Define screenshots/DOM/API assertions for both themes, common viewport widths, and loading/stale/empty/error/unknown states.

## Sources

### Primary (HIGH confidence)
- `.planning/PROJECT.md` — product constraints, desired outcomes, deployment model, and non-goals.
- `.planning/codebase/ARCHITECTURE.md`, `CONCERNS.md`, `STRUCTURE.md`, `TESTING.md`, and `INTEGRATIONS.md` — current implementation and behavior evidence cited by the research reports.

### Secondary (MEDIUM confidence)
- [Flask application factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/) and [blueprints](https://flask.palletsprojects.com/en/stable/blueprints/) — modular web composition.
- [SQLite WAL](https://www.sqlite.org/wal.html), [Online Backup API](https://www.sqlite.org/backup.html), [date/time values](https://www.sqlite.org/lang_datefunc.html), [query planning](https://sqlite.org/eqp.html), and [wal_checkpoint](https://www.sqlite.org/pragma.html#pragma_wal_checkpoint) — concurrency, backup, UTC, query, and checkpoint guidance.
- [APScheduler user guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html) — coalescing, misfires, and concurrent-job controls.
- [Chart.js performance](https://www.chartjs.org/docs/latest/general/performance.html) and [decimation](https://www.chartjs.org/docs/latest/configuration/decimation.html) — bounded local chart rendering.
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — allowlists, DNS validation, and redirect handling.
- [Docker Compose services reference](https://docs.docker.com/reference/compose-file/services/) and [Playwright BrowserContext API](https://playwright.dev/docs/api/class-browsercontext) — resource limits and browser lifecycle.
- [Grafana time settings](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/modify-dashboard-settings/), [Grafana time-series](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/time-series/), and [Prometheus storage](https://prometheus.io/docs/prometheus/latest/storage/) — interaction and bounded-retention conventions adapted to Beacon's local scope.

---
*Research completed: 2026-07-24*
*Ready for roadmap: yes*
