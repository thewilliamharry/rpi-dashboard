# Domain Pitfalls

**Domain:** Local Raspberry Pi operations dashboard: Flask API, APScheduler worker, SQLite telemetry, LAN service probing, and browser previews
**Researched:** 2026-07-24
**Confidence:** MEDIUM — findings combine the mapped implementation with current SQLite, Docker, Playwright, and OWASP guidance. Production behavior on the target Pi still needs measured acceptance tests.

## Critical Pitfalls

### Pitfall 1: Data loss or an un-upgradeable existing database

**What goes wrong:** A refactor changes the SQLite schema, names, retention model, or thumbnail storage in place and either loses useful history/service metadata or leaves an old database partly migrated. Copying only `dashboard.db` while it is live in WAL mode can also omit committed data still held in its companion WAL.

**Why it happens:** The current schema evolution is embedded in `init_db()` and inferred from columns rather than represented by ordered, versioned migrations. The same database is live for the web and worker containers and currently holds both telemetry and up-to-2 MiB thumbnail BLOBs.

**Consequences:** A failed rollout can prevent both containers from starting, silently reset 90-day history, orphan previews, or make a rollback impossible. This directly violates the compatibility constraint.

**Prevention:** Establish an explicit schema-version table and forward-only, idempotent migrations before moving tables or changing retention. Wrap each migration in one transaction where SQLite permits it; take and verify a logical point-in-time backup immediately before any destructive migration. Use a two-step copy/switch migration for thumbnails or aggregates: backfill, validate counts/checksums and query results, then switch readers, and only later delete the old representation. Keep the old database readable by the release that made the backup until rollout acceptance completes. SQLite's online backup API creates a consistent snapshot while the source is active, rather than relying on a filesystem copy of one WAL-mode file. [SQLite Backup API](https://www.sqlite.org/backup.html) (MEDIUM)

**Detection:** Migration log has no recorded start/end/version; backup cannot be opened and queried; row counts by table or oldest/newest timestamps change unexpectedly; startup applies schema changes more than once; rollback starts against a newer schema.

**Roadmap phase:** **Phase 1 — Stabilize boundaries and migration contract.** No analytics schema or thumbnail relocation should ship before this gate.

**Migration/test implications:** Maintain fixtures from at least the current production schema, an empty database, and a partially populated database with screenshots and events. Test upgrade, restart during migration, repeated migration invocation, read-only restoration of the backup, and rollback-to-supported-version behaviour. Acceptance should compare service metadata, availability intervals, and sampled-history counts before/after—not just whether the new schema exists.

### Pitfall 2: Treating WAL as multi-writer scalability

**What goes wrong:** The refactor adds 5-second sampling, 90-day rollups, service checks, cleanup, and UI reads against the existing shared SQLite file without changing write ownership. Under preview work or a long dashboard/history read, writes stall, `database is locked` errors surface, jobs misfire, and the WAL grows.

**Why it happens:** WAL allows readers and a writer to overlap, but it still allows only one writer at a time. A checkpoint cannot complete while an older reader needs WAL pages; continuous overlapping readers can cause checkpoint starvation and unbounded WAL growth. Process-local locks in `dashboard/app.py` do not coordinate the web and worker containers. [SQLite WAL documentation](https://www.sqlite.org/wal.html) (MEDIUM)

**Consequences:** Missing samples masquerade as healthy zero/flat data, API latency rises, the disk fills, the worker fails its heartbeat health check, or recovery after an unclean shutdown becomes slow.

**Prevention:** Keep SQLite but make the worker the designated telemetry/event writer for this milestone; web requests must be short read transactions and must not enqueue work by holding a database connection. Batch ingestion and retention changes into bounded transactions, serialize migrations/checkpoints, and expose WAL size, checkpoint result, write latency, and busy/locked retry counts as local health metrics. Run passive checkpoints during normal operation and an explicit, bounded checkpoint as part of controlled shutdown/maintenance—not an unbounded `TRUNCATE` attempt on the request path. If measured contention remains after this discipline, introduce a durable local job queue before adding more collectors; do not add web replicas or a second scheduler to compensate.

**Detection:** WAL file steadily grows across cleanup cycles; checkpoint reports unfinished work; sample timestamps have growing gaps; p95 API latency aligns with check/cleanup jobs; logs contain busy/locked retries; more than one process claims scheduler ownership.

**Roadmap phase:** **Phase 1 — Runtime ownership and persistence contract**, then **Phase 2 — 90-day telemetry pipeline** only after a two-container contention test passes.

**Migration/test implications:** Run Compose-level tests with web reads, metric writes, cleanup, service checks, and a deliberately slow history response concurrently. Force a process restart during a write, then validate SQLite integrity, no duplicated event transition, a recoverable worker heartbeat, and bounded WAL size. Define a documented gap marker when a sample cannot be persisted; never fabricate an interpolated “healthy” sample.

### Pitfall 3: Retention that is bounded in time but not correct or bounded on disk

**What goes wrong:** The project simply changes `cleanup_history()` from one day to 90 days while retaining every high-frequency raw metric, every service check/event, and thumbnail BLOB. Alternatively, a cleanup job deletes by local clock or only one table, leaving aggregate/data relationships inconsistent.

**Why it happens:** Existing history is a short raw series (`METRIC_HISTORY_SECONDS=60`, one-day cleanup) and the new requirement changes both historical duration and the expected analytics queries. Retention is often treated as a nightly `DELETE`, not as a product-level storage and semantics design.

**Consequences:** SD-card pressure, vacuum/checkpoint pauses, slow 90-day queries, misleading availability percentages, and charts whose oldest boundary shifts by timezone, restart, or a delayed cleanup job.

**Prevention:** Define a retention contract before storage changes: timestamps are UTC epoch seconds; “last 90 days” has an inclusive/exclusive boundary; an absent sample is a gap, not a zero; availability is time-weighted from state intervals and records `unknown` across gaps. Retain recent raw samples only for the diagnostic window, then store fixed-resolution rollups (for example 5-minute min/mean/max/count for system metrics and state intervals for services) through day 90. Give each table/index/blob an explicit maximum and a cleanup order, make cleanup idempotent and batched, and record its watermark/rows deleted/duration. Query and alert on data freshness separately from resource values.

**Detection:** Database/WAL/thumbnail directory growth exceeds the budget; counts exceed the 90-day ceiling after cleanup; a single missing interval is rendered as zero; availability changes when a chart range is reloaded; oldest retained bucket is not aligned with the defined cutoff.

**Roadmap phase:** **Phase 2 — Telemetry, rollups, and retention semantics.** It is a prerequisite for advanced historical charts.

**Migration/test implications:** Use deterministic clocks for cutoff and daylight-saving tests; seed 91+ days of raw data with state changes straddling bucket boundaries; verify exact retention, rollup arithmetic, empty/gap rendering, query plans, and storage budget. Test cleanup interruption and retry. Use a real Pi or resource-constrained CI job to measure vacuum/checkpoint time and write latency at the expected maximum data volume.

### Pitfall 4: A “diagnostic” workload creates the outage it reports

**What goes wrong:** Full discovery, HTTP/title fetching, Playwright screenshots, and analytics aggregation share the small APScheduler executors and the Pi's CPU/memory with 5-second collection. A slow or hostile service keeps browser pages alive or causes repeated thumbnail retries, producing sampling gaps and an unresponsive dashboard.

**Why it happens:** Current discovery serially combines port probing, HTTP parsing, and previews; preview work may take up to 27 seconds and Chromium has a substantial footprint. The worker has a 1 GiB memory limit and `shm_size`, but no workload budget that preserves critical sampling. Playwright contexts own pages, and closing a context closes its pages; lifecycle ownership must therefore be explicit. [Playwright BrowserContext API](https://playwright.dev/docs/api/class-browsercontext) (MEDIUM)

**Consequences:** The dashboard reports stale “current” values, health checks flap, OOM kills/restarts lose work, and SD-card writes surge while trying to recover.

**Prevention:** Classify work: heartbeat/system collection and service probes are critical; discovery, screenshot refresh, and historical compaction are best-effort. Use separate, bounded queues/executors with concurrency of one for Chromium; hard deadlines, exponential backoff, per-target failure caching, and cancellation/shutdown cleanup. Always close page/context/browser in `finally` paths and publish a degraded preview state rather than retrying synchronously. Establish a measured resource budget and enforce per-container CPU/memory/PID limits supported by the deployed Compose runtime; Docker documents service `mem_limit`, CPU, and PID constraints, but the configuration must be validated on the actual runtime. [Docker Compose services reference](https://docs.docker.com/reference/compose-file/services/) (MEDIUM)

**Detection:** `last_sample_at` age exceeds twice its interval; scheduler misfire/coalescing counters rise; browser/context/page count grows; preview queue age/retry count rises; worker RSS/CPU, OOM events, and disk I/O spike during scans.

**Roadmap phase:** **Phase 1 — Isolate runtime jobs and lifecycle**, with a **Phase 4 — Pi soak/performance acceptance** gate before enabling frequent previews or full discovery by default.

**Migration/test implications:** Add integration tests for repeated preview failure, scheduler restart, and page/context cleanup. Run a 24-hour constrained-Pi soak with deliberately slow endpoints, a disconnected service, and concurrent dashboard traffic; assert sampling freshness, bounded queue length/RSS/WAL/disk, and that core monitoring continues if Chromium is unavailable.

### Pitfall 5: Extending URL-based probing or previews reopens SSRF/network exposure

**What goes wrong:** Service metadata, discovery, preview capture, or a webhook accepts a URL that passes a coarse trusted-network check but resolves/redirects to an unintended host. Disabling TLS verification for all probes worsens the problem by accepting an intercepted HTTPS endpoint.

**Why it happens:** The worker runs with host networking and is intentionally able to reach the trusted LAN. Existing broad CIDR defaults and the split between URL validation and the actual request make DNS rebinding, IPv6, redirects, unusual ports, and changes to preview tooling easy to miss.

**Consequences:** The dashboard becomes a proxy to host/LAN resources, sends alert details to an unintended webhook, captures sensitive pages in thumbnails, or reports manipulated service health.

**Prevention:** Make a single reusable outbound-target policy the only entry point for probe, HTML fetch, screenshot, and webhook clients: allow only `http`/`https`, explicit configured host/port entries (not broad default private ranges), no userinfo, resolved A and AAAA addresses validated at connection time, redirects disabled or revalidated hop-by-hop, short connect/read/total limits, and certificate verification on by default. Prefer a bridge-networked/sandboxed fetcher with only the routes it requires; isolate Chromium from the monitoring writer. OWASP recommends allowlists over denylists, resolving all A/AAAA answers to defend DNS pinning, disabling automatic redirects, and adding network-layer controls. [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) (MEDIUM)

**Detection:** A configured target has an unapproved scheme/port, DNS answer, redirect, or TLS failure; outbound-denial logs rise; a screenshot job accesses a URL different from the approved endpoint; webhook destination changes without explicit configuration review.

**Roadmap phase:** **Phase 1 — Network policy seam and security regression suite.** Do this before moving fetch code into new modules, so all callers inherit the same policy.

**Migration/test implications:** Add table-driven URL tests for IPv4/IPv6 literals, encoded addresses, loopback, link-local, multicast, invalid schemes, credentials, and redirects. Run a controlled rebinding/redirect test with a fake resolver or local servers; assert every client (requests and Playwright) rejects the target. Test trusted certificates and reject self-signed/invalid certificates unless a narrowly documented per-service exception is approved.

## Moderate Pitfalls

### Pitfall 1: UI parity regressions during light/dark restructuring

**What goes wrong:** Advanced analytics is added to the dense dark view and only superficially reproduced in light mode, or responsive changes hide controls/empty/error states in one theme. Main-dashboard preview analytics are accidentally replaced by the advanced page.

**Prevention:** Define view-model/API contracts independent of theme; use shared data/state components with theme-specific layout tokens. Capture visual/DOM contract tests for both themes and common widths, including stale, empty, unknown, loading, and failure states. Treat light/dark as two presentations of the same capabilities, not separate feature queues.

### Pitfall 2: Monolith extraction changes semantics through import-time work

**What goes wrong:** Splitting `dashboard/app.py` moves scheduler/database initialization into new modules that still execute on import, or both web and worker start jobs after an environment/default regression.

**Prevention:** Use explicit composition roots: a side-effect-free application factory for web and one worker entrypoint that owns scheduling. Inject clock, store, prober, preview, and scheduler interfaces. Add a startup ownership record/lock and test imports without network, DB writes, threads, or scheduler registration.

### Pitfall 3: Availability and state transitions are double-counted

**What goes wrong:** Concurrent periodic checks, a restart recovery, or a migration recomputes current state and inserts duplicate event transitions. “Uptime” is calculated as check-pass percentage rather than duration in each state.

**Prevention:** Give each probe run a durable identity and make state change insertion transactional/idempotent. Model intervals (`start_ts`, `end_ts`, `state`, `source`) and calculate availability as elapsed healthy time divided by known observation time; explicitly display unknown periods.

### Pitfall 4: Tests preserve implementation details but not operator behaviour

**What goes wrong:** Existing unit tests monkeypatch functions in the monolith, so the refactor either breaks tests unnecessarily or changes real Compose behaviour while tests remain green.

**Prevention:** Preserve a thin set of black-box contract tests for API payloads, migrations, worker ownership, persistence, target policy, and theme behaviour. Add Compose integration and realistic constrained-resource smoke/soak coverage; avoid tying new tests to private module names.

## Minor Pitfalls

### Pitfall 1: Time and clock assumptions

**What goes wrong:** Local-time display values leak into storage/cutoffs, host clock adjustment creates non-monotonic samples, or the chart UI assumes perfectly periodic data.

**Prevention:** Store UTC epoch timestamps, use monotonic elapsed time for job-duration metrics, order/deduplicate deterministically, and render gaps/stale data explicitly.

### Pitfall 2: Scope creep toward a monitoring platform

**What goes wrong:** Advanced analytics expands into remote control, accounts, fleet discovery, generic alert routing, or a hosted backend before one-Pi collection is dependable.

**Prevention:** Keep a one-host, configured-service data model and phase exit criteria tied to the stated 90-day/current-diagnostics outcomes. Record remote actions, multi-device support, and hosted storage as non-goals; require a separate safety/design milestone before reconsidering them.

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| 1. Behavioral safety net, modular boundaries, runtime ownership | Import-time schedulers, duplicate job execution, accidental API/UI behaviour changes | Freeze API/UI/persistence contracts first; make web imports side-effect free; give the worker exclusive scheduler ownership; prove it in Compose tests. |
| 1. Persistence and network seams | Data migration without recovery; a new fetch client bypasses policy | Version migrations plus verified pre-migration backup/restore; route every outbound client through one target-policy interface. |
| 2. 90-day telemetry and retention | Raw-data explosion, cutoff/aggregate errors, WAL contention | Define gap/UTC/availability semantics; raw-to-rollup retention tiers; bounded batch cleanup; one writer; WAL/checkpoint and storage-budget metrics. |
| 3. Advanced current diagnostics and both themes | “Current” data is stale; dark-only capability or inaccessible narrow-screen controls | Include freshness in every current-state payload; shared view model; visual contract coverage for both themes and states. |
| 4. Preview/discovery reliability and release hardening | Chromium/slow services starve sampling or leak contexts | Best-effort queue with hard limits/backoff/cleanup; 24-hour constrained-Pi soak; degrade previews independently of monitoring. |
| Any phase | Scope expands to control/fleet/hosted services | Enforce project non-goals in phase acceptance; capture ideas as deferred work rather than adding them to this milestone. |

## Sources

- [SQLite: Write-Ahead Logging](https://www.sqlite.org/wal.html) — WAL concurrency, checkpoint starvation, and checkpoint modes (MEDIUM; official primary source retrieved through WebSearch).
- [SQLite: Online Backup API](https://www.sqlite.org/backup.html) — live point-in-time backup behaviour (MEDIUM; official primary source retrieved through WebSearch).
- [SQLite: Atomic Commit and File Control](https://www.sqlite.org/draft/fileio.html) — DDL/DML can participate in atomic write transactions (MEDIUM; official primary source retrieved through WebSearch).
- [OWASP: SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — allowlists, DNS pinning/rebinding, redirects, and network-layer controls (MEDIUM; primary security guidance retrieved through WebSearch).
- [Docker Compose services reference](https://docs.docker.com/reference/compose-file/services/) — memory, CPU, PID, and swap constraints (MEDIUM; official primary source retrieved through WebSearch).
- [Playwright BrowserContext API](https://playwright.dev/docs/api/class-browsercontext) — context/page lifecycle semantics (MEDIUM; official primary source retrieved through WebSearch).
- Project evidence: `.planning/PROJECT.md`, `.planning/codebase/CONCERNS.md`, `.planning/codebase/TESTING.md`, `.planning/codebase/INTEGRATIONS.md` (HIGH for the current codebase observations).
