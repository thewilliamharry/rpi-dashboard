# Codebase Concerns

**Analysis Date:** 2026-07-24

## Tech Debt

**Large monolithic application module:**
- Issue: HTTP routes, schema migrations, discovery, probing, thumbnail capture, metrics, alerting, and worker coordination are all implemented in `dashboard/app.py` (over 2,000 lines).
- Files: `dashboard/app.py`
- Impact: Changes cross many concerns and require broad regression testing; synchronization and lifecycle bugs are difficult to isolate.
- Fix approach: Split persistence/schema, discovery/probing, previews, metrics, and route handlers into modules with explicit interfaces; retain a thin Flask entrypoint.

**Duplicated background/runtime lifecycle:**
- Issue: Import-time startup is enabled unless `DISABLE_BACKGROUND=1`, while `dashboard/worker.py` separately initializes and schedules jobs.
- Files: `dashboard/app.py`, `dashboard/worker.py`, `dashboard/Dockerfile`
- Impact: Incorrect deployment flags can start schedulers in web processes, duplicate work, or make tests depend on import side effects.
- Fix approach: Keep background startup exclusively in the worker entrypoint and make app imports side-effect free.

**SQLite as shared queue and telemetry store:**
- Issue: The web process and worker coordinate all requests, history, checks, events, and blobs through one SQLite file and process-local locks.
- Files: `dashboard/app.py`, `docker-compose.yml`
- Impact: Locks do not coordinate across processes/containers; write contention, WAL growth, or abrupt shutdown can stall API requests and queued jobs.
- Fix approach: Use a dedicated queue/store or enforce one writer with durable queue semantics; add WAL checkpoint/size monitoring and cross-process locking strategy.

## Known Bugs

**TLS verification is disabled for every outbound request:**
- Symptoms: HTTPS probes and HTML/preview fetches accept invalid or MITM certificates.
- Files: `dashboard/app.py` (`_probe_http`, `_fetch_html_response`)
- Trigger: Configure a service URL with `https://` and intercept or present an untrusted certificate.
- Workaround: Use HTTP only on trusted LANs; no per-service opt-in exists.

## Security Considerations

**SSRF exposure via configurable service URLs:**
- Risk: The browser and requests clients fetch user-configured URLs from a host-networked worker. Broad default trusted networks include RFC1918, CGNAT, and IPv6 ULA ranges.
- Files: `dashboard/app.py`, `docker-compose.yml`
- Current mitigation: URL normalization, host allowlists, redirect checks, userinfo rejection, and no-follow redirects.
- Recommendations: Resolve DNS and validate every resulting IP (including rebinding protection), restrict ports/hosts to explicit configuration, and run fetchers in a network-isolated process.

**Host networking increases blast radius:**
- Risk: `worker` uses `network_mode: host`, so a fetcher compromise can reach all host interfaces and LAN services.
- Files: `docker-compose.yml`
- Current mitigation: dropped capabilities, read-only filesystem, non-root user, and pids/memory limits.
- Recommendations: Prefer bridge networking with narrowly scoped access or a separate sandbox for Chromium and HTTP fetches.

**Webhook destination is externally configurable:**
- Risk: Alert delivery can post service-state data to an arbitrary `ALERT_WEBHOOK_URL`; configuration mistakes can exfiltrate event details.
- Files: `dashboard/app.py`, `docker-compose.yml`
- Current mitigation: Empty by default and cooldown controls.
- Recommendations: Validate webhook scheme/host, redact details, and document secret handling and authentication.

## Performance Bottlenecks

**Periodic full-network discovery:**
- Problem: Discovery scans a port range and performs HTTP/title/thumbnail work serially under a small APScheduler executor.
- Files: `dashboard/app.py`, `dashboard/worker.py`
- Cause: Socket probing, BeautifulSoup parsing, and Playwright screenshots share worker capacity; previews can consume up to 27 seconds each.
- Improvement path: Bound scan ranges, parallelize safe probes, queue previews separately, and cache failures with backoff.

**Thumbnail blobs stored in SQLite:**
- Problem: Up to 2 MiB screenshots are persisted per service in the primary database.
- Files: `dashboard/app.py` (`services.thumb_data`, `/api/thumbnail`)
- Cause: Binary payloads enlarge WAL/backups and make reads compete with telemetry writes.
- Improvement path: Store files/object blobs under managed retention and keep only metadata/path in SQLite.

## Fragile Areas

**Playwright singleton and thread-local preview context:**
- Files: `dashboard/app.py`, `dashboard/worker.py`
- Why fragile: Browser lifecycle is global, guarded by process-local locks, while scheduler jobs and shutdown handlers can overlap; failures are broadly swallowed.
- Safe modification: Add explicit browser ownership, health checks, bounded context/page cleanup, and integration tests for restart and concurrent preview requests.
- Test coverage: Tests mostly monkeypatch `fetch_thumbnail`; real browser lifecycle is not exercised.

**Schema migration-by-introspection:**
- Files: `dashboard/app.py` (`init_db`, `_table_columns`)
- Why fragile: Migrations are embedded in startup code and rely on ad-hoc column checks rather than a migration tool.
- Safe modification: Version every schema change, test upgrades from representative old databases, and make migrations transactional.
- Test coverage: No dedicated migration/upgrade test suite detected.

## Scaling Limits

**Single worker and bounded executors:**
- Current capacity: Gunicorn runs one web worker; scheduler uses one default thread, two probe threads, and one screenshot thread.
- Limit: Long discovery, uptime checks, or screenshots delay queued scans and metadata previews; increasing web replicas would not safely share process locks.
- Scaling path: Separate API, scheduler, and fetch workers with a durable queue and externally coordinated database.

## Dependencies at Risk

**Playwright Chromium footprint:**
- Risk: `playwright install --with-deps chromium` creates a large image and runtime dependency surface on Raspberry Pi deployments.
- Impact: Slow builds, high memory use, and browser startup failures can disable previews while core health checks remain green.
- Migration plan: Make previews optional/degraded, isolate browser image, and expose operational health/queue metrics.

## Missing Critical Features

**Operational authentication/authorization:**
- Problem: Mutation endpoints such as `/api/trigger-scan` and `/api/service-meta/<port>` rely on UI headers/origin checks rather than user identity or credentials.
- Blocks: Safe exposure beyond a trusted LAN and attribution/auditing of configuration changes.

## Test Coverage Gaps

**Real deployment and concurrency behavior:**
- What's not tested: Gunicorn multi-thread requests, two-container SQLite access, scheduler shutdown/restart, actual Chromium screenshots, TLS failures, DNS rebinding, and webhook delivery.
- Files: `tests/`, `dashboard/app.py`, `dashboard/worker.py`, `docker-compose.yml`
- Risk: Production-only races, deadlocks, SSRF bypasses, and resource leaks can pass the current mostly unit-level suite.
- Priority: High

---

*Concerns audit: 2026-07-24*
