# External Integrations

**Analysis Date:** 2026-08-27

## APIs & External Services

**Service Discovery & Probing:**
- HTTP/HTTPS service probing via `requests` library
  - Arbitrary TCP port scanning (default ports: 80, 443, 8100, user-configurable)
  - Outbound policy validates DNS resolution and network access before connecting
  - Used by: `dashboard/beacon/diagnosis.py` (service discovery), `dashboard/app.py` (_legacy_probe_http)
  - No authentication required; probes hit local/LAN services only

**Webhook Alerts:**
- Optional webhook endpoint for service state alerts
  - Configured via env var: `ALERT_WEBHOOK_URL`
  - Supports HTTP/HTTPS with strict certificate validation (no LAN exception)
  - HTTP POST payload with incident JSON data
  - Outbound policy enforces no redirects for webhooks
  - Rate-limited by `ALERT_COOLDOWN_SECONDS` (default 300s)
  - Only critical incidents reported if `ALERT_ONLY_CRITICAL=1`
  - Retry logic: exponential backoff from 300s to 3600s (configurable)
  - Used by: `dashboard/beacon/incidents.py`

**HTML Content Retrieval:**
- Fetch and parse service web pages for previews
  - BeautifulSoup4 parses HTML to extract title, status, links
  - Used by: `dashboard/beacon/previews.py`, `dashboard/app.py` (_legacy_screenshot_service)
  - No external API authentication; retrieves from local/LAN services

**Browser Preview & Screenshot:**
- Playwright Chromium browser for rendering service web pages
  - Installed in Docker image at build time (`playwright install --with-deps chromium`)
  - Connects to localhost (no external internet)
  - Sandbox constraints: non-root execution, read-only root filesystem, capability dropping
  - Used by: `dashboard/app.py` (screenshot rendering), browser automation tests

## Data Storage

**Databases:**
- SQLite 3 (Python stdlib `sqlite3`)
  - Single file at `/data/dashboard.db` (mounted volume)
  - No ORM; raw SQL queries in `dashboard/beacon/repositories.py`, `dashboard/beacon/migrations.py`
  - Connection pooling via custom `ManagedConnection` class with maintenance lock (`dashboard/beacon/db.py`)
  - PRAGMA settings, all set explicitly in `connect_db`: `busy_timeout=30000`, `foreign_keys=ON`, `journal_mode=WAL`
  - Transactions managed explicitly: `read_transaction()`, `write_transaction()` context managers
  - Schema versioned via `dashboard/beacon/migrations.py` (hand-written migrations, no Alembic)

**File Storage:**
- Local filesystem only
  - `/data/dashboard.db` - Main SQLite database
  - `/data/previews/` - Service preview screenshots (JPEG, refreshed daily by `THUMB_REFRESH_DAYS`)
  - `/tmp/` - Temporary files (mounted as tmpfs, cleared on restart)

**Caching:**
- In-memory: Python object caching (no Redis/Memcached)
  - `dashboard/app.py`: `servicesByPort` Map in JavaScript frontend
  - `dashboard/beacon/queues.py`: In-memory job queue with SQLite backing

## Authentication & Identity

**Access Control:**
- No username/password authentication
- Trust-based access control via `TRUSTED_HOSTS` and `TRUSTED_HOST_NETWORKS` configuration
  - Default trusted networks: localhost, RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Configurable via env vars: `TRUSTED_HOSTS`, `LOCAL_SERVICE_HOSTS`, `SERVICE_TARGET_HOSTS`, `SERVICE_TARGET_NETWORKS`
  - Used by: `dashboard/app.py` (_parse_trusted_hosts), `dashboard/beacon/outbound.py` (outbound policy)

**Outbound Network Policy:**
- `dashboard/beacon/outbound.py`: Immutable policy for all outbound requests
  - Validates DNS resolution before each connection
  - Enforces separate network policies for service probes vs. webhooks
  - LAN certificate exception for service probes (localhost, RFC1918, link-local)
  - Strict TLS verification for webhook endpoints (no exceptions)
  - Purpose-specific timeouts: service probes (2.5s), browser previews (27s), webhooks (configurable)
  - Resolver injected for deterministic testing

## Monitoring & Observability

**Error Tracking:**
- None; errors logged to stdout/stderr only

**Logs:**
- Standard Python logging to stdout (Gunicorn captures and forwards)
  - Format: `%(asctime)s %(levelname)s %(message)s`
  - Level: INFO by default
  - Docker logs available via `docker logs beacon-web` and `docker logs beacon-worker`

**Prometheus Metrics (Optional):**
- Endpoint: `GET /metrics`
- Disabled by default; enable with `ENABLE_PROMETHEUS=1`
- Exports: CPU %, RAM pressure %, RAM used (bytes), disk %, services online count, services total count
- Format: Prometheus text exposition format (v0.0.4)
- Status: 503 if metrics not ready, 404 if disabled, 200 with metrics

## CI/CD & Deployment

**Hosting:**
- Self-hosted Docker containers on Raspberry Pi or compatible Linux
- No cloud platform dependency (AWS, GCP, Azure)
- Composition: web service on port 80, worker on host network, migrate init container, data ownership init

**CI Pipeline:**
- GitHub Actions (`.github/workflows/ci.yml`)
- Triggers: push, pull_request
- Jobs:
  1. **test-and-audit** (ubuntu-latest):
     - Setup Python 3.12, uv 0.11.28
     - Run pytest with `uv run --frozen`
     - Run pip-audit for dependency vulnerabilities
  2. **image-scan** (ubuntu-latest):
     - Build Docker image (beacon:2.0.1)
     - Run docker-compose health checks
     - Scan with Trivy (v0.70.0) for HIGH/CRITICAL vulnerabilities
     - Exit code 1 on unfixed vulnerabilities
  3. **arm64-runtime** (ubuntu-24.04-arm):
     - Build and run on actual ARM64 hardware
     - Verify Chromium sandbox constraints (non-root, read-only, capabilities dropped)

**Dependency Updates:**
- Dependabot (`.github/dependabot.yml`)
  - pip: weekly updates
  - docker: weekly updates
  - github-actions: weekly updates

## Environment Configuration

**Required env vars (none; all have defaults):**
- Example deployment config in `docker-compose.yml`: `EXPIRE_DAYS`, `METRIC_SAMPLE_SECONDS`, `WORKER_READY_SECONDS`, etc.

**Critical env vars (for production use):**
- `TRUSTED_HOSTS` - Restrict dashboard access to specific networks
- `ALERT_WEBHOOK_URL` - Enable incident notifications
- `TZ` - Set timezone for timestamps
- `ENABLE_PROMETHEUS` - Enable metrics export for monitoring systems

**Secrets location:**
- Environment variables only; no .env files committed
- Docker: passed via `environment:` section in docker-compose.yml or at runtime
- No API keys stored in code; webhooks configured via URL only

## Webhooks & Callbacks

**Incoming:**
- Health check endpoints:
  - `GET /healthz` - Simple health check (returns 200 OK)
  - `GET /readyz` - Readiness check (returns 200 OK when ready)
- Used by: Docker Compose health checks and orchestrators

**Outgoing:**
- Alert webhooks (`ALERT_WEBHOOK_URL`)
  - HTTP POST to configured URL
  - JSON payload with incident data (service, status, event type, timestamp)
  - Retry on failure (exponential backoff)
  - No redirect following for webhook requests (security)

**Monitoring Callbacks:**
- Worker heartbeat stored in SQLite (`runtime_state` table)
- Docker health checks query heartbeat from database to verify worker liveness
- No external monitoring callbacks

---

*Integration audit: 2026-08-27*
