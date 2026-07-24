# External Integrations

**Analysis Date:** 2026-07-24

## APIs & External Services

**LAN HTTP services:**
- Discovered services on loopback, Pi aliases and configured private networks are probed with `requests` (`dashboard/app.py:586`, `dashboard/app.py:636`); HTML is parsed with BeautifulSoup and screenshots may be captured with Chromium.
- SDK/Client: `requests==2.34.2`, `beautifulsoup4==4.15.0`, `playwright==1.61.0`.
- Auth: no dashboard account; optional target authentication is represented by configured service metadata/accepted status codes.

**Alert webhook:**
- Optional POST transition notifications to `ALERT_WEBHOOK_URL` (`dashboard/app.py:806-828`).
- SDK/Client: `requests.post` JSON payload with four-second timeout.
- Auth: URL itself (environment variable); no provider-specific SDK.

**Prometheus scrape endpoint:**
- Optional local `/metrics` exposition controlled by `ENABLE_PROMETHEUS` (`dashboard/app.py:2034`). This is pull-based and does not require a remote backend.

## Data Storage

**Databases:**
- SQLite file `/data/dashboard.db` (override `DB_PATH`) with additive migrations, WAL mode, busy timeout and foreign keys (`dashboard/app.py:98-110`).
- Client: Python stdlib `sqlite3`; shared by `web` and `worker` through Compose named volume.

**File Storage:**
- Docker named volume `dashboard-data` mounted at `/data` stores SQLite database and thumbnail BLOBs (`docker-compose.yml`). No object storage integration.

**Caching:**
- In-process/module state and SQLite tables cache metrics, service checks, runtime state and screenshots; no Redis or external cache.

## Authentication & Identity

**Auth Provider:**
- Custom network trust controls, not user authentication. Flask host/origin validation uses `TRUSTED_HOSTS` and private CIDR allowlists; service URL targets are restricted to loopback/configured Pi aliases (`dashboard/app.py`).

## Monitoring & Observability

**Error Tracking:**
- None detected. Health/readiness endpoints (`/healthz`, `/readyz`) and optional Prometheus metrics provide machine checks.

**Logs:**
- Python `logging` to stdout; Gunicorn access log to stdout (`dashboard/app.py`, `dashboard/Dockerfile`). Docker Compose healthchecks inspect HTTP endpoints and worker heartbeat in SQLite.

## CI/CD & Deployment

**Hosting:**
- Self-hosted Raspberry Pi via Docker Compose; `web` publishes host port 80 and `worker` uses host networking (`docker-compose.yml`).

**CI Pipeline:**
- GitHub Actions (`.github/workflows/ci.yml`) runs pytest, pip-audit, Compose validation/build, smoke checks and Trivy image scanning. Dependabot configuration covers Python, Docker and Actions updates.

## Environment Configuration

**Required env vars:**
- No mandatory secrets. Operational variables include `DB_PATH`, `TRUSTED_HOSTS`, `LOCAL_SERVICE_HOSTS`, `EXTRA_SCAN_PORTS`, metric/discovery timing, `ENABLE_PROMETHEUS`, and optional `ALERT_WEBHOOK_URL` (`dashboard/app.py`, `docker-compose.yml`).

**Secrets location:**
- Values are supplied through Compose environment or deployment environment; `.env` files may be used by Compose but are not required or read by application code.

## Webhooks & Callbacks

**Incoming:**
- None; Flask exposes REST-like dashboard and health routes only (`dashboard/app.py:1681-2035`).

**Outgoing:**
- Optional alert transition POST to `ALERT_WEBHOOK_URL`; cooldown and critical-only filters are enforced in `dashboard/app.py`.

---

*Integration audit: 2026-07-24*
