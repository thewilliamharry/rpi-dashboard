# Technology Stack

**Analysis Date:** 2026-08-27

## Languages

**Primary:**
- Python 3.11–3.12 - Backend API, worker processes, database migrations, CLI utilities
- JavaScript (vanilla, no framework) - Frontend dashboard and advanced UI
- HTML5/CSS3 - Markup and styling for web interface

## Runtime

**Environment:**
- Docker container (Python 3.12-slim-bookworm base image)
- Single-user non-root execution (UID 10001, GID 10001)
- Read-only root filesystem with tmpfs for /tmp and /data volume mount

**Package Manager:**
- `uv` (0.11.28) - Python dependency management and virtual environment
- Lockfile: `dashboard/uv.lock` (present and frozen)

## Frameworks

**Core:**
- Flask 3.1.3 - REST API web framework, routing, request/response handling
- APScheduler 3.11.3 - Scheduled job execution (service discovery, metrics collection, maintenance)

**Testing:**
- Pytest 9.0.2+ - Unit and integration test framework
- Playwright 1.61.0 - Browser automation for contract tests (Chromium browser)

**Build/Runtime:**
- Gunicorn 26.0.0 - Production WSGI application server (1 worker, 8 threads, 60s timeout)
- Docker Compose - Local development and deployment orchestration

## Key Dependencies

**Critical:**
- `requests` 2.34.2 - HTTP client for service probing, webhook delivery, HTML content retrieval
- `urllib3` 2.7.0 - HTTP connection pooling and SSL/TLS handling (transitive via requests)
- `beautifulsoup4` 4.15.0 - HTML parsing for service previews and content extraction
- `psutil` 7.2.2 - System metrics collection (CPU, RAM, disk, temperature)
- `playwright` 1.61.0 - Headless browser automation for screenshot/preview generation
- `tzdata` 2026.3 - Timezone database for IANA zone support

**Task Scheduling:**
- `apscheduler` 3.11.3 - Job scheduling (depends on `tzlocal`)

**Security & Auditing:**
- `pip-audit` 2.10.1 (dev) - Vulnerability scanning for Python dependencies

## Configuration

**Environment:**
- Configuration loaded from environment variables at startup
- Settings immutable in `dashboard/beacon/config.py` via `load_settings()` function
- No config files required; all settings have safe defaults

**Key Runtime Configuration:**
- `DB_PATH` - SQLite database location (default: `/data/dashboard.db`)
- `TRUSTED_HOSTS` - IP addresses/networks allowed to access dashboard (default: local networks)
- `ALERT_WEBHOOK_URL` - Optional webhook endpoint for alert notifications
- `ENABLE_PROMETHEUS` - Enable Prometheus metrics endpoint at `/metrics` (default: disabled)
- `TZ` - IANA timezone name for timestamps (default: `UTC`)
- Telemetry retention, sampling, and history parameters (7 dev settings with validation)
- Maintenance window and scan rate limiting settings

**Build:**
- `Dockerfile` at `dashboard/Dockerfile` - Multi-stage container build
- `docker-compose.yml` - Local composition with 4 services: `data-init`, `migrate`, `worker`, `web`
- `pyproject.toml` - Dependency declarations and pytest configuration
- `.github/workflows/ci.yml` - GitHub Actions CI pipeline (unit tests, Docker image scan, ARM runtime verification)

## Platform Requirements

**Development:**
- Docker and Docker Compose
- Python 3.11+
- `uv` 0.11.28 or compatible
- Bash shell for scripts

**Production:**
- Raspberry Pi (ARMv7 or ARMv8 CPU) or compatible ARM/x86 Linux system
- Docker runtime
- 256MB–1GB RAM allocation per service (web, worker, migrate containers)
- Persistent volume for SQLite database and preview cache
- Network access to local services (typically on port 80 for dashboard, 8100 for extra scans)

**Container Requirements:**
- Linux kernel with `CAP_CHOWN` for data initialization
- Capability dropping for security (`CAP_DROP: [ALL]`)
- Read-only root filesystem enforcement
- tmpfs mounts for temporary data (no-exec, nosuid, nodev flags)

---

*Stack analysis: 2026-08-27*
