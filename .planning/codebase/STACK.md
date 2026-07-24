# Technology Stack

**Analysis Date:** 2026-07-24

## Languages

**Primary:**
- Python 3.11–3.12 (`dashboard/app.py`, `dashboard/worker.py`) - Flask web API, SQLite persistence, discovery and background jobs.
- JavaScript (browser, `dashboard/app.js`) - dashboard UI behavior and API client.
- HTML/CSS (`dashboard/index.html`, `dashboard/style.css`) - single-page dashboard presentation.

## Runtime

**Environment:**
- Python `python:3.12-slim-bookworm` container (`dashboard/Dockerfile`), requiring Python `>=3.11,<3.13`.

**Package Manager:**
- uv `0.11.28`, dependencies locked in `dashboard/uv.lock`.
- Lockfile: present

## Frameworks

**Core:**
- Flask `3.1.3` - HTTP routes and JSON/static responses (`dashboard/app.py`).
- Gunicorn `26.0.0` - production WSGI server, one worker with eight threads (`dashboard/Dockerfile`).
- APScheduler `3.11.3` - UTC interval/date jobs for metrics, probes, discovery, previews and cleanup (`dashboard/worker.py`).

**Testing:**
- pytest `>=9,<10` (`dashboard/pyproject.toml`, `tests/`).
- pip-audit `2.10.1` for dependency vulnerability checks.

**Build/Dev:**
- Docker Compose (`docker-compose.yml`) orchestrates `data-init`, `worker`, and `web`.
- Playwright `1.61.0` with bundled Chromium (`dashboard/Dockerfile`) captures service thumbnails and supports smoke checks.

## Key Dependencies

**Critical:**
- `requests==2.34.2` and `urllib3==2.7.0` - HTTP service probing, redirects, and optional alert webhook delivery (`dashboard/app.py`).
- `beautifulsoup4==4.15.0` - parse discovered HTML titles and metadata (`dashboard/app.py`).
- `psutil==7.2.2` - CPU, RAM, disk, temperature and process/system metrics (`dashboard/app.py`).
- Python stdlib `sqlite3` - embedded persistent database at `/data/dashboard.db`.

**Infrastructure:**
- `playwright==1.61.0`/Chromium - isolated browser previews.
- `threading` locks/semaphores - coordinate SQLite, scans, browser and uptime workers.

## Configuration

**Environment:**
- Runtime is configured through Compose environment (`docker-compose.yml`) and `os.environ` defaults in `dashboard/app.py`.
- Key settings include `DB_PATH`, discovery/metric intervals, trusted host/network allowlists, `EXTRA_SCAN_PORTS`, `ALERT_WEBHOOK_URL`, alert cooldown/filtering, and `ENABLE_PROMETHEUS`.

**Build:**
- `dashboard/Dockerfile` pins base image by digest, installs frozen uv dependencies and Chromium, and runs as UID/GID 10001.
- `dashboard/pyproject.toml` defines package metadata, versions and pytest paths.

## Platform Requirements

**Development:**
- Docker Compose, uv, and Python 3.11/3.12; tests run with `uv run --project dashboard python -m pytest -q`.

**Production:**
- 64-bit Raspberry Pi OS with Docker Compose; host networking is required by `worker` to probe LAN services. Named volume `dashboard-data` provides writable SQLite storage while containers remain read-only.

---

*Stack analysis: 2026-07-24*
