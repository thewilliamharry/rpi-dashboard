<!-- GSD:project-start source:PROJECT.md -->

## Project

**Beacon**

Beacon is a self-contained, local-only Raspberry Pi operations dashboard for understanding the Pi's current system health and the availability of configured LAN or web services. It combines a simple everyday dashboard with service links and previews, system information, uptime monitoring, and a separate advanced analytics and monitoring workspace.

The product is primarily for its operator on a trusted local network. It deliberately offers two visual experiences: light mode is simpler and calmer, while dark mode is denser and more hands-on without withholding functionality.

**Core Value:** At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.

### Constraints

- **Deployment**: Must remain self-contained on a 64-bit Raspberry Pi using Docker Compose — simple local operation is central to the product
- **Network scope**: Monitor one host Pi and explicitly configured or discovered trusted LAN/web services — fleet management is not part of this milestone
- **Security model**: Operates only on a trusted local network, but outbound fetching and mutation endpoints must still maintain narrow, testable safety boundaries
- **Data retention**: Advanced analytics retains a rolling 90 days of history with bounded storage, aggregation, and cleanup behavior
- **Theme behavior**: Compact preview analytics remain on the main dashboard in both themes; advanced analytics is fully functional in both themes
- **Experience**: Light mode stays calm and simple; dark mode remains denser and more hands-on
- **Compatibility**: Existing useful dashboard capabilities and stored data should survive restructuring unless an explicitly approved migration replaces them
- **Performance**: Monitoring, discovery, and thumbnail work must not create visible sampling gaps or make the dashboard unresponsive on Raspberry Pi hardware
- **Maintainability**: New features must use explicit module boundaries and testable interfaces rather than increasing the existing monolith

<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->

## Technology Stack

## Languages

- Python 3.11–3.12 (`dashboard/app.py`, `dashboard/worker.py`) - Flask web API, SQLite persistence, discovery and background jobs.
- JavaScript (browser, `dashboard/app.js`) - dashboard UI behavior and API client.
- HTML/CSS (`dashboard/index.html`, `dashboard/style.css`) - single-page dashboard presentation.

## Runtime

- Python `python:3.12-slim-bookworm` container (`dashboard/Dockerfile`), requiring Python `>=3.11,<3.13`.
- uv `0.11.28`, dependencies locked in `dashboard/uv.lock`.
- Lockfile: present

## Frameworks

- Flask `3.1.3` - HTTP routes and JSON/static responses (`dashboard/app.py`).
- Gunicorn `26.0.0` - production WSGI server, one worker with eight threads (`dashboard/Dockerfile`).
- APScheduler `3.11.3` - UTC interval/date jobs for metrics, probes, discovery, previews and cleanup (`dashboard/worker.py`).
- pytest `>=9,<10` (`dashboard/pyproject.toml`, `tests/`).
- pip-audit `2.10.1` for dependency vulnerability checks.
- Docker Compose (`docker-compose.yml`) orchestrates `data-init`, `worker`, and `web`.
- Playwright `1.61.0` with bundled Chromium (`dashboard/Dockerfile`) captures service thumbnails and supports smoke checks.

## Key Dependencies

- `requests==2.34.2` and `urllib3==2.7.0` - HTTP service probing, redirects, and optional alert webhook delivery (`dashboard/app.py`).
- `beautifulsoup4==4.15.0` - parse discovered HTML titles and metadata (`dashboard/app.py`).
- `psutil==7.2.2` - CPU, RAM, disk, temperature and process/system metrics (`dashboard/app.py`).
- Python stdlib `sqlite3` - embedded persistent database at `/data/dashboard.db`.
- `playwright==1.61.0`/Chromium - isolated browser previews.
- `threading` locks/semaphores - coordinate SQLite, scans, browser and uptime workers.

## Configuration

- Runtime is configured through Compose environment (`docker-compose.yml`) and `os.environ` defaults in `dashboard/app.py`.
- Key settings include `DB_PATH`, discovery/metric intervals, trusted host/network allowlists, `EXTRA_SCAN_PORTS`, `ALERT_WEBHOOK_URL`, alert cooldown/filtering, and `ENABLE_PROMETHEUS`.
- `dashboard/Dockerfile` pins base image by digest, installs frozen uv dependencies and Chromium, and runs as UID/GID 10001.
- `dashboard/pyproject.toml` defines package metadata, versions and pytest paths.

## Platform Requirements

- Docker Compose, uv, and Python 3.11/3.12; tests run with `uv run --project dashboard python -m pytest -q`.
- 64-bit Raspberry Pi OS with Docker Compose; host networking is required by `worker` to probe LAN services. Named volume `dashboard-data` provides writable SQLite storage while containers remain read-only.

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

## Naming Patterns

- Python modules use lowercase snake case (`dashboard/app.py`, `dashboard/worker.py`, `tests/test_api_and_auth.py`); browser assets use lowercase names (`dashboard/app.js`, `dashboard/style.css`).
- Functions and Flask handlers use snake_case (`init_db`, `collect_system_stats`, `queue_discovery_request`). Private helpers are prefixed with `_` (`_probe_http`, `_normalize_service_url`).
- Local and module variables use snake_case; constants are uppercase with underscores (`DB_PATH`, `UPTIME_WINDOW_SECONDS`).
- Test doubles and helper classes use PascalCase (`FakeResponse`, `ThreadingHTTPServer`, `ApiAndAuthTests`). No application type-hint-heavy model layer is present.

## Code Style

- Python follows readable PEP 8 layout: four-space indentation, one statement per line, grouped imports, and trailing commas in multiline calls (`dashboard/app.py`). No formatter configuration is checked in.
- No dedicated flake8/ruff/eslint configuration detected. `pyproject.toml` defines dependencies and pytest settings only.

## Import Organization

- No import aliases or package path mappings beyond pytest `pythonpath = [".."]` in `dashboard/pyproject.toml`.

## Error Handling

- Narrow exception handling is used for expected parsing/cleanup failures (`except (TypeError, ValueError)` around environment parsing in `dashboard/app.py`; `FileNotFoundError` in `tests/helpers.py`).
- Flask/API validation returns explicit HTTP status responses and JSON reasons; domain validation raises `ValueError` for invalid service URLs/status ranges, asserted in `tests/test_release_contract.py`.
- Cleanup and state-reset logic uses `try/finally` to restore monkeypatches and clear scan state (`tests/test_security_and_scanning.py`).

## Logging

- Module loggers are created with `logging.getLogger(__name__)` (or a component name in the worker); scheduler noise is reduced with a targeted logger level in `dashboard/worker.py`.

## Comments

- Comments identify migrations and non-obvious compatibility/security behavior (for example, the older `services` table migration in `dashboard/app.py`). Most straightforward code is self-documenting.
- No systematic JSDoc/TSDoc or Python docstring convention detected.

## Function Design

## Module Design

<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

## System Overview

```text

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

- `dashboard/app.py` contains both HTTP handlers and domain/data operations; worker imports it as a module.
- APScheduler uses bounded thread pools for metrics, probes, screenshots, and default jobs (`dashboard/worker.py`).
- SQLite WAL mode, explicit locks, and runtime state rows coordinate processes.
- Frontend is dependency-free vanilla JavaScript; all dynamic data comes from `/api/*` polling endpoints.

## Layers

- Purpose: Serve static assets and JSON endpoints; enforce host/origin and security headers.
- Location: `dashboard/app.py` route functions; assets in `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css`.
- Depends on: persistence/domain functions in same module.
- Purpose: Discover services, probe health, calculate uptime, collect system metrics, create events/alerts, render thumbnails.
- Location: `dashboard/app.py` functions `run_discovery`, `do_uptime_check`, `collect_system_stats`, `_handle_state_transition`.
- Depends on: `requests`, `psutil`, BeautifulSoup, Playwright, SQLite.
- Purpose: Trigger operations periodically and recover worker state.
- Location: `dashboard/worker.py`.
- Depends on: exported operations/constants from `dashboard/app.py`.
- Purpose: Persist services, metadata, checks, events, metrics, queue requests, and runtime state.
- Location: SQLite initialized by `init_db()` in `dashboard/app.py`; volume defined in `docker-compose.yml`.

## Data Flow

### Primary Request Path

### Background Monitoring Flow

## Key Abstractions

## Entry Points

## Architectural Constraints

- **Concurrency:** Web and worker are separate processes sharing SQLite; writes must retain explicit transactions/locks.
- **Global state:** Module-level Flask app, locks, browser singleton, and configuration in `dashboard/app.py`.
- **Deployment:** Containers run as UID 10001 with read-only filesystems; only `/data` volume is writable (`docker-compose.yml`).
- **Network:** Worker uses host networking for LAN discovery; web exposes port 80 mapped to 8080.

## Anti-Patterns

### Mixing web and domain concerns

### Direct cross-process in-memory coordination

## Error Handling

## Cross-Cutting Concerns

<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `$gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `$gsd-debug` for investigation and bug fixing
- `$gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `$gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
