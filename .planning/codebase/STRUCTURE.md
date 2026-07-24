# Codebase Structure

**Analysis Date:** 2026-07-24

## Directory Layout

```text
rpi-dashboard/
├── dashboard/          # Application, frontend assets, container/build metadata
├── tests/               # Pytest contract, integration, security, and UI tests
├── .github/workflows/   # CI automation
├── .planning/codebase/  # Generated architecture/quality maps
├── docker-compose.yml   # worker/web/data-init deployment
└── README.md            # Project/operator documentation
```

## Directory Purposes

**`dashboard/`:**
- Purpose: Self-contained Python service and browser dashboard.
- Key files: `dashboard/app.py`, `dashboard/worker.py`, `dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css`, `dashboard/pyproject.toml`, `dashboard/Dockerfile`.

**`tests/`:**
- Purpose: Black-box and contract validation against the Flask app and deployment artifacts.
- Key files: `tests/test_api_and_auth.py`, `tests/test_uptime_integration.py`, `tests/test_release_contract.py`, `tests/test_security_and_scanning.py`, `tests/test_ui_contract.py`, `tests/helpers.py`.

**`.github/workflows/`:**
- Purpose: CI checks and dependency automation; inspect workflow files before changing build/test commands.

## Key File Locations

**Entry Points:**
- `dashboard/app.py`: Flask application object and all HTTP routes.
- `dashboard/worker.py`: APScheduler process entry point.
- `dashboard/index.html`: Browser document entry.

**Configuration:**
- `dashboard/pyproject.toml`: Python version, dependencies, pytest settings.
- `dashboard/uv.lock`: Locked Python dependency graph.
- `docker-compose.yml`: Container commands, environment, volumes, health checks, resource/security constraints.
- `dashboard/Dockerfile`: Image build/runtime setup.

**Core Logic:**
- `dashboard/app.py`: database schema, probes, discovery, uptime, metrics, API/security helpers.
- `dashboard/app.js`: client polling, rendering, metadata modal, scan interactions.

**Testing:**
- `tests/` (repository-level pytest suite); test imports are enabled by `dashboard/pyproject.toml` `pythonpath = [".."]`.

## Naming Conventions

**Files:** Python modules use lowercase snake_case (`app.py`, `worker.py`); frontend assets use lowercase names (`app.js`, `style.css`). Tests use `test_*.py`.

**Functions/variables:** Python uses snake_case; private helpers are prefixed `_`. JavaScript uses camelCase for functions and variables, with DOM IDs in kebab-free descriptive forms.

**Directories:** Lowercase descriptive directories (`dashboard`, `tests`, `.planning`).

## Where to Add New Code

**New Feature:**
- Backend operation and route: `dashboard/app.py` (preserve helper/route organization and SQLite locking).
- Scheduled behavior: add a bounded APScheduler job in `dashboard/worker.py`.
- UI behavior: `dashboard/app.js`; markup in `dashboard/index.html`; styling in `dashboard/style.css`.
- Tests: add focused files under `tests/` following existing `test_*.py` patterns.

**New Component/Module:** Keep deployable runtime modules under `dashboard/`; update `dashboard/Dockerfile`/`pyproject.toml` if dependencies or copy rules change.

**Utilities:** Reuse private helpers in `dashboard/app.py`; avoid duplicating URL/security/database logic in route functions.

## Special Directories

**`dashboard/.venv/`:** Local virtual environment; generated, not application source, and should not be committed.

**`.planning/codebase/`:** Generated mapping artifacts consumed by GSD planning; committed project documentation.

**`dashboard/__pycache__/`, `tests/__pycache__/`, `.pytest_cache/`:** Runtime/test caches; generated and not committed.

---

*Structure analysis: 2026-07-24*
