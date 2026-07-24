# Coding Conventions

**Analysis Date:** 2026-07-24

## Naming Patterns

**Files:**
- Python modules use lowercase snake case (`dashboard/app.py`, `dashboard/worker.py`, `tests/test_api_and_auth.py`); browser assets use lowercase names (`dashboard/app.js`, `dashboard/style.css`).

**Functions:**
- Functions and Flask handlers use snake_case (`init_db`, `collect_system_stats`, `queue_discovery_request`). Private helpers are prefixed with `_` (`_probe_http`, `_normalize_service_url`).

**Variables:**
- Local and module variables use snake_case; constants are uppercase with underscores (`DB_PATH`, `UPTIME_WINDOW_SECONDS`).

**Types:**
- Test doubles and helper classes use PascalCase (`FakeResponse`, `ThreadingHTTPServer`, `ApiAndAuthTests`). No application type-hint-heavy model layer is present.

## Code Style

**Formatting:**
- Python follows readable PEP 8 layout: four-space indentation, one statement per line, grouped imports, and trailing commas in multiline calls (`dashboard/app.py`). No formatter configuration is checked in.

**Linting:**
- No dedicated flake8/ruff/eslint configuration detected. `pyproject.toml` defines dependencies and pytest settings only.

## Import Organization

**Order:**
1. Python standard library imports (`logging`, `os`, `sqlite3`, `threading`).
2. Third-party imports (`psutil`, `requests`, `flask`, `apscheduler`).
3. Local module imports (`import app as beacon` in `dashboard/worker.py`; `from tests.helpers ...` in tests).

**Path Aliases:**
- No import aliases or package path mappings beyond pytest `pythonpath = [".."]` in `dashboard/pyproject.toml`.

## Error Handling

**Patterns:**
- Narrow exception handling is used for expected parsing/cleanup failures (`except (TypeError, ValueError)` around environment parsing in `dashboard/app.py`; `FileNotFoundError` in `tests/helpers.py`).
- Flask/API validation returns explicit HTTP status responses and JSON reasons; domain validation raises `ValueError` for invalid service URLs/status ranges, asserted in `tests/test_release_contract.py`.
- Cleanup and state-reset logic uses `try/finally` to restore monkeypatches and clear scan state (`tests/test_security_and_scanning.py`).

## Logging

**Framework:** Python `logging` configured at INFO in `dashboard/app.py` and `dashboard/worker.py`.

**Patterns:**
- Module loggers are created with `logging.getLogger(__name__)` (or a component name in the worker); scheduler noise is reduced with a targeted logger level in `dashboard/worker.py`.

## Comments

**When to Comment:**
- Comments identify migrations and non-obvious compatibility/security behavior (for example, the older `services` table migration in `dashboard/app.py`). Most straightforward code is self-documenting.

**JSDoc/TSDoc:**
- No systematic JSDoc/TSDoc or Python docstring convention detected.

## Function Design

**Size:** Keep route/business helpers cohesive; `dashboard/app.py` contains larger orchestration functions for discovery and uptime workflows.

**Parameters:** Use explicit parameters and keyword arguments for options (`do_uptime_check(only_down=False)`, `run_discovery(source='scheduled')`).

**Return Values:** API handlers return Flask responses/JSON; internal probes return tuples with status, latency, error class, and response. Tests assert tuple fields and response contracts directly.

## Module Design

**Exports:** `dashboard/app.py` is the shared application/service module; `dashboard/worker.py` imports it as `beacon` and invokes its functions. Tests import through `dashboard.app`.

**Barrel Files:** No barrel/index modules detected.

---

*Convention analysis: 2026-07-24*
