# Testing Patterns

**Analysis Date:** 2026-07-24

## Test Framework

**Runner:**
- pytest (>=9,<10) is declared in the dev dependency group in `dashboard/pyproject.toml`; tests are written with `unittest.TestCase` classes and discovered from `tests/`.
- Config: `dashboard/pyproject.toml` (`[tool.pytest.ini_options]`, `pythonpath = [".."]`, `testpaths = ["../tests"]`).

**Assertion Library:**
- Standard `unittest` assertions (`assertEqual`, `assertTrue`, `assertRaises`, `assertIn`, etc.); no separate assertion library.

**Run Commands:**
```bash
pytest
pytest -q
pytest tests/test_api_and_auth.py
```

## Test File Organization

**Location:** Tests are separated from implementation in the top-level `tests/` directory; UI contract tests inspect files under `dashboard/` directly.

**Naming:** Files use `test_*.py`; classes end in `Tests`; methods begin `test_` (`tests/test_release_contract.py`).

**Structure:**
```
tests/helpers.py
tests/test_api_and_auth.py
tests/test_release_contract.py
tests/test_security_and_scanning.py
tests/test_ui_contract.py
tests/test_uptime_integration.py
```

## Test Structure

**Suite Organization:**
```python
class ApiAndAuthTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app({...})
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_trigger_scan_rate_limit(self):
        response = self.client.post('/api/trigger-scan', headers=self.ui_headers)
        self.assertEqual(response.status_code, 202)
```

**Patterns:**
- `tests/helpers.py::load_app` sets isolated environment variables, reloads `dashboard.app`, creates a temporary SQLite database, disables background work, and calls `init_db()`.
- Flask routes are exercised through `app.test_client()`; database setup uses `_db_lock`, `get_db()`, explicit SQL inserts, `commit()`, and `close()`.
- Tests clean up temporary DB files in `tearDown`; monkeypatches are restored in `finally` blocks.

## Mocking

**Framework:** `unittest.mock` is used sparingly; most seams are replaced by assigning lambdas/functions to module attributes.

**Patterns:**
```python
original_probe = self.appmod._probe_http
self.appmod._probe_http = fake_probe
try:
    self.appmod.do_uptime_check(only_down=False)
finally:
    self.appmod._probe_http = original_probe
```

**What to Mock:** Network probes (`requests.get`, `_probe_http`), thumbnail capture, socket connections, time/sleep, and unavailable `psutil` via the stub in `tests/helpers.py`.

**What NOT to Mock:** SQLite persistence and Flask routing are generally tested against real temporary databases and Flask's real test client.

## Fixtures and Factories

**Test Data:** Small inline tuples/rows and purpose-built doubles (`FakeResponse`, `Memory`, `DummySock`) are preferred; shared server helpers are provided by `run_server()` in `tests/helpers.py`.

**Location:** Shared setup/cleanup and HTTP server fixtures live in `tests/helpers.py`; domain records are created inline within each suite.

## Coverage

**Requirements:** No coverage threshold or coverage configuration detected.

**View Coverage:**
```bash
pytest --cov=dashboard
```

## Test Types

**Unit Tests:** Pure calculations and validators such as uptime bucketing and healthy-status parsing in `tests/test_release_contract.py`.

**Integration Tests:** Flask API + SQLite workflows, discovery/uptime state transitions, and network behavior simulated with local doubles (`tests/test_api_and_auth.py`, `tests/test_uptime_integration.py`, `tests/test_security_and_scanning.py`).

**E2E Tests:** No browser automation suite detected; `tests/test_ui_contract.py` performs source/markup contract checks and runs Node for exported formatter functions.

## Common Patterns

**Async Testing:** Background scheduling is disabled for tests (`DISABLE_BACKGROUND=1`); worker behavior is tested by directly invoking functions such as `recover_worker_state()` and `update_worker_heartbeat()`.

**Error Testing:** Use status-code assertions for API errors (403/400/429), `assertRaises(ValueError)` for validation, and explicit persisted error-class checks for probe failures.

---

*Testing analysis: 2026-07-24*
