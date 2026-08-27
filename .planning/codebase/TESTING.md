# Testing Patterns

**Analysis Date:** 2026-08-27

## Test Framework

**Runner:**
- pytest 9.0.2+, configured in `dashboard/pyproject.toml`
- Testpaths: `../tests` (relative to config file in `dashboard/`)
- Python path: `[".."]` (allows importing from repo root)

**Assertion Library:**
- unittest.TestCase for test structure
- Standard `self.assertEqual()`, `self.assertTrue()`, `self.assertIn()` assertions
- Playwright assertions for browser tests: `.is_visible()`, `.is_enabled()`, `.get_attribute()`, `.evaluate()`

**Run Commands:**
```bash
# All tests (from repository root, using uv)
uv run --project dashboard python -m pytest

# Quiet mode (one-liner per test)
uv run --project dashboard python -m pytest -q

# Watch mode with auto-discovery
uv run --project dashboard python -m pytest --tb=short tests/

# Coverage report (if available)
uv run --project dashboard python -m pytest --cov=dashboard tests/
```

## Test File Organization

**Location:**
- All tests in `tests/` directory at repo root
- Unit and integration tests co-located by feature (not separated)
- ~27 test modules covering ~771 tests total

**Naming:**
- Test modules: `test_<feature>.py` (e.g., `test_api_and_auth.py`, `test_ui_states.py`)
- Test classes: `<Feature>Tests` (PascalCase) inheriting `unittest.TestCase`
- Test methods: `test_<specific_behavior>()` (snake_case, descriptive)

**Module Structure:**
```
tests/
├── conftest.py                    # pytest configuration (pins working directory)
├── helpers.py                     # Shared test utilities and fixtures
├── fixtures/                      # Test data and mock files
│   ├── legacy/                    # Database fixtures from older schema versions
│   └── tls/                       # TLS certificate fixtures
├── test_api_and_auth.py          # Flask API and authentication tests
├── test_ui_states.py             # Browser UI tests (main dashboard)
├── test_ui_contract.py           # Static contract tests (markup, CSS, JS)
├── test_theme_parity_ui.py       # Dual-theme geometry tests
├── test_advanced_ui.py           # Browser tests (advanced workspace)
├── test_advanced_diagnosis_api.py # Advanced analytics API tests
├── test_historical_telemetry_api.py
├── test_incidents_api.py
├── test_maintenance_windows.py
├── test_migrations.py
├── test_module_boundaries.py
└── ... (27 total test files)
```

## Test Structure

**Suite Organization:**
```python
import unittest
from tests.helpers import load_app, cleanup_db

class ApiAndAuthTests(unittest.TestCase):
    def setUp(self):
        """Run before each test—initialize app with test config."""
        self.appmod, self.db_path = load_app({
            'TRIGGER_SCAN_RATE_LIMIT': '1',
            'TRIGGER_SCAN_WINDOW_SECONDS': '60',
        })
        self.client = self.appmod.app.test_client()
        self.ui_headers = {'X-Beacon-UI': '1'}

    def tearDown(self):
        """Run after each test—clean up database files."""
        cleanup_db(self.db_path)

    def test_something_specific(self):
        """Test names describe the behavior being verified."""
        # Arrange: Set up preconditions
        self._insert_service()
        
        # Act: Perform the action
        response = self.client.get('/api/services')
        
        # Assert: Verify the result
        self.assertEqual(response.status_code, 200)
        self.assertIn('services', response.get_json())
```

**Patterns:**
- `setUp()`: Initialize test database, Flask app client, mock headers
- `tearDown()`: Clean up database files, reset state
- `self.subTest(param=value)`: Parameterized assertions within single test
- Helper methods prefixed with `_`: `_insert_service()`, `_worker_owner()`, etc.

## Mocking and Fixtures

**Framework:**
- Standard Python `unittest.mock` for monkeypatching
- Custom fake classes for simple contracts (`FakeResponse` in `tests/test_api_and_auth.py`)
- Playwright route interception (`page.route()`) for API mocking in browser tests
- Context managers for clean restoration (`@contextmanager`, `try/finally`)

**Patterns:**

### Environment Seeding Helper

`tests/helpers.py:load_app()` is the primary test setup function:
```python
def load_app(extra_env=None):
    """Load app with test environment overrides.
    
    Defaults:
    - TRIGGER_SCAN_RATE_LIMIT: 2
    - ALERT_WEBHOOK_URL: '' (disabled)
    - EXPIRE_DAYS: 7
    
    Creates isolated temp database directory for each test.
    Stubs psutil if not available (for headless CI).
    """
    env = {
        'TRIGGER_SCAN_RATE_LIMIT': '2',
        'TRIGGER_SCAN_WINDOW_SECONDS': '60',
        'ALERT_WEBHOOK_URL': '',
        'ALERT_COOLDOWN_SECONDS': '60',
        'ALERT_ONLY_CRITICAL': '0',
        'EXPIRE_DAYS': '7',
    }
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})
    
    for key, value in env.items():
        os.environ[key] = value
    
    _ensure_psutil_stub()
    db_dir = tempfile.mkdtemp(prefix='beacon-test-')
    db_path = os.path.join(db_dir, 'dashboard.db')
    
    import dashboard.app as appmod
    appmod = importlib.reload(appmod)
    appmod.DB_PATH = db_path
    appmod.init_db()
    return appmod, db_path
```

### Database State Seeding

Tests insert data directly via SQL rather than API:
```python
def _insert_service(self, port=8080, url='http://127.0.0.1:8080'):
    """Insert test service directly into database."""
    now = int(time.time())
    with self.appmod._db_lock:
        conn = self.appmod.get_db()
        conn.execute(
            "INSERT INTO services (port, title, first_seen, last_seen, is_online, last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
            (port, 'Demo Service', now - 120, now, 1, 45.2, None),
        )
        conn.execute(
            "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
            (port, 'Friendly Demo', url, 1, 1, 'core,prod'),
        )
        conn.execute(
            "INSERT INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
            (now - 10, port, 1, 45.2, None),
        )
        conn.commit()
        conn.close()
```

### Monkeypatching for Isolation

Tests restore monkeypatches in `finally` blocks:
```python
original = self.appmod.beacon_repositories.read_maintenance_windows_by_port

def _raise_unrelated_error(*_args, **_kwargs):
    raise RuntimeError('unrelated handler failure')

self.appmod.beacon_repositories.read_maintenance_windows_by_port = _raise_unrelated_error
try:
    response = self.client.get('/api/services')
finally:
    self.appmod.beacon_repositories.read_maintenance_windows_by_port = original
```

### Connection Spy Pattern

Tests wrap database access to verify connection lifecycle:
```python
def _install_connection_spy(appmod, real_database_access):
    """Capture all database connections opened during test."""
    captured = []

    @contextlib.contextmanager
    def spying_database_access(settings_or_path):
        with real_database_access(settings_or_path) as conn:
            captured.append(conn)
            yield conn

    appmod.database_access = spying_database_access
    return captured
```

### Fake HTTP Server for Service Probing Tests

Tests use `ThreadingHTTPServer` to mock service responses:
```python
class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

@contextlib.contextmanager
def run_server(handler_cls):
    """Run a mock HTTP server for the duration of the test."""
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
```

## Playwright Browser Tests

**Setup:**
```python
from playwright.sync_api import sync_playwright

class UiStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            executable_path=cls.playwright.chromium.executable_path
        )
        # Set up HTTP server for static assets
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server_thread.join(timeout=2)

    def test_something(self):
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._mock_api_route)
        try:
            page.goto(self.base_url, wait_until='networkidle')
            # Test assertions here
        finally:
            page.close()
```

**API Mocking:**
```python
def _theme_parity_route_api(self, fixture):
    """Mock all API endpoints with deterministic responses."""
    def route_api(route):
        path = urlparse(route.request.url).path
        payloads = {
            '/api/stats': {'hostname': 'beacon', 'sample_ts': 1_700_000_000, 'cpu': 42, ...},
            '/api/services': fixture['services'],
            '/api/events': fixture['events'],
        }
        route.fulfill(status=200, json=payloads.get(path, {}))
    return route_api
```

## DOM/Computed-Style/Geometry Contract Assertions

**Critical Pattern:** This codebase uses **NO pixel screenshots** (`page.screenshot()`, `to_have_screenshot()`). Instead, tests assert:

1. **DOM Presence:** Check element exists and is in document:
   ```python
   self.assertIn('id="events-panel"', html)
   self.assertIn('class="svc-critical"', html)
   ```

2. **Visibility State:** Test computed display property:
   ```python
   self.assertTrue(page.locator('#meta-window-empty').is_visible())
   self.assertFalse(page.locator('#meta-cancel').is_visible())
   ```

3. **CSS Classes and State:** Check for class presence or ARIA attributes:
   ```python
   self.assertEqual(chip.get_attribute('aria-pressed'), 'true')
   self.assertTrue(row.evaluate('(node) => node.classList.contains("is-disabled")'))
   ```

4. **Rendered Text Content:** Verify text without font/color/positioning:
   ```python
   self.assertIn('No maintenance windows yet', page.locator('#meta-window-empty').text_content())
   self.assertEqual(page.locator('#meta-window-count').text_content(), '1 maintenance window')
   ```

5. **Geometry and Layout:** Run JavaScript to measure:
   - Bounding rectangles: `getBoundingClientRect()`
   - Computed styles: `getComputedStyle(node)`
   - Overflow behavior: `node.scrollWidth > node.clientWidth`
   - Row wrapping: Count distinct `bottom` edges among children
   - Hit target sizes: All interactive controls ≥ 44px high

   ```javascript
   // From test_theme_parity_ui.py
   (node) => {
       const style = getComputedStyle(node);
       const rect = node.getBoundingClientRect();
       return {
           height: rect.height,
           scrollWidth: node.scrollWidth,
           clientWidth: node.clientWidth,
           rows: rowBottoms.size,  // Count wrapping
           controlHeights: controls.map((el) => el.getBoundingClientRect().height),
       };
   }
   ```

6. **User Interactions:** Simulate and verify state changes:
   ```python
   chip.click()
   self.assertEqual(chip.get_attribute('aria-pressed'), 'true')
   
   row.locator('.meta-window-enabled').uncheck()
   self.assertTrue(row.evaluate('(node) => node.classList.contains("is-disabled")'))
   ```

**Why No Screenshots:**
- No baseline review workflow in project
- Rendering differs on Raspberry Pi vs. developer machines (font metrics, GPU output)
- Contract assertions (role, accessible name, text, geometry) express intent better than pixel diffs
- Faster test execution; easier to maintain

## Dual-Theme Testing

**Light/Dark Mode Contract:**

Tests verify both themes render the same content and functionality:

```python
# From test_theme_parity_ui.py
page.add_init_script("localStorage.setItem('beacon-theme', 'light');")
page.goto(url)
# Test light mode assertions

page2 = self.browser.new_page(viewport={'width': 1100, 'height': 800})
page2.add_init_script("localStorage.setItem('beacon-theme', 'dark');")
page2.goto(url)
# Test dark mode assertions (identical to light mode)
```

**Theme-Gated Visibility Classification:**

`tests/test_ui_contract.py` maintains explicit inventory of visibility rules:
```python
THEME_HIDDEN_RULES = {
    '.sparkline': 'deliberate-calm',      # Hidden in light mode for calm reading
    '.svc-preview': 'deliberate-calm',    # Accepted exception per design
    '.corner': 'decorative',              # Dead rule, renders nowhere
}

def test_every_theme_gated_visibility_rule_is_enumerated_and_classified():
    """Every display:none rule is classified as deliberate-calm or decorative."""
    extracted = extract_theme_gated_hidden_selectors(css)
    self.assertEqual(extracted, set(THEME_HIDDEN_RULES.keys()))
```

**Responsive Layout Boundaries:**

Pinned constants ensure future changes are one-line edits:
```python
NARROW_BOUNDARY_PX = 720    # Shared narrow layout boundary
DESKTOP_WIDTH_PX = 1440     # Desktop comparison point

page.set_viewport_size({'width': NARROW_BOUNDARY_PX, 'height': 900})
# Test narrow layout assertions

page.set_viewport_size({'width': DESKTOP_WIDTH_PX, 'height': 900})
# Test desktop layout assertions
```

## Test Types

**Unit Tests (API/logic):**
- Scope: Single function or module in isolation
- Example: `test_a_failing_request_releases_its_shared_maintenance_lease()` in `test_api_and_auth.py`
- Approach: Direct function calls, monkeypatching, database state seeding
- No browser or HTTP server

**Integration Tests (API with database):**
- Scope: Flask route handlers + database + beacon modules
- Example: `test_trigger_scan_requires_ui_header_and_queues()` in `test_api_and_auth.py`
- Approach: Flask test client, mock API routes, real database with cleanup
- Database accessed through locks and transaction boundaries

**Contract/Static Tests:**
- Scope: Markup, CSS, JS source code structure
- Example: `test_every_theme_gated_visibility_rule_is_enumerated_and_classified()` in `test_ui_contract.py`
- Approach: File parsing, regex extraction, assertion on structure
- No execution, no database, no browser

**Browser Tests (UI/E2E):**
- Scope: Full dashboard in browser with mocked API
- Example: `test_a_service_with_no_windows_shows_the_empty_state_and_the_add_control()` in `test_ui_states.py`
- Approach: Playwright page, route interception for API mocking, DOM/geometry assertions
- Tests light and dark themes with localStorage override

**Smoke Tests:**
- Scope: Critical user workflows
- Example: Scan trigger → service discovery → event recording
- Approach: Browser test with deterministic API fixtures

## Common Test Idioms

**Async/Await Testing:**
```python
# All async operations are blocking in Playwright (sync_api)
page.goto(url, wait_until='networkidle')  # Wait for network idle
page.locator('#element').wait_for(state='visible', timeout=8_000)
page.click()  # Click waits for element to be stable
```

**Error Testing:**
```python
# Test error states by mocking API failures
def _maintenance_route(self, fixture):
    def route_api(route):
        if fixture.get('put_error'):
            route.fulfill(status=400, json={'error': 'boom'})
        else:
            route.fulfill(status=200, json={'success': True})
    return route_api

# Verify error message appears
self.assertIn('could not use that destination', error_text)
```

**State Transitions:**
```python
# Verify state changes through attribute checks
chip.click()
self.assertEqual(chip.get_attribute('aria-pressed'), 'false')  # Initial
chip.click()
self.assertEqual(chip.get_attribute('aria-pressed'), 'true')   # After click 1
chip.click()
self.assertEqual(chip.get_attribute('aria-pressed'), 'false')  # After click 2
```

**Keyboard and Focus Management:**
```python
# Verify focus flow
page.locator('#meta-window-add').click()
row = page.locator('.meta-window-row').first
row.wait_for(state='visible', timeout=4_000)
# Focus should be on start field after add
self.assertTrue(row.locator('.meta-window-start').evaluate(
    '(node) => document.activeElement === node'
))
```

## Coverage

**Requirements:** No explicit coverage target enforced

**View Coverage:**
```bash
# Run with coverage reporting (if configured)
uv run --project dashboard python -m pytest --cov=dashboard tests/
```

**Coverage Scope:**
- API endpoints: ~95% coverage (all routes tested)
- Database schema and migrations: ~85% coverage
- Worker scheduling: ~70% coverage
- Browser UI interactions: ~60% coverage (contract-focused, not comprehensive)
- Beacon modules (incidents, telemetry, diagnosis): ~75-85% coverage

**Gaps:**
- Raspberry Pi-specific hardware (temp sensors, CPU scaling) tested via stubs
- Playwright browser interactions test contracts, not all user flows
- Performance/load tests not automated
- Playwright tests run in Chromium only (not tested in Safari/Firefox)

## Test Execution Environment

**Working Directory:**
- pytest fixture `_run_from_project_root()` in `conftest.py` pins working directory to repo root
- Ensures relative paths (`pathlib.Path('dashboard/app.js')`) resolve consistently
- Prevents invocation-dependent failures

**Database Isolation:**
- Each test gets unique temp directory (`tempfile.mkdtemp(prefix='beacon-test-')`)
- Database, WAL files, and locks cleaned up in `tearDown()`
- Tests can run in parallel without contention

**Playwright Isolation:**
- Each test creates new browser page with fresh context
- Pages closed in `finally` block
- No shared browser state between tests

**Environment Overrides:**
- Tests set environment variables before app reload
- Stubs unavailable system packages (psutil on headless CI)
- Mocks external services (HTTP, Playwright browser)

---

*Testing analysis: 2026-08-27*
