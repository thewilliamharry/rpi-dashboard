# Coding Conventions

**Analysis Date:** 2026-08-27

## Naming Patterns

**Files:**
- Python modules use lowercase snake_case (`dashboard/app.py`, `dashboard/worker.py`, `tests/test_api_and_auth.py`)
- HTML/CSS/JS use lowercase names (`dashboard/index.html`, `dashboard/app.js`, `dashboard/style.css`)
- Package directories use lowercase (`dashboard/beacon/`, `tests/fixtures/`)

**Functions:**
- Python functions use snake_case (`init_db`, `collect_system_stats`, `queue_discovery_request`)
- Private/internal functions prefixed with single underscore (`_probe_http`, `_normalize_service_url`, `_create_alert_event`)
- Flask route handlers use snake_case (`/api/services`, `/api/scan-status`, `/api/trigger-scan`)
- JavaScript functions use camelCase (`fmtAgo`, `updateStats`, `apiFetch`, `serviceHref`)
- Async JavaScript functions prefix with `async` keyword (e.g., `async function apiFetch(...)`)

**Variables:**
- Local and module variables use snake_case (Python) or camelCase (JavaScript)
- Constants are UPPERCASE_WITH_UNDERSCORES:
  - Python: `DB_PATH`, `UPTIME_WINDOW_SECONDS`, `METRIC_SAMPLE_SECONDS`, `PREVIEW_SETTLE_MS`
  - JavaScript: `MAINTENANCE_OVERRUN_EVENT_TYPE`, `EVENT_TYPES_VISIBLE`, `UI_HEADERS`, `WORKER_STALE_COPY`
- Module-level state variables are camelCase in JavaScript (`servicesByPort`, `editingService`, `pollFailures`)

**Types and Classes:**
- Test doubles and helper classes use PascalCase (`FakeResponse`, `ThreadingHTTPServer`, `UiStateTests`, `ApiAndAuthTests`)
- No type hints or dataclass models in production code (domain logic uses plain dicts and tuples)

## Code Style

**Python:**
- Follow PEP 8 layout: four-space indentation, one statement per line
- Grouped imports: stdlib, third-party, local modules
- Trailing commas in multiline function calls and imports
- Comments identify migrations and non-obvious compatibility behavior (e.g., backward compatibility notes in `dashboard/app.py`)
- No dedicated linter configuration (flake8/ruff)—style is enforced through code review

**JavaScript:**
- 'use strict' at module start
- Avoid client framework dependencies—vanilla DOM manipulation only
- Use `const`/`let`, never `var`
- Avoid nested callbacks; prefer `async`/`await` for async operations
- Self-closing tags and consistent whitespace

**CSS:**
- Dual-theme support using theme-scoped selectors:
  - Light mode: `html.light [selector] { ... }`
  - Dark mode: `html:not(.light) [selector] { ... }`
- Theme-gated visibility rules must be explicitly classified (see `tests/test_ui_contract.py`):
  - `"decorative"`: purely cosmetic flourishes with no informational content
  - `"deliberate-calm"`: genuine informational surfaces hidden in light mode for calm reading
- Layout boundaries pinned as constants (e.g., `NARROW_BOUNDARY_PX = 720` in `tests/test_theme_parity_ui.py`)

## Import Organization

**Python:**
- No custom path aliases beyond pytest `pythonpath = [".."]` in `dashboard/pyproject.toml`
- Module can be imported two ways to support Gunicorn and direct testing:
  - Relative: `from .beacon.config import load_settings`
  - Absolute: `from beacon.config import load_settings`
- Both are wrapped in try/except to handle both import modes gracefully (`dashboard/app.py` lines 24-50)

**JavaScript:**
- No module system—all code in single file (`dashboard/app.js`)
- Global formatters exported as frozen object: `globalThis.BeaconFormatters = Object.freeze({...})`
- Helper `$()` function for `document.getElementById()` shorthand (line 60 in `dashboard/app.js`)

## Error Handling

**Python:**
- Narrow exception handling for expected failures:
  - Parsing/environment errors: `except (TypeError, ValueError)`
  - File operations: `except FileNotFoundError`
  - Database operations: `except MaintenanceBusy` (for lock conflicts)
- Flask/API handlers return explicit HTTP status codes (202 for queued, 400/500 for errors) with JSON reasons
- Domain validation raises `ValueError` for invalid service URLs or status ranges (asserted in `tests/test_release_contract.py`)
- Cleanup logic uses `try/finally` to restore monkeypatches and clear state (e.g., `tests/test_security_and_scanning.py`)

**JavaScript:**
- Error messages passed through `Error()` constructor: `throw new Error(message)`
- Try/catch blocks used around JSON parsing with silent fallback on parse errors (line 82 in `dashboard/app.js`):
  ```javascript
  try { message = (await response.json()).error || message; } catch (_) { /* ignore */ }
  ```
- API errors surfaced to user with status-code context (e.g., "HTTP 500")

## Logging

**Python:**
- Module loggers created with `logging.getLogger(__name__)` or component name
- Baseline logger created with `logging.basicConfig()` at module level (`dashboard/app.py` line 52)
- Scheduler noise reduced with targeted logger level in `dashboard/worker.py`
- Log statements use info-level (`log.info()`) for operational events; debug-level for detail

**JavaScript:**
- No logger—use `console` methods directly for development only
- Production feedback to user via `feedbackRegion()` helper (creates/reuses `div#dashboard-feedback` with `role="status"` and `aria-live="polite"`)
- Connection state changes logged implicitly through DOM updates and banner visibility

## Comments

**Python:**
- Comments identify migrations and compatibility decisions (e.g., "Preserve the established compatibility repair" in `dashboard/app.py`)
- Most code is self-documenting—no systematic comment convention
- Comments reference planning docs and task IDs (e.g., "G-03.1-2", "05-03", "MNT-04")
- No docstrings in production code; entry points have brief docstrings (e.g., `init_db()`)

**JavaScript:**
- Comments reference planning docs and task IDs (e.g., "05-04 Task 1" in `dashboard/app.js` line 213)
- Comments explain non-obvious DOM/accessibility decisions (e.g., why uptime strips are not focusable)
- Self-documenting code preferred over comments

## Function Design

**Python:**
- Keep functions focused on single responsibility
- Return early to reduce nesting depth
- Use context managers (`@contextmanager`) for resource cleanup
- Thread-safe operations use explicit locks (`threading.Lock()`, `threading.Semaphore()`)
- Exported functions from beacon modules follow naming convention of `verb_noun()` (e.g., `read_maintenance_windows_by_port`)

**JavaScript:**
- Keep functions short and focused
- Use destructuring for object parameters
- Consistently handle nullish values and NaN (e.g., `normalizedBytes()` in line 45)
- Use Optional Chaining (`?.`) for safe navigation: `focusTarget?.focus()`
- Short helper functions assigned as module-level functions (e.g., `$()`, `fmtAgo()`, `uptimeLabel()`)

## Module Design

**Python:**
- Beacon package (`dashboard/beacon/`) contains modular feature domains:
  - `config.py`: Configuration loading and parsing
  - `db.py`: Database connection and transaction management
  - `repositories.py`: Data access layer for all queries
  - `monitoring.py`: Health check coordination
  - `previews.py`: Service thumbnail capture
  - `queues.py`: Work queue and lease management
  - `worker_main.py`: Scheduled job coordination
  - `incidents.py`: Event/alert creation and filtering
  - `maintenance.py`: Maintenance window logic
  - `telemetry.py`: Metrics collection and retention
  - `diagnosis.py`: Advanced analytics queries
  - `outbound.py`: HTTP safety policy and validation
- Each module exports public functions and classes; internal functions prefixed with underscore
- `dashboard/app.py` is the main entry point; imports and orchestrates beacon modules

**JavaScript:**
- Single-file application (`dashboard/app.js`) organized by function groups:
  - Formatters: `fmtAgo()`, `fmtLocalDateTime()`, `fmtDecimalBytes()`, etc.
  - API functions: `apiFetch()` with error handling
  - State updaters: `updateStats()`, `updateHistory()`, `updateScanStatus()`
  - DOM builders: `uptimeStrip()`, `serviceRow()` (creates elements)
  - Event handlers: `handleScanClick()`, `handleEditClick()` (click/input handlers)
  - Initialization: `initializePage()` or run on module load

**Exports and Barrels:**
- Python modules export public functions directly
- JavaScript exports formatters as frozen object (`globalThis.BeaconFormatters`)
- No barrel files used

## Concurrency and Threading

**Python:**
- Global locks protect shared resources:
  - `_db_lock`: SQLite connection pool and transaction serialization
  - `_scan_lock`: Discovery/probe operation serialization
  - `_screenshot_sem` (Semaphore): Browser instance synchronization (max 1 screenshot at a time)
  - `_uptime_lock`: Check aggregation and state transitions
  - `_browser_lock`: Playwright browser lifecycle
  - `_startup_lock`: Application startup sequencing
- Locks are acquired with `with lock:` context manager
- Context variables used for per-request authority tracking (`_worker_effect_authority`, `_worker_mutation_authority`)

**JavaScript:**
- Single-threaded browser environment—no explicit concurrency
- Async operations use `async`/`await`
- State changes propagate through `fetch` → update DOM → next poll

## Validation

**Python:**
- Service URLs validated through `OutboundPolicy` (in `dashboard/beacon/outbound.py`)
- Status code ranges parsed and validated (e.g., `'200-399'`)
- Trusted hosts/networks validated with `ipaddress` module
- Configuration loaded and type-checked in `dashboard/beacon/config.py`

**JavaScript:**
- URL construction uses `URL()` constructor with try/catch fallback (line 160 in `dashboard/app.js`)
- Number validation with `Number.isFinite()`, `Number.isNaN()`
- Nullish value handling consistent across formatters

## Database and Persistence

**Python:**
- SQLite with WAL mode for concurrent read/write access, set explicitly by `connect_db` in `dashboard/beacon/db.py`
- Explicit transactions with `conn.commit()` after mutations
- Shared maintenance lease acquired for all requests (read and write)
- Migrations managed in `dashboard/beacon/migrations.py` with upgrade locks
- Database path: `/data/dashboard.db` (configurable via `DB_PATH`)

## Cross-Cutting Concerns

**Accessibility:**
- ARIA labels and roles required for all interactive controls
- Semantic HTML5 elements used (no divs for buttons)
- Focus management explicit (e.g., `$('meta-error').focus()` in `dashboard/app.js`)
- Uptime strips use `role="img"` with `aria-label` for both hover title and accessible name (line 213)

**Security:**
- Outbound HTTP requests validated through `OutboundPolicy` (`dashboard/beacon/outbound.py`)
- Only HTTPS or HTTP on localhost/trusted LAN allowed
- No inline scripts in HTML (`dashboard/index.html` has no `<script>`)
- X-Beacon-UI header required for UI endpoints (e.g., `/api/trigger-scan`)

**Observability:**
- Logging at module level; no framework-level middleware logging
- Errors propagate with HTTP status codes and JSON error fields
- Worker degradation communicated through API (`worker_degraded` in `/api/scan-status`)

---

*Convention analysis: 2026-08-27*
