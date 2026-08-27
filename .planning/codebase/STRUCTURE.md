# Codebase Structure

**Analysis Date:** 2026-08-27

## Directory Layout

```
rpi-dashboard/
├── dashboard/               # Main application code (Flask web + background worker)
│   ├── app.py               # Flask application with HTTP routes and handlers
│   ├── worker.py            # Worker composition entry point
│   ├── runtime_smoke.py     # Runtime verification/smoke test
│   │
│   ├── index.html           # Everyday dashboard template
│   ├── advanced.html        # Advanced workspace template
│   │
│   ├── app.js               # Everyday dashboard client logic
│   ├── advanced.js          # Advanced workspace client logic
│   │
│   ├── style.css            # Shared styling for both dashboards
│   ├── advanced.css         # Advanced workspace specific styling
│   │
│   ├── pyproject.toml       # Python dependencies
│   ├── uv.lock              # Locked dependency versions
│   ├── Dockerfile           # Container image definition
│   │
│   └── beacon/              # Domain business logic package
│       ├── __init__.py      # Package marker (shared boundaries)
│       │
│       ├── db.py            # SQLite connection, transactions, locking
│       ├── repositories.py  # Parameterized SQL queries
│       ├── migrations.py    # Schema versioning and migrations
│       │
│       ├── diagnosis.py     # Diagnosis composition pipeline
│       ├── telemetry.py     # Retention policy, rollup strategy
│       ├── incidents.py     # Event recording and filtering
│       ├── maintenance.py   # Maintenance window detection
│       │
│       ├── worker_main.py   # Job scheduling and lifecycle
│       ├── worker_authority.py  # Worker lease and ownership
│       ├── monitoring.py    # HTTP probing, metrics, discovery
│       │
│       ├── config.py        # Settings loading
│       ├── web.py           # Flask compatibility adapters
│       ├── queues.py        # Scan/preview request queues
│       ├── outbound.py      # Webhook policies and delivery
│       ├── previews.py      # Browser-based thumbnail capture
│       ├── recovery.py      # Upgrade recovery procedures
│       │
│       ├── migrate.py       # CLI migration runner
│       ├── inventory.py     # Job/callback references (if used)
│       └── # Generated artifacts:
│           ├── beacon.db    # SQLite database (gitignored)
│           ├── .beacon-maintenance.lock  # fcntl maintenance lock
│           └── .beacon-upgrade.lock      # Upgrade/recovery lock
│
├── tests/                   # Test suite
│   ├── conftest.py          # pytest fixtures and configuration
│   ├── test_*.py            # Test modules
│   ├── helpers.py           # Test helpers
│   ├── worker_ownership_contract.py  # Worker ownership assertions
│   └── fixtures/            # Test data and fixtures
│       ├── legacy/          # Legacy deployment fixtures
│       └── tls/             # TLS certificate fixtures
│
├── .planning/               # GSD project planning (not application code)
│   ├── codebase/            # Generated architecture/structure docs
│   │   ├── ARCHITECTURE.md
│   │   ├── STRUCTURE.md
│   │   ├── STACK.md
│   │   ├── INTEGRATIONS.md
│   │   ├── CONVENTIONS.md
│   │   ├── TESTING.md
│   │   └── CONCERNS.md
│   ├── phases/              # Implementation phases
│   ├── research/            # Research notes
│   ├── seeds/               # Planning seeds
│   ├── quick/               # Quick tasks
│   └── tmp/                 # Temporary planning files
│
├── .github/                 # CI/CD workflows
│   └── workflows/
│
├── .claude/                 # Claude Code configuration
│   └── worktrees/           # Agent working branches
│
├── .gsd/                    # GSD state tracking
│
├── README.md                # Project overview
├── docker-compose.yml       # Local development setup
└── AGENTS.md                # GSD agent documentation

```

## Directory Purposes

**`dashboard/`** — Application root
- Contains Flask web app (`app.py`), background worker (`worker.py`), HTML/JS/CSS frontends
- Entrypoint: `app.py` for web, `worker.py` for background jobs
- Configuration: `pyproject.toml`, Dockerfile

**`dashboard/beacon/`** — Domain business logic (shared by web and worker)
- SQL query abstractions (`repositories.py`), persistence layer (`db.py`)
- Diagnosis snapshot composition (`diagnosis.py`)
- Job scheduling and callbacks (`worker_main.py`)
- Supporting modules: telemetry policy, maintenance windows, incident recording, webhooks
- NOT application code: `web.py` (Flask adapters), `config.py` (settings loading)

**`tests/`** — Automated test suite
- Unit tests, integration tests, contract tests
- Fixtures: legacy deployments, TLS certificates
- Test contracts: `worker_ownership_contract.py`, `test_release_contract.py` (guarantee prod behavior)

**`.planning/`** — GSD planning metadata (NOT application code)
- `codebase/`: Generated architecture documentation
- `phases/`: Implementation phase tracking
- Other: Research, seeds, temporary files
- Do NOT treat as part of the codebase proper — it's planning output

**`.claude/`, `.gsd/`, `.github/`** — Tooling and infrastructure
- `.claude/`: Claude Code worktrees and configuration
- `.gsd/`: GSD workflow state
- `.github/`: CI/CD pipeline definitions

## Key File Locations

**Entry Points:**
- Web app: `dashboard/app.py` (Flask application, routes, handlers)
- Background worker: `dashboard/worker.py` (composition root, calls `worker_main.run_worker()`)
- Database migrations: `dashboard/beacon/migrations.py` (schema versions, called by P0 callback)
- CLI runner: `dashboard/beacon/migrate.py` (manual migration tool)

**Configuration:**
- App settings: `dashboard/beacon/config.py` (loads from environment, settings file)
- Database path: Resolved from settings → `db_path` (typically `/home/pi/.config/beacon/beacon.db`)
- Python dependencies: `dashboard/pyproject.toml`, `dashboard/uv.lock`
- Container: `dashboard/Dockerfile`

**Core Logic:**
- Diagnosis pipeline: `dashboard/beacon/diagnosis.py` (`get_current_diagnosis()`, service/pipeline/host composition)
- Job scheduling: `dashboard/beacon/worker_main.py` (APScheduler setup, `WORKER_CALLBACK_INVENTORY`)
- Data access: `dashboard/beacon/repositories.py` (all SQL queries)
- Database: `dashboard/beacon/db.py` (connection pooling, locking, transactions)

**Frontend:**
- Everyday dashboard: `dashboard/index.html` + `dashboard/app.js` + `dashboard/style.css`
- Advanced workspace: `dashboard/advanced.html` + `dashboard/advanced.js` + `dashboard/advanced.css`

**Testing:**
- Fixtures: `tests/conftest.py` (pytest configuration, common fixtures)
- Test data: `tests/fixtures/legacy/`, `tests/fixtures/tls/`
- Contracts: `tests/worker_ownership_contract.py`, `tests/test_worker_ownership_matrix.py`

## Naming Conventions

**Files:**
- Python modules: `snake_case.py` (e.g., `worker_main.py`, `repositories.py`)
- HTML templates: `lowercase.html` (e.g., `index.html`, `advanced.html`)
- JavaScript: `camelCase` or `lowercase.js` (e.g., `app.js`, `advanced.js`)
- CSS: `lowercase.css` (e.g., `style.css`, `advanced.css`)
- Configuration: `snake_case.py` or `lowercase.toml` (e.g., `config.py`, `pyproject.toml`)
- Tests: `test_snake_case.py` (e.g., `test_ui_states.py`, `test_worker_ownership.py`)
- Database: `beacon.db` (SQLite file at path specified in settings)

**Directories:**
- Domain packages: `snake_case/` (e.g., `beacon/`)
- Test suite: `tests/`
- Planning/infrastructure: `.dotname/` (e.g., `.planning/`, `.claude/`, `.gsd/`)
- Fixtures: `fixtures/`, organized by type (e.g., `fixtures/legacy/`, `fixtures/tls/`)

**Python identifiers:**
- Functions/methods: `snake_case` (e.g., `get_current_diagnosis()`, `read_current_services()`)
- Classes: `PascalCase` (e.g., `ManagedConnection`, `WorkerCallback`, `MonitoringOperations`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `WORKER_CALLBACK_INVENTORY`, `RECOVERY_MARKER`, `UNRECORDED_OUTCOME_FLOOR_SECONDS`)
- Module-level private: `_snake_case` (e.g., `_db_lock`, `_screenshot_sem`)

**Job identifiers:**
- Format: `[PSJ][0-9]` (P=pre-epoch, S=startup, J=job, L=lifecycle)
- Examples: `P0` (prepare), `S1` (recover), `S2` (heartbeat+lease), `J1` (heartbeat 5s), `J2` (metrics), J5–J9 (various), `L1` (finalize)
- Used in: `WORKER_CALLBACK_INVENTORY`, logs, database `background_job_health` table

**Database tables:**
- Plural, snake_case (e.g., `services`, `service_checks`, `system_stats`)
- Join/attribute tables: suffixed with metadata (e.g., `service_meta`, `service_tls_posture`)
- History tables: `*_history` suffix (e.g., `stats_history`, `service_checks` stores history implicitly)

## Where to Add New Code

**New Feature (monitoring capability, e.g., new metric type):**
- Logic: `dashboard/beacon/monitoring.py` (add operation interface) or new `dashboard/beacon/new_module.py`
- Worker job: Add `WorkerCallback` to `WORKER_CALLBACK_INVENTORY` in `dashboard/beacon/worker_main.py`
- Route: Add `@app.route()` in `dashboard/app.py` or delegate to handler imported from beacon
- Database: Add table(s) to `dashboard/beacon/migrations.py` (next version)
- Repository: Add query function(s) to `dashboard/beacon/repositories.py`
- Tests: `tests/test_new_feature.py` with fixtures from `tests/conftest.py`

**New Frontend Component (dashboard section):**
- Everyday dashboard: Add HTML to `dashboard/index.html`, JS to `dashboard/app.js`, CSS to `dashboard/style.css`
- Advanced workspace: Add section nav button + panel to `dashboard/advanced.html`, JS to `dashboard/advanced.js`, CSS to `dashboard/advanced.css`
- API endpoint: Add route + handler in `dashboard/app.py` calling repository functions from `dashboard/beacon/repositories.py`
- Tests: `tests/test_ui_*.py` (e.g., `test_ui_states.py`, `test_ui_safety_integration.py`)

**New Configuration Parameter:**
- Define: `dashboard/beacon/config.py` in `Settings` dataclass
- Load: From environment or settings file (already handled by `load_settings()`)
- Reference: Use `SETTINGS.parameter_name` in routes/workers (e.g., `SETTINGS.worker_ready_seconds`, `SETTINGS.timezone`)

**Database Schema Change:**
- Add migration: New version in `dashboard/beacon/migrations.py` (increment `CURRENT_SCHEMA_VERSION`)
- Update schema: Add table/column/constraint in migration function
- Update queries: Add/modify functions in `dashboard/beacon/repositories.py`
- Update diagnosis: Modify `get_current_diagnosis()` or helpers in `dashboard/beacon/diagnosis.py` if affecting state representation
- Test: Verify migration in `tests/test_migrations.py`

**New Job/Scheduled Operation:**
- Define callback: Add `WorkerCallback(...)` to `WORKER_CALLBACK_INVENTORY` in `dashboard/beacon/worker_main.py` with:
  - Unique `identifier` (e.g., `J10` for next job)
  - `operation_fields`: tuple of required operations from `WorkerOperations`
  - `database_surfaces`: tables this job reads/writes
  - `scheduler_metadata`: interval/trigger config (or omit for one-time jobs)
- Implement operation: Add to `WorkerOperations` fields and handler in `dashboard/app.py` (e.g., `worker_operation_name()`)
- Database surfaces: Declare all tables touched (used for ownership validation)
- Tests: Add to `tests/worker_ownership_contract.py` to verify job preconditions

**New Alert/Webhook:**
- Policy: Add to `dashboard/beacon/outbound.py` (when to send, which service)
- Trigger: Call `beacon_outbound.send_webhook()` in job handler or route (e.g., in uptime check logic)
- Test: `tests/test_outbound_policy.py`

**Supporting Module (utilities, helpers):**
- Location: `dashboard/beacon/util_name.py` or add to existing module if small
- Export: Import in `dashboard/beacon/__init__.py` if meant for cross-module use
- Example: `dashboard/beacon/telemetry.py` (not application logic, but reusable policy)

## Special Directories

**`dashboard/beacon/`** — NOT a utilities directory
- Purpose: Shared domain logic between web and worker processes
- Content: All production code except Flask routing is here
- Discipline: No dependency on Flask, Playwright, or requests library at module level (passed via MonitoringOperations)

**`tests/`** — Test suite with contracts
- Purpose: Verify behavior matches specification (not just "doesn't crash")
- Key files: 
  - `worker_ownership_contract.py`: Asserts job callbacks have declared all touched tables
  - `test_release_contract.py`: Verifies production behavior is preserved across releases
  - `conftest.py`: Fixtures, database setup for tests
- Discipline: Tests drive implementation; contracts prevent regressions

**`.planning/codebase/`** — Generated documentation (read-only for this mapper)
- Purpose: Architecture reference for `/gsd-plan-phase` and `/gsd-execute-phase`
- Files: ARCHITECTURE.md, STRUCTURE.md, STACK.md, INTEGRATIONS.md, CONVENTIONS.md, TESTING.md, CONCERNS.md
- Governance: Written by `/gsd-map-codebase`, not manually maintained

**`.planning/phases/`** — Phase tracking
- Format: `NN-phase-name/` directories with phase documentation
- Examples: `01-behavioral-safety-runtime-ownership/`, `03-advanced-current-diagnosis/`, `04-historical-investigation/`
- Content: Phase spec, implementation notes, phase-gate results

---

*Structure analysis: 2026-08-27*
