---
phase: 01-behavioral-safety-runtime-ownership
plan: 02
subsystem: web-persistence
tags: [flask, sqlite, configuration, repository, docker]
requires:
  - phase: 01-01
    provides: side-effect-free startup and compatibility regression baseline
provides:
  - Explicit SQLite connection and transaction contexts
  - Repository-owned metadata and durable preview-request writes
  - Immutable Settings and a side-effect-free Flask composition factory
affects: [worker extraction, migrations, durable queues, outbound policy]
tech-stack:
  added: []
  patterns: [injected SQLite transactions, repository-owned SQL, factory service registry]
key-files:
  created: [dashboard/beacon/config.py, dashboard/beacon/db.py, dashboard/beacon/repositories.py, dashboard/beacon/web.py, tests/test_module_boundaries.py]
  modified: [dashboard/app.py, dashboard/Dockerfile, tests/test_api_and_auth.py]
key-decisions:
  - "Keep dashboard.app.app as the WSGI and monkeypatch compatibility surface while composing its service registry through beacon.web.create_app."
  - "Persist metadata and preview enqueue work in one explicit SQLite transaction so worker freshness never blocks an operator edit."
patterns-established:
  - "Routes validate and translate compatibility fields; repository functions receive an explicit connection and own parameterized SQL."
  - "Factory construction may load Settings and register adapters, but it opens no database and starts no lifecycle work."
requirements-completed: [FND-01, FND-02, FND-03]
coverage:
  - id: D1
    description: "Metadata edits preserve response fields and atomically enqueue preview work through explicit SQLite repository seams."
    requirement: FND-02
    verification:
      - kind: integration
        ref: "tests/test_api_and_auth.py#test_repository_metadata_upsert_is_transactional_and_flask_free"
        status: pass
    human_judgment: false
  - id: D2
    description: "Immutable settings and an isolated side-effect-free Flask factory provide one-way composition boundaries."
    requirement: FND-03
    verification:
      - kind: unit
        ref: "tests/test_module_boundaries.py#test_factory_isolation_and_dependency_direction"
        status: pass
    human_judgment: false
duration: 4min
completed: 2026-07-25
status: complete
---

# Phase 01 Plan 02: Web and Persistence Boundaries Summary

**Atomic metadata persistence, explicit SQLite repositories, immutable settings, and a side-effect-free Flask factory preserve Beacon's WSGI compatibility surface.**

## Performance

- **Duration:** 4 min
- **Started:** 2026-07-25T07:31:13Z
- **Completed:** 2026-07-25T07:34:39Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Added explicit SQLite connection/read/write transaction helpers with row mapping, busy timeout, foreign keys, rollback, and closure.
- Moved service metadata lookup and its metadata-plus-preview-request persistence into Flask-free repository functions; valid edits remain available during a stale or absent worker heartbeat.
- Added an immutable Settings value, a factory-owned service registry, dependency-direction checks, and Docker packaging for the `beacon/` package while retaining `app:app`.

## Task Commits

1. **Task 1: Route service metadata through explicit database and repository seams** - `729eb53` (test RED), `5b45351` (feat GREEN)
2. **Task 2: Make the Flask factory the complete compatibility composition root** - `8397a7d` (test RED), `56e4928` (feat GREEN)

## Files Created/Modified

- `dashboard/beacon/db.py` - Explicit SQLite connection and transaction context managers.
- `dashboard/beacon/repositories.py` - Parameterized service metadata, preview queue, runtime-state, and event queries.
- `dashboard/beacon/config.py` - Frozen validated process configuration.
- `dashboard/beacon/web.py` - Metadata response adapter and side-effect-free factory registry.
- `dashboard/app.py` - Preserved WSGI compatibility shim with factory composition and repository delegation.
- `dashboard/Dockerfile` - Copies the complete `beacon/` package into the existing non-root image.
- `tests/test_api_and_auth.py` - Covers injected real-SQLite repository mutation behavior.
- `tests/test_module_boundaries.py` - Covers factory isolation, import direction, immutable settings, and container packaging.

## Decisions Made

- Kept the decorated legacy Flask object as the compatibility bridge while `create_app` owns explicit Settings and service dependency composition; this retains existing test and worker monkeypatch seams during staged extraction.
- Treat metadata and durable preview enqueue as a single transaction, so web edits do not depend on worker heartbeats or another process committing follow-up state.

## Verification

- `dashboard/.venv/bin/python -m pytest -q` — 52 passed.
- `docker compose config -q` — passed.
- Focused boundary suite: `tests/test_module_boundaries.py tests/test_runtime_ownership.py tests/test_api_and_auth.py tests/test_release_contract.py` — 38 passed.

## Deviations from Plan

None - plan executed as specified.

## Known Stubs

None.

## Next Phase Readiness

The web-facing persistence and configuration contracts are ready for the worker, migration, queue, and outbound-policy extractions. `dashboard.app` remains a deliberate compatibility bridge until those later plans move the remaining domain functions behind the same injected boundaries.

## Self-Check: PASSED

- Created module and test files exist on disk.
- TDD RED and GREEN commits `729eb53`, `5b45351`, `8397a7d`, and `56e4928` exist in Git history.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-07-25*
