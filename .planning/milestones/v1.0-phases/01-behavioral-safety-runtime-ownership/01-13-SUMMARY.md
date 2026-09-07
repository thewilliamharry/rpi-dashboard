---
phase: 01-behavioral-safety-runtime-ownership
plan: 13
subsystem: runtime-ownership
tags: [python, flask, sqlite, apscheduler, security, dependency-injection]
requires:
  - phase: 01-behavioral-safety-runtime-ownership
    provides: "Compatibility web edge, managed SQLite connections, worker lease, and preview queue"
provides:
  - "Package-independent worker scheduler with injected compatibility operations"
  - "Repository-owned thumbnail completion persistence"
  - "Validated startup integers and total metadata JSON parsing"
affects: [worker, previews, metadata-api, startup-configuration]
tech-stack:
  added: []
  patterns: ["executable composition roots", "typed repository protocols", "Settings-derived compatibility constants"]
key-files:
  created: []
  modified:
    - dashboard/beacon/worker_main.py
    - dashboard/worker.py
    - dashboard/beacon/repositories.py
    - dashboard/beacon/previews.py
    - dashboard/app.py
    - tests/test_module_boundaries.py
    - tests/test_runtime_ownership.py
    - tests/test_api_and_auth.py
key-decisions:
  - "Only dashboard/worker.py imports the legacy dashboard.app edge and injects WorkerOperations into the package runtime."
  - "Preview completion persists through ThumbnailRepository while previews.py exposes only a named protocol."
  - "dashboard.app reads its runtime integer constants from one validated Settings instance and rejects malformed metadata before processing."
patterns-established:
  - "Package code receives compatibility behavior through immutable operation collaborators rather than importing the compatibility monolith."
  - "Repository ownership is protected by real-SQLite behavior tests and source-level SQL boundary assertions."
requirements-completed: [FND-02, OPS-05]
coverage:
  - id: D1
    description: "Worker runtime has no legacy app reverse import and starts through explicit injected operations."
    requirement: FND-02
    verification:
      - kind: unit
        ref: "tests/test_module_boundaries.py and tests/test_runtime_ownership.py"
        status: pass
    human_judgment: false
  - id: D2
    description: "Preview success and failure persistence is owned by the repository and observed through the API."
    requirement: FND-02
    verification:
      - kind: integration
        ref: "tests/test_runtime_ownership.py::RuntimeOwnershipTests::test_thumbnail_repository_persists_success_and_failure_for_api_reads"
        status: pass
    human_judgment: false
  - id: D3
    description: "Malformed metadata JSON and integer environment values return safe validation outcomes without import crashes."
    requirement: OPS-05
    verification:
      - kind: integration
        ref: "tests/test_api_and_auth.py and tests/test_runtime_ownership.py"
        status: pass
    human_judgment: false
duration: 9min
completed: 2026-08-01
status: complete
---

# Phase 01 Plan 13: Behavioral Safety & Runtime Ownership Summary

**Injected worker operations, repository-owned thumbnail writes, and Settings-backed safe metadata parsing close the runtime ownership compatibility gaps.**

## Performance

- **Duration:** 9 min
- **Started:** 2026-08-01T06:49:39Z
- **Completed:** 2026-08-01T06:58:32Z
- **Tasks:** 3/3
- **Files modified:** 8

## Accomplishments

- Removed every `dashboard.app` reverse import from `dashboard.beacon`; the executable worker shim now assembles immutable `WorkerOperations` and starts the package-owned scheduler.
- Moved thumbnail completion SQL into `ThumbnailRepository`, injected it through a named protocol, and retained the existing screenshot success/failure behavior.
- Made application integer settings total over malformed environment text and metadata mutation total over scalar JSON and invalid string fields.

## Task Commits

1. **Task 1: Start the worker through an injected composition root** — `1e3f446`, `fb86026`, `eff6af8`
2. **Task 2: Give preview persistence an explicit repository owner** — `5c06c04`, `eba4fb3`
3. **Task 3: Make startup and metadata parsing safe for malformed values** — `47eafb1`, `fc94a7d`

## Files Created/Modified

- `dashboard/beacon/worker_main.py` — independent scheduler runtime accepting injected operations.
- `dashboard/worker.py` — legacy-compatible executable composition root.
- `dashboard/beacon/repositories.py` — concrete thumbnail result persistence boundary.
- `dashboard/beacon/previews.py` — named thumbnail repository protocol and caller.
- `dashboard/app.py` — Settings-backed constants and safe metadata validation.
- `tests/test_module_boundaries.py` — comprehensive reverse-import and SQL ownership assertions.
- `tests/test_runtime_ownership.py` — worker injection, thumbnail SQLite, and clean-subprocess configuration coverage.
- `tests/test_api_and_auth.py` — scalar JSON and invalid metadata-field response coverage.

## Decisions Made

- Kept `dashboard.app` as the stable WSGI compatibility edge, but restricted its worker dependency assembly to `dashboard/worker.py`.
- Kept the caller-owned transaction model for preview requests; the repository owns parameterized thumbnail SQL only.
- Reused existing `Settings` bounds/defaults instead of adding another environment parser.

## Verification

- `dashboard/.venv/bin/python -m pytest -q tests/test_module_boundaries.py tests/test_runtime_ownership.py tests/test_api_and_auth.py` — 33 passed, 86 subtests passed.
- `dashboard/.venv/bin/python -m pytest -q` — 135 passed, 90 subtests passed (with loopback access enabled for existing browser/proxy tests).

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The default sandbox denies loopback socket binding, which blocks existing browser/proxy integration tests. Re-running the unchanged full suite with local loopback access passed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 01-14 can build on an import-isolated worker package, explicit preview persistence, and safe runtime configuration parsing.
- No compatibility blocker remains for this plan.

## Self-Check: PASSED

- Found all eight modified implementation and test files plus this summary.
- Found every Task 1–3 TDD RED/GREEN commit in git history.
- Confirmed the focused boundary/runtime/API suite and full suite pass.

---
*Phase: 01-behavioral-safety-runtime-ownership*
*Completed: 2026-08-01*
