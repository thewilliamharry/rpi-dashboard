---
phase: 06-workload-resilience-pi-acceptance
plan: 09
subsystem: database
tags: [sqlite, wal, inventory, thumbnails, code-review-gap-closure]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: WAL rollout, schema inventory tooling, and thumbnail/preview retry budget (06-01..06-08)
provides:
  - _readonly_connection's third mode=ro&immutable=1 attempt, closing AR-06-02's residual inspection gap
  - a recorded connection_strategy field on every inventory report, alongside journal_mode
  - thumb_state precedence fix so a servable thumbnail is never reported as degraded
affects: [06-verify-work, future migration/inventory tooling, thumbnail-status API consumers]

# Actuals (#2632)
actuals:
  tokens: 4808
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Parameter-based pass-through helpers (_query_only, _validated) keep a connection factory's return statement ownership-gate-compatible while still validating/configuring the connection before it is handed to the caller"
    - "A validating probe (SELECT 1) inside a connection-opening attempt's own try/except, closing the connection before re-raising on failure, catches SQLite builds that defer -shm/WAL initialization failures to first statement execution rather than connect() time"

key-files:
  created: []
  modified:
    - dashboard/beacon/inventory.py
    - dashboard/app.py
    - tests/test_migrations.py
    - tests/test_api_and_auth.py

key-decisions:
  - "Added a _validated probe to the mode=ro and query_only attempts in _readonly_connection, not just the new immutable one: this environment's SQLite build (3.51.2) defers -shm mapping failures to first statement execution rather than connect() time, which was silently defeating the entire fallback chain until the probe was added -- discovered while writing the tests, not anticipated by the plan"
  - "Recorded connection_strategy as a human-readable description string (e.g. 'mode=ro&immutable=1 -- ignores the -wal file; a reading taken this way may omit committed but not-yet-checkpointed WAL transactions') rather than a bare code, so the caveat travels with the reading itself rather than depending on a reader already knowing what immutable=1 implies"
  - "thumb_state's existing thumb_error/thumb_attempt_ts/thumb_source fields already distinguish a stale-but-servable thumbnail (thumb_state='ok' with a non-null thumb_error) from a fully current one (thumb_state='ok', thumb_error=None) -- no new response field was needed to preserve the degraded signal's information content"

patterns-established:
  - "Parameter-based pass-through connection helper: take an already-open connection as a function parameter (never reassign to a new Name), operate on it, return the same parameter -- keeps the module's AST-based connection-ownership gate seeing direct return-of-opening-call ownership transfer"

requirements-completed: [OPS-02, OPS-03, OPS-04]

coverage:
  - id: D1
    description: "A locked-down archival copy of a WAL-mode database (the copy-then-restrict workflow this phase's README documents) inspects successfully via a final mode=ro&immutable=1 attempt, reached only after both write-requiring attempts fail"
    requirement: OPS-04
    verification:
      - kind: unit
        ref: "tests/test_migrations.py#InventoryTests.test_the_immutable_attempt_is_reached_only_after_both_writable_attempts_fail"
        status: pass
      - kind: integration
        ref: "tests/test_migrations.py#InventoryTests.test_wal_mode_on_a_non_writable_directory_inspects_successfully"
        status: pass
      - kind: unit
        ref: "tests/test_migrations.py#InventoryTests.test_wal_mode_on_a_writable_directory_never_reports_the_immutable_strategy"
        status: pass
    human_judgment: false
  - id: D2
    description: "The inventory report records which connection strategy produced it, with the immutable strategy's value stating that such a reading may omit committed but not-yet-checkpointed WAL content"
    requirement: OPS-04
    verification:
      - kind: unit
        ref: "tests/test_migrations.py#InventoryTests.test_non_wal_fixture_still_inspects_through_the_first_attempt"
        status: pass
      - kind: unit
        ref: "tests/test_migrations.py#InventoryTests.test_the_immutable_attempt_is_reached_only_after_both_writable_attempts_fail"
        status: pass
    human_judgment: false
  - id: D3
    description: "A service with a servable thumbnail is reported 'ok', never 'degraded', while a service with no servable thumbnail and a degraded preview request still reports 'degraded'"
    requirement: OPS-02
    verification:
      - kind: integration
        ref: "tests/test_api_and_auth.py#ApiAndAuthTests.test_thumb_state_precedence_across_the_four_has_thumb_and_preview_status_combinations"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-09-01
status: complete
---

# Phase 6 Plan 09: Code-review gap closure (WR-01, WR-02) Summary

**Closed WR-01 (immutable-URI fallback so locked-down WAL archival copies inspect successfully, with a disclosed connection-strategy field) and WR-02 (thumb_state precedence so a servable thumbnail is never misreported as degraded)**

## Performance

- **Duration:** ~45 min
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- `_readonly_connection` gained a final `mode=ro&immutable=1` attempt, reached only after both write-requiring attempts fail, closing `AR-06-02`'s residual gap: an archival copy locked down per this phase's own README workflow now inspects successfully instead of raising `InventoryError`.
- Every inventory report now carries `connection_strategy` alongside `journal_mode`; the immutable strategy's recorded value states inline that such a reading may omit committed but not-yet-checkpointed WAL transactions.
- Discovered and fixed a real defect while writing the tests for the above: this environment's SQLite build (3.51.2) defers `-shm`/WAL initialization failures to first statement execution rather than `connect()` time. The original two-attempt fallback (and the plan's proposed third attempt) would have silently never triggered, because `sqlite3.connect()` itself appeared to succeed and the real failure surfaced later, outside every attempt's exception handling, in `collect_inventory`'s first schema query. Added a `_validated` probe (matching `_query_only`'s existing parameter-based pass-through shape, so the AST connection-ownership gate still recognizes `_readonly_connection` as a factory) to force this class of failure into the correct attempt's own `except` clause.
- `thumb_state` in `/api/thumbnail-status` now checks `has_thumb` before the degraded preview status, so a service whose thumbnail is being served successfully is never reported `degraded`. The degraded signal still reaches the response whenever no servable thumbnail exists.

## Task Commits

Each task was committed atomically:

1. **Task 1: Make read-only inspection succeed on genuinely read-only media (WR-01)** - `155d553` (fix, tdd)
2. **Task 2: A served thumbnail outranks a degraded preview request (WR-02)** - `e874fcb` (fix, tdd)

**Plan metadata:** (this commit)

_Both tasks were single commits each — RED/GREEN were folded into one atomic commit per task since the fix and its tests were developed together and verified before committing._

## Files Created/Modified

- `dashboard/beacon/inventory.py` - Third `mode=ro&immutable=1` attempt in `_readonly_connection`; new `_validated` probe helper; `connection_strategy` recorded in `collect_inventory`'s report
- `dashboard/app.py` - `thumb_state` derivation in `api_thumbnail_status` reordered so `has_thumb` is checked first
- `tests/test_migrations.py` - New `InventoryTests` covering the writable/non-writable/non-WAL/deterministic-mocked-ordering cases
- `tests/test_api_and_auth.py` - New test covering all four `has_thumb`/`preview_status` combinations for `thumb_state`

## Decisions Made

- Added the `_validated` probe to the mode=ro and query_only attempts (not just the new immutable one) after discovering this SQLite build defers WAL failures past connect time — undocumented in the plan, found and fixed during test-writing (Rule 1: auto-fixed bug — the plan's design would not have functioned in this environment).
- Recorded `connection_strategy` as a self-describing string (carrying the uncheckpointed-WAL caveat inline) rather than a bare enum code, so an operator meets the disclosure at the point they read the field.
- Relaxed the "writable directory" test's assertion to "not immutable" rather than "specifically query_only", since which of the two write-capable attempts resolves the connection is itself an SQLite-build detail (newer SQLite can serve `mode=ro` against WAL without `-shm` write access) — the actual safety property (PROH-OPS-04-03) is that immutable is never reached, not which earlier attempt succeeds.
- Kept the non-writable-directory integration test real (chmod-based) with an honest `skipTest` when this sandbox's SQLite build resolves the scenario via an earlier attempt rather than immutable, and added a separate deterministic mocked test that pins the immutable attempt's ordering and success independent of the host SQLite build's WAL-without-shared-memory support.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `_readonly_connection`'s fallback chain never triggered in this environment because SQLite defers `-shm` mapping failures to first statement execution, not `connect()` time**
- **Found during:** Task 1, while writing the "non-writable directory" test
- **Issue:** The plan's design (and the review's own reproduction) assumed a failing attempt raises at `sqlite3.connect()` time. On this SQLite build (3.51.2), `sqlite3.connect(url, uri=True)` for a WAL database with no pre-existing `-shm`/`-wal` on a locked directory succeeds immediately; the actual `sqlite3.OperationalError('attempt to write a readonly database')` only surfaces on the first real query, which happens in `collect_inventory`'s `_tables(conn)` call — entirely outside `_readonly_connection`'s exception handling. Without a fix, the first attempt would silently "win" every time, the second and third attempts would never be tried, and `collect_inventory` itself would raise `InventoryError`, exactly reproducing the original AR-06-02 bug despite the new third attempt existing in the code.
- **Fix:** Added a `_validated(conn)` helper — a parameter-based pass-through matching `_query_only`'s existing shape (so the AST-based connection-ownership gate still sees direct return-of-opening-call transfer) — that executes `SELECT 1` inside the attempt's own try/except, closing the connection and re-raising on failure. Applied to the mode=ro attempt directly and via `_query_only` for the query_only attempt. The immutable attempt does not need it: it never exhibits this deferred-failure behavior since it bypasses WAL/`-shm` entirely.
- **Files modified:** dashboard/beacon/inventory.py
- **Verification:** `test_the_immutable_attempt_is_reached_only_after_both_writable_attempts_fail` (deterministic, mocked) and `test_wal_mode_on_a_non_writable_directory_inspects_successfully` (real filesystem) both pass; full test suite (`uv run --project dashboard python -m pytest -q`) passes at 836 passed.
- **Committed in:** `155d553` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary for WR-01's fix to actually function as designed; without it the plan's stated objective (AR-06-02's residual gap resolved) would not have been achieved on this SQLite build. No scope creep — confined to `_readonly_connection`'s existing attempt structure.

## Issues Encountered

- The WR-01 review's reproduction (`sqlite3.connect(...)` raising immediately for WAL databases) does not hold on this environment's newer SQLite (3.51.2), which supports read-only WAL access without `-shm` write access in more cases than the review's original environment. This meant the "writable directory" and "non-writable directory" real-filesystem tests needed relaxed/honest assertions (accepting either write-capable attempt, and skipping cleanly when the immutable attempt isn't reached) rather than asserting a specific attempt was used — resolved by adding a deterministic mocked test as the primary pin for the ordering behavior, independent of host SQLite version quirks.

## Next Phase Readiness

- `WR-01` and `WR-02` are both closed with tests, ending the deferred-warnings carryforward from `06-REVIEW.md`.
- `AR-06-02` in `06-SECURITY.md` is code-fixed by this plan; the accepted-risk log entry itself was left unedited (out of this plan's declared file scope) — a future security-audit pass should reconcile it against this SUMMARY the same way other phase risk-log entries are independently re-verified before promotion.
- No blockers for the phase's remaining acceptance work.

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-01*
