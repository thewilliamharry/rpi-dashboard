---
phase: 07-optional-advanced-diagnostics
plan: 01
subsystem: api
tags: [flask, sqlite, feature-flag, docker-compose]

# Dependency graph
requires:
  - phase: 03-advanced-current-diagnosis
    provides: "/api/advanced/current, get_current_diagnosis, and the maintenance-path three-service seeding shape this plan's golden reuses"
  - phase: 06-workload-resilience-pi-acceptance
    provides: "the enable_prometheus/enable_lock_profile default-off toggle shape and _enabled parse helper this plan's default-on toggle mirrors"
provides:
  - "Settings.enable_advanced_diagnostics (default True), parsed through the existing _enabled helper"
  - "dashboard/app.py's ENABLE_ADVANCED_DIAGNOSTICS module constant and api_advanced_current's handler-first-statement 404 gate"
  - "docker-compose.yml's ENABLE_ADVANCED_DIAGNOSTICS env line and README's matching Configuration row"
  - "the pre-change enabled-response golden (tests/fixtures/07_advanced_current_enabled_response_golden.json), captured at ceef6da"
  - "DatabaseWorkCounter / _counting_connections, a reusable connection+statement measurement harness over the real connect_db seam"
affects: [07-optional-advanced-diagnostics]

# Actuals (#2632) — pairs with the plan's estimate to calibrate future estimates.
# Same estimateTokens scale (chars/4 over the realized diff), never a harness token count.
actuals:
  tokens: 10730
  tasks: 3
  commits: 5

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Handler-first-statement 404 gate mirroring prometheus_metrics/lock_profile_snapshot exactly (D-07-02)"
    - "Connection/statement counting via set_trace_callback on a wrapped connect_db, patched at both its independent bindings (dashboard.beacon.db and dashboard.app's imported alias)"
    - "Pre-change response golden with both captured_at_commit and captured_at_head, checked against a literal `git diff --quiet <commit> -- dashboard/` precondition rather than HEAD identity"

key-files:
  created:
    - tests/test_optional_advanced_diagnostics.py
    - tests/fixtures/07_advanced_current_enabled_response_golden.json
  modified:
    - dashboard/beacon/config.py
    - dashboard/app.py
    - docker-compose.yml
    - README.md
    - .planning/WINDOWS.md

key-decisions:
  - "D-07-01: enable_advanced_diagnostics defaults True — existing deployments have this page today; a silent removal on upgrade is worse than the cost it saves."
  - "D-07-02: gating is a handler-level 404 as the first statement, mirroring prometheus_metrics/lock_profile_snapshot exactly, ahead of the request.args check, so a disabled route can't be probed for 400 vs 404."
  - "D-07-03: the enabled path is left textually alone below the new guard, so byte-identity is a property of the code shape, not only of a test."
  - "The parse vocabulary's one asymmetry (a typo like 'enabled' degrades to disabled, not to the True default) is pinned deliberately by SettingsAdvancedDiagnosticsTests — inherited from _enabled, not invented."
  - "Deviation: tests/test_optional_advanced_diagnostics.py's EnabledResponseGoldenTests additionally pins every TELEMETRY_*/METRIC_SAMPLE_SECONDS/DISCOVERY_TIMEOUT_SECONDS key the response's settings block reads, after the full-suite run showed an unrelated module's own load_app env leak (tests/test_historical_telemetry_api.py) moving the golden comparison when the suite runs in file order."
  - "Deviation: tests/test_lock_profile.py::LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit now fails because this plan's mandated dashboard/app.py edits shift every _db_lock site's line number below each insertion point. Not fixed — 06-LOCK-AUDIT.md is a Phase-6 artifact this plan's scope fence forbids touching. Recorded at .planning/WINDOWS.md #21."

patterns-established:
  - "Module rule: every load_app call in tests/test_optional_advanced_diagnostics.py passes an explicit ENABLE_ADVANCED_DIAGNOSTICS value, enforced by a module-level comment and a setUpModule/tearDownModule pair that restores the key to its pre-module state so this module can never poison a later module's own bare load_app({})."

requirements-completed: []  # DIA-09 spans all three plans in this phase; 07-01 is the tracer only — see scope fence "Do not promote DIA-09"

coverage:
  - id: D1
    description: "An unset ENABLE_ADVANCED_DIAGNOSTICS resolves to enabled through the real load_settings parser (criterion 1's unset default), established at the settings layer only, never through load_app."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::SettingsAdvancedDiagnosticsTests::test_an_unset_value_defaults_to_enabled"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::SettingsAdvancedDiagnosticsTests::test_the_enabled_vocabulary_matches_the_existing_enabled_helper"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::SettingsAdvancedDiagnosticsTests::test_an_out_of_vocabulary_value_is_treated_as_disabled"
        status: pass
    human_judgment: false
  - id: D2
    description: "With the toggle off, /api/advanced/current answers 404 (with and without a query string) having opened zero SQLite connections and executed zero SQLite statements, measured on real connections during a real request."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedApiTests::test_the_disabled_route_answers_404_with_an_empty_body"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedApiTests::test_the_disabled_route_answers_404_even_with_a_query_string"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedApiTests::test_disabled_request_opens_zero_connections_and_executes_zero_statements"
        status: pass
    human_judgment: false
  - id: D3
    description: "With the toggle on, /api/advanced/current's status, content type, Cache-Control and body are byte-identical to the response captured from the pre-change tree at ceef6da, and the four static Advanced assets' digests are unchanged."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::EnabledResponseGoldenTests::test_the_enabled_response_matches_the_pre_change_golden"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::EnabledResponseGoldenTests::test_the_static_advanced_assets_match_the_pre_change_golden_digests"
        status: pass
    human_judgment: false
  - id: D4
    description: "The connection/statement counter is itself proven sensitive — it fires on ordinary traffic (/api/stats) and the off-vs-on contrast is a strict relation (off == 0 < on), never an absolute count."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedApiTests::test_the_counter_fires_on_ordinary_traffic_not_only_the_route_under_test"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::DisabledAdvancedApiTests::test_enabled_measurement_of_the_same_request_is_strictly_greater_than_disabled"
        status: pass
    human_judgment: false
  - id: D5
    description: "docker-compose.yml's x-beacon-environment anchor gets ENABLE_ADVANCED_DIAGNOSTICS with a BEACON_ADVANCED_DIAGNOSTICS override, and README's Configuration table documents it — the operator's one-value deployment switch."
    requirement: "DIA-09"
    verification:
      - kind: other
        ref: "docker compose config -q (validated clean); tests/test_ui_contract.py + tests/test_maintenance_windows.py compose-slicing tests still pass"
        status: pass
    human_judgment: false

duration: 28min
completed: 2026-09-04
status: complete
---

# Phase 7 Plan 01: Optional Advanced Diagnostics — Tracer Summary

**ENABLE_ADVANCED_DIAGNOSTICS wired end to end from environment through Settings and dashboard/app.py's module constant to a handler-first-statement 404 gate on /api/advanced/current, proven byte-identical when on and zero-SQLite-work when off, against a pre-change response golden and a real connect_db-wrapping measurement instrument.**

## Performance

- **Duration:** 28 min (commit span; excludes upfront file reading)
- **Started:** 2026-09-04T10:45:49+03:00
- **Completed:** 2026-09-04T11:13:49+03:00
- **Tasks:** 3
- **Files modified:** 7 (2 created, 5 modified)

## Accomplishments
- `Settings.enable_advanced_diagnostics: bool = True`, the only one of the three optional-surface toggles defaulting on, parsed through the existing `_enabled` helper — no new parsing code, no second vocabulary.
- `dashboard/app.py`'s `api_advanced_current` gated by a handler-first-statement 404, textually identical below the guard, mirroring `prometheus_metrics`/`lock_profile_snapshot` exactly.
- `docker-compose.yml` and `README.md` give the operator a one-environment-value deployment switch (`BEACON_ADVANCED_DIAGNOSTICS`, defaulting to on).
- A pre-change response golden (`tests/fixtures/07_advanced_current_enabled_response_golden.json`), captured from the tree at `ceef6da` before any production line moved, carrying both `captured_at_commit` and `captured_at_head` so its validity rests on `git diff --quiet ceef6da -- dashboard/` rather than HEAD identity.
- `DatabaseWorkCounter`/`_counting_connections`, a real-request connection/statement counter wrapping the actual `connect_db` seam (both its independent bindings), reused by 07-02 and 07-03.

## Task Commits

Each task was committed atomically, plus two post-hoc fix/docs commits discovered by the whole-suite run:

1. **Task 1: Capture the enabled goldens from the pre-change tree** - `62e041c` (test)
2. **Task 2: The toggle, end to end, on /api/advanced/current** - `d02fc29` (feat)
3. **Task 3: Measure the work, do not read it** - `1cd1354` (test)
4. **Fix: pin telemetry/sampling env for the enabled response golden** - `3685614` (fix)
5. **Docs: record the lock-audit line-shift as an open WINDOWS.md deviation** - `17d025c` (docs)

_Note: commits 4-5 were found and made during the plan's own whole-suite `<verification>` step, not during any individual task's own `<verify>`._

## Files Created/Modified
- `tests/test_optional_advanced_diagnostics.py` - New module: `DisabledAdvancedApiTests`, `EnabledResponseGoldenTests`, `SettingsAdvancedDiagnosticsTests`, `DatabaseWorkCounter`/`_counting_connections`, the golden generator, and the module-leak-protection `setUpModule`/`tearDownModule` pair.
- `tests/fixtures/07_advanced_current_enabled_response_golden.json` - Pre-change response golden (status, content type, Cache-Control, body, four asset digests, both commit identifiers).
- `dashboard/beacon/config.py` - `Settings.enable_advanced_diagnostics` field and its `load_settings` parse site.
- `dashboard/app.py` - `ENABLE_ADVANCED_DIAGNOSTICS` module constant and `api_advanced_current`'s gate.
- `docker-compose.yml` - `ENABLE_ADVANCED_DIAGNOSTICS: "${BEACON_ADVANCED_DIAGNOSTICS:-1}"` in the shared environment anchor.
- `README.md` - Configuration table row for the new variable.
- `.planning/WINDOWS.md` - Entry #21 recording the lock-audit line-shift as an open, out-of-scope deviation.

## Decisions Made
- **D-07-01** (toggle defaults enabled): existing deployments already have this page; an upgrade that sets nothing must not silently remove it.
- **D-07-02** (handler-level 404, not conditional route registration): consistency with the two existing gates in the same file; the outcome (404) doesn't require this specific mechanism, but the mechanism keeps all three optional-surface gates in one shape.
- **D-07-03** (enabled path left textually alone): byte-identity is a property of the code shape, not only of a test.
- The out-of-vocabulary parse behavior (a typo degrades to disabled, the one place this default-on toggle diverges from the two default-off toggles sharing `_enabled`) is pinned deliberately by `SettingsAdvancedDiagnosticsTests::test_an_out_of_vocabulary_value_is_treated_as_disabled`.
- Module rule for the whole phase: every `load_app` call in `tests/test_optional_advanced_diagnostics.py` passes an explicit `ENABLE_ADVANCED_DIAGNOSTICS` value, because `load_app` copies `extra_env` into `os.environ` and never clears it (`tests/helpers.py:51-65`). `setUpModule`/`tearDownModule` additionally restore the key to its pre-module state so this module can never poison a later module's own bare `load_app({})` call.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] EnabledResponseGoldenTests' golden comparison was vulnerable to an unrelated module's own environment leak**
- **Found during:** the plan's whole-suite `<verification>` run (not caught by Task 2's five-module `<verify>`, since that command never runs `tests/test_historical_telemetry_api.py` before this module).
- **Issue:** `tests/test_historical_telemetry_api.py::ConfiguredTelemetryPolicyApiTests` sets `TELEMETRY_RAW_DAYS=8`, `TELEMETRY_FIVE_MINUTE_DAYS=31`, `TELEMETRY_RETENTION_DAYS=91`, `TELEMETRY_POINT_BUDGET=2` via `load_app` and never clears them (the same general `tests/helpers.py:51-65` leak this plan already named for `ENABLE_ADVANCED_DIAGNOSTICS`). That module sorts alphabetically before `tests/test_optional_advanced_diagnostics.py`, so in a full-suite run those values were still in `os.environ` when `EnabledResponseGoldenTests` built its own application, and the response's `settings.retention` block diverged from the golden (`point_budget` 2048→2, `raw_days` 7→8, `five_minute_days` 30→31).
- **Fix:** added `_DEFAULT_SETTINGS_PAYLOAD_ENV`, pinning every environment key `dashboard/beacon/diagnosis.py::_settings_payload` reads (`METRIC_SAMPLE_SECONDS`, `DISCOVERY_TIMEOUT_SECONDS`, all six `TELEMETRY_*` keys) at `dashboard/beacon/config.py`'s literal defaults, used by both `generate_enabled_response_golden()` and `EnabledResponseGoldenTests.setUp()`.
- **Files modified:** `tests/test_optional_advanced_diagnostics.py`
- **Verification:** `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py tests/test_optional_advanced_diagnostics.py` — 32 passed, 16 subtests passed. Full suite re-run afterward showed no remaining failure attributable to this module.
- **Committed in:** `3685614`

**2. [Recorded, not fixed — out of scope] tests/test_lock_profile.py::LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit now fails**
- **Found during:** the plan's whole-suite `<verification>` run.
- **Issue:** this plan's mandated `dashboard/app.py` edits (the 4-line `ENABLE_ADVANCED_DIAGNOSTICS` module constant block and the 6-line docstring+gate on `api_advanced_current`) shift every `_db_lock` call site's line number below each insertion point. `06-LOCK-AUDIT.md`'s table hardcodes `(function, line)` pairs and is explicitly designed to fail the moment they drift (its own text: "a table nobody re-reads is not a prerequisite"). Confirmed this is a pure line-number desync, not a scope or safety change: same 28 sites, same 26 functions, `LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock` (structural, not line-based) still passes.
- **Why not fixed:** `06-LOCK-AUDIT.md` is a `.planning/phases/06-*` artifact, and this plan's scope fence explicitly forbids touching it ("Phase 6 is unsealed and mid-flight"). The shift is unavoidable given the plan's own mandated action (D-07-02 requires the module constant grouped with `ENABLE_PROMETHEUS`/`ENABLE_LOCK_PROFILE`, and the gate mirroring the two existing gates line-for-line) — no smaller edit satisfying the plan's own acceptance criteria would avoid it. None of this plan's three tasks' own `<verify>` commands include `tests/test_lock_profile.py`, which is consistent with this having been a known trade-off.
- **Recorded:** `.planning/WINDOWS.md` entry #21 (kind: deviation, phase 07, open).
- **Impact:** the phase-wide full-suite floor (939 passed / 564 subtests, 0 failed at `ceef6da`) is exceeded — 949 passed / 573 subtests, 1 failed — and the sole failure is this recorded, understood, non-functional line-number desync, not a new behavioral regression.

---

**Total deviations:** 1 auto-fixed (test isolation bug), 1 recorded-not-fixed (out-of-scope line-number desync in a Phase-6 artifact).
**Impact on plan:** The auto-fix was necessary for the golden test's own correctness under whole-suite load. The recorded deviation is a documentation-sync issue in another phase's artifact, not a functional or security regression in this plan's own code; `_db_lock`'s scope and safety are unchanged (confirmed by the still-passing structural guard).

## Sensitivity Demonstrations (observed values)

All mutations below were applied, run, observed, and reverted before the corresponding commit.

| # | Mutation | Test | Observed failure |
|---|----------|------|-------------------|
| 1 | Mutated one character of the golden fixture's `body` | `EnabledResponseGoldenTests::test_the_enabled_response_matches_the_pre_change_golden` | `AssertionError: ... : /api/advanced/current's enabled response body moved from the golden captured at ceef6da` |
| 2 | Mutated the golden fixture's `cache_control` (`no-store`→`no-cache`) | same test | `AssertionError: 'no-store' != 'no-cache' : /api/advanced/current's enabled Cache-Control moved from the golden captured at ceef6da` |
| 3 | Flipped `load_settings`' parse default from `'1'` to `'0'` | `SettingsAdvancedDiagnosticsTests::test_an_unset_value_defaults_to_enabled` | `AssertionError: False is not true` |
| 4 | Removed `api_advanced_current`'s early return | `DisabledAdvancedApiTests::test_the_disabled_route_answers_404_with_an_empty_body` | `AssertionError: 200 != 404` |
| 5 | Removed `api_advanced_current`'s early return (statement-count guard) | `DisabledAdvancedApiTests::test_disabled_request_opens_zero_connections_and_executes_zero_statements` | `AssertionError: 8 != 0 : disabled /api/advanced/current executed 8 SQLite statement(s) across 1 connection(s) instead of zero` |

**Instrument sensitivity (not a mutation, a positive proof):** `GET /api/stats` (toggle on, never gated by this phase) recorded 1 connection / 1 statement, proving the trace callback fires on ordinary traffic. Observed pairs for the record: disabled `/api/advanced/current` = 0 connections / 0 statements; disabled `/` = 0/0; enabled `/api/advanced/current` (3-service seeded dataset) = 1 connection / 15 statements.

## Golden Digests (recorded per Task 1's acceptance criteria)

- `body` sha256: `58f7afdcaa21fe90e676977cd17a4b51949c11e27884edeaac914faf9a1547f3` (7575 bytes)
- `index.html` sha256: `17117d4940aef5cd468ee077009003b799ec124c1643229bcdbe9314ab17fcf0`
- `advanced.html` sha256: `fc7c22348ee4c922b2006b285d4ba29872fee3191cf079094f25b59d97043a63`
- `advanced.css` sha256: `fe97df99ab2c4fe5e359a6b5389eff39d2d32c4ed5c5b97e4e900f0f2a6a805e`
- `advanced.js` sha256: `501fc4d7bcb4654a1393fec8e5eba8176161337627c01d29c8317dc027ad9ef0`
- `captured_at_commit`: `ceef6da` — `captured_at_head`: `2026cb146e11d4f2a1893bc0ba600a15fc9d58f5`

## Module Rule Compliance (Task 1's acceptance criterion)

`grep -n 'load_app(' tests/test_optional_advanced_diagnostics.py` finds 5 real call sites (2 text mentions in docstrings excluded): 1 disabled (`'0'`, `DisabledAdvancedApiTests.setUp`), 4 enabled (`'1'`) — 2 inline literal (`test_the_counter_fires_on_ordinary_traffic_not_only_the_route_under_test`, `test_enabled_measurement_of_the_same_request_is_strictly_greater_than_disabled`) and 2 via the shared `_DEFAULT_SETTINGS_PAYLOAD_ENV` constant (`generate_enabled_response_golden`, `EnabledResponseGoldenTests.setUp`) which itself pins `'ENABLE_ADVANCED_DIAGNOSTICS': '1'`. Confirmed `EnabledResponseGoldenTests` passes with the whole module run in one process, in alphabetical class order, after `DisabledAdvancedApiTests` has written `'0'` into `os.environ`.

## Issues Encountered
None beyond the two deviations documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `07-02` can proceed: `dashboard/app.py`'s three remaining advanced routes (`/advanced`, `/advanced.css`, `/advanced.js`) follow the same handler-first-statement 404 shape this plan established, and `_counting_connections`/`DatabaseWorkCounter` are ready to reuse for the front page's own zero-work measurement.
- `07-03`'s front-page cost equality and reversibility measurements depend on `07-02`'s front-page conditional branch landing first — not yet in place.
- Open item for whoever next works Phase 6: `.planning/WINDOWS.md` #21 needs a mechanical line-number refresh of `06-LOCK-AUDIT.md`'s table (no content/judgment change) once Phase 6 is unsealed.
- DIA-09 remains **not** promoted (scope fence honored) — only `07-01`'s tracer scope is complete.

---
*Phase: 07-optional-advanced-diagnostics*
*Completed: 2026-09-04*

## Self-Check: PASSED

All 8 files listed in Files Created/Modified (plus this SUMMARY) confirmed present on disk. All 5 commit hashes (`62e041c`, `d02fc29`, `1cd1354`, `3685614`, `17d025c`) confirmed present in `git log --oneline --all`.
