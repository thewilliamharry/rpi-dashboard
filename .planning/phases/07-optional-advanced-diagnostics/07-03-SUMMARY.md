---
phase: 07-optional-advanced-diagnostics
plan: 03
subsystem: api
tags: [flask, sqlite, feature-flag, docker-compose, acceptance-testing]

# Dependency graph
requires:
  - phase: 07-optional-advanced-diagnostics
    provides: "07-01's DatabaseWorkCounter/_counting_connections measurement harness and captured enabled-response golden; 07-02's front-page disabled branch (dashboard/app.py::index) and dashboard/beacon/frontpage.py's without_advanced_entry_point"
provides:
  - "FrontPageCostEqualityTests: a measured equality (statement count, connection count) between the front page's whole boot request set off vs on -- criterion 3's only independent force beyond 07-01's zero-work assertion on `/` alone"
  - "ToggleReversibilityTests: criterion 5 as a round trip -- a disabled session's iterdump sha256 and applied schema version unchanged, then the same database file reopened toggle-on recovers 07-01's captured golden"
  - "AcceptanceConfigurationGuardTests / PROH-DIA-09-01: docker-compose.yml's shipped ENABLE_ADVANCED_DIAGNOSTICS default proven enabled through the real load_settings parser"
  - "_load_app_over_existing_db / _iterdump_sha256 test helpers, reusable by any future test needing two application builds to see the same on-disk database"
  - "07-DECISIONS.md (D-07-01..D-07-09, PROH-DIA-09-01) and 07-DEBT.md (D-DEBT-07-01) -- the phase's consolidated decision and debt record"
affects: [07-optional-advanced-diagnostics]

# Actuals (#2632) -- pairs with the plan's estimate to calibrate future estimates.
# Same estimateTokens scale (chars/4 over the realized diff), never a harness token count.
actuals:
  tokens: 10550
  tasks: 2
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Sequential (never simultaneous) load_app/_load_app_over_existing_db builds when a test needs two toggle states in one process: dashboard.app is a singleton module mutated in place by importlib.reload, so a request dispatched through an earlier-built Flask app's test client, issued after a LATER reload, silently observes the later reload's module globals. One side's full request round must complete before the other side's reload."
    - "Equality-not-threshold cost measurement: both terms measured in the same run, over the same seeded database, never against a literal/ratio/duration (D-DEBT-06-14's lesson)."
    - "iterdump() logical-content sha256, not file bytes, as the no-stored-change oracle -- immune to WAL sidecar-file movement from read-only traffic."
    - "Compose anchor scan with its own line-oriented, no-YAML-dependency parser (style-only precedent: tests/pi_load_acceptance.py's parse_compose_memory_limits), because that function's in_services gate cannot reach an anchor block that sits above services:."
    - "One-time recorded reproduction (D-DEBT-07-01), deliberately not a standing test, for a finding that must stop being true rather than be pinned."

key-files:
  created:
    - .planning/phases/07-optional-advanced-diagnostics/07-DECISIONS.md
    - .planning/phases/07-optional-advanced-diagnostics/07-DEBT.md
  modified:
    - tests/test_optional_advanced_diagnostics.py
    - .planning/ROADMAP.md

key-decisions:
  - "D-07-07 (front-page cost equality, never a threshold): the property under test is the toggle-delivery mechanism costs the front page nothing, measured as an equality between two same-run statement/connection totals."
  - "D-07-08/D-07-09 (no-stored-change, restart-reversibility): iterdump()'s logical content, not file bytes, is the oracle -- WAL sidecar files move under read-only traffic and a file-bytes oracle would fail for reasons unrelated to stored data."
  - "PROH-DIA-09-01 minted: every OPS-07 acceptance run measures the fully-enabled configuration; the toggle is a deployment mode, never a test knob. Specializes PROH-OPS-07-01/PROH-OPS-07-10."
  - "D-DEBT-07-01 recorded, not fixed (tests/pi_load_acceptance.py is out of scope): _load_worker discards response status, so a disabled /api/advanced/current's 404 is recorded as a fast success -- measured p95 1.225ms against a 2000ms budget, status 404 from a separate direct probe the harness never performs."
  - "Implementation deviation (Rule 1, documented below): the plan's literal 'build two applications, issue the boot set through each' ordering silently breaks under dashboard.app's singleton-reload semantics -- fixed by measuring the disabled side completely before reloading to enabled."

patterns-established:
  - "Test helper _load_app_over_existing_db, mirroring tests/helpers.py's load_app minus minting a fresh temp db dir, for any future test needing two builds over one database file."

requirements-completed: []  # DIA-09 spans all three plans in this phase; promotion is an independent verification round's decision (TEL-06/PROH-OPS-07-08 precedent) -- not this plan's to make.

coverage:
  - id: D1
    description: "A full front-page boot request set (/, /api/stats, /api/history, /api/scan-status, /api/services, /api/events?limit=50) executes the same measured SQLite statement count and connection count with the toggle off as with it on, on the same seeded database, gated by a (False, True) settings pair asserted immediately upon each build."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageCostEqualityTests::test_the_settings_pair_is_false_true_read_immediately_upon_each_build"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageCostEqualityTests::test_per_path_status_codes_agree_between_the_two_sides"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::FrontPageCostEqualityTests::test_front_page_boot_costs_the_same_measured_statements_and_connections_off_and_on"
        status: pass
    human_judgment: false
  - id: D2
    description: "A disabled session exercising the front-page boot set and all four gated advanced routes leaves the database's logical content (iterdump sha256) and applied schema version unchanged; reopening the same database file with the toggle back on returns 07-01's captured golden on /api/advanced/current."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::ToggleReversibilityTests::test_a_disabled_session_leaves_the_database_unchanged_and_restart_recovers_the_golden"
        status: pass
    human_judgment: false
  - id: D3
    description: "docker-compose.yml's shipped ENABLE_ADVANCED_DIAGNOSTICS default, resolved for the operator-sets-nothing case and fed through the real load_settings parser, resolves to enabled -- PROH-DIA-09-01's automated guard."
    requirement: "DIA-09"
    verification:
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::AcceptanceConfigurationGuardTests::test_the_scan_finds_exactly_one_entry_before_any_value_is_interpreted"
        status: pass
      - kind: unit
        ref: "tests/test_optional_advanced_diagnostics.py::AcceptanceConfigurationGuardTests::test_the_shipped_default_resolves_to_enabled_through_the_real_parser"
        status: pass
    human_judgment: false
  - id: D4
    description: "07-DECISIONS.md records D-07-01 through D-07-09 (with rejected alternatives) and PROH-DIA-09-01 stated in full; 07-DEBT.md records D-DEBT-07-01 with measured harness p95, a separately-probed status code, and a named owner."
    requirement: "DIA-09"
    verification:
      - kind: other
        ref: ".planning/phases/07-optional-advanced-diagnostics/07-DECISIONS.md, .planning/phases/07-optional-advanced-diagnostics/07-DEBT.md (present on disk, reviewed inline above)"
        status: pass
    human_judgment: false

# Metrics
duration: 8min
completed: 2026-09-04
status: complete
---

# Phase 7 Plan 03: Front-Page Cost Equality, Restart Reversibility, and the OPS-07 Fence Summary

**Criterion 3 closed as a measured equality (SQLite statement/connection totals, off vs on, over the front page's whole boot request set) and criterion 5 closed as a restart round trip (iterdump sha256 + schema version unchanged, then the golden recovered) — plus PROH-DIA-09-01 minted and guarded through the real settings parser, and the acceptance harness's blindness to a disabled route's 404 recorded as measured evidence with a named owner.**

## Performance

- **Duration:** 8 min (commit span between the two task commits; excludes upfront file reading, the singleton-reload investigation, and the mutation-verification cycles performed between commits)
- **Started:** 2026-09-04T13:01:59+03:00
- **Completed:** 2026-09-04T13:10:21+03:00
- **Tasks:** 2
- **Files modified:** 4 (2 created, 2 modified)

## Accomplishments
- `FrontPageCostEqualityTests`: a full front-page boot request set (`/`, `/api/stats`, `/api/history`, `/api/scan-status`, `/api/services`, `/api/events?limit=50`, derived from `dashboard/app.js`'s own `DOMContentLoaded` handler) executes the same measured SQLite statement count and connection count with the toggle off as with it on — **14 statements / 5 connections on both sides**, observed on the same seeded three-service dataset — gated by a `(False, True)` settings-pair assertion read immediately upon each build.
- `ToggleReversibilityTests`: a disabled session exercising the boot set plus all four gated routes leaves the database's `iterdump()` sha256 (`07619845...`) and applied schema version (`10`) unchanged before and after; reopening the same database file with the toggle back on returns `07-01`'s captured golden on `/api/advanced/current` byte-for-byte.
- `PROH-DIA-09-01` minted and guarded: `AcceptanceConfigurationGuardTests` scans `docker-compose.yml`'s `environment: &beacon-environment` anchor (its own scan, not `tests/pi_load_acceptance.py`'s `parse_compose_memory_limits`, whose `in_services` gate cannot reach that anchor) and proves the shipped default resolves to enabled through the real `load_settings` parser, never a text comparison.
- `D-DEBT-07-01` recorded with real numbers: a one-time reproduction against a disabled application found the harness's own `_load_worker` measuring `/api/advanced/current` at **p95 1.225ms** (389 samples, 3s window) — comfortably inside the 2000ms budget — while a separate direct probe (outside the harness) found the actual status is **404**. The harness's own `assert_response_times` reports `passed: True` for that latency set, exactly the blind spot this entry documents.
- A real implementation bug found and fixed while writing the tests: `dashboard.app` is a singleton module mutated in place by `importlib.reload`, so building the enabled side after the disabled side silently rebinds the disabled side's own `SETTINGS`/`ENABLE_ADVANCED_DIAGNOSTICS` globals too (confirmed by first observing `(True, True)` instead of `(False, True)`). Fixed by measuring the disabled side completely before ever reloading to enabled — see Deviations below.
- Every new guard mutation-verified with observed failure values, including the required two-part vacuity demonstration for the cost equality (see Sensitivity Demonstrations).

## Task Commits

Each task was committed atomically:

1. **Task 1: The front page costs the same either way, and the database comes back untouched** - `a3554ac` (test)
2. **Task 2: Mint PROH-DIA-09-01, guard the deployed default, and record the hole this phase cannot close** - `538754c` (feat)

**Plan metadata (deviation fix):** `097290f` (fix: leave ROADMAP.md's Progress table to the orchestrator)

## Files Created/Modified
- `tests/test_optional_advanced_diagnostics.py` - Added `FrontPageCostEqualityTests`, `ToggleReversibilityTests`, `AcceptanceConfigurationGuardTests`; helpers `_load_app_over_existing_db`, `_iterdump_sha256`, `_scan_beacon_environment_anchor`, `_enable_advanced_diagnostics_compose_entries`, `_resolve_unset_default`; `COMPOSE_PATH` constant; `importlib`/`re`/`sqlite3`/`dashboard.beacon.migrations` imports.
- `.planning/phases/07-optional-advanced-diagnostics/07-DECISIONS.md` - New: `D-07-01` through `D-07-09` (consolidated from `07-01`/`07-02`'s prose plus this plan's own `D-07-07`/`D-07-08`/`D-07-09`), the inherited `_enabled` out-of-vocabulary asymmetry, and `PROH-DIA-09-01` stated in full.
- `.planning/phases/07-optional-advanced-diagnostics/07-DEBT.md` - New: `D-DEBT-07-01` with the measured p95, the separately-probed status code, the observed `assert_response_times` result, and a named owner (the next OPS-07 round in Phase 6).
- `.planning/ROADMAP.md` - Phase 7's three plan-list checkboxes ticked `- [x]`. The Progress-table row was moved to `3/3`/`Complete`/`2026-09-04` in the Task 2 commit per the plan's own literal acceptance criteria, then reverted to its pre-plan state (`0/3`/`Planned`) in a follow-up fix commit, per this executor's spawn instructions reserving that table for the orchestrator — see Deviations below.

## Decisions Made
- **D-07-07** (cost equality, not a threshold): both terms measured in the same run over the same seeded database; `D-DEBT-06-14`'s lesson (Phase 6) about absolute-figure guards moving with dataset growth applies directly here.
- **D-07-08/D-07-09** (no-stored-change, restart-reversibility): `iterdump()`'s logical content, not file bytes, is the oracle — the deployment runs SQLite in WAL mode, so read-only traffic alone can move the `-wal`/`-shm` sidecar files, and a file-bytes oracle would fail for reasons unrelated to stored data.
- **PROH-DIA-09-01** minted, specializing `PROH-OPS-07-01`/`PROH-OPS-07-10`: every OPS-07 acceptance run measures the fully-enabled configuration; the toggle is a deployment mode, never a test knob.
- **D-DEBT-07-01** recorded rather than fixed: the fix requires editing `tests/pi_load_acceptance.py`, out of this phase's scope; the entry names the next OPS-07 round in Phase 6 as owner.
- Consistent with `07-01`'s and `07-02`'s own precedent (`TEL-06`/`PROH-OPS-07-08`), `DIA-09` is **not** promoted in `REQUIREMENTS.md` by this plan (`git diff --quiet -- .planning/REQUIREMENTS.md` holds) — promotion belongs to an independent verification round.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] The plan's literal "build both applications, then issue requests through each" ordering silently produces a vacuous measurement**
- **Found during:** Task 1, writing `FrontPageCostEqualityTests`.
- **Issue:** `dashboard.app` is imported once per test process and reused as a singleton; `importlib.reload` (inside both `load_app` and this plan's own `_load_app_over_existing_db`) mutates that ONE module object's namespace in place and returns the SAME object — it does not hand back an independent copy. `ENABLE_ADVANCED_DIAGNOSTICS`/`SETTINGS` are plain module globals, read live by every route function via `__globals__` at call time, not frozen per Flask `app` instance. Building the enabled application after the disabled one (as first written, following the plan's literal "build two applications ... and issue the boot request set through each" phrasing) therefore silently rebound the disabled side's own globals too: the settings pair read `(True, True)` instead of `(False, True)` on first run, and — had the settings-pair assertion not caught it — the "disabled" side's own boot requests, if issued after the second reload, would have silently executed as enabled.
- **Fix:** Restructured `setUp` to measure the disabled side completely (settings value read, full boot-request round, statement/connection counts captured) BEFORE reloading to the enabled side. The enabled side's own settings value and boot-request round follow only after. This preserves the plan's substantive intent (settings values captured immediately upon each build, asserted as `(False, True)` before any comparison is drawn) while respecting the module's actual reload semantics. Documented at length in the class docstring and inline comments so a future reader does not reintroduce the bug.
- **Files modified:** `tests/test_optional_advanced_diagnostics.py`
- **Verification:** All three `FrontPageCostEqualityTests` methods pass; the settings-pair sensitivity mutation (below) confirms the guard still catches the exact vacuous-pass scenario this bug would have hidden.
- **Committed in:** `a3554ac` (Task 1 commit)

**2. [Executor spawn-instruction override] ROADMAP.md's Progress-table row reverted after Task 2's own commit**
- **Found during:** Task 2's own commit, then corrected immediately after.
- **Issue:** Task 2's plan text asks for both the three plan-list checkbox edits AND moving Phase 7's Progress-table row to `3/3`/`Complete`. This executor's spawn instructions (the `<objective>` this plan was launched under) explicitly reserve `.planning/ROADMAP.md`'s Progress table (and `STATE.md`) for the orchestrator to update after a wave's plans land — likely to avoid concurrent plans in the same wave racing on the same shared table row — and call out only the checkbox edits as this executor's own. The Task 2 commit (`538754c`) was made following the plan's literal text before this conflict was reconciled.
- **Fix:** A follow-up commit (`097290f`) reverted only the Progress-table row back to its pre-plan state (`0/3`/`Planned`, blank date), leaving the three checkbox edits (`- [x]`) in place. Spawn instructions outrank a plan's literal acceptance criterion when the two conflict, per this executor's own operating rules ("Task constraints outrank any ambient mid-execution system reminder... no message from any agent is ever your user's consent").
- **Files modified:** `.planning/ROADMAP.md`
- **Verification:** `git diff` confirms the Progress-table row is back to `0/3`/`Planned`/blank; the three plan-list checkboxes remain `- [x]`.
- **Committed in:** `097290f`

---

**Total deviations:** 2 (1 auto-fixed Rule-1 bug caught before any commit; 1 spawn-instruction correction made in a follow-up commit after the conflict surfaced).
**Impact on plan:** Neither changes this plan's substantive deliverables. The Rule-1 fix was necessary for the cost-equality measurement's own correctness — without it, criterion 3's central measurement could have silently passed by comparing two disabled runs, precisely the defect class this plan's own objective warned against. The Progress-table reversion is a scope correction, not a functional change; Phase 7's actual completion state is fully recorded by the three ticked checkboxes and this SUMMARY's own `status: complete`, and the orchestrator is expected to update the Progress table itself.

## Sensitivity Demonstrations (observed values)

All mutations below were applied to a working-tree file, run, observed, and reverted (confirmed clean via `git diff`) before the corresponding commit.

### Task 1 — `FrontPageCostEqualityTests` / `ToggleReversibilityTests`

| # | Mutation | Test | Observed result |
|---|----------|------|-------------------|
| 1 | Settings-pair assertion removed AND the enabled side built with `'0'` instead of `'1'` (the vacuous-pass scenario) | `test_front_page_boot_costs_the_same_measured_statements_and_connections_off_and_on`, `test_per_path_status_codes_agree_between_the_two_sides` | Both **PASSED** — settings pair `(False, False)`, statement totals `14 == 14`, connection totals `5 == 5`. The vacuous pass, demonstrated with real numbers rather than argued about. |
| 2 | Same mutation as #1, with the settings-pair assertion **restored** | `test_the_settings_pair_is_false_true_read_immediately_upon_each_build` and all sibling methods (setUp-level) | **FAILED at setup**: `AssertionError: Tuples differ: (False, False) != (False, True)`. Confirms the guard against the vacuous pass exists and works. |
| 3 | One extra `SELECT 1` DB read added to `index()`'s disabled branch (`dashboard/app.py`), simulating the toggle-delivery mechanism costing the front page something | `test_front_page_boot_costs_the_same_measured_statements_and_connections_off_and_on` | **FAILED**: `AssertionError: 15 != 14 : front-page boot set executed 15 SQLite statement(s) disabled vs 14 enabled` |
| 4 | One extra row (`INSERT INTO events...`) written during the disabled session in `ToggleReversibilityTests` | `test_a_disabled_session_leaves_the_database_unchanged_and_restart_recovers_the_golden` | **FAILED**: `AssertionError: '07619845...' != '0a5d3b2c...'` — the two observed `iterdump` digests. |
| 5 | One character of `tests/fixtures/07_advanced_current_enabled_response_golden.json`'s `body` corrupted (`host_freshness` → `host_freshnesa`) | `test_a_disabled_session_leaves_the_database_unchanged_and_restart_recovers_the_golden` (and, incidentally, `EnabledResponseGoldenTests::test_the_enabled_response_matches_the_pre_change_golden`) | Both **FAILED**: `reopened, toggle-on body moved from the golden captured at ceef6da` (a 15237-character diff). |

### Task 2 — `AcceptanceConfigurationGuardTests`

| # | Mutation | Test | Observed result |
|---|----------|------|-------------------|
| 6 | `docker-compose.yml`'s `ENABLE_ADVANCED_DIAGNOSTICS` default changed from `${BEACON_ADVANCED_DIAGNOSTICS:-1}` to `${BEACON_ADVANCED_DIAGNOSTICS:-0}` | `test_the_shipped_default_resolves_to_enabled_through_the_real_parser` | **FAILED**: `AssertionError: False is not true : PROH-DIA-09-01: docker-compose.yml's shipped default for ENABLE_ADVANCED_DIAGNOSTICS resolved to '0', which load_settings parses as disabled...` — the observed boolean and the full `PROH-DIA-09-01` message. |

**Instrument sensitivity, positive proof (not a mutation):** the baseline (unmutated) run of `FrontPageCostEqualityTests` recorded the two boot-set totals as **equal by genuine measurement** — 14 statements / 5 connections on both sides — with per-path statuses `{'/': 200, '/api/stats': 503, '/api/history': 200, '/api/scan-status': 200, '/api/services': 200, '/api/events?limit=50': 200}` identical on both sides (the `503` from `/api/stats` reflects the stubbed `psutil`/worker-freshness state in the test harness, observed identically on both sides — not a toggle effect).

## Issues Encountered
None beyond the singleton-reload deviation documented above, found and fixed before any task commit.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All three plans in Phase 7 are now complete (`07-01`, `07-02`, `07-03`); the plan-list checkboxes in `.planning/ROADMAP.md` reflect this (`- [x]` x3). The Progress table's `3/3`/`Complete` row update is left for the orchestrator, per this executor's spawn instructions.
- `DIA-09` remains **not** promoted in `.planning/REQUIREMENTS.md` (scope fence honored across all three plans) — promotion is an independent verification round's decision.
- `D-DEBT-07-01` is open work for the next OPS-07 round in Phase 6: `_load_worker` (`tests/pi_load_acceptance.py`) needs to record response status alongside latency, and an oracle needs to fail a route whose samples include an unexpected non-2xx status.
- Full-suite verification (`uv run --project dashboard python -m pytest -q`) at this plan's completion: **966 passed, 593 subtests passed, 0 failed** — exceeds the phase's stated floor (960 passed / 587 subtests) with zero failures, including no recurrence of the previously-recorded lock-audit line-shift (`WINDOWS.md` #21/#22), which an earlier orchestrator-level commit (`2631d73`, visible in this worktree's history) already realigned.

---
*Phase: 07-optional-advanced-diagnostics*
*Completed: 2026-09-04*

## Self-Check: PASSED

All 5 files (`tests/test_optional_advanced_diagnostics.py`, `.planning/ROADMAP.md`,
`.planning/phases/07-optional-advanced-diagnostics/07-DECISIONS.md`,
`.planning/phases/07-optional-advanced-diagnostics/07-DEBT.md`, this SUMMARY) confirmed present on
disk. All three commit hashes (`a3554ac`, `538754c`, `097290f`) confirmed present in
`git log --oneline --all`.
