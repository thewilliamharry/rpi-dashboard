---
phase: 03-advanced-current-diagnosis
plan: 10
subsystem: advanced-current-diagnosis
tags: [error-handling, test-isolation, traceability, gap-closure]
status: complete

requires:
  - "dashboard/beacon/db.py::MaintenanceBusy (raised through connect_db's shared lease)"
  - "dashboard/advanced.js::apiFetch / renderRefreshError (03-09, renders the server-supplied error string)"
  - ".planning/phases/03-advanced-current-diagnosis/03-VERIFICATION.md (WR-05, WR-08, traceability correction)"
provides:
  - "dashboard/app.py::api_advanced_current — 503 JSON for a maintenance window and for an operational database failure"
  - "MaintenanceBusy imported in both the relative and the Gunicorn fallback import branches"
  - "tests/test_advanced_diagnosis_api.py::AdvancedDiagnosisApiTests._freeze_clock — addCleanup-unwound time.time patch"
  - "tests/test_advanced_diagnosis_api.py::ClockIsolationTests — the leak regression"
  - ".planning/REQUIREMENTS.md traceability matching the verified per-requirement result"
affects:
  - "Every later test module in the pytest process now sees the real wall clock"
  - "A future verifier can accept suite greenness as evidence instead of hand-reproducing"

tech-stack:
  added: []
  patterns:
    - "Named exception branches only; the underlying detail is logged, never returned"
    - "Import / package fallback pattern — a new import lands in both branches"
    - "Lazily-started, addCleanup-unwound patch with a mutable instant container, re-pointable within one test"
    - "Traceability status follows independent verification, never an implementation claim"

key-files:
  created: []
  modified:
    - dashboard/app.py
    - tests/test_advanced_diagnosis_api.py
    - .planning/REQUIREMENTS.md

key-decisions:
  - "Only MaintenanceBusy and sqlite3.OperationalError are caught; no bare except Exception, so an unmodelled failure stays a loud 500"
  - "The maintenance body names its cause ('database maintenance in progress'); the database-failure body is a fixed non-revealing string with the exception class logged server-side"
  - "_db_lock is deliberately NOT acquired on this route (threat T-03-62, accepted with a written rationale)"
  - "time.time is patched by its stdlib module path, one patcher per test, so the intent is explicit at the patch site"
  - "TEL-06 and DIA-08 stay at Gaps Found: only a re-verification of this gap-closure round may promote them"

requirements-completed: [DIA-01, DIA-02, DIA-03, UX-02]
requirements-declared: [TEL-06, DIA-01, DIA-02, DIA-03, DIA-08, UX-02]

coverage:
  - deliverable: "A maintenance window reaches the operator as a parseable 503 JSON body naming its cause"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_maintenance_window_reaches_the_operator_as_a_named_cause"
        status: pass
  - deliverable: "An operational SQLite failure returns a fixed 503 message leaking no exception text, path, or SQL fragment"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_database_unavailable_never_reveals_exception_detail"
        status: pass
  - deliverable: "No catch-all: an unmodelled failure class is not swallowed into a 503"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_unexpected_failure_stays_loud_instead_of_becoming_a_service_unavailable"
        status: pass
  - deliverable: "The route stays GET-only, parameterless and no-store"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_direct_route_tracer_preserves_middleware_assets_and_get_only_api"
        status: pass
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_advanced_snapshot_rejects_query_arguments_before_reading_sqlite"
        status: pass
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_host_tracer_returns_one_current_snapshot_with_server_freshness"
        status: pass
  - deliverable: "The frozen test clock never outlives the test that installed it"
    human_judgment: false
    verification:
      - kind: test
        ref: "tests/test_advanced_diagnosis_api.py#test_a_frozen_clock_never_outlives_the_test_that_froze_it"
        status: pass
  - deliverable: "Suite greenness is no longer order-dependent"
    human_judgment: false
    verification:
      - kind: command
        ref: "pytest -q (281 passed) vs pytest -q --deselect tests/test_advanced_diagnosis_api.py (251 passed); tests/test_telemetry_retention.py alone (17 passed) vs after the phase module (47 passed)"
        status: pass
  - deliverable: "REQUIREMENTS.md reports the verified per-requirement result"
    human_judgment: false
    verification:
      - kind: command
        ref: "grep gate: 4 Phase 3 rows Complete, 2 still Gaps Found — TRACEABILITY_OK"
        status: pass
  - deliverable: "A maintainer accepts the restored-clock evidence as sufficient for the suite to count as verification evidence"
    human_judgment: true
    rationale: "Carried forward from 03-VERIFICATION.md human_verification item 2. Task 2's both-orders command now produces the evidence; accepting it remains the maintainer's call. Collected at phase level (human_verify_mode: end-of-phase)."
  - deliverable: "On the target Pi, a real open gap and a stale host read as correctly labelled exceptions"
    human_judgment: true
    rationale: "Carried forward from 03-VERIFICATION.md human_verification item 1, shared with plans 03-08 and 03-09. Collected at phase level."

metrics:
  duration: "14 min"
  completed: 2026-08-18
  tasks: 3
  files_modified: 3

actuals:
  tokens: 4100
  tasks: 3
  commits: 5
---

# Phase 03 Plan 10: Legible Failure, Restored Clock, Honest Record Summary

`/api/advanced/current` now names a maintenance window instead of failing as an unparseable HTML 500, the phase test module leaves the process-global `time.time` exactly as it found it, and the traceability table reports what the verifier actually established rather than what the plans claimed.

## Accomplishments

- **WR-08 error-handling half closed** — `MaintenanceBusy` is imported in **both** import branches of `dashboard/app.py` (the relative block and the Gunicorn `from beacon...` fallback), and `api_advanced_current` wraps only the `get_current_diagnosis` call. A held maintenance lease now returns `{"error": "database maintenance in progress"}` with HTTP 503, which `apiFetch` can parse and plan 03-09's `renderRefreshError` surfaces verbatim — the operator sees the real cause instead of the generic connection-retry copy.
- **Nothing leaks through the error boundary** — `sqlite3.OperationalError` returns a fixed `diagnosis database is temporarily unavailable` string; the underlying detail is logged through the module's existing `log` as a class name only. The regression drives an exception whose message carries a table name, an absolute path, and a `SELECT` fragment and asserts none of them (nor `OperationalError`, nor `Traceback`) appears in the response body, and that the body has exactly one key.
- **The boundary is narrow on purpose** — there is no `except Exception`. A regression forces a `ValueError` and asserts the response is still a loud 500, so a real defect can never hide behind a service-unavailable status (threat T-03-64). `_db_lock` is deliberately not acquired; the rationale is recorded in the plan's `<deferred_with_rationale>` and as accepted threat T-03-62.
- **WR-05 closed** — `_freeze_clock(value)` installs exactly one `unittest.mock.patch('time.time', ...)` per test, started lazily on first use and registered with `addCleanup(patcher.stop)` so the real function is restored even when a test fails. The instant lives in a mutable `self._clock` container the patch reads, so the worker-freshness test can re-point it three times inside one test without stacking patchers, and the real `time.time` captured before the patch is the fallback when no instant was ever set.
- **The leak regression reproduces the defect, not a proxy** — `ClockIsolationTests` runs one real clock-freezing test method in-process through a `TestResult` and then asserts the wall clock is real. Before the fix it failed with `AssertionError: 1700000005 not greater than 1750000000`; that is exactly the WR-05 demonstration from the review, now permanently guarded.
- **Order-dependence is gone, and measured in both directions** — the full suite is 281 passed with the phase module running first (it sorts first alphabetically), and 251 passed with it deselected: 281 = 251 + 30, with no result changing. `tests/test_telemetry_retention.py` gives 17 passed alone and the same 17 when run immediately after the phase module.
- **The record now matches the evidence** — `DIA-01`, `DIA-02`, `DIA-03` and `UX-02` are promoted to `Complete` because `03-VERIFICATION.md` established each as SATISFIED through independent reproduction. `TEL-06` and `DIA-08` are **deliberately left at `Gaps Found`**: they are BLOCKED in the verification report, and although 03-08 and 03-09 are intended to close them, promoting them now would repeat exactly the mistake commit `c753593` had to revert. Only a re-verification of this gap-closure round may promote them.

## Task Commits

| Task | Gate | Commit | Message |
|------|------|--------|---------|
| 1 | RED | `25ba1e4` | test(03-10): add failing legible-failure regressions for the current-diagnosis route |
| 1 | GREEN | `58c268d` | feat(03-10): make the current-diagnosis route fail legibly instead of as HTML 500 |
| 2 | RED | `060bf14` | test(03-10): add failing regression for the leaked process-global clock |
| 2 | GREEN | `9b0e91a` | test(03-10): restore the process-global clock instead of leaking it (WR-05) |
| 3 | — | `a1122f2` | docs(03-10): correct requirements traceability to the verified state |

No REFACTOR commit was needed — both GREEN changes were minimal and in their final shape. Task 2's GREEN gate is a `test(...)` commit rather than `feat(...)` because the task is test-harness-only by contract ("No production file is modified by this task"); the commit-type table mandates `test` for test-only changes.

## Verification Results

| Command | Result |
|---------|--------|
| Task 1 (`-k "maintenance or route_tracer or unexpected_query or database_unavailable or unexpected_failure"`) | 4 passed, 14 subtests passed |
| Task 2 module run | 30 passed, 60 subtests passed |
| Task 2 both-orders (`--deselect` the phase module) | 251 passed, 309 subtests passed |
| Task 2 pointed order check (retention alone / after the phase module) | 17 passed / 47 passed — identical results |
| Task 3 traceability grep gate | `TRACEABILITY_OK` |
| Phase regression (`test_advanced_diagnosis_api.py test_advanced_ui.py test_module_boundaries.py`) | 67 passed, 125 subtests passed |
| Full project gate (`pytest -q`) | **281 passed, 369 subtests passed** (277 before this plan) |

RED gates were proven by real failures:

- Task 1 RED: 2 failures — `AttributeError: module 'dashboard.app' has no attribute 'MaintenanceBusy'`, and the raw `sqlite3.OperationalError` escaping the handler uncaught.
- Task 2 RED: `AssertionError: 1700000005 not greater than 1750000000 : the frozen test clock leaked past the test that installed it`.

One Task 1 test — `test_unexpected_failure_stays_loud_instead_of_becoming_a_service_unavailable` — passed on arrival. That is correct and intended: it is a **contract lock** on the absence of a catch-all, and before Task 1 there was no handler at all. Its value is guarding the boundary against a future widening to `except Exception`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The module had 18 clock-assignment sites, not the 13 the plan enumerated**

- **Found during:** Task 2
- **Issue:** The plan's `<interfaces>` and `<action>` list 13 sites at lines 39, 61, 111, 298, 335, 376, 400, 447, 522, 549, 585, 614, 641 — the file as it stood when the plan was written. Plan 03-08 then added five more clock-freezing tests. Converting only the enumerated 13 would have left five live `time.time` assignments and the leak would have persisted, failing the task's own regression.
- **Fix:** the conversion was applied to every assignment site by pattern rather than by line number: 17 `self.appmod.time.time = ...` sites plus the one bare `appmod.time.time = ...` site inside the worker-freshness test's own `try`/`finally`. `grep -c "time.time = "` over the module now returns 0.
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Commit:** `9b0e91a`

**2. [Rule 3 - Blocking] The unexpected-failure regression pins `PROPAGATE_EXCEPTIONS`**

- **Found during:** Task 1
- **Issue:** Flask's exception propagation defaults to `testing or debug`, so whether an unhandled `ValueError` surfaces as a 500 response or is re-raised out of the test client is ambient configuration rather than a property of the route.
- **Fix:** the test sets `app.config['PROPAGATE_EXCEPTIONS'] = False` explicitly, so it asserts the route's behaviour (a loud 500, not a 503) rather than the harness's default. `setUp` reloads the app module per test, so the setting cannot leak.
- **Files modified:** `tests/test_advanced_diagnosis_api.py`
- **Commit:** `25ba1e4`

### Adjustments within plan scope

- **`requirements.mark-complete` was deliberately not run.** The generic state-update step would pass all six frontmatter IDs — including `TEL-06` and `DIA-08` — and would also tick the body checklist items. Both outcomes are forbidden by this plan's own `<action>` and by its `must_haves` prohibition against recording status ahead of verification. The traceability table was edited with scoped replacements instead; the diff is 4 insertions and 4 deletions, entirely inside the `## Traceability` table.
- **The v1 checklist boxes for `DIA-01`/`DIA-02`/`DIA-03`/`UX-02` remain unchecked**, per the plan's explicit "leave the requirement checklist items in the body untouched". This understates rather than overstates completion, which is the safe direction, but it does diverge from the file's own convention where a `Complete` row has an `[x]` body item. The re-verification round that promotes `TEL-06` and `DIA-08` should reconcile all six body items in one pass.

## Deferred Issues

Nothing new. The pre-existing `latency_ms: null` → `0 ms` sort defect recorded by plan 03-09 in `.planning/phases/03-advanced-current-diagnosis/deferred-items.md` was **not** absorbed here — this plan does not touch `dashboard/advanced.js` and the item remains deferred as 03-09 left it.

The six findings this plan deliberately defers (`03-REVIEW.md` WR-07, IN-01 through IN-05, and the `_db_lock` half of WR-08) each carry a written rationale and a named future home in the plan's `<deferred_with_rationale>` block. None is silently dropped.

## Authentication Gates

None encountered.

## Issues Encountered

None beyond the deviations recorded above.

## Known Stubs

None. No placeholder, TODO, FIXME, hardcoded-empty value, or unwired data source was introduced. Both new response bodies are fixed module-owned strings; no request or exception text is interpolated into any response.

## Threat Flags

None. No new route, endpoint, query parameter, storage key, migration, column, table, index, or dependency was introduced. The plan's `mitigate` dispositions each have executable evidence:

| Threat | Mitigation evidence |
|--------|---------------------|
| T-03-61 (Information Disclosure — unhandled exceptions) | `test_database_unavailable_never_reveals_exception_detail` asserts seven distinct leak fragments are absent and the body has exactly one key |
| T-03-63 (Repudiation — order-dependent suite evidence) | `test_a_frozen_clock_never_outlives_the_test_that_froze_it` plus the both-orders suite runs (281 vs 251 + 30) |
| T-03-64 (Denial of Service — catch-all hiding a real defect) | `test_unexpected_failure_stays_loud_instead_of_becoming_a_service_unavailable`; the handler contains exactly two `except` clauses, both named |
| T-03-65 (Repudiation — status promoted ahead of verification) | `TEL-06` and `DIA-08` verifiably still read `Gaps Found`; the grep gate asserts both counts |
| T-03-62 (Denial of Service — `_db_lock` bypass) | Accepted, not mitigated, with a written rationale; the handler contains no `_db_lock` acquisition, as the acceptance criteria require |
| T-03-66 (Supply chain) | No install command ran; `unittest.mock` is stdlib and no dependency was added, removed, or upgraded |

## Follow-ups for Later Plans

- **`TEL-06` and `DIA-08` need a re-verification pass.** Plans 03-08, 03-09 and 03-10 implement everything the verifier named as blocking them, but nothing may promote them except a fresh `/gsd-verify-work` run over this gap-closure round. Until then the traceability table correctly reports them as open.
- The two carried-forward human verifications (real Pi rendering; maintainer acceptance of the restored-clock evidence) are collected at phase level per `workflow.human_verify_mode: end-of-phase`.
- `03-VERIFICATION.md`'s note refusing to accept the green suite as evidence is now stale — the leak it cites is fixed and measured in both orders.

## Next

Phase 3 gap closure is complete. Re-verify the phase.

## Self-Check: PASSED

- Modified files verified present on disk: `dashboard/app.py`, `tests/test_advanced_diagnosis_api.py`, `.planning/REQUIREMENTS.md`.
- All five task commits verified present in `git log`: `25ba1e4`, `58c268d`, `060bf14`, `9b0e91a`, `a1122f2`.
- Required artifact strings verified: `MaintenanceBusy` in `dashboard/app.py` (both import branches plus the except clause), `addCleanup` in `tests/test_advanced_diagnosis_api.py`, `TEL-06` in `.planning/REQUIREMENTS.md`.
- `grep -c "time.time = " tests/test_advanced_diagnosis_api.py` returns 0; the handler's `Cache-Control: no-store` and GET-only registration are unchanged.
- `dashboard/advanced.js`, `dashboard/beacon/diagnosis.py`, `dashboard/beacon/repositories.py` and every asset route confirmed unmodified by this plan.
- All task `<acceptance_criteria>` re-run and passing; full project gate green at 281 passed.
