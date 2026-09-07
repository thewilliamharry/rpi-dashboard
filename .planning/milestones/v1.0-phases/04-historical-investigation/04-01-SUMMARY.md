---
phase: 04-historical-investigation
plan: 01
subsystem: ui
tags: [vanilla-js, svg, flask, sqlite, history, telemetry]

# Dependency graph
requires:
  - phase: 02-bounded-telemetry-retention
    provides: "Bounded, mixed-tier /api/telemetry/history with the five-state coverage partition and point_budget discipline"
  - phase: 03-advanced-current-diagnosis
    provides: "The /advanced workspace shell, section navigation, validated browser-local preference pattern, and the api_config GET route"
provides:
  - "History nav entry and section wired through the unmodified selectSection() shell"
  - "Shared six-preset range control (1h/6h/24h/7d/30d/90d), persisted as a validated preference"
  - "Gap-breaking CPU history chart drawn from /api/telemetry/history, with a per-chart coverage strip (five-state + storage_pressure vocabulary)"
  - "Pi-local-time shared axis, resolved from a new timezone field on GET /api/config"
  - "Per-metric loading/empty/error render entry point (renderMetricHistory), extensible to ram/disk/temp without new state-machine logic"
  - "DIA-08 traceability reconciled across phases in REQUIREMENTS.md"
affects: [04-02, 04-03, 04-04, 04-05, 04-06, 04-07]

# Actuals (#2632)
actuals:
  tokens: 14449
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Gap-breaking SVG path builder (buildSeriesPath): emits M instead of L unless the interval between two points is fully covered by observed evidence"
    - "Coverage-strip pattern+label vocabulary keyed on (state, detail) together, rendered via static shared SVG <pattern> defs referenced by class"
    - "Per-metric render entry point (renderMetricHistory) parameterised by metric id, composed with Promise.allSettled so one metric's failure never blanks its siblings"
    - "Dedicated historyRequestGeneration staleness counter, separate from the current-diagnosis poll's requestGeneration"

key-files:
  created:
    - tests/test_history_investigation_ui.py
  modified:
    - dashboard/app.py
    - dashboard/advanced.html
    - dashboard/advanced.js
    - dashboard/advanced.css
    - tests/test_historical_telemetry_api.py
    - tests/test_advanced_ui.py
    - tests/test_api_and_auth.py
    - .planning/REQUIREMENTS.md

key-decisions:
  - "History uses its own state.historyRequestGeneration counter rather than sharing state.requestGeneration with the current-diagnosis poll, so an unrelated periodic overview refresh can never discard an in-flight History render"
  - "Boot sequence calls refreshCurrentDiagnosis() before fetchRuntimeConfig() so /api/advanced/current stays the page's first network call, preserving test_advanced_ui.py's reverse-order regression harness's index-0 assumption"
  - "Coverage-strip patterns are static shared SVG <pattern> defs in advanced.html, referenced by fill:url(#id) from dynamically created rects, rather than generating pattern defs at render time"

patterns-established:
  - "renderMetricHistory(metric, bounds, requestId): the per-metric fetch/loading/empty/error contract every future History metric (ram, disk, temp) will reuse verbatim"
  - "buildSeriesPath/coverageStripSegments: pure functions over (points, coverage) usable by the service latency chart in a later plan without modification"

requirements-completed: []

coverage:
  - id: D1
    description: "Operator can open History from the advanced nav and see a CPU history chart drawn from /api/telemetry/history for the default 24h range, with the line broken at every non-observed coverage interval and a labelled coverage strip beneath it"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_history_section_breaks_gaps_labels_coverage_and_renders_local_time_axis"
        status: pass
    human_judgment: false
  - id: D2
    description: "All six range presets (1h/6h/24h/7d/30d/90d) request their documented span and toggle aria-pressed on exactly one button"
    requirement: "DIA-04"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_all_six_presets_request_the_documented_span_and_toggle_aria_pressed"
        status: pass
    human_judgment: false
  - id: D3
    description: "A 7d-preset fixture whose points straddle the raw/5-minute tier seam renders one coordinate per point with no duplicate x-coordinate"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_7d_preset_renders_one_coordinate_per_point_with_no_duplicate_ts"
        status: pass
    human_judgment: false
  - id: D4
    description: "Hostile stored historyRange values (array, unknown preset, non-object JSON) never throw, always fall back to the 24h default, and never build a request from the untrusted stored value"
    requirement: "DIA-04"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_hostile_stored_history_range_falls_back_to_24h_default"
        status: pass
    human_judgment: false
  - id: D5
    description: "Loading, empty, and per-metric error states render the exact contracted copy, are parameterised by metric id, and isolate one metric's failure from its siblings"
    requirement: "HIS-01"
    verification:
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_empty_response_renders_empty_copy_and_still_renders_coverage_strip"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_error_response_renders_server_reason_and_keeps_shared_axis"
        status: pass
      - kind: e2e
        ref: "tests/test_history_investigation_ui.py#test_pending_request_shows_skeleton_and_draws_no_chart_path"
        status: pass
    human_judgment: false
  - id: D6
    description: "GET /api/config exposes the Pi's configured timezone, failing closed to UTC on an unresolvable IANA zone name"
    requirement: "HIS-01"
    verification:
      - kind: unit
        ref: "tests/test_historical_telemetry_api.py#test_api_config_reports_configured_timezone_and_fails_closed_to_utc"
        status: pass
    human_judgment: false
  - id: D7
    description: "DIA-08's three-document traceability conflict (R-04) is reconciled in REQUIREMENTS.md, naming which half shipped in Phase 3 and which ships in Phase 4"
    requirement: "DIA-08"
    verification: []
    human_judgment: true
    rationale: "Traceability-row wording correctness is a documentation judgment call for the phase verifier, not something an automated test can assert. The DIA-08 checkbox is deliberately left unchecked per the plan's own instruction."

duration: 55min
completed: 2026-08-26
status: complete
---

# Phase 4 Plan 1: History Section Tracer Summary

**Gap-honest CPU history chart wired end to end through a new History section: six-preset range control, per-chart coverage strip, Pi-local-time axis, and per-metric loading/empty/error states, all reading the existing bounded `/api/telemetry/history` contract.**

## Performance

- **Duration:** 55 min
- **Tasks:** 3
- **Files modified:** 8 (1 created)

## Accomplishments

- Operator can click `History` in the advanced nav and see a CPU chart for the default 24h range, its line broken at every interval Beacon did not observe as `observed`, with a coverage strip beneath it labelling each gap by reason and pattern
- All six range presets (1h/6h/24h/7d/30d/90d) select, persist as a validated `historyRange` preference under the existing `beacon-advanced-preferences-v1` key, survive reload, and report the server-selected resolution rather than computing it client-side
- Every timestamp on the History axis renders in the Pi's configured local time via a new `timezone` field on `GET /api/config`, which fails closed to `UTC` on an unresolvable zone name
- Loading, empty, and error states are parameterised by metric id (`renderMetricHistory`) and composed with `Promise.allSettled`, so the three metrics the next plan (04-03) adds inherit the state machine without new logic
- `DIA-08`'s three-document traceability conflict (R-04) is closed in `REQUIREMENTS.md`: the row now reads `Phase 3 + Phase 4 | Complete` with a clarifying line naming which half shipped where; the checkbox itself is left for the phase verifier

## Task Commits

1. **Task 1: End-to-end "operator sees honest CPU history for a chosen range"** - `8c092bc` (feat)
2. **Task 2: The full preset ladder, persisted and resolution-honest** - `96bd3ca` (test)
3. **Task 3: Loading, empty, and error states for the History surface** - `c2b2f3b` (feat)

_Note: Task 2 is recorded as `test` because its own code (persistence, resolution-note, aria-pressed toggling) was already implemented generically by Task 1; the task's actual delta was the three new Playwright tests plus the REQUIREMENTS.md reconciliation._

## Files Created/Modified

- `dashboard/app.py` - `"timezone": SETTINGS.timezone` added to the `GET /api/config` response dict
- `dashboard/advanced.html` - `History` nav entry and section, shared range-control markup (six presets, resolution note, error slot), CPU chart/coverage-strip/axis markup, shared SVG `<pattern>` defs for the five coverage-strip patterns
- `dashboard/advanced.js` - `HISTORY_PRESETS`, `validHistoryRange`, `resolveRangeBounds`, `fetchRuntimeConfig`, `formatLocalTimestamp`, `fetchHostMetricHistory`, `buildSeriesPath`, `coverageStripSegments`, `renderHistoryChart`, `renderCoverageStrip`, `renderSharedTimeAxis`, `renderMetricHistory`, `renderHistorySection`, `selectRangePreset`; `historyRange` added to the validated preference schema
- `dashboard/advanced.css` - `.hist-*` chart/strip/axis/range/skeleton styling, reusing only existing custom properties
- `tests/test_historical_telemetry_api.py` - `/api/config` timezone assertion, including the fail-closed-to-UTC path
- `tests/test_history_investigation_ui.py` (new, 496 lines) - Playwright coverage for the tracer, the six presets, the tier-seam dedup case, three hostile stored-preference shapes, and the loading/empty/error states
- `tests/test_advanced_ui.py` - four pre-existing Phase 3 assertions updated for this plan's authorized, additive changes (see Deviations)
- `tests/test_api_and_auth.py` - `/api/config` key-set assertion extended with `timezone`
- `.planning/REQUIREMENTS.md` - DIA-08 traceability row and clarifying line

## Decisions Made

- Used a dedicated `state.historyRequestGeneration` counter instead of literally sharing `state.requestGeneration` with the current-diagnosis poll (the plan's literal wording said "reuse the existing... idiom") — sharing it would let an unrelated 15-second overview refresh silently discard an in-flight, still-current History render. Same staleness-guard *pattern*, separate counter.
- Ordered the boot sequence so `refreshCurrentDiagnosis()` fires before `fetchRuntimeConfig()`, keeping `/api/advanced/current` the page's first network call — required to preserve `test_advanced_ui.py`'s pre-existing reverse-order regression harness, which assumes the first fetch is the diagnosis poll.
- Defined the five coverage-strip patterns as static, shared SVG `<pattern>` elements in `advanced.html` rather than generating pattern defs per render, referenced by class name (`.hist-pattern-dots`, etc.) via `fill:url(#id)`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Pre-existing Phase 3 tests updated for this plan's authorized, additive changes**
- **Found during:** Task 1 (phase-level `<verification>` regression run)
- **Issue:** Five Phase 3 tests hardcoded assumptions that predate Phase 4's explicitly authorized behavior: the exact five-entry nav list (now six with History), a forbidden-substring check that included the literal word `history` (D-18 explicitly authorizes parameterised GET history reads — only the *document route* stays parameterless), the SVG XML namespace string incidentally containing the substring `http://`, the exact validated-preference key set (now including `historyRange`), and a hardcoded total fetch count in a reverse-order regression harness (now 3 with the new boot-time `GET /api/config` call).
- **Fix:** Updated each assertion to the new, still-correct invariant rather than loosening the check's intent: nav list now includes `History`; `history` removed from the forbidden-word list (all other mutation/exfiltration signals still checked) and the SVG namespace literal is explicitly excluded from the `http://` check; preference key-set assertion includes `historyRange`; fetch-count assertion is `3`, with the boot order deliberately preserving which call is index 0.
- **Files modified:** tests/test_advanced_ui.py, tests/test_api_and_auth.py
- **Verification:** Full Phase 3 regression (`tests/test_advanced_ui.py tests/test_advanced_diagnosis_api.py`, 119 passed / 200 subtests) and the full suite (571 passed / 481 subtests) both green
- **Committed in:** 8c092bc (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — pre-existing test assertions updated for authorized additive changes)
**Impact on plan:** All updates were to test assertions documenting now-superseded Phase 3-era invariants; no test's actual security or correctness intent was weakened. No scope creep — no new files or features beyond the plan's own scope.

## Issues Encountered

- Playwright's sync API runs all page/route communication over one driver-thread event loop; a Python-side `time.sleep()` inside a `page.route()` handler (the initial approach for the pending-state test) deadlocks that loop rather than merely delaying the response. Resolved by reusing the codebase's own established pattern (`AdvancedUiTests.REVERSE_ORDER_HARNESS`): hold the JS-side `fetch()` Promise's resolution via an init script rather than blocking the network layer.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The per-metric render contract (`renderMetricHistory`, `HISTORY_METRICS`, `METRIC_LABELS`) is ready for 04-03 to extend with `ram`, `disk`, `temp` by adding markup and one array/map entry each — no new state-machine logic needed.
- `buildSeriesPath` and `coverageStripSegments` are metric-agnostic pure functions, ready for reuse by the service latency chart in a later plan.
- DIA-08's documentation conflict is closed; DIA-04 and HIS-01 remain correctly `Pending` in REQUIREMENTS.md (this plan is a thin tracer slice — the full preset/threshold/tooltip/four-metric surface is not yet complete) and are left for the phase verifier to promote once later plans in this phase land.
- No blockers for 04-02 through 04-07.

## Self-Check: PASSED

All created/modified files found on disk; all four commit hashes (8c092bc, 96bd3ca, c2b2f3b, 8a951c7) found in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*
