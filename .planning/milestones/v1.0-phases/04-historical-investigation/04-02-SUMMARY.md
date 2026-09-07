---
phase: 04-historical-investigation
plan: 02
subsystem: api
tags: [flask, sqlite, incidents, grouping, events, historical-range]

# Dependency graph
requires:
  - phase: 03.1-planned-maintenance-recognition
    provides: "Durable events.suppressed_reason, maintenance_grace_until, down_since_ts columns and migration 9"
  - phase: 02-bounded-telemetry-retention
    provides: "HistoricalRange half-open bounds validator and its exact rejection message strings"
provides:
  - "GET /api/events/history: a validated, bounded, filtered range read returning both grouped down-to-recovered episodes and the flat filtered transition rows"
  - "dashboard/beacon/incidents.py: read_events_in_range, read_open_episode_anchors, group_episodes, split_overrun_span, classify_flapping, compose_incidents_response"
  - "Server-side incident grouping as a view over durable events rows, never a new durable record"
affects: [04-03, 04-04, 04-05, 04-06, 04-07]

# Actuals (#2632)
actuals:
  tokens: 10150
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Framework-free beacon module (dashboard/beacon/incidents.py) mirroring telemetry.py's shape: module-level constants, plain functions, no Flask import, no direct sqlite3.connect"
    - "build_events_query() split out from read_events_in_range so a test can EXPLAIN QUERY PLAN the exact statement without a second, possibly-diverging copy"
    - "Grouping is a view over durable rows: group_episodes/classify_flapping/compose_incidents_response create no durable record and merge no rows"

key-files:
  created:
    - dashboard/beacon/incidents.py
    - tests/test_incidents_api.py
  modified:
    - dashboard/app.py

key-decisions:
  - "The new incidents read takes HistoricalRange as its primary identity, exactly as /api/telemetry/history already does, rather than adding a second bounds contract alongside api_events's limit/since pair (the assumption-delta 'promote' decision from the plan)"
  - "api_events (limit/since) is left completely untouched; the new range-and-filter contract lives entirely in the new /api/events/history route"
  - "matched_count reports the number of rows actually returned (post-truncation), not an unknowable true total, since the LIMIT budget+1 trick only detects whether more rows exist, not how many"

patterns-established:
  - "compose_incidents_response(rows, anchors, ...) returns both episodes[] and events[] from one query result set -- the API shape resolution from 04-RESEARCH.md Open Question 1"
  - "read_open_episode_anchors: a per-port most-recent-down-before-start_ts read using idx_events_port_ts, letting an outage that began before the range group with its true down_ts instead of appearing as an uncaused recovery"

requirements-completed: []

coverage:
  - id: D1
    description: "A parameterised GET /api/events/history returns both grouped down-to-recovered episodes and the flat filtered transition rows for one validated range"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py::EventsHistoryRouteTests::test_response_shape"
        status: pass
    human_judgment: false
  - id: D2
    description: "Incident episodes are grouped server-side from durable event rows and no grouping is ever written back to the database"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py::GroupEpisodesTests"
        status: pass
    human_judgment: false
  - id: D3
    description: "An episode with no observed recovery row is returned open -- recovered_ts null and duration_seconds null -- never backfilled with the query end_ts or the current time"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py::GroupEpisodesTests::test_down_alone_returns_open_episode_with_no_synthesized_end"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::EventsHistoryRouteTests::test_open_episode"
        status: pass
    human_judgment: false
  - id: D4
    description: "An overrun episode carries both durable timestamps and splits its span into the grace-covered portion and the post-grace unplanned-fault portion"
    requirement: "DIA-05"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py::SplitOverrunSpanTests"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::EventsHistoryRouteTests::test_overrun_episode_splits_grace_and_fault"
        status: pass
    human_judgment: false
  - id: D5
    description: "Maintenance-suppressed rows are returned by default and carry their suppressed_reason so the client can tag them rather than infer them"
    requirement: "HIS-04"
    verification:
      - kind: e2e
        ref: "tests/test_incidents_api.py::EventsHistoryRouteTests::test_maintenance_suppressed_row_present_by_default_and_excludable"
        status: pass
    human_judgment: false
  - id: D6
    description: "Every filter value is validated against an explicit allowlist before any SQL is built, and every query uses bound parameters"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py::ReadEventsInRangeTests"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::EventsHistoryRouteTests::test_invalid_event_type_returns_400_naming_parameter"
        status: pass
    human_judgment: false
  - id: D7
    description: "The new route reuses HistoricalRange so inverted and over-90-day spans are rejected with the same message the telemetry history route returns"
    requirement: "DIA-05"
    verification:
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_inverted_span_error_matches_telemetry_route"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_over_90_day_span_error_matches_telemetry_route"
        status: pass
    human_judgment: false
  - id: D8
    description: "An event whose ts exactly equals the range start_ts is included and one whose ts exactly equals end_ts is excluded -- the range is half-open, matching HistoricalRange"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py::ReadEventsInRangeTests::test_half_open_bounds_include_start_exclude_end"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_route_half_open_boundary"
        status: pass
    human_judgment: false
  - id: D9
    description: "Episodes are ordered by episode start descending with event id descending as the tie-breaker so equal timestamps produce a stable repeatable order, and open episodes sort ahead of closed ones"
    requirement: "HIS-04"
    verification:
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_equal_down_ts_tiebreaks_descending_opening_id_and_is_stable"
        status: pass
    human_judgment: false
  - id: D10
    description: "The row budget is bounded and disclosed, truncation never fabricates an episode, and both range-only and range-plus-port statements are index-backed"
    requirement: "HIS-04"
    verification:
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_row_budget_truncation_disclosed"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_orphan_recovery_with_no_anchor_emits_no_episode"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_durable_prior_down_row_is_picked_up_as_anchor"
        status: pass
      - kind: e2e
        ref: "tests/test_incidents_api.py::BoundsParityRowBudgetAndQueryPlanTests::test_query_plans_use_index_not_full_table_scan"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-08-25
status: complete
---

# Phase 4 Plan 2: Incidents API Summary

**New parameterised `GET /api/events/history` route composing bounded, filtered, allowlisted event reads with server-side down-to-recovered episode grouping, overrun split at grace expiry, and flapping classification — a pure view over durable `events` rows.**

## Performance

- **Duration:** 25 min
- **Tasks:** 3
- **Files modified:** 3 (2 created)

## Accomplishments

- `dashboard/beacon/incidents.py` (new, framework-free): `EVENT_TYPES`, `CRITICALITY_VALUES`, `MAINTENANCE_MODES`, `INCIDENT_ROW_BUDGET`, `FLAPPING_EPISODE_THRESHOLD`, `FLAPPING_SPAN_SECONDS`, `EVENT_COLUMNS`, `build_events_query`, `read_events_in_range`, `read_open_episode_anchors`, `group_episodes`, `split_overrun_span`, `classify_flapping`, `compose_incidents_response`
- `GET /api/events/history` returns `{requested, filters, episodes, events, flapping_groups, row_budget, truncated, matched_count}` for one validated `start_ts`/`end_ts` range, filtered by `port`, `event_type`, `criticality`, and `maintenance` (default `include`)
- Open episodes stay open (`recovered_ts`/`duration_seconds` both `null`) — never backfilled with the query's `end_ts` or the current time
- An overrun episode's span splits at `maintenance_grace_until` into `grace_seconds` (at/before) and `fault_seconds` (after); `overrun` is true only when `fault_seconds > 0`
- Maintenance-suppressed rows are present in the default response and excludable with `maintenance=exclude`
- Every filter is checked against an explicit allowlist and reaches SQLite as a bound `?` parameter before any SQL is built — no f-string or concatenated SELECT anywhere in `dashboard/beacon/incidents.py`
- The route reuses `HistoricalRange` as the single bounds validator: the inverted-span and over-90-day error strings are byte-identical to `/api/telemetry/history`'s
- `INCIDENT_ROW_BUDGET` (2048) truncation is disclosed via `truncated`/`matched_count`, and truncation never fabricates an episode — an orphan recovery with no locatable opening row emits no episode while staying visible in `events`; a durable down row before `start_ts` is correctly picked up by `read_open_episode_anchors` as the episode's true `down_ts`
- Both the range-only and range-plus-port statements are proven index-backed (`idx_events_ts` / `idx_events_port_ts`) via `EXPLAIN QUERY PLAN` — no new composite index needed (Research Assumption A3 confirmed)
- `api_events` (the main dashboard's `limit`/`since` feed) is byte-identical to its pre-plan form — verified via `git diff --stat` showing pure additions

## Task Commits

1. **Task 1: beacon/incidents.py — range-filtered reads and honest episode grouping** - `6174311` (feat)
2. **Task 2: GET /api/events/history — validated, locked, bounded** - `3e083a3` (feat)
3. **Task 3: Bounds parity, row budget disclosure, and index-backed query plans** - `25c1d32` (test)

## Files Created/Modified

- `dashboard/beacon/incidents.py` (new) — the grouping/filtering module described above
- `dashboard/app.py` — `beacon_incidents` import alias added alongside the existing `beacon_telemetry`/`beacon_repositories`/`beacon_maintenance` aliases; `_incident_filters()` helper; `api_events_history()` route and its `/api/events/history` path. `api_events` untouched (verified byte-identical apart from surrounding line moves)
- `tests/test_incidents_api.py` (new, 37 tests) — pure-function coverage for `group_episodes`/`split_overrun_span`/`classify_flapping`, DB-backed coverage for `read_events_in_range`/validation, route-level coverage for closed/open/overrun episodes, maintenance suppression default+exclude, malformed-parameter 400s, bounds parity with `/api/telemetry/history`, row-budget truncation disclosure, anchor/no-anchor episode-fabrication safety, index-backed query plans, and stable descending-id tiebreak ordering across 10 identical requests

## Decisions Made

- Episode `transitions` entries are stored as plain `dict`s (converted from `sqlite3.Row` at grouping time) rather than raw `Row` objects, so `compose_incidents_response`'s payload is directly JSON-serializable by Flask's `jsonify` without a separate serialization pass.
- `build_events_query()` was split out of `read_events_in_range` specifically so the Task 3 `EXPLAIN QUERY PLAN` tests could inspect the exact statement text the production code executes, rather than maintaining a second, potentially-diverging hand-written copy of the SQL in the test file.
- `matched_count` reports the count of rows actually returned (post-truncation-cap), not an unknowable true total — the `LIMIT budget + 1` trick only detects *whether* more rows exist, not how many, so reporting an exact "total matches" figure beyond the budget would require a second COUNT query this plan deliberately avoids (mirroring the telemetry route's own point-budget discipline).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Episode `transitions` rows were not JSON-serializable**
- **Found during:** Task 2 (route-level test run)
- **Issue:** `group_episodes` stored raw `sqlite3.Row` objects in each episode's `transitions` list; Flask's `jsonify` raised `TypeError: Object of type Row is not JSON serializable` the first time a route test actually returned an episode with transitions.
- **Fix:** Convert each row to a plain `dict` at the point `group_episodes` appends it to `transitions`.
- **Files modified:** `dashboard/beacon/incidents.py`
- **Verification:** All 4 previously-failing route tests (`test_closed_episode`, `test_open_episode`, `test_overrun_episode_splits_grace_and_fault`, `test_maintenance_suppressed_row_present_by_default_and_excludable`) pass after the fix; full `tests/test_incidents_api.py` suite green (28/28 at that point, 37/37 after Task 3).
- **Committed in:** `3e083a3` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — a genuine serialization bug caught by the route's own tests before it reached a real client)
**Impact on plan:** No scope creep. The fix is entirely internal to `compose_incidents_response`'s data shape and does not change any documented behavior, field name, or ordering contract.

## Issues Encountered

None beyond the deviation above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `compose_incidents_response`'s `episodes[]`/`events[]`/`flapping_groups` shape is ready for 04-07's Incidents-section renderer to consume without modification.
- `read_events_in_range`'s allowlisted filter contract (`port`, `event_type`, `criticality`, `maintenance`) is the exact vocabulary 04-05/04-07's filter UI will wire controls to.
- `INCIDENT_ROW_BUDGET`/`truncated`/`matched_count` gives 04-07 the same truncation-disclosure pattern the History section already renders for telemetry (`aggregation_pending`/`gaps.truncated`), so the UI-contract idiom is consistent across both surfaces.
- No blockers for 04-03 through 04-07.

## Self-Check: PASSED

All created/modified files found on disk (`dashboard/beacon/incidents.py`, `dashboard/app.py`, `tests/test_incidents_api.py`); all three commit hashes (`6174311`, `3e083a3`, `25c1d32`) found in git log.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-25*
