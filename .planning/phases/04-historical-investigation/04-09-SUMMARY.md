---
phase: 04-historical-investigation
plan: 09
subsystem: api
tags: [flask, sqlite, incidents, gap-closure]

requires:
  - phase: 04-02
    provides: HistoricalRange bounds validation and the range-and-filter events read discipline
  - phase: 04-07
    provides: the shipped Incidents Service filter (port) and its route consumer
  - phase: 04-08
    provides: the shipped Event type / maintenance filter UI and the marker rail that reads `episodes`
provides:
  - "read_open_episode_anchors tightened to skip anchors for services that already recovered before start_ts"
  - "build_open_anchor_query / build_open_ports_query statement builders"
  - "read_open_ports_as_of: events-derived open-port discovery, independent of the services table"
  - "anchor_candidate_ports: independent anchor-eligible port derivation, always honoring an explicit port filter"
  - "read_episode_state_changes: episode-scoped state_change read pinned to maintenance=include"
  - "filter_episodes + episode_scope response key: post-grouping narrowing with machine-readable disclosure"
  - "compose_incidents_response rebuilt from episode_rows + anchors instead of the filtered flat rows"
affects: [04-10, historical-investigation-ui]

actuals:
  tokens: 8085
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Episodes are grouped from a durable, independently-scoped read (read_episode_state_changes) and narrowed only after grouping (filter_episodes), never grouped from the already-filtered flat row set"
    - "Statement builders (build_open_anchor_query, build_open_ports_query) return (statement, params) so tests can inspect exact SQL text without a second hand-written copy, mirroring build_events_query"

key-files:
  created: []
  modified:
    - dashboard/beacon/incidents.py
    - dashboard/app.py
    - tests/test_incidents_api.py

key-decisions:
  - "Task 1 checkpoint: option-a selected — group from the durable state_change record, then narrow episodes after grouping (see Decision below)"
  - "Anchor candidate universe is derived from the durable events record, never the services table, because services rows expire at EXPIRE_DAYS (default 7) while events outlive that by design — a services-derived universe would make the phase's own worst case (a silently-down, long-unseen service) permanently invisible"
  - "criticality is applied to the anchor row inside read_open_episode_anchors, never inside anchor_candidate_ports, so an explicit port filter under a mismatching criticality still reaches the seek and is then correctly dropped — episodes and events can never disagree about which services are in criticality scope"

patterns-established:
  - "episode_scope response key: {grouped_from, narrowed_by} discloses what episodes were grouped from and which operator filters narrowed the already-grouped set"

requirements-completed: [HIS-04, HIS-05, DIA-06]

coverage:
  - id: D1
    description: "A silently-down service with zero in-range events appears as an open episode, including under an explicit port filter (CR-01 closed)"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_open_anchor_with_no_in_range_rows_still_appears_as_open_episode"
        status: pass
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_port_filter_surfaces_silently_down_service_with_no_in_range_rows"
        status: pass
    human_judgment: false
  - id: D2
    description: "A non-state_change event_type filter never fabricates an open episode for a recovered incident, and never silently drops a real one without disclosing the narrowing (CR-02 closed)"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_non_state_change_event_type_filter_never_reports_recovered_episode_as_open"
        status: pass
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_non_state_change_event_type_filter_keeps_matching_incident_and_discloses_the_narrowing"
        status: pass
    human_judgment: false
  - id: D3
    description: "maintenance=exclude never surfaces a suppressed anchor's evidence, and maintenance=only returns only such episodes (WR-01 closed)"
    requirement: "HIS-04"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_maintenance_exclude_drops_episode_whose_opening_event_is_suppressed"
        status: pass
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_maintenance_only_keeps_only_suppressed_opening_episodes"
        status: pass
    human_judgment: false
  - id: D4
    description: "A service that recovered entirely before the range start yields no episode; episode_scope discloses grouping source and applied narrowing; criticality reaches the explicit-port anchor path; the anchor seek is index-backed and open-port discovery cost tracks distinct down-ports, not row volume; no value is ever interpolated into SQL text"
    requirement: "DIA-06"
    verification:
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_service_recovered_before_range_start_contributes_no_episode"
        status: pass
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_episode_scope_discloses_grouping_source_and_applied_narrowing"
        status: pass
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_criticality_filter_applies_to_the_explicit_port_anchor_path"
        status: pass
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_anchor_seek_is_index_backed_and_open_port_discovery_is_bounded"
        status: pass
      - kind: unit
        ref: "tests/test_incidents_api.py#EpisodeScopeRegressionTests.test_no_anchor_or_open_port_value_is_interpolated_into_sql_text"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-26
status: complete
---

# Phase 04 Plan 09: Independent Incident Episode Scope Summary

**Rewrote `/api/events/history`'s episode grouping to read the durable `state_change` record independently of the `event_type`/`maintenance`/`port` filters, closing CR-01 (silently-down services vanishing), CR-02 (recovered incidents mislabelled "Ongoing" or silently dropped), and WR-01 (suppressed-anchor evidence leaking through `maintenance=exclude`), with a new `episode_scope` disclosure key.**

## Performance

- **Duration:** 55 min
- **Started:** 2026-08-26T00:00:00Z (approx, worktree base)
- **Completed:** 2026-08-26
- **Tasks:** 3 (1 checkpoint:decision, 1 tracer, 1 auto)
- **Files modified:** 3

## Decision

**Task 1 checkpoint result: `option-a`** — "Group from the durable state_change record, then narrow episodes after grouping."

This was resolved by the orchestrator/operator before this plan executed and is recorded here verbatim per the plan's acceptance criteria. Per Task 1's acceptance criteria, option-a means Task 2 and Task 3 proceed unchanged (no `REPLAN REQUIRED`).

## Accomplishments

- `read_open_episode_anchors` no longer filters `online = 0` in SQL — it fetches each port's true most-recent `state_change` before `start_ts` and evaluates `online`/`criticality` in Python, so a service that went down and recovered entirely before the range never fabricates an anchor (the tightening required alongside CR-01's widening, per the plan's surfaced assumption).
- `build_open_anchor_query` and `build_open_ports_query` extracted as `(statement, params)` builders (mirroring `build_events_query`), so both statements are testable without a second hand-written copy.
- `read_open_ports_as_of` derives the open-port candidate universe from the durable `events` record alone — never the `services` table, because `services` rows expire at `EXPIRE_DAYS` (default 7) and cascade-delete `service_meta`, while `events` outlive that by design. This is the direct CR-01 fix for the unscoped (no `port` filter) path.
- `anchor_candidate_ports` always includes an explicit `port` filter regardless of what the window returned — the direct CR-01 fix for the per-service investigation path — and, when unscoped, unions episode-row ports with the discovery query's result (neither subsumes the other).
- `read_episode_state_changes` pins `event_type='state_change'` and `maintenance='include'`, forwarding only `port`/`criticality`, so episode grouping is never narrowed by the operator's `event_type`/`maintenance` selection before grouping happens (D-12).
- `filter_episodes` applies `maintenance`/`event_type` narrowing to already-grouped episodes and returns the applied filter names; `compose_incidents_response` now builds episodes from `episode_rows` + anchors (never from the filtered flat `rows`), classifies flapping only after filtering, and publishes `episode_scope: {grouped_from, narrowed_by}`.
- `dashboard/app.py`'s `api_events_history` rewired inside the existing `_db_lock` block to call the new independent reads and pass `episode_rows=` to `compose_incidents_response`, with `truncated` set to the OR of both reads' truncation flags.
- Eleven named route-level regression tests added (`04-REVIEW.md` IN-01), plus the two Task 2 tracer tests, for a net +13 tests (37 → 50 counting the two Task 2 tests, final count 48 after accounting for the class total — see Task Commits for exact per-commit counts).

## Task Commits

Each task was committed atomically:

1. **Task 1: Decide the published `episodes` semantics** — resolved via pre-supplied operator decision (option-a); no commit (decision-only checkpoint, recorded above).
2. **Task 2: End-to-end honest incident scope** — `406e58a` (test: RED, confirmed failing against pre-change tree) then `bfd4029` (feat: GREEN — anchor/episode reads independent of the filtered row set)
3. **Task 3: Remaining route-level regression battery** — `3e0532c` (test: CR-02b, WR-01, recovered-before-range guard, disclosure, parameterisation, query plans)

**Plan metadata:** committed together with this SUMMARY.md (see final commit).

_TDD note: Task 2 followed RED→GREEN (test commit `406e58a`, confirmed failing, then feat commit `bfd4029`, confirmed passing). Task 3 is `type="auto" tdd="true"` and lands as a single test commit against the already-implemented Task 2 production code — every new assertion was confirmed to fail or pass against the intended defect/regression class as documented per-test in the commit message._

## Files Created/Modified

- `dashboard/beacon/incidents.py` — `EPISODE_GROUPING_SOURCE`, `build_open_anchor_query`, `build_open_ports_query`, tightened `read_open_episode_anchors` (+`criticality`), `read_open_ports_as_of`, `anchor_candidate_ports`, `read_episode_state_changes`, `_episode_is_suppressed`, `_episode_evidence_window`, `_row_matches_episode_evidence`, `filter_episodes`, rewritten `compose_incidents_response` (+required `episode_rows`, +`episode_scope`)
- `dashboard/app.py` — `api_events_history` rewired to call `read_episode_state_changes` and `anchor_candidate_ports` independently of the filtered `read_events_in_range` result, passing `episode_rows=` through to `compose_incidents_response`
- `tests/test_incidents_api.py` — new `EpisodeScopeRegressionTests` class with 13 tests (2 from Task 2, 11 from Task 3); no pre-existing test modified or deleted

## Decisions Made

- Option-a (durable-record grouping) selected at the Task 1 checkpoint — see `## Decision` above.
- The anchor candidate universe is derived from `events`, never `services`, per the plan's pre-resolved "option (a)" analysis (services rows expire at `EXPIRE_DAYS`=7 and cascade to `service_meta`, while events retain far longer) — this was specified in the plan itself, not a new deviation.
- `criticality` is applied inside `read_open_episode_anchors` on the anchor row, not inside `anchor_candidate_ports`, so an explicit `port` filter under a mismatching `criticality` still reaches the seek and is then correctly dropped — keeping `episodes` and `events` in permanent agreement on criticality scope.

## Deviations from Plan

None — plan executed exactly as written. The plan's own "Planner assumptions surfaced" section pre-authorized the `read_open_episode_anchors` tightening as in-scope (not separate scope), and that was implemented as specified.

## Issues Encountered

- First draft of `test_anchor_seek_is_index_backed_and_open_port_discovery_is_bounded` acquired `self.appmod._db_lock` and then called `self._insert_event(...)` from inside that lock — `_insert_event` acquires the same non-reentrant lock itself, producing a deadlock (test run hung past the 120s timeout). Fixed by moving every `_insert_event` call outside the lock acquisition, matching the fixture's actual (non-reentrant) locking contract. No production code was affected; this was purely a test-authoring bug caught by the hang and fixed before committing Task 3.
- Initial `test_no_anchor_or_open_port_value_is_interpolated_into_sql_text` asserted the bare string `'critical'`/`'standard'` was absent from the anchor statement, which false-failed because `COALESCE(m.critical, 0) AS critical` is a legitimate schema column alias, not an interpolated filter value. Narrowed the assertion to check for the quoted SQL string-literal form (`"'critical'"`/`"'standard'"`), which is what an actual interpolation defect would produce.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `episode_scope` is additive on the response; `dashboard/advanced.js`'s `renderIncidentsSection` (the sole consumer of `episodes`) does not yet render it — that UI wiring is 04-10's Task 1, as referenced by this plan's `key_links` (`dashboard/advanced.js` → `dashboard/app.py` via `fetchIncidents` consuming `episode_scope`).
- Full suite green and grown: 738 passed (>= 727 required by this plan's verification gate), including `tests/test_uptime_integration.py`, `tests/test_maintenance_windows.py`, `tests/test_api_and_auth.py`, and `tests/test_history_investigation_ui.py` run individually as this plan's `<verification>` block specifies.
- No blockers for 04-10.

---
*Phase: 04-historical-investigation*
*Completed: 2026-08-26*

## Self-Check: PASSED

- FOUND: dashboard/beacon/incidents.py
- FOUND: dashboard/app.py
- FOUND: tests/test_incidents_api.py
- FOUND commit: 406e58a
- FOUND commit: bfd4029
- FOUND commit: 3e0532c
