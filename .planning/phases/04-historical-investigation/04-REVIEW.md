---
phase: 04-historical-investigation
reviewed: 2026-08-26T00:35:24Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - dashboard/app.py
  - dashboard/beacon/incidents.py
  - dashboard/advanced.js
  - dashboard/advanced.html
  - dashboard/advanced.css
  - tests/test_incidents_api.py
  - tests/test_history_investigation_ui.py
  - tests/test_historical_telemetry_api.py
  - tests/test_advanced_ui.py
  - tests/test_api_and_auth.py
findings:
  critical: 2
  warning: 2
  info: 1
  total: 5
status: issues_found
---

# Phase 04: Code Review Report

**Reviewed:** 2026-08-26T00:35:24Z
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

This phase adds `GET /api/events/history` (`dashboard/beacon/incidents.py`, wired in
`dashboard/app.py`) plus a large History/Incidents UI (`dashboard/advanced.js`,
`dashboard/advanced.html`, `dashboard/advanced.css`). The parameter validation, SQL
parameterization, timestamp/timezone handling (including the DST-tick detector and the
iterative local-wall-clock parser), the gap-breaking chart path builder, and the
divide-by-zero guards in the statistics code (trend slope, range aggregate, time-weighted
availability) are all careful and well-documented. No `innerHTML`/`insertAdjacentHTML` usage
exists anywhere in `advanced.js` — every dynamic string reaches the DOM through `textContent`
or attribute assignment, so there is no XSS surface from service names or event reasons.
Event-listener lifecycle is also clean: window-level drag/cursor listeners are added and
removed via named function references, and every re-rendered list uses `replaceChildren`
rather than `append`, so there is no listener-accumulation leak across polling cycles.

The one systemic problem is in `dashboard/beacon/incidents.py`'s episode-grouping/anchor
mechanism: it structurally requires every state-transition row that opens and closes an
episode to be present in the SQL-filtered row set, but the route derives which ports get an
"anchor" lookup — and which rows even reach grouping — from that same filtered set. Two
concrete, currently-untested request shapes cause the Incidents view to misreport an
operator-visible incident's actual status (see CR-01 and CR-02). Both are reachable directly
from the shipped UI (the port-scoped History service picker, and the Incidents "Event type"
filter dropdown), not just via direct API calls.

## Critical Issues

### CR-01: Ongoing outages disappear from `/api/events/history` whenever the query window (or a `port` filter) excludes every non-anchor row for that port

**File:** `dashboard/app.py:2664-2679`, `dashboard/beacon/incidents.py:154-176, 312-338`

**Issue:**
`api_events_history` computes the set of ports eligible for an "open episode" anchor lookup
purely from the rows returned by the *filtered, range-bounded* query:

```python
rows, truncated = beacon_incidents.read_events_in_range(conn, ..., port=filters.get('port'), ...)
ports = sorted({row['port'] for row in rows})
anchors = beacon_incidents.read_open_episode_anchors(conn, start_ts=requested.start_ts, ports=ports)
```

`compose_incidents_response` then only ever consults an anchor for a port that already has at
least one row in `rows_by_port` (`incidents.py:332-338`). A service that went down before
`start_ts` and has *not yet recovered*, and that produced **no other event** inside the
requested window (no `alert_sent`, no `preview_capture`, nothing — which is the normal case
for a long-silent outage, since `state_change` rows are only written on a state flip), has
zero rows in the filtered result set. `ports` is therefore empty for that service, no anchor
is fetched, and the still-open episode is completely absent from `episodes` — even though the
module's own docstring states this is exactly the scenario `read_open_episode_anchors` exists
to handle ("lets an outage that *began* before the selected range group correctly instead of
appearing as a recovery with no cause").

The same gap is reachable through the explicit `port` filter: the History service picker and
the Incidents "Service" filter both call `/api/events/history?port=<N>&...`
(`dashboard/advanced.js:550`, `incidentQueryParams` at `advanced.js:1056-1069`). If an operator
picks a specific service to investigate a currently-ongoing, event-quiet outage over a narrow
range, `read_events_in_range` returns zero rows for that port, `ports` is empty, and the
Incidents list renders "No incidents match this range and these filters" for the exact service
the operator is trying to investigate — directly contradicting the product's core value
proposition ("what is failing" — PROJECT.md).

Every existing test that exercises `read_open_episode_anchors` (`test_durable_prior_down_row_is_picked_up_as_anchor`,
`test_orphan_recovery_with_no_anchor_emits_no_episode` in `tests/test_incidents_api.py:404-430`)
seeds a recovery row *inside* the window, which is exactly the one case that already works.
No test covers "anchor exists, port has zero other rows in-range."

**Fix:** Compute the anchor candidate port set independently of what happened to match inside
the window — e.g. always look up the anchor for the filter's explicit `port` when one is
supplied, and otherwise query for every port with a currently-open `state_change` (`online = 0`
with no later `online = 1`) as of `start_ts`, not just the ports that happen to appear in
`rows`. A minimal fix without a broader query: when `filters.get('port')` is set, always pass
`[filters['port']]` to `read_open_episode_anchors` regardless of whether `rows` is empty.

---

### CR-02: The `event_type` (and `maintenance`) filter can fabricate a false "Ongoing" badge for an already-recovered incident, or silently erase a real one

**File:** `dashboard/beacon/incidents.py:210-256, 312-338`, `dashboard/advanced.js:1063-1067, 125-136 (HTML)`

**Issue:** `group_episodes` only participates rows whose `event_type == 'state_change'`
(`incidents.py:224-225`) — by design, per its own docstring. But `read_events_in_range`'s
`event_type` filter is applied at the SQL level *before* grouping, and the shipped Incidents UI
lets an operator pick any single event type, including non-`state_change` values
(`dashboard/advanced.html:127-135`: `Alert sent`, `Alert failed`, `Preview capture`, `Preview
complete`, `Maintenance overrun`, plus the two `maintenance:` options that map to the
`maintenance=exclude`/`only` parameter, which filters on `suppressed_reason` at the row level).

Concretely: an operator filters Incidents to `Event type: Alert sent`. The server-side query
now returns only `alert_sent` rows for the range. For a port whose outage already recovered
entirely inside the range (down `state_change` + up `state_change`, both excluded by the
filter) but that also has a prior open-episode anchor from before `start_ts`:
- `rows_by_port` for that port contains only the `alert_sent` rows, which `group_episodes`
  skips entirely (line 224-225).
- The anchor (always fetched with no `event_type`/`maintenance` predicate —
  `incidents.py:164-169`) is still prepended and is the *only* `state_change` row seen by
  `group_episodes`, so it opens an episode that is **never closed**, because the real closing
  `online=1` row was excluded by the filter.
- The route reports this already-resolved incident as `open: True` with the `▶ Ongoing — not
  yet recovered` badge (`advanced.js:1214-1219`) — a fabricated status the codebase's own
  design mandate (D-12/Pitfall 4, repeated throughout `04-UI-SPEC.md` and the `incidents.py`
  module docstring) explicitly forbids ("never backfilled with the query's `end_ts` or the
  current time"; here it is backfilled with a false "still open" state instead).

The inverse also happens: a port whose incident is entirely inside the range with no
pre-existing anchor simply vanishes from `episodes` under this filter (no anchor, no
`state_change` rows survive the filter), even though `events` (the flat list) still shows the
underlying activity — so "N of M incidents" silently undercounts real incidents whenever a
non-`state_change` event type or a `maintenance` mode is selected.

No test in `tests/test_incidents_api.py` drives the route with an `event_type` or `maintenance`
query-string filter and inspects the resulting `episodes`/`flapping_groups`/matching-count
output; the only `event_type`-related test (`test_non_state_change_rows_never_participate_in_grouping`,
line 65-72) calls the pure `group_episodes` function directly on a hand-built list that already
contains both the `state_change` rows and the extra event — it never goes through
`read_events_in_range`'s SQL filter, so it cannot catch this.

**Fix:** Either (a) restrict the `event_type` filter (and `maintenance`'s effect on grouping)
to the flat `events` list only, and always group `episodes` from an unfiltered-by-event-type,
unfiltered-by-maintenance `state_change` read (then filter/annotate episodes after grouping),
or (b) when `event_type` is supplied and is not `state_change`, only ever return the `events`
list (return `episodes: []` explicitly, or reject episode-shaped filters server-side) rather
than grouping a partial row set that cannot represent a real state machine. Add a route-level
test that applies `event_type=alert_sent` to a port with a fully-recovered in-range episode and
asserts it is **not** reported as `open`.

## Warnings

### WR-01: `read_open_episode_anchors` bypasses the `maintenance` filter, so a suppressed anchor can still surface under `maintenance=exclude`

**File:** `dashboard/beacon/incidents.py:154-176`

**Issue:** `read_open_episode_anchors`'s query has no `suppressed_reason` predicate — it always
returns the most recent prior down row regardless of the caller's `maintenance` filter. If that
anchor's `suppressed_reason` is set (the down event began during a maintenance window) and the
recovery event inside the window is not suppressed, requesting `maintenance=exclude` (the
"hide expected maintenance" filter) still produces an episode carrying the anchor's
`suppressed_reason` and the `Expected` chip (`advanced.js:1205-1210`), i.e. the exact evidence
the operator asked to exclude. This is the same class of problem as CR-02 (filter predicate
applied inconsistently between the anchor read and the range read) but scoped to a single
field (`suppressed_reason`) rather than dropping the whole episode.

**Fix:** Either apply the same `maintenance` predicate to the anchor query, or explicitly
document/test that an anchor's suppression state is authoritative regardless of the
`maintenance` filter (and confirm that's the intended semantics — currently untested either
way).

### WR-02: `parseLocalRangeInput`'s convergence loop does not handle a nonexistent local time (spring-forward gap)

**File:** `dashboard/advanced.js:1726-1745`

**Issue:** `parseLocalRangeInput` iteratively nudges a candidate UTC instant until
`localWallClockMinutes(candidate)` reports the wall-clock minutes the operator typed. This
converges correctly for an unambiguous time and (per the file's own comments) for the
"fall back" ambiguous hour, but for a wall-clock time that never occurs at all (the
"spring forward" gap, e.g. entering `02:30` on the day a zone jumps from 02:00 to 03:00), there
is no candidate `ts` for which `localWallClockMinutes(candidate) === targetMinutes`, so
`deltaMinutes` never reaches `0`. The loop still exits after exactly 3 iterations and returns
whatever `candidate` it last computed — silently accepting a value that does not actually
render back to the text the operator entered, with no error surfaced to `validateCustomRange`
(which only checks ordering/span/future-ness, not round-trip fidelity). Since this phase
explicitly reasons about DST elsewhere (the `dstAnnotations` detector, `advanced.js:2564-2600`),
this input path is the one place that edge case isn't handled.

**Fix:** After the loop, verify `localWallClockMinutes(candidate) === targetMinutes`; if not
(nonexistent local time), return `null` (or a sentinel `validateCustomRange` can turn into "that
local time does not exist because of a clock change — pick another") rather than silently
accepting an inaccurate instant.

## Info

### IN-01: `criticality`/`event_type`/`maintenance` interaction is untested at the route level

**File:** `tests/test_incidents_api.py`

**Issue:** All 37 tests either exercise the pure grouping functions with hand-built row lists,
or exercise the route with range/port/malformed-parameter combinations. None combine a
non-default `event_type` or `maintenance` filter with a route-level request that has both an
anchor and an in-range recovery (the scenario CR-02 and WR-01 depend on), so this class of bug
had no regression coverage before this review.

**Fix:** Add the route-level tests suggested in CR-01/CR-02/WR-01's fix sections; they would
have caught all three findings above.

---

_Reviewed: 2026-08-26T00:35:24Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
