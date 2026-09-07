---
phase: 04-historical-investigation
reviewed: 2026-08-26T08:44:38Z
depth: standard
files_reviewed: 10
files_reviewed_list:
  - dashboard/advanced.css
  - dashboard/advanced.html
  - dashboard/advanced.js
  - dashboard/app.py
  - dashboard/beacon/incidents.py
  - tests/test_advanced_ui.py
  - tests/test_api_and_auth.py
  - tests/test_historical_telemetry_api.py
  - tests/test_history_investigation_ui.py
  - tests/test_incidents_api.py
findings:
  critical: 0
  warning: 2
  info: 1
  total: 3
status: issues_found
---

# Phase 04: Code Review Report

**Reviewed:** 2026-08-26T08:44:38Z
**Depth:** standard
**Files Reviewed:** 10
**Status:** issues_found

## Summary

This is a re-review of the same file set as the prior `04-REVIEW.md`, after plans 04-09 and
04-10 closed the four findings that review raised (CR-01, CR-02, WR-01, WR-02). Both closures
were verified directly against the current code, not taken on faith:

- **CR-01/CR-02/WR-01 (closed by 04-09):** `dashboard/app.py`'s `api_events_history`
  (`app.py:2664-2702`) now reads episode-grouping material two ways: `read_episode_state_changes`
  (`incidents.py:297-315`) always reads every `state_change` row in range for the in-scope
  services, pinned to `event_type='state_change'` and `maintenance='include'` regardless of the
  operator's `event_type`/`maintenance` filter selection, and `anchor_candidate_ports`
  (`incidents.py:266-294`) computes which ports get an anchor lookup independently of what
  matched inside the window — always `[port]` for an explicit per-service filter, otherwise the
  union of in-range episode ports and `read_open_ports_as_of`'s durable-event-derived discovery
  query. `filter_episodes` (`incidents.py:485-526`) then narrows the already-grouped episodes by
  `maintenance`/`event_type` *after* grouping, checking `maintenance` against each episode's own
  `suppressed_reason` (which `group_episodes` assigns from the opening/anchor row), which is what
  closes WR-01 (an anchor's own suppression state is now authoritative for the `maintenance`
  filter, not bypassed). A dedicated `EpisodeScopeRegressionTests` class
  (`tests/test_incidents_api.py:486-755`) directly exercises the CR-01 (silently-down service,
  both unscoped and `port`-scoped), CR-02 (non-`state_change` `event_type` filter on a
  fully-recovered episode), and WR-01 (`maintenance=exclude`/`only` against a suppressed anchor)
  scenarios at the route level and asserts the previously-wrong outcomes no longer occur. Closure
  confirmed.
- **WR-02 (closed by 04-10):** `parseLocalRangeInput` (`advanced.js:1788-1810`) now performs a
  round-trip check after the convergence loop — `localWallClockMinutes(rounded) !== targetMinutes`
  returns the `NONEXISTENT_LOCAL_TIME` sentinel rather than silently accepting a mismatched
  instant — and `validateCustomRange` (`advanced.js:1829-1857`) surfaces a named rejection for it
  ahead of every other check. `tests/test_history_investigation_ui.py:4373-4620` (the
  `HistoryDstAnnotationLondonTests`/spring-forward classes) cover both the sentinel value and the
  end-to-end "no request issued" behavior for an absent local hour. Closure confirmed.
- **IN-01** (route-level filter-interaction test gap) is closed by the same `EpisodeScopeRegressionTests`
  addition.

No new Critical issues were found in this pass. Two new Warnings were found that the prior
review's structural focus did not cover: a silent, misleading "N of M incidents" count when the
unfiltered baseline fetch fails, and an ARIA role/interactivity mismatch on the single incident
marker that is inconsistent with every other interactive control this same file defines. One Info
item notes a related, narrower gap in test coverage.

## Warnings

### WR-01: "N of M incidents" silently substitutes the filtered count for the total when the unfiltered baseline fetch fails

**File:** `dashboard/advanced.js:1387-1416`

**Issue:** `renderIncidentsSection` fetches the operator's filtered incident list and an
unfiltered baseline for the same range in parallel via `Promise.allSettled`:

```js
const [filteredOutcome, totalOutcome] = await Promise.allSettled([
  fetchIncidents(bounds.start_ts, bounds.end_ts, filters),
  fetchIncidents(bounds.start_ts, bounds.end_ts, DEFAULT_HISTORY_FILTERS),
]);
...
const total = totalOutcome.status === 'fulfilled' && Array.isArray(totalOutcome.value.episodes)
  ? totalOutcome.value.episodes.length
  : episodes.length;
updateMatchingIncidentCount(episodes.length, total);
```

When the filtered request succeeds but the unfiltered baseline request fails (a transient
network error, a timeout, or a server 5xx that does not also affect the first, nearly-identical
request), `total` silently falls back to `episodes.length` — i.e. the exact filtered count. The
UI then renders `"N of N incidents"`, which reads as "every incident in this range matches your
filter" even when the operator has an active `criticality`/`event_type`/`service` filter and the
real total is unknown and possibly much larger. No error, partial-failure notice, or `?` is
surfaced anywhere for this case; `errorEl` is only populated when `filteredOutcome` itself fails
(`advanced.js:1399-1408`). This is the same class of problem the codebase's own design principle
(D-12/Pitfall 4, "never fabricate, never fill a gap with a guess that reads as a fact") is meant
to prevent, but applied here to a fetch failure rather than a query-shape gap. No test in
`tests/test_history_investigation_ui.py` exercises the "unfiltered baseline request fails" path
(only successful-both-requests assertions exist at `test_history_investigation_ui.py:2887,3056`).

**Fix:** Track baseline-fetch failure explicitly and render a state that does not claim parity,
e.g. `"N of ? incidents (total unavailable)"`, or retry the baseline fetch once before falling
back. Minimal fix:

```js
const totalKnown = totalOutcome.status === 'fulfilled' && Array.isArray(totalOutcome.value.episodes);
const total = totalKnown ? totalOutcome.value.episodes.length : null;
updateMatchingIncidentCount(episodes.length, total); // render "N of ? incidents" when total is null
```

### WR-02: Single incident marker uses `role="img"` while being fully keyboard/pointer interactive, inconsistent with every other actionable control in this file

**File:** `dashboard/advanced.js:1582-1601`

**Issue:** `renderMarkerSingle` builds the lone (non-clustered) incident marker on the shared time
axis:

```js
circle.setAttribute('tabindex', '0');
circle.setAttribute('role', 'img');
const text = markerTitle(episode);
circle.setAttribute('aria-label', text);
...
circle.addEventListener('click', () => focusIncident(episode));
circle.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); focusIncident(episode); }
});
```

`role="img"` tells assistive technology this element is a static graphic whose content is
described by its label — not an actionable control. Screen readers commonly do not expose an
`img`-role element as operable (no "button" role announcement, and some AT strips it from the
interactive-elements rotor entirely), so a screen-reader user tabbing through the time axis may
land on a focusable-but-silent-as-to-purpose circle that in fact opens `focusIncident` on
Enter/Space/click. Every other interactive element this same file adds in the same feature area
uses the correct role: `renderMarkerCluster` (`advanced.js:1544-1573`) uses `role="button"`, and
`incidentRow` (`advanced.js:1194-1312`) uses `role="button"` with an action-stating `aria-label`
("Investigate ... incident starting ..."). The single-marker circle is the one outlier, both in
role (`img` instead of `button`) and in label wording (a plain description instead of a
call-to-action), despite having identical click/keydown behavior to the cluster glyph next to it.

**Fix:** Use `role="button"` to match `renderMarkerCluster` and `incidentRow`, and word the label
consistently:

```js
circle.setAttribute('role', 'button');
circle.setAttribute('aria-label', `Investigate ${text}`);
```

## Info

### IN-01: No test exercises the incident-count baseline-fetch-failure path

**File:** `tests/test_history_investigation_ui.py`

**Issue:** As noted in WR-01 above, no test drives `renderIncidentsSection` with the filtered
request succeeding and the unfiltered-baseline request failing (or vice versa), so the misleading
`"N of N"` fallback had no regression coverage to catch it.

**Fix:** Add a Playwright-style test that stubs `/api/events/history` to succeed for the filtered
query string and fail (network error or 500) for the unfiltered one, then asserts
`#matching-incident-count` does not silently claim `N of N`.

---

_Reviewed: 2026-08-26T08:44:38Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
