# Phase 4: Historical Investigation - Research

**Researched:** 2026-08-25
**Domain:** Server-side bounded-history composition + hand-rolled vanilla-JS SVG multi-chart investigation UI, on Flask/SQLite/Raspberry Pi
**Confidence:** HIGH (existing-code claims — all read this session) / MEDIUM (external charting-performance guidance)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Historical investigation lives in **two new top-level sections — `History` and `Incidents`** — added to the existing advanced section navigation. Phase 3's `Overview`, `Host`, `Services`, `Pipeline`, and `Settings` sections remain strictly current-state and are not made range-aware. Current-versus-historical is an explicit mode switch, not a blended view. — **Reversibility:** costly.
- **D-02:** The shared preset ladder is **1h, 6h, 24h, 7d, 30d, 90d**. These map onto the retention tiers deliberately: 1h/6h/24h sit inside the 7-day raw tier, 7d is the raw boundary, 30d is the 5-minute tier boundary, and 90d is the hourly tier boundary — so every preset change is a visible, explainable resolution change. — **Reversibility:** reversible (presentation-level list, persisted per D-04).
- **D-03:** Custom ranges are entered through **explicit local-time start/end fields as the canonical entry, plus drag-to-select across any host or service chart** which sets the same range and updates the fields to show what was selected. The fields remain the authoritative, statable representation of the current range. — **Reversibility:** costly (couples chart renderer to range state; Phase 5 keyboard-equivalent obligation, R-03).
- **D-04:** The operator's chosen range and history-view filters **persist as validated presentation preferences** alongside Phase 3's existing keys. This is the DIA-08 remainder — the only part of DIA-08 Phase 4 picks up (see R-04). — **Reversibility:** reversible (additive to the existing validated-preference schema).
- **D-05:** All historical timestamps — chart axes, tooltips, incident rows, custom-range entry — display in **the Pi's configured local time**, resolved from the existing `timezone` Settings field (`dashboard/beacon/config.py:60`, default `UTC`, plumbed with tzdata in Phase 03.1). This matches 03.1 D-02, which locked maintenance windows to local wall-clock. DST transitions produce one ambiguous and one absent hour on the axis; that is honest and must be labelled, not smoothed. — **Reversibility:** costly.
- **D-06:** Missing intervals **break the line** — the series stops and restarts, never bridging a gap. Beneath each chart, on the same time axis, a **per-chart coverage strip** is segmented by reason (`collection_gap`, `unknown`, `expired`, `not_yet_monitored`, `storage_pressure`), each segment distinguished by pattern **and** text label rather than colour alone. A single shared strip beneath the stacked group was explicitly rejected because Phase 2 made host coverage metric-specific. — **Reversibility:** costly.
- **D-07:** All four host metrics (CPU, memory, disk, temperature) are **stacked and simultaneously visible on one shared time axis**, so correlation is visible without interaction. See R-01 for the Pi rendering-cost risk. — **Reversibility:** costly.
- **D-08:** "Simple trend" (HIS-06) means a **least-squares slope over observed points only**, expressed per-hour on short ranges and per-day on long ones (e.g. `disk +0.4%/day ↑`). Comparison against a preceding equal-length window was rejected structurally (90d preset has no prior-90d retained window). — **Reversibility:** reversible.
- **D-09:** "Latest" in the HIS-06 comparison means **the latest observation within the selected range**, so latest/minimum/maximum/average all describe the same window. Where a range ends in the past, the reading must not be presentable as a current value. — **Reversibility:** reversible.
- **D-10:** Contextual threshold lines (HIS-01) are **documented fixed defaults, drawn only where a defensible hardware or filesystem fact exists** — temperature throttle points and disk capacity. **CPU and memory get no threshold line.** Each drawn threshold discloses its source on inspection. Beacon has **no configurable host-metric thresholds** anywhere (`dashboard/beacon/config.py:28-76` — alerting is entirely service-availability based). — **Reversibility:** reversible.
- **D-11:** One service's history is laid out as a **horizontal state band** (online / offline / unknown / maintenance) across the range, with the **latency chart directly beneath it on the same time axis**, and failure classes summarised as counts beside it. State shading *inside* the latency plot was rejected (collides with coverage strip's background meaning). — **Reversibility:** costly.
- **D-12:** One row in the Incidents list is **one grouped down→recovered episode** — start, duration, end, failure class — with the underlying transitions available on expand. 03.1 D-08 already stores the true `down_since_ts`. **Grouping is a view over durable rows and must never become a new durable record.** — **Reversibility:** costly.
- **D-13:** Maintenance-suppressed entries are **shown by default in the advanced Incidents list, visibly tagged as expected maintenance**, with the event-type filter able to exclude them. This diverges deliberately from 03.1 D-10 (hidden by default on the *main dashboard*). — **Reversibility:** reversible.
- **D-14:** An overrun outage row spans the **true down-since timestamp through recovery, with the portion after grace expiry marked as the unplanned fault**. Both timestamps 03.1 D-08 stored are used. — **Reversibility:** reversible.
- **D-15:** Selecting an incident **pushes** a focused window (incident span plus padding) onto a navigation stack; a visible Back control returns to the range it came from. Drag-to-select (D-03) pushes onto the same stack — one shared memory model. — **Reversibility:** costly.
- **D-16:** The **range governs `History` and `Incidents` only**; Phase 3's five sections stay current-state. A **selected service carries across all sections** — read-only, changes no Phase 3 payload or contract. — **Reversibility:** costly.
- **D-17:** Correlation (DIA-07) is presented as the **shared time axis plus neutral incident markers**, **and** a **hover time cursor** tracking across all stacked charts at once. Neither asserts a relationship. No wording anywhere may claim causation. — **Reversibility:** reversible (cursor incurs Phase 5 keyboard debt, R-03).
- **D-18:** Investigation state (range, selected service, filters) lives in **browser storage only**, under `beacon-advanced-preferences-v1`. **Nothing is encoded in the `/advanced` URL.** This constrains the **`/advanced` document route only** — it does **not** bar parameterised reads. `/api/telemetry/history` (`dashboard/app.py:2507`) already accepts `start_ts`, `end_ts`, and a selector with existing validation; Phase 4's history and incident reads are expected to be parameterised GET APIs.

### Claude's Discretion

- **API shape** — one composite bounded history read vs. composing per-view calls over `/api/telemetry/history` plus a new range-and-filter events API. Phase 3's *current*-snapshot lock (fixed parameterless one-read GET) does not extend to Phase 4's parameterised historical reads.
- **Rendering strategy for D-07 under the Pi budget** — SVG vs. canvas, point decimation above the fetched resolution, render scheduling, reuse/replacement of the sparkline pattern at `dashboard/app.js:139`. Bounding R-01 is a research obligation, not a licence to change D-07.
- **Grouping edge semantics for D-12** — explicit representation of a still-unresolved (open) incident and of a flapping service, without inventing a durable record.
- **Coverage strip mechanics** — segment minimum widths, sub-pixel gap representation at 90d, pattern vocabulary for the five reasons.
- **Slope computation details for D-08** — minimum observed-point count below which slope is withheld, and how a sparse range discloses low confidence.
- **Padding applied to a pushed incident window (D-15)**, and the stack's visual home relative to the browser's own back button.
- **Time-weighted availability presentation for the range (HIS-02)** — precision, prominence, maintenance attribution in expanded detail, subject to 03.1 D-09.
- **Default incident filter state**, filter combination semantics across service/criticality/event-type/time, matching-count and clear-all treatment (following Phase 3 D-15's pattern).
- **Module boundaries, markup, styling, and test surface**, within the existing calm-light / dense-dark direction and `_db_lock` posture (AR-03-01).

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DIA-04 | Operator can select shared preset ranges from one hour through 90 days | D-02 preset ladder mapped to retention tiers (`select_resolution`/`RESOLUTION_LADDER_SECONDS`, `dashboard/beacon/telemetry.py:11`); preference persistence pattern in `dashboard/advanced.js:1-45` |
| DIA-05 | Operator can select a validated custom range within retained history | `HistoricalRange` validation (`dashboard/beacon/telemetry.py:29-42`) already rejects inverted/overlong (>90d) ranges server-side; D-03 field+drag entry |
| DIA-06 | Selecting a service, incident, or time range updates related host, service, and event views as one investigation context | D-15 navigation stack, D-16 read-only carried service selection |
| DIA-07 | Correlated views present observed evidence without asserting an unsupported root cause | D-17 shared axis + markers + hover cursor; Phase 3 precedent of do-not-infer-cause copy (03-CONTEXT.md D-10/D-11) |
| HIS-01 | Inspect CPU, memory, disk, temperature history with units, thresholds, tooltips, gaps | `/api/telemetry/history` host composition (`dashboard/app.py:2507-2580`); D-06 gap/coverage rendering; D-10 threshold provenance |
| HIS-02 | Time-weighted service availability over the selected range | `compose_historical_response`/service bucket shape (`dashboard/beacon/telemetry.py:175-217`); 03.1 D-09 maintenance attribution |
| HIS-03 | Service state timeline, latency history, failure classes, unknown intervals | D-11 state band + latency chart; events table + `error_class` vocabulary (`dashboard/app.py:649-663`) |
| HIS-04 | Filter incidents/transitions by service, criticality, event type, time range | New range-and-filter events API composed over `events(ts)`/`events(port,ts)` indexes (`dashboard/beacon/migrations.py:145-146`); existing criticality vocabulary (`dashboard/advanced.html:54`) |
| HIS-05 | Selecting an incident focuses the relevant service and time window | D-15 push-to-stack |
| HIS-06 | Compare latest value with selected-range minimum, maximum, average, and simple trend | D-08 slope, D-09 latest-within-range; aggregate shape already returns min/max/avg/latest per Phase 2 D-04 |
</phase_requirements>

## Summary

Phase 4 is almost entirely a **composition and presentation** problem, not a new-capability problem: Phase 2 already built the bounded, mixed-tier, five-state-coverage telemetry substrate (`dashboard/beacon/telemetry.py`, `dashboard/beacon/repositories.py`) and Phase 3 already built the workspace shell, preference pattern, and copy-map conventions (`dashboard/advanced.js`, `dashboard/advanced.html`, `dashboard/advanced.css`). The `/api/telemetry/history` endpoint (`dashboard/app.py:2507`) already returns exactly the shape D-06/D-08/D-09 need — bounded points, `coverage` intervals, `aggregation_pending` disclosure, and a `point_budget` of 2048 — for one host metric or one service at a time. What Phase 4 must add is: (1) two new nav sections and their range/filter UI shell (D-01), (2) a new range-and-filter **events/incidents** read (the `api_events` route only takes `limit`/`since` today), (3) client-side composition of four parallel host-metric fetches plus one service fetch into the stacked D-07/D-11 layout, and (4) the investigation-context state machine (range, carried service selection, navigation stack) that ties History and Incidents together per D-15/D-16, entirely in validated `localStorage` (D-18) — never the URL.

The single largest technical risk is R-01 (Pi rendering cost): four simultaneously-visible SVG line charts, each already point-budget-bounded to ≤2048 points server-side, plus a coverage strip, threshold lines, incident markers, a drag handler, and a cross-chart hover cursor. This is squarely within SVG's comfortable interactivity/accessibility zone per chart (a few thousand marks), but stacking four of them plus a state band and latency chart for one service pushes total on-screen marks into a range where naive re-render-on-every-pointermove will visibly stutter on a Pi-class CPU. The mitigation is architectural, not exotic: reuse the server's already-bounded point arrays directly (no client-side LTTB needed at ≤2048 points/series — decimate only if a future point budget increase makes it necessary), throttle the hover cursor to `requestAnimationFrame`, and update only cursor/tooltip DOM nodes on pointer movement rather than re-rendering the whole chart.

A second, independently important finding: **no existing API currently exposes the Pi's configured `timezone` string to the browser.** `SETTINGS.timezone` is used server-side (`dashboard/app.py:936,954,2318,2643,2652`) to format strings and compute maintenance coverage, but is never returned as a raw value the client can pass to `Intl.DateTimeFormat`. The two existing client-side "format a timestamp" call sites (`dashboard/advanced.js:87`, `dashboard/app.js:34`) both call bare `toLocaleString()`, which renders in the **browser's** local timezone, not the Pi's configured one — this is the wrong pattern for D-05 and must not be copied. The existing parameterless `/api/config` GET (`dashboard/app.py:2440-2447`) is the natural, minimal, additive place to expose `timezone` (an IANA name string) so every D-05 display site can construct `Intl.DateTimeFormat(undefined, {timeZone: cfg.timezone, ...})` consistently.

**Primary recommendation:** Compose Phase 4's UI over the existing `/api/telemetry/history` (called once per host metric and once for the selected service's latency) plus one new parameterised `GET /api/events/history` route (range + service + criticality + event_type filters, grouped incident view computed server-side per D-12), add `timezone` to `/api/config`, and render all charts as hand-rolled inline SVG following the `dashboard/app.js:139` sparkline precedent — no charting library, since the project has no frontend build step (`.planning/codebase/STACK.md`).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Range/preset selection, validation feedback | Browser / Client | API / Backend (`HistoricalRange` re-validates) | UI state is browser-local (D-18); server is the trust boundary for the actual query bounds |
| Host metric history (CPU/RAM/disk/temp) fetch + compose | API / Backend | Browser / Client (renders) | `/api/telemetry/history` already owns resolution selection, coverage, aggregation-pending disclosure — UI must not recompute (Phase 3 established pattern) |
| Service availability/state timeline/latency/failure-class history | API / Backend | Browser / Client (renders) | Same substrate, `kind=service` selector |
| Coverage strip rendering (five-state + storage_pressure sub-reason) | Browser / Client | API / Backend (supplies `coverage[]`) | Server supplies exhaustive partition; client only maps state+detail to pattern/label |
| Incident grouping (down→recovered episodes) | API / Backend | — | D-12: "grouping is a view over durable rows," must not become a new durable record — but classification logic belongs server-side per the diagnosis.py precedent ("server classifies, UI renders") |
| Incident/transition filtering (service, criticality, event_type, time) | API / Backend | Browser / Client (local sub-filter/search) | Time/service/criticality/event_type are query-shaped and should be pushed to SQL via the existing `events(ts)`/`events(port,ts)` indexes; matches Phase 3 D-15 filter+matching-count pattern |
| Navigation/focus stack (drag-to-select, incident focus, Back) | Browser / Client | — | D-15/D-18: pure browser-local state, never server-visible |
| Carried selected-service value across Phase 3 + Phase 4 sections | Browser / Client | — | D-16: read-only, must not cause any Phase 3 section to recompute against a historical bound |
| Threshold-line provenance (temp throttle, disk capacity) | API / Backend (documented constants) | Browser / Client (renders line + disclosure) | D-10: no config-derived thresholds exist yet; values are fixed, documented constants the server can also validate against actual hardware facts if ever added |
| Timezone resolution for display | API / Backend (source of truth) | Browser / Client (`Intl.DateTimeFormat`) | `SETTINGS.timezone` is server config; browser has no way to know it without a new read (gap identified this session — see Summary) |
| Simple trend (slope) computation | API / Backend or Browser / Client (discretion) | — | D-08 slope is a pure function over already-fetched points; either tier can compute it without a new query — recommend Browser/Client to avoid widening the response contract, since the raw points are already present client-side |

## Standard Stack

### Core

No new runtime libraries are introduced by this phase. `[VERIFIED: dashboard/pyproject.toml, .planning/codebase/STACK.md]`

| Component | Version | Purpose | Why Standard (for this project) |
|-----------|---------|---------|----------------------------------|
| Flask | 3.1.3 | New parameterised GET route(s) for events/incidents history | Existing framework; `.planning/codebase/STACK.md` `[VERIFIED: .planning/codebase/STACK.md]` |
| SQLite (stdlib `sqlite3`) | bundled w/ Python 3.11–3.12 | Range-filtered events query | Existing persistence; `events(ts)` and `events(port, ts)` indexes already exist `[VERIFIED: dashboard/beacon/migrations.py:145-146]` |
| Vanilla browser JS, no framework, no bundler | n/a | All chart, axis, tooltip, coverage-strip, drag, hover-cursor rendering | Project has **no frontend build step**; existing precedent is hand-rolled inline SVG `[VERIFIED: dashboard/app.js:139, .planning/codebase/STACK.md]` |
| `zoneinfo` (Python stdlib) | bundled | Server-side local-time formatting, already used for maintenance windows | `[VERIFIED: dashboard/beacon/config.py:8, dashboard/beacon/maintenance.py]` |
| `Intl.DateTimeFormat` (browser built-in) | n/a | Client-side local-time rendering against the Pi's configured IANA timezone, once exposed via `/api/config` | No library needed; browsers implement IANA-timezone-aware formatting natively `[ASSUMED — standard Web API behavior, not verified against a specific browser this session]` |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| none | — | — | This phase adds zero new dependencies to `dashboard/pyproject.toml` or any frontend package manifest (there is none) |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled inline SVG charts | A JS charting library (Chart.js, D3, ApexCharts, uPlot) | Rejected: project has no build step and no package manager for the frontend (`.planning/codebase/STACK.md`); introducing one is a project-wide architectural change far outside this phase's boundary, and the existing sparkline precedent (`dashboard/app.js:139`) already establishes hand-rolled SVG as the house style |
| Composing 4-5 parallel GETs per view | One new composite "bundle" endpoint returning host+service+coverage+events in one response | Rejected as the default: widens the response contract, complicates caching/error-partial-failure semantics (`aggregation_pending` per-stream disclosure would need merging), and is harder to unit-test per capability. Composing over existing `/api/telemetry/history` (already correct and tested) plus one new focused events endpoint keeps blast radius small and matches D-01's explicit two-section split |
| Server-computed trend slope | Client-computed trend slope over the already-fetched points array | Recommend client-side: avoids a new response field/version bump on `/api/telemetry/history` for a pure function over data already present; documented as Claude's Discretion in CONTEXT.md |

**Installation:** None required — no new packages.

**Version verification:** Not applicable; no new packages, so `npm view`/`pip index versions` checks do not apply to this phase.

## Package Legitimacy Audit

**Required only when installing external packages.** This phase installs zero external packages (Python or JavaScript) — it is entirely composition over the existing Flask/SQLite backend and hand-rolled vanilla-JS frontend, matching the no-build-step constraint verified in `.planning/codebase/STACK.md`.

**Packages removed due to [SLOP] verdict:** none — none proposed.
**Packages flagged as suspicious [SUS]:** none — none proposed.

## Architecture Patterns

### System Architecture Diagram

```
┌─────────────────────────────── Browser (advanced.html / advanced.js) ───────────────────────────────┐
│                                                                                                        │
│  Range control (presets 1h..90d + custom fields + drag-to-select) ──┐                                 │
│                                                                       │  writes                        │
│                                                                       ▼                                │
│                              investigation-context state (range, selected service,                    │
│                              filters, navigation stack) — validated, localStorage only (D-18)          │
│                                       │                       │                                        │
│              on range/service/filter change                  │ carried read-only (D-16)                │
│                                       ▼                       ▼                                        │
│        ┌──────────────────────────────────────┐   ┌────────────────────────────────────┐              │
│        │   History section (D-01)              │   │  Phase 3 sections (Overview/Host/   │              │
│        │   4x parallel host-metric fetch        │   │  Services/Pipeline/Settings) —      │              │
│        │   + 1x service latency/state fetch     │   │  unaffected by range; only reads    │              │
│        └──────────────────┬─────────────────────┘   │  the carried service selection      │              │
│                            │                          └────────────────────────────────────┘              │
│                            │ GET (parameterised, per D-18 scope note)                                    │
└────────────────────────────┼──────────────────────────────────────────────────────────────────────────┘
                             ▼
        GET /api/telemetry/history?kind=host&metric=cpu|ram|disk|temp&start_ts&end_ts   (existing, unchanged)
        GET /api/telemetry/history?kind=service&port=<selected>&start_ts&end_ts          (existing, unchanged)
                             │
                             ▼
        beacon_repositories.get_host_telemetry / get_service_telemetry / get_telemetry_coverage /
        get_pending_aggregation  →  beacon_telemetry.compose_historical_response / partition_coverage
                             │
                             ▼
                        SQLite (raw / 5-min rollup / hourly rollup tiers, per Phase 2)


┌─────────────────────────────── Browser (Incidents section, D-01) ────────────────────────────────────┐
│  Filter form: service, criticality, event_type, time range (HIS-04) ──► matching-count + list          │
│  Row = one grouped down→recovered episode (D-12); click ► push {span+padding} onto nav stack (D-15)     │
└────────────────────────────────────┬────────────────────────────────────────────────────────────────┘
                                      ▼
                    GET /api/events/history?start_ts&end_ts&port=&criticality=&event_type=   (NEW route)
                                      │
                                      ▼
              new beacon module (e.g. beacon/incidents.py): SELECT over events(ts)/events(port,ts),
              JOIN service_meta for criticality, group state_change pairs into episodes,
              attach suppressed_reason/maintenance_grace_until/down_since_ts (already columns, 03.1)
                                      │
                                      ▼
                                   SQLite events table
```

### Recommended Project Structure

```
dashboard/
├── app.py                     # + new GET /api/events/history route; + timezone in /api/config
├── advanced.html              # + <button data-section="history"> / "incidents"> nav entries + 2 <section>s
├── advanced.js                # + range/filter state, chart composition, drag/hover, nav stack
├── advanced.css               # + chart, coverage-strip, state-band, incident-list styles
└── beacon/
    ├── telemetry.py           # unchanged — reused as-is for host/service history + coverage
    ├── repositories.py        # unchanged — reused as-is
    ├── incidents.py           # NEW — range/filter query + down→recovered grouping (server classifies)
    └── config.py               # unchanged (timezone already present at line 60)
```

### Pattern 1: Compose, don't extend, the bounded-history read

**What:** Call the existing `/api/telemetry/history` once per host metric (4 calls) and once for the selected service, in parallel, rather than modifying its selector contract to accept multiple metrics per request.
**When to use:** Building the History section's stacked charts (D-07) and the service state/latency pairing (D-11).
**Example:**
```javascript
// Source: pattern derived from dashboard/app.py:2507 api_telemetry_history contract
async function fetchHostMetric(metric, startTs, endTs) {
  const url = `/api/telemetry/history?kind=host&metric=${metric}&start_ts=${startTs}&end_ts=${endTs}`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error((await resp.json().catch(() => ({}))).error || 'history request failed');
  return resp.json(); // { requested, selector, effective_resolution_seconds, points, coverage, aggregation_pending }
}

async function fetchHostHistory(startTs, endTs) {
  const metrics = ['cpu', 'ram', 'disk', 'temp'];
  const results = await Promise.allSettled(metrics.map((m) => fetchHostMetric(m, startTs, endTs)));
  // Partial failure must be visible per metric — do not fail the whole view if one metric's fetch fails.
  return Object.fromEntries(metrics.map((m, i) => [m, results[i]]));
}
```

### Pattern 2: Coverage state + detail, not a sixth "storage_pressure" state

**What:** The wire `coverage[]` array's `state` field is one of exactly five values; `storage_pressure` is a `detail` string attached to a `state: "collection_gap"` entry, not a sixth state.
**When to use:** Rendering the D-06 per-chart coverage strip — the pattern/label vocabulary must branch on `(state, detail)` together, not `state` alone.
**Example:**
```python
# Source: dashboard/beacon/telemetry.py:14-19 (verbatim state set) and :483-492 (storage_pressure write site)
_COVERAGE_STATES = {
    'collection_gap',
    'expired',
    'not_yet_monitored',
    'observed',
    'unknown',
}
# ...
record_coverage_interval(
    conn, stream_kind, stream_key, int(start), int(now),
    'collection_gap', 'storage_pressure',   # reason='collection_gap', detail='storage_pressure'
)
```
```javascript
// Client-side strip segment classification — branches on state+detail, matching the server's partition
function stripSegmentFor(interval) {
  if (interval.state === 'collection_gap' && interval.detail === 'storage_pressure') {
    return { pattern: 'diagonal-hatch', label: 'Storage pressure (no persistence)' };
  }
  if (interval.state === 'collection_gap') return { pattern: 'dots', label: 'Collection gap' };
  if (interval.state === 'unknown') return { pattern: 'dashed', label: 'Unknown' };
  if (interval.state === 'expired') return { pattern: 'diagonal-thin', label: 'Expired (outside retention)' };
  if (interval.state === 'not_yet_monitored') return { pattern: 'solid-muted', label: 'Not yet monitored' };
  return null; // 'observed' — no strip segment, chart line is drawn
}
```

### Pattern 3: Break the line at gap boundaries (D-06)

**What:** Never draw an SVG `<path>` `L` command across two points that straddle a non-`observed` coverage interval; emit a new `M` (moveto) instead.
**When to use:** All four host charts and the service latency chart.
**Example:**
```javascript
// Extends the existing sparkline precedent (dashboard/app.js:139) with gap-awareness it currently lacks
function buildPath(points, coverageIntervals) {
  const isObserved = (ts) => coverageIntervals.some((c) => c.start_ts <= ts && ts < c.end_ts && !('detail' in c) && c.state === 'observed');
  let d = '';
  let penDown = false;
  for (const p of points) {
    const cmd = penDown && isObserved(p.bucket_start) ? 'L' : 'M';
    d += `${cmd}${xFor(p.bucket_start)},${yFor(p.value)} `;
    penDown = true;
  }
  return d.trim();
}
```

### Pattern 4: Server-side classification for incident grouping (D-12)

**What:** Group `event_type='state_change'` rows into down→recovered episodes inside a new `beacon/incidents.py` module — mirroring the existing `beacon/diagnosis.py` split where the server classifies and the UI only renders.
**When to use:** Building the `/api/events/history` response for the Incidents section.
**Example:**
```python
# Source: pattern derived from dashboard/beacon/repositories.py:833-845 (state_change query shape)
# and dashboard/app.py:2686 api_events (existing column set: suppressed_reason,
# maintenance_grace_until, down_since_ts)
def group_episodes(rows):
    """rows: state_change events ordered by ts ASC for one port.
    Returns closed episodes (down_ts, recovered_ts, ...) plus at most one open
    episode (down_ts set, recovered_ts=None) if the service is still down —
    an explicit, named representation per D-12's Claude's Discretion note,
    never a synthesized 'end' timestamp.
    """
    episodes = []
    open_episode = None
    for row in rows:
        if row['online'] == 0:
            open_episode = {'down_ts': row['down_since_ts'] or row['ts'], 'recovered_ts': None, 'events': [row]}
        elif open_episode is not None:
            open_episode['recovered_ts'] = row['ts']
            open_episode['events'].append(row)
            episodes.append(open_episode)
            open_episode = None
    if open_episode is not None:
        episodes.append(open_episode)  # still open — HIS-04/D-12 must render this distinctly
    return episodes
```

### Anti-Patterns to Avoid

- **Bare `toLocaleString()` for historical timestamps:** `dashboard/advanced.js:87` and `dashboard/app.js:34` both call `new Date(ts * 1000).toLocaleString()`, which renders in the **browser's** timezone. This is the wrong pattern for D-05 (must render in the Pi's *configured* timezone) — do not copy this call site into Phase 4 code; use `Intl.DateTimeFormat(undefined, {timeZone: cfg.timezone, ...})` once `timezone` is exposed via `/api/config`.
- **Encoding range/filter state in the `/advanced` URL:** D-18 explicitly forbids this — the 46-threat verification in `03-SECURITY.md` covers a parameterless document route; any query string on `/advanced` itself reopens that gate.
- **A single shared coverage strip under all four stacked host charts:** D-06 explicitly rejects this because coverage is metric-specific (Phase 2); a merged strip would misreport or collapse to worst-case.
- **State shading inside the latency plot:** D-11 explicitly rejects this — it collides with the coverage strip's background meaning.
- **Treating `storage_pressure` as a sixth coverage state:** it is a `detail` value under `state: "collection_gap"` — see Pattern 2.
- **Re-rendering full SVG paths on every `pointermove` for the hover cursor:** update only the cursor/tooltip DOM nodes; recomposing all four chart paths per frame is the primary R-01 performance hazard.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| Timezone-aware date/time display in the browser | Manual UTC-offset arithmetic or a hand-rolled DST table | `Intl.DateTimeFormat(locale, { timeZone })` (built into every evergreen browser) | DST ambiguous/absent-hour edge cases (D-05) are exactly the class of bug manual offset math gets wrong; the Web platform already implements the IANA tz database client-side with no dependency needed |
| Server-side local time formatting | A second timezone library | `zoneinfo` (Python stdlib, already imported at `dashboard/beacon/config.py:8` and used in `dashboard/beacon/maintenance.py`) | Already the established, tested pattern in this codebase — no new dependency, no divergent behavior from 03.1's maintenance-window evaluation |
| Least-squares trend slope | A statistics library | Plain closed-form least-squares over the `(x, y)` pairs already in the fetched `points` array (a ~10-line function) | D-08 requires this over "observed points only" within an already-fetched, already-bounded (≤2048 points) array — a library adds a dependency for a one-screen algorithm, and this project has no frontend package manager to add one to anyway |
| Point-array downsampling for chart rendering | A generic decimation library (e.g., a bundled LTTB implementation) | Nothing yet — the server's `point_budget` (2048, `dashboard/beacon/config.py:50`) already bounds the array size before it reaches the browser; only add a client-side LTTB pass if profiling on real Pi hardware shows 2048-point SVG paths are the bottleneck, and if so, implement the well-documented O(n) algorithm directly (~30 lines) rather than adding a package, consistent with the no-build-step constraint |
| Incident grouping / episode reconstruction | A generic event-correlation or CEP (complex event processing) framework | The direct SQL + Python grouping in `beacon/incidents.py` (Pattern 4) | The full state machine is two states (down/up) driven by rows this codebase already writes and already stores `down_since_ts` for (03.1 D-08) — a general framework would be solving a much bigger problem than this one has |

**Key insight:** Almost nothing in this phase is a "don't hand-roll a hard problem" situation — the hard problems (bounded mixed-tier queries, five-state coverage, maintenance suppression/overrun) were already solved in Phase 2/3/03.1. Phase 4's genuine net-new logic is small, single-purpose, and best kept as plain functions co-located with the data they already have in hand, matching the existing `beacon/*.py` module-per-concern convention.

## Common Pitfalls

### Pitfall 1: Timezone not actually available to the client
**What goes wrong:** D-05 requires every historical timestamp to render in the Pi's configured local time, but no current API returns `SETTINGS.timezone` to the browser as a raw value.
**Why it happens:** `SETTINGS.timezone` is only ever consumed server-side (`dashboard/app.py:936,954,2318,2643,2652`) to *produce* formatted strings or compute coverage/attribution — never echoed back as a plain IANA name.
**How to avoid:** Add `"timezone": SETTINGS.timezone` to the existing parameterless `GET /api/config` response (`dashboard/app.py:2440-2447`) as a small, additive, low-risk change, and have every Phase 4 timestamp-formatting call site read it once at page load.
**Warning signs:** Any Phase 4 code that calls bare `toLocaleString()` or hardcodes `'UTC'`/browser-local formatting instead of reading a fetched `timezone` value.

### Pitfall 2: Confusing "observed" with "no gap" in the coverage partition
**What goes wrong:** Treating any coverage interval that isn't literally reason `collection_gap` as "fine to draw a line through."
**Why it happens:** The five-state partition includes `expired`, `not_yet_monitored`, and `unknown` as equally valid "don't draw a line here" states — only `observed` means "draw the line."
**How to avoid:** Gate line-drawing exclusively on `state === 'observed'` (Pattern 3), never on `state !== 'collection_gap'`.
**Warning signs:** A chart that shows a continuous line through a range that predates the service's `started_ts` (should be `not_yet_monitored`) or past the retention cutoff (should be `expired`).

### Pitfall 3: R-01 — stacking four live SVG charts plus a drag handler plus a synced hover cursor
**What goes wrong:** Naive re-render of all four chart `<path>` elements (up to 2048 points each) on every `pointermove` event during drag-select or hover-cursor tracking causes visible jank on Raspberry Pi-class CPUs.
**Why it happens:** `pointermove` fires far more often than a frame budget allows (potentially hundreds of times/second); recomputing four SVG path strings and reflowing the DOM on each event is O(pointer events × points).
**How to avoid:** (1) Throttle all pointer-driven visual updates through `requestAnimationFrame`, coalescing multiple `pointermove` events into one update per frame. (2) On hover, update only a shared crosshair line's `x` attribute and tooltip text content — never regenerate the chart `<path>` `d` attributes on hover. (3) On drag, only regenerate a lightweight selection-rectangle overlay, not the chart paths. (4) The chart paths themselves are regenerated only when the fetched range actually changes (on request completion), not during interaction.
**Warning signs:** Visible stutter/lag when dragging to select a range on real Pi hardware; CPU usage in the browser process spiking during hover, not just during data fetch.

### Pitfall 4: Incident grouping accidentally invents state
**What goes wrong:** A "smart" grouping algorithm that infers an implicit recovery for a still-down service (e.g., treating "no more events" as "recovered at query end") produces a false timestamp.
**Why it happens:** D-12 requires an explicit, honest representation of an unresolved (open) incident, but it's tempting to close every group for a tidy UI.
**How to avoid:** An episode with no matching `online=1` `state_change` row stays `recovered_ts: None` / open, rendered with its own explicit "still down" treatment (Pattern 4) — never backfilled with the query's `end_ts` or the current time.
**Warning signs:** An incident row whose duration exactly equals `end_ts - down_since_ts` for every currently-down service, regardless of when the range was queried — a tell that "recovered" was synthesized rather than observed.

### Pitfall 5: Cross-surface incident/availability contradiction (the exact defect D-14 exists to prevent)
**What goes wrong:** An overrun incident row shows only the post-grace unplanned-fault duration while the availability figure (per 03.1 D-09) counts the full down period including the planned/grace portion — producing two different "how long was this down" numbers for the same event.
**Why it happens:** It's tempting to show the incident row using only the `raised_ts`→`recovered_ts` span (the "fault" period) since that's what triggered the alert.
**How to avoid:** Render the full `down_since_ts`→`recovered_ts` span as the incident's span, with the post-`maintenance_grace_until` portion visually distinguished as the unplanned-fault sub-segment (D-14) — both durable timestamps are already on the event row (03.1 D-08, `dashboard/beacon/migrations.py:566-568`).
**Warning signs:** Any UI text or duration computation for an incident row that uses only one of `down_since_ts`/`maintenance_grace_until`/`raised (ts)` without the other.

### Pitfall 6: DST transitions silently smoothed by naive axis generation
**What goes wrong:** A chart axis generated by fixed-interval tick math (e.g., "one tick per hour") either duplicates or skips a tick across a DST transition, and the operator has no indication anything unusual happened.
**Why it happens:** `Intl.DateTimeFormat` will correctly format any given epoch timestamp in local time, but generating the axis *tick positions themselves* from naive epoch-interval arithmetic doesn't know about the day's ambiguous/absent hour.
**How to avoid:** D-05 requires the ambiguous/absent hour to be **labelled, not smoothed** — when generating axis ticks, detect where two adjacent local-time labels are identical (ambiguous hour, DST fall-back) or where a expected local hour is skipped (absent hour, DST spring-forward) and mark that segment explicitly rather than silently rendering a normal-looking axis.
**Warning signs:** An axis with two ticks reading the same local time, or a visually "compressed" hour with no visual indication of why.

## Code Examples

### Existing bounded-history contract (reuse as-is)
```python
# Source: dashboard/app.py:2507-2580 (api_telemetry_history) — full response shape
return jsonify({
    'requested': {'start_ts': requested.start_ts, 'end_ts': requested.end_ts},
    'selector': selector,                                  # {'kind': 'host', 'metric': ...} or {'kind': 'service', 'port': ...}
    'effective_resolution_seconds': resolution,             # server-selected, from select_resolution()
    'point_budget': policy.point_budget,                    # 2048 (dashboard/beacon/config.py:50)
    'source_resolutions_seconds': history['source_resolutions_seconds'],
    'points': history['points'],
    'coverage': coverage,                                   # [{start_ts, end_ts, state, detail?}, ...]
    'aggregation_pending': list(pending),
})
```

### Existing preference-persistence pattern (extend for D-04)
```javascript
// Source: dashboard/advanced.js:1-45 — the pattern Phase 4 must extend, not replace
const PREFS_KEY = 'beacon-advanced-preferences-v1';
const DEFAULT_PREFERENCES = {refreshSeconds: 15, paused: false, density: null, range: '24h', filters: {}};
// Phase 4 adds validated keys here: historyRange: {preset|custom}, historyFilters: {...},
// selectedService: port|null — each validated on load exactly like refreshSeconds/density/range today.
```

### Existing events query shape (extend for range+filter)
```python
# Source: dashboard/app.py:2686-2724 (api_events) — column set and join Phase 4's new
# /api/events/history route must reuse (adding WHERE ts BETWEEN ?/AND ? plus port/event_type filters,
# and criticality via the existing service_meta.critical join seen at dashboard/app.py:2643/2652 usage sites)
"SELECT e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
"e.latency_ms, e.error_class, e.alert_status, e.details, "
"e.suppressed_reason, e.maintenance_grace_until, e.down_since_ts, "
"COALESCE(m.display_name, s.title, ':' || e.port) AS service_name "
"FROM events e "
"LEFT JOIN services s ON s.port = e.port "
"LEFT JOIN service_meta m ON m.port = e.port "
```

### Verified failure-class vocabulary (for HIS-03's failure-class counts)
```python
# Source: dashboard/app.py:648-663 (probe outcome classification) — verbatim strings observed
# f"http_{resp.status_code}"   # e.g. http_500
# "invalid_target"             # OutboundPolicyError
# "invalid_url"                # dashboard/app.py:1525
# "not_responding"             # dashboard/app.py:1396
# "timeout"                    # requests.exceptions.Timeout
# "connection_error"           # requests.exceptions.ConnectionError
# "request_error"              # requests.exceptions.RequestException (catch-all)
# "probe_error"                # bare Exception (catch-all)
```

### Verified current-state availability vocabulary (informs D-11's state band)
```python
# Source: dashboard/beacon/diagnosis.py:265 and :23
availability = 'online' if online == 1 else 'offline' if online == 0 else 'unknown'
MAINTENANCE_AVAILABILITY = 'maintenance'
# service['availability'] is overwritten to 'maintenance' when offline AND an active maintenance window
# covers `now` — the same four-state vocabulary (online/offline/unknown/maintenance) D-11 specifies for
# the historical state band.
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-------------------|---------------|--------|
| Fixed-window sparkline over the last 80 in-memory samples, browser-local time (`dashboard/app.js:139-142`) | Server-bounded, coverage-aware, mixed-tier history query with an explicit point budget (`dashboard/beacon/telemetry.py`, built in Phase 2) | Phase 2 (2026-08-11) | The Phase 4 charts must NOT reuse the old sparkline's "just plot whatever's in memory, ignore gaps" approach — it predates the five-state coverage model entirely and has no gap-awareness |

**Deprecated/outdated:**
- The `dashboard/app.js:139` sparkline's line-drawing approach (always connects every point, no gap-breaking) is superseded by D-06 for anything in the History/Incidents sections — it remains valid only for the main dashboard's existing compact previews, which are explicitly out of Phase 4's scope (deferred to Phase 5's UX-01).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | `Intl.DateTimeFormat(locale, { timeZone })` correctly and natively handles arbitrary IANA timezone names (including DST ambiguous/absent-hour detection support via `Intl.DateTimeFormat` + manual boundary comparison) across all browsers this project targets | Don't Hand-Roll, Pitfall 6 | If a targeted browser has incomplete `Intl` timezone-database support, DST-hour labelling (D-05) could silently misbehave; low risk given this is a personal-LAN, modern-browser-only deployment, but not verified against a specific browser version this session |
| A2 | Client-side least-squares slope computation (D-08) is acceptable performance-wise for up to 2048 points per metric per chart, computed on every range change | Don't Hand-Roll | If profiling on Pi-class hardware shows this is slow, it is trivially movable server-side since the aggregate rows already contain the necessary sums; low risk, cheap to relocate |
| A3 | The recommended `GET /api/events/history` route can reuse the existing `events(ts)` and `events(port, ts)` indexes efficiently for a 90-day range with additional `event_type`/criticality filtering, without a new composite index | Architecture Patterns, Pattern 4 | If query plans show a full scan under the criticality join at 90-day scale, a new index (e.g., on `events(ts, event_type)`) may be needed — should be verified with `EXPLAIN QUERY PLAN` during planning/implementation against representative data volume, per the project's established performance-verification pattern (`.planning/STATE.md` blockers) |

**If this table is empty:** N/A — three assumptions logged above, all low-risk and independently verifiable during planning/execution.

## Open Questions (RESOLVED)

*All three were settled during planning (2026-08-25); each resolution below cites the plan that carries it in executable form. No open question remains for this phase.*

1. **Should the new incidents API return raw filtered events, pre-grouped episodes, or both?**
   - What we know: D-12 requires grouped rows with transitions available "on expand," and grouping must be a view over durable rows, computed server-side per the established classification split.
   - What's unclear: Whether HIS-04's "filter incidents and transitions" implies the raw ungrouped transition list must also be independently filterable (e.g., filtering to just `alert_sent`/`alert_failed` events, which don't participate in down/recovered grouping at all).
   - Recommendation: Have `/api/events/history` return both the grouped `episodes[]` (for the Incidents list) and the flat filtered `events[]` (for "transitions" and for the expand-to-see-underlying-transitions view), since the underlying SQL read is the same and both projections come from one query result set.
   - **RESOLVED — both.** `04-02-PLAN.md` Task 1 `compose_incidents_response` returns `episodes[]` *and* `events[]` from one query result set; the flat list carries the non-grouping event types (`alert_sent`/`alert_failed`/`monitoring_gap`) that never participate in down-to-recovered grouping, and `04-07-PLAN.md` Task 2 renders `episode.transitions` behind the `Show transitions` disclosure.

2. **Exact padding amount for a pushed incident window (D-15)?**
   - What we know: The window is "the incident span plus padding," explicitly left to Claude's Discretion.
   - What's unclear: A specific fixed amount (e.g., 10% of span, or a fixed 15-minute pad) is not decided.
   - Recommendation: Planning should pick a simple, explainable rule (e.g., 15% of the episode's own duration on each side, with a floor of a few minutes so very short incidents remain legible) and document it as a locked decision at plan time, since it affects test fixtures.
   - **RESOLVED — 15% per side, 300-second floor.** `04-05-PLAN.md` Task 2 declares `INCIDENT_PAD_FRACTION = 0.15` and `INCIDENT_PAD_FLOOR_SECONDS = 300`; `04-07-PLAN.md` Task 3 `incidentFocusWindow` applies them, caps an open episode's window at the current range's own `end_ts`, and clamps the padded window to the retention bound. Both plans carry the exact fixture values as acceptance criteria (5400s per side for a 10-hour episode, 300s per side for a 60-second episode).

3. **Does `/api/events/history` need a response point/row cap analogous to `point_budget`?**
   - What we know: `/api/telemetry/history` enforces `policy.point_budget` (2048) and raises if exceeded (`dashboard/app.py:2555-2557`); `api_events` today caps at `limit` (max 200, `dashboard/app.py:2685`).
   - What's unclear: A 90-day range with a busy service could produce far more than 200 individual events; HIS-04 needs both a filtered list and a "does this need pagination/truncation-disclosure" answer analogous to the coverage `aggregation_pending` pattern.
   - Recommendation: Cap and disclose truncation explicitly (following the existing `gaps.truncated`/`streams.truncated` pattern in `dashboard/advanced.js:398-424`) rather than silently dropping or unboundedly returning rows.
   - **RESOLVED — yes, capped and disclosed.** `04-02-PLAN.md` declares `INCIDENT_ROW_BUDGET = 2048` (mirroring the telemetry `point_budget` discipline), selects `LIMIT budget + 1` to detect truncation without a second COUNT, and returns an explicit `truncated` flag plus `matched_count`. `04-02-PLAN.md` Task 3 additionally proves truncation never fabricates an episode, and `04-07-PLAN.md` Task 1 surfaces the flag as a visible disclosure so a trimmed list can never read as complete.

## Environment Availability

Skipped — this phase introduces no new external tool, service, or runtime dependency. All required runtimes (Python 3.11–3.12 with `zoneinfo`, SQLite, Flask 3.1.3) are already installed and verified operational by prior phases (`.planning/codebase/STACK.md`; Phase 03.1 plumbed `tzdata` for `zoneinfo`). The frontend has no package manager or build step to audit.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest `>=9.0.2,<10` `[VERIFIED: dashboard/pyproject.toml:21]` |
| Config file | `dashboard/pyproject.toml` (`[tool.pytest.ini_options]`, `testpaths = ["../tests"]`) `[VERIFIED: dashboard/pyproject.toml:27-29]` |
| Quick run command | `uv run --project dashboard python -m pytest tests/test_historical_telemetry_api.py tests/test_advanced_diagnosis_api.py -q` |
| Full suite command | `uv run --project dashboard python -m pytest -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|--------------|
| DIA-04 | Preset range selection produces correct `start_ts`/`end_ts` request | unit (JS) / integration | new `tests/test_history_investigation_ui.py::test_preset_range_selection` | ❌ Wave 0 |
| DIA-05 | Custom range validated, out-of-retention/inverted ranges rejected | integration | `pytest tests/test_historical_telemetry_api.py -k range -x` (extend existing) | ✅ existing file, extend |
| DIA-06 | Selecting service/incident/range updates related views together | integration (UI contract) | new `tests/test_history_investigation_ui.py::test_investigation_context_propagation` | ❌ Wave 0 |
| DIA-07 | No causal wording anywhere in correlated views | UI-contract (copy assertion) | new `tests/test_history_investigation_ui.py::test_no_causal_language` | ❌ Wave 0 |
| HIS-01 | Host metric charts: units, thresholds, tooltips, gaps | integration | new `tests/test_history_investigation_ui.py::test_host_chart_gap_rendering` | ❌ Wave 0 |
| HIS-02 | Time-weighted availability for range | unit (Python) | extend `tests/test_historical_telemetry_api.py` (service aggregate assertions) | ✅ existing file, extend |
| HIS-03 | Service state timeline / latency / failure classes / unknown intervals | integration | new `tests/test_history_investigation_ui.py::test_service_state_band` | ❌ Wave 0 |
| HIS-04 | Incident/transition filtering by service/criticality/event_type/time | integration (API) | new `tests/test_incidents_api.py::test_filter_combinations` | ❌ Wave 0 |
| HIS-05 | Incident selection focuses service+window | integration (UI contract) | new `tests/test_history_investigation_ui.py::test_incident_focus_pushes_stack` | ❌ Wave 0 |
| HIS-06 | Latest/min/max/avg/trend comparison, latest within range not presented as current | unit | new `tests/test_incidents_api.py` or extend `tests/test_historical_telemetry_api.py::test_trend_slope` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `uv run --project dashboard python -m pytest tests/test_historical_telemetry_api.py tests/test_incidents_api.py tests/test_history_investigation_ui.py -q` (once created)
- **Per wave merge:** full suite (`uv run --project dashboard python -m pytest -q`)
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_incidents_api.py` — covers HIS-04, HIS-05, D-12/D-13/D-14 grouping and suppressed-visibility semantics
- [ ] `tests/test_history_investigation_ui.py` — covers DIA-04 through DIA-07, HIS-01, HIS-03, HIS-05 UI-contract behavior (gap rendering, state band, navigation stack, no-causal-language)
- [ ] Extend `tests/test_historical_telemetry_api.py` with range-composition and trend-slope (HIS-06) assertions if the trend helper is implemented server-side; otherwise a client-side unit test harness is needed for the pure slope function
- [ ] No new pytest framework/config install needed — `pytest` and `testpaths` already cover `tests/`

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|--------------------|
| V2 Authentication | No | Single-operator, trusted-LAN, no accounts (`.planning/REQUIREMENTS.md` Out of Scope) |
| V3 Session Management | No | No session/cookie mechanism introduced |
| V4 Access Control | No | No new privilege boundary; `/advanced` remains reachable to anyone on the trusted LAN, same as Phase 3 |
| V5 Input Validation | Yes | Every new parameterised GET (`start_ts`, `end_ts`, `port`, `criticality`, `event_type`) must be validated with the same discipline as `_parse_history_timestamp`/`_history_selector` (`dashboard/app.py:2472-2503`) — reject, don't coerce, on malformed input |
| V6 Cryptography | No | No new secret/credential handling |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|------------------------|
| SQL injection via new filter parameters (`port`, `event_type`, `criticality`, `start_ts`, `end_ts`) | Tampering | Parameterized queries only (existing codebase convention — every query in `dashboard/app.py`/`repositories.py` uses `?` placeholders); reject unvalidated `event_type`/`criticality` values against an explicit allowlist before building SQL, exactly as `_history_selector` does for `kind` |
| Unbounded/expensive range query (e.g., a maliciously large or malformed `start_ts`/`end_ts` on the new events route) causing resource exhaustion on Pi-class hardware | Denial of Service | Reuse `HistoricalRange`'s existing validation (`dashboard/beacon/telemetry.py:29-42`, rejects >90-day spans and inverted ranges) for the new incidents route rather than inventing new bounds logic |
| `/advanced` document route regaining a query-string attack surface | Tampering / Information Disclosure | D-18 explicitly forbids URL-encoded state on the document route; the 46-threat verification in `03-SECURITY.md` (`threats_open: 0`) assumed a parameterless document route — any deviation must be re-threat-modelled, not silently added |
| New parameterised data APIs bypassing the existing `_db_lock` discipline | Tampering (data race) | Follow the existing pattern: reads acquire `_db_lock` around the `database_access(DB_PATH)` context (see `api_telemetry_history`, `dashboard/app.py:2534`); AR-03-01's accepted-risk exception for `/api/advanced/current` does not automatically extend to new routes — new routes should take `_db_lock` unless a specific, documented reason (like AR-03-01's maintenance-flock wait) argues otherwise |

## Sources

### Primary (HIGH confidence — read directly this session)
- `dashboard/app.py` (lines 640-3000 range, specifically 2418-2620, 2650-2760, 930-980) — existing routes, selectors, error-class vocabulary
- `dashboard/beacon/telemetry.py` (lines 1-300, 460-500) — coverage partition, resolution ladder, point budget, storage-pressure detail mechanics
- `dashboard/beacon/repositories.py` (lines 455-560) — host/service telemetry query composition
- `dashboard/beacon/config.py` (lines 1-80) — `Settings` dataclass, `timezone` field
- `dashboard/beacon/diagnosis.py` (lines 255-300) — current availability vocabulary (`online`/`offline`/`unknown`/`maintenance`)
- `dashboard/beacon/maintenance.py` — `MAINTENANCE_REASON`, grace/coverage functions
- `dashboard/beacon/migrations.py` (lines 115-146, 540-571) — `events` schema, indexes, migration 9 column additions
- `dashboard/advanced.js`, `dashboard/advanced.html` (full) — nav shell, preference schema, copy-map, existing gap-evidence rendering pattern
- `dashboard/app.js` (lines 120-190) — existing sparkline precedent
- `.planning/codebase/STACK.md` — confirms no frontend build step/package manager
- `.planning/phases/04-historical-investigation/04-CONTEXT.md` — all D-01..D-18 decisions and discretion areas
- `.planning/phases/03.1-planned-maintenance-recognition/03.1-VERIFICATION.md` — 9/9 must-haves met with `gaps: []` and every gap-closure round resolved; frontmatter `status: human_needed` remains open on one unrelated item (WR-06). The durable event shape this phase consumes (`suppressed_reason`, `maintenance_grace_until`, `down_since_ts`, migration 9) is settled, which is the substance R-02 asked to confirm — the phase is not, however, sealed

### Secondary (MEDIUM confidence — WebSearch, cross-referenced against well-known technique)
- [LTTB downsampling algorithm reference](https://github.com/seanvelasco/lttb) — O(n) largest-triangle-three-buckets technique, cited only as a fallback if client-side decimation is ever needed beyond the server's existing 2048-point budget
- [SVG vs Canvas performance for time-series charts](https://apexcharts.com/blog/svg-vs-canvas-charts/) — confirms SVG remains appropriate for per-chart point counts in the low thousands with interactivity/accessibility requirements, informing the recommendation to keep the existing hand-rolled SVG approach rather than switch to canvas

### Tertiary (LOW confidence)
- None used as load-bearing claims; all `[ASSUMED]` items are logged in the Assumptions table above with explicit risk notes.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; all reused components verified by direct source read this session
- Architecture: HIGH — composition strategy is directly derived from existing, tested endpoint contracts and the explicit D-01–D-18 decision set
- Pitfalls: HIGH for codebase-specific pitfalls (timezone gap, coverage-state confusion, cross-surface contradiction — all verified against source); MEDIUM for the Pi rendering-performance guidance (informed by general web research, not measured on this project's actual hardware — R-01 explicitly requires that measurement to happen during/after planning, not be resolved by research alone)

**Research date:** 2026-08-25
**Valid until:** 2026-09-24 (30 days — stable internal APIs; re-verify if Phase 03.1 gap-closure work resumes and touches `events` schema or `SETTINGS.timezone` plumbing again)
