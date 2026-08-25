# Phase 4: Historical Investigation - Context

**Gathered:** 2026-08-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn Phase 2's bounded, truthful 90-day telemetry substrate into an interactive historical investigation experience inside Phase 3's GET-only `/advanced` workspace. This phase delivers shared range selection (1h–90d presets plus a validated custom range), host metric history with units, thresholds, tooltips and visible gaps, per-service availability/state-timeline/latency/failure-class history, incident filtering and focus, and one correlated investigation context that presents observed evidence without asserting an unsupported root cause.

Theme parity, responsive behavior, accessibility work, and main-dashboard preview analytics remain Phase 5. Workload resilience and Pi-class acceptance remain Phase 6. Remote actions remain v2. No mutation surface is introduced anywhere.

</domain>

<decisions>
## Implementation Decisions

### Placement and Range Control

- **D-01:** Historical investigation lives in **two new top-level sections — `History` and `Incidents`** — added to the existing advanced section navigation. Phase 3's `Overview`, `Host`, `Services`, `Pipeline`, and `Settings` sections remain strictly current-state and are not made range-aware. Current-versus-historical is an explicit mode switch, not a blended view. — **Reversibility:** costly — the section split shapes the nav contract, the preference schema, and every UI-contract test written for the workspace; merging history into the Phase 3 sections later means re-verifying that phase's current-state contract.

- **D-02:** The shared preset ladder is **1h, 6h, 24h, 7d, 30d, 90d**. These map onto the retention tiers deliberately: 1h/6h/24h sit inside the 7-day raw tier, 7d is the raw boundary, 30d is the 5-minute tier boundary, and 90d is the hourly tier boundary — so every preset change is a visible, explainable resolution change. — **Reversibility:** reversible — presentation-level list, though preset identity is persisted (D-04).

- **D-03:** Custom ranges are entered through **explicit local-time start/end fields as the canonical entry, plus drag-to-select across any host or service chart** which sets the same range and updates the fields to show what was selected. The fields remain the authoritative, statable representation of the current range. — **Reversibility:** costly — the drag interaction couples the chart renderer to range state and incurs a Phase 5 keyboard-equivalent obligation (see R-03).

- **D-04:** The operator's chosen range and history-view filters **persist as validated presentation preferences** alongside Phase 3's existing keys. This is the DIA-08 remainder, and it is the only part of DIA-08 Phase 4 picks up — see R-04 for the documentation inconsistency behind that scoping. — **Reversibility:** reversible — additive to the existing validated-preference schema.

- **D-05:** All historical timestamps — chart axes, tooltips, incident rows, custom-range entry — display in **the Pi's configured local time**, resolved from the existing `timezone` Settings field (`dashboard/beacon/config.py:60`, default `UTC`, plumbed with tzdata in Phase 03.1). This matches 03.1 D-02, which locked maintenance windows to local wall-clock so they line up with the cron or systemd timer causing the restart. DST transitions produce one ambiguous and one absent hour on the axis; that is honest and must be labelled, not smoothed. — **Reversibility:** costly — the display base runs through every axis, tooltip, incident row, range input, and their tests, and must agree with maintenance-window evaluation.

### Chart Honesty

- **D-06:** Missing intervals **break the line** — the series stops and restarts, never bridging a gap. Beneath each chart, on the same time axis, a **per-chart coverage strip** is segmented by reason (`collection_gap`, `unknown`, `expired`, `not_yet_monitored`, `storage_pressure`), each segment distinguished by pattern **and** text label rather than colour alone. The chart never implies data Beacon does not have; the strip carries *why*. A single shared strip beneath the stacked group was explicitly rejected because Phase 2 made host coverage metric-specific (cpu/ram/disk/temp separately) — one merged strip would either misreport or collapse to worst-case. — **Reversibility:** costly — the strip is the visible expression of Phase 2's five-state coverage partition; changing it later touches every chart, the coverage query shape, and the honesty regression tests.

- **D-07:** All four host metrics (CPU, memory, disk, temperature) are **stacked and simultaneously visible on one shared time axis**, so correlation between, say, a temperature climb and a CPU spike is visible without interaction. See R-01 for the Pi rendering-cost risk this creates. — **Reversibility:** costly — the stacked shared-axis layout is what makes the correlation model (D-14) and the hover cursor work; collapsing to a metric selector later removes the correlation affordance those decisions depend on.

- **D-08:** "Simple trend" (HIS-06) means a **least-squares slope over observed points only**, expressed per-hour on short ranges and per-day on long ones (e.g. `disk +0.4%/day ↑`). Comparison against a preceding equal-length window was rejected on a structural ground: at the 90d preset the preceding 90 days are entirely outside retention, so the longest range could never compute it, and 30d+ ranges would compare against partially-expired windows. Slope works uniformly across all six presets, needs no second query (material with four charts already fetching), and uses only observed points — inheriting Phase 2 D-07's no-interpolation guarantee without new disclosure machinery. — **Reversibility:** reversible — a computation over data already fetched.

- **D-09:** "Latest" in the HIS-06 comparison means **the latest observation within the selected range**, so latest/minimum/maximum/average all describe the same window and the comparison is internally consistent. Where a range ends in the past, the reading must not be presentable as a current value — the range bounds are the disambiguator and must be visible alongside it. — **Reversibility:** reversible.

- **D-10:** Contextual threshold lines (HIS-01) are **documented fixed defaults, drawn only where a defensible hardware or filesystem fact exists** — temperature throttle points and disk capacity. **CPU and memory get no threshold line**, because 100% CPU on a Pi is not a fault and Pi memory pressure has no single defensible line; drawing them for visual symmetry would mean inventing a threshold Beacon cannot justify. Each drawn threshold discloses its source on inspection so it never reads as an operator-configured alert. Verified during discussion: Beacon has **no configurable host-metric thresholds** anywhere (`dashboard/beacon/config.py:28-76` — alerting is entirely service-availability based), so a config-derived option would have read nothing. If host thresholds ever become configurable, the line should follow config — an additive change, not a reversal. — **Reversibility:** reversible — reference lines are presentation over documented constants.

### Service History and Incidents

- **D-11:** One service's history is laid out as a **horizontal state band** (online / offline / unknown / maintenance) across the range, with the **latency chart directly beneath it on the same time axis**, and failure classes summarised as counts beside it with each band segment carrying its class on inspection. This mirrors the host layout in D-07 — stacked, shared axis, correlation visible without interaction. State shading *inside* the latency plot was rejected because it would collide with the coverage strip's background meaning (D-06). — **Reversibility:** costly — the band-plus-chart pairing is the shared-axis contract the correlation model depends on.

- **D-12:** One row in the Incidents list is **one grouped down→recovered episode** — start, duration, end, failure class — with the underlying transitions available on expand. 03.1 D-08 already stores the true `down_since_ts`, so the grouping reads from durable evidence rather than reconstructing it. **Grouping is a view over durable rows and must never become a new durable record.** Representations for a still-unresolved outage and for a flapping service must be explicitly defined (see Claude's Discretion). — **Reversibility:** costly — grouping semantics drive the filter contract, the focus behavior in D-15, and every incident-list test.

- **D-13:** Maintenance-suppressed entries are **shown by default in the advanced Incidents list, visibly tagged as expected maintenance**, with the event-type filter able to exclude them. This deliberately diverges from 03.1 D-10, which hides them by default in the *main dashboard* feed: `/advanced` is the investigation surface an operator opens precisely because they want everything, and hiding evidence there works against the phase goal. The main dashboard's hidden-by-default behavior and its hidden-count reveal control are unchanged. The same service therefore reads differently in the two surfaces **by design**, and each surface must make its own default legible. — **Reversibility:** reversible — a read-time filter default; the durable tag and the stored rows are untouched either way.

- **D-14:** An overrun outage row spans the **true down-since timestamp through recovery, with the portion after grace expiry marked as the unplanned fault**. Both timestamps 03.1 D-08 stored are used and neither is discarded. Showing only the post-grace fault period was rejected because 03.1 D-09 keeps planned downtime in the availability figure in full — a "12-minute incident" beside "47 minutes of availability lost" for the same event is exactly the cross-surface contradiction Phase 3 spent nine verification rounds eliminating. — **Reversibility:** reversible — presentation over two durable timestamps.

### Investigation Context

- **D-15:** Selecting an incident **pushes** a focused window (the incident span plus padding) onto a navigation stack; a visible Back control returns to the range it came from. Drag-to-select (D-03) pushes onto the same stack. Both narrowing gestures therefore share one memory model rather than presenting two similar actions with different semantics. This also handles the routine case where an incident begins outside the current range without a special rule — the pushed window is the incident's own span. — **Reversibility:** costly — the stack is a shared state model across range control, chart interaction, and incident focus.

- **D-16:** The **range governs `History` and `Incidents` only**; Phase 3's five sections stay current-state. But a **selected service carries across all sections** — picking a service in the Phase 3 Services table makes it the subject in History, and vice versa. This is the one thing genuinely shared between current and historical investigation. The carried value is read-only, changes no Phase 3 payload or contract, and must not cause any Phase 3 section to recompute against a historical bound. — **Reversibility:** costly — a selection concept now spans sections Phase 3 verified without one; its read-only boundary is the thing that must be preserved.

- **D-17:** Correlation (DIA-07) is presented as the **shared time axis plus neutral incident markers** along it, **and** a **hover time cursor** tracking across all stacked charts at once for point-in-time readout. Markers give the persistent "when did things happen"; the cursor gives "what was true at that moment". Neither asserts a relationship — alignment is the reader's inference from evidence Beacon actually observed. No wording anywhere may claim causation, and a dense incident period must degrade the marker rail legibly rather than saturating the axis. — **Reversibility:** reversible — both are presentation over the shared axis, though the cursor incurs Phase 5 keyboard debt (R-03).

- **D-18:** Investigation state (range, selected service, filters) lives in **browser storage only** — Phase 3's validated-preference pattern under `beacon-advanced-preferences-v1`. **Nothing is encoded in the `/advanced` URL.** `03-SECURITY.md` verified 46 blocking threats against a parameterless GET surface, and PROJECT.md publishes GET-only-no-selector as a *validated* Key Decision; bookmarkability is a modest win for one operator two clicks from the page and does not justify reopening that. A share/copy-link variant was rejected as the worst trade — it pays the full parsing and threat-modelling cost for occasional convenience. D-04's persisted range already delivers most of the practical benefit, since the view reopens where it was left. — **Reversibility:** one-way in practice — adding URL parameters later reopens a security surface published as validated and requires re-threat-modelling the route.

  **Scope of this decision — read carefully:** D-18 constrains the **`/advanced` document route only**. It does **not** bar parameterised reads. The data APIs take parameters today and must continue to: `/api/telemetry/history` (`dashboard/app.py:2507`) already accepts `start_ts`, `end_ts`, and a host-metric/service-port selector with existing validation. Phase 4's history and incident reads are expected to be parameterised GET APIs.

### Claude's Discretion

Research and planning own the following, subject to the decisions above:

- **API shape** — whether Phase 4 adds one composite bounded history read or composes per-view calls over the existing `/api/telemetry/history` plus a new range-and-filter events API. Note that Phase 3 locked its *current* snapshot as a fixed parameterless one-read GET; that constraint is specific to that endpoint and does not extend to Phase 4's parameterised historical reads (D-18).
- **Rendering strategy for D-07 under the Pi budget** — SVG versus canvas, point decimation above the fetched resolution, render scheduling, and reuse or replacement of the existing hand-rolled sparkline pattern at `dashboard/app.js:139`. Bounding R-01 is a research obligation, not a licence to change D-07.
- **Grouping edge semantics for D-12** — the explicit representation of a still-unresolved (open) incident and of a flapping service, without inventing a durable record.
- **Coverage strip mechanics** — segment minimum widths, how sub-pixel gaps at 90d are represented without disappearing or being overstated, and the pattern vocabulary for the five reasons.
- **Slope computation details for D-08** — minimum observed-point count below which slope is withheld rather than reported, and how a sparse range discloses low confidence.
- **Padding applied to a pushed incident window (D-15)**, and the stack's visual home relative to the browser's own back button.
- **Time-weighted availability presentation for the range (HIS-02)** — precision, prominence, and the maintenance attribution in expanded detail, subject to 03.1 D-09 (headline availability is never adjusted and no "excluding maintenance" figure appears at equal weight).
- **Default incident filter state**, filter combination semantics across service/criticality/event-type/time, and the matching-count and clear-all treatment (following Phase 3 D-15's established pattern).
- **Module boundaries, markup, styling, and test surface**, within the existing calm-light / dense-dark direction and the `_db_lock` posture recorded as accepted risk AR-03-01.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product and Phase Contract

- `.planning/PROJECT.md` — Product mission, local-only boundary, 90-day retention constraint, theme intent, and the validated Key Decision that `/advanced` stays strictly read-only (GET-only routes, no selector or mutation body). Also records accepted risk AR-03-01 (`api_advanced_current` does not take the process-global `_db_lock`), flagged for Phase 6 revisit.
- `.planning/REQUIREMENTS.md` — Phase 4 requirements `DIA-04`, `DIA-05`, `DIA-06`, `DIA-07`, `HIS-01` through `HIS-06`. See R-04 for the `DIA-08` traceability inconsistency.
- `.planning/ROADMAP.md` §"Phase 4: Historical Investigation" (line 335) — Goal, dependency on Phase 03.1, five success criteria, and the boundary against Phase 5's theme-parity work.
- `.planning/STATE.md` — Current project position and the accumulated cross-phase decision list.

### Prior Locked Decisions (all binding on this phase)

- `.planning/phases/02-bounded-telemetry-retention/02-CONTEXT.md` — **The most important upstream contract for this phase.** D-04 aggregate shape (host min/max/avg/latest/count; service time-weighted online/offline/unknown, latency min/max/avg with real sample count, check count, failure-class counts), D-05 five-reason missing-data vocabulary, D-07 no-interpolation and mixed-coverage rules, D-08 preserved requested bounds with `expired`/`not_yet_monitored` disclosure, D-11 `storage_pressure` gaps, D-03 events retained individually for the full 90 days.
- `.planning/phases/03-advanced-current-diagnosis/03-CONTEXT.md` — Workspace shell and section navigation (D-01 to D-04), freshness vocabulary and the do-not-infer-cause rule (D-10, D-11), D-12 actionable-only promotion to the global exception summary, D-13 refresh controls, D-14 validated browser-local preferences, D-15 search/filter/matching-count pattern, D-16 theme sets density not capability.
- `.planning/phases/03.1-planned-maintenance-recognition/03.1-CONTEXT.md` — D-02 local wall-clock evaluation, D-06 derived `In maintenance` display state, D-08 overrun events carrying both true down-since and raised-at timestamps, D-09 availability counts planned downtime with attribution in detail only, D-10 suppressed events written-and-tagged then filtered at read.
- `.planning/phases/01-behavioral-safety-runtime-ownership/01-CONTEXT.md` — Worker ownership, outbound-safety, and read-oriented outage behavior this phase must preserve.

### Security Contract

- `.planning/phases/03-advanced-current-diagnosis/03-SECURITY.md` — The 46 blocking threats verified against a parameterless GET-only `/advanced`, with `threats_open: 0`. D-18 exists to keep this verdict intact; any new parameterised read must carry its own threat coverage.

### Existing-System Evidence

- `.planning/codebase/STACK.md` — Flask, SQLite, vanilla-JS browser, Docker Compose, and the Raspberry Pi deployment constraint.
- `.planning/codebase/CONVENTIONS.md` — Python, JavaScript, API-validation, and error-handling conventions.
- `.planning/codebase/ARCHITECTURE.md` — Shared-SQLite web/worker topology and telemetry flow.

No external specifications were referenced during discussion.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- `dashboard/app.py:2507` `api_telemetry_history` — Already serves bounded, mixed-tier host and service history with a validated `start_ts`/`end_ts`/selector contract, server-selected `effective_resolution_seconds`, a `point_budget` (2048), the five-state `coverage` partition, and `aggregation_pending` disclosure. This is the substrate D-06, D-08, and D-09 read from; it should be composed or extended, not bypassed.
- `dashboard/app.py:2686` `api_events` — Already returns `suppressed_reason`, `maintenance_grace_until`, and `down_since_ts` per event with the service name joined. D-12, D-13, and D-14 build directly on these columns. It currently takes only `limit` and `since` — a range-and-filter contract is the gap.
- `dashboard/advanced.html`, `dashboard/advanced.js`, `dashboard/advanced.css` — The verified Phase 3 workspace: section navigation shell, refresh/pause/last-updated controls, safety-warning cluster, filter + matching-count pattern, and skeleton loading states. D-01 adds two nav entries and two sections into this shell.
- `dashboard/app.js:139` — The only existing chart in the product: a hand-rolled inline SVG `<path>` sparkline. It is the precedent for D-07's rendering, and the honest measure of how far the current codebase is from four interactive stacked charts.
- `dashboard/beacon/telemetry.py`, `dashboard/beacon/repositories.py` — `select_resolution`, `compose_historical_response`, `partition_coverage`, `get_host_telemetry`, `get_service_telemetry`, `get_telemetry_coverage`, `get_pending_aggregation`. The bounded query and coverage vocabulary this phase renders.
- `dashboard/beacon/diagnosis.py` — Server-side classification (freshness, active exceptions, health rules). Phase 3 established that the server classifies and the UI renders without recomputing; historical classification should follow the same split.
- `dashboard/beacon/maintenance.py` — Window evaluation and the suppression tagging D-13 and D-14 read.
- `dashboard/beacon/config.py:60` `timezone` — The Settings field D-05 resolves local time from (default `UTC`; tzdata plumbed in Phase 03.1).

### Established Patterns

- The browser is **dependency-free vanilla JavaScript with no build step** — the roadmap overview explicitly excludes a frontend build stack. Every chart, axis, tooltip, coverage strip, drag handler, and hover cursor in this phase is hand-written SVG and DOM.
- The server classifies and the UI renders; the UI does not recompute server-derived state.
- Web and worker are separate processes sharing SQLite. This phase is entirely read-side and introduces no background ownership.
- Distinct facts stay distinct in the UI — worker staleness, disconnection, recovery-required, retention expiry, collection gaps, and storage pressure are never merged.
- Preferences are validated before use and versioned in browser-local storage.

### Integration Points

- Two new sections and nav entries in the Phase 3 workspace shell (D-01), plus the shared range control.
- A range-and-filter events read for the Incidents section (D-12 to D-14) — the current `api_events` `limit`/`since` contract does not cover it.
- Composition of `api_telemetry_history` for four host metrics and per-service latency over one shared range, under the existing point budget.
- The carried selected-service value spanning Phase 3's Services table and the new History section, strictly read-only (D-16).
- Extension of the advanced preference schema for range and history filters (D-04).
- UI-contract and browser-regression coverage for gap rendering, threshold provenance, incident grouping, suppressed-entry visibility, and the absence of any mutation affordance.

</code_context>

<specifics>
## Specific Ideas

- The chart must never draw a line across an interval Beacon did not observe. Breaking the line is the non-negotiable form of that; the coverage strip explains why it broke.
- Four stacked host charts on one axis exist so that "the temperature climbed while CPU spiked" is visible without the operator asking for it.
- A threshold line is only drawn when Beacon can name the hardware or filesystem fact behind it. Two honest lines beat four symmetrical ones.
- `/advanced` is where the operator goes because they want everything — so suppressed maintenance evidence is shown there and tagged, not hidden.
- An incident row and the availability figure for the same service must never disagree about how long the service was down.
- Drilling in is non-destructive: drag to narrow, click an incident to focus, Back to return to the range you were scanning.

</specifics>

<risks_and_flags>
## Risks and Flags for Downstream Agents

- **R-01 — Pi rendering cost (from D-03 + D-07).** Four simultaneously visible charts, each up to the 2,048-point budget, plus a drag-to-select handler and a hover cursor tracking across all four, is the single largest performance risk in this phase and it lands on Raspberry Pi-class hardware. The user chose this layout deliberately after the cost was raised. **Research must bound it** — decimation above the fetched resolution, render scheduling, SVG-versus-canvas, and a measured budget — rather than resolve it by narrowing D-07. OPS-01 (Phase 6) will hold this to account; do not defer the measurement to then.
- **R-02 — Phase 03.1 is reopened and its dependency is not yet verified.** `.planning/STATE.md` has Phase 03.1 in `executing` with gap-closure round-4 plans pending, and `ROADMAP.md:19` records it reopened on 2026-08-23. D-12, D-13, and D-14 depend on 03.1's durable event shape (`suppressed_reason`, `maintenance_grace_until`, `down_since_ts`, migration 9). Confirm that shape is settled before planning work that consumes it.
- **R-03 — Phase 5 accessibility debt is being created knowingly.** Drag-to-select (D-03), the hover time cursor and marker rail (D-17), the state band (D-11), and the coverage strip (D-06) all require keyboard-accessible equivalents and non-colour-dependent encodings under UX-06. Recorded here at creation time so Phase 5 inherits a known list rather than discovering it.
- **R-04 — DIA-08 is inconsistent across three planning documents.** `PROJECT.md:31` lists it validated in Phase 3; `REQUIREMENTS.md:43` has it unchecked with traceability row `DIA-08 | Phase 3 | Deferred to Phase 4`; `ROADMAP.md:339` does not list it under Phase 4. The user's decision: Phase 4 picks up **only** the range-preference remainder (D-04), which could not have existed before this phase. The documentation conflict itself needs reconciling — most likely correcting the stale `REQUIREMENTS.md` traceability row — and is not resolved by this CONTEXT.md.
- **R-05 — D-13 creates an intentional cross-surface divergence.** The same service's suppressed maintenance events are hidden by default on the main dashboard (03.1 D-10) and shown by default in the advanced Incidents list. This is deliberate, not a defect. Each surface must make its own default legible so neither reads as the other's bug — and any future audit comparing the two should be pointed at this decision.

</risks_and_flags>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 04-historical-investigation*
*Context gathered: 2026-08-25*
