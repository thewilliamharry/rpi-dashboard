# Phase 4: Historical Investigation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-25
**Phase:** 04-historical-investigation
**Areas discussed:** Range Control & Placement, Chart Honesty, Service History & Incidents, Investigation Context

**Area selection:** The operator declined to narrow the gray-area list, answering *"Anything you need my preference on, leave the technical stuff to researcher."* All four identified areas were discussed, restricted to preference-level questions; implementation mechanics were routed to Claude's Discretion in CONTEXT.md.

---

## Range Control & Placement

### Where historical investigation lives

| Option | Description | Selected |
|--------|-------------|----------|
| Range-aware existing sections | Global range control in the header; Host and Services sections gain history below their current-state evidence | |
| Separate History + Incidents sections | Phase 3's five sections stay pure current-state; two new nav entries | ✓ |
| One Investigate section | A single new section owning range, charts, service history, and incidents together | |

**User's choice:** Separate History + Incidents sections.
**Notes:** Keeps Phase 3's verified current-state contract untouched; current-vs-historical becomes an explicit mode switch. Accepted cost: investigating one service means moving between the Services and History sections — later partly mitigated by the carried service selection (D-16).

### Preset ladder

| Option | Description | Selected |
|--------|-------------|----------|
| 1h, 6h, 24h, 7d, 30d, 90d | Six presets aligned to the retention tier boundaries | ✓ |
| 1h, 24h, 7d, 30d, 90d | Five presets; leaner header control | |
| 1h, 3h, 6h, 12h, 24h, 7d, 30d, 90d | Eight presets; more sub-day granularity | |

**User's choice:** Six presets.
**Notes:** Each preset change corresponds to a visible, explainable resolution change against the 7 / 30 / 90-day tiers.

### Timezone

| Option | Description | Selected |
|--------|-------------|----------|
| Local time throughout | Axes, tooltips, incident rows, and range entry all in the Pi's configured local time | ✓ |
| Local, with UTC on inspection | Local by default, exact UTC revealed in tooltips and expanded detail | |
| UTC throughout | Everything in UTC; unambiguous across DST | |

**User's choice:** Local time throughout.
**Notes:** Consistent with 03.1 D-02's local wall-clock maintenance evaluation. DST produces one ambiguous and one absent hour on the axis — accepted as honest, requires labelling.

### DIA-08 documentation inconsistency

| Option | Description | Selected |
|--------|-------------|----------|
| Range preference only | Phase 4 picks up only the range/filter persistence that couldn't exist before | ✓ |
| Full DIA-08 re-verification | Treat the whole requirement as open and re-verify in Phase 4 | |
| Out of scope — fix the docs | DIA-08 is done; correct the stale traceability row instead | |

**User's choice:** Range preference only.
**Notes:** Raised proactively — `PROJECT.md:31` lists DIA-08 validated in Phase 3, `REQUIREMENTS.md:43` has it deferred to Phase 4, and `ROADMAP.md:339` omits it from Phase 4 entirely. Recorded as R-04; the documentation conflict still needs reconciling separately.

### Custom range entry

| Option | Description | Selected |
|--------|-------------|----------|
| Explicit start/end fields | Two local-time datetime inputs with validate/apply | |
| Fields plus drag-to-select on a chart | Fields stay canonical; dragging any chart sets the same range | ✓ |
| Fields plus zoom-out/back control | Fields plus a range history stack | |

**User's choice:** Fields plus drag-to-select.
**Notes:** The back-stack idea was not discarded — it resurfaced and was adopted separately in D-15, so drag and incident-focus share one push/Back model.

### Host metric presentation

| Option | Description | Selected |
|--------|-------------|----------|
| All four stacked, shared time axis | CPU, memory, disk, temperature always visible on one aligned axis | ✓ |
| One chart, metric selector | Single large chart with a metric picker | |
| Two visible, rest collapsed | CPU and memory expanded; disk and temperature collapsed | |

**User's choice:** All four stacked.
**Notes:** Claude flagged at the time that four 2,048-point SVG charts plus drag interaction is the phase's main Pi-performance risk. The user's choice stands; the risk was recorded as R-01 with a research obligation to bound it rather than narrow the layout.

---

## Chart Honesty

### Missing-data rendering

| Option | Description | Selected |
|--------|-------------|----------|
| Broken line + per-chart coverage strip | Line stops and restarts; a strip beneath each chart is segmented by reason with pattern and label | ✓ |
| Broken line + hatched bands in-plot | Missing spans shaded inside the plot area, reason in tooltip | |
| Broken line + one shared strip | A single strip beneath the whole stacked group | |

**User's choice:** Broken line plus per-chart coverage strip.
**Notes:** The shared-strip option was argued against during presentation — Phase 2 made host coverage metric-specific (cpu/ram/disk/temp separately), so one merged strip would either misreport or collapse to worst-case.

### Trend definition (HIS-06)

| Option | Description | Selected |
|--------|-------------|----------|
| Slope over observed points | Least-squares slope, per-hour on short ranges, per-day on long ones | ✓ |
| vs preceding equal window | Compare this range's average against the preceding window of equal length | |
| Both | Slope always, window comparison when retained | |

**User's choice:** *"What would be better here"* — deferred to Claude, who recommended slope; the user then confirmed the recommendation.
**Notes:** The deciding argument was a retention cliff: at the 90d preset the preceding 90 days are entirely expired, so the comparison-window option could never compute at the longest range, and 30d+ ranges would compare against partially-expired windows. Slope also needs no second query, which matters with four charts already fetching.

### "Latest" in a historical range

| Option | Description | Selected |
|--------|-------------|----------|
| Both, explicitly labelled | Latest-in-range and current live value, side by side | |
| Latest within the range | Last observed point inside the selected bounds | ✓ |
| Current live value | Freshest observation, compared against range statistics | |

**User's choice:** Latest within the range.
**Notes:** Keeps latest/min/max/average all describing the same window. Requires that a past-ending range never let the reading pass as current.

### Threshold provenance (HIS-01)

| Option | Description | Selected |
|--------|-------------|----------|
| Only where a hardware fact exists | Temperature throttle points and disk capacity only; no CPU or memory line | ✓ |
| All four, documented defaults | A reference line on every metric for visual consistency | |
| Hardware facts plus memory | Three lines; CPU still bare | |

**User's choice:** *"Idk"* — deferred to Claude, who checked the codebase before recommending; the user then confirmed.
**Notes:** Claude verified during discussion that Beacon has **no configurable host-metric thresholds at all** (`dashboard/beacon/config.py:28-76` — alerting is entirely service-availability based), which collapsed the "operator config, defaults otherwise" option into plain defaults. The recommendation went further than any presented option: draw a line only where a defensible hardware or filesystem fact exists, since 100% CPU on a Pi is not a fault and drawing a line there would invent a threshold to fill a slot.

---

## Service History & Incidents

### Service history layout (HIS-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Timeline band + latency chart | State band above, latency chart beneath, shared time axis, failure classes as counts | ✓ |
| One combined chart | Latency chart with state-shaded background | |
| Availability summary first, then detail | Lead with the availability figure, evidence below | |

**User's choice:** Timeline band plus latency chart.
**Notes:** Mirrors the stacked shared-axis host layout. The combined-chart option was argued against because state shading would collide with the coverage strip's background meaning.

### Incident row granularity (HIS-04)

| Option | Description | Selected |
|--------|-------------|----------|
| Grouped episode | One row per down→recovered episode, transitions on expand | ✓ |
| Every transition | One row per stored event, zero derivation | |
| Grouped, with a transitions toggle | Grouped by default with a raw-transitions mode | |

**User's choice:** Grouped episode.
**Notes:** 03.1 D-08 already stores the true `down_since_ts`, so grouping reads durable evidence rather than reconstructing it. CONTEXT.md records the constraint that grouping is a view, never a new durable record, and leaves open-incident and flapping representations to discretion.

### Suppressed maintenance entries

| Option | Description | Selected |
|--------|-------------|----------|
| Shown by default, visibly tagged | Advanced list shows them tagged; event-type filter can exclude | ✓ |
| Hidden by default, same reveal control | Mirror 03.1 D-10 exactly | |
| Shown by default, remembered per operator | Shown and tagged, with the choice persisted | |

**User's choice:** Shown by default, visibly tagged.
**Notes:** A deliberate divergence from the main dashboard's default. Recorded as R-05 so a future cross-surface audit reads it as intent rather than a defect.

### Overrun outage span

| Option | Description | Selected |
|--------|-------------|----------|
| Full outage, fault period marked | True down-since through recovery, post-grace portion marked unplanned | ✓ |
| Full outage only | One span, raised-at available on inspection | |
| Fault period only | Grace expiry to recovery | |

**User's choice:** *"idk you pick"* — Claude selected full outage with the fault period marked.
**Notes:** Rationale given at the time: 03.1 D-09 keeps planned downtime in the availability figure in full, so a fault-period-only row would report a 12-minute incident beside 47 minutes of availability loss for the same event — the exact cross-surface contradiction Phase 3 spent nine verification rounds eliminating. It is also the only option using both timestamps 03.1 D-08 deliberately stored.

---

## Investigation Context

All four questions in this area were returned as *"you pick"*. Claude selected each and stated its reasoning; the operator did not revise any.

### Incident focus behavior (HIS-05)

| Option | Description | Selected |
|--------|-------------|----------|
| Pushed — Back returns | Incident pushes a focused window onto a stack with a Back control | ✓ |
| Replaced — presets restore | The incident window simply becomes the current range | |
| Focused overlay, range untouched | Incident opens as a detail view over a stable range | |

**Claude's choice:** Pushed, Back returns.
**Rationale:** Drag-to-select is itself a range-narrowing gesture; if drag pushes and incident-select replaces, two near-identical actions carry different memory semantics. One stack also handles the routine case of an incident beginning outside the current range without a special rule.

### Context scope (DIA-06)

| Option | Description | Selected |
|--------|-------------|----------|
| History + Incidents only | Range governs the two new sections; nothing carries | |
| Range stays, service selection carries | Range scoped to new sections; selected service is shared across all | ✓ |
| Range governs everything | All seven sections become range-aware | |

**Claude's choice:** Range scoped to the new sections; selected service carries.
**Rationale:** "Range governs everything" contradicts the separate-sections placement the user chose and would rework Phase 3's verified current-state contract. Pure isolation leaves DIA-06's "one investigation context" thin. The genuinely shared thing is which service is under suspicion — carried as a read-only value that changes no Phase 3 payload.

### Correlation presentation (DIA-07)

| Option | Description | Selected |
|--------|-------------|----------|
| Shared axis + incident markers | Neutral markers along the shared time axis | |
| Shared axis + hover time cursor | Cursor reading all stacked charts at one instant | |
| Both markers and cursor | Persistent markers plus point-in-time readout | ✓ |

**Claude's choice:** Both.
**Rationale:** Markers alone satisfy DIA-07; a cursor alone provides no persistent link between an incident and surrounding metrics. With the shared axis and drag handler already committed, the cursor reuses the same pointer-to-time math. Phase 5 keyboard debt recorded as R-03.

### URL versus browser storage

| Option | Description | Selected |
|--------|-------------|----------|
| Browser storage only | Phase 3's validated-preference pattern; nothing in the URL | ✓ |
| URL query params | Range, service, and filters encoded for bookmarkability | |
| Storage, with an explicit share/copy action | Storage live, params produced deliberately | |

**Claude's choice:** Browser storage only.
**Rationale:** `03-SECURITY.md` verified 46 blocking threats against a parameterless GET surface and PROJECT.md publishes GET-only-no-selector as validated. Bookmarkability is a modest win for one operator two clicks from the page. The share/copy option was rejected as the worst trade — full parsing and threat cost for occasional convenience. The persisted range (D-04) already delivers most of the practical benefit.

**Important clarification recorded at the time:** this constrains the `/advanced` **document route only**. Data APIs take parameters today (`/api/telemetry/history` already accepts `start_ts`, `end_ts`, and a selector with existing validation) and Phase 4's historical reads are expected to be parameterised GETs.

---

## Claude's Discretion

Explicitly deferred by the operator, either through the framing *"leave the technical stuff to researcher"* or per-question:

- Trend definition (recommended by Claude, then confirmed by the operator)
- Threshold provenance (recommended by Claude after a codebase check, then confirmed)
- Overrun outage span (chosen outright by Claude)
- All four Investigation Context decisions (chosen outright by Claude)
- API shape, rendering strategy under the Pi budget, grouping edge semantics, coverage strip mechanics, slope confidence floor, incident window padding, availability presentation, default filter state, and module/test boundaries — all enumerated in CONTEXT.md's Claude's Discretion section

## Deferred Ideas

None — discussion stayed within phase scope. No scope-creep redirection was required.

## Flags Raised During Discussion

- **Pi rendering cost** of four stacked 2,048-point charts plus drag and hover interaction (R-01) — raised before the user's choice, choice confirmed, routed to research to bound.
- **Phase 03.1 is reopened** and its durable event shape is not yet verified, while Phase 4 depends on it (R-02).
- **Phase 5 accessibility debt** created knowingly by drag, hover cursor, marker rail, state band, and coverage strip (R-03).
- **DIA-08 inconsistent across PROJECT.md, REQUIREMENTS.md, and ROADMAP.md** (R-04) — scoped by operator decision, but the document conflict itself remains unreconciled.
- **Intentional cross-surface divergence** in suppressed-event visibility between the main dashboard and `/advanced` (R-05).
