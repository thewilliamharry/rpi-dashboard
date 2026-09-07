---
phase: 04
slug: historical-investigation
status: draft
shadcn_initialized: false
preset: none
created: 2026-08-25
---

# Phase 04 — UI Design Contract

> Visual and interaction contract for two new `/advanced` sections — `History` and `Incidents` —
> that turn Phase 2's bounded 90-day telemetry substrate into a correlated, gap-honest
> investigation experience. Extends the existing read-only workspace shell
> (`dashboard/advanced.html`, `dashboard/advanced.js`, `dashboard/advanced.css`) and reuses the
> Phase 3 / Phase 03.1 token system, status vocabulary, and evidence-row conventions rather than
> introducing a parallel one. Does not reopen any decision locked in `04-CONTEXT.md`.

---

## Design System

| Property | Value |
|----------|-------|
| Tool | none — dependency-free vanilla HTML, CSS, and JavaScript (unchanged); no frontend build step exists in this project |
| Preset | not applicable |
| Component library | none |
| Icon library | none; concise text labels, native `<time>`/`title` disclosure, and hand-rolled inline SVG (the `dashboard/app.js:139` sparkline precedent, extended with gap-breaking per D-06) |
| Font | existing system sans in light mode (`--font-sans`); existing system monospace in dark mode (`--font-mono`); chart axis ticks, tooltips, and numeric readouts always use `--font-mono` in both themes, matching the existing numeric-value convention |

No frontend build step, charting library, icon package, or third-party registry is introduced. Every
new element reuses `dashboard/style.css`'s existing custom properties, `dashboard/advanced.css`'s
`.evidence-row`/`.evidence-list`/`.diagnosis-card`/`.service-filters` class vocabulary, and the
Phase 3 `.section-navigation` shell. New class names extend these families (e.g. `.hist-chart`,
`.hist-coverage-strip`, `.incident-row`) rather than starting a competing one.

---

## Spacing Scale

Declared values (multiples of 4), reused unchanged from Phase 3/03.1:

| Token | Value | Usage |
|-------|-------|-------|
| xs | 4px | Coverage-strip segment gaps, marker/tick internal padding, badge padding |
| sm | 8px | Gap between a chart and its coverage strip, gap between stacked charts' internal legend rows, evidence-row internal gaps |
| md | 16px | Gap between stacked host charts, gap between the state band and its latency chart, incident-row internal padding, filter-control gaps |
| lg | 24px | Gap between the range control and the chart stack, gap between the History chart stack and the Incidents list when both are reachable from the same scroll region |
| xl | 32px | Separation between the shared range-control header and section content |
| 2xl | 48px | Not used by this phase's additions |
| 3xl | 64px | Not used by this phase's additions |

**Chart dimension tokens** (declared here for consistency; not margin/padding but sized on the
same 4px rhythm):

| Token | Value | Usage |
|-------|-------|-------|
| Host/latency chart plot height | 96px | Each of the four stacked host-metric charts and the service latency chart |
| State band height | 32px | The horizontal online/offline/unknown/maintenance band (D-11) |
| Coverage strip height | 16px | Each per-chart coverage strip (D-06) |

**Exceptions:**
- Every interactive control this phase adds (preset range buttons, `Apply custom range`, drag
  handles, incident-row `Show transitions` disclosure, filter controls, `Back`) keeps a minimum
  44px by 44px hit target at narrow (`< 720px`) viewport widths, matching the existing site-wide
  narrow-action rule.
- The coverage strip and hover-cursor readout are visual/informational only and are exempt from
  the 44px rule; their keyboard-operable equivalents are explicit Phase 5 debt (R-03) — see Layout
  and Responsive Contract note below.
- **Coverage-strip minimum segment width is 3px (not a multiple of 4).** This is a deliberate
  departure from the 4px rhythm: at the 90d preset, sub-pixel-duration coverage intervals would
  otherwise be merged away entirely or rounded up to the next 4px token (8px), which would either
  hide a distinct state reason or overstate how much time it actually covers. 3px is the minimum
  width at which all five state reasons remain independently visible as distinct segments at
  maximum zoom-out. See Chart Contract — Coverage Strip Mechanics.

---

## Typography

Every size below is an EXISTING measured value from Phase 3's four-size scale — no new size is
introduced.

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Metadata / axis tick / coverage-strip label | 12px, `--font-mono` | 400 | 1.5 |
| Body / incident row / filter label | 14px | 400 | 1.5 |
| Section heading (`History`, `Incidents`) | 20px | 600 | 1.2 |
| Range summary / trend headline (e.g. `disk +0.4%/day ↑`) | 28px numeric, `--font-mono`, paired with 14px unit/label | 600 | 1.2 |

No third font weight is introduced. Chart tooltips and the hover-cursor readout use the 12px mono
metadata size. Trend, latest, minimum, maximum, average values in the HIS-06 comparison row all use
the same 14px body size with the numeric portion in `--font-mono`; only the single primary
range-level headline value (if the design surfaces one, e.g. current service availability
percentage) uses the 28px size, matching Phase 3's page-title/count precedent.

---

## Color

Use the existing CSS variables (verified at `dashboard/style.css:5-21,24-37`). No new token is
created; two existing tokens gain new, explicit semantic roles for this phase, following the exact
pattern 03.1 used for `--accent3`.

**Color distribution:** 60% dominant (`--bg`), 30% secondary (`--bg2`/`--bg3`), 10% accent
(`--accent`, reserved for the interactive range/investigation controls listed below). Status
colors (online/offline/maintenance/unknown), threshold lines, incident markers, and coverage-strip
patterns are semantic overlays on top of that 60/30/10 split, not a competing distribution — they
occupy small, specific areas of the secondary (30%) surface, never the dominant background.

| Role | Value | Usage |
|------|-------|-------|
| Dominant (60%) | dark `--bg` `#010a14` / light `--bg` `#ffffff` | Page and section background (unchanged) |
| Secondary (30%) | dark `--bg2`/`--bg3` / light `--bg3` `#f7f7f7` | Chart plot backgrounds, coverage-strip track, incident-row background, filter-control backgrounds |
| Accent (10%) | dark `--accent` `#00d4ff` / light `--accent` `#0066cc` | Selected range preset, `Apply custom range`, the hover time cursor line and its readout, drag-selection rectangle border, `Back` (navigation-stack return), selected/focused filter control — an explicit, documented widening of Phase 3's accent reservation to cover this phase's new interactive range/investigation controls |
| Online (state band / status) | dark `--green` `#00ff88` / light `--green` `#16a34a` | State-band `online` segments only |
| Offline (state band / status) | dark `--red` `#ff3d3d` / light `--red` `#dc2626` | State-band `offline` segments; the unplanned-fault sub-segment of an overrun incident row (D-14) |
| Maintenance (state band / status) | dark `--accent3` `#7b6fff` / light `--accent3` `#5b21b6` | State-band `maintenance` segments; the grace-covered sub-segment of an overrun incident row; the `Expected` tag on a maintenance-tagged incident row — reused from 03.1's calm, non-fault register, never a button |
| Unknown (state band) | dark `--muted` `#3a7a96` / light `--muted` `#b0b0b0` | State-band `unknown` segments |
| Threshold reference line | `--muted` (dashed) in both themes | Temperature throttle points, disk capacity line (D-10) — deliberately NOT `--accent2` (warning), because a fixed documented constant is not a live alert; conflating the two would misrepresent a comfortable current reading as an active warning |
| Incident marker (shared-axis correlation) | `--muted` in both themes | Neutral markers on the host-chart shared axis (D-17) — never colored by severity or criticality; this is the mechanism that keeps a marker from implying a causal or severity claim |
| Coverage-strip segments | pattern + `--muted`/`--border2`, never a saturated color | See Chart Contract — no coverage reason is red/green/amber; all five reasons (plus the `storage_pressure` detail) are visually calm and distinguished by pattern and text label, not color weight |

**Accent reserved for (Phase 4 additions, explicit and exhaustive):** selected range preset button,
`Apply custom range`, the hover time cursor line and its point-in-time readout, the drag-to-select
rectangle's border (fill uses a low-opacity accent tint, never a solid fill), `Back` (D-15 stack
return), and a focused/selected filter control in the Incidents section. Do not use accent for
chart lines themselves, coverage-strip segments, incident markers, the state band, or ordinary
incident-row text — those carry their own vocabulary above.

**Explicit negatives (do not violate):**
- No coverage-strip reason is ever rendered in a status color (red/green/amber/accent). All five
  reasons plus `storage_pressure` are pattern-and-label only, on a muted/neutral palette — this is
  what keeps the strip legible as "explains why," not "another warning."
- Incident markers on the shared axis are never colored by event severity/criticality (`--muted`
  only). Coloring them by severity would read as an implicit causal/importance claim, which D-17
  explicitly forbids.
- Chart series lines themselves use `--accent` in dark mode and `--accent` (blue) in light mode —
  matching the existing sparkline precedent — regardless of metric; metrics are distinguished by
  their labelled chart, not by line color, since four differently-colored lines sharing one axis
  would misread as a legend the design does not provide.

---

## Layout and Responsive Contract

### Section navigation

- Two new entries, `History` and `Incidents`, are added to the existing `#section-navigation`
  immediately after `Services` and before `Pipeline`: `Overview, Host, Services, History,
  Incidents, Pipeline, Settings`. This ordering places the two range-aware sections as the natural
  continuation of "inspect current state" → "inspect its history," ahead of the meta/pipeline-health
  sections that remain current-state only (D-01).
- The nav rail/tab-list mechanics (persistent 224px rail at `>= 960px`, horizontal
  keyboard-scrollable tab list at `< 960px`) are unchanged from Phase 3 — no new responsive
  breakpoint is introduced.

### Shared range control

- A single range-control header sits above both `History` and `Incidents` (shared state per D-16),
  never duplicated per-section. It contains: the six preset buttons (`1h 6h 24h 7d 30d 90d`), the
  canonical local-time start/end fields (D-03), `Apply custom range`, and — only when the
  navigation stack (D-15) is non-empty — a `Back` control showing what range it returns to.
- Desktop (`>= 960px`): presets, fields, and `Apply custom range` sit on one row; `Back` (when
  present) sits on its own row above them, left-aligned, so a pushed incident/drag focus is never
  confused with the operator's own preset choice.
- Narrow (`< 960px`): the range control reflows into stacked rows — presets first (horizontally
  scrollable, each button keeping its 44px hit target), then the two custom-range fields side by
  side down to `~380px` inner width and stacked below that, then `Apply custom range`, then `Back`
  when present. No control is ever hidden at narrow width; nothing about range selection is
  progressive-disclosure gated.
- The active preset (or `Custom`) is always visibly indicated (selected/accent state on the
  button, or the fields carrying focus styling) — the operator must never be uncertain which range
  is currently governing the charts below.

### Focal points

- **Primary visual anchor on the `History` screen:** the four-chart stack (and, when a service is selected, the state band/latency pairing beneath it). The range control above it is a persistent but secondary utility strip — legible and reachable, never competing with the charts for attention.
- **Primary visual anchor on the `Incidents` screen:** the incident list. Filters sit above it as a secondary utility strip, matching the Services section's established filter-then-content weighting from Phase 3.

### Chart stack (`History` section, D-07)

- All four host-metric charts (CPU, memory, disk, temperature) render top-to-bottom in that fixed
  order, each with its own coverage strip immediately beneath its plot (D-06), sharing one
  continuous time axis drawn once at the bottom of the stack, not repeated per chart. Each chart
  keeps its own Y-axis, unit label, and — where applicable — threshold line(s) (D-10).
- Below the host stack, when a service is selected (D-16), the service state band (D-11) renders
  directly above its latency chart, sharing the same time axis as the host stack above it. Failure
  class counts render as a compact summary strip beside the state band, not inside either chart.
- At `< 960px`, charts remain full-width and stacked (no side-by-side layout ever existed for
  this stack, so narrow width changes only overall width, not arrangement); the shared time axis
  scrolls horizontally within its own labelled container if six-month-scale label density would
  otherwise overlap, matching the Phase 3 services-table horizontal-scroll pattern.
- **Keyboard/non-pointer equivalents for drag-to-select and the hover time cursor are explicit
  Phase 5 debt (R-03), not delivered in this phase.** This UI-SPEC does not claim keyboard parity
  for those two interactions; the canonical start/end fields remain the fully keyboard-operable
  path to any range, satisfying DIA-05 without them.

### Incidents list

- One column, full-width, below the range control (or in its own section route via nav). Each row
  is a fixed-height (min 44px, grows with content) card using `.diagnosis-card`/`.evidence-row`
  visual language, not a dense table — incident rows carry more prose than the Services table's
  compact cells warrant.
- Filter controls (service, criticality, event type, time range) sit above the list using the
  existing `.service-filters` grid pattern, with the existing `N of M` matching-count convention
  and a `Clear all filters` control (Phase 3 D-15 pattern, reused verbatim).
- At `< 720px`, filter controls stack to one column exactly as `.service-filters` already does;
  the incident-row layout collapses its inline metadata (duration, failure class, criticality) to
  a wrapped second line rather than truncating any of it.

---

## Chart Contract

### Gap honesty (D-06)

- A chart `<path>` never draws an `L` (line-to) command across two points that straddle any
  non-`observed` coverage interval — it emits a new `M` (move-to) instead, per Research Pattern 3.
  This applies uniformly to all four host charts and the service latency chart.
- Line-drawing is gated exclusively on `coverage[i].state === 'observed'`; `expired`,
  `not_yet_monitored`, and `unknown` are equally "do not draw a line here" states as
  `collection_gap` — never inferred from the absence of the `collection_gap` reason alone.

### Coverage strip mechanics (D-06, Claude's Discretion resolved)

One strip per chart, 16px tall, positioned directly beneath its plot on the shared time axis.
Each of the five wire states, plus the `storage_pressure` detail under `collection_gap`, gets its
own pattern **and** text label — never color alone, and never a status color:

| Wire `state` | Wire `detail` | Pattern | Label |
|---|---|---|---|
| `observed` | — | no segment rendered (line is drawn) | — |
| `collection_gap` | (absent) | dotted fill | `Collection gap` |
| `collection_gap` | `storage_pressure` | diagonal hatch | `Storage pressure (no persistence)` |
| `unknown` | — | dashed outline, hollow fill | `Unknown` |
| `expired` | — | thin diagonal stripe | `Expired (outside retention)` |
| `not_yet_monitored` | — | solid muted fill (no pattern) | `Not yet monitored` |

- **Minimum segment width:** every rendered segment is at least 3px wide, regardless of its true
  time span. At the 90d preset, multiple adjacent same-reason sub-pixel intervals are visually
  merged into one 3px-minimum segment; the merged segment's `title`/tooltip discloses the true
  count and total duration (e.g. `Collection gap — 4 intervals, 6 minutes total`), so compression
  never overstates or hides how much is actually missing.
- Adjacent segments of *different* reasons are never merged, even if both would be sub-pixel —
  each keeps its own minimum-width slot, preserving the exhaustive five-state partition on screen.
- A shared strip beneath the stacked group is explicitly rejected (D-06) — coverage is
  metric-specific and each chart's strip reflects only its own metric's `coverage[]` array.

### Threshold lines (D-10)

- **Temperature chart only:** two dashed reference lines at the Raspberry Pi's documented default
  thermal throttle points — **80°C** (soft throttle, frequency capping begins) and **85°C** (hard
  throttle limit). Each line's label/tooltip discloses its source: `Raspberry Pi documented
  default soft/hard thermal throttle point — not a Beacon-configured alert.`
- **Disk chart only:** one dashed reference line at **100% of the filesystem-reported disk
  capacity** (`disk_total`, the same value already used for the current dashboard's disk gauge).
  Label/tooltip: `Filesystem-reported total capacity — the disk cannot exceed this line.` This is
  the one line that is a physical fact rather than a manufacturer default.
- **CPU and memory charts get no threshold line**, per D-10 — Beacon has no configurable
  host-metric thresholds anywhere (`dashboard/beacon/config.py:28-76`) and inventing a percentage
  for visual symmetry would assert a fact Beacon cannot justify.
- If host thresholds ever become configurable, the line follows config — an additive change, not
  a reversal of this contract.

### Trend, latest, and comparison values (D-08, D-09, HIS-06 — Claude's Discretion resolved)

- **Slope computation:** least-squares over observed points only, expressed per-hour when the
  selected range is `<= 24h` and per-day for `7d/30d/90d`.
- **Minimum observed-point count:** fewer than 3 observed points in the range → withhold the
  trend entirely, showing `Not enough data for a trend` in place of the value. 3–9 observed
  points → show the slope with an explicit low-confidence qualifier: `{metric} {sign}{value}/{unit}
  {arrow} (low confidence — {N} points)`. 10 or more observed points → show the slope with no
  qualifier: `{metric} {sign}{value}/{unit} {arrow}` (e.g. `disk +0.4%/day ↑`).
- **Flat/steady band:** if the slope's total predicted change over the display window rounds to
  `0` at the displayed precision, render `steady` (no arrow, no sign) rather than a misleadingly
  precise `+0.0%/day`.
- **Latest:** always the latest *observed* point within the selected range, never "now." The
  exact timestamp of that latest point renders directly beside the value at all times — e.g.
  `Latest: 42% (as of 14:32, Aug 24)` — so a range ending in the past can never be read as a
  current reading (D-09).
- Minimum/maximum/average describe the same selected-range window as Latest and Trend; all four
  values (plus Latest) render together in one compact comparison row per chart, using the 14px
  body/mono size.

---

## Service History Contract (D-11)

- The state band is a single horizontal bar, 32px tall, spanning the shared time axis, using the
  existing four-state vocabulary (`online`/`offline`/`unknown`/`maintenance`) and its existing
  color mapping (green/red/muted/`--accent3`) — no new state or color is introduced.
- Hovering or focusing a band segment discloses its exact start/end timestamps and duration in a
  tooltip; each segment additionally carries a `title` attribute with the same text for
  non-pointer disclosure.
- Failure classes render as a compact horizontal list of `{class}: {count}` chips beside the band
  (reusing the existing failure-class vocabulary verbatim: `http_{code}`, `invalid_target`,
  `invalid_url`, `not_responding`, `timeout`, `connection_error`, `request_error`, `probe_error`),
  never inside the latency chart.
- The latency chart sits directly beneath the band on the identical time axis, using the same
  gap-breaking (D-06) and coverage-strip mechanics as the host charts. State shading never appears
  inside the latency plot — its background stays the plain plot background, preserving the
  coverage strip's exclusive claim on that visual channel (D-11's explicit rejection).

---

## Incidents Contract (D-12, D-13, D-14)

### Row anatomy

- One row = one grouped down→recovered episode: service name/port, start (`down_since_ts`),
  duration, end (recovery timestamp or absent), failure class, criticality, and — when the
  episode is maintenance-tagged — an `Expected` chip in the Maintenance color.
- **Open (unresolved) incident:** an episode with no matching recovery row renders duration as
  `Ongoing` (never a synthesized end-time or duration computed against "now"), carries a distinct
  `▶ Ongoing — not yet recovered` text-and-glyph badge (never color alone), and sorts to the top
  of its default ordering. This is an honest, explicit representation per D-12/Pitfall 4 — never
  backfilled with the query's `end_ts` or the current time.
- **Overrun incident (D-14):** the row's visual duration bar spans the full
  `down_since_ts → recovered_ts`, split into two sub-segments: the grace-covered portion in the
  Maintenance color and the post-grace unplanned-fault portion in the Offline/red color. Both
  timestamps (`down_since_ts` and `maintenance_grace_until`/raised-at) render as separate text
  lines beside the bar — never merged into one string, and the row's displayed total duration
  always equals the same span the availability figure attributes to this service (Pitfall 5).
- **Flapping services (Claude's Discretion resolved):** no new durable record and no merged row.
  When 3 or more episodes for the same service fall within any 15-minute span in the currently
  filtered list, each episode still renders as its own row, but consecutive rows meeting that
  condition gain a shared, purely presentational `Flapping — {N} episodes in {span}` banner
  directly above the group. The banner is a display-time grouping label only; it filters nothing
  and creates no new row.
- Underlying individual transitions are available via a `Show transitions` disclosure
  (`aria-expanded`) on each row, listing the raw `state_change` events that compose the episode.

### Maintenance visibility (D-13)

- Maintenance-suppressed entries are **shown by default** in this list, visibly tagged `Expected`
  — the opposite default of the main dashboard's hidden-by-default feed (03.1 D-10). The
  event-type filter can exclude them, but nothing is hidden without an explicit operator action
  here. Each surface's own default is stated in its own empty/loading copy so neither reads as the
  other's bug (R-05).

### Filters (HIS-04, Claude's Discretion resolved)

- Four filters — service, criticality, event type, time range — combine with AND semantics
  (narrowing, never widening), following Phase 3 D-15's established filter pattern.
- **Default state:** no filters applied; the current shared range (from the range control) is the
  only active bound, and the event-type filter defaults to including maintenance-tagged entries
  (consistent with the shown-by-default rule above).
- `N of M incidents` matching-count renders above the list at all times; `Clear all filters`
  resets every filter but leaves the shared range untouched (range is not a "filter" in this
  control's scope — it is the investigation context itself, per D-16).

---

## Investigation Context and Correlation Contract (D-15, D-16, D-17, D-18)

### Navigation stack

- Selecting an incident, or completing a drag-to-select gesture on any host or service chart,
  pushes one entry onto an in-memory navigation stack: `{ range, origin: 'incident'|'drag',
  label }`. A visible `Back` control (accent-colored, in the shared range-control header) appears
  whenever the stack is non-empty and pops exactly one entry, restoring the previous range.
- **Incident push padding (Claude's Discretion resolved):** the pushed window is the incident's
  own `down_since_ts → recovered_ts` span (or `down_since_ts → now` for an open incident, capped
  at the current shared range's own end), padded by **15% of the episode's own duration on each
  side, with a floor of 5 minutes per side** — so very short incidents (a 1-minute blip) remain
  legible with meaningful surrounding context, and long incidents aren't padded into an
  unreasonably wide window.
- The stack lives entirely in memory/`localStorage` (never the URL, per D-18) and is cleared when
  the operator manually changes the range via a preset button or `Apply custom range` — a manual
  range change is a fresh investigation, not a continuation of the drill-down chain.

### Carried service selection (D-16)

- A service selected in the Phase 3 Services table becomes the subject of the History/Incidents
  service-scoped views, and vice versa — read-only, changing no Phase 3 payload or contract. The
  carried value renders as a small, persistent "Investigating: {service}" indicator in the History
  section header, with a `Clear` action that unsets the selection without touching the range.
- No Phase 3 section ever recomputes against a historical bound because of this carried value —
  Phase 3's five sections remain strictly current-state (D-01/D-16).

### Correlation presentation (D-17)

- The shared time axis plus neutral (`--muted`) incident markers is the persistent "when did
  things happen" signal; a hover time cursor (accent-colored vertical line, `requestAnimationFrame`
  throttled per Research Pitfall 3) tracking across all stacked charts and the state band at once
  is the "what was true at that moment" signal. Cursor movement updates only the cursor line and a
  single shared readout panel's text content — chart `<path>` elements are never regenerated on
  `pointermove`.
- **Dense incident period degradation:** when incident markers on the axis would overlap at the
  current zoom/resolution, adjacent markers collapse into a single cluster glyph showing a count
  (`+N`), which expands to a small disclosure list on hover/focus rather than a scrollable
  saturated axis.
- **No causal wording anywhere.** The following words/phrases are forbidden in any Phase 4 copy,
  label, tooltip, or generated string: "causes", "caused by", "due to", "because of", "led to",
  "resulted in", "triggered by". Correlated evidence is described only as co-occurring in time
  (e.g. `Temperature rose while CPU was elevated in this window` — never `Temperature rose because
  CPU spiked`).

### Timezone display (D-05)

- Every historical timestamp — chart axes, tooltips, incident rows, custom-range fields — renders
  via `Intl.DateTimeFormat(undefined, { timeZone: cfg.timezone, ... })` once `/api/config` exposes
  the Pi's configured `timezone` string (Research Pitfall 1). Bare `toLocaleString()` (the existing
  `dashboard/advanced.js:87`/`dashboard/app.js:34` pattern) is never copied into Phase 4 code.
- **DST ambiguous/absent hour:** axis tick generation detects where two adjacent local-time labels
  would read identically (fall-back) or where an expected local hour is skipped (spring-forward)
  and marks that segment with an explicit `⚠ DST transition` tick annotation rather than silently
  rendering a normal-looking axis (Research Pitfall 6).

---

## Copywriting Contract

| Element | Copy |
|---------|------|
| Primary CTA (range control) | `Apply custom range` |
| Preset range labels | `1h`, `6h`, `24h`, `7d`, `30d`, `90d` (exact ladder, D-02) |
| Back control | `Back to {previous range label}` |
| Investigating-service indicator | `Investigating: {service name}` with a `Clear` action |
| Empty History (no data in range) | `No {metric} data in this range.` — `Beacon has no observations, gaps, or expiry evidence for this window.` |
| Empty Incidents (no matches) | `No incidents match this range and these filters.` — `Clear filters to see every recorded incident in this range.` |
| Loading state | `Loading historical investigation…` with skeleton chart/row placeholders; never show zeroed charts or empty bands while loading |
| Error state (chart fetch failed) | `This chart could not load. {metric} data is unavailable — other charts and the coverage evidence below are unaffected.` (per-metric partial failure, Research Pattern 1) |
| Error state (incidents fetch failed) | `Beacon could not load incidents for this range. Try again, or narrow the range.` |
| Trend — insufficient data | `Not enough data for a trend` |
| Trend — low confidence | `{metric} {sign}{value}/{unit} {arrow} (low confidence — {N} points)` |
| Trend — normal | `{metric} {sign}{value}/{unit} {arrow}` e.g. `disk +0.4%/day ↑` |
| Trend — flat | `{metric} steady` |
| Latest with range disambiguation | `Latest: {value} (as of {exact local timestamp})` |
| Coverage strip labels | `Collection gap`, `Storage pressure (no persistence)`, `Unknown`, `Expired (outside retention)`, `Not yet monitored` (exact wire-state → label mapping in Chart Contract) |
| Coverage strip merged-segment tooltip | `{Reason} — {N} intervals, {duration} total` |
| Threshold line — temperature | `Raspberry Pi documented default soft/hard thermal throttle point — not a Beacon-configured alert.` |
| Threshold line — disk | `Filesystem-reported total capacity — the disk cannot exceed this line.` |
| Open incident badge | `▶ Ongoing — not yet recovered` |
| Flapping banner | `Flapping — {N} episodes in {span}` |
| Overrun row timestamps | `Down since {exact timestamp}` and `Raised at {exact timestamp}` — always two separate lines |
| Maintenance-tagged incident chip | `Expected` |
| Incidents matching-count | `{N} of {M} incidents` |
| Incidents clear filters | `Clear all filters` |
| Show/hide transitions | `Show transitions` / `Hide transitions`, with `aria-expanded` |
| DST transition tick annotation | `⚠ DST transition` |
| Correlation copy pattern | `{Metric A} rose while {Metric B} was elevated in this window` — co-occurrence phrasing only, see Investigation Context Contract for the full forbidden-word list |
| Destructive confirmation | Not applicable — Phase 4 exposes no destructive actions, remote control, or monitoring mutations; every route is GET-only, matching D-18's scope note |
| Incidents event-type narrowing note | `Incident rows are grouped from every state change in this range; the Event type filter keeps only incidents with a matching event during the incident.` |
| Incidents maintenance narrowing note | `Expected-maintenance filtering applies to each incident's own opening event, so an incident that began during maintenance is filtered as expected maintenance.` |
| Custom range — nonexistent local time | `That local time does not exist on this date — the clock jumps forward here (DST). Enter a time outside the absent hour.` |
| Incidents matching-count — unfiltered total unavailable | `{N} of ? incidents (total unavailable)` |

The three rows above were added by gap-closure plan 04-10. The first two disclose, on screen, the
episode-scope narrowing semantics plan 04-09 introduced (`episode_scope.narrowed_by`) — closing the
gap where the Incidents section changed count without stating the rule by which the Event type or
expected-maintenance filter narrowed the already-grouped episode list. The third is the one
client-only message in the range control: every other `validateCustomRange` message is a verbatim
copy of a server rejection string, but the server takes epoch integers and has no equivalent
rejection to copy for a wall-clock time its own zone never reaches.

The fourth row above was added by gap-closure plan 04-11. The `{N} of {M}` row above it (`Incidents
matching-count`) describes only the state where both the filtered read and the unfiltered baseline
read succeed; this row is the state where the baseline read failed and the total is genuinely
unknown — the count says so rather than reusing the filtered number as though it were the total,
the same disclosure policy `Correlation markers unavailable for this range` already applies to the
marker rail's own baseline fetch.

---

## UI Considerations

Applicable state considerations: **36 applicable, 36 resolved (explicit), 0 backstop, 0 unresolved.**

Derived from the post-verification UI-consideration probe over five surfaces. Element kinds were
confirmed by the operator rather than taken from the prose classifier alone — E2/E3 were additionally
classified `media` + `interactive-control`, E4 `form` + `static-content`, and E5 `static-content`,
which raised four considerations the heuristic alone would have missed.

Empty-state and error-state COPY lives in `## Copywriting Contract`; the rows below cover shape-rooted
STATE coverage and reference that copy rather than restating it.

| Category | Element(s) | Status | Resolution / Reason |
|----------|------------|--------|---------------------|
| empty, loading, error, populated, partial, overflow, zero-one-many, long-text | E1 — Range control (presets, custom fields, `Apply`, `Back`) | ✅ resolved (explicit) | Documented empty/invalid-range validation reuses server-side `HistoricalRange` rejection copy; loading disables `Apply` without hiding fields; `Back` renders only when the stack is non-empty; long custom-range labels wrap within the header row rather than overlapping controls. |
| empty, loading, error, populated, partial, overflow, long-text | E2 — Host chart stack (4 charts + coverage strips) | ✅ resolved (explicit) | Per-metric partial fetch failure is isolated (Research Pattern 1) and shown per chart; loading uses skeleton plot/strip placeholders; gap-drawing and merged sub-pixel strip segments are documented in the Chart Contract; long threshold-line labels wrap in their tooltip, never on the axis itself. |
| **zero-one-many** | E2 — Host chart stack | ✅ resolved (explicit) | All four charts always render in the fixed CPU → memory → disk → temperature order regardless of how many metrics have retained data. A metric with no data in the selected range renders its chart frame with the documented empty copy; it is never omitted. Stack height and metric order are therefore stable across every range, and an absent sensor is visibly distinguishable from a rendering failure. |
| empty, loading, error, populated, partial, overflow, long-text | E3 — Service state band + latency chart | ✅ resolved (explicit) | Band/latency share the host stack's loading/error/partial handling; failure-class chip list wraps to a second line at narrow widths rather than truncating; an unselected service renders an explicit `Select a service to view its history` placeholder instead of an empty band. |
| **zero-one-many** | E3 — Service state band + latency chart | ✅ resolved (explicit) | A single uninterrupted state spans the full band width with one duration label. Zero observations render the `unknown` fill across the entire band rather than a blank strip, so "we did not observe" is never shown as "nothing happened". Failure-class chip counts use explicit singular/plural copy (`1 failure class` / `{N} failure classes`). |
| empty, loading, error, populated, partial, overflow, zero-one-many, long-text | E4 — Incidents list and filters | ✅ resolved (explicit) | Documented empty/error copy above; `N of M` count and `Clear all filters` cover zero-one-many; open, overrun, and flapping rows are explicitly defined states (never inferred); long service names/error-class text wrap within the row, matching the existing `.evidence-row` `overflow-wrap: anywhere` rule. The `partial` category now covers a failed unfiltered-baseline read (04-11): the filtered list still renders and the count states the total is unknown, so a partial failure degrades one number rather than the view. |
| overflow, long-text | E5 — Investigation context (carried service, navigation stack, correlation markers/cursor) | ✅ resolved (explicit) | Dense-marker clustering degrades to a count glyph rather than saturating the axis; the `Investigating: {service}` indicator and `Back` label truncate with a full-string tooltip rather than pushing the header layout; the forbidden-word list is a static, testable constraint (DIA-07). |
| **loading** | E5 — Investigation context | ✅ resolved (explicit) | The `Investigating: {service}` indicator and `Back` control render immediately from client-side navigation state and stay visible throughout — they require no fetch. Correlation markers and the shared hover time cursor are suppressed until their underlying charts finish loading, so a marker is never plotted against a skeleton axis. |
| **error** | E5 — Investigation context | ✅ resolved (explicit) | The indicator and `Back` control remain usable so the operator can navigate back out of a failed investigation. Correlation markers are omitted and the chart area carries an explicit `Correlation markers unavailable for this range` note — a silently marker-free chart is forbidden, because it reads as "nothing correlated" rather than "Beacon could not check". |

---
## Registry Safety

| Registry | Blocks Used | Safety Gate |
|----------|-------------|-------------|
| none | none | not applicable — the project is dependency-free vanilla JavaScript and no third-party registry is declared |

---

## Checker Sign-Off

- [x] Dimension 1 Copywriting: PASS
- [x] Dimension 2 Visuals: PASS
- [x] Dimension 3 Color: PASS
- [x] Dimension 4 Typography: PASS
- [x] Dimension 5 Spacing: PASS
- [x] Dimension 6 Registry Safety: PASS

**Approval:** approved 2026-08-25
