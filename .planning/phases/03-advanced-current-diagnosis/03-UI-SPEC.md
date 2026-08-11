---
phase: 03
slug: advanced-current-diagnosis
status: draft
shadcn_initialized: false
preset: none
created: 2026-08-11
---

# Phase 03 — UI Design Contract

> Visual and interaction contract for the read-only `/advanced` current-diagnosis workspace. This contract preserves the established dashboard theme token system and safety-warning order.

---

## Design System

| Property | Value |
|----------|-------|
| Tool | none — retain the existing dependency-free HTML, CSS, and vanilla JavaScript architecture |
| Preset | not applicable |
| Component library | none |
| Icon library | none; use concise text labels and native disclosure markers |
| Font | existing system sans in light mode; existing system monospace in dark mode |

Do not add a frontend build step, third-party component package, icon package, or third-party registry for this phase. Reuse `dashboard/style.css` custom properties and the existing `beacon-theme` local-storage key.

---

## Spacing Scale

Declared values (all multiples of 4):

| Token | Value | Usage |
|-------|-------|-------|
| xs | 4px | Icon/text gaps, status-dot gaps, compact tag padding |
| sm | 8px | Table-cell internals, filter/control gaps, compact row separation |
| md | 16px | Default card padding, form/control groups, summary-grid gaps |
| lg | 24px | Workspace section padding and desktop panel gaps |
| xl | 32px | Separation between overview groups and page regions |
| 2xl | 48px | Major detail-section breaks |
| 3xl | 64px | Top-level page breathing room on desktop |

Exceptions: all icon-only and compact controls retain a minimum 44px by 44px hit target; table rows are at least 44px high before an expanded detail area. This preserves the established narrow-dashboard action target rule.

---

## Typography

Use only these four sizes in new advanced-workspace UI. Numeric values, timestamps, ports, error classes, and cadence values use the active theme’s existing mono treatment; readable prose uses the active theme’s base font.

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Metadata / compact label | 12px | 400 | 1.5 |
| Body / table cell | 14px | 400 | 1.5 |
| Section heading | 20px | 600 | 1.2 |
| Page title / exception count | 28px | 600 | 1.2 |

No third font weight is introduced. Uppercase tracking may continue the dark dashboard’s compact HUD language for metadata only; it must not be the only semantic indication of a state.

---

## Color

Use the existing CSS variables; the paired values below make the same visual roles explicit in both themes.

| Role | Value | Usage |
|------|-------|-------|
| Dominant (60%) | dark `#010a14` / light `#ffffff` | Page background and primary workspace surface |
| Secondary (30%) | dark `#030f1e` and `#041525` / light `#f7f7f7` | Navigation rail, grouped cards, table header, expanded diagnostic panels |
| Accent (10%) | dark `#00d4ff` / light `#0066cc` | Selected section, keyboard focus, selected filter/control, `Refresh now`, and direct Dashboard return link |
| Warning | dark `#ffab00` / light `#b45309` | Existing connection, worker, and recovery warnings; aging and actionable collection-gap labels |
| Healthy | dark `#00ff88` / light `#16a34a` | Explicit fresh / healthy service and job labels only |
| Destructive | dark `#ff3d3d` / light `#dc2626` | Failed / stale / critical-failure state text and indicators; no destructive action is offered in this phase |

Accent reserved for: selected navigation, focus indicators, selected filters, the `Refresh now` action, and the Dashboard return link. Do not use accent for ordinary service status, warning, criticality, or body text. Every status pairs color with a text label and a non-colour marker.

---

## Layout and Responsive Contract

- Route: open the advanced workspace in the same tab at `/advanced`; the dashboard top bar exposes an `Advanced diagnosis` link in both themes. The advanced header exposes a `Dashboard` return link and restores the captured dashboard scroll position when practical.
- Desktop (`>= 960px`): use a persistent 224px left section rail and a fluid main detail column. The header remains visible above both; the selected section replaces the main detail region without a full document reload.
- Narrow (`< 960px`): make the section rail a single horizontal, keyboard-scrollable tab list immediately under the header. Keep the selected tab visible and preserve all section destinations; do not hide any diagnostic field due to viewport width.
- Service table: use fixed visible columns for Name + port, Status, Latency / failure class, State duration, Criticality, and Freshness. At `< 960px`, allow the table to scroll horizontally in its own labelled container; keep Name + port sticky at the inline start. Never convert services back to preview cards.
- Summary cards: Overview presents active exceptions first, then a 3-column Host / Services / Collection Health summary grid. At `< 720px`, summaries stack in one column; cards retain md padding and no content overlaps.
- Long service names and failure classes: one-line ellipsis in collapsed rows with the complete string available in the expanded row and programmatic accessible name. Tags wrap in expanded detail; error evidence wraps at word boundaries. Table filters and navigation labels do not wrap into overlapping controls.
- Light mode uses comfortable section spacing and progressive disclosure; dark mode starts compact. Density is user-overridable in either theme, never changes available fields, and is stored with other explicit advanced preferences.

---

## Workspace and Interaction Contract

### Header and refresh controls

- Preserve the existing static safety-warning cluster at the very top in this exact order: connection unavailable, worker unavailable, recovery required. Each remains independently visible; a healthy item must never suppress another active warning.
- The workspace header contains: `Dashboard`, page title `Advanced diagnosis`, last successful update in relative time plus its exact timestamp in a native tooltip/detail, refresh interval select, `Pause`, and primary `Refresh now`.
- Interval choices are 5 seconds, 15 seconds (default), 30 seconds, and 60 seconds. `Pause` stops scheduled browser polling only; `Refresh now` performs one bounded read refresh while paused or running. Show `Updates paused` beside the last-successful-update time when paused.
- On a refresh failure, retain the last successful screen, show the error state in the affected region, and keep `Refresh now` available. Never imply that displayed data was newly fetched when it was not.

### Sections

| Section | Required content and behaviour |
|---------|--------------------------------|
| Overview | Active exceptions first: critical/down services, stale or unknown streams, worker/recovery safety conditions, actionable collection gaps, failed or overdue jobs, and storage pressure. Each item names its affected service/stream, state, relative age or duration, and links to its owning section. Follow with compact Host, Services, and Collection Health summaries. |
| Host | CPU, memory, disk, temperature, hostname/host identity, current sample timestamp, relative age, freshness label, and expected configured cadence. Do not render a history chart in this phase. |
| Services | One sortable table of all configured or discovered services with multi-row expansion. Default sort is critical failures, other failures, stale/unknown, then healthy; preserve configured pinned order within each group. The table supports text search on service name, port, or tag and combinable Status, Criticality, Freshness, and Tag filters. |
| Pipeline | Effective 7-day raw / 5-minute through day 30 / hourly through day 90 retention, displayed resolution, retention expiry, database-pressure state, worker heartbeat/freshness, open and recent actionable collection gaps, resolved historical gaps, and every background job’s last run, next expected run/cadence, state, and error evidence. Pending aggregation is separate from observed coverage. |
| Settings | Read-only effective monitoring settings plus presentation controls: density, refresh interval, range preference, and service filters. Clearly label controls as local presentation preferences; provide no remote-control, monitoring-mutation, or service-action control. |

### Service diagnosis

- Collapsed service rows show Name + port, textual status with marker, latency when healthy or failure class when not, `up/down since` duration, criticality, and freshness. All rows expose an explicit `Show details` / `Hide details` control with `aria-expanded`.
- Expanded rows show tags, full effective health rule, exact last probe timestamp, expected probe cadence, TLS posture as a trust annotation separate from availability, last error evidence, and any applicable freshness or collection-gap evidence. Multiple rows may remain expanded; `Collapse all details` appears when at least one is open.
- Column sorting is keyboard operable. Activating a sortable column toggles ascending/descending order and announces the field/direction. A user sort supersedes default operational ordering until filters are cleared, the table is refreshed, or the user chooses `Reset operational order`.
- Filters apply immediately without a network mutation, always expose `N of M services`, and include `Clear all filters`. Persist filter values, not expanded rows or transient exception selections.

### Freshness and evidence vocabulary

- Each host, service, worker, and pipeline stream uses exactly one current freshness label: `fresh`, `aging`, `stale`, or `unknown`.
- Calculate labels from the server-provided expected cadence: fresh at age `<= 1 × cadence`; aging at `> 1 ×` and `<= 4 × cadence`; stale at `> 4 × cadence`; unknown if no valid timestamp/cadence exists. With current defaults, host and worker turn stale after 20 seconds. A collection gap may become actionable after two missed expected observations and must be shown as a separate fact rather than changing an evidence label silently.
- Always show relative age in the collapsed/summary surface and exact timestamp plus expected cadence in detail. `Stale` never asserts a cause. If a stream is stale while the worker heartbeat is fresh, state both facts and direct the operator to Pipeline job/cadence evidence.
- Collection gaps are promoted to Overview only while open or recently resolved and still actionable. Older resolved gaps remain in Pipeline detail. Unknown, pending aggregation, retention expiry, and collection gaps use their distinct Phase 2 terms; do not interpolate or merge them.

### Preference persistence and navigation

- Persist only explicit advanced preferences in `localStorage` under a versioned key such as `beacon-advanced-preferences-v1`: refresh interval/pause state, density, range, and filter values. Keep the existing `beacon-theme` key unchanged.
- Do not persist expanded table rows, in-page warning selection, transient error banners, or live data. Theme carries from Dashboard to `/advanced` and back without any user action.
- Use native buttons for refresh, pause, filter clear, sorting, and disclosure; use links for navigation. Initial focus on a section change moves to that section heading; return link restores dashboard scroll before receiving focus when feasible.

---

## Copywriting Contract

| Element | Copy |
|---------|------|
| Primary CTA | `Refresh now` |
| Pause control | `Pause` when polling; `Resume updates` when paused |
| Empty services heading | `No services match these filters` |
| Empty services body | `Clear filters to view every monitored service, or wait for the next discovery result.` |
| Empty exceptions | `No active exceptions` — `Host, services, and collection pipeline are reporting normally.` |
| Loading state | `Loading current diagnosis…` with skeleton rows/cards; never show zeros or healthy placeholders while loading |
| Error state | `Beacon could not refresh current diagnosis. Showing data from {last successful time}. Check the connection warning, then try again.` |
| Partial-data state | `Some current-state evidence is unavailable. Available values are shown; see freshness and pipeline details for timestamps and cadence.` |
| Stale-stream state | `This stream is stale. Its last sample was {relative age}; expected every {cadence}.` |
| Worker-fresh / stream-stale evidence | `The worker heartbeat is fresh, but this stream is stale. Review its cadence and background-job evidence.` |
| Destructive confirmation | Not applicable — Phase 3 exposes no destructive actions, remote control, or monitoring mutations. |

---

## UI Considerations

Applicable state considerations resolved: 22 covered, 0 backstop, 0 unresolved.

| Category | Element(s) | Status | Resolution / Reason |
|----------|------------|--------|---------------------|
| loading | Workspace route and section detail | ✅ covered | The initial document uses labelled skeleton cards/rows and `Loading current diagnosis…`; prior values remain visible during refresh. |
| error | Workspace route and section detail | ✅ covered | A failed bounded read retains last successful values, reports the supplied error copy, and offers `Refresh now`. |
| empty | Active-exception collection | ✅ covered | Overview renders the documented `No active exceptions` state instead of an empty gap. |
| populated | Active-exception collection | ✅ covered | Exceptions are ordered by operational urgency, name their affected item, and link to the owning section. |
| overflow | Active-exception collection | ✅ covered | The collection remains vertically scrollable after the summary viewport; individual evidence wraps without overlap. |
| zero-one-many | Active-exception collection | ✅ covered | Count language is singular/plural aware; zero uses the empty state, one retains the same exception-card layout, and many preserve priority order. |
| loading | Host summary and detail | ✅ covered | Four labelled metric skeletons display until a current sample and freshness evidence are received. |
| error | Host summary and detail | ✅ covered | The Host panel keeps last valid metrics and displays the common error state rather than replacing values with zero. |
| partial | Host summary and detail | ✅ covered | Missing temperature or identity fields render `Unavailable` with timestamp/cadence evidence while other host fields remain visible. |
| long-text | Host identity and settings values | ✅ covered | Hostnames/settings wrap at word boundaries; canonical values remain selectable and never overlap labels. |
| empty | Service table/filter result | ✅ covered | The documented service-empty copy distinguishes a zero match from a loading failure. |
| loading | Service table | ✅ covered | Skeleton rows preserve the table’s visible column structure while service evidence loads. |
| error | Service table | ✅ covered | The table retains prior rows on refresh failure and shows the common error state above the filter bar. |
| populated | Service table and expanded diagnostics | ✅ covered | Rows follow locked operational ordering, expose all required collapsed fields, and support multiple expanded details. |
| partial | Service table and expanded diagnostics | ✅ covered | A missing latency, probe time, tag, or health rule renders `Unavailable`/`Not configured` in-place without inferring a healthy or failed value. |
| overflow | Service table and expanded diagnostics | ✅ covered | The table has labelled horizontal scroll below 960px, sticky Name + port, ellipsis in collapsed cells, and full wrapping values in details. |
| zero-one-many | Service table/filter result | ✅ covered | Result count reads `1 of 1 service` or `N of M services`; zero follows the empty state without changing layout semantics. |
| long-text | Search, filter chips, tags, failure/effective-rule text, navigation | ✅ covered | Tags wrap only in details; compact labels truncate with accessible full text; chips clip text before their remove/clear control. |
| loading | Pipeline and Settings | ✅ covered | Labelled skeleton rows show while durable diagnostics load; read-only controls remain disabled until their effective values are known. |
| error | Pipeline and Settings | ✅ covered | Last known effective settings and pipeline evidence remain visible with a timestamped refresh error. |
| partial | Pipeline and Settings | ✅ covered | Each unavailable stream/job/pressure value states `Unknown` and retains the available independent evidence. |
| overflow | Pipeline job list and settings values | ✅ covered | Job lists scroll vertically; cadence/error strings wrap within their value column and never clip a state label. |

---

## Registry Safety

| Registry | Blocks Used | Safety Gate |
|----------|-------------|-------------|
| none | none | not applicable — the project is dependency-free vanilla JavaScript and no third-party registry is declared |

---

## Checker Sign-Off

- [ ] Dimension 1 Copywriting: PASS
- [ ] Dimension 2 Visuals: PASS
- [ ] Dimension 3 Color: PASS
- [ ] Dimension 4 Typography: PASS
- [ ] Dimension 5 Spacing: PASS
- [ ] Dimension 6 Registry Safety: PASS

**Approval:** pending
