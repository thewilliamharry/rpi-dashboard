---
phase: 05
slug: theme-parity-analytics-experience
status: draft
shadcn_initialized: false
preset: none
created: 2026-08-26
---

# Phase 05 — UI Design Contract

> Visual and interaction contract for making the main dashboard and the `/advanced` workspace
> cohesive, responsive, accessible, and theme-equivalent. This is an **audit-and-extend** phase, not
> a build-new one — every mechanism it needs (the `html.light` token system, the
> `density-comfortable`/`density-compact` classes, the dual-theme Playwright test pattern, the
> focus-triggered tooltip idiom, the `role="button"` ARIA convention) already exists in the codebase
> in a directionally-correct form (`05-RESEARCH.md`). This contract does not reopen `05-CONTEXT.md`
> D-01/D-02/D-03; it applies them and resolves the questions `05-CONTEXT.md` explicitly left open.

---

## Design System

| Property | Value |
|----------|-------|
| Tool | none — dependency-free vanilla HTML, CSS, and JavaScript (unchanged); no frontend build step exists in this project |
| Preset | not applicable |
| Component library | none |
| Icon library | none — concise text labels, native `<title>`/`aria-label` disclosure, and hand-rolled inline SVG glyphs, matching Phase 3/4 precedent |
| Font | existing system sans in light mode (`--font-sans`); existing system monospace in dark mode (`--font-mono`); no change |

No frontend build step, charting library, icon package, or third-party registry is introduced. Every
new element this phase adds reuses `dashboard/style.css`'s existing custom properties, the
`.safety-warning`/`.diagnosis-card`/`.evidence-row` class vocabulary, and the `density-comfortable`/
`density-compact` mechanism (`03-CONTEXT.md` D-16, `dashboard/advanced.js:223-227`). New class names
extend these families (e.g. `.freshness-degraded`, `.hist-coverage-segment[tabindex]`) rather than
starting a competing one.

---

## Spacing Scale

Declared values (multiples of 4), reused unchanged from Phase 3/03.1/4 — **no new spacing token is
introduced this phase**:

| Token | Value | Usage |
|-------|-------|-------|
| xs | 4px | Badge/glyph internal padding, coverage-strip segment gaps (unchanged) |
| sm | 8px | Gap between a status glyph and its word, inline-badge padding |
| md | 16px | Gap between stacked sections (unchanged) |
| lg | 24px | Section padding (unchanged) |
| xl | 32px | `density-comfortable`'s `.advanced-detail` gap (unchanged, `advanced.css:30`) |
| 2xl | 48px | Not used by this phase's additions |
| 3xl | 64px | Not used by this phase's additions |

**Exceptions (unchanged from Phase 4, restated for this phase's new interactive elements):**
- Every interactive control this phase adds or makes keyboard-operable (the pending-anchor keyboard
  range gesture, the coverage-strip segment's new focus target) keeps the existing 44px minimum hit
  target at narrow (`< 720px`) viewports where it is a discrete control; the coverage-strip segment
  and the point-target hit-circle remain visual/disclosure-only and are exempt from 44px, exactly as
  Phase 4's UI-SPEC already establishes for the coverage strip and hover cursor.
- The new "Degraded" inline badge (see Copywriting Contract) is text, not a control, and carries no
  minimum hit-target requirement.

---

## Typography

Every size below is an EXISTING measured value — **no new size or weight is introduced this phase**:

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Safety banner (worker/recovery/connection/degraded) | 12px | 400 | 1.5 (`.safety-warning`, `style.css:60`, unchanged) |
| Status word / freshness word / new "Degraded" badge | 12px, `--font-mono` on the advanced workspace's freshness column | 400 | 1.5 |
| Body / incident row / filter label | 14px | 400 | 1.5 (unchanged) |
| Section heading | 20px | 600 | 1.2 (unchanged) |

The new "Degraded" state reuses the existing 12px metadata/safety-banner size in both its global-banner
form (main dashboard and advanced Overview) and its inline per-subject form (Services table freshness
column, Overview summary cards). No third weight and no new size is introduced.

---

## Color

Use the existing CSS variables (verified at `dashboard/style.css:5-21,24-37`). **No new token is
created.** The existing `--accent2` role (already shared by `.advanced-error`/`.advanced-partial`/
`.hist-error`/`.hist-range-error`/`.hist-dst-tick`/`.worker-warning`/`.recovery-warning`/
`.connection-banner`) gains one more, explicit member — `degraded` — following the same
disambiguate-by-copy-and-shape discipline those five already rely on (five distinct meanings already
share this one token, disambiguated by text and by container shape, never by hue).

| Role | Value | Usage |
|------|-------|-------|
| Dominant (60%) | dark `--bg` / light `--bg` | Page and section background (unchanged) |
| Secondary (30%) | dark `--bg2`/`--bg3` / light `--bg3` | Cards, chart plot backgrounds (unchanged) |
| Accent (10%) | dark `--accent` / light `--accent` | Interactive range/investigation controls (unchanged Phase 4 reservation); this phase's new keyboard pending-anchor marker reuses this exact token, never a new one |
| Fresh / online | `--green` | Unchanged |
| Offline / error / fault | `--red` / `--accent2` | Unchanged (see the box-vs-inline distinction below for the `error`/`degraded` collision) |
| Maintenance (calm, expected, non-fault) | `--accent3` | Unchanged — **never reused for `degraded`**, which is an unplanned condition, not an expected one; conflating the two would misrepresent an unplanned reduced-fidelity condition as calmly expected |
| Stale / unknown | `--muted` | Unchanged, extended to the new glyph-differentiated badges below |
| Degraded | `--accent2` (same token as `error`, differentiated by shape — see below) | New: the worker/host/service "aging" freshness tier's dedicated presentation, and the new global degraded banner |

**Explicit negative — the `error`/`degraded` collision is resolved by shape, not hue:** `--accent2`
already carries five meanings (partial-fetch, chart-fetch error, invalid custom-range input, a DST
axis anomaly, and the worker/recovery/connection safety banners). Adding `degraded` as a sixth would
make two of those six indistinguishable by color alone if nothing else changed, so this contract adds
one structural rule: **`error` is always a bordered box** (`.advanced-error`/`.hist-error`'s existing
`border: 1px solid var(--accent2)` treatment, unchanged); **`degraded` is always inline text with a
leading glyph, never boxed.** A boxed accent2 element always means "something failed to load"; an
inline accent2 badge always means "this loaded, but is running in a reduced-fidelity condition, not a
failure." This is testable per-theme via `getComputedStyle` (`display`/`border-style`), matching
OPS-06's existing verification pattern.

---

## Theme-Parity Contract

`05-CONTEXT.md` D-03 applies **only to the main dashboard**; the advanced workspace requires full
capability parity per criterion 2. This section states each surface's rule explicitly, per D-03's own
instruction not to conflate the two.

### Main dashboard (D-03 governs)

**Reachable and visible in both themes, unchanged:** arc gauges (CPU/RAM/disk, numeric percentage),
host identity/sample time, service cards' online/offline/maintenance status row (`.svc-online`/
`.svc-offline`/`.svc-maintenance-status`, always text + `.status-pip`), the uptime strip (segments,
with their existing per-segment `title` disclosure — see Accessibility Contract, Open Question 2
resolved below), the event feed, scan status, theme toggle, and every safety banner
(`connection-banner`/`worker-warning`/`recovery-warning`, plus this phase's new degraded banner).

**Deliberately dark-mode-only — a complete, exhaustive audit of every `html.light .foo { display:
none }` rule in `dashboard/style.css`, not a spot-check** (`[VERIFIED: grep for 'html\.light [^{]*{
display: none' across dashboard/style.css dashboard/advanced.css returns exactly 8 matches, no more]`):

| Element | Rule | Classification | Reasoning |
|---|---|---|---|
| `.arc-unit` (the static "%" glyph beside each gauge's number) | `style.css:296` | Decorative-only, not a parity defect | The number itself (`.arc-pct`) stays visible in both themes and is self-evidently a percentage in this gauge context; the unit glyph is redundant emphasis, not a distinct data point |
| `.sparkline` | `style.css:353` | Deliberate calm (D-03, named) | — |
| `.temp-row` | `style.css:363` | Deliberate calm (D-03, named) | — |
| `.corner` (HUD-corner sci-fi decoration) | `style.css:410` | Decorative-only, not a parity defect | Pure visual flavor, carries no data |
| `.svc-preview` | `style.css:437` | Deliberate calm (D-03, named) | — |
| `.svc-uptime-pct` (the "7d {pct}%" label on each service card) | `style.css:522` | **Deliberate calm — extending D-03 by the identical rationale, this UI-SPEC's own explicit resolution of `05-CONTEXT.md` Open Question 2** | Structurally the same category as the sparkline: a numeric analytics-history preview, not the core online/offline fact (which stays visible via `.svc-online`/`.svc-offline` regardless). D-03's own reasoning — "arc gauges alone satisfy UX-01... deliberate calm, not a parity defect" — applies identically here; this instance was not enumerated by name in `05-CONTEXT.md` because it required this phase's code audit to find, matching the CONTEXT's own instruction that the four named items are a starting list, not an exhaustive one |
| `.uptime-labels` (day-range labels under the strip) | `style.css:574` | Deliberate calm (D-03, named) | — |
| `.offline-badge` (the corner "OFFLINE" ribbon on an offline service card) | `style.css:583` | Decorative-only, not a parity defect | Redundant with `.svc-offline`'s text row, which stays visible and identically informative in both themes (`● OFFLINE`); the ribbon is emphasis, not the sole conveyor of the offline fact |

No other `html.light`/`html:not(.light)` rule anywhere in either CSS file sets `display: none` —
this list is exhaustive as of this research pass, not a starting checklist.

### Advanced workspace (full capability parity governs, criterion 2)

The workspace shell, section navigation, filters, and every Phase 3/4 investigation surface already
render from the same DOM/JS in both themes — theme is a CSS-only skin here (`05-RESEARCH.md`
"Current Theming Reality"). No `html.light` rule in `dashboard/advanced.css` hides any element (the
8-item audit above is exhaustive across *both* files, and none of the 8 falls inside
`advanced.css`). **The only theme-driven difference inside `/advanced` is density's default**
(comfortable in light / compact in dark, per `03-CONTEXT.md` D-16) — which changes *default
disclosure state*, never reachability. Every control, filter, chart, and investigation workflow this
phase touches must remain reachable via the section navigation and, where density defaults it closed,
one keyboard-operable `<summary>`/toggle activation — never a second, theme-gated code path. A control
present in dark and unreachable in light is a parity defect (D-02's invariant), not a density choice.

---

## Density & Progressive Disclosure Contract (UX-04, extends D-02)

Per `05-RESEARCH.md` Pitfall 2, this is scoped to a short, named list rather than an open-ended
redesign. The existing `density-comfortable`/`density-compact` body classes
(`dashboard/advanced.js:223-227`) are extended to govern the **default open/closed state** of exactly
two existing disclosure containers — no new mechanism, no `renderComfortable()`/`renderCompact()`
pair:

| Surface | Element | `density-comfortable` (light default) | `density-compact` (dark default) |
|---|---|---|---|
| History → selected service | `<details id="service-availability-detail" class="hist-availability-detail">` (`advanced.html:157`, time-weighted availability breakdown + maintenance attribution) | Closed by default | Open by default |
| Incidents → each row | The existing `Show transitions`/`Hide transitions` toggle (`advanced.js:1288-1307`) | Collapsed by default | Expanded by default |

Both are read at render time from `document.body.classList.contains('density-compact')` — the native
`<details open>` attribute (or the equivalent `aria-expanded`/`hidden` pair for the JS-built
transitions toggle) is set once when the container is created, exactly mirroring
`applyDensity()`'s own class-toggle discipline. **The operator's own explicit toggle of a single
`<details>`/row always overrides the density default for that one instance** — density sets the
*initial* state only, never forces it back closed/open on every re-render. No other surface gains a
density-gated disclosure default this phase; this list is the complete scope, matching the research
brief's explicit warning against an open-ended list.

The existing three-rule spacing mechanism (`advanced.css:30-32`, `.density-comfortable`/
`.density-compact` gap/padding on `.advanced-detail`/`.diagnosis-card`/`.evidence-row`) already
applies unchanged to every section this phase touches (History, Incidents, Overview) because those
selectors are not section-scoped — no new CSS is required for spacing itself, only the two disclosure
defaults above.

---

## The Six States (UX-07)

Every state below is text + glyph, never color alone, matching the coverage-strip precedent
(`04-UI-SPEC.md` Chart Contract). `error` is always a bordered box; every other state is inline.

| State | Visual treatment | Distinguishing glyph | Color |
|---|---|---|---|
| Loading | Existing skeleton shimmer (`--bg3`/`--border2` gradient, `.skeleton-row`/`.hist-skeleton`/`.service-skeleton`) — unchanged | none (motion is the signal; under `prefers-reduced-motion`, the existing static fallback already applies, unchanged) | none |
| Empty | Plain paragraph, muted text, explicit next-step copy — unchanged existing pattern | none | `--muted` |
| Unknown | Inline text, existing `● {word}` bullet convention extended with a distinct glyph | `○` (hollow circle) | `--muted` |
| Stale | Inline text, existing `● {word}` bullet convention extended with a distinct glyph | `◐` (half-filled circle) | `--muted` |
| Degraded | **New** — inline text badge, never boxed (see Color's explicit negative) | `◈` | `--accent2` |
| Error | Existing bordered box (`.advanced-error`/`.hist-error`), unchanged | `✕` | `--accent2` |

**`unknown` vs `stale` are already structurally distinct today** — both are existing wire literals
from `freshness_state()` (`dashboard/beacon/diagnosis.py:101-118`) and already render as distinct
words in the Services table (`● {state} — {age}`, `dashboard/advanced.js:3509`); this contract adds
only the glyph, not a new distinction.

### Degraded — definition (this UI-SPEC's resolution of D-01's open evidence question)

**Recommended definition:** `degraded` for a given subject (worker heartbeat, host sample, or a
service's probe evidence) is true exactly when that subject's own `freshness_state()` tier is
`aging` — evidence exists and has not yet crossed the `stale` threshold, but has exceeded its
expected cadence. This is the tier `05-RESEARCH.md` confirms "already exists... but has no dedicated
UI treatment distinct from fresh" — no new evidence collection, no new heuristic; `degraded` and
`stale` are mutually exclusive per subject by construction (`freshness_state()`'s existing four-way
partition: fresh / aging / stale / unknown), so the two are structurally guaranteed distinguishable
rather than needing a runtime disambiguation rule, satisfying D-01's explicit constraint.

**What this requires, per surface (the planner should confirm/adjust, not silently accept):**
- **Advanced workspace:** `pipeline.worker.freshness.state`, `host.freshness.state`, and each
  service's `freshness.state` already surface `'aging'` today (`dashboard/beacon/diagnosis.py:659`
  composes it into `worker_stale` alongside `stale`, but the underlying per-subject `aging` value is
  already present in the payload) — **this is a client-only change**: render `aging` as the
  "Degraded" word/glyph/badge above wherever a freshness word is shown (Overview summary cards,
  Services table freshness column, Pipeline evidence), instead of leaving it visually identical to
  `fresh`.
- **Main dashboard:** `worker_stale` (`dashboard/app.py:3034`) is a single ad hoc age-threshold
  boolean (`heartbeat_age_seconds > WORKER_READY_SECONDS`), not a three-tier value — **this is the
  one genuine backend change D-01 anticipates**: expose a `worker_degraded` boolean (or the full
  three-tier state) computed via the same shared `freshness_state()` classification the advanced
  workspace already uses, not a second ad hoc cutoff. This is additive to, not a replacement for, the
  existing `worker_stale`/`recovery_required` fields.

**Explicit limitation, recorded per D-01's own instruction:** this definition covers *freshness/
evidence-staleness* degradation only. Phase 6's OPS-02 "visible non-fatal degraded state" concerns
preview/thumbnail capture-pipeline health (retry counts, timeout patterns, browser-ownership
contention) — a different evidence domain. Phase 6 may reuse this contract's *visual and copy*
pattern (`◈` glyph, inline `--accent2`, never boxed) directly, but its own boolean will very likely
compose from different, capture-pipeline-specific evidence, not `freshness_state()`. This UI-SPEC does
not attempt to pre-define that composition, per `05-RESEARCH.md` Open Question 3's own guidance not
to speculate about Phase 6.

---

## Accessibility Contract (UX-06, inherits `04-CONTEXT.md` R-03)

### The confirmed, already-diagnosed fix (apply verbatim)

`renderMarkerSingle` (`dashboard/advanced.js:1603-1622`) sets `role="img"` on a fully click/keydown-
actionable SVG circle. Change to `role="button"` with `aria-label` reworded to
`Investigate {text}`, matching `renderMarkerCluster`'s already-correct pattern
(`advanced.js:1572-1574`) verbatim, per `04-REVIEW.md` WR-02.

### The `role="img"` convention, resolved (05-RESEARCH.md Assumption A4)

**Rule:** `role="button"` is required only for a focusable element with a click/keydown *action*
(activates something). `role="img"` is correct and stays unchanged for a focusable element that is
*disclosure-only* (focus/hover reveals a tooltip, no action fires). Under this rule:
`renderServiceStateBand`'s segment (`advanced.js:751-758`) and `renderPointTargets`'s hit-circle
(`advanced.js:2438-2444`) are **correct as-is** — no change. `renderMarkerSingle` was the sole
outlier because it is actionable. This resolves A4 explicitly rather than leaving it open.

### Confirmed new gap — the coverage strip has no keyboard path at all

`renderCoverageStrip` (`advanced.js:2480-2503`) gives every segment an SVG `<title>` (mouse-hover-only)
and nothing else — no `tabindex`, no `role`, no `aria-label`. This is R-03's coverage-strip item,
concretely diagnosed at the code level for the first time this phase. **Fix:** add `tabindex="0"`,
`role="img"` (disclosure-only, per the rule above), and `aria-label` equal to the same text the
`<title>` already carries; add `focus`/`blur` handlers driving the same shared tooltip mechanism
`renderServiceStateBand`'s `scheduleBandTooltipUpdate` already uses, reusing that function rather than
writing a second one.

### Drag-to-select — keyboard equivalent (in scope this phase, not deferred again)

Each chart's existing per-point hit-targets (`renderPointTargets`, already `tabindex="0"`) gain one
new interaction, reusing the mouse drag's own range-application code path — never a second range-
setting function:
- `Shift+Enter` on a focused point target marks it as the pending range anchor, shown with the exact
  same visual language as the mouse drag rectangle (`.hist-drag-select`'s accent-tinted overlay,
  reused, not duplicated) collapsed to a single edge.
- Tabbing to a second point target and pressing `Enter` (or `Shift+Enter` again) completes the range
  and calls the identical range-apply function the mouse drag's `pointerup` already calls — the
  canonical start/end fields update identically either way.
- `Escape` cancels a pending anchor without applying anything.

### Hover time cursor — keyboard equivalent (in scope this phase, not deferred again)

Each point target's existing `focus` handler (`advanced.js:2432-2456`, already calls
`schedulePointTooltipUpdate`) is extended to also drive the shared cross-chart cursor line and readout
that the mouse `pointermove` path drives — so tabbing through point targets on any one chart moves the
shared cursor and updates every other stacked chart's readout exactly as mouse hover does. This is the
small, low-risk extension `05-RESEARCH.md` identifies (reusing `renderPointTooltip`'s existing plumbing,
not new architecture).

### Marker rail

Already keyboard-reachable end to end (`renderMarkerSingle`/`renderMarkerCluster`, both `tabindex="0"`,
both activate `focusIncident`); the only defect is the role fix above. No further work.

### Text labels that do not rely on colour alone — per-element audit

| Element | Colour used | Text alternative | Status |
|---|---|---|---|
| Uptime strip segments (`.us.up/.down/.partial/.unknown`) | Yes | Per-segment `title` attribute, already present (`dashboard/app.js:189`) | ✅ Compliant — **resolves `05-CONTEXT.md` Open Question 1 / `05-RESEARCH.md` Open Question 2: confirmed compliant, not a gap**; every segment already carries `"{pct}% available"` or `"No data"` regardless of theme |
| Service status pips (`.status-pip`) | Yes | Adjacent `.svc-online`/`.svc-offline` text ("ONLINE"/"OFFLINE") | ✅ Compliant (confirmed by `tests/test_ui_states.py:855`) |
| Services table freshness column | No (plain text `● {state} — {age}`) | N/A — already text-only | ✅ Compliant, no change needed |
| State band segments | Yes (green/red/muted/accent3) | `aria-label`/`title` sentence on focus/hover, always present | ✅ Compliant via programmatic text alternative — matches Phase 4's own accepted resolution for this exact element; a colour-independent *always-visible* pattern was explicitly rejected in `04-CONTEXT.md` D-11 (would collide with the latency chart's coverage-strip meaning) and this phase does not reopen that |
| Coverage strip segments | No (pattern + label already, Phase 4 precedent) | `title`, now also `aria-label` via the fix above | ✅ Compliant |
| Incident duration bar (grace/fault split) | Yes (accent3/red) | Two adjacent text timestamp lines, always rendered (D-14) | ✅ Compliant, unchanged |
| New "Degraded"/"Stale"/"Unknown" badges | Yes (`--accent2`/`--muted`) | Glyph + word, always rendered inline | ✅ Compliant by design (this contract) |

---

## Responsive Contract (UX-05)

### Breakpoint reconciliation (`05-RESEARCH.md` Assumption A3, resolved)

The main dashboard's `720px` breakpoint (`style.css:1215`) and the advanced workspace's narrowest
breakpoint (`719px`, `advanced.css:99`) are reconciled to **one shared value: `720px`**, changing
`advanced.css:99`'s `max-width: 719px` to `max-width: 720px`. No evidence anywhere documents an
intentional reason for the two to differ (`05-RESEARCH.md` confirms), and this phase's explicit job is
cross-surface consistency — a viewport exactly `720px` wide must get the narrow layout on both
surfaces. The `959px` breakpoint (`advanced.css:98`, nav-rail collapse) is unrelated and unchanged.

### Supported widths

| Width class | Range | Governs |
|---|---|---|
| Desktop | `>= 960px` | Persistent 224px nav rail; range control on one row; chart stack full-width, never side-by-side (unchanged, Phase 4) |
| Narrow-medium | `720px – 959px` | Nav rail collapses to a horizontal scrollable tab list; `.service-identity` sticky-left column; shared time axis becomes horizontally scrollable within its own container (`advanced.css:139`) |
| Narrow | `< 720px` | Header wraps to two rows; summary/evidence grids collapse to one column; filter controls collapse to one column; range control reflows to stacked rows; main-dashboard metrics/services grids collapse to one column; every discrete control keeps its 44px hit target |

### At-risk layouts, resolved

- **Four-chart host stack:** already full-width/stacked at every width (no side-by-side layout ever
  existed for it) — regression risk only, covered by extending the existing narrow-viewport Playwright
  pattern (`tests/test_ui_states.py:858/906`), not new CSS.
- **Incidents list:** not a table by design (`04-UI-SPEC.md`) — the genuine-table horizontal-scroll
  risk class does not apply; inline metadata wraps to a second line at `< 720px`, unchanged.
- **Services table:** the one genuine `<table>` at risk; already mitigated
  (`.services-table-scroll { overflow-x: auto }`, sticky `.service-identity` at `< 960px`) —
  regression risk only.
- **Marker rail:** inherits the chart's own `.hist-axis-scroll` horizontal-scroll container at
  `< 960px` exactly like the shared axis already does; cluster-glyph degradation (D-17) is
  resolution-independent. No new CSS required — this phase adds a narrow-viewport Playwright
  assertion pinning this (previously unverified per `05-RESEARCH.md`), not new behavior.
- **Filter controls:** `.service-filters`/`.incident-filters` already collapse to one column at
  `< 720px` (now reconciled from `719px`) — unchanged behavior, corrected boundary.

---

## Copywriting Contract

| Element | Copy |
|---------|------|
| Degraded — inline badge (freshness column, summary card) | `◈ Degraded` with the existing `formatFreshnessEvidence` sentence pattern extended: `This stream is degraded. Its last sample was {age}; expected every {cadence} seconds — not yet stale.` |
| Degraded — global banner (main dashboard `.safety-warning`, advanced Overview) | `Degraded — Beacon's worker heartbeat is aging. Monitoring continues; this is not a failure.` |
| Stale — inline badge | `◐ Stale` (word unchanged; glyph added) |
| Unknown — inline badge | `○ Unknown` (word unchanged; glyph added) |
| Error — unchanged | Existing per-surface error strings (`04-UI-SPEC.md` Copywriting Contract), unchanged |
| Empty — unchanged | Existing per-surface empty strings (`04-UI-SPEC.md` Copywriting Contract), unchanged |
| Loading — unchanged | Existing `Loading historical investigation…` and equivalents, unchanged |
| Coverage-strip segment `aria-label` (new) | Identical text to the existing `<title>` — `{Reason}` or `{Reason} — {N} intervals, {duration} total` (04-UI-SPEC Chart Contract, unchanged copy, newly also exposed as `aria-label`) |
| Pending keyboard range anchor (new) | Visually indicated only (no new text string) — the canonical start/end fields update with the same values a mouse drag produces, so no new copy is needed beyond what already exists for those fields |
| Density-driven disclosure — no new copy | `Show transitions`/`Hide transitions` and the availability `<summary>` text are unchanged; only their *default open state* changes by density |

No destructive actions exist in this phase's scope — `/advanced` remains strictly read-only, unchanged
from Phase 3/4.

---

## UI Considerations

Applicable state considerations: **11 applicable, 11 resolved (explicit), 0 backstop, 0 unresolved.**

Empty-state and error-state COPY is unchanged from `04-UI-SPEC.md`'s Copywriting Contract; the rows
below cover this phase's own shape-rooted STATE and PARITY coverage.

| Category | Element(s) | Status | Resolution / Reason |
|----------|------------|--------|---------------------|
| zero-one-many, populated | E1 — Main dashboard `html.light` audit (8 `display:none` instances) | ✅ resolved (explicit) | Exhaustively enumerated and classified above — all 8 classified (5 deliberate-calm + 3 decorative), 0 unresolved; `.svc-uptime-pct` explicitly extends D-03 rather than being silently left ambiguous |
| **populated, partial** | E2 — Degraded state (worker/host/service) | ✅ resolved (explicit) | Definition, per-surface backend/client split, and Phase 6 limitation all stated in "The Six States" above; distinguishable from `stale`/`unknown` by construction (mutually exclusive tiers) |
| error, partial | E3 — `error`/`degraded`/`partial` accent2 collision | ✅ resolved (explicit) | Box-vs-inline structural rule stated in Color's explicit negative; testable per-theme via `getComputedStyle` `display`/`border-style` |
| loading, empty, error, populated, partial, stale, unknown, degraded | E4 — Six-state distinctness across both themes | ✅ resolved (explicit) | Each state's glyph/color/shape combination declared in "The Six States" table; no state relies on color alone |
| **zero-one-many** | E5 — Density-driven disclosure defaults | ✅ resolved (explicit) | Exactly two named surfaces (`service-availability-detail`, incident-row transitions toggle); the operator's own explicit toggle always overrides the density default for that instance, so a manual choice is never silently reverted on re-render |
| overflow | E6 — Coverage-strip keyboard reachability | ✅ resolved (explicit) | `tabindex`/`role="img"`/`aria-label` added, reusing the state band's existing `scheduleBandTooltipUpdate`-style focus/blur pattern rather than a new one |
| overflow | E7 — Drag-to-select keyboard equivalent | ✅ resolved (explicit) | Two-focus-plus-Enter gesture reuses the mouse drag's own range-apply function; `Escape` cancels a pending anchor cleanly |
| populated | E8 — Hover cursor keyboard equivalent | ✅ resolved (explicit) | Extends the existing point-target `focus` handler to drive the shared cursor, no new architecture |
| long-text | E9 — `renderMarkerSingle` ARIA role | ✅ resolved (explicit) | Verbatim fix from `04-REVIEW.md` WR-02 applied; `role="img"` convention for the two non-actionable siblings resolved (A4) rather than left open |
| overflow, zero-one-many | E10 — Responsive breakpoint reconciliation (719px→720px) | ✅ resolved (explicit) | Single shared narrow boundary across both stylesheets; every previously-documented narrow-width mitigation (services table scroll, filter collapse, axis scroll) is unchanged, only the boundary value moves |
| populated | E11 — Marker rail at narrow width | ✅ resolved (explicit) | Confirmed to inherit the existing `.hist-axis-scroll` container; no new CSS, new Playwright assertion only (OPS-06 coverage, not a behavior change) |

---

## Verification Approach (OPS-06)

Per `05-RESEARCH.md`'s recommendation (accepted, not reopened here): extend the existing
`getComputedStyle`/DOM-contract dual-theme Playwright pattern
(`tests/test_advanced_ui.py::test_every_interactive_control_reads_as_interactive_in_both_themes`) to
every new/audited surface in this contract. Do not introduce pixel-snapshot testing — the reasoning
(zero setup cost, immune to font/GPU flakiness on Pi-class CI, and contract assertions can express
`role`/`aria-label`/text-content claims a pixel diff cannot) is unchanged from the research.
Assertions this contract implies, concretely: `role`/`aria-label` on the coverage-strip segment and
the fixed marker; `display`/`border-style` distinguishing boxed `error` from inline `degraded`; the
`<details open>`/`aria-expanded` state differing by `density-compact` vs `density-comfortable`; and a
`720px` viewport producing the narrow layout identically on both `/` and `/advanced`.

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
