# Phase 5: Theme-Parity Analytics Experience - Research

**Researched:** 2026-08-26
**Domain:** Dual-theme (light/dark) responsive, accessible frontend parity for a dependency-free vanilla-JS dashboard + advanced analytics workspace
**Confidence:** MEDIUM-HIGH — the existing codebase was read directly for every structural claim; the open design questions (density mechanism depth, six-state vocabulary, visual-regression approach) are genuinely the user's/planner's to resolve, and are presented as options below rather than decided.

<user_constraints>
## User Constraints (from CONTEXT.md)

**There is no CONTEXT.md for this phase.** The user deliberately skipped `/gsd-discuss-phase` and
told the planner to proceed. There are no locked decisions, discretion areas, or deferred ideas to
copy verbatim. This RESEARCH.md is therefore the primary grounding for planning — every place a
locked decision would normally go, this document instead lays out the concrete options and their
tradeoffs so the planner can choose explicitly and record its own assumption (flagged `[ASSUMED]`
below) rather than silently inventing a preference on the user's behalf.

The nearest thing to locked constraints are prior-phase decisions that bind forward (all sourced
from `.planning/STATE.md`'s Accumulated Context and the individual phase CONTEXT.md files, cited
inline below):

- Light mode is calmer/simpler; dark mode is denser/more hands-on — **without capability loss in
  either theme** (`PROJECT.md` "What This Is", `PROJECT.md` Constraints "Experience").
- Theme changes **density, not capability** (`03-CONTEXT.md` D-16, verbatim: "Use theme-aware
  density defaults: comfortable in light mode and compact in dark mode. Either theme may override
  density without losing any capability.").
- No frontend build step, charting library, icon package, or third-party registry — dependency-free
  vanilla HTML/CSS/JS (`04-UI-SPEC.md` "Design System"; `ROADMAP.md` Overview).
- `/advanced` remains strictly read-only: GET-only routes, no selector or mutation body
  (`PROJECT.md` Key Decisions, validated in Phase 3 against 46 blocking threats, `threats_open: 0`).
- Investigation state (range, filters, selected service) lives in browser storage only, never the
  URL (`04-CONTEXT.md` D-18) — Phase 5 must not need to reopen this to satisfy accessibility or
  responsive requirements.
- R-03 (`04-CONTEXT.md`, recorded at Phase 4 creation time, binding on this phase): drag-to-select,
  the hover time cursor, the marker rail, the state band, and the coverage strip all need
  keyboard-accessible equivalents and non-colour-dependent encodings under UX-06. This is
  Phase-5-inherited debt, not new discovery.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description (verbatim, `REQUIREMENTS.md`) | Research Support |
|----|-------------|------------------|
| UX-01 | Existing compact analytics previews remain on the main dashboard in both light and dark modes. | Already true today (main-dashboard sparklines/uptime-strip render in both themes — see Standard Stack/Architecture below); phase work here is regression-proofing this with dual-theme UI-contract coverage, not new capability. |
| UX-02 | *(Complete, Phase 3 — not this phase's scope; listed for traceability only.)* | — |
| UX-03 | Advanced analytics exposes the same data, filters, settings, and investigations in both themes. | The workspace shell, sections, filters and History/Incidents investigation surfaces already render identically in both themes (theme is a CSS-only skin on the same DOM/JS) — see "Current Theming Reality" below. The verification burden is exhaustive dual-theme coverage of Phase 3/4's surfaces, not new markup. |
| UX-04 | Light mode presents analytics with calmer grouping and progressive disclosure, while dark mode may present denser simultaneous context. | The `density-comfortable`/`density-compact` mechanism (Phase 3 D-16) already exists but is shallow — see "Light-vs-Dark Density Asymmetry" below, the key open design question for this phase. |
| UX-05 | Advanced analytics remains usable at supported narrow and desktop viewport widths. | Existing breakpoints (`959px`, `719px` in `advanced.css`; `720px` in `style.css`) and 44px touch-target convention are established precedent — see "Responsive Behavior" below. |
| UX-06 | Status and chart information is available through text, labels, and keyboard-accessible interactions rather than colour alone. | R-03's inherited debt (drag-to-select, hover cursor, marker rail keyboard gap) plus the confirmed `renderMarkerSingle` ARIA role mismatch — see "Accessibility" below. |
| UX-07 | Loading, empty, stale, unknown, degraded, and error states are visibly distinct. | Partial vocabulary exists server-side (`freshness_state`: fresh/aging/stale/unknown) and client-side (loading/empty/error/partial patterns in `advanced.js`/`advanced.html`); "degraded" has **no existing wire literal anywhere in the codebase** — this is a genuine gap, not just a coverage gap. See "The Six States" below. |
| OPS-06 | Both themes have UI-contract or visual-regression coverage for shared capabilities and important states. | A dual-theme `getComputedStyle`-based UI-contract test pattern already exists and passes today (`tests/test_advanced_ui.py::test_every_interactive_control_reads_as_interactive_in_both_themes`) — no pixel-screenshot tooling exists anywhere in the repo. See "Visual-Regression / UI-Contract Tooling" below for the recommendation. |
</phase_requirements>

## Summary

Beacon's theming is a single CSS custom-property system (`dashboard/style.css:4-41`) switched by
toggling an `html.light` class, persisted to `localStorage['beacon-theme']`, applied identically by
both the main dashboard (`dashboard/app.js:732-760`) and the advanced workspace
(`dashboard/advanced.js:219-221`). It is **not** derived from `prefers-color-scheme` anywhere — the
theme is 100% an explicit manual toggle. The token system is close to complete for color, but a
large amount of *typography, spacing, and structural* divergence between the two themes is expressed
as hundreds of scattered `html.light .foo { ... }` override rules throughout `style.css` (1,318
lines) and `advanced.css` (299 lines), rather than a small set of themed tokens. This is the biggest
risk for "theme parity" work: a missed override is a silent capability or legibility gap in one
theme only, and the codebase has no single place that enumerates "everything that must exist in both
themes."

The mechanism the roadmap's "calmer disclosure vs. denser context" language (UX-04) is almost
certainly meant to build on already exists: Phase 3's `density-comfortable`/`density-compact` body
classes (`03-CONTEXT.md` D-16, implemented `advanced.js:223-227`, styled `advanced.css:30-32`). Today
it is genuinely shallow — it changes only `.advanced-detail` gap and `.diagnosis-card`/`.evidence-row`
padding, nothing about information density, grouping, or progressive disclosure. Extending this
mechanism (more density-scoped rules, not a second theming system) is the path that avoids forking
the UI into two codebases; a `<details>`-based progressive-disclosure wrapper reused across themes
with theme-driven default open/closed state is the concrete implementation pattern recommended below.

No visual-regression (pixel screenshot) tooling exists anywhere in this repo, and the existing UI test
suite (6,930+ lines across `test_advanced_ui.py` and `test_history_investigation_ui.py`) already has
a working, passing dual-theme pattern built entirely on Playwright + `getComputedStyle`/DOM
assertions — no screenshots, no pixel diffing. This existing pattern is the strong precedent OPS-06
should extend, not a new pixel-based tool.

Accessibility debt is partially pre-catalogued by Phase 4: `04-CONTEXT.md` R-03 names drag-to-select,
the hover cursor, the marker rail, the state band, and the coverage strip as needing keyboard
equivalents/non-colour encodings; `04-VERIFICATION.md` and `04-REVIEW.md` additionally pin one
concrete, already-diagnosed-with-a-fix defect: `renderMarkerSingle` (`dashboard/advanced.js:1610-1611`)
sets `role="img"` on a fully click/keydown-interactive SVG circle, when `role="button"` (used by every
sibling interactive control in the same file) is correct.

**Primary recommendation:** Treat this phase as *audit-and-close* rather than *build-new*. The
architecture, token system, density mechanism, breakpoints, and test harness pattern all already
exist and are directionally correct; the work is (1) closing the density mechanism's shallowness so
UX-04 is actually true, (2) systematically inventorying and closing colour-only/keyboard-inaccessible
interactions (UX-06), (3) defining and wiring an explicit "degraded" state that does not exist today
(UX-07), and (4) extending the proven `getComputedStyle` dual-theme Playwright pattern to cover every
shared capability and state (OPS-06) — not introducing a new visual-regression tool, charting library,
or theming mechanism.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Theme selection & persistence | Browser / Client | — | `localStorage`-only toggle, no server involvement; applied identically in `app.js` and `advanced.js` (`dashboard/app.js:732-760`, `dashboard/advanced.js:219-221`). |
| Color tokens (light/dark) | Browser / Client (CSS) | — | Pure CSS custom properties in `dashboard/style.css:4-41`; no server-side theming concern. |
| Density (comfortable/compact) | Browser / Client (CSS + JS state) | — | `state.preferences.density`, validated and persisted client-side (`advanced.js:5,190-227`); server never sees this preference. |
| Freshness/staleness classification | API / Backend | Browser / Client (rendering only) | `freshness_state()` (`dashboard/beacon/diagnosis.py:101-119`) is the sole source of the fresh/aging/stale/unknown vocabulary; the client renders, never recomputes (established Phase 3 convention, `03-CONTEXT.md`). |
| Chart/marker/band rendering, keyboard interaction | Browser / Client | — | Hand-rolled SVG, no library; all interaction wiring (`tabindex`, `role`, `keydown`) lives in `dashboard/advanced.js`. |
| Responsive layout breakpoints | Browser / Client (CSS) | — | Pure `@media` queries in `style.css`/`advanced.css`; no server-side viewport awareness (no server-rendered variants). |
| UI-contract / dual-theme test coverage | Test infrastructure (Python + Playwright) | — | `tests/*.py` drive a real Chromium instance against the actual static files served by Flask (`werkzeug.serving.make_server`); this is integration-level, not unit-level. |
| "Degraded" state definition | API / Backend (source of truth) | Browser / Client (rendering) | Does not exist yet in either tier — must be defined server-side first (which durable signal(s) it composes from) before the client can render it, matching the established "server classifies, client renders" split. |

## Current Theming Reality

**Mechanism:** A single `html.light` class toggle, applied and removed by:
- Main dashboard: `applyTheme(light)` at `dashboard/app.js:732-736`, sets/clears the class and writes
  `localStorage.setItem('beacon-theme', light ? 'light' : 'dark')`; wired to the `#toggle` button
  click handler at `app.js:758-760`.
- Advanced workspace: `applyTheme()` at `dashboard/advanced.js:219-221` reads
  `localStorage.getItem('beacon-theme') === 'light'` and toggles the same class. There is no visible
  toggle control confirmed inside `advanced.js` in the excerpt read; theme carries over via the shared
  `localStorage` key (`03-CONTEXT.md`/`UX-02`, already validated Complete: "operator can move
  between dashboard and advanced without losing theme choice").

**Not derived from `prefers-color-scheme` anywhere** `[VERIFIED: grep across dashboard/*.css, dashboard/*.js, dashboard/*.html for "prefers-color-scheme" returns zero matches]`. This is a deliberate product choice already made (not something Phase 5 needs to revisit) — the toggle is explicit and persisted, matching a personal single-operator dashboard rather than a general web app.

**Token system** — declared once in `:root`-equivalent (`html`) and overridden in `html.light`
`[VERIFIED: dashboard/style.css:4-41]`:
```css
html {
  --bg: #010a14; --bg2: #030f1e; --bg3: #041525;
  --border: rgba(0,180,220,0.18); --border2: rgba(0,180,220,0.06);
  --text: #c8eaf5; --muted: #3a7a96; --muted2: #1a4a6a;
  --accent: #00d4ff; --accent2: #ffab00; --accent3: #7b6fff;
  --green: #00ff88; --red: #ff3d3d;
  --gauge-bg: #041525; --gauge-w: 5; --hud: 1;
  --font-sans: -apple-system, ...; --font-mono: ui-monospace, ...;
}
html.light {
  --bg: #ffffff; --bg2: #ffffff; --bg3: #f7f7f7;
  --border: rgba(0,0,0,0.06); --border2: rgba(0,0,0,0.03);
  --text: #0a0a0a; --muted: #b0b0b0; --muted2: #e8e8e8;
  --accent: #0066cc; --accent2: #b45309; --accent3: #5b21b6;
  --green: #16a34a; --red: #dc2626;
  --gauge-bg: #e5e7eb; --gauge-w: 1.5; --hud: 0;
}
```
This is a complete, well-formed 15-token palette (background×3, border×2, text, muted×2, accent×3,
status green/red, gauge geometry, HUD-opacity flag, two font stacks) and Phase 4's UI-SPEC extends it
correctly (reusing `--accent3` for the maintenance state, `--muted` for coverage-strip/threshold
lines, never inventing a new token) `[VERIFIED: 04-UI-SPEC.md "Color" section, cross-checked against dashboard/advanced.css:212-216 hist-band-* rules using exactly these token names]`.

**Where the divergence is NOT tokenized — this is the real "theme parity" cost.** The two themes are
not just different color values on the same shapes; large parts of the *layout, typography, and even
which elements render at all* differ per theme via direct `html.light .foo { ... }` / `html:not(.light) .foo { ... }`
selector overrides, e.g.:
- `html.light .sparkline { display: none; }` (`style.css:353`) — sparklines are **dark-mode only**,
  contradicting UX-01's "compact analytics previews remain... in both themes" if sparklines count as
  "analytics preview" (they likely do — this needs an explicit planner decision, see Open Questions).
- `html.light .temp-row { display: none; }` (`style.css:363`) — the temperature readout row is
  **hidden entirely in light mode**.
- `html.light .svc-preview { display: none; }` (`style.css:437`) — service thumbnail previews are
  **dark-mode only**.
- `html.light .uptime-labels { display: none; }` (`style.css:574`) — uptime strip day labels are
  **dark-mode only**.
- `html.light .arc-unit { display: none; }` (`style.css:296`) — the gauge unit label is **dark-mode only**.
- Light mode uses a completely different font stack/weight for many elements (`font-family: var(--font-sans); font-weight: 300`) vs. dark mode's `--font-mono`, and a different spacing rhythm (`.page { gap: 48px }` dark vs `html.light .page { gap: 64px }`, `.sh { margin-bottom: 20px }` dark vs `html.light .sh { margin-bottom: 32px }`).

`[VERIFIED: dashboard/style.css:353,363,437,574,296,204-231]` — these are not exhaustive; a grep for
`html.light .* { display: none` returns at least the five instances above and should be treated as
a starting checklist, not the complete list, for a Phase 5 "capability parity" audit.

**What "theme parity" concretely requires changing, per this evidence:**
1. **An explicit, exhaustive audit of every `display: none` under `html.light`/`html:not(.light)`**
   to classify each as (a) an intentional decorative-only omission (e.g., the scanline/HUD-corner
   sci-fi decoration is legitimately dark-mode-only flavor, not "capability") vs. (b) an actual
   information/capability loss that UX-01/UX-03 forbid. This audit does not exist anywhere in prior
   phase artifacts — it is new work for Phase 5.
2. Because color tokens are complete but *layout* tokens are not, "theme parity" work is mostly CSS
   restructuring/auditing, not new JS logic — the data and interaction layer is already shared
   (same `advanced.js`/`app.js` render into the same DOM in both themes; only CSS decides what's
   visible).

## Light-vs-Dark Density Asymmetry (UX-04)

**The mechanism already exists and is the correct one to extend — do not invent a second one.**

`03-CONTEXT.md` D-16 locked (Phase 3, binding on Phase 5): *"Use theme-aware density defaults:
comfortable in light mode and compact in dark mode. Either theme may override density without
losing any capability."* This is implemented today:

```js
// dashboard/advanced.js:223-227
function applyDensity() {
  const density = state.preferences.density || (document.documentElement.classList.contains('light') ? 'comfortable' : 'compact');
  document.body.classList.toggle('density-comfortable', density === 'comfortable');
  document.body.classList.toggle('density-compact', density === 'compact');
}
```
`state.preferences.density` is a validated, persisted preference (`advanced.js:5,194,210`) with an
operator-facing `<select>` (`advanced.js:3189-3198`, options: "Theme default" / "Comfortable" /
"Compact") — so an operator can already run comfortable-in-dark or compact-in-light if they choose,
which is exactly D-16's "either theme may override" clause. `[VERIFIED: dashboard/advanced.js:5,190-227,3189-3198]`

**The gap: the mechanism is real but shallow.** The only CSS consuming these two body classes today
is `[VERIFIED: dashboard/advanced.css:30-32]`:
```css
.density-comfortable .advanced-detail { gap: 32px; }
.density-comfortable .diagnosis-card, .density-comfortable .evidence-row { padding: 16px; }
.density-compact .diagnosis-card, .density-compact .evidence-row { padding: 8px; }
```
That is *spacing only* — three rules, no progressive disclosure, no information grouping, no
difference in what is simultaneously visible. UX-04's actual language — "calmer grouping and
progressive disclosure" (light) vs. "denser simultaneous context" (dark) — describes an
*information-architecture* difference, not a padding difference. This is the single largest design
gap in the phase and the one requiring the most planner judgment.

**How this is normally implemented without forking the UI (options, not a decision):**

1. **Density-scoped `<details>`/progressive-disclosure wrapping.** Wrap secondary information (e.g.
   Phase 4's `.hist-availability-detail` `<details>` already exists at `advanced.css:225` and is a
   working precedent — `<summary>` collapsed by default) so that:
   - `density-comfortable` (light default): more sections start `<details>` **closed**, revealing
     detail progressively on click/tap.
   - `density-compact` (dark default): the same sections start **open** (or are rendered as
     always-visible, non-collapsible content), so more is visible simultaneously without extra clicks.
   - This reuses one DOM/JS code path (`<details open>` attribute driven by the density class, or a
     `density === 'compact'` check at render time) rather than two divergent render functions — the
     mechanism that "keeps it honest" per the research brief's framing. A single render function that
     branches only on the boolean "start open" avoids the two-codebases risk entirely.
2. **Density tokens for spacing/grouping (extend the existing pattern).** More `.density-comfortable`/
   `.density-compact` CSS rules in the same vein as the existing three — larger gaps, more whitespace,
   fewer items per row in comfortable; tighter grids, more columns/rows visible without scrolling in
   compact. Lower risk, purely additive, but does not by itself satisfy "progressive disclosure" —
   only the visual density half of UX-04.
3. **Per-theme defaults on shared components, not per-theme components.** Every new interactive
   surface this phase touches should take a `density` parameter/class read at render time rather than
   having a `renderCompact()`/`renderComfortable()` pair — this is the concrete practice that prevents
   drift into "two divergent UIs" the research brief warns about. The existing `applyDensity()` +
   CSS-class-driven pattern already follows this discipline (one DOM tree, class-gated visibility) and
   should be the template for every extension.

**Risk flagged explicitly (per the research brief's request):** the greatest risk to UX-04 is not
building the mechanism (it exists) but under-specifying which specific pieces of the advanced
workspace need a comfortable/compact treatment at all. Options 1 and 2 above should be scoped to a
short, explicit list (History chart stack? Incidents list? Services table?) rather than applied
workspace-wide as an open-ended redesign — an open-ended scope here is the likeliest way this phase
overruns. **This list is a planner decision, not a research finding** — the phase requirements do not
name which surfaces need density treatment, only that the *capability* must exist and both themes
must retain full capability.

## Visual-Regression / UI-Contract Tooling (OPS-06) — Key Decision

**Finding: no pixel-based visual-regression tooling exists anywhere in this repository.**
`[VERIFIED: grep for "screenshot\|to_have_screenshot\|percy\|pixelmatch\|visual" across tests/*.py returns only unrelated matches — Playwright thumbnail-capture *feature* tests in test_api_and_auth.py, not visual-regression *test infrastructure*]`. `page.screenshot()`/`expect(locator).to_have_screenshot()` (Playwright's built-in pixel-snapshot API) is available since the `playwright==1.61.0` dependency is already pinned (`dashboard/pyproject.toml:11`), but it is unused.

**What exists instead, and already passes today, is a `getComputedStyle`/DOM-assertion dual-theme
pattern** — this is the load-bearing precedent for OPS-06:

```python
# tests/test_advanced_ui.py:164-230 (excerpted, confirmed present and passing)
def computed(locator, prop):
    return locator.evaluate(f'(node) => getComputedStyle(node)[{prop!r}]')
...
for theme in ('dark', 'light'):
    with self.subTest(theme=theme):
        page = self.browser.new_page(...)
        if theme == 'light':
            page.add_init_script("localStorage.setItem('beacon-theme', 'light');")
        page.goto(self.base_url, wait_until='networkidle')
        ...
        self.assertEqual(computed(page.locator('#advanced-refresh'), 'cursor'), 'pointer')
        self.assertEqual(computed(page.locator('#advanced-refresh'), 'minHeight'), '44px')
        ...
```
`[VERIFIED: dashboard/../tests/test_advanced_ui.py:164-292, test named test_every_interactive_control_reads_as_interactive_in_both_themes]`

Additional established patterns in the same files: narrow-viewport testing via
`page.set_viewport_size({'width': 720, 'height': 800})` (`tests/test_ui_states.py:858`) and
`{'width': 360, 'height': 800}` (`tests/test_ui_states.py:906`), and a dark/light color-resolution
helper that compares *computed* colors (not raw CSS variable strings) so a token indirection cannot
hide a real rendering bug: `getComputedStyle(probe).color` resolved against a detached probe element
(`tests/test_advanced_ui.py:1858-1867`).

**Recommendation: extend the existing `getComputedStyle`/DOM-contract pattern to cover OPS-06's
"shared capabilities and important states in both themes" clause. Do not introduce pixel-snapshot
testing.** Reasoning:

1. **Setup cost is zero** — the harness (Playwright + `werkzeug.serving.make_server` + `load_app`)
   already exists, is proven across two large test files (6,930 lines combined), and needs no new
   dependency, fixture, or CI step.
2. **Pi/CI rendering-determinism risk is structurally avoided.** Pixel screenshot testing is
   documented to be sensitive to "CSS animations, late-loading web fonts, dynamic content, and
   sub-pixel anti-aliasing that varies by GPU and OS" (WebSearch, testquality.com 2026 guide) — exactly
   the kind of cross-environment flakiness a project whose CI/dev machine and eventual Pi-class
   acceptance target (Phase 6, OPS-07) are different hardware cannot afford. `getComputedStyle`
   assertions on specific CSS properties are immune to anti-aliasing/GPU/font-substitution flakiness
   because they read resolved values, not rendered pixels.
3. **Doubling the artifact count is real and avoidable.** The research brief correctly flags that
   pixel snapshots across two themes double the baseline/artifact count; this project has no existing
   snapshot-review workflow (no reviewer tooling for image diffs is set up, per the same source:
   "a reviewer who cannot see image diffs in GitHub" is cited as a real friction point) — adopting
   pixel snapshots would require building that reviewer workflow from scratch as a Phase 5
   side-quest, unrelated to the phase's actual goal.
4. **Contract assertions directly express the requirement text.** UX-06 asks for "text labels that do
   not rely on colour alone" and OPS-06 asks for "UI-contract... coverage for shared capabilities and
   important states" — both are naturally phrased as "does this element have attribute X / computed
   style Y / text content Z", which is exactly what the existing pattern already tests. A pixel diff
   cannot assert "this uses `role="button"` not `role="img"`" or "this has a text label, not just a
   color" — it can only say "these two renders differ," which is a strictly weaker signal for these
   specific requirements.

**Runner-up, if the planner judges pixel coverage genuinely necessary for some subset (e.g. chart
gap-rendering or coverage-strip pattern legibility, which are visual by nature and harder to assert
via computed style alone):** Playwright's built-in `expect(locator).to_have_screenshot()` scoped
**narrowly** to 2-4 specific chart/pattern elements (not full-page), with a documented pixel-diff
threshold and baselines regenerated per-theme. This is additive to, not a replacement for, the
DOM-contract approach above, and should be scoped small precisely because of the doubling-artifact
concern the brief raises. `[ASSUMED — this recommendation is my synthesis of the codebase evidence plus general Playwright visual-testing practice, not a project-specific decision on record anywhere]`

## Accessibility (UX-06 and inherited debt)

### Already-catalogued debt (inherit, do not rediscover)

From `04-CONTEXT.md` R-03 (recorded at Phase 4 creation time, explicitly for Phase 5):
> "Drag-to-select (D-03), the hover time cursor and marker rail (D-17), the state band (D-11), and
> the coverage strip (D-06) all require keyboard-accessible equivalents and non-colour-dependent
> encodings under UX-06."

From `04-UI-SPEC.md` "Chart stack" section, the same debt stated with its accepted interim mitigation:
> "Keyboard/non-pointer equivalents for drag-to-select and the hover time cursor are explicit Phase 5
> debt (R-03), not delivered in this phase. This UI-SPEC does not claim keyboard parity for those two
> interactions; the canonical start/end fields remain the fully keyboard-operable path to any range,
> satisfying DIA-05 without them." `[CITED: .planning/phases/04-historical-investigation/04-UI-SPEC.md:194-197]`

From `04-VERIFICATION.md` Anti-Patterns (re-confirmed present in the live tree at time of writing,
2026-08-27 round-3 re-verification) and `04-REVIEW.md` WR-02:

**Confirmed, concrete, low-cost fix already diagnosed** — `renderMarkerSingle`
`[VERIFIED: dashboard/advanced.js:1603-1622, quoted below]`:
```js
function renderMarkerSingle(marker) {
  const {episode, x} = marker;
  const circle = document.createElementNS(SVG_NS, 'circle');
  ...
  circle.setAttribute('tabindex', '0');
  circle.setAttribute('role', 'img');
  const text = markerTitle(episode);
  circle.setAttribute('aria-label', text);
  ...
  circle.addEventListener('click', () => focusIncident(episode));
  circle.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); focusIncident(episode); }
  });
  return circle;
}
```
This element is fully click/keydown-interactive (activates `focusIncident`) but announces itself to
assistive technology as `role="img"` (a static, non-actionable graphic). Every sibling interactive
element in the same file uses `role="button"` correctly: `renderMarkerCluster` at
`advanced.js:1572-1573` (`g.setAttribute('role', 'button')`) and the incident row at
`advanced.js:1214` (`row.setAttribute('role', 'button')`). The reviewer's own diagnosed fix
`[CITED: 04-REVIEW.md WR-02, lines 147-153]`:
```js
circle.setAttribute('role', 'button');
circle.setAttribute('aria-label', `Investigate ${text}`);
```
This is a two-line, already-specified fix — Phase 5 should apply it essentially verbatim rather than
re-diagnosing it.

**Two related, not-yet-flagged-as-defects instances of the same pattern worth the planner's explicit
judgment** (found during this research, not previously recorded as a gap by any prior verification —
tagged `[ASSUMED]` as to whether they actually need to change, since unlike the marker they are
read-only-on-focus, not click-actionable):
- `renderServiceStateBand`'s per-segment `<rect>` (`dashboard/advanced.js:751-758`): `role="img"`,
  `tabindex="0"`, but no click/keydown handler — focus only triggers a tooltip disclosure
  (`pointerover`/`focus` → `scheduleBandTooltipUpdate`). `role="img"` may be defensible here (the
  element is not "actionable," only "has more detail on focus") but is inconsistent with the
  point-target pattern below, which does the identical thing.
- `renderPointTargets`'s per-point hit-circle (`dashboard/advanced.js:2438-2444`): same
  shape — `role="img"`, `tabindex="0"`, tooltip-only on focus, no click action.
Neither of these is confirmed a defect by any prior verification round; they are structurally
identical to each other and structurally different from the marker (no keyboard *action*, only keyboard
*disclosure*). The planner should decide once whether "focusable, tooltip-only, `role="img"`" is the
project's intended convention for hover-disclosure elements (in which case these two are fine and
`renderMarkerSingle` is the outlier that needs fixing) or whether all three should use a more precise
role such as ARIA's `aria-describedby`-driven tooltip pattern instead of `role="img"` + focus-triggered
tooltip. This is exactly the kind of "genuinely the user's/planner's decision" the research brief asks
to be surfaced rather than silently resolved.

### What "keyboard-accessible chart interactions" concretely means here

Given the codebase's existing conventions (confirmed working precedent, not proposed):
- **Point targets already exist and are keyboard-reachable** — `renderPointTargets`
  (`advanced.js:2432-2456`) places a `tabindex="0"`/`role="img"` hit-circle per plotted point,
  reachable by `Tab`, with the same tooltip shown on `focus` as on `pointerover`. This is the
  existing, working pattern for "a keyboard user can inspect any single data point."
- **What is missing is range-level interaction**, per R-03: drag-to-select (choosing a sub-range by
  dragging across the chart) has no keyboard equivalent. The UI-SPEC's accepted interim position is
  that the canonical start/end text fields are the keyboard-accessible path to *any* range, which
  technically satisfies DIA-05 (custom range selection) but does not give a keyboard user the
  *exploratory* drag-to-narrow interaction a mouse user gets. Concrete options for Phase 5 (not
  decided here):
  1. Arrow-key range adjustment on the canonical start/end fields when focused (nudge by resolution
     step) — lowest implementation cost, reuses existing validated-input plumbing.
  2. A keyboard-operable "drag" mode on the chart itself (e.g. focus a point target, then
     Shift+Arrow to extend a selection, Enter to apply) — higher cost, closer functional parity with
     the mouse gesture.
  3. Accept the UI-SPEC's existing position (fields are the keyboard path; drag is a mouse
     convenience, not a second capability) and treat UX-06 as satisfied for range selection without
     new work here — cheapest, but the planner must explicitly record this as the interpretation
     chosen, since "keyboard-accessible... chart interactions" in the requirement text is not
     self-evidently satisfied by "you can still type numbers into a field instead."
- **The hover time cursor** (`04-CONTEXT.md` D-17) has no keyboard equivalent either — it is a
  continuous pointermove-driven readout. A keyboard equivalent would most naturally piggyback on the
  point-target focus events that already exist (each point target's `focus` handler could additionally
  drive the same shared cursor/readout the mouse path uses) — this looks like a small, low-risk
  extension of existing code (`schedulePointTooltipUpdate`/`renderPointTooltip`,
  `advanced.js:2421-2428`) rather than new architecture.

### What "text labels that do not rely on colour alone" requires

Current status/state rendering already does this correctly in several places — verified precedent to
follow, not a gap:
- The main-dashboard uptime strip: `.us.up`/`.us.down`/`.us.partial`/`.us.unknown` differ by color
  **and** are backed by the `n < 0 ? 'unknown' : n === 0 ? 'down' : n === 1 ? 'up' : 'partial'` class
  logic (`dashboard/app.js:188`), but the strip itself has no adjacent text label per-segment
  confirmed in the excerpt read — this needs verification against the full uptime-strip render
  function (not fully read in this research pass; flagged as an **open question** below, not a
  confirmed gap).
- The Incidents "Ongoing" badge is explicitly text+glyph, not color alone: `▶ Ongoing — not yet
  recovered` (`04-UI-SPEC.md` Copywriting Contract, implemented per D-12/Pitfall 4).
- The coverage strip (`04-UI-SPEC.md` Chart Contract) is explicitly pattern+label, never color alone,
  for all five wire states — this is a *documented, already-implemented* precedent for how UX-06
  should be satisfied elsewhere: never ship a state that is color-only.
- **Confirmed existing violation candidates for audit** (not confirmed defects — need a rendered-DOM
  check, which this research pass did not perform): the service-card status pips (`.status-pip`,
  `style.css:511-516`) are colored circles; text nearby (`.svc-online`/`.svc-offline` text content,
  e.g. "ONLINE"/"OFFLINE") does appear to accompany them based on `test_ui_states.py:855`
  (`self.assertIn('ONLINE', page.locator('.svc-status-row').text_content())`), which suggests this is
  **not** a violation — but Phase 5 should still audit this systematically rather than assume every
  pip has an adjacent label.

## Responsive Behavior (UX-05)

**Breakpoints in use today** `[VERIFIED: grep for "@media" across dashboard/style.css and dashboard/advanced.css]`:
| File | Breakpoint | Scope |
|------|-----------|-------|
| `style.css:1215` | `max-width: 720px` | Main dashboard: topbar, metrics grid → 1 column, services grid → 1 column, 44px touch targets on scan/edit/theme-toggle buttons, modal reflow |
| `advanced.css:98` | `max-width: 959px` | Advanced workspace: nav rail becomes a horizontal scrollable tab list, sticky service-identity column |
| `advanced.css:99` | `max-width: 719px` | Advanced workspace: header wraps to two rows, summary grid → 1 column, evidence-row → 1 column |
| both files | `prefers-reduced-motion: reduce` | Disables scanline animation and clamps all transition/animation durations |

**Inconsistency worth flagging:** the main dashboard's single breakpoint is `720px` while the advanced
workspace's second breakpoint is `719px` — these are *not* the same boundary (a viewport exactly
720px wide gets the main dashboard's narrow layout but not the advanced workspace's narrowest layout).
This is very likely an unintentional off-by-one rather than a deliberate design choice (no CONTEXT.md
or UI-SPEC anywhere documents a reason for the two values to differ), and Phase 5 — whose explicit
job is cross-surface consistency — should either reconcile them to one shared value or document why
they differ. `[ASSUMED — no evidence found of an intentional reason for the mismatch; flagged as a likely defect for the planner to confirm]`

**Layouts most at risk at narrow widths**, per direct evidence:
- **The four-chart host stack** (`04-UI-SPEC.md` "Chart stack") — already has a documented, existing
  behavior at `< 960px`: charts stay full-width/stacked (no side-by-side ever existed), but the shared
  time axis scrolls horizontally within its own container if label density would overlap
  (`advanced.css:139`: `@media (max-width: 959px) { .hist-axis-scroll svg { min-width: 640px; } }`).
  This is implemented, not a gap — the risk here is regression, not missing coverage.
- **The incidents table/list** — is not a table (deliberately, per `04-UI-SPEC.md`: "not a dense
  table — incident rows carry more prose"), so the risk class that affects `#services-table`
  (horizontal scroll of a genuine `<table>`, `advanced.css:39-40`,
  `min-width: 920px` forcing `overflow-x: auto`) does not apply to Incidents. The Services table
  **is** the highest-risk genuine-table surface at narrow widths, and already has a documented,
  tested mitigation (`.services-table-scroll { overflow-x: auto }`, `service-identity` sticky-left
  column at `< 960px`, `advanced.css:48,98`) — again, regression risk, not a missing capability.
- **The marker rail** (`.hist-marker-rail`, `advanced.css:274`) — a fixed `height: 16px` SVG with no
  documented narrow-width behavior beyond inheriting the chart's own full-width scroll container. Dense
  marker clustering (D-17) already degrades gracefully at any zoom level per the UI-SPEC, but this
  was not verified against an actual narrow-viewport render in this research pass — flagged as needing
  a narrow-viewport Playwright check in Phase 5's Wave 0.
- **Filter controls** (`.service-filters`, `advanced.css:36-38`; `.incident-filters`,
  `advanced.css:240`) — `flex-wrap: wrap` with `min-width: 130px` per label; documented to collapse to
  one column at `< 720px` per `04-UI-SPEC.md` ("Incidents list" section) — implemented via the shared
  `.service-filters` grid pattern, another regression-risk-not-gap surface.

**44px touch-target convention** is applied consistently and is the established site-wide rule
(referenced explicitly in `04-UI-SPEC.md` Spacing Scale "Exceptions" and confirmed in both
`style.css` mobile media query and throughout `advanced.css`) — Phase 5 should audit any *new* element
it touches against this existing rule rather than invent a different one.

## The Six States (UX-07): loading, empty, stale, unknown, degraded, error

**Server-side vocabulary that exists today** `[VERIFIED: dashboard/beacon/diagnosis.py:101-119, quoted]`:
```python
def freshness_state(now, sample_ts, cadence_seconds):
    """Classify durable sampling evidence without inferring its cause."""
    if (type(now) is not int or type(sample_ts) is not int
        or type(cadence_seconds) is not int or cadence_seconds <= 0):
        return {'state': 'unknown', 'age_seconds': None}
    age_seconds = max(0, now - sample_ts)
    if age_seconds <= cadence_seconds:
        state = 'fresh'
    elif age_seconds <= 4 * cadence_seconds:
        state = 'aging'
    else:
        state = 'stale'
    return {'state': state, 'age_seconds': age_seconds}
```
This gives four of the six requirement states an existing wire literal: **stale** and **unknown**
directly (`'stale'`, `'unknown'`); **loading** and **empty** are handled entirely client-side today
(skeleton rows, `advanced-loading` class, documented empty-copy strings) with no server literal needed
for them. **`error`** likewise is a client-side HTTP-failure rendering concern (`advanced-error` /
`hist-error` classes), not a server-emitted state literal.

**`degraded` has no existing wire literal anywhere in the codebase**
`[VERIFIED: grep -rn "degraded" across dashboard/ returns zero matches in any .py/.js/.html/.css file — the only hits anywhere in the repo are prose in Phase-4 planning-doc commentary about an "already-degraded server," not a UI state]`.
This is a genuine gap, not a coverage gap: the roadmap/requirement text uses "degraded" but the
system has never defined what durable evidence constitutes "degraded" as distinct from "stale" or
"unknown." The closest existing precedent is Phase 6's not-yet-built OPS-02 ("Preview work uses...
a visible non-fatal degraded state") — that is explicitly future work (Phase 6), so Phase 5 cannot
borrow its definition.

**This is the single largest open design question for UX-07** and must be resolved by the planner
(with user input, ideally, since it is a genuine product-semantics question) before task-level work
can proceed:
- Is "degraded" a *new* server-emitted state, requiring a `beacon/diagnosis.py` change (server
  classifies, per established convention)?
- Or is "degraded" a *client-side composite* — e.g., "worker stale AND at least one service unknown"
  — computed from existing signals without a new server literal?
- Candidate existing signals it might compose from: `worker_stale` (`app.js:100-107`,
  `advanced.js` pipeline evidence), `recovery_required` (`recovery-warning` banner), the `aging`
  freshness tier (a state that already exists but has no dedicated UI treatment distinct from
  `fresh` in the excerpts read), and Phase 4's own `advanced-partial` state (a per-section partial
  data failure, distinct from a total failure).

`[ASSUMED — I could not determine from the codebase alone which of these composition strategies the
project intends; this needs an explicit planner/user decision, not a research-supplied default.]`

**Existing state-rendering precedent to follow for whichever definition is chosen** (already-established
conventions Phase 5 should reuse, not reinvent):
- Server classifies, client renders without recomputing (Phase 3 convention, reused throughout Phase 4).
- Distinct facts stay distinct — never merge worker staleness, disconnection, recovery-required,
  retention expiry, collection gaps, and storage pressure into one signal (`04-CONTEXT.md` "Established
  Patterns", itself inherited from Phase 3's nine-verification-round lesson about truthful labelling).
- Every state gets its own copy string in a documented Copywriting Contract (`04-UI-SPEC.md` pattern)
  — Phase 5 should produce its own such contract for whatever states it adds/clarifies.
- `04-UI-SPEC.md`'s "partial" precedent (E4: a failed unfiltered-baseline read degrades one number, not
  the whole view — `04-11`'s `"N of ? incidents (total unavailable)"` fix) is the concrete, working
  model for what "degraded" (in the sense of "partially working, not fully failed") looks like in this
  codebase's idiom, even though the word "degraded" itself was never used for it.

## Package Legitimacy Audit

**Not applicable.** This phase, per every piece of evidence read (roadmap overview, `04-UI-SPEC.md`
"Design System", `ROADMAP.md` Overview, existing `dashboard/pyproject.toml` dependency list), is
scoped to CSS/JS/HTML restructuring and existing-dependency test coverage. No new third-party package
in any ecosystem is indicated by any research finding above. If planning surfaces a need for a new
dependency (e.g., an accessibility-linting tool), the Package Legitimacy Gate protocol must be run at
that time — it was not run here because no candidate package was identified.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Pixel-level visual regression | A custom screenshot-diffing harness | Playwright's built-in `expect(locator).to_have_screenshot()`, scoped narrowly, only if the planner decides pixel coverage is needed for chart/pattern legibility | Already a pinned dependency (`playwright==1.61.0`); a hand-rolled diff tool would duplicate maintained functionality for no benefit |
| Color-contrast auditing | A manual token-by-token contrast calculation | Not identified as needed this phase (existing tokens were presumably vetted in earlier phases; no WCAG contrast-ratio failure was found or claimed in this research pass) — if the planner wants automated contrast checking, note WCAG 1.4.1 ("Use of Color", Level A) requires **at least one other visual indicator besides color** for status/action information (WebSearch, w3.org Understanding WCAG 2.1), which is a different, more actionable criterion than raw contrast ratio for this phase's UX-06 requirement | Contrast-ratio tooling is a distinct concern (WCAG 1.4.3) from "color alone" (1.4.1); UX-06's wording maps to 1.4.1, not 1.4.3 — don't conflate the two when scoping |
| A second theming/density system | A parallel "light-mode-only" or "dark-mode-only" component tree | The existing single-DOM + CSS-class-driven `density-comfortable`/`density-compact` pattern (`03-CONTEXT.md` D-16) | This is the explicit anti-pattern the research brief warns about (forking into two divergent UIs); the codebase already avoids it and Phase 5 must not introduce it |

**Key insight:** every mechanism this phase needs (theme toggle, density classes, dual-theme test
harness, keyboard-focus/tooltip pattern, ARIA role usage precedent) already exists in the codebase in
a directionally-correct form. The risk in this phase is not "we lack the tools" but "the existing
tools are applied inconsistently or shallowly" — which argues strongly for an audit-and-extend
posture over a build-new posture.

## Architecture Patterns

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│ Browser (single page, no build step, no framework)                  │
│                                                                       │
│  localStorage['beacon-theme']  ──┐                                  │
│  localStorage['beacon-advanced-  │                                  │
│    preferences-v1'].density  ────┼──► applyTheme() / applyDensity() │
│                                   │      (app.js / advanced.js)      │
│                                   ▼                                  │
│                          html.light + body.density-* classes         │
│                                   │                                  │
│                                   ▼                                  │
│         ┌─────────────────────────────────────────────┐             │
│         │  CSS custom properties (style.css tokens)     │             │
│         │  resolved differently per html.light presence  │             │
│         └─────────────────────────────────────────────┘             │
│                                   │                                  │
│                                   ▼                                  │
│   Same DOM tree, same JS render functions, in BOTH themes           │
│   (app.js renders index.html; advanced.js renders advanced.html)     │
│                                   │                                  │
│                    ┌──────────────┴───────────────┐                  │
│                    ▼                               ▼                  │
│         Main dashboard sections          Advanced workspace sections  │
│         (metrics, services, events)      (Overview/Host/Services/     │
│                                            History/Incidents/          │
│                                            Pipeline/Settings)          │
└───────────────────────┬───────────────────────────┬───────────────────┘
                         │ fetch (GET only)           │ fetch (GET only)
                         ▼                             ▼
              ┌─────────────────────────────────────────────┐
              │ Flask web process (dashboard/app.py)          │
              │  - freshness_state() classifies staleness      │
              │    (dashboard/beacon/diagnosis.py)              │
              │  - No "degraded" literal emitted anywhere       │
              │    today — gap for this phase to resolve        │
              └─────────────────────┬───────────────────────────┘
                                    ▼
                          SQLite (shared w/ worker)
```

### Recommended Project Structure

No new files/directories are indicated — this phase extends existing files in place:
```
dashboard/
├── style.css        # Main-dashboard tokens + light/dark overrides — audit target for capability parity
├── advanced.css      # Advanced-workspace tokens + density rules — extension target for UX-04
├── app.js            # Main dashboard render/state — UX-01 regression coverage target
├── advanced.js        # Advanced workspace render/state — UX-03/UX-06/UX-07 primary edit target
tests/
├── test_ui_contract.py            # Static-content assertion pattern (markup/CSS token presence) — extend for OPS-06 "shared capability" checks
├── test_advanced_ui.py             # Existing dual-theme getComputedStyle pattern — extend for OPS-06
├── test_history_investigation_ui.py  # Existing Playwright browser-driven pattern — extend for state/accessibility coverage
```

### Pattern 1: Dual-theme Playwright subtest loop

**What:** Iterate `for theme in ('dark', 'light')`, using `page.add_init_script` to set
`localStorage['beacon-theme']` before `page.goto`, wrapped in `self.subTest(theme=theme)` so both
themes' failures are reported independently rather than the first failure masking the second.

**When to use:** Any new OPS-06 coverage — this is the established, working, zero-setup-cost pattern.

**Example:**
```python
# Source: tests/test_advanced_ui.py:164-230 (existing, passing test)
def computed(locator, prop):
    return locator.evaluate(f'(node) => getComputedStyle(node)[{prop!r}]')

for theme in ('dark', 'light'):
    with self.subTest(theme=theme):
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        if theme == 'light':
            page.add_init_script("localStorage.setItem('beacon-theme', 'light');")
        page.goto(self.base_url, wait_until='networkidle')
        try:
            self.assertEqual(computed(page.locator('#advanced-refresh'), 'cursor'), 'pointer')
        finally:
            page.close()
```

### Pattern 2: Density-scoped CSS classes, not per-density render functions

**What:** A single body-level class (`density-comfortable`/`density-compact`) gates CSS rules; JS
never branches on density to choose which markup to build.

**When to use:** Any UX-04 extension work.

**Example:**
```css
/* Source: dashboard/advanced.css:30-32 (existing) */
.density-comfortable .advanced-detail { gap: 32px; }
.density-comfortable .diagnosis-card, .density-comfortable .evidence-row { padding: 16px; }
.density-compact .diagnosis-card, .density-compact .evidence-row { padding: 8px; }
```

### Anti-Patterns to Avoid

- **Two render functions for two densities/themes:** the moment a `renderCompact()`/`renderComfortable()`
  pair (or `renderLight()`/`renderDark()`) appears, the "two divergent UIs" risk the research brief
  flags has materialized. The existing codebase has zero instances of this pattern — keep it that way.
- **`role="img"` on a click/keydown-actionable element:** confirmed live defect (`renderMarkerSingle`);
  do not introduce a second instance while fixing the first.
- **A colour-only state distinction:** the coverage-strip precedent (pattern + label, never color
  alone) is the standard to match for any new state Phase 5 introduces (especially "degraded").
- **Deriving theme from `prefers-color-scheme`:** would silently change existing, validated behavior
  (the explicit toggle + persisted choice) — not indicated by anything in this phase's requirements
  and would be a scope-creep regression risk, not a parity improvement.

## Common Pitfalls

### Pitfall 1: Treating "theme parity" as a color-token problem
**What goes wrong:** Assuming the existing 15-token CSS custom-property system is "the theming system"
and auditing only colors, missing the `display: none` / font-family / spacing divergences that are
the actual capability-parity risk.
**Why it happens:** The color tokens are genuinely complete and well-organized, creating a false
impression that theming is "done" everywhere.
**How to avoid:** Explicitly grep and enumerate every `html.light` / `html:not(.light)` override rule
across both CSS files (hundreds of rules) and classify each, not just spot-check.
**Warning signs:** A UI-contract test that only checks `getComputedStyle(...).color` and never checks
`display`, `visibility`, or DOM presence per theme.

### Pitfall 2: Scoping UX-04 as an open-ended visual redesign
**What goes wrong:** "Calmer grouping and progressive disclosure" is broad language that could justify
redesigning every surface in the advanced workspace, dramatically overrunning the phase.
**Why it happens:** The requirement text is evocative rather than a bounded spec, and no CONTEXT.md
exists to bound it (this phase skipped discuss-phase).
**How to avoid:** The planner should produce an explicit, short, named list of which surfaces get
density treatment (extending the existing 3-rule mechanism) rather than treating UX-04 as license to
redesign the workspace.
**Warning signs:** A plan whose task list touches every `.advanced-detail` section rather than a
named subset.

### Pitfall 3: Inventing a "degraded" definition without a durable-evidence source
**What goes wrong:** Rendering a client-side "degraded" label based on ad-hoc heuristics (e.g. "if
more than N seconds have passed, show degraded") that isn't backed by a server-classified signal,
repeating the exact failure class Phase 3 spent nine verification rounds eliminating (inferred,
resolved, or retention-expired evidence presented as a current fact).
**Why it happens:** "Degraded" has no existing vocabulary anywhere, and it is tempting to compute it
client-side from whatever signals are already being fetched.
**How to avoid:** Follow the established "server classifies, client renders" split — if "degraded"
needs new durable evidence, add it server-side (in `diagnosis.py`, alongside `freshness_state`)
rather than computing it ad hoc in `advanced.js`.
**Warning signs:** A `degraded` literal appearing first in `advanced.js` with no corresponding
server-side field it was read from.

### Pitfall 4: Adding pixel-snapshot tests without a review workflow
**What goes wrong:** Introducing `to_have_screenshot()` baselines that immediately start flaking on
CI/dev-machine font or GPU differences, with no established process for reviewing/approving
intentional baseline changes, producing noisy failing tests that get skipped or `# noqa`'d.
**Why it happens:** Pixel snapshots feel like the most literal reading of "visual-regression coverage"
in OPS-06's wording.
**How to avoid:** Default to the existing `getComputedStyle`/DOM-contract pattern (see Visual-Regression
section above); only add narrowly-scoped pixel coverage with an explicit owner decision to accept the
maintenance cost.
**Warning signs:** A CI run that fails on unrelated font-rendering differences between local and CI
Chromium builds.

## Code Examples

### Dual-theme + narrow-viewport combined pattern (verified precedent)
```python
# Source: tests/test_ui_states.py:826-872 (existing, passing test,
# test_playwright_zero_one_many_states_in_dark_light_and_narrow_layout)
page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
...
page.goto(self.base_url, wait_until='networkidle')
# ... assert desktop/dark-mode state ...
page.set_viewport_size({'width': 720, 'height': 800})
page.locator('#toggle').click()
self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))
# ... assert narrow/light-mode state ...
```

### Focus-triggered tooltip pattern (existing, reusable for keyboard-cursor extension)
```js
// Source: dashboard/advanced.js:2432-2456 (renderPointTargets, existing)
target.setAttribute('tabindex', '0');
target.setAttribute('role', 'img');
target.addEventListener('pointerover', (event) => schedulePointTooltipUpdate(metric, point, event.clientX, event.clientY));
target.addEventListener('focus', () => {
  const rect = target.getBoundingClientRect();
  schedulePointTooltipUpdate(metric, point, rect.left, rect.top);
});
target.addEventListener('blur', hidePointTooltip);
```

### Confirmed-correct ARIA pattern to match when fixing `renderMarkerSingle`
```js
// Source: dashboard/advanced.js:1572-1574 (renderMarkerCluster, existing, correct)
g.setAttribute('tabindex', '0');
g.setAttribute('role', 'button');
g.setAttribute('aria-label', summary);
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| N/A — no theming-library migration is indicated | CSS custom properties + class toggle | Established since before Phase 1 (pre-GSD baseline) | Stable, no change needed |
| N/A | `density-comfortable`/`density-compact` body classes | Phase 3 (D-16) | The mechanism Phase 5 must extend, not replace |

**Deprecated/outdated:** None identified — the codebase has no legacy theming approach being phased
out; this is a maturation/completion phase for an approach already in place.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Pixel-snapshot testing should be a narrowly-scoped supplement, not the primary OPS-06 mechanism | Visual-Regression Tooling | If the user actually wants full pixel-diff coverage (e.g. for a specific compliance/QA reason not stated anywhere in the read documents), this recommendation under-delivers; low risk since it is presented as the runner-up option, not silently omitted |
| A2 | "Degraded" composition strategy (client-composite vs. new server literal) is undetermined | The Six States | If the planner picks the wrong composition without user input, the state may either duplicate `stale`/`aging` (redundant) or infer a fact the server cannot support (repeating Phase 3's core failure mode) |
| A3 | The `720px`/`719px` breakpoint mismatch is an unintentional inconsistency, not a deliberate design choice | Responsive Behavior | If it is actually intentional (e.g. accounting for a scrollbar width difference between the two layouts), "fixing" it could introduce a regression; low likelihood given no documentation supports intentionality |
| A4 | `renderServiceStateBand` and `renderPointTargets`'s `role="img"` (tooltip-only, non-actionable) is a defensible convention distinct from `renderMarkerSingle`'s defect (actionable) | Accessibility | If the intended standard is actually "every focusable SVG element should use a more precise ARIA pattern than `role="img"`" regardless of actionability, these two also need fixing and were under-scoped here |
| A5 | Sparklines, temperature row, service thumbnail previews, and uptime-strip day labels being dark-mode-only via `display: none` are candidates needing a parity decision (rather than confirmed as acceptable decorative omissions) | Current Theming Reality | If some of these are actually intentional, well-considered dark-mode-only decorations (matching the calm-light product intent), "fixing" them risks cluttering light mode against the product's own stated design direction (`PROJECT.md`: "light mode is simpler and calmer") |

## Open Questions

1. **Does UX-01's "compact analytics previews" include the sparklines that are currently
   `display: none` in light mode?**
   - What we know: `style.css:353` hides `.sparkline` entirely under `html.light`; the arc gauges
     (CPU/RAM/disk percentage rings) remain visible in both themes and already carry the primary
     "at a glance" numeric readout.
   - What's unclear: whether the sparkline (a small trend-over-time line, distinct from the current
     numeric value) counts as part of "compact analytics previews" the requirement protects, or
     whether the arc gauges alone satisfy it and the sparkline's light-mode omission is a deliberate,
     acceptable "calmer" simplification consistent with the product's stated light-mode intent.
   - Recommendation: this is squarely a planner/user call — flag it explicitly in planning rather than
     silently choosing "add it" (scope growth) or "leave it hidden" (potential requirement violation).

2. **Is the uptime strip's color-coding (`up`/`down`/`partial`/`unknown`) accompanied by an adjacent
   text label anywhere, satisfying UX-06 for that specific element?**
   - What we know: the class names (`us.up`/`us.down`/`us.partial`/`us.unknown`,
     `dashboard/app.js:188`) are computed from data and applied to small colored segments
     (`.uptime-strip`, `style.css:560-574`); nearby `.uptime-labels` show day labels (hidden in light
     mode per `style.css:574`), not per-segment state labels.
   - What's unclear: whether each segment has an accessible name (e.g. a `title`/`aria-label` per
     segment) — this research pass did not read the uptime-strip render function in `app.js` closely
     enough to confirm or deny.
   - Recommendation: Wave-0-level code read of the uptime-strip render function before planning tasks
     for UX-06, to convert this from "open question" to "confirmed gap" or "confirmed compliant."

3. **What is the intended scope boundary between this phase's accessibility work and Phase 6's OPS-02
   "visible non-fatal degraded state"?**
   - What we know: OPS-02 (Phase 6) explicitly introduces a "degraded" state for preview/thumbnail
     work specifically; UX-07 (this phase) asks for a general "degraded" state across "loading, empty,
     stale, unknown, degraded, and error."
   - What's unclear: whether Phase 5 should define "degraded" generally (and Phase 6 reuses that
     definition for previews) or whether each phase defines its own narrower "degraded" for its own
     domain, risking two different meanings of the same word in the product.
   - Recommendation: Phase 5 should define "degraded" in a way general enough for Phase 6 to adopt
     without renaming/redefining it — worth an explicit cross-phase note in whatever CONTEXT.md or
     UI-SPEC Phase 5 produces, so Phase 6 doesn't repeat this research question.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Node.js | `tests/test_ui_contract.py`'s `node -e` subprocess calls (existing pattern for JS-unit-style assertions) | ✓ | v22.14.0 | — |
| Python | Test suite / `uv run` | ✓ | 3.11.15 | — |
| Playwright (Python) | All browser-driven UI tests | ✓ (import confirmed) | 1.61.0 (pinned, `dashboard/pyproject.toml:11`) | — |
| Playwright Chromium browser binary | `browser = playwright.chromium.launch(...)` in every UI test's `setUpClass` | ✓ | chromium-1208/1228 present in local cache | — |
| `uv` | Project's documented test command (`.planning/config.json` `test_command: "uv run --project dashboard python -m pytest -q"`) | Not directly probed this session (test command references it; assumed present since it's the project's own documented invocation) | — | If absent, `pip install -e` + `pytest` directly is the fallback, but this was not needed/tested |

**Missing dependencies with no fallback:** None identified.

**Missing dependencies with fallback:** None identified — everything this phase needs (per every
research finding above: no new package, only existing-stack CSS/JS/test work) is already present and
working in this environment.

## Validation Architecture

`workflow.nyquist_validation` is `true` in `.planning/config.json` (absent-defaults-to-enabled, and
here explicitly set) — this section is required.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `pytest` (`pytest>=9.0.2,<10`, `dashboard/pyproject.toml:16`), with `playwright.sync_api` for browser-driven tests |
| Config file | `dashboard/pyproject.toml:22-25` (`[tool.pytest.ini_options]`, `testpaths = ["../tests"]`) |
| Quick run command | `uv run --project dashboard python -m pytest tests/test_ui_states.py tests/test_advanced_ui.py tests/test_ui_contract.py -q` (scoped to the UI-relevant modules for fast iteration) |
| Full suite command | `uv run --project dashboard python -m pytest -q` (project's own documented `test_command`, `.planning/config.json`) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| UX-01 | Compact previews visible in both themes | browser/UI-contract | `pytest tests/test_ui_states.py -k zero_one_many -q` (existing dual-theme test; extend, don't replace) | ✅ existing, extend |
| UX-03 | Advanced workspace data/filters/settings/investigations identical in both themes | browser/UI-contract | `pytest tests/test_advanced_ui.py -k both_themes -q` (existing dual-theme test; extend) | ✅ existing, extend |
| UX-04 | Density mechanism actually changes disclosure/grouping, not just padding | browser/UI-contract (new assertions) | New test asserting `<details>`/disclosure `open` attribute state differs by density class | ❌ Wave 0 — new assertions needed once the density-extension mechanism is chosen |
| UX-05 | Narrow/desktop usability | browser, viewport-parameterized | `pytest tests/test_ui_states.py tests/test_advanced_ui.py -k narrow -q` (existing viewport-size pattern; extend) | ✅ existing, extend |
| UX-06 | Keyboard-accessible, non-colour-only encodings | browser, ARIA/keyboard-focused | New/extended tests asserting `role`, `aria-label`, `Tab`-reachability, and text-label presence alongside color | ❌ Wave 0 gap — no existing test asserts `role="button"` on the marker; must be added alongside the fix |
| UX-07 | Six states visibly distinct in both themes | browser/UI-contract, state-parameterized | New tests per state, extending the existing `page.route()` fixture-stubbing pattern already used throughout `test_history_investigation_ui.py`/`test_ui_states.py` | ❌ Wave 0 gap for "degraded" specifically — no existing fixture/state to extend from |
| OPS-06 | Dual-theme coverage of shared capabilities/states | browser, theme-parameterized | Extend `tests/test_advanced_ui.py`'s existing `for theme in ('dark', 'light')` subtest pattern to every new/audited surface | ✅ pattern exists, needs breadth not new infrastructure |

### Sampling Rate
- **Per task commit:** quick run command above (UI-relevant modules only, ~seconds given the existing
  suite's demonstrated speed — e.g. `4 passed in 3.32s` for a comparable Playwright subset per
  `04-VERIFICATION.md`'s own spot-check evidence)
- **Per wave merge:** full suite command
- **Phase gate:** Full suite green before `/gsd-verify-work`, matching every prior phase's established
  gate discipline (`04-VERIFICATION.md` re-verification rounds all re-ran targeted + full suites)

### Wave 0 Gaps
- [ ] A named test/fixture for the "degraded" state, once the planner/user resolves Open Question 3 —
  no existing fixture or route-stub represents this state today.
- [ ] An ARIA-role regression test for `renderMarkerSingle` (`role="button"`, not `role="img"`) —
  the fix is diagnosed but no test currently pins it, unlike every other interactive element in the
  same file.
- [ ] A `<details>`/disclosure-state assertion for whatever density-extension mechanism the planner
  chooses (Option 1 under "Light-vs-Dark Density Asymmetry") — no existing test asserts anything about
  progressive disclosure differing by density/theme.
- [ ] Framework install: none — pytest, Playwright, and the Chromium binary are all already present
  and working in this environment (see Environment Availability).

## Security Domain

`security_enforcement` is `true` and `security_asvs_level` is `1` in `.planning/config.json` — this
section is required.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Beacon has no accounts/auth surface (`PROJECT.md` Out of Scope: "Accounts, roles, or multi-user operation"); unaffected by theming/accessibility work |
| V3 Session Management | No | No session concept beyond `localStorage` preference persistence, already validated (Phase 3 D-14, Phase 4 D-18) |
| V4 Access Control | No | `/advanced` is already GET-only, no-selector, validated against 46 blocking threats (`03-SECURITY.md`, `threats_open: 0`); this phase does not add routes, parameters, or mutation surfaces |
| V5 Input Validation | Marginal | This phase's only "input" surface is browser-local preference values (theme, density) — the existing `loadPreferences()`/`validHistoryRange()`-style strict-allowlist validation pattern (`advanced.js:105-217`) is the established standard and should be followed if any new preference key (e.g. an explicit density-extension setting) is added |
| V6 Cryptography | No | Not applicable — no new cryptographic surface introduced |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| A malformed/hostile `localStorage` value for a new preference key (e.g. a future density-extension setting) | Tampering | Follow the existing strict-allowlist validator pattern (`validHistoryRange`, `validSelectedService`, `validHistoryFilters` — `advanced.js:121-182`): any unrecognised/malformed stored value resolves to the documented default, never trusted directly into a request or render path |
| A new ARIA `aria-label`/text content built from unescaped operator-controlled data (e.g. a service display name) | Tampering / Information Disclosure (XSS via DOM) | Continue the existing convention of `textContent`/`setAttribute` (never `innerHTML`/`insertAdjacentHTML`) — confirmed zero uses of either HTML sink in `advanced.js` (`04-VERIFICATION.md` spot-check: `grep -c "innerHTML\|insertAdjacentHTML" dashboard/advanced.js` → `0`); this phase must not introduce the first one while adding new label text |

No new blocking threats are anticipated from this phase's scope (CSS/JS presentation, test coverage,
no new routes/params/mutations) beyond the one V5 note above, which is a "follow the existing pattern"
item rather than a novel risk.

## Sources

### Primary (HIGH confidence — direct codebase reads, this session)
- `dashboard/style.css` (full file, 1,318 lines) — token system, light/dark overrides, breakpoints
- `dashboard/advanced.css` (full file, 299 lines) — density rules, chart/marker/incident styling, breakpoints
- `dashboard/advanced.js` (targeted reads: lines 1-240, 700-773, 1560-1630, 2420-2460) — theme/density
  application, ARIA role usage, preference validation
- `dashboard/app.js` (targeted grep + reads) — theme toggle, connection/worker state
- `dashboard/beacon/diagnosis.py` (lines 80-119) — `freshness_state` vocabulary
- `tests/test_ui_contract.py` (full file, 191 lines), `tests/test_advanced_ui.py` (targeted, ~230
  lines), `tests/test_ui_states.py` (targeted, ~700 lines), `tests/test_history_investigation_ui.py`
  (targeted, ~150 lines), `tests/helpers.py` (full file) — existing test-harness conventions
- `.planning/REQUIREMENTS.md`, `.planning/PROJECT.md`, `.planning/STATE.md`, `.planning/ROADMAP.md`,
  `.planning/config.json` — requirement wording, locked decisions, workflow config
- `.planning/phases/04-historical-investigation/04-CONTEXT.md`, `04-UI-SPEC.md`, `04-VERIFICATION.md`,
  `04-REVIEW.md`, `04-11-REVIEW.md` — inherited accessibility debt, prior decisions binding on Phase 5
- `.planning/phases/03-advanced-current-diagnosis/03-CONTEXT.md` (D-16 excerpt) — origin of the
  density mechanism

### Secondary (MEDIUM confidence)
- WebSearch: "Playwright Visual Regression: Baselines, Flake & CI Guide 2026" (testquality.com) —
  flakiness sources and CI tradeoffs for pixel-snapshot testing, used to support the visual-regression
  tooling recommendation
- WebSearch: W3C "Understanding Success Criterion 1.4.1: Use of Color" (w3.org/WAI/WCAG21) — the
  authoritative definition behind UX-06's "not colour alone" requirement

### Tertiary (LOW confidence)
- None — no unverified/single-source claims were relied upon for a phase-defining recommendation in
  this document; every claim above is either a direct codebase read or an explicitly flagged
  `[ASSUMED]`/Open Question.

## Metadata

**Confidence breakdown:**
- Standard stack / architecture: HIGH — everything is a direct read of the existing, working codebase;
  no new library or pattern is being introduced
- Density/theme-parity design direction: MEDIUM — the mechanism is verified, but the *scope* of what
  needs to change is genuinely open (no CONTEXT.md), so several items are correctly flagged as planner
  decisions rather than research conclusions
- "Degraded" state definition: LOW — this is a genuine, unresolved product-semantics gap; flagged
  prominently rather than resolved, per the phase's own "no CONTEXT.md, surface options" instruction
- Visual-regression/OPS-06 tooling recommendation: MEDIUM-HIGH — strong internal precedent (existing,
  passing tests) plus external corroboration (WebSearch) for the flakiness/CI tradeoff reasoning
- Accessibility inherited debt: HIGH for the `renderMarkerSingle` fix (independently confirmed by two
  separate prior verification rounds plus this session's own direct read); MEDIUM for the two
  newly-flagged `role="img"` tooltip-only instances (structurally observed this session, not
  previously adjudicated by any prior round)

**Research date:** 2026-08-26
**Valid until:** Effectively for the duration of this phase's planning and execution — the findings
are direct reads of the current repository state, not externally-sourced facts subject to drift, with
the exception of the two WebSearch citations (general web/accessibility practice, low volatility;
valid ~180 days).
