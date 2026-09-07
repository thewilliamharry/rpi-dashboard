# Phase 5: Theme-Parity Analytics Experience - Pattern Map

**Mapped:** 2026-08-26
**Files analyzed:** 6 (all modifications; no new files indicated by CONTEXT.md/RESEARCH.md)
**Analogs found:** 6 / 6 — this is a brownfield "extend in place" phase; every touched file already
contains the pattern it must be extended with elsewhere in the same file. There is no cross-file
scaffold to copy — the analog for each file is itself, at a different line range.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `dashboard/beacon/diagnosis.py` (add `degraded` classification) | service (server-side classifier) | transform (durable evidence → state literal) | `freshness_state()`, same file, lines 101-119 | exact — same file, same function shape |
| `dashboard/style.css` (theme-parity audit: `html.light` overrides) | config/style (token + override rules) | transform (CSS custom property resolution) | Token block, same file, lines 4-41 | exact — extend the tokenized pattern into the untokenized overrides |
| `dashboard/advanced.css` (density → disclosure extension) | config/style (density-scoped rules) | transform | `.density-comfortable`/`.density-compact` rules, same file, lines 30-32 | exact — same mechanism, more rules |
| `dashboard/advanced.js` (`applyDensity`, disclosure wiring, `renderMarkerSingle` fix, keyboard-cursor extension) | component/controller (client render + interaction wiring) | event-driven (DOM interaction) + request-response (state render) | `renderMarkerCluster` (1565-1580), `renderPointTargets` (2431-2456), `applyDensity` (223-227), same file | exact — role-correct ARIA sibling + focus/tooltip pattern already present |
| `dashboard/app.js` (uptime-strip accessible-name audit, theme regression coverage) | component (client render) | request-response | `uptimeStrip()`, same file, lines 181-197 | exact — file already has the surface to audit |
| `tests/test_advanced_ui.py` / `tests/test_ui_states.py` / `tests/test_ui_contract.py` (new/extended dual-theme + accessibility assertions) | test | browser/UI-contract | `test_every_interactive_control_reads_as_interactive_in_both_themes`, `tests/test_advanced_ui.py:164-292` | exact — proven, passing, zero-setup-cost pattern to extend, not replace |

## Pattern Assignments

### `dashboard/beacon/diagnosis.py` — new `degraded` classification (D-01)

**Analog:** `freshness_state()`, same file, lines 101-119.

**Core pattern to copy verbatim in shape** (`dashboard/beacon/diagnosis.py:101-119`):
```python
def freshness_state(now, sample_ts, cadence_seconds):
    """Classify durable sampling evidence without inferring its cause."""
    if (
        type(now) is not int
        or type(sample_ts) is not int
        or type(cadence_seconds) is not int
        or cadence_seconds <= 0
    ):
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

**What to copy:**
- Strict type/shape guarding before any classification logic (fail to `unknown`/equivalent, never
  guess) — same discipline the `degraded` classifier must follow (D-01 constraint: distinguishable
  from `stale` and `unknown`, no ad-hoc time-threshold heuristic per Pitfall 3).
- A pure function taking only durable evidence values as arguments (`now`, `sample_ts`,
  `cadence_seconds`) — no hidden global state, no client-observable side effect — so the new
  `degraded` function is trivially testable the same way `freshness_state` already is.
- Return shape is a small dict with a `state` literal plus supporting numeric evidence
  (`age_seconds`) — the wire contract new callers key off of.

**Wiring points to replicate** — every call site that currently calls `freshness_state(...)` and
folds the result into a `'freshness'` key (`diagnosis.py:144, 169, 288, 359, 442`) is the template for
where a `degraded` computation would be composed alongside it, e.g.:
```python
# dashboard/beacon/diagnosis.py:169 (pattern to extend, not the exact line to copy)
'freshness': freshness_state(now, sample_ts, cadence_seconds),
```

**Constraint from CONTEXT.md D-01:** do not merge `degraded` into `freshness_state`'s own four-value
enum — keep it a distinct field/function per the "distinct facts stay distinct" convention (also
stated in `04-CONTEXT.md` "Established Patterns", cited in `05-RESEARCH.md` lines 541-542).

---

### `dashboard/style.css` — theme-parity audit of `html.light` overrides (D-03, UX-01/UX-03)

**Analog:** the token block itself, `dashboard/style.css:4-41` (verbatim, quoted in full below) —
this is the "correct" pattern (color expressed as a token resolved per-theme); the override rules
below it are the audit surface, not the pattern to imitate.

```css
html {
  --bg:           #010a14;
  --bg2:          #030f1e;
  --bg3:          #041525;
  --border:       rgba(0,180,220,0.18);
  --border2:      rgba(0,180,220,0.06);
  --text:         #c8eaf5;
  --muted:        #3a7a96;
  --muted2:       #1a4a6a;
  --accent:       #00d4ff;
  --accent2:      #ffab00;
  --accent3:      #7b6fff;
  --green:        #00ff88;
  --red:          #ff3d3d;
  --gauge-bg:     #041525;
  --gauge-w:      5;
  --hud:          1;
  --font-sans:    -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --font-mono:    ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}
html.light {
  --bg:           #ffffff;
  --bg2:          #ffffff;
  --bg3:          #f7f7f7;
  --border:       rgba(0,0,0,0.06);
  --border2:      rgba(0,0,0,0.03);
  --text:         #0a0a0a;
  --muted:        #b0b0b0;
  --muted2:       #e8e8e8;
  --accent:       #0066cc;
  --accent2:      #b45309;
  --accent3:      #5b21b6;
  --green:        #16a34a;
  --red:          #dc2626;
  --gauge-bg:     #e5e7eb;
  --gauge-w:      1.5;
  --hud:          0;
}
```

**Audit surface — full enumerated list of `display: none` under `html.light` (grep-verified,
`dashboard/style.css`):**
| Line | Rule | Surface | D-03 disposition |
|---|---|---|---|
| 296 | `html.light .arc-unit { display: none; }` | main dashboard, gauge unit label | keep — decorative, part of calm reading |
| 353 | `html.light .sparkline { display: none; }` | main dashboard, per-service trend line | D-03 covers this: calm reading, gauges alone satisfy UX-01 — keep hidden, record as deliberate |
| 363 | `html.light .temp-row { display: none; }` | main dashboard, temperature readout row | D-03 covers this — keep hidden |
| 410 | `html.light .corner { display: none; }` | main dashboard, HUD-corner sci-fi decoration | keep — explicitly decorative per RESEARCH.md, not a parity concern |
| 437 | `html.light .svc-preview { display: none; }` | main dashboard, service thumbnail preview | D-03 covers this — keep hidden |
| 522 | `html.light .svc-uptime-pct { display: none; }` | main dashboard, per-service 7d uptime % text | **not named by D-03** — needs an explicit planner call; adjacent to `uptimeStrip()` which does render (see below) |
| 574 | `html.light .uptime-labels { display: none; }` | main dashboard, uptime-strip day labels ("7d ago"/"now") | D-03 covers this — keep hidden |
| 583 | `html.light .offline-badge { display: none; }` | main dashboard, offline badge | **not named by D-03** — needs an explicit planner call (this looks like a capability signal, not decoration) |

Only 4 of these (353, 363, 437, 574) are the ones D-03 explicitly names as deliberate calm. Lines 296,
410, 522, 583 are outside D-03's named scope and must get an explicit planner disposition rather than
being silently swept into "already decided."

**Do not tokenize these as a shortcut** — D-03 says keep them hidden by disposition, not "convert
`display: none` into a token." Only cross-cutting *color* divergence belongs in the `:root`/`html.light`
token block above; layout/visibility divergence stays as scoped override rules, audited and recorded,
per RESEARCH.md's Pitfall 1 warning against treating parity as purely a token problem.

**Breakpoint mismatch to reconcile or document (Assumption A3):**
```css
/* dashboard/style.css:1215 */
@media (max-width: 720px) { /* main dashboard narrow layout */ }
/* dashboard/advanced.css:99 */
@media (max-width: 719px) { /* advanced workspace narrowest layout */ }
```

---

### `dashboard/advanced.css` — extend density mechanism to drive disclosure (D-02)

**Analog:** the existing three-rule density block, `dashboard/advanced.css:30-32` (verbatim):
```css
.density-comfortable .advanced-detail { gap: 32px; }
.density-comfortable .diagnosis-card, .density-comfortable .evidence-row { padding: 16px; }
.density-compact .diagnosis-card, .density-compact .evidence-row { padding: 8px; }
```

**Working `<details>` progressive-disclosure precedent already in the file** (`advanced.css:220-230`,
class names only shown; full CSS at those lines):
```css
.hist-band-header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 8px; }
.hist-availability-headline { margin: 0; font-family: var(--font-mono); font-size: 28px; font-weight: 600; }
.hist-availability-detail summary { cursor: pointer; font-size: 12px; color: var(--muted); }
.hist-availability-detail p { margin: 4px 0 0; font-size: 12px; font-family: var(--font-mono); color: var(--muted); }
```
`.hist-availability-detail` is a real `<details>` element already in `advanced.html`/rendered by
`advanced.js` — a collapsed-by-default `<summary>` disclosure wrapper around secondary detail. This is
the existing DOM shape D-02's extension should reuse: wrap the same kind of secondary content in
`<details>` and drive the `open` attribute from the density class (e.g. `density-compact` sections
start `open`, `density-comfortable` sections start closed) rather than writing a second render path.

**Pattern to copy for new density-scoped rules:** same selector shape as the three existing rules
(`.density-comfortable X { ... }` / `.density-compact X { ... }`), scoped to a short, explicitly named
list of surfaces (per RESEARCH.md Pitfall 2 — do not apply workspace-wide).

---

### `dashboard/advanced.js` — density/disclosure wiring, ARIA fix, keyboard-cursor extension

**Analog for `applyDensity` extension:** same file, lines 223-227 (verbatim):
```js
function applyDensity() {
  const density = state.preferences.density || (document.documentElement.classList.contains('light') ? 'comfortable' : 'compact');
  document.body.classList.toggle('density-comfortable', density === 'comfortable');
  document.body.classList.toggle('density-compact', density === 'compact');
}
```
Extend by toggling `open` attributes / classes on named disclosure wrappers from this same function
(or a sibling function called immediately after it), not by branching render functions on density.

**Confirmed defect and its verbatim fix — `renderMarkerSingle`** (`dashboard/advanced.js:1602-1620`,
current/broken state, quoted in full):
```js
function renderMarkerSingle(marker) {
  const {episode, x} = marker;
  const circle = document.createElementNS(SVG_NS, 'circle');
  circle.setAttribute('cx', String(x));
  circle.setAttribute('cy', '8');
  circle.setAttribute('r', '4');
  circle.setAttribute('class', 'hist-marker');
  circle.setAttribute('tabindex', '0');
  circle.setAttribute('role', 'img');
  const text = markerTitle(episode);
  circle.setAttribute('aria-label', text);
  const title = document.createElementNS(SVG_NS, 'title');
  title.textContent = text;
  circle.append(title);
  circle.addEventListener('click', () => focusIncident(episode));
  circle.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); focusIncident(episode); }
  });
  return circle;
}
```
**Fix (from `04-REVIEW.md` WR-02, apply near-verbatim):** change
`circle.setAttribute('role', 'img')` → `circle.setAttribute('role', 'button')`, and change the
`aria-label` text to `Investigate ${text}` to match the action, not just describe the shape.

**Correct sibling pattern already in the same file to match** — `renderMarkerCluster`
(`dashboard/advanced.js:1565-1580`, verbatim excerpt of the relevant lines):
```js
function renderMarkerCluster(group) {
  ...
  const g = document.createElementNS(SVG_NS, 'g');
  g.setAttribute('class', 'hist-marker-cluster');
  g.setAttribute('tabindex', '0');
  g.setAttribute('role', 'button');
  g.setAttribute('aria-label', summary);
  ...
}
```
This is the confirmed-correct ARIA pattern (`role="button"` on a click/keydown-actionable SVG element)
`renderMarkerSingle` must be brought into line with.

**Focus-triggered tooltip pattern — the template for the keyboard hover-cursor equivalent
(R-03)** — `renderPointTargets`, `dashboard/advanced.js:2431-2456` (verbatim):
```js
function renderPointTargets(metric, points, scale) {
  const svg = $(`chart-${metric}`);
  if (!svg) return;
  svg.querySelectorAll('.hist-point-target').forEach((node) => node.remove());
  (Array.isArray(points) ? points : []).forEach((point) => {
    if (point.avg_value === null || point.avg_value === undefined) return;
    const target = document.createElementNS(SVG_NS, 'circle');
    target.setAttribute('cx', String(scale.xFor(point.ts)));
    target.setAttribute('cy', String(scale.yFor(point.avg_value)));
    target.setAttribute('r', '6');
    target.setAttribute('class', 'hist-point-target');
    target.setAttribute('tabindex', '0');
    target.setAttribute('role', 'img');
    const unit = HOST_METRIC_UNITS[metric] || '';
    const label = HOST_METRIC_LABELS[metric] || metric;
    target.setAttribute('aria-label', `${label} ${point.avg_value}${unit} at ${formatLocalTimestamp(point.ts)}`);
    target.addEventListener('pointerover', (event) => schedulePointTooltipUpdate(metric, point, event.clientX, event.clientY));
    target.addEventListener('pointerout', hidePointTooltip);
    target.addEventListener('focus', () => {
      const rect = target.getBoundingClientRect();
      schedulePointTooltipUpdate(metric, point, rect.left, rect.top);
    });
    target.addEventListener('blur', hidePointTooltip);
    svg.append(target);
  });
}
```
This `pointerover`/`focus` dual-wiring (same tooltip update function driven by both events) is the
existing, working template for extending the hover time-cursor to a keyboard equivalent — each
point-target's `focus` handler already drives the same readout the mouse path uses; R-03's remaining
gap is the continuous cursor, not per-point tooltips, which are already solved this way.

**Note on `role="img"` used above:** `renderPointTargets` and `renderServiceStateBand`
(`dashboard/advanced.js:751-758`, not fully quoted here) both use `role="img"` on focusable,
tooltip-only (non-click-actionable) elements. RESEARCH.md Assumption A4 flags this as a planner
decision — treat as the established convention (tooltip-disclosure = `role="img"`, action = `role=
"button"`) unless the plan explicitly overrides it; do not "fix" these two while fixing
`renderMarkerSingle` without an explicit stated reason.

**Density preference validation pattern to reuse if any new preference key is added** —
`dashboard/advanced.js:190-210` (loadPreferences, strict allowlist, excerpted):
```js
density: stored.density === 'comfortable' || stored.density === 'compact' ? stored.density : null,
```
Any new density-extension setting must follow this same strict-allowlist-else-default shape (matches
`validHistoryRange`/`validSelectedService` elsewhere in the file, and the V5 threat-pattern note in
RESEARCH.md's Security Domain section).

---

### `dashboard/app.js` — uptime-strip accessible-name audit (UX-06 Open Question 2)

**Analog/audit target:** `uptimeStrip()`, `dashboard/app.js:181-197` (verbatim):
```js
function uptimeStrip(values) {
  const wrapper = document.createElement('div');
  const strip = document.createElement('div');
  strip.className = 'uptime-strip';
  for (const value of values || []) {
    const segment = document.createElement('span');
    const n = Number(value);
    segment.className = `us ${n < 0 ? 'unknown' : n === 0 ? 'down' : n === 1 ? 'up' : 'partial'}`;
    segment.title = n < 0 ? 'No data' : `${(n * 100).toFixed(n === 1 ? 0 : 1)}% available`;
    strip.appendChild(segment);
  }
  const labels = document.createElement('div');
  labels.className = 'uptime-labels';
  labels.append(Object.assign(document.createElement('span'), {textContent: '7d ago'}), Object.assign(document.createElement('span'), {textContent: 'now'}));
  wrapper.append(strip, labels);
  return wrapper;
}
```
**Finding (resolves RESEARCH.md Open Question 2):** each segment already carries a `title` attribute
(`'No data'` / `'N% available'`) computed from the same data that drives its color class — this is a
per-segment accessible hint, but `title` alone is not reliably announced by assistive tech or visible
without hover, so it does **not** fully satisfy UX-06's "text labels ... not colour alone" on its own
the way the coverage-strip/Ongoing-badge precedents do (see below). Treat this as a confirmed partial
gap, not a confirmed pass: the color class (`us.up`/`us.down`/`us.partial`/`us.unknown`) is the only
thing driving both visual appearance and (via `title`) the hover text; there is no persistently visible
or `aria-label`-carried text equivalent per segment.

**Theme toggle wiring to replicate for any parity regression test** — `applyTheme`,
`dashboard/app.js:732-736`:
```js
function applyTheme(light) {
  document.documentElement.classList.toggle('light', light);
  $('toggle').setAttribute('aria-pressed', String(light));
  localStorage.setItem('beacon-theme', light ? 'light' : 'dark');
}
```
Note the `aria-pressed` state sync on the toggle button itself — this is the established pattern for
any new theme-adjacent control state that needs to be announced to assistive tech.

**Precedent for correct non-colour-alone encoding (already compliant, use as the model):** service
online/offline status pips are backed by adjacent text content (`ONLINE`/`OFFLINE`), confirmed by
`tests/test_ui_states.py:855`: `self.assertIn('ONLINE', page.locator('.svc-status-row').text_content())`.
This — persistently visible text content alongside the color-only pip — is the pattern any UX-06 fix
(including the uptime-strip gap above) should match, not the `title`-only hover-hint pattern.

---

### `tests/test_advanced_ui.py` / `tests/test_ui_states.py` / `tests/test_ui_contract.py` — dual-theme UI-contract extension (OPS-06)

**Analog:** `test_every_interactive_control_reads_as_interactive_in_both_themes`,
`tests/test_advanced_ui.py:164-233` (key excerpt, verbatim):
```python
def test_every_interactive_control_reads_as_interactive_in_both_themes(self):
    def computed(locator, prop):
        return locator.evaluate(f'(node) => getComputedStyle(node)[{prop!r}]')

    payload = self._snapshot()
    payload.update({...})
    for theme in ('dark', 'light'):
        with self.subTest(theme=theme):
            page = self.browser.new_page(viewport={'width': 1280, 'height': 900})
            if theme == 'light':
                page.add_init_script("localStorage.setItem('beacon-theme', 'light');")

            def route_api(route):
                if urlparse(route.request.url).path != '/api/advanced/current':
                    route.fallback()
                    return
                route.fulfill(status=200, json=payload)

            page.route('**/api/**', route_api)
            try:
                page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
                page.locator('[data-section="services"]').click()
                page.locator('#services-table').wait_for(timeout=5_000)
                ...
                self.assertEqual(computed(page.locator('#advanced-refresh'), 'cursor'), 'pointer')
                self.assertEqual(computed(page.locator('#advanced-refresh'), 'minHeight'), '44px')
                ...
            finally:
                page.close()
```

**What to copy exactly:**
- `page.add_init_script("localStorage.setItem('beacon-theme', 'light');")` before `page.goto` — the
  only mechanism used anywhere in the suite to force light mode pre-render (no query param, no
  server-side theme).
- `page.route('**/api/**', route_api)` fixture-stubbing pattern to supply deterministic payload data
  (including a synthetic `degraded`/new state literal once D-01's server field is defined) — this is
  the reusable fixture shape for UX-07's new-state tests, not a new stubbing mechanism.
- `with self.subTest(theme=theme):` wrapping so both themes report failures independently.
- `computed(locator, prop)` helper reading resolved `getComputedStyle` values, not raw CSS variable
  strings — required so token indirection cannot mask a real rendering bug (RESEARCH.md, dark/light
  color-resolution helper note, `tests/test_advanced_ui.py:1858-1867`).

**Narrow-viewport combination pattern to copy** (`tests/test_ui_states.py:826-872`, key lines):
```python
page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
...
page.goto(self.base_url, wait_until='networkidle')
# ... assert desktop/dark-mode state ...
page.set_viewport_size({'width': 720, 'height': 800})
page.locator('#toggle').click()
self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))
# ... assert narrow/light-mode state ...
```
Use this combined dual-theme + narrow-viewport shape for UX-05 regression coverage, rather than
writing separate theme-only and viewport-only tests.

**New assertions needed (no existing analog — genuinely new, not extension):**
- ARIA-role regression test pinning `renderMarkerSingle`'s fixed `role="button"` + `Investigate ...`
  aria-label (mirror the shape of an existing `role`/`aria-label` assertion elsewhere in
  `test_advanced_ui.py`, e.g. against `renderMarkerCluster`'s `role="button"`, `aria-label` if such an
  assertion exists — otherwise write it fresh using the same `computed`/`getAttribute` evaluate idiom).
- `<details>`/`open` attribute assertion for the density-driven disclosure extension — use
  `.evaluate('(node) => node.open')` against the `<details>` locator, gated by `density-comfortable`
  vs `density-compact` body class, following the same `for theme in (...)`/`subTest` shape.
- A `degraded`-state fixture (extend `route_api`'s `payload.update({...})` shape above with the new
  server field once D-01's `diagnosis.py` change lands) — no existing fixture represents this state.

## Shared Patterns

### Theme application (single source of truth, copy verbatim shape for any new surface)
**Source:** `dashboard/app.js:732-736` (main dashboard) and `dashboard/advanced.js:219-221` (advanced
workspace).
```js
// dashboard/app.js:732-736
function applyTheme(light) {
  document.documentElement.classList.toggle('light', light);
  $('toggle').setAttribute('aria-pressed', String(light));
  localStorage.setItem('beacon-theme', light ? 'light' : 'dark');
}
// dashboard/advanced.js:219-221
function applyTheme() {
  document.documentElement.classList.toggle('light', localStorage.getItem('beacon-theme') === 'light');
}
```
**Apply to:** any Phase 5 work touching theme state — never derive from `prefers-color-scheme`
(explicitly a non-goal per RESEARCH.md Anti-Patterns), never introduce a second toggle mechanism.

### Density mechanism (single source of truth for both spacing and, after D-02, disclosure)
**Source:** `dashboard/advanced.js:223-227` + `dashboard/advanced.css:30-32` (both quoted above).
**Apply to:** any new progressive-disclosure surface named in the plan's explicit, short list (per
RESEARCH.md Pitfall 2) — one DOM tree, class-gated visibility/open-state, never a second render path.

### Server classifies, client renders (D-01's binding convention)
**Source:** `dashboard/beacon/diagnosis.py:101-119` (`freshness_state`), consumed at
`diagnosis.py:144,169,288,359,442` and rendered client-side without recomputation.
**Apply to:** the new `degraded` field — server computes and emits it; `advanced.js`/`app.js` render
the literal, never infer it from timestamps/heuristics client-side (Pitfall 3).

### Correct interactive-SVG ARIA pattern
**Source:** `dashboard/advanced.js:1572-1574` (`renderMarkerCluster`) and the incident row
(`advanced.js:1214`, `row.setAttribute('role', 'button')`, not independently re-quoted here — same
shape).
```js
g.setAttribute('tabindex', '0');
g.setAttribute('role', 'button');
g.setAttribute('aria-label', summary);
```
**Apply to:** any click/keydown-actionable element — `role="button"` — vs. any focus-for-tooltip-only
element — `role="img"` (per `renderPointTargets`/`renderServiceStateBand` convention). Never mix the
two: actionable elements never keep `role="img"`.

### Never `innerHTML`/`insertAdjacentHTML` for new label text
**Source:** confirmed zero uses in `dashboard/advanced.js` (`04-VERIFICATION.md` spot-check,
re-cited in `05-RESEARCH.md` Security Domain).
**Apply to:** every new `aria-label`/text-content string this phase adds (e.g. `Investigate ${text}`,
any new uptime-strip label, any new degraded-state copy) — always `textContent`/`setAttribute`.

### Dual-theme Playwright subtest loop (OPS-06's mandated tooling — do not add pixel snapshots)
**Source:** `tests/test_advanced_ui.py:164-233`, quoted in full above under Pattern Assignments.
**Apply to:** every new/audited UI-contract assertion this phase adds. Do not introduce
`expect(locator).to_have_screenshot()` as the primary mechanism (RESEARCH.md recommendation, Pitfall 4)
— only as a narrowly-scoped, explicitly-decided supplement if the planner judges specific chart/pattern
legibility genuinely needs pixel coverage.

## No Analog Found

None. Every file this phase touches already contains a directly analogous pattern elsewhere in the
same file (this is the expected shape of an audit-and-extend phase per RESEARCH.md's primary
recommendation — no new architecture, mechanism, or file is indicated).

The only genuinely *new* code shapes with no existing precedent anywhere in the codebase:
| Concept | Role | Data Flow | Why no analog | Nearest structural template |
|---|---|---|---|---|
| `degraded` server-side classifier | service | transform | Zero wire vocabulary anywhere (`05-RESEARCH.md` line 21-24) | `freshness_state()` shape (function signature, guard-then-classify, dict return) |
| `<details>`-driven density→disclosure wiring | component | event-driven | Existing `<details>` (`.hist-availability-detail`) is static-collapsed, not density-driven | `.hist-availability-detail` DOM shape + `applyDensity()` class-toggle mechanism, composed together |
| Keyboard-equivalent continuous hover cursor | component | event-driven | Cursor is currently `pointermove`-only, no `focus` path | `renderPointTargets`'s `focus`→`schedulePointTooltipUpdate` wiring, extended to drive the shared cursor readout instead of/alongside the per-point tooltip |

## Metadata

**Analog search scope:** `dashboard/style.css`, `dashboard/advanced.css`, `dashboard/app.js`,
`dashboard/advanced.js`, `dashboard/beacon/diagnosis.py`, `tests/test_advanced_ui.py`,
`tests/test_ui_states.py`, `tests/test_ui_contract.py` — all read directly this session (targeted
ranges) or already fully characterized by `05-RESEARCH.md`'s direct-codebase-read primary sources.
**Files scanned:** 8 source/test files, all pre-existing (no directory search needed — CONTEXT.md and
RESEARCH.md name exact files and line numbers throughout).
**Pattern extraction date:** 2026-08-26
