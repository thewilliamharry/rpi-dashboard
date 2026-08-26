# Phase 5 Context: Theme-Parity Analytics Experience

**Captured:** 2026-08-26
**Source:** Targeted decisions captured during `/gsd-plan-phase 5`, after `05-RESEARCH.md` surfaced
three questions that are product decisions rather than technical ones.

> **Provenance note — read this before treating the file as a normal CONTEXT.md.**
> A full `/gsd-discuss-phase` pass was deliberately declined for this phase. This file is NOT the
> output of that workflow and does not carry its breadth. It records exactly three decisions the
> user answered directly, plus the scope fences inherited from Phase 4. Everything else in this
> phase remains an open planner decision that MUST be recorded as an explicit assumption in the
> plan — absence of a decision here means "not decided", never "planner's discretion, unrecorded".

---

## Decisions

### D-01 — "degraded" is a server-emitted state, not a client-side guess

**Decision:** Define `degraded` server-side (in the `beacon/diagnosis.py` classification tier) from
durable evidence, then render it client-side. Accept the backend change this requires.

**Rationale:** `05-RESEARCH.md` verified that `degraded` has **zero wire vocabulary anywhere in the
codebase** — a grep across `dashboard/` returns no hits in any `.py`/`.js`/`.html`/`.css` file. It is
a genuine definitional gap, not a coverage gap. Beacon's established split is "server classifies,
client renders" (the existing `freshness_state`: fresh/aging/stale/unknown follows it). Computing
`degraded` from an ad-hoc client heuristic would put a confident-looking label in front of the
operator that no observed evidence backs — the same class of defect Phase 4 spent three verification
rounds eliminating.

**Constraints on the implementation:**
- The server must decide what durable evidence constitutes `degraded`, and that evidence must be
  distinguishable from `stale` and from `unknown` — if it cannot be distinguished, say so rather
  than emitting a state that overlaps an existing one.
- Do not invent a time-threshold heuristic ("degraded after N seconds") — `05-RESEARCH.md` Pitfall 3
  names this explicitly.
- Phase 6's OPS-02 involves a non-fatal degraded state. Prefer a definition Phase 6 can reuse over
  one that will need redefining; if that is not possible without speculating about Phase 6, define
  it narrowly for Phase 5 and record the limitation.

### D-02 — extend the existing density mechanism to drive progressive disclosure

**Decision:** Reuse and extend the density mechanism that already exists (`03-CONTEXT.md` D-16;
implemented `dashboard/advanced.js:223-227`, styled `dashboard/advanced.css:30-32`) so that it
governs progressive disclosure as well as spacing — e.g. driving default open/closed state of
disclosure containers. Do **not** build a second, parallel mechanism.

**Rationale:** The mechanism exists but is shallow (three padding/gap rules). Criterion 2 asks for
light = calmer progressive disclosure, dark = denser simultaneous context. One mechanism governing
both spacing and disclosure delivers that without forking the UI into two theme-specific codebases —
which `05-RESEARCH.md` flags as the main risk in this phase.

**Invariant this must preserve:** density and disclosure change *what is shown by default*, never
*what is reachable*. Both themes must expose the same advanced analytics data, filters, settings, and
investigation workflows. A control that exists in dark mode and is unreachable in light mode is a
parity defect, not a density choice.

### D-03 — on the main dashboard, arc gauges alone satisfy UX-01 in light mode

**Decision:** The existing `html.light .foo { display: none }` overrides that hide sparklines, the
temp row, service previews, and uptime labels in light mode are **deliberate calm, not a parity
defect**. Light mode keeps the quieter arc-gauge presentation, and UX-01 is satisfied by the gauges.

**This is an explicit interpretation of UX-01 and must be recorded as such in the plan** — UX-01's
wording ("compact analytics and history previews on the main dashboard in both light and dark
themes") admits a stricter reading in which light mode must show the previews. The plan must state
that it adopts the calmer reading, so a later verifier evaluates the phase against the decision
actually made rather than re-deriving the requirement from scratch.

**Do not conflate D-03 with D-02.** They apply to different surfaces and are not in tension:
- **Main dashboard** (UX-01 / criterion 1) — light mode stays calm; hidden elements stay hidden.
- **Advanced workspace** (criterion 2) — full capability parity, with density driving disclosure.

A plan that hides advanced-workspace capability in light mode by citing D-03 has misread it.

---

## Inherited scope — work Phase 4 deliberately deferred into Phase 5

Phase 4 fenced accessibility work out of its own scope and recorded these for Phase 5 to inherit.
They are in scope now:

- **`renderMarkerSingle` role mismatch** — `role="img"` / `role="button"` inconsistency at
  `dashboard/advanced.js:1610-1611`. A concrete fix is already specified in
  `04-REVIEW.md` (WR-02) and the defect is recorded in `04-VERIFICATION.md` Anti-Patterns. It was
  confirmed present by two independent verification rounds.
- **Keyboard equivalents** for interactions named in `04-CONTEXT.md` R-03: drag-to-select, the hover
  cursor, the marker rail, the state band, and the coverage strip.
- Any further accessibility debt catalogued in `05-RESEARCH.md` — inherit the full list rather than
  rediscovering items piecemeal.

## Related tracked debt (not Phase 5 scope unless the planner argues otherwise)

- **Stale incident count on filtered-fetch failure** — `dashboard/advanced.js` (~1421-1430): the
  early-return path when the filtered `/api/events/history` request fails never resets
  `#matching-incident-count`, so a prior render's text can persist beside an error banner. Recorded
  as tracked debt in `04-VERIFICATION.md` Anti-Patterns and as the single Info finding in
  `04-11-REVIEW.md`. Phase 4's verifier judged it below the gap threshold because an explicit error
  banner always accompanies it. It touches UX-07's state-distinctness goal, so the planner may pull
  it in — but should say so deliberately rather than absorbing it silently.

---

## Open questions NOT decided here

These remain open. The planner must record its choice on each as an explicit, visible assumption:

1. Whether the uptime strip has per-segment text labels or relies on colour alone (needs a code read —
   `05-RESEARCH.md` open question 2).
2. The exact scope of the theme-parity audit across the scattered `html.light` layout/visibility
   overrides beyond the four named in D-03.
3. OPS-06 tooling: `05-RESEARCH.md` recommends extending the existing `getComputedStyle`/Playwright
   dual-theme DOM-contract pattern (proven at
   `tests/test_advanced_ui.py::test_every_interactive_control_reads_as_interactive_in_both_themes`)
   rather than adding pixel snapshots, which would double artifacts and add CI flakiness with no
   existing review workflow. The planner should follow that recommendation or argue against it
   explicitly.
