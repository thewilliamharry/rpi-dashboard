No external API integration: the detector fired on the phrase "consumes `/api/scan-status`", which is Beacon's own first-party Flask route, and this phase adds no external API, SDK, or service — it audits CSS/JS/HTML presentation, adds keyboard and ARIA affordances, and adds two additive fields to Beacon's own existing internal payloads.

## Why the detector fired, and why there is no matrix

The phase scope references Beacon's own internal HTTP routes (`/api/scan-status`,
`/api/advanced/current`, `/api/telemetry/history`, `/api/events/history`, `/api/config`, and the
main dashboard's `/api/stats`, `/api/history`, `/api/services`, `/api/events`). Every one of these
is served by `dashboard/app.py` in this same repository and is consumed only by this project's own
two browser documents. There is no third-party capability surface to enumerate, so a capability
matrix would have to be fabricated rather than derived.

Corroborating evidence, already recorded rather than re-derived here:

- `05-RESEARCH.md` → "Package Legitimacy Audit": *"Not applicable. This phase … is scoped to
  CSS/JS/HTML restructuring and existing-dependency test coverage. No new third-party package in
  any ecosystem is indicated by any research finding."*
- `05-UI-SPEC.md` → "Registry Safety": registry `none`, blocks used `none` — *"the project is
  dependency-free vanilla JavaScript and no third-party registry is declared."*
- `05-RESEARCH.md` → "Environment Availability": every dependency this phase needs (pytest,
  Playwright, the Chromium binary) is already present and pinned; nothing new is added.

The one server-side change in scope — the additive `worker_freshness` and `worker_degraded` fields
on `/api/scan-status` and on `/api/advanced/current`'s `safety` block (plan 05-01) — extends a
first-party payload this project both produces and consumes. It is covered by that plan's own
`must_haves`, `<threat_model>` and acceptance gates, not by an external-API coverage matrix.
