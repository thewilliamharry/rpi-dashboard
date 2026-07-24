# Feature Landscape

**Domain:** Advanced local Raspberry Pi and service monitoring
**Researched:** 2026-07-24
**Overall confidence:** MEDIUM — project boundaries and current capabilities are HIGH-confidence codebase evidence; ecosystem conventions are corroborated by official Grafana and Prometheus documentation, but the exact prioritization is necessarily product judgement for a single-operator installation.

## Product Position

Beacon is not a general observability platform. The advanced page should answer one operator's two urgent questions: *what is wrong now?* and *has this Pi or one of its configured services been degrading or unavailable over the last 90 days?* The existing dashboard remains the glanceable surface, so the advanced page may be information-dense without making the ordinary route feel like an operations console.

The current implementation already provides current CPU/RAM/disk/temperature values, HTTP health/latency checks, service criticality/tags, time-weighted seven-day availability, events, and a one-day system history. It does **not** retain enough history or expose enough query/drill-down structure for the proposed 90-day diagnostic task. The feature set below intentionally turns those same concepts into coherent history and diagnosis, rather than introducing a second monitoring product.

## Table Stakes

Features an operator will expect from a credible advanced page. Missing one prevents reliable diagnosis.

| Feature | Why Expected | Complexity | Dependencies | Notes | Confidence |
|---|---|---:|---|---|---|
| Advanced-page entry and shared navigation | An operator must be able to move from the existing glanceable dashboard to the detailed workspace from either theme without losing the main dashboard's compact analytics. | Low | Stable routes/layout; existing theme preference | Link from both themes; retain a simple return path. Do not replace the current dashboard. | HIGH |
| Explicit current host state with freshness | Show CPU, memory, disk, temperature, hostname, sample timestamp, and a visible stale/unknown state so a frozen worker is not mistaken for a healthy Pi. | Medium | Worker heartbeat; system sampler; current `system_stats` | Values require units and current-versus-stale semantics, not only coloured gauges. | HIGH |
| Current service status inventory | Operators need every configured/discovered monitored HTTP service, health, latency or failure class, state-since time, criticality, tags, and effective health rule. | Medium | Service/meta/check domain boundary; safe URL handling | Filter and sort locally by status, criticality, and tag; preserve service links and metadata editing behavior. | HIGH |
| Date-range controls for diagnosis | Detailed monitoring must make the 90-day horizon explorable: presets (for example 1h, 24h, 7d, 30d, 90d), a bounded custom range, timezone-consistent labels, and optional bounded auto-refresh for live ranges. | Medium | Range-query API; client state/URL parameters | A shared time range is the minimum useful control for correlated host/service views. Grafana documents shared time settings, auto-refresh, and time-series pan/zoom as core dashboard interactions. | MEDIUM |
| 90-day host history | CPU, RAM, disk, and temperature need time-series charts with tooltip values, units, threshold context, and honest gaps/unknowns. Time series are appropriate when timestamped numeric values would be hard to inspect in a list. | High | New retention/roll-up schema; range-query APIs; chart renderer | Keep per-metric charts readable; never join missing samples with a false continuous line. | MEDIUM |
| 90-day service availability and latency history | Per-service drill-down must show selected-range availability, a state timeline, transition events, latency when online, error classes when offline, and explicit unknown/no-check intervals. | High | `service_checks`, events, service metadata; retention/aggregation | Calculate availability time-weightedly from boundary state, as the existing seven-day summary already does; do not average boolean samples. | HIGH |
| Incident/event investigation | A chronological, filterable event list must expose exact timestamps, service identity, transition direction, error class/details, and criticality; selecting an event should focus the relevant time window/service. | Medium | Canonical event store; range/event endpoints; UI selection model | Overlay events as chart annotations where useful, then keep the textual event list as the accessible source of detail. | MEDIUM |
| Correlated diagnosis view | During a selected incident/window, show host pressure beside the affected service's availability and latency so the operator can inspect correlation rather than switching screens. | High | Shared time range; host/service range APIs; event selection | Present evidence, not causal claims (e.g. “CPU was elevated during this window,” not “CPU caused the outage”). | HIGH |
| Bounded, visible retention | The UI must state that history is retained for 90 rolling days and distinguish retention expiry from an instrumentation gap. Cleanup must be deterministic and storage use observable. | High | Migration; roll-ups; cleanup scheduling; database health metric | Time alone is insufficient on a small Pi: cap the stored data and leave headroom. Prometheus documents using both time/size retention and background cleanup. | MEDIUM |
| Full monitoring capability in both themes | Theme selection must change presentation density, not page availability or monitoring data. Light is calm and readable; dark is denser and hands-on. | Medium | Shared semantic component/API contract; two theme styles | Use text, shape, labels, and contrast in addition to status colour. Preserve the existing deliberate theme behavior. | HIGH |
| Responsive and accessible inspection | Charts, service details, keyboard focus, tooltips, tables/event rows, and filters must work at small viewport widths and without colour-only status cues. | Medium | UI component contract; layout tests | The accessible textual state is essential when graphical density is reduced in light mode. | HIGH |

## Differentiators

Features that make Beacon notably better for its precise local-operator use case, without becoming a generic dashboard builder.

| Feature | Value Proposition | Complexity | Dependencies | Notes | Confidence |
|---|---|---:|---|---|---|
| Investigation context that follows the operator | A selected service, event, and time window remains synchronized across host charts, service history, and the event list; optionally encode only these bounded controls in the URL. | Medium | Client state model; range APIs | Removes repeated filtering during diagnosis; Grafana's documented variables and URL time context support the underlying interaction pattern. | MEDIUM |
| Monitoring-pipeline health and data-quality panel | Show worker heartbeat, last successful metric/check/cleanup time, pending work, collection gaps, and retention/DB pressure. The operator can distinguish “Pi/service is down” from “Beacon has stopped observing.” | High | Runtime state; scheduler instrumentation; storage statistics | This directly addresses known two-process SQLite and scheduler fragility. It is more valuable than decorative analytics. | HIGH |
| Adaptive historical resolution | Retain detailed recent samples/checks while serving older ranges as bounded roll-ups (min/max/avg for host metrics; availability/latency/error aggregates for services), with the displayed resolution disclosed. | High | Versioned schema; roll-up jobs; retention policy; query planner | Keeps 90-day interaction responsive on Pi hardware while retaining useful spikes and outage detail. | HIGH |
| Baseline comparison, not opaque anomaly scoring | For a selected range, present current/latest value alongside selected-range min/max/average and simple trend direction; let the operator judge abnormality. | Medium | Aggregate queries; semantic units/thresholds | Practical and explainable for one Pi; defer predictive/ML “root cause” claims. | HIGH |
| Critical-service-first incident lens | A focused control to show critical services and their affected windows first gives the operator the fastest answer during an outage, while ordinary services remain discoverable. | Low | Existing `critical` metadata; events/checks | Reuses a proven semantic field rather than creating incident policies. | HIGH |
| Designed density parity | Dark mode can show more simultaneous context (dense side-by-side diagnostics); light mode can use stronger grouping and progressive disclosure, while every filter, time range, and drill-down remains available. | Medium | Shared interaction contract; visual-regression/UI tests | The differentiator is faithful capability parity with intentional presentation—not two separate feature sets. | HIGH |

## Anti-Features

Features to explicitly not build in this milestone.

| Anti-Feature | Why Avoid | What to Do Instead |
|---|---|---|
| Remote control actions (restart, deploy, shell, reboot, container controls) | A read-oriented monitoring page does not have the authorization, safety, audit, or failure model to execute control actions. The project explicitly defers them. | Surface diagnosis, timestamps, and direct links; design any future action as a separately authorized, safe, non-fatal milestone. |
| Fleet, multi-Pi, tenancy, teams, or RBAC | Beacon's value and architecture are deliberately one host plus explicitly configured services. These features imply identity, authorization, inventory, and distributed data concerns. | Keep host context fixed to this Pi and offer only service/tag/criticality filters. |
| Hosted telemetry backend, cloud account, or remote write | External monitoring changes the defining self-contained/local-only operating model and creates connectivity, privacy, credentials, and lifecycle burden. | Keep the bounded 90-day store local; expose an existing optional local metrics endpoint only when separately configured. |
| User-programmable dashboards, arbitrary queries, plugins, or a Grafana clone | Dashboard construction, query safety, saved definitions, and plugin compatibility would eclipse Beacon's fixed diagnostic task. | Ship opinionated views and bounded filters/date ranges whose API contracts are testable. |
| Infinite raw telemetry, unbounded screenshots, or raw log aggregation | On Raspberry Pi hardware, unlimited local retention and blob-heavy storage compete with sampling/query latency and risk database/WAL growth. | Use 90-day policy, roll-ups, explicit expiry, storage headroom, and retain only diagnostic event/error details. |
| High-frequency synthetic tests, browser journeys, or broad port scans from the analytics page | These can create monitoring gaps and load on a constrained host/network; existing discovery and Playwright work are already performance-sensitive. | Keep analytics read-only; continue scheduled, bounded HTTP checks and queue preview/discovery work outside the sampling path. |
| Alert-routing rules, paging schedules, acknowledgement workflows, or incident collaboration | They presume accounts, ownership and escalation workflows that are out of scope for a personal trusted-LAN tool. | Preserve the existing optional transition webhook and make its delivery/last-error visible as monitoring context. |
| “AI root cause” or predictive outage claims | The planned data does not establish causation; opaque output would undermine operator trust. | Show synchronized evidence, simple range statistics, and collection-quality indicators. |

## Feature Dependencies

```text
Foundation cleanup / side-effect-free process boundaries
  → versioned telemetry schema + migration tests
  → bounded raw retention + roll-up/cleanup policy
  → range-query APIs (host metrics, service checks, events, pipeline health)
  → advanced page shell + shared date/filter state
  → host charts + service history + incident timeline
  → correlated diagnostic drill-down and baseline summaries

Existing service metadata (criticality, tags, health rules)
  → current service inventory and critical-service filters

Worker heartbeat / scheduler state
  → freshness indicators and monitoring-pipeline health panel

Shared semantic interaction contract
  → fully functional light and dark implementations
```

## MVP Recommendation

Prioritize:

1. **Trustworthy 90-day telemetry foundation:** versioned migrations, bounded retention, roll-ups, cleanup observability, and range APIs before visual expansion.
2. **Advanced current-state and host history:** freshness-aware host diagnosis, date presets, and readable CPU/RAM/disk/temperature history in both themes.
3. **Service investigation:** filtered inventory, selected-service availability/latency/event timeline, critical-service focus, and cross-linked incident context.
4. **Monitoring-pipeline health:** make collection gaps, worker freshness, and retention/storage status first-class so the operator can trust conclusions.

Defer: dashboard authoring, general query language, multi-host abstractions, collaboration/alert workflow, and all remote actions. Each either conflicts with Beacon's local single-host boundary or requires a distinct safety and authorization model.

## Sources

- [Beacon project definition](../PROJECT.md) — HIGH confidence; validates local-only, single-Pi, 90-day, theme-parity, and remote-action constraints.
- [Beacon architecture map](../codebase/ARCHITECTURE.md) and [concerns audit](../codebase/CONCERNS.md) — HIGH confidence; validates existing data, worker/SQLite constraints, security boundaries, and performance risks.
- [Grafana: dashboard time settings, annotations, variables, and links](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/modify-dashboard-settings/) — MEDIUM confidence through the verified web-research provider; supports shared time controls, annotations, contextual navigation, and crosshair inspection patterns.
- [Grafana: time-series visualizations](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/time-series/) — MEDIUM confidence; supports time-series use for timestamped numeric data, tooltip inspection, event annotations, and preserving/null-rendering decisions.
- [Prometheus: local storage and retention](https://prometheus.io/docs/prometheus/latest/storage/) — MEDIUM confidence; supports explicit time/size retention, background expiry, capacity headroom, and local-store operational limits.
