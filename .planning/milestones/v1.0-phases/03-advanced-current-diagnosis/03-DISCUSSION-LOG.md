# Phase 3: Advanced Current Diagnosis - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-11
**Phase:** 03-advanced-current-diagnosis
**Areas discussed:** Workspace structure, Service diagnosis layout, Freshness and warning priority, Preferences and controls

---

## Workspace Structure

### Workspace organization

| Option | Description | Selected |
|--------|-------------|----------|
| Overview with drill-down | Concise health summary with Host, Services, Pipeline, and Settings detail destinations. | ✓ |
| Tabbed workspace | Separate subsystem tabs with no persistent overview. | |
| Single continuous page | Put all advanced diagnosis into one scrollable page. | |
| Another structure | User-defined organization. | |

**User's choice:** Overview with drill-down.

### Overview priority

| Option | Description | Selected |
|--------|-------------|----------|
| Exceptions first | Lead with active warnings and degraded components, then subsystem summaries. | ✓ |
| Balanced status summary | Give each subsystem equal visual weight regardless of state. | |
| Host first | Lead with Pi resource health. | |
| Another priority | User-defined hierarchy. | |

**User's choice:** Exceptions first.

### Drill-down navigation

| Option | Description | Selected |
|--------|-------------|----------|
| Persistent section navigation | Keep section navigation visible while replacing the detail area. | ✓ |
| In-page navigation | Jump from summary cards to expanded sections on one page. | |
| Contextual drawers | Open detail beside the overview in drawers. | |
| Another interaction | User-defined behavior. | |

**User's choice:** Persistent section navigation.

### Entry and return

| Option | Description | Selected |
|--------|-------------|----------|
| Same-tab route with clear return | Use `/advanced`, preserve theme/preferences, and restore dashboard scroll when practical. | ✓ |
| Same-tab route with simple return | Preserve theme but return to the dashboard top. | |
| New browser tab | Leave the dashboard open separately. | |
| Another behavior | User-defined behavior. | |

**User's choice:** Same-tab route with a clear Dashboard return.

---

## Service Diagnosis Layout

### Primary layout

| Option | Description | Selected |
|--------|-------------|----------|
| Compact table with expandable rows | Scan every service in one sortable list and expand full evidence. | ✓ |
| Dense diagnostic cards | Extend the dashboard's card pattern with more detail. | |
| Master-detail layout | Pair a service list with one selected service detail panel. | |
| Another layout | User-defined layout. | |

**User's choice:** Compact table with expandable rows.

### Default order

| Option | Description | Selected |
|--------|-------------|----------|
| Operational priority | Critical failures, failures, stale/unknown, then healthy; pinned order within groups. | ✓ |
| Configured order | Preserve pinned order regardless of status. | |
| Status then name | Group by state and alphabetize. | |
| Tags first | Group by tag before status. | |

**User's choice:** Operational priority.

### Collapsed columns

| Option | Description | Selected |
|--------|-------------|----------|
| Core diagnosis columns | Show identity, state, evidence, duration, criticality, and freshness; expand tags/rule. | ✓ |
| Everything visible | Keep tags and the full rule as columns. | |
| Minimal scan view | Show only identity, status, and duration. | |
| Another column set | User-defined columns. | |

**User's choice:** Core diagnosis columns.

### Expansion behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Multiple rows may stay open | Compare several services and provide collapse-all. | ✓ |
| Only one row open | Keep focus on a single expanded service. | |
| Separate detail panel | Move selected-service detail out of the table. | |
| Another behavior | User-defined behavior. | |

**User's choice:** Multiple rows may stay open.

---

## Freshness and Warning Priority

### Simultaneous conditions

| Option | Description | Selected |
|--------|-------------|----------|
| Tiered independent warnings | Keep conditions distinct, summarize globally, and detail locally. | ✓ |
| One combined health warning | Show only one highest-severity banner. | |
| Section-local warnings only | Avoid a global exception summary. | |
| Another hierarchy | User-defined hierarchy. | |

**User's choice:** Tiered independent warnings.

### Freshness evidence

| Option | Description | Selected |
|--------|-------------|----------|
| State, age, and sample time | Show freshness state and relative age, with exact time/cadence in detail. | ✓ |
| Age only | Leave interpretation to the operator. | |
| Simple fresh/stale badge | Use binary freshness with timestamp in detail. | |
| Another freshness model | User-defined model. | |

**User's choice:** State, age, and sample time.

### Stale stream with fresh worker

| Option | Description | Selected |
|--------|-------------|----------|
| Report without guessing | State both observations and expose supporting job evidence. | ✓ |
| Treat as collection failure | Immediately assign failure to the background job. | |
| Worker freshness is sufficient | Suppress the stale-stream warning. | |
| Another interpretation | User-defined interpretation. | |

**User's choice:** Report the observation without guessing.

### Global gap visibility

| Option | Description | Selected |
|--------|-------------|----------|
| Only when currently actionable | Promote open/recent ongoing gaps; retain resolved gaps in Pipeline detail. | ✓ |
| Any retained gap | Keep the global state degraded for every gap in range. | |
| Open gaps only | Remove global notice immediately upon recovery. | |
| Never globally | Keep all gaps within Pipeline detail. | |

**User's choice:** Only when currently actionable.

---

## Preferences and Controls

### Refresh behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Predictable auto-refresh | Selectable fixed interval, Pause, Refresh now, and last-updated time. | ✓ |
| Automatic with no controls | Beacon chooses the interval. | |
| Manual by default | Update only on request. | |
| Adaptive refresh | Beacon varies frequency based on context. | |

**User's choice:** Predictable auto-refresh.

### Persistence

| Option | Description | Selected |
|--------|-------------|----------|
| Persist explicit preferences only | Save theme, refresh, density, range, and filters, but not transient UI state. | ✓ |
| Persist everything | Restore section, sort, and expanded rows too. | |
| Session only | Reset controls in a new browser session. | |
| Persist theme only | Reset all analytics controls. | |

**User's choice:** Persist explicit preferences only.

### Service filtering

| Option | Description | Selected |
|--------|-------------|----------|
| Search plus combinable quick filters | Search identity/tags and combine status, criticality, freshness, and tags. | ✓ |
| Preset views only | Offer All, Problems, Critical, and Stale. | |
| Advanced filter builder | Construct arbitrary multi-condition rules. | |
| Search only | Provide text matching without filters. | |

**User's choice:** Search plus combinable quick filters.

### Theme and density

| Option | Description | Selected |
|--------|-------------|----------|
| Theme-aware default with manual override | Light defaults comfortable, dark defaults compact, either may switch. | ✓ |
| Theme determines density | Fix one density per theme. | |
| One shared density choice | Apply one operator choice to both themes. | |
| Another relationship | User-defined behavior. | |

**User's choice:** Theme-aware default with manual override.

---

## the Agent's Discretion

- Exact refresh interval choices and cadence-derived freshness thresholds.
- Narrow-screen navigation and table adaptation.
- Internal module boundaries, accessibility mechanics, and browser-storage versioning.
- Exact styling and copy within the locked presentation hierarchy.

## Deferred Ideas

None.
