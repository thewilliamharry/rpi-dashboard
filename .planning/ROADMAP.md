# Roadmap: Beacon

## Overview

Beacon becomes a dependable, self-contained Raspberry Pi operations dashboard by first protecting the working product and its data, then establishing bounded and truthful telemetry, adding an advanced diagnosis and investigation workspace, and finally proving a theme-parity experience remains responsive while low-priority discovery and previews run. The roadmap retains Flask, SQLite WAL, Docker Compose, and the two-process deployment; it deliberately does not introduce hosted monitoring, a broker, an ORM, or a frontend build stack.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Behavioral Safety & Runtime Ownership** - Preserve working Beacon behavior while making upgrades, background ownership, and outbound access safe.
- [ ] **Phase 2: Bounded Telemetry & Retention** - Establish truthful 90-day host and service history with bounded storage and query contracts.
- [ ] **Phase 3: Advanced Current Diagnosis** - Let the operator open an advanced workspace for fresh host, service, settings, and pipeline-health diagnosis.
- [ ] **Phase 4: Historical Investigation** - Turn retained telemetry into honest range-based charts, service history, and incident investigation.
- [ ] **Phase 5: Theme-Parity Analytics Experience** - Make the dashboard and advanced workspace cohesive, responsive, accessible, and equivalent in both themes.
- [ ] **Phase 6: Workload Resilience & Pi Acceptance** - Ensure discovery and previews remain bounded best-effort work and prove Beacon holds up under Pi-class load.

## Phase Details

### Phase 1: Behavioral Safety & Runtime Ownership

**Goal**: The operator can safely continue using and upgrading Beacon while its web, worker, persistence, and outbound-access responsibilities are dependable and independently maintainable.
**Depends on**: Nothing (first phase)
**Requirements**: FND-01, FND-02, FND-03, FND-04, FND-05, FND-06, FND-07, OPS-05
**Success Criteria** (what must be TRUE):

  1. Operator can continue using the dashboard, service metadata, scans, previews, uptime, and events with existing data intact after Beacon is restructured and upgraded.
  2. Operator can create a usable backup before an upgrade and recover Beacon data after a migration failure.
  3. Loading the web application does not start monitoring, browser, probe, or scheduler work; the worker visibly owns shared scheduled work without duplicate execution.
  4. Service probes, fetched previews, redirects, and webhooks consistently block disallowed targets or invalid TLS and report a safe, understandable failure.

**Plans**: 1/8 plans executed

- [x] 01-01-PLAN.md
- [ ] 01-02-PLAN.md
- [ ] 01-03-PLAN.md
- [ ] 01-04-PLAN.md
- [ ] 01-05-PLAN.md
- [ ] 01-06-PLAN.md
- [ ] 01-07-PLAN.md
- [ ] 01-08-PLAN.md

**Wave 1**

- `01-01` — Runtime-ownership tracer and compatibility baseline

**Wave 2** *(blocked on Wave 1 completion)*

- `01-02` — Web, configuration, persistence, and repository boundaries

**Wave 3** *(blocked on Wave 2 completion)*

- `01-03` — Monitoring, preview, and worker composition boundaries

**Wave 4** *(blocked on Wave 3 completion)*

- `01-04` — Legacy database inventory, backups, and transactional migrations
- `01-07` — Unified outbound-target, redirect, and TLS policy

**Wave 5** *(blocked on relevant Wave 4 plans)*

- `01-05` — Offline backup recovery workflow
- `01-06` — Durable worker leases and scan/preview queues

**Wave 6** *(blocked on Wave 5 and outbound-policy completion)*

- `01-08` — Narrow safety UI and light/dark state verification

### Phase 2: Bounded Telemetry & Retention

**Goal**: Beacon maintains an accurate, bounded 90-day telemetry record whose resolution, gaps, and retention rules remain trustworthy under normal operation.
**Depends on**: Phase 1
**Requirements**: TEL-01, TEL-02, TEL-03, TEL-04, TEL-05
**Success Criteria** (what must be TRUE):

  1. Beacon retains host metrics, service history, and events for a rolling 90 days without unbounded database growth.
  2. Recent observations remain detailed while older history is represented by documented aggregates, with each aggregate completed before its source data is removed.
  3. A requested historical range explicitly distinguishes observed values from collection gaps, unknown intervals, and data that has expired under retention.
  4. Beacon selects an appropriate server-side resolution for each historical request and returns a bounded number of points without misleading the operator about coverage.

**Plans**: TBD

### Phase 3: Advanced Current Diagnosis

**Goal**: The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.
**Depends on**: Phase 2
**Requirements**: TEL-06, DIA-01, DIA-02, DIA-03, DIA-08, UX-02
**Success Criteria** (what must be TRUE):

  1. Operator can open the dedicated advanced analytics and monitoring page from the main dashboard and return without losing the selected theme.
  2. Operator can inspect current CPU, memory, disk, temperature, host identity, sample time, and whether the host data is fresh.
  3. Operator can inspect every configured or discovered service's status, latency or failure class, state duration, criticality, tags, and effective health rule.
  4. Operator can view effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health, then change supported presentation, refresh, range, and filtering preferences without being offered remote-control actions.

**Plans**: TBD
**UI hint**: yes

### Phase 4: Historical Investigation

**Goal**: The operator can investigate a selected time range, service, or incident through correlated history that is detailed, bounded, and candid about what Beacon did and did not observe.
**Depends on**: Phase 3
**Requirements**: DIA-04, DIA-05, DIA-06, DIA-07, HIS-01, HIS-02, HIS-03, HIS-04, HIS-05, HIS-06
**Success Criteria** (what must be TRUE):

  1. Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.
  2. Operator can inspect CPU, memory, disk, and temperature history with units, threshold context, tooltips, visible gaps, and latest/minimum/maximum/average/trend comparisons.
  3. Operator can inspect time-weighted availability, state duration and timeline, latency, failure classes, and unknown intervals for a selected service.
  4. Operator can filter incidents and transitions by service, criticality, event type, and time range; choosing an incident focuses the related service and time window.
  5. Selecting a service, incident, or time range updates related host, service, and event views together, presenting observed correlation without claiming an unsupported root cause.

**Plans**: TBD
**UI hint**: yes

### Phase 5: Theme-Parity Analytics Experience

**Goal**: Beacon provides a cohesive, responsive, accessible monitoring experience in which light and dark themes expose the same advanced capability while retaining the calm everyday dashboard.
**Depends on**: Phase 4
**Requirements**: UX-01, UX-03, UX-04, UX-05, UX-06, UX-07, OPS-06
**Success Criteria** (what must be TRUE):

  1. Operator continues to see compact analytics and history previews on the main dashboard in both light and dark themes.
  2. Both themes expose the same advanced analytics data, filters, settings, and investigation workflows, with light mode using calmer progressive disclosure and dark mode allowing denser simultaneous context.
  3. Operator can use the dashboard and advanced workspace at supported narrow and desktop viewport widths, including keyboard-accessible status and chart interactions with text labels that do not rely on colour alone.
  4. Loading, empty, stale, unknown, degraded, and error states are visibly and meaningfully distinct in both themes.
  5. UI-contract or visual-regression coverage verifies shared capabilities and important states in both themes.

**Plans**: TBD
**UI hint**: yes

### Phase 6: Workload Resilience & Pi Acceptance

**Goal**: Beacon keeps essential monitoring reliable while discovery and previews operate as bounded, recoverable best-effort work on Raspberry Pi-class hardware.
**Depends on**: Phase 5
**Requirements**: OPS-01, OPS-02, OPS-03, OPS-04, OPS-07
**Success Criteria** (what must be TRUE):

  1. Metric sampling and service checks remain within their accepted cadence while discovery, previews, cleanup, and analytics queries are active.
  2. Preview work has one serialized browser owner, bounded deadlines and retries, and a visible non-fatal degraded state instead of blocking core monitoring.
  3. Thumbnail data expires within a bounded managed store and no longer puts large preview blobs on Beacon's primary telemetry path.
  4. Beacon recovers predictably from restarts, concurrent web/worker database activity, and failed background jobs, as proven by automated runtime and persistence coverage.
  5. A Raspberry Pi-class representative-load run demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling.

**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Behavioral Safety & Runtime Ownership | 1/8 | In Progress|  |
| 2. Bounded Telemetry & Retention | 0/TBD | Not started | - |
| 3. Advanced Current Diagnosis | 0/TBD | Not started | - |
| 4. Historical Investigation | 0/TBD | Not started | - |
| 5. Theme-Parity Analytics Experience | 0/TBD | Not started | - |
| 6. Workload Resilience & Pi Acceptance | 0/TBD | Not started | - |
