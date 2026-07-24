# Requirements: Beacon

**Defined:** 2026-07-24  
**Core Value:** At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.

## v1 Requirements

### Foundation Integrity

- [ ] **FND-01**: Existing dashboard, service-management, discovery, preview, uptime, and event behavior is protected by compatibility tests before restructuring.
- [ ] **FND-02**: Web delivery, configuration, persistence, monitoring, analytics, discovery, previews, and scheduling have explicit module boundaries.
- [ ] **FND-03**: Importing the web application starts no scheduler, browser, probe, or other background work.
- [ ] **FND-04**: The worker is the sole scheduler owner and uses durable persisted coordination for work shared with the web process.
- [ ] **FND-05**: Database changes use versioned, transactional, idempotent migrations validated against representative existing databases.
- [ ] **FND-06**: The operator can create and verify a usable backup before a migration and recover existing Beacon data after a failed upgrade.
- [ ] **FND-07**: Probes, HTML fetches, previews, redirects, and webhooks use one tested outbound-target and TLS safety policy.

### Telemetry and Retention

- [ ] **TEL-01**: Beacon retains a rolling 90 days of bounded host metrics, service history, and events.
- [ ] **TEL-02**: Beacon preserves detailed recent observations and uses documented aggregates for older ranges.
- [ ] **TEL-03**: Rollups complete successfully before their source observations are deleted.
- [ ] **TEL-04**: Historical queries explicitly distinguish known values, unknown intervals, collection gaps, and retention expiry.
- [ ] **TEL-05**: Historical APIs select an appropriate resolution and enforce a bounded response-point budget.
- [ ] **TEL-06**: The operator can see effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health.

### Advanced Diagnosis

- [ ] **DIA-01**: The operator can open a dedicated advanced analytics and monitoring page from either theme.
- [ ] **DIA-02**: The operator can inspect current CPU, memory, disk, temperature, host identity, sample time, and freshness.
- [ ] **DIA-03**: The operator can inspect every configured or discovered service's status, latency or failure class, state duration, criticality, tags, and effective health rule.
- [ ] **DIA-04**: The operator can select shared preset ranges from one hour through 90 days.
- [ ] **DIA-05**: The operator can select a validated custom range within retained history.
- [ ] **DIA-06**: Selecting a service, incident, or time range updates related host, service, and event views as one investigation context.
- [ ] **DIA-07**: Correlated views present observed evidence without asserting an unsupported root cause.
- [ ] **DIA-08**: The operator can view effective monitoring settings and change supported analytics presentation, refresh, range, and filtering preferences without exposing remote-control actions.

### Historical Investigation

- [ ] **HIS-01**: The operator can inspect CPU, memory, disk, and temperature history with units, contextual thresholds, tooltips, and visible gaps.
- [ ] **HIS-02**: The operator can inspect time-weighted service availability over the selected range.
- [ ] **HIS-03**: The operator can inspect a service state timeline, latency history, failure classes, and unknown intervals.
- [ ] **HIS-04**: The operator can filter incidents and transitions by service, criticality, event type, and time range.
- [ ] **HIS-05**: Selecting an incident focuses the relevant service and time window.
- [ ] **HIS-06**: The operator can compare the latest value with selected-range minimum, maximum, average, and simple trend information.

### Experience and Themes

- [ ] **UX-01**: Existing compact analytics previews remain on the main dashboard in both light and dark modes.
- [ ] **UX-02**: The operator can move clearly between the main dashboard and advanced analytics without losing theme choice.
- [ ] **UX-03**: Advanced analytics exposes the same data, filters, settings, and investigations in both themes.
- [ ] **UX-04**: Light mode presents analytics with calmer grouping and progressive disclosure, while dark mode may present denser simultaneous context.
- [ ] **UX-05**: Advanced analytics remains usable at supported narrow and desktop viewport widths.
- [ ] **UX-06**: Status and chart information is available through text, labels, and keyboard-accessible interactions rather than colour alone.
- [ ] **UX-07**: Loading, empty, stale, unknown, degraded, and error states are visibly distinct.

### Operational Resilience

- [ ] **OPS-01**: Metric sampling and service checks continue within their accepted cadence while discovery, previews, cleanup, and analytics queries are active.
- [ ] **OPS-02**: Preview work uses serialized browser ownership, bounded deadlines and retries, and a visible non-fatal degraded state.
- [ ] **OPS-03**: Thumbnail storage and expiry remain bounded without placing large preview blobs in the primary telemetry path.
- [ ] **OPS-04**: Automated tests cover migrations, restart recovery, concurrent web/worker database access, scheduler ownership, and failed background jobs.
- [ ] **OPS-05**: Automated tests cover outbound-target validation, DNS/redirect handling, TLS behavior, and mutation-request protections.
- [ ] **OPS-06**: Both themes have UI-contract or visual-regression coverage for shared capabilities and important states.
- [ ] **OPS-07**: A Raspberry Pi-class acceptance run verifies responsiveness, resource budgets, recovery, and sampling continuity under representative load.

## v2 Requirements

### Safe Remote Actions

- **ACT-01**: Operator can execute an explicitly allowlisted, non-fatal service action.
- **ACT-02**: Operator receives a confirmation describing the exact target and effect before an action runs.
- **ACT-03**: Beacon records the action request, result, duration, and failure details in a local audit history.
- **ACT-04**: Action execution uses independent authorization, concurrency, timeout, and recovery controls rather than reusing monitoring mutations.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Remote control in v1 | Deferred until monitoring, persistence, and safety boundaries are trustworthy |
| Multiple Raspberry Pis or fleet management | Beacon is intentionally scoped to one Pi plus configured services |
| Accounts, roles, or multi-user operation | Current deployment is personal and local-only |
| Internet-facing or hosted operation | Trusted-LAN, self-contained operation is a defining constraint |
| Hosted telemetry or cloud synchronization | Adds credentials, connectivity, privacy, and operational dependencies |
| Arbitrary dashboards, query languages, or plugins | Would turn Beacon into a general observability platform |
| AI anomaly or root-cause claims | Planned evidence supports correlation and diagnosis, not causal certainty |
| Alert routing and incident collaboration | Requires ownership and escalation workflows outside the personal-dashboard mission |

## Definition of Done

- Every v1 requirement maps to exactly one roadmap phase and is verified against observable evidence.
- Existing validated dashboard behavior and stored-data compatibility pass the agreed regression and migration checks.
- Both themes expose the same advanced monitoring capabilities and pass responsive/accessibility acceptance.
- Ninety-day retention, rollups, gaps, and range-query limits are tested with representative data volumes.
- Raspberry Pi-class acceptance demonstrates bounded resource use, responsive interaction, recovery, and uninterrupted critical sampling.
- No unreviewed fixable high or critical security findings remain in the release dependency/container gates.

## Traceability

Roadmap creation will map each v1 requirement to exactly one phase.

| Requirement | Phase | Status |
|-------------|-------|--------|
| FND-01 | TBD | Pending |
| FND-02 | TBD | Pending |
| FND-03 | TBD | Pending |
| FND-04 | TBD | Pending |
| FND-05 | TBD | Pending |
| FND-06 | TBD | Pending |
| FND-07 | TBD | Pending |
| TEL-01 | TBD | Pending |
| TEL-02 | TBD | Pending |
| TEL-03 | TBD | Pending |
| TEL-04 | TBD | Pending |
| TEL-05 | TBD | Pending |
| TEL-06 | TBD | Pending |
| DIA-01 | TBD | Pending |
| DIA-02 | TBD | Pending |
| DIA-03 | TBD | Pending |
| DIA-04 | TBD | Pending |
| DIA-05 | TBD | Pending |
| DIA-06 | TBD | Pending |
| DIA-07 | TBD | Pending |
| DIA-08 | TBD | Pending |
| HIS-01 | TBD | Pending |
| HIS-02 | TBD | Pending |
| HIS-03 | TBD | Pending |
| HIS-04 | TBD | Pending |
| HIS-05 | TBD | Pending |
| HIS-06 | TBD | Pending |
| UX-01 | TBD | Pending |
| UX-02 | TBD | Pending |
| UX-03 | TBD | Pending |
| UX-04 | TBD | Pending |
| UX-05 | TBD | Pending |
| UX-06 | TBD | Pending |
| UX-07 | TBD | Pending |
| OPS-01 | TBD | Pending |
| OPS-02 | TBD | Pending |
| OPS-03 | TBD | Pending |
| OPS-04 | TBD | Pending |
| OPS-05 | TBD | Pending |
| OPS-06 | TBD | Pending |
| OPS-07 | TBD | Pending |

**Coverage:**
- v1 requirements: 41 total
- Mapped to phases: 0
- Unmapped: 41

---
*Requirements defined: 2026-07-24*  
*Last updated: 2026-07-24 after initial definition*
