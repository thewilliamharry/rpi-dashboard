# Requirements: Beacon

**Defined:** 2026-07-24  
**Core Value:** At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.

## v1 Requirements

### Foundation Integrity

- [x] **FND-01**: Existing dashboard, service-management, discovery, preview, uptime, and event behavior is protected by compatibility tests before restructuring.
- [x] **FND-02**: Web delivery, configuration, persistence, monitoring, analytics, discovery, previews, and scheduling have explicit module boundaries.
- [x] **FND-03**: Importing the web application starts no scheduler, browser, probe, or other background work.
- [x] **FND-04**: The worker is the sole scheduler owner and uses durable persisted coordination for work shared with the web process.
- [x] **FND-05**: Database changes use versioned, transactional, idempotent migrations validated against representative existing databases.
- [x] **FND-06**: The operator can create and verify a usable backup before a migration and recover existing Beacon data after a failed upgrade.
- [x] **FND-07**: Probes, HTML fetches, previews, redirects, and webhooks use one tested outbound-target and TLS safety policy.

### Telemetry and Retention

- [x] **TEL-01**: Beacon retains a rolling 90 days of bounded host metrics, service history, and events.
- [x] **TEL-02**: Beacon preserves detailed recent observations and uses documented aggregates for older ranges.
- [x] **TEL-03**: Rollups complete successfully before their source observations are deleted.
- [x] **TEL-04**: Historical queries explicitly distinguish known values, unknown intervals, collection gaps, and retention expiry.
- [x] **TEL-05**: Historical APIs select an appropriate resolution and enforce a bounded response-point budget.
- [x] **TEL-06**: The operator can see effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health.

### Planned Maintenance

- [x] **MNT-01**: The operator can manually configure, edit, disable, and remove a bounded recurring local-time maintenance window for an individual service, including an explicit overrun grace period.
- [x] **MNT-02**: After three similar daily restart outages, Beacon can suggest a candidate maintenance window that remains inactive until the operator confirms or edits it.
- [x] **MNT-03**: During a confirmed maintenance window, Beacon retains every failed probe and continues counting downtime in availability while suppressing only the expected down/recovered event entries and transition alerts.
- [x] **MNT-04**: If a service remains unavailable beyond its confirmed maintenance window and grace period, Beacon records and alerts one truthful outage without hiding the continuing failure.

### Advanced Diagnosis

- [x] **DIA-01**: The operator can open a dedicated advanced analytics and monitoring page from either theme.
- [x] **DIA-02**: The operator can inspect current CPU, memory, disk, temperature, host identity, sample time, and freshness.
- [x] **DIA-03**: The operator can inspect every configured or discovered service's status, latency or failure class, state duration, criticality, tags, and effective health rule.
- [x] **DIA-04**: The operator can select shared preset ranges from one hour through 90 days.
- [x] **DIA-05**: The operator can select a validated custom range within retained history.
- [x] **DIA-06**: Selecting a service, incident, or time range updates related host, service, and event views as one investigation context.
- [x] **DIA-07**: Correlated views present observed evidence without asserting an unsupported root cause.
- [x] **DIA-08**: The operator can view effective monitoring settings and change supported analytics presentation, refresh, range, and filtering preferences without exposing remote-control actions.

### Historical Investigation

- [x] **HIS-01**: The operator can inspect CPU, memory, disk, and temperature history with units, contextual thresholds, tooltips, and visible gaps.
- [x] **HIS-02**: The operator can inspect time-weighted service availability over the selected range.
- [x] **HIS-03**: The operator can inspect a service state timeline, latency history, failure classes, and unknown intervals.
- [x] **HIS-04**: The operator can filter incidents and transitions by service, criticality, event type, and time range.
- [x] **HIS-05**: Selecting an incident focuses the relevant service and time window.
- [x] **HIS-06**: The operator can compare the latest value with selected-range minimum, maximum, average, and simple trend information.

### Experience and Themes

- [x] **UX-01**: Existing compact analytics previews remain on the main dashboard in both light and dark modes.
- [x] **UX-02**: The operator can move clearly between the main dashboard and advanced analytics without losing theme choice.
- [x] **UX-03**: Advanced analytics exposes the same data, filters, settings, and investigations in both themes.
- [x] **UX-04**: Light mode presents analytics with calmer grouping and progressive disclosure, while dark mode may present denser simultaneous context.
- [x] **UX-05**: Advanced analytics remains usable at supported narrow and desktop viewport widths.
- [x] **UX-06**: Status and chart information is available through text, labels, and keyboard-accessible interactions rather than colour alone.
- [x] **UX-07**: Loading, empty, stale, unknown, degraded, and error states are visibly distinct.

### Operational Resilience

- [ ] **OPS-01**: Metric sampling and service checks continue within their accepted cadence while discovery, previews, cleanup, and analytics queries are active.
- [ ] **OPS-02**: Preview work uses serialized browser ownership, bounded deadlines and retries, and a visible non-fatal degraded state.
- [ ] **OPS-03**: Thumbnail storage and expiry remain bounded without placing large preview blobs in the primary telemetry path.
- [ ] **OPS-04**: Automated tests cover migrations, restart recovery, concurrent web/worker database access, scheduler ownership, and failed background jobs.
- [x] **OPS-05**: Automated tests cover outbound-target validation, DNS/redirect handling, TLS behavior, and mutation-request protections.
- [x] **OPS-06**: Both themes have UI-contract or visual-regression coverage for shared capabilities and important states.
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

Every v1 requirement maps to exactly one roadmap phase.

| Requirement | Phase | Status |
|-------------|-------|--------|
| FND-01 | Phase 1 | Complete |
| FND-02 | Phase 1 | Complete |
| FND-03 | Phase 1 | Complete |
| FND-04 | Phase 1 | Complete |
| FND-05 | Phase 1 | Complete |
| FND-06 | Phase 1 | Complete |
| FND-07 | Phase 1 | Complete |
| TEL-01 | Phase 2 | Complete |
| TEL-02 | Phase 2 | Complete |
| TEL-03 | Phase 2 | Complete |
| TEL-04 | Phase 2 | Complete |
| TEL-05 | Phase 2 | Complete |
| TEL-06 | Phase 3 | Complete |
| MNT-01 | Phase 03.1 | Complete |
| MNT-02 | Phase 03.1 | Complete |
| MNT-03 | Phase 03.1 | Complete |
| MNT-04 | Phase 03.1 | Complete |
| DIA-01 | Phase 3 | Complete |
| DIA-02 | Phase 3 | Complete |
| DIA-03 | Phase 3 | Complete |
| DIA-04 | Phase 4 | Complete |
| DIA-05 | Phase 4 | Complete |
| DIA-06 | Phase 4 | Complete |
| DIA-07 | Phase 4 | Complete |
| DIA-08 | Phase 3 + Phase 4 | Complete |
| HIS-01 | Phase 4 | Complete |
| HIS-02 | Phase 4 | Complete |
| HIS-03 | Phase 4 | Complete |
| HIS-04 | Phase 4 | Complete |
| HIS-05 | Phase 4 | Complete |
| HIS-06 | Phase 4 | Complete |
| UX-01 | Phase 5 | Complete |
| UX-02 | Phase 3 | Complete |
| UX-03 | Phase 5 | Complete |
| UX-04 | Phase 5 | Complete |
| UX-05 | Phase 5 | Complete |
| UX-06 | Phase 5 | Complete |
| UX-07 | Phase 5 | Complete |
| OPS-01 | Phase 6 | Pending |
| OPS-02 | Phase 6 | Pending |
| OPS-03 | Phase 6 | Pending |
| OPS-04 | Phase 6 | Pending |
| OPS-05 | Phase 1 | Complete |
| OPS-06 | Phase 5 | Complete |
| OPS-07 | Phase 6 | Pending |

DIA-08 splits across two phases: the effective-settings view, refresh controls, and
service filtering half shipped in Phase 3 (recorded in `PROJECT.md`'s Phase 3 Validated
line); the range and history-filter presentation preference half ships in Phase 4
(04-01, 04-07), because a range preference could not exist before this phase introduced
a range.

HIS-04 was found broken by `04-VERIFICATION.md` (CR-01/CR-02/WR-01): the Event type and
service filters could hide a silently-down service's open episode, fabricate or mislabel a
recovered incident's status, and leak a suppressed-maintenance anchor's evidence through
`maintenance=exclude`. It was restored by gap-closure plans 04-09 (the independent
episode-scope grouping and `filter_episodes` narrowing that closed CR-01/CR-02/WR-01
server-side) and 04-10 (the Incidents section's on-screen disclosure of the narrowing rule).
Its evidence is the named route-level regression tests in
`tests/test_incidents_api.py::EpisodeScopeRegressionTests`. The 2026-08-26 re-verification
confirmed those three closures at the code and test level but found a further candour defect
in the same view, recorded as `04-REVIEW.md` WR-01 (new): `renderIncidentsSection` rendered
the filtered count as the total when the unfiltered baseline read failed (`"N of N
incidents"` for a genuinely unknown total). It was closed by gap-closure plan 04-11, which
made the count state the total is unknown rather than reuse the filtered number. Its evidence
is the named UI regression
`tests/test_history_investigation_ui.py::HistoryInvestigationUiTests::test_baseline_total_fetch_failure_never_claims_the_filtered_count_is_the_total`.

DIA-04 was determined satisfied by `04-VERIFICATION.md` (the six-preset ladder, its
active-state indication, and its validated persisted preference, untouched by any confirmed
defect) and its promotion was recommended there, but it was deliberately held at Pending in
04-10 because a gap-closure plan may not promote a requirement unconnected to any gap in its
own closure set — promotion was left for the next independent re-verification. Gap-closure
plan 04-10 deliberately held at Pending until an independent re-verification could decide;
that hold is now discharged by 04-VERIFICATION.md (2026-08-26T12:15:00Z), which determined
DIA-04 satisfied and recommended promotion on the evidence of the preset ladder, its
active-state indication, and its validated persisted preference.

**Coverage:**

- v1 requirements: 45 total
- Mapped to phases: 45
- Unmapped: 0

---
*Requirements defined: 2026-07-24*  
*Last updated: 2026-08-14 after inserting planned-maintenance recognition*
