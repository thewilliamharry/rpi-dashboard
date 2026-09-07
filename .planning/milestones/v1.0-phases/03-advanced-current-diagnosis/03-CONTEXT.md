# Phase 3: Advanced Current Diagnosis - Context

**Gathered:** 2026-08-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver a dedicated, read-oriented advanced workspace for diagnosing the Pi's current host state, every monitored service, effective monitoring settings, and collection-pipeline health. The workspace must be reachable from either theme and return to the main dashboard without losing theme choice. Historical investigation charts, cross-view time correlation, remote control, fleet monitoring, and the broader visual redesign remain outside this phase.

</domain>

<decisions>
## Implementation Decisions

### Workspace Structure

- **D-01:** Use an overview-first workspace with drill-down sections for Overview, Host, Services, Pipeline, and Settings.
- **D-02:** Lead the overview with active exceptions and degraded components, followed by compact Host, Services, and Collection Health summaries.
- **D-03:** Keep persistent section navigation visible while the selected section replaces the main detail area.
- **D-04:** Open the advanced workspace in the same tab at `/advanced`, provide a clear Dashboard return, preserve theme and explicit advanced preferences, and restore the dashboard's prior scroll position when practical.

### Service Diagnosis

- **D-05:** Present every service in one compact, sortable table with expandable diagnostic rows rather than reusing the main dashboard's preview-card grid.
- **D-06:** Default to operational-priority ordering: critical failures, other failures, stale or unknown services, then healthy services. Preserve configured pinned order within each group.
- **D-07:** Keep name and port, status, latency or failure class, state duration, criticality, and freshness visible in the collapsed row. Put tags and the full effective health rule in expanded detail.
- **D-08:** Allow multiple service rows to remain expanded for comparison and provide a collapse-all action.

### Freshness and Warning Priority

- **D-09:** Keep simultaneous safety, freshness, and pipeline conditions distinct. Preserve the established connection, worker, and recovery safety-warning cluster, then summarize other active exceptions globally with details in the affected section.
- **D-10:** Describe host and service freshness as `fresh`, `aging`, `stale`, or `unknown`, show relative age, and expose the exact sample timestamp and expected cadence in detail.
- **D-11:** Do not infer a failed cause from stale data alone. When a stream is stale but the worker heartbeat is fresh, report both observations and expose cadence and background-job evidence for diagnosis.
- **D-12:** Promote collection gaps to the global exception summary only while they are actionable: open gaps or recent gaps that indicate an ongoing problem. Keep resolved older gaps available in Pipeline detail.

### Preferences and Controls

- **D-13:** Use predictable auto-refresh with a visible, selectable fixed interval, Pause, Refresh now, and a clear last-updated time.
- **D-14:** Persist explicit preferences in browser-local storage: theme, refresh interval, presentation density, range, and filters. Do not restore expanded rows or transient warning selections.
- **D-15:** Provide search by service name, port, or tag plus combinable status, criticality, freshness, and tag filters. Always show the matching count and a clear-all action.
- **D-16:** Use theme-aware density defaults: comfortable in light mode and compact in dark mode. Either theme may override density without losing any capability.

### the Agent's Discretion

- Choose exact refresh-interval choices and freshness thresholds, grounded in the configured sampling and probe cadences.
- Choose responsive behavior for the persistent navigation and service table at narrow widths while preserving access to all fields.
- Choose the internal frontend and API module boundaries, accessibility mechanics, and browser-storage key/versioning scheme.
- Choose the exact visual styling and wording within the locked hierarchy and the existing calm-light/dense-dark product direction.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product and Phase Contract

- `.planning/PROJECT.md` — Product mission, local-only boundary, theme intent, compatibility requirements, and deferred remote-control scope.
- `.planning/REQUIREMENTS.md` — Phase 3 requirements `TEL-06`, `DIA-01`, `DIA-02`, `DIA-03`, `DIA-08`, and `UX-02`.
- `.planning/ROADMAP.md` — Phase 3 goal, dependency, success criteria, and boundary from later historical investigation work.
- `.planning/STATE.md` — Current project position and accumulated cross-phase decisions.

### Prior Locked Decisions

- `.planning/phases/01-behavioral-safety-runtime-ownership/01-CONTEXT.md` — Worker freshness, recovery, compatibility, safety-warning, TLS-posture, and read-oriented outage behavior that this workspace must preserve.
- `.planning/phases/02-bounded-telemetry-retention/02-CONTEXT.md` — Retention tiers, truthful missing-data vocabulary, storage-pressure behavior, and bounded telemetry contracts exposed by current pipeline diagnosis.

### Existing-System Evidence

- `.planning/codebase/STRUCTURE.md` — Current frontend, Flask route, module, and test locations.
- `.planning/codebase/CONVENTIONS.md` — Existing Python, JavaScript, API-validation, and error-handling conventions.

No external specifications were referenced during discussion.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- `dashboard/index.html`, `dashboard/app.js`, and `dashboard/style.css`: Existing theme toggle, safety-warning cluster, host metrics, service status rendering, metadata controls, polling helpers, responsive behavior, and browser formatting utilities establish the visible compatibility baseline.
- `dashboard/app.py::api_stats`, `api_services`, `api_scan_status`, and `api_telemetry_history`: Existing current-state, worker-freshness, service metadata, and bounded telemetry surfaces can be composed or adapted behind the advanced workspace.
- `dashboard/beacon/telemetry.py` and `dashboard/beacon/repositories.py`: Existing retention policy, coverage partition, storage-pressure state, aggregation-pending evidence, and bounded query vocabulary can support truthful Pipeline diagnostics.
- Existing Flask test-client, temporary-SQLite, UI-contract, runtime-ownership, and telemetry suites under `tests/`: Reusable patterns for route, payload, warning, persistence, and compatibility tests.

### Established Patterns

- The browser is dependency-free vanilla JavaScript and polls same-origin `/api/*` endpoints; the new workspace should retain bounded polling and avoid increasing worker load.
- The web and worker are separate processes sharing SQLite; advanced diagnosis reads durable state and must not introduce background ownership or remote-control mutations.
- Worker staleness, browser/API disconnection, recovery-required state, TLS posture, historical gaps, and storage pressure are distinct facts and must remain distinct in the UI.
- The main dashboard's compact analytics and preview cards remain intact in both themes; advanced diagnosis is a separate experience.

### Integration Points

- Add the `/advanced` document route and its static assets at the Flask web boundary without changing worker lifecycle ownership.
- Add or compose bounded read APIs for host identity/freshness, effective monitoring settings, retention/database pressure, job health, and every service's effective diagnosis fields.
- Link the main top bar to the advanced route and preserve theme, preferences, and return-scroll state through browser-local state.
- Extend UI and route contract tests to cover both themes, navigation/return behavior, table/filter states, stale-data semantics, and the absence of remote-control actions.

</code_context>

<specifics>
## Specific Ideas

- The default advanced landing view should answer “what needs attention?” before presenting balanced subsystem summaries.
- Multiple expanded service rows should support direct comparison of simultaneous failures without losing the sortable overview.
- Freshness should always pair an interpreted state with observable evidence: relative age, exact timestamp, and expected cadence.
- Theme affects default density, not data access, settings, filtering, or diagnostic capability.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 03-advanced-current-diagnosis*
*Context gathered: 2026-08-11*
