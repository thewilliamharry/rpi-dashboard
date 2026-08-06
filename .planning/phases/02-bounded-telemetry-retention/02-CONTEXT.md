# Phase 2: Bounded Telemetry & Retention - Context

**Gathered:** 2026-08-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Establish a truthful, storage-bounded 90-day record for host metrics, service observations, and operational events. This phase defines collection-detail tiers, aggregation and cleanup guarantees, missing-data semantics, historical response limits, and failure-pressure behavior. Advanced diagnostic presentation, interactive historical charts, and theme-specific analytics experiences remain in later phases.

</domain>

<decisions>
## Implementation Decisions

### Detail Over 90 Days

- **D-01:** Retain raw host metrics and service observations for 7 days. — **Reversibility:** costly — changing this after release affects storage sizing, rollup boundaries, cleanup behavior, and the historical API contract.
- **D-02:** Represent days 8 through 30 with 5-minute aggregates and days 31 through 90 with hourly aggregates. Telemetry older than 90 days is expired and deleted. — **Reversibility:** one-way — once source observations or aggregates expire, later policy changes cannot recover them.
- **D-03:** Retain individual operational events in full for the entire 90-day window; do not aggregate events into counts that replace the original records. — **Reversibility:** one-way — expiring individual event records earlier would permanently remove incident evidence.
- **D-04:** Host aggregate buckets preserve minimum, maximum, average, latest, and sample count. Service aggregate buckets preserve time-weighted online, offline, and unknown duration; latency minimum, maximum, and average; check count; and failure-class counts. — **Reversibility:** costly — Phase 4 range summaries and investigations will depend on this aggregate contract.

### Missing-Data Meaning

- **D-05:** Every unavailable historical interval has one explicit reason: `collection_gap`, `unknown`, `expired`, or `not_yet_monitored`. — **Reversibility:** costly — these reason values become a historical API vocabulary consumed by later analytics views.
- **D-06:** Confirm a `collection_gap` after two expected observations are missed according to that stream's configured cadence. The gap begins at the first missed boundary and ends at the next valid observation.
- **D-07:** For buckets containing mixed coverage, compute statistics only from observed values and separately report observed, gap, and unknown duration plus sample counts. Never interpolate across unavailable intervals.
- **D-08:** Historical responses preserve the caller's full requested time bounds and explicitly represent retained observations, `expired` intervals, and `not_yet_monitored` intervals with coverage metadata. Do not silently clamp the requested range. — **Reversibility:** costly — range consumers will depend on stable requested/effective bounds and coverage semantics.

### Pressure and Failed Rollups

- **D-09:** When a rollup fails, preserve all unaggregated source observations, expose the affected interval as pending aggregation, record the failure, and retry automatically with bounded backoff. Source observations are never deleted before their rollup succeeds. — **Reversibility:** one-way — premature deletion would permanently violate TEL-03 and lose evidence.
- **D-10:** Protect storage with two guardrails: a configurable maximum telemetry/database allocation and a minimum free-disk reserve. Enter pressure handling when either boundary is approached.
- **D-11:** Maintain a bounded emergency reserve for rollup backlog. If it is exhausted, keep live monitoring and current-state updates running but suspend new historical persistence; record the interval as an explicit `storage_pressure` collection gap. Never delete unaggregated evidence merely to make room.
- **D-12:** Recover historical persistence automatically only after storage falls below a lower safe threshold. Preserve the pressure interval as a gap, clear the degraded state automatically, and do not reconstruct or interpolate missed history.

### the Agent's Discretion

- Choose exact default byte limits, minimum-free-space values, warning thresholds, lower recovery thresholds, and hysteresis margins appropriate for Raspberry Pi deployments.
- Choose bounded retry/backoff timing and the schema/module boundaries that implement the locked retention and coverage contracts.
- Choose the server-side response-point budget and deterministic resolution-selection thresholds, provided responses remain bounded and accurately disclose their effective resolution and coverage.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product and Phase Contract

- `.planning/PROJECT.md` — Product mission, 90-day retention constraint, Raspberry Pi deployment boundary, compatibility expectations, and later-phase analytics scope.
- `.planning/REQUIREMENTS.md` — Locked Phase 2 requirements `TEL-01` through `TEL-05`, including rollup-before-delete and explicit missing-data semantics.
- `.planning/ROADMAP.md` — Phase 2 goal, dependency on Phase 1, fixed boundary, and observable success criteria.
- `.planning/STATE.md` — Current project position and Phase 2 planning status.

### Prior Foundation Decisions

- `.planning/phases/01-behavioral-safety-runtime-ownership/01-CONTEXT.md` — Compatibility, durable worker ownership, monitoring-gap, migration, and recovery decisions that Phase 2 must preserve.

### Existing-System Evidence

- `.planning/codebase/STACK.md` — SQLite, Flask, APScheduler, psutil, container, and Raspberry Pi constraints.
- `.planning/codebase/ARCHITECTURE.md` — Shared-SQLite web/worker topology, current telemetry flow, and persistence integration points.
- `.planning/codebase/INTEGRATIONS.md` — Local storage, health/metrics exposure, and self-contained deployment boundaries.

No external specifications were referenced during discussion.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- `dashboard/beacon/migrations.py`: Existing versioned migration path and telemetry tables provide the safe place to introduce rollup, coverage, and job-health schema changes.
- `dashboard/beacon/monitoring.py`: Existing monitoring boundary can host retention-facing operations without moving scheduling ownership back into the web process.
- `dashboard/beacon/repositories.py`: Existing query boundary can be extended with bounded range and coverage-aware historical reads.
- `dashboard/beacon/worker_main.py`: Existing sole-worker scheduler and cleanup job provide the authority-fenced execution point for aggregation, retention, retry, and pressure recovery.
- `tests/helpers.py` and the migration/runtime-ownership suites: Existing temporary-SQLite, legacy-fixture, concurrency, and worker-fencing patterns can validate rollup-before-delete and recovery behavior.

### Established Patterns

- The web and worker are separate processes sharing SQLite; all aggregation and cleanup mutations must preserve Phase 1 transaction-local worker fencing rather than rely on process-local locks.
- Database evolution uses versioned, transactional, idempotent migrations with verified backups and representative legacy fixtures.
- Existing browser/API fields remain compatible while new historical contracts can be introduced behind repositories and adapters.
- SQLite is the source of truth and containers are read-only outside `/data`; storage-pressure calculations must account for the database and filesystem boundaries without adding an external backend.

### Integration Points

- `dashboard/app.py::_legacy_collect_system_stats`, `worker_collect_system_stats`, and the service-check writers currently populate `stats_history`, `system_stats`, `service_checks`, and `events`.
- `dashboard/app.py::_legacy_cleanup_history` and `worker_cleanup_history` currently perform age-based deletion and are the compatibility boundary to replace with rollup-before-delete retention behavior.
- `dashboard/app.py::api_history` and existing service/history queries are the current API compatibility surface; new bounded range APIs must disclose resolution and coverage without breaking the main dashboard preview.
- `dashboard/beacon/worker_main.py` schedules metric sampling and cleanup under durable worker authority; rollups and retries must integrate without creating a second scheduler owner.

</code_context>

<specifics>
## Specific Ideas

- The retention ladder should be easy to explain: 7 days raw, 5-minute detail through day 30, hourly detail through day 90, then explicit expiry.
- Missing evidence must remain visibly missing. Smooth charts or aggregates must never invent observations through interpolation.
- Under severe storage pressure, preserve live monitoring usefulness and old unaggregated evidence while candidly recording a gap in newly persisted history.

</specifics>

<deferred>
## Deferred Ideas

- Consider retaining hourly telemetry aggregates through day 365 in a future phase. This expands the locked 90-day retention capability and requires a separate roadmap/requirements decision.

</deferred>

---

*Phase: 02-bounded-telemetry-retention*
*Context gathered: 2026-08-07*
