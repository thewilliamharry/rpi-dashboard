---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
current_phase: 2
current_phase_name: Bounded Telemetry & Retention
status: executing
stopped_at: Completed 02-02-PLAN.md
last_updated: "2026-08-10T14:28:10.617Z"
last_activity: 2026-08-10
last_activity_desc: Phase 2 execution started
progress:
  total_phases: 2
  completed_phases: 1
  total_plans: 29
  completed_plans: 25
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-08-07)

**Core value:** At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.
**Current focus:** Phase 2 — Bounded Telemetry & Retention

## Current Position

Phase: 2 (Bounded Telemetry & Retention) — EXECUTING
Plan: 3 of 6
Status: Ready to execute
Last activity: 2026-08-10 — Phase 2 execution started

Progress: [█████████░] 86%

## Performance Metrics

**Velocity:**

- Total plans completed: 23
- Average duration: -
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1 | 23 | - | - |

**Recent Trend:**

- Last 5 plans: -
- Trend: Not enough data

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 01 P01 | 6min | 2 tasks | 8 files |
| Phase 01 P02 | 4min | 2 tasks | 8 files |
| Phase 01 P03 | 20min | 2 tasks | 8 files |
| Phase 01 P04 | 6min | 3 tasks | 10 files |
| Phase 01 P07 | 16min | 3 tasks | 8 files |
| Phase 01 P05 | 6min | 2 tasks | 5 files |
| Phase 01 P06 | 31min | 3 tasks | 9 files |
| Phase 01-behavioral-safety-runtime-ownership P08 | 14min | 2 tasks | 6 files |
| Phase 01 P09 | 16min | 2 tasks | 7 files |
| Phase 01 P10 | 21min | 2 tasks | 4 files |
| Phase 01 P11 | 3min | 2 tasks | 3 files |
| Phase 01 P12 | 14min | 3 tasks | 8 files |
| Phase 01 P13 | 9min | 3 tasks | 8 files |
| Phase 01 P14 | 12m | 2 tasks | 4 files |
| Phase 01 P15 | 19m | 2 tasks | 2 files |
| Phase 01 P16 | 12min | 2 tasks | 3 files |
| Phase 01 P17 | 3min | 1 tasks | 2 files |
| Phase 01 P18 | 12min | 1 tasks | 4 files |
| Phase 01 P20 | 12min | 3 tasks | 8 files |
| Phase 01 P21 | 9 min | 2 tasks | 2 files |
| Phase 01 P22 | 18 min | 2 tasks | 8 files |
| Phase 01 P23 | 15 min | 3 tasks | 5 files |
| Phase 02 P01 | 16 min | 2 tasks | 6 files |
| Phase 02-bounded-telemetry-retention P02 | 4 min | 1 tasks | 1 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table. Recent decisions affecting current work:

- [Phase 1]: Preserve existing behavior and stored data while establishing side-effect-free web startup, sole worker scheduling, versioned migrations, and a unified outbound safety policy.
- [Phase 2]: Establish bounded raw-to-rollup telemetry and range-query semantics before building analytics visualizations.
- [Phases 3-5]: Keep the main dashboard glanceable in both themes; add a separate full-capability advanced workspace with intentional light/dark density differences.
- [Phase 6]: Treat discovery and Chromium previews as optional bounded work that cannot starve essential monitoring.
- [Phase ?]: Only worker.main() owns database preparation, recovery, scheduler construction, signals, and scheduler startup.
- [Phase ?]: Worker freshness is a server-derived, non-blocking dashboard condition distinct from browser/API disconnection.
- [Phase ?]: Kept dashboard.app.app as the WSGI compatibility bridge while beacon.web.create_app owns explicit settings and service composition.
- [Phase ?]: Metadata and preview queue persistence share one SQLite transaction so valid web edits never depend on worker freshness.
- [Phase ?]: Kept dashboard.app as the compatibility edge while worker services receive named operation collaborators.
- [Phase ?]: Gate scheduled work on explicit database preparation before recovery, heartbeat, signals, or scheduler start.
- [Phase ?]: Freeze migration support at the three history fixtures plus the operator-confirmed production fingerprint.
- [Phase ?]: Use verified SQLite online backups with Linux flock serialization and a redacted filesystem recovery marker; no browser restore action.
- [Phase ?]: Outbound service targets use dedicated host/network allowlists, not inbound Host/Origin trust lists.
- [Phase ?]: Trusted-LAN TLS is an immutable service-only posture; webhooks remain verified and redirect-free.
- [Phase ?]: Recovery accepts opaque automatic-backup catalog IDs only; it never accepts a filesystem path.
- [Phase ?]: Web waits only for data ownership initialization so compatible read surfaces remain available while worker recovery is paused.
- [Phase ?]: SQLite runtime state is the authoritative worker-owner lease; process-local locks do not establish ownership.
- [Phase ?]: Metadata persistence and latest preview enqueue share one transaction, and preview completion must match both its lease and current revision.
- [Phase ?]: Safety warnings use one static cluster in connection, worker, recovery order.
- [Phase ?]: TLS posture remains separate from availability and uptime in every service card.
- [Phase ?]: Every ordinary Beacon SQLite connection keeps a shared sibling-lock lease until close.
- [Phase ?]: Schema upgrades acquire the shared upgrade lock before exclusive database maintenance.
- [Phase ?]: Restore takes the upgrade lock followed by exclusive maintenance; a stale heartbeat never acts as writer exclusion.
- [Phase ?]: Restore writes an opaque recovery marker before replacement and clears it only after the verified, readable target is the only visible SQLite state.
- [Phase ?]: The external deployed/retained inventory comparison is intentionally human-only and fail-closed for fingerprints absent from the sanitized support floor.
- [Phase ?]: Every scan claim receives a new opaque owner token, which all renewal and terminal transitions must present.
- [Phase ?]: Scan polling recovers expired leases and expires missed deadlines before selecting the next request in the same SQLite write transaction.
- [Phase ?]: Discovery starts a bounded half-lease heartbeat and skips terminal writes after authority is lost.
- [Phase ?]: Pinned outbound sockets to the approved numeric address while preserving original Host, TLS SNI, and certificate hostname identity.
- [Phase ?]: Each Chromium preview context owns a short-lived loopback policy proxy; route callbacks are early gates, not socket enforcement.
- [Phase ?]: Trusted-LAN service TLS remains service-only and unverified; strict pinned webhooks remain verified and redirect-free.
- [Phase ?]: Only dashboard/worker.py imports the legacy dashboard.app edge and injects WorkerOperations into the package runtime.
- [Phase ?]: Preview completion persists through ThumbnailRepository while previews.py exposes only a named protocol.
- [Phase ?]: dashboard.app reads its runtime integer constants from one validated Settings instance and rejects malformed metadata before processing.
- [Phase ?]: Recovery-required and stale-worker warnings remain independently visible in the locked safety-warning cluster.
- [Phase ?]: Narrow dashboard actions use 44px touch targets while scan status text truncates rather than overflowing.
- [Phase ?]: CLI restore selectors resolve only through the validated marker-bound catalog ID.
- [Phase ?]: Browser previews are retrieval-only: only GET and HEAD may cross either the route gate or plain-proxy boundary.
- [Phase ?]: An acquired origin remains handler-owned until transfer to _relay(), whose existing cleanup is the sole post-transfer owner.
- [Phase ?]: Validate critical and pinned_order from raw JSON before database, outbound-policy, preview, or event work.
- [Phase ?]: Keep omitted metadata values compatible while converting only validated JSON booleans to SQLite integers.
- [Phase ?]: Every preview context registers HTTP and WebSocket gates before a page is exposed.
- [Phase ?]: WSS is closed in Chromium before it can use the approved HTTPS CONNECT carrier as opaque duplex transport.
- [Phase ?]: Every worker acquisition rotates an opaque owner epoch; worker IDs alone are never durable queue authority.
- [Phase ?]: Lease loss closes local job admission before non-blocking scheduler shutdown, while the lifecycle thread drains work before Chromium cleanup.
- [Phase ?]: Freeze all worker startup, scheduler, lifecycle, database, and effect boundaries before changing production authority.
- [Phase ?]: Keep filesystem publication explicit with an empty current producer set because preview bytes remain SQLite BLOBs.
- [Phase ?]: Worker authority is an immutable value bound to the exact acquisition epoch; logs and representations omit the opaque epoch.
- [Phase ?]: Existing queue row, revision, lease, deadline, and coalescing fences remain additive to worker epoch authority.
- [Phase ?]: All ownership-required callbacks preserve immutable startup/scheduled classifications through one close-and-drain registry.
- [Phase ?]: Preview publication is atomic with durable authority and Wave 14 queue fencing; webhooks reserve the exact epoch across bounded delivery.
- [Phase ?]: Host history preserves exact half-open bounds with a 2,048-point cap and explicit coverage instead of interpolation.
- [Phase ?]: Wave 0 retention tests inject UTC time and use real Worker A-to-B lease takeover without wall-clock sleeps.
- [Phase ?]: Migration preservation snapshots source fixture columns and values before asserting the same data after additive upgrades.
- [Phase ?]: Approved additive telemetry evidence contract: per-metric and per-service bucket rows, sparse coverage, stream/bucket retries, exact 7/30/90-day cutoffs, and aggregate write/read-back verification before same-transaction source deletion.

### Pending Todos

None yet.

### Blockers/Concerns

- Before Phase 1 planning, inventory representative production database variants and verify backup/restore outcomes.
- Before Phase 2 planning, validate legacy service identity, retention resolution, capacity limits, and SQLite query plans on target storage.
- Before Phase 6 planning, measure Chromium and representative-load resource budgets on Raspberry Pi-class hardware.

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Product scope | Remote control, fleet monitoring, accounts, hosted telemetry, and AI root-cause claims | Deferred to later milestone / out of scope | 2026-07-24 |

## Session Continuity

Last session: 2026-08-10T14:28:10.607Z
Stopped at: Completed 02-02-PLAN.md
Resume file: None
