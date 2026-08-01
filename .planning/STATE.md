---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
current_phase: 01
current_phase_name: Behavioral Safety & Runtime Ownership
status: needs_review
stopped_at: Phase 1 re-verification found 2 blocking gaps (17/20)
last_updated: "2026-08-01T07:30:17Z"
last_activity: 2026-08-01
last_activity_desc: Phase 01 re-verification closed the original mechanics but found 2 blocking safety gaps.
progress:
  total_phases: 6
  completed_phases: 0
  total_plans: 14
  completed_plans: 14
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-24)

**Core value:** At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.
**Current focus:** Phase 01 — Behavioral Safety & Runtime Ownership

## Current Position

Phase: 01 of 6 (Behavioral Safety & Runtime Ownership)
Plan: 14 of 14
Status: Needs review — 2 blocking safety gaps remain
Last activity: 2026-08-01 — Phase 01 re-verification closed the original mechanics but found 2 blocking safety gaps.

Progress: [██████████] 100%

## Performance Metrics

**Velocity:**

- Total plans completed: 0
- Average duration: -
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

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

Last session: 2026-08-01T07:30:17Z
Stopped at: Phase 1 re-verification found 2 blocking gaps (17/20)
Resume file: .planning/phases/01-behavioral-safety-runtime-ownership/01-VERIFICATION.md
