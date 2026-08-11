# Beacon

## What This Is

Beacon is a self-contained, local-only Raspberry Pi operations dashboard for understanding the Pi's current system health and the availability of configured LAN or web services. It combines a simple everyday dashboard with service links and previews, system information, uptime monitoring, and a separate advanced analytics and monitoring workspace.

The product is primarily for its operator on a trusted local network. It deliberately offers two visual experiences: light mode is simpler and calmer, while dark mode is denser and more hands-on without withholding functionality.

## Core Value

At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.

## Requirements

### Validated

- ✓ Operator can view current Raspberry Pi CPU, memory, disk, temperature, and related system-pressure information — existing
- ✓ Operator can discover and monitor HTTP services on the Pi or trusted LAN — existing
- ✓ Operator can see time-weighted service availability, state transitions, and recent service events — existing
- ✓ Operator can open configured service links and view generated service thumbnails/previews — existing
- ✓ Operator can edit service metadata and trigger scans from the local dashboard — existing
- ✓ Dashboard provides compact analytics/history previews in both light and dark modes — existing
- ✓ Web and background monitoring processes run locally in containers with SQLite persistence and no external monitoring backend — existing
- ✓ Phase 1 established explicit web, persistence, monitoring, discovery, preview, scheduling, migration, and recovery boundaries while preserving compatibility — validated in Phase 1
- ✓ Background work has one durable worker owner with transaction-local fencing, bounded admission/drain, and stale-worker effect rejection — validated in Phase 1
- ✓ Critical migration, recovery, ownership, outbound-network, mutation, and UI safety contracts have automated regression coverage — validated in Phase 1
- ✓ Host metrics, service history, and events retain a bounded rolling 90-day record with explicit tiered aggregation and cleanup — validated in Phase 2
- ✓ Rollups are verified before exact source deletion, with bounded retries, storage-pressure handling, and preserved evidence while compaction is pending — validated in Phase 2
- ✓ Historical APIs return bounded, server-selected resolution with explicit observed, gap, unknown, expired, and pending states — validated in Phase 2

### Active

- [ ] Existing dashboard UI and interactions form a cohesive, responsive experience while preserving the distinct intent of light and dark modes
- [ ] Compact preview analytics remain available on the main dashboard in both themes
- [ ] Operator can open a separate advanced analytics and monitoring page from either theme
- [ ] Advanced analytics provides detailed current-state diagnosis for the host Pi and configured services
- [ ] Advanced analytics provides 90 days of bounded historical system and service data
- [ ] Advanced analytics exposes the same monitoring capabilities and settings in both themes while adapting presentation and density to each theme

### Out of Scope

- Remote control actions — deferred to a later milestone after monitoring and architecture are trustworthy; future actions must be explicitly safe and non-fatal
- Multi-device or fleet monitoring — this project monitors one Raspberry Pi plus its configured services
- Internet-facing or hosted operation — Beacon is designed for a trusted local network
- User accounts and multi-user authorization — unnecessary for the current local-only operating model
- External monitoring backend — local, self-contained operation is a defining product constraint

## Context

Beacon already works for most day-to-day use, but it accumulated mixed architectural and UI decisions across several disconnected development sessions. The existing implementation is therefore a behavioral reference rather than a structure that must be preserved; substantial restructuring and replacement are acceptable when they improve cohesion, maintainability, efficiency, and correctness.

The current system uses a Flask web process and an APScheduler worker sharing SQLite. It samples Raspberry Pi metrics, discovers and probes HTTP services, stores checks and events, captures thumbnails with Playwright, and serves a dependency-free browser UI. The codebase map in `.planning/codebase/` is the evidence-backed baseline for planning changes.

The main architectural concern is concentration of routes, persistence, monitoring, discovery, thumbnail capture, and coordination in `dashboard/app.py`. Import-time lifecycle behavior, cross-process SQLite coordination, embedded schema evolution, large thumbnail blobs, and limited production-concurrency coverage make future analytics harder to add safely.

The first GSD milestone combines foundation work and analytics. Phase 1 completed the behavioral-safety and runtime-ownership foundation, including versioned migration/recovery, tested outbound boundaries, durable worker authority, and exhaustive stale-worker fencing. Phase 2 completed the bounded 90-day telemetry substrate: tiered rollups, truthful coverage, migration compatibility, storage-pressure behavior, retry safety, and bounded historical APIs. Phase 3 can now build advanced current diagnosis on those verified contracts rather than extending accidental coupling.

## Constraints

- **Deployment**: Must remain self-contained on a 64-bit Raspberry Pi using Docker Compose — simple local operation is central to the product
- **Network scope**: Monitor one host Pi and explicitly configured or discovered trusted LAN/web services — fleet management is not part of this milestone
- **Security model**: Operates only on a trusted local network, but outbound fetching and mutation endpoints must still maintain narrow, testable safety boundaries
- **Data retention**: Advanced analytics retains a rolling 90 days of history with bounded storage, aggregation, and cleanup behavior
- **Theme behavior**: Compact preview analytics remain on the main dashboard in both themes; advanced analytics is fully functional in both themes
- **Experience**: Light mode stays calm and simple; dark mode remains denser and more hands-on
- **Compatibility**: Existing useful dashboard capabilities and stored data should survive restructuring unless an explicitly approved migration replaces them
- **Performance**: Monitoring, discovery, and thumbnail work must not create visible sampling gaps or make the dashboard unresponsive on Raspberry Pi hardware
- **Maintainability**: New features must use explicit module boundaries and testable interfaces rather than increasing the existing monolith

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Treat current behavior as the reference while allowing substantial internal restructuring | The product mostly works, but earlier development sessions produced inconsistent architecture and UX | ✓ Validated in Phase 1 |
| Build foundation and advanced analytics in the first GSD milestone | Analytics needs trustworthy collection, persistence, and UI boundaries | — Pending |
| Defer remote actions to a later milestone | Control requires a stricter safety and audit model than read-oriented monitoring | — Pending |
| Retain 90 days of analytics history | Provides meaningful operational trends without turning the Pi into an indefinite monitoring archive | ✓ Validated in Phase 2 |
| Monitor one Raspberry Pi plus configured LAN/web services | Matches the personal local-dashboard mission and avoids fleet-management complexity | ✓ Validated in Phase 2 telemetry scope |
| Preserve preview analytics in both themes and add a separate advanced page | Keeps the main dashboard familiar and lightweight while allowing deeper investigation | — Pending |
| Provide full advanced analytics capability in both themes | Theme choice changes presentation and density, not access to monitoring functionality | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `$gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `$gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-08-11 after Phase 2 completion*
