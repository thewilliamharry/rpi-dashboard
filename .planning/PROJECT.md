# Beacon

## What This Is

Beacon is a self-contained, local-only Raspberry Pi operations dashboard for understanding the Pi's current system health and the availability of configured LAN or web services. It combines a simple everyday dashboard with service links and previews, system information, uptime monitoring, and a separate advanced analytics and monitoring workspace backed by a bounded 90-day telemetry record.

The product is primarily for its operator on a trusted local network. It deliberately offers two visual experiences: light mode is simpler and calmer, while dark mode is denser and more hands-on without withholding functionality.

Two capabilities emerged during v1.0 that the original description did not anticipate, and both are now defining. Beacon recognises **planned maintenance**: the operator can confirm a recurring restart window, after which the expected event noise is suppressed while every failed probe and all downtime are still counted — and an overrun still produces one truthful outage. And the advanced workspace is **optional**: a deployment already monitored elsewhere can disable it by configuration, at which point the page, its entry point and all four of its routes disappear and the services front page costs measurably the same as before.

## Core Value

At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.

## Requirements

### Validated

<details>
<summary>v1.0 Beacon — all 46 v1 requirements (45 Complete, 1 Accepted with deviation), shipped 2026-09-07</summary>

**Pre-existing behavior, protected by Phase 1's compatibility tests**

- ✓ Operator can view current Raspberry Pi CPU, memory, disk, temperature, and related system-pressure information — existing
- ✓ Operator can discover and monitor HTTP services on the Pi or trusted LAN — existing
- ✓ Operator can see time-weighted service availability, state transitions, and recent service events — existing
- ✓ Operator can open configured service links and view generated service thumbnails/previews — existing
- ✓ Operator can edit service metadata and trigger scans from the local dashboard — existing
- ✓ Dashboard provides compact analytics/history previews in both light and dark modes — existing
- ✓ Web and background monitoring processes run locally in containers with SQLite persistence and no external monitoring backend — existing

**Foundation Integrity** — Phase 1, verified 8/8

- ✓ FND-01..FND-07 — explicit web/persistence/monitoring/discovery/preview/scheduling boundaries, an import-inert web application, one durable worker owner with transaction-local fencing and bounded admission/drain, versioned transactional migrations with verified backup and recovery, and one tested outbound-target/TLS policy — v1.0

**Telemetry and Retention** — Phase 2, verified 4/4

- ✓ TEL-01..TEL-06 — a bounded rolling 90-day record with tiered aggregation, rollups verified before source deletion, historical queries that distinguish known / unknown / gap / expired / pending, server-selected resolution under a bounded point budget, and operator-visible retention, pressure, worker freshness, gaps and job health — v1.0

**Planned Maintenance** — Phase 03.1 (INSERTED), verified 9/9

- ✓ MNT-01..MNT-04 — bounded recurring local-time maintenance windows with an explicit grace period, a candidate window suggested after three similar daily restart outages that stays inactive until confirmed, suppression of only the expected event entries while every failed probe and all downtime are retained, and one truthful outage when a service overruns its window — v1.0

**Advanced Diagnosis** — Phase 3, verified 5/5 (round 9); Phase 7, verified 5/5

- ✓ DIA-01..DIA-08 — a GET-only `/advanced` workspace reachable from either theme serving host, per-service, effective-settings and collection-health evidence, a six-preset range ladder plus validated custom ranges, one shared investigation context, correlation without asserted causation, and presentation preferences that expose no remote-control action — v1.0 (Phase 3)
- ✓ DIA-09 — advanced diagnostics can be disabled for a deployment already monitored elsewhere; the page, its entry point and all four owned routes disappear while the services front page works unchanged, at measured equal database cost — v1.0 (Phase 7; wording amended by D-07-10 on ownership grounds)

**Historical Investigation** — Phase 4, verified 6/6

- ✓ HIS-01..HIS-06 — host metric history with units, thresholds and visible gaps; time-weighted availability; service state timeline with failure classes and unknown intervals; incident and transition filtering that cannot hide a silently-down service's open episode; incident-to-service focus; and latest-vs-range min/max/average/trend comparison — v1.0

**Experience and Themes** — Phase 5, verified 5/5

- ✓ UX-01..UX-07 — compact previews retained on the main dashboard in both themes, theme choice preserved across the dashboard/advanced boundary, full capability parity with theme-specific density, usable narrow and desktop widths, status and chart information available through text and keyboard rather than colour alone, and visibly distinct loading / empty / stale / unknown / degraded / error states — v1.0

**Operational Resilience** — Phase 6, verified 5/5 (1 by override)

- ✓ OPS-01..OPS-06 — sampling cadence held while discovery, previews, cleanup and analytics run; serialized browser ownership with bounded deadlines and a non-fatal degraded state; bounded thumbnail storage kept out of the telemetry path; and automated coverage of migrations, restart recovery, concurrent access, scheduler ownership, failed jobs, outbound safety, and both themes' UI contracts — v1.0
- ⚠️ OPS-07 — **Accepted with deviation, not Complete.** Cadence, resources, recovery and sampling continuity all PASS on Pi hardware. `/api/services` misses its 500ms p95 on three independent runs (635.6 / 679.3 / 662.3ms) under a closed-loop harness at ~34.5x the deployment's real per-route rate; at the actual 0.067 req/s it measures 77.1ms. No budget, criterion, assertion or harness default was moved (`PROH-OPS-07-01`, `-10` verified intact). `PROH-OPS-07-08` reserves promotion to a future independent round. Revisit only if the real request rate rises — `D-DEBT-06-27`.

</details>

### Active

(None — v1.0 shipped every v1 requirement. Next milestone's requirements are defined by `/gsd-new-milestone`.)

The v2 candidate set carried forward from `v1.0-REQUIREMENTS.md` is Safe Remote Actions
(ACT-01..ACT-04): an explicitly allowlisted non-fatal service action, a confirmation naming
the exact target and effect, a local audit history of request/result/duration/failure, and
independent authorization, concurrency, timeout and recovery controls rather than reused
monitoring mutations. It is a candidate, not a commitment.

### Out of Scope

- Remote control actions — deferred to a later milestone after monitoring and architecture are trustworthy; future actions must be explicitly safe and non-fatal. **Reasoning still valid, and v1.0 strengthened it:** the advanced workspace shipped GET-only with `threats_open: 0` across 46 blocking threats, so the read/write boundary is now a verified property rather than an intention.
- Multi-device or fleet monitoring — this project monitors one Raspberry Pi plus its configured services. **Still valid.**
- Internet-facing or hosted operation — Beacon is designed for a trusted local network. **Still valid.**
- User accounts and multi-user authorization — unnecessary for the current local-only operating model. **Still valid.**
- External monitoring backend — local, self-contained operation is a defining product constraint. **Still valid**, and Phase 7 made the converse explicit: a deployment already monitored elsewhere can run Beacon as a services-only dashboard rather than adopting a second backend.
- Higher-concurrency load as a release gate — added during v1.0. OPS-07 fixes the gate at concurrency 3, the ceiling a single operator generates; higher-concurrency runs are optional evidence, never a gate. Chosen before any run failed, not after.

## Context

**Shipped v1.0 Beacon on 2026-09-07** — 8 phases (1, 2, 3, 03.1, 4, 5, 6, 7), 129 plans of
which 127 executed, across 45 days of planning from 2026-07-24. Test suite green at 993
passed / 593 subtests / 0 failures.

Current codebase: 13,496 LOC Python (`dashboard/`), 6,524 LOC hand-written JS/CSS, and
41,614 LOC of tests — a test-to-source ratio above 2:1, which is the milestone's most
telling number. Tech stack unchanged from the start: Flask, SQLite in WAL mode, APScheduler,
Playwright, Docker Compose, two processes, no ORM, no broker, no frontend build step.

Beacon began this milestone as a working product with mixed architecture accumulated across
disconnected sessions, and `dashboard/app.py` concentrating routes, persistence, monitoring,
discovery, capture and coordination. That concentration is now bounded rather than
eliminated: explicit module boundaries exist under `dashboard/beacon/`, the web application
starts no background work at import, and the worker is the sole durable owner of scheduled
mutations with transaction-local fencing.

**The milestone's recurring failure mode was truthful labelling, not missing features.**
Phase 3 alone took nine verification rounds and 23 plans, most of them gap closure, and the
defects were consistently the same shape: inferred, resolved, or retention-expired evidence
presented as a current actionable fault; background jobs reporting a success or failure they
had not established; a filtered count rendered as an unfiltered total; a `null` latency
displayed as `0 ms` and sorted as the fastest service. Phase 4 and Phase 5 hit the same class
independently. The generalisable lesson is that in a monitoring product, every operator-facing
label must be derived from the durable row it describes rather than a neighbouring row or a
stream-level fact — and that this is not enforced by types, only by tests that assert the
untrue rendering is impossible.

**Known issues and technical debt carried into the next milestone:**

- `OPS-07` is Accepted with deviation, never Complete. Seven remediation rounds moved
  per-request cost 45.07% on hardware but the concurrency-3 p95 only 2.5%. The residual is
  lock contention, not per-request cost — `D-DEBT-06-27`, and the named trigger to revisit.
- `06-VERIFICATION.md` remains `human_needed` for one residual: the concurrency-1 HTTP
  control run on `a7c3ef1`, which would replace the acceptance's one inferential step (an
  in-process cProfile at 77.1ms) with a direct measurement.
- `07-VERIFICATION.md` remains `gaps_found` for one recorded, unclosed finding: a per-service
  `environment:` block in `docker-compose.yml` takes precedence over the merged anchor, so
  `PROH-DIA-09-01`'s guard can be evaded on the actual web container while both guard tests
  still pass. Found by mutation M8.
- `dashboard/beacon/diagnosis.py:448` emits a hardcoded three-step `resolution_policy`
  literal against `telemetry.py`'s ten-step `RESOLUTION_LADDER_SECONDS`. Two sources of truth
  that can drift silently. It has zero production consumers, so it is debt rather than a
  defect — but it is served in `/api/advanced/current`.
- `tests/helpers.py::load_app` writes `extra_env` into `os.environ` and never restores it.
  This already caused one real cross-module regression; the hazard remains latent for every
  other setting. Fixing it changes shared behaviour for the whole suite and wants its own
  scoped change.
- `D-DEBT-07-01` — the Pi acceptance harness records `elapsed_ms` but never `status_code`,
  so a 404 reads as a fast, budget-clearing success. Owned by the next OPS-07 round.
- Seventeen carried-forward `03-REVIEW.md` round-1 findings, plus the deferred items now
  enumerated in `STATE.md`. 30 items in total were acknowledged at close.

`AR-03-01` is resolved as a standing decision rather than debt: `api_advanced_current`
deliberately does not take the process-global `_db_lock`, because a 30s maintenance flock
wait held inside a global lock on a 5s poll is worse than the read inconsistency it removes.
Phase 6 revisited it alongside the WAL decision and left it standing; `D-DEBT-06-16` records
the sibling finding that non-`api_services` sites hold non-database work under `_db_lock`.

## Constraints

- **Deployment**: Must remain self-contained on a 64-bit Raspberry Pi using Docker Compose — simple local operation is central to the product
- **Network scope**: Monitor one host Pi and explicitly configured or discovered trusted LAN/web services — fleet management is not part of this milestone
- **Security model**: Operates only on a trusted local network, but outbound fetching and mutation endpoints must still maintain narrow, testable safety boundaries
- **Data retention**: Advanced analytics retains a rolling 90 days of history with bounded storage, aggregation, and cleanup behavior
- **Theme behavior**: Compact preview analytics remain on the main dashboard in both themes; advanced analytics is fully functional in both themes
- **Experience**: Light mode stays calm and simple; dark mode remains denser and more hands-on
- **Compatibility**: Existing useful dashboard capabilities and stored data should survive restructuring unless an explicitly approved migration replaces them
- **Performance**: Monitoring, discovery, and thumbnail work must not create visible sampling gaps or make the dashboard unresponsive on Raspberry Pi hardware. Measured against the load a single operator generates (concurrency 3); higher-concurrency runs are optional evidence, never a gate
- **Maintainability**: New features must use explicit module boundaries and testable interfaces rather than increasing the existing monolith
- **Truthful labelling**: Every operator-facing `open`, `actionable`, `kind`, count, total, or measurement must be derived from the durable row it describes, and a value that is unknown must render as unknown rather than as a plausible number. Added after v1.0, where this was the recurring defect class across Phases 3, 4 and 5
- **Migration rehearsal**: A schema migration is not done until it has been applied to a representative *existing* deployment, not only to a fresh database. Added after Phase 03.1 reopened on exactly this

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Treat current behavior as the reference while allowing substantial internal restructuring | The product mostly works, but earlier development sessions produced inconsistent architecture and UX | ✓ Good — validated in Phase 1; existing data and behavior survived eight phases of restructuring |
| Build foundation and advanced analytics in the first GSD milestone | Analytics needs trustworthy collection, persistence, and UI boundaries | ✓ Good — all 8 phases shipped; the foundation-first order is what made Phase 3's nine gap-closure rounds tractable at all |
| Defer remote actions to a later milestone | Control requires a stricter safety and audit model than read-oriented monitoring | ✓ Good — the GET-only workspace made the boundary verifiable (`threats_open: 0` over 46 blocking threats), not merely intended |
| Retain 90 days of analytics history | Provides meaningful operational trends without turning the Pi into an indefinite monitoring archive | ✓ Good — validated in Phase 2 |
| Monitor one Raspberry Pi plus configured LAN/web services | Matches the personal local-dashboard mission and avoids fleet-management complexity | ✓ Good — validated in Phase 2 telemetry scope |
| Preserve preview analytics in both themes and add a separate advanced page | Keeps the main dashboard familiar and lightweight while allowing deeper investigation | ✓ Good — advanced page in Phase 3, preview parity confirmed in Phase 5 |
| Provide full advanced analytics capability in both themes | Theme choice changes presentation and density, not access to monitoring functionality | ✓ Good — validated in Phase 5 (UX-03, UX-04) |
| Keep the advanced workspace strictly read-only — GET-only routes, no selector or mutation body, no operation endpoint | Reinforces the deferred-remote-actions boundary at the surface an operator uses during a live incident | ✓ Good — validated in Phase 3 |
| Insert Phase 03.1 for planned-maintenance recognition mid-milestone | Suppressing expected restart noise is worthless if it can hide a real outage; the honesty rules had to be designed before more surfaces consumed events | ✓ Good — but it reopened after human UAT found migration 9 could not apply to any existing deployment, which is the milestone's clearest evidence that migrations need a real upgrade rehearsal, not a fresh-database test |
| Derive every operator-facing label from the durable row it describes, never from a neighbour or a stream-level fact | The milestone's recurring defect class was truthful labelling, not missing features | ✓ Good — the single highest-value convention v1.0 produced; adopt it from day one next milestone |
| Never erase a recorded finding, even when superseded | A monitoring product that edits its own history teaches its authors the wrong habit | ✓ Good — three failing hardware runs stand unsuperseded on the record, and the acceptance is legible because of it |
| Fix OPS-07's gate at concurrency 3 rather than a higher load | Concurrency 3 is the ceiling a single operator generates; the deployment's real rate is 0.067 req/s per route | ✓ Good — and load-bearing precisely because it was chosen before any run failed, so accepting the deviation later could not be mistaken for moving the goalposts |
| Accept OPS-07 with deviation on usage grounds rather than promote or weaken it | Seven remediation rounds moved per-request cost 45.07% but the concurrency-3 p95 only 2.5% — the residual is contention, not per-request cost | ⚠️ Revisit — correct on the evidence and correctly recorded, but it leaves the milestone closing with a measured budget miss. Revisit if the real request rate rises or services are added (`D-DEBT-06-27`) |
| Amend DIA-09's wording (D-07-10) rather than gate the shared history APIs behind the advanced toggle | `/api/telemetry/history` and `/api/events/history` are Phase 2 and Phase 4 deliverables owned by TEL-05 and HIS-01..06, not advanced diagnostics' own routes | ✓ Good — an ownership correction, not a scope reduction; the amendment and its counter-argument are both on the record |
| Let `api_advanced_current` skip the process-global `_db_lock` (AR-03-01) | A 30s maintenance flock wait held inside a global lock on a 5s poll is worse than the read inconsistency it removes | ✓ Good — revisited in Phase 6 alongside the WAL decision and left standing |

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
*Last updated: 2026-09-07 after v1.0 Beacon milestone completion*
