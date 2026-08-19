---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
current_phase: 03
current_phase_name: advanced-current-diagnosis
status: executing
stopped_at: "Completed 03-21-PLAN.md (round-7 gap closure: WR-01, WR-02, WR-03)"
last_updated: "2026-08-19T17:06:50.220Z"
last_activity: 2026-08-19
last_activity_desc: 03-21 closed round-6's three remaining warnings — an unrecognised discovery outcome now fails closed and loud (WR-01), the uptime-lock contention comment states the true J3/J4 asymmetry (WR-02), and the job_outcome_unrecorded floor derives from the operator's configured DISCOVERY_TIMEOUT_SECONDS (WR-03)
progress:
  total_phases: 4
  completed_phases: 3
  total_plans: 57
  completed_plans: 56
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-08-11)

**Core value:** At a glance, the operator can trust what is running, what is failing, and how the Raspberry Pi and its configured services have behaved over time.
**Current focus:** Phase 03 — advanced-current-diagnosis

## Current Position

Phase: 03 (advanced-current-diagnosis) — READY TO EXECUTE
Plan: 21 of 22
Status: Gap-closure round 8 planned — 03-22-PLAN.md cleared the plan-checker (0 blockers, 0 warnings on revision 3) and closes both 03-VERIFICATION.md round-7 gaps: J6's inability to report a fault of its own capture machinery (plus J5's by-exclusion outcome) and the globally-widened job_outcome_unrecorded floor. Not yet executed. TEL-06 stays Gaps Found pending re-verification.
Last activity: 2026-08-19 — planned round 8: fault-class split moved upstream to _get_browser()/context.new_page() so it bypasses both blanket handlers, both scan pollers routed through _discovery_outcome_verdict, and the unrecorded-outcome floor scoped to DISCOVERY_JOB_IDS with a type guard replacing int() coercion

Progress: [█████████░] 95%

## Performance Metrics

**Velocity:**

- Total plans completed: 35
- Average duration: -
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1 | 23 | - | - |
| 02 | 12 | - | - |

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
| Phase 02-bounded-telemetry-retention P03 | 4 min | 1 tasks | 5 files |
| Phase 02-bounded-telemetry-retention P04 | 18 min | 2 tasks | 3 files |
| Phase 02 P05 | 10min | 2 tasks | 5 files |
| Phase 02 P06 | 21min | 2 tasks | 8 files |
| Phase 02 P07 | 6min | 2 tasks | 4 files |
| Phase 02 P08 | 3 min | 2 tasks | 3 files |
| Phase 02 P09 | 25min | 2 tasks | 3 files |
| Phase 03 P01 | 3min | 1 tasks | 7 files |
| Phase 03-advanced-current-diagnosis P02 | 16min | 2 tasks | 10 files |
| Phase 03 P03 | 18min | 3 tasks | 4 files |
| Phase 03 P04 | 10min | 3 tasks | 6 files |
| Phase 03 P05 | 14min | 2 tasks | 5 files |
| Phase 03 P06 | 20min | 1 tasks | 1 files |
| Phase 03 P07 | 21min | 3 tasks | 5 files |
| Phase 03 P08 | 12 min | 3 tasks | 4 files |
| Phase 03 P09 | 10 min | 2 tasks | 3 files |
| Phase 03 P10 | 14 min | 3 tasks | 3 files |
| Phase 03 P11 | 8min | 2 tasks | 2 files |
| Phase 03 P12 | 8min | 2 tasks | 2 files |
| Phase 03 P13 | 21min | 2 tasks | 4 files |
| Phase 03 P14 | 7 min | 1 tasks | 1 files |
| Phase 03 P15 | 20min | 3 tasks | 5 files |
| Phase 03 P16 | 22min | 2 tasks | 5 files |
| Phase 03 P17 | 18min | 3 tasks | 6 files |
| Phase 03 P18 | 24min | 2 tasks | 3 files |
| Phase 03 P19 | 11min | 3 tasks | 4 files |
| Phase 03 P20 | 15min | 2 tasks | 2 files |
| Phase 03 P21 | 7min | 3 tasks | 4 files |

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
- [Phase ?]: Migration 5 telemetry DDL executes as individual statements inside the existing SQLite transaction; service port remains the confirmed durable service-rollup stream key.
- [Phase ?]: Host raw rows are deleted only after all observed fixed metrics in their shared bucket are verified, with a single durable host-bucket job identity.
- [Phase ?]: Storage pressure returns an explicit historical-write decision; later worker wiring owns persistence-state recording and leaves safe rollup compaction available.
- [Phase ?]: J8 remains the sole coalesced cleanup callback; retention and observation writes are fenced by the exact worker epoch.
- [Phase ?]: Historical suspension skips only new rows and records storage_pressure gaps while current host and service state remains live.
- [Phase ?]: Service rollups retain latency_sample_count so cross-tier latency averages use their real denominator.
- [Phase ?]: Coverage is an exhaustive five-state partition, while pending and failed rollups remain a separate raw-evidence disclosure.
- [Phase 02]: Host coverage is metric-specific (cpu, ram, disk, temp); host:host remains only the shared raw-rollup job identity.
- [Phase 02]: The historical API uses the same Settings-derived RetentionPolicy as worker cleanup, including its point budget.
- [Phase ?]: Hourly rollups expire only when their complete half-open bucket ends at or before the retention cutoff.
- [Phase ?]: Durable pending or failed rollups are admitted only when due; new work stays bounded and succeeded/deferred jobs do not consume capacity.
- [Phase ?]: Completed rollups exclusively own their exact half-open source intervals; lower-tier fallback remains observable until then.
- [Phase ?]: Pending aggregation is disclosed separately from observed coverage, with shared raw-host job identity and durable metadata precedence.
- [Phase ?]: Phase 03: Current-host freshness is classified server-side from timestamp and cadence; absent or invalid evidence remains unknown.
- [Phase ?]: Phase 03: The advanced current snapshot is GET-only and effect-free, and refresh failures retain the last successful evidence.
- [Phase ?]: Approved additive Migration 8 job-health evidence with exact-epoch worker authority fencing.
- [Phase ?]: Advanced current diagnosis remains a fixed, parameterless GET-only one-read snapshot with separately typed pipeline evidence.
- [Phase ?]: Advanced UI renders server-classified freshness and typed pipeline evidence without recomputing it.
- [Phase ?]: Only validated presentation preferences are persisted under beacon-advanced-preferences-v1.
- [Phase ?]: Service filters, sorting, and detail disclosures remain local to the bounded current snapshot.
- [Phase ?]: Dashboard return consumes one validated tab-local scroll offset while retaining the existing beacon-theme contract.
- [Phase ?]: Connection availability remains browser-local while worker and recovery safety remain server-derived.
- [Phase ?]: Worker freshness derives from J1's immutable five-second heartbeat cadence, not metric sampling.
- [Phase ?]: Gap truncation uses one sentinel row beyond the cap rather than returned-list length.
- [Phase ?]: Accepted the operator-approved combined 6/11/20-minute samples because browser polling remained continuously successful for more than 20 minutes.
- [Phase ?]: Used host-process RSS as the RAM record because the target Docker/cgroup memory field was unavailable (0B).
- [Phase ?]: Phase 03: An open telemetry_streams gap is durable active-gap evidence synthesized into one open, actionable pipeline gap item and promoted to exceptions.
- [Phase ?]: Phase 03: Stream and pending truncation are sentinel-measured, replacing the inferred length >= cap derivation outright.
- [Phase ?]: Phase 03: Stale or unknown host evidence is its own host_freshness exception, never merged with worker freshness or recovery.
- [Phase ?]: Phase 03: Bounded stream reads rank open-gap then stale streams ahead of quiet ones so the cap never hides actionable evidence.
- [Phase ?]: Phase 03: Refresh ordering uses a memory-only monotonic request generation guard rather than AbortController.
- [Phase 03]: Coverage-derived gap items report open=false unconditionally; only the telemetry_streams synthesis pass may emit open=true — A persisted telemetry_coverage row is a closed interval by construction (DDL enforces end_ts > start_ts); open_gap_start_ts is a stream-level fact and applying it per row produced false open/actionable labels
- [Phase 03]: Each telemetry_coverage reason maps to exactly one outcome via GAP_REASON_EXCEPTION_KINDS; an unrecognised reason surfaces as coverage_unknown — D-11 forbids inferring a cause from an observation: dropping would hide evidence, and collection_gap would assert a cause the row does not carry
- [Phase 03]: The gaps disclosure consumes the narrow open_gap_streams_truncated predicate, never the broad streams_truncated — A false incompleteness claim is the mirror of the defect being fixed; the stream ORDER BY places open-gap streams strictly first, which makes the narrow predicate sound
- [Phase ?]: [Phase 03]: A client-side EXCEPTION_COPY map is the sole source of exception card text; an unrecognised kind renders an explicit counted card rather than being dropped — the dead item.label/item.evidence fallbacks made every card read as a machine identifier over a placeholder
- [Phase ?]: [Phase 03]: The service sort is session-local memory state that survives every automatic poll and manual refresh; only Reset operational order and Clear all filters clear it — D-14 does not list sort among the persisted preferences, and the UI-SPEC refresh clause was reconciled rather than left contradicting the shipped behaviour
- [Phase ?]: [Phase 03]: Only a reason the server itself supplied through apiFetch's own thrown Error is appended to the contracted refresh-error copy; browser-raised TypeError/SyntaxError failures are never shown
- [Phase ?]: [Phase 03]: /api/advanced/current catches only MaintenanceBusy and sqlite3.OperationalError and returns a 503 JSON body — a maintenance window must reach the operator as a named cause, and an unmodelled failure must stay a loud 500 rather than hide behind a catch-all
- [Phase ?]: [Phase 03]: The advanced-diagnosis read is deliberately left outside _db_lock (threat T-03-62 accepted) — placing a 30-second maintenance-flock wait inside the process-global lock would stall every DB route on a 5-second poll
- [Phase ?]: [Phase 03]: Test clocks are frozen through one addCleanup-unwound patch of the stdlib time.time per test — a fixture that mutates process-global state makes suite greenness order-dependent and unusable as verification evidence
- [Phase ?]: [Phase 03]: Only independently verified requirements are promoted in REQUIREMENTS.md; TEL-06 and DIA-08 stay at Gaps Found until a re-verification of the gap-closure round, never on the strength of a plan summary
- [Phase ?]: finiteMeasurement is the numeric sibling of displayValue: reject null/undefined/empty BEFORE Number(), because Number(null) === 0 passes Number.isFinite
- [Phase ?]: An unmeasured value ranks as an extreme (POSITIVE_INFINITY) in the services sort, never as zero; equal keys fall through to the stable index tiebreak
- [Phase ?]: DIA-03 stays Gaps Found after 03-11: only Gap A bullets 1 and 3 are closed; collection_gaps is deferred to 03-13 and reconciliation to 03-14
- [Phase ?]: 03-12: A durable job-health bookkeeping failure raises JobHealthBookkeepingError (callback id + transition + bounded class name only) instead of being recorded as a work failure
- [Phase ?]: 03-12: dispatch_callback decides the outcome in a non-writing scope and performs exactly one outcome write outside it — no compensating or retried bookkeeping write (T-03-77)
- [Phase ?]: 03-12: TEL-06 left at Gaps Found — Gap B closure requires independent re-verification; 03-14 owns the REQUIREMENTS.md reconciliation
- [Phase ?]: 03-13: service.collection_gaps is populated by a join over the composed per-stream gap items, not dropped — a fixed no-evidence string would assert an absence the code never established
- [Phase ?]: 03-13: gap_evidence_truncated (the coverage read's bound) stays a separate field from streams.truncated (the stream read's bound); one flag must never describe two populations
- [Phase ?]: 03-13: a truncation flag that is missing or non-boolean resolves to not_established, never to a derived absence
- [Phase ?]: 03-13: formatServiceGapEvidence derives singular/plural through the existing countLabel helper, so the services and Pipeline surfaces cannot drift from one copy rule
- [Phase ?]: 03-13: DIA-03 and TEL-06 left at Gaps Found — Gap A closure requires independent re-verification; 03-14 owns the REQUIREMENTS.md reconciliation
- [Phase ?]: 03-14: DIA-01, DIA-02 and UX-02 promoted to Complete in BOTH halves of REQUIREMENTS.md — each is established by executed behavioural evidence in 03-VERIFICATION.md and named in no open gap
- [Phase ?]: 03-14: TEL-06, DIA-03 and DIA-08 deliberately left at Gaps Found — 03-11..03-13 closing Gaps A and B is an implementation claim by this round about its own work, not the independent re-verification that alone may promote a requirement (03-10 prohibition; precedent eed5ccb)
- [Phase ?]: 03-14: 03-VERIFICATION.md contradicts itself on TEL-06 and DIA-08; resolved in favour of the gap frontmatter's authoritative 'missing' end state over the closing narrative's capability-satisfaction summary, corroborated by each requirement's own text
- [Phase ?]: 03-14: requirements mark-complete was invoked with only DIA-01/DIA-02/UX-02, never the plan's full six-ID requirements frontmatter — the workflow default would have re-promoted the three requirements this plan exists to keep open
- [Phase ?]: 03-15: chain a bookkeeping condition from the work error, not the write error — Python already binds the write error as implicit __context__, so binding the work error as explicit __cause__ is what keeps both reachable
- [Phase ?]: 03-15: derive the job_outcome_unrecorded promotion only from the job's own durable row, reusing freshness_state's four-times-cadence boundary and strict integer discipline rather than a second staleness convention
- [Phase ?]: 03-15: a failure to record that a startup job began is a fact about the recording, never a verdict on whether Beacon runs — startup logs the condition and continues instead of dying on a transient lock
- [Phase ?]: 03-15: build safety-surface exceptions from explicit keys only, never by spreading a durable row, so CF-WR-10's override hazard gains no second site
- [Phase ?]: 03-16: an absence the pipeline never established gets its own operator sentence ahead of the collected-and-clean branch, with the two rendered strings asserted unequal by port in the live DOM so the distinction cannot be re-collapsed
- [Phase ?]: 03-16: the absent-value rule finiteMeasurement decides on type (finite number, or non-blank string that parses finite) rather than on a list of observed values, so no boolean, array, object or blank string can become the measurement zero
- [Phase ?]: 03-16: the client completeness-states array is kept complete as the wire vocabulary and bound to the server constants by a source-level set comparison, so a rename on either side fails a test and a reordering does not
- [Phase 03]: An empty durable queue is a completed poll, not a failure: worker_process_scan_requests and worker_process_preview_requests return None so dispatch_callback's unchanged False->failed mapping stops fabricating job_failed cards on an idle Pi
- [Phase 03]: The job_outcome_unrecorded promotion boundary is max(UNRECORDED_OUTCOME_FLOOR_SECONDS=900, 4 x cadence) — the larger of the two, applied uniformly whether or not a cadence is configured, so a poll interval is never read as an upper bound on run duration and a None cadence no longer exempts S1/S2/S3/J9
- [Phase 03]: run_worker re-raises a startup JobHealthBookkeepingError whose work_error_class is not None, so a work failure that could not record itself never reaches build_scheduler; a bookkeeping-only failure still warns and continues
- [Phase 03]: TEL-06 was deliberately NOT promoted in REQUIREMENTS.md by 03-17 — a gap-closure round may not record its own requirement complete; only independent re-verification may
- [Phase 03]: 03-18: worker_process_scan_requests and worker_process_preview_requests return the verdict they themselves computed and durably recorded (status == 'completed' / not warning), never a constant True — a genuine J5/J6 failure can no longer reach the operator as succeeded
- [Phase 03]: 03-18: _run_scheduled_discovery and _run_startup_discovery return outcome != 'failed' on the work path and an explicit None only on a genuine skip — None now carries exactly one meaning at the worker dispatch boundary
- [Phase 03]: 03-18: outcome != 'failed' is typed against run_discovery's documented three-literal contract ('busy' | 'completed' | 'failed'), so contention stays a success and only a genuine failure is False
- [Phase 03]: 03-18: outcome regressions must force the failure at the collaborator boundary and drive the exact callable dashboard/worker.py wires in — stubbing the poller under test is what kept five verification rounds green while the defect was live
- [Phase 03]: Closed deferred-items.md row 8's two transient contention sites rather than merely restating the deferral: a busy discovery lock and a contended uptime probe now return None, so dispatch_callback records succeeded instead of a fabricated job_failed card — requeue_scan_for_worker genuinely returns the claim to status='queued' and _uptime_lock contention is self-clearing on the next tick, and no existing test pinned the old False-mapped behaviour; both contracts are now pinned by the new regressions
- [Phase 03]: The compound-startup durable-evidence retry is strictly additive: one bounded best-effort _write_job_health_transition wrapped in its own try/except, placed before an unconditional re-raise that stays unchanged — Round 5's achievement was making a compound startup failure escape loudly; the retry adds an operator-facing evidence channel without ever suppressing, delaying or looping around that escape, pinned in both the retry-succeeds and retry-fails directions
- [Phase 03]: UNRECORDED_OUTCOME_FLOOR_SECONDS is now pinned against external facts (connect_db's two 30 s lock waits, DISCOVERY_TIMEOUT_SECONDS) and proven non-tautological by a mutation-and-restore run — Round 5 proved the prior subtests derived every expectation from the constant under test, so setting it to 30 left the suite byte-identical; the new assertions read only other modules' values and were confirmed to fail against a regressed floor
- [Phase 03]: J6 succeeds whenever the poll claimed a request, attempted a capture, and durably recorded its own verdict -- regardless of the previewed service's health (03-19-REVIEW.md CR-01)
- [Phase 03]: A lost lease is fatal on every terminal path of worker_process_scan_requests, including the discovery-busy branch, which no longer returns before the guard (WR-04)
- [Phase 03]: worker_process_scan_requests (J5) verified against live source as NOT sharing CR-01's defect class and deliberately left unchanged
- [Phase 03]: TEL-06 left open in both halves of REQUIREMENTS.md; promotion belongs to the next independent verifier after 03-20 and 03-21 both execute
- [Phase 03]: An outcome literal outside run_discovery's 'completed'|'busy'|'failed' contract raises ValueError, recorded durably as failed -- membership, never exclusion (WR-01)
- [Phase 03]: The uptime-lock contention comment states the J3/J4 asymmetry: a down-only holder does not perform a full sweep, so the loser's cycle is skipped, not covered (WR-02)
- [Phase 03]: The job_outcome_unrecorded floor is max(900, configured DISCOVERY_TIMEOUT_SECONDS + 60), deriving its guarantee from the operator's value rather than the default (WR-03)
- [Phase 03]: TEL-06 left open in both halves of REQUIREMENTS.md after 03-20 and 03-21; only independent re-verification may promote it

### Pending Todos

None yet.

### Blockers/Concerns

- Before Phase 1 planning, inventory representative production database variants and verify backup/restore outcomes.
- Before Phase 2 planning, validate legacy service identity, retention resolution, capacity limits, and SQLite query plans on target storage.
- Before Phase 6 planning, measure Chromium and representative-load resource budgets on Raspberry Pi-class hardware.
- Second unsatisfiable acceptance criterion in phase 03: plan 03-16's 'pytest -k attach' selector deselects all tests and exits 5 (after 03-13's arithmetically unsatisfiable grep gate). Instance closed in-round by adding a real regression; the plan-defect class is open for the next planning round and recorded in .planning/WINDOWS.md.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260814-kfc | Shorten TLS unverified badge to TLS and Edit service action to Edit | 2026-08-14 | 003d3af | [260814-kfc-shorten-tls-unverified-badge-to-tls-and-](./quick/260814-kfc-shorten-tls-unverified-badge-to-tls-and-/) |

### Roadmap Evolution

- Phase 03.1 inserted after Phase 3: Planned Maintenance Recognition (URGENT)

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Product scope | Remote control, fleet monitoring, accounts, hosted telemetry, and AI root-cause claims | Deferred to later milestone / out of scope | 2026-07-24 |

## Session Continuity

Last session: 2026-08-19T15:27:47.000Z
Stopped at: Completed 03-21-PLAN.md (round-7 gap closure: WR-01, WR-02, WR-03)
Resume file: None
