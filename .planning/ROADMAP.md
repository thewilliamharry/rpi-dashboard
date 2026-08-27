# Roadmap: Beacon

## Overview

Beacon becomes a dependable, self-contained Raspberry Pi operations dashboard by first protecting the working product and its data, then establishing bounded and truthful telemetry, adding an advanced diagnosis and investigation workspace, and finally proving a theme-parity experience remains responsive while low-priority discovery and previews run. The roadmap retains Flask, SQLite WAL, Docker Compose, and the two-process deployment; it deliberately does not introduce hosted monitoring, a broker, an ORM, or a frontend build stack.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Behavioral Safety & Runtime Ownership** - Preserve working Beacon behavior while making upgrades, background ownership, and outbound access safe. (completed 2026-08-07)
- [x] **Phase 2: Bounded Telemetry & Retention** - Establish truthful 90-day host and service history with bounded storage and query contracts. (completed 2026-08-11)
- [x] **Phase 3: Advanced Current Diagnosis** - Let the operator open an advanced workspace for fresh host, service, settings, and pipeline-health diagnosis. (completed 2026-08-20)
- [ ] **Phase 03.1: Planned Maintenance Recognition (INSERTED)** - Confirm or define expected recurring service restarts without hiding downtime or overruns. (reopened 2026-08-23 — closed on automated verification 2026-08-22; human UAT then found migration 9 could not apply to any existing deployment, see 03.1-UAT.md gaps G-03.1-1 and G-03.1-2)
- [x] **Phase 4: Historical Investigation** - Turn retained telemetry into honest range-based charts, service history, and incident investigation. (completed 2026-08-26)
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

**Plans**: 23/23 plans executed

- [x] 01-01-PLAN.md
- [x] 01-02-PLAN.md
- [x] 01-03-PLAN.md
- [x] 01-04-PLAN.md
- [x] 01-05-PLAN.md
- [x] 01-06-PLAN.md
- [x] 01-07-PLAN.md
- [x] 01-08-PLAN.md
- [x] 01-09-PLAN.md — Gap closure: shared SQLite maintenance and writer barrier
- [x] 01-10-PLAN.md — Gap closure: WAL/SHM-safe, writer-exclusive restore
- [x] 01-11-PLAN.md — Gap closure: scan lease renewal, recovery, and fencing
- [x] 01-12-PLAN.md — Gap closure: pinned HTTP and Chromium destinations
- [x] 01-13-PLAN.md — Gap closure: dependency direction, preview repository, and safe input/config parsing
- [x] 01-14-PLAN.md — Gap closure: deterministic safety UI and durable-state evidence
- [x] 01-15-PLAN.md — Gap closure: marker-authorized, catalog-bound recovery
- [x] 01-16-PLAN.md — Gap closure: retrieval-only previews and proxy cleanup
- [x] 01-17-PLAN.md — Gap closure: exact metadata JSON typing
- [x] 01-18-PLAN.md — Gap closure: block hostile WSS while preserving HTTPS retrieval
- [x] 01-19-PLAN.md — Gap closure: release worker ownership on every terminal path
- [x] 01-20-PLAN.md — Gap closure: fence in-flight queue work with the current durable worker epoch
- [x] 01-21-PLAN.md — Freeze the production worker mutation/effect inventory and RED takeover oracle
- [x] 01-22-PLAN.md — Propagate immutable authority and fence every worker SQLite transaction
- [x] 01-23-PLAN.md — Close universal admission, non-SQL effects, and the production-to-evidence gate

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

**Wave 7** *(gap closure; blocked on executed Phase 1 baseline)*

- `01-09` — Shared SQLite maintenance and writer barrier

**Wave 8** *(blocked on Wave 7 completion)*

- `01-10` — WAL/SHM-safe, writer-exclusive restore
- `01-11` — Scan lease renewal, recovery, and fencing

**Wave 9** *(blocked on scan coordination closure)*

- `01-12` — Pinned HTTP and Chromium destinations

**Wave 10** *(blocked on outbound enforcement closure)*

- `01-13` — Dependency direction, preview repository, and safe input/config parsing

**Wave 11** *(blocked on all implementation gap plans)*

- `01-14` — Deterministic safety UI and durable-state evidence

**Wave 12** *(second gap closure; blocked on completed Wave 11)*

- `01-15` — Marker-authorized, catalog-bound recovery
- `01-16` — Retrieval-only previews and exception-safe proxy cleanup
- `01-17` — Exact metadata JSON typing and unchanged-persistence proof

**Wave 13** *(third gap closure; blocked on completed Wave 12)*

- `01-18` — Block hostile WSS before opaque CONNECT while preserving HTTPS previews
- `01-19` — Release worker ownership after every scheduler exit and post-acquisition failure

**Wave 14** *(fourth gap closure; blocked on completed Wave 13)*

- `01-20` — Fence stale in-flight scan and preview work after durable worker takeover

**Wave 15** *(system-wide ownership closure; blocked on completed Wave 14)*

- `01-21` — Freeze the exhaustive worker callback/effect inventory and real-SQLite RED takeover contract

**Wave 16** *(blocked on the Wave 15 ownership oracle)*

- `01-22` — Thread immutable authority through every worker-originated SQLite transaction

**Wave 17** *(blocked on Wave 16 durable fencing)*

- `01-23` — Close universal admission/drain, non-SQL effects, and the hard coverage gate

### Phase 2: Bounded Telemetry & Retention

**Goal**: Beacon maintains an accurate, bounded 90-day telemetry record whose resolution, gaps, and retention rules remain trustworthy under normal operation.
**Depends on**: Phase 1
**Requirements**: TEL-01, TEL-02, TEL-03, TEL-04, TEL-05
**Success Criteria** (what must be TRUE):

  1. Beacon retains host metrics, service history, and events for a rolling 90 days without unbounded database growth.
  2. Recent observations remain detailed while older history is represented by documented aggregates, with each aggregate completed before its source data is removed.
  3. A requested historical range explicitly distinguishes observed values from collection gaps, unknown intervals, and data that has expired under retention.
  4. Beacon selects an appropriate server-side resolution for each historical request and returns a bounded number of points without misleading the operator about coverage.

**Plans**: 12/12 plans executed

Plans:

- [x] 02-12-PLAN.md

- [x] 02-10-PLAN.md
- [x] 02-11-PLAN.md

**Wave 1**

- [x] 02-01-PLAN.md — Trace a bounded host-history request end to end and establish Wave 0 telemetry tests.

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 02-02-PLAN.md — Confirm the one-way aggregate, coverage, and expiry storage contract.

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 02-03-PLAN.md — Add migration 5 with legacy/current data-preservation and rollback proof.

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 02-04-PLAN.md — Implement idempotent tiered rollups, retries, event expiry, and pressure hysteresis.

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 02-05-PLAN.md — Wire retention and coverage gaps into the sole epoch-fenced worker.

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 02-06-PLAN.md — Complete bounded mixed-tier host/service queries and exhaustive coverage responses.

**Wave 7** *(gap closure; blocked on the executed Phase 2 baseline)*

- [x] 02-07-PLAN.md — Trace canonical host metric streams and settings-backed worker/API policy parity.

**Wave 8** *(blocked on production tracer repair)*

- [x] 02-08-PLAN.md — Expire only closed hourly buckets and enforce persisted retry due times.

**Wave 9** *(blocked on retention/retry repair; final Phase 2 regression gate)*

- [x] 02-09-PLAN.md — Keep host/service source evidence queryable and non-duplicating while compaction is pending.

### Phase 3: Advanced Current Diagnosis

**Goal**: The operator can enter an advanced workspace from either theme and quickly diagnose the current Pi, every monitored service, effective monitoring settings, and collection health.
**Depends on**: Phase 2
**Requirements**: TEL-06, DIA-01, DIA-02, DIA-03, DIA-08, UX-02
**Success Criteria** (what must be TRUE):

  1. Operator can open the dedicated advanced analytics and monitoring page from the main dashboard and return without losing the selected theme.
  2. Operator can inspect current CPU, memory, disk, temperature, host identity, sample time, and whether the host data is fresh.
  3. Operator can inspect every configured or discovered service's status, latency or failure class, state duration, criticality, tags, and effective health rule.
  4. Operator can view effective retention, displayed resolution, database pressure, worker freshness, collection gaps, and background-job health, then change supported presentation, refresh, range, and filtering preferences without being offered remote-control actions.

**Plans**: 23/23 plans executed (22/23 executed — 03-18/03-19 closed round-5's background-job-health finding; 03-20/03-21 closed the one Critical and four Warnings 03-19-REVIEW.md's round-6 code review found in that same closure; 03-22 closed the two gaps 03-VERIFICATION.md round 7 found on the same background-job-health clause; 03-23 closes the one cosmetic gap 03-UAT.md found — pending)

- [x] 03-07-PLAN.md

- [x] 03-05-PLAN.md
- [x] 03-06-PLAN.md

**Gap closure (after 03-VERIFICATION.md, status gaps_found, 3/4)**

- [x] 03-08-PLAN.md — Truthful gap projection: per-row `open`, reason→exception-kind mapping, and one bounded population for `gaps.count`/`gaps.truncated` (wave 1)
- [x] 03-09-PLAN.md — Operator-readable exception cards, a service sort that survives refresh, and a guarded section selector (wave 2)
- [x] 03-10-PLAN.md — Legible route failure modes, a test module that restores the global clock, and the corrected requirements traceability record (wave 3)

**Gap closure round 2 (after 03-VERIFICATION.md re-verification, status gaps_found, 3/4 — prior gaps 1-3 confirmed closed, three new gaps found)**

- [x] 03-11-PLAN.md — Services surface stops fabricating measurements: reject absent before coercing to zero in the latency cell, the latency sort key, and the state-duration reader (wave 1)
- [x] 03-12-PLAN.md — Worker job health reports what the job did: decide the outcome outside the scope that records it, and give a failed bookkeeping write its own named condition (wave 1)
- [x] 03-13-PLAN.md — Per-service collection-gap evidence joined from composed pipeline gaps with explicit completeness, rendered as operator copy instead of a serialized container (wave 2)
- [x] 03-14-PLAN.md — REQUIREMENTS.md reconciled in one pass so its traceability table and body checklist agree at the statuses independent verification established (wave 3)

**Gap closure round 3 (after 03-VERIFICATION.md re-verification round 3, status gaps_found, 3/4 — Gaps A and C closed, Gap B half-closed and half-regressed, one new gap found; DIA-03 promoted to Complete, DIA-08 ruled a Phase 4 deferral)**

- [x] 03-15-PLAN.md — Background-job health: a genuine work failure survives a failing outcome write in the raised condition, the exception chain and the log; a job stuck without an outcome becomes an operator exception; startup no longer dies on a transient lock (wave 1)
- [x] 03-16-PLAN.md — Per-service gap evidence: a service with no established collection stream reads differently from a collected clean one, the browser regression asserts the difference instead of pinning it shut, and the absent-value rule becomes type-based (wave 2)

**Gap closure round 4 (after 03-VERIFICATION.md re-verification round 4, status gaps_found, 3/4 — Gap 1 (background-job health) half-closed and half-regressed by round 3's own fix, plus one pre-existing defect newly found; TEL-06 remains Gaps Found)**

- [x] 03-17-PLAN.md — Background-job health: an empty durable queue records succeeded instead of a fabricated failure, the outcome-unrecorded promotion becomes a floor no legitimate run or wedged startup job can dodge, and a compound startup failure reaches the operator instead of an unnamed warning (wave 1)

**Gap closure round 5 (after 03-VERIFICATION.md re-verification round 5, status gaps_found, 3/4 — the fabricated-FAILURE direction (round 4's seven `missing` items) fully closed and reproduced closed; the fabricated-SUCCESS direction found live for J5/J6/J7/J9 and ruled the still-failed half of the same truth, plus a compound-startup-evidence residual and two deferred transient contention sites; TEL-06 remains Gaps Found)**

- [x] 03-18-PLAN.md — Background-job health, the decisive regression: the two queue pollers and both discovery dispatchers return the verdict they already computed instead of a constant, proven against work that genuinely fails through the real production adapters (wave 1)
- [x] 03-19-PLAN.md — Background-job health, remaining closure: the outcome-unrecorded floor is pinned against external facts instead of itself, a compound startup failure leaves durable evidence when a best-effort retry succeeds, and the two deferred transient contention sites are closed rather than left as fabricated faults (wave 2)

**Gap closure round 6 (after 03-19-REVIEW.md code review round 6 of plans 03-18/03-19, status issues_found — one Critical (CR-01: a per-service preview warning was conflated with J6's own job outcome) and four Warnings; no round-6 verification was run because the review found the Critical regression first)**

- [x] 03-20-PLAN.md — J6's job outcome is decoupled from the previewed service's own health per the user's decision (CR-01), the round-6 test that pinned the defect is corrected, and a lost lease during the discovery-busy branch raises instead of reporting success (WR-04) (wave 1)
- [x] 03-21-PLAN.md — The three remaining review warnings closed: the discovery-outcome vocabulary fails closed and loud on an unrecognised literal (WR-01), the uptime-lock-contention comment states the true J3/J4 asymmetry (WR-02), and the outcome-unrecorded floor derives from the operator's own configured discovery timeout (WR-03) (wave 2)

**Gap closure round 7 (after 03-VERIFICATION.md re-verification round 7, status gaps_found, 3/4 — five of six round-6 review findings fully closed and reproduced closed; two gaps found, both on Success Criterion 4's background-job-health clause: J6 cannot report a fault of its own capture machinery, and the widened job_outcome_unrecorded floor is global and coerces its input; TEL-06 remains Gaps Found)**

- [x] 03-22-PLAN.md — Give J6 a job-owned failure signal for a total capture-machinery failure distinct from every per-service condition, route J5's discovery outcome through the same fail-closed membership check J7/J9 already use, and scope the job_outcome_unrecorded floor to the jobs that actually run discovery while guarding its input instead of coercing it (wave 1)

**Gap closure round 9 (after 03-UAT.md conversational verification, status complete, 3/4 — the three hardware tests for collection gaps, idle-Pi job health, and the J6 machinery-fault signal all PASSED on the real Pi on 2026-08-20; one cosmetic gap found, G-03-4, on the advanced workspace's control affordance; the J6 signal-duration observation is a recorded Deferred Follow-Up, not a gap)**

- [x] 03-23-PLAN.md — The /advanced workspace answers the mouse: every click target gets a pointer cursor and a theme-scoped hover state lifted from style.css's own vocabulary, and `Refresh now` finally carries the accent treatment 03-UI-SPEC.md:76 reserves for it — pinned by a real-Chromium computed-style regression in both themes and by an explicit negative that the accent never widens to an ordinary control (wave 1)

**Wave 1**

- [x] 03-01-PLAN.md

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 03-02-PLAN.md

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 03-03-PLAN.md

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 03-04-PLAN.md

**UI hint**: yes

### Phase 03.1: Planned Maintenance Recognition (INSERTED)

**Goal:** The operator can confirm or define expected recurring service restarts so Beacon suppresses routine transition noise without hiding failed probes, reducing uptime impact, or overlooking an overrun.
**Requirements**: MNT-01, MNT-02, MNT-03, MNT-04
**Depends on:** Phase 3
**Plans:** 18/18 plans executed (10 original + 3 gap-closure plans for G-03.1-2 + 2 gap-closure round-3 plans, all executed 2026-08-23 + 3 gap-closure round-4 plans, planned 2026-08-24, pending — 03.1-UAT.md's human dispositions of 03.1-REVIEW.md WR-03, WR-04 and WR-05 produced gaps G-03.1-69, G-03.1-70 and G-03.1-71, all decided "fix now")

**Success Criteria** (what must be TRUE):

  1. Operator can manually add, edit, disable, and remove a recurring per-service local-time maintenance window with an explicit grace period.
  2. After three similar daily restart outages, Beacon offers an inactive suggested window that requires operator confirmation or adjustment before it changes event or alert behavior.
  3. Confirmed maintenance suppresses only expected down/recovered event entries and transition alerts; every probe remains stored and planned downtime still lowers service availability.
  4. A service still down after its window and grace period produces one truthful outage event and alert, while the dashboard distinguishes active maintenance from an unresolved failure.

Plans:
**Wave 1**

- [x] 03.1-01-PLAN.md — Tracer: one covered down-transition is tagged, retained, and never alerted

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 03.1-02-PLAN.md — IANA time-zone data in the container (tzdata dependency + TZ plumbing)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 03.1-03-PLAN.md — Window CRUD over the existing service-meta write surface

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 03.1-04-PLAN.md — Overrun outage: one truthful event past window and grace
- [x] 03.1-05-PLAN.md — Maintenance windows section in the service editor

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 03.1-06-PLAN.md — Suggestion detector recomputed on every metadata read

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 03.1-07-PLAN.md — Derived maintenance availability, exception exclusion, and attribution
- [x] 03.1-08-PLAN.md — Suggestion card with Confirm and Adjust

**Wave 7** *(blocked on Wave 6 completion)*

- [x] 03.1-09-PLAN.md — Main dashboard: calm maintenance card and suppressed-entry reveal
- [x] 03.1-10-PLAN.md — /advanced maintenance evidence, overrun timestamps, and attribution

**Gap closure (after 03.1-UAT.md conversational verification on the real Pi, status diagnosed, 66/68 — two blockers found that no automated round could see: G-03.1-1, migration 9 could not apply to any deployed database, resolved directly in 80b8c3e with v8 support-floor entries and a version-agnostic guard test; G-03.1-2, a failed or slow migration takes the dashboard down and hides its own cause, open and planned below)**

- [x] 03.1-11-PLAN.md — Migration runs alone: a one-shot migrate step both long-running services must wait on, its real error as the process's own output, and the recovery command moved behind a compose profile (wave 1)
- [x] 03.1-12-PLAN.md — The exclusive lock is requested only when there is pending work, and a contended request backs off within a bounded budget instead of dying with a message that displaces the real schema error (wave 1)
- [x] 03.1-13-PLAN.md — Every web handler releases its shared maintenance lease on every exit path, so a request failing against an unmigrated schema can no longer starve the migrator (wave 2)

**Gap closure round 3 (after 03.1-VERIFICATION.md round 2, status gaps_found, 8/9 truths — truth 8 failed at one unenumerated site, and 03.1-REVIEW.md round 1 left one Critical and two Warnings open. Rounds 1 and 2 each fixed the instances they enumerated and then wrote a gate recognising only the shape they had just fixed; this round closes the defect CLASS instead, and every fix already named in the review is made now rather than left to be rediscovered)**

- [x] 03.1-14-PLAN.md — A connection-ownership detector with package-wide seam resolution, proven firing on nine real sites against the unfixed tree, then the class emptied beneath a standing gate (wave 1)
- [x] 03.1-15-PLAN.md — Close proofs that reach the migration paths they name, a contention budget that is the hard ceiling its comment claims, and G-03.1-2 closed on evidence a verifier can re-run (wave 2)

**Gap closure round 4 (after 03.1-UAT.md human dispositions of 03.1-REVIEW.md's three remaining Warnings, all decided "fix now" 2026-08-24 — G-03.1-69, a configuration knob parsed and validated with zero consumers; G-03.1-70, midnight wraparound in the suggestion detector; G-03.1-71, an attribution bound covering 129 days behind a comment claiming over a year. All three diagnosed at runtime before planning, and two of the three corrected 03.1-REVIEW.md's own analysis. The three plans are serialized rather than parallel because all three touch `tests/test_maintenance_windows.py`)**

- [x] 03.1-16-PLAN.md — A configuration knob that means something: the parsed default grace reaches the editor's prefill through the payload the editor already reads, proven at all three client sites (wave 1)
- [x] 03.1-17-PLAN.md — The clustering dial closes at midnight, and so does the cluster's own median start minute, so a nightly restart is offered at the hour it actually happens rather than not at all (wave 2)
- [x] 03.1-18-PLAN.md — An attribution bound derived from the interval it must cover, never silent when it binds, plus the round's closure record for all three gaps (wave 3)

### Phase 4: Historical Investigation

**Goal**: The operator can investigate a selected time range, service, or incident through correlated history that is detailed, bounded, and candid about what Beacon did and did not observe.
**Depends on**: Phase 03.1
**Requirements**: DIA-04, DIA-05, DIA-06, DIA-07, DIA-08, HIS-01, HIS-02, HIS-03, HIS-04, HIS-05, HIS-06
**Requirements note**: DIA-08 covers the range/filter-preference remainder only — the settings/refresh half shipped in Phase 3. See 04-CONTEXT.md D-04 and R-04.
**Success Criteria** (what must be TRUE):

  1. Operator can choose shared ranges from one hour through 90 days or a validated custom range within retained history.
  2. Operator can inspect CPU, memory, disk, and temperature history with units, threshold context, tooltips, visible gaps, and latest/minimum/maximum/average/trend comparisons.
  3. Operator can inspect time-weighted availability, state duration and timeline, latency, failure classes, and unknown intervals for a selected service.
  4. Operator can filter incidents and transitions by service, criticality, event type, and time range; choosing an incident focuses the related service and time window.
  5. Selecting a service, incident, or time range updates related host, service, and event views together, presenting observed correlation without claiming an unsupported root cause.

**Plans**: 11 plans executed (04-01 – 04-11)

Plans:
**Wave 1**

- [x] 04-01-PLAN.md — Tracer: end-to-end honest CPU history — History section, shared preset ladder, gap-breaking series, coverage strip, Pi-local timestamps (wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 04-02-PLAN.md — `GET /api/events/history`: range-and-filter incident reads with server-side down-to-recovered grouping, open episodes, and the overrun grace/fault split (wave 2)
- [x] 04-03-PLAN.md — Memory, disk and temperature complete the stacked shared-axis host charts, with threshold lines only where a hardware or filesystem fact exists (wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 04-04-PLAN.md — HIS-06 comparison row: latest with its own timestamp, min/max/average, a least-squares trend with three confidence tiers, and DST-labelled axis ticks (wave 3)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 04-05-PLAN.md — Validated custom local-time ranges, one shared navigation stack with Back, and drag-to-select that redraws no series (wave 4)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 04-06-PLAN.md — Service history: carried read-only service selection, four-state band, latency chart, failure-class chips, time-weighted availability (wave 5)

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 04-07-PLAN.md — Incidents section: four narrowing filters, grouped episode rows with open/overrun/expected/flapping states, and incident focus that moves every view together (wave 6)

**Wave 7** *(blocked on Wave 6 completion)*

- [x] 04-08-PLAN.md — Correlation without causation: neutral clustering incident markers, one cross-chart hover cursor, and an enforced no-causal-language gate (wave 7)

**Gap closure round 1 (after 04-VERIFICATION.md, status gaps_found, 4/6 — Observable Truth #2 (validated custom ranges, DIA-05) and #5 (honest incident filtering, HIS-04) both failed; 04-REVIEW.md CR-01/CR-02/WR-01/WR-02 independently confirmed present in the current tree; HIS-04 found recorded Complete while demonstrably broken by two of its own four filter dimensions)**

- [x] 04-09-PLAN.md — Honest incident scope: the open-episode anchor and the episode row set are resolved independently of the filtered read, expected-maintenance filtering becomes the episode’s own opening event, and ten route-level regressions pin CR-01/CR-02/WR-01 shut (wave 8)
- [x] 04-10-PLAN.md — A local time that does not exist is rejected with a message naming the clock change instead of silently accepted (WR-02), the Incidents section states the rule that narrowed its list, and the DIA-05/DIA-06/DIA-08/HIS-04 records are reconciled with the evidence (wave 9)

**Gap closure round 2 (after 04-VERIFICATION.md re-verification, status gaps_found, 5/6 — CR-01, CR-02, WR-01 (original) and WR-02 all independently re-confirmed genuinely closed at the code and test level; one new gap found in the same view, 04-REVIEW.md WR-01 (new): `renderIncidentsSection` silently substitutes the filtered count for the unfiltered baseline total when the baseline fetch fails, rendering a misleading "N of N incidents" with no uncertainty indication and no test coverage. DIA-04 independently determined SATISFIED and recommended for promotion. `renderMarkerSingle`'s ARIA role mismatch recorded in Anti-Patterns for Phase 5 to inherit, not treated as a Phase 4 gap.)**

- [x] 04-11-PLAN.md — A failed unfiltered baseline read can no longer be rendered as a known total: the matching-count states the total is unknown instead of reusing the filtered count, pinned by the 04-REVIEW.md IN-01 regression and its recovery case, with the new copy recorded in the design contract and DIA-04 promoted on cited evidence (wave 10)

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

**Plans**: 6/6 plans executed

Plans:
**Wave 1**

- [x] 05-01-PLAN.md — Tracer: `degraded` end to end — one shared server classifier, both payloads, one banner in both documents, proven by an unstubbed dual-theme test

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 05-02-PLAN.md — Six-state vocabulary across the advanced workspace: glyph-and-word badges, the box-versus-inline rule, and a dual-theme distinctness test
- [x] 05-03-PLAN.md — Theme-parity audit: the exhaustive, self-maintaining visibility inventory plus main-dashboard parity and deliberate-calm substitutes

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 05-04-PLAN.md — Keyboard parity for chart interactions: the marker role fix, coverage-strip reachability, the focus-driven time cursor, and one shared range-apply function

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 05-05-PLAN.md — Density drives progressive disclosure on two named surfaces, with the reachability invariant asserted and the stale incident count closed
- [x] 05-06-PLAN.md — Responsive reconciliation to one shared narrow boundary, and the cross-surface dual-theme contract module that closes OPS-06

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
| 1. Behavioral Safety & Runtime Ownership | 23/23 | Complete    | 2026-08-07 |
| 2. Bounded Telemetry & Retention | 12/12 | Complete    | 2026-08-11 |
| 3. Advanced Current Diagnosis | 23/23 | Complete    | 2026-08-20 |
| 4. Historical Investigation | 11/11 | Complete    | 2026-08-26 |
| 5. Theme-Parity Analytics Experience | 6/6 | In Progress|  |
| 6. Workload Resilience & Pi Acceptance | 0/TBD | Not started | - |
