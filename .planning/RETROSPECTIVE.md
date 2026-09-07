# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.0 — Beacon

**Shipped:** 2026-09-07
**Phases:** 8 (1, 2, 3, 03.1, 4, 5, 6, 7) | **Plans:** 129 exist, 127 executed | **Tasks:** 270
**Timeline:** 2026-07-24 → 2026-09-07 (45 days)
**Closeout:** `override_closeout` — 45/46 requirements Complete, 2 verifications left open by decision
**Suite at close:** 993 passed · 593 subtests · 0 failures

### What Was Built

- A single-owner runtime: the web application starts no background work at import, and the
  worker holds an opaque per-acquisition epoch that fences every scan and preview write.
  Versioned transactional migrations with verified snapshots, three-backup retention, and a
  catalog-constrained restore CLI behind an isolated Compose recovery service.
- A bounded, truthful 90-day telemetry substrate — tiered rollups verified before source
  deletion, historical APIs that select resolution under a point budget and distinguish
  observed / unknown / gap / expired / pending without interpolating across any of them.
- A GET-only `/advanced` workspace for current diagnosis and historical investigation, at full
  capability parity across light and dark, usable at narrow and desktop widths, with status and
  chart information reachable through text and keyboard rather than colour alone.
- Planned-maintenance recognition: a candidate window suggested after three similar daily
  restart outages, inactive until confirmed; during a confirmed window every failed probe is
  retained and downtime still counts; an overrun produces one truthful outage.
- An advanced-diagnostics kill switch, verified as a measured equality of SQLite statement and
  connection counts off vs on, and as a restart round trip on the database file itself.

### What Worked

- **Foundation before features.** Phases 1 and 2 bought the boundaries, migrations, ownership
  and retention semantics that everything after them assumed. Phase 3's nine gap-closure rounds
  were survivable only because they were arguing about labels on top of contracts that held.
- **Never erasing a recorded finding.** Three failing hardware acceptance runs stand unsuperseded
  in the record; so do two refuted performance premises and two reverted optimisations. The
  OPS-07 acceptance is legible *because* the failures were not tidied away, and a reader can
  check that no budget moved rather than taking it on faith.
- **Prohibitions as first-class artifacts.** `PROH-OPS-07-01` ("a route budget may never be
  tuned so that a failing measurement passes") was written before any run failed, and verified
  at close by diffing `ROUTE_BUDGETS_MS` across three commits. Naming the temptation in advance
  is what made the eventual deviation an acceptance rather than a quiet edit.
- **Mutation-confirming verification.** Phase 7's 5/5 were each proven by breaking them —
  including M8, which found a real escape the phase's own decision record had missed. A test
  that has never been made to fail has not been shown to test anything.
- **Executors reporting across scope rather than editing across it.** At the Phase 5 wave-4
  merge, 05-06 finished with two failing tests it could not legally fix, diagnosed them exactly,
  and reported the two-line reconciliation. Cost: one reconciliation commit, not a silent
  overwrite.

### What Was Inefficient

- **Phase 3 took nine verification rounds and 23 plans**, most of them gap closure, on a defect
  class that recurred independently in Phases 4 and 5. The labelling convention was discovered
  late and paid for repeatedly rather than stated once up front.
- **Seven remediation rounds on `/api/services`**, of which two made things measurably worse and
  were reverted (`06-25`'s bulk SQL uptime aggregation regressed the route 315.8%). The rounds
  were rigorously measured, but the search was undirected until profiling attributed the residual
  to contention rather than per-request cost — which could have been established earlier.
- **Migration 9 shipped unable to apply to any existing deployment**, and was caught by human
  UAT rather than by the suite. Phase 03.1 reopened for it. The tests exercised fresh databases;
  the deployments were not fresh.
- **Wave grouping compares `files_modified` paths only**, so it grouped 05-05 and 05-06 in
  parallel despite 05-06's whole purpose being to change a breakpoint constant that two of
  05-05's assertions hardcode. Path overlap is necessary but not sufficient for wave safety.
- **Planning records drifted from the tree.** At the milestone audit, five separate records were
  stale — ROADMAP checkboxes, a progress table, a `Next: Phase 08` pointer to a phase that never
  existed, and two verification frontmatters describing trees that no longer existed. All
  reconcilable, but they cost an audit round to find.

### Patterns Established

- **Derive every operator-facing label from the durable row it describes**, never from a
  neighbouring row or a stream-level fact. A value that is unknown renders as unknown, not as a
  plausible number. Now a standing constraint in `PROJECT.md`.
- **A schema migration is not done until it has been applied to a representative *existing*
  deployment**, not only to a fresh database. Now a standing constraint.
- **Write the prohibition before the pressure arrives.** `PROH-*` statements are minted when a
  criterion is set, verified independently at close, and never retired by an override.
- **A differential can prove a reduction correct but never prove it is present**
  (`PROH-OPS-07-28`) — an input-count guard is a separate obligation from a correctness
  differential, because removing the reduction entirely measured zero divergences.
- **Set the load gate from real usage before measuring**, so accepting a deviation later cannot
  be mistaken for moving the goalposts.
- **Amend a requirement's wording on ownership grounds, in the open, with the counter-argument
  recorded** (D-07-10) — rather than quietly gating shared APIs to make a scope line tidy.

### Key Lessons

1. **In a monitoring product, the hard part is not collecting evidence but labelling it
   truthfully.** Every recurring defect this milestone — a `null` latency shown as `0 ms` and
   sorted fastest, a filtered count rendered as an unfiltered total, jobs recording outcomes
   they had not established, an empty queue producing two fabricated failure cards — is the same
   bug: a plausible value substituted for an unestablished one. Types do not catch it. Only
   tests that assert the untrue rendering is *impossible* catch it.
2. **Moving work out of a lock does not make it free; it makes it compete elsewhere.**
   Narrowing `_db_lock` moved `/api/services`' Python-side work out of the critical section
   exactly as designed and the deployment got *worse* under concurrency-8, because the released
   work then contended for the GIL instead of queueing behind the lock. Per-request cost moved
   45.07%; the concurrency-3 p95 moved 2.5%.
3. **Test a migration against the databases you actually have.** A migration suite that only
   sees fresh databases tests the happy path of a code path whose entire purpose is the
   unhappy one.
4. **Record the failure and the acceptance separately.** OPS-07 is `Accepted with deviation`,
   never `Complete`, and the three failing runs are not retired by the override. That
   distinction is what lets a future reader re-open the decision on new evidence instead of
   inheriting a pass they cannot audit.
5. **Path-level dependency analysis misses semantic coupling.** A plan that changes a shared
   constant, wire literal, CSS custom property, threshold or route is coupled to every file
   asserting on that value, regardless of who owns those files. Candidate fix for next
   milestone: have plans declare `constants_changed` alongside `files_modified`, and serialise
   any plan whose objective is "reconcile value X across surfaces" into its own wave.
6. **Reconcile planning records at phase close, not at milestone audit.** Five stale records
   accumulated across 45 days and all surfaced at once. Each was individually trivial; finding
   them was not.

### Cost Observations

- Model mix: `adaptive` profile throughout, with `gsd-plan-checker` pinned to opus.
- Plans: 129 written, 127 executed — 06-23 and 06-24 marked `do_not_execute` after the `ea8689e`
  revert rather than deleted, which kept the plan-set's history legible.
- The dominant cost was gap-closure iteration, not initial implementation: Phase 3 alone spent
  23 plans and nine verification rounds, and Phase 6 spent seven remediation rounds on a single
  route. Both were caused by a criterion the first implementation could not meet, discovered
  after the fact.
- Test-to-source ratio at close is above 2:1 (41,614 LOC tests against 13,496 LOC Python and
  6,524 LOC hand-written JS/CSS). Expensive, and the reason the reverts were safe.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Key Change |
|-----------|--------|-------|------------|
| v1.0 Beacon | 8 | 127/129 | First GSD milestone. Established truthful-labelling and migration-rehearsal constraints, prohibitions as first-class verified artifacts, and the convention that no recorded finding is erased. |

### Cumulative Quality

| Milestone | Tests | Suite result | Requirements | Closeout |
|-----------|-------|--------------|--------------|----------|
| v1.0 Beacon | 993 passed, 593 subtests | 0 failures | 45/46 Complete | `override_closeout` |

### Top Lessons (Verified Across Milestones)

*One milestone so far — these are candidates awaiting cross-validation.*

1. Truthful labelling is the recurring defect class in monitoring products, and it recurs
   independently in every surface that renders evidence. (v1.0: Phases 3, 4, 5.)
2. Contention, not per-request cost, is what a concurrency budget actually measures. (v1.0:
   Phase 6, pending confirmation on other workloads.)
3. Naming a prohibition before the pressure arrives is what distinguishes an accepted deviation
   from a moved goalpost. (v1.0: OPS-07.)
