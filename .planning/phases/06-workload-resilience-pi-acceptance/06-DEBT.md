---
phase: 6
slug: workload-resilience-pi-acceptance
kind: debt-and-dispositions
created: 2026-09-01
---

# Phase 6 — Tracked Debt & Revision Dispositions

> A later verifier must read this before re-litigating anything in this phase: what was deliberately
> **not** done, why, and what evidence this phase already produced for the next evaluation to start from.

---

## 1. Deferred — awaiting a human decision

### D-DEBT-06-03 — production starting journal mode never read

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Open Question 1, `06-05-PLAN.md` Task 1's `<human-check>` |
| **Status** | **Deferred — awaiting the next Pi deployment.** Not blocking; not a defect. |
| **Recorded in the plan** | `06-05-PLAN.md` Task 1 `<human-check>` (non-blocking evidence capture) and Task 3's acceptance criteria |

**What was not done and why.** This execution environment has no reachable Raspberry Pi and no copy of
a deployed `/data/dashboard.db` to run `python -m beacon.inventory --db /data/dashboard.db --output
<report.json>` against before this build lands. The deployed database's pre-switch `journal_mode` was
therefore **not observed** — it is recorded here as `unverified`, not silently assumed to be either
mode.

**Why this does not block the rollout.** The rollout does not depend on knowing the starting mode:
`connect_db` issues `PRAGMA journal_mode=WAL` unconditionally on every connection, and
`configured_journal_mode` reads back the mode actually in force. Both starting-mode paths converge on
the same end state and are proven against synthetic fixtures by
`tests/test_workload_resilience.py::WalModeTests::test_connections_run_in_wal_mode_from_either_starting_mode`
(one fixture left at SQLite's default rollback journal, one pre-set to WAL before `connect_db` ever
sees it) and by `tests/test_migrations.py::MigrationTests::test_a_wal_mode_deployment_inspects_backs_up_and_upgrades`
(a tracked lineage already carrying a non-empty `-wal` sidecar inspects, backs up, and upgrades
end-to-end). What is missing is the *production reading*, not the rollout's correctness.

**Not addressed this round.** The `06-10` gap-closure round deployed to and ran against the real Pi
twice (see `D-DEBT-06-04`), but no operator captured a `beacon.inventory` journal-mode reading during
either deployment. Do not read the surrounding real-hardware activity this round as having touched
this entry — it has not. It remains open, unchanged.

**What would need to be true to proceed / close this entry.** On the next Pi deployment, run
`python -m beacon.inventory --db /data/dashboard.db --output /tmp/beacon-journal-mode-before.json`
before deploying this build, deploy, then run it again to
`/tmp/beacon-journal-mode-after.json`. Confirm `journal_mode` reads `wal` in the after-report (and note
whether the before-report already showed `wal`, in which case the deployment was a no-op confirmation
rather than a first-time conversion). Attach both reports as phase evidence and close this entry.

---

### D-DEBT-06-08 — OPS-07 not promoted by this round; evidence exists, promotion does not

| Field | Value |
|---|---|
| **Raised by** | `06-14-PLAN.md` Task 2, `PROH-OPS-07-08` |
| **Status** | **Deferred — awaiting independent verification.** New this round. |
| **Recorded in the plan** | `06-14-PLAN.md`, `06-ACCEPTANCE-ROUND3.md` |

**What now exists.** The third real Pi acceptance run (`06-ACCEPTANCE-ROUND3.md`,
`beacon-acceptance-round3.json`, `beacon-control-c1-round3.json`) is the first hardware evidence this
phase has produced with a working CPU column (`D-DEBT-06-06`, discharged below) and cadence still
holding (`assertions.cadence.passed: true`). That is real, durable evidence bearing on OPS-07.

**What this round deliberately does not do.** It does not promote OPS-07. `.planning/REQUIREMENTS.md`
line 72's checkbox stays unchecked (`- [ ] **OPS-07**`) and line 155's traceability row stays
`| OPS-07 | Phase 6 | Pending |`, unedited by this plan (`git diff --quiet -- .planning/REQUIREMENTS.md`
holds). A gap-closure round that both produces the evidence for a requirement and promotes that same
requirement is certifying itself — `PROH-OPS-07-08` forbids exactly that.

**The project's own precedent.** `.planning/STATE.md` § Key Decisions records: "TEL-06 was deliberately
NOT promoted in REQUIREMENTS.md by 03-17 — a gap-closure round may not record its own requirement
complete; only independent re-verification may." Phase 3's `03-11` through `03-14` established the same
rule the hard way, after `03-VERIFICATION.md` was found to contradict itself between a gap-frontmatter
"missing" end state and a closing narrative's "capability satisfied" summary — resolved in favour of
the frontmatter, not the narrative. This entry follows that precedent directly: the acceptance report
this round produced is exactly the kind of "closing narrative" evidence Phase 3's precedent says must
not self-certify, however clean the report looks.

**What closes this entry.** An independent verification round — not this plan, not `06-13`, not the
operator who ran the hardware checkpoint — reads `06-ACCEPTANCE-ROUND3.md` and the two attached JSON
reports, confirms the run's `overall_passed`, cadence, resource, and CPU-sampling evidence
independently, and is the one to check OPS-07's box and update its traceability row. Note that this
round's `overall_passed` is currently `false` (see `D-DEBT-06-09`), so promotion is not yet even a live
question — this entry documents the promotion *rule*, not a pending promotion.

---

### D-DEBT-06-09 — round 3's acceptance failure is serialization, attributed to `_db_lock`'s scope

| Field | Value |
|---|---|
| **Raised by** | `06-14-PLAN.md` Task 1's real hardware run, `06-ACCEPTANCE-ROUND3.md` |
| **Status** | **Measured 2026-09-03 — verdict INCONCLUSIVE, not CONFIRMED. The user chose `fix-now` against that measurement; the narrowing itself lands in a follow-up plan (06-19+), not here.** See "MEASURED — round 4 hardware diagnostic" below. |
| **Recorded in the plan** | `06-ACCEPTANCE-ROUND3.md`, `beacon-acceptance-round3.json`, `06-18-PLAN.md`, `06-LOCK-DIAGNOSTIC.md` |

**MEASURED — round 4 hardware diagnostic (2026-09-03).** `06-18-PLAN.md` Task 1 ran two instrumented
passes on real Raspberry Pi hardware (`d9cecb8`, concurrency-1 control + concurrency-8/600s
acceptance-shaped) and Task 2 wrote `06-LOCK-DIAGNOSTIC.md` from the two attached JSON reports. This
replaces the "not yet attributed" framing below with a measured verdict; a later reader should read
this section first, not re-derive an attribution the round already measured.

**Verdict: INCONCLUSIVE** (`lock_profile.attribution.verdict`, `beacon-lockdiag-c8.json`). Four of
five checks held, including both decisive ones:

| check | measured | threshold | held |
|---|---|---|---|
| `scan_status_lock_wait_share_of_wall` (refutation check, decisive) | 0.9902 | 0.5 | **HELD** |
| `scan_status_median_hold_near_zero` | 2,531,729ns | 5,000,000ns | **HELD** |
| `services_median_hold_in_band` | 596,245,129ns | [200,000,000, 500,000,000]ns | **FAILED** (high) |
| `scan_status_wait_tracks_services_hold` | 0.5141 | 0.5 | **HELD** |
| `utilisation_above_superlinear_threshold` (decisive) | 0.9639 | 0.85 | **HELD** |

`/api/scan-status`'s degradation is measured, not inferred, to be 99.0% `_db_lock` wait
(`requests['/api/scan-status'].lock_wait_ns_total / wall_ns_total = 269,736.4ms / 272,392.5ms`).
Utilisation over the concurrency-8 window is 0.9639, well past the 0.85 superlinear threshold, and
`/api/services` alone accounts for ~90.9% of total lock hold time
(`882 × 596.245129ms = 525,888.19ms` of `578,783.96ms` total). The single failed check
(`services_median_hold_in_band`) failed on the *high* side — 596.2ms against a band calibrated to
round 3's 25,278-row dataset, on a Pi that now holds 2.24x that (56,828 rows) — which strengthens
the attribution's mechanism (a lock held longer because there is genuinely more work under it on a
larger dataset) without the verdict function papering over a failed prediction to call it CONFIRMED.
Full figures, the clause-by-clause prediction evaluation, and the GIL-versus-lock separation are in
`06-LOCK-DIAGNOSTIC.md`; this entry states the verdict and its consequence, not the derivation.

**The decision.** Put to the user at `06-18-PLAN.md` Task 3's checkpoint, against this INCONCLUSIVE
measurement and the planner's recorded recommendation to defer. **The user selected `fix-now`.**
This is recorded as the user's engineering call, made on the evidence, without upgrading the
verdict: four of five checks held (including both decisive ones), and the lone failure is a stale
absolute band, not a missing measurement — rescaling that band to this run's own dataset growth
(`257.6ms / 209.355ms ≈ 1.230x`, applied to `[200,000,000, 500,000,000]`ns) gives approximately
`[246,000,000, 615,000,000]`ns, inside which the measured 596.2ms falls. The same figures would
read CONFIRMED against a band calibrated to the data that actually exists. That recalibration
arithmetic is context for the decision; it is not a retroactive upgrade of `06-LOCK-DIAGNOSTIC.md`'s
recorded verdict, which states what the harness measured and stays INCONCLUSIVE.

**What this closes and what remains open.** This entry's own stated closure condition — "a
diagnostic round that instruments the deployment under concurrency-8 load and identifies, with
direct evidence, which specific serialization point is responsible" — is **met**: `_db_lock` is
identified with direct evidence (99.0% lock-wait share on `/api/scan-status`, 0.9639 utilisation),
and the GIL is separately measured and shown not to explain `/api/scan-status`'s degradation (0.33%
off-CPU share of its own wall). What remains is the fix itself, scoped into a follow-up plan
(`06-19` or later) per `PROH-OPS-04-05`'s prerequisites — see `D-DEBT-06-01` below, which the
`fix-now` decision reopens.

**ATTRIBUTION ADDED 2026-09-02, after verification and code review.** This entry was filed as
"measured but not attributed." It is now attributed, with a mechanism that survived falsification.
The diagnostic round the user chose should therefore **confirm or refute a named mechanism**, not
search an open field.

**The chain, each link verified against source by the orchestrator:**

1. `api_services` acquires `_db_lock` at `dashboard/app.py:2785` and does not release it until
   `return jsonify(result)` at line 2940 — **155 lines**, wrapping the entire per-service loop,
   `_uptime_summary`, and all maintenance-coverage work. Per `06-PROFILE.md`'s own buckets,
   **82.042%** of that critical section is non-SQL Python held under a process-wide mutex.
2. Four of the five lock-taking exercised routes confirmed by direct read (`api_services`,
   `api_scan_status`, `api_thumbnail_status`, `api_history`). `/api/advanced/current` is the sole
   exception — `dashboard/beacon/diagnosis.py` contains **zero** `_db_lock` references.
3. `tests/pi_load_acceptance.py:371` places `/api/scan-status` at rotation index **1**, immediately
   after `/api/services` at index 0, closed-loop, all 8 threads started in lockstep. Every thread
   reaches scan-status just as its siblings hold the lock taken in services.
4. **The arithmetic closes it.** scan-status's excess wait, `242.614 − 3.281 = 239.333ms`, is
   **1.143×** one `/api/services` critical section (209.355ms, measured on the same hardware in the
   same round's control pass). It also explains the ~13× p50 spread *among lock-taking routes*,
   which this entry originally left unexplained: degradation tracks **rotation distance behind
   `/api/services`**, not route cost.
5. **Falsification survived.** Eight threads can serialize at most ~8× through the GIL alone.
   **74× was observed.** The GIL is therefore insufficient as an explanation, whatever its
   contribution.

**Two inferences recorded earlier in this phase do not survive, and are withdrawn here:**

- `D-DEBT-06-01`'s second reopening test — "the unlocked `/api/advanced/current` recovering while
  the locked routes stay over budget" — **is not diagnostic.** It uses an unlocked, GIL-bound 82ms
  route as the discriminator for a lock; it cannot fire while any GIL cost exists, regardless of
  whether `_db_lock` is the dominant serializer. Its failure to fire in round 3 was read as evidence
  against `_db_lock`. It was not evidence either way.
- The orchestrator's reading that "165.504% is not a hard pin at 100%, so the GIL hypothesis is
  weakened" is **unsound**. A CPython process routinely exceeds 100% while GIL-saturated, because
  GIL-releasing C code (SQLite) runs concurrently on top of it. Both `06-ACCEPTANCE-ROUND3.md` and
  this file state that mechanism one sentence before drawing the opposite conclusion from it.

**What the diagnostic round should now do.** Instrument `_db_lock` hold and wait time per call site
under concurrency-8 load and confirm or refute the prediction above: that scan-status's wait is
dominated by time blocked on a lock held by a concurrent `api_services` call, and that shrinking the
critical section to cover only SQL — not the 82% Python — collapses the degradation. That is a
narrower and cheaper round than the open-ended search this entry originally called for.

**What round 3 measured.** The control pass (concurrency 1, 120s) passes cleanly on every route, and
`/api/services`'s control p50 improved 27.6% over round 2 (289.0ms → 209.355ms), attributable to
`06-13`'s `reduce-request-cost` fix. Per-request cost is therefore no longer the dominant problem. But
`/api/scan-status` — a 3.281ms route at concurrency 1 — degrades **74x** to a 242.614ms p50 under
concurrency 8, while `assertions.resources.summary.web.cpu_sampling.mean_cpu_percent` reads 165.504
against 400% available on this 4-core Pi 5 (roughly 2.3 cores idle on mean). Eight clients cannot make
a 3ms computation take 243ms through added computation alone on a host with that much idle capacity;
the mechanism producing the acceptance-pass failure is **serialization**, not per-request cost.

**What this measurement does not do.** It does not implicate `_db_lock`. `D-DEBT-06-01`'s own second
named reopening test — the unlocked `/api/advanced/current` route recovering to near its control-pass
p95 under concurrency 8 while the locked routes (`/api/services`, `/api/scan-status`) stay over budget
— did **not** fire this round: `/api/advanced/current`'s p95 improved only 13.1% (2742.1ms → 2382.2ms)
and remains over its own 2000ms budget. An unlocked route degrading 12.6x is not explained by a lock it
never takes. `_db_lock` is measured to be insufficient to explain the failure (as `D-DEBT-06-01`
already recorded from round 2), and round 3 adds nothing that newly implicates it either.

It also does not confirm the one-interpreter/GIL hypothesis, though it does not rule it out.
`mean_cpu_percent` of 165.504% (a single Python process sustaining more than one core's worth of CPU)
shows real parallelism is occurring — SQLite's C-level driver releases the GIL during I/O and some
built-in operations — so the classic GIL-saturation signature (a hard pin near 100%, one core fully
consumed and no more) is not what this run shows. The one-interpreter hypothesis is weakened by this
reading, not confirmed, and the deployment is still measured to be far from using the machine (roughly
2.3 of 4 cores idle on mean even at the CPU-bound web role's peak).

**Why this is deferred rather than fixed here.** This is the second and third consecutive rounds
(`06-10`, `06-14`) in which a plausible single-cause hypothesis was proposed and then not confirmed by
the next round's hardware evidence — first `_db_lock`, then `/api/services`'s per-request cost. The
user's explicit choice for the next round is to measure the serialization mechanism directly (thread
timeline / lock-wait instrumentation under the same concurrency-8 load) rather than propose and ship a
third inferred fix against an attribution that, twice now, has not survived contact with hardware.

**What would need to be true to close this entry.** A diagnostic round that instruments the deployment
under concurrency-8 load and identifies, with direct evidence (not inference from aggregate p50/p95
figures), which specific serialization point — `_db_lock`, gunicorn's `--threads 8`/GIL scheduling,
SQLite's own busy-timeout/WAL-writer serialization, or another mechanism not yet named — is responsible
for the measured 74x-on-a-3ms-route degradation. Only then should a fix be proposed and implemented
against that attribution.

---

### D-DEBT-06-10 — a plan clause required bounding a query that must not be bounded

| field | value |
|---|---|
| **Filed** | 2026-09-02, after round 3's verification and code review |
| **Severity** | Critical (fixed); the *process* half remains open |
| **Found by** | `gsd-verifier` and `gsd-code-reviewer`, independently, with separate reproductions |
| **Code fix** | `bcad398` — shipped and pushed |
| **Status** | **Closed 2026-09-03 — both halves discharged.** Code fixed (`bcad398`). Process half closed by round 4's planning, which satisfied this entry's own stated closure condition ("a planning round that does that, not another code change") across all four of its plans. |

**What happened.** `06-13-PLAN.md` Task 2 carried an unconditional clause: *"`/api/services` must remain
bounded in rows read per request on whatever path it uses."* `06-13` satisfied it literally, moving
`_OFFLINE_INTERVALS_BULK_ROW_LIMIT` onto the surviving `checks_by_port` query when it removed the
duplicate `service_checks` read.

That query feeds **two consumers with different correctness requirements**:

| consumer | bounded before 06-13? | tolerates truncation? |
|---|---|---|
| `checks_by_port` → `_uptime_summary` (`uptime_pct`, 168-hour bar) | **No — never** | **No.** Truncation falsifies it. |
| `points_by_port` → offline-interval reconstruction | Yes, always | Yes, by design |

Ordered `port ASC, ts ASC`, the cap sheds each port's **newest** rows — so a service going offline late
loses exactly the samples that record it. Measured: a service with 10% real downtime reported
**100.0% uptime**, with a fully populated 168-bucket bar and no truncation signal anywhere on the
response. The reviewer's independent repro found the same mechanism inverted (99.998% → 0.002%).
Per `06-PROFILE.md` the cap is *already reached* at the documented 8-service/8-day shape, so this was
live on the deployed Pi, not theoretical.

**Why the clause was defective, not merely mis-implemented.** It treated two reads as one. The bound it
demanded had never applied to the uptime path; requiring it "on whatever path it uses" mandated
extending a cap into a computation that cannot survive one. `06-13` implemented the clause correctly.

**Why every gate passed anyway — the part worth keeping.**

- The clause's own guard test (`test_the_route_bounds_checks_by_port_rows_through_the_limit_constant`)
  asserted the SQL contained a `LIMIT` and the route returned `200`. It never asserted a resulting
  **value**. It is green in exactly the state that falsifies the metric.
- The plan checker verified the clause was *present and enforced*, and flagged it as the constraint
  most likely to be lost in implementation — correctly, but it never questioned the clause's premise.
- The orchestrator confirmed compliance and reported the constraint "honored," which added confidence
  without adding scrutiny. Checking that a requirement was met is not checking that the requirement
  was right.

**The generalizable lesson.** A guard asserting *shape* (SQL text, presence of a clause, a `200`) rather
than *consequence* (the number the user sees) can be satisfied by the exact defect it was written to
prevent. When a plan mandates a mechanism, at least one test must assert the mechanism's effect on
observable output. The replacement tests do: one asserts the uptime read carries **no** `LIMIT`, and a
second is mutation-verified to fail against the bug (`90.0` vs `100.0`).

**What would need to be true to close this entry.** Round 4's planning explicitly reviews any clause
mandating a *mechanism* rather than an *outcome*, and confirms each such clause's guard asserts
observable consequence. Closing it needs a planning round that does that, not another code change.

**Process half closed 2026-09-03.** All four of round 4's plans (`06-15` through `06-18`) carry an
explicit `<plan_review_against_d_debt_06_10>` section, and each one changed the plan it reviewed —
this is the entry's own bar ("a planning round that does that"), and it is met four times over, not
merely asserted once:

- **`06-15`** (the instrument itself). The unsatisfiable AST clause was caught at plan-check: an
  earlier draft asserted that no statement at all followed the `with _db_lock` block in
  `api_services` — false at HEAD, where the terminal `return jsonify(result)` genuinely does follow
  it — and the review replaced that with the real shape (containment of the four expensive calls
  plus a "nothing escaped but the terminal return" assertion), because a clause that is false at HEAD
  forces either a wrong pin or a weakened one. Two further changes: the hold-time guard moved from "a
  non-zero hold time" (satisfiable by a wrapper recording garbage) to "a hold matching a known
  critical-section duration within a stated tolerance"; and the inertness check moved from an
  `isinstance(lock, threading.Lock)` shape assertion to a call-count assertion on the module's own
  timing entry point, falsifiable by any code path that does timing work.
- **`06-16`** (the hold decomposition). Two summing identities were demoted from load-bearing guards
  to sanity checks reported for readability only: `connect_ns + sql_execute_ns + sql_fetch_ns +
  python_ns == hold_ns` and `wall_ns_total == cpu_ns_total + lock_wait_ns_total +
  other_off_cpu_ns_total` both hold by construction (each is a defined remainder), so neither
  demonstrates accuracy — confirmed directly by mutation: a thread-local-leak mutation pushed
  `clamped_python_count` to 706/3255 (21.7%) and `clamped_off_cpu_count` to 2505/3712 (67.5%) while
  the `sum(per-route hold) == global hold` identity survived exactly (`2,494,319,763 ==
  2,494,319,763`), proving the identity cannot catch the defect its prose originally claimed it
  would. `clamped_python_count`/`clamped_off_cpu_count` are documented as the real, mutation-verified
  concurrency guards instead.
- **`06-17`** (the harness wiring and verdict). A collection failure originally fed
  `failure_reasons` directly, which would have turned a diagnostic instrument into an oracle
  (violating `PROH-OPS-07-12`); the review changed it to record `collected: false` with a reason and
  leave the verdict untouched, with a test asserting the equivalence. Separately, the verdict
  function originally returned a boolean `attribution_confirmed`, which cannot express "the
  measurement did not settle it" — a run with too few acquisitions to be conclusive would have read
  as a refutation; it now returns the three-valued CONFIRMED/REFUTED/INCONCLUSIVE verdict this
  round's own result (INCONCLUSIVE) depended on existing.
- **`06-18`** (the hardware report). The deterministic arm's failing-oracle test gained the
  non-empty assertion it needed: the observer fires before the database-oracle read that appends the
  seeded failure, so both captured `(failure_reasons, overall_passed)` pairs are legitimately
  empty/`False` at that point — the review added an assertion on the run's *final*
  `failure_reasons` being non-empty, so the test proves the seeded failure genuinely fired rather
  than comparing two vacuously-empty snapshots.

**Every new test added across the four plans was mutation-verified, with observed failure values
recorded in each plan's own SUMMARY** — `06-15-SUMMARY.md`, `06-16-SUMMARY.md`, `06-17-SUMMARY.md`
each name their mutation and its observed effect, matching this entry's own evidentiary bar
("removing a guard's mechanism must be observed to fail before the guard is trusted").

---

### D-DEBT-06-13 — the full suite has become intermittently flaky under load (2 tests, both green in isolation)

| Field | Value |
|---|---|
| **Raised by** | Orchestrator, during round 4 wave 11 verification |
| **Status** | **Deferred — recorded, not fixed.** Does not block round 4. |
| **Severity** | Low for correctness; **medium for process** — the suite floor is a gate every plan cites |

**What was observed.** Two consecutive full-suite runs at the same commit produced two *different*
failures, and a third would likely produce another:

| run | result |
|---|---|
| 1 | `2 failed, 894 passed, 559 subtests` — `test_worker_ownership_matrix.py::…::test_heartbeat_renewal_to_persistence_handoff_is_fenced` (subtests S2, J1) |
| 2 | `1 failed, 893 passed, 561 subtests` — `test_services_route_scaling.py::…::test_a_check_count_independent_bucket_does_not_track_the_check_row_ratio` |

**Both pass reliably in isolation** — the ownership test 3/3, the bucket-ratio test 5/5. Neither
indicates a functional defect; both are assertions about very small measured quantities under
whole-suite load.

**A hypothesis that was tested and REFUTED, recorded so it is not re-proposed.** The obvious suspect
was `06-16`'s `TimingCursor`, which adds a Python-level override to every
`fetchall`/`fetchone`/`fetchmany` even on the disabled path. Measured directly:
**94 ns/query, 0.1%** (82,231 ns plain vs 82,325 ns via `TimingCursor`, `lockprofile.ENABLED` false,
3,000 queries). That cannot account for a flaky test. `db.py`'s "zero-overhead-when-disabled"
claim stands as written; the instrumentation is not the cause.

**The more likely reading.** Both assertions are inherently load-sensitive.
`test_a_check_count_independent_bucket…` asserts a growth ratio on `maintenance_windows_read`, which
`06-PROFILE.md` measured at **0.004% share / 0.032ms** — a quantity small enough that scheduler noise
dominates it. And `D-DEBT-06-05` already records the ownership fencing test as pre-existing flaky, not
a Phase 6 regression. The suite has grown from 859 to 894 tests across this round, which raises load
and surfaces latent sensitivity that was always there.

**Why this matters more than its severity suggests.** Every plan in this phase cites the suite floor
("no fewer than N passed") as an acceptance criterion. A floor that fails intermittently for reasons
unrelated to the change under test either blocks good work or, worse, trains a reader to wave failures
through — which is precisely how `06-13`'s truncation defect survived a green suite. A gate that cries
wolf is a gate that stops being read.

**What would need to be true to close this entry.** Either the two assertions are rewritten to bound
quantities large enough to be stable under load (or marked as measurement-sensitive and excluded from
the floor), or the floor criterion is restated as "no NEW failures outside the known-flaky set", with
that set named. Round 4's remaining plans should not adopt the current floor wording unchanged without
noticing this.

---

### D-DEBT-06-11 — the offline-interval reconstruction path's row cap silently bounds `maintenance_attributed_seconds`

| Field | Value |
|---|---|
| **Raised by** | `06-VERIFICATION.md` gap 2's third `missing:` item |
| **Status** | **Deferred — accepted by design, separable from Phase 6, not fixed here.** New this round. |
| **Recorded in the plan** | `06-18-PLAN.md` `<artifacts_this_plan_produces>`, `06-13-SUMMARY.md` (the entry `06-13` declined to file) |

**What it is.** `_OFFLINE_INTERVALS_BULK_ROW_LIMIT = 20000`
(`dashboard/beacon/repositories.py:1105`) bounds `read_service_offline_intervals_by_port`'s own
in-window `service_checks` query (`ORDER BY port ASC, ts ASC LIMIT ...`,
`dashboard/beacon/repositories.py:1206-1210`) — once the combined row count across every requested
port exceeds 20,000, the cap sheds the highest-numbered port(s)' **newest** in-window rows. Since
`06-13`, `/api/services` no longer calls that function directly; `bcad398` made it replicate the
identical cap in Python over its own already-fetched `checks_by_port` points
(`dashboard/app.py:2863-2897`), so the same truncation behavior governs
`maintenance_attributed_seconds` (`dashboard/app.py:2944`) regardless of which code path computes
it. `read_service_offline_intervals_by_port` itself is currently exercised only by tests
(`tests/test_services_route_scaling.py`), not by any live `app.py` route.

**Why this is not the same defect `bcad398` fixed.** The uptime-sweep path
(`checks_by_port` -> `_uptime_summary`) was fixed to be unbounded because truncation there silently
inflated `uptime_pct` — a correctness failure on the phase goal's own "keeps essential monitoring
reliable" clause. The offline-interval/maintenance path is bounded **by design** — `06-RESEARCH.md`'s
precedent for `_MAINTENANCE_WINDOWS_BULK_ROW_LIMIT` and this constant's own docstring both accept
truncation here as a memory/DoS bound with graceful degradation, not a defect. "By design" does not
mean invisible, though: a port whose newest in-window checks are shed under-reports
`maintenance_attributed_seconds` for the same structural reason the uptime path over-reported
`uptime_pct` before the fix.

**Why it is recorded here rather than left as prose.** `06-13-SUMMARY.md` explicitly declined to
file a discrete entry ("No separate Deferred-section entry was added"), so this finding has survived
only as prose inside `D-DEBT-06-01` and `06-PROFILE.md` §6 — at risk of being lost when the phase
closes. `06-VERIFICATION.md` gap 2's own wording agrees the finding is separable from Phase 6 and
asks only for an ID of its own, not a fix.

**What would need to be true to close this entry.** A decision on whether
`maintenance_attributed_seconds` tolerates truncation at the current 20,000-row cap at realistic
production data volumes — the cap is combined across every port requested in one call, not
per-port, so an install with many services and long retention could reach it even though this
round's Pi (56,828 `service_checks` rows total, 8 services) and `06-PROFILE.md`'s reference shape
both sit well under it — and a test asserting `maintenance_attributed_seconds`' actual value under
a patched-small limit, the same shape `WR-04` (see `D-DEBT-06-12`) already names as missing.

---

### D-DEBT-06-12 — carried-forward `06-REVIEW-ROUND3.md` findings still open

| Field | Value |
|---|---|
| **Raised by** | `06-REVIEW-ROUND3.md` Medium and Low sections |
| **Status** | **Deferred — recorded, not fixed.** New this round; consolidates seven findings so they survive the phase. |
| **Recorded in the plan** | `06-18-PLAN.md` `<artifacts_this_plan_produces>`, `06-REVIEW-ROUND3.md` |

Seven findings from `06-REVIEW-ROUND3.md` remain open. None is fixed by this round; this entry exists
so none evaporates when the phase closes.

| ID | Severity | File / line | Issue | Disposition |
|---|---|---|---|---|
| WR-01 | Medium | `tests/pi_load_acceptance.py:530-538` (prime on insert), `:621-626` (read in tick) | A process discovered mid-run gets two `cpu_percent` calls in the same tick; the second, over a sub-millisecond delta, can read in the thousands of percent and flows into `peak_cpu_percent`. | Open. Handled by avoidance this round, not fixed — see below. |
| WR-02 | Medium | `tests/pi_load_acceptance.py:832` | `primed_pid_count` reports the last tick's live PID count (post-pruning), not the count actually primed — a plausible-looking wrong number. | Open. Handled by avoidance this round, not fixed — see below. |
| WR-04 | Medium | `tests/test_services_route_scaling.py:488-543` (`OfflineIntervalsFromPointsTests`), `:352-419` (route bound guard) | No test exercises reconstruction or uptime output from a *truncated* row set — only that a `LIMIT` clause is present, which is exactly how `D-DEBT-06-10`'s regression shipped green. | Open. Directly relevant to closing `D-DEBT-06-11` above. |
| WR-05 | Medium | `dashboard/app.py:2825`; constant/docstring at `dashboard/beacon/repositories.py:1095-1105` | `app.py` reaches across the module boundary into a private (`_`-prefixed) `beacon_repositories` constant; the constant's docstring is now stale since `06-13` gave it a second consumer with a different failure mode. | Open. |
| IN-01 | Low | `dashboard/app.py:2822-2833` | The row-limit budget is spent on rows with `ts > now` before the Python-side upper-bound filter is applied, so a future-dated row (clock skew, NTP step) can displace a real in-window row. | Open. |
| IN-02 | Low | `dashboard/beacon/maintenance.py:223-252` | `_local_occurrence_epochs` is no longer lazy on the `cache=None` path, contrary to its docstring's "preserves the previous unmemoized behavior exactly" claim — the *values* are preserved, the evaluation strategy is not. | Open. No current caller breaks early, so nothing behaves differently today. |
| IN-03 | Low | `tests/pi_load_acceptance.py:489-497` | Both self-test roles share one `psutil.Process` object; the second role sampled each tick always reads ~0.0 CPU, which the harness's own `cpu_sampling.all_samples_zero` flag would report as a broken measurement in self-test mode specifically. | Open. Pre-existing; only newly visible now that `cpu_sampling` reports it. |

**Two of the seven bore directly on this round and were handled by avoidance, not by fix.** WR-01
can inflate `peak_cpu_percent` into the thousands of percent when a process is discovered mid-run;
this round's diagnostic reasoning about CPU (where it appears at all) uses `mean_cpu_percent`
exclusively and any `peak_cpu_percent` figure this artifact reports is caveated inline, never relied
on. WR-02 makes `primed_pid_count` report the last tick's live PID count rather than the primed
count; `06-LOCK-DIAGNOSTIC.md` does not cite that field anywhere as evidence. **Neither defect was
fixed by this round.** A future round reading `peak_cpu_percent` or `primed_pid_count` from the
harness must fix the underlying defect first, not merely repeat this round's avoidance.

---

### D-DEBT-06-14 — an absolute-band prediction failed under dataset growth; the relational prediction on the same quantity did not

| Field | Value |
|---|---|
| **Raised by** | `06-LOCK-DIAGNOSTIC.md`'s Verdict section, `06-18-PLAN.md` Task 1 |
| **Status** | **Deferred — a diagnostic-harness change for round 5's predictions, not a code fix.** New this round. |
| **Recorded in the plan** | `06-LOCK-DIAGNOSTIC.md` §§1–2 and Verdict, `tests/pi_load_acceptance.py`'s `LOCK_ATTRIBUTION_PREDICTIONS` |

**What was observed.** Round 4's hardware run carried two predictions over the same underlying
quantity — `/api/services`' measured hold — expressed two different ways, and only one survived the
Pi's dataset growing 2.24x since the predictions were calibrated (25,278 → 56,828 `service_checks`
rows):

- **The relational check, `scan_status_wait_tracks_services_hold`** (`scan_status_wait_median /
  services_hold_median >= 0.5`) **HELD**, measured **0.5141**.
- **The absolute check, `services_median_hold_in_band`** (a fixed `[200,000,000, 500,000,000]`ns
  band) **FAILED**, measured **596,245,129ns** — 19.2% over the band's upper edge.

Both checks were evaluated against the same hardware run's own `/api/services` hold figure. The
relational check expresses a ratio between two quantities measured in that same run; the absolute
check encodes a fixed millisecond value calibrated to round 3's dataset size and does not rescale
when the deployment's data volume grows.

**Why this is the same defect class `D-DEBT-06-10` names, in a different costume.** `D-DEBT-06-10`'s
lesson is that a plan clause mandating a *mechanism* instead of an *outcome* can be satisfied by the
exact defect it exists to catch. An absolute-millisecond prediction is a mechanism-shaped
commitment wearing an outcome's clothing: it looks like it asserts a measured consequence, but it
actually asserts a specific number tied to the dataset size that number was calibrated against —
change the dataset and the prediction fails for a reason that has nothing to do with whether the
attributed mechanism (the lock) is real. `06-LOCK-DIAGNOSTIC.md`'s own recalibration arithmetic
demonstrates this precisely: rescaling the band by this run's own control-pass growth ratio
(`257.6ms / 209.355ms ≈ 1.230x`, applied to `[200,000,000, 500,000,000]`ns) gives approximately
`[246,000,000, 615,000,000]`ns — inside which the measured 596.2ms falls, which would read
CONFIRMED on the identical measured figures. The relational check needed no such rescaling because
it was never tied to an absolute dataset size in the first place.

**What round 5 must do differently.** Any new prediction phrased in `LOCK_ATTRIBUTION_PREDICTIONS`
should be relational (a ratio or comparison between two quantities measured in the same run) or, if
an absolute figure is genuinely required, explicitly dataset-scaled (calibrated against a
recorded row count or growth ratio captured in the same run, not a constant carried over from a
prior round's dataset size). This is a change to the diagnostic harness's prediction constants, not
a change to `_db_lock` or any production code path.

**What would need to be true to close this entry.** Round 5 (or the follow-up fix plan, if it
re-runs the diagnostic harness) either replaces `services_median_hold_in_band` with a relational
form, or documents why an absolute band is retained and how it is rescaled against the run's own
measured dataset growth before being evaluated.

---

### D-DEBT-06-15 — narrowing `_db_lock` alone cannot make OPS-07 pass; the GIL/topology half is a separate problem, and the laptop-based fix sizing overstated the payoff

| Field | Value |
|---|---|
| **Raised by** | `06-LOCK-DIAGNOSTIC.md` §§3–4, `06-18-PLAN.md` Task 1 |
| **Status** | **Deferred — scoping input for the follow-up fix plan (`06-19` or later); not fixed here.** New this round. |
| **Recorded in the plan** | `06-LOCK-DIAGNOSTIC.md` §§3–4, `D-DEBT-06-01`'s "Round 4 reopening" section above |

**What narrowing `_db_lock` cannot touch.** `/api/advanced/current` is over its own 2000ms budget
(measured p95 2217.6ms per the operator's Task-1 transcript) and records **exactly 0.0ms** lock wait
across 880 requests (`requests['/api/advanced/current'].lock_wait_ns_total`,
`beacon-lockdiag-c8.json`) — its cost is entirely `cpu_ns_total = 536,241.0ms` and
`other_off_cpu_ns_total = 550,980.5ms` (`06-LOCK-DIAGNOSTIC.md` §3). A lock this route never
acquires cannot be narrowed into fixing it; whatever is producing that 12.31x degradation
(92.4ms → 1,137.5ms wall p50) is GIL/thread-scheduling or topology-bound, and lives entirely outside
`_db_lock`'s reach. **A fix that narrows `_db_lock` and nothing else cannot make OPS-07 pass on its
own** — `/api/advanced/current`'s budget failure needs its own remedy (a topology change such as
`--workers`/`--threads` retuning, which `PROH-OPS-04-05` gates separately, or a cost reduction in
`beacon/diagnosis.py` itself) or the round must accept it as a second, un-fixed budget failure.

**Why the candidate fix's sizing was overstated.** `06-PROFILE.md` §3 measured, on a laptop,
`/api/services`' held region at 17.958% SQL / 82.042% Python (`sql_execute` 2.338% + `sql_fetch`
15.620%). Round 4's hardware measurement, under the same concurrency-8 load the fix is meant to
relieve, found the opposite proportion: **connect .002 / sql .748 / py .250** — roughly **75% SQL,
25% Python** (`06-LOCK-DIAGNOSTIC.md` §4, `beacon-lockdiag-c8.json`
`lock_profile.routes['/api/services']`). The laptop figure implied that moving the "Python" work out
of the critical section would remove roughly 82% of what the lock protects; the hardware figure
shows only 25% of it is actually Python — SQL, not Python, dominates the held region under real
load. The achievable cut is therefore much smaller than the laptop profile suggested.

**Arithmetic, shown against round 4's own planning-stage sizing assumption.** Before Task 2's
correction (see `06-18-SUMMARY.md`'s Issues Encountered section), this round's own plan text
estimated `/api/services` at "roughly 61% of total hold." Applying the hardware-measured 25.0%
Python share — not the laptop's assumed 82.042% — to that planning-stage share estimate:
`0.61 × 0.25 ≈ 0.1525` — **roughly a 15% cut to total hold**. New total hold:
`578,783.964515ms × (1 − 0.1525) ≈ 490,530ms`. New utilisation: `490,530 / 600,444.800885 ≈ 0.82` —
barely under the 0.85 superlinear threshold, not a comfortable margin. This is a materially smaller
and more marginal payoff than the laptop-implied estimate would have promised (a naive
`0.61 × 0.82042 ≈ 0.50` cut would have suggested utilisation falling to roughly 0.48, comfortably
under threshold) and is also more marginal than `06-LOCK-DIAGNOSTIC.md` §4's own corrected estimate
using the accurate 90.9%-of-total-hold share (`882 × 596.245129ms = 525,888.19ms`,
`525,888.19 × 0.25 = 131,472.05ms` cut, `(578,783.96 − 131,472.05) / 600,444.80 ≈ 0.745`). Both
figures are recorded here because they bracket the payoff's sensitivity to which share estimate is
used — the round's own planning-stage estimate (0.82, barely under threshold) versus its
measurement-corrected one (0.745, comfortably under threshold) — and `06-LOCK-DIAGNOSTIC.md` §4
itself cautions that even the corrected 0.745 figure "is sized as a payoff estimate, not a
commitment... it assumes the 25% Python cut translates linearly into hold-time reduction and holds
all other routes' behavior constant, neither of which this round measures directly."

**What the follow-up plan must carry as a result.** The fix plan should treat 0.745–0.82 as the
estimated post-fix utilisation range for a Python-only cut to `/api/services`' critical section —
not the deeper cut the laptop profile implied — and should plan for `/api/advanced/current`'s
budget failure as a second, separate problem `_db_lock` narrowing does not touch, per the item
above. `D-DEBT-06-01`'s "Round 4 reopening" section names the audit and testing prerequisites
(`PROH-OPS-04-05`) that gate the fix itself; this entry names what the fix can and cannot be
expected to achieve once those prerequisites are met.

**What would need to be true to close this entry.** The follow-up plan implements the fix, measures
its actual hardware-verified utilisation (not the arithmetic estimate here), and either closes
`/api/advanced/current`'s budget failure by a separate remedy or explicitly scopes it into a further
round.

---

### D-DEBT-06-16 — non-`api_services` sites holding non-database work under `_db_lock`, found by the 28-site audit and left untouched

| Field | Value |
|---|---|
| **Raised by** | `06-19-PLAN.md` Task 1, `06-LOCK-AUDIT.md`'s per-call-site review |
| **Status** | **Deferred — future narrowing candidates, not fixed here.** New this round. |
| **Recorded in the plan** | `06-LOCK-AUDIT.md` "Future narrowing candidates this round is deliberately not taking" |

**What the audit found.** `06-LOCK-AUDIT.md`'s per-call-site review of all 28 `with _db_lock` sites
found two sites, beyond `api_services` (the sole site `06-20` narrows), that hold non-database
Python work under the lock:

- **`api_service_meta` (PUT), `dashboard/app.py:3069`.** Field validation, URL normalization
  (`_normalize_service_url`, `_service_url_with_path`), and outbound-policy planning
  (`_outbound_policy().plan(...)`) all execute inside the critical section, ahead of the actual
  metadata write. This route is not hardware-profiled this phase — no measured share of its held
  region exists, unlike `api_services`' measured 25.0% Python share (`06-LOCK-DIAGNOSTIC.md` §4).
- **`recover_worker_state`, `dashboard/app.py:240`.** JSON serialization of the `monitoring_gap`
  event's `details` payload runs under the lock — a small, bounded cost (one `json.dumps` call over
  a two-key dict), named for completeness rather than as a meaningful narrowing target.

**Why neither is narrowed this round.** `PROH-OPS-04-05`'s decision checkpoint (`06-18-PLAN.md`
Task 3) scoped the user's `fix-now` decision to `_db_lock`'s attribution evidence, which measured
`api_services` and `/api/scan-status` specifically. Narrowing a site with no measured evidence
behind it would be exactly the kind of un-evidenced fix `D-DEBT-06-09` and `D-DEBT-06-15` warn
against repeating. `06-20`'s scope is `api_services` alone.

**What would need to be true to close this entry.** A future round hardware-profiles
`api_service_meta`'s PUT path specifically (its own lock-profile route label, analogous to
`api_services`'), measures whether its held-region Python share is large enough to matter under
load, and either narrows it on that evidence or explicitly declines to, the same way this round
declined to act on the laptop-only `06-PROFILE.md` figure for `api_services` before
`06-LOCK-DIAGNOSTIC.md`'s hardware measurement existed.

---

## 2. Decided — recorded rationale, no further action needed this phase

### D-DEBT-06-01 — narrow `_db_lock`'s scope now that WAL is in force

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Open Question 3, `PROJECT.md`'s `AR-03-01` accepted-risk note |
| **Status** | **Reopened 2026-09-03 — the user selected `fix-now` at `06-18-PLAN.md` Task 3's checkpoint, against `06-LOCK-DIAGNOSTIC.md`'s measured INCONCLUSIVE verdict.** Deferred three times before this (see history below); the deferral is now reversed by explicit user decision. Narrowing itself is scoped into a follow-up plan (`06-19` or later), not this plan — see "Round 4 reopening" below for what that plan must carry. |
| **Recorded in the plan** | `06-05-PLAN.md` decision D-01, `PROH-OPS-04-02`, `06-10-PLAN.md` Task 2's decision checkpoint |

**What was not done and why.** `_db_lock`'s scope in `dashboard/app.py` remains unchanged at every one
of its 30 call sites. `D-01` locked this boundary for Phase 6 explicitly: WAL only, `_db_lock` untouched.
`06-RESEARCH.md` Pitfall 4 is the reason this is a boundary and not an oversight: WAL governs
reader/writer blocking *across connections*, while `_db_lock` serializes access from *multiple threads
inside one gunicorn process* (`--workers 1 --threads 8`). Enabling WAL does not make `_db_lock`'s
serialization redundant — the two solve different problems, and relaxing the second is not a free
consequence of enabling the first.

**This round's re-examination (`06-10`, Task 2) — the deferral was re-tested against measured evidence,
not merely repeated.** Before this round there was only an argument for narrowing the lock (a single
2.5-second `/api/services` route amplified by the lock into a 600s-run-wide stall). This round produced
real hardware evidence and put the decision to the user against it:

- The control pass (concurrency 1, 120s) showed `/api/services` p50 at **289.0ms** after `06-08`'s fix
  — an 8.7x improvement over the pre-fix 2504.6ms, but not the "tens of milliseconds" `06-08` predicted.
  It still consumes 58% of that route's own 500ms budget at zero contention.
- The acceptance pass (concurrency 8, 600s) still **failed**: `overall_passed: false`, with
  `/api/services` (p95 2465.9ms vs. 500ms budget), `/api/scan-status` (p95 1797.4ms vs. 500ms), and
  `/api/advanced/current` (p95 2742.1ms vs. 2000ms) all over budget.
- Critically, `/api/advanced/current` does **not** take `_db_lock` at all — `dashboard/app.py` calls
  `beacon_diagnosis.get_current_diagnosis` directly, and `dashboard/beacon/diagnosis.py` holds no lock
  (this is the pre-existing `AR-03-01` accepted-risk route). That unlocked route still degraded from an
  80.7ms control p50 to a 2344.0ms acceptance p50 — a 29x regression under concurrency 8. A
  process-wide lock cannot produce that effect on a caller that never acquires it. This is direct
  evidence that `_db_lock` is not sufficient to explain the observed failure, which is exactly the
  precondition the `narrow-now` option required ("routes still over budget with `/api/services` now
  fast") and which did not hold: `/api/services` is not fast, and the worst-regressed route in the
  failing run is not even locked.
- The evidence instead points at `--workers 1 --threads 8` (`dashboard/Dockerfile`) — eight threads in
  one Python interpreter behind one GIL — combined with `/api/services`'s residual Python-side cost:
  `06-08` removed the 168x per-bucket rescan but the per-service `_uptime_summary` sweep and
  `attributed_downtime_seconds` computation over the full check-retention window remain proportional to
  stored check count and hold the GIL for the duration.
- A rough closed-loop arithmetic check (a model, not proof): applying the control pass's per-request
  p50s as service times against the acceptance run's observed request counts predicts roughly 359s of
  single-threaded service time inside the 600s window (~60% utilisation), of which `/api/services`
  accounts for roughly 250s (~70%). The mean observed response (~376ms) is close to what an M/M/1-style
  single-server model with 8 waiting clients predicts (~430ms) — consistent with the deployment
  behaving as effective concurrency ~1 regardless of lock scope, because the GIL alone is enough to
  produce that behavior for locked and unlocked routes alike.
- **Honest limit of this evidence.** These two runs cannot fully separate GIL contention from
  `_db_lock` contention, because `/api/services`'s residual cost is large enough to saturate either
  mechanism on its own. What the 29x regression on the unlocked `/api/advanced/current` route
  establishes is narrower but load-bearing: `_db_lock` is not *sufficient* to explain the failure. It
  does not by itself prove the lock is contributing nothing.

**The decision: `defer-again`, chosen by the user.** `_db_lock`'s scope stays exactly as it is. No line
touching the lock changed in `06-10`. `T-06-24`'s closure evidence in `06-SECURITY.md` remains valid
and `/gsd-secure-phase 06` does not need to re-run.

**What would reopen this.** Per the original entry: a future route whose own service time is large
enough to saturate the serialized path again. This round sharpens that with two concrete, evidence-
grounded candidates rather than a restated abstraction:
1. `/api/services`'s residual per-request cost (289ms at zero contention) and the single-worker,
   multi-threaded GIL configuration are the live suspects for the acceptance run's remaining slowness —
   not `_db_lock`.
2. A run in which the *unlocked* `/api/advanced/current` route recovers to near its control-pass p95
   under concurrency 8 while the *locked* routes (`/api/services`, `/api/scan-status`) remain over
   budget would newly and specifically implicate `_db_lock` itself, because it would isolate the
   failure to exactly the routes the lock touches. That comparison is the reopening test.

**The evidence this phase produced that a future evaluation should start from:**

- The starting-mode evidence outcome for the production database is recorded below (see `D-DEBT-06-03`)
  — the production reading itself was not captured this phase, but the rollout logic is proven for
  both starting modes by `tests/test_workload_resilience.py::WalModeTests::test_connections_run_in_wal_mode_from_either_starting_mode`.
- `tests/test_workload_resilience.py::ConcurrentAccessTests::test_concurrent_web_and_worker_writers_are_corruption_free`
  proves a bounded stress run of eight `_db_lock`-serialized web-shaped writers plus one worker-shaped
  writer completes with zero unhandled exceptions, `PRAGMA integrity_check` returning `ok`, and every
  reported-committed write present afterward (PROH-OPS-04-01), all under WAL and with `_db_lock` in
  its current, unnarrowed form.
- `tests/test_workload_resilience.py::ConcurrentAccessTests::test_worker_restart_recovery_fences_the_dead_epoch`
  proves a worker restart correctly fences the dead epoch's claim, and that the dead epoch's terminal
  write is rejected with `LeaseLost` and changes nothing.
- The pre-existing `AR-03-01` accepted-risk note for `api_advanced_current` (`.planning/PROJECT.md`),
  the one route already outside `_db_lock` — its reasoning (a 30s maintenance-flock wait inside a
  process-global lock would stall every DB route behind a 5-second poll) is the baseline a `_db_lock`
  narrowing evaluation must reconcile with, not relitigate from scratch. This round's evidence (that
  route degrading 29x while unlocked) is consistent with that baseline reasoning and does not overturn
  it.
- This round's two hardware reports (`beacon-control-c1.json`, `beacon-acceptance.json`), attached as
  phase evidence — the first hardware evidence this entry has ever had, where before there was only an
  argument.
- `06-14`'s two round-3 hardware reports (`beacon-control-c1-round3.json`, `beacon-acceptance-round3.json`,
  both recorded in full in `06-ACCEPTANCE-ROUND3.md`) — the entry's own second reopening test evaluated
  for the first time (did not fire), and the first working CPU reading this entry has ever had to reason
  about (165.504% mean on the web role, ruling out both "genuinely idle" and "classic GIL hard-pin" as
  the shape of the contention, without yet attributing it to a specific mechanism).

**What would need to be true to proceed with narrowing, if this is reopened.** Unchanged from the
original entry: a per-call-site audit of all `_db_lock` uses; a demonstration that read-only routes no
longer block behind a writer under WAL specifically (not merely an assumption that WAL implies it); and
a regression that fails if any route regains unserialized access it should not have. None of that audit
exists yet.

**Explicitly not a bug.** `_db_lock` is correct as it stands today. This is an optimization opportunity,
not a defect; removing or narrowing it without the audit above would reintroduce the exact race it was
added to prevent.

**`06-13`'s re-examination — the deferral now also rests on a measured cost attribution, not only on
the 29x unlocked-route evidence.** `06-12`'s profiler (`tests/services_route_profile.py`) supplied the
attribution `D-DEBT-06-01` previously argued about: at the profiled 8-service/8-day shape,
`/api/services`'s residual cost is dominated by two named, measured, in-process Python-side
sub-computations — `maintenance_coverage` (29.649% share, growth ratio 7.564, *exceeding* the measured
`check_row_ratio` of 4.249 — the single bucket the profile found growing faster than stored check
count) and a duplicate full-window `service_checks` scan inside `sql_fetch`/`offline_intervals_read`
(15.620% + 10.266% share, confirmed 79.1% duplication of the same rows). Both are reducible without
touching `_db_lock`, `dashboard/Dockerfile`'s topology, or `docker-compose.yml`. Given the user selected
`reduce-request-cost` at Task 1's checkpoint — attacking the input rather than the lock or the GIL —
this bears on the entry's first named reopening condition (`/api/services`'s residual cost as the live
suspect) directly: the residual is now smaller than it was, on measured evidence, not by argument. It
does not bear on the second reopening condition (the unlocked-route recovery comparison) at all —
`06-13` changes no topology and takes no `/api/services`/`/api/advanced/current` hardware measurement.
`_db_lock`'s scope stays exactly as it is; no line touching it changed in `06-13`. `T-06-24`'s closure
evidence remains valid and `/gsd-secure-phase 06` does not need to re-run.

**`06-14`'s re-examination — the third hardware run, and the entry's own second reopening test
evaluated for the first time.** `06-14` Task 1 ran the real Pi acceptance harness a third time against
this round's build (`b8ed60b`, `06-13`'s fix included). Full figures are in `06-ACCEPTANCE-ROUND3.md`.
The run's `overall_passed` is **still `false`**: `/api/services` (p95 1732.3ms vs. 500ms), `/api/scan-status`
(p95 656.5ms vs. 500ms), and `/api/advanced/current` (p95 2382.2ms vs. 2000ms) all remain over budget.

**What the chosen fix achieved.** `06-13`'s `reduce-request-cost` fix is confirmed to have reduced
`/api/services`'s per-request cost on real hardware, not just in profiling: the control-pass p50 fell
27.6% (289.0ms → 209.355ms) and the acceptance-pass p95 fell 29.7% (2465.9ms → 1732.3ms). It did not
close the gap under concurrency — `/api/services` is still 3.5x over its own 500ms p95 budget.

**The entry's own second reopening test, evaluated for the first time — and it did NOT fire.** The
test named above is: the unlocked `/api/advanced/current` route recovering to near its control-pass p95
under concurrency 8 while the locked routes (`/api/services`, `/api/scan-status`) stay over budget.
Round 3 shows the opposite of recovery: `/api/advanced/current`'s p95 improved only 13.1% (2742.1ms →
2382.2ms, round 2 → round 3) and remains over its own 2000ms budget, degrading 12.6x from its own
82.281ms control p50. A process-wide lock this route never takes cannot produce a 12.6x degradation on
it. **This test not firing means `_db_lock` is not newly implicated by round 3** — the entry's original
"not sufficient to explain the failure" finding from round 2 stands, unstrengthened and unweakened by
this run specifically with respect to the lock question.

**What round 3 measured instead.** The failure mechanism is now measured to be serialization under
concurrency, not per-request cost: `/api/scan-status`, a 3.281ms route at concurrency 1, degrades 74x to
242.614ms at concurrency 8, while the web role's `mean_cpu_percent` (165.504 of 400% available, a real
CPU reading for the first time — see `D-DEBT-06-06` below) shows roughly 2.3 of 4 cores idle on
average. That combination — a 3ms computation taking 243ms while most of the machine sits idle — cannot
be explained by added computation; something is serializing requests. Whether that something is
`_db_lock`, the deployment's `--threads 8` single-interpreter GIL scheduling, SQLite's own
busy-timeout/WAL-writer serialization, or a mechanism not yet named is **not established by this run**
— see the new `D-DEBT-06-09` entry, which this round adds specifically to track that open question as
a diagnostic item rather than leaving it implicit inside this entry. `_db_lock`'s scope stays exactly as
it is; no line touching it changed in `06-14` (this plan runs a harness and writes documentation only).

**What `06-13` implemented, concretely.** A request-scoped memo in `dashboard/beacon/maintenance.py`
for `_local_occurrence_epochs` (keyed on `(window, the calendar date now_epoch resolves to, timezone)`
— the exact granularity at which that function's result is provably invariant) and for
`window_from_row`'s per-call re-parse/re-validate work, both threaded through `coverage()` and
`attributed_downtime_seconds()` via an optional `cache=` parameter that defaults to `None` (every
caller outside `/api/services` is unaffected). Measured at the fast growth-shape used by
`tests/test_services_route_scaling.py`'s `ServicesRouteProfilerGuardTests` (2 services, 1-vs-4 days,
seed `20260901`, 20 repeats): `maintenance_coverage` fell from small=276.221ms / large=1322.387ms
(memo disabled, verified by hand) to small≈30ms / large≈133ms (memo enabled, as shipped) — roughly a
9-10x absolute reduction. Separately, `dashboard/app.py`'s `api_services` no longer calls
`beacon_repositories.read_service_offline_intervals_by_port` a second time over rows it already fetched
into `checks_by_port`; a new `beacon_repositories.offline_intervals_from_points_by_port` reconstructs
offline intervals from those already-fetched points instead, reusing the same
`_offline_intervals_from_points` helper the removed call used, proven equivalent to the single-port
oracle by `tests/test_services_route_scaling.py::OfflineIntervalsFromPointsTests`. The `checks_by_port`
query itself now carries `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` as its `LIMIT` — the same named constant,
not a second literal — so `/api/services` does not lose its 20,000-row bound as a side effect of no
longer duplicating the read; proven through the route by a new test patching the constant small and
asserting the bound holds via `test_client()`.

**Honest limit of this round's evidence.** `06-13`'s guard for `maintenance_coverage` asserts the
achieved *absolute* cost reduction, not the growth-ratio classification Task 2's plan text named
(`growth_ratio` below half the measured `check_row_ratio`): that classification was not reached. Call
*count* into `coverage()`, not per-call cost, still scales with retained days, because it is driven by
the number of discrete stored-check-derived offline intervals `attributed_downtime_seconds` processes
one at a time — over a thousand short intervals at the profiled seeded shape, from J3/J4-cadence
sampling for the one port carrying a window. Reducing that further would mean changing
`_offline_intervals_from_points`'s interval-merging behavior, which `06-13` did not do: out of this
round's scope, and risking the byte-identical output guarantee `PROH-OPS-07-05` protects. See
`06-13-SUMMARY.md`'s Deviations section for the full accounting. Whether this round's cost reduction is
*sufficient* to close the `OPS-07` responsiveness gap is not established here — that is `06-14`'s
hardware run to determine. `D-DEBT-06-06` (the broken CPU-percent sampling) is untouched by `06-13` and
remains open below.

---

**Round 4 reopening (2026-09-03) — the second reopening test is withdrawn as non-diagnostic, and the
user's `fix-now` decision replaces it as the entry's live reopening evidence.**

**The second reopening test named above — "the unlocked `/api/advanced/current` route recovering to
near its control-pass p95 under concurrency 8 while the locked routes stay over budget" — is
withdrawn.** It never fired across rounds 3 or 4, and round 4's own hardware measurement establishes
why it never could: it uses `/api/advanced/current`, an unlocked, GIL-bound 82.281ms route, as the
discriminator for a *lock* it never takes. Round 4 measured that route directly:
`requests['/api/advanced/current'].lock_wait_ns_total` is exactly **0.0ms** across 880 requests
(`beacon-lockdiag-c8.json`), confirming by direct measurement, not inference, that this route can
never carry evidence about `_db_lock` in either direction — a route with zero lock exposure cannot
discriminate a lock hypothesis regardless of how it performs. Its own degradation (92.4ms → 1,137.5ms
wall p50, 12.31x) is separately measured to be GIL/CPU contention (`cpu = 536,241.0ms`,
`other_off_cpu = 550,980.5ms` across 880 requests, `06-LOCK-DIAGNOSTIC.md` §3), not evidence about
the lock. This test is retired, not merely unfired — a future round must not run it a third time
expecting a different reading; the mechanism that makes it non-diagnostic does not depend on load or
dataset size, only on the route never acquiring `_db_lock`.

**The decision, recorded verbatim.** Put to the user at `06-18-PLAN.md` Task 3's blocking
`checkpoint:decision`, against `06-LOCK-DIAGNOSTIC.md`'s measured INCONCLUSIVE verdict and the
planner's recorded recommendation (`defer-to-round-5`). **The user selected `fix-now`.** This
reverses the `defer-again` decision recorded above for the third time — the deferral held across
three prior rounds (`06-10`, `06-13`, `06-14`), each re-examined against fresh evidence; round 4's
hardware measurement is the first evidence to support the mechanism directly (99.0%
`scan_status_lock_wait_share_of_wall`, 0.9639 utilisation) rather than only rule out competing
explanations, and the user weighed that against the round's own recorded verdict being INCONCLUSIVE,
not CONFIRMED, and chose to proceed anyway. That is the reopening evidence now on record for this
entry; the second reopening test above no longer applies.

**`06-CONTEXT.md` D-01's fence is explicitly lifted by this decision, not implicitly overridden.**
D-01 fenced `_db_lock`'s scope for this phase; `PROH-OPS-04-02` forbade narrowing it "unless the
decision checkpoint in this plan explicitly resolves in favour of narrowing it." That checkpoint has
now resolved in favour of narrowing it. No line touching `_db_lock` changes in this plan (`06-18`)
— the fence is lifted for the follow-up plan that implements the fix, not retroactively for this one.

**What the follow-up plan (`06-19` or later) must carry, restating `PROH-OPS-04-05`'s prerequisites
rather than re-deriving them.** `PROH-OPS-04-05` (`06-13-PLAN.md`) states: *"Raising gunicorn's
worker count therefore grants a second OS process unserialized concurrent write access to the same
database file without any line of `_db_lock` changing. Such a change must never be made as an
incidental performance tuning: it requires the same cross-process audit `D-DEBT-06-01` names for
narrowing the lock, a `mem_limit` re-derived from the measured per-worker RSS, and
`/gsd-secure-phase 06` re-run because `T-06-24`'s closure evidence is invalidated by construction."*
Narrowing `_db_lock`'s scope is the same class of change this prohibition describes for a different
lever (scope instead of worker count), and the original entry's own prerequisites still apply
verbatim:

1. **The cross-process audit this entry has always named:** a per-call-site `_db_lock` audit across
   all 28 sites — `06-15`'s `LockScopePreservationTests` already pins the current shape by count (28
   sites: 3 bare, 25 combined `database_access(DB_PATH) as conn:`) and by AST containment/escape
   assertions on `api_services`' critical section specifically; the follow-up plan's audit is a
   superset of that pin, covering every site the narrowing touches, not only `api_services`'.
2. **A demonstration that read-only routes no longer block behind a writer under WAL specifically**
   — not an assumption that WAL implies it (unchanged from the original entry).
3. **A cross-process/concurrent-writer integrity test** extending
   `tests/test_workload_resilience.py::ConcurrentAccessTests::test_concurrent_web_and_worker_writers_are_corruption_free`'s
   guarantee (`PROH-OPS-04-01`) across whatever new concurrency the narrowing introduces — the
   existing test proves the *current*, unnarrowed lock's guarantee; a narrowed lock needs its own
   proof, not an inherited one.
4. **`/gsd-secure-phase 06` re-run**, because `T-06-24`'s closure evidence is invalidated by
   construction the moment `_db_lock`'s scope changes. `06-15` already replaced `T-06-24`'s original
   diff-based closure evidence (`git diff 8c2fc48..HEAD -- dashboard/app.py` showing 0 added/removed
   `_db_lock` lines) with a test-enforced call-site pin (`LockScopePreservationTests`' count
   assertion) plus the AST scope pin (containment + no-escape, `06-SECURITY.md` `T-06-24`). The
   follow-up plan's job is to re-close `T-06-24` again on new evidence describing the narrowed
   shape — not to restore the retired diff-based form. `06-15`'s scope pin **will fail by design**
   when the narrowing changes what sits inside the `with _db_lock` block; that failure is the pin
   doing its job (routing the implementer to this entry and to `PROH-OPS-04-05`, per the assertion
   message convention `test_the_deployment_pins_its_gunicorn_concurrency_model` established for
   `D-DEBT-06-07`), and it is correct and expected — not something to suppress or work around.

**What `06-LOCK-DIAGNOSTIC.md` §4 sizes for that follow-up plan, and why the sizing is smaller than
`06-PROFILE.md`'s laptop figure implied.** See the new `D-DEBT-06-15` below — narrowing `_db_lock`
addresses only `/api/services`' lock-hold contribution, and the hardware-measured payoff of that fix
is materially smaller than the laptop profile's 82.042%-Python figure would have suggested, because
the hardware's own SQL share is far higher (74.8% under load, not 17.958%). `_db_lock`'s narrowing
also does nothing for `/api/advanced/current`'s GIL-bound degradation, which is a second, separate
problem the follow-up plan must have in view — narrowing the lock alone cannot make OPS-07 pass.

---

### D-DEBT-06-07 — deployment gunicorn concurrency model pinned at the source level

| Field | Value |
|---|---|
| **Raised by** | `06-VERIFICATION.md` (warning-level anti-pattern on `dashboard/Dockerfile:27`), `06-13-PLAN.md` Task 3 |
| **Status** | **Decided — pinned by a test, not by convention.** Closed for this phase. |
| **Recorded in the plan** | `06-13-PLAN.md` Task 3, `tests/test_module_boundaries.py::ModuleBoundaryTests::test_the_deployment_pins_its_gunicorn_concurrency_model` |

**The values in force.** `dashboard/Dockerfile`'s gunicorn `CMD` runs `--workers 1 --threads 8` —
unchanged by `06-13`, since the user's Task 1 decision (`reduce-request-cost`) touches no deployment
topology. These two numbers are the deployment's concurrency model: one OS process, one Python
interpreter, one GIL, eight HTTP-serving threads, and therefore one `_db_lock` instance serializing
every database-touching route that takes it.

**Why they are now pinned by a test, not merely documented.** Every latency figure this phase's
evidence rests on — the Pi control-pass and acceptance-pass numbers in `D-DEBT-06-01`, `06-PROFILE.md`'s
attribution and growth tables, the acceptance-harness runs `06-10` and `06-14` produce — was gathered
under exactly this topology. `06-VERIFICATION.md` flagged the unpinned `CMD` line as a warning-level
anti-pattern precisely because nothing prevented a future edit from silently changing the concurrency
model those numbers describe, without anyone noticing the evidence base had shifted underneath them.
`tests/test_module_boundaries.py::ModuleBoundaryTests::test_the_deployment_pins_its_gunicorn_concurrency_model`
parses the `CMD` line's argument list and asserts `--workers == "1"` and `--threads == "8"` at the
source level, with assertion messages naming `D-DEBT-06-01` and `PROH-OPS-04-05` so a developer who
trips it is routed to the decision record rather than tempted to update the constant to make the test
pass. Proven non-tautological by mutation: temporarily changing `--workers` to `"2"` and, separately,
`--threads` to `"4"` was each observed to fail this test (verified by hand while writing it; both
mutations reverted, `git diff -- dashboard/Dockerfile` clean afterward).

**What `PROH-OPS-04-05` requires of anyone changing these values.** Raising `--workers` above 1 grants a
second OS process unserialized concurrent write access to the same SQLite file with no line of
`_db_lock` changing — the same boundary `06-SECURITY.md`'s `T-06-24` is closed on. That change may not
ship as an incidental performance tuning: it requires the same cross-process audit `D-DEBT-06-01` names
for narrowing the lock, a per-call-site `_db_lock` audit, a separate-process concurrent-writer integrity
test extending `PROH-OPS-04-01`'s guarantee across the process boundary, a `mem_limit` re-derived from
measured per-worker RSS (see below), and `/gsd-secure-phase 06` re-run because `T-06-24`'s closure
evidence would be invalidated by construction. Lowering `--threads` is a lower-stakes, git-revertible
config change (no new database-access boundary), but it still invalidates the comparability of every
prior acceptance run's numbers, gathered at eight threads — `PROH-OPS-07-10` still requires the
acceptance harness to be driven at `--concurrency 8` regardless of the deployment's own thread count.

**The `mem_limit` arithmetic constraining any future worker-count increase.** `06-10`'s hardware reports
measured the `web` service's RSS rising from ~106.8MB mean at concurrency 1 to ~128.0MB mean at
concurrency 8, for a single worker, against `docker-compose.yml`'s current `mem_limit: 256m` — already
roughly half-consumed by one worker under load. A second worker would not simply double that figure
(each worker's own RSS floor includes shared, not-strictly-per-worker cost), but it would push
measured peak RSS meaningfully closer to, and plausibly past, `mem_limit: 256m` well before eight
threads' worth of per-worker headroom is accounted for. This is exactly why `PROH-OPS-04-05` requires
`mem_limit` to be re-derived from measurement — not assumed proportional — before any `add-workers`
branch can ship.

**`06-14` finding: `mem_limit` is declared but not kernel-enforced on the Pi host, which changes what
this arithmetic is protecting against.** Round 3's `docker compose up --build` emitted, for `migrate`,
`web` and `worker`: "Your kernel does not support memory limit capabilities or the cgroup is not
mounted. Limitation discarded." The web role's round-3 peak RSS (124,928,000 B, well inside the
declared 256m) is genuine and the harness's `assert_resource_budget` still checks it against the value
parsed out of `docker-compose.yml`, so the pass/fail signal stays meaningful and comparable across
rounds. But the 256m figure above is a **declared budget the harness checks, not a ceiling the kernel
enforces on this host**: a container that exceeds it does not get OOM-killed, it gets memory pressure on
a host that has no cgroup-level backstop. The `mem_limit` arithmetic above (headroom for a second
worker) is therefore an even tighter constraint in practice than the declared numbers alone suggest —
there is no kernel-level safety net catching an over-budget worker before it degrades the whole host,
so `PROH-OPS-04-05`'s measured, not-assumed re-derivation requirement matters more, not less, once a
second worker is on the table. This is a host/kernel configuration fact, not a `docker-compose.yml`
defect — the file's declaration is correct and worth keeping even though this kernel cannot enforce it.

---

### D-DEBT-06-02 — no cgroup CPU limit is declared in docker-compose.yml

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Assumptions Log entry A4 |
| **Status** | **Decided — not adding a `cpus:` cap this phase.** Closed; revisit only if the trigger below occurs. Its trigger has now been evaluated for the first time, on `06-14`'s round-3 hardware run, and read **NOT TRIGGERED** — see below. |
| **Recorded in the plan** | `06-06-PLAN.md` Task 2, `06-10-PLAN.md` Task 1 (re-measurement attempt) |

**The decision.** `docker-compose.yml` declares `mem_limit` for every service (`worker: 1g`, `web:
256m`, `recovery`/`migrate`: `256m` each) but no `cpus:` key on any service. This phase does **not**
add one. CPU budget compliance is instead evidenced by observation: `tests/pi_load_acceptance.py`
samples and reports peak and mean CPU percent for both the worker and web processes across every
acceptance run, so the operator gets a measured number rather than an assumed ceiling.

**Rationale.** A cgroup CPU cap on the `worker` service would throttle Chromium mid-capture against
the already-bounded `PREVIEW_BROWSER_BUDGET_MS = 27_000` deadline — precisely the class of contention
OPS-01 (06-04) just finished eliminating by giving `J8` its own executor lane. Introducing a new
throttle to satisfy a documentation gap (A4 only asked that the absence be an explicit decision, not
that a cap be added) would be trading a solved problem for an unsolved one: a CPU-starved Chromium
capture failing against its own deadline is exactly the kind of contention failure this phase exists
to remove, not reintroduce.

**What would justify revisiting this.** Either of:
- An acceptance run (`tests/pi_load_acceptance.py` without `--self-test`) showing sustained CPU
  percent that starves the host — i.e., the observed evidence this decision relies on turning up a
  real problem instead of confirming none exists.
- A co-tenant workload deployed alongside Beacon on the same Pi that needs a guaranteed CPU share
  Beacon could otherwise consume unbounded.

**This round's attempt to evaluate the trigger, and why it still could not be evaluated.** `06-10`'s
real Pi acceptance run is exactly the kind of run the first trigger condition describes, and unlike the
previous round it sampled the *correct* PIDs (`06-07`'s container-derived resolution, independently
confirmed against `docker inspect` — see `D-DEBT-06-04`). But the CPU figures it produced were
`peak_cpu_percent` / `mean_cpu_percent` of exactly `0.0` for both `web` and `worker`, on both the
control and acceptance runs, under a 600s load whose own p50 latencies are in the seconds. That reading
cannot be treated as "no sustained CPU percent that starves the host" — a genuine 0.0% CPU figure under
that load is implausible on its face, so this is a broken measurement, not a confirming one (see the
new `D-DEBT-06-06`). Neither the previous round's figures (measuring another program entirely) nor this
round's (a non-functioning CPU sample) have ever actually evaluated this entry's stated trigger. The
decision above stands on its original rationale, not on any CPU measurement to date, because no usable
CPU measurement has yet existed. A reviewer with a working CPU reading — once `D-DEBT-06-06` is
resolved — should be the one to actually test the trigger for the first time.

**`06-14`'s evaluation — the trigger tested for the first time on a usable reading, verdict NOT
TRIGGERED.** `D-DEBT-06-06` is discharged this round (see the Discharged section below):
`06-11`'s fix produced a genuine, non-zero CPU reading on round 3's real hardware run. The web role's
`assertions.resources.summary.web.cpu_sampling` reads `all_samples_zero: false`,
`mean_cpu_percent: 165.504`, `peak_cpu_percent: 233.6`, `nonzero_sample_count: 594`,
`zero_sample_count: 0` — against 400% available on this 4-core Raspberry Pi 5. The worker role reads
`mean_cpu_percent: 0.698`, `peak_cpu_percent: 8.9`, `nonzero_sample_count: 309`,
`zero_sample_count: 285` — genuine idleness driven by the worker's own cadence (J1-J4 poll intervals,
not continuous work), confirmed real rather than a sampling defect because `nonzero_sample_count` is
substantial (309) and `all_samples_zero` is `false`; the 285 zero samples are the worker legitimately
idle between cadence ticks, not a broken measurement.

Reading this against the trigger: "an acceptance run showing sustained CPU percent that starves the
host." 165.504% mean is sustained CPU use above one core's worth, on a service under a 600s
concurrency-8 load — but it leaves roughly 2.3 of the Pi's 4 cores idle on average, and the worker role
barely registers at all. This is not a host being starved; it is a host with substantial spare CPU
capacity while its acceptance run is failing on latency for other reasons (see `D-DEBT-06-01`'s round-3
update and the new `D-DEBT-06-09`). **The trigger did NOT fire.** This is a real, load-bearing result —
not an absence of evidence, but a first-time confirmation, by measurement rather than mere assertion,
of this entry's original rationale: a `cpus:` cap was not needed for CPU-starvation reasons, and round
3's evidence is the first data point that actually tests that claim rather than merely repeating it.
This does not close the question forever (a future co-tenant workload could still justify revisiting,
per the second named trigger condition, unaffected by this round), but the CPU-starvation trigger
specifically has now been tested and did not hold.

Full figures: `06-ACCEPTANCE-ROUND3.md`, `beacon-acceptance-round3.json`.

**Round 4 re-read attempted, and why it could not add a new figure.** `06-18-PLAN.md` Task 1's
acceptance criteria required `mean_cpu_percent` and `peak_cpu_percent` to be recorded for both roles
on both instrumented passes (`beacon-lockdiag-c1.json`, `beacon-lockdiag-c8.json`), specifically so
this entry's trigger could be re-read against a fourth data point. `06-LOCK-DIAGNOSTIC.md` does not
transcribe those process-level CPU-sampling fields into the artifact — its own figures are all
per-request wall/CPU/lock-wait accounting from `lock_profile.requests[*]` (e.g.
`/api/advanced/current`: 536,241.0ms CPU across 880 requests, ≈609.4ms/request mean), which measures
per-request CPU time inside the Python process, not the process-level `psutil.cpu_percent()` reading
`cpu_sampling.mean_cpu_percent` reports. The two hardware JSON reports themselves are not committed
to this repository (unchanged from `D-DEBT-06-04`'s note: they exist only on the Pi host), so this
entry cannot re-derive `mean_cpu_percent` from a source available here. **This entry's trigger is
therefore re-read against round 3's figure, unchanged by round 4**: `mean_cpu_percent: 165.504` (web
role, `06-ACCEPTANCE-ROUND3.md`) remains the most recent process-level CPU reading on record, the
trigger reading stays **NOT TRIGGERED** on that basis, and a future round wanting a round-4 CPU
figure must read it directly from `beacon-lockdiag-c8.json`'s `cpu_sampling` block on the Pi host,
or have a future round commit that block into a durable artifact the way `06-ACCEPTANCE-ROUND3.md`
did for round 3.

---

### D-DEBT-06-05 — pre-existing flaky test in worker ownership fencing

| Field | Value |
|---|---|
| **Raised by** | `06-UAT.md` § "Carried-forward items for decision" |
| **Status** | **Decided — not a Phase 6 regression, not fixed this phase.** Recorded rationale below; no further action needed this phase. |
| **Recorded in the plan** | `06-UAT.md`, `06-10-PLAN.md` Task 3 |

**The decision.** `tests/test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced`
fails intermittently — measured at roughly **1 run in 20** — at a rate measured as **identical before
and after** this phase's changes. Because the failure rate does not shift across Phase 6's changes, this
is not a Phase 6 regression, and this phase does not attempt to fix it.

**Why it is recorded here rather than silently retried away.** A genuinely intermittent test inside
ownership-fencing code — the exact mechanism responsible for preventing two workers from both believing
they hold a lease — is not a candidate for a blanket retry annotation. A retry would make the symptom
disappear from CI without explaining it, and ownership-fencing correctness is precisely the kind of
property where a hidden, unexplained intermittency is worth its own dedicated investigation rather than
being masked.

**What would need to be true to proceed / close this entry.** Someone reproduces the failure locally
with enough repetition to characterize it (timing-dependent assertion, a race in the fixture's fake
clock, a real race in the fencing logic under test, etc.), determines whether the flake is in the test
harness or the production code path it exercises, and either fixes the root cause or documents precisely
why the intermittency is test-harness-only and safe to leave. Until that investigation happens, this
entry stays open with no further action assumed.

---

## 3. Discharged — closed this round

### D-DEBT-06-04 — real Raspberry Pi-class acceptance run never executed

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` § Environment Availability, `06-06-PLAN.md` Task 2's `<precondition>` and `<human-check>` |
| **Status** | **Discharged.** The real Pi acceptance run happened, across two attempts this round. Closed on `06-10`'s re-run report. |
| **Recorded in the plan** | `06-06-PLAN.md` Task 2 `<precondition>` fallback clause, `06-06-SUMMARY.md`, `06-10-PLAN.md` Task 1, `06-10-SUMMARY.md` |

**What was not done and why (as originally recorded, for context).** At the time this entry was raised,
this execution environment had no confirmed, deployed Raspberry Pi target, so only the harness's
`--self-test` smoke path could be run, and the real-hardware execution was carried forward as an open
item. That reasoning is preserved unchanged above the line — the discharge below describes what
happened afterward, in `06-10`.

**What actually happened across two attempts — and why the first attempt failing is the substantive
finding, not something to write around.** An operator deployed this gap-closure round's build to the
real Raspberry Pi target (`aarch64` / `raspi`) and ran the harness's real, non-self-test acceptance path
twice:

1. **The first real-hardware run** (the round this `D-DEBT-06-04` entry originally anticipated closing)
   found the harness itself untrustworthy: it sampled a process belonging to an unrelated application
   (`/opt/offline-portal`'s gunicorn master) instead of Beacon's own containers, and separately found
   `/api/services` costing ~2.5s per request under load — a real product defect, not a harness artifact.
   Both were exactly the class of defect this harness exists to surface. `06-07` and `06-08` were
   written to fix them. **The first run doing its job — catching two real, previously-invisible defects
   on real hardware — is what this entry actually discharges on, not a clean first pass.** Do not read
   the eventual "acceptance run executed" outcome as meaning the first run went well; it did not, and
   that failure is the reason `06-07` and `06-08` exist.
2. **This round's re-run**, against `06-07`'s and `06-08`'s fixes plus `06-09`'s code-review closures
   (commit `e46a044` and later), produced the report this entry closes on: **`beacon-acceptance.json`**
   (paired with a concurrency-1 control report, `beacon-control-c1.json`). That report shows
   `run_kind: "acceptance"` on host `aarch64` / `raspi`, confirms — independently, against the
   operator's own `docker inspect --format '{{.State.Pid}}' beacon-web beacon-worker'` — that every
   sampled PID (`1745069`/`1745146` for web, `1745076` for worker) genuinely belongs to Beacon's own
   containers with `sampled_set_changed: false`, and shows `assertions.cadence.passed: true` with J1-J4
   never `stale` across the full 600s run.

**Discharged on execution, not on a passing result.** The re-run's own `overall_passed` is **`false`**:
`/api/services` (p95 2465.9ms vs. 500ms budget), `/api/scan-status` (p95 1797.4ms vs. 500ms budget), and
`/api/advanced/current` (p95 2742.1ms vs. 2000ms budget) are all over budget under concurrency 8. This
entry discharges because the run was actually executed on real Pi-class hardware and its evidence is now
verifiably trustworthy — not because the deployment passed. Whether the deployment passing is itself
still open is tracked at the phase level (see `06-10-SUMMARY.md`), not by this entry, which was scoped
narrowly to "a real hardware run happened and its evidence can be trusted."

**Evidence attached.** `beacon-control-c1.json` (concurrency 1, 120s control pass) and
`beacon-acceptance.json` (concurrency 8, 600s acceptance pass), both from `06-10`. As of this writing
both reports exist only on the Pi host at `~/projects/rpi-dashboard/`; they are not committed to this
repository (`06-10-PLAN.md`'s `files_modified` covers only this file).

---

### D-DEBT-06-06 — acceptance harness reports 0.0 CPU percent for both roles on real hardware

| Field | Value |
|---|---|
| **Raised by** | `06-10-PLAN.md` Task 1, the real Pi acceptance run |
| **Status** | **Discharged.** `06-11`'s fix produced a genuine, non-zero, plausible CPU reading on `06-14`'s round-3 real hardware run. Closed on that run's report. |
| **Recorded in the plan** | `06-10-SUMMARY.md` (original defect), `06-11-SUMMARY.md` (fix), `06-VERIFICATION.md` (root cause), `06-14-PLAN.md` Task 1 / `06-ACCEPTANCE-ROUND3.md` (closing hardware confirmation) |

**What was found (as originally recorded, for context).** `06-07` corrected the harness's
process-resolution oracle to derive `web` and `worker` PIDs from the `beacon-web` and `beacon-worker`
containers via `docker_container_tree`, rather than host-wide command-line matching. PID resolution was
verifiably correct on the round-2 real-hardware run, yet `peak_cpu_percent` and `mean_cpu_percent` read
exactly `0.0` for both roles on both the control and acceptance runs — including the 600-second
concurrency-8 acceptance run, whose own p50 latencies were in the seconds. A deployment serving that
load cannot genuinely be spending 0.0% CPU; the figure was not a measurement of low CPU use, it was a
broken measurement.

**Root cause, as `06-VERIFICATION.md` located it.** The harness's per-tick CPU sampling constructed a
fresh `psutil.Process` object for each sampled PID on every tick. `psutil.Process.cpu_percent(interval=None)`
requires a prior call on the *same* `Process` object to have a baseline to diff the current CPU-time
counters against; called on a freshly-constructed object with no prior call, it always returns `0.0` on
that first (and, because a fresh object was built every tick, *every*) call. The process set was
correctly derived from the container each tick, but the object identity backing each PID's `cpu_percent`
baseline was discarded and rebuilt every tick, so the baseline never had a chance to accumulate.

**The fix, as `06-11` landed it.** `_live_role_processes` now holds one `psutil.Process` object per PID
for the whole run and hands the same object back on every tick (`handle_cache: "per_pid_run_lifetime"`
in the report), so `cpu_percent(interval=None)` has a genuine prior-tick baseline to diff against on
every call after the first. The process *set* is still re-derived from the container on every tick, so
a mid-run gunicorn respawn is still correctly sampled; only the per-PID `Process` object handle is
cached across ticks, not the set membership. Each role's summary now carries a `cpu_sampling` block
recording whether its CPU column is a measurement or a structural zero (`all_samples_zero`,
`nonzero_sample_count`, `zero_sample_count`, `primed_pid_count`, `handle_cache`), so a future reader
never again has to infer this from raw figures alone.

**The closing hardware confirmation — `06-14`'s round-3 run.** `06-14` Task 1's real Pi acceptance run
is the first hardware evidence to test `06-11`'s fix. Both roles' `cpu_sampling.all_samples_zero` read
`false`:
- **web:** `all_samples_zero: false`, `nonzero_sample_count: 594`, `zero_sample_count: 0`,
  `primed_pid_count: 2`, `handle_cache: "per_pid_run_lifetime"`. `mean_cpu_percent: 165.504`,
  `peak_cpu_percent: 233.6`, `mean_rss_bytes: 123,869,521`, `peak_rss_bytes: 124,928,000`,
  `sample_count: 594`.
- **worker:** `all_samples_zero: false`, `nonzero_sample_count: 309`, `zero_sample_count: 285`,
  `primed_pid_count: 1`. `mean_cpu_percent: 0.698`, `peak_cpu_percent: 8.9`,
  `mean_rss_bytes: 54,876,856`.

Both figures are plausible for their roles: the web role, serving the concurrency-8 HTTP load directly,
sustains well over one core's worth of CPU (165.504% of 400% available on this 4-core Pi 5); the worker
role, cadence-driven rather than continuously busy, shows real but modest CPU use with genuine zero
samples between cadence ticks (`nonzero_sample_count: 309` alongside `zero_sample_count: 285` — a mix
consistent with intermittent work, not a broken sampler, since `all_samples_zero` is `false` and a
substantial majority-adjacent fraction of samples are non-zero). This is the first working CPU
measurement this phase has produced (`PROH-OPS-07-07` satisfied: the column is a genuine measurement,
not rounded up to a plausible-looking number).

**Consequence for `D-DEBT-06-02`.** With a working CPU reading in hand, `D-DEBT-06-02`'s stated revisit
trigger ("an acceptance run showing sustained CPU percent that starves the host") was evaluable for the
first time this phase. See `D-DEBT-06-02` above for the full evaluation; the verdict is **NOT
TRIGGERED** — 165.504% mean leaves roughly 2.3 of 4 cores idle, which is not a host being starved.

**Evidence attached.** `beacon-control-c1-round3.json`, `beacon-acceptance-round3.json` (from `06-14`),
both recorded in full in `06-ACCEPTANCE-ROUND3.md`.
</content>
