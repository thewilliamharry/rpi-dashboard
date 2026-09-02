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

### D-DEBT-06-09 — round 3's acceptance failure is measured to be serialization, not yet attributed to a cause

| Field | Value |
|---|---|
| **Raised by** | `06-14-PLAN.md` Task 1's real hardware run, `06-ACCEPTANCE-ROUND3.md` |
| **Status** | **Deferred — awaiting a diagnostic round, chosen by the user over a third inferred fix.** New this round. |
| **Recorded in the plan** | `06-ACCEPTANCE-ROUND3.md`, `beacon-acceptance-round3.json` |

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

## 2. Decided — recorded rationale, no further action needed this phase

### D-DEBT-06-01 — narrow `_db_lock`'s scope now that WAL is in force

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Open Question 3, `PROJECT.md`'s `AR-03-01` accepted-risk note |
| **Status** | **Decided — deferred a third time, now on a third hardware run whose failure the entry's own reopening test rules out as newly implicating this lock.** Re-examined by the user in `06-10-PLAN.md` Task 2 and upheld; re-examined again in `06-13-PLAN.md` Task 1 against `06-PROFILE.md`'s attribution and upheld again; re-examined against `06-14`'s round-3 hardware run below and upheld a third time. Closed for this phase; revisit only if the condition below occurs. |
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
