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

### D-DEBT-06-06 — acceptance harness reports 0.0 CPU percent for both roles on real hardware

| Field | Value |
|---|---|
| **Raised by** | `06-10-PLAN.md` Task 1, the real Pi acceptance run |
| **Status** | **Deferred — awaiting a human decision.** New this round; not fixed here. |
| **Recorded in the plan** | `06-10-SUMMARY.md`, both attached reports (`beacon-control-c1.json`, `beacon-acceptance.json`) |

**What was found.** `06-07` corrected the harness's process-resolution oracle to derive `web` and
`worker` PIDs from the `beacon-web` and `beacon-worker` containers via `docker_container_tree`, rather
than host-wide command-line matching. On this round's real-hardware run, PID resolution is verifiably
correct: the operator's independent `docker inspect --format '{{.State.Pid}}' beacon-web beacon-worker`
returned exactly the PIDs the report sampled (`1745069` for web, `1745076` for worker), `sampled_set_changed`
is `false` for both roles on both runs, and no sampled PID traces to `/opt/offline-portal` — the unrelated
process whose figures corrupted the previous round's report. `peak_rss_bytes` / `mean_rss_bytes` are
plausible and move sensibly between the control and acceptance runs (web: ~106.8MB mean at concurrency 1
to ~128.0MB mean at concurrency 8; worker essentially flat at ~55.3–55.7MB in both), which is further
evidence the PIDs are right.

Despite that, `peak_cpu_percent` and `mean_cpu_percent` read exactly `0.0` for **both** roles on
**both** runs — including the 600-second concurrency-8 acceptance run, whose own p50 latencies are in
the seconds. A deployment serving that load cannot genuinely be spending 0.0% CPU; the figure is not a
measurement of low CPU use, it is a broken measurement. Because `assertions.resources.passed` in this
harness asserts only peak RSS against each service's `mem_limit` and carries CPU purely as unasserted
observed evidence, the acceptance run's resource check still reports `passed: true` — the harness did
not fail dishonestly here, but the CPU column it prints is not trustworthy and must not be read as
evidence of anything.

**Why this is not fixed here.** `06-10`'s scope was to re-run the acceptance harness and record what it
established, not to modify the harness. This entry exists so the defect is visible to whoever next
touches `tests/pi_load_acceptance.py`'s resource-sampling code, rather than silently reappearing as a
false "0% CPU, nothing to worry about" reading in a future report.

**Consequence for `D-DEBT-06-02`.** `D-DEBT-06-02`'s stated revisit trigger — "an acceptance run showing
sustained CPU percent that starves the host" — has now been attempted against a correctly-targeted PID
set and still could not be evaluated, because the CPU column itself does not function. This is the
second consecutive round in which that trigger could not be assessed on real evidence: first because the
PIDs were wrong, now because the CPU sampling mechanism built on the (now-correct) PIDs returns 0.0
regardless of load. See `D-DEBT-06-02` below.

**What would need to be true to proceed / close this entry.** Someone investigates why
`tests/pi_load_acceptance.py`'s CPU sampling (likely a `psutil.Process.cpu_percent()` call with no
warm-up interval, or a per-sample instantaneous read never given time to integrate between samples)
returns 0.0 under measured load, fixes the sampling method, and re-runs the acceptance harness on real
Pi hardware to confirm it now reports a plausible non-zero figure consistent with the observed latency.
Only then can `D-DEBT-06-02`'s revisit trigger be meaningfully evaluated.

---

## 2. Decided — recorded rationale, no further action needed this phase

### D-DEBT-06-01 — narrow `_db_lock`'s scope now that WAL is in force

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Open Question 3, `PROJECT.md`'s `AR-03-01` accepted-risk note |
| **Status** | **Decided — deferred again, on measured hardware evidence, now also on a measured cost attribution.** Re-examined by the user in `06-10-PLAN.md` Task 2 and upheld; re-examined again in `06-13-PLAN.md` Task 1 against `06-PROFILE.md`'s attribution and upheld again. Closed for this phase; revisit only if the condition below occurs. |
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

---

### D-DEBT-06-02 — no cgroup CPU limit is declared in docker-compose.yml

| Field | Value |
|---|---|
| **Raised by** | `06-RESEARCH.md` Assumptions Log entry A4 |
| **Status** | **Decided — not adding a `cpus:` cap this phase.** Closed; revisit only if the trigger below occurs. Its trigger has now been attempted against real hardware twice and could not be evaluated either time — see below. |
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

Neither condition has occurred (or could be checked); this is a judgment call about deployment risk, not
a fact, and a reviewer with either piece of evidence above should overrule it.

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
</content>
