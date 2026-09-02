---
phase: 06-workload-resilience-pi-acceptance
verified: 2026-09-02T19:00:25Z
status: gaps_found
score: 4/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 4/5
  gaps_closed:
    - "The acceptance harness's CPU-sampling defect (D-DEBT-06-06, recorded as ✗ STUB in the round-2 report) is genuinely fixed — tests/pi_load_acceptance.py:509 _cached_handle now returns a run-lifetime per-PID psutil.Process object verified by create_time(), primed once on insert, and _live_role_processes:567 maps every discovered process through it. Confirmed behaviourally on hardware: cpu_sampling.all_samples_zero: false, 594 non-zero web samples, 0 zero samples. The 'resource-budget compliance' clause's CPU half is measured for the first time in this phase."
    - "The round-2 gap item 'profile api_services' residual per-request cost' is discharged — 06-PROFILE.md attributes 98.653% of measured self time to named buckets and corrects the round-2 report's own prediction, which was materially incomplete (it named 44.479%, missing maintenance_coverage at 29.649%)."
    - "The round-2 gap item 'reduce that residual cost' is discharged on hardware — 06-13's request-scoped memoization and duplicate-scan removal are present and substantive in dashboard/app.py, dashboard/beacon/maintenance.py and dashboard/beacon/repositories.py, and the control pass now passes cleanly on every route with /api/services p50 down 27.6% (289.0ms → 209.355ms)."
    - "The round-2 gap item 'a third hardware acceptance run' is discharged as an activity — the run was performed on real hardware (aarch64/raspi, Pi 5 Model B, nproc 4) against b8ed60b, which this verification confirms is code-identical to HEAD (git diff --stat b8ed60b..HEAD -- dashboard/ tests/ is empty). Its result is failing, so the underlying truth does not close."
  gaps_remaining:
    - "Truth 5 / OPS-07: the Pi-class acceptance run's own overall_passed is false — three routes exceed their declared p95 budgets under representative concurrent load. The failure has changed shape from round 2: per-request cost is measurably fixed and the residual is concurrency-only."
  regressions:
    - "06-13 introduced a data-correctness regression on the essential-monitoring read path. dashboard/app.py:2821-2826's all_checks query was UNBOUNDED before 06-13 (git show 4352198 confirms the removed line: `WHERE port IN ({placeholders}) AND ts >= ? ORDER BY ts ASC`) and now carries `ORDER BY port ASC, ts ASC LIMIT _OFFLINE_INTERVALS_BULK_ROW_LIMIT` (20,000). Those rows populate checks_by_port, which feeds _uptime_summary (dashboard/app.py:2874) — so the 20,000-row cap, previously confined to the offline-interval/maintenance-attribution path, now truncates the uptime computation as well. 06-PROFILE.md §5 measured this cap as ALREADY REACHED at 8 services / 8 days (25,278 rows). Reproduced behaviourally during this verification: a service whose true uptime is 20.833% is reported by /api/services as 100.0% when the cap truncates its newest rows. The outage is silently erased in the optimistic direction. No test asserts uptime output under truncation — tests/test_services_route_scaling.py:352 exercises the truncation path but asserts only status_code == 200 and the SQL LIMIT shape."
gaps:
  - truth: "A Raspberry Pi-class representative-load run demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling"
    status: failed
    reason: "The third acceptance run was executed on real Pi-class hardware against this round's build (b8ed60b, confirmed code-identical to HEAD) and returned overall_passed: false. Three of six exercised routes exceeded their declared p95 budgets under concurrency 8 / 600s: /api/services (1732.3ms vs 500ms), /api/scan-status (656.5ms vs 500ms), /api/advanced/current (2382.2ms vs 2000ms). Cadence (OPS-01) and RSS resource budgets passed, and the CPU column is a real measurement for the first time (mean 165.504% of 400% available). The failure is now concurrency-only: the concurrency-1 control pass passes cleanly on every route. CONTRARY TO 06-DEBT.md D-DEBT-06-09, the serialization mechanism IS attributable from evidence already in this repository — see artifacts below. It is _db_lock, and the phase's own reopening test was not diagnostic."
    artifacts:
      - path: "dashboard/app.py"
        issue: "api_services holds the process-wide `_db_lock` (declared at line 127 as a bare threading.Lock) across its ENTIRE handler body: the `with _db_lock, database_access(DB_PATH) as conn:` block opens at line 2785 and the first dedent back to function level is line 2925 (`return jsonify(result)`). Every expensive computation sits inside it — _uptime_summary (2874), beacon_maintenance.coverage (2886), attributed_downtime_seconds (2893), offline_intervals_from_points_by_port (2850). By 06-PROFILE.md's own bucket table only 17.958% of that work is SQL (sql_fetch 15.620 + sql_execute 2.338); the other 82.042% is pure-Python computation executed while holding a global mutex. 5 of the 6 exercised routes take this same lock (/api/services 2785, /api/history 2539, /api/thumbnail 3093, /api/thumbnail-status 3108, /api/scan-status 3172); only /api/advanced/current does not (it calls beacon_diagnosis.get_current_diagnosis, and dashboard/beacon/diagnosis.py contains no lock of any kind — grep for _db_lock/threading.Lock returns zero hits)."
      - path: "tests/pi_load_acceptance.py"
        issue: "The load generator makes the attribution decisive rather than inferred. _routes_for_ports (line 371) builds a FIXED rotation whose index 0 is '/api/services' and whose index 1 is '/api/scan-status' — adjacent. _load_worker (line ~600) is closed-loop: `route = routes[index % len(routes)]`, one request in flight per thread, no think time. All 8 threads are started in a tight loop and begin at index 0 simultaneously. Consequence: every thread issues /api/scan-status the instant it finishes /api/services, while up to 7 sibling threads are still inside /api/services holding _db_lock. The arithmetic confirms it exactly — /api/scan-status's excess wait (242.614 − 3.281 = 239.333ms) is 1.143x one /api/services critical section (209.355ms control p50), i.e. one full holder plus ~14% GIL stretch. This also explains the 13x p50 spread AMONG lock-taking routes that D-DEBT-06-09 leaves unexplained: degradation tracks rotation distance from /api/services (scan-status idx1 +239ms; thumbnail-status idx2 +18ms; history idx3 +36ms; thumbnails idx5-12 +22ms), not each route's own cost."
      - path: ".planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md"
        issue: "D-DEBT-06-01's second reopening test is not diagnostic, so 'it did not fire' carries no information about _db_lock. The test asks whether the UNLOCKED /api/advanced/current recovers while locked routes stay over budget. But that route is an 82.281ms CPU/GIL-bound route — the most expensive non-services route in the mix — so it degrades under 8-way concurrency on a shared interpreter whether or not _db_lock is the serializer for everything else. The test can only fire if the GIL contribution is negligible, which the same run measures it is not. Two independent mechanisms were treated as mutually exclusive alternatives. Separately, D-DEBT-06-09's and 06-ACCEPTANCE-ROUND3.md's inference that mean_cpu_percent 165.504 'weakens the one-interpreter hypothesis' because it is not 'a hard pin near 100%' is unsound: a single CPython process routinely exceeds 100% while the GIL is fully saturated, because GIL-releasing C code adds CPU on top of the GIL-bound 100% — the documents name that exact mechanism (SQLite's C driver releases the GIL) and then draw the opposite conclusion from it. 100% GIL-bound Python + ~65% parallel C is a textbook-consistent reading of 165.504%."
    missing:
      - "Instrument _db_lock directly under the concurrency-8 load and report, per route and per request: time spent WAITING to acquire the lock versus time spent HOLDING it. This is the single measurement that converts the attribution above from strong inference to direct evidence. Prediction to falsify: /api/scan-status will show ~0ms hold and ~240ms median wait; /api/services will show ~200-500ms hold and a wait that grows with the number of siblings queued ahead of it. A wrapper recording monotonic timestamps around the acquire in a contextmanager replacing the bare `with _db_lock` is sufficient — no fix, no topology change."
      - "Measure lock utilisation (fraction of wall time _db_lock is held by anyone) over the acceptance window, and attribute it by route. The control-pass figures already imply /api/services alone accounts for >=35% (1020 completions x 209ms / 600s) BEFORE any load-induced stretch of its 82%-Python critical section; confirm whether utilisation under load crosses the ~0.85 threshold where M/G/1 queueing delay goes superlinear. This determines whether the fix is narrowing the lock's scope or reducing the critical section, and by how much."
      - "Separate the GIL contribution from the lock contribution by measuring them independently rather than inferring one from the other's absence. For the GIL: sample per-thread state (or run under a GIL-contention profiler) to get gil-wait time for /api/advanced/current, the one route that takes no lock. Do NOT reuse D-DEBT-06-01's reopening test — this verification finds it non-diagnostic, and the round should record that finding rather than run it a third time. Note the decisive bound already available: an 8-thread interpreter can stretch a CPU-bound route at most ~8x, but /api/scan-status degraded 74x, so the GIL provably cannot be that route's dominant mechanism."
      - "Measure how much of /api/services' critical section is actually database work needing the lock's protection. 06-PROFILE.md already puts it at 17.958% on a laptop; confirm the split on the Pi under load. This sizes the payoff of the obvious candidate fix — releasing _db_lock after the reads and performing the uptime sweep, maintenance coverage and offline-interval reconstruction outside it — without committing to that fix this round."
      - "Re-run the acceptance harness on real Pi-class hardware only AFTER a fix chosen against the diagnostic measurements above. PROH-OPS-07-01 forbids tuning budgets (verified intact this round: ROUTE_BUDGETS_MS at tests/pi_load_acceptance.py:102 is unchanged since 06-07 and its values match those the report cites) and PROH-OPS-07-02 forbids treating anything but a genuine hardware run as OPS-07 evidence."
  - truth: "Beacon keeps essential monitoring reliable (phase goal clause) — /api/services reports correct uptime for every monitored service"
    status: failed
    reason: "Regression introduced by 06-13 this round. The all_checks query in api_services was unbounded before 06-13 and now carries LIMIT 20000 with ORDER BY port ASC; its rows feed _uptime_summary. 06-PROFILE.md §5 measured the cap as already reached at 8 services / 8 days. Reproduced behaviourally during this verification: with the cap truncating a port's newest rows, /api/services reports uptime_pct 100.0 for a service whose true uptime is 20.833 — a real outage silently erased, in the optimistic direction, on the primary monitoring surface. This does not falsify any single ROADMAP success criterion as literally worded (SC1 is about sampling cadence, and sampling/storage are unaffected) which is why the score stays 4/5, but it is a direct hit on the phase goal's own 'keeps essential monitoring reliable' clause and it was introduced, not inherited."
    artifacts:
      - path: "dashboard/app.py"
        issue: "Lines 2821-2826: `SELECT ts, port, online FROM service_checks WHERE port IN (...) AND ts >= ? ORDER BY port ASC, ts ASC LIMIT ?` bound to beacon_repositories._OFFLINE_INTERVALS_BULK_ROW_LIMIT. Line 2828-2829 populates checks_by_port from this result; line 2874 passes it to _uptime_summary. The in-code comment justifies the LIMIT solely as preserving the offline-interval read's bound and does not acknowledge that it now also gates the uptime sweep. The comment's claim that at-limit behaviour costs 'only the highest-numbered port(s) their newest in-window rows' also understates it: a port entirely past the cutoff receives zero rows."
      - path: "tests/test_services_route_scaling.py"
        issue: "test_the_route_bounds_checks_by_port_rows_through_the_limit_constant (line 352) patches the limit to 5 against 20 inserted rows — it actively exercises the truncation path — but asserts only response.status_code == 200 and that the SQL carries 'LIMIT 5'. Nothing asserts what uptime_pct, uptime_buckets or availability become when rows are dropped, so the regression is invisible to the suite. This is why the full suite is green at 854/561 with the defect present."
      - path: "dashboard/beacon/repositories.py"
        issue: "_OFFLINE_INTERVALS_BULK_ROW_LIMIT = 20000 (line 1105) is now load-bearing for two different concerns with different correctness requirements — a memory/DoS bound on an offline-interval read, and (newly, via app.py) the completeness of the uptime computation. 06-13-SUMMARY.md explicitly declined to file a discrete debt entry for the row-cap finding ('No separate Deferred-section entry was added'), so 06-DEBT.md carries no D-DEBT row for it; it survives only as prose inside D-DEBT-06-01 and 06-PROFILE.md §6."
    missing:
      - "A decision on whether /api/services' uptime computation may be truncated at all. If not, the uptime sweep needs its rows unbounded (or bounded per-port rather than globally) while the offline-interval reconstruction keeps its own cap — the two consumers have different correctness requirements and should not share one bound."
      - "A test that asserts /api/services' uptime OUTPUT under truncation, not merely that a LIMIT clause is present. The existing bound test already sets up the exact conditions; it needs output assertions added. The reproduction used by this verification (two ports, the higher-numbered one offline for its newest half, limit patched to truncate mid-dataset, compare uptime_pct against the untruncated run) is sufficient and takes under a second."
      - "A discrete debt entry for the pre-existing _OFFLINE_INTERVALS_BULK_ROW_LIMIT finding in read_service_offline_intervals_by_port (the maintenance_attributed_seconds truncation), which this verification agrees is separable from Phase 6 but which currently has no ID of its own in 06-DEBT.md and can therefore be lost."
deferred: []
human_verification: []

---

> ## Orchestrator addendum — 2026-09-02, after this report was written
>
> **Not a verifier finding.** Recorded by the orchestrator so a later reader (and the round-4 planner)
> does not re-plan work that has already landed. The report above is preserved verbatim.
>
> **The second failed truth in this report — the `/api/services` uptime regression — is CLOSED.**
> Fixed in `bcad398`. The `all_checks` query is unbounded again; the 20,000-row cap now applies in
> Python, after the `ts <= now` filter, replicating exactly what
> `read_service_offline_intervals_by_port`'s own `LIMIT` shed, so it reaches only the
> offline-interval reconstruction and never `_uptime_summary`. 06-13's dedup and its measured 27.6%
> control-pass improvement are retained. The defective guard this report names
> (`test_the_route_bounds_checks_by_port_rows_through_the_limit_constant`, which asserted SQL shape
> and a `200`) is **inverted** to assert the uptime read carries no `LIMIT`, and a new
> mutation-verified test pins the uptime *value* across a lowered cap — it fails `90.0 != 100.0`
> against the pre-fix code. Root cause and the planning lesson are recorded as `D-DEBT-06-10`.
>
> **Two further findings from `06-REVIEW-ROUND3.md` are also fixed** (`631381f`), both
> mutation-verified: CR-02 (`_window_from_row_cached` keyed on `id(row)` without pinning the
> referent — reproduced returning the wrong `Window` at iteration 1 of 2000) and CR-03 (`--self-test`
> skipped CPU priming and reported `primed_pid_count: 0`, the exact signature 06-11 added to flag a
> broken CPU column).
>
> **This report's attribution of the serialization to `_db_lock` is accepted.** Every link was
> re-verified independently against source, and `D-DEBT-06-09` has been updated from "measured but
> not attributed" to carry the attribution, the arithmetic, and the withdrawal of the two inferences
> this report identifies as unsound. Round 4 is therefore scoped to **confirm or refute a named
> mechanism**, not to search an open field.
>
> **Still open, and the whole of round 4's scope:** the five `missing:` items under Truth 5 above.
> Suite at the time of this addendum: **859 passed, 561 subtests, 0 failed**.


---

# Phase 6: Workload Resilience & Pi Acceptance Verification Report

**Phase Goal:** Beacon keeps essential monitoring reliable while discovery and previews operate as bounded, recoverable best-effort work on Raspberry Pi-class hardware.

**Verified:** 2026-09-02T19:00:25Z
**Status:** gaps_found
**Re-verification:** Yes — third round, after gap-closure plans `06-11`–`06-14`. Supersedes the round-2 report (`gaps_found`, 4/5).

## Goal Achievement

### Observable Truths

| # | Truth (ROADMAP Success Criterion) | Status | Evidence |
|---|------|--------|----------|
| 1 | Metric sampling and service checks remain within their accepted cadence while discovery, previews, cleanup, and analytics queries are active | ✓ VERIFIED | No regression. `dashboard/beacon/worker_main.py`'s `'metrics'`/`'cleanup'` lane split still present; `tests/test_workload_resilience.py:522 CadenceUnderContentionTests` present and passing in this verification's own full-suite run. Now backed by a **third** hardware run: `assertions.cadence.passed: true`, `failures: []`, J1–J4 never stale, on both round-3 passes. Cadence has now held on every hardware run this phase has produced, including the one whose latency assertions failed — which is the stronger result, since it shows essential sampling survives the very contention that breaks responsiveness. |
| 2 | Preview work has one serialized browser owner, bounded deadlines and retries, and a visible non-fatal degraded state instead of blocking core monitoring | ✓ VERIFIED | No regression. `queues.py` retry/backoff and the degraded badge unchanged. WR-02's `has_thumb`-before-`preview_status` precedence fix survives `06-13`'s edits to the same file — now at `dashboard/app.py:3149` (shifted from 3100-3116 by `06-13`'s additions above it), with the precedence rationale intact at 3132-3140. `tests/test_api_and_auth.py:316 test_thumb_state_precedence_across_the_four_has_thumb_and_preview_status_combinations` present and passing. |
| 3 | Thumbnail data expires within a bounded managed store and no longer puts large preview blobs on Beacon's primary telemetry path | ✓ VERIFIED | No regression. Migration 10 and `ThumbnailStoreRepository` (`dashboard/beacon/repositories.py:709`) untouched this round; TTL/budget reap intact; passing in the full-suite run. |
| 4 | Beacon recovers predictably from restarts, concurrent web/worker database activity, and failed background jobs, as proven by automated runtime and persistence coverage | ✓ VERIFIED | No regression. WAL, `tests/test_workload_resilience.py:747 ConcurrentAccessTests` and `tests/test_migrations.py:1425 InventoryTests` all present and passing. WR-01's third `mode=ro&immutable=1` fallback still present (`dashboard/beacon/inventory.py:128`). `_db_lock`'s scope is unchanged this round — `06-13` and `06-14` touched no line of it, so `T-06-24`'s closure evidence in `06-SECURITY.md` remains valid. (Note: this truth is about *correctness* under concurrency, which holds. The same lock's *performance* consequence is Truth 5's finding — they are not in conflict; `_db_lock` is doing its job correctly and expensively.) |
| 5 | A Raspberry Pi-class representative-load run demonstrates responsive interaction, resource-budget compliance, recovery, and uninterrupted essential sampling | ✗ FAILED | `overall_passed: false` on real hardware (`aarch64`/`raspi`, Pi 5 Model B, `nproc` 4) against `b8ed60b`, which this verification independently confirmed is code-identical to `HEAD` (`git diff --stat b8ed60b..HEAD -- dashboard/ tests/` → empty; the four commits since are documentation only). Three routes over budget under concurrency 8 / 600s. **The failure has changed shape and is materially narrower than round 2's** — see below. |

**Score:** 4/5 truths verified; 1 failed (measured, not untested). 0 present-but-behavior-unverified. The score does not capture the newly-introduced uptime-truncation regression, which sits under the phase goal's "keeps essential monitoring reliable" clause rather than under any single success criterion's literal wording; it is recorded as a second gap and as a `regressions:` entry.

### Truth 5, characterised precisely

**Agreed: per-request cost is fixed; what remains is concurrency-only.** The evidence supports this without reservation. The concurrency-1 control pass returns `overall_passed: true` with every route inside budget and comfortable headroom (`/api/services` 227.4ms p95 against a 500ms budget). `/api/services`' control p50 fell 27.6% (289.0 → 209.355ms), and `06-13`'s two named fixes are present and substantive in the code, not just claimed. Round-2 → round-3 p95 improved on all three failing routes (−29.7%, −63.5%, −13.1%). Nothing in the acceptance failure is reachable at concurrency 1.

**Not agreed: that the remaining failure is unattributable.** `D-DEBT-06-09` records it as "measured to be serialization but not yet attributed," and the next round was scoped as diagnostic on that basis. This verification finds the mechanism **is** attributable from evidence already in the repository, and names it: **`_db_lock`**.

The chain, each link independently verified above and in the tables below:

1. `_db_lock` is a single process-wide `threading.Lock` (`dashboard/app.py:127`) taken by **5 of the 6** exercised routes. Only `/api/advanced/current` is exempt.
2. `/api/services` holds it across its **entire handler body** (lines 2785–2924; first dedent at 2925). Per `06-PROFILE.md`'s own bucket table, **82.042%** of that work is non-SQL Python — the uptime sweep, maintenance coverage, and offline-interval reconstruction all execute under a global mutex.
3. The harness's rotation places `/api/scan-status` **immediately after** `/api/services` (`tests/pi_load_acceptance.py:371`), and `_load_worker` is closed-loop with all 8 threads started simultaneously at index 0. Every thread therefore requests `scan-status` the instant it leaves `/api/services`, while siblings are still inside holding the lock.
4. The arithmetic closes it: `/api/scan-status`'s excess wait is **239.333ms**, which is **1.143×** one `/api/services` critical section (209.355ms) — one full holder plus ~14% GIL stretch. A 3.281ms route whose latency equals one holder's service time is the textbook signature of a shared mutex, not of computation.
5. It also explains what `D-DEBT-06-09` leaves unexplained — the **13× p50 spread among routes that all take the same lock**. Degradation tracks rotation distance from `/api/services`, not route cost: scan-status (idx 1) +239ms, thumbnail-status (idx 2) +18ms, history (idx 3) +36ms, thumbnails (idx 5–12) +22ms.
6. And it survives the obvious falsification: an 8-thread interpreter can stretch a CPU-bound route by at most ~8×, but `/api/scan-status` degraded **74×**. The GIL provably cannot be that route's dominant mechanism; a lock can.

**Why the phase concluded otherwise.** `D-DEBT-06-01`'s second reopening test is not diagnostic. It uses `/api/advanced/current`'s recovery as the discriminator for `_db_lock` — but that route is the most expensive non-`/api/services` route in the mix (82.281ms control p50) and takes no lock, so it degrades from GIL/CPU contention regardless of the lock's state. The test can only fire if the GIL contribution is negligible, which the same run measures it is not. Two independent, co-existing mechanisms were treated as mutually exclusive alternatives, so "the test did not fire" was read as evidence for `_db_lock`'s innocence when it carries no information either way. `_db_lock` and the GIL are not competing hypotheses — they **compose**: the GIL stretches the 82%-Python critical section, and the lock then serializes every other route behind the stretched section.

**A second inference to correct.** `06-ACCEPTANCE-ROUND3.md` and `D-DEBT-06-09` both argue that `mean_cpu_percent` 165.504 "weakens the one-interpreter hypothesis" because it is not "a hard pin near 100%." This is unsound. A single CPython process routinely exceeds 100% while the GIL is fully saturated, because GIL-releasing C extension code runs concurrently on top of the GIL-bound 100% — and both documents name that exact mechanism ("SQLite's C code releases the GIL") one sentence before drawing the opposite conclusion from it. 100% GIL-bound Python plus ~65% parallel C is a fully consistent reading of 165.504%. Likewise, "roughly 2.3 of 4 cores idle" is not neutral evidence about *which* serializer is responsible — idle capacity alongside high latency is the generic symptom of serialization, and is equally predicted by a mutex, by the GIL, or by both.

**What this changes.** The diagnostic round remains the right call — the attribution above is strong inference from aggregate figures plus code structure, and it should be confirmed by direct lock-wait/lock-hold instrumentation rather than adopted on argument (this phase has now twice adopted an unconfirmed single-cause hypothesis). But the round should be scoped to *confirm or refute a specific named mechanism* with a falsifiable prediction, not to search an open field. `gaps[].missing` above is written to that shape.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `tests/pi_load_acceptance.py` (CPU sampling) | Working per-PID handle cache replacing the round-2 structural `0.0` | ✓ VERIFIED (was ✗ STUB) | `_cached_handle` (line 509) returns the cached `psutil.Process` when `create_time()` confirms identity, replaces and primes on PID recycle, and `_live_role_processes` (line 567) maps every discovered process through it. Confirmed **behaviourally on hardware**: `all_samples_zero: false`, 594 non-zero web samples, 0 zero samples, `handle_cache: "per_pid_run_lifetime"`. |
| `tests/pi_load_acceptance.py` (`cpu_sampling` provenance) | Reader-facing block stating whether the CPU column is trustworthy | ✓ VERIFIED | Lines 807-836 emit `handle_cache`, `primed_pid_count`, `nonzero_sample_count`, `all_samples_zero`. Correctly excluded from `failure_reasons` per `PROH-OPS-07-01`. |
| `tests/pi_load_acceptance.py` (`ROUTE_BUDGETS_MS`) | Unchanged — no budget tuning | ✓ VERIFIED | Line 102. Values (`/api/services` 500, `/api/scan-status` 500, `/api/advanced/current` 2000) match those the failure report cites. `git log -L` shows last touched in `06-07`; `git diff 32781e5..HEAD` shows no budget lines changed. **`PROH-OPS-07-01` intact.** |
| `dashboard/beacon/maintenance.py` | Request-scoped memo for the occurrence walk | ✓ VERIFIED | `_window_from_row_cached` (132), `_local_occurrence_epochs(..., cache=None)` (174), `coverage(..., *, cache=None)` (255), `_covering_boundaries` (501), `attributed_downtime_seconds` (552). Keyword-only, defaults `None`, so every non-opted-in caller is byte-identical by construction. |
| `dashboard/app.py` (duplicate scan removal) | Offline intervals reconstructed from already-fetched rows | ✓ VERIFIED | `read_service_offline_interval_boundaries_by_port` (2847, strictly-before-`start_ts`, genuinely non-duplicative) + `offline_intervals_from_points_by_port` (2850) replace the second full-window read. Memo threaded at 2887/2894. |
| `dashboard/app.py` (row bound) | Bound preserved via the named constant | ⚠️ VERIFIED BUT HARMFUL | The bound is correctly wired to `beacon_repositories._OFFLINE_INTERVALS_BULK_ROW_LIMIT` (2825), not a drifting literal — the stated requirement is met. But applying it to `all_checks`, which was previously unbounded, extends truncation onto the uptime path. See Anti-Patterns. |
| `tests/test_services_route_scaling.py` (cost guard) | Guard against regression toward the unmemoized cost | ✓ VERIFIED | `test_maintenance_coverage_cost_is_no_longer_dominated_by_unmemoized_occurrence_walks` (752). Thresholds `small < 100.0ms` / `large < 400.0ms` sit ~3× above shipped (≈30/133ms) and ~3× below unmemoized (276.2/1322.4ms) — real mid-band placement. Mutation-verified by the executor (disabling both `cache=` call sites and re-measuring). See the deviation judgment below. |
| `tests/test_module_boundaries.py` (topology pin) | Source-level pin on `--workers 1 --threads 8` | ✓ VERIFIED | `test_the_deployment_pins_its_gunicorn_concurrency_model` present; executor reports mutation-verification in both directions. |
| `06-PROFILE.md` | Cost attribution driving the fix decision | ✓ VERIFIED | `attributed_pct` 98.653 at the real 8-service/8-day shape; `check_row_ratio` 4.249 measured (not assumed); host difference and non-transferability of absolute ms disclaimed explicitly per `PROH-OPS-07-09`. Notably corrects the round-2 report's own prediction as materially incomplete — a self-critical finding the phase surfaced against itself. |
| `06-ACCEPTANCE-ROUND3.md` | Durable record of the third run | ✓ VERIFIED | Both passes, degradation factors, cadence, resources, `cpu_sampling`, `scenario`, and the `mem_limit`-not-kernel-enforced finding all recorded. Records the failure plainly rather than writing around it. |
| `06-DEBT.md` | Round-3 dispositions | ⚠️ VERIFIED WITH RESERVATION | Structure and dispositions are present and honest (06-06 discharged, 06-02 evaluated, 06-08/06-09 added). Two inferences inside `D-DEBT-06-01`/`D-DEBT-06-09` do not survive scrutiny (the non-diagnostic reopening test; the 165.504% GIL reading) — see Truth 5. Additionally, the `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` finding has **no `D-DEBT` ID of its own**, by `06-13`'s explicit choice. |
| `.planning/REQUIREMENTS.md` | OPS-07 unchanged and Pending | ✓ VERIFIED | Line 72 `- [ ] **OPS-07**` unchecked; line 155 `| OPS-07 | Phase 6 | Pending |`. `git diff --quiet` holds. **`PROH-OPS-07-08` intact.** |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| Pi build `b8ed60b` | working tree `HEAD` (`b13afea`) | code identity | ✓ WIRED | `git diff --stat b8ed60b..HEAD -- dashboard/ tests/` is empty. The four intervening commits are documentation only. The hardware result therefore applies to the code under verification — this is what makes it authoritative rather than stale. |
| `dashboard/app.py` `api_services` | `beacon_maintenance.coverage` / `attributed_downtime_seconds` | `cache=maintenance_occurrence_cache` | ✓ WIRED | Lines 2887, 2894. One dict created per request, shared across every service's calls. |
| `dashboard/app.py` `api_services` | `beacon_repositories.offline_intervals_from_points_by_port` | reconstruction from `points_by_port` | ✓ WIRED | Line 2850; boundary query at 2847 reads strictly before `start_ts`, so it is genuinely non-duplicative. |
| `dashboard/app.py` `all_checks` LIMIT | `beacon_repositories._OFFLINE_INTERVALS_BULK_ROW_LIMIT` | live constant reference | ✓ WIRED | Line 2825 — the same named constant, not a copied literal. Correctly wired; the problem is the consumer set, not the wiring. |
| `dashboard/app.py` `all_checks` | `_uptime_summary` | `checks_by_port` | 🛑 WIRED, NEWLY TRUNCATED | 2828-2829 → 2874. This link is why the LIMIT is a correctness change, not only a bound. Previously unbounded on this path. |
| `tests/pi_load_acceptance.py` `_live_role_processes` | `_cached_handle` | per-tick mapping | ✓ WIRED | Line 567. Hardware run confirms the cache is effective (`nonzero_sample_count: 594`, `zero_sample_count: 0`). |
| `/api/advanced/current` | `_db_lock` | (absence) | ✓ CONFIRMED ABSENT | `dashboard/app.py:2491-2512` calls `beacon_diagnosis.get_current_diagnosis`; `dashboard/beacon/diagnosis.py` contains zero `_db_lock`/`threading.Lock` references. The phase's claim is correct — but load-bearing in a way that does not support the conclusion drawn from it. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `/api/services` | `uptime_pct`, `uptime_buckets`, `availability` | `checks_by_port` ← `all_checks` (`LIMIT 20000`) | **No** above 20,000 in-window rows | 🛑 TRUNCATED — reproduced: true 20.833% reported as 100.0% |
| `/api/services` | `maintenance_attributed_seconds` | `offline_intervals_by_port` ← same bounded `all_checks` | Partial at scale (pre-existing concern, same cap) | ⚠️ STATIC-AT-LIMIT |
| `/api/services` | `preview_status`, `has_thumb`, `tls_unverified` | live `conn.execute` reads | Yes | ✓ FLOWING |
| acceptance report | `cpu_sampling.mean_cpu_percent` | `_cached_handle` → `psutil.cpu_percent(interval=None)` | Yes — first time this phase | ✓ FLOWING (was ✗ DISCONNECTED) |
| acceptance report | `assertions.resources` RSS | `proc.memory_info().rss` summed over live PIDs | Yes | ✓ FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full suite green, re-run once independently on a quiet tree | `time uv run --project dashboard python -m pytest -q` | `854 passed, 561 subtests passed in 255.05s (0:04:15)`, exit 0 | ✓ PASS — matches the stated 854/561/0 baseline exactly |
| Pi build matches verified code | `git diff --stat b8ed60b..HEAD -- dashboard/ tests/` | empty | ✓ PASS |
| Route budgets not tuned | `sed -n '102,110p' tests/pi_load_acceptance.py` + `git log -L102,115` | values match the report; last touched `06-07` | ✓ PASS (`PROH-OPS-07-01`) |
| `_db_lock` spans the whole `api_services` body | dedent scan of `dashboard/app.py:2785-2925` | no line returns to function indent until 2925; `_uptime_summary`/`coverage`/`attributed_downtime_seconds` all inside | ✓ CONFIRMED |
| `/api/advanced/current` takes no lock | `grep -n "_db_lock\|threading.Lock" dashboard/beacon/diagnosis.py` | zero hits | ✓ CONFIRMED |
| Harness rotation adjacency | `sed -n '371,384p' tests/pi_load_acceptance.py` | idx 0 `/api/services`, idx 1 `/api/scan-status` | ✓ CONFIRMED — the attribution's keystone |
| GIL cannot explain 74× | arithmetic: max 8-thread stretch = 8×; observed 74× | 242.614 / 3.281 = 73.9× ≫ 8× | ✓ CONFIRMED |
| Lock-wait arithmetic | `(242.614 − 3.281) / 209.355` | **1.143** — one critical section + ~14% | ✓ CONFIRMED |
| **Uptime truncation reproduction** | throwaway harness: 2 ports × 60 checks, higher port offline for its newest half, limit patched to truncate | untruncated `{9002: 20.833%}` vs truncated `{9002: 100.0%}` — **DIFFERS: True** | 🛑 **FAIL — regression reproduced** |

### Probe Execution

| Probe | Command | Result | Status |
|-------|---------|--------|--------|
| Real Pi-class acceptance run (`tests/pi_load_acceptance.py`, non-self-test) | Performed by the operator on real hardware; not re-executable from this environment (no Pi access). Treated as measured authoritative evidence, not routed to `human_needed`. | Control (c1, 120s): `overall_passed: true`. Acceptance (c8, 600s): `overall_passed: false`, 3 routes over budget | FAILED (authoritative) |
| Full regression suite | `uv run --project dashboard python -m pytest -q` | 854 passed, 561 subtests, 0 failed | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| OPS-01 | 06-04, 06-07, 06-08, 06-10, 06-14 | Cadence holds under contention | ✓ SATISFIED | Held on all three hardware runs including the failing one; `REQUIREMENTS.md` reads Complete |
| OPS-02 | 06-03, 06-09 | Bounded preview retry, degraded state | ✓ SATISFIED | WR-02 fix survives `06-13`'s edits to the same file; Complete |
| OPS-03 | 06-01, 06-02 | Bounded thumbnail store off primary telemetry path | ✓ SATISFIED | Untouched this round; Complete |
| OPS-04 | 06-05, 06-09, 06-10 | Restart/concurrency/failed-job automated coverage | ✓ SATISFIED | `_db_lock` unchanged, so `T-06-24`'s closure holds; Complete |
| OPS-07 | 06-06, 06-07, 06-08, 06-10, 06-11, 06-13, 06-14 | Pi-class acceptance run | ✗ BLOCKED | Run performed three times; round-3 `overall_passed: false`. **Correctly recorded as Pending.** |

No orphaned requirements — all 5 phase requirement IDs appear in plan frontmatter and in `REQUIREMENTS.md`'s Phase 6 mapping.

**OPS-07 disposition — agreed, and correctly recorded.** `REQUIREMENTS.md` line 72 is unchecked and line 155 reads Pending; `git diff --quiet -- .planning/REQUIREMENTS.md` holds across `06-14`. Three independent reasons converge, and it is worth separating them because they are often conflated:

1. **Dispositive:** the run failed. `overall_passed: false` means OPS-07 is not satisfied on the merits, so no promotion question arises at all.
2. **Procedural (`D-DEBT-06-08`, `PROH-OPS-07-08`):** a gap-closure round may not promote its own requirement. The `TEL-06`/`03-17` precedent in `STATE.md` is correctly cited and correctly applied. I am the independent round that precedent names, and I confirm the disposition is right — but I am confirming a *Pending* status, not withholding a promotion I would otherwise grant.
3. **Not yet reached:** even had the run passed, the CPU column had never been a real measurement before this round, so the "resource-budget compliance" clause would have had only one round of trustworthy evidence behind it.

`D-DEBT-06-08` states point 2 clearly and explicitly notes that promotion "is not yet even a live question." That is accurate and well-scoped. Recorded correctly.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `dashboard/app.py` | 2821-2826 → 2874 | A previously-unbounded query gains a `LIMIT` whose rows feed a second, unrelated consumer (`_uptime_summary`), silently truncating a user-facing correctness value | 🛑 **Blocker** | At a scale the phase itself measured as already reached (8 services / 8 days), a service that was offline for most of the window is reported at 100% uptime. Reproduced behaviourally during this verification. Directly contradicts the phase goal's "keeps essential monitoring reliable" clause. |
| `tests/test_services_route_scaling.py` | 352-421 | A test that sets up a failure condition and asserts only structure (`status_code == 200`, SQL shape), never output | ⚠️ Warning | This is precisely why 854/561 is green with the blocker above present. The test exercises truncation and looks away from its effect. |
| `dashboard/app.py` | 2785-2924 | A global mutex held across ~82% non-database Python computation | ⚠️ Warning (correctness is fine; this is the performance mechanism) | The identified root cause of Truth 5's failure. Not a defect in `_db_lock` itself — it is doing exactly what it was added to do — but its *scope* makes `/api/services` a ~200ms global serialization point at concurrency 1 and worse under load. |
| `06-DEBT.md` | `D-DEBT-06-01`, `D-DEBT-06-09` | A non-diagnostic test reported as exculpatory evidence; a CPU reading interpreted against the mechanism the same paragraph names | ⚠️ Warning | Led the phase to record the failure as unattributable and to scope the next round as an open search rather than a targeted confirmation. |
| `06-DEBT.md` | (absent) | A named correctness-adjacent finding with no debt ID | ⚠️ Warning | `06-13-SUMMARY.md` explicitly declined to file the `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` finding as its own entry. It now survives only as prose inside another entry, and its blast radius has since grown. |

No `TBD`/`FIXME`/`XXX` debt markers in any file modified by this round's plans (`dashboard/app.py`, `dashboard/beacon/maintenance.py`, `dashboard/beacon/repositories.py`, `tests/pi_load_acceptance.py`, `tests/test_services_route_scaling.py`, `tests/test_module_boundaries.py`, `tests/test_workload_resilience.py`). No stub patterns in this round's new code — the round-2 report's one stub (`tests/pi_load_acceptance.py`'s CPU sampling) is genuinely fixed.

### The `06-13` deviation — judged legitimate

The plan asked the `maintenance_coverage` cost guard to assert `growth_ratio < half the measured check_row_ratio` (the profiler's `not_proportional_to_check_count` classification). The guard instead asserts absolute cost reduction. **This is a legitimate deviation, not a quietly weakened criterion**, on four grounds:

1. **The plan's criterion was mathematically unreachable by the chosen mechanism.** If cost = `call_count(days) × cost_per_call` and memoization reduces only `cost_per_call` by a factor `k`, the ratio `cost(8d)/cost(2d)` is `call_count(8d)/call_count(2d)` — with `k` cancelling exactly. Memoization alone provably cannot move the growth ratio. The measured drop that did occur (7.564 → ≈5.96–6.06) comes from differing cache hit rates between shapes, not from the mechanism the criterion was testing. The plan specified a criterion its own prescribed intervention could not satisfy; that is a planning error, and the executor was right to surface it rather than contort the fix toward an unreachable bar.
2. **The replacement still guards the shipped change.** Disabling the memoization returns `maintenance_coverage` to 276.2/1322.4ms, well above the 100/400ms thresholds — so the guard trips. The executor mutation-verified exactly this by removing both `cache=` call sites, re-measuring, and restoring. That is the right evidence and it is the evidence a non-tautological guard requires.
3. **The thresholds are honestly placed.** ~3× above shipped and ~3× below unmemoized is a genuine mid-band, not a bar set just under the current number.
4. **It was documented in three places** (guard docstring, `06-13-SUMMARY.md` Deviations, `D-DEBT-06-01`'s "Honest limit"), each carrying both measured baselines. Nothing was hidden.

**One reservation, recorded rather than held against it:** the replacement is an absolute-millisecond assertion and therefore host-dependent, where the original was a ratio and host-independent. It could pass on a fast machine while the behaviour regressed on a Pi. Given the original was unattainable, this is the better of the two available options — but it is a strictly less portable guard, and a future round could strengthen it by asserting the *ratio between memo-enabled and memo-disabled runs of the same shape*, which would restore host-independence while remaining reachable.

### The `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` finding — split verdict

The question posed was whether the row-cap finding belongs in this phase's gap set or is separable. It is **both**, because it is two different findings that `06-13` merged:

- **The pre-existing half is separable.** `read_service_offline_intervals_by_port`'s cap truncates `maintenance_attributed_seconds` — a Phase-3.1 maintenance-attribution value, not essential monitoring. It predates Phase 6, needs its own fleet-scale sizing decision, and does not bear on OPS-07's latency clause. Filing as debt was the right call. **One correction, though:** it was *not* actually filed. `06-13-SUMMARY.md` explicitly declined to add a Deferred entry ("No separate Deferred-section entry was added to avoid duplicating the same finding"), so `06-DEBT.md` carries no `D-DEBT` ID for it. A finding recorded only as prose inside another entry is one an auditor can lose. It should get an ID.
- **The half `06-13` created is not separable.** Applying that same cap to `all_checks` — previously unbounded — extended truncation onto `_uptime_summary`, the primary monitoring surface. That is a regression introduced this round, at a scale the phase's own profiling documented as already reached, with a user-visible failure mode that is optimistic rather than fail-safe (100% shown for a 20.833% service), and with no test coverage of the consequence. It belongs in this phase's gap set and is recorded there.

### Human Verification Required

None. The hardware run is measured, authoritative evidence and is treated as such rather than routed to human verification. Every finding in this report was verified programmatically or reproduced behaviourally in this environment.

## Gaps Summary

Four of five success criteria hold, with no regressions against any of them. Truth 1 is now the strongest it has been — cadence held on all three hardware runs, including the one whose latency assertions failed, which is a better result than a clean run would have been: essential sampling demonstrably survives the exact contention that breaks responsiveness. The suite is green at **854 passed, 561 subtests, 0 failed**, re-run once independently here, matching the stated baseline exactly.

**Truth 5 remains failed, but the failure is much narrower than round 2's and is now, in this verification's assessment, attributable.** `06-13` did what it set out to do: the concurrency-1 control pass is clean on every route, and per-request cost is no longer the binding constraint. What remains appears only under concurrency. The phase recorded that residual as "serialization, mechanism unattributed" and scoped the next round as an open diagnostic search. This verification finds the mechanism identifiable from evidence already committed: `/api/services` holds the process-wide `_db_lock` across its entire handler, 82% of which is non-SQL Python; five of six exercised routes take that same lock; the harness's rotation puts `/api/scan-status` immediately after `/api/services` in a closed loop with all eight threads starting in lockstep; and `/api/scan-status`'s excess wait is 1.143× exactly one `/api/services` critical section. The GIL cannot be the dominant mechanism for that route — eight threads cap the possible stretch at ~8×, and 74× was observed. The phase reached the opposite conclusion because `D-DEBT-06-01`'s reopening test is not diagnostic: it uses an unlocked, GIL-bound 82ms route as the discriminator for a lock, so it cannot fire while any GIL cost exists, and its silence was misread as exculpatory. The next round should still be diagnostic — this attribution deserves direct lock-wait instrumentation before a fix is built on it, and this phase has twice adopted an unconfirmed hypothesis — but it should confirm or refute a named mechanism against a falsifiable prediction rather than search an open field. `gaps[].missing` is written to that shape and states what to measure, not what to build.

**A second, newly-introduced gap.** `06-13` bounded a query that was previously unbounded, and those rows feed the uptime computation as well as the offline-interval reconstruction the bound was meant for. At the 8-service / 8-day scale `06-PROFILE.md` itself measured as already exceeding the cap, `/api/services` now reports a service that was offline for most of the window as 100% up — reproduced behaviourally during this verification (true 20.833%, reported 100.0%). The failure is silent and optimistic, on the surface operators trust most, and the suite cannot see it because the one test that exercises truncation asserts only the SQL shape. This does not falsify any single success criterion as literally worded, which is why the score stays 4/5 — but it is a direct hit on the phase goal's own "keeps essential monitoring reliable" clause, and the goal, not the wording, is what this verification is measuring against.

**OPS-07's disposition is correct.** It stays Pending on the merits — the run failed — and the `D-DEBT-06-08` self-certification rule that would independently prevent promotion is correctly recorded and correctly scoped. `PROH-OPS-07-01`, `PROH-OPS-07-02` and `PROH-OPS-07-08` are all verified intact: budgets unchanged since `06-07` and matching the cited figures, the only OPS-07 evidence is a genuine hardware run, and `REQUIREMENTS.md` is byte-identical across this round.

This phase does not seal.

---

_Verified: 2026-09-02T19:00:25Z_
_Verifier: Claude (gsd-verifier)_
