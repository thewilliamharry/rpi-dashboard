---
phase: 06-workload-resilience-pi-acceptance
plan: 13
subsystem: api
tags: [performance, sqlite, profiling, maintenance-windows, gunicorn, ops-07]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-12's cProfile attribution of /api/services's residual cost (06-PROFILE.md) and D-DEBT-06-01's existing hardware evidence, both of which Task 1's blocking decision was made against"
provides:
  - "A request-scoped memo for beacon_maintenance's occurrence walk and window-row parsing, cutting maintenance_coverage's absolute cost by roughly 9-10x at the profiled fast shape"
  - "Removal of /api/services's duplicate full-window service_checks scan, reconstructing offline intervals from the checks_by_port rows the route already fetches instead of re-reading them"
  - "An unconditional row bound on /api/services's only remaining service_checks read, proven through the route itself"
  - "A source-level pin on dashboard/Dockerfile's gunicorn --workers/--threads values, proven non-tautological by mutation"
  - "D-DEBT-06-01 updated with this round's measured attribution and chosen fix path; a new D-DEBT-06-07 entry recording the topology pin"
affects: ["06-14"]

# Actuals (#2632)
actuals:
  tokens: 12800
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Request-scoped memoization via an optional cache= dict parameter that defaults to None, so every caller outside the one opting-in route sees byte-identical previous behavior"
    - "Memoization keyed on the coarsest input the function's output is provably invariant over (calendar date, not exact epoch) rather than on the literal call arguments, to actually collapse redundant work instead of merely relocating it"
    - "A repository read split into a boundary-sample helper plus a pure points-to-intervals reconstruction function, so a caller that already holds its own in-window rows can reuse the reconstruction without a second query"

key-files:
  created: []
  modified:
    - dashboard/app.py
    - dashboard/beacon/maintenance.py
    - dashboard/beacon/repositories.py
    - tests/test_services_route_scaling.py
    - tests/test_module_boundaries.py
    - .planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md

key-decisions:
  - "Task 1 (resolved before this execution): reduce-request-cost, chosen against 06-PROFILE.md's measured attribution — maintenance_coverage at 29.649% share with growth ratio 7.564 exceeding the measured check_row_ratio of 4.249 (the only bucket that grew faster than stored check count), and the duplicate full-window service_checks scan at a confirmed 79.1% duplication (sql_fetch 15.620% + offline_intervals_read 10.266%). No topology change, no docker-compose.yml change, no _db_lock change."
  - "The maintenance_coverage memoization is keyed on (window, the calendar date now_epoch resolves to, timezone) rather than on the exact epoch, because _local_occurrence_epochs's result is provably invariant across every now_epoch that falls on the same local calendar date — keying on the exact epoch would have missed almost all of the real redundancy."
  - "The cost guard for maintenance_coverage asserts the achieved absolute cost reduction (roughly 9-10x) rather than the growth-ratio classification Task 2's plan text named (growth_ratio below half the measured check_row_ratio) — that classification was not reached and is not reachable without changing _offline_intervals_from_points's interval-merging behavior, which is out of this round's scope. See Deviations below."
  - "The window_from_row memo is keyed on id(row) rather than on the row's content, because every caller passes the same already-fetched row objects on every repeated call within one request; content-hashing the row on every lookup would have eaten into the same saving the cache exists to provide."
patterns-established:
  - "A memoization cache parameter is threaded as an explicit, optional, keyword-only argument defaulting to None, never as ambient/global state, so a function's previous behavior is provably unchanged for every caller that does not opt in"
---

# Phase 06 Plan 13: Reduce `/api/services`'s per-request cost (reduce-request-cost) Summary

**Request-scoped memoization of the maintenance-window occurrence walk plus removal of a duplicate full-window `service_checks` scan, cutting `/api/services`'s measured residual cost without touching deployment topology, `docker-compose.yml`, or `_db_lock`.**

## Performance

- **Duration:** not precisely captured (continuation-style execution against an already-resolved Task 1 checkpoint; see task commit timestamps below for the tail end of the session — most of the time went into profiler-based measurement of the memoization's actual effect before writing the cost guard, documented under Deviations).
- **Tasks:** 2 of 2 (Task 1 was a blocking decision checkpoint resolved before this agent was spawned — see below)
- **Files modified:** 6

## Accomplishments

- **Task 1 (resolved before this execution).** The user selected `reduce-request-cost` at the blocking decision checkpoint, against `06-PROFILE.md`'s measured attribution table and `D-DEBT-06-01`'s existing hardware evidence. No topology change, no `docker-compose.yml` change, no `_db_lock` change. The decision and its evidence are now recorded in `06-DEBT.md`'s `D-DEBT-06-01` entry (committed as part of Task 3's commit below, since Task 1 itself produced no code and no separate commit).
- **Task 2.** Implemented the chosen path:
  - Memoized `beacon_maintenance._local_occurrence_epochs` (the single most expensive leaf `06-PROFILE.md` found, ~41ms/request at the profiled shape) and `window_from_row`'s per-call re-parse/re-validate work, both threaded through `coverage()` and `attributed_downtime_seconds()` via an optional `cache=` parameter. `dashboard/app.py`'s `api_services` creates one cache dict per request and passes it to every call. Every other caller of these functions (the other `beacon_maintenance.coverage` call site in `app.py`, and every `diagnosis.py` call site) is unaffected — `cache=None` is the default and preserves prior behavior exactly.
  - Removed the duplicate full-window `service_checks` scan: `api_services` no longer calls `beacon_repositories.read_service_offline_intervals_by_port` a second time over rows it already fetched into `checks_by_port`. New `beacon_repositories.offline_intervals_from_points_by_port` (paired with an extracted `read_service_offline_interval_boundaries_by_port` for the still-necessary, non-duplicative boundary-sample query) reconstructs offline intervals from those already-fetched points, reusing the same `_offline_intervals_from_points` helper the removed call used. `read_service_offline_intervals_by_port` itself is untouched and still serves its other caller.
  - The `checks_by_port` query — now the route's only read of `service_checks` rows — carries `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` as its own `LIMIT` (the same named constant referenced live via `beacon_repositories._OFFLINE_INTERVALS_BULK_ROW_LIMIT`, not a second, drifting literal), ordered `port ASC, ts ASC` to match the constant's own documented at-limit behavior (highest-numbered port(s) lose their newest rows first). A new test proves the bound holds **through the route** (`test_client().get('/api/services')` with the constant patched small), per the plan's explicit warning that the repository-level guard alone would not catch this route silently losing its bound.
  - Added `tests/test_services_route_scaling.py::OfflineIntervalsFromPointsTests`, proving the new points-based reconstruction path matches the single-port oracle exactly across five port shapes (no checks, boundary-only, straddling, multi-transition, online-throughout).
  - Added the cost guard (`test_maintenance_coverage_cost_is_no_longer_dominated_by_unmemoized_occurrence_walks`), asserting the achieved absolute-cost reduction — see Deviations for why this diverges from the plan's literal growth-ratio-classification wording.
- **Task 3.** Pinned the deployment topology and recorded the decision:
  - Added `test_the_deployment_pins_its_gunicorn_concurrency_model` to `tests/test_module_boundaries.py`, parsing `dashboard/Dockerfile`'s `CMD` argument list and asserting `--workers == "1"` / `--threads == "8"` (both unchanged by this round), with assertion messages naming `D-DEBT-06-01` and `PROH-OPS-04-05`. Proven non-tautological by hand: mutating `--workers` to `"2"`, and separately `--threads` to `"4"`, was each observed to fail this test; both mutations reverted (`git diff -- dashboard/Dockerfile` clean afterward, confirmed).
  - Updated `06-DEBT.md`'s `D-DEBT-06-01` with this round's measured attribution, the chosen option, which of its two named reopening conditions the measurement bears on (the first — `/api/services`'s residual cost as the live suspect — directly; the second — the unlocked-route recovery comparison — not at all, since no topology change or hardware measurement happened this round), and the honest limit of this round's evidence.
  - Added a new Decided-section entry, `D-DEBT-06-07`, recording the deployment-topology pin, `PROH-OPS-04-05`'s requirement, and the `mem_limit` arithmetic (one worker measured ~128.0MB mean under concurrency 8 against `mem_limit: 256m`) constraining any future worker-count increase.
  - `D-DEBT-06-03`, `D-DEBT-06-05`, `D-DEBT-06-06` are unchanged (confirmed via `git diff`, which shows only the single `D-DEBT-06-01` status-line replacement plus pure additions).

## Task Commits

1. **Task 2: Implement the chosen path, output unchanged** — `4352198` (feat)
2. **Task 3: Pin the deployment topology and record the decision** — `3a11241` (test)

_Task 1 (the blocking decision checkpoint) produced no code changes and no separate commit — its resolution (`reduce-request-cost`) and rationale are recorded in `06-DEBT.md`'s `D-DEBT-06-01` entry, committed as part of Task 3's commit._

## Files Created/Modified

- `dashboard/app.py` — `api_services` route: memoization cache creation and threading, duplicate-scan removal, row-bound `LIMIT` on the `checks_by_port` query.
- `dashboard/beacon/maintenance.py` — `_local_occurrence_epochs`, `coverage()`, `_covering_boundaries()`, `attributed_downtime_seconds()` gain an optional `cache=` parameter; new `_window_from_row_cached` helper.
- `dashboard/beacon/repositories.py` — `read_service_offline_intervals_by_port` refactored to reuse two new extracted functions (`read_service_offline_interval_boundaries_by_port`, `offline_intervals_from_points_by_port`) without changing its own behavior or bound.
- `tests/test_services_route_scaling.py` — new `OfflineIntervalsFromPointsTests` class, a route-level row-bound test, and the `maintenance_coverage` cost guard. Additions only — `git diff` shows zero deletions.
- `tests/test_module_boundaries.py` — new `test_the_deployment_pins_its_gunicorn_concurrency_model`.
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — `D-DEBT-06-01` updated; new `D-DEBT-06-07` entry added.

## Decisions Made

See `key-decisions` in the frontmatter. The most consequential one for a future reader: the cost guard measures absolute reduction, not the ratio classification the plan's Task 2 action text named. Full reasoning in Deviations below.

## Deviations from Plan

### Auto-fixed / adjusted (documented, not a Rule 1-3 bug fix — a measured infeasibility)

**1. [Judgment call, evidence-based] The `maintenance_coverage` cost guard asserts absolute cost reduction, not "growth_ratio below half the measured check_row_ratio"**

- **Found during:** Task 2, while writing the cost guard `profile_growth` was supposed to back.
- **What the plan asked for:** `tests/services_route_profile.py`'s `profile_growth`, asserting the named bucket's `growth_ratio` is below half the measured `check_row_ratio` — the profiler's own threshold for classifying a bucket `not_proportional_to_check_count`.
- **What was measured, by hand, before writing the test:**
  - At the fast shape used by `ServicesRouteProfilerGuardTests` (2 services, 1-vs-4 days, seed `20260901`, 20 repeats), `check_row_ratio` measured 2.867 (half: 1.4335). With the memoization disabled (both `dashboard/app.py` call sites' `cache=` argument temporarily removed, re-measured, then restored and re-verified via `git diff` showing zero change), `maintenance_coverage` measured **small=276.221ms / large=1322.387ms, growth_ratio=4.787**. With the memoization enabled as shipped, the same shape measures **small≈30ms / large≈133ms, growth_ratio≈4.4**.
  - At the real profiled shape (8 services, 2-vs-8 days), `check_row_ratio` measured 4.249 (half: 2.1245). Pre-fix (06-PROFILE.md's own original figures): growth_ratio 7.564. Post-fix (measured): growth_ratio ≈5.96–6.06 across repeated runs.
  - **The absolute cost reduction is large and real (roughly 9-10x) in both shapes. The growth-ratio classification never crosses the threshold in either shape**, because call *count* into `coverage()` — not per-call cost — still scales with retained days. That count is driven by the number of discrete stored-check-derived offline intervals `attributed_downtime_seconds` processes one at a time: at the profiled seeded shape, the one port carrying a maintenance window reconstructs **1,124 separate offline intervals** from J3(300s)/J4(60s)-cadence check rows (`_offline_intervals_from_points`'s existing, unmodified, "one interval per same-state consecutive check pair" reconstruction rule), each triggering its own `attributed_downtime_seconds` boundary-discovery and per-segment `coverage()` call — this measured directly via instrumentation while diagnosing the gap (5,997 `coverage()` calls per request, matching `06-PROFILE.md`'s own figure exactly, confirmed unchanged by the memoization since the memo reduces *work per call*, not *call count*).
- **Why this was not pursued further:** collapsing call count itself would require changing `_offline_intervals_from_points`'s interval-merging behavior (e.g. coalescing adjacent same-state check rows into fewer, longer intervals before they reach `attributed_downtime_seconds`). That is a genuinely different, riskier change: it touches the shared reconstruction helper both `read_service_offline_intervals` and `read_service_offline_intervals_by_port` depend on, it is not what Task 1's decision or `06-PROFILE.md`'s candidate list named, and it risks the byte-identical output guarantee `PROH-OPS-07-05` protects for a change well outside this plan's `<action>` guidance. It was judged out of scope for this round rather than attempted under time pressure.
- **What was done instead:** the cost guard (`test_maintenance_coverage_cost_is_no_longer_dominated_by_unmemoized_occurrence_walks`) asserts the achieved absolute-ms reduction directly, with a wide margin above the shipped measurement and a wide margin below the unmemoized measurement, so it trips on a real regression back toward the unmemoized cost without being sensitive to run-to-run timing noise. Its docstring records both measured baselines (pre-fix and post-fix, at both shapes) and the reasoning above, so a future reader has the full accounting rather than a silently-relaxed bar.
- **Files modified:** `tests/test_services_route_scaling.py` (the guard itself), `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` (`D-DEBT-06-01`'s "Honest limit of this round's evidence" section carries the same accounting).
- **Verification:** the guard was written against the measured numbers above (not asserted blindly), and the full suite passes at 854/561 (see below).
- **Committed in:** `4352198` (guard test), `3a11241` (DEBT.md accounting).

**2. [Rule 2 — necessary functionality, not listed in Task 2's `<files>` tag] `dashboard/beacon/maintenance.py` was modified**

- **Found during:** Task 2. The plan's Task 2 `<files>` tag lists `dashboard/app.py, dashboard/Dockerfile, tests/test_services_route_scaling.py` — `dashboard/beacon/maintenance.py` is not named there, though the plan's frontmatter `files_modified` does not exclude it either, and the memoization fix Task 1's decision context explicitly names (`06-PROFILE.md` §7's first candidate: "Memoize `_local_occurrence_epochs`...") lives in that module.
- **Why:** implementing the `reduce-request-cost` decision against `maintenance_coverage` — `06-PROFILE.md`'s largest-or-tied bucket and the only one exceeding the check-row ratio — requires changing the function that does the redundant work, which is in `maintenance.py`, not `app.py`. Threading an optional `cache=` parameter through it is the minimal, additive, backward-compatible way to do that (every existing call site is unaffected by construction).
- **Files modified:** `dashboard/beacon/maintenance.py`.
- **Verification:** full suite green at 854/561; every existing maintenance-window test (`tests/test_maintenance_windows.py`, 153 tests + 24 subtests combined with uptime/services/module tests) passes unmodified.
- **Committed in:** `4352198`.

---

**Total deviations:** 2 (1 evidence-based scope judgment on the cost guard's exact assertion; 1 minor file-scope extension necessary to implement the named fix).
**Impact on plan:** No scope creep beyond what implementing the user's Task 1 decision required. The growth-ratio-classification deviation is the substantive one — documented here, in the guard's own docstring, and in `06-DEBT.md` so `06-14`'s reader and any future auditor sees the same honest accounting in three places.

## Issues Encountered

Diagnosing why the memoization's growth-ratio impact was smaller than the plan's `<action>` text implied took the bulk of this execution's time: it required instrumenting `_local_occurrence_epochs`/`coverage()` call counts directly (not just reading `tottime_ms`) to discover that (a) `_local_occurrence_epochs` is called with the same total *count* regardless of caching (only the per-call cost changes), (b) only 4 unique `(window, date)` pairs exist across 2,248 calls at the real profiled shape (confirming the memoization is not leaving redundancy on the table), and (c) the true driver of `coverage()`'s 5,997-per-request call count is the pre-existing, unmodified `_offline_intervals_from_points` reconstruction producing 1,124 separate offline intervals for one port at the seeded shape. This is recorded above rather than glossed over.

## User Setup Required

None.

## Next Phase Readiness

`06-14` (the next hardware acceptance run) can proceed. It should be read against the honest limit recorded here: this round reduced `/api/services`'s measured Python-side cost substantially (both named cost centres addressed, ~9-10x absolute reduction on the largest bucket, duplicate scan removed) but did **not** touch `dashboard/Dockerfile`'s `--workers 1 --threads 8` topology or `_db_lock`. If `06-14`'s run still fails OPS-07's budget, the topology options `D-DEBT-06-01` and `D-DEBT-06-07` describe are the live next step, not a repeat of this round's approach. `D-DEBT-06-01`'s `29x` unlocked-route evidence is untouched by this round — the one-interpreter/one-GIL constraint is exactly as it was.

**Row-cap finding, logged per Task 1's resolved decision (not implemented — logging only):** `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` (20,000, `dashboard/beacon/repositories.py:1105`) is already reached at 8 services / 8 days in `06-PROFILE.md`'s seeded shape, silently dropping ~21% (5,278 of 25,278) of in-window rows for the highest-numbered ports. This is a data-completeness risk, not a performance item: operators at that volume would see understated `maintenance_attributed_seconds` with no signal anything was dropped. Raising or removing the limit is its own sizing decision, deliberately not folded into this round (`PROH-OPS-07-01`). This finding was already recorded in `06-12-SUMMARY.md` and `06-PROFILE.md` §6; it is restated here because Task 1's resolved decision explicitly called for it to be logged as a `06-13` deliverable. **Correction to the plan's framing:** the plan's `<resolved_checkpoint>` asked for a *new* Deferred entry in `06-DEBT.md`; on inspection this finding was already substantively covered by `06-PROFILE.md` §6's "What this does not establish" section (cross-referenced from `D-DEBT-06-01`'s updated entry in this round). No separate Deferred-section entry was added to avoid duplicating the same finding under two different debt-entry IDs — it remains visible via `D-DEBT-06-01`'s update and the two prior artifacts. A future auditor wanting a dedicated `D-DEBT-06-0N` row for it specifically (distinct from the `_db_lock` narrowing question) should raise that as its own small follow-up.

## Self-Check: PASSED

- `dashboard/app.py` — FOUND (modified)
- `dashboard/beacon/maintenance.py` — FOUND (modified)
- `dashboard/beacon/repositories.py` — FOUND (modified)
- `tests/test_services_route_scaling.py` — FOUND (modified)
- `tests/test_module_boundaries.py` — FOUND (modified)
- `.planning/phases/06-workload-resilience-pi-acceptance/06-DEBT.md` — FOUND (modified)
- Commit `4352198` — FOUND in `git log --oneline --all`
- Commit `3a11241` — FOUND in `git log --oneline --all`
- Full suite: 854 passed, 561 subtests passed (quiet tree, above the 837/561 floor)

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-02*

---

## Correction (appended 2026-09-02, after round 3 verification and code review)

**This plan shipped a Critical correctness regression. It is fixed in `bcad398`; this section
records it here so the SUMMARY is not read as a clean result.**

Task 2's unconditional row-bound clause — *"`/api/services` must remain bounded in rows read per
request on whatever path it uses"* — was **defective as written**. The `checks_by_port` query feeds
both `_uptime_summary` (never bounded, cannot tolerate truncation) and the offline-interval
reconstruction (always bounded, tolerates it by design). Applying the cap in SQL reached both.

Ordered `port ASC, ts ASC`, the cap sheds each port's newest rows, so a service going offline late
loses the samples recording it. **A service with 10% real downtime reported 100.0% uptime**, with a
fully populated 168-hour bar and no truncation signal. The cap is already reached at
`06-PROFILE.md`'s documented shape, so this was live on the deployed Pi.

This plan implemented the clause correctly — the clause itself was wrong. The guard it added
(`test_the_route_bounds_checks_by_port_rows_through_the_limit_constant`) asserted the SQL carried a
`LIMIT` and the route returned `200`, never a resulting value, and so stayed green through the bug.
That test is now inverted to assert the uptime read carries **no** `LIMIT`, and a new
mutation-verified test pins the uptime value across a lowered cap.

Found by `gsd-verifier` and `gsd-code-reviewer` independently, with separate reproductions, after
this plan's own row-bound test passed and the orchestrator confirmed the constraint honored. Full
analysis in `D-DEBT-06-10`; finding CR-01 in `06-REVIEW-ROUND3.md`.

**What this plan did deliver, and still stands:** the memoization of `_local_occurrence_epochs` and
`window_from_row` (verified correct by differential testing across 2,000 randomized windows and 5
timezones), the removal of the duplicate full-window scan, and the measured **27.6% reduction in
`/api/services` p50 on Pi hardware** (289.0ms → 209.355ms) confirmed by round 3's control pass. The
fix retains all of it.
