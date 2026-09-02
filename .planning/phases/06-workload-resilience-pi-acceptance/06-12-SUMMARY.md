---
phase: 06-workload-resilience-pi-acceptance
plan: 12
subsystem: testing
tags: [profiling, cProfile, attribution, performance-measurement, api-services]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-08's linear-sweep fix to _legacy_uptime_summary, which reduced /api/services from 2504.6ms to 289.0ms p50 on Pi hardware and left the residual this plan attributes"
provides:
  - "tests/services_route_profile.py: a cProfile-based attribution harness that drives the real /api/services route through app.test_client() and classifies every pstats self-time entry into one of eleven declared PROFILE_PHASES buckets"
  - "_classify_with_call_graph: redistributes an unmatched builtin/leaf entry's cost to its caller's bucket, so comprehensions and datetime arithmetic are not misattributed to `other`"
  - "--growth mode: measures each bucket's growth ratio against a measured (not assumed) stored-check-row ratio"
  - "--min-attributed flag (default 90.0) enforcing the attribution contract through the profiler's own exit code"
  - "06-PROFILE.md: the evidence 06-13's blocking fix-path decision is made against"
affects: ["06-13"]

# Actuals (#2632)
actuals:
  tasks: 3
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Attribution by pstats self-time into declared buckets, with caller-redistribution for unmatched leaves, and a warm-up request discarded so import/connection cost is never attributed per-request"
    - "Reporting wall_ms_unprofiled alongside wall_ms_profiled so a reader can see how far the instrument perturbed the total it measured"

key-files:
  created:
    - tests/services_route_profile.py
    - tests/test_services_route_scaling.py
    - .planning/phases/06-workload-resilience-pi-acceptance/06-PROFILE.md
  modified: []

key-decisions:
  - "Absolute milliseconds are explicitly disclaimed as non-transferable: this profile ran on an arm64 development laptop, not the aarch64 Pi. Only share_pct and growth_ratio carry forward; the operator's 289.0ms Pi control-pass figure remains the sole authority on absolute per-request cost (PROH-OPS-07-09)."
  - "The 90.0 attribution contract is asserted only at the real 8-service/8-day dataset size, through the profiler's own exit code. Task 1 and Task 2's fast shape gates pass --min-attributed 0 deliberately, because fixed Flask dispatch overhead dominates the `other` bucket proportionally at small dataset sizes."

patterns-established:
  - "A measurement plan states plainly what it does not establish (host difference, GIL contention, deployment topology, representativeness) rather than letting silence imply coverage"
---

# Plan 06-12: Attribute `/api/services`' residual per-request cost

**Status:** Complete. Executed autonomously, then closed out by the orchestrator after the executor
agent stalled — see *Execution anomaly* below.

## What was built

A profiling harness (`tests/services_route_profile.py`, 655 lines) that drives the real
`/api/services` route through `appmod.app.test_client()` under `cProfile`, discards a warm-up
request, and attributes every `pstats` self-time entry to one of eleven declared buckets. Plus
`tests/test_services_route_scaling.py`, which pins the profiler's own properties — most importantly
`test_profiling_does_not_change_the_route_response` and
`test_profiling_does_not_change_the_route_query_count`, proving the instrument does not alter what
it measures.

The deliverable that matters downstream is `06-PROFILE.md`.

## The named finding

`06-VERIFICATION.md`'s recorded expectation is **partially confirmed, and materially incomplete.**

It predicted the residual was "the per-service `_uptime_summary` sweep plus the
`attributed_downtime_seconds`/offline-interval computation." Those buckets are real and substantial —
`uptime_sweep` (29.975%) + `attributed_downtime` (4.238%) + `offline_intervals_read` (10.266%) =
**44.479%**, and `uptime_sweep` is indeed the single largest bucket. But it is not the majority, and
two costs the prediction never named are comparably large:

1. **`maintenance_coverage` at 29.649%** — effectively tied with `uptime_sweep`, measured here for
   the first time. `beacon_maintenance.coverage()` is called ~5,997 times per request even though
   only one of eight seeded services has a maintenance window, because
   `attributed_downtime_seconds` splits each offline interval at every occurrence boundary and
   `coverage()` re-walks three calendar days of fold-aware `datetime` construction on every call,
   with no memoization. `_local_occurrence_epochs` alone is ~41ms/request — the most expensive leaf
   found. Its growth ratio (7.564) *exceeds* the check-row ratio (4.249): the cost scales with
   accumulated offline intervals, not with maintenance-window count.

2. **The duplicate full-window `service_checks` scan.** `dashboard/app.py:2806` reads the whole
   retention window into `checks_by_port`; `read_service_offline_intervals_by_port`
   (`repositories.py:1148`) then re-reads the same bounds. Confirmed by row count: 25,278 rows
   fetched, then **20,000 of the same rows re-fetched — 79.1% duplication.**

## A correctness-adjacent finding this plan did not go looking for

That second read returning exactly 20,000 rows is `_OFFLINE_INTERVALS_BULK_ROW_LIMIT`
(`repositories.py:1104`). **At 8 services with 8 days of J3/J4-cadence checks, the bulk
offline-interval read is already at its cap and silently dropping ~21% (5,278 rows) of in-window
data** for the highest-numbered ports. A deployment at or above this volume may already be
reconstructing incomplete offline intervals, silently.

This plan did not fix it — that is outside its scope fence. It is recorded here and in `06-PROFILE.md`
§5 for `06-13` or a follow-up to weigh. It has not yet been filed as a debt item.

## Verification

| Check | Result |
|---|---|
| Task 3 verify, re-run independently by the orchestrator | `PROFILE_RUNS_OK 98.27 4.249` then `PROFILE_REPORT_OK` |
| `attributed_pct` ≥ 90.0 at 8 services / 8 days | 98.27 (executor's own run reported 98.653 — run-to-run variance) |
| `check_row_ratio` > 3.0 | 4.249, identical across both runs (deterministic seed `20260902`) |
| Share sum within 99.0–101.0 | Yes |
| Full suite, quiet tree | **849 passed, 561 subtests, 0 failed** in 295.75s — above the 837 floor |
| Production code untouched | `git diff f672832..HEAD -- dashboard/` is empty |

## Execution anomaly

The executor agent stalled after writing `06-PROFILE.md` but before committing it — its stream
watchdog gave up after 600s with no progress, during a full-suite run. Its three code commits
(`cb4d845`, `1739a18`, `29b0ed7`) were intact; the 20k report was uncommitted in the worktree and
would have been lost when the worktree was removed (#2070).

The orchestrator recovered it: copied the report out before touching the worktree, committed it as
`8ac0c3d`, merged the branch, then **independently re-ran Task 3's verify command rather than
trusting the report's own claim of having passed it**, and re-ran the full suite on a quiet tree.
Both confirmed. This SUMMARY was written by the orchestrator, not the executor.

The stall also explains a discrepancy worth recording: 06-11's agent reported 15–16 full-suite
failures, all in `test_advanced_ui.py` / `test_history_investigation_ui.py` / `test_ui_states.py`,
and attributed them to Playwright/Chromium contention from this plan's concurrently-running agent.
That attribution is now **confirmed** — the quiet-tree run has zero failures.

## What this does not establish

Carried forward verbatim from `06-PROFILE.md` §6, because `06-13` must not over-read this evidence:

- **Host difference.** Measured on `arm64` / a development laptop, not the `aarch64` Pi. Only shares
  and ratios transfer; milliseconds do not.
- **GIL contention.** A single-threaded `test_client()` run cannot separate GIL effects, which
  appear only under the concurrent load `--workers 1 --threads 8` serializes. `D-DEBT-06-01` remains
  a separate line of evidence this report neither extends nor contradicts.
- **Deployment topology.** This report says nothing about the worker/thread configuration. `06-13`
  must weigh that on `D-DEBT-06-01`, not on this.
- **Representativeness of the `maintenance_coverage` finding.** It depends on the seeded dataset
  having one service with both an enabled window and real offline history. A deployment with no
  maintenance windows configured — a common case, since the feature is operator-opt-in — pays none
  of this cost.
