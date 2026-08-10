---
phase: 02-bounded-telemetry-retention
verified: 2026-08-10T15:37:24Z
status: gaps_found
score: 15/27 must-haves verified
behavior_unverified: 0
overrides_applied: 0
gaps:
  - truth: "Beacon retains a rolling 90 days of bounded host metrics, service history, and events without unbounded database growth."
    status: failed
    reason: "Hourly host and service rollups are deleted by bucket start, so an hourly bucket that overlaps a non-hour-aligned 90-day cutoff is removed while part of it is still retained history."
    artifacts:
      - path: "dashboard/beacon/telemetry.py"
        issue: "Lines 963-964 use bucket_start < expiry_cutoff instead of requiring bucket_start + bucket_seconds <= expiry_cutoff."
    missing:
      - "Expire only fully closed hourly buckets and add a non-hour-aligned cutoff regression test for host and service rollups."
  - truth: "Recent observations remain detailed while older history is represented by documented aggregates, with each aggregate completed before its source data is removed."
    status: failed
    reason: "Tier selection excludes raw rows as soon as they pass the configured raw cutoff, even while they are still retained awaiting bounded asynchronous compaction. The API therefore omits preserved source evidence."
    artifacts:
      - path: "dashboard/beacon/repositories.py"
        issue: "_tier_ranges (lines 133-141) reads raw, five-minute, and hourly tiers exclusively; it has no awaiting-compaction raw fallback."
      - path: "dashboard/beacon/telemetry.py"
        issue: "run_retention_batch compacts a bounded batch asynchronously, so retained source rows can remain outside the queryable tier for more than one cleanup interval."
    missing:
      - "Make preserved raw evidence queryable until its replacement rollup is available, or durably disclose and query pending aggregation before excluding it."
  - truth: "A requested historical range explicitly distinguishes observed values from collection gaps, unknown intervals, and data that has expired under retention."
    status: failed
    reason: "The production host sampler writes stream, cadence, and storage-pressure evidence under host:host, but host history/rollup readers look up host:cpu, host:ram, host:disk, or host:temp. Normal host requests therefore report not_yet_monitored/unknown instead of the worker-recorded evidence."
    artifacts:
      - path: "dashboard/app.py"
        issue: "worker_collect_system_stats lines 1743-1753 closes/opens and records only host:host; api_telemetry_history derives the reader key from the requested metric."
      - path: "dashboard/beacon/telemetry.py"
        issue: "_roll_host_raw reads coverage per metric, so worker-recorded host:host pressure/gap evidence cannot enter host aggregates."
    missing:
      - "Use one canonical per-metric host stream identity across sampling, pressure-gap recording, rollups, and history reads, with a production-writer-to-reader integration test."
  - truth: "Beacon selects an appropriate server-side resolution for each historical request and returns a bounded number of points without misleading the operator about coverage."
    status: failed
    reason: "The API constructs a default RetentionPolicy and constant point budget rather than the validated deployed settings used by the worker. Configured tier boundaries and point budget can therefore disagree with the tables the worker writes and expires."
    artifacts:
      - path: "dashboard/app.py"
        issue: "api_telemetry_history lines 2192-2200 and 2212/2253 use POINT_BUDGET and RetentionPolicy() instead of _telemetry_policy()."
    missing:
      - "Use the same settings-backed policy for API resolution, cutoffs, retention coverage, and response budget as the worker uses for retention."
  - truth: "Failure or retry never duplicates an aggregate or deletes source evidence; the job remains failed/pending with bounded backoff and an error class."
    status: failed
    reason: "_mark_failed persists next_retry_ts, but _raw_candidates and _five_minute_candidates never examine telemetry_rollup_jobs. A failed candidate is retried by every cleanup invocation before its due time."
    artifacts:
      - path: "dashboard/beacon/telemetry.py"
        issue: "Lines 780-818 select solely from source/rollup rows; run_retention_batch lines 928-958 processes all selected candidates without a due-time predicate."
    missing:
      - "Filter candidates using persisted failed/pending job state and next_retry_ts, and test that a pre-due retry leaves attempt_count and source rows unchanged."
---

# Phase 2: Bounded Telemetry & Retention Verification Report

**Phase Goal:** Beacon maintains an accurate, bounded 90-day telemetry record whose resolution, gaps, and retention rules remain trustworthy under normal operation.
**Verified:** 2026-08-10T15:37:24Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Beacon retains host metrics, service history, and events for a rolling 90 days without unbounded database growth. | ✗ FAILED | `run_retention_batch()` deletes hourly rollups on `bucket_start < expiry_cutoff` at `telemetry.py:963-964`; a bucket crossing a non-hour-aligned cutoff loses still-in-window data. |
| 2 | Recent observations remain detailed while older history is represented by documented aggregates, with each aggregate completed before its source data is removed. | ✗ FAILED | Aggregate-before-delete is ordered correctly, but `_tier_ranges()` omits retained raw rows awaiting a bounded asynchronous rollup. Preserved evidence can disappear from reads. |
| 3 | A requested range distinguishes observed values, collection gaps, unknown intervals, and expired data. | ✗ FAILED | The worker writes host coverage as `host:host` (`app.py:1743-1753`), while API and host rollups read metric keys (`host:cpu`, etc.). Worker evidence is disconnected from responses. |
| 4 | Historical APIs choose appropriate server-side resolution and return a bounded point count without misleading coverage. | ✗ FAILED | The endpoint fixes both policy and budget to defaults (`app.py:2192-2200`, `2253`) rather than using `_telemetry_policy()` and deployed settings. |

**Roadmap-contract score:** 0/4 truths verified (0 present, behavior-unverified).  
**Merged must-have score:** 15/27 verified — this includes the 23 plan truths; the four non-negotiable roadmap truths above all fail, so the phase goal is not achieved.

## Plan Must-Have Findings

| Plan | Finding | Status | Evidence |
| --- | --- | --- | --- |
| 02-01 | Fixed selector validation, half-open bound preservation, ordering/coalescing, and legacy route coexistence are implemented. | ✓ VERIFIED | `HistoricalRange`, `select_resolution`, repository query maps, `api_telemetry_history`, and `api_history` are substantive and wired. The named API coverage test passed. |
| 02-02 | The summary says `approve-contract`, but no independent developer decision artifact records the checkpoint; its claimed exact expiry contract is contradicted by production code. | ⚠️ UNCERTAIN / ✗ FAILED | `02-02-SUMMARY.md` is the sole approval evidence. Separately, the implemented hourly expiry removes a partially retained bucket, contrary to the recorded contract. |
| 02-03 | Supported fixtures migrate transactionally and preserve legacy rows. | ✓ VERIFIED | Migration 5 tables plus migration 6 are registered; the named current-v4 preservation test passed. |
| 02-04 | Verified aggregate-before-exact-source-delete is present; retention expiry and retry backoff contracts are not. | ✗ FAILED | `_upsert_and_verify()` precedes source `DELETE`, but hourly expiry is unsafe and `next_retry_ts` is not enforced. |
| 02-05 | J8 is wired through worker authority and stale epoch rejection works, but host coverage production wiring is wrong. | ✗ FAILED | `_worker_write_transaction()` asserts current authority; named stale/current epoch test passed. `worker_collect_system_stats()` nevertheless uses the incompatible `host:host` stream key. |
| 02-06 | Fixed queries, selector allowlists, and response ceiling exist, but mixed-tier data and configured retention policy are not truthfully wired. | ✗ FAILED | `_tier_ranges()` has no raw-awaiting-compaction fallback and the API bypasses settings-backed policy. |

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/beacon/migrations.py` | Additive telemetry migration | ✓ VERIFIED | Substantive migrations 5/6, indexes, transactional migration engine, and current-v4 preservation test. |
| `dashboard/beacon/config.py` | Validated retention/budget settings | ⚠️ PARTIAL | Validates settings, and `_telemetry_policy()` consumes them for worker retention; the history API does not. |
| `dashboard/beacon/telemetry.py` | Retention, coverage, rollup policy | ⚠️ HOLLOW | Substantive and worker-wired, but has unsafe hourly expiry and ignores persisted retry due time. |
| `dashboard/beacon/repositories.py` | Bounded mixed-tier history reads | ⚠️ HOLLOW | Fixed parameterized shapes are real, but exclusive tiers make preserved uncompacted raw evidence unreadable. |
| `dashboard/app.py` | Authority-fenced writes and bounded history endpoint | ⚠️ HOLLOW | Wired to worker, policy and repositories, but production host stream identity and API policy wiring break truthfulness. |
| `dashboard/beacon/worker_main.py` | Sole J8 worker dispatch | ✓ VERIFIED | J8 dispatches `cleanup_history(authority)` and its mutation inventory declares telemetry surfaces. |
| `tests/test_historical_telemetry_api.py` | End-to-end history evidence | ⚠️ PARTIAL | It seeds `host:cpu` directly, bypassing the production `host:host` writer. |
| `tests/test_telemetry_retention.py` | Retention and authority evidence | ⚠️ PARTIAL | Tests aligned cutoff and post-due retry, but not non-aligned hourly expiry or a pre-due retry. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `worker_main.py` | `app.py` | J8 → `cleanup_history(authority)` | ✓ WIRED | Inventory dispatch invokes the bound cleanup operation. |
| `app.py` | `telemetry.py` | Worker transaction + policy/retention helpers | ✓ WIRED | `_worker_write_transaction()` asserts current epoch before `run_retention_batch()`. |
| `app.py` | `repositories.py` | Validated history request → fixed query maps | ⚠️ PARTIAL | Calls are real, but API supplies default rather than deployed cutoffs. |
| `worker_collect_system_stats()` | host history/rollups | Coverage stream identity | ✗ NOT_WIRED | Writer is `host:host`; readers require per-metric keys. |
| `telemetry.py` | `telemetry_rollup_jobs` | Retry scheduling | ✗ NOT_WIRED | Failed jobs are written, but candidate selection never reads their due timestamp. |
| `repositories.py` | retained raw source | Pending aggregation fallback | ✗ NOT_WIRED | Tier routing excludes retained raw source before its replacement aggregate exists. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| `app.py` history route | `sources`, `coverage_data`, `pending` | SQLite repository reads | Yes, but selection is inconsistent | ⚠️ HOLLOW — defaults can select wrong tiers and raw backlog is omitted. |
| `worker_collect_system_stats()` | host telemetry stream/coverage | Real system sample → `stats_history` + telemetry state | Yes, but wrong identity | ✗ DISCONNECTED — coverage is written for `host:host`, never read by metric requests. |
| `run_retention_batch()` | rollups/jobs/events | SQLite raw rows and rollups | Yes, but unsafe lifecycle | ⚠️ HOLLOW — partial hourly expiry and pre-due retries violate retention contract. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| API coverage response, aggregate-before-delete, stale worker epoch, current-v4 migration preservation | `uv run --project dashboard python -m pytest -q` with four named tests | `4 passed in 0.20s` | ✓ PASS |
| Full workspace suite | `uv run --project dashboard python -m pytest -q` | Process completed after emitting progress through 30%; terminal exit/result was not returned by the execution channel. It is not counted as a passing result. | ? INCONCLUSIVE |

The four passing named tests establish that these limited paths work; they do not exercise the production writer-to-reader host identity, a non-hour-aligned expiry cutoff, configured API settings, preserved-uncompacted raw data, or a pre-due retry.

### Probe Execution

Step 7c: SKIPPED — no `scripts/**/tests/probe-*.sh` files or Phase 02 probe declarations found.

### Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| TEL-01 | 02-02, 02-03, 02-04, 02-05 | Rolling 90-day bounded host/service/event retention | ✗ BLOCKED | `bucket_start < expiry_cutoff` deletes overlapping hourly retention data. |
| TEL-02 | 02-02, 02-03, 02-04, 02-06 | Recent detailed data and documented older aggregates | ✗ BLOCKED | Retained raw evidence is omitted while awaiting compaction. |
| TEL-03 | 02-02, 02-03, 02-04, 02-05 | Aggregate completes before source deletion | ✓ SATISFIED | `_upsert_and_verify()` and `_mark_succeeded()` precede exact-range deletion; named regression passed. |
| TEL-04 | 02-01, 02-05, 02-06 | Explicit values, unknowns, gaps, and expiry | ✗ BLOCKED | Host coverage identity mismatch and raw-awaiting-compaction omission cause wrong partitions. |
| TEL-05 | 02-01, 02-06 | Appropriate resolution and bounded response budget | ✗ BLOCKED | Point count is capped, but API ignores deployed policy/budget and can select misleading tiers. |

No Phase 02 requirement is orphaned: every TEL-01 through TEL-05 ID appears in at least one plan frontmatter and maps to Phase 2 in `REQUIREMENTS.md`.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/app.py` | 1743-1753 | Writer/reader stream-key mismatch | 🛑 Blocker | Normal host coverage and pressure gaps cannot reach the metric-specific API. |
| `dashboard/app.py` | 2192-2200, 2253 | Settings bypass | 🛑 Blocker | Deployed retention and response policy can disagree with API results. |
| `dashboard/beacon/telemetry.py` | 963-964 | Partial-bucket expiry | 🛑 Blocker | Irreversible deletion of in-window hourly evidence. |
| `dashboard/beacon/repositories.py` | 133-175 | Exclusive tier reads | 🛑 Blocker | Retained, queryable source evidence disappears until compaction. |
| `dashboard/beacon/telemetry.py` | 780-818, 928-958 | Retry backoff state unwired | ⚠️ Warning | Cleanup retries failures before persisted `next_retry_ts`. |

No unreferenced `TBD`, `FIXME`, or `XXX` debt markers were found in Phase 02 production/test files.

### Gaps Summary

The phase is not ready to advance. The data model, migrations, fixed query shapes, and worker epoch fence are substantive, but four production-path defects directly contradict the phase goal: misleading host coverage, mismatch between configured retention and API policy, deletion of partial hourly buckets, and omission of retained raw evidence. A fifth defect leaves the declared retry backoff inactive. Later roadmap phases cover analytics presentation and Pi acceptance, not these retention/telemetry correctness repairs, so none are deferred.

_Verified: 2026-08-10T15:37:24Z_
_Verifier: the agent (gsd-verifier)_
