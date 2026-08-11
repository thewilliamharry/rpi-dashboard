---
phase: 02-bounded-telemetry-retention
verified: 2026-08-11T00:00:00Z
status: gaps_found
score: 2/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 15/27
  gaps_closed:
    - "New worker samples use canonical per-metric host stream identities and the API uses the same Settings-derived policy."
    - "Hourly retention expires only fully closed buckets."
    - "Preserved raw and five-minute source evidence remains queryable until a completed replacement exists."
    - "Rollup admission honors persisted retry due times."
  gaps_remaining: []
  regressions: []
gaps:
  - truth: "A requested historical range explicitly distinguishes observed values from collection gaps, unknown intervals, and data that has expired under retention."
    status: failed
    reason: "Existing installations can retain legacy host:host stream metadata, coverage rows, and pressure state, but current readers and writers use only host:cpu/ram/disk/temp. No data migration or compatibility lookup transfers that durable evidence, so a metric request reports unknown/not_yet_monitored despite recorded historical collection-gap evidence."
    artifacts:
      - path: "dashboard/beacon/migrations.py"
        issue: "The migration catalog ends at version 6 and contains no idempotent host:host-to-per-metric telemetry data migration."
      - path: "dashboard/beacon/repositories.py"
        issue: "get_telemetry_coverage performs an exact stream_key lookup and has no legacy host:host compatibility path."
      - path: "dashboard/app.py"
        issue: "The writer and API both use host_stream_key(metric), so they cannot close or read pre-upgrade host:host pressure state."
    missing:
      - "Add an idempotent upgrade path that expands legacy host:host stream/coverage/pressure-gaps to all four metric keys, plus a seeded upgrade regression through the API."
  - truth: "Beacon selects an appropriate server-side resolution for each historical request and returns a bounded number of points without misleading the operator about coverage."
    status: failed
    reason: "Derived five-minute aggregation backlog is emitted as a 3,600-second pending interval even though the source bucket is 300 seconds. Coalescing can therefore claim pending aggregation for timestamps with no preserved source evidence."
    artifacts:
      - path: "dashboard/beacon/repositories.py"
        issue: "Both host and service five_query projections use bucket_start + 3600 AS end_ts while filtering bucket_seconds=300."
    missing:
      - "Project five-minute derived backlog as bucket_start + 300 and add host/service exact-interval and coalescing regressions."
---

# Phase 2: Bounded Telemetry & Retention Verification Report

**Phase Goal:** Beacon maintains an accurate, bounded 90-day telemetry record whose resolution, gaps, and retention rules remain trustworthy under normal operation.
**Verified:** 2026-08-11T00:00:00Z
**Status:** gaps_found
**Re-verification:** Yes — after gap closure

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Beacon retains host metrics, service history, and events for a rolling 90 days without unbounded database growth. | ✓ VERIFIED | `run_retention_batch()` expires hourly rows only when `bucket_start + bucket_seconds <= expiry_cutoff`; the focused non-aligned host/service/event regression passed. Bounded due-only batch admission and strict event expiry are also present. |
| 2 | Recent observations remain detailed while older history is represented by documented aggregates, with each aggregate completed before its source data is removed. | ✓ VERIFIED | Fallback query shapes retain lower-tier source evidence until a completed higher tier exists; `run_retention_batch()` verifies the aggregate before its exact source delete. The fallback/replacement and retry regressions passed. |
| 3 | A requested historical range explicitly distinguishes observed values from collection gaps, unknown intervals, and data that has expired under retention. | ✗ FAILED | New samples are metric-specific, but pre-upgrade `host:host` stream/coverage/pressure state is neither migrated nor read. Exact metric lookup therefore strands durable gap evidence. |
| 4 | Beacon selects an appropriate server-side resolution for each historical request and returns a bounded number of points without misleading the operator about coverage. | ✗ FAILED | Resolution and point-budget policy are Settings-backed, but derived five-minute backlog is reported as `[bucket_start, bucket_start + 3600)` rather than its actual 300-second interval. |

**Score:** 2/4 roadmap success criteria verified.

## Original Gap-Closure Reconciliation

| Previous finding | Actual current-code result |
| --- | --- |
| New host sample coverage used `host:host` while readers used metrics. | Fixed for new writes: `worker_collect_system_stats()` loops `HOST_METRICS`, and API reads `host_stream_key(metric)`. The separate legacy-upgrade gap remains. |
| API used default policy/budget instead of deployed settings. | Fixed: `_telemetry_policy()` composes `RetentionPolicy.from_settings(SETTINGS)` and the route uses `policy` for resolution, query limit, retention, and response budget. |
| Expiry removed hourly buckets crossing a non-aligned 90-day cutoff. | Fixed: both hourly deletes require `bucket_start + bucket_seconds <= expiry_cutoff`. |
| Uncompacted raw evidence was omitted from historical reads. | Fixed: fixed raw/five-minute fallback queries exclude only intervals covered by a completed replacement. |
| Persisted retry backoff was not admitted by due time. | Fixed: raw and five-minute candidate queries join `telemetry_rollup_jobs` and require pending/failed `next_retry_ts <= now` (or NULL). |

## Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/beacon/migrations.py` | Transactional, additive telemetry schema and compatibility upgrade path | ⚠️ PARTIAL | Migrations 5/6 are substantive and tested, but no migration handles already-persisted shared host telemetry state. |
| `dashboard/beacon/telemetry.py` | Retention, rollup, coverage, and retry lifecycle | ✓ VERIFIED | Closed-bucket expiry, aggregate-before-delete savepoints, due-only admission, metric stream key helper, and pressure state helpers are substantive and worker-wired. |
| `dashboard/beacon/repositories.py` | Fixed, bounded, non-overlapping historical reads and pending disclosure | ✗ HOLLOW | Main tier/fallback reads are wired, parameterized, and bounded; derived five-minute pending interval width is false for both kinds. |
| `dashboard/app.py` | Sole-worker writers and bounded history API | ⚠️ PARTIAL | New writes and API policy are correctly wired, but neither provides legacy `host:host` evidence compatibility. |
| `tests/test_telemetry_retention.py` | Retention, authority, stream, pressure, and retry evidence | ⚠️ PARTIAL | Tests prove new-worker metric streams and original repairs; none seeds legacy shared state and proves upgrade/API preservation. |
| `tests/test_historical_telemetry_api.py` | Host/service fallback and pending API evidence | ⚠️ PARTIAL | Tests prove fallback/replacement paths; no host/service test asserts a five-minute derived pending interval ends at `+300`. |

## Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `worker_collect_system_stats()` | history coverage read | `host_stream_key(metric)` on both writer and API | ⚠️ PARTIAL | Correct for post-upgrade samples; no legacy-state conversion/read bridge. |
| `Settings` | worker cleanup and history API | `_telemetry_policy()` | ✓ WIRED | The shared immutable policy supplies cutoffs, resolution budget, query sentinel, and serialized `point_budget`. |
| `run_retention_batch()` | hourly rollups/retry jobs | closed-bucket expiry and due job predicates | ✓ WIRED | Every source class joins durable job state before batch admission; hourly deletes are bucket-end based. |
| fallback source rows | `partition_coverage()` | `SourceSegment` values become observed coverage | ✓ WIRED | Completed replacement `NOT EXISTS` predicates preserve exactly one contributing tier. |
| five-minute source rows | `aggregation_pending` | `_pending_source_rows()` → `get_pending_aggregation()` | ✗ NOT_WIRED CORRECTLY | Its 300-second sources are projected as 3,600-second intervals before coalescing. |

## Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| history route | `sources`, `coverage_data`, `pending` | SQLite repositories through a short-lived connection | Yes, except five-minute derived pending end timestamps | ⚠️ HOLLOW |
| host sampler | per-metric streams/gaps | live system sample → `stats_history`, `telemetry_streams`, `telemetry_coverage` | Yes for new samples; persisted legacy evidence is disconnected | ⚠️ HOLLOW |
| retention engine | rollups/jobs/events | raw tables and durable job rows | Yes | ✓ FLOWING |

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| New metric-specific worker streams and pressure gaps | `uv run --project dashboard python -m pytest -q ...test_real_worker_samples_use_metric_streams_and_close_pressure_gaps` | passed | ✓ PASS |
| Deployed policy parity | `uv run --project dashboard python -m pytest -q ...test_configured_policy_controls_worker_and_history_route` | passed | ✓ PASS |
| Closed hourly expiry | `uv run --project dashboard python -m pytest -q ...test_non_aligned_hourly_expiry_keeps_crossing_host_and_service_buckets` | passed | ✓ PASS |
| Due-only retries | `uv run --project dashboard python -m pytest -q ...test_pre_due_host_and_service_jobs_preserve_sources_until_exact_due_time` | passed | ✓ PASS |
| Pending source fallback ownership | `uv run --project dashboard python -m pytest -q ...test_host_five_minute_fallback_and_exact_cutoffs_have_one_owner` | passed | ✓ PASS |

The five named checks ran together and completed as **5 passed, 6 subtests passed in 0.34s**. They establish the original repair paths but do not cover either newly identified failure.

## Probe Execution

SKIPPED — no Phase 2 probe declaration or `scripts/**/tests/probe-*.sh` file exists.

## Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| TEL-01 | 02-02, 02-03, 02-04, 02-05, 02-08 | Rolling 90-day bounded host/service/event retention | ✓ SATISFIED | Closed-bucket expiry, strict event deletion, and bounded due-only rollup processing are implemented and focused-tested. |
| TEL-02 | 02-02, 02-03, 02-04, 02-06, 02-07, 02-09 | Detailed recent evidence and documented older aggregates | ✓ SATISFIED | Retained raw/five-minute fallback stays queryable until the completed aggregate owns the interval. |
| TEL-03 | 02-02, 02-03, 02-04, 02-05, 02-08, 02-09 | Aggregate completed before source deletion | ✓ SATISFIED | Aggregate read-back precedes exact source deletion; pre-due jobs retain sources and succeeded jobs are not repeated. |
| TEL-04 | 02-01, 02-05, 02-06, 02-07, 02-09 | Explicit known, unknown, collection-gap, and expiry history | ✗ BLOCKED | Legacy `host:host` coverage and pressure state is stranded from per-metric API reads. |
| TEL-05 | 02-01, 02-06, 02-07 | Appropriate server-side resolution and bounded response budget | ✗ BLOCKED | Policy/budget selection is correct, but five-minute pending disclosure overstates the actual range by 3,300 seconds. |

Every TEL-01 through TEL-05 requirement appears in at least one plan frontmatter and maps to Phase 2 in `REQUIREMENTS.md`; no Phase 2 requirement is orphaned.

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/beacon/migrations.py` | 300-308 | Missing durable upgrade for shared host evidence | 🛑 Blocker | Historical stored gap/pressure evidence can be silently hidden after upgrade. |
| `dashboard/beacon/repositories.py` | 425-457 | `bucket_seconds=300` projected as `+3600` | 🛑 Blocker | `aggregation_pending` can disclose a full hour with only five minutes of source work. |

No unreferenced `TBD`, `FIXME`, or `XXX` marker was found in the Phase 2 implementation or focused test files.

## Gaps Summary

The original five defects have executable repairs and focused passing evidence. Phase 2 nevertheless remains incomplete: a real upgrade can lose access to pre-existing collection-gap/pressure evidence, and a normal five-minute compaction backlog is reported as an hour. Neither issue is assigned to a later roadmap phase; Phase 3/4 add diagnosis and visualization on top of this data contract, so both are current Phase 2 correctness gaps.

**Next action:** Run `$gsd-plan-phase 2 --gaps` to plan the two scoped repairs, then re-run `$gsd-execute-phase 2 --gaps-only`.

_Verified: 2026-08-11T00:00:00Z_
_Verifier: the agent (gsd-verifier)_
