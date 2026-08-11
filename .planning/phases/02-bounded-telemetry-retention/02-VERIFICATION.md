---
phase: 02-bounded-telemetry-retention
verified: 2026-08-11T16:35:35Z
status: passed
score: 4/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 3/4
  gaps_closed:
    - "Migration 7 now rejects a present JSON-null or other malformed legacy host:host pressure value before any durable mutation."
  gaps_remaining: []
  regressions: []
---

# Phase 2: Bounded Telemetry & Retention Verification Report

**Phase Goal:** Beacon maintains an accurate, bounded 90-day telemetry record whose resolution, gaps, and retention rules remain trustworthy under normal operation.
**Verified:** 2026-08-11T16:35:35Z
**Status:** passed
**Re-verification:** Yes — after gap closure plan 02-12

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Beacon retains host metrics, service history, and events for a rolling 90 days without unbounded database growth. | ✓ VERIFIED | `run_retention_batch()` applies the Settings-derived 90-day policy, deletes hourly host/service rollups only where `bucket_start + bucket_seconds <= cutoff`, and expires events where `ts < cutoff`. Candidate SQL is batch-limited and admits pending/failed retry work only when `next_retry_ts` is null or due. Focused retention regressions passed. |
| 2 | Recent observations remain detailed while older history is represented by documented aggregates, with each aggregate completed before its source data is removed. | ✓ VERIFIED | The retention engine keeps raw data for 7 days, five-minute data through day 30, and hourly data through day 90. Each rollup calls `_upsert_and_verify()`, marks its job succeeded, and only then deletes its exact half-open source interval inside the transaction/savepoint. Repository fallback queries continue returning raw/five-minute evidence until a completed replacement aggregate owns it. |
| 3 | A requested historical range explicitly distinguishes observed values from collection gaps, unknown intervals, and data that has expired under retention. | ✓ VERIFIED | The history route partitions requested bounds using persisted coverage, source segments, and the retention cutoff. Migration 7 canonicalizes valid legacy `host:host` evidence, while present malformed pressure values—including JSON `null`—raise before stream, coverage, retention-state, or schema-version mutation. The runner's `BEGIN IMMEDIATE` transaction rolls the failed migration back to exact version-6 evidence. |
| 4 | Beacon selects an appropriate server-side resolution for each historical request and returns a bounded number of points without misleading the operator about coverage. | ✓ VERIFIED | `/api/telemetry/history` validates a half-open request, selects server resolution, passes `point_budget + 1` to fixed repository queries, rejects overflow, and returns the effective resolution, disclosed budget, source resolutions, coverage, and pending aggregation separately. Host/service five-minute pending intervals are exactly `[bucket_start, bucket_start + 300)` and only exactly touching pending intervals coalesce. |

**Score:** 4/4 roadmap success criteria verified.

## Historical Gap Closure: Migration 7

| Required property | Code and test evidence | Status |
| --- | --- | --- |
| Absent `pressure_gaps["host:host"]` is a valid pressure-state no-op. | The presence flag is false when the key is absent; `test_migration_seven_absent_legacy_pressure_key_is_a_successful_no_op` passes. Normal legacy stream/coverage conversion remains allowed. | ✓ VERIFIED |
| Present JSON `null` or another malformed pressure value fails before mutation. | `_migration_7_canonical_host_streams()` distinguishes membership from `.get()` and accepts only a non-boolean `int`; JSON null, booleans, string, float, list, and object are covered by named regressions. | ✓ VERIFIED |
| Failure leaves v6 schema and all legacy evidence/job state unchanged. | The validation occurs before canonical stream/coverage writes. `run_migrations()` wraps helper execution and version-7 insertion in one `BEGIN IMMEDIATE` transaction. Snapshot tests compare telemetry streams, coverage, exact retention JSON, rollup jobs, and `schema_migrations` before/after each failure. | ✓ VERIFIED |
| Valid integers expand/removal is correct and idempotent. | Valid `host:host` pressure time expands to cpu/ram/disk/temp using earliest canonical time, removes the obsolete key, preserves unrelated state and the intentional raw-rollup job key `host:host`; helper re-entry and a second runner execution make no change. | ✓ VERIFIED |

## Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- |
| `dashboard/beacon/migrations.py` | Transactional v5–v7 telemetry schema and legacy canonicalization | ✓ VERIFIED | Migration 7's presence-aware validation precedes mutations; migration runner commits schema version only after successful helper return. |
| `dashboard/beacon/telemetry.py` | Tiered retention, rollup-before-delete, pressure and retry lifecycle | ✓ VERIFIED | Savepoint-contained rollups, read-back verification, due-only candidates, closed-bucket expiry, and event expiry are substantive. |
| `dashboard/beacon/repositories.py` | Fixed bounded reads and truthful pending disclosure | ✓ VERIFIED | Completed replacements suppress only their owned source interval; fallback remains observable; five-minute pending end is `+ 300` and coalescing needs equality. |
| `dashboard/app.py` | Canonical worker writes and policy-aware historical API | ✓ VERIFIED | Worker writes per-metric canonical host streams; route composes one Settings-backed policy and returns real SQLite history/coverage/pending data. |
| `tests/test_migrations.py` | Migration 7 valid, absent, malformed, rollback, and idempotence proof | ✓ VERIFIED | The test suite snapshots all version-6 evidence and exercises null plus each malformed JSON type. |
| `tests/test_telemetry_retention.py` and `tests/test_historical_telemetry_api.py` | Retention and API contract proof | ✓ VERIFIED | Tests cover closed expiry, due retries, aggregate ownership/fallback, bounded response, and exact host/service pending intervals. |

## Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- |
| `worker_collect_system_stats()` | `api_telemetry_history()` | Shared `host_stream_key(metric)` identities | ✓ WIRED | New host evidence writes each canonical metric; host history reads the same metric identity. |
| `_migration_7_canonical_host_streams()` | `schema_migrations` | One runner-owned immediate SQLite transaction | ✓ WIRED | A validation exception prevents both data publication and version-7 insertion; tests prove snapshot equality after failure. |
| `run_retention_batch()` | host/service source tables | `_upsert_and_verify()` then succeeded job then exact source delete | ✓ WIRED | Aggregate visibility is confirmed before source deletion and failed work is retained for due retry. |
| `RetentionPolicy.from_settings()` | cleanup and history response | `_telemetry_policy()` | ✓ WIRED | A single policy controls cutoffs, resolution selection, repository limit, overflow enforcement, and response budget. |
| `get_pending_aggregation()` | history response | fixed host/service SQL and response serialization | ✓ WIRED | Durable jobs take exact interval precedence; derived five-minute intervals use 300 seconds and stay outside coverage states. |

## Data-Flow Trace

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Historical response | points, coverage, aggregation_pending | SQLite source/rollup/coverage/job tables | Yes; fixed parameterized queries feed the route and response composition. | ✓ FLOWING |
| Host collection path | per-metric streams and pressure gaps | live sample → `stats_history`/runtime state/telemetry streams | Yes; all four metric identities are recorded after a persisted history sample. | ✓ FLOWING |
| Retention batch | aggregate/job/source lifecycle | source observations plus durable rollup jobs | Yes; verified aggregates and due retry state determine deletion/admission. | ✓ FLOWING |

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Migration 7 absent, valid, malformed, rollback, expansion/removal, and idempotency | `uv run --project dashboard python -m pytest -q tests/test_migrations.py -k 'migration_seven or current_v6_legacy_host_state' -x` | Included in independent focused matrix; 17 tests/8 subtests total passed. | ✓ PASS |
| Closed hourly expiry and exact due-time retry admission | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py -k 'non_aligned_hourly_expiry or pre_due_host_and_service or deferred_and_succeeded_jobs' -x` | Included in independent focused matrix; passed. | ✓ PASS |
| Fallback ownership, point budget, and exact host/service five-minute pending intervals | `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py -k 'five_minute_pending or fallback or point_budget' -x` | Included in independent focused matrix; passed. | ✓ PASS |

**Independent command actually run:**

```text
uv run --project dashboard python -m pytest -q tests/test_migrations.py tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py -k 'migration_seven or current_v6_legacy_host_state or non_aligned_hourly_expiry or pre_due_host_and_service or deferred_and_succeeded_jobs or five_minute_pending or fallback or point_budget' -x
17 passed, 43 deselected, 8 subtests passed in 0.62s
```

## Probe Execution

SKIPPED — Phase 2 declares no probe and `scripts/**/tests/probe-*.sh` is absent.

## Requirements Coverage

| Requirement | Source plans | Status | Evidence |
| --- | --- | --- | --- |
| TEL-01 | 02-02, 02-03, 02-04, 02-05, 02-08 | ✓ SATISFIED | Rolling raw/aggregate/event retention, bounded candidate batches, closed-hour expiry, and pressure controls are implemented and tested. |
| TEL-02 | 02-02, 02-03, 02-04, 02-06, 02-07, 02-09 | ✓ SATISFIED | The documented 7-day/30-day/90-day tiers retain detailed lower-tier evidence until a completed aggregate owns it. |
| TEL-03 | 02-02, 02-03, 02-04, 02-05, 02-08, 02-09 | ✓ SATISFIED | Upsert/read-back verification and success-marking precede exact source deletion; pre-due failures preserve sources. |
| TEL-04 | 02-01, 02-05, 02-06, 02-07, 02-09, 02-10, 02-11, 02-12 | ✓ SATISFIED | Coverage partitioning exposes observed/gap/unknown/expired semantics; Migration 7 either fully canonicalizes valid evidence or rolls malformed state back. |
| TEL-05 | 02-01, 02-06, 02-07, 02-11 | ✓ SATISFIED | Server-side resolution selection, point-budget enforcement, bounded repository limits, and honest 300-second pending ranges are verified. |

All TEL-01 through TEL-05 are claimed by Phase 2 plans. No requirement is orphaned. No later roadmap phase owns an outstanding Phase 2 defect.

## Anti-Patterns Found

None. The Phase 2 implementation and focused test files contain no unreferenced `TBD`, `FIXME`, or `XXX` marker and no user-visible stub/hardcoded-empty implementation.

## Human Verification Required

None. Every roadmap success criterion is backend behavior exercised by the focused automated evidence above; no visual, external-service, or unexercised state-transition claim remains.

## Conclusion

Phase 2's goal is achieved. The prior blocker is closed: a present malformed `host:host` pressure value can no longer be mistaken for absence or leave malformed state behind a published Migration 7. Host/service telemetry retention, tier transitions, query coverage, resolution budget, pending intervals, and retry behavior remain code-backed and regression-tested.

**Next action:** Mark Phase 2 complete in orchestrator state, then proceed with `$gsd-plan-phase 3`.

_Verified: 2026-08-11T16:35:35Z_
_Verifier: the agent (gsd-verifier)_
