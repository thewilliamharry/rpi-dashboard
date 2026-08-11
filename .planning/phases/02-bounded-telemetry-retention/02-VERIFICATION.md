---
phase: 02-bounded-telemetry-retention
verified: 2026-08-11T12:03:51Z
status: gaps_found
score: 3/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 2/4
  gaps_closed:
    - "Existing version-6 host:host stream and coverage evidence migrates to canonical cpu, ram, disk, and temp identities."
    - "Canonical host history endpoints expose migrated collection-gap coverage while the shared raw-rollup job identity remains host:host."
    - "Five-minute host and service pending ranges use exact 300-second half-open intervals with equality-only adjacency coalescing."
  gaps_remaining:
    - "A present JSON-null host:host pressure entry is accepted as absent, so Migration 7 publishes successfully without removing or rejecting the obsolete malformed identity."
  regressions: []
gaps:
  - truth: "Legacy host:host is removed from telemetry_streams, telemetry_coverage, and telemetry_retention_state.pressure_gaps after a successful Migration 7; malformed legacy pressure values fail closed."
    status: failed
    reason: "Migration 7 uses pressure_gaps.get('host:host'), so a present JSON null is indistinguishable from an absent key. It then deletes legacy stream and coverage rows, records schema version 7, and leaves the malformed host:host pressure key behind."
    artifacts:
      - path: "dashboard/beacon/migrations.py"
        issue: "Lines 387-391 validate only non-null values and lines 451-468 remove the key only when its value is non-null."
      - path: "tests/test_migrations.py"
        issue: "The malformed-state rollback test covers boolean true but not JSON null."
    missing:
      - "Distinguish key presence from its value, reject any present non-integer (including null) before mutating data, and add a rollback regression proving a null host:host value leaves the database at version 6."
---

# Phase 2: Bounded Telemetry & Retention Verification Report

**Phase Goal:** Beacon maintains an accurate, bounded 90-day telemetry record whose resolution, gaps, and retention rules remain trustworthy under normal operation.
**Verified:** 2026-08-11T12:03:51Z
**Status:** gaps_found
**Re-verification:** Yes — after the 02-10 and 02-11 gap-closure plans

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Beacon retains host metrics, service history, and events for a rolling 90 days without unbounded database growth. | ✓ VERIFIED | `run_retention_batch()` expires only fully closed hourly buckets (`bucket_start + bucket_seconds <= cutoff`) and events older than the strict 90-day cutoff. Candidate admission is bounded and due-only. The focused retention regressions had already passed, and the phase’s final full suite was green. |
| 2 | Recent observations remain detailed while older history is represented by documented aggregates, with each aggregate completed before its source data is removed. | ✓ VERIFIED | The retention batch uses per-bucket savepoints; each rollup is inserted and read back before its exact source deletion. Repository fallback queries retain raw/5-minute evidence until a completed replacement owns the interval. |
| 3 | A requested historical range explicitly distinguishes observed values from collection gaps, unknown intervals, and data that has expired under retention. | ✗ FAILED | Normal legacy host coverage migrates and is visible to all four host endpoints, but a present malformed `host:host: null` pressure key bypasses Migration 7 validation/removal while the migration is published. The compatibility migration therefore falsely reports completion with an obsolete invalid pressure identity still persisted. |
| 4 | Beacon selects an appropriate server-side resolution for each historical request and returns a bounded number of points without misleading the operator about coverage. | ✓ VERIFIED | The route composes one Settings-derived `RetentionPolicy`, passes its point budget to fixed repository queries, returns it in `point_budget`, and emits `bucket_start + 300` for both host and service five-minute pending rows. Direct focused tests passed. |

**Score:** 3/4 roadmap success criteria verified.

## Re-verification of Prior Gaps

| Prior concern | Current code evidence | Result |
| --- | --- | --- |
| Canonical new host streams vs. shared `host:host` reads | `worker_collect_system_stats()` writes/opens/closes each `host_stream_key(metric)`; the history route reads the same metric key. | ✓ Closed |
| Deployed policy parity | `_telemetry_policy()` builds `RetentionPolicy.from_settings(SETTINGS)` and supplies it to both cleanup and history responses. | ✓ Closed |
| Non-aligned hourly expiry | Hourly host/service deletes require bucket end at or before the cutoff. | ✓ Closed |
| Pending compaction hiding source evidence | Raw/5-minute fallback queries exclude source rows only when a completed replacement exists. | ✓ Closed |
| Retry before persisted due time | Candidate queries join job state and require a due `next_retry_ts`. | ✓ Closed |
| Legacy host stream/coverage conversion | Migration 7 expands normal v6 `host:host` metadata and coverage into all four canonical metric streams; the Flask regression verifies each endpoint; raw rollup jobs deliberately keep shared `host:host`. | ✓ Closed |
| Five-minute pending width/coalescing | Host and service projections use `bucket_start + 300`; coalescing requires exact boundary equality. | ✓ Closed |
| JSON-null legacy pressure key | A present `host:host: null` is treated as absent, then survives migration version publication. | ✗ Open blocker |

## Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/beacon/migrations.py` | Transactional, idempotent v7 conversion of legacy host stream, coverage, and pressure state | ✗ PARTIAL | Correctly migrates valid evidence and preserves shared raw rollup-job identity, but accepts JSON null rather than rejecting it or removing the key. |
| `dashboard/beacon/telemetry.py` | Bounded retention, aggregate-before-delete, coverage, pressure, and retry lifecycle | ✓ VERIFIED | Worker-owned batching, closed-bucket expiry, exact source deletion after verification, and due-only retries are substantive and wired. |
| `dashboard/beacon/repositories.py` | Fixed, bounded historical reads and truthful pending disclosure | ✓ VERIFIED | Host/service five-minute derived pending SQL now uses `bucket_start + 300`; durable jobs take precedence and exact adjacency is the only coalescing condition. |
| `dashboard/app.py` | Per-metric writing plus policy-aware bounded history API | ✓ VERIFIED | Worker and route use the canonical stream key and shared Settings-derived policy. |
| `tests/test_migrations.py` | v7 valid-state, overlap, idempotence, and rollback evidence | ⚠️ PARTIAL | Valid legacy migration, generic rollback, and boolean malformed pressure state are tested; JSON null is not. |
| `tests/test_historical_telemetry_api.py` | API-visible migration and exact pending evidence | ✓ VERIFIED | Covers all host metric endpoints plus host/service exact width, adjacency, empty, order, and durable-precedence cases. |

## Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `worker_collect_system_stats()` | `api_telemetry_history()` | `host_stream_key(metric)` at both write and read boundaries | ✓ WIRED | All new host evidence is canonical metric-specific. |
| `_migration_7_canonical_host_streams()` | `telemetry_streams` / `telemetry_coverage` / `runtime_state` | One runner-owned transaction | ⚠️ PARTIAL | Stream and coverage migration are transactional; null pressure-state handling is neither rejected nor completed. |
| `get_pending_aggregation()` | history response `aggregation_pending` | fixed selector SQL and `bucket_start + 300` five-minute projections | ✓ WIRED | Host/service regressions directly assert repository and Flask response output. |
| `RetentionPolicy.from_settings()` | cleanup and history API | `_telemetry_policy()` | ✓ WIRED | The policy controls cutoff, resolution budget, repository limit, response check, and serialized budget. |

## Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| History response | points, coverage, aggregation_pending | SQLite source/rollup/coverage/job tables via repositories | Yes; parameterized queries return real rows and coverage is composed from source segments plus sparse ledger. | ✓ FLOWING |
| Host worker path | per-metric streams and pressure gaps | live system sample → `stats_history` + canonical telemetry state | Yes for valid persisted state; malformed legacy JSON-null state remains an invalid migration edge. | ⚠️ PARTIAL |
| Retention batch | aggregate/job/source lifecycle | source observations + durable retry rows | Yes; read-back occurs before delete and retries are admitted only when due. | ✓ FLOWING |

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Valid v6 legacy migration, rollback, all metric history endpoints, and exact pending output | `uv run --project dashboard python -m pytest -q tests/test_migrations.py tests/test_historical_telemetry_api.py -k 'current_v6 or migration_seven or legacy_host_upgrade or five_minute and pending' -x` | `7 passed, 34 deselected in 0.24s` | ✓ PASS |
| JSON-null legacy pressure-state migration | Disposable v6 fixture copied to `/private/tmp`; write `pressure_gaps.host:host = null`, run migration, inspect database | Migration applied `(7,)`, database version became `7`, and `legacy_pressure_key_present` was `True`. | ✗ FAIL |

The full Phase 2 suite was reported green after both final execution waves. This verifier independently ran the focused 7-test migration/API matrix above and reproduced the remaining null-state defect in an isolated copy; it did not rerun the full suite.

## Probe Execution

SKIPPED — no Phase 2 probe was declared and no `scripts/**/tests/probe-*.sh` exists.

## Requirements Coverage

| Requirement | Status | Evidence |
| --- | --- | --- |
| TEL-01 | ✓ SATISFIED | Rolling raw/aggregate/event retention, closed-bucket expiry, bounded batch size, and storage-pressure retention controls are implemented. |
| TEL-02 | ✓ SATISFIED | Raw/five-minute source fallback remains queryable until a completed replacement aggregate owns the same half-open interval. |
| TEL-03 | ✓ SATISFIED | Savepoint-contained aggregate read-back precedes exact source deletion; failed/pending jobs preserve evidence until their retry is due. |
| TEL-04 | ✗ BLOCKED | Migration 7 must migrate or fail closed for every persisted legacy pressure entry. JSON null instead advances the schema while leaving the obsolete invalid identity, violating the phase compatibility and truthful-gap contract. |
| TEL-05 | ✓ SATISFIED | Settings-derived resolution/point budget is enforced at route, repository, composition, and response boundaries; exact 300-second pending intervals no longer misstate coverage. |

All TEL-01 through TEL-05 requirements are declared by Phase 2 plans; none is orphaned. No later roadmap phase specifically owns correction of a Phase 2 migration’s malformed-state transaction, so this blocker is not deferred.

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `dashboard/beacon/migrations.py` | 387-391, 451-468 | `.get()` conflates an absent key with a present JSON-null legacy pressure value. | 🛑 BLOCKER | A success-versioned migration leaves an invalid obsolete state identity and defeats the specified malformed-state fail-closed boundary. |

No unreferenced `TBD`, `FIXME`, or `XXX` marker was found in the Phase 2 implementation or focused test files.

## Gaps Summary

Migration 7 is correct for valid legacy `host:host` data: streams and coverage are expanded into cpu, ram, disk, and temp; canonical coverage wins overlaps; all four historical APIs expose the migrated gap; and the shared raw rollup job remains intentionally unchanged. Plan 11 also closes the false one-hour pending disclosure with exact 300-second host/service intervals.

However, a persisted `{"host:host": null}` is malformed legacy state. The migration currently treats it as absent and publishes version 7 after deleting the other shared records, leaving the invalid obsolete key. This is not merely cosmetic: it marks canonicalisation complete without enforcing the data-integrity boundary the migration advertises, and TEL-04’s trustworthy historical-gap compatibility contract depends on that boundary. The phase therefore cannot pass until this state either fails the migration transaction or is explicitly and safely normalized under an approved contract.

**Next action:** Run `$gsd-plan-phase 2 --gaps` to add the small Migration 7 validation/rollback repair, then `$gsd-execute-phase 2 --gaps-only`.

_Verified: 2026-08-11T12:03:51Z_
_Verifier: the agent (gsd-verifier)_
