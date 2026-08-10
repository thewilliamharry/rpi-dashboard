# Phase 2: Bounded Telemetry & Retention - Research

**Researched:** 2026-08-10  
**Domain:** SQLite-backed time-series retention, rollups, coverage semantics, and bounded historical APIs  
**Confidence:** MEDIUM

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Retain raw host metrics and service observations for 7 days. — **Reversibility:** costly — changing this after release affects storage sizing, rollup boundaries, cleanup behavior, and the historical API contract.
- **D-02:** Represent days 8 through 30 with 5-minute aggregates and days 31 through 90 with hourly aggregates. Telemetry older than 90 days is expired and deleted. — **Reversibility:** one-way — once source observations or aggregates expire, later policy changes cannot recover them.
- **D-03:** Retain individual operational events in full for the entire 90-day window; do not aggregate events into counts that replace the original records. — **Reversibility:** one-way — expiring individual event records earlier would permanently remove incident evidence.
- **D-04:** Host aggregate buckets preserve minimum, maximum, average, latest, and sample count. Service aggregate buckets preserve time-weighted online, offline, and unknown duration; latency minimum, maximum, and average; check count; and failure-class counts. — **Reversibility:** costly — Phase 4 range summaries and investigations will depend on this aggregate contract.
- **D-05:** Every unavailable historical interval has one explicit reason: `collection_gap`, `unknown`, `expired`, or `not_yet_monitored`. — **Reversibility:** costly — these reason values become a historical API vocabulary consumed by later analytics views.
- **D-06:** Confirm a `collection_gap` after two expected observations are missed according to that stream's configured cadence. The gap begins at the first missed boundary and ends at the next valid observation.
- **D-07:** For buckets containing mixed coverage, compute statistics only from observed values and separately report observed, gap, and unknown duration plus sample counts. Never interpolate across unavailable intervals.
- **D-08:** Historical responses preserve the caller's full requested time bounds and explicitly represent retained observations, `expired` intervals, and `not_yet_monitored` intervals with coverage metadata. Do not silently clamp the requested range. — **Reversibility:** costly — range consumers will depend on stable requested/effective bounds and coverage semantics.
- **D-09:** When a rollup fails, preserve all unaggregated source observations, expose the affected interval as pending aggregation, record the failure, and retry automatically with bounded backoff. Source observations are never deleted before their rollup succeeds. — **Reversibility:** one-way — premature deletion would permanently violate TEL-03 and lose evidence.
- **D-10:** Protect storage with two guardrails: a configurable maximum telemetry/database allocation and a minimum free-disk reserve. Enter pressure handling when either boundary is approached.
- **D-11:** Maintain a bounded emergency reserve for rollup backlog. If it is exhausted, keep live monitoring and current-state updates running but suspend new historical persistence; record the interval as an explicit `storage_pressure` collection gap. Never delete unaggregated evidence merely to make room.
- **D-12:** Recover historical persistence automatically only after storage falls below a lower safe threshold. Preserve the pressure interval as a gap, clear the degraded state automatically, and do not reconstruct or interpolate missed history.

### the Agent's Discretion

- Choose exact default byte limits, minimum-free-space values, warning thresholds, lower recovery thresholds, and hysteresis margins appropriate for Raspberry Pi deployments.
- Choose bounded retry/backoff timing and the schema/module boundaries that implement the locked retention and coverage contracts.
- Choose the server-side response-point budget and deterministic resolution-selection thresholds, provided responses remain bounded and accurately disclose their effective resolution and coverage.

### Deferred Ideas (OUT OF SCOPE)

- Consider retaining hourly telemetry aggregates through day 365 in a future phase. This expands the locked 90-day retention capability and requires a separate roadmap/requirements decision.
</user_constraints>

## Project Constraints (from AGENTS.md)

- Preserve self-contained 64-bit Raspberry Pi Docker Compose deployment; do not introduce a hosted backend. [VERIFIED: AGENTS.md]
- Keep monitoring to one host Pi plus trusted configured/discovered LAN or web services. [VERIFIED: AGENTS.md]
- Maintain narrow, testable boundaries for outbound fetching and mutation endpoints. [VERIFIED: AGENTS.md]
- Preserve existing useful capabilities and stored data unless an approved migration replaces them. [VERIFIED: AGENTS.md]
- Avoid visible sampling gaps and dashboard unresponsiveness on Pi-class hardware. [VERIFIED: AGENTS.md]
- Use explicit module boundaries and testable interfaces instead of increasing the monolith. [VERIFIED: AGENTS.md]
- Follow readable PEP 8 Python, snake_case names, narrow exception handling, versioned migrations, and real temporary-SQLite pytest patterns. [VERIFIED: AGENTS.md]

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TEL-01 | Retain rolling 90 days of bounded host metrics, service history, and events. | Fixed retention ladder, sparse coverage ledger, capped storage and event-expiry transaction. |
| TEL-02 | Preserve recent observations and documented aggregates for older ranges. | Exact raw/5-minute/hourly tier boundaries and aggregate schemas. |
| TEL-03 | Complete rollups before deleting source observations. | One authority-fenced transaction inserts/verifies aggregate then deletes its exact source range. |
| TEL-04 | Distinguish known values, unknown intervals, collection gaps, and expiry. | Exhaustive coverage response plus durable sparse gap intervals. |
| TEL-05 | Select resolution and cap response points. | Deterministic 2,048-point server selection and response metadata. |
</phase_requirements>

## Summary

Use the existing SQLite database, migration gate, and sole worker-owned cleanup callback; introduce no package, service, ORM, or second scheduler. [VERIFIED: AGENTS.md] [VERIFIED: codebase grep] The current implementation stores one-minute host history, service checks, and events, but the worker cleanup callback deletes them after one day, eight days, and fourteen days respectively; Phase 2 must replace those age-only deletes with tiered rollup and coverage-aware retention. [VERIFIED: codebase grep]

The implementation must treat a rollup as evidence preservation, not cache compaction: write one uniquely keyed complete bucket, verify its coverage and aggregate fields, then delete only the exact source rows in the same short authority-fenced transaction. [CITED: https://www.sqlite.org/lang_transaction.html] Existing worker writes already enter `BEGIN IMMEDIATE`, verify the durable worker epoch, commit or roll back, and close the connection; extend that boundary rather than making a maintenance lock or process-local mutex the retention authority. [VERIFIED: codebase grep]

Historical reads need an explicit contract, separate from the existing one-day `/api/history` compatibility response: retain requested bounds, choose a server display bucket under a documented point budget, and return an exhaustive coalesced coverage partition. [ASSUMED] `expired`, `not_yet_monitored`, `collection_gap`, and `unknown` are availability reasons, while observed values remain data points; never use a numeric sentinel or interpolate a missing interval. [VERIFIED: 02-CONTEXT.md]

**Primary recommendation:** Build a `telemetry` persistence/repository module and a single idempotent worker `telemetry_retention` callback that produces durable rollups and coverage before source deletion.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Metric and probe observation persistence | API / Backend | Database / Storage | The worker owns collection and writes observations through SQLite. [VERIFIED: codebase grep] |
| Rollup, retention, retry, and pressure recovery | API / Backend | Database / Storage | Only the durable-lease worker may mutate shared telemetry tables. [VERIFIED: codebase grep] |
| Aggregate, coverage, and retention-state storage | Database / Storage | — | SQLite remains Beacon's source of truth on the writable `/data` volume. [VERIFIED: AGENTS.md] |
| Historical range and resolution selection | API / Backend | Database / Storage | The server can cap query work and state the effective resolution before data reaches a browser. [ASSUMED] |
| Rendering charts/labels later | Browser / Client | API / Backend | Later phases consume explicit values and coverage; this phase does not add analytics presentation. [VERIFIED: 02-CONTEXT.md] |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Python stdlib `sqlite3` | Runtime SQLite 3.51.0 in the research environment | Transactional telemetry, rollups, and bounded queries | The project already uses it with WAL-oriented connection settings and shared-process access controls. [VERIFIED: codebase grep] |
| APScheduler | 3.11.3 pinned | Run the single worker-owned retention callback | The project already uses it with `coalesce=True` and `max_instances=1`; APScheduler documents this combination for limiting overlapping/missed executions. [VERIFIED: dashboard/pyproject.toml] [CITED: https://apscheduler.readthedocs.io/en/3.x/userguide.html] |
| Flask | 3.1.3 pinned | Expose a bounded historical JSON API | The existing web process owns API responses while the worker owns scheduled mutation. [VERIFIED: dashboard/pyproject.toml] [VERIFIED: codebase grep] |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `shutil.disk_usage()` | Python stdlib | Measure free bytes on the database filesystem | Run before and after bounded retention work; do not shell out to `df` in production. [ASSUMED] |
| `os.stat()` | Python stdlib | Measure SQLite, `-wal`, and `-shm` footprint | Include all three files when enforcing allocation. [CITED: https://www.sqlite.org/wal.html] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| SQLite rollups | TimescaleDB/InfluxDB or a hosted telemetry service | These expand deployment, storage, and operational scope contrary to the self-contained Pi constraint. [VERIFIED: AGENTS.md] |
| Durable aggregate tables | On-read calculation from raw history | Raw evidence is intentionally deleted after seven days, so on-read aggregation cannot serve the 90-day contract. [VERIFIED: 02-CONTEXT.md] |
| Sparse coverage ledger | Numeric sentinels/interpolation | Sentinels and interpolation cannot preserve the required reason vocabulary or mixed coverage truthfully. [VERIFIED: 02-CONTEXT.md] |

**Installation:** No new external package is required. [VERIFIED: dashboard/pyproject.toml]

## Architecture Patterns

### System Architecture Diagram

```text
metric sampler / service probes
              |
              v
  raw stats_history + service_checks  ----->  coverage interval ledger
              |                                       |
              | (worker lease + BEGIN IMMEDIATE)      |
              v                                       v
  telemetry retention callback ---> rollup job state / failure record
              |                 (retry with bounded backoff)
              | success: aggregate written and verified
              v
  delete exact eligible raw source rows -----> 5-minute / hourly rollup tables
              |                                      |
              +-----> expire >90-day events/data -----+
                                                     |
web historical range request --> validate bounds --> select display bucket <= budget
                                                     |
                                                     v
                            points + requested bounds + effective resolution + coverage
```

SQLite WAL supports concurrent readers and one writer, but a long read can prevent checkpoint progress and grow the WAL; therefore both retention mutation and historical reads must be bounded and promptly close their cursors/connections. [CITED: https://www.sqlite.org/wal.html]

### Recommended Project Structure

```text
dashboard/beacon/
├── migrations.py              # additive telemetry schema migration
├── telemetry.py               # pure bucket, coverage, retention, and pressure policy
├── repositories.py            # parameterized historical range and aggregate reads
├── monitoring.py              # observation writers call telemetry registration seam
├── worker_main.py             # one new/in-place retention callback registration
└── web.py or app.py           # validate and serialize historical response adapter
tests/
├── test_telemetry_retention.py
└── test_historical_telemetry_api.py
```

Keep `telemetry.py` Flask-free and provide it an already-open connection/authority through the existing operation adapters. [VERIFIED: dashboard/beacon/repositories.py] [VERIFIED: dashboard/beacon/worker_main.py]

### Pattern 1: Canonical UTC bucket keys and tier boundary ownership

**What:** Store integer UTC `bucket_start`, positive `bucket_seconds`, and a unique stream key; generate buckets from a single shared function, never from display-local time. [CITED: https://www.sqlite.org/lang_datefunc.html]

**When to use:** Every rollup insert, raw eligibility predicate, coverage interval, and history response. [ASSUMED]

**Recommended contract:** Raw rows are eligible only when their whole destination bucket is closed and its end is at or before the raw cutoff; 5-minute buckets remain through day 30, hourly buckets through day 90, and cutoff comparisons use the injected worker clock. [VERIFIED: 02-CONTEXT.md]

```python
# Source: project retention contract + SQLite Unix-epoch documentation
def bucket_start(ts: int, seconds: int) -> int:
    return (int(ts) // seconds) * seconds

def is_complete_bucket(start: int, seconds: int, raw_cutoff: int) -> bool:
    return start + seconds <= raw_cutoff
```

### Pattern 2: Aggregate-before-delete as one idempotent transaction

**What:** Claim a bounded eligible range, derive aggregate plus coverage from all source rows, upsert a row keyed by `(stream, bucket_start, bucket_seconds)`, assert the stored result, then delete only sources in that exact closed range before committing. [VERIFIED: 02-CONTEXT.md]

**When to use:** The hourly worker retention callback and each retry. [ASSUMED]

```python
# Source: existing _worker_write_transaction() and SQLite transaction documentation
with _worker_write_transaction(authority, now=now) as conn:
    bucket = build_complete_rollup(conn, stream, bucket_start, bucket_seconds)
    upsert_rollup(conn, bucket)  # uniqueness makes a retry safe
    assert_rollup_complete(conn, bucket)
    delete_raw_sources(conn, stream, bucket.start, bucket.end)
    mark_rollup_succeeded(conn, bucket)
```

The transaction must be small and batch a fixed number of buckets because SQLite permits only one write transaction at a time and a large transaction can create a large WAL file. [CITED: https://www.sqlite.org/lang_transaction.html] [CITED: https://www.sqlite.org/wal.html]

### Pattern 3: Sparse, exhaustive coverage intervals

**What:** Persist only non-observed intervals in `telemetry_coverage(stream_kind, service_port, start_ts, end_ts, reason, detail)` with non-overlap validation; coalesce adjacent equal-reason intervals. [ASSUMED]

**When to use:** After two missed expected cadence boundaries, when a service probe has no determinable state, during historical-persistence suspension, and when an eligible retention tier expires. [VERIFIED: 02-CONTEXT.md]

**Recommended cadence rule:** The host base cadence is the configured `METRIC_HISTORY_SECONDS` (currently 60 seconds); the service base cadence is the full-service five-minute probe, while the down-only one-minute check is extra evidence and must not create a missing interval for online services. [VERIFIED: dashboard/beacon/config.py] [VERIFIED: dashboard/beacon/worker_main.py] [ASSUMED]

### Pattern 4: Bounded range API with stable coverage vocabulary

**What:** Validate one kind/metric/service selector and integer `start_ts`/`end_ts`; retain those requested bounds verbatim, select the smallest server bucket that fits the point budget, then return data and a coalesced coverage partition. [VERIFIED: 02-CONTEXT.md]

```json
{
  "requested": {"start_ts": 0, "end_ts": 0},
  "effective_resolution_seconds": 7200,
  "point_budget": 2048,
  "points": [],
  "coverage": [
    {"start_ts": 0, "end_ts": 0, "state": "expired"}
  ]
}
```

Use a 2,048-point inclusive budget and choose the smallest bucket from `[60, 300, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400]` satisfying `ceil((end - start) / bucket) <= 2048`; report both this resolution and the actual source tiers used. [ASSUMED]

### Anti-Patterns to Avoid

- **Delete then roll up:** A crash, constraint error, or lease loss after deletion makes retention evidence unrecoverable; insert/verify before deletion in one transaction. [VERIFIED: 02-CONTEXT.md]
- **Partial-bucket rollups:** They double-count or omit a boundary when later data arrives; only roll up closed, fully eligible buckets. [ASSUMED]
- **Treating failed probes as missing:** A completed probe reporting offline is observed evidence; missing/unknown instead describes absence or indeterminate result. [VERIFIED: 02-CONTEXT.md]
- **A second scheduler or process-local retention lock:** It violates the durable sole-worker ownership model. [VERIFIED: codebase grep]
- **Leaving range query cursors open:** Long readers can block WAL checkpoint completion and cause storage growth. [CITED: https://www.sqlite.org/wal.html]
- **Silently clamping a 90+-day request:** The caller loses the required expiry/not-yet-monitored distinction. [VERIFIED: 02-CONTEXT.md]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Database concurrency | A new daemon mutex or another writer | Existing durable worker epoch plus `_worker_write_transaction()` | The existing write path verifies durable ownership in SQLite before commit. [VERIFIED: codebase grep] |
| Schema upgrade safety | Ad-hoc table creation at worker startup | Existing versioned migration/verified-backup path | It already provides transactional migrations and recovery markers. [VERIFIED: dashboard/beacon/migrations.py] |
| Range SQL safety | String-concatenated filters/identifiers | Repository allowlists and parameterized values | Existing repositories demonstrate parameterized SQL and fixed query shapes. [VERIFIED: dashboard/beacon/repositories.py] |
| Space measurement | Parsing CLI output | Python stat/disk-usage functions | Application code can inspect the mounted data directory directly and deterministically. [ASSUMED] |
| Time-weighted availability | Averaging booleans | Interval overlap calculation used by current uptime logic, extended with explicit coverage | Current uptime code already treats availability as duration over observed time. [VERIFIED: dashboard/app.py] |

**Key insight:** The difficult part is the evidence contract—closed bucket boundaries, transaction order, and coverage semantics—not calculating `MIN`, `MAX`, or `AVG`. [ASSUMED]

## Common Pitfalls

### Pitfall 1: Raw rows removed after a partial or failed rollup

**What goes wrong:** A retry finds no source evidence, while the aggregate is absent or incomplete. [VERIFIED: 02-CONTEXT.md]

**Why it happens:** Deletion was committed separately or aggregate completeness was inferred rather than checked. [ASSUMED]

**How to avoid:** Use a unique bucket identity, one worker-authority transaction, an explicit successful-job record, and delete only after aggregate verification. [VERIFIED: 02-CONTEXT.md]

**Warning signs:** A raw cutoff advances while a matching rollup-job failure or missing bucket exists. [ASSUMED]

### Pitfall 2: Incorrect service cadence and fabricated uptime

**What goes wrong:** Online services appear to have one-minute collection gaps merely because the one-minute down-only probe did not run for them. [VERIFIED: dashboard/beacon/worker_main.py]

**Why it happens:** The implementation treats every scheduler callback as an expected observation stream. [ASSUMED]

**How to avoid:** Name the five-minute all-service probe as the service base cadence and treat down-only results as additional observations. [ASSUMED]

**Warning signs:** A continuously healthy service receives gaps between every five-minute check. [ASSUMED]

### Pitfall 3: Bounded database file but unbounded WAL

**What goes wrong:** The main database appears within allocation while the WAL occupies unexpected disk space and reads slow down. [CITED: https://www.sqlite.org/wal.html]

**Why it happens:** A long reader or oversized retention transaction prevents checkpoint progress. [CITED: https://www.sqlite.org/wal.html]

**How to avoid:** Count `db`, `db-wal`, and `db-shm`; keep retention transactions and range reads bounded; never force a blocking checkpoint on the interactive request path. [CITED: https://www.sqlite.org/wal.html] [ASSUMED]

**Warning signs:** `-wal` grows while every historical request is active, or cleanup duration exceeds its scheduling interval. [CITED: https://www.sqlite.org/wal.html] [ASSUMED]

### Pitfall 4: Retention pressure deletes the evidence it is meant to protect

**What goes wrong:** Low disk space causes loss of unrolled raw data. [VERIFIED: 02-CONTEXT.md]

**Why it happens:** Pressure handling uses the old age-only cleanup path or treats raw data as disposable. [ASSUMED]

**How to avoid:** Suspend new historical persistence only after the emergency reserve is spent; continue live/current updates and record `collection_gap` with `detail="storage_pressure"`. [VERIFIED: 02-CONTEXT.md]

**Warning signs:** Retention cleanup deletes unaggregated source rows when a rollup job remains pending. [VERIFIED: 02-CONTEXT.md]

## Code Examples

### Deterministic service duration aggregation

```python
# Source: existing _uptime_summary() interval-overlap pattern
def add_duration(segment_start, segment_end, status, bucket_start, bucket_end, totals):
    overlap = max(0, min(segment_end, bucket_end) - max(segment_start, bucket_start))
    if overlap:
        totals[status + "_seconds"] += overlap
```

Only observed online/offline durations contribute to availability; `unknown_seconds` and `gap_seconds` are reported separately and never interpolated. [VERIFIED: 02-CONTEXT.md]

### Storage-pressure state transition

```python
# Source: Phase 2 locked decisions
if pressure_exhausted:
    record_coverage_gap(conn, stream, start_ts, now, "collection_gap", "storage_pressure")
    set_telemetry_mode(conn, "historical_persistence_suspended")
elif telemetry_mode_is_suspended and below_recovery_threshold:
    close_open_pressure_gap(conn, now)
    set_telemetry_mode(conn, "normal")
```

The planner should use defaults of 512 MiB database allocation, 1 GiB filesystem reserve, warning at 80%, hard pressure at 90%, recovery at 75%, and a 64 MiB rollup-backlog reserve; all values must remain validated settings because Pi storage sizes vary. [ASSUMED]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Age-based deletes: one day host, eight days service checks, fourteen days events | Tiered aggregate-before-delete history with individual events retained 90 days | Phase 2 | Enables a bounded, truthful 90-day record. [VERIFIED: codebase grep] |
| One-day `/api/history` array | Explicitly bounded historical contract with resolution and coverage metadata | Phase 2 | Allows later analytics without hidden clamping or invented continuity. [VERIFIED: 02-CONTEXT.md] |

**Deprecated/outdated:**

- `worker_cleanup_history()` age-only deletion for telemetry/events: replace it with the retention operation; retain scan-rate cleanup as a separate non-telemetry concern. [VERIFIED: codebase grep]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | A 2,048-point response budget and listed display bucket ladder fit Pi/browser payload needs. | Architecture Patterns | Range responses may be too large or downsample more than desired. |
| A2 | 512 MiB allocation, 1 GiB free reserve, 80/90/75% thresholds, and 64 MiB backlog reserve are suitable defaults. | Code Examples | Default pressure behavior may be too strict or too permissive for a particular SD card. |
| A3 | `shutil.disk_usage()`/`os.stat()` should implement production space accounting. | Standard Stack / Don't Hand-Roll | Actual deployment accounting may need a different mounted-volume boundary. |
| A4 | A sparse non-observed coverage ledger and a Flask-free `telemetry.py` module are the best schema/module division. | Architecture Patterns | Implementation may need small adaptation to preserve current adapters. |
| A5 | The five-minute all-service probe is the base cadence and down-only checks are extra evidence. | Architecture Patterns | Gap detection may be semantically wrong for a service lifecycle edge case. |

## Open Questions (RESOLVED)

1. **Does the confirmed production database fingerprint contain enough existing service identity/history to migrate without a service-key transition?**
   - **Final choice:** Preserve the existing port identity: raw checks remain keyed by `(ts, port)`, service rollups and stream state use `service_port`, and Phase 2 introduces no opaque service identity or history rewrite. [VERIFIED: dashboard/beacon/migrations.py] [RESOLVED: Plan 02-03]
   - **Reversibility:** Costly — changing identity after rollups exist would require a versioned schema/API migration and an explicit history-association policy.
   - **Validation status:** Plan 02-03 inspects the frozen operator fixture before migration work and tests the exact supported fingerprints plus legacy-data preservation. If that fixture contradicts port identity, execution halts rather than silently choosing a different identity; this is an evidence precondition, not an open design choice.

2. **What target filesystem capacity must defaults protect?**
   - **Final choice:** Use a 512 MiB database allocation, 1 GiB minimum free-disk reserve, 80% warning threshold, 90% hard-pressure threshold, 75% recovery threshold, and 64 MiB emergency rollup-backlog reserve. Every value is a validated environment override, and recovery requires both allocation and free-space conditions. [RESOLVED: Plan 02-04]
   - **Reversibility:** Reversible — operators can tune validated settings without changing the schema or retention vocabulary; the locked 7/30/90-day retention contract remains unchanged.
   - **Validation status:** Plan 02-04 supplies automated threshold, boundary, reserve, and hysteresis tests. The target-Pi capacity exercise remains a deployment-suitability measurement in Phase 6 and may tune defaults, but it does not block the Phase 2 pressure-state contract.

3. **What represents an indeterminate service result?**
   - **Final choice:** `online is True` is observed-online; `online is False` is observed-offline even when an `error_class` is present; only an explicit adapter result `online is None` creates an `unknown` interval. Never infer `unknown` from a false Boolean or from `error_class`, and never encode indeterminate state as a numeric latency/status sentinel. `storage_pressure` remains detail on a `collection_gap`, not a service-result state. [VERIFIED: 02-CONTEXT.md] [RESOLVED: Plan 02-05]
   - **Reversibility:** Costly — reclassifying persisted service history would change D-05 coverage meaning consumed by later analytics.
   - **Validation status:** Wave 0 and Plan 02-05 add a table-driven assertion for `True -> observed online`, `False -> observed offline`, and `None -> unknown`, including a false result with `error_class`; Plan 02-06 verifies that the resulting unknown interval is returned unchanged in the exhaustive coverage partition.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| Python | Runtime and stdlib SQLite | ✓ | 3.11.15 | — |
| SQLite | Persistence and aggregate SQL | ✓ | 3.51.0 | Project container supplies its own runtime SQLite. |
| uv | Test command | ✓ | 0.11.32 | — |
| Docker Compose | Pi deployment validation | ✓ | 5.3.1 | — |

**Missing dependencies with no fallback:** None. [VERIFIED: environment probe]

**Missing dependencies with fallback:** None. [VERIFIED: environment probe]

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest `>=9,<10` over existing unittest-style suites. [VERIFIED: dashboard/pyproject.toml] |
| Config file | `dashboard/pyproject.toml`. [VERIFIED: dashboard/pyproject.toml] |
| Quick run command | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py` |
| Full suite command | `uv run --project dashboard python -m pytest -q` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEL-01 | Raw/rollup/event expiry results in bounded 90-day retained data. | unit + integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ Wave 0 |
| TEL-02 | Exact 7d/30d/90d tier boundary and aggregate fields. | unit | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ Wave 0 |
| TEL-03 | Fail/crash/retry never deletes raw source before a successful rollup. | integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ Wave 0 |
| TEL-04 | Coverage exhaustively labels observed, unknown, gap, expired, and not-yet-monitored ranges; service results map `True` to observed online, `False` to observed offline, and only `None` to unknown. | API + worker integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py` | ❌ Wave 0 |
| TEL-05 | Valid range chooses stable resolution and cannot exceed point budget. | API unit + integration | `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py`
- **Per wave merge:** `uv run --project dashboard python -m pytest -q`
- **Phase gate:** Full suite green before `$gsd-verify-work`.

### Wave 0 Gaps

- [ ] `tests/test_telemetry_retention.py` — deterministic clock/data fixtures, tier boundaries, rollup-before-delete, retries, pressure/recovery, concurrent worker epoch loss, and the exact service-result table `True -> observed online`, `False -> observed offline` (including `error_class`), `None -> unknown`.
- [ ] `tests/test_historical_telemetry_api.py` — query validation, coverage partition, requested bounds, response budget, and resolution metadata.
- [ ] Extend `tests/test_migrations.py` — assert upgrade preserves legacy tables/data and creates all telemetry indexes/constraints.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Beacon remains trusted-LAN and has no accounts in this milestone. [VERIFIED: AGENTS.md] |
| V3 Session Management | No | No session mechanism is introduced. [VERIFIED: AGENTS.md] |
| V4 Access Control | No new role control | Preserve existing request host/origin protections on the new read route. [VERIFIED: AGENTS.md] |
| V5 Input Validation | Yes | Strict integer bounds, max 90-day span, selector allowlists, and parameterized repository SQL. [VERIFIED: dashboard/beacon/repositories.py] [VERIFIED: 02-CONTEXT.md] |
| V6 Cryptography | No | Phase 2 stores local operational telemetry and adds no crypto protocol. [VERIFIED: 02-CONTEXT.md] |

### Known Threat Patterns for SQLite telemetry

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Unbounded historical request / WAL growth | Denial of Service | Server point budget, max 90-day validated range, short-lived read connections, and no interactive checkpoint. [CITED: https://www.sqlite.org/wal.html] [ASSUMED] |
| SQL injection via metric/service selector | Tampering | Map selectors to fixed query shapes and bind every value. [VERIFIED: dashboard/beacon/repositories.py] |
| Storage exhaustion | Denial of Service | Allocation/free-space guardrails, hysteresis, bounded backlog reserve, and truthful pressure gaps. [VERIFIED: 02-CONTEXT.md] |
| Stale worker deletes/rolls data after takeover | Tampering | Existing transaction-local durable worker epoch assertion on every retention write. [VERIFIED: dashboard/app.py] |

## Sources

### Primary (HIGH confidence)

- [Beacon Phase 2 Context](.planning/phases/02-bounded-telemetry-retention/02-CONTEXT.md) - locked retention tiers, coverage vocabulary, pressure behavior, and scope.
- [Beacon migration/worker/db code](dashboard/beacon/migrations.py) - migration, durable authority, and SQLite transaction seams.

### Secondary (MEDIUM confidence)

- [SQLite WAL documentation](https://www.sqlite.org/wal.html) - one-writer WAL behavior, checkpoints, long-reader and large-transaction pitfalls.
- [SQLite transaction documentation](https://www.sqlite.org/lang_transaction.html) - transaction modes and write contention.
- [SQLite date/time documentation](https://www.sqlite.org/lang_datefunc.html) - Unix-epoch timestamp behavior.
- [APScheduler 3 user guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html) - `max_instances`, missed executions, and coalescing.

### Tertiary (LOW confidence)

- Default byte thresholds, 2,048-point budget, sparse coverage schema, and the five-minute base-cadence interpretation are marked in the assumptions log for plan-time confirmation.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — the phase extends the pinned, already deployed Python/SQLite/APScheduler stack. [VERIFIED: dashboard/pyproject.toml]
- Architecture: MEDIUM — transactional and WAL properties are cited, while exact schema/budget defaults are intentionally assumed. [CITED: https://www.sqlite.org/wal.html]
- Pitfalls: HIGH — project code and locked decisions expose the current deletion behavior and required failure semantics. [VERIFIED: codebase grep] [VERIFIED: 02-CONTEXT.md]

**Research date:** 2026-08-10  
**Valid until:** 2026-09-09
