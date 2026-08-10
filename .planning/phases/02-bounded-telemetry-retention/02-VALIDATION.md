---
phase: 02
slug: bounded-telemetry-retention
status: gaps_found
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-10
---

# Phase 02 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest `>=9,<10` over existing unittest-style suites |
| **Config file** | `dashboard/pyproject.toml` |
| **Quick run command** | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py` |
| **Full suite command** | `uv run --project dashboard python -m pytest -q` |
| **Estimated runtime** | To be measured during Wave 0; target <60 seconds quick and <180 seconds full |

---

## Sampling Rate

- **After every task commit:** Run `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py`
- **After every plan wave:** Run `uv run --project dashboard python -m pytest -q`
- **Before `$gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 180 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-04-01 / 02-05-02 | 04 / 05 | 4 / 5 | TEL-01 | T-02-12 / T-02-14 | Retention stays bounded and stale workers cannot mutate data | unit + integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ W0 via 02-01-02 | ⬜ pending |
| 02-04-01 | 04 | 4 | TEL-02 | T-02-10 | Tier boundaries and aggregate fields are deterministic | unit | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ W0 via 02-01-02 | ⬜ pending |
| 02-04-01 / 02-05-01 | 04 / 05 | 4 / 5 | TEL-03 | T-02-10 / T-02-14 | Raw data is never deleted before verified rollup persistence | integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ W0 via 02-01-02 | ⬜ pending |
| 02-05-01 / 02-06-02 | 05 / 06 | 5 / 6 | TEL-04 | T-02-17 / T-02-19 | Coverage partitions are exhaustive, selectors use fixed query shapes, and service results map `True` to observed online, `False` to observed offline even with `error_class`, and only `None` to unknown | worker + API integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py tests/test_historical_telemetry_api.py` | ❌ W0 via 02-01-02 | ⬜ pending |
| 02-01-01 / 02-06-02 | 01 / 06 | 1 / 6 | TEL-05 | T-02-01 / T-02-18 | Range validation and server resolution cap response work | API unit + integration | `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py` | ❌ W0 via 02-01-02 | ⬜ pending |
| 02-07-01 | 07 | 7 | TEL-04 | T-02-G01 / T-02-G03 | Real worker samples and pressure gaps use the same per-metric stream identity as rollups and history reads | production worker + API integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py -k "host and (stream or pressure or worker or production)" -x` | ✅ existing, extend | ❌ verified gap |
| 02-07-02 | 07 | 7 | TEL-02, TEL-05 | T-02-G02 | Worker and API use one validated policy for configured tiers, expiry, resolution, repository limits, and response budget | config + API integration | `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py tests/test_telemetry_retention.py -k "policy or settings or budget or configured or production or host" -x` | ✅ existing, extend | ❌ verified gap |
| 02-08-01 | 08 | 8 | TEL-01 | T-02-G05 | Non-hour-aligned expiry removes only host/service hourly buckets fully closed before the cutoff | SQLite integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py -k "non_aligned or hourly or expiry or cutoff" -x` | ✅ existing, extend | ❌ verified gap |
| 02-08-02 | 08 | 8 | TEL-03 | T-02-G06 / T-02-G08 | Persisted retry due time filters candidate admission without premature attempts or source deletion | SQLite state-machine integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py -k "retry or due or pending or failed or batch or idempotent" -x` | ✅ existing, extend | ❌ verified gap |
| 02-09-01 / 02-09-02 | 09 | 9 | TEL-02, TEL-03, TEL-04 | T-02-G09 / T-02-G10 / T-02-G11 | Host/service lower-tier evidence remains bounded, non-duplicated, observed, and separately disclosed while compaction is backlogged/pending/failed | repository + API integration | `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py` | ✅ existing, extend | ❌ verified gap |

*Task IDs, plans, and waves are populated when PLAN.md files are finalized. Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky.*

---

## Wave 0 Requirements

- [x] `tests/test_telemetry_retention.py` — existing deterministic clock/data, tier, rollup-before-delete, retry, pressure/recovery, epoch, and service-result foundation; Plans 02-07/08 add the verified production identity, non-aligned expiry, and pre-due retry regressions.
- [x] `tests/test_historical_telemetry_api.py` — existing query/coverage/budget/mixed-tier foundation; Plans 02-07/09 add configured-policy and awaiting-compaction host/service regressions.
- [x] `tests/test_migrations.py` — existing preservation, telemetry schema/index, rollback, no-op, and migration-6 latency denominator coverage; no new schema is planned for gap closure.

Existing pytest infrastructure and shared test helpers cover framework setup; no new test dependency is required.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Storage thresholds remain suitable on target Raspberry Pi hardware | TEL-01 | Host filesystem behavior and practical database growth require target-hardware observation | Seed representative telemetry, run retention through all tiers, inspect database/WAL/free-space behavior, and record measured thresholds before production rollout |

All retention ordering, tier boundaries, coverage semantics, and response bounding otherwise require automated verification.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [ ] Feedback latency < 180s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending gap-closure execution

---

## Threat References

| Ref | Threat | Required verification |
|-----|--------|-----------------------|
| T-02-01 | Unbounded historical request or WAL growth | Validate maximum range, bounded point count, and short-lived reads |
| T-02-02 | SQL injection through metric or service selectors | Test allowlisted selectors and bound query values |
| T-02-03 | Storage exhaustion | Test bounded retention, pressure hysteresis, reserve behavior, and truthful gap recording |
| T-02-04 | Stale worker mutation after authority takeover | Test transaction-local worker epoch rejection for rollup and cleanup writes |
| T-02-G01 / T-02-G03 | Canonical host identity and truthful pressure coverage | Invoke the real worker for all four metrics and verify stream/API/gap identity under current and stale epochs |
| T-02-G02 | Policy/budget drift between worker and API | Load non-default validated settings and assert tier, retention, repository, and response caps use one policy value |
| T-02-G05 | Partial hourly bucket deletion | Use a non-hour-aligned cutoff and assert host/service bucket-end ownership |
| T-02-G06 / T-02-G08 | Premature retry or source deletion | Snapshot pending/failed jobs and sources before due, at due, and after idempotent success |
| T-02-G09 / T-02-G10 / T-02-G11 | Duplicate, unbounded, or mislabeled awaiting-compaction evidence | Exercise host/service raw and five-minute fallback, replacement precedence, pending disclosure, exact boundaries, and configured caps |

---

## Gap-Closure Source Coverage Audit

| Source | ID | Gap-closure obligation | Plan | Status |
|--------|----|------------------------|------|--------|
| GOAL | — | Accurate bounded 90-day telemetry remains truthful under production wiring and asynchronous retention | 02-07, 02-08, 02-09 | COVERED |
| REQ | TEL-01 | Rolling retention never deletes the retained portion of an hourly bucket | 02-08 Task 1 | COVERED |
| REQ | TEL-02 | Configured tiers and retained lower-tier evidence agree during compaction | 02-07 Task 2; 02-09 Tasks 1-2 | COVERED |
| REQ | TEL-03 | Retry due time is enforced and preserved sources remain visible until verified replacement | 02-08 Task 2; 02-09 Tasks 1-2 | COVERED |
| REQ | TEL-04 | Per-metric coverage and awaiting-compaction evidence are never mislabeled ordinary unknown | 02-07 Task 1; 02-09 Tasks 1-2 | COVERED |
| REQ | TEL-05 | Deployed response budget and tier policy govern all history reads | 02-07 Task 2 | COVERED |
| RESEARCH | closed buckets | Eligibility/expiry uses full UTC bucket end, including non-aligned cutoffs | 02-08 Task 1 | COVERED |
| RESEARCH | bounded WAL/read work | Candidate and fallback reads remain fixed, grouped, capped, and promptly closed | 02-08 Task 2; 02-09 Tasks 1-2 | COVERED |
| CONTEXT | D-01, D-02, D-08 | Settings-backed 7/30/90 tiers, requested bounds, and response policy remain coherent | 02-07 Task 2; 02-08 Task 1; 02-09 Tasks 1-2 | COVERED |
| CONTEXT | D-05, D-06, D-07 | Metric-specific cadence/coverage and non-interpolated preserved evidence remain explicit | 02-07 Task 1; 02-09 Tasks 1-2 | COVERED |
| CONTEXT | D-09 | Failed/pending rollups preserve sources, respect backoff, and disclose pending work | 02-08 Task 2; 02-09 Tasks 1-2 | COVERED |
| CONTEXT | D-10, D-11, D-12 | Existing storage policy remains worker-owned; pressure gaps use readable per-metric identities | 02-07 Tasks 1-2 | COVERED |
| CONTEXT | D-03, D-04 | Existing event and aggregate-field contracts remain protected by focused/full regression | 02-08 Task 1; 02-09 Task 2 | COVERED |

Deferred 365-day retention remains excluded. No confirmed gap, Phase 2 requirement, relevant research constraint, or locked decision is unplanned.
