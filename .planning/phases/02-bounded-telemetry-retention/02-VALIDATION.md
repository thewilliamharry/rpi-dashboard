---
phase: 02
slug: bounded-telemetry-retention
status: draft
nyquist_compliant: false
wave_0_complete: false
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
| TBD | TBD | 0 | TEL-01 | T-02-03 / T-02-04 | Retention stays bounded and stale workers cannot mutate data | unit + integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ W0 | ⬜ pending |
| TBD | TBD | 0 | TEL-02 | T-02-03 | Tier boundaries and aggregate fields are deterministic | unit | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ W0 | ⬜ pending |
| TBD | TBD | 0 | TEL-03 | T-02-04 | Raw data is never deleted before verified rollup persistence | integration | `uv run --project dashboard python -m pytest -q tests/test_telemetry_retention.py` | ❌ W0 | ⬜ pending |
| TBD | TBD | 0 | TEL-04 | T-02-01 / T-02-02 | Coverage partitions are exhaustive and selectors use fixed query shapes | API integration | `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py` | ❌ W0 | ⬜ pending |
| TBD | TBD | 0 | TEL-05 | T-02-01 | Range validation and server resolution cap response work | API unit + integration | `uv run --project dashboard python -m pytest -q tests/test_historical_telemetry_api.py` | ❌ W0 | ⬜ pending |

*Task IDs, plans, and waves are populated when PLAN.md files are finalized. Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky.*

---

## Wave 0 Requirements

- [ ] `tests/test_telemetry_retention.py` — deterministic clock/data fixtures, tier boundaries, rollup-before-delete, retries, pressure/recovery, and concurrent worker epoch loss
- [ ] `tests/test_historical_telemetry_api.py` — query validation, coverage partition, requested bounds, response budget, and resolution metadata
- [ ] `tests/test_migrations.py` — extend migration coverage to prove legacy data survives and telemetry indexes/constraints are created

Existing pytest infrastructure and shared test helpers cover framework setup; no new test dependency is required.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Storage thresholds remain suitable on target Raspberry Pi hardware | TEL-01 | Host filesystem behavior and practical database growth require target-hardware observation | Seed representative telemetry, run retention through all tiers, inspect database/WAL/free-space behavior, and record measured thresholds before production rollout |

All retention ordering, tier boundaries, coverage semantics, and response bounding otherwise require automated verification.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 180s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

---

## Threat References

| Ref | Threat | Required verification |
|-----|--------|-----------------------|
| T-02-01 | Unbounded historical request or WAL growth | Validate maximum range, bounded point count, and short-lived reads |
| T-02-02 | SQL injection through metric or service selectors | Test allowlisted selectors and bound query values |
| T-02-03 | Storage exhaustion | Test bounded retention, pressure hysteresis, reserve behavior, and truthful gap recording |
| T-02-04 | Stale worker mutation after authority takeover | Test transaction-local worker epoch rejection for rollup and cleanup writes |
