---
phase: 02
slug: bounded-telemetry-retention
status: verified
threats_open: 0
asvs_level: 1
block_on: high
created: 2026-08-11
verified: 2026-08-11
---

# Phase 02 — Security

> ASVS L1 verification of the threat registers authored across Plans 02-01 through 02-12.

## Trust Boundaries

| Boundary | Description | Data Crossing |
|---|---|---|
| HTTP history API → telemetry repositories | Validated selectors and half-open time ranges enter fixed, bounded SQLite queries | Host/service identifiers, timestamps, aggregate rows |
| Worker authority → telemetry mutation | Only the epoch-fenced worker may collect, compact, expire, or record coverage gaps | Samples, coverage intervals, rollup state |
| Supported database → migration runner | Exact support-floor admission, backup, recovery marker, and one immediate transaction guard upgrades | Legacy telemetry schema and persisted JSON state |
| Retention engine → source deletion | Verified aggregates and durable job state must precede exact-range source removal | Raw samples, rollups, retry metadata |

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation / Evidence | Status |
|---|---|---|---|---|---|---|
| T-02-01 | DoS | history range read | high | mitigate | Strict range validation, fixed limits, final response cap | closed |
| T-02-02 | Tampering | host selector | high | mitigate | Four-metric allowlist and fixed query map | closed |
| T-02-03 | Information Disclosure | error responses | low | accept | Fixed validation messages on a trusted local network; no SQL exception exposure | closed — accepted risk |
| T-02-04 | Tampering | aggregate-before-delete | high | mitigate | Read-back verification and exact delete ordering | closed |
| T-02-05 | DoS | allocation/WAL design | high | mitigate | Validated thresholds plus DB/WAL/SHM pressure accounting | closed |
| T-02-06 | Repudiation | operator decision | medium | mitigate | One-way retention contract recorded in 02-02-SUMMARY | closed |
| T-02-07 | Tampering | migration/support floor | high | mitigate | Exact fingerprint admission, backup, transaction, recovery marker | closed |
| T-02-08 | DoS | range/due indexes | medium | mitigate | Versioned range and due-time indexes | closed |
| T-02-09 | Repudiation | rollup job state | medium | mitigate | Unique durable job identity and retry fields | closed |
| T-02-10 | Tampering | retention deletion | critical | mitigate | Savepoint rollback and verified aggregate before deletion | closed |
| T-02-11 | DoS | retention/WAL growth | high | mitigate | Due-only SQL-capped candidates and global batch cap | closed |
| T-02-12 | DoS | storage exhaustion | high | mitigate | Suspension threshold and two-condition recovery | closed |
| T-02-13 | Repudiation | retry outcomes | medium | mitigate | Durable attempt count, retry time, and error class | closed |
| T-02-14 | Tampering | stale worker writes | critical | mitigate | Immediate transaction asserts durable worker authority | closed |
| T-02-15 | DoS | J8 callback | high | mitigate | Single coalesced cleanup job with max-one execution | closed |
| T-02-16 | DoS | suspended persistence | high | mitigate | Current state continues; only historical inserts are gated | closed |
| T-02-17 | Repudiation | gap evidence | medium | mitigate | Bounded coverage and observation persistence | closed |
| T-02-18 | DoS | mixed-tier query | high | mitigate | Retention bounds, sentinel limits, and final cap | closed |
| T-02-19 | Tampering | request selectors | high | mitigate | Exact selector combinations and bound SQL values | closed |
| T-02-20 | Information Disclosure | query errors | medium | mitigate | Fixed caught validation errors; no raw database error path | closed |
| T-02-21 | Spoofing | coverage state | medium | mitigate | Five-state partition derives from durable evidence | closed |
| T-02-G01 | Tampering | host stream identity | high | mitigate | Canonical per-metric stream keys in writer and reader | closed |
| T-02-G02 | DoS | configured budget | high | mitigate | Shared Settings-derived retention policy and budget | closed |
| T-02-G03 | Repudiation | pressure coverage | medium | mitigate | Per-metric pressure gaps under worker transaction | closed |
| T-02-G04 | Information Disclosure | history validation | low | accept | Narrow validation detail is acceptable on the trusted LAN | closed — accepted risk |
| T-02-G05 | Tampering | hourly expiry | critical | mitigate | Only fully closed buckets expire | closed |
| T-02-G06 | DoS | retry admission | high | mitigate | Future and succeeded jobs excluded before bounded admission | closed |
| T-02-G07 | Repudiation | retry history | medium | mitigate | Attempt state changes only on actual failed attempts | closed |
| T-02-G08 | Tampering | retry source deletion | critical | mitigate | Savepoint rollback and verified ordering on retries | closed |
| T-02-G09 | Tampering | fallback ownership | high | mitigate | Completed replacement predicates enforce one tier owner | closed |
| T-02-G10 | DoS | backlog reads | high | mitigate | SQLite grouping, sentinel cap, and prompt connection close | closed |
| T-02-G11 | Spoofing | coverage/pending | medium | mitigate | Source evidence and pending disclosure remain separate | closed |
| T-02-G12 | Information Disclosure | repository/overflow errors | low | accept | Fixed overflow/validation detail accepted on trusted LAN | closed — accepted risk |
| T-02-G13 | Tampering | Migration 7 rewrite | high | mitigate | Canonical migration under exact admission and transaction | closed |
| T-02-G14 | Tampering | retention JSON mutation | high | mitigate | Object/map/type validation precedes state writes | closed |
| T-02-G15 | Repudiation | evidence lineage | medium | mitigate | Deterministic clipping/coalescing; rollup job identity preserved | closed |
| T-02-G16 | DoS | migration work | medium | mitigate | One fixed legacy identity expands to four metrics | closed |
| T-02-G17 | Information Disclosure | migration/API failures | low | accept | Redacted fixed failure class accepted for local diagnostics | closed — accepted risk |
| T-02-G18 (Plan 11) | Spoofing | pending interval | high | mitigate | Five-minute pending interval is exactly 300 seconds | closed |
| T-02-G19 (Plan 11) | Tampering | pending coalescing | high | mitigate | Coalescing requires exact boundary equality | closed |
| T-02-G20 (Plan 11) | DoS | pending query | high | mitigate | Fixed bound queries with overflow rejection | closed |
| T-02-G21 (Plan 11) | Information Disclosure | repository/validation errors | low | accept | Narrow fixed validation detail accepted on trusted LAN | closed — accepted risk |
| T-02-G18 (Plan 12) | Tampering | legacy pressure validation | high | mitigate | Presence/value split rejects booleans and non-integers before writes | closed |
| T-02-G19 (Plan 12) | Tampering | transaction/version publication | high | mitigate | Migration and version publication share one immediate transaction | closed |
| T-02-G20 (Plan 12) | Repudiation | malformed-state evidence | medium | mitigate | Redacted recovery marker and rollback regressions | closed |
| T-02-G21 (Plan 12) | DoS | persisted-state validation | low | accept | Fail-fast validation cost on one bounded JSON object is accepted | closed — accepted risk |

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---|---|---|---|---|
| AR-02-01 | T-02-03 | Fixed local validation messages may reveal minor request-shape detail; no SQL or secret data is exposed. | Plan threat model | 2026-08-11 |
| AR-02-02 | T-02-G04 | Narrow history validation detail is useful to the trusted-LAN operator and carries low disclosure impact. | Plan threat model | 2026-08-11 |
| AR-02-03 | T-02-G12 | Fixed overflow/repository validation messages disclose no query text or persisted values. | Plan threat model | 2026-08-11 |
| AR-02-04 | T-02-G17 | Redacted migration/API failure classes aid local recovery without exposing database contents. | Plan threat model | 2026-08-11 |
| AR-02-05 | T-02-G21 (Plan 11) | Fixed pending-query validation details are low impact within the trusted-LAN scope. | Plan threat model | 2026-08-11 |
| AR-02-06 | T-02-G21 (Plan 12) | Validating one bounded persisted JSON object before mutation has negligible accepted availability cost. | Plan threat model | 2026-08-11 |

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open at/above high | Run By |
|---|---:|---:|---:|---|
| 2026-08-11 | 46 | 46 | 0 | gsd-security-auditor + orchestrator |

Focused security regression: `60 passed, 19 subtests passed`.

## Sign-Off

- [x] All threats have a disposition.
- [x] Accepted risks are documented.
- [x] `threats_open: 0` confirmed at the configured `high` threshold.
- [x] `status: verified` set in frontmatter.

**Approval:** verified 2026-08-11
