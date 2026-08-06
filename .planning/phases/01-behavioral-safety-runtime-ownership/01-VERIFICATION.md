---
phase: 01-behavioral-safety-runtime-ownership
verified: 2026-08-06T21:13:04Z
status: passed
score: 8/8 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 18/20
  gaps_closed:
    - "The worker is the sole durable authority for all scheduled mutations after a successor takes over."
  gaps_remaining: []
  regressions: []
---

# Phase 01: Behavioral Safety & Runtime Ownership Verification Report

**Phase Goal:** The operator can safely continue using and upgrading Beacon while its web, worker, persistence, and outbound-access responsibilities are dependable and independently maintainable.

**Verified:** 2026-08-06T21:13:04Z
**Status:** passed
**Re-verification:** Yes — after FND-04 ownership closure (Plans 21–23)

## Goal Achievement

This re-verification started from the former FND-04 blocker rather than the summaries. The prior late-Worker-A uptime reproduction is no longer possible through the production worker composition: every post-acquisition startup/scheduled operation is dispatched from `WORKER_CALLBACK_INVENTORY`, carries one acquired `WorkerAuthority`, is admitted through the shared drain registry, and writes only after a same-transaction durable-epoch assertion. The real-SQLite A→B tests include S2 and J1's renewal-to-persistence handoff, the callback/effect matrix, current-B controls, and Wave 14 queue preservation.

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | FND-01: Existing dashboard, metadata, scan, preview, uptime, and event behavior remains compatible with persisted data. | ✓ VERIFIED | Browser/API, uptime, UI-state, durable-queue, migration, recovery, and release-contract tests are in the successful full suite. `app.js` consumes the existing `/api/stats`, `/api/history`, `/api/services`, `/api/events`, `/api/scan-status`, metadata, scan, and thumbnail routes. |
| 2 | FND-02: Web, configuration, persistence, monitoring, discovery, preview, and scheduling responsibilities have maintainable boundaries. | ✓ VERIFIED | `dashboard/worker.py` is the explicit composition shim; `worker_main.py` owns lifecycle/scheduling; `beacon` modules own database, migrations, recovery, outbound policy, previews, queues, and web collaborators. No reverse `dashboard.app` import exists under `dashboard/beacon/`; `test_module_boundaries.py` is in the full suite. |
| 3 | FND-03: Loading the web application starts no scheduler, browser, probe, or background work. | ✓ VERIFIED | `test_fresh_imports_do_not_start_runtime_or_create_database` exercises fresh imports. The only APScheduler construction/start is in `worker_main.build_scheduler()` / `run_worker()`, reached through `dashboard/worker.py`. |
| 4 | FND-04: One durable worker owns all shared scheduled work; a successor prevents every late old-worker database mutation or authoritative effect. | ✓ VERIFIED | Production inventory contains P0, S1–S3, J1–J9, L1; `build_scheduler()` registers its jobs only from that inventory and `dispatch_callback()` universally admits them. `WorkerAuthority` is built from the exact durable lease. `_worker_write_transaction()` does `BEGIN IMMEDIATE` then `assert_current_worker_authority()` before the mutation. Real SQLite A→B matrix covers S1–S3/J1–J9, including S2/J1 renewal→heartbeat persistence, stale preview publication, and current-B controls. Both order-sensitive focused runs passed 46 tests / 133 subtests. |
| 5 | FND-05: Supported existing schemas migrate versionedly, transactionally, idempotently, and fail closed on unknown shapes. | ✓ VERIFIED | `migrations.py` uses upgrade/maintenance locking, verified backups, and `BEGIN IMMEDIATE`; `support_floor.json` and representative fixtures are validated by `test_migrations.py`. The accepted production inventory artifact is `tests/fixtures/legacy/operator/production.json`; it is included in the support-floor test. |
| 6 | FND-06: A verified pre-upgrade backup can be created and a failed migration can be recovered safely. | ✓ VERIFIED | `create_verified_backup()` verifies/adopts bounded backups; `restore_backup()` requires marker/catalog authorization, excludes active writers, manages WAL/SHM, and stages replacement under exclusive maintenance. `test_backup_recovery.py` exercises backup, retention, interruption, marker binding, and restore refusal paths. |
| 7 | FND-07: Probes, previews, redirects, and webhooks use a single pinned target/TLS policy with safe failures. | ✓ VERIFIED | `OutboundPolicy.plan()` validates purpose, host, DNS answers, selected address, scheme/port, and TLS posture. `OutboundTransport` re-plans redirects and sends pinned requests. Chromium context routing and the proxy enforce retrieval-only requests. `test_outbound_policy.py` covers redirects, rebinding, TLS/SNI, hostile WSS, and cleanup. |
| 8 | OPS-05: Unsafe outbound and mutation paths are blocked without weakening valid trusted-LAN operation. | ✓ VERIFIED | Strict webhook TLS/allowlisting and bounded current-epoch webhook reservation are production-wired; exact metadata types reject malformed mutation payloads before persistence or queue effects. API/outbound/UI-contract tests cover these boundaries. |

**Score:** 8/8 truths verified (0 present-but-behavior-unverified).

### Roadmap Success Criteria

| # | Success criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Existing dashboard/data behavior remains usable after restructuring and upgrade. | ✓ VERIFIED | Compatibility route/data-flow coverage plus migration, recovery, UI, and full-suite evidence. |
| 2 | Operator can make a usable backup before upgrade and recover after migration failure. | ✓ VERIFIED | Marker-authorized restore, exclusive maintenance, real fixture recovery tests, and accepted production inventory evidence. |
| 3 | Web loading starts no background work; worker owns scheduled work without duplicate execution. | ✓ VERIFIED | Fresh-import test, sole scheduler entry point, universal admission/drain, and all-row real-SQLite takeover matrix. |
| 4 | Probes/previews/redirects/webhooks reject unsafe targets or invalid TLS with safe failures. | ✓ VERIFIED | Shared policy/transport wiring and hostile HTTP/HTTPS/WSS, redirect, rebinding, and strict-webhook tests. |

## Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/beacon/worker_main.py` | Sole lifecycle, callback inventory, scheduler, admission, drain | ✓ VERIFIED | 393 substantive lines; the immutable inventory is the actual startup/scheduler dispatch source. |
| `dashboard/beacon/worker_authority.py`, `queues.py` | Acquired epoch and same-transaction durable authority fence | ✓ VERIFIED | `WorkerAuthority` is immutable; `assert_current_worker_authority()` requires an active transaction and validates exact current epoch. |
| `dashboard/app.py`, `dashboard/worker.py` | Authority-taking worker adapters while web remains owner-free | ✓ VERIFIED | Worker operations bind only `worker_*` adapters; explicit owner-free metadata/manual-scan/preview-enqueue controls remain available. |
| `tests/worker_ownership_contract.py`, `tests/test_worker_ownership_matrix.py` | Production-to-evidence callback/effect bijection and A→B oracle | ✓ VERIFIED | Exact set equality links the 14 production descriptors to the immutable contract, scheduler registrations, effect producers, dynamic rows, and controls. |
| `dashboard/beacon/migrations.py`, `recovery.py`, `inventory.py` | Safe upgrade, backup, recovery, and inventory mechanics | ✓ VERIFIED | Substantive production implementation and broad transactional/restore fixtures, including production inventory fixture. |
| `dashboard/beacon/outbound.py`, `previews.py` | Pinned, purpose-aware outbound/Chromium boundary | ✓ VERIFIED | Substantive policy, proxy, transport, request routing, and cleanup implementation. |
| `dashboard/app.js`, `index.html`, `style.css` | Existing dashboard behavior and candid safety state | ✓ VERIFIED | UI renders API data and retained controls; UI contract/state/integration coverage is in the full suite. |

## Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `WORKER_CALLBACK_INVENTORY` | `run_worker()` and `build_scheduler()` | `dispatch_callback()` / registry iteration | ✓ WIRED | The sole worker scheduler loops over the registry; every job uses a registry callback ID. |
| Acquired `WorkerLease` | `WorkerServices.authority` | `WorkerAuthority.from_lease()` | ✓ WIRED | The exact worker ID/opaque epoch from the durable acquisition is converted once and passed to S1–S3/J1–J9 and final release. |
| Worker database adapters | durable owner row | `_worker_write_transaction()` → `BEGIN IMMEDIATE` → `assert_current_worker_authority()` | ✓ WIRED | Applies to recovery, heartbeat, metrics, cleanup, discovery/uptime writes, queue transitions, and preview publication. |
| Lease loss | all callbacks / finalizer | `dispatch_callback()` admission close → `stop_worker()` → drain → browser cleanup → matching release | ✓ WIRED | Admission categories are derived from every ownership-required descriptor; tests prove rejection and ordered drain. |
| Transition webhook | current durable epoch | exact renewal before strict pinned POST; fenced outcome event | ✓ WIRED | `worker_send_transition_alert()` reserves the bounded effect budget and uses `OutboundPurpose.WEBHOOK`. |
| Browser candidate | preview rows/service/event BLOB fields | one authority + row/revision-fenced transaction | ✓ WIRED | Capture remains in memory until `worker_process_preview_requests()` commits its publication transaction. |
| Browser UI | Flask/SQLite state | `app.js` API polling/mutations → Flask `/api/*` routes → repositories/SQLite | ✓ WIRED | No static dashboard data path was found. |

## Data-Flow Trace (Level 4)

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Dashboard UI | stats, services, events, scan status, history | `/api/*` Flask routes → SQLite/repositories | Yes | ✓ FLOWING |
| Worker callbacks | immutable `WorkerAuthority` | real `acquire_worker_lease()` → `WorkerServices` → worker adapter | Yes; current durable epoch is asserted per transaction | ✓ FLOWING |
| Queues/previews | claims, revisions, thumbnails/events | SQLite queue rows → in-memory browser result → fenced publish transaction | Yes; no hardcoded output or stale publish path | ✓ FLOWING |
| Recovery | marker/catalog/fingerprint/backup | support floor + checked backup catalog + maintenance barrier | Yes | ✓ FLOWING |
| Outbound operations | selected address/TLS plan | policy plan → pinned transport / loopback policy proxy | Yes | ✓ FLOWING |

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Ownership matrix then runtime/queue regressions | `dashboard/.venv/bin/python -m pytest -q tests/test_worker_ownership_matrix.py tests/test_runtime_ownership.py tests/test_durable_queues.py -x` | 46 passed, 133 subtests | ✓ PASS |
| Same ownership regressions in reverse module order | `dashboard/.venv/bin/python -m pytest -q tests/test_durable_queues.py tests/test_runtime_ownership.py tests/test_worker_ownership_matrix.py -x` | 46 passed, 133 subtests | ✓ PASS |
| Full repository regression | `uv run --project dashboard python -m pytest -q` | exit 0; current authoritative run records 174 passed, 235 subtests | ✓ PASS |

## Probe Execution

Step 7c: **SKIPPED** — no phase-declared or conventional `scripts/*/tests/probe-*.sh` probe exists.

## Requirements Coverage

| Requirement | Source plans | Status | Evidence |
| --- | --- | --- | --- |
| FND-01 | 01–03, 06, 08, 14 | ✓ SATISFIED | API/UI/uptime/queue compatibility tests and real dashboard data flow. |
| FND-02 | 02, 03, 13 | ✓ SATISFIED | Explicit package boundaries, independent worker shim, and module-boundary coverage. |
| FND-03 | 01, 02, 03, 19 | ✓ SATISFIED | Fresh import test and source-level sole scheduler ownership. |
| FND-04 | 01, 03, 06, 11, 19–23 | ✓ SATISFIED | Exhaustive registry, all-category admission/drain, same-transaction epoch fence, real A→B matrix (including S2/J1), non-SQL effects, and current-B controls. |
| FND-05 | 04, 09, 10 | ✓ SATISFIED | Versioned transaction tests, unknown-shape refusal, accepted operator inventory/fingerprint fixture. |
| FND-06 | 04, 05, 09, 10, 15 | ✓ SATISFIED | Verified pre-upgrade backup and fail-safe marker/catalog-bound recovery tests. |
| FND-07 | 07, 08, 12, 16, 18 | ✓ SATISFIED | Shared outbound policy plus hostile redirect/TLS/WSS coverage. |
| OPS-05 | 07, 08, 12–18 | ✓ SATISFIED | Outbound, proxy, mutation typing, UI safety, and error-state regressions. |

No Phase 1 requirement is orphaned. The former FND-04 gap is closed in this phase, not deferred to a later roadmap phase.

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | ---: | --- | --- | --- |
| — | — | No `TBD`, `FIXME`, or `XXX` debt marker in Phase 1 implementation/tests; no output-flowing placeholder, empty handler, orphaned worker callback, or hardcoded UI data path found. | ℹ️ Info | None. |

The literal recovery message `backup is not available`, HTML input `placeholder` attributes, empty collection initializers, and SQL `?` placeholders were inspected and are intentional safe errors, form hints, or ordinary collection/query setup — not implementation stubs.

## Human/Judgment Resolution

The historical external-Pi inventory checkpoint is completed: the operator ran the production SQLite snapshot through `inventory.py`, received `PRAGMA integrity_check=ok`, generated and verified `tests/fixtures/legacy/operator/production.json`, and explicitly confirmed completion. The support-floor regression consumes that accepted artifact.

The descriptor-less planning prohibitions (locked outage, compatibility removal, appliance scope, unknown schema mutation, destructive recovery, TLS/UI honesty, HTTPS JavaScript/WSS behavior, and premature lifecycle transfer) have no remaining untested observable failure: their implementation is covered by the API/UI contract, browser/outbound, migration/recovery, lifecycle, and A→B takeover evidence above; the final review is clean. They do not create unresolved human verification debt.

## Gaps Summary

None. The previous blocker was falsified by production wiring and independently order-sensitive real-SQLite takeover tests. No later phase is being used to defer a Phase 1 requirement.

---

_Verified: 2026-08-06T21:13:04Z_
_Verifier: the agent (gsd-verifier)_
