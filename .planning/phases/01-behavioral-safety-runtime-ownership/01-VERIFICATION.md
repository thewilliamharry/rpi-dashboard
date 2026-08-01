---
phase: 01-behavioral-safety-runtime-ownership
verified: 2026-08-01T09:22:06Z
status: gaps_found
score: 17/20 must-haves verified
behavior_unverified: 1
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 17/20
  gaps_closed:
    - "Recovery is marker-authorized and catalog-bound; a healthy database is refused without mutation."
    - "Plain HTTP and Playwright-routed browser mutations are rejected before origin connection."
    - "Pre-relay proxy origin sockets and capacity slots are released exactly once on tested failures."
    - "Metadata critical and pinned_order fields now enforce exact JSON types before durable mutation."
  gaps_remaining:
    - "Encrypted CONNECT tunnels still allow a hostile allowed preview to upgrade a GET request to WebSocket and send opaque state-changing frames."
    - "Worker ownership leases are not released when scheduler startup/lifecycle exits outside stop_worker()."
  regressions:
    - "CR-01 from the fresh code review: retrieval-only preview enforcement is bypassable through HTTPS CONNECT/WebSocket."
    - "WR-01 from the fresh code review: a durable worker lease survives ordinary scheduler exit or post-acquisition startup failure."
gaps:
  - truth: "Service previews remain retrieval-only and cannot mutate a policy-approved service through HTTPS or WebSocket transport."
    status: failed
    reason: "The loopback proxy unconditionally establishes CONNECT and relays encrypted bytes bidirectionally. A hostile preview can open wss:// using GET and then send state-changing WebSocket frames that neither the Playwright request-method gate nor proxy can inspect or block."
    artifacts:
      - path: "dashboard/beacon/outbound.py"
        issue: "_PolicyProxyHandler.handle() accepts CONNECT before the safe-method check and transfers the tunnel to _relay()."
      - path: "dashboard/beacon/previews.py"
        issue: "route_browser_request() gates only HTTP request.method; it has no WebSocket/upgrade control."
      - path: "tests/test_outbound_policy.py"
        issue: "Tests prove form/fetch HTTP mutations are blocked, but none opens a hostile HTTPS WebSocket and proves no mutation frame reaches the allowed target."
    missing:
      - "Block WebSocket/upgrade creation for untrusted preview contexts (or otherwise constrain CONNECT to retrieval-only navigation) before a tunnel is opened."
      - "Add an HTTPS hostile-preview regression that attempts a WebSocket mutation and proves the target receives no frame."
  - truth: "A worker that owns the durable scheduler lease releases it on normal scheduler exit and on every failure after acquisition, allowing a replacement worker to start promptly."
    status: failed
    reason: "run_worker() acquires the lease before recovery, heartbeat, metrics, scheduler construction, and signal setup. Its final cleanup only shuts down Chromium; it never calls release_worker_lease() or clears active worker state."
    artifacts:
      - path: "dashboard/beacon/worker_main.py"
        issue: "run_worker() lines 207-235 has no post-acquisition try/finally lease release; early return from failed heartbeat also bypasses stop_worker()."
      - path: "tests/test_runtime_ownership.py"
        issue: "Covers lease contention and scheduler non-construction for a contender, but not release after scheduler exit or an exception after lease acquisition."
    missing:
      - "Put release_worker_lease() in a post-acquisition finally block, tolerating only LeaseLost, and clear active worker globals there."
      - "Add regressions for scheduler return/SystemExit and each representative post-acquisition startup failure, asserting an immediate replacement can acquire the lease."
behavior_unverified_items:
  - truth: "D-04: every current or retained operator Pi database is represented by the confirmed support-floor inventory."
    test: "Run the documented read-only inventory command against every deployed and retained Pi database, then compare fingerprints with dashboard/beacon/support_floor.json and tests/fixtures/legacy/operator/."
    expected: "Every fingerprint is represented by the support floor and has a matching sanitized fixture; an unknown shape is refused before migration."
    why_human: "Repository tests can exercise only checked-in sanitized fixtures and cannot inspect the operator's live or retained database files."
---

# Phase 01: Behavioral Safety & Runtime Ownership Verification Report

**Phase Goal:** The operator can safely continue using and upgrading Beacon while its web, worker, persistence, and outbound-access responsibilities are dependable and independently maintainable.

**Verified:** 2026-08-01T09:22:06Z
**Status:** gaps_found
**Re-verification:** Yes — after Plans 01-15 through 01-17

## Goal Achievement

Plans 01-15 through 01-17 genuinely close the two preceding implementation blockers: destructive recovery is now marker-authorized and the HTTP preview mutation path is rejected. The phase goal remains unachieved because the same preview boundary is still bypassable over encrypted WebSockets, and a worker can retain its durable owner lease after it has stopped doing scheduler work. These are current-code failures, not missing visual confirmation.

### Observable Truths

All roadmap criteria and every plan-frontmatter truth were reviewed. Closely coupled plan truths are grouped below to avoid counting the same behavior repeatedly; artifacts and key links were checked separately across all 17 plans.

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Existing dashboard, metadata, scans, previews, uptime, and events preserve compatible persisted behavior. | ✓ VERIFIED | Compatibility/browser/SQLite test artifacts are substantive and wired; API/UI behavior remains exercised through current compatibility routes. |
| 2 | Backup, transactional migration, retention, exclusive maintenance, and recovery are safe and repeatable. | ✓ VERIFIED | `recovery.py` validates the marker before lock/sidecar/replacement work; named healthy-refusal and marker-bound CLI tests passed. |
| 3 | Recovery is authorized only by a regular, valid failed-migration marker bound to the exact verified catalog ID, and invalid/direct/CLI attempts leave healthy bytes untouched. | ✓ VERIFIED | `_authorized_recovery()` precedes maintenance; `test_restore_without_marker_refuses_before_database_or_sidecar_mutation` and marker-bound CLI coverage passed. |
| 4 | Web imports and Flask construction start no background work; package boundaries and explicit persistence collaborators remain in place. | ✓ VERIFIED | Runtime-ownership and module-boundary artifacts are substantive; worker shim injects operations at the composition root. |
| 5 | A single persisted worker owns scheduling and releases that ownership whenever its lifecycle ends or aborts after acquisition. | ✗ FAILED | `run_worker()` acquires at line 211, but its final block only calls `shutdown_browser()`; no release occurs on ordinary exit or post-acquisition errors. |
| 6 | Durable scans/previews coordinate by lease, renew long scans, recover/expire safely, coalesce, and fence stale workers. | ✓ VERIFIED | `queues.py` state transitions and `test_durable_queues.py` are substantive and production-wired. |
| 7 | Probes, fetches, redirects, webhooks, and Chromium use the unified selected-address/TLS policy. | ⚠️ PARTIAL | Numeric pinning, Host/SNI identity, redirect/rebinding and HTTP safe-method behavior pass; encrypted preview tunnels remain an unbounded mutation channel. |
| 8 | Preview traffic is retrieval-only for every supported transport. | ✗ FAILED | `_PolicyProxyHandler` accepts CONNECT and `_relay()` passes opaque encrypted frames; no WebSocket-prevention implementation or regression exists. |
| 9 | HTTP browser-preview POST/PUT/PATCH/DELETE/OPTIONS/TRACE are rejected before policy planning/origin connection, and pre-relay resources are always cleaned up. | ✓ VERIFIED | Elevated local-only tests for hostile Chromium HTTP mutation, CONNECT/SNI, and pre-relay cleanup passed (3 tests, 4 subtests). |
| 10 | Metadata rejects scalar payloads and exact-type violations before persistence/outbound/queue side effects, while compatible valid edits work. | ✓ VERIFIED | `api_service_meta()` exact boolean/non-boolean bounded-int checks precede `_db_lock`; named snapshot regression passed. |
| 11 | Stale/recovered monitoring, queue/expiry, TLS, error, responsive, and theme states remain candid and interactive. | ✓ VERIFIED | UI integration/state artifacts are substantive, API-connected, and consume real temporary SQLite state. |
| 12 | Every current/retained operator database is represented in the support floor. | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | Checked-in fixtures and unknown-shape rejection are present; the external Pi inventory cannot be proven from this repository. |

**Score:** 17/20 truths verified (1 present, behavior-unverified)

### Roadmap Success Criteria

| # | Success criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Existing dashboard/data behavior remains usable after restructuring/upgrading. | ✓ VERIFIED | Compatibility routes, real SQLite, and browser-state tests are present and wired. |
| 2 | Operator can create a usable backup before an upgrade and recover data after migration failure. | ✓ VERIFIED | Marker-bound recovery refuses healthy current data, restores only the bound verified backup, and preserves interruption/repeat semantics. |
| 3 | Web loading starts no background work; worker owns scheduled work without duplication. | ✗ FAILED | Import/start separation is implemented, but an exited/failed owner keeps its persisted lease until expiry, blocking prompt replacement. |
| 4 | Probes/previews/redirects/webhooks block unsafe targets or invalid TLS and report safe failure. | ✗ FAILED | HTTP target/TLS/pinning protections work, but WebSocket frames can bypass retrieval-only preview enforcement through CONNECT. |

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `dashboard/beacon/db.py`, `migrations.py`, `recovery.py` | Managed SQLite, migrations, backup/recovery | ✓ VERIFIED | L1/L2 substantive; marker authorization, lock ordering, sidecar handling, and atomic replacement are wired. |
| `dashboard/beacon/queues.py`, `dashboard/app.py` | Durable claims, scan heartbeats, fenced queues | ✓ VERIFIED | Transactional queue state flows from web enqueue through worker claim to persisted terminal status. |
| `dashboard/beacon/worker_main.py`, `dashboard/worker.py` | Sole worker composition/scheduler owner | ⚠️ PARTIAL | Construction and lease acquisition are wired, but terminal lifecycle cleanup does not release the lease. |
| `dashboard/beacon/outbound.py`, `previews.py` | Pinned, retrieval-only preview transport | ⚠️ PARTIAL | GET/HEAD checks and selected-address sockets are real; CONNECT relays opaque WebSocket traffic. |
| `dashboard/beacon/repositories.py`, `web.py`, `config.py` | Explicit web/config/persistence boundaries | ✓ VERIFIED | Static artifact query passed; composition and repository collaborators are used in production paths. |
| Phase 01 test files | Behavioral and regression evidence | ⚠️ PARTIAL | Recovery, metadata, HTTP preview, queue, UI, and boundaries have evidence; scheduler terminal release and hostile WebSocket coverage are absent. |

The generic artifact probe found all declared file artifacts substantive. Its false negatives for Plan 03, 04, 15, and 17 were non-file/pattern limitations (directory or `module::symbol` endpoints); manual source traces confirm those intended links. They do not offset either failed behavior above.

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `recovery.py` | `recovery-required.json` and verified catalog | validation before lock/replacement | ✓ WIRED | Valid marker/catalog/current pre-version agreement is required before restore proceeds. |
| `worker.py` | `worker_main.run_worker()` | injected `WorkerOperations` | ⚠️ PARTIAL | `release_worker_lease` is injected and `stop_worker()` can call it, but `run_worker()` bypasses that on scheduler return/startup failure. |
| `previews.py` | `PolicyProxy` | context proxy plus route callback | ⚠️ UNSAFE | Route method gate is wired, but proxy CONNECT transfers opaque encrypted traffic to bidirectional relay. |
| `outbound.py` | approved numeric destination | request plan selected address, Host/SNI retained | ✓ WIRED | HTTP/proxy transport pinning and TLS identity evidence passed. |
| `app.py::api_service_meta` | repository/preview queue/events | validation before transaction | ✓ WIRED | Exact type validation is before the durable mutation path; named no-side-effect test passed. |
| `app.js` | Flask/SQLite APIs | polling and mutation rendering | ✓ FLOWING | Safety UI integration uses copied production-schema SQLite data and observes durable states. |

### Data-Flow Trace

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Dashboard safety UI | services, events, worker/queue state | Flask APIs → repositories → SQLite | Yes | ✓ FLOWING |
| Recovery | validated marker → verified catalog record → staged `dashboard.db` | filesystem catalog and SQLite validation | Yes | ✓ FLOWING |
| Worker ownership | `worker_owner` runtime-state row | acquire/renew/release lease transactions | Yes, but terminal cleanup is disconnected | ⚠️ HOLLOW EXIT PATH |
| Browser previews | browser request → policy plan → selected socket | route gate and loopback proxy | Yes, but CONNECT is opaque after setup | ✗ UNSAFE TUNNEL |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Healthy recovery refusal, marker-bound CLI selection, metadata exact typing, lease contender | `dashboard/.venv/bin/python -m pytest -q` with four named tests | 4 passed, 22 subtests | ✓ PASS |
| Hostile Chromium HTTP mutation, CONNECT/SNI pinning, pre-relay cleanup | Focused `tests/test_outbound_policy.py` named tests with temporary loopback origins | 3 passed, 4 subtests | ✓ PASS |
| Full workspace suite | `dashboard/.venv/bin/python -m pytest -q` run once under loopback permission | Progress output reached 79%; final completion summary was not captured, so it is not used as passing evidence. | ? INCONCLUSIVE |
| WebSocket mutation prevention | No named regression exists; source permits CONNECT and opaque relay. | No prevention path found. | ✗ FAIL |
| Worker lease release on scheduler exit/startup exception | No named regression exists; source finalizer omits release. | No release path found. | ✗ FAIL |

### Requirements Coverage

| Requirement | Source plans | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| FND-01 | 01-01, 02, 03, 06, 08, 14 | Compatibility protection for existing dashboard/service/discovery/preview/uptime/event behavior | ✓ SATISFIED | Current routes and real SQLite/browser compatibility paths remain connected. |
| FND-02 | 01-02, 03, 13 | Explicit web/config/persistence/monitoring/discovery/preview/scheduling boundaries | ✓ SATISFIED | Boundary audit, worker injection, and explicit repository ownership are present. |
| FND-03 | 01-01, 02, 03 | Web import starts no background work | ✓ SATISFIED | Runtime ownership tests and side-effect-free composition structure support it. |
| FND-04 | 01-01, 03, 06, 11 | Worker-only scheduling with durable persisted coordination | ✗ BLOCKED | Owner lease is acquired/renewed, but not released on normal scheduler exit or post-acquisition failure. |
| FND-05 | 01-04 | Versioned transactional idempotent migrations against representative databases | ? NEEDS HUMAN | Fixture/migration evidence passes; actual retained Pi databases remain outside repository visibility. |
| FND-06 | 01-04, 05, 09, 10, 15 | Verified pre-upgrade backup and safe failed-upgrade recovery | ✓ SATISFIED | Marker-bound authorization closes the prior healthy-rollback blocker. |
| FND-07 | 01-07, 08, 12, 16 | One tested outbound-target and TLS safety policy | ✗ BLOCKED | HTTPS CONNECT/WebSocket bypass leaves preview mutation authority against policy-approved targets. |
| OPS-05 | 01-07, 08, 12, 13, 14, 16, 17 | Automated outbound/DNS/redirect/TLS/mutation protections | ✗ BLOCKED | HTTP mutation coverage passes, but no test or control covers encrypted WebSocket mutation through the proxy. |

No Phase 01 requirement is orphaned: each of FND-01 through FND-07 and OPS-05 appears in at least one plan frontmatter. The later roadmap phases do not explicitly schedule either open Phase 01 safety defect, so neither is deferred.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | ---: | --- | --- | --- |
| `dashboard/beacon/outbound.py` | 292-305, 399-444 | Unrestricted encrypted CONNECT relay | 🛑 BLOCKER | A preview can upgrade a safe GET to WebSocket and send opaque mutations. |
| `dashboard/beacon/worker_main.py` | 207-235 | Acquired durable lease lacks a lifecycle finalizer | 🛑 BLOCKER | Replacement worker may be refused until expiry after the owner stops/fails. |

No unreferenced `TBD`, `FIXME`, or `XXX` debt marker was found in Phase 01 implementation/test files. `placeholders` SQL parameters and the deliberate safe error text `backup is not available` are not stubs.

### Human Verification Required

### 1. Current/retained Pi database inventory

**Test:** Before a real upgrade, run the documented read-only inventory checklist for every deployed and retained Beacon database.

**Expected:** Every fingerprint is in the support-floor manifest with a corresponding sanitized fixture; unknown shapes stop the upgrade.

**Why human:** Repository tests cannot access the operator's actual database files.

### Gaps Summary

This is an **Escalation Gate**. Do not advance Phase 01 or mark FND-04, FND-07, or OPS-05 complete. First close the encrypted WebSocket/CONNECT mutation channel and guarantee lease release across all worker terminal paths, with focused regressions for both. Then re-run Phase 01 verification. The database-inventory item remains a separate pre-upgrade operator check.

---

_Verified: 2026-08-01T09:22:06Z_
_Verifier: the agent (gsd-verifier)_
