---
phase: 01-behavioral-safety-runtime-ownership
verified: 2026-08-04T21:29:07Z
status: gaps_found
score: 18/20 must-haves verified
behavior_unverified: 1
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 18/20
  gaps_closed: []
  gaps_remaining:
    - "The worker is not the sole durable authority for all scheduled mutations after a successor takes over."
  regressions:
    - "CR-01 confirmed: an expired Worker A can run the actual uptime operation and commit service, check, and preview-enqueue writes after Worker B acquires the durable lease."
gaps:
  - truth: "The worker visibly owns shared scheduled work without duplicate execution; a successor takeover prevents every late Worker A scheduled mutation."
    status: failed
    reason: "Plan 20 atomically fences scan and preview queue mutations, but scheduler entries for uptime, discovery, metrics, cleanup, and startup recovery neither receive the owner epoch nor prove it in their write transactions. WorkerAdmission covers only scan and preview processors."
    artifacts:
      - path: "dashboard/beacon/worker_main.py"
        issue: "build_scheduler() submits services.do_uptime_check(), scheduled_discovery(), startup_discovery(), sample_metrics(), and cleanup_history directly; only process_scans()/process_previews() use admission and owner-token propagation."
      - path: "dashboard/app.py"
        issue: "run_discovery(), do_uptime_check(), collect_system_stats(), cleanup_history(), and recover_worker_state() expose worker mutations without worker_id/owner_token parameters or a current-worker assertion in their SQLite transactions."
      - path: "tests/test_runtime_ownership.py"
        issue: "The lease-loss drain test holds only a preview job; no Worker A/Worker B takeover regression holds an actual discovery, uptime, recovery, or metrics operation across durable-owner expiry."
    missing:
      - "Thread worker_id and owner_token through every worker-only scheduled operation and assert the current durable epoch in the same SQLite transaction as each write."
      - "Use the admission/drain guard for every scheduler entry that can mutate shared state, including discovery, uptime, metrics, cleanup, and recovery."
      - "Add deterministic real-SQLite takeover tests proving late Worker A discovery, uptime, recovery, and worker-originated preview enqueue leave services, checks, events, runtime state, and queues unchanged after Worker B acquires."
behavior_unverified_items:
  - truth: "Every current or retained operator Pi database is represented by the confirmed support-floor inventory."
    test: "Run the documented read-only inventory command against every deployed and retained Pi database, then compare fingerprints with dashboard/beacon/support_floor.json and tests/fixtures/legacy/operator/."
    expected: "Every fingerprint is represented by the support floor and has a matching sanitized fixture; an unknown shape is refused before migration."
    why_human: "Repository tests can exercise checked-in fixtures and refusal logic but cannot inspect operator-owned database files. This is a deployment preflight, not an automated implementation defect."
human_verification:
  - test: "Before a real upgrade, inventory every current and retained operator Beacon database using the documented read-only command."
    expected: "Every fingerprint is present in the support-floor manifest and has a corresponding sanitized fixture; an unknown shape blocks migration."
    why_human: "The repository has no access to operator-owned database files."
  - test: "After the ownership blocker is fixed, manually preview an approved HTTPS service with JavaScript and GET/HEAD subresources, and observe the trusted-LAN TLS exception state."
    expected: "The preview renders without globally disabling JavaScript; WebSocket creation is blocked and the TLS exception is distinguished from service downtime."
    why_human: "Plan 18 carries a judgment-tier, descriptor-less prohibition beyond the automated TLS/WSS regression."
  - test: "After the ownership blocker is fixed, perform a controlled worker restart/failure while a discovery or uptime job is active."
    expected: "The dashboard remains usable, Worker B becomes sole owner, and Worker A produces no late scheduled write."
    why_human: "Plan 19's end-to-end lifecycle prohibition requires a deployed process check; the current automated evidence instead demonstrates a blocking late-write path."
---

# Phase 01: Behavioral Safety & Runtime Ownership Verification Report

**Phase Goal:** The operator can safely continue using and upgrading Beacon while its web, worker, persistence, and outbound-access responsibilities are dependable and independently maintainable.

**Verified:** 2026-08-04T21:29:07Z
**Status:** gaps_found
**Re-verification:** Yes — after Plan 01-20 / Wave 14

## Goal Achievement

Plan 20 closes the narrow queue-mutation failure: real SQLite tests prove a stale worker epoch cannot claim, renew, requeue, complete, fail, or persist a preview result after takeover. It does **not** close CR-01 or the roadmap's sole-active-worker criterion. Non-queue scheduler jobs still run without durable authority and can write after their owner lease has expired.

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Existing dashboard, metadata, scans, previews, uptime, and events preserve compatible persisted behavior. | ✓ VERIFIED | The full repository test command exited 0; compatibility/API/UI tests exercise real temporary SQLite state and browser-facing contracts. |
| 2 | Backup, transactional migration, retention, exclusive maintenance, and recovery are safe and repeatable. | ✓ VERIFIED | Recovery authorization and backup/migration modules are substantive and their focused test artifacts remain production-wired. |
| 3 | Recovery is authorized only by a valid failed-migration marker bound to its verified catalog ID; invalid/direct attempts leave healthy bytes untouched. | ✓ VERIFIED | `recovery.py` validates authorization before maintenance/replacement; its tests are included in the successful full suite. |
| 4 | Web imports and Flask construction start no background work; explicit module boundaries and persistence collaborators remain in place. | ✓ VERIFIED | Focused import/lifecycle regression: 2 passed; `dashboard/beacon/` has no reverse `dashboard.app` import. |
| 5 | A single persisted worker owns **all** shared scheduled execution, and successor takeover prevents late old-worker writes. | ✗ FAILED | Real SQLite reproduction: after B acquired, A's actual `do_uptime_check()` changed service state to online, wrote one `service_checks` row, and enqueued one preview request. |
| 6 | Durable scans/previews coordinate by row lease, renew long scans, recover/expire safely, coalesce, and fence queue-row takeovers. | ✓ VERIFIED | Plan 20's focused stale A→B queue matrix passed: 3 tests, 10 subtests. |
| 7 | Probes, fetches, redirects, webhooks, and Chromium use one selected-address/TLS policy. | ✓ VERIFIED | Hostile HTTPS/WSS focused regression passed; outbound artifacts and policy links are substantive and wired. |
| 8 | Preview traffic is retrieval-only for supported browser transports. | ✓ VERIFIED | Focused hostile HTTPS preview test passed; production context installs HTTP and WebSocket routing gates before page creation. |
| 9 | Browser-preview non-retrieval methods are rejected before policy/origin connection, and pre-relay resources clean up exactly once. | ✓ VERIFIED | `previews.py`/`outbound.py` implement the method gate and explicit ownership transfer; associated integration tests passed in the full suite. |
| 10 | Metadata rejects scalar/exact-type violations before persistence, outbound, or queue side effects while compatible edits work. | ✓ VERIFIED | The API validation and real-SQLite snapshot tests are substantive and included in the successful suite. |
| 11 | Stale/recovered monitoring, queue/expiry, TLS, error, responsive, and theme states remain candid and interactive. | ✓ VERIFIED | UI assets are API-wired and the supplied schema/UI gates plus full suite pass. |
| 12 | Every current/retained operator database is represented in the support floor. | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | Checked-in support-floor fixtures and unknown-shape refusal are real; the live/retained Pi database inventory is an external pre-upgrade check. |

**Score:** 18/20 truths verified (1 present but external-behavior-unverified).

### Roadmap Success Criteria

| # | Success criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Existing dashboard/data behavior remains usable after restructuring/upgrading. | ✓ VERIFIED | Compatibility, Flask/SQLite, and UI safety coverage passes. |
| 2 | Operator can create a usable backup before an upgrade and recover data after migration failure. | ✓ VERIFIED | Recovery/backup artifacts are substantive, policy-gated, and test-covered. |
| 3 | Loading web starts no background work; the worker owns shared scheduled work without duplicate execution. | ✗ FAILED | Import separation passes, but stale A can still execute and commit an uptime job after B owns the durable lease. |
| 4 | Probes/previews/redirects/webhooks block unsafe targets or invalid TLS and report safe failure. | ✓ VERIFIED | Hostile HTTPS/WSS regression passed; shared outbound policy is production-wired. |

### Required Artifacts

| Artifact group | Expected | Status | Details |
| --- | --- | --- | --- |
| `config.py`, `db.py`, `repositories.py`, `web.py` | Explicit web/config/persistence boundaries | ✓ VERIFIED | All declared artifacts are substantive; `app.py` delegates through the factory/repository seams. |
| `migrations.py`, `recovery.py`, fixtures/tests | Safe migration, backup, and recovery | ✓ VERIFIED | Authorization is before maintenance/replacement and the paths are test-covered. |
| `queues.py`, `app.py`, durable-queue tests | Worker epoch and row/revision-fenced queue processing | ✓ VERIFIED | `_assert_current_worker_owner()` is inside the queue `BEGIN IMMEDIATE` transactions; focused A→B tests pass. |
| `worker_main.py`, `app.py` scheduler operations | Sole durable authority for every worker-originated mutation | ✗ HOLLOW | Epoch/admission wiring exists only for scan/preview processing. Direct scheduler jobs remain unfenced. |
| `outbound.py`, `previews.py`, policy tests | Pinned retrieval-only outbound/browser transport | ✓ VERIFIED | HTTP and WebSocket gates are installed in production context creation and focused hostile test passes. |
| `app.js`, `index.html`, `style.css`, UI tests | Candid, usable safety states | ✓ VERIFIED | API-fed UI artifacts are substantive and linked to real Flask/SQLite integration tests. |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `run_worker()` | `WorkerLease.owner_token` | acquisition → `WorkerServices` → heartbeat/processors/final release | ✓ WIRED | `worker_main.py:123-153, 272-274` retains and passes the exact token. |
| scan/preview processors | queue mutations | `worker_id`, owner token, and row/revision credentials | ✓ WIRED | `app.py:1467+` and `1526+` pass owner token; `queues.py` asserts it inside transactions. |
| preview terminal result | title/thumbnail/event persistence | one fenced app-owned transaction | ✓ WIRED | `app.py:1548+` calls `finish_preview_in_transaction()` before result-side writes. |
| heartbeat | scan/preview admission/drain | `LeaseLost` closes admission then requests `shutdown(wait=False)` | ✓ WIRED | `worker_main.py:123-136, 235-251`; focused drain-order regression passes. |
| scheduler discovery/uptime/metrics/cleanup/recovery | current durable worker epoch | worker-owned mutating transaction | ✗ NOT WIRED | Direct scheduler callbacks do not take credentials; corresponding app operations have no durable-owner predicate. |

### Data-Flow Trace (Level 4)

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Scan/preview queue processing | `worker_id`, `owner_token`, row/revision lease | worker acquisition → `WorkerServices` → app processors → SQLite | Yes; every queue mutation asserts live owner in transaction | ✓ FLOWING |
| Dashboard safety UI | services/events/runtime status | Flask APIs → repositories → SQLite | Yes | ✓ FLOWING |
| Recovery | marker → catalog record → staged database | filesystem manifest and SQLite validation | Yes | ✓ FLOWING |
| Discovery/uptime/metrics/cleanup | scheduled callback | APScheduler → app monitoring operation → SQLite | Yes, but without an owner token/current-owner predicate | ✗ UNFENCED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Full repository regression suite | `uv run --project dashboard python -m pytest -q` | Exit 0 | ✓ PASS |
| Queue takeover rejects late stale mutations | Focused `tests/test_durable_queues.py -k 'stale_worker_takeover... or worker_owner_epoch...'` | 3 passed, 10 subtests | ✓ PASS |
| Web import/lifecycle no-side-effect regressions | Focused `tests/test_runtime_ownership.py -k 'fresh_process_import or worker_main_is_the_only...'` | 2 passed | ✓ PASS |
| Hostile HTTPS preview cannot establish WSS/mutate | Focused `tests/test_outbound_policy.py -k 'hostile_https_preview_cannot_open_wss...'` | 1 passed | ✓ PASS |
| Stale A uptime write after B takeover | Real temporary SQLite: A expires, B acquires, then A calls actual `do_uptime_check()` | Service `(online=1, latency=7.5)`, 1 check, 1 preview enqueue | ✗ FAIL |

### Probe Execution

Step 7c: **SKIPPED** — no conventional `scripts/*/tests/probe-*.sh` files and no phase-declared probes exist.

### Requirements Coverage

| Requirement | Source plans | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| FND-01 | 01-01, 02, 03, 06, 08, 14 | Compatibility protection for dashboard/service/discovery/preview/uptime/event behavior | ✓ SATISFIED | Full suite plus compatibility/API/UI artifacts pass. |
| FND-02 | 01-02, 03, 13 | Explicit web/config/persistence/monitoring/discovery/preview/scheduling boundaries | ✓ SATISFIED | Substantive package modules; no reverse `dashboard.app` import found. |
| FND-03 | 01-01, 02, 03, 19 | Web import starts no background work | ✓ SATISFIED | Focused fresh-process import regression passes. |
| FND-04 | 01-01, 03, 06, 11, 19, 20 | Worker-only scheduling with durable persisted coordination | ✗ BLOCKED | Owner epoch fences only queue paths; CR-01 remains reproducible for actual uptime work. |
| FND-05 | 01-04 | Versioned, transactional, idempotent migrations against representative databases | ✓ SATISFIED (preflight pending) | Fixtures/refusal logic are verified. Live-inventory confirmation is a required operator preflight, not a code gap. |
| FND-06 | 01-04, 05, 09, 10, 15 | Verified pre-upgrade backup and safe failed-upgrade recovery | ✓ SATISFIED | Marker/catalog authorization and maintenance/recovery evidence present. |
| FND-07 | 01-07, 08, 12, 16, 18 | One tested outbound-target and TLS safety policy | ✓ SATISFIED | Focused TLS/WSS and shared policy wiring pass. |
| OPS-05 | 01-07, 08, 12, 13, 14, 16, 17, 18 | Automated outbound/DNS/redirect/TLS/mutation protections | ✓ SATISFIED | Security regressions, including hostile WSS, pass. |

No Phase 1 requirement is orphaned. The ownership gap is not deferred: later Phase 6 mentions broad workload resilience, but does not explicitly deliver the Phase 1 durable sole-worker contract.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | ---: | --- | --- | --- |
| `dashboard/beacon/worker_main.py` | 138-169, 199-230 | Admission and epoch propagation exist only for scan/preview; other mutating callbacks are direct | 🛑 BLOCKER | A scheduler job submitted before lease loss can run after successor takeover. |
| `dashboard/app.py` | 182-185, 984-1004, 1023-1221, 1233-1328 | Worker-originated writes have no durable owner predicate | 🛑 BLOCKER | Stale owner can update health/check/event/runtime state and enqueue previews. |

No unreferenced `TBD`, `FIXME`, or `XXX` marker was found in Phase 1 implementation/test files. SQL `?` placeholders and intentionally safe "backup is not available" recovery errors are not stubs.

### Human Verification Required

#### 1. Current/retained Pi database inventory

**Test:** Run the documented read-only inventory checklist for every deployed and retained Beacon database before an upgrade.

**Expected:** Every fingerprint is in the support-floor manifest with a corresponding sanitized fixture; unknown shapes stop the upgrade.

**Why human:** Repository tests cannot access the operator's database files.

#### 2. Judgment-tier preview and deployed worker lifecycle checks

**Test:** After fixing the blocker, complete the HTTPS preview and controlled worker-replacement checks listed in the frontmatter.

**Expected:** HTTPS previews remain usable while WSS is blocked, and a replacement worker has no stale old-worker effects.

**Why human:** These plan prohibitions deliberately require an operator-facing, deployed-process judgment beyond the automated suite.

### Gaps Summary

This is an **Escalation Gate**. Do not advance Phase 1 or mark FND-04 complete.

Wave 14 successfully repaired the original scan/preview queue transition: stale epoch operations now fail closed with no queue/result-side write. But the phase goal requires a sole active worker for *all* shared scheduled execution. The direct real-SQLite reproduction proves that the same stale worker can still mutate uptime state and enqueue preview work after a successor owns `runtime_state.worker_owner`; static tracing shows discovery, metrics, cleanup, and recovery have the same missing authority boundary.

The next action is a focused FND-04 closure plan that applies durable epoch fencing and admission/drain protection to every worker-only scheduler mutation, adds real SQLite A→B takeover coverage for each class, then re-runs this verification. The live database inventory remains a separate pre-upgrade operator checkpoint, not an automated implementation blocker.

---

_Verified: 2026-08-04T21:29:07Z_
_Verifier: the agent (gsd-verifier)_
