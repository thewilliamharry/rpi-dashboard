---
phase: 01-behavioral-safety-runtime-ownership
verified: 2026-08-04T16:32:34Z
status: gaps_found
score: 18/20 must-haves verified
behavior_unverified: 1
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 17/20
  gaps_closed:
    - "Service previews remain retrieval-only and cannot mutate a policy-approved service through HTTPS or WebSocket transport."
    - "A worker that owns the durable scheduler lease releases it on normal scheduler exit and on every failure after acquisition, allowing a replacement worker to start promptly."
  gaps_remaining:
    - "The worker lease does not fence in-flight scheduled scan and preview work after a successor acquires the durable owner lease."
  regressions:
    - "CR-01 from 01-REVIEW.md: a stale worker can resume and commit a scan or preview after losing durable worker ownership."
gaps:
  - truth: "The worker is the sole active scheduler owner and durable ownership fences every shared scheduled operation after successor takeover."
    status: failed
    reason: "Worker heartbeat loss only requests scheduler shutdown. Already-running scan/preview jobs retain their independent row lease and terminal SQL never verifies runtime_state.worker_owner, so a stale worker can commit after a successor owns the durable worker lease."
    artifacts:
      - path: "dashboard/beacon/worker_main.py"
        issue: "heartbeat() calls shutdown(wait=False), which does not cancel or join running executor jobs before successor acquisition."
      - path: "dashboard/app.py"
        issue: "process_scan_requests() and process_preview_requests() pass only row-lease ownership to terminal writes; they do not prove the current durable worker owner."
      - path: "dashboard/beacon/queues.py"
        issue: "renew/finish/fail/requeue predicates check queue-row lease fields but never the current runtime_state worker_owner."
      - path: "tests/test_runtime_ownership.py"
        issue: "Lifecycle tests prove release on terminal paths, but no test loses the worker lease while a still-valid scan/preview lease is in flight."
    missing:
      - "Fence queue claim, renewal, requeue, and terminal writes with a durable worker-ownership epoch/token or equivalent current-worker predicate."
      - "On LeaseLost, prevent new work and cancel or join active jobs before releasing lifecycle ownership."
      - "Add real-SQLite scan and preview regressions in which Worker A loses the 15-second owner lease while retaining a longer queue lease, Worker B acquires, and every late A write raises LeaseLost."
behavior_unverified_items:
  - truth: "D-04: every current or retained operator Pi database is represented by the confirmed support-floor inventory."
    test: "Run the documented read-only inventory command against every deployed and retained Pi database, then compare fingerprints with dashboard/beacon/support_floor.json and tests/fixtures/legacy/operator/."
    expected: "Every fingerprint is represented by the support floor and has a matching sanitized fixture; an unknown shape is refused before migration."
    why_human: "Repository tests can exercise only checked-in sanitized fixtures and cannot inspect the operator's live or retained database files."
human_verification:
  - test: "Before a real upgrade, inventory every current and retained operator Beacon database using the documented read-only command."
    expected: "Every fingerprint is present in the support-floor manifest and has a matching sanitized fixture; any unknown shape blocks migration."
    why_human: "The repository has no access to operator-owned database files."
  - test: "Manually preview an approved HTTPS service with JavaScript and GET/HEAD subresources, and observe the trusted-LAN TLS exception state."
    expected: "The preview renders without globally disabling JavaScript; WebSocket creation is blocked and the TLS exception is distinguished from service downtime."
    why_human: "Plan 18's descriptor-less prohibition requires an operator-facing visual judgment beyond the automated TLS/WSS regression."
  - test: "During a controlled worker restart/failure, verify the dashboard stays usable and no old scheduler performs work after the replacement becomes owner."
    expected: "No locked dashboard outage or overlapping old/new scheduled effects occur."
    why_human: "Plan 19's descriptor-less prohibition has no separate end-to-end deployment check; the new automated fencing gap must be fixed first."
---

# Phase 01: Behavioral Safety & Runtime Ownership Verification Report

**Phase Goal:** The operator can safely continue using and upgrading Beacon while its web, worker, persistence, and outbound-access responsibilities are dependable and independently maintainable.

**Verified:** 2026-08-04T16:32:34Z
**Status:** gaps_found
**Re-verification:** Yes — after Plans 01-18 and 01-19

## Goal Achievement

The prior HTTPS/WebSocket preview-mutation and ordinary worker-exit lease-release blockers are closed in the current code and independently exercised. Phase 1 still fails its ownership contract: a worker that loses the short durable owner lease can complete an already-running long queue lease after a successor takes ownership. This creates stale monitoring/preview writes and violates the roadmap promise of one visible owner without duplicate execution.

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Existing dashboard, metadata, scans, previews, uptime, and events preserve compatible persisted behavior. | ✓ VERIFIED | Compatibility, UI-state, API, SQLite, migration, queue, and release-contract tests are substantive and included in the authoritative 155-test gate. |
| 2 | Backup, transactional migration, retention, exclusive maintenance, and recovery are safe and repeatable. | ✓ VERIFIED | `recovery.py` authorizes marker/catalog-bound recovery before locks or replacement; migration/recovery paths retain transactional maintenance and checked fixtures. |
| 3 | Recovery is authorized only by a regular, valid failed-migration marker bound to the exact verified catalog ID, and invalid/direct/CLI attempts leave healthy bytes untouched. | ✓ VERIFIED | `_authorized_recovery()` runs before `exclusive_database_maintenance()` and recovery tests cover healthy refusal and catalog-bound selection. |
| 4 | Web imports and Flask construction start no background work; package boundaries and explicit persistence collaborators remain in place. | ✓ VERIFIED | Fresh-process import test, `create_app(load_settings(), legacy_app=app)`, and worker-only composition imports remain wired. |
| 5 | A single persisted worker owns shared scheduled execution; release and successor takeover cannot leave old jobs able to write. | ✗ FAILED | `heartbeat()` only calls `scheduler.shutdown(wait=False)`. The direct temporary-SQLite reproduction acquired Worker B at t=16 then allowed Worker A to `finish_scan()` its valid 60-second row lease; the row became `completed`. |
| 6 | Durable scans/previews coordinate by row lease, renew long scans, recover/expire safely, coalesce, and fence row-lease takeovers. | ✓ VERIFIED | `queues.py` has transactional row-lease predicates and `test_durable_queues.py` exercises expiry, token takeover, renewal, and stale row owners. This does not substitute for worker-owner fencing in Truth 5. |
| 7 | Probes, fetches, redirects, webhooks, and Chromium use the unified selected-address/TLS policy. | ✓ VERIFIED | Pinned destination, Host/SNI identity, redirect/rebinding, strict webhook, and trusted-LAN TLS paths remain production-wired and gate-tested. |
| 8 | Preview traffic is retrieval-only for every supported transport. | ✓ VERIFIED | `browser_proxy_context()` installs both `route()` and catch-all `route_web_socket()` before yielding; the focused hostile TLS/WSS test passed with no handshake or frame. |
| 9 | HTTP browser-preview non-retrieval methods are rejected before policy/origin connection, and pre-relay resources are cleaned up exactly once. | ✓ VERIFIED | Route and proxy method gates plus explicit pre-relay close/release ownership are present; cleanup and hostile-method tests passed in the authoritative gate. |
| 10 | Metadata rejects scalar payloads and exact-type violations before persistence/outbound/queue side effects, while compatible valid edits work. | ✓ VERIFIED | Compatibility endpoint validates exact boolean/non-boolean bounded integer before durable work; real SQLite snapshot regressions cover rejected payloads. |
| 11 | Stale/recovered monitoring, queue/expiry, TLS, error, responsive, and theme states remain candid and interactive. | ✓ VERIFIED | Browser assets are API-wired to real temporary-SQLite state and UI safety/state contract coverage is present. |
| 12 | Every current/retained operator database is represented in the support floor. | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | Checked-in fixtures and unknown-shape refusal are substantive, but the repository cannot inventory actual Pi database files. |

**Score:** 18/20 truths verified (1 present, behavior-unverified)

### Roadmap Success Criteria

| # | Success criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Existing dashboard/data behavior remains usable after restructuring/upgrading. | ✓ VERIFIED | Compatibility and real SQLite/browser tests remain connected and pass the supplied complete gate. |
| 2 | Operator can create a usable backup before an upgrade and recover data after migration failure. | ✓ VERIFIED | Marker-bound recovery and backup/migration artifacts are substantive and production-wired. |
| 3 | Loading the web app starts no background work; the worker owns shared scheduled work without duplicate execution. | ✗ FAILED | Import separation holds, but an in-flight stale worker can still complete work after durable ownership transfers. |
| 4 | Probes/previews/redirects/webhooks block unsafe targets or invalid TLS and report safe failure. | ✓ VERIFIED | The dedicated hostile HTTPS/WSS test passed; policy-pinned retrieval and safe failures remain wired. |

### Required Artifacts

| Artifact group | Expected | Status | Details |
| --- | --- | --- | --- |
| `config.py`, `db.py`, `repositories.py`, `web.py` | Explicit web/config/persistence boundaries | ✓ VERIFIED | All declared artifacts are substantive; app factory and repository links remain production-used. |
| `monitoring.py`, `previews.py`, `worker_main.py`, `worker.py` | Flask-free monitoring/preview work and worker-only composition | ⚠️ PARTIAL | Lifecycle finalization is real, but the worker layer does not propagate durable ownership into in-flight job writes. |
| `migrations.py`, `recovery.py`, support-floor fixtures/tests | Safe migration, backup, and recovery | ✓ VERIFIED | Authorization precedes mutation, maintenance is exclusive, and tests cover repeat/refusal paths. |
| `queues.py`, `app.py`, durable-queue tests | Durable claims and fenced terminal work | ⚠️ PARTIAL | Queue-row fence is real; durable worker-owner fence is absent from claims and terminal transitions. |
| `outbound.py`, `previews.py`, outbound-policy tests | Pinned retrieval-only outbound/browser transport | ✓ VERIFIED | HTTP and WebSocket gates are installed before pages; WSS block has direct TLS evidence. |
| `app.js`, `index.html`, `style.css`, UI tests | Candid, usable safety and stale-monitoring state | ✓ VERIFIED | API-driven dashboard states and controls remain connected. |

All file artifacts declared in Plans 01-01 through 01-19 passed the substantive artifact query except the tool's known descriptor limitations for a directory artifact and `file.py::symbol` sources. Those exceptions were manually traced in the production files above; they are not the reason for this verdict.

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `recovery.py` | marker, catalog, maintenance lifecycle | authorization before lock/replacement | ✓ WIRED | `_authorized_recovery()` precedes `exclusive_database_maintenance()`. |
| `worker_main.py` | `queues.release_worker_lease()` | post-acquisition outer finalizer | ✓ WIRED | `run_worker()` invokes `_finalize_worker_lifecycle()` from its outer `finally`; focused lifecycle tests passed. |
| `worker_main.py` → `app.py` → `queues.py` | current durable worker owner | active job claim/renew/terminal mutation | ✗ NOT WIRED | Jobs receive only `worker_id`/queue-row tokens; no query or predicate binds them to `runtime_state.worker_owner`. |
| `previews.py` | Playwright route and WebSocket route | policy installer before context yields/page creation | ✓ WIRED | Installer registers both handlers before `context.new_page()`; focused WSS test passed. |
| `outbound.py` | selected numeric destination | policy plan, pinned sockets, preserved Host/SNI | ✓ WIRED | Transport and proxy use the selected address while retaining origin identity. |
| `app.py::api_service_meta` | repository/preview queue/events | exact validation before transaction | ✓ WIRED | Invalid fields return before mutation work; snapshot regressions cover it. |

### Data-Flow Trace (Level 4)

| Artifact | Data variable | Source | Produces real data | Status |
| --- | --- | --- | --- | --- |
| Dashboard safety UI | services, events, worker/queue state | Flask APIs → repositories → SQLite | Yes | ✓ FLOWING |
| Recovery | marker → catalog record → staged database | filesystem manifest and SQLite validation | Yes | ✓ FLOWING |
| Preview browser policy | route/WebSocket event → proxy/policy context | production `browser_proxy_context()` | Yes | ✓ FLOWING |
| Worker queue execution | `worker_id`, queue-row lease | scheduler → app queue processors → SQLite | Yes, but no owner-epoch/current-owner check | ✗ UNFENCED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Hostile HTTPS preview cannot establish WSS or deliver mutation frame | `uv run --project dashboard python -m pytest -q tests/test_outbound_policy.py -k 'hostile_https_preview_cannot_open_wss_or_deliver_mutation_frame'` | 1 passed, 23 deselected in 3.13s | ✓ PASS |
| Normal return, post-acquisition failures, and signal ordering release a worker lease | Focused `tests/test_runtime_ownership.py -k 'worker_releases_lease... or stop_worker...'` | 3 passed, 14 deselected, 11 subtests in 0.27s | ✓ PASS |
| Stale in-flight scan after worker-owner takeover | Temporary SQLite: A claims 60s row lease; B acquires expired 15s worker lease; A finishes at t=16 | Printed `completed` | ✗ FAIL |
| Full Phase 1 test gate | `uv run --project dashboard python -m pytest -q` | Authoritative combined Wave 13 evidence: 155 tests, 158 subtests passed | ✓ PASS (supplied evidence) |
| Python compilation and Compose topology | Python compilation; `docker compose config -q` | Authoritative combined Wave 13 evidence: passed | ✓ PASS (supplied evidence) |

### Probe Execution

Step 7c: SKIPPED — no conventional `scripts/*/tests/probe-*.sh` files or phase-declared probes exist.

### Requirements Coverage

| Requirement | Source plans | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| FND-01 | 01-01, 02, 03, 06, 08, 14 | Compatibility protection for existing dashboard/service/discovery/preview/uptime/event behavior | ✓ SATISFIED | Compatibility and browser/SQLite coverage remains production-connected. |
| FND-02 | 01-02, 03, 13 | Explicit web/config/persistence/monitoring/discovery/preview/scheduling boundaries | ✓ SATISFIED | Explicit modules and composition root remain intact. |
| FND-03 | 01-01, 02, 03, 19 | Web import starts no background work | ✓ SATISFIED | Fresh-import behavior is still covered; the stale-job failure begins after worker ownership transfer, not on web import. |
| FND-04 | 01-01, 03, 06, 11, 19 | Worker-only scheduling with durable persisted coordination | ✗ BLOCKED | Durable ownership gates startup and lifecycle exit but does not fence in-flight scan/preview operations after takeover. |
| FND-05 | 01-04 | Versioned transactional idempotent migrations against representative databases | ? NEEDS HUMAN | Fixture/migration evidence passes; live and retained Pi inventory is external. |
| FND-06 | 01-04, 05, 09, 10, 15 | Verified pre-upgrade backup and safe failed-upgrade recovery | ✓ SATISFIED | Bound-marker authorization and maintenance/recovery evidence are present. |
| FND-07 | 01-07, 08, 12, 16, 18 | One tested outbound-target and TLS safety policy | ✓ SATISFIED | WSS is blocked before handshake; pinned HTTP/TLS/redirect protections remain tested. |
| OPS-05 | 01-07, 08, 12, 13, 14, 16, 17, 18 | Automated outbound/DNS/redirect/TLS/mutation protections | ✓ SATISFIED | Focused real TLS/WSS regression passed; HTTP mutation and metadata protections remain covered. |

No Phase 1 requirement is orphaned. The stale-worker gap is not deferred: no later phase explicitly promises to repair Phase 1's durable sole-worker ownership contract. Phase 6's broader resilience goal is not a valid substitute for FND-04.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | ---: | --- | --- | --- |
| `dashboard/beacon/worker_main.py` | 87-96, 134-138 | Lease loss only asks the scheduler to stop | 🛑 BLOCKER | Already-running executor jobs can continue past ownership transfer. |
| `dashboard/app.py` | 1467-1516, 1519-1557 | Queue processors lack current-owner validation | 🛑 BLOCKER | Stale owner can persist late scan/preview outcomes. |
| `dashboard/beacon/queues.py` | 376-405, 582-623 | Row-lease checks omit `worker_owner` fencing | 🛑 BLOCKER | Row validity outlives durable worker ownership. |

No unreferenced `TBD`, `FIXME`, or `XXX` marker was found in Phase 1 implementation/test files. Placeholder form attributes, SQL parameter placeholders, and the deliberate safe recovery error are not stubs.

### Human Verification Required

#### 1. Current/retained Pi database inventory

**Test:** Before a real upgrade, run the documented read-only inventory checklist for every deployed and retained Beacon database.

**Expected:** Every fingerprint is in the support-floor manifest with a corresponding sanitized fixture; unknown shapes stop the upgrade.

**Why human:** Repository tests cannot access the operator's actual database files.

#### 2. Descriptor-less prohibition review for the preview and worker safeguards

**Test:** Complete the two manual checks recorded in frontmatter after closing the worker-fencing gap.

**Expected:** HTTPS previews stay usable without globally disabling JavaScript, TLS posture is candid, and a controlled worker replacement leaves no stale scheduler effect.

**Why human:** Plans 18 and 19 intentionally carried judgment-tier prohibitions without executable descriptors. They are flagged, not silently accepted.

### Gaps Summary

This is an **Escalation Gate**. Do not advance Phase 1 or mark FND-04 complete. The prior two blockers are closed, but CR-01 is a new independent blocker: the durable worker lease controls admission and lifecycle release, not authority for already-running queue jobs.

The required next action is a focused FND-04 closure plan: introduce durable owner fencing through scan and preview claim/renew/requeue/terminal paths; halt or join active work on lease loss; then add an integration regression that proves stale Worker A cannot write after Worker B acquires ownership. Re-run Phase 1 verification afterward. The external database-inventory check remains a separate pre-upgrade operator checkpoint.

---

_Verified: 2026-08-04T16:32:34Z_
_Verifier: the agent (gsd-verifier)_
