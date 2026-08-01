---
phase: 01-behavioral-safety-runtime-ownership
verified: 2026-08-01T07:27:40Z
status: gaps_found
score: 17/20 must-haves verified
behavior_unverified: 1
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 31/45
  gaps_closed:
    - "FND-02 dependency direction and explicit preview repository ownership"
    - "FND-04 scan lease renewal, claim-time recovery, deadline expiry, and fencing"
    - "FND-06 WAL/SHM cleanup and all-writer maintenance exclusion"
    - "FND-07 and OPS-05 selected-address enforcement for HTTP and Chromium"
    - "Scalar JSON metadata rejection and malformed-integer Settings fallback"
    - "Eight browser/UI behavior items previously present but unexercised"
  gaps_remaining:
    - "Recovery accepts a healthy database and can roll it back without a pre-existing recovery-required condition."
    - "The preview proxy forwards unsafe HTTP methods from untrusted preview content to policy-allowed services."
  regressions: []
gaps:
  - truth: "Operator can recover Beacon data after a migration failure without the recovery command silently replacing a healthy current database."
    status: failed
    reason: "restore_backup() selects any verified catalog record and replaces dashboard.db without requiring or validating recovery-required.json."
    artifacts:
      - path: "dashboard/beacon/recovery.py"
        issue: "restore_backup() at lines 266-328 writes a marker only after it has selected the backup; it never reads a pre-existing marker as authorization."
      - path: "dashboard/beacon/recovery.py"
        issue: "CLI restore --latest/--id at lines 342-367 reaches restore_backup() even when status reports recovery_required=false."
    missing:
      - "Require and validate the existing recovery marker before restore, binding its catalog ID to the requested restore (or make --latest use only that ID)."
      - "Add a regression proving a healthy database is byte-for-byte unchanged and restore is refused when no recovery marker exists."
  - truth: "Fetched Chromium previews are retrieval-only and cannot mutate an allowed service while enforcing the outbound policy."
    status: failed
    reason: "The loopback policy proxy forwards browser-supplied HTTP methods and bodies unchanged; a preview page can submit POST/PUT/PATCH/DELETE to any policy-approved origin."
    artifacts:
      - path: "dashboard/beacon/outbound.py"
        issue: "_PolicyProxyHandler.handle() at lines 282-299 uses the supplied method in the forwarded request line and has no safe-method allowlist."
      - path: "dashboard/beacon/previews.py"
        issue: "route_browser_request() at lines 71-79 validates only URL policy and continues every browser request method."
    missing:
      - "Allow only GET and HEAD for browser-preview traffic at both the route and plain-HTTP proxy boundary; reject other methods before opening an origin socket."
      - "Add a real-browser/proxy regression proving a preview form or fetch POST to another allowed service never reaches that service."
behavior_unverified_items:
  - truth: "D-04: every current or retained operator Pi database is represented by the confirmed support-floor inventory."
    test: "Run the documented read-only inventory command against every deployed/retained Pi database and compare fingerprints with dashboard/beacon/support_floor.json and tests/fixtures/legacy/operator."
    expected: "Each fingerprint is classified by the support floor and has a corresponding sanitized fixture; any unknown shape is refused rather than upgraded."
    why_human: "The repository contains only sanitized fixtures and cannot inspect databases currently retained by the operator."
human_verification_count: 1
human_verification:
  - test: "Operator Pi database inventory"
    expected: "All current/retained database fingerprints are represented in the support floor before an upgrade is attempted."
    why_human: "External deployed/retained database inventory is unavailable to repository tests."
---

# Phase 01: Behavioral Safety & Runtime Ownership Verification Report

**Phase Goal:** The operator can safely continue using and upgrading Beacon while its web, worker, persistence, and outbound-access responsibilities are dependable and independently maintainable.

**Verified:** 2026-08-01T07:27:40Z
**Status:** gaps_found
**Re-verification:** Yes — after Plans 01-09 through 01-14

## Goal Achievement

The five originally failed implementation truths are now substantively closed, and the prior nine UI behavior gaps are reduced to one honest operator-only database-inventory check. However, the goal is still **not achieved**: recovery is destructive when invoked on a healthy database, and a hostile page rendered for a preview can send state-changing requests to another policy-allowed service. Both are reproducible current-code safety failures, not missing test evidence alone.

### Roadmap Success Criteria

| # | Success criterion | Status | Evidence |
|---|---|---|---|
| 1 | Existing dashboard/data behavior remains usable after restructuring/upgrading | ✓ VERIFIED | Compatibility routes retain their API shapes and real SQLite/browser coverage exercises services, metadata, scans, previews, uptime, and events. The orchestrator's full run passed: 137 tests and 90 subtests. |
| 2 | Operator can create a usable backup before an upgrade and recover Beacon data after a migration failure | ✗ FAILED | Verified backup, WAL/SHM lifecycle, writer exclusion, and repeat-restore mechanics exist; but recovery has no pre-existing recovery-required authorization and can roll a healthy database back. |
| 3 | Web loading starts no background work; worker owns scheduled work without duplication | ✓ VERIFIED | Fresh-process isolation tests, injected worker composition, persisted owner lease, and scan lease heartbeat/recovery are present and exercised. |
| 4 | Probes/previews/redirects/webhooks block unsafe targets/TLS safely and report safe failure | ✗ FAILED | Destination pinning and TLS/SNI preservation work, but preview content can use the proxy for unsafe mutations to an allowed target. |

### Observable Truths

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | Existing dashboard, metadata, scans, previews, uptime, and events retain usable compatibility behavior | ✓ VERIFIED | `tests/test_api_and_auth.py`, `test_uptime_integration.py`, `test_ui_safety_integration.py`, and the full suite use current routes and real SQLite. |
| 2 | Recovery is safe only after a migration failure and preserves a healthy database otherwise | ✗ FAILED | Direct isolated probe changed a database title to `healthy-current`, called `restore_backup()` with no marker, and read back `Sample Service` from the old backup. |
| 3 | Fresh web import starts no background work; one persisted worker owns scheduling and durable shared work | ✓ VERIFIED | `worker_main.run_worker()` acquires the durable owner before scheduler construction; fresh-import and ownership tests pass. |
| 4 | Outbound probes, previews, redirects, and webhooks consistently enforce safe retrieval boundaries | ✗ FAILED | A loopback probe through `PolicyProxy` received the origin's `HTTP/1.0 501 Unsupported method ('POST')`, proving the proxy forwarded the preview POST to the allowed origin. |
| 5 | FND-02 dependency direction and preview persistence ownership are explicit | ✓ VERIFIED | Package AST test rejects all absolute/relative legacy-app imports; `dashboard/worker.py` injects `WorkerOperations`; `previews.store_thumbnail_result()` delegates to `ThumbnailRepository`. |
| 6 | FND-04 scans renew ownership, recover without restart, expire at deadline, and fence stale workers | ✓ VERIFIED | `process_scan_requests()` starts `ScanLeaseHeartbeat`; queue transitions condition on owner and unexpired lease; `test_durable_queues.py` covers long scan, takeover, recovery, and expiry. |
| 7 | FND-06 restore quiesces WAL/SHM and excludes all managed web/worker connections | ✓ VERIFIED | `exclusive_database_maintenance()` holds an exclusive flock; `restore_backup()` orders upgrade then maintenance locks, performs zero-busy WAL checkpoint, deletes exact sidecars, fsyncs, and tests a concurrent metadata writer. |
| 8 | FND-07 actual HTTP and Chromium sockets use an approved numeric destination while retaining Host/SNI identity | ✓ VERIFIED | `OutboundTransport._send_pinned()` pools by `selected_address`; `PolicyProxy._connect()` connects to it; tests prove Host, SNI, redirect replan, and rebinding behavior. |
| 9 | OPS-05 covers outbound and mutation-request protections at the browser-preview boundary | ✗ FAILED | Tests cover Host/Origin/UI headers and rebinding, but no safe-method restriction or negative browser mutation test exists; source forwards the method/body. |
| 10 | Scalar metadata JSON returns stable 4xx rather than raising | ✓ VERIFIED | `api_service_meta()` rejects non-object JSON at `dashboard/app.py:1836-1838`; tests send `[]`, strings, numbers, booleans, and null. |
| 11 | Malformed integer environment values fall back safely and app import remains available | ✓ VERIFIED | `config._positive_int()` returns defaults on parse/range failure; `test_malformed_integer_environment_uses_settings_defaults_without_import_crash` exercises malformed deployment values. |
| 12 | Stale monitoring leaves controls usable and stale-to-fresh recovery records the monitoring gap without reload | ✓ VERIFIED | `test_stale_to_fresh_page_persists_actions_and_records_recovery` operates theme/link/metadata/scan, observes durable rows, then observes banner removal and event rendering in one browser session. |
| 13 | Connected, stale, recovery, blocked-save, preview-failed, expiry, online/offline, and TLS states are distinct across themes | ✓ VERIFIED | Playwright safety matrix covers these states at 360px and 1440px and toggles to light theme. |
| 14 | TLS-unverified remains independent from online/offline, including stale/recovery presentation | ✓ VERIFIED | The safety matrix renders online and offline TLS-unverified cards while retaining their availability labels. |
| 15 | Long names/tags/events/errors remain readable and controls reachable at supported widths | ✓ VERIFIED | Browser matrix supplies deliberately long values, asserts no horizontal overflow, containment, and 44px controls at narrow and wide widths. |
| 16 | Queued/expired/recovered scan and preview behavior is truthful end to end | ✓ VERIFIED | The real Flask/SQLite/Chromium test queues work while stale, claims/completes it after recovery, expires an old request, and observes the candid UI states. |
| 17 | Every current/retained operator database is represented in the support floor | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | Fixtures and support-floor checks exist, but the repository cannot inspect the operator's actual retained/deployed databases. |

**Score:** 17/20 truths verified (1 present, behavior-unverified)

## Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `dashboard/beacon/db.py` | Shared access/exclusive maintenance leases | ✓ VERIFIED | Substantive managed SQLite connection implementation; used by app, queues, and migration/recovery paths. |
| `dashboard/beacon/recovery.py` | Sidecar-safe, writer-exclusive recovery | ⚠️ PARTIAL | WAL/SHM and writer-exclusion implementation is real and wired, but destructive entry is not guarded by a pre-existing recovery condition. |
| `dashboard/beacon/queues.py` | Durable worker and scan ownership state machines | ✓ VERIFIED | Claims, renewal, deadline expiry, recovery, and fenced terminal updates are transactional and called by production scan handling. |
| `dashboard/beacon/outbound.py` | Pinned policy transport and Chromium proxy | ⚠️ PARTIAL | Numeric destination enforcement is real; method policy is absent and resource cleanup has an unrepaired warning path. |
| `dashboard/beacon/previews.py` + `repositories.py` | Explicit preview persistence boundary | ✓ VERIFIED | Preview operations require a thumbnail repository collaborator and delegate storage there. |
| `dashboard/beacon/worker_main.py` + `dashboard/worker.py` | Package-independent runtime plus composition root | ✓ VERIFIED | Package module does not import legacy app; executable shim injects compatibility operations. |
| `dashboard/beacon/config.py` | Validated immutable settings | ✓ VERIFIED | Positive-integer fallback supplies the app's startup constants. |
| `dashboard/app.py` | Compatibility API and durable wiring | ✓ VERIFIED | Uses managed `connect_db`, Settings constants, queue heartbeat, repository collaborator, and outbound transport. |
| `tests/test_ui_safety_integration.py` + `tests/test_ui_states.py` | Browser evidence for Phase 1 safety UI | ✓ VERIFIED | Real Flask/SQLite/Chromium stale-to-fresh flow plus deterministic two-theme state and overflow matrix. |

Artifact-query sanity checks reported all declared closure artifacts substantive and all declared links found for Plans 01-09 through 01-14. That is L1-L3 evidence only; the behavioral findings above override an artifact-only pass.

## Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `dashboard/worker.py` | `beacon.worker_main` | `WorkerOperations` injection / `run_worker()` | ✓ WIRED | Keeps the one allowed legacy dependency at executable composition root, outside the package. |
| `dashboard/app.py` | `beacon.queues` | `process_scan_requests()` heartbeat / terminal update | ✓ WIRED | One owner token is used for claim, renewal, requeue, and finish/fail. |
| `beacon.recovery` | `beacon.db` | upgrade lock then `exclusive_database_maintenance()` | ✓ WIRED | Excludes managed connections during WAL checkpoint/replacement. |
| `beacon.recovery` | `dashboard.db-wal` / `dashboard.db-shm` | checkpoint, unlink, fsync | ✓ WIRED | Exact target sidecars are removed after a successful zero-busy checkpoint. |
| `beacon.outbound` | numeric socket destination | urllib3 pools / proxy `_connect()` | ✓ WIRED | Uses `plan.selected_address`; Host/SNI stay on original authority. |
| Chromium preview context | loopback `PolicyProxy` | `browser_proxy_context()` | ⚠️ UNSAFE | The proxy is used for main frame/subresources, but forwards state-changing methods. |
| `app.js` | Flask/SQLite scan, service, event, metadata APIs | polling and mutation responses | ✓ FLOWING | UI integration test observes state changes from actual temporary SQLite rows. |

## Data-Flow Trace

| Artifact | Data variable | Source | Produces real data | Status |
|---|---|---|---|---|
| Dashboard safety UI | worker/queue/service/event state | Flask API → managed SQLite repositories | Yes; browser test uses copied production-schema fixture and reads/writes real rows | ✓ FLOWING |
| Scan processing | claimed request / owner token | `scan_requests` transaction | Yes; claim and heartbeat updates persist and are re-read by UI/API | ✓ FLOWING |
| Recovery | verified catalog backup → `dashboard.db` | catalog validation / copy / fsync | Yes, but lacks failure-state authorization | ⚠️ UNSAFE_ENTRY |
| Browser previews | browser request → policy plan → selected address | loopback proxy / policy resolver | Yes; origin socket is pinned, but method/body is not constrained | ⚠️ UNSAFE_METHOD |

## Behavioral Spot-Checks

| Behavior | Command / evidence | Result | Status |
|---|---|---|---|
| Full Phase suite | Orchestrator run with loopback privileges | 137 passed, 90 subtests, exit 0 | ✓ PASS (evidence, not sufficient for uncovered paths) |
| Build/config | Orchestrator run | compilation and `docker compose config -q` passed | ✓ PASS |
| Healthy recovery refusal | isolated temporary-db direct call to `restore_backup()` without marker | output `Sample Service` after current title was changed to `healthy-current` | ✗ FAIL |
| Preview safe-method boundary | loopback proxy probe sending `POST` to allowed origin | origin returned `HTTP/1.0 501 Unsupported method ('POST')`, which proves it received the forwarded request | ✗ FAIL |
| HTTP/Chromium pinning, redirect, SNI, rebind | `tests/test_outbound_policy.py` local origin scenarios | full suite passed; source uses `selected_address` in both transports | ✓ PASS |
| UI behavior closure | `test_ui_safety_integration.py` and `test_ui_states.py` | eight formerly unexercised UI items now have real browser coverage | ✓ PASS |

## Requirements Coverage

| Requirement | Description | Status | Evidence |
|---|---|---|---|
| FND-01 | Compatibility protection for existing dashboard/service/discovery/preview/uptime/event behavior | ✓ SATISFIED | Current API, SQLite, and browser compatibility tests cover retained routes and data flows. |
| FND-02 | Explicit web/config/persistence/monitoring/discovery/preview/scheduling boundaries | ✓ SATISFIED | AST import audit, injected worker composition, explicit repository persistence, and managed connection seam establish the intended direction. |
| FND-03 | Web import starts no background work | ✓ SATISFIED | Fresh subprocess tests cover no DB initialization, scheduler, browser, probe, signal, or network startup at import. |
| FND-04 | Worker-only scheduling with durable persisted shared coordination | ✓ SATISFIED | Owner lease, claims, scan heartbeat, normal-poll recovery, deadlines, and fencing are code-wired and tested. |
| FND-05 | Versioned transactional idempotent migrations against representative databases | ? NEEDS HUMAN | Fixtures, support floor, no-op/rollback, and migration tests pass; current/retained Pi database inventory remains unobservable here. |
| FND-06 | Verified pre-upgrade backup and safe recovery after failed upgrade | ✗ BLOCKED | The restore mechanics are robust, but invocation can silently discard healthy current data without a recovery-required guard. |
| FND-07 | One tested outbound-target and TLS policy for probes, previews, redirects, webhooks | ✗ BLOCKED | Purpose planning and destination pinning work; browser previews retain unauthorized mutation capability against allowed targets. |
| OPS-05 | Automated coverage of outbound target/DNS/redirect/TLS/mutation protections | ✗ BLOCKED | Broad coverage exists, but the browser-preview unsafe-method path is neither prevented nor covered by a negative regression. |

No Phase 1 requirement is orphaned: all eight map to Phase 1 plans. FND-06, FND-07, and OPS-05 must remain incomplete while the two safety gaps remain; FND-05 awaits the single operator inventory check.

## Fresh Review Finding Disposition

| Finding | Disposition | Requirement/goal impact | Exact evidence |
|---|---|---|---|
| CR-01: healthy database restore rollback | 🛑 BLOCKER — valid | Blocks FND-06 and roadmap criterion 2 | `restore_backup()` never reads a pre-existing marker; `restore --latest/--id` calls it directly. Direct temporary-db probe restored old title with no marker. |
| CR-02: preview proxy forwards unsafe methods | 🛑 BLOCKER — valid | Blocks FND-07, OPS-05, and roadmap criterion 4 | Proxy forwards `${method}` and request body at `outbound.py:294-299`; route guard checks URL only. Loopback POST reached origin. |
| WR-01: proxy slot/socket leak before relay | ⚠️ WARNING — valid | Does not itself falsify a current formal Phase 1 truth, but threatens preview availability after four pre-relay send failures; Phase 6 resilience work must not absorb it silently. | `_connect()` acquires a bounded semaphore; exceptions from `client.sendall`, header formatting, or `origin.sendall` go to `_reject()` before `_relay()` closes/releases origin. |
| WR-02: metadata boolean/integer coercion | ⚠️ WARNING — valid | Does not block a named current requirement, but makes mutation input ambiguous and can alter critical alert behavior contrary to caller intent. | `int(bool(payload.get('critical')))` accepts e.g. non-empty `"false"`; `int(True)` accepts boolean `pinned_order`; current scalar test does not cover these field values. |

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---:|---|---|---|
| `dashboard/beacon/recovery.py` | 266-328 | Destructive restore lacks failure-state authorization | 🛑 BLOCKER | A healthy current database can be silently replaced by an old backup. |
| `dashboard/beacon/outbound.py` | 282-300 | Browser proxy forwards arbitrary method/body | 🛑 BLOCKER | Previewed content can mutate any policy-approved service. |
| `dashboard/beacon/outbound.py` | 287-300, 400-445 | Semaphore/origin ownership transfers only inside `_relay()` | ⚠️ WARNING | Pre-relay failure can exhaust preview capacity. |
| `dashboard/app.py` | 1865-1867 | Boolean/integer coercion rather than strict validation | ⚠️ WARNING | Ambiguous metadata can change criticality or sort order. |

No unreferenced `TBD`, `FIXME`, or `XXX` debt marker was found in Phase 1 implementation or test files. Matches for ordinary UI input `placeholder` attributes and the user-facing `backup is not available` error are not stubs.

## Human Verification Required

### 1. Current/retained Pi database inventory

**Test:** Before upgrading a real Pi, execute the documented read-only inventory process for every deployed or retained database and compare results to the support-floor manifest and sanitized operator fixtures.

**Expected:** Every fingerprint is represented; unknown schema shapes stop the upgrade rather than being migrated.

**Why human:** Repository tests cannot see the operator's live and retained database files.

## Gaps Summary and Next Action

This is an **Escalation Gate**: do not advance Phase 1 or mark FND-06/FND-07/OPS-05 complete. First make recovery marker-gated and catalog-bound, then restrict preview traffic to safe methods at both enforcement seams and add negative tests for both findings. Address the two warnings in the same closure if feasible; after code repair, re-run focused recovery, outbound proxy/browser, metadata validation, and full Phase 1 verification. The Pi inventory remains a final operator action, not a code gap.

---

_Verified: 2026-08-01T07:27:40Z_
_Verifier: the agent (gsd-verifier)_
