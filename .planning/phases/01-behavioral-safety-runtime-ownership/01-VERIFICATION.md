---
phase: 01-behavioral-safety-runtime-ownership
verified: 2026-07-31T21:42:08Z
status: gaps_found
score: 31/45 must-haves verified
behavior_unverified: 9
overrides_applied: 0
gaps:
  - truth: "FND-02 edge resolution: web delivery, validated configuration, SQLite connections/transactions, and query ownership have explicit dependency direction with no import from beacon domain modules back into dashboard.app."
    status: failed
    reason: "The worker composition module imports the legacy dashboard.app module directly, and the preview module has no repository persistence wiring despite the declared key link."
    artifacts:
      - path: "dashboard/beacon/worker_main.py"
        issue: "Lines 18-21 import dashboard.app/app; this is a beacon-domain-to-legacy-app dependency."
      - path: "dashboard/beacon/previews.py"
        issue: "No repositories import or persistence call exists, so the declared preview-to-repositories link is absent."
    missing:
      - "Inject monitoring/preview compatibility operations from the composition root without importing dashboard.app from beacon modules."
      - "Wire preview persistence through an explicit repository dependency or revise the architecture with an accepted override."
  - truth: "FND-06 idempotency resolution: restoring the same verified backup twice while services are stopped leaves the same readable schema/data and no partial target."
    status: failed
    reason: "restore_backup replaces dashboard.db only and treats a stale worker heartbeat as proof that writers are stopped. It neither handles dashboard.db-wal/dashboard.db-shm nor excludes the still-live web writer, so a reported restore can replay or lose concurrent writes."
    artifacts:
      - path: "dashboard/beacon/recovery.py"
        issue: "Lines 253-269 check only worker staleness and have no web-writer lease, WAL/SHM quiesce/removal, or post-replace sidecar handling."
    missing:
      - "Quiesce/checkpoint or safely remove the exact WAL/SHM sidecars under the upgrade lock, fsync durability boundaries, and regression-test a live WAL sidecar."
      - "Prove all web and worker database writers are stopped or hold a shared maintenance lease before restore; add a concurrent web-metadata-write regression test."
  - truth: "FND-04 durable coordination: valid manual discovery reaches a terminal queue result within its bounded request lifetime."
    status: failed
    reason: "A scan is claimed with the queue default 30-second lease, but discovery is configured for up to 180 seconds and process_scan_requests never calls renew_scan_lease. finish_scan then rejects the stale claim and leaves the row running until restart recovery."
    artifacts:
      - path: "dashboard/app.py"
        issue: "Lines 1511-1535 run discovery and finish/fail the request without renewing its lease."
      - path: "dashboard/beacon/queues.py"
        issue: "claim_scan/finish_scan require an unexpired 30-second lease."
    missing:
      - "Renew the scan lease throughout discovery or align the lease with the full bounded operation and recover expired running rows promptly."
      - "Add an integration test for discovery lasting longer than 30 seconds that reaches a terminal queue state."
  - truth: "FND-07 edge resolution: service probes, HTML/title fetches, Chromium main/subresource requests, every redirect hop, and webhooks obtain a purpose-specific request plan from one outbound policy before network access."
    status: failed
    reason: "Plans validate DNS answers but the requests transport reconnects using plan.url's hostname and Chromium is allowed through route.continue_(). Neither connection is pinned to or checked against plan.resolved_addresses."
    artifacts:
      - path: "dashboard/beacon/outbound.py"
        issue: "Lines 259-266 pass hostname URL to requester and never consume resolved_addresses for connection binding."
      - path: "dashboard/beacon/previews.py"
        issue: "Lines 62-70 validate then call route.continue_(), letting Chromium perform an unverified later lookup."
    missing:
      - "Use a transport/resolver hook that binds each socket to a currently validated address while preserving Host/SNI, and replace/mediate Chromium continuation accordingly."
      - "Add rebinding tests that return an allowed policy lookup and a disallowed transport lookup."
  - truth: "D-11 / OPS-05: every redirect candidate and every current A/AAAA result are revalidated before the next connection, including rebinding-style result changes."
    status: failed
    reason: "Replanning redirect URLs is present, but it validates only a pre-connection resolver result. The actual transport/browser resolver can return a different address after validation."
    artifacts:
      - path: "tests/test_outbound_policy.py"
        issue: "Tests assert immutable plans and redirect replanning, but have no post-plan rebinding/socket-address test."
    missing:
      - "Prove per-connection selected-address enforcement for requests and Chromium in an automated rebinding regression test."
behavior_unverified_items:
  - truth: "D-13: stale-worker warning leaves links, metadata editing, scans, previews, and theme controls usable."
    test: "Make /api/scan-status report worker_stale=true and operate each listed control."
    expected: "The warning is shown but every control remains usable; browser/API disconnect styling is not shown."
    why_human: "The browser test exercises cards and theme controls, not this stale-worker transition with all controls."
  - truth: "D-16: recovery removes the stale warning and announces the persisted monitoring-gap event without refresh."
    test: "Transition /api/scan-status from stale to fresh in one loaded browser session."
    expected: "The warning disappears once, feedback announces recovery, and the event is visible."
    why_human: "Database recovery is tested and rendering branches exist, but no browser test exercises the transition."
  - truth: "D-04: every deployed or retained operator database shape is represented by the confirmed support-floor inventory."
    test: "Compare the current Pi's retained/deployed database inventory reports with tests/fixtures/legacy/operator and support_floor.json."
    expected: "Every fingerprint is classified and has a matching sanitized fixture; unknown shapes are not upgraded."
    why_human: "The repository cannot observe databases currently held by the operator."
  - truth: "Safety UI has distinct connected, stale, recovery-required, blocked-destination, save-failure, preview-failure, and expiry states."
    test: "Exercise each listed API/UI failure state in a browser."
    expected: "Each has the specified distinct copy, warning treatment, and recovery guidance."
    why_human: "Most states have source contracts only; the Playwright fixture does not traverse all error transitions."
  - truth: "Stale/recovery presentation preserves readable data and keeps TLS posture independent from availability."
    test: "Render stale and recovery states for online and offline TLS-unverified services."
    expected: "Readable cards remain; TLS unverified never replaces ONLINE/OFFLINE."
    why_human: "The browser test covers only an online TLS-unverified service without stale/recovery state."
  - truth: "Long service names, tags, events, and safe errors remain readable at supported widths."
    test: "Use long values in the metadata and event fixtures at desktop and 720px widths."
    expected: "The documented truncation/wrapping occurs without obscuring controls or exposing destination data."
    why_human: "No browser assertion uses long text or verifies the error presentation."
  - truth: "D-12 renders the TLS-unverified badge for both online and offline eligible services."
    test: "Render one online and one offline TLS-unverified service."
    expected: "Both show the persistent non-interactive badge while retaining their own availability state."
    why_human: "Automated browser coverage checks only the online case."
  - truth: "D-13 through D-16 queue, metadata, expiry, and recovery interactions remain candid end to end."
    test: "Queue a scan and preview while stale, expire each request, save metadata, then recover the worker."
    expected: "The UI shows queued/running/expired/recovered outcomes without claiming work ran early."
    why_human: "Current tests use isolated API/state fixtures rather than an end-to-end durable-worker transition."
  - truth: "Warning copy wraps and narrow controls remain unobscured for all safety states."
    test: "Inspect each safety banner and modal with long content at 720px."
    expected: "Copy stays within the page inset and all actions remain visible and operable."
    why_human: "The browser check verifies button height but not all warning/layout overflow cases."
---

# Phase 01: Behavioral Safety & Runtime Ownership Verification Report

**Phase Goal:** The operator can safely continue using and upgrading Beacon while its web, worker, persistence, and outbound-access responsibilities are dependable and independently maintainable.
**Verified:** 2026-07-31T21:42:08Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

The phase goal is **not achieved**. The codebase contains substantive Phase 1 modules and broad regression coverage, but five must-have truths fail. Four are the code-review critical risks independently confirmed in source: restore can replay old WAL state, recovery can race a web writer, manual discovery can outlive its queue lease, and outbound validation does not bind the actual connection. A fifth failure is the promised dependency direction: a `beacon` module imports the legacy application directly.

### Roadmap Success Criteria

| # | Success criterion | Status | Evidence |
|---|---|---|---|
| 1 | Existing dashboard/data behavior remains usable after restructuring/upgrading | ✓ VERIFIED | Compatibility, migration, queue, uptime, and UI tests pass; real API data flows from SQLite to the browser. |
| 2 | Usable backup and recovery after migration failure | ✗ FAILED | Recovery has verified catalog/staging checks, but sidecars and live web writers can defeat the restored state. |
| 3 | Web loading starts no background work; worker owns scheduled work without duplication | ✗ FAILED | Fresh default imports are side-effect-free and owner leasing blocks duplicate schedulers, but a valid manual scan can be stranded after its 30-second lease expires. |
| 4 | Probes/previews/redirects/webhooks block unsafe targets/TLS safely | ✗ FAILED | Policy validates request plans, but requests and Chromium reconnect by hostname after validation, allowing DNS rebinding. |

### Observable Must-Haves

| Plan | Truths checked | Result |
|---|---|---|
| 01-01 | Import ownership; stale-worker distinction; recovery gap; compatibility baseline | 2 verified; 2 present/behavior-unverified |
| 01-02 | Dependency direction; compatibility adapter; metadata during outage; pure factory | 3 verified; 1 failed |
| 01-03 | Flask-free domain operations; worker composition; no import-time scheduler/browser; compatibility behavior | 4 verified; declared preview→repository key link failed |
| 01-04 | Support floor; migration idempotency; verified backups; retention; locking; failure gate | 6 verified; 1 present/behavior-unverified (current operator inventory) |
| 01-05 | Offline restore path; catalog safety; repeat restore; migration/recovery lock; web while worker stopped | 4 verified; 1 failed |
| 01-06 | Worker owner lease; expiry; atomic claims; coalescing; metadata revisions; durable gap recovery | 6 verified |
| 01-07 | Unified outbound plans; TLS scope; redirects/DNS; OPS-05 matrix; immutable policy decisions | 2 verified; 3 failed |
| 01-08 | Ten locked UI state truths | 4 verified; 6 present/behavior-unverified |

**Score:** 31/45 truths verified (9 present, behavior-unverified)

### Required Artifacts

| Plan | Artifact status | Details |
|---|---|---|
| 01-01 | ✓ 4/4 substantive and wired | Runtime tests, app/worker composition, and dashboard stale-warning rendering exist. |
| 01-02 | ⚠️ 5/5 substantive; boundary incomplete | Config/db/repository/web modules exist, but `worker_main.py` imports `dashboard.app` and bypasses the intended direction. |
| 01-03 | ⚠️ 4/4 substantive; one link incomplete | Monitoring, previews, worker main, and shim exist; `previews.py` has no declared repository persistence dependency. |
| 01-04 | ✓ 6 substantive file artifacts plus legacy fixtures | The artifact query cannot inspect the directory artifact itself (`EISDIR`); its fixtures and support-floor files were inspected directly. |
| 01-05 | ✗ Recovery artifact is substantive but unsafe | Catalog validation/staging/lock code exists; WAL/SHM and live-web-writer protections are missing. |
| 01-06 | ✗ Queue artifact is substantive but scan lifecycle is hollow | Lease API exists, but production scan processing never renews it. |
| 01-07 | ✗ Outbound artifact is substantive but connection binding is missing | `resolved_addresses` is calculated yet unused by the actual requester/Chromium connection. |
| 01-08 | ✓ 4/4 substantive and flowing | Browser fetches `/api/scan-status`, `/api/services`, and `/api/events`; Flask routes query SQLite and Playwright exercises zero/one/many data. |

### Key Link Verification

| Link | Status | Evidence |
|---|---|---|
| Worker → persisted heartbeat/recovery | ✓ WIRED | `worker_main.main()` acquires owner lease, recovers, heartbeats, then builds the scheduler. |
| Browser → scan/services/events API → SQLite | ✓ FLOWING | `app.js` fetches the APIs; Flask handlers use persisted runtime/service/event data. |
| Web → queues | ✓ WIRED | Metadata and scan mutation paths enqueue durable work. |
| Worker → queues | ✓ WIRED, but behavior fails | Worker lease renewal is wired; scan-request lease renewal is not wired into discovery execution. |
| Preview → repositories | ✗ NOT_WIRED | `dashboard/beacon/previews.py` contains no `repositories` reference or persistence call. |
| Outbound policy → requests/Chromium | ✗ PARTIAL | Plan creation is wired; actual connection identity is not bound to the approved address. |
| Recovery → catalog/staging/database | ✗ PARTIAL | Verified catalog/staging and `os.replace` are wired, but sidecar handling and writer exclusion are absent. |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Phase automated suite | `dashboard/.venv/bin/python -m pytest -q` | 100 passed, 4 subtests passed; one browser test could not bind a loopback port in the sandbox | ? ENVIRONMENT-LIMITED |
| Real browser UI states | `dashboard/.venv/bin/python -m pytest -q tests/test_ui_states.py` | 6 passed outside the sandbox with a loopback-only ephemeral server | ✓ PASS |
| Malformed scalar metadata JSON | Flask test client PUT of JSON string | 500 with `AttributeError: 'str' object has no attribute 'keys'` | ⚠️ WARNING |
| Invalid deployment integer | `EXPIRE_DAYS=broken ... python -c 'import app'` | Import exits with `ValueError` at `dashboard/app.py:47` | ⚠️ WARNING |

The suite is useful but not sufficient evidence for the failed truths: `test_backup_recovery.py` does not retain a WAL sidecar, `test_outbound_policy.py` does not make a post-plan resolver/socket choice, and `test_module_boundaries.py` misses relative imports such as `from .. import app`.

### Requirements Coverage

| Requirement | Status | Evidence |
|---|---|---|
| FND-01 | ✓ SATISFIED | Compatibility/migration/uptime/UI contracts cover route and persisted-data behavior; focused and full tests pass apart from sandbox port restriction. |
| FND-02 | ✗ BLOCKED | `dashboard/beacon/worker_main.py:18-21` imports app directly; preview repository ownership link is missing; validated settings are bypassed by raw compatibility constants. |
| FND-03 | ✓ SATISFIED | Fresh-process import test passes with no database created and app tail runs initialization only under `__main__`. |
| FND-04 | ✗ BLOCKED | Durable owner leasing works, but scan work can exceed and lose its own lease, leaving a permanent `running` row. |
| FND-05 | ✓ SATISFIED | Ordered migrations, support floor, unknown-shape rejection, rerun no-op, rollback, and lock contender tests pass. |
| FND-06 | ✗ BLOCKED | Restore cannot ensure rollback correctness with SQLite sidecars or a live web writer. |
| FND-07 | ✗ BLOCKED | Outbound requests/browser resources are validated before, but not at, the real network connection. |
| OPS-05 | ✗ BLOCKED | DNS/rebinding protection is incomplete; metadata mutation also returns a 500 for a valid scalar JSON body rather than a safe validation response. |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---:|---|---|---|
| `dashboard/beacon/recovery.py` | 237-285 | Main database replacement without WAL/SHM lifecycle | 🛑 BLOCKER | Restored data can be superseded by live WAL content. |
| `dashboard/beacon/recovery.py` | 253-258 | Only worker-heartbeat check before restore | 🛑 BLOCKER | Live web metadata/queue/rate-limit writers are not excluded. |
| `dashboard/app.py` | 1511-1535 | Discovery work without `renew_scan_lease()` | 🛑 BLOCKER | Long valid scan becomes permanently running. |
| `dashboard/beacon/outbound.py` | 259-266 | Hostname connection after DNS plan | 🛑 BLOCKER | DNS rebinding can bypass the policy. |
| `dashboard/beacon/previews.py` | 62-70 | `route.continue_()` after plan-only check | 🛑 BLOCKER | Chromium performs a later unverified DNS connection. |
| `dashboard/app.py` | 1855-1858 | Assumes JSON body is a mapping | ⚠️ WARNING | Valid scalar JSON creates a 500. |
| `dashboard/app.py` | 47-107 | Raw `int()` environment parsing bypasses Settings | ⚠️ WARNING | Invalid deployment configuration prevents app import/startup. |

No unreferenced `TBD`, `FIXME`, or `XXX` marker was found in Phase 1 implementation/test files.

### Human Verification Required After Gap Closure

The nine behavior-unverified items in frontmatter are genuine manual/browser/inventory checks, not substitutes for the automated blockers. Most importantly, the operator must compare the actual Pi's deployed/retained database fingerprints against the recorded support floor; the repository cannot establish that external fact.

### Gaps Summary

Five failed must-haves block the phase. Repair the restore transaction first (writer exclusion plus WAL/SHM handling), then make discovery own a valid lease for its whole bounded duration, bind every outbound connection to validated DNS results, and remove the domain-to-legacy-app dependency. Add the missing negative regressions; current green tests do not exercise any of those four critical paths.

---

_Verified: 2026-07-31T21:42:08Z_
_Verifier: the agent (gsd-verifier)_
