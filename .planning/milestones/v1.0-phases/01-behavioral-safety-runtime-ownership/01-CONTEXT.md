# Phase 1: Behavioral Safety & Runtime Ownership - Context

**Gathered:** 2026-07-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Preserve Beacon's working dashboard, stored data, and local monitoring behavior while making upgrades, runtime ownership, and outbound access dependable. This phase may correct confirmed bugs and make directly supporting UI changes, but it does not add advanced analytics, general visual redesign, broader discovery coverage, or remote control.

</domain>

<decisions>
## Implementation Decisions

### Compatibility Boundary

- **D-01:** Preserve all existing browser/API routes, response fields, and relied-upon behavior through compatibility adapters while internals are restructured. — **Reversibility:** costly — removing compatibility later affects the existing browser, integrations, tests, and upgrade path.
- **D-02:** Fix any confirmed functional or UI bug when intended behavior is made explicit and protected by tests.
- **D-03:** Visible UI may be redesigned when the change directly supports corrected behavior or compatibility work; unrelated visual polish and general redesign remain Phase 5 scope.
- **D-04:** Inventory actual legacy database/schema variants before choosing the compatibility floor; do not assume either universal or latest-only support during planning.

### Upgrade and Recovery Experience

- **D-05:** Before every schema-changing migration, automatically create a timestamped local backup and verify that the backup can be opened.
- **D-06:** Retain the latest three verified pre-migration backups and remove older automatic migration backups under bounded cleanup.
- **D-07:** A failed or partial migration must never allow the worker to operate against a partially migrated database.
- **D-08:** Recovery must have one clear, supported operator path. The planner may choose a recovery screen, supported command, automatic rollback, or another minimal mechanism after assessing transaction and container safety.

### Local HTTPS Policy

- **D-09:** Preserve permissive certificate handling where needed for monitored services on the trusted LAN; Beacon is not intended to validate the identity of local HTTPS services.
- **D-10:** Constrain the unverified-TLS exception as narrowly as practical. External destinations such as webhooks must not automatically inherit a LAN-service exception.
- **D-11:** Revalidate the destination host, resolved address, port, and scheme on every redirect.
- **D-12:** Show a persistent `TLS unverified` indicator for affected services without classifying the certificate condition itself as service downtime.

### Worker Failure Behavior

- **D-13:** When the worker heartbeat is stale, keep the dashboard fully interactive and show a clear stale-monitoring warning.
- **D-14:** Continue accepting scan and preview requests into durable queues. Run still-relevant requests after recovery and visibly expire requests older than a bounded age.
- **D-15:** Persist service metadata edits immediately through the web process while the worker is unavailable; the worker consumes the updated values after recovery.
- **D-16:** Clear the stale warning automatically after worker recovery and persist the outage interval as a monitoring-gap event.

### the agent's Discretion

- Choose the legacy database support floor after inventorying actual schema variants and available production data.
- Choose migration-failure presentation and the smallest safe restore interface.
- Define bounded expiry durations per queued request type.
- Determine the narrowest practical scope for permissive LAN TLS while keeping external destinations strict.
- Choose internal module boundaries, migration tooling details, and compatibility-adapter structure consistent with the locked decisions.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product and Phase Contract

- `.planning/PROJECT.md` — Product mission, trusted-LAN boundary, compatibility expectations, and deferred capabilities.
- `.planning/REQUIREMENTS.md` — Phase 1 requirements `FND-01` through `FND-07` and `OPS-05`.
- `.planning/ROADMAP.md` — Phase goal, dependency order, and observable success criteria.
- `.planning/STATE.md` — Current project position and pre-planning database-inventory concern.

### Existing-System Evidence

- `.planning/codebase/ARCHITECTURE.md` — Current two-process topology, shared SQLite coordination, entry points, queues, and security helpers.
- `.planning/codebase/TESTING.md` — Current pytest/Flask/SQLite test patterns and production-behavior gaps.
- `.planning/codebase/CONCERNS.md` — Monolith, import-time lifecycle, migration, TLS, SSRF, SQLite, and concurrency risks this phase addresses.
- `.planning/research/SUMMARY.md` — Approved extract-and-adapt direction, migration safeguards, worker ownership, and outbound-policy research.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- `tests/helpers.py::load_app`: Existing isolated Flask/temporary-SQLite harness can seed compatibility and migration fixtures.
- Existing suites in `tests/test_api_and_auth.py`, `tests/test_release_contract.py`, `tests/test_security_and_scanning.py`, and `tests/test_uptime_integration.py`: Starting points for behavior and security contracts.
- `dashboard/app.py` security helpers (`_is_trusted_request_host`, `_safe_service_url`, `_origin_is_same_host`, `enforce_request_security`): Existing policy behavior to consolidate rather than bypass.
- SQLite-backed `scan_requests`, `preview_requests`, and `runtime_state`: Existing durable coordination primitives to formalize.

### Established Patterns

- Flask routes are tested through `app.test_client()` against real temporary SQLite databases.
- Web and worker are separate containers sharing `/data/dashboard.db`; process-local locks cannot coordinate them.
- The browser uses polling and existing `/api/*` contracts, so compatibility adapters can isolate internal restructuring.
- Containers run non-root with read-only filesystems; persistent backups and recovery artifacts must live in explicitly writable storage.

### Integration Points

- `dashboard/app.py` is the current web, persistence, migration, monitoring, discovery, preview, and security integration point to extract behind stable adapters.
- `dashboard/worker.py` imports application operations and owns APScheduler startup; it must become the sole explicit background entry point.
- `dashboard/Dockerfile` and `docker-compose.yml` define startup, health checks, shared volume ownership, and recovery behavior.
- `dashboard/app.js` consumes current API shapes and provides the visible compatibility boundary.

</code_context>

<specifics>
## Specific Ideas

- During worker outages, favor continued local interaction with candid stale-state messaging rather than a locked outage screen.
- Treat unverified LAN TLS as an operator-visible trust choice, not as an availability failure.
- Keep automatic upgrade recovery bounded and understandable: three verified pre-migration backups rather than an accumulating archive.

</specifics>

<deferred>
## Deferred Ideas

- Broaden service discovery to scan every tenth port plus an explicit list of other common service ports. This changes discovery capability and belongs in the discovery-focused work, not Phase 1 safety restructuring.

</deferred>

---

*Phase: 01-behavioral-safety-runtime-ownership*
*Context gathered: 2026-07-24*
