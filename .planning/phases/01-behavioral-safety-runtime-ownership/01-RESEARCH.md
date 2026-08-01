# Phase 1: Behavioral Safety & Runtime Ownership - Research

**Researched:** 2026-07-24
**Domain:** Safe extraction of a Flask/SQLite two-process appliance, transactional upgrades, durable worker ownership, and outbound-target policy
**Confidence:** MEDIUM

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Preserve all existing browser/API routes, response fields, and relied-upon behavior through compatibility adapters while internals are restructured. — **Reversibility:** costly — removing compatibility later affects the existing browser, integrations, tests, and upgrade path.
- **D-02:** Fix any confirmed functional or UI bug when intended behavior is made explicit and protected by tests.
- **D-03:** Visible UI may be redesigned when the change directly supports corrected behavior or compatibility work; unrelated visual polish and general redesign remain Phase 5 scope.
- **D-04:** Inventory actual legacy database/schema variants before choosing the compatibility floor; do not assume either universal or latest-only support during planning.
- **D-05:** Before every schema-changing migration, automatically create a timestamped local backup and verify that the backup can be opened.
- **D-06:** Retain the latest three verified pre-migration backups and remove older automatic migration backups under bounded cleanup.
- **D-07:** A failed or partial migration must never allow the worker to operate against a partially migrated database.
- **D-08:** Recovery must have one clear, supported operator path. The planner may choose a recovery screen, supported command, automatic rollback, or another minimal mechanism after assessing transaction and container safety.
- **D-09:** Preserve permissive certificate handling where needed for monitored services on the trusted LAN; Beacon is not intended to validate the identity of local HTTPS services.
- **D-10:** Constrain the unverified-TLS exception as narrowly as practical. External destinations such as webhooks must not automatically inherit a LAN-service exception.
- **D-11:** Revalidate the destination host, resolved address, port, and scheme on every redirect.
- **D-12:** Show a persistent `TLS unverified` indicator for affected services without classifying the certificate condition itself as service downtime.
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

### Deferred Ideas (OUT OF SCOPE)

- Broaden service discovery to scan every tenth port plus an explicit list of other common service ports. This changes discovery capability and belongs in the discovery-focused work, not Phase 1 safety restructuring.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| FND-01 | Existing dashboard, service-management, discovery, preview, uptime, and event behavior is protected by compatibility tests before restructuring. | Preserve the enumerated `/api/*` shapes and current browser calls; expand the existing real-SQLite Flask-client suites before extraction. [VERIFIED: repository] |
| FND-02 | Web delivery, configuration, persistence, monitoring, analytics, discovery, previews, and scheduling have explicit module boundaries. | Extract behind factory-created web adapters and an explicit worker composition root; retain `dashboard/app.py` only as a compatibility WSGI import surface during the move. [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/] |
| FND-03 | Importing the web application starts no scheduler, browser, probe, or other background work. | `dashboard/app.py` currently invokes `_ensure_runtime_started()` at import unless `DISABLE_BACKGROUND=1`; remove all lifecycle I/O from import and test it in a fresh interpreter. [VERIFIED: repository] |
| FND-04 | The worker is the sole scheduler owner and uses durable persisted coordination for work shared with the web process. | Formalize the current SQLite queues/runtime rows into ownership leases, queue claims, expiry, and recovery; only the worker starts APScheduler. [VERIFIED: repository] |
| FND-05 | Database changes use versioned, transactional, idempotent migrations validated against representative existing databases. | Replace the current column-introspection startup routine with ordered versioned migrations, a verified preflight backup, and historical/production fixture tests. [VERIFIED: repository] |
| FND-06 | The operator can create and verify a usable backup before a migration and recover existing Beacon data after a failed upgrade. | Use SQLite's online-backup snapshot into `/data/backups`, open and integrity-check it, retain three verified migration backups, and provide a Compose recovery command. [CITED: https://www.sqlite.org/backup.html] |
| FND-07 | Probes, HTML fetches, previews, redirects, and webhooks use one tested outbound-target and TLS safety policy. | Centralize parsing, host/port/scheme/DNS validation, per-hop redirects, purpose-specific TLS, and browser request interception; keep webhook policy strict and separate. [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html] |
| OPS-05 | Automated tests cover outbound-target validation, DNS/redirect handling, TLS behavior, and mutation-request protections. | Add table-driven unit/integration coverage around a single policy seam plus retain host/origin/header mutation tests. [VERIFIED: repository] |
</phase_requirements>

## Project Constraints (from AGENTS.md)

- Remain self-contained on a 64-bit Raspberry Pi with Docker Compose. [VERIFIED: repository]
- Keep monitoring to one host Pi plus explicitly configured or discovered trusted LAN/web services; fleet management is out of scope. [VERIFIED: repository]
- Keep outbound fetching and mutation endpoints behind narrow, testable safety boundaries even on a trusted LAN. [VERIFIED: repository]
- Preserve useful dashboard behavior and stored data unless an approved migration replaces it. [VERIFIED: repository]
- Avoid work that creates visible sampling gaps or makes the dashboard unresponsive on Pi hardware. [VERIFIED: repository]
- Use explicit, testable module boundaries rather than extending the existing monolith. [VERIFIED: repository]
- Follow lowercase snake-case Python modules/functions, narrow expected-error handling, real SQLite + Flask-client tests, and module loggers. [VERIFIED: repository]
- Do not make unrelated visual redesign work in this phase. [VERIFIED: repository]

## Summary

Beacon already runs as two containers sharing `/data/dashboard.db`: Gunicorn serves the dashboard while `worker.py` starts APScheduler, but the web module still creates the database at import time and the worker performs migrations, recovery, its initial heartbeat, metric collection, scheduler construction, and signal registration at module import. The current locks are process-local and cannot coordinate the two containers; the durable `runtime_state`, `scan_requests`, and `preview_requests` rows are the correct foundation to formalize. [VERIFIED: repository]

The safe implementation is an extract-and-adapt sequence: first pin externally observable contracts and representative legacy databases; then introduce a side-effect-free factory, database/migration/backup service, persisted worker-owner lease and queue-claim semantics; finally route every outbound caller through one purpose-aware policy. Keep the existing Flask, APScheduler, stdlib SQLite, requests, Playwright, Docker Compose, and vanilla browser stack. No new package is needed for this phase. [VERIFIED: repository] [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/]

The urgent correctness gap is outbound policy. `_probe_http()` and `_fetch_html_response()` set `verify=False` for all HTTPS service requests, suppress insecure-request warnings globally, and validate only host strings on redirects; `_send_transition_alert()` posts an arbitrary configured URL without applying either policy. The new policy must retain the deliberately permissive TLS option only for explicitly eligible trusted-LAN monitored services, while webhook destinations remain independently allowlisted HTTPS with normal certificate verification. [VERIFIED: repository] [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html]

**Primary recommendation:** Plan Phase 1 as a compatibility-first vertical slice: establish contract/legacy fixtures and the factory plus migration/backup preflight first, then move worker ownership/queues and outbound policy behind stable adapters, with no package installation or product-scope expansion. [VERIFIED: repository]

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Existing JSON/static dashboard contract | Frontend Server (WSGI) | Browser / Client | Flask owns route and response compatibility; the browser continues polling its existing routes. [VERIFIED: repository] |
| Service metadata edits and durable command enqueue | Frontend Server (WSGI) | Database / Storage | The web process must commit operator metadata immediately even while the worker is stale. [VERIFIED: repository] |
| Migration backup, schema versioning, recovery state | Database / Storage | API / Backend | Migration safety is database lifecycle work; web only exposes compatible reads/status and must not run upgrades. [CITED: https://www.sqlite.org/backup.html] |
| Scheduled sampling, probes, discovery, queue consumption, outage-gap recording | API / Backend | Database / Storage | One worker process owns APScheduler and persists its claims/heartbeats/jobs in SQLite. [VERIFIED: repository] [CITED: https://apscheduler.readthedocs.io/en/3.x/userguide.html] |
| Outbound destination/TLS policy | API / Backend | Database / Storage | Network actions need a shared policy and persisted service configuration; browser code must not decide trust. [VERIFIED: repository] |
| Stale-monitoring/TLS-unverified presentation | Browser / Client | Frontend Server (WSGI) | The browser renders status from API state without blocking normal dashboard interaction. [VERIFIED: repository] |

## Standard Stack

### Core

| Library / component | Version | Purpose in Phase 1 | Why standard here |
|---------------------|---------|--------------------|-------------------|
| Python + stdlib `sqlite3` | Python 3.11–3.12; local SQLite 3.51.0 | Versioned migrations, transactional data access, backups, queues and leases | Current deployment and tests already use SQLite; its online backup API supports a consistent snapshot of a live database. [VERIFIED: repository] [CITED: https://www.sqlite.org/backup.html] |
| Flask | 3.1.3 | Side-effect-free web factory, routes, compatibility adapters | Flask documents factories for configurable isolated app instances and blueprint registration. [VERIFIED: repository] [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/] |
| APScheduler | 3.11.3 | Worker-only periodic jobs | The installed scheduler supports explicit per-job IDs, `max_instances`, coalescing, and misfire policies already used by Beacon. [VERIFIED: repository] [CITED: https://apscheduler.readthedocs.io/en/3.x/userguide.html] |
| `requests` + `urllib3` | 2.34.2 / 2.7.0 | HTTP probes, title fetches, webhooks | Retain the installed client but wrap it behind one outbound policy rather than letting callers choose TLS/redirect behavior. [VERIFIED: repository] |
| Playwright | 1.61.0 | Serialized Chromium previews | Retain preview capability, but construct the browser only in worker-owned preview execution and apply the same target policy to every navigation. [VERIFIED: repository] |
| pytest | 9.1.1 in local environment | Compatibility, migration, lifecycle and policy contracts | The current suite uses real temporary SQLite databases and Flask's test client; 43 tests pass locally. [VERIFIED: repository] |

### Supporting

| Component | Purpose | When to use |
|-----------|---------|-------------|
| Docker Compose named volume `/data` | Holds the database, backup set, and recovery artifacts | Keep all migratable state and automatically retained backups under the existing writable volume. [VERIFIED: repository] |
| `urllib.parse`, `ipaddress`, `socket.getaddrinfo` | Parse target URLs and validate every A/AAAA result against policy | Use inside one outbound-policy module; do not accept a string-only host allowlist as proof of a safe destination. [VERIFIED: repository] [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Explicit in-process SQLite migration registry | ORM plus external migration framework | Adds a dependency and a parallel data model without resolving Beacon's actual legacy-schema inventory; explicit ordered SQL/data migrations are smaller and directly testable for this appliance. [VERIFIED: repository] |
| SQLite-backed queues and ownership lease | Redis/Celery or another broker | A new daemon and operational surface conflicts with the self-contained one-Pi constraint; durable rows already exist and need semantics, not replacement. [VERIFIED: repository] |
| Factory + compatibility adapter | Full Flask/SPA rewrite | Would make FND-01 compatibility and stored-data preservation harder while adding unrelated scope. [VERIFIED: repository] |

**Installation:** None. Preserve the pinned dependencies in `dashboard/pyproject.toml` and `dashboard/uv.lock`; this phase should not install a new package. [VERIFIED: repository]

## Architecture Patterns

### System Architecture Diagram

```text
Browser
  │ existing /api/* requests and UI mutations
  ▼
Web factory / compatibility routes ── immediate metadata transaction ──┐
  │                                                                     │
  │ reads dashboard data; reports worker stale/TLS state               ▼
  └────────────────────────────── SQLite /data/dashboard.db ◄── durable queues
                                           │  ▲              (queued/running/expired,
                                           │  │               lease + expiry)
                     verified backup +    │  │
                     transactional migration│  │ worker owner lease / heartbeat
                                           ▼  │
                                  worker_main() only
                                           │
                   APScheduler jobs / recovery / monitoring-gap event
                                           │
                       shared outbound policy by purpose
                         ├── service probe / HTML / browser preview
                         │     explicit trusted-LAN target; HTTPS may be unverified;
                         │     persistent `TLS unverified` status
                         └── alert webhook
                               independently allowlisted HTTPS; TLS always verified
```

The web process must remain readable and allow metadata updates while the worker is stale; it must not wait for a heartbeat or own a scheduler. The worker must refuse to acquire scheduled work until migration preflight succeeds, then persist a monitoring-gap event when it observes recovery after a stale heartbeat. [VERIFIED: repository]

### Recommended Project Structure

```text
dashboard/
├── beacon/
│   ├── config.py             # validated immutable runtime settings
│   ├── db.py                 # connections, short transactions, backups, migration gate
│   ├── migrations.py         # ordered immutable migration registry
│   ├── repositories.py       # SQL for services, events, runtime and queues
│   ├── queues.py             # enqueue, lease/claim, expiry and recovery
│   ├── outbound.py           # target resolution, redirect and TLS policy
│   ├── monitoring.py         # metrics/probes/transitions; no Flask imports
│   ├── previews.py           # worker-owned browser lifecycle and previews
│   ├── web.py                # factory, route blueprints, request security
│   └── worker_main.py        # migration preflight, owner lease, scheduler composition
├── app.py                    # temporary WSGI/legacy-import compatibility shim
└── worker.py                 # temporary CLI compatibility shim to worker_main.main()
```

This is a target structure, not a requirement to move every function at once. Move behavior by domain behind stable adapters, retain the legacy module names while existing tests/Gunicorn use them, and delete adapters only in a separately approved compatibility-removal phase. [VERIFIED: repository] [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/]

### Pattern 1: Side-effect-free composition roots

**What:** `create_app(settings)` registers routes and request policy only; `worker_main.main()` alone opens the migration gate, acquires worker ownership, creates the scheduler, and starts jobs. [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/]

**When to use:** At the first extraction. It directly removes the current `DISABLE_BACKGROUND` test-only escape hatch and worker import-time executions. [VERIFIED: repository]

**Example (illustrative contract):**

```python
# Source: [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/]
def create_app(settings):
    app = Flask(__name__)
    app.config["beacon_services"] = build_web_services(settings)
    register_compat_routes(app)
    return app                    # no database initialization or background I/O

def main():
    services = build_worker_services(load_settings())
    services.upgrades.backup_verify_and_migrate()
    services.worker_owner.acquire_or_exit()
    build_scheduler(services).start()
```

### Pattern 2: Pre-migration backup, then atomic versioned migration

**What:** Inventory schema first; for each pending schema-changing version, create a timestamped SQLite snapshot in `/data/backups`, verify it can be opened and passes an integrity check, run the migration and its version-row insert in one transaction, then retain only the newest three verified automatic migration backups. [VERIFIED: repository] [CITED: https://www.sqlite.org/backup.html]

**When to use:** Every migration that changes schema or backfills persisted data. A migration failure must roll back its transaction, leave the worker owner lease unacquired, and leave recovery status visible to the supported command. [VERIFIED: repository]

**Required support floor discovery:** Repository history proves three candidate shapes but cannot prove deployed data: (1) the 2026-04 initial `stats_history`/`services`/`service_checks` schema; (2) the 2026-04 metadata/events schema; and (3) the 2026-07 schema with `system_stats`, `runtime_state`, queues, thumbnail provenance, `state_since`, and `healthy_statuses`. No `.db`, `.sqlite`, WAL, or SHM artifact exists in the working tree. Capture a sanitized schema/data inventory from the operator volume and turn every encountered shape into a fixture before freezing the compatibility floor. [VERIFIED: repository]

### Pattern 3: Durable worker ownership and queue state machine

**What:** Persist a single worker-owner lease and use durable queue statuses plus lease expiry rather than `_scan_lock`, `_uptime_lock`, and `_screenshot_sem` for cross-process ownership. Process-local locks may still serialize threads inside the one worker, but are never the source of inter-container truth. [VERIFIED: repository]

**Queue contract to plan:**

| Queue | Web responsibility | Worker responsibility | Expiry recommendation |
|-------|--------------------|-----------------------|-----------------------|
| Manual scan | Insert request after mutation/header validation; surface `queued`, `running`, `completed`, `failed`, or `expired` | Atomically claim only a non-expired request, renew/finish its lease, and recover expired running leases | 15 minutes [ASSUMED] |
| Preview refresh | Upsert the service's latest requested revision in the same transaction as metadata edit | Claim one request under serialized browser ownership; discard obsolete revision or mark failure | 30 minutes [ASSUMED] |

The existing queues requeue every `running` row on restart and have no durable lease, deadline, attempt counter, or expired state. The existing scan route reports only a queued count, so it cannot meet the locked visible-expiry behavior without a response/UI extension. [VERIFIED: repository]

### Pattern 4: One purpose-aware outbound policy

**What:** All HTTP, HTML, Playwright navigation, and webhook callers invoke one policy that receives a purpose (`service_probe`, `html_preview`, `browser_preview`, or `webhook`) and returns a validated request plan plus a TLS posture. [VERIFIED: repository]

**Rules to lock into tests:**

1. Accept only `http`/`https`; reject credentials, malformed ports, and unconfigured host/network targets. Resolve the hostname immediately before each hop and require every returned A/AAAA address to satisfy the purpose's address policy. [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html]
2. Disable automatic redirects. Parse each `Location`, then revalidate scheme, host, resolved addresses, and port before issuing the next hop; cap the hop count. [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html]
3. Only explicitly configured trusted-LAN service targets may set `verify=False`/Playwright `ignore_https_errors`; persist/expose `tls_unverified: true` for that policy choice and do not convert a certificate condition into a health failure. [VERIFIED: repository]
4. Webhooks have a separate policy: explicit configured HTTPS destination, strict certificate verification, no inherited LAN exception, a small redirect policy (recommended: reject redirects), timeout, and redacted error recording. [VERIFIED: repository] [ASSUMED]
5. Playwright needs routing/interception for every browser request and navigation, not only a post-navigation `page.url` check; otherwise subresources and redirect hops can bypass the common policy. [VERIFIED: repository]

### Anti-Patterns to Avoid

- **A global `app` that initializes runtime:** `dashboard/app.py` now conditionally calls `_ensure_runtime_started()` during import; test flags must not be required to make imports safe. [VERIFIED: repository]
- **A migration version record without a migration registry:** the current code writes only `schema_migrations(version=1)` after a collection of `CREATE`/`ALTER` checks, so it cannot describe which historical upgrade steps ran. [VERIFIED: repository]
- **Copying `dashboard.db` while it is live:** with WAL, an OS-level file copy is not the verified snapshot contract; use SQLite's backup mechanism and open the result. [CITED: https://www.sqlite.org/backup.html]
- **Using host-string validation as DNS validation:** the current local-host helpers do not resolve named hosts and `_normalize_service_url()` rewrites accepted aliases to `127.0.0.1`; this cannot implement the required trusted-LAN service exception or DNS revalidation. [VERIFIED: repository]
- **Treating an HTTPS certificate failure as downtime:** the locked policy intentionally allows unverified TLS for eligible LAN services, so status must separately expose trust posture and reachability. [VERIFIED: repository]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Live SQLite backup | File copy of `dashboard.db`/WAL files | SQLite online backup into a new destination plus open/integrity verification | The documented backup API creates a consistent snapshot of a live database. [CITED: https://www.sqlite.org/backup.html] |
| Generic migration framework | An ORM, schema DSL, or ad-hoc startup `ALTER` scatter | A small explicit ordered migration registry of SQL/data functions and a migrations table | Beacon needs auditable compatibility with known historical SQLite files, not a second data model. [VERIFIED: repository] |
| URL parsing / IP classification | Regexes and string-prefix checks | `urllib.parse`, `ipaddress`, `socket.getaddrinfo`, and one policy adapter | URLs, IPv6, credentials, port parsing, redirects, and multi-address DNS have edge cases the current split helpers do not cover. [VERIFIED: repository] [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html] |
| Scheduler replay logic | Custom catch-up loop | APScheduler job IDs, `max_instances=1`, coalescing and explicit per-job misfire grace | The current scheduler already uses these controls; formalize ownership rather than inventing another scheduler. [VERIFIED: repository] [CITED: https://apscheduler.readthedocs.io/en/3.x/userguide.html] |

**Key insight:** The phase should introduce a few explicit domain interfaces, not a platform. SQLite remains the durable coordination boundary and Flask/worker remain the process boundaries. [VERIFIED: repository]

## Common Pitfalls

### Pitfall 1: First-run migration prevents recovery UI/command

**What goes wrong:** Current Compose makes `web` depend on a healthy worker; if the worker exits on an upgrade failure, the operator may have no running web process to reach a recovery flow. [VERIFIED: repository]

**How to avoid:** Make web independently startable and compatibility-safe against the last committed schema; add a one-shot recovery command that reports migration status, lists verified backups, verifies a selected backup, and restores only while web/worker are stopped. Store the status/backups under `/data`, the only writable volume. [VERIFIED: repository] [ASSUMED]

### Pitfall 2: A partial migration lets the worker collect against mixed schema

**What goes wrong:** The current `init_db()` interleaves DDL, data updates, and a single version insert in a startup function. [VERIFIED: repository]

**How to avoid:** Each pending migration is an all-or-nothing transaction; the worker obtains its ownership lease and starts APScheduler only after all versions validate. Test a forced failure midway and assert no new version, no partial columns/data, no heartbeat/scheduler start, and an intact verified backup. [VERIFIED: repository]

### Pitfall 3: Process-local locks masquerade as distributed coordination

**What goes wrong:** `_scan_lock`, `_uptime_lock`, and screenshot locks exist only in the importing process, while web and worker are separate containers. [VERIFIED: repository]

**How to avoid:** Persist owner/lease state and claim rows transactionally. Test a second worker contender, stale lease takeover, worker restart, and metadata update during worker outage. [VERIFIED: repository]

### Pitfall 4: Queue recovery replays obsolete work forever

**What goes wrong:** Current recovery unconditionally requeues every running scan/preview and neither queue records a deadline. [VERIFIED: repository]

**How to avoid:** Persist expiration/revision/attempt information and return an explicit expired outcome to the existing status surface. Preserve only still-relevant latest preview work. [VERIFIED: repository]

### Pitfall 5: Narrow TLS exception leaks to webhooks

**What goes wrong:** Current service fetches deliberately set `verify=False`, while webhook delivery has no destination policy. [VERIFIED: repository]

**How to avoid:** Make TLS posture a mandatory policy result. Only an eligible local-service purpose can be unverified; all webhook requests remain strict HTTPS and are covered by negative tests. [VERIFIED: repository]

### Pitfall 6: Redirect checks occur after network access

**What goes wrong:** `_fetch_html_response()` checks the next host before its next `requests.get`, but only string-checks it; Playwright verifies `page.url` after navigation. [VERIFIED: repository]

**How to avoid:** Validate each candidate before connection, resolve every hop, and intercept browser requests. Test scheme, credentials, redirect host/port/address changes, multiple DNS answers, and a service redirect that remains eligible. [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html]

## Code Examples

### Compatibility-safe web/worker boundary

```python
# Illustrative target contract.
# Source: [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/]
def create_app(settings):
    app = Flask(__name__)
    register_compatibility_routes(app, build_web_services(settings))
    return app

def worker_main(settings):
    worker = build_worker_services(settings)
    worker.migrations.prepare_for_worker_start()  # backup, verify, migrate
    worker.ownership.require_lease()
    return configure_scheduler(worker)
```

### Queue claim with bounded relevance

```python
# Illustrative target contract derived from current scan/preview tables.
# Source: [VERIFIED: repository]
def claim_next_preview(conn, now, worker_id):
    # Run under one short SQLite write transaction.
    expire_stale_preview_rows(conn, now)
    row = select_oldest_eligible_preview(conn, now)
    if row is None:
        return None
    mark_running_with_lease(conn, row.id, worker_id, now + LEASE_SECONDS)
    return row
```

### Per-hop outbound policy

```python
# Illustrative target contract; automatic redirects stay disabled.
# Source: [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html]
plan = outbound_policy.plan(url, purpose="service_probe")
while True:
    response = transport.send(plan, allow_redirects=False)
    if not response.is_redirect:
        break
    plan = outbound_policy.plan(urljoin(plan.url, response.headers["Location"]),
                                purpose="service_probe")
```

## State of the Art

| Old approach | Current repository approach | Phase-1 target | Impact |
|--------------|-----------------------------|----------------|--------|
| Web process owns daemon loops | `DISABLE_BACKGROUND` gates import-time database initialization, while a new worker owns APScheduler | Factory import with no runtime I/O; worker-only explicit startup | Removes environment-dependent lifecycle behavior. [VERIFIED: repository] |
| In-memory scan state and mutexes | SQLite `runtime_state` and queue tables plus process-local locks | Durable owner/queue leases and explicit expiry | Makes cross-container recovery observable and correct. [VERIFIED: repository] |
| Introspection-based startup migration | Additive `CREATE`/`ALTER` checks and one `version=1` row | Ordered versioned transactional migrations with verified backups | Provides an auditable upgrade/recovery boundary. [VERIFIED: repository] |
| Blanket unverified service TLS | `verify=False` for probe/title fetches; webhook is separate raw request | Purpose-specific LAN exception and strict webhook policy | Preserves local usability without extending the exception externally. [VERIFIED: repository] |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | A manual scan older than 15 minutes and a preview request older than 30 minutes are no longer operator-relevant. | Durable worker ownership and queue state machine | Valid requested work might expire too soon or stale work might run too long. |
| A2 | A one-shot Compose recovery command, requiring web/worker to be stopped before restore, is the smallest clear recovery experience. | Common Pitfall 1 | The operator may prefer an in-dashboard flow or operational setup may need a different stop/restore sequence. |
| A3 | Webhooks should reject redirects rather than follow a separately validated redirect chain. | Outbound policy | A valid webhook provider redirect could fail until explicitly supported. |

## Open Questions (RESOLVED)

1. **Which legacy schemas are actually deployed?**
   - What we know: Git history proves initial (2026-04), metadata/events (2026-04), and queue/runtime-state (2026-07) shapes. [VERIFIED: repository]
   - What's unclear: There is no production database artifact or volume snapshot in the repository. [VERIFIED: repository]
   - Recommendation: Make the first executable task collect sanitized `sqlite_master`, `PRAGMA table_info`, migration rows, counts, database/WAL sizes, and backup/restore evidence; turn each observed shape into a migration fixture before choosing the support floor. [VERIFIED: repository]
   - **RESOLVED:** Per D-04 and Plan 01-10, compatibility remains fail-closed until the operator inventories every current or retained Pi database and compares its sanitized fingerprint with the documented support floor. Gathering and comparing that external evidence remains a human execution and verification action; it has not been claimed complete by repository planning or automation.

2. **How should trusted-LAN host configuration distinguish service aliases from resolved addresses?**
   - What we know: Current configuration permits named aliases and networks but normalizes any accepted service hostname to `127.0.0.1`, so it does not actually support a separately addressed LAN service. [VERIFIED: repository]
   - What's unclear: The intended operator configuration syntax and minimum necessary local-network ranges. [VERIFIED: repository]
   - Recommendation: Keep an explicit service-target allowlist/allow-network setting separate from webhook allowlisting; test all returned resolver addresses and avoid broad default expansion. [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html]
   - **RESOLVED:** Plan 01-12 applies purpose-specific policy at every connection boundary, revalidates every current A/AAAA result for the configured alias, and rejects the connection when any newly returned address is disallowed.

3. **What recovery command belongs in the delivered Docker Compose UX?**
   - What we know: `/data` is the only intended writable mount and current Compose blocks web startup on worker health. [VERIFIED: repository]
   - What's unclear: Whether the project wants a separate `recovery` service/profile or a command on the existing image. [VERIFIED: repository]
   - Recommendation: Plan one named, documented command and exercise it against a deliberately failed migration fixture before implementation is considered complete. [ASSUMED]
   - **RESOLVED:** Plan 01-10 retains and hardens the single supported offline `restore --latest` recovery command, including exclusive maintenance and safe SQLite sidecar handling; no second recovery interface is planned.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| Python | Local test/recovery tooling | ✓ | 3.11.15; project permits 3.11–3.12 | — [VERIFIED: repository] |
| Project virtual environment | Test runner | ✓ | pytest 9.1.1; Flask 3.1.3; APScheduler 3.11.3 | `dashboard/.venv/bin/python -m pytest -q` [VERIFIED: repository] |
| `uv` CLI | Project-documented test command/build workflow | ✗ | — | Use the checked-in virtual environment locally; CI/container continues to use frozen `uv`. [VERIFIED: repository] |
| Docker + Compose CLI | Compose startup/recovery validation | ✓ | Docker 29.3.1; Compose v5.1.1 | — [VERIFIED: repository] |
| SQLite CLI | Manual schema/backup inspection | ✓ | 3.51.0 | Python stdlib `sqlite3` is the shipped runtime path. [VERIFIED: repository] |

**Missing dependencies with no fallback:** None for planning-level unit tests. [VERIFIED: repository]

**Missing dependencies with fallback:** Local `uv` is absent; use the project virtual environment for pytest. [VERIFIED: repository]

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 9.1.1 executing `unittest.TestCase` suites against Flask and temporary SQLite files. [VERIFIED: repository] |
| Config file | `dashboard/pyproject.toml` (`pythonpath = [".."]`, tests in `../tests`). [VERIFIED: repository] |
| Quick run command | `dashboard/.venv/bin/python -m pytest -q` (43 passed in 0.66s during research). [VERIFIED: repository] |
| Full suite command | `dashboard/.venv/bin/python -m pytest -q`; add Compose/recovery tests only where the Docker daemon is available. [VERIFIED: repository] |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FND-01 | Existing routes/response fields, metadata edits, scan, preview, uptime and event behavior survive extraction | API contract + integration | `dashboard/.venv/bin/python -m pytest -q tests/test_api_and_auth.py tests/test_uptime_integration.py tests/test_ui_contract.py` | ✅ expand existing |
| FND-02 | Web, persistence, monitoring, previews, queues and scheduler have dependency directions/no circular app import | import-boundary unit tests | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py` | ❌ Wave 0 |
| FND-03 | Importing WSGI/factory performs no init, scheduler, browser, probe or network work | fresh-subprocess/import unit test | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py -k import` | ❌ Wave 0 |
| FND-04 | One worker lease, durable queue claims, stale recovery and monitoring-gap event | SQLite integration + optional two-process smoke | `dashboard/.venv/bin/python -m pytest -q tests/test_runtime_ownership.py tests/test_durable_queues.py` | ❌ Wave 0 |
| FND-05 | Each representative legacy fixture upgrades once, is idempotent, and rolls back on failure | migration fixture tests | `dashboard/.venv/bin/python -m pytest -q tests/test_migrations.py` | ❌ Wave 0 |
| FND-06 | Pre-migration backup opens/integrity-checks; only three automatic backups remain; restore returns readable old data | backup/restore integration | `dashboard/.venv/bin/python -m pytest -q tests/test_backup_recovery.py` | ❌ Wave 0 |
| FND-07 | Every outbound purpose reaches the policy seam; LAN TLS exception is marked; webhook stays strict | policy unit/integration | `dashboard/.venv/bin/python -m pytest -q tests/test_outbound_policy.py` | ❌ Wave 0 |
| OPS-05 | Invalid scheme/credentials/port/address, DNS answers, each redirect hop, TLS mode, host/origin/header mutation checks | table-driven security tests | `dashboard/.venv/bin/python -m pytest -q tests/test_outbound_policy.py tests/test_security_and_scanning.py tests/test_release_contract.py` | ✅ existing suites need expansion |

### Sampling Rate

- **Per task commit:** `dashboard/.venv/bin/python -m pytest -q`
- **Per wave merge:** full unit suite plus migration/backup fixtures.
- **Phase gate:** full suite green; a Compose recovery run, if Docker is available, demonstrates failed migration leaves the worker non-owner and a verified backup restores expected service/metadata/event rows.

### Wave 0 Gaps

- [ ] `tests/fixtures/legacy/` — one sanitized SQLite fixture for each schema shape found in git history and every production shape discovered during the inventory.
- [ ] `tests/test_migrations.py` — upgrade/idempotency/forced-rollback/version tests.
- [ ] `tests/test_backup_recovery.py` — verified online backup, three-file retention, stopped-service restore, and post-restore API data tests.
- [ ] `tests/test_runtime_ownership.py` — clean import, single owner lease, stale worker interaction, automatic recovery gap event, and no duplicate schedule startup.
- [ ] `tests/test_durable_queues.py` — atomic claim, lease expiry, restart recovery, visible expiry, metadata persistence while worker is absent.
- [ ] `tests/test_outbound_policy.py` — full purpose matrix, DNS A/AAAA answers, redirect chain, strict webhook TLS, and unverified-LAN service indicator.
- [ ] A stable Compose smoke command/harness for web/worker ownership and the documented recovery command; keep it optional only when Docker cannot run locally.

## Security Domain

The security focus is Phase 1's trusted-LAN boundary: it is not an authorization-system build, but it does need testable request mutation protection and a single SSRF/TLS boundary. OWASP ASVS is a verification framework for web application technical controls. [CITED: https://owasp.org/www-project-application-security-verification-standard/]

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|------------------|
| V2 Authentication | No accounts are in scope | Do not add pseudo-authentication; retain trusted-host deployment boundary. [VERIFIED: repository] |
| V3 Session Management | No sessions are in scope | Do not introduce cookie/session state in this extraction. [VERIFIED: repository] |
| V4 Access Control | Yes, for local mutation boundary | Keep trusted-host, same-origin, and `X-Beacon-UI` checks on every mutation route; test negative cases. [VERIFIED: repository] |
| V5 Input Validation | Yes | Central URL/host/port/address validation; JSON metadata field validation; parameterized SQLite values. [VERIFIED: repository] |
| V6 Cryptography | Yes, narrowly | Never hand-roll TLS; strict default certificate verification, with the explicit local service exception only. [VERIFIED: repository] |

### Known Threat Patterns for Beacon

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Service URL or redirect reaches disallowed host/address | Tampering / Information disclosure | One per-purpose allowlist; parse, resolve and validate all addresses on every hop; automatic redirects disabled. [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html] |
| TLS exception leaks to external alert destination | Information disclosure | Separate webhook policy requiring HTTPS and normal TLS verification; test no `verify=False`. [VERIFIED: repository] |
| Cross-origin/local-network caller mutates data | Tampering | Existing Host, Origin and UI-header checks remain compatibility-tested at the Flask boundary. [VERIFIED: repository] |
| Second worker or stale worker repeats jobs | Tampering / Denial of service | Persisted worker-owner lease and queue leases; no scheduler creation outside worker main. [VERIFIED: repository] |
| Failed upgrade damages persisted monitoring data | Denial of service / Tampering | Verified backup, transaction per migration, worker-start gate, and supported offline restore command. [CITED: https://www.sqlite.org/backup.html] |

## Sources

### Primary (HIGH confidence)

- `dashboard/app.py`, especially `init_db` (117), `recover_worker_state` (336), `_probe_http` (578), `_fetch_html_response` (625), `_send_transition_alert` (804), queue functions (1475–1579), and import lifecycle (2057) — current schema, side effects, queues, and outbound callers. [VERIFIED: repository]
- `dashboard/worker.py` (48–107) and `docker-compose.yml` — import-time worker work, job ownership, health/dependency topology, and writable volume constraints. [VERIFIED: repository]
- Git commits `c2e0e80`, `5b3d420`, `51a4393`, and `1e9161c` — historically visible schema and runtime variants. [VERIFIED: repository]
- `tests/helpers.py`, `tests/test_api_and_auth.py`, `tests/test_release_contract.py`, `tests/test_security_and_scanning.py`, `tests/test_uptime_integration.py`, and `tests/test_ui_contract.py` — current compatibility seams and gaps. [VERIFIED: repository]

### Secondary (MEDIUM confidence)

- [Flask application factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/) — factory/blueprint composition and isolated test configuration. [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/]
- [SQLite Online Backup API](https://www.sqlite.org/backup.html) — live-database snapshot and lock behavior. [CITED: https://www.sqlite.org/backup.html]
- [APScheduler 3.x user guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html) — coalescing, max-instance and misfire behavior. [CITED: https://apscheduler.readthedocs.io/en/3.x/userguide.html]
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — allowlisting and redirect controls. [CITED: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html]
- [OWASP ASVS project](https://owasp.org/www-project-application-security-verification-standard/) — security verification framing. [CITED: https://owasp.org/www-project-application-security-verification-standard/]

### Tertiary (LOW confidence)

- None. [VERIFIED: repository]

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — retained dependencies and versions are pinned in the project lockfile; official behavior was checked for Flask, SQLite and APScheduler. [VERIFIED: repository] [CITED: https://flask.palletsprojects.com/en/stable/patterns/appfactories/]
- Architecture: HIGH — direct current-code and git-history evidence identifies every present lifecycle, queue, schema, and compatibility seam. [VERIFIED: repository]
- Pitfalls: MEDIUM — code proves the current weaknesses; exact production schema population and trusted-LAN configuration still require operator inventory. [VERIFIED: repository]

**Research date:** 2026-07-24
**Valid until:** 2026-08-23 for repository-specific findings; re-run the production database inventory immediately before migration implementation. [VERIFIED: repository]
