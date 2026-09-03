---
phase: 06
slug: workload-resilience-pi-acceptance
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-09-01
---

# Phase 06 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

Register origin: **authored at plan time** — all six `06-0N-PLAN.md` files carried a
parseable `<threat_model>` block. This audit verified that each declared mitigation
exists in the implementation; it did not re-scan for new threats (retroactive-STRIDE
mode was not required).

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| worker process → SQLite `thumbnails` | Chromium-derived bytes cross from a browser-rendered page into durable storage | Screenshot JPEG/PNG blobs (≤ 2 MiB/row) |
| SQLite `thumbnails` → browser (`GET /api/thumbnail/<port>`) | Stored bytes and a stored `mime` string are echoed to the operator's browser | Image bytes + a `Content-Type` header value |
| migration process → operator's live database | A one-way schema+data transformation runs against production state | Full operational database |
| support floor manifest → migration admission | A JSON manifest decides which on-disk shapes are allowed to upgrade | Schema fingerprints, minimum versions |
| environment → `Settings` | Operator-supplied env strings become storage and retry bounds | `THUMBNAIL_TTL_DAYS`, `THUMBNAIL_STORE_MAX_BYTES`, `PREVIEW_MAX_ATTEMPTS` |
| worker → operator's LAN service | Each retry is another outbound Chromium page load against an operator-run service | Outbound HTTP requests |
| `preview_requests.error` → browser | A stored failure string reaches the dashboard through `/api/services` and `/api/thumbnail-status` | Error classes / status strings |
| scheduler thread pool → durable evidence | Which lane a job runs on determines whether freshness evidence stays truthful | `background_job_health` rows |
| web process (8 threads) ↔ worker process | Two OS processes write one SQLite file concurrently | All durable state |
| crashed worker epoch → surviving durable state | A dead process's in-flight claims must not outlive it | Queue claims, terminal outcomes |
| harness → running Beacon instance | The harness drives real HTTP load against a live deployment and reads its live database | Read-only HTTP + DB reads |
| harness report → phase verification | A JSON verdict becomes the evidence a requirement is judged against | Latency/resource statistics, job-health rows |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-06-01 | Denial of Service | `thumbnails.data` growth | high | mitigate | Per-row cap `THUMB_MAX_BYTES = 2 MiB` (`dashboard/app.py:65,1093`); `expires_ts` written on every store (`repositories.py:729-733`) | closed |
| T-06-02 | Tampering | migration 10 backfill/empty | high | mitigate | Backfill INSERT and services-emptying UPDATE share the one `BEGIN IMMEDIATE` transaction `_apply_pending_migrations` wraps each migration in; `create_verified_backup` (`migrations.py:657`) runs first | closed |
| T-06-03 | Spoofing | `Content-Type` from stored `mime` | medium | mitigate | `api_thumbnail` keeps `row['mime'] or 'image/jpeg'` (`app.py:3021`); `read_thumbnail` filters `source='screenshot'` (`repositories.py:749-757`), so no foreign-source row is ever served | closed |
| T-06-04 | Information Disclosure | thumbnail bytes served without auth | low | accept | Trusted-LAN-only deployment with no auth model (locked project constraint) — see AR-06-01 | closed |
| T-06-05 | Elevation of Privilege | SQL injection via port parameter | low | mitigate | `?` placeholders throughout; `port` arrives via Flask's `<int:port>` converter | closed |
| T-06-06 | Denial of Service | unbounded `thumbnails` growth | high | mitigate | `delete_expired_thumbnails` + `evict_thumbnails_over_budget` run every J8 pass (`app.py:2027-2028`); `_positive_int` (`config.py:107`) falls back to the documented default on a bad env value | closed |
| T-06-07 | Denial of Service | eviction scan cost on a Pi | medium | mitigate | `idx_thumbnails_expires` (`migrations.py:614`) backs the expiry delete; the budget walk is `LIMIT`-bounded and runs on J8's hourly cadence, never a request path | closed |
| T-06-08 | Tampering | over-permissive support floor | high | mitigate | Fingerprints computed from real fixture upgrades; `test_support_floor_covers_history_and_confirmed_operator_evidence` asserts exact set equality **and** byte-equality of the packaged `dashboard/beacon/support_floor.json` against the fixture manifest (`test_migrations.py:171-190`) | closed |
| T-06-09 | Denial of Service | under-permissive support floor | high | mitigate | `test_support_floor_admits_every_tracked_lineage_at_the_previous_version` drives from `MIGRATIONS[-1].version - 1` via `LINEAGE_FINGERPRINTS` (`test_migrations.py:255-305`), so the migration-9 lockout cannot recur silently | closed |
| T-06-10 | Elevation of Privilege | SQL injection in the eviction delete | low | mitigate | `port IN (...)` built from `?` markers with values bound separately (`repositories.py:812-816`) — no row data interpolated into SQL text | closed |
| T-06-11 | Denial of Service | retry amplification against a monitored service | high | mitigate | `preview_retry_decision` returns `None` at `attempt_count >= max_attempts` (`queues.py:740-748`); `claim_preview` honors `next_attempt_ts`; single-thread `screenshots` executor + `_screenshot_sem(1)` (`app.py:130`) cap concurrency at one | closed |
| T-06-12 | Denial of Service | retry starving the essential lanes | high | mitigate | Retries stay on the `screenshots` executor, sharing no thread with `metrics` (J1/J2) or `probes` (J3/J4) — `worker_main.py:464-468`; asserted by the lane-isolation suite | closed |
| T-06-13 | Spoofing | misattributed failure copy | medium | mitigate | Degraded copy names the preview capture, not the service; `PreviewCaptureUnavailable` keeps machinery faults on J6's own job-health path | closed |
| T-06-14 | Information Disclosure | stored error text rendered in the DOM | medium | mitigate | Fixed client-side string from the `previewCopy` map, rendered via `textContent` (`app.js:296,303`). **Deferred canon output-encoding check discharged here:** `innerHTML` occurrences across `app.js` and `advanced.js` = **0** | closed |
| T-06-15 | Tampering | unbounded retry via configuration | medium | mitigate | `_positive_int` returns the documented default for non-positive and unparseable env values (`config.py:107,264`) | closed |
| T-06-16 | Denial of Service | a wedged cleanup pass starving heartbeat and metric sampling | high | mitigate | Dedicated `'cleanup': ThreadPoolExecutor(1)` (`worker_main.py:466`); `test_worker_ownership_matrix.py:175-179` asserts the `metrics` lane is claimed by exactly J1 and J2 | closed |
| T-06-17 | Denial of Service | a 180s discovery pass delaying J3/J4 service checks | medium | mitigate | Measured directly by the lane-isolation test's cadence assertion; J5/J7/J9 sit on the 2-thread `probes` lane, separate from `cleanup` | closed |
| T-06-18 | Spoofing | fabricated freshness | high | mitigate | `dispatch_callback` writes `succeeded` only after `_invoke_callback` returns (`worker_main.py:348-366`); the oracle is `freshness_state` over `background_job_health.last_success_ts` | closed |
| T-06-19 | Repudiation | silently starved best-effort work | medium | mitigate | Every dispatched job leaves a durable `background_job_health` transition row (`worker_main.py:336,368`), so deferral is observable | closed |
| T-06-20 | Tampering | concurrent writers corrupting SQLite | high | mitigate | WAL log-replay + `write_transaction` commit/rollback discipline + `PRAGMA busy_timeout=30000` (`db.py:94-96,144`); proven by a bounded stress run asserting `PRAGMA integrity_check` returns `ok` | closed |
| T-06-21 | Denial of Service | WAL breaking schema inspection and locking every deployment out of upgrading | high | mitigate | `_readonly_connection` falls back to a `PRAGMA query_only=ON` connection when `mode=ro` cannot initialize `-shm` (`inventory.py:41-56`); the live upgrade path (`_apply_pending_migrations` → `collect_inventory`) runs against a writable data dir and is covered end-to-end by a non-empty-sidecar WAL fixture test. Residual gap on read-only *source* copies recorded as AR-06-02 | closed |
| T-06-22 | Denial of Service | WAL breaking the pre-migration verified backup | high | mitigate | The backup artifact is normalized to rollback-journal mode before its integrity check (`migrations.py:678`), so it passes `mode=ro` and carries no sidecars | closed |
| T-06-23 | Repudiation | a failed write reported as succeeded | high | mitigate | `write_transaction` rolls back and re-raises on any exception (`db.py:144-151`); asserted by the stress test's injected `OperationalError` propagation | closed |
| T-06-24 | Elevation of Privilege | a route gaining unserialized DB access as a WAL side effect | high | mitigate | **Re-closed on the narrowed shape's own evidence (`06-20`), diff-based and frozen-scope forms both retired:** `LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock` (no connection use escapes its owning `_db_lock` block, across all 28 sites, mutation-verified twice in `06-19`); `LockScopePreservationTests::test_api_services_lock_scope_is_database_reads_only` (the narrowed scope pinned by AST); `NarrowedShapeConcurrentAccessTests` (snapshot-after-close and serial-oracle proofs under a concurrent writer, `06-19`). `/gsd-secure-phase 06` re-run remains outstanding per `PROH-OPS-04-05` prerequisite 4, scheduled in `06-24` — see Security Audit Trail | closed |
| T-06-101 | Tampering | a computation quietly moved back inside the critical section, undoing `06-20`'s narrowing without changing output | high | mitigate | `HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing` (measured composition guard) and `LockScopePreservationTests::test_api_services_lock_scope_is_database_reads_only` (AST pin) — both fail on the same mutation, one asserting a consequence, the other a shape (`06-20`) | closed |
| T-06-102 | Information Disclosure | a `sqlite3.Row` field read after its connection closed, yielding a partial or wrong value | high | mitigate | Every result consumed outside `api_services`' `_db_lock` block is materialized into a plain dict inside it (`services`, `all_checks`, `preview_rows`); `06-19` Task 2's recorded `sqlite3.ProgrammingError` mutation is the evidence the hazard is real, not hypothetical (`06-20`) | closed |
| T-06-103 | Repudiation | `/api/services`' output changing under a scope-only edit while every gate stays green — the `D-DEBT-06-10` `CR-01` shape | critical | mitigate | `ApiServicesOutputEquivalenceTests::test_narrowed_route_reproduces_the_pre_narrowing_response_bytes` — three golden fixtures (maintenance-path, over-cap, empty-services) captured from unmodified pre-narrowing code, byte-equality re-checked after; `PROH-OPS-07-05` (`06-20`) | closed |
| T-06-112 | Tampering | `/api/advanced/current`'s payload changing under a cost or topology change while every gate stays green | critical | mitigate | `PROH-OPS-07-14` (minted `06-22`) and `AdvancedCurrentCostTests::test_payload_is_unchanged_by_the_round_5_remedy` — golden captured from the pre-remedy code (`tests/fixtures/advanced_current_pre_remedy_golden.json`), byte-equality checked after the T-C memo shipped, mutation-verified sensitive to a dropped composed field (`06-22`) | closed |
| T-06-25 | Spoofing | a dead worker epoch writing a terminal outcome | high | mitigate | `_assert_current_worker_owner` fencing (`queues.py:181-204`) raising `LeaseLost`, plus `recover_queues_for_worker`; asserted by the restart test | closed |
| T-06-26 | Repudiation | a smoke run passed off as hardware acceptance evidence | high | mitigate | `run_kind = 'smoke' if scenario.self_test else 'acceptance'` derived from the invocation (`tests/pi_load_acceptance.py:420`); the report always carries `platform.machine()` and `platform.node()` (`:423-424`) | closed |
| T-06-27 | Tampering | thresholds tuned to make a run pass | high | mitigate | The cadence oracle delegates to the product's own `freshness_state`; `test_pi_load_acceptance_oracles_are_the_products_own` (`test_workload_resilience.py:947`) locks the oracles to product code | closed |
| T-06-28 | Denial of Service | the harness itself overloading the Pi | medium | mitigate | `--concurrency` defaults to 8, matching gunicorn's own thread count; `--duration` is bounded and required; the harness issues no writes | closed |
| T-06-29 | Information Disclosure | the report embedding operator data | low | mitigate | `AcceptanceReport` carries route names, latency statistics, resource samples and job-health rows only — no thumbnail bytes, no service URLs, no request bodies (`tests/pi_load_acceptance.py:122-140`) | closed |
| T-06-30 | Spoofing | a run against the wrong target reported as the deployment | medium | mitigate | The report records the resolved `--base-url` and `--db` alongside the host; an unreachable target exits non-zero rather than reporting a pass (`:431-434`) | closed |
| T-06-SC | Tampering | npm/pip/cargo installs | high | mitigate | **Verified by scoped diff:** `git diff 8c2fc48..HEAD -- dashboard/pyproject.toml dashboard/uv.lock dashboard/Dockerfile` is empty — no dependency was added, removed, or re-pinned in this phase. The harness uses `requests`, `psutil`, `threading` and the stdlib, all already pinned | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above workflow.security_block_on count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-06-01 | T-06-04 | `/api/thumbnail/<port>` serves stored screenshot bytes with no authentication. Beacon is a trusted-LAN-only deployment with no auth model — a locked project constraint, not an oversight. This route carried exactly this exposure before phase 06; relocating the blobs into the `thumbnails` table did not widen it. | project constraint (PROJECT.md) | 2026-09-01 |
| AR-06-02 | T-06-21 | Residual gap surfaced by code review WR-01: `_readonly_connection`'s WAL fallback opens a writable connection and applies `PRAGMA query_only=ON`, which still needs write access to the *source directory* to map `-shm`. Inspecting a locked-down archival copy (`chmod a-w`, read-only mount) therefore raises `InventoryError` loudly. The threat as scoped — deployment lockout on upgrade — is unaffected: `_apply_pending_migrations` inspects the live database in a writable `/data` dir, and that path is covered end-to-end. The gap is confined to the offline copy-then-lock-down inspection workflow the phase's own README describes. Suggested remedy is recorded in `06-REVIEW.md` WR-01 (`mode=ro&immutable=1` as an intermediate attempt). | operator (documented, unfixed at audit time) | 2026-09-01 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-09-01 | 31 | 31 | 0 | /gsd-secure-phase (orchestrator, ASVS L1 short-circuit) |

### Security Audit 2026-09-01

| Metric | Count |
|--------|-------|
| Threats found | 31 |
| Closed | 31 |
| Open | 0 |

Verification depth: ASVS L1 (grep + targeted read). Two threats were verified by scoped
`git diff` rather than presence-grep, because their mitigation is an *absence* of change
(T-06-24 `_db_lock` call sites, T-06-SC dependency manifests). The deferred canon
output-encoding breadcrumb attached to T-06-14 was discharged in this run.

Contract tests executed at audit time, all green:

- `tests/test_workload_resilience.py`, `tests/test_worker_ownership_matrix.py`,
  `tests/test_security_and_scanning.py` — 30 passed, 71 subtests passed
- `tests/test_migrations.py` — 43 passed, 6 subtests passed

Per the workflow's short-circuit rule (`threats_open: 0` ∧ `register_authored_at_plan_time: true`
∧ `asvs_level == 1`), no separate auditor subagent pass was required.

### 06-20 — `T-06-24` re-closed on the narrowed shape's own evidence; formal re-audit still outstanding

`api_services`' `_db_lock` scope narrowed (`D-DEBT-06-01`, `PROH-OPS-04-06`). `T-06-24`'s closure
evidence is replaced above — the retired diff-based form (`git diff 8c2fc48..HEAD`) and `06-15`'s
frozen-scope pin are both superseded by three tests describing the shape the code now has, per
`PROH-OPS-04-05` prerequisite 4's own instruction ("re-close `T-06-24` again on new evidence
describing the narrowed shape — not to restore the retired diff-based form"). Three new threats
this narrowing introduces (`T-06-101`, `T-06-102`, `T-06-103`) are added to the register above,
each closed on its own named test.

**`/gsd-secure-phase 06` itself has NOT re-run.** `PROH-OPS-04-05` prerequisite 4 requires the
formal re-audit; this SUMMARY-level re-closure is evidence for that re-audit to consume, not a
substitute for it. Scheduled in `06-24`, per this plan's own sequencing and `D-DEBT-06-01`'s
"Round 4 reopening" prerequisite list. `threats_open` stays `0` — every threat in the register
above, including the three new ones, has a `closed` disposition — but the phase-level
`status: verified` / Sign-Off below describes the `2026-09-01` audit, not a re-run against this
narrowing; `06-24`'s re-run is what makes that frontmatter current again.

---

### 06-22 — T-C (the occurrence memo) shipped for `/api/advanced/current`; `PROH-OPS-04-05` NOT engaged

`06-22-PLAN.md` Task 1's blocking `checkpoint:decision` resolved **T-C** (`t-c-reduce-cost`) as the
remedy for `/api/advanced/current`'s measured budget failure — a request-scoped occurrence-walk memo
threaded through `dashboard/beacon/diagnosis.py`'s `get_current_diagnosis`, mirroring `06-13`'s
identical `/api/services` fix. **`PROH-OPS-04-05` is explicitly NOT engaged by this branch**, stated
here rather than left ambiguous: that prohibition gates a second OS process gaining unserialized
concurrent write access to the shared SQLite file (the `t-a-add-workers` branch this plan's Task 1
held in reserve but did not select). T-C changes no deployment topology, opens no new
database-access boundary, and touches neither `dashboard/Dockerfile` nor `docker-compose.yml` — `git
diff --quiet` holds for both. `T-06-24`'s closure evidence is therefore untouched by this plan; no
re-audit trigger fires.

New threat `T-06-112` (Tampering — the payload changing under this cost change) is added to the
register above, closed on `PROH-OPS-07-14` (minted this plan) and the mutation-verified
payload-equivalence guard. `threats_open` stays `0`.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-09-01
