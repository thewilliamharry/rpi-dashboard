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
| T-06-24 | Elevation of Privilege | a route gaining unserialized DB access as a WAL side effect | high | mitigate | **Re-closed 2026-09-06 (`06-32`) on HEAD's own current evidence — the round-6 narrowed-shape citation (`test_api_services_lock_scope_is_database_reads_only`) is withdrawn; that def no longer exists in the tree (confirmed: a definition-grep for it returns nothing; only two comment references survive, at `tests/test_lock_profile.py:643` and `:1947`, each inside a sentence recording the rename's history, never presented as live evidence).** Closed instead on: `LockScopePreservationTests::test_call_site_count_and_shape` (28-site count/shape: 3 bare + 25 combined, confirmed present); `LockScopePreservationTests::test_api_services_lock_scope_containment_and_termination` (the CURRENT pre-narrowing containment pin, restored by the `ea8689e` revert and carried through `06-25`'s and `06-31`'s producer renames without the lock's scope ever moving); `LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock` (no connection use escapes its owning `_db_lock` block, across all 28 sites); `LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit` (the AST-versus-`06-LOCK-AUDIT.md` set-equality invariant). All four confirmed present and passing at HEAD (`993 passed, 593 subtests passed`). `NarrowedShapeConcurrentAccessTests` (`tests/test_workload_resilience.py:945`) is confirmed to still exist, but is NOT cited as live containment evidence here: its docstring proves a hazard specific to a narrowed shape (rows materialized inside `_db_lock`, consumed after the connection closes) that is not HEAD's current shape — HEAD computes everything inside the lock again, so this class is retained evidence for a hazard class, not a description of HEAD's containment posture. `/gsd-secure-phase 06` re-run remains outstanding per `PROH-OPS-04-05` prerequisite 4 — see Security Audit Trail | closed |
| T-06-101 | Tampering | `/api/services`' held-region Python share exceeding its calibrated ceiling without being noticed (originally scoped as "a computation quietly moved back inside the critical section, undoing `06-20`'s narrowing") | high | mitigate | **Re-closed 2026-09-06 (`06-32`) — the original threat framing (an undisclosed regression of a narrowing) no longer applies: `06-31` reverted the narrowing overtly, by recorded decision, not by accident.** The underlying protective mechanism is retained and re-scoped rather than dropped: `HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing` (`tests/test_lock_profile.py:609`) still exists, still passes at HEAD, and still measures `/api/services`' actual Python share of its own held region against `PYTHON_SHARE_CEILING` (0.5) on every route call — its docstring and name describe the now-reverted narrowing and are stale, but the assertion itself continues to guard a live property: even with `_uptime_summary` executing inside `_db_lock` again, `06-31`'s state-change-only reduction keeps its Python cost share under the calibrated ceiling. The stale AST-pin citation (`test_api_services_lock_scope_is_database_reads_only`) is dropped from this row; `LockScopePreservationTests::test_api_services_lock_scope_containment_and_termination` (see `T-06-24`) is the current shape pin | closed |
| T-06-102 | Information Disclosure | a `sqlite3.Row` field read after its connection closed, yielding a partial or wrong value | high | mitigate | Every result consumed outside `api_services`' `_db_lock` block is materialized into a plain dict inside it (`services`, `all_checks`, `preview_rows`); `06-19` Task 2's recorded `sqlite3.ProgrammingError` mutation is the evidence the hazard is real, not hypothetical (`06-20`) | closed |
| T-06-103 | Repudiation | `/api/services`' output changing under a scope-only edit while every gate stays green — the `D-DEBT-06-10` `CR-01` shape | critical | mitigate | `ApiServicesOutputEquivalenceTests::test_narrowed_route_reproduces_the_pre_narrowing_response_bytes` — three golden fixtures (maintenance-path, over-cap, empty-services) captured from unmodified pre-narrowing code, byte-equality re-checked after; `PROH-OPS-07-05` (`06-20`). **Re-checked 2026-09-06 (`06-28`): the class and all three fixtures still exist (`tests/fixtures/api_services_pre_narrowing_{,over_cap_,empty_}golden.json`, confirmed present on disk) and `06-25` re-exercised them against a new change (the SQL-reader wiring) and they still passed — this strengthens rather than invalidates the row, since the guard has now survived two independent shape changes on the surface it protects** | closed |
| T-06-112 | Tampering | `/api/advanced/current`'s payload changing under a cost or topology change while every gate stays green | critical | mitigate | `PROH-OPS-07-14` (minted `06-22`) and `AdvancedCurrentCostTests::test_payload_is_unchanged_by_the_round_5_remedy` — golden captured from the pre-remedy code (`tests/fixtures/advanced_current_pre_remedy_golden.json`), byte-equality checked after the T-C memo shipped, mutation-verified sensitive to a dropped composed field (`06-22`). **Re-checked 2026-09-06 (`06-28`): `AdvancedCurrentCostTests` (`tests/test_advanced_diagnosis_api.py:3106`) and `test_payload_is_unchanged_by_the_round_5_remedy` (`:3119`) confirmed present as definitions; the golden fixture confirmed present on disk (11K). Both survive the `06-25`..`06-32` interval unchanged — this route's remedy was never touched by round 6/7's work, so the row stays closed on the same evidence, not re-derived** | closed |
| T-06-25 | Spoofing | a dead worker epoch writing a terminal outcome | high | mitigate | `_assert_current_worker_owner` fencing (`queues.py:181-204`) raising `LeaseLost`, plus `recover_queues_for_worker`; asserted by the restart test | closed |
| T-06-26 | Repudiation | a smoke run passed off as hardware acceptance evidence | high | mitigate | `run_kind = 'smoke' if scenario.self_test else 'acceptance'` derived from the invocation (`tests/pi_load_acceptance.py:420`); the report always carries `platform.machine()` and `platform.node()` (`:423-424`) | closed |
| T-06-27 | Tampering | thresholds tuned to make a run pass | high | mitigate | The cadence oracle delegates to the product's own `freshness_state`; `test_pi_load_acceptance_oracles_are_the_products_own` (`test_workload_resilience.py:947`) locks the oracles to product code | closed |
| T-06-28 | Denial of Service | the harness itself overloading the Pi | medium | mitigate | `--concurrency` defaults to 8, matching gunicorn's own thread count; `--duration` is bounded and required; the harness issues no writes | closed |
| T-06-29 | Information Disclosure | the report embedding operator data | low | mitigate | `AcceptanceReport` carries route names, latency statistics, resource samples and job-health rows only — no thumbnail bytes, no service URLs, no request bodies (`tests/pi_load_acceptance.py:122-140`) | closed |
| T-06-30 | Spoofing | a run against the wrong target reported as the deployment | medium | mitigate | The report records the resolved `--base-url` and `--db` alongside the host; an unreachable target exits non-zero rather than reporting a pass (`:431-434`) | closed |
| T-06-SC | Tampering | npm/pip/cargo installs | high | mitigate | **Verified by scoped diff:** `git diff 8c2fc48..HEAD -- dashboard/pyproject.toml dashboard/uv.lock dashboard/Dockerfile` is empty — no dependency was added, removed, or re-pinned in this phase. The harness uses `requests`, `psutil`, `threading` and the stdlib, all already pinned | closed |
| T-06-158 | Tampering | the input reduction silently moving a rendered value under a change described as cost-only | high | mitigate | Partition-additivity argument recorded in the source comment (`dashboard/app.py`, `06-31` Task 2); `UptimeStripCoalescingDifferentialTests` (1,813 randomized transition-dense cases, 86 carrying a NULL row, this run's seed); the three `api_services_pre_narrowing_*_golden.json` fixtures byte-matched unregenerated, confirmed by an empty `git status` on `tests/fixtures/` | closed |
| T-06-159 | Tampering | a NULL `online` row coalesced away, converting a producer refusal into a rendered number | high | mitigate | `PROH-OPS-07-28`. `last_state_by_port` resets to `None` on every NULL row (a value no real 0/1 state can equal), so the row immediately following a NULL is always appended; mutation (m1) measured 29/1,813 divergences when this reset is removed (`06-31-SUMMARY.md`) | closed |
| T-06-160 | Repudiation | the reduction removed later while the differential still passes, leaving the cost regression invisible | high | mitigate | `UptimeStripInputReductionGuardTests` pins the producer's input count to state transitions rather than stored volume on both a dense fixture and a mostly-unobserved-window fixture; mutation (m3) measured 0/1,813 differential divergences when the reduction is removed entirely, which is exactly why this second, independent guard class exists rather than relying on the differential alone — both of its test methods confirmed to fail when the reduction was manually reverted from `dashboard/app.py` (restored, `git diff --stat` empty afterward) | closed |
| T-06-161 | Elevation of Privilege | the revert widening or narrowing `_db_lock`'s scope as a side effect of renaming its cited producer | high | mitigate | `PROH-OPS-04-02`. `LockScopePreservationTests::test_api_services_lock_scope_containment_and_termination` re-pins containment against `_uptime_summary` (renamed back from `beacon_repositories.read_uptime_strips_by_port`); `LockScopeInvariantTests`' 28-site AST-versus-audit set equality (`test_every_db_lock_site_is_covered_by_the_audit`) asserted independently of the rename and confirmed passing at HEAD | closed |
| T-06-162 | Information Disclosure | `read_uptime_strips_by_port` remaining in the tree being read later as live production code | medium | mitigate | `D-DEBT-06-24` records it as debt with the operator's `06-GUARD-DECISION.md` §8 retention rationale, the guards that keep exercising it, and the condition for deletion | closed |
| T-06-163 | Repudiation | a future round re-proposing the `service_rollups` remedy for a third time | medium | mitigate | `PROH-OPS-07-29`. `D-DEBT-06-21`'s round-7 addendum records the independent re-refutation next to the round-6 original, plus the epoch-hour alignment finding (168/168 buckets straddle, worst error 0.461) the original did not carry, upgrading the rejection to "not reconstructible" | closed |
| T-06-164 | Tampering | npm/pip/cargo installs | high | accept | No package install occurs this round either. `06-RESEARCH.md` § Standard Stack: "Installation: None." No `[ASSUMED]`/`[SUS]` entry exists, so no legitimacy checkpoint is required | closed |
| T-06-120 | Tampering | `UPTIME_STRIP_QUERY`'s dynamic `IN` list (`dashboard/beacon/repositories.py`) | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`'s `<threat_model>`); code retained, unreferenced by production (`D-DEBT-06-24`).** Ports are bound through `','.join('?' * len(ports))` placeholders, never interpolated; `UptimeStripSqlTextGuardTests` asserts no port literal appears in the rendered SQL. Ports originate from the `services` table, not from the request. `read_uptime_strips_by_port` has zero production callers as of `06-31`'s revert — this is a threat about retained, tested, unreferenced code, not the live request path | closed |
| T-06-121 | Repudiation | The SQL-rendered strip changing under a cost-only edit while every gate stays green — `T-06-103`'s shape at a new door | critical | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** Three unregenerated golden fixtures byte-compared, plus `UptimeStripSqlDifferentialTests`' randomized differential against `_legacy_uptime_summary`. `PROH-OPS-07-05`, `PROH-OPS-07-15`. `06-31` reverted this producer off the request path; the live-path equivalent of this threat (the Python producer's reduction changing the rendered strip) is `T-06-158`, already registered and closed on its own evidence | closed |
| T-06-122 | Denial of Service | The SQL aggregation running inside `_db_lock` and being slower than the Python sweep it replaced, extending the critical section under load | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** Measured at the route level twice and REFUTED both times (`06-25` +315.8%, `06-29`'s reshape +21.78% over the 56.820ms bar) — `D-DEBT-06-21`, `D-DEBT-06-23`. The operator's `revert-route-wiring` decision (`06-GUARD-DECISION.md` §8) removed this cost from the request path entirely rather than continuing to reduce it | closed |
| T-06-123 | Information Disclosure | A truncated aggregation silently reporting optimistic uptime — `D-DEBT-06-10`'s defect class | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** No `LIMIT`, no `_checked_rows` point budget on the SQL read; bounded by construction at `ports x UPTIME_BUCKETS`; `UptimeStripRowEmissionTests` asserts an over-cap case's strip value, not merely a 200 (`PROH-OPS-07-17`) | closed |
| T-06-124 | Elevation of Privilege | A route gaining unserialized database access — `T-06-24`'s lineage, at the SQL reader's door | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** When wired (`06-25`/`06-29`), the read sat inside the existing `with _db_lock` block; `LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock` and the 28-site audit both passed then and pass now that the read is unwired. `_db_lock`'s scope has not moved (`PROH-OPS-04-02`) | closed |
| T-06-125 | Denial of Service | An unbounded recursive CTE generating more bucket rows than intended if a constant (e.g. `UPTIME_BUCKETS`) changes | low | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** The generator's row count is `bucket_count`, asserted by `UptimeStripBoundednessTests`; the reader raises `ValueError` when `window_seconds % bucket_count` is non-zero. Distinct from `T-06-172` below: this threat is a misconfiguration hazard (a constant changing), not the data-dependent row-count hazard that threat covers | closed |
| T-06-144 | Repudiation | The SQL replacement producer reading a wider input set than the producer it replaces — a boundary sample taken from a check older than `CHECK_RETENTION_SECONDS`, which `all_checks` has never returned | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** The reader's boundary lookup and in-window scan are both floored at a caller-supplied `retention_seconds`; `api_services` passed `CHECK_RETENTION_SECONDS` when wired. Two beyond-retention differential cases in `UptimeStripSqlDifferentialTests` assert the pre-change sentinel behaviour survives; mutation (a) removes the floor to prove they discriminate. `PROH-OPS-07-22`. Not covered by `T-06-121`'s golden fixtures: none contains a row older than retention | closed |
| T-06-145 | Information Disclosure | A NULL `online` row rendering as a plausible availability number in the SQL producer while the Python one raises — `online` is nullable at `migrations.py:119-120` | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** The reader counts admitted NULL-`online` rows per port and raises `ValueError` rather than coercing, so both producers refuse the same input; both production writers bind an integer, so the path is schema-permitted but unwritten. The live-path equivalent for the current Python producer is `T-06-159`, already registered and closed | closed |
| T-06-126 | Tampering | npm/pip/cargo installs | high | accept | **Registered by `06-28`, 2026-09-06 (from `06-25-PLAN.md`).** No package install occurred in `06-25`. `06-RESEARCH.md` § Standard Stack: "Installation: None." No `[ASSUMED]`/`[SUS]` package was introduced | closed |
| T-06-127 | Repudiation | `06-PROFILE-3.md`'s figures being read as Pi latency evidence in a later round | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-26-PLAN.md`).** The report names `host_machine`/`host_node` and carries the honesty block; `PROH-OPS-07-09` is cited in the report itself. The profiler's `HONESTY_CAVEAT` was verified unedited by `06-26`'s own acceptance criteria | closed |
| T-06-128 | Repudiation | A share percentage compared across two different shapes, producing arithmetic that must later be withdrawn | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-26-PLAN.md`).** `PROH-OPS-07-18`; the invocation, seed and shape are pinned to `06-PROFILE-2.md`'s and stated in `06-PROFILE-3.md`; no `06-PROFILE.md` §4 growth figure is quoted | closed |
| T-06-129 | Spoofing | `uptime_sweep`'s collapse presented as a saving when the work merely moved into C | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-26-PLAN.md`).** `PROH-OPS-07-19`; the headline is `wall_ms_unprofiled`, and `06-PROFILE-3.md` attributes where the cost went | closed |
| T-06-130 | Denial of Service | A flaky timing guard entering the suite and eroding the "no NEW failures" gate | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-26-PLAN.md`).** No wall-clock assertion was added to the new test class; ten consecutive isolated runs were `06-26`'s own acceptance criterion. Precedent: `deferred-items.md` Entry 2 | closed |
| T-06-131 | Tampering | npm/pip/cargo installs | high | accept | **Registered by `06-28`, 2026-09-06 (from `06-26-PLAN.md`).** No package install occurred. `06-RESEARCH.md` § Standard Stack: "Installation: None." No `[ASSUMED]`/`[SUS]` package, so no legitimacy checkpoint was required | closed |
| T-06-132 | Repudiation | An acceptance result recorded more favourably than it measured | critical | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-27-PLAN.md`); executed against `06-31`'s current build, `06-ACCEPTANCE-C3-RUN3.md`.** The report's admissibility block states all four gating properties; `git diff -- tests/ dashboard/` empty proved nothing was tuned in response (`PROH-OPS-07-01`, `PROH-OPS-07-10`); every figure traces to the operator's reported values, cross-checked against committed JSON before writing (`06-27-SUMMARY.md`) | closed |
| T-06-133 | Spoofing | An instrumented run presented as acceptance evidence | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-27-PLAN.md`).** The diagnostic endpoint returned `404` before the run started and `lock_profile` is empty (`{}`) in `06-ACCEPTANCE-C3-RUN3.md` — both confirmed (`PROH-OPS-07-11`) | closed |
| T-06-134 | Denial of Service | A 600-second closed-loop run degrading the live deployment or starving essential sampling | medium | accept | **Registered by `06-28`, 2026-09-06 (from `06-27-PLAN.md`).** Accepted: this is the measurement's purpose. `assertions.cadence` PASSED in `06-ACCEPTANCE-C3-RUN3.md` — essential sampling survived. Six prior runs (across this phase) completed without durable damage | closed |
| T-06-135 | Elevation of Privilege | The harness running under `sudo` against the deployment's live database | medium | accept | **Registered by `06-28`, 2026-09-06 (from `06-27-PLAN.md`).** Accepted and pre-existing: the resource oracle must resolve host-namespace PIDs through `docker inspect`, which requires host privileges. The harness's database access is read-only polling of job-health evidence, recorded explicitly in `06-ACCEPTANCE-RUNBOOK.md` | closed |
| T-06-136 | Tampering | A figure compared across a changed dataset, producing a conclusion that must later be withdrawn | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-27-PLAN.md`).** `service_checks` counts recorded before and after the run (66,005 → 66,035) and printed alongside the run's p95 in the three-run comparison table in `06-ACCEPTANCE-C3-RUN3.md` (`D-DEBT-06-14`'s lesson) | closed |
| T-06-137 | Tampering | npm/pip/cargo installs | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-27-PLAN.md`).** `uv sync --project dashboard` installed from the committed `dashboard/uv.lock` only; `git diff -- dashboard/uv.lock dashboard/pyproject.toml` was empty, an acceptance criterion `06-27` confirmed | closed |
| T-06-138 | Repudiation | A threat recorded closed on evidence removed by `ea8689e` | high | mitigate | **Registered by `06-28`, 2026-09-06 (this plan's own threat).** This task re-checked every closed `mitigate` row's cited artifact against the tree and corrected or reopened as needed; `PROH-OPS-07-21`. See this round's Security Audit Trail entry for the full before/after accounting | closed |
| T-06-139 | Tampering | A closed threat silently dropped from the register during this plan's own edit | high | mitigate | **Registered by `06-28`, 2026-09-06 (this plan's own threat).** Row count and full ID set recorded before (42) and after (88) this edit, compared, and both recorded in `06-28-SUMMARY.md` and this round's Security Audit Trail entry | closed |
| T-06-140 | Repudiation | `PROH-OPS-04-05` read as discharged because a re-run performed for a different reason happened | medium | mitigate | **Registered by `06-28`, 2026-09-06 (this plan's own threat).** This round's Security Audit Trail entry states covered scope (the formal re-run against `06-31`'s shape) and outstanding scope (worker-count-tied prerequisites, unengaged because no worker count changed) in separate sentences | closed |
| T-06-141 | Denial of Service | An unscoped write to `ROADMAP.md` or `STATE.md` destroying entries for other phases | high | mitigate | **Registered by `06-28`, 2026-09-06 (this plan's own threat).** Scoped `Edit` calls only, never a whole-file rewrite; `grep -c "^### Phase "` recorded before and after this plan's Task 2 edit, in `06-28-SUMMARY.md` | closed |
| T-06-142 | Spoofing | A consolidation sentence asserting a measurement this round did not take | high | mitigate | **Registered by `06-28`, 2026-09-06 (this plan's own threat).** Every claim about `06-27`'s result in this plan's `ROADMAP.md`/`STATE.md` edits traces to `06-27-SUMMARY.md` or `06-ACCEPTANCE-C3-RUN3.md`; no figure is inferred | closed |
| T-06-143 | Tampering | npm/pip/cargo installs | high | accept | **Registered by `06-28`, 2026-09-06 (this plan's own threat).** No package install occurs; this plan edits Markdown planning documents and runs the existing suite. No `[ASSUMED]`/`[SUS]` package is introduced | closed |
| T-06-146 | Tampering | The reshaped `bucket_totals` silently moving a rendered value under a change described as cost-only | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-29-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** The three golden fixtures byte-match unregenerated, and every `06-25` correctness guard passed with `git diff --stat -- tests/` empty on `06-29`'s Task 1 commit — the reshape is proven by 1,824 differential cases written before it existed | closed |
| T-06-147 | Spoofing | Integer division entering the query being read by a later round as licence for arithmetic on rendered values | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-29-PLAN.md`); code retained, unreferenced by production (`D-DEBT-06-24`).** `PROH-OPS-07-23`. `UptimeStripCostModelTests`' allowlist enumerates the exact two index expressions and asserts the constant's total division count equals theirs; mutation (c-double-prime) proves a division in a projected total still fails | closed |
| T-06-148 | Denial of Service | The recursive `expanded` CTE's intermediate row count being data-dependent where the old shape's intermediate was fixed at `ports x UPTIME_BUCKETS` | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-29-PLAN.md`, at its own planning-time figures); code retained, unreferenced by production (`D-DEBT-06-24`).** Bounded by `segments + len(ports) * (UPTIME_BUCKETS - 1)`; `06-29-PLAN.md`'s own text cites a planner-measured 28,682 expanded rows for 27,805 segments against a bound of 29,141. `UptimeStripBoundednessTests` asserts the bound. **`06-29`'s own executed measurement superseded this planning-time figure with 22,247 against 23,583** (`06-29-SUMMARY.md`) — carried forward, with the disposition this threat needed re-scoped to HEAD's unreferenced code path, as the separately minted `T-06-172` below, per `06-GUARD-DECISION.md` §7 point 1 | closed |
| T-06-149 | Repudiation | `06-PROFILE-4.md`'s number re-based against 236.265ms to manufacture a pass | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-29-PLAN.md`).** `PROH-OPS-07-26`. The pass bar, the projection and all three branch wordings were written to disk before the measurement; `06-29`'s own acceptance criteria confirmed 56.820 precedes 236.265 in the verdict section | closed |
| T-06-150 | Information Disclosure | A narrowed guard being read later as evidence that the rounding hazard was never real | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-29-PLAN.md`).** The class docstring carries the concrete demonstration (trial 33, port 40331, `0.063` against `0.062` near one sixteenth); mutation (c) was re-run against the narrowed form in the same commit | closed |
| T-06-151 | Tampering | npm/pip/cargo installs | high | accept | **Registered by `06-28`, 2026-09-06 (from `06-29-PLAN.md`).** No package install occurred. `06-RESEARCH.md` § Standard Stack line 71: "Installation: None." No `[ASSUMED]`/`[SUS]` entry, so no legitimacy checkpoint was required | closed |
| T-06-152 | Repudiation | An unmet acceptance criterion in an executed plan being absorbed into the fixing round's record and disappearing from the owning plan's | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-30-PLAN.md`).** `PROH-OPS-07-27`. `06-GUARD-DECISION.md` section 1 names `06-25-PLAN.md` lines 508-522 and quotes the grep that proves the omission (`D-DEBT-06-22`); `git diff` on both `06-25` artifacts stayed empty, so the original specification and the original omission both stay in place | closed |
| T-06-153 | Spoofing | A guard narrowing recorded in a way that reads, later, as a criterion amended because the code could not comply | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-30-PLAN.md`).** `PROH-OPS-07-01`, `PROH-OPS-07-10`, `PROH-OPS-07-23`. `06-GUARD-DECISION.md` section 4 carries the distinction as a standalone sentence and cites the ROADMAP's criterion-5 amendment note as precedent; section 5 reproduces three mutation messages rather than asserting detection power | closed |
| T-06-154 | Spoofing | A decision checkpoint framed so only one branch looks acceptable | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-30-PLAN.md`).** The options list led with the revert branch, costed it honestly (a fourth lock-audit realignment, dead tested code), and stated the numbers before any framing; the projection was fixed before the measurement (`06-GUARD-DECISION.md` §8) | closed |
| T-06-155 | Repudiation | `06-27` and `06-28` left describing a build that no longer exists | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-30-PLAN.md`); this plan is the discharge of its own mitigation.** `06-GUARD-DECISION.md` section 7 enumerated the required amendments for both without editing either (the append contract); this plan (`06-28`) performs the re-close `06-28` needed, and `06-27` performed its own segment A/B against the current build rather than the stale SHAs the original plan text named | closed |
| T-06-156 | Information Disclosure | The round's substantive technical finding — the SQL formulation's floor exceeding the Python sweep — being lost inside a one-word verdict | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-30-PLAN.md`).** `D-DEBT-06-23` records the four measured components separately from the verdict, each labelled with its measurement source, so the finding survives independently of whether the fix passed | closed |
| T-06-157 | Tampering | npm/pip/cargo installs | high | accept | **Registered by `06-28`, 2026-09-06 (from `06-30-PLAN.md`).** No package install occurred. `06-RESEARCH.md` § Standard Stack line 71: "Installation: None." No `[ASSUMED]`/`[SUS]` entry, so no legitimacy checkpoint was required | closed |
| T-06-165 | Repudiation | `06-PROFILE-5.md`'s number re-based against 69.191ms or 236.265ms to manufacture a pass | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-32-PLAN.md`).** `PROH-OPS-07-26`. Pass bar, projection and all three branch wordings were committed before the measurement, in their own commit; `06-32`'s own acceptance criterion required the 56.820ms delta to appear before any other comparison | closed |
| T-06-166 | Tampering | A near-miss result argued into a fourth branch rather than executing the stop-and-revert | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-32-PLAN.md`).** Only three branches were worded, the FAIL branch named the revert as an action rather than a recommendation, and `PROH-OPS-07-01`/`-10` forbid touching the bar, harness, seed or shape in response | closed |
| T-06-167 | Information Disclosure | A `06-SECURITY.md` entry left citing `06-25`/`06-29` route wiring as live evidence | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-32-PLAN.md`); discharged by `06-32` for `T-06-24`/`T-06-101` and by this plan (`06-28`) for every remaining row.** `PROH-OPS-07-21`. This round's Security Audit Trail entry records the before/after row counts and ID sets compared | closed |
| T-06-168 | Repudiation | An eighth round re-proposing the `service_rollups` remedy for a third time | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-32-PLAN.md`).** `PROH-OPS-07-29`. `D-DEBT-06-21` carries the round-7 re-refutation plus the alignment finding, upgrading the rejection from "not currently populated" to "not reconstructible at any population" | closed |
| T-06-169 | Information Disclosure | `read_uptime_strips_by_port` being read later as live production code | medium | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-32-PLAN.md`); duplicate coverage of the same code surface as `T-06-162`, both retained deliberately.** `D-DEBT-06-24` records it as deliberately retained, unreferenced by production, with the operator's rationale and the deletion condition | closed |
| T-06-170 | Elevation of Privilege | OPS-07 promoted by a plan in its own round | high | mitigate | **Registered by `06-28`, 2026-09-06 (from `06-32-PLAN.md`); this plan's own Task 2 is held to the same invariant.** `PROH-OPS-07-08`. `.planning/REQUIREMENTS.md` is outside this plan's `files_modified` as well; `git diff --quiet -- .planning/REQUIREMENTS.md` is one of this plan's own acceptance criteria | closed |
| T-06-171 | Tampering | npm/pip/cargo installs | high | accept | **Registered by `06-28`, 2026-09-06 (from `06-32-PLAN.md`).** No package install occurred. `06-RESEARCH.md` § Standard Stack: "Installation: None." No `[ASSUMED]`/`[SUS]` entry, so no legitimacy checkpoint was required | closed |
| T-06-172 | Denial of Service | The recursive `expanded` CTE's intermediate row count is data-dependent, where the shape it replaced (`requested_ports CROSS JOIN buckets`) was fixed at `ports x UPTIME_BUCKETS` regardless of the underlying data | low | mitigate | **Minted by `06-28`, 2026-09-06, per `06-GUARD-DECISION.md` §7 point 1 — the fourth `06-25`-lineage threat no prior round registered.** Bound: `segments + len(ports) * (UPTIME_BUCKETS - 1)`, provable because a port's segments partition `[start, now]` contiguously, so each internal bucket boundary splits exactly one segment, contributing at most one extra expanded row per boundary crossed. Carries `06-29`'s own executed measurement as evidence rather than re-deriving it: **22,247 expanded rows against a computed bound of 23,583** (`06-29-SUMMARY.md`), on the 8-service/8-day profiled shape. Closed on `UptimeStripBoundednessTests` (`tests/test_services_route_scaling.py:1240`) and `PROH-OPS-07-17`. **Materiality, stated rather than carried forward unaltered:** `06-GUARD-DECISION.md` §7 raised this threat while the reshape was wired to `/api/services`; `06-31`'s revert took `read_uptime_strips_by_port` off the request path. This row is therefore mitigated against a **retained, tested, unreferenced** code path, NOT the live request path — severity `low` rather than the `medium` §7's framing implied, for that reason. The guard is real and still passes; the exposure it guards is currently unreachable from outside (`D-DEBT-06-24`) | closed |

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
| 2026-09-06 | 88 | 88 | 0 | `06-28` — the formal `/gsd-secure-phase 06` re-run `PROH-OPS-04-05` prerequisite 4 has required since `06-20`; see the `06-28` entry below |

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

### 06-32 — round 7's threats registered; `T-06-24` and `T-06-101` re-closed on HEAD's current evidence, not the round-5 narrowed shape

**Register counts, before and after this edit, per this task's own instruction (no threat may be
quietly reopened or dropped).**

| | Total | IDs |
|---|---|---|
| Before | 35 | `T-06-01`..`T-06-30`, `T-06-101`, `T-06-102`, `T-06-103`, `T-06-112`, `T-06-SC` |
| After | 42 | Before's 35, plus `T-06-158`..`T-06-164` (7 new) |

**42 = 35 + 7 exactly. No pre-existing ID is absent from the post-edit set** — confirmed by set
comparison against the "Before" list above.

**Why this re-audit was needed.** `06-31` reverted `/api/services`' route wiring back to the Python
producer and, in the same commit, renamed the identifier `LockScopePreservationTests`' AST pin
checks from `beacon_repositories.read_uptime_strips_by_port` to `_uptime_summary` — the second such
rename this phase (`06-25` made the first, in the opposite direction). `T-06-24` and `T-06-101`'s
closure evidence cited a test named for the round-5 narrowed shape,
`test_api_services_lock_scope_is_database_reads_only`, which does not exist as a definition
anywhere in the tree at HEAD — a definition-grep (`grep -rn "def
test_api_services_lock_scope_is_database_reads_only" tests/`) returns nothing; a bare-name grep
returns exactly two comment hits, at `tests/test_lock_profile.py:643` and `:1947`, both inside
sentences that record the rename's history rather than presenting it as live evidence. Per
`PROH-OPS-07-21`, a security register entry may never cite evidence not present in the tree it
describes — this was exactly that defect, carried since round 5's revert (`ea8689e`) and never
corrected because `06-28` (the plan scoped to correct it) has not yet executed.

**What changed in each row, stated so the judgement is auditable.**

- `T-06-24` — re-closed on `LockScopePreservationTests::test_call_site_count_and_shape`,
  `LockScopePreservationTests::test_api_services_lock_scope_containment_and_termination`,
  `LockScopeInvariantTests::test_no_database_access_escapes_the_db_lock`, and
  `LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit` — all four confirmed
  present in `tests/test_lock_profile.py` and passing in the `993 passed, 593 subtests passed`
  suite run this task's own precondition required. `NarrowedShapeConcurrentAccessTests`
  (`tests/test_workload_resilience.py:945`) is confirmed present, not removed, but is no longer
  cited as live containment evidence for HEAD's shape (see the register row for why).
- `T-06-101` — re-closed on the same containment pin plus
  `HeldRegionCompositionTests::test_services_held_region_is_sql_dominated_after_narrowing`
  (`tests/test_lock_profile.py:609`), confirmed present and passing, re-scoped from "detects an
  undisclosed narrowing regression" (moot — the narrowing was reverted overtly, by decision) to "the
  held region's measured Python share stays under its calibrated ceiling even with `_uptime_summary`
  running inside the lock again," which is what the assertion has actually measured all along.

**`PROH-OPS-04-05` prerequisite 4 status, restated precisely rather than left ambiguous.** This
re-closure is a SUMMARY-level correction of two stale citations, performed by the executing plan
itself — it is not the formal `/gsd-secure-phase 06` re-run that prerequisite 4 requires, and does
not discharge it. That re-run remains outstanding, as it has since `06-20` first narrowed the lock.
`threats_open` stays `0`.

Contract tests re-confirmed at this audit-trail entry's time, all green (full suite, precondition
to Task 1 of this plan): `993 passed, 593 subtests passed, 0 failed`.

---

### 06-28 — the formal `/gsd-secure-phase 06` re-run against `06-31`'s shape; every unregistered threat range registered; the recursive-CTE threat minted and scoped

**This is the re-run `PROH-OPS-04-05` prerequisite 4 has required since `06-20` first narrowed
`_db_lock`, and the first entry in this file entitled to say so.** `06-20`'s own audit-trail entry
recorded the re-run as owed to `06-24`; `06-24` was superseded by the `ea8689e` revert and never
executed. `06-22`'s entry recorded the re-run as not engaged. `06-32`'s entry explicitly disclaimed
being that re-run — "a SUMMARY-level correction of two stale citations... not the formal
`/gsd-secure-phase 06` re-run." This plan (`06-28`) performs it: the register re-close pass at ASVS
level 1, blocking on `high`, run against `06-31`'s current shape (the Python producer `_uptime_summary`
on the request path, `read_uptime_strips_by_port` retained but unreferenced).

**Register counts, before and after this edit.**

| | Total | IDs |
|---|---|---|
| Before | 42 | `T-06-01`..`T-06-30`, `T-06-101`, `T-06-102`, `T-06-103`, `T-06-112`, `T-06-SC`, `T-06-158`..`T-06-164` |
| After | 88 | Before's 42, plus `T-06-120`..`T-06-145` (26), `T-06-146`..`T-06-151` (6), `T-06-152`..`T-06-157` (6), `T-06-165`..`T-06-171` (7), and the newly minted `T-06-172` (1) |

**88 = 42 + 46 exactly** (26 + 6 + 6 + 7 + 1 = 46). No pre-existing ID is absent from the post-edit
set — confirmed by set comparison. `grep -o "^| T-06-[0-9A-Za-z]*" | sort | wc -l` = 88;
`sort -u | wc -l` = 88 — no duplicate IDs. `T-06-158`..`T-06-164` were verified present exactly once
each (`06-32` registered them; this plan did not re-add them).

**The registration ledger, as measured at this task's own run — matching the table this plan's own
`<action>` predicted, with no divergence.**

| Range | Count | Source plan | Action taken |
|---|---|---|---|
| `T-06-120`..`T-06-145` | 26 | `06-25`/`06-26`/`06-27`/`06-28` | Registered |
| `T-06-146`..`T-06-151` | 6 | `06-29` | Registered |
| `T-06-152`..`T-06-157` | 6 | `06-30` | Registered |
| `T-06-158`..`T-06-164` | 7 | `06-31` | Verified present (registered by `06-32`); not re-added |
| `T-06-165`..`T-06-171` | 7 | `06-32` | Registered |
| `T-06-172` | 1 | Minted by `06-28`, per `06-GUARD-DECISION.md` §7 point 1 | Registered |

**`T-06-24` and `T-06-101` verified, not redone.** Both rows' four/two cited tests
(`test_call_site_count_and_shape`, `test_api_services_lock_scope_containment_and_termination`,
`test_no_database_access_escapes_the_db_lock`, `test_every_db_lock_site_is_covered_by_the_audit`,
`test_services_held_region_is_sql_dominated_after_narrowing`) were confirmed present as definitions
in `tests/test_lock_profile.py` and passing in this task's own run of
`tests/test_lock_profile.py tests/test_services_route_scaling.py` (128 passed, 3 subtests passed).
`NarrowedShapeConcurrentAccessTests` confirmed present at `tests/test_workload_resilience.py:945`.
The definition-grep for `test_api_services_lock_scope_is_database_reads_only` returned nothing;
the bare-name grep returned exactly the same two comment hits `06-32` recorded
(`tests/test_lock_profile.py:643` and `:1947`) — no further line drift since `06-32`. Neither row was
edited; both stand exactly as `06-32` left them.

**`T-06-103` and `T-06-112` re-checked and annotated in place.** Both rows' cited tests and fixtures
were confirmed present and unchanged through the `06-25`..`06-32` interval — `T-06-103`'s guard
strengthened by surviving `06-25`'s SQL-reader wiring as a second shape change; `T-06-112` untouched
because no round-6/7 work touched `/api/advanced/current`. Neither row required re-closure; both were
annotated with the confirmation so the judgement is auditable rather than assumed.

**Every SQL-reader row scoped to what HEAD actually runs.** `T-06-120`..`T-06-126`, `T-06-144`,
`T-06-145`, `T-06-146`..`T-06-151`, and `T-06-172` — every row describing `UPTIME_STRIP_QUERY` or
`read_uptime_strips_by_port` — states that the code is retained with zero production callers as of
`06-31`'s revert (`D-DEBT-06-24`), confirmed by grepping `dashboard/` for callers of
`read_uptime_strips_by_port` (only the function's own definition and repositories.py's internal
references; `dashboard/app.py`'s sole reference is a comment). None is downgraded to `accept` on that
basis — the guards keeping them closed are what make re-wiring the code safe later.

**The fourth `06-25`-lineage threat, minted at `T-06-172`.** Per `06-GUARD-DECISION.md` §7 point 1:
the recursive `expanded` CTE's intermediate row count is data-dependent, bounded by
`segments + len(ports) * (UPTIME_BUCKETS - 1)`, carrying `06-29`'s own executed measurement
(22,247 against a computed bound of 23,583, `06-29-SUMMARY.md`) rather than its stale planning-time
figure (28,682/29,141, still readable verbatim in the newly registered `T-06-148`). Its disposition is
stated as mitigated against a **retained, tested, unreferenced** code path, not the live request path —
severity `low` rather than the `medium` §7's original framing implied, because `06-31`'s revert took
the reshape off the request path after §7 was written.

**`PROH-OPS-04-05` prerequisite 4, stated precisely.** This re-run covers: the register re-close pass
against `06-31`'s shape, at ASVS level 1, blocking on `high`, with every closed `mitigate` row's cited
evidence checked against the tree. It does **not** cover, and does not claim to discharge, the
prerequisite's worker-count-tied clauses (a cross-process audit, a `mem_limit` re-derived from
measured per-worker RSS) — this round changes no worker count, so those clauses remain unengaged and
undischarged, exactly as `06-25-PLAN.md` originally scoped them. A future round proposing a worker-count
increase must still perform those parts fresh.

Contract tests executed at this audit-trail entry's time, all green: full suite
`993 passed, 593 subtests passed, 0 failed`; `tests/test_lock_profile.py tests/test_services_route_scaling.py`
alone `128 passed, 3 subtests passed`. `threats_open` stays `0`.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-09-01; formally re-run 2026-09-06 (`06-28`) against `06-31`'s shape per
`PROH-OPS-04-05` prerequisite 4 — see the `06-28` Security Audit Trail entry above for scope covered
and scope still outstanding (worker-count-tied clauses, unengaged because no worker count changed)
