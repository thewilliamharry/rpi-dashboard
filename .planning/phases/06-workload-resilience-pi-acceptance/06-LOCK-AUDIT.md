---
phase: 06-workload-resilience-pi-acceptance
plan: 19
kind: audit
created: 2026-09-03
---

# 06-LOCK-AUDIT — per-call-site review of all 28 `with _db_lock` sites

> `PROH-OPS-04-05` prerequisite 1: "a per-call-site `_db_lock` audit across all 28 sites." This is
> that review. Its durable enforcement is not this document alone — a table nobody re-reads is not
> a prerequisite — but
> `tests/test_lock_profile.py::LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit`,
> which fails the moment a site's `(function, line)` pair here drifts from what
> `dashboard/app.py` actually contains.

**28 sites across 26 distinct functions.** `process_preview_requests` and `api_service_meta` each
own two `_db_lock` blocks — the only two functions that do. One row per **site**, not per
function.

**Form:** `bare` = `with _db_lock:` (a nested `database_access(...)` connection, if any, is opened
separately inside the block). `combined` = `with _db_lock, database_access(DB_PATH) as conn:` (one
statement, connection setup itself inside the critical section).

**Narrowed this round:** `yes` only for `api_services` (line 2821) — the sole site this round's
follow-up plan (`06-20`) narrows, per `D-DEBT-06-01`'s "Round 4 reopening" and
`06-LOCK-DIAGNOSTIC.md` §4's measured 25.0% Python share under load. Every other site is reviewed
here but left untouched.

| # | Function | Line | Form | Read/Write | Non-DB work held under the lock | Narrowed this round |
|---|----------|------|------|------------|----------------------------------|----------------------|
| 1 | `init_db` | 173 | bare | write | `prepare_database` migration run plus the legacy `state_since` backfill `UPDATE` | no |
| 2 | `update_worker_heartbeat` | 232 | bare | write | none | no |
| 3 | `recover_worker_state` | 240 | combined | read+write | JSON serialization of the `monitoring_gap` event's `details` payload | no |
| 4 | `_mutation_write_transaction` | 298 | combined | write (caller-defined body) | none — a generic transaction wrapper; whatever the caller's `yield conn` body does | no |
| 5 | `_update_scan_state` | 381 | combined | read+write | dict merge of the scan-state `changes` | no |
| 6 | `_legacy_record_event` | 846 | combined | write | none | no |
| 7 | `_legacy_should_send_alert` | 863 | combined | read | none | no |
| 8 | `_legacy_collect_system_stats` | 1297 | combined | read+write | none — the `sample` dict is built before the lock is taken | no |
| 9 | `_legacy_cleanup_history` | 1322 | combined | write | none | no |
| 10 | `_legacy_do_discovery` | 1362 | combined | read | none — `existing_probe_urls` is built after the block closes | no |
| 11 | `_legacy_do_uptime_check` | 1561 | combined | read | none — per-row probing and the follow-up `_mutation_write_transaction` calls run after this block closes | no |
| 12 | `process_preview_requests` | 2261 | combined | read | none | no |
| 13 | `process_preview_requests` | 2269 | combined | read+write | none | no |
| 14 | `_check_scan_rate_limit` | 2383 | combined | read+write | small rate-limit arithmetic (`retry_after`) | no |
| 15 | `api_stats` | 2563 | combined | read | none | no |
| 16 | `api_history` | 2575 | combined | read | none | no |
| 17 | `api_telemetry_history` | 2645 | combined | read | none — every call inside the block is itself a DB read (`get_host_telemetry`/`get_service_telemetry`/`get_telemetry_coverage`/`get_pending_aggregation`); response composition happens after | no |
| 18 | `api_events_history` | 2773 | combined | read | none — `read_events_in_range`/`read_episode_state_changes`/`anchor_candidate_ports`/`read_open_episode_anchors` are all DB reads; response composition happens after | no |
| 19 | `api_services` | 2821 | combined | read | `_uptime_summary`, `beacon_maintenance.coverage`, `beacon_maintenance.attributed_downtime_seconds`, `beacon_repositories.offline_intervals_from_points_by_port`, and the per-service `result` dict construction — measured **25.0% of this route's held region** under concurrency-8 load (`06-LOCK-DIAGNOSTIC.md` §4, `beacon-lockdiag-c8.json`) | **yes** |
| 20 | `api_events` | 2995 | combined | read | none | no |
| 21 | `api_service_meta` (GET) | 3028 | combined | read | none — delegates to `beacon_web.metadata_response`, itself DB reads only | no |
| 22 | `api_service_meta` (PUT) | 3069 | combined | read+write | field validation, URL normalization (`_normalize_service_url`, `_service_url_with_path`), and outbound-policy planning (`_outbound_policy().plan(...)`) — see "Future narrowing candidates" below | no |
| 23 | `api_thumbnail` | 3144 | combined | read | none | no |
| 24 | `api_thumbnail_status` | 3159 | combined | read | none — `thumb_state` derivation happens after the block closes | no |
| 25 | `api_scan_status` | 3223 | combined | read | none — freshness/staleness classification happens after the block closes | no |
| 26 | `healthz` | 3293 | combined | read | none (`SELECT 1`) | no |
| 27 | `readyz` | 3303 | bare | read | none — readiness classification happens after the block closes | no |
| 28 | `prometheus_metrics` | 3314 | combined | read | none | no |

**Row count: 28. Distinct function count: 26** (`process_preview_requests` and `api_service_meta`
each contribute two rows). `LockScopeInvariantTests::test_every_db_lock_site_is_covered_by_the_audit`
asserts both counts separately, and asserts `(function, line)` set equality between this table and
the AST-derived site set, in both directions.

## `AR-03-01` — the one route already outside `_db_lock`, named as an exception, not a site

`api_advanced_current` (`dashboard/app.py:2528`) takes no `_db_lock` at all —
`dashboard/beacon/diagnosis.py` holds zero `_db_lock` references. This is the pre-existing,
accepted-risk route `06-SECURITY.md`'s `AR-03-01` and `06-DEBT.md`'s `D-DEBT-06-01` both name. It
does not appear in the 28-row table above because it owns no `_db_lock` block; it is recorded here
so its absence reads as a deliberate, reviewed exception rather than an omission.
`06-LOCK-DIAGNOSTIC.md` §3 separately measures this route's own 12.31x degradation under load as
GIL/CPU contention (`lock_wait_ns_total` exactly 0.0ms across 880 requests), not `_db_lock`
contention — `_db_lock`'s narrowing cannot fix it; `D-DEBT-06-15` already records this as a second,
separate problem the follow-up plan does not close.

## Future narrowing candidates this round is deliberately not taking

Two sites hold non-database Python work under the lock beyond `api_services` (line 19 above, the
sole site this round narrows). Neither is touched by this plan or by `06-20`; both are filed as
`D-DEBT-06-16` in `06-DEBT.md` so they survive the phase rather than living only in this table:

- **`api_service_meta` (PUT), line 3069.** Field validation, URL normalization
  (`_normalize_service_url`, `_service_url_with_path`), and outbound-policy planning
  (`_outbound_policy().plan(next_url, OutboundPurpose.SERVICE_PROBE)`) all execute inside the
  critical section, ahead of the actual metadata write. This route is not hardware-profiled this
  phase (`06-PROFILE.md` and `06-LOCK-DIAGNOSTIC.md` both instrument `/api/services` and
  `/api/scan-status` specifically), so no measured share exists for it — it is named here as a
  structural observation from source, not a measured one.
- **`recover_worker_state`, line 240.** JSON serialization of the `monitoring_gap` event's
  `details` payload runs under the lock. This is a small, bounded cost (one `json.dumps` call over
  a two-key dict) and is named for completeness, not because it is a meaningful narrowing target.

Every other site's non-DB work is either none, or (per row 4, `_mutation_write_transaction`) is a
generic transaction wrapper whose body is entirely caller-defined and therefore not a fixed cost
attributable to this site itself.

## Provenance

Figures cited above from `06-LOCK-DIAGNOSTIC.md` are Pi hardware evidence (concurrency-8 pass,
`beacon-lockdiag-c8.json`, host `d9cecb8`), labeled per `PROH-OPS-07-09`. Every other column in
this table is a direct source read of `dashboard/app.py` at this plan's HEAD, not a measurement.
