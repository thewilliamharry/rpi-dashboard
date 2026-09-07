# Milestones

## v1.0 Beacon (Shipped: 2026-09-07)

**Phases completed:** 8 phases (1, 2, 3, 03.1, 4, 5, 6, 7) · 129 plans, 127 executed · 270 tasks
**Timeline:** 2026-07-24 → 2026-09-07 (45 days)
**Closeout type:** `override_closeout`
**Test suite at close:** 993 passed · 593 subtests · 0 failures
**Code:** 13,496 LOC Python · 6,524 LOC hand-written JS/CSS · 41,614 LOC tests

### Delivered

Beacon went from a working-but-accreted Raspberry Pi dashboard into one whose claims are
verifiable. It now protects existing behaviour and data behind versioned transactional
migrations with real backup and recovery; gives all shared scheduled work a single durable
worker owner with transaction-local fencing; keeps a bounded, truthful rolling 90-day
telemetry record that distinguishes observed values from unknown intervals, collection gaps
and retention expiry; serves a GET-only advanced workspace for current diagnosis and
historical investigation across both themes at parity; recognises confirmed maintenance
windows without ever hiding a real outage; and can be run with advanced diagnostics switched
off entirely, at measured equal cost, on a host already monitored elsewhere.

### Key accomplishments

1. **Behavioural safety and single-owner runtime** (Phase 1, 8/8 verified, 23 plans) — the web
   application starts no background work at import; the worker holds an opaque per-acquisition
   epoch that fences every scan and preview write; lease loss stops admission and drains active
   work before Chromium cleanup. Versioned transactional migrations, verified SQLite snapshots
   with three-backup retention, and a catalog-constrained restore CLI behind an isolated Compose
   recovery service. One tested outbound policy pins every approved HTTP and Chromium origin to
   a numeric address while preserving HTTP authority, TLS SNI and certificate identity.

2. **Bounded, truthful 90-day telemetry** (Phase 2, 4/4 verified, 12 plans) — tiered rollups that
   complete and are verified before their source observations are deleted, per-metric stream
   identity shared between writer and reader, storage-pressure handling, bounded retry deadlines,
   and historical APIs that select a server-side resolution under an explicit point budget and
   never interpolate across a gap.

3. **Advanced current diagnosis, and the labelling discipline behind it** (Phase 3, 5/5 verified
   over nine rounds, 23 plans) — a GET-only `/advanced` workspace serving host, per-service,
   effective-settings and collection-health evidence. Its real cost was gap closure, and its real
   output was a convention: every operator-facing `open` / `actionable` / `kind` / count is
   derived from the durable row it describes, and an unestablished value renders as unknown
   rather than as a plausible number.

4. **Planned maintenance recognition** (Phase 03.1, 9/9 verified, 18 plans) — a candidate window
   suggested after three similar daily restart outages that stays inactive until confirmed;
   during a confirmed window every failed probe is retained and downtime still counts, with only
   the expected event entries suppressed; an overrun past the grace period produces one truthful
   outage. Reopened mid-phase when human UAT found migration 9 could not apply to any existing
   deployment — the milestone's clearest lesson about rehearsing upgrades.

5. **Historical investigation and theme parity** (Phases 4 and 5, 6/6 and 5/5 verified, 18 plans)
   — metric history with units, thresholds and visible gaps; time-weighted availability; incident
   and transition filtering that cannot hide a silently-down service's open episode; and full
   capability parity across light and dark at supported narrow and desktop widths, with status
   and chart information reachable through text and keyboard rather than colour alone.

6. **Pi-class workload resilience, measured honestly** (Phase 6, 5/5 verified with 1 override,
   30 of 32 plans) — sampling cadence held while discovery, previews, cleanup and analytics run;
   serialized browser ownership with bounded deadlines and a non-fatal degraded state. Seven
   remediation rounds on `/api/services`, every one profiled and recorded including the two that
   made things worse and were reverted. The phase's transferable finding: moving work out of a
   global lock moved per-request cost 45.07% and the concurrency-3 p95 only 2.5%, because the
   released work then competed for the GIL instead of queueing behind the lock.

7. **Optional advanced diagnostics** (Phase 7, 5/5 verified, all mutation-confirmed, 3 plans) —
   `ENABLE_ADVANCED_DIAGNOSTICS` wired from environment through Settings to a handler-first-
   statement gate on all four owned routes, with the front-page entry point excised server-side.
   Criterion 3 closed as a measured equality of SQLite statement and connection counts off vs on
   across the front page's whole boot request set; criterion 5 as a restart round trip
   (`iterdump` sha256 and schema version unchanged, then the enabled golden recovered).

### Known Gaps

Closed as `override_closeout`. 30 open items were surfaced by the pre-close artifact audit,
acknowledged by the operator, and recorded in `STATE.md` under `## Deferred Items`.

**Requirements: 45 of 46 Complete.**

- `OPS-07` — **Accepted with deviation, not Complete.** A Pi-class acceptance run passes on
  cadence, resources, recovery and sampling continuity. `/api/services` misses its 500 ms p95
  on three independent hardware runs (635.6 / 679.3 / 662.3 ms) under a closed-loop harness at
  ~34.5× the deployment's real per-route rate; at the actual 0.067 req/s it measures 77.1 ms.
  Accepted on usage grounds. No budget, criterion, assertion or harness default was moved —
  `PROH-OPS-07-01` and `-10` were verified intact and `ROUTE_BUDGETS_MS` is byte-identical to
  its introduction. `PROH-OPS-07-08` reserves promotion to a future independent round. The three
  failing runs stand unsuperseded on the record. Revisit if the real request rate rises or
  services are added — `D-DEBT-06-27`.

**Verification overrides: 2 phases did not reach `passed`.**

- Phase 6 — `06-VERIFICATION.md` is `human_needed`, 5/5 with 1 override. Residual: the
  concurrency-1 HTTP control run on build `a7c3ef1`, which would replace the acceptance's one
  inferential step (an in-process cProfile at 77.1 ms) with a direct measurement. Not a
  condition of the override.
- Phase 7 — `07-VERIFICATION.md` is `gaps_found`, 5/5 all mutation-confirmed. Gap 1 (DIA-09
  scope) closed by operator amendment `D-07-10`. Gap 2 is open and recorded: a per-service
  `environment:` block in `docker-compose.yml` takes precedence over the merged anchor, so
  `PROH-DIA-09-01`'s guard can be evaded on the actual web container while both guard tests
  still pass. Found by mutation M8.

**Technical debt carried forward:** `D-DEBT-06-27` (concurrency-3 contention, unattributed),
`D-DEBT-06-16` (non-`api_services` sites holding non-database work under `_db_lock`),
`D-DEBT-06-11` (offline-interval row cap bounding `maintenance_attributed_seconds`),
`D-DEBT-07-01` (acceptance harness records `elapsed_ms` but never `status_code`, so a 404
reads as a budget-clearing success), the `diagnosis.py:448` `resolution_policy` literal
duplicating `telemetry.py`'s ten-step ladder, `tests/helpers.py::load_app` leaking `extra_env`
into `os.environ`, and seventeen carried-forward `03-REVIEW.md` round-1 findings.

**Archived:** `milestones/v1.0-ROADMAP.md` · `milestones/v1.0-REQUIREMENTS.md` ·
`milestones/v1.0-MILESTONE-AUDIT.md` · `milestones/v1.0-phases/`

---
