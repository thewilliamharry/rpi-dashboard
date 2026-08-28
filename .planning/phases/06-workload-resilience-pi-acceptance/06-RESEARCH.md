# Phase 6: Workload Resilience & Pi Acceptance - Research

**Researched:** 2026-08-28
**Domain:** Scheduler contention management, browser-automation resource governance, SQLite concurrency (WAL/locking), bounded blob storage, Raspberry Pi load acceptance testing
**Confidence:** HIGH (all findings grounded in the current codebase, read this session; no CONTEXT.md exists, so this document carries full design latitude per the roadmap goal and success criteria)

## Summary

Beacon already has more of OPS-01/OPS-02's foundation in place than the phase description implies. The worker (`dashboard/beacon/worker_main.py`) is a single `APScheduler` `BlockingScheduler` with **four named `ThreadPoolExecutor` lanes** (`default`, `metrics`, `probes`, `screenshots`) and `job_defaults={'coalesce': True, 'max_instances': 1, 'misfire_grace_time': 15}` — this is already priority-lane scheduling, not a monolithic queue. Preview capture already has a single process-local browser owner (`dashboard/app.py` `_legacy_get_browser`/`_get_browser`, guarded by `_browser_lock`), a bounded 27-second capture deadline (`PREVIEW_BROWSER_BUDGET_MS = 27_000`), and a `threading.Semaphore(1)` (`_screenshot_sem`) that serializes capture even though the `screenshots` executor already has exactly one thread — so OPS-02's "one serialized browser owner" and "bounded deadlines" already exist. What is genuinely missing for OPS-02 is a **bounded retry-with-backoff policy** (today a failed preview capture simply goes terminal and is not retried until the next daily discovery cycle re-enqueues it, ~24h later) and a **visible non-fatal degraded UI state** (today a failed thumbnail renders the same generic "NO PREVIEW" fallback as a thumbnail that was simply never requested — `dashboard/app.js:231-237`).

Two concrete, evidence-backed contention risks exist that the phase must address for OPS-01: (1) the worker's `J1` heartbeat (5s cadence), `J2` metric sampling (5s default cadence), **and** `J8` hourly cleanup **all share the single-thread `metrics` executor** (`worker_main.py:79-95`), so a slow cleanup pass can delay the heartbeat and metric-sampling cadence that everything else's freshness classification depends on; (2) SQLite is **never put into WAL mode anywhere in the codebase** — `PROJECT.md` explicitly flags "the WAL decision" as deferred to Phase 6 (`.planning/PROJECT.md:60`) — so today's only concurrency mechanisms are a custom `flock`-based sibling lease (`dashboard/beacon/db.py`) plus `PRAGMA busy_timeout=30000`, and the web process additionally serializes **all** of its own DB access behind one process-global `threading.Lock()` (`dashboard/app.py:115` `_db_lock`, used at 25+ call sites) because gunicorn runs `--workers 1 --threads 8`.

OPS-03's target is unambiguous: `thumb_data BLOB` lives directly on the `services` table (`migrations.py:154`, `_migration_2_service_diagnostics`) — Beacon's primary service/telemetry identity table — with no TTL/eviction, only an opportunistic overwrite-on-next-successful-capture. This phase must move thumbnails to a separate, size-bounded, TTL-expiring store and migrate/backfill existing blobs out of `services`.

For OPS-04/OPS-07, Beacon already has strong raw material to build on: a `background_job_health` durable table recording per-job start/success/failure state (`repositories.py:26-73`), a codebase-wide `freshness_state` classifier that already defines "accepted cadence" precisely (`fresh` ≤ 1× cadence, `aging` ≤ 4× cadence, else `stale` — `dashboard/beacon/diagnosis.py:101-118`), and Docker Compose resource ceilings already declared (`worker` `mem_limit: 1g`, `web` `mem_limit: 256m`, no CPU limit set — `docker-compose.yml`). The Pi-acceptance run (OPS-07) should reuse these existing evidence surfaces as its pass/fail oracle rather than inventing new thresholds.

**Primary recommendation:** Extend the existing executor-lane pattern (don't replace it) — split cleanup onto its own lane, keep heartbeat+metrics isolated from best-effort work, add an explicit bounded preview retry/backoff policy on top of the existing single-owner browser and deadline machinery, relocate thumbnails to a new bounded/TTL'd table with a migration that empties `services.thumb_data`, decide and implement the deferred WAL-mode question explicitly (with an accompanying `_db_lock`/read-during-write reconsideration), and build the Pi-acceptance run as an automated, repo-checked-in load harness that asserts against the existing `freshness_state` and `background_job_health` evidence rather than a manual checklist.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| OPS-01 | Metric sampling and service checks continue within their accepted cadence while discovery, previews, cleanup, and analytics queries are active. | Architecture Patterns §1 (executor lanes), Common Pitfalls §1 (shared `metrics` executor), Validation Architecture (freshness-state-based cadence assertions) |
| OPS-02 | Preview work uses serialized browser ownership, bounded deadlines and retries, and a visible non-fatal degraded state. | Architecture Patterns §2 (browser ownership — already exists), Common Pitfalls §2/§3 (no bounded retry, no degraded UI state), Code Examples §2 |
| OPS-03 | Thumbnail storage and expiry remain bounded without placing large preview blobs in the primary telemetry path. | Architecture Patterns §3 (bounded thumbnail store), Runtime State Inventory, Code Examples §3 |
| OPS-04 | Automated tests cover migrations, restart recovery, concurrent web/worker database access, scheduler ownership, and failed background jobs. | Architecture Patterns §4 (SQLite concurrency model), Validation Architecture, Don't Hand-Roll |
| OPS-07 | A Raspberry Pi-class acceptance run verifies responsiveness, resource budgets, recovery, and sampling continuity under representative load. | Environment Availability, Validation Architecture, Architecture Patterns §5 |
</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Scheduler cadence / executor lanes | Worker (background process) | — | `worker_main.py` `build_scheduler` is the sole scheduler owner (FND-04, already locked); no web-tier involvement |
| Browser ownership & preview capture | Worker (background process) | — | `_get_browser`/`_screenshot_sem` are worker-process-local singletons; J6 is the only caller |
| Thumbnail storage & expiry | Database / Storage | Worker (writer), API/Backend (reader via `/api/thumbnail/<port>`) | Storage location and TTL are a schema/persistence concern; the worker writes, the web tier serves bytes |
| SQLite concurrency (WAL, locking, `_db_lock`) | Database / Storage | API/Backend (web `_db_lock`), Worker (write transactions) | Concurrency policy is a storage-layer decision that both processes must honor identically |
| Restart / recovery correctness | Worker (background process) | Database / Storage | `worker_main.run_worker` startup ordering and `recovery.py` own this; DB is the durable state they recover from |
| Pi-class load acceptance | Ops / Test tooling (new) | All tiers (assertions read worker, API, DB evidence) | A new harness that exercises every tier under load and reads back their own durable evidence — not a new architectural tier itself |

## Standard Stack

### Core (already in use — reuse, do not replace)

| Library | Version (pinned in `dashboard/pyproject.toml`, verified by `Read` this session) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| APScheduler | `==3.11.3` [VERIFIED: dashboard/pyproject.toml] | Worker job scheduling, multi-executor lanes | Already the sole scheduler (FND-04); `BlockingScheduler` + named `ThreadPoolExecutor`s already implement priority-lane scheduling — extending executor assignment is strictly additive, no new library needed |
| playwright | `==1.61.0` [VERIFIED: dashboard/pyproject.toml] | Chromium preview capture | Already the sole browser-automation library (`dashboard/app.py` `_legacy_get_browser`); single-owner + policy-proxy pattern is already built |
| psutil | `==7.2.2` [VERIFIED: dashboard/pyproject.toml] | Host/process resource stats | Already used for `collect_system_stats`; reusable for the Pi-acceptance harness's own RSS/CPU assertions without adding a dependency |
| Flask | `==3.1.3` [VERIFIED: dashboard/pyproject.toml] | Web tier | Unchanged this phase |
| gunicorn | `==26.0.0` [VERIFIED: dashboard/pyproject.toml] | WSGI server, `--workers 1 --threads 8` [VERIFIED: dashboard/Dockerfile:27] | Unchanged this phase; the `1 worker / 8 threads` model is *why* `_db_lock` exists in-process |
| sqlite3 (Python stdlib) | Bundled with `python:3.12-slim-bookworm` [VERIFIED: dashboard/Dockerfile:1] | Persistence | No new dependency; WAL mode and busy-timeout tuning are `PRAGMA` statements against the existing driver, not a new package |
| pytest | `>=9.0.2,<10` [VERIFIED: dashboard/pyproject.toml] | Test framework | Unchanged; used for the new resilience/load regression suite |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| (none new) | — | — | This phase is deliberately implementable entirely with the existing pinned dependency set: `ThreadPoolExecutor` lane reassignment, SQLite `PRAGMA` tuning, a new table + cleanup job for thumbnails, and a `psutil`/`requests`-based load harness are all achievable without adding a package. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Extending APScheduler's existing executor lanes | Replacing APScheduler with Celery/RQ + Redis broker | Adds a broker process, contradicts the "self-contained, single SQLite, no external backend" constraint (`PROJECT.md` Constraints: "Deployment ... Docker Compose"), and the existing scheduler already has the lane primitive needed — not a hand-roll problem to solve with a bigger tool |
| SQLite WAL mode + `busy_timeout` tuning | PostgreSQL or another server DB | Contradicts "self-contained on a 64-bit Raspberry Pi" and "SQLite persistence" constraints explicit in `PROJECT.md`/`ROADMAP.md` Overview; out of scope |
| A dedicated blob-cleanup table + cron-style TTL job | An object-store / filesystem cache for thumbnails | Filesystem storage is plausible (see Architecture Patterns §3) but reintroduces the "filesystem publication" effect surface the `WORKER_CALLBACK_INVENTORY` deliberately keeps empty today (`worker_main.py:80`, `('filesystem_publication',)` currently unused for previews — `PROJECT.md` Key Decisions: "Keep filesystem publication explicit with an empty current producer set because preview bytes remain SQLite BLOBs"); a bounded SQLite table with its own TTL/eviction is the smaller, already-precedented change |
| A locust/k6-style load-testing tool for OPS-07 | New load-testing dependency | Beacon's existing stack (`requests`, `threading`, `psutil`, `pytest`) is sufficient to build a repeatable load harness in-repo; adding a new tool for one phase increases the dependency surface for no capability the stdlib/`requests` combination lacks |

**Installation:** None. No new packages this phase.

**Version verification:** All versions above were read directly from `dashboard/pyproject.toml` and `dashboard/Dockerfile` this session (`[VERIFIED]`), not looked up externally — these are exact-pinned in-repo facts, not registry queries.

## Package Legitimacy Audit

**No new external packages are introduced by this phase.** Every recommendation below reuses libraries already pinned in `dashboard/pyproject.toml` (APScheduler, playwright, psutil, Flask, gunicorn) or Python's stdlib (`sqlite3`, `threading`, `time`). The Package Legitimacy Gate protocol therefore does not apply — there is nothing to check against the npm/PyPI registry.

If the planner or a plan check identifies a need for a new package during planning (e.g., a load-generation helper), run `gsd_run query package-legitimacy check --ecosystem pypi <pkg>` before adding it to any plan, per the standard protocol.

**Packages removed due to [SLOP] verdict:** none — no new packages evaluated.
**Packages flagged as suspicious [SUS]:** none.

## Architecture Patterns

### System Architecture Diagram

```
                         ┌─────────────────────────────────────────────┐
                         │            gunicorn (web, 1 proc/8 thr)       │
   Browser  ──HTTP──────►│  dashboard/app.py routes                     │
                         │    _db_lock (proc-global) ──► database_access │
                         └───────────────────┬───────────────────────────┘
                                             │ shared SQLite file
                                             │ (flock sibling-lease +
                                             │  PRAGMA busy_timeout=30000;
                                             │  journal_mode: UNSET today)
                                             ▼
   ┌───────────────────────────── worker.py (1 process) ─────────────────────────────┐
   │  BlockingScheduler (UTC)                                                         │
   │                                                                                   │
   │  executor 'metrics' (1 thread) ── J1 heartbeat(5s) ─┐                            │
   │                                 ── J2 metric sample(5s)├─ SHARED THREAD (risk)    │
   │                                 ── J8 cleanup(1h) ───┘                            │
   │                                                                                   │
   │  executor 'probes' (2 threads) ── J3 uptime_all(5m)                              │
   │                                 ── J4 uptime_down(1m)                            │
   │                                 ── J5 scan_requests poll(2s)                     │
   │                                 ── J7 scheduled_discovery(24h, ≤180s budget)      │
   │                                 ── J9 startup_discovery(one-shot)                │
   │                                                                                   │
   │  executor 'screenshots' (1 thread) ── J6 preview_requests poll(2s)               │
   │        └─► _screenshot_sem(1) ──► _get_browser() (single Chromium owner)         │
   │              deadline: PREVIEW_BROWSER_BUDGET_MS=27_000                          │
   │              on failure: thumb_error stored, NO bounded retry today (gap)        │
   │                                                                                   │
   │  every dispatch ──► dispatch_callback() ──► background_job_health (durable)      │
   └───────────────────────────────────────────────────────────────────────────────────┘
                                             │
                                             ▼
                        services.thumb_data BLOB (on primary table — OPS-03 target)
```

### Recommended Project Structure

No new top-level modules are required; extend existing files along their existing boundaries:

```
dashboard/beacon/
├── worker_main.py     # executor/lane reassignment (J8 off 'metrics'; new retry policy wiring for J6)
├── queues.py          # preview retry/backoff bookkeeping (extend attempt_count semantics)
├── db.py              # WAL-mode PRAGMA decision, connection tuning
├── migrations.py      # new bounded thumbnail table + backfill/empty-services migration
├── repositories.py    # new thumbnail-store repository (separate from services table access)
└── diagnosis.py       # (read-only) reuse freshness_state for the new preview-degraded surface
tests/
└── test_workload_resilience.py   # new: cadence-under-contention, retry/backoff, WAL/concurrency regressions
scripts/ or tests/
└── pi_load_acceptance.py         # new: repeatable, checked-in Pi-class load harness (OPS-07)
```

### Pattern 1: Executor-lane separation for scheduler cadence (OPS-01)

**What:** APScheduler's `BlockingScheduler` already accepts a dict of named `ThreadPoolExecutor`s, and each `WorkerCallback` in `WORKER_CALLBACK_INVENTORY` already declares an `executor` field. The pattern is fully in place — only the *lane assignment* needs to change.

**What is verified today** [VERIFIED: dashboard/beacon/worker_main.py:79-95, 457-483]:
```python
# worker_main.py:79-95 (WORKER_CALLBACK_INVENTORY, quoted verbatim)
WorkerCallback('J1', ('update_worker_heartbeat', 'renew_worker_lease'), 'heartbeat', 'scheduled', ('worker_owner', 'worker_heartbeat'), ('browser_resource_lifecycle',), scheduler_id='heartbeat', trigger='interval', trigger_kwargs=(('seconds', 5),), executor='metrics'),
WorkerCallback('J2', ('collect_system_stats',), 'metrics', 'scheduled', ('system_stats', 'stats_history', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'), (), scheduler_id='metrics', trigger='interval', trigger_kwargs=(('seconds', None),), executor='metrics', misfire_grace_time=10),
WorkerCallback('J8', ('cleanup_history',), 'cleanup', 'scheduled', (...), (), scheduler_id='cleanup', trigger='interval', trigger_kwargs=(('hours', 1),), executor='metrics', misfire_grace_time=300),
```
```python
# worker_main.py:457-462 (build_scheduler executors, quoted verbatim)
executors = {
    'default': ThreadPoolExecutor(1),
    'metrics': ThreadPoolExecutor(1),
    'probes': ThreadPoolExecutor(2),
    'screenshots': ThreadPoolExecutor(1),
}
job_defaults = {
    'coalesce': True,
    'max_instances': 1,
    'misfire_grace_time': 15,
}
```

**When to use:** J1 (heartbeat) and J2 (metric sampling) are exactly the two things OPS-01 names as essential and must stay isolated from best-effort work (discovery, previews, cleanup, analytics). J8 (cleanup) is explicitly grouped with the essential lane today via `executor='metrics'` and is exactly the kind of bounded-but-potentially-slow batch operation (rollups, `telemetry_rollup_batch_buckets=32` per Settings default) that OPS-01 requires NOT to compete with essential sampling.

**Recommended change:** Add a dedicated `'cleanup'` executor (1 thread) and move J8 onto it, leaving `'metrics'` exclusively for J1+J2 (both fast, bounded, essential). Evaluate — with the Pi-acceptance load run as the oracle — whether J5's 2-second queue-drain poll should also move off the shared `'probes'` lane so a long-running J7/J9 discovery (up to `discovery_timeout_seconds=180` [VERIFIED: dashboard/beacon/config.py:34, `discovery_timeout_seconds: int = 180`]) cannot delay J3/J4 service-check cadence beyond their `misfire_grace_time` (60s/30s respectively [VERIFIED: dashboard/beacon/worker_main.py:86-87]).

### Pattern 2: Single-owner, bounded-deadline browser capture (OPS-02 — mostly already exists)

**What is verified today** [VERIFIED: dashboard/app.py:118, 1006-1090, 733-780]:
```python
# app.py:65-68, 118 (constants, quoted verbatim)
THUMB_MAX_BYTES = 2 * 1024 * 1024
PREVIEW_SETTLE_MS = 5_000
PREVIEW_BROWSER_BUDGET_MS = 27_000
...
_screenshot_sem = threading.Semaphore(1)
```
The browser itself is a lazily-launched, connectivity-checked module-level singleton guarded by `_browser_lock` (`app.py:120-780`), and `screenshot_service` acquires `_screenshot_sem` before touching Chromium and releases it in a `finally` (`app.py:1021-1089`). A dedicated sentinel (`THUMB_ERROR_BROWSER_UNAVAILABLE`) already distinguishes a total machinery failure (browser can't launch / can't open a page) from an ordinary per-service capture failure — the machinery failure is raised as `PreviewCaptureUnavailable` and recorded as a genuine `job_failed` for J6, while a per-service failure is stored as `thumb_error` text and the job itself still reports success (`worker_process_preview_requests`, `app.py:2227-2281`; class docstring `PreviewCaptureUnavailable`, `dashboard/beacon/previews.py:20-35`).

**What is missing (the actual OPS-02 gap):**
1. **Bounded retry with backoff.** `finish_preview_in_transaction` marks a failed capture terminal (`status='failed'`) with no automated re-attempt [VERIFIED: dashboard/beacon/queues.py:700-725]. `attempt_count` is incremented on every claim (`queues.py:657`) but nothing reads or caps it — it is bookkeeping, not a retry gate. The only thing that re-triggers a failed preview today is the next discovery cycle's `THUMB_REFRESH_DAYS`-driven re-enqueue (`app.py:1343`, default 1 day) or a manual operator action (edit/scan) — not a bounded, fast retry loop. This must be built: e.g., a small number of attempts (2-3) with short backoff before the request goes to a genuinely terminal "degraded" state distinct from "never attempted."
2. **Visible non-fatal degraded UI state.** The dashboard's thumbnail fallback (`dashboard/app.js:229-237`) renders the identical generic "NO PREVIEW" badge whether a service has never been scanned or its capture has been failing repeatedly — `thumb_error`/`thumb_attempt_ts` are already exposed via `GET /api/thumbnail-status` (`app.py:2990-3012`) but nothing in `app.js` reads that endpoint or renders a distinct state. Phase 5 already established a six-state visibility vocabulary (loading/empty/stale/unknown/degraded/error) for exactly this kind of distinction (UX-06/UX-07, validated) — reuse that established pattern rather than inventing a new one for previews.

**When to use:** Keep the existing single-owner/semaphore/deadline machinery as-is (it is correct and tested); add the retry-count/backoff policy at the `preview_requests` queue layer (`queues.py`) and add a degraded-state read at the dashboard layer consuming `/api/thumbnail-status` (or a new small endpoint that classifies per Phase 5's vocabulary).

### Pattern 3: Bounded, TTL'd thumbnail store off the primary telemetry path (OPS-03)

**What is verified today** [VERIFIED: dashboard/beacon/migrations.py:111-114, 152-158; dashboard/beacon/repositories.py:710-726; dashboard/app.py:2973-2987]:
```python
# migrations.py:111-114 (services table baseline, quoted verbatim)
CREATE TABLE IF NOT EXISTS services (
    port INTEGER PRIMARY KEY, title TEXT, first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL, is_online INTEGER DEFAULT 1
);
```
```python
# migrations.py:152-158 (_migration_2_service_diagnostics, quoted verbatim)
for column in (
    'thumb_data BLOB', 'thumb_mime TEXT DEFAULT \'image/jpeg\'', 'thumb_ts INTEGER',
    'thumb_source TEXT', 'thumb_attempt_ts INTEGER', 'thumb_error TEXT',
    'last_latency_ms REAL', 'last_error TEXT', 'state_since INTEGER',
):
    _add_column(conn, 'services', column)
```
`services` is the row every scheduled sampling job (J3, J4, J5, discovery) reads and writes for basic online/offline state — this is squarely "the primary telemetry path" OPS-03 names. `ThumbnailResultRepository.store_thumbnail_result` (`repositories.py:710-726`) writes directly to these columns, and `api_thumbnail` (`app.py:2973-2987`) reads `thumb_data`/`thumb_mime` straight off `services` with no size cap enforcement at read time (only a 2 MiB cap enforced at capture time, `THUMB_MAX_BYTES`) and **no expiry** — a captured thumbnail is retained forever until overwritten by a newer successful capture.

**Recommended change:** Add a new table (e.g. `thumbnails(port INTEGER PRIMARY KEY, data BLOB, mime TEXT, captured_ts INTEGER, source TEXT, expires_ts INTEGER)`) via a new migration, with `services.thumb_data`/`thumb_mime` emptied (`UPDATE services SET thumb_data=NULL, thumb_mime=NULL`) once the new table is backfilled — following the exact precedent `_migration_3_metadata_and_state` already used for a similar `thumb_source='fallback'` cleanup (`migrations.py:165-168`). Bound total size (e.g., cap enforced at write time, already partially done via `THUMB_MAX_BYTES`) and add expiry (TTL from `captured_ts`, reaped by a new or extended J8-style cleanup pass) so the store cannot grow unbounded even if a service is never rescanned. Keep the blob **on-disk-adjacent-to-SQLite but in its own table**, not in `services` — `PROJECT.md`'s locked Key Decision explicitly keeps preview bytes as SQLite BLOBs rather than filesystem-published files ("Keep filesystem publication explicit with an empty current producer set because preview bytes remain SQLite BLOBs" — `.planning/STATE.md` Decisions log), so a separate table (not a separate filesystem store) is the decision-compatible fix.

### Pattern 4: SQLite concurrency — the deferred WAL decision (OPS-04)

**What is verified today** [VERIFIED: dashboard/beacon/db.py:74-89; dashboard/app.py:115]:
```python
# db.py:74-89 (connect_db, quoted verbatim — no journal_mode PRAGMA anywhere in the codebase)
def connect_db(settings_or_path):
    """Open a configured SQLite connection while holding a shared access lease."""
    handle = _acquire_lock(maintenance_lock_path(settings_or_path), fcntl.LOCK_SH, 30)
    try:
        conn = sqlite3.connect(
            _db_path(settings_or_path), timeout=30, factory=ManagedConnection,
        )
        conn._set_maintenance_handle(handle)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn
```
```python
# app.py:115 (quoted verbatim)
_db_lock = threading.Lock()
```
A repo-wide grep this session confirmed `journal_mode` appears only where it is *read* (`inventory.py:134`, `telemetry.py`, diagnostic reporting) — never *set*. `PROJECT.md:60` explicitly records this as an open, deferred decision: *"api_advanced_current does not take the process-global _db_lock (recorded as accepted risk AR-03-01 in 03-SECURITY.md) ... Flagged for revisit in Phase 6 alongside the WAL decision."* Today's only concurrency guarantees are: (1) a custom `flock`-based sibling-lease (`db.py` `_acquire_lock`/`ManagedConnection`) that lets many "ordinary" connections share access but excludes them all during `exclusive_database_maintenance` (migrations/restore); (2) SQLite's own `busy_timeout=30000`; (3) inside the web process specifically, a single Python `threading.Lock()` (`_db_lock`) serializing all 8 gunicorn threads' DB access, because gunicorn runs `--workers 1 --threads 8` [VERIFIED: dashboard/Dockerfile:27].

**When to use:** This phase must make the WAL decision explicit rather than leave it implicit. Enabling `PRAGMA journal_mode=WAL` (a one-time, persistent-in-the-file-header change) would let readers proceed without blocking on a writer — directly relevant to OPS-01's "analytics queries active" clause and to the `AR-03-01` accepted-risk note about `api_advanced_current` skipping `_db_lock`. Recommended: enable WAL explicitly in `connect_db` (idempotent `PRAGMA journal_mode=WAL` — safe to issue on every connection), keep the `flock` sibling-lease as-is (it protects the *maintenance* exclusion, not ordinary read/write concurrency, and is orthogonal to journal mode), and re-evaluate whether `_db_lock`'s full serialization is still necessary once WAL is active and reads no longer block behind writes — but treat any relaxation of `_db_lock` as its own carefully-tested change given `AR-03-01`'s prior reasoning, not a free side effect of the WAL switch.

### Pattern 5: Reuse the existing job-health and freshness evidence for Pi acceptance (OPS-07)

**What is verified today** [VERIFIED: dashboard/beacon/diagnosis.py:101-118; dashboard/beacon/repositories.py:26-73]:
```python
# diagnosis.py:101-118 (freshness_state, quoted verbatim — the codebase's own definition of "accepted cadence")
def freshness_state(now, sample_ts, cadence_seconds):
    """Classify durable sampling evidence without inferring its cause."""
    if (
        type(now) is not int
        or type(sample_ts) is not int
        or type(cadence_seconds) is not int
        or cadence_seconds <= 0
    ):
        return {'state': 'unknown', 'age_seconds': None}

    age_seconds = max(0, now - sample_ts)
    if age_seconds <= cadence_seconds:
        state = 'fresh'
    elif age_seconds <= 4 * cadence_seconds:
        state = 'aging'
    else:
        state = 'stale'
    return {'state': state, 'age_seconds': age_seconds}
```
This is already the shared, tested classifier every freshness surface in the product uses (worker heartbeat, host metrics, telemetry streams). `background_job_health` (`migrations.py:521-534`, `repositories.py:26-73`) already durably records `last_started_ts`/`last_finished_ts`/`last_success_ts`/`state`/`error_class` per job ID. Docker Compose already declares resource ceilings the acceptance run must respect: `worker: mem_limit: 1g` (Chromium's real memory user), `web: mem_limit: 256m`, `recovery`/`migrate`: `256m` each [VERIFIED: docker-compose.yml] — **no CPU limit is currently set anywhere**, which the phase should either add (`cpus:` in compose) or explicitly decide is out of scope and document why.

**When to use:** Build the OPS-07 acceptance harness to (a) generate representative concurrent load (discovery + preview churn + analytics queries against `/api/history/*`/`/api/advanced/*`), (b) sample `system_stats`/`background_job_health` and the process's own RSS/CPU via `psutil` throughout the run, and (c) assert pass/fail using `freshness_state`'s existing `fresh`/`aging`/`stale` boundaries against J1/J2/J3/J4's own cadences — rather than picking new, unrelated numeric thresholds. This makes the acceptance run's oracle traceable to code the product already trusts and tests, satisfying "automated runtime and persistence coverage" (OPS-04) at the same time.

### Anti-Patterns to Avoid

- **Introducing a message broker or a second scheduler library:** APScheduler's executor-lane primitive already solves the priority-lane problem; reaching for Celery/RQ/Redis would violate the "self-contained on a Raspberry Pi... Docker Compose" constraint and duplicate a solved problem.
- **Storing thumbnails on the filesystem instead of a bounded table:** contradicts the locked decision keeping preview bytes as SQLite BLOBs with an empty filesystem-publication effect surface; also reopens container `read_only: true`/`tmpfs` considerations already tuned around SQLite-only persistence (`docker-compose.yml` `read_only: true`, `tmpfs: /tmp`).
- **Widening `_db_lock` scope or removing it opportunistically while "fixing" WAL:** `AR-03-01` was an explicit, reasoned accepted risk about *narrowing* lock scope for one read-only route; broadening the same reasoning to remove `_db_lock` everywhere without re-verifying every route's assumptions would be a regression, not resilience work.
- **Treating `attempt_count` as an existing retry cap:** it is incremented on every claim today but nothing reads it as a limit (`queues.py:657`) — do not assume retry bounding exists; it must be built.
- **Asserting new, unrelated cadence thresholds for the Pi-acceptance run:** the codebase already has a tested, shared `freshness_state` definition of acceptable staleness; inventing parallel thresholds creates two conventions for the same concept (a pattern this codebase has explicitly refactored away from before — see `.planning/STATE.md` Phase 03 decisions on `freshness_state`'s "one convention" discipline).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Priority/lane-based job scheduling | A custom priority queue or second scheduler | APScheduler's existing named `ThreadPoolExecutor`s + `WorkerCallback.executor` field | Already built, already tested (`test_worker_ownership_matrix.py`); only lane *assignment* needs to change |
| Single-owner browser lifecycle | A new browser-pool/session manager | The existing `_browser_lock`/`_get_browser`/`_screenshot_sem` singleton pattern | Already correct; adding a second ownership mechanism would create two competing sources of truth for "who owns Chromium" |
| Freshness/staleness classification | A new "is this preview data fresh?" threshold scheme | `dashboard/beacon/diagnosis.py`'s `freshness_state` (fresh/aging/stale, 1×/4× cadence) | One shared convention already exists and is exercised across host, worker, and telemetry-stream freshness; a second convention for previews/Pi-load would fragment the product's own truthfulness discipline that Phases 3-4 spent many gap-closure rounds establishing |
| Per-job durable health bookkeeping | A new job-status table for the load harness | `background_job_health` (`repositories.py:26-73`) | Already records start/success/failure/error-class per job ID; the acceptance run should read this, not duplicate it |
| Bounded blob storage with expiry | A hand-rolled file cache with manual LRU | A new SQLite table with `expires_ts`/size cap, reaped by a scheduled job (same pattern as `cleanup_history`/J8) | SQLite already handles the durability/atomicity Beacon needs; a filesystem LRU cache would need its own crash-recovery story that SQLite transactions already give for free |

**Key insight:** Every one of this phase's five success criteria has a close structural precedent already built and tested somewhere else in Beacon (executor lanes, single-owner resources, freshness classification, durable job health, transactional bounded storage). The work is extension and gap-closure, not new-pattern invention — treating it as new-pattern invention risks fragmenting conventions this codebase has already paid (in gap-closure rounds, per `.planning/STATE.md`) to unify.

## Runtime State Inventory

> Included because OPS-03 requires relocating `thumb_data` off the primary `services` table — a data migration, triggering this protocol.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | `services.thumb_data`/`thumb_mime`/`thumb_ts`/`thumb_source`/`thumb_attempt_ts`/`thumb_error` columns hold existing captured thumbnail blobs for every currently-tracked service [VERIFIED: dashboard/beacon/migrations.py:152-158] | **Data migration required**: new migration must backfill existing non-NULL `thumb_data` rows into the new bounded table before emptying the `services` columns, following the exact `_migration_3_metadata_and_state` precedent that already did a narrower cleanup of these same columns (`migrations.py:163-168`) |
| Live service config | None found outside git — Beacon has no external service (n8n-style) with UI-only config; all runtime configuration is either `docker-compose.yml` environment variables (in git) or DB rows covered above | None |
| OS-registered state | None — Beacon has no OS-level task registration (no cron/launchd/systemd units created by the app itself); Docker Compose `healthcheck` entries are declarative and in git | None |
| Secrets/env vars | No new secret or env var is introduced by this phase's recommended changes (WAL is a `PRAGMA`, not a config toggle requiring a new env var, though the planner may choose to expose one, e.g., `THUMBNAIL_TTL_DAYS` alongside the existing `THUMB_REFRESH_DAYS` convention in `config.py`) | None required; optional new env var if planner adds a configurable TTL |
| Build artifacts | None found — no compiled/installed artifact caches the old `services.thumb_data` schema shape; `dashboard/.venv` is a local dev artifact unrelated to this migration | None |

**Nothing found in "Live service config," "OS-registered state," or "Build artifacts":** confirmed by grep across `dashboard/`, `docker-compose.yml`, and `dashboard/Dockerfile` this session — Beacon's only durable state is the single SQLite file plus the container filesystem's `-wal`/`-shm` sidecars, both already covered by the existing migration/recovery machinery.

## Common Pitfalls

### Pitfall 1: Assuming cadence is already protected because executors already exist
**What goes wrong:** A plan that "adds priority lanes" without first reading `WORKER_CALLBACK_INVENTORY`'s actual `executor` assignments risks re-implementing something that's already 80% present, or worse, missing that J1/J2/J8 already share one thread.
**Why it happens:** The roadmap phase description reads as if lane separation must be built from scratch; it must not be — it must be extended and corrected in three specific places (J8 off `metrics`; verify J5 vs. J7/J9 contention on `probes`).
**How to avoid:** Read `worker_main.py:79-95` and `:457-483` before writing any plan task; change only the lane *assignments* that measurement (the Pi-acceptance load run) shows are actually contended.
**Warning signs:** A plan task titled "implement executor pools" without referencing `WORKER_CALLBACK_INVENTORY` or `build_scheduler` by name.

### Pitfall 2: Treating `attempt_count` as an enforced retry cap
**What goes wrong:** Assuming preview retries are already bounded because `preview_requests.attempt_count` exists and increments on every claim.
**Why it happens:** The column name and increment logic (`queues.py:657`) look like retry bookkeeping, and are — but nothing reads or enforces a maximum. A "failed" preview simply stays terminal.
**How to avoid:** Explicitly design and implement the retry/backoff decision (how many attempts, what backoff, what final "degraded" terminal state distinct from "never attempted") rather than assuming it exists.
**Warning signs:** A plan or test asserting "previews already retry N times" without a citation to code that enforces N.

### Pitfall 3: Conflating "browser unavailable" (job fault) with "capture degraded" (UI state)
**What goes wrong:** `THUMB_ERROR_BROWSER_UNAVAILABLE` already correctly distinguishes a total machinery fault (raises `PreviewCaptureUnavailable`, becomes a genuine `job_failed`) from an ordinary per-service capture failure (`thumb_error` text, job still "succeeded"). OPS-02's "visible non-fatal degraded state" is about the **second** case reaching the operator's screen, not about surfacing the machinery fault (which already has its own job-health path). Building UI only for the machinery-fault case would miss OPS-02's actual requirement.
**Why it happens:** The machinery-fault distinction was hard-won (per `03-VERIFICATION.md` round 7 gap 1, referenced in `previews.py`'s `PreviewCaptureUnavailable` docstring) and is fresh in the codebase's own commentary, making it easy to over-index on.
**How to avoid:** Confirm the UI change targets `thumb_error`/`thumb_attempt_ts` surfaced via `/api/thumbnail-status` (per-service, non-fatal) using Phase 5's established degraded-state vocabulary, distinct from the worker-freshness `#degraded-warning` banner which is about heartbeat aging, not preview capture.
**Warning signs:** A plan that only touches `worker_process_preview_requests`'s `PreviewCaptureUnavailable` path and never touches `app.js`'s thumbnail-fallback rendering.

### Pitfall 4: Changing journal mode without re-verifying `_db_lock`'s assumptions
**What goes wrong:** Flipping to WAL mode changes read/write blocking behavior process-wide; naively removing or narrowing `_db_lock` at the same time (reasoning "WAL makes it safe now") without re-testing every one of its 25+ call sites risks reintroducing exactly the race `_db_lock` was added to prevent within the 8-thread gunicorn process (WAL does not eliminate the need for a single writer at a time within one connection's transaction discipline, and does nothing about multiple threads sharing one Python-level SQLite connection object incorrectly).
**Why it happens:** WAL and `_db_lock` solve adjacent but different problems — WAL is about reader/writer blocking *across processes/connections*; `_db_lock` is about serializing access from *multiple threads inside one process*. Fixing one does not fix the other.
**How to avoid:** Treat the WAL PRAGMA change and any `_db_lock` scope change as two separately-tested decisions, in that order, with `AR-03-01`'s existing reasoning as the baseline for the second.
**Warning signs:** A single plan task or commit that both flips `journal_mode` and removes `_db_lock` from a route.

## Code Examples

### Extending the executor lane assignment (illustrative — not a verbatim diff)
```python
# Source: pattern extension of dashboard/beacon/worker_main.py:457-483 (existing code read this session)
executors = {
    'default': ThreadPoolExecutor(1),
    'metrics': ThreadPoolExecutor(1),   # J1 heartbeat + J2 metric sampling ONLY
    'cleanup': ThreadPoolExecutor(1),   # NEW: J8 moves here, off the essential lane
    'probes': ThreadPoolExecutor(2),    # J3, J4, J5, J7, J9
    'screenshots': ThreadPoolExecutor(1),  # J6 (unchanged)
}
```

### Reading the existing job-health evidence for a load-test assertion
```python
# Source: dashboard/beacon/repositories.py:66-73 (read_background_job_health, quoted verbatim)
def read_background_job_health(conn, *, limit=32):
    """Return a deterministic, bounded projection of durable job outcomes."""
    return [dict(row) for row in conn.execute(
        'SELECT job_id, last_started_ts, last_finished_ts, last_success_ts, '
        'state, error_class, updated_ts FROM background_job_health '
        'ORDER BY job_id ASC LIMIT ?',
        (max(1, min(int(limit), 128)),),
    )]
```
The Pi-acceptance harness (and new regression tests) should call this directly to assert, e.g., `J1`/`J2` never transition to `'failed'` and their `last_success_ts` age stays within `freshness_state`'s `fresh`/`aging` band throughout a load run.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| (n/a — this is the first phase to touch scheduler contention/WAL/thumbnail storage) | — | — | — |

**Deprecated/outdated:** None identified — this phase is additive to a recently-built (2026, Phases 1-5) codebase; no legacy pattern is being replaced, only a deferred decision (WAL) and an incomplete pattern (preview retry/degraded UI) being completed.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Enabling `PRAGMA journal_mode=WAL` on every `connect_db()` call is safe and sufficient to flip the whole database to WAL mode (SQLite persists journal mode in the file header, so any connection issuing the PRAGMA converts the file) | Architecture Patterns §4 | If wrong (e.g., a read-only mount or the `read_only: true` container filesystem constraint on `/data`'s parent affects WAL sidecar file creation), the migration could fail at runtime; must be verified against the actual Pi filesystem/mount options during planning, not assumed from this research alone |
| A2 | A dedicated `'cleanup'` executor lane (1 thread) is sufficient to resolve J8/J1/J2 contention, without needing to also resize the `'probes'` lane | Architecture Patterns §1 | If wrong, the Pi-acceptance load run (OPS-07) will surface it directly — this assumption is falsifiable by the phase's own acceptance criterion and should be treated as a starting hypothesis, not a locked decision |
| A3 | 2-3 bounded retry attempts with short backoff is an appropriate policy shape for preview capture failures (exact numbers not specified anywhere in the codebase) | Architecture Patterns §2 | If wrong (too aggressive retries could compete with the essential lanes; too few could leave a transient failure looking permanently degraded), the specific numbers need explicit user/planner decision, not this research's estimate |
| A4 | No CPU resource limit (`cpus:` in `docker-compose.yml`) is currently set for any service, and this is worth explicitly deciding on rather than silently continuing without one | Architecture Patterns §5 | If a CPU limit already exists via an out-of-repo Pi-level cgroup config not visible in this codebase, the recommendation to add one would be redundant; verified only against the in-repo `docker-compose.yml` this session |

**If this table is empty:** N/A — see entries above; all are genuine open decisions best surfaced to the user/planner rather than resolved silently by this research.

## Open Questions (RESOLVED)

> All three questions were resolved during planning. Each carries a **Resolution** line naming the
> artifact that closed it. Nothing below is still open.

1. **Exact WAL rollout mechanics for an already-deployed production database**
   - What we know: `journal_mode` is never set anywhere in the codebase today; `PROJECT.md` explicitly defers this decision to Phase 6.
   - What's unclear: Whether the operator's existing production `dashboard.db` (referenced elsewhere as "the operator-confirmed production fingerprint" in `.planning/STATE.md`'s Phase 1 decisions) is already in WAL mode from some earlier manual operation, or in the SQLite default (rollback-journal) mode — this determines whether enabling WAL is a no-op confirmation or an actual first-time mode change with real sidecar-file implications.
   - Recommendation: The plan should include a step that reads `PRAGMA journal_mode` from the actual production database fingerprint/backup before deciding the migration's behavior, using the same evidence-based approach `01-04-PLAN.md` used for the original migration-support-floor inventory.
   - **Resolution (`06-05-PLAN.md` Task 1):** The rollout does not depend on knowing the starting mode. `connect_db` issues `PRAGMA journal_mode=WAL` unconditionally and `configured_journal_mode` reads back the mode actually in force, so both starting modes converge on the same end state; `test_connections_run_in_wal_mode_from_either_starting_mode` proves both paths against synthetic fixtures. The production reading the recommendation asked for is captured as *evidence* by Task 1's `<human-check>`, non-blocking: when a Pi or a copy of the deployed database is reachable, the before/after `journal_mode` and `wal_bytes` readings are attached to the plan summary; when it is not, the starting mode is recorded as `unverified` and carried as `D-DEBT-06-03` in `06-DEBT.md` (Task 3) rather than assumed. The two consequences the question flagged — WAL-mode schema inspection and WAL-mode verified backup — are handled unconditionally in the same task (`inventory.py`'s `PRAGMA query_only=ON` fallback, and normalizing the backup artifact to rollback-journal mode).

2. **Exact retry-count/backoff numbers and TTL duration for the new thumbnail store**
   - What we know: No existing convention specifies these; `THUMB_REFRESH_DAYS=1` is a *refresh* cadence, not a retry-backoff or storage-TTL value.
   - What's unclear: Whether a new TTL should mirror `THUMB_REFRESH_DAYS`, be independently configurable, or use a fixed multiple.
   - Recommendation: Treat as a `Claude's Discretion`-equivalent decision for the planner to make explicitly and document, since no CONTEXT.md exists to constrain it and no code precedent fixes the number.
   - **Resolution (user decision D-02, implemented in `06-02-PLAN.md` Task 2 and `06-03-PLAN.md` Tasks 1-2):** D-02 delegated the numbers to the planner on the condition that they be specified, env-exposed, and carry recorded rationale. Chosen and locked: `THUMBNAIL_TTL_DAYS = 7` (survives six consecutive missed daily `THUMB_REFRESH_DAYS` cycles and equals `EXPIRE_DAYS`, so a thumbnail can never outlive its own service's visibility window), `THUMBNAIL_STORE_MAX_BYTES = 67_108_864` (matches the existing `telemetry_backlog_reserve_bytes` reserve; an order of magnitude below the telemetry store it shares a disk with), `PREVIEW_MAX_ATTEMPTS = 3`, `PREVIEW_RETRY_BASE_SECONDS = 60` and `PREVIEW_RETRY_MAX_SECONDS = 600` (60s doubling, capped at 600s). Every value is loaded through `_positive_int`, so a bad env value falls back to the documented default rather than to "no limit" (PROH-OPS-03-04), and all five are exposed in the `docker-compose.yml` shared environment anchor. The question's specific framing — mirror `THUMB_REFRESH_DAYS`, or independent — is answered: independent and configurable, with `THUMB_REFRESH_DAYS` used as the *reasoning* input rather than the value.

3. **Whether `_db_lock`'s scope should narrow as part of this phase or remain a documented follow-up**
   - What we know: `AR-03-01` already accepted a narrow, reasoned exception for one route; `PROJECT.md` groups this with the WAL decision for Phase 6.
   - What's unclear: Whether the phase's scope (as written) expects `_db_lock` itself to be touched, or only the WAL/underlying SQLite concurrency model, leaving `_db_lock` untouched pending its own future evaluation.
   - Recommendation: Default to *not* touching `_db_lock`'s scope beyond what OPS-04's "concurrent web/worker database activity" testing requires to prove correct, given Pitfall 4's risk — but flag this explicitly for the planner/user to confirm the intended boundary.
   - **Resolution (user decision D-01, implemented in `06-05-PLAN.md` Tasks 1 and 3):** The boundary was confirmed by the user exactly as recommended — WAL only, `_db_lock`'s scope UNCHANGED at every call site this phase. It is enforced, not merely intended: `PROH-OPS-04-02` forbids any route or job gaining unserialized access as a side effect of the journal-mode change, and Task 1's acceptance criteria require a `git diff` scoped to `dashboard/app.py` showing no change to any `_db_lock` occurrence. The narrowing is recorded as `D-DEBT-06-01` in `06-DEBT.md` (Task 3), citing this phase's own evidence — the journal-mode readings, the concurrent-writer and restart-recovery test results, and the pre-existing `AR-03-01` accepted risk for `api_advanced_current` — plus what would need to be true to proceed.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Docker / Docker Compose | Pi-acceptance run (OPS-07) must exercise the real deployment topology | Not verified in this sandboxed research session (no Docker daemon probed) | — | The planner must verify Docker availability on the actual target Raspberry Pi before planning the OPS-07 acceptance-run task; this research could not probe the target hardware directly |
| A physical/emulated Raspberry Pi-class host | OPS-07's success criterion explicitly requires "Raspberry Pi-class hardware" | Not available in this research environment | — | If a real Pi is unavailable during planning, the harness must still be built and checked in as an automated, repeatable script; actual hardware execution becomes a `checkpoint:human-verify`-gated manual run, consistent with how `03-UAT.md`'s real-Pi hardware tests were previously handled for this same project |
| `python:3.12-slim-bookworm` base image / `uv` / `playwright install --with-deps chromium` | Worker container build | Declared and pinned in `dashboard/Dockerfile` [VERIFIED] | Python 3.12, uv 0.11.28, Chromium via playwright 1.61.0 | None needed — already the existing, working build |

**Missing dependencies with no fallback:**
- None that block *planning* this phase — all code-level dependencies already exist in the pinned toolchain. Actual hardware execution of the OPS-07 acceptance run depends on physical/target Pi access this research session cannot verify; the plan must account for this as a human-gated step if the target Pi is not reachable from the execution environment.

**Missing dependencies with fallback:**
- Docker daemon availability during planning/execution: fallback is to build the harness as a standalone script (not requiring live Docker) that can also run against a `docker compose up` stack when available, matching the project's existing precedent of real-Pi UAT phases running outside the automated verification loop (see `03-UAT.md`, `03.1-UAT.md` in `.planning/phases/`).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest `>=9.0.2,<10` [VERIFIED: dashboard/pyproject.toml] |
| Config file | `dashboard/pyproject.toml` `[tool.pytest.ini_options]` — `pythonpath = [".."]`, `testpaths = ["../tests"]` [VERIFIED: dashboard/pyproject.toml] |
| Quick run command | `uv run --project dashboard python -m pytest -q -k <module_or_test>` |
| Full suite command | `uv run --project dashboard python -m pytest -q` [VERIFIED: .planning/config.json `workflow.test_command`] |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OPS-01 | J1/J2 (essential) freshness stays `fresh`/`aging` (never `stale`, per `freshness_state`) while J5/J6/J7/J8 fire concurrently under synthetic load | integration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py -k cadence_under_contention` | ❌ Wave 0 |
| OPS-02 | A forced repeated preview capture failure exhausts a bounded retry count, reaches a distinct terminal "degraded" state, and never blocks J1/J2/J3/J4 dispatch | integration | `uv run --project dashboard python -m pytest -q tests/test_workload_resilience.py -k preview_retry_bounded` | ❌ Wave 0 |
| OPS-03 | After migration, `services.thumb_data` is NULL for all rows and the new thumbnail table holds the migrated blobs, size-capped and TTL-expiring | migration + unit | `uv run --project dashboard python -m pytest -q tests/test_migrations.py -k thumbnail_relocation` | ❌ Wave 0 (extends existing `test_migrations.py`) |
| OPS-04 | Concurrent web (`_db_lock`-serialized, 8 threads) and worker writers against a shared SQLite file under WAL produce no corruption/lock errors across a bounded stress run; worker restart mid-job correctly resumes/fences per `background_job_health` | integration | `uv run --project dashboard python -m pytest -q tests/test_worker_ownership_matrix.py tests/test_workload_resilience.py -k restart_recovery` | ❌ Wave 0 (new concurrency file; extends existing ownership-matrix file) |
| OPS-07 | A checked-in load harness runs a representative-load scenario and asserts response-time, RSS/CPU-vs-`mem_limit`, `freshness_state`, and `background_job_health` bounds | e2e / acceptance (may require real Pi — see Environment Availability) | `python tests/pi_load_acceptance.py --duration 600` (standalone; not necessarily pytest-gated) | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `uv run --project dashboard python -m pytest -q -k <touched module>`
- **Per wave merge:** `uv run --project dashboard python -m pytest -q` (full suite — this repo's `test_command`)
- **Phase gate:** Full suite green before `/gsd-verify-work`; OPS-07's Pi-class harness run is additionally required as human-gated evidence if no live Pi is reachable from the automated environment (see Environment Availability)

### Wave 0 Gaps
- [ ] `tests/test_workload_resilience.py` — new file covering OPS-01 (cadence under contention), OPS-02 (bounded preview retry), OPS-04 (restart + concurrent access stress)
- [ ] `tests/pi_load_acceptance.py` (or `scripts/pi_load_acceptance.py`) — new, checked-in, repeatable load harness covering OPS-07, built on `requests`/`threading`/`psutil` (no new dependency)
- [ ] Extension to `tests/test_migrations.py` — new migration test for the thumbnail-table relocation and `services.thumb_data` emptying, following the existing preservation-snapshot pattern already used for prior migrations (per `.planning/STATE.md` Phase 2 decisions: "Migration preservation snapshots source fixture columns and values before asserting the same data after additive upgrades")
- [ ] Framework install: none — pytest, psutil, and requests are already pinned dependencies

*(No gaps in framework availability — only new test files/harness scripts are needed; the framework itself is already fully set up.)*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Beacon has no auth model (trusted-LAN-only, per locked project constraints); unchanged by this phase |
| V3 Session Management | No | No session state introduced by this phase |
| V4 Access Control | No | No new access boundary introduced |
| V5 Input Validation | Partial | Any new thumbnail-store query parameters (e.g., a port-scoped read) must reuse the existing parameterized-query discipline already established in `repositories.py` (the codebase's own `CONCERNS.md` already confirms no SQL-injection vector exists in comparable dynamic-query code, `repositories.py:938-940`) |
| V6 Cryptography | No | No new cryptographic surface |
| V1 Architecture, Design and Threat Modeling | Yes | This phase is fundamentally about resource-exhaustion/availability threats (a slow/starved essential job, an unbounded blob store, a stuck browser) rather than confidentiality/integrity threats — the relevant "standard control" is bounded resource budgets (thread pools, TTLs, size caps, timeouts) already the pattern established elsewhere in this codebase (`DISCOVERY_TIMEOUT_SECONDS`, `THUMB_MAX_BYTES`, `telemetry_db_max_bytes`, etc.) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Unbounded blob growth (thumbnail store) causing disk exhaustion | Denial of Service | Size cap at write time (already exists, `THUMB_MAX_BYTES`) plus a new TTL/expiry reap job, following the existing `telemetry_db_max_bytes`/pressure-hysteresis pattern (`config.py` `telemetry_pressure_*` fields) already proven for the telemetry store in Phase 2 |
| A wedged/slow background job (e.g., cleanup, discovery) starving essential sampling threads | Denial of Service (availability) | Executor-lane isolation (this phase's Architecture Pattern 1) plus the existing `misfire_grace_time`/`coalesce`/`max_instances=1` job defaults, which already bound how a stuck job degrades rather than cascades |
| A crashed/OOM'd Chromium under sustained preview load on constrained Pi memory | Denial of Service | Existing `mem_limit: 1g` on the `worker` container plus the existing browser-connectivity check in `_get_browser` (`is_connected()`) that already relaunches a dead browser; this phase's bounded-retry addition further bounds how long a degraded browser is retried before surfacing to the operator instead of looping |
| Concurrent writers corrupting SQLite state across a worker restart mid-transaction | Tampering / Denial of Service | Existing `write_transaction`/`ManagedConnection` rollback-on-exception discipline (`db.py:121-129`) plus (if adopted) WAL mode's crash-safe log-replay semantics — must be proven, not assumed, via the new OPS-04 restart-recovery regression tests |

## Sources

### Primary (HIGH confidence — read directly this session)
- `dashboard/beacon/worker_main.py` — scheduler, executor lanes, `dispatch_callback`, job-health wiring
- `dashboard/beacon/queues.py` — durable scan/preview lease and queue semantics, `attempt_count`
- `dashboard/beacon/previews.py` — preview operation interfaces, `PreviewCaptureUnavailable`
- `dashboard/beacon/db.py` — connection/transaction/lock primitives, `PRAGMA` usage
- `dashboard/beacon/migrations.py` — full schema history including `services.thumb_*` columns
- `dashboard/beacon/repositories.py` — `background_job_health`, `ThumbnailResultRepository`
- `dashboard/beacon/diagnosis.py` — `freshness_state`, cadence-boundary conventions
- `dashboard/beacon/config.py` — `Settings` (all tunable cadences/timeouts/budgets)
- `dashboard/beacon/monitoring.py`, `dashboard/beacon/inventory.py`, `dashboard/beacon/recovery.py` — monitoring/inventory/recovery interfaces and WAL-checkpoint defensive code
- `dashboard/app.py` — legacy browser ownership, screenshot capture, `_db_lock`, thumbnail routes
- `dashboard/app.js` — dashboard thumbnail rendering/fallback
- `dashboard/Dockerfile`, `docker-compose.yml` — pinned versions, resource limits, process topology
- `dashboard/pyproject.toml` — exact pinned dependency versions, pytest config
- `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, `.planning/STATE.md`, `.planning/PROJECT.md`, `.planning/config.json` — requirement text, phase history, locked decisions, workflow toggles
- `.planning/codebase/CONCERNS.md` — existing known bugs/bottlenecks/scaling notes
- `tests/` directory listing and `test_worker_ownership_matrix.py` — existing regression coverage baseline

### Secondary (MEDIUM confidence)
- None — no external documentation lookups were needed; every finding for this phase was groundable directly in the local codebase and planning artifacts.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new libraries; all versions read directly from `dashboard/pyproject.toml`/`dashboard/Dockerfile` this session
- Architecture: HIGH — every pattern cited is quoted verbatim from code read this session, not inferred from documentation or memory
- Pitfalls: HIGH — each pitfall is grounded in a specific, cited code location and (where applicable) a specific prior gap-closure precedent from `.planning/STATE.md`
- Pi-acceptance methodology: MEDIUM — the *evidence sources* to assert against (`freshness_state`, `background_job_health`, Compose resource limits) are HIGH confidence (verified in code), but the exact load-generation shape and hardware access were not verifiable from this research environment (see Environment Availability and Open Questions)

**Research date:** 2026-08-28
**Valid until:** 2026-09-27 (30 days — stable, internal-codebase-grounded research; re-verify if Phase 6 planning is deferred past this window or if the codebase changes materially in the interim)
