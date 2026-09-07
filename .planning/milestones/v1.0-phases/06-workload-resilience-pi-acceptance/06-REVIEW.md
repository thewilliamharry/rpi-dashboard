---
phase: 06-workload-resilience-pi-acceptance
reviewed: 2026-09-01T00:00:00Z
depth: standard
files_reviewed: 29
files_reviewed_list:
  - dashboard/app.py
  - dashboard/app.js
  - dashboard/style.css
  - dashboard/beacon/config.py
  - dashboard/beacon/db.py
  - dashboard/beacon/inventory.py
  - dashboard/beacon/migrations.py
  - dashboard/beacon/queues.py
  - dashboard/beacon/repositories.py
  - dashboard/beacon/worker_main.py
  - dashboard/beacon/support_floor.json
  - docker-compose.yml
  - tests/pi_load_acceptance.py
  - tests/test_workload_resilience.py
  - tests/worker_ownership_contract.py
  - tests/test_worker_ownership_matrix.py
  - tests/test_migrations.py
  - tests/test_durable_queues.py
  - tests/test_ui_states.py
  - tests/test_advanced_diagnosis_api.py
  - tests/test_api_and_auth.py
  - tests/test_backup_recovery.py
  - tests/test_maintenance_windows.py
  - tests/test_module_boundaries.py
  - tests/test_runtime_ownership.py
  - tests/test_security_and_scanning.py
  - README.md
  - AGENTS.md
  - tests/fixtures/legacy/support-floor.json
findings:
  critical: 0
  warning: 2
  info: 1
  total: 3
status: issues-found
---

# Phase 6: Code Review Report

**Reviewed:** 2026-09-01
**Depth:** standard
**Files Reviewed:** 29
**Status:** issues-found

## Summary

This review examined the full diff for phase 06 (`91f8751..HEAD`), which relocates thumbnail BLOBs
into a bounded, TTL/byte-budget-enforced satellite table (migration 10, OPS-03), adds bounded
backoff-and-degrade retry to the preview capture queue (OPS-02), isolates the hourly cleanup job
onto its own scheduler lane (OPS-01), turns on SQLite WAL mode end-to-end (OPS-04), and adds a
standalone Raspberry Pi load-acceptance harness (OPS-07).

The core, highest-risk logic held up under scrutiny:

- **Migration 10** genuinely shares one `BEGIN IMMEDIATE` transaction (inherited, unmodified
  transaction machinery in `_apply_pending_migrations`) between the BLOB backfill INSERT and the
  `services` NULL-out UPDATE, with `INSERT OR IGNORE` making a re-entrant run of the same migration
  version idempotent. No path exists to commit the NULL-out without the backfill, or vice versa.
- **The eviction/reap SQL** in `repositories.py` is fully parameterized (`?`-bound values, no
  string-interpolated row data; the `IN (...)` placeholder list is built from `?` markers, never
  values), and the bounded-scan-converges-across-passes design is sound and matches its own
  documented limitation.
- **The retry/backoff logic** in `queues.py` has no off-by-one on the attempt cap: `attempt_count`
  is incremented once per claim (never twice), `preview_retry_decision`'s `attempt_count >=
  max_attempts` boundary correctly yields exactly `PREVIEW_MAX_ATTEMPTS` real attempts before
  degrading, and `next_attempt_ts` is honored symmetrically by both `claim_preview`'s candidate
  `SELECT` and its conditional `UPDATE`, closing the race the plan's own commentary calls out.
- **The frontend changes** (`app.js`, `style.css`) use `textContent` exclusively for the new
  degraded-state strings — no injection surface was introduced — and the degraded copy renders
  through `.svc-preview-status`, which both themes style, so the theme-parity claim holds.
- The `tests/test_advanced_diagnosis_api.py` and `tests/test_migrations.py` realignments checked
  against their claimed rationale in the plan summaries are genuine, narrowly-scoped consequences of
  the intended behavior changes (bounded-retry-pending status; WAL flipping the file header on
  connect) — not weakened assertions. Every other field in each realigned test (error text,
  job-health state, exception class, byte-identical legacy rows) is unchanged.

Two real defects surfaced by direct reproduction, both concentrated in the areas the review brief
flagged as highest-risk (WAL/backup interaction, and the new API surface added alongside the retry
work). Neither is a data-loss or corruption risk, and neither affects the live, writable `/data`
deployment path this phase's own tests exercise — which is exactly why the test suite did not catch
either of them.

## Warnings

### WR-01: WAL readonly-inspection fallback is not actually read-only — it fails outright on a read-only source

**File:** `dashboard/beacon/inventory.py:41-56`

**Issue:** `_readonly_connection`'s WAL fallback opens a *normal, writable* SQLite connection
(`sqlite3.connect(resolved)`) and only forbids writes at the SQL level afterward
(`PRAGMA query_only=ON`). Establishing that connection against a WAL-mode database requires SQLite
to create/attach the `-shm` shared-memory file, which needs **write access to the source directory**
— even though the connection is conceptually read-only and no `INSERT`/`UPDATE`/`DDL` is ever issued
through it.

**Concrete failure scenario:** An operator follows this same phase's own new README guidance
("Any other copy of the live database ... must include all three files (`dashboard.db`,
`dashboard.db-wal`, `dashboard.db-shm`) taken together, and only while Beacon is stopped") and copies
those three files to a location they then lock down (e.g. `chmod -R a-w` on an archival copy, or a
read-only mount) before running `python -m beacon.inventory --db <copy> --output <report.json>` for
verification. The primary `mode=ro` URI path already fails for a WAL database (that's the reason the
fallback exists), and the fallback now *also* fails — reproduced directly:

```
$ python - <<'EOF'
sqlite3.connect('file:test.db?mode=ro', uri=True)       # fails: WAL needs -shm
sqlite3.connect('test.db'); conn.execute('PRAGMA query_only=ON')  # ALSO fails on a read-only dir:
# sqlite3.OperationalError: attempt to write a readonly database
EOF
```

Both attempts raise `sqlite3.OperationalError`, which `_readonly_connection` correctly catches and
re-raises as `InventoryError('unable to inspect SQLite database')` — so the failure is loud, not
silent — but it defeats the fallback's entire purpose (inspecting a WAL-mode deployment) for exactly
the external, copied-database scenario this phase's own documentation just told operators to use.
Before this phase (no WAL), the same copy-then-lock-down-then-inspect workflow worked fine, because a
rollback-journal-mode database needs no `-shm` file and `mode=ro` alone is sufficient. This is a
functional regression for that workflow, not merely an untested edge case.

No test in `tests/test_migrations.py`'s new `InventoryTests::test_cli_inspects_a_wal_mode_database_through_the_query_only_fallback`
exercises this — it inspects the WAL fixture from a normal (writable) temp directory, so the
regression is invisible to the suite.

**Fix:** Use SQLite's own `immutable=1` URI hint for the WAL fallback, which is designed for exactly
this case (a database file that will not change and does not need `-shm`/locking machinery):

```python
try:
    return sqlite3.connect(resolved.as_uri() + '?mode=ro', uri=True)
except sqlite3.Error:
    try:
        return sqlite3.connect(resolved.as_uri() + '?mode=ro&immutable=1', uri=True)
    except (OSError, sqlite3.Error) as exc:
        raise InventoryError('unable to inspect SQLite database') from exc
```

Note `immutable=1` changes what `PRAGMA journal_mode` reports (it does not consult the WAL file, so
it will *not* truthfully report `wal`) — if `collect_inventory`'s `journal_mode`/`wal_bytes` fields
must stay accurate, keep the current `query_only` fallback as a *second* attempt (for genuinely
writable-but-inspection-only copies) after `immutable=1` fails, rather than replacing it outright.
Either way, a truly read-only source should not raise `InventoryError` the way it does today.

---

### WR-02: `/api/thumbnail-status`'s `thumb_state` can report `degraded` while a valid image is still being served, and no test covers the interaction

**File:** `dashboard/app.py:3054-3062`

**Issue:** `thumb_state` is derived with `degraded` checked *before* `has_thumb`:

```python
if preview_status == beacon_queues.PREVIEW_STATUS_DEGRADED:
    thumb_state = beacon_queues.PREVIEW_STATUS_DEGRADED
elif row['has_thumb']:
    thumb_state = 'ok'
elif preview_status in ('queued', 'running'):
    thumb_state = 'pending'
else:
    thumb_state = 'empty'
```

`has_thumb` and `preview_status` are independent facts: `has_thumb` reflects whether a stored,
unexpired thumbnail row exists (via `read_thumbnail`'s query semantics); `preview_status` reflects
only the *most recent* `preview_requests` row for that port. A service's thumbnail is refreshed
periodically (`THUMB_REFRESH_DAYS`, default daily) while the stored thumbnail's TTL is longer
(`THUMBNAIL_TTL_DAYS`, default 7 days) — this gap exists specifically so a stored thumbnail survives
several missed refresh cycles (per the `THUMBNAIL_TTL_DAYS` rationale comment in `config.py`).

**Concrete failure scenario:** A service's preview capture succeeds on day 0 (thumbnail stored,
`expires_ts` = day 7). On day 1 the daily refresh fires and fails repeatedly; by day 3 the bounded
retry budget (`PREVIEW_MAX_ATTEMPTS`, default 3) is exhausted and the *latest* `preview_requests` row
for that port lands on `status='degraded'`. The day-0 thumbnail is still stored and still unexpired
(`expires_ts` is day 7, `now` is day 3) — `GET /api/services`'s `has_thumb` and `GET
/api/thumbnail/<port>` both still serve it correctly. But `GET /api/thumbnail-status` now reports
`"thumb_state": "degraded"` for that port, even though a real, currently-servable image exists. This
contradicts the field's own documented contract (06-03-SUMMARY.md D3: "`thumb_state` distinguishes
`ok`/`pending`/`empty` from stored facts only") — a `degraded` verdict from `thumb_state` should not
be possible while `has_thumb` is true, or the two should agree via an additional state (e.g.
`stale-degraded`) rather than silently overriding the "ok" signal.

This field currently has **zero consumers** (`grep -rn thumb_state dashboard/` outside its own
definition returns nothing in `app.js`) and **zero test coverage** anywhere in the suite (`grep -rn
thumb_state tests/` matches nothing) — the interaction was never exercised, which is why it shipped.

**Fix:** Either report both facts independently (e.g. keep `thumb_state` as the "is there a servable
image" signal — `ok`/`pending`/`empty` — and add a separate `capture_state`/`preview_status` field
for the degraded signal, mirroring what `/api/services` already does with two independent fields), or
document/test the override as intentional if it truly is. At minimum, add a
`ThumbnailBudgetTests`/`PreviewRetryTests`-style regression covering "has_thumb=true and the latest
preview_requests row is degraded" so this combination is a decided behavior, not an accidental one.

## Info

### IN-01: Backfilled legacy thumbnails rely on an invariant that is not enforced by schema

**File:** `dashboard/beacon/migrations.py:617-621`

**Issue:** The migration 10 backfill computes `expires_ts` as `COALESCE(thumb_ts, 0) + THUMBNAIL_BACKFILL_TTL_SECONDS`.
If a legacy `services` row ever had `thumb_data IS NOT NULL` with `thumb_ts IS NULL`, the resulting
`expires_ts` would be `604800` (1970-01-08), i.e. already expired at backfill time, and the next
hourly reap (`delete_expired_thumbnails`) would silently discard that thumbnail immediately post-
migration. Confirmed by reading history that both the pre-phase `ThumbnailRepository` and the new
`ThumbnailStoreRepository` always write `thumb_data` and `thumb_ts` together, so this combination
should not occur in practice given only in-application write paths — but nothing in the schema
enforces it, and the `COALESCE` exists precisely because the author anticipated it could. Not a bug
under any currently-reachable code path; flagged only because the defensive `COALESCE` masks what
would otherwise be a loud, investigable failure (a thumbnail that silently vanishes right after
upgrade) if the invariant is ever violated by a future write path or a hand-edited row. Consider
excluding `thumb_ts IS NULL` rows from the backfill's `WHERE` clause (or logging when it happens)
instead of coalescing to an already-expired timestamp.

---

_Reviewed: 2026-09-01_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
