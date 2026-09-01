---
status: complete
phase: 06-workload-resilience-pi-acceptance
source: [06-VERIFICATION.md]
started: 2026-09-01T00:00:00Z
updated: 2026-09-01T00:00:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Real Raspberry Pi-class acceptance run (OPS-07)
expected: Harness reports `run_kind: "acceptance"`, Pi-class host, `overall_passed: true`, no failed job-health rows, J1-J4 never `stale`, resource budgets and route p95s within limits.
result: issue
reported: "Ran on real hardware (raspi, aarch64). run_kind: acceptance, cadence passed, resources passed, but overall_passed: false — all five exercised routes blew their p95 budgets: /api/services 10010.9ms vs 500ms, /api/scan-status 10011.1ms vs 500ms, /api/thumbnail-status 5106.8ms vs 750ms, /api/advanced/current 2353.9ms vs 2000ms, /api/thumbnail/<port> 3046.1ms vs 1500ms."
severity: blocker

## Summary

total: 1
passed: 0
issues: 1
pending: 0
skipped: 0
blocked: 0

## Gaps

```yaml
- gap_id: G-06-1
  truth: "Every exercised route's p95 latency stays within its declared budget under representative concurrent load on Pi-class hardware."
  status: failed
  reason: "User reported: real acceptance run on raspi (aarch64) returned overall_passed: false with all five routes over budget. /api/services p50 7926ms / p95 10010.9ms (budget 500ms); /api/scan-status p50 7695ms / p95 10011.1ms (budget 500ms); /api/thumbnail-status p50 31.8ms / p95 5106.8ms (budget 750ms); /api/advanced/current p50 1899ms / p95 2353.9ms (budget 2000ms); /api/thumbnail/<port> p50 24.4ms / p95 3046.1ms (budget 1500ms)."
  severity: blocker
  test: 1
  artifacts:
    - beacon-acceptance.json (on the Pi, run 2026-09-01)
    - dashboard/beacon/migrations.py:604-611 (thumbnails column order)
    - dashboard/app.py:2757 (/api/services has_thumb subquery)
    - dashboard/app.py:3036 (/api/thumbnail-status has_thumb subquery)
    - dashboard/app.py:1368 (_legacy_do_discovery, inside write transaction)
    - dashboard/app.py:1519 (_legacy_do_uptime_check, inside write transaction)
  missing:
    - Covering/partial index on thumbnails(port, source, expires_ts) so the has_thumb existence check never reads the row body
    - A load-path assertion that the has_thumb check does not touch thumbnails.data overflow pages
```

### Diagnosis (2026-09-01)

**Measurement caveat that changes how the numbers read.** The harness calls
`session.get(url, timeout=10)` and swallows the exception while still recording elapsed time
(`tests/pi_load_acceptance.py:349`). Every reported value clustered at ~10010-10019ms is therefore
the *client timeout*, not a measured response — those requests never returned. Real latency on the
two worst routes is unbounded and strictly worse than the report shows.

**The Pi was idle while this happened.** Web CPU mean 0.01% / peak 1.0%; worker CPU mean 0.685% /
peak 12.0%; RSS 45.9MB (limit 256MB) and 56.6MB (limit 1GB). Not compute-bound, not memory-bound.
Requests were blocked, not working.

#### Refuted hypothesis — SQLite overflow-page walks (measured false on hardware)

The first hypothesis was that the `has_thumb` correlated subquery reads `source`/`expires_ts`,
which sit *after* the 2 MiB `data` blob in the `thumbnails` record (`migrations.py:604-611`), forcing
SQLite to traverse the blob's overflow page chain once per service row. Measured on the Pi against
the live database:

```
thumbnails: 8 rows, 1.8 MiB total, 0.95 MiB largest
services: 8 rows
reads post-blob columns (current): 1 ms (warm)
header-only, no post-blob read: 0 ms (warm)
```

The store holds 8 rows, not the ~85 the hypothesis assumed, and the exact production query returns
in 1 ms. **The query is not the bottleneck.** No index change is warranted on this evidence.

#### Established facts

- `--workers 1 --threads 8` (`dashboard/Dockerfile:27`) — 8 HTTP threads.
- Every DB-touching route holds the process-wide `_db_lock` (30 sites in `app.py`), so those 8
  threads are serialized to an effective concurrency of **1**.
- Every `database_access` call opens a **brand-new** SQLite connection: an `fcntl` `LOCK_SH` lease
  on the maintenance lock file, `sqlite3.connect`, then three PRAGMAs
  (`busy_timeout`, `foreign_keys`, `journal_mode=WAL`) — `db.py:85-99`. Nothing is pooled.
- Observed throughput: ~2718 requests over 600s = **4.53 req/s**, implying a mean serialized
  service time of ~221 ms per request.
- `/api/scan-status` does only a handful of tiny reads on an 8-row database (`app.py:3076-3085`)
  yet shows p50 7695ms. It cannot be slow on its own work — it is queued.
- `/api/thumbnail/<port>` shows p50 24ms against p95 3046ms for identical work — a spread that
  indicates scheduling/queueing, not variable work.
- The `LOCK_SH` lease is shared, so it does not contend with the worker's ordinary access; only
  `exclusive_database_maintenance` (`LOCK_EX`) would block it, and no migration ran during the load.

#### Open question — what the ~221 ms per request is actually spent on

Contention is established; the per-request cost that contention multiplies is **not yet
attributed**. The two candidates are (a) per-request connection setup (flock + connect + three
PRAGMAs, on SD-card storage) and (b) transferring ~1 MiB thumbnail blobs, which are 8 of the 13
rotated routes. Both are measurable directly and neither is yet confirmed. Deliberately not
guessing a third time — the concurrency-1 control run and the connection-cost measurement are
recorded as the next step.

**Do not plan a fix from this section until the open question is closed.**

### Carried-forward items for decision (not blocking this UAT)

- **WR-01** (`dashboard/beacon/inventory.py:41-56`, code-review Warning): the WAL read-only-inspection
  fallback requires filesystem write access to create the `-shm` sidecar, so inspecting a WAL
  database on read-only media fails. Accepted as `AR-06-02` in `06-SECURITY.md`.
- **WR-02** (`dashboard/app.py:3054-3062`, code-review Warning): `thumb_state` checks `degraded`
  before `has_thumb` and can report `"degraded"` while a valid thumbnail is still served. Scoped
  to an API field with zero frontend consumers.
- **Flaky test**: `tests/test_worker_ownership_matrix.py::WorkerOwnershipTakeoverMatrixTests::test_heartbeat_renewal_to_persistence_handoff_is_fenced`
  fails ~1 run in 20, measured at an identical rate before and after this phase's changes.

### Verified this run (real hardware, not deferred)

The following Phase 6 criteria were confirmed on the actual Pi and are no longer outstanding:

- **Cadence isolation (OPS-01)** — J1/J2/J3/J4 all `fresh`, none `stale`, for the full 600s under load.
- **Resource budgets** — worker and web RSS well inside declared `mem_limit` values.
- **Harness honesty (OPS-07)** — `run_kind: "acceptance"`, `host_machine: "aarch64"`,
  `host_node: "raspi"`. `D-DEBT-06-04` (no real-hardware execution) is now discharged.
