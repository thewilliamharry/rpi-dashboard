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

#### Confirmed root cause (measured on hardware, concurrency 1)

A control run at `--concurrency 1` removes all queueing, so measured latency is pure per-request
service time:

```
/api/services          p50 2504.6ms   p95 2523.3ms   max 2529.8ms
/api/advanced/current  p50   67.8ms
/api/history           p50   12.3ms
/api/thumbnail-status  p50    4.8ms
/api/thumbnail/<port>  p50    3.3ms
/api/scan-status       p50    3.4ms
```

**`/api/services` costs ~2.5 seconds of its own work with zero contention.** Every other route is
single-digit-to-double-digit milliseconds. Both cost candidates from the previous section are
eliminated by direct measurement: managed connection open+close is **0.8 ms**, and opening plus
reading the largest (978 KiB) thumbnail blob is **1.8 ms**. Neither connection setup nor blob I/O
is material.

The distribution is the tell: 2504.6 / 2523.3 / 2529.8 across p50 / p95 / max is a spread of ~1%.
That is the signature of **fixed-size CPU work**, not I/O, not lock waiting, not variable load.

**The work is an O(buckets x intervals x services) nested loop in pure Python** (`app.py:1199-1211`):

```python
bucket_seconds = UPTIME_WINDOW_SECONDS / UPTIME_BUCKETS
for idx in range(UPTIME_BUCKETS):            # 168 buckets
    ...
    for begin, end, online in intervals:     # one interval per check row in the 7-day window
        overlap = max(0, min(end, bucket_end) - max(begin, bucket_start))
```

`UPTIME_BUCKETS = 168` and `UPTIME_WINDOW_SECONDS = 7 * 86400` (`app.py:86-87`). `intervals` is
derived per service from `service_checks` over that window; with J3 sampling every 5 minutes and J4
every minute for down services, that is roughly 2,000-10,000 intervals per service. `api_services`
calls `_uptime_summary` once per service inside its result loop (`app.py:2795`), so a single request
performs on the order of **168 x 2,000 x 8 services = ~2.7 million inner iterations** of Python
arithmetic. On Pi-class hardware that is ~2.5 seconds — matching the measurement.

Secondary, same loop body: `read_service_offline_intervals` (`app.py:2814`) is issued **per service
inside the loop** — an N+1 the adjacent `read_maintenance_windows_by_port` bulk read (`app.py:2782`)
was specifically introduced to avoid for maintenance windows. Minor next to the bucket math, but the
same shape.

**This is not a Phase 06 regression.** `git diff 8c2fc48..HEAD -- dashboard/app.py` touches no
uptime, bucket, or interval code; the loop last changed in `51a4393`. The defect predates this
phase. OPS-07 built the harness precisely to surface latent behaviour like this on real hardware,
and on its first genuine acceptance run it did exactly that.

**Why it presents as a total dashboard stall.** `_db_lock` serializes all 8 gunicorn threads
(`--workers 1 --threads 8`, `Dockerfile:27`) down to an effective concurrency of 1. One route
holding the process for 2.5s therefore blocks every other route behind it, which is why
`/api/scan-status` — 3.4ms of its own work — reported p50 7695ms under load. The deferred
`_db_lock` narrowing (`D-DEBT-06-01`, threat `T-06-24`) is not the defect but is the amplifier that
converts one slow endpoint into a whole-deployment outage.

#### Second defect — the harness's resource oracle samples the wrong process

The 600s run reported web CPU `mean 0.01% / peak 1.0%`. That cannot be true of a process spending
~2.5s of CPU on each of 216 `/api/services` requests (~540s of CPU in a 600s window). The cause is
`_find_process_by_cmdline(('gunicorn',))` (`tests/pi_load_acceptance.py:383`), which returns the
**first** matching process — the gunicorn **master**, which is idle — rather than the forked worker
child that actually serves requests. RSS 45.9MB is consistent with an idle master.

Consequence: `assertions.resources.passed: true` is not evidence. The oracle would have reported a
pass while the serving process saturated its CPU, which is the exact class of unearned-evidence
failure `PROH-OPS-07-02` exists to prevent. This needs its own fix independent of the latency defect.

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
