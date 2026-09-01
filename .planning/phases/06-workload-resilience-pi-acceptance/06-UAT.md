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

**Root cause — SQLite overflow-page walks on the `has_thumb` existence check.** Migration 10
declares `thumbnails(port INTEGER PRIMARY KEY, data BLOB, mime TEXT, captured_ts INTEGER,
source TEXT, expires_ts INTEGER)` (`migrations.py:604-611`) — `data` holds up to 2 MiB per row
(`THUMB_MAX_BYTES`) and sits at column 2, while `source` and `expires_ts` are columns 5 and 6.
SQLite stores a record's columns sequentially and spills large rows into an overflow page chain, so
reading a column *positioned after* a 2 MiB blob requires traversing that blob's entire chain
(~500 pages at 4 KiB). The `has_thumb` correlated subquery reads exactly those two post-blob
columns, once per service row:

```sql
EXISTS (SELECT 1 FROM thumbnails t WHERE t.port = s.port AND t.data IS NOT NULL
        AND t.source='screenshot' AND (t.expires_ts IS NULL OR t.expires_ts > ?))
```

(`t.data IS NOT NULL` is cheap — NULL-ness lives in the record header. `t.source` and
`t.expires_ts` are what force the walk.) At roughly 85 discovered services that is on the order of
40,000 overflow-page reads per request, off the Pi's SD card — seconds of pure I/O wait, which is
exactly the near-zero-CPU multi-second stall observed.

**Why the failure distributes the way it does:**

- `/api/services` (`app.py:2757`) and `/api/thumbnail-status` (`app.py:3036`) run the subquery
  themselves.
- `_legacy_do_discovery` (`app.py:1368`) and `_legacy_do_uptime_check` (`app.py:1519`) run it
  **inside `_mutation_write_transaction`** — so the worker's J3/J4/J7/J9 passes hold the SQLite
  write lock for the duration of the walk.
- `/api/scan-status` contains no such subquery yet still shows p50 7695ms: it is queuing behind
  those write transactions and behind the process-wide `_db_lock` that serializes all 8 gunicorn
  threads.
- `/api/thumbnail/<port>` shows p50 24ms but p95 3046ms — a single-row read is fast; the tail is
  time spent queued behind the above.

**Relationship to the phase's own recorded debt.** `D-DEBT-06-01` (deferred `_db_lock` narrowing)
and threat `T-06-24` deliberately left `_db_lock` untouched this phase. That decision is not the
defect, but it is the amplifier: the lock converts one slow reader into a whole-process stall.
The primary defect is the column-order/overflow interaction above, which is independent of the lock.

Note also that OPS-03 relocated thumbnail blobs out of `services` specifically to get them off the
hot path. The relocation moved the bytes but the correlated subquery reintroduced the cost on the
read path, so the intended benefit was not realized.

**Status: hypothesis, not yet measured on hardware.** Derived from schema, query shape, and the
observed idle-CPU stall signature. Confirmation command is recorded with the gap.

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
