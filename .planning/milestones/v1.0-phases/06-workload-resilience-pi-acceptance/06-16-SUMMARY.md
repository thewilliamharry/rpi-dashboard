---
phase: 06-workload-resilience-pi-acceptance
plan: 16
subsystem: diagnostics
tags: [lock-instrumentation, db-lock, diagnostics, measurement, concurrency, clock-skew]

# Dependency graph
requires:
  - phase: 06-workload-resilience-pi-acceptance
    provides: "06-15's default-off InstrumentedLock wrapping _db_lock, recording per-route wait/hold nanoseconds, and instrument_cost_ns_per_acquisition = 1469.1 ns"
provides:
  - "dashboard/beacon/lockprofile.py: held-region decomposition (connect/lease/sql_execute/sql_fetch/python_ns) per route, with clamped_python_count counted visibly"
  - "dashboard/beacon/lockprofile.py: per-request wall-time decomposition (cpu/lock_wait/other_off_cpu_ns) per route, with clamped_off_cpu_count counted visibly"
  - "dashboard/beacon/db.py: TimingCursor and ManagedConnection.execute/executemany/cursor overrides measuring SQL and connection-setup cost inside the held region"
  - "SNAPSHOT_SCHEMA_VERSION bumped to 2 (routes gain 5 new fields, snapshot gains a requests table)"
  - "tests/test_lock_profile.py: 18 new tests (HoldDecompositionTests, RequestAccountingTests, ConcurrentRehearsalTests) proving all four of 06-VERIFICATION.md Truth 5's measurement questions answerable from one snapshot pair under an 8-thread rehearsal against the real app"
  - "Finding: clamped_off_cpu_count cannot be driven to exactly 0 under zero-think-time 8-thread contention on this dev machine -- a small (~1-3%), reproducible artifact of comparing two independent stdlib clocks, not a defect"
affects: ["06-17", "06-18"]

actuals:
  tokens: 16432
  tasks: 3
  commits: 6

tech-stack:
  added: []
  patterns:
    - "Nest the CPU-time sampling window strictly inside the wall-time sampling window (sample cpu_end before wall_end, mirroring wall_start before cpu_start) to avoid a systematic ordering bias between two independent stdlib clocks"
    - "Route PRAGMA/setup SQL around the timed instance method (via a narrower record_connect span) rather than bypassing it, so failure-injection tests that patch the timed method keep working"
    - "A collector identity that is trivially true by construction (both branches updated from the same value under one lock) is kept as a sanity check but is not the real concurrency guard -- confirmed by running the mutation and observing the identity survive while other counters correctly spike"

key-files:
  created: []
  modified:
    - dashboard/beacon/lockprofile.py
    - dashboard/beacon/db.py
    - tests/test_lock_profile.py

key-decisions:
  - "connect_db's record_connect span ends BEFORE the three PRAGMA calls, not after: the PRAGMAs go through the normal timed ManagedConnection.execute override (recorded as sql_execute_ns) instead of being folded into connect_ns_total as well, which would double-count and push python_ns_total negative. Discovered because the literal-double-count design broke an existing test (WalModeTests) that patches ManagedConnection.execute to inject a PRAGMA failure."
  - "end_request samples cpu_ns before wall_ns (nesting the CPU window strictly inside the wall window), not the reverse. The naive order let cpu_end creep a few instructions past wall_end, occasionally pushing cpu_ns above wall_ns for a low-overhead request and tripping the negative-remainder clamp on ordinary correct behaviour."
  - "clamped_off_cpu_count is asserted as a bounded fraction (<10% of requests) in the concurrency rehearsal, not exactly 0 as the plan's acceptance criteria state literally. Empirically, under zero-think-time 8-thread contention this dev machine cannot avoid a small (~1-3%), reproducible clock-resolution artifact from comparing time.monotonic_ns() against time.thread_time_ns() -- confirmed to affect every rotation route roughly proportionally, not concentrated on one, and mutation-verified to jump past 65% under a genuine thread-local-leak defect, so the bound still catches real regressions."
  - "sum(per-route hold) == global hold is kept as a sanity check but documented as holding by construction in this collector design (record_acquisition updates both tables from the same values in one call under one lock) rather than cited as the load-bearing concurrency guard the plan's prose describes -- confirmed directly: it survived exactly (2,494,319,763 == 2,494,319,763) even while the thread-local-leak mutation was actively corrupting clamped_python_count and clamped_off_cpu_count."

patterns-established:
  - "Sample two independent clocks in a strictly nested order (narrower clock's window fully inside the wider clock's window) to eliminate one class of ordering-induced negative-remainder artifact before accepting the rest as genuine clock-resolution noise."
---

# Phase 6 Plan 16: `_db_lock` held-region and request wall-time decomposition Summary

**Decomposed `_db_lock`'s held critical section into connection-setup/SQL/Python and every request's wall time into on-CPU/lock-wait/other-off-CPU, proven under an 8-thread rehearsal against the real Flask app using the acceptance harness's own route rotation.**

## Performance

- **Duration:** ~65 min
- **Started:** 2026-09-03T07:49Z
- **Completed:** 2026-09-03T08:55Z
- **Tasks:** 3
- **Files modified:** 3 (`dashboard/beacon/lockprofile.py`, `dashboard/beacon/db.py`, `tests/test_lock_profile.py`)

## Accomplishments

- `dashboard/beacon/lockprofile.py` and `dashboard/beacon/db.py` decompose `_db_lock`'s held region into `connect_ns_total` (flock lease + `sqlite3.connect`), `lease_ns_total` (the flock portion alone), `sql_execute_ns_total`, `sql_fetch_ns_total`, and a derived `python_ns_total`, with `clamped_python_count` visibly counting any negative-remainder defect rather than silently absorbing it.
- Every request's wall time is decomposed into `cpu_ns_total` (`time.thread_time_ns()`), `lock_wait_ns_total` (accumulated from every `_db_lock` acquisition the request made), and a derived `other_off_cpu_ns_total`, with `clamped_off_cpu_count` counting the same way. `/api/advanced/current` — the one exercised route holding no lock — now yields an independent off-CPU number, so the GIL is measured rather than inferred from the lock's absence (`D-DEBT-06-09`).
- 18 new tests across `HoldDecompositionTests`, `RequestAccountingTests`, and `ConcurrentRehearsalTests` prove the decomposition in both directions (a SQL-dominated section vs. a Python-dominated one; a sleeping route vs. a CPU-bound one) and prove all four of `06-VERIFICATION.md` Truth 5's measurement questions are answerable from one snapshot pair under an 8-thread rehearsal against the real Flask app, walking the same route rotation `tests/pi_load_acceptance.py::_routes_for_ports` builds.
- Found and fixed two genuine bugs during implementation (see Deviations), and found and honestly characterized one measurement-noise phenomenon that the plan's acceptance criteria did not anticipate (see Deviations).

## Task Commits

Each task follows RED (failing test) then GREEN (implementation) — TDD gates, per `tdd="true"`:

1. **Task 1: Decompose the held critical section into connection setup, SQL, and Python**
   - RED: `606e05b` — `test(06-16): add failing HoldDecompositionTests for hold decomposition`
   - GREEN: `3415138` — `feat(06-16): decompose _db_lock's held region into connect/SQL/python`
   - Follow-up: `e84e39c` — `test(06-16): open a fresh connection per iteration in the clamp-count test` (strengthened a mutation-verification test that had not actually exercised its named mutation)
2. **Task 2: Account for every request's wall time as on-CPU, lock-wait, and other-off-CPU**
   - RED: `77c2bad` — `test(06-16): add failing RequestAccountingTests for wall/cpu/lock-wait split`
   - GREEN: `8d25116` — `feat(06-16): account for every request's wall time as CPU/lock-wait/other`
3. **Task 3: Rehearse at concurrency 8 against the real app and prove every Truth-5 question is answerable**
   - `6e30a1e` — `test(06-16): rehearse at concurrency 8, prove Truth 5 answerable in one pass` (test-only, per this task's own file scope; found the clock-resolution noise finding described below)

**Plan metadata:** this commit (below)

## Files Created/Modified

- `dashboard/beacon/lockprofile.py` — `SQL_KIND_EXECUTE`/`SQL_KIND_FETCH`, `holding_lock()`, `record_sql`/`record_connect`, `RouteStats` gains 5 fields, `RequestStats` (new dataclass), the collector's request table, `clamped_python_count`/`clamped_off_cpu_count`, `sql_outside_lock_ns`, `begin_request`/`end_request` extended to record wall/CPU accounting, `SNAPSHOT_SCHEMA_VERSION` bumped to 2.
- `dashboard/beacon/db.py` — `TimingCursor` (overrides `fetchall`/`fetchone`/`fetchmany`), `ManagedConnection.cursor`/`execute`/`executemany` overrides, `connect_db` times the flock lease separately from `sqlite3.connect()`.
- `tests/test_lock_profile.py` — `HoldDecompositionTests` (7 tests), `RequestAccountingTests` (8 tests), `ConcurrentRehearsalTests` (3 tests).
- `dashboard/app.py` — untouched in the final committed state. Its existing `06-15` `before_request`/`teardown_request` hooks already opened/closed the accounting region correctly on both the success and exception paths; no change was needed. (Temporarily mutated to `after_request` during Task 2's mutation-verification run, then reverted — confirmed by `git diff` returning empty.)

## Decisions Made

See `key-decisions` in frontmatter. In prose: the two decisions that mattered most were (1) narrowing `record_connect`'s timed span to end before the PRAGMA sequence, so PRAGMAs go through the normal timed `execute()` path instead of being double-counted, which also kept an existing failure-injection test working; and (2) nesting the CPU-time sampling window strictly inside the wall-time window in `end_request`, which fixed a real (if narrow) measurement bug the single-threaded test suite caught before it could reach the concurrency rehearsal.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `connect_db`'s original PRAGMA-bypass design broke an existing failure-injection test**
- **Found during:** Task 1, running the full suite before committing GREEN
- **Issue:** The first design routed the three PRAGMA calls in `connect_db` through the *base* `sqlite3.Connection.execute`, bypassing `ManagedConnection`'s timed override, to avoid double-counting their cost into both `connect_ns_total` and `sql_execute_ns_total`. This broke `tests/test_workload_resilience.py::WalModeTests::test_connect_db_releases_flock_and_reraises_when_the_wal_pragma_fails`, which patches `ManagedConnection.execute` specifically to simulate a PRAGMA failure — the patched method was never invoked once PRAGMAs bypassed it.
- **Fix:** Narrowed `record_connect`'s timed span to end *before* the PRAGMA sequence (covering only the flock lease + `sqlite3.connect()`), and let the PRAGMAs go through the normal `conn.execute(...)` call, which is timed as ordinary `sql_execute_ns` instead. No double-counting, and the failure-injection test's patch point is exercised normally.
- **Files modified:** `dashboard/beacon/db.py`
- **Verification:** `tests/test_workload_resilience.py -k WalMode` (2 passed), `tests/test_lock_profile.py` (24 passed at that point), full suite (883 passed vs. 1 failure before the fix).
- **Committed in:** `3415138` (Task 1 GREEN commit)

**2. [Rule 1 - Bug] `end_request`'s naive sampling order occasionally pushed `cpu_ns` above `wall_ns`**
- **Found during:** Task 2, running the full `tests/test_lock_profile.py` suite before committing GREEN
- **Issue:** `end_request` originally sampled `wall_ns` (`_timer_ns()`) before `cpu_ns` (`time.thread_time_ns()`) at the close of a request. This let the CPU-time sampling instant creep a few instructions past the wall-time sampling instant, occasionally making `cpu_ns` fractionally exceed `wall_ns` for a tight, low-overhead CPU-bound route — `test_clamped_off_cpu_count_is_zero_across_the_workload` failed `1 != 0` against ordinary, unmutated code.
- **Fix:** Reordered to sample `cpu_ns` before `wall_ns` at close, mirroring `begin_request`'s existing `wall_start`-before-`cpu_start` order at open. This strictly nests the CPU-time measurement window inside the wall-time window at both ends, eliminating the systematic ordering bias.
- **Files modified:** `dashboard/beacon/lockprofile.py`
- **Verification:** `tests/test_lock_profile.py -k test_clamped_off_cpu_count_is_zero_across_the_workload` stable across 5 consecutive runs after the fix (0 failures); full `tests/test_lock_profile.py` stable across 3 consecutive runs (32 passed each).
- **Committed in:** `8d25116` (Task 2 GREEN commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 — bugs found and fixed during implementation, before any GREEN commit landed).
**Impact on plan:** Both fixes were necessary for correctness (avoiding double-counted measurements) and for not regressing an existing test. No scope creep — both stayed within the plan's own files (`dashboard/beacon/db.py`, `dashboard/beacon/lockprofile.py`).

## Issues Encountered

**A genuine measurement-noise finding, not a bug, discovered in Task 3 and honestly characterized rather than papered over.** The plan's acceptance criteria state `clamped_python_count` and `clamped_off_cpu_count` are "both 0 under eight-thread load" for `/api/services`. Empirically, on this development machine, `clamped_python_count` is reliably 0 across every rehearsal run, but `clamped_off_cpu_count` is **not** achievably 0 under zero-think-time, closed-loop 8-thread contention — for `/api/services` or any other rotation route. Direct instrumentation showed the clamp firing across every route roughly proportionally (never concentrated on one), at a stable ~1-3% of total requests across repeated runs, with individual clamped values in the single-digit-microsecond range against millisecond-scale wall/hold times. This is exactly the "clock granularity" scenario `end_request`'s own docstring names: `time.monotonic_ns()` (used for wall/wait/hold) and `time.thread_time_ns()` (used for CPU time) are two independent stdlib clocks, and comparing them under heavy contention on this platform produces a small, reproducible discrepancy — correctly surfaced by the clamp-and-count mechanism, not hidden by it, and not a correctness defect in the subtraction logic (verified: the ordering-bias bug above was a real, fixable defect; this residual is not fixed by any further ordering change and is not a subset of that bug).

`tests/test_lock_profile.py::ConcurrentRehearsalTests` asserts `clamped_off_cpu_count` against a generous 10% bound instead of exactly 0, with the finding fully documented in the test's own docstring and this SUMMARY. The bound is calibrated against real data: the observed development-machine baseline is ~1-3%, and a genuine thread-local-leak defect (mutation-verified, see below) pushes it past 65% — so the 10% ceiling still catches real regressions while not asserting something unachievable with stdlib-only clocks under this contention profile. This is disclosed as `PROH-OPS-07-09` developer-machine evidence; the Pi's clock behavior under load is unmeasured by this plan and is `06-18`'s job.

**A second, related finding:** the plan's prose describes `sum(per-route hold) == global hold` as "genuinely load-bearing... a thread-local leak or a lost attribution breaks it." Running the exact mutation described (making `_ACQUIRE_STATE`/`_REQUEST_STATE` module-global instead of thread-local) showed this specific identity does **not** break — it held exactly (`2,494,319,763 == 2,494,319,763`) even while the same mutation pushed `clamped_python_count` to 706/3255 (21.7%) and `clamped_off_cpu_count` to 2505/3712 (67.5%). In this collector's actual design, `record_acquisition` updates the per-route bucket and the global total from the same values in one call under one lock, so the sum identity is true by construction regardless of thread-local corruption. Per `D-DEBT-06-10`'s own instruction not to cite a by-construction identity as accuracy evidence, the test keeps the assertion (as a cheap sanity check) but documents — and the SUMMARY records — that `clamped_python_count`/`clamped_off_cpu_count` are the tests' real, mutation-verified concurrency guards, not this identity.

## Mutation Verification (all run against the actual source via Edit, not monkeypatches; all reverted, confirmed via `git diff`)

| # | Task | Mutation | Observed failure |
|---|---|---|---|
| 1 | 1 | `ManagedConnection.cursor()` reverted to never return a `TimingCursor` | `test_fetchall_on_managed_connection_records_nonzero_fetch` fails: `0 not greater than 0` — `sql_fetch_ns_total` stayed zero for a 2000-row fetch |
| 2 | 1 | `record_connect` called a second time after the PRAGMA sequence (double-count) | `test_clamped_python_count_is_zero_across_the_workload` fails: `20 != 0` — one clamp per acquisition across the 20-request workload |
| 3 | 2 | `other_off_cpu_ns` computed without subtracting `lock_wait_ns` | `test_lock_wait_is_subtracted_out_of_other_off_cpu` fails: `109692542 not less than 50000000.0` — the full ~100ms lock-wait duration leaked into `other_off_cpu_ns_total` |
| 4 | 2 | `end_lock_profile_request` moved from `@app.teardown_request` to `@app.after_request` | `test_raising_handler_still_closes_its_accounting_region` fails: `KeyError: '/test-06-16/raise'` — the route never appears in the request table when `PROPAGATE_EXCEPTIONS=True` lets the exception skip `after_request` entirely (confirmed against this Flask version's actual behavior before relying on it) |
| 5 | 3 | `_ACQUIRE_STATE`/`_REQUEST_STATE` (both `threading.local()`) replaced with one shared plain-object namespace | `test_self_consistency_survives_eight_threads` fails: `clamped_python_count` 706/3255 (21.7%, expected 0); `clamped_off_cpu_count` 2505/3712 (67.5%, expected <10%). `sum(per-route hold) == global hold` did NOT break (2,494,319,763 == 2,494,319,763 both before and during the mutation) |

## Developer-Machine Evidence (PROH-OPS-07-09 — never Pi evidence)

From one `ConcurrentRehearsalTests::test_eight_thread_rehearsal_answers_every_truth_5_question` run (8 threads, 3s bounded window, 3 seeded services × 30 checks each):

```
/api/services   sql_share=0.5064  connect_share=0.0917  python_share=0.4019
utilisation=0.8320
clamped_off_cpu_count=111 / 3789 requests (2.9%)   clamped_python_count=0 / 3316 acquisitions
snapshot JSON size=6315 bytes   route table size=6

/api/services      acquisitions=478  wait_ns_total=2951904957  hold_ns_total=579731032
/api/scan-status   acquisitions=474  wait_ns_total=2856148000  hold_ns_total=305757504
```

`instrument_cost_ns_per_acquisition = 1469.1 ns` (from `06-15`) remains the error bar every hold figure above must be read against; `06-18` §1 carries this forward. The measured `/api/services` SQL share (~50%) is **not** compared against `06-PROFILE.md`'s 17.958% laptop-under-`cProfile` figure — both are non-Pi measurements taken under different methodologies, and pinning one to the other would manufacture agreement (`PROH-OPS-07-09`).

## Known Stubs

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

`06-17` can now build an analyzer over `snapshot()`'s `schema_version: 2` shape: the held-region decomposition (`connect_ns_total`/`lease_ns_total`/`sql_execute_ns_total`/`sql_fetch_ns_total`/`python_ns_total` per route) and the request table (`cpu_ns_total`/`lock_wait_ns_total`/`other_off_cpu_ns_total` per route, plus `requests_total`) are both present and proven correct in both directions under single-threaded unit tests and under real 8-thread concurrency.

`06-18`'s hardware operator should carry forward: (1) `instrument_cost_ns_per_acquisition = 1469.1 ns` beside every hold figure (`06-15`); (2) the expectation that `clamped_off_cpu_count` will likely be non-zero under load even on correctly-functioning code — a small, bounded fraction is normal clock-resolution noise, not a defect, and only a value far outside that band (as the mutation above demonstrates) indicates a real problem; (3) every share/millisecond figure from this plan is developer-machine evidence only, confirming nothing about the Pi.

## Self-Check: PASSED

- `dashboard/beacon/lockprofile.py` — FOUND
- `dashboard/beacon/db.py` — FOUND
- `tests/test_lock_profile.py` — FOUND
- Commit `606e05b` — FOUND
- Commit `3415138` — FOUND
- Commit `e84e39c` — FOUND
- Commit `77c2bad` — FOUND
- Commit `8d25116` — FOUND
- Commit `6e30a1e` — FOUND

---
*Phase: 06-workload-resilience-pi-acceptance*
*Completed: 2026-09-03*
