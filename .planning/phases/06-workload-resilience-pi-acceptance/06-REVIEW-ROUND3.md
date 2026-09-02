---
phase: 06-workload-resilience-pi-acceptance
round: 3
scope: "plans 06-11 .. 06-13 (git diff f672832..HEAD -- dashboard/ tests/)"
reviewed: 2026-09-02T00:00:00Z
depth: deep
files_reviewed: 8
files_reviewed_list:
  - dashboard/app.py
  - dashboard/beacon/maintenance.py
  - dashboard/beacon/repositories.py
  - tests/pi_load_acceptance.py
  - tests/services_route_profile.py
  - tests/test_services_route_scaling.py
  - tests/test_workload_resilience.py
  - tests/test_module_boundaries.py
findings:
  critical: 3   # 1 Critical + 2 High -- blocker tier
  warning: 5    # Medium tier
  info: 3       # Low tier
  total: 11
status: issues_found
---

# Phase 6 Round 3: Code Review Report

**Reviewed:** 2026-09-02
**Depth:** deep (cross-file, with executed differential/repro harnesses)
**Files Reviewed:** 8
**Status:** issues_found

Severity headings use the requested Critical / High / Medium / Low scale.
Frontmatter maps them to the pipeline's tiers: Critical+High → `critical`
(blocker), Medium → `warning`, Low → `info`.

## Summary

Three of the four risk concentrations named in the review brief came back
clean under direct testing; the fourth did not, and the failure is worse
than the brief anticipated because it lands outside the module the round
was refactoring.

The memoization work in `dashboard/beacon/maintenance.py` is correct. The
`(window, local date, timezone)` key is genuinely the granularity at which
`_local_occurrence_epochs` is invariant — verified analytically and by
differential execution across DST-transition, 30-minute-DST and 45-minute-offset
zones (details under *Verified Clean*). The `cache=None` default genuinely
preserves prior behavior for every non-opted-in call site.

The problem is `dashboard/app.py`. Removing the duplicate offline-interval
read collapsed two independent `service_checks` reads into one, and the
`LIMIT` that used to bound only the *offline-interval* read was moved onto
the survivor — which is also the read that feeds `_uptime_summary`. Before
this round, `api_services`'s check sweep was unbounded and `uptime_pct` was
always correct. It is now bounded by `_OFFLINE_INTERVALS_BULK_ROW_LIMIT`,
truncated from the *newest* end, and the profile already establishes that
this limit is reached at the 8-service/8-day deployment shape. I reproduced
a service's reported uptime moving from **99.998% to 0.002%** — and, at a
slightly tighter cut, to `None` with all 168 buckets unknown — purely from
the new `LIMIT`.

This is not a re-report of the recorded `_OFFLINE_INTERVALS_BULK_ROW_LIMIT`
debt. That debt is scoped to offline-interval reconstruction, whose
truncation behavior this round did not change (same constant, same ordering,
same `start_ts`, same query it replaced). What is new is that the same
truncation now also corrupts `uptime_pct` and `uptime_buckets`, which were
previously immune. That is precisely the "made the debt's consequences worse
or newly reachable" case the brief asked to be reported.

Two further blockers sit in the harness and the maintenance helper: a
`id(row)`-keyed cache whose safety argument is prose-only and demonstrably
false in general, and a priming regression in `pi_load_acceptance.py` that
silently disables CPU baseline priming for `--self-test` runs while the same
round adds a report field advertising that priming happened.

---

## Critical

### CR-01: `/api/services` uptime percentages and buckets are now silently truncated by the row limit

**File:** `dashboard/app.py:2820-2833` (query at 2824-2825), constant docstring at `dashboard/beacon/repositories.py:1095-1105`

**Issue.**
Pre-06-13 this route issued two independent reads of `service_checks`:

```python
# before (f672832) -- no LIMIT
"SELECT ts, port, online FROM service_checks "
"WHERE port IN (...) AND ts >= ? ORDER BY ts ASC"
```

feeding `checks_by_port` → `_uptime_summary`, plus a *separate*,
`_OFFLINE_INTERVALS_BULK_ROW_LIMIT`-bounded read inside
`read_service_offline_intervals_by_port` feeding offline intervals. Only the
second was capped, so the recorded truncation debt could only corrupt
maintenance attribution.

06-13 deleted the second read and moved its cap onto the survivor:

```python
f"WHERE port IN ({placeholders}) AND ts >= ? "
f"ORDER BY port ASC, ts ASC LIMIT ?",
(*ports, start_ts, beacon_repositories._OFFLINE_INTERVALS_BULK_ROW_LIMIT),
```

`checks_by_port` is now capped for the first time, and `uptime_pct` /
`uptime_buckets` are derived from it. Two compounding factors make the
resulting number wrong rather than merely incomplete:

1. **Truncation direction.** `ORDER BY port ASC, ts ASC` keeps each port's
   *oldest* rows and discards its *newest*. For a trailing-7-day uptime
   metric that is the worst possible direction: `_uptime_summary` extends
   the last surviving state forward to `now`, so a service that was offline
   at the cut point and has since recovered reports as offline for the
   entire tail.
2. **The route's own comment understates the at-limit shape.** It claims
   "only the highest-numbered port(s) lose their newest in-window rows".
   With a global `LIMIT` over a `port ASC` ordering, exactly one port loses
   its newest rows — every port *past* the cut loses **all** of its rows and
   is reported as having no history at all.

**Reproduced.** Two services, port 9002 with an early offline transition and
a later recovery, run through `app.test_client().get('/api/services')`
unmodified except for patching the limit constant:

```
# limit 32 -- port 9002 loses only its recovery row
port=9002 uptime_full=99.998  uptime_trunc=0.002    buckets_unknown 0 -> 0
# limit 30 -- port 9002 loses every row
port=9002 uptime_full=99.998  uptime_trunc=None     buckets_unknown 0 -> 168
```

The `0.002%` case is the dangerous one: the operator is shown a confident,
well-formed, catastrophically wrong availability figure with a fully
populated 168-bucket bar. There is no signal in the response that the
underlying read was truncated.

**Reachability.** 06-PROFILE.md establishes the limit is already reached at
the profiled 8-service / 8-day shape, dropping ~21% of in-window rows. At
~3,160 rows/service the 20,000-row budget covers ~6.3 of 8 ports, so at the
*documented deployment shape* one port reports a wrong uptime and one
reports no uptime at all.

**Fix.** Any of the following, in decreasing order of preference:

```python
# 1. Bound per-port, and shed the OLDEST rows, not the newest -- the only
#    direction under which a trailing-window metric degrades gracefully.
all_checks = conn.execute(
    f"SELECT ts, port, online FROM ("
    f"  SELECT ts, port, online, "
    f"    ROW_NUMBER() OVER (PARTITION BY port ORDER BY ts DESC) AS rn "
    f"  FROM service_checks WHERE port IN ({placeholders}) "
    f"    AND ts >= ? AND ts <= ?"
    f") WHERE rn <= ? ORDER BY port ASC, ts ASC",
    (*ports, start_ts, now, per_port_row_limit),
).fetchall()
```

2. Or keep the reads separate again: leave the uptime sweep unbounded (or
   bounded by its own, uptime-appropriate rule) and reintroduce the bounded
   read only for interval reconstruction. This sacrifices the deduplication
   win but restores correctness.

3. **Minimum viable, if neither lands this round:** make truncation
   self-announcing rather than silent. `len(all_checks) == LIMIT` means the
   cap was hit; in that case emit `uptime_pct: None` and `[-1] * 168` for
   every port at or past the cut. A visible "unknown" is honest; `0.002%` is
   not.

---

## High

### CR-02: `_window_from_row_cached` keys on `id(row)` while holding no reference to `row`

**File:** `dashboard/beacon/maintenance.py:132-171` (key construction at 166, store at 170)

**Issue.**
The cache stores `id(row) -> Window` and drops the row. CPython reuses `id()`
values immediately after an object is freed, and dict objects of identical
shape come straight off the freelist, so the key is not stable for any caller
that does not independently keep the row alive.

The docstring asserts safety by construction:

> "there is no window in which a stale id could be reused for a different
> row's content before this cache is discarded"

That claim is false in general. It is true only of `api_services`, and only
incidentally — `windows_by_port` happens to hold every row dict for the
duration of the request. Nothing in `maintenance.py` enforces it: no
reference is held, no assertion is made, and no test covers it.

**Reproduced.** Calling `_window_from_row_cached` with a shared cache and
per-call row dicts:

```
id collisions with different content: 1998 (of 2000)  ->  wrong Window returned: 1998
```

Every one of those returns a `Window` carrying another row's `start_minute`,
`duration_minutes`, `weekdays` and `grace_minutes`.

**Failure scenario.** The next obvious optimization is threading the same
cache through `dashboard/beacon/diagnosis.py` — it already calls
`maintenance.coverage()` at :232 and :240 and loops
`attributed_downtime_seconds()` per port at :653, which is exactly the
repetition this round's memo exists to kill. `diagnosis.py:240` builds a
fresh single-element list per row. The moment someone adds `cache=` there
and a row's lifetime shortens, `availability`, `maintenance_until` and
`maintenance_attributed_seconds` start reporting one service's maintenance
window applied to a different service — silently, with no exception and no
log line. The failure mode is a wrong operator-visible number, which is the
same class of failure this round was commissioned to avoid.

**Fix.** One line, zero measurable cost, removes the hazard entirely by
pinning the referent for the cache's lifetime:

```python
key = ('window', id(row))
entry = cache.get(key)
if entry is not None:
    return entry[1]
window = window_from_row(row)
cache[key] = (row, window)   # holding `row` makes its id un-recyclable
return window
```

(Note `entry is not None` rather than `key in cache` — the tuple is always
truthy even when `window` is `None`, so the malformed-row memo still works.)
Add a regression test that calls the helper with a shared cache and
deliberately short-lived row dicts and asserts each result matches
`window_from_row` on the same row.

### CR-03: `_prime_cpu_percent` no longer primes `self_test` targets, and the new provenance block reports that as "primed"

**File:** `tests/pi_load_acceptance.py:575-600` (rewritten priming), `:542-570` (`_live_role_processes` early return at :558), `:832` (`primed_pid_count`)

**Issue.**
The old priming loop called `cpu_percent(interval=None)` on every process
`_live_role_processes` returned, including the `self_test` branch:

```python
for proc in _live_role_processes(target):
    try: proc.cpu_percent(interval=None)
    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
```

The rewrite delegates priming entirely to `_cached_handle`'s insert path and
triggers it by calling `_live_role_processes(target)` for its side effect.
But `_live_role_processes` returns *before* reaching `_cached_handle` for
self-test targets:

```python
if target.method == 'self_test':
    return list(target.processes)      # never touches _cached_handle
```

so nothing is primed and `target.handles` stays empty.

**Reproduced.**

```
self_test prime cpu_percent calls: 0   handles: {}
```

**Consequences.**
1. A `--self-test` / smoke run's first sampling tick now reads `0.0` CPU for
   both roles because no baseline exists — a regression against the previous
   behavior, in the run mode used by CI (`run_self_test()` is called directly
   by two of this round's own new tests).
2. `cpu_sampling.primed_pid_count` reports `0` for smoke runs, and
   `all_samples_zero` becomes more likely to be `True`. The provenance block
   added in this same round to make a broken CPU column *self-announcing*
   now emits the broken-measurement signature for a run mode this round
   itself broke. `test_the_report_carries_cpu_sampling_provenance_for_every_role`
   only asserts the key set, never the values, so it passes.

**Fix.** Route the self-test branch through the same cache, so one code path
serves both methods:

```python
def _live_role_processes(target):
    if target.method == 'self_test':
        return [_cached_handle(target, proc) for proc in target.processes]
    ...
```

and extend the provenance test to assert `primed_pid_count > 0` for a
resolved role.

---

## Medium

### WR-01: a process discovered mid-run gets two `cpu_percent` calls in the same tick

**File:** `tests/pi_load_acceptance.py:530-538` (prime on insert) and `:621-626` (read in the sampling tick)

**Issue.** `_cached_handle` primes on insert; `_sample_resources_tick` then
immediately reads the handle it just received. For a process already present
at run start that is correct (prime happens during `_prime_cpu_percent`, the
read happens on the next tick). For a process that first appears mid-run,
both happen microseconds apart in the same tick.

This directly violates the contract quoted verbatim in `_prime_cpu_percent`'s
own docstring: *"cpu_percent(interval=None) is called exactly once for
priming plus exactly once per tick — never twice per tick."*

**Reproduced** (child appears on tick 1, after priming):

```
child cpu_percent calls in the tick it first appeared: 2
```

**Failure scenario.** The second call computes `delta_proc / delta_time * 100`
over a sub-millisecond wall delta. `delta_proc` has 10 ms clock-tick
granularity on Linux, so it is usually `0` (harmless `0.0`) — but when the
sample straddles a tick boundary it is `0.01` over a `~1e-4 s` denominator,
yielding a reading in the thousands of percent. That value flows straight
into `peak_cpu_percent`, which the report presents as observed evidence and
which 06-14's hardware checkpoint is supposed to read.

**Fix.** Have `_cached_handle` record the PIDs it primed on this pass and
have `_sample_resources_tick` contribute `0.0` for them instead of calling
`cpu_percent` a second time; or drop the prime from `_cached_handle` and let
the tick's own first read be the (correctly meaningless) baseline. The
existing guard `test_cpu_percent_is_primed_once_and_read_once_per_tick` does
not cover this because every process in its fixture exists at prime time —
extend it with a child that appears after priming.

### WR-02: `primed_pid_count` reports the last tick's live PID count, not the primed count

**File:** `tests/pi_load_acceptance.py:832`

**Issue.** `'primed_pid_count': len(target.handles)` is read after the run
completes, and `_live_role_processes` prunes `target.handles` to exactly the
PID set discovered on each tick (`:565-568`). So the field is "live PIDs at
the final tick", which is a different quantity from the one its name
promises. A run that primed 6 gunicorn workers and ended with 1 surviving
reports `primed_pid_count: 1`; combined with CR-03, a self-test run reports
`0` while having sampled two roles.

The whole point of the field is provenance for a human reading the report at
the hardware checkpoint. A provenance field that reports a plausible wrong
number is worse than an absent one.

**Fix.** Track priming separately and never prune it:

```python
# ResourceTarget
primed_pids: set = field(default_factory=set)
# _cached_handle, on the insert path
target.primed_pids.add(pid)
# report
'primed_pid_count': len(target.primed_pids),
```

Or rename the field to `live_pid_count_at_end` and say so.

### WR-03: absolute wall-clock thresholds in a unit test will fail on the target hardware

**File:** `tests/test_services_route_scaling.py:797-808`

**Issue.**

```python
self.assertLess(bucket['small_tottime_ms'], 100.0, ...)
self.assertLess(bucket['large_tottime_ms'], 400.0, ...)
```

The docstring records the shipped measurement as ~30 ms / ~133 ms, so the
margin is roughly 3x. This entire phase targets Raspberry Pi hardware, which
is commonly 5-15x slower per core than the machine those figures were taken
on, and 06-14 is an on-hardware checkpoint. This guard will go red on the
machine it exists to protect, for correct code, and the failure message will
tell the reader that `maintenance_coverage` "regressed toward the unmemoized
baseline" when nothing regressed.

A guard that fails for the wrong reason on the target platform trains people
to ignore it — the same failure mode 06-VERIFICATION.md flagged elsewhere in
this phase.

**Fix.** Assert a hardware-independent ratio measured in the same run, so
the control and the treatment share a CPU:

```python
memoized = self._small_growth_report()['buckets']['maintenance_coverage']
with mock.patch.object(beacon_maintenance, '_MEMO_ENABLED', False):   # or an
    unmemoized = self._small_growth_report()['buckets']['maintenance_coverage']
self.assertLess(
    memoized['large_tottime_ms'], unmemoized['large_tottime_ms'] / 4.0,
    ...,
)
```

If a same-run control is genuinely infeasible, gate the absolute thresholds
behind an environment marker so they only assert on the machine class they
were calibrated on.

### WR-04: no test exercises reconstruction or uptime from a *truncated* row set

**File:** `tests/test_services_route_scaling.py:488-543` (`OfflineIntervalsFromPointsTests`), `:352-419` (route bound guard)

**Issue.** The equivalence class the SUMMARY leans on builds `points_by_port`
with an explicitly unlimited query:

```python
f"WHERE port IN ({placeholders}) AND ts >= ? AND ts <= ? "
f"ORDER BY port ASC, ts ASC",          # :521-524 -- no LIMIT
```

So all five shapes prove equivalence only for the complete row set. The
partial row set — the condition the route now actually operates in at the
profiled 8-service/8-day shape — is never exercised.

The one test that does patch the limit,
`test_the_route_bounds_checks_by_port_rows_through_the_limit_constant`,
patches it to `5` against 20 rows and then asserts only
`response.status_code == 200` and that the string `LIMIT 5` appears in the
traced SQL. It never inspects the response body. That is exactly how CR-01
shipped green: the test proves the bound *exists* and says nothing about
whether the answer under that bound is correct.

**Fix.** Add a truncation-shape case to the same class that patches the limit
so a known port loses its newest rows, and asserts the route's
`uptime_pct`/`uptime_buckets`/`maintenance_attributed_seconds` against the
*intended* at-limit contract — whatever CR-01 settles that contract to be.
Pin the decision in a test rather than in a comment on a constant.

### WR-05: `app.py` reaches across the module boundary into a private repository constant, whose docstring is now stale

**File:** `dashboard/app.py:2825`, constant and docstring at `dashboard/beacon/repositories.py:1095-1105`

**Issue.** `beacon_repositories._OFFLINE_INTERVALS_BULK_ROW_LIMIT` is a
leading-underscore module member consumed from the application edge module.
This repo maintains an explicit boundary suite (`tests/test_module_boundaries.py`),
which this reach-through evades — and this round *added* a boundary test to
that file, so the discipline is actively being invested in.

Separately the constant's docstring no longer describes its own effect:

> "In-window rows are ordered (port ASC, ts ASC), so if the limit is reached,
> only the highest-numbered port(s) in the request lose in-window rows ...
> and **that port's reconstructed intervals** may under-report its true
> offline time"

The constant now also bounds the uptime sweep (CR-01), and the consequence is
no longer confined to reconstructed intervals nor to under-reporting.

**Fix.** Promote it to a public name (`OFFLINE_INTERVALS_BULK_ROW_LIMIT`, or a
narrow accessor such as `service_checks_row_limit()`), have `app.py` import
that, and rewrite the docstring to name both consumers and both consequences.
Consider adding a boundary test asserting `app.py` references no
underscore-prefixed `beacon_repositories` member — `app.py:2123` and `:2198`
(`beacon_worker_main._discovery_outcome_verdict`) show the pattern is already
spreading.

---

## Low

### IN-01: the row-limit budget is now spent on rows with `ts > now`

**File:** `dashboard/app.py:2822-2833`

**Issue.** The removed query bounded the upper edge in SQL
(`AND ts >= ? AND ts <= ?`). The replacement bounds only the lower edge in
SQL and applies the upper bound in Python, *after* `LIMIT` has already been
applied:

```python
f"WHERE port IN ({placeholders}) AND ts >= ? "        # no upper bound
...
    if ts <= now:                                      # filtered post-LIMIT
        points_by_port[row['port']].append(...)
```

Any future-dated `service_checks` row — worker clock skew, an NTP step, a
manual insert — consumes limit budget and displaces a real in-window row,
compounding CR-01. It also silently enters `checks_by_port` (which is *not*
filtered by `ts <= now`), though `_uptime_summary` discards it downstream.

**Fix.** Restore the SQL upper bound: `AND ts >= ? AND ts <= ?` with `now`,
and drop the redundant Python filter.

### IN-02: `_local_occurrence_epochs` is no longer lazy, including on the `cache=None` path

**File:** `dashboard/beacon/maintenance.py:223-252`

**Issue.** The docstring states `cache=None` "preserves the previous
unmemoized behavior exactly". It preserves the *values*, not the evaluation
strategy: the walk now accumulates into `occurrences` and the function does
not yield anything until the entire `MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS + 1`
day walk has completed, for cached and uncached callers alike.

No current caller breaks out early (`coverage()` at :270 and
`_covering_boundaries()` at :539 both drain fully), so nothing behaves
differently today. But the claim as written is inaccurate, and it silently
removes early exit as an option for a future caller who reads the docstring
and believes the generator is still incremental.

**Fix.** Either restore a genuinely lazy path when `cache is None`, or
narrow the docstring claim to "produces the same sequence of values" and note
that the walk is now eager.

### IN-03: both self-test roles share one `psutil.Process` object, which the new provenance flag now advertises as broken measurement

**File:** `tests/pi_load_acceptance.py:489-497`

**Issue.** Pre-existing and unchanged this round — flagged only because this
round makes it newly visible. `self_process = psutil.Process()` is evaluated
once outside the dict comprehension, so `worker` and `web` hold the *same*
object. `_sample_resources_tick` iterates roles and calls
`cpu_percent(interval=None)` on that shared object twice per tick, so the
second role sampled always reads ~0.0 over a microsecond delta.

Combined with CR-03, a smoke run's `web` (or `worker`) role will reliably
report `all_samples_zero: true` — the exact "broken measurement" signature
the new `cpu_sampling` block was added to surface, arising from the harness
rather than from the deployment. Whoever reads 06-14's report needs to know
this is structural in self-test mode.

**Fix.** Construct a separate `psutil.Process(os.getpid())` per role inside
the comprehension, and note in `cpu_sampling` that `all_samples_zero` is not
meaningful for `method == 'self_test'`.

---

## Verified Clean

Stated plainly rather than padded: three of the four brief-nominated risks
did not yield a finding, and I tested them rather than eyeballing them.

**1. The `_local_occurrence_epochs` memo key is correct.** The claim that the
result is invariant per `(window, the local date now_epoch resolves to, tz)`
holds:

- Aware-datetime arithmetic in CPython is field-based (wall clock), not
  instant-based, so `(now_local - timedelta(days=n)).date()` is exactly
  `now_local.date() - n days` for every `n`, independent of time-of-day and
  independent of any DST transition inside the span. The candidate-date set
  is therefore a pure function of the date already in the key.
- Every candidate epoch is then built from `candidate_date` plus
  `window.start_minute` alone; the fold/gap round-trip check consults only
  the candidate. `now_epoch` does not appear in the loop body.
- `coverage()` applies the `start_epoch <= now_epoch < grace_end` test
  *outside* the memo (:271-275), so the instant-sensitive part is never
  cached.
- Midnight-spanning requests and `MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS`
  boundaries are handled correctly precisely *because* the date is a key
  component — two epochs either side of local midnight get different keys and
  different (correct) walks.

Executed differential test: 2,000 randomized `Window`s × 5 timezones
(`America/New_York`, `Australia/Lord_Howe` (30-minute DST), `Pacific/Chatham`
(45-minute offset), `UTC`, `Asia/Kolkata`) × 8 epoch offsets straddling
midnight and DST gap/fold instants, comparing cached against uncached output;
plus 500 randomized `coverage()` and `attributed_downtime_seconds()` pairs
cached-vs-uncached. **Zero mismatches.**

**2. Cache lifetime and scope are correct.**
`maintenance_occurrence_cache` (`app.py:2871`) is a function-local dict created
inside the request handler, passed only by keyword, and never stored on
`SETTINGS`, a module global, the connection, or `g`. It dies with the request.
The two key namespaces cannot collide (`('window', int)` 2-tuples vs
`(Window, date, str)` 3-tuples). `cache.get(...) is not None` correctly
distinguishes an empty-list memo from a miss; `key in cache` correctly
retrieves a memoized `None` for a malformed row. Grep confirms `cache=` is
passed at exactly two call sites, both in `api_services` — `app.py:950`,
`diagnosis.py:232`, `diagnosis.py:240` and `diagnosis.py:653` all take the
`None` default and are byte-for-byte unaffected. No cross-request, cross-service
or module-state sharing exists.

**3. `offline_intervals_from_points_by_port` is a faithful extraction.**
`read_service_offline_intervals_by_port` passes
`ports=set(boundary_by_port) | set(points_by_port)` while `api_services`
passes the full `ports` list; these are equivalent because a port with
neither a boundary nor points yields `[]` from
`_offline_intervals_from_points` and is dropped by the `if intervals:` filter.
`_offline_intervals_from_points` itself is untouched, so the route's
reconstruction cannot drift from the single-port oracle *for a given row set*.
The `ts <= now` Python filter reproduces the removed query's `AND ts <= ?`
(subject to IN-01). **Offline-interval output is unchanged by this round** —
the truncation behavior is the same constant, the same `ORDER BY port ASC, ts ASC`,
the same `start_ts` as the query it replaced. The recorded
`_OFFLINE_INTERVALS_BULK_ROW_LIMIT` debt is neither worsened nor newly
reachable *for offline intervals*; CR-01 is about the uptime path, which was
previously outside that debt's blast radius entirely.

**4. No injection surface introduced.** Both new/changed SQL statements build
their f-string only from `','.join('?' * len(ports))`. Every value — the ports,
`start_ts`, and the `LIMIT` itself — is parameter-bound. No user-controlled
string reaches the SQL text.

---

_Reviewed: 2026-09-02_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
