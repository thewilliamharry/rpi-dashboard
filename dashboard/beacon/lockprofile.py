"""Diagnostic instrumentation for ``_db_lock``: per-route wait/hold nanoseconds.

This is the round-4 diagnostic tracer for `06-VERIFICATION.md` Truth 5's first
`missing:` item: the measurement that converts the `_db_lock` attribution from
strong inference (`06-DEBT.md` D-DEBT-06-09) into direct evidence, or refutes
it. It wraps the lock object at its declaration -- `dashboard/app.py:127` --
rather than editing any of the 28 `with _db_lock` call sites, so `_db_lock`'s
**scope** is provably unchanged (`06-CONTEXT.md` D-01, `PROH-OPS-04-02`;
pinned by `tests/test_lock_profile.py::LockScopePreservationTests`).

Stdlib-only (`dataclasses`, `threading`, `time`) and imports nothing from the
`beacon` package -- `dashboard/beacon/db.py` will import this module in
`06-16`, so a reverse edge here would create an import cycle.

``record_acquisition`` deliberately runs after ``raw.release()`` inside
``InstrumentedLock.__exit__``/``release``: recording the acquisition -- taking
the collector's own lock and updating counters -- while still holding
``_db_lock`` would inflate every measured hold by the instrument's own cost,
which is precisely the distortion this round exists to avoid measuring
(`D-DEBT-06-10`).

``LockProfileCollector.snapshot()`` holds its own lock only long enough to
take a per-route shallow copy of the scalar counters and histogram bucket
lists; it does no further work under that lock. This bounds how long a
concurrent ``/api/diagnostics/lock-profile`` poll can contend with
``record_acquisition`` for the collector's own internal lock (`T-06-77b`) --
a poller cannot serialize behind formatting work that never happens while
the lock is held.
"""

import dataclasses
import threading
import time


# Lets 06-17's analyzer refuse a snapshot shape it does not understand.
# Bumped to 2 in 06-16: RouteStats gains connect/lease/sql_execute/sql_fetch/
# python fields and the snapshot gains a request table and clamp counters.
SNAPSHOT_SCHEMA_VERSION = 2

# The two SQL buckets, matching 06-PROFILE.md's own sql_execute / sql_fetch
# split.
SQL_KIND_EXECUTE = 'sql_execute'
SQL_KIND_FETCH = 'sql_fetch'

# The single switch every hot path checks first. Flipped to True by install().
ENABLED = False

# Cardinality bound on the per-route table -- keeps collector memory constant
# regardless of run duration, no matter how many distinct route labels a run
# exercises.
MAX_TRACKED_ROUTES = 64

# Bucket acquisitions land in once MAX_TRACKED_ROUTES is reached.
OVERFLOW_ROUTE_LABEL = '<overflow>'

# Bucket for acquisitions with no Flask request context (startup, background
# threads).
NO_REQUEST_ROUTE_LABEL = '<no-request>'


def _log_spaced_edges_ns(start_ns, end_ns, bucket_count):
    """Fixed, log-spaced upper edges in nanoseconds, computed once at import.

    Fixed edges -- not a growing sample list -- so the collector's memory is
    constant, independent of run duration, and 06-17 can derive percentiles
    by subtracting two cumulative snapshots without needing a reset.
    """
    ratio = (end_ns / start_ns) ** (1.0 / (bucket_count - 1))
    edges = []
    value = float(start_ns)
    for _ in range(bucket_count):
        edges.append(int(round(value)))
        value *= ratio
    return tuple(edges)


# Roughly 10 microseconds to 10 seconds in twenty buckets, with one implicit
# overflow bucket above the last edge (index len(edges)).
WAIT_HISTOGRAM_EDGES_NS = _log_spaced_edges_ns(10_000, 10_000_000_000, 20)
HOLD_HISTOGRAM_EDGES_NS = _log_spaced_edges_ns(10_000, 10_000_000_000, 20)

# 06-16 Task 2: per-request wall/CPU histograms use the same fixed,
# log-spaced shape as the acquisition histograms above, for the same reason
# -- constant collector memory, independent of run duration.
WALL_HISTOGRAM_EDGES_NS = _log_spaced_edges_ns(10_000, 10_000_000_000, 20)
CPU_HISTOGRAM_EDGES_NS = _log_spaced_edges_ns(10_000, 10_000_000_000, 20)


def _bucket_index(value_ns, edges):
    for index, edge in enumerate(edges):
        if value_ns <= edge:
            return index
    return len(edges)


def _timer_ns():
    """The module's single timing entry point.

    Every timestamp lockprofile.py takes goes through this function, so a
    disabled-path test can count calls to it and prove zero timing work is
    performed when the diagnostic is off (`tests/test_lock_profile.py`'s
    `LockProfileInertnessTests`).
    """
    return time.monotonic_ns()


@dataclasses.dataclass
class RouteStats:
    """One route's counters plus its two fixed-edge histograms.

    06-16 adds the held-region decomposition: `connect_ns_total` (the whole
    `_acquire_lock` + `sqlite3.connect` + PRAGMA span), `lease_ns_total` (the
    `_acquire_lock` portion of that span, reported separately so contention
    on the maintenance lease is distinguishable from the rest of connection
    setup), `sql_execute_ns_total` / `sql_fetch_ns_total` (the two SQL
    buckets), and `python_ns_total` -- the remainder, `hold_ns_total` minus
    the other three, clamped at zero. That summing identity holds by
    construction and is reported for readability only; it is never cited as
    accuracy evidence (`D-DEBT-06-10`).
    """

    acquisitions: int = 0
    wait_ns_total: int = 0
    hold_ns_total: int = 0
    wait_ns_max: int = 0
    hold_ns_max: int = 0
    connect_ns_total: int = 0
    lease_ns_total: int = 0
    sql_execute_ns_total: int = 0
    sql_fetch_ns_total: int = 0
    python_ns_total: int = 0
    wait_histogram: list = dataclasses.field(
        default_factory=lambda: [0] * (len(WAIT_HISTOGRAM_EDGES_NS) + 1)
    )
    hold_histogram: list = dataclasses.field(
        default_factory=lambda: [0] * (len(HOLD_HISTOGRAM_EDGES_NS) + 1)
    )


def _copy_route_stats(stats):
    """Plain-dict, JSON-serializable copy of one RouteStats -- no encoder."""
    return {
        'acquisitions': stats.acquisitions,
        'wait_ns_total': stats.wait_ns_total,
        'hold_ns_total': stats.hold_ns_total,
        'wait_ns_max': stats.wait_ns_max,
        'hold_ns_max': stats.hold_ns_max,
        'connect_ns_total': stats.connect_ns_total,
        'lease_ns_total': stats.lease_ns_total,
        'sql_execute_ns_total': stats.sql_execute_ns_total,
        'sql_fetch_ns_total': stats.sql_fetch_ns_total,
        'python_ns_total': stats.python_ns_total,
        'wait_histogram': list(stats.wait_histogram),
        'hold_histogram': list(stats.hold_histogram),
    }


def _accumulate(stats, wait_ns, hold_ns, connect_ns, lease_ns, sql_execute_ns, sql_fetch_ns, python_ns):
    stats.acquisitions += 1
    stats.wait_ns_total += wait_ns
    stats.hold_ns_total += hold_ns
    stats.connect_ns_total += connect_ns
    stats.lease_ns_total += lease_ns
    stats.sql_execute_ns_total += sql_execute_ns
    stats.sql_fetch_ns_total += sql_fetch_ns
    stats.python_ns_total += python_ns
    if wait_ns > stats.wait_ns_max:
        stats.wait_ns_max = wait_ns
    if hold_ns > stats.hold_ns_max:
        stats.hold_ns_max = hold_ns
    stats.wait_histogram[_bucket_index(wait_ns, WAIT_HISTOGRAM_EDGES_NS)] += 1
    stats.hold_histogram[_bucket_index(hold_ns, HOLD_HISTOGRAM_EDGES_NS)] += 1


@dataclasses.dataclass
class RequestStats:
    """One route's per-request wall-time decomposition plus its two
    fixed-edge histograms.

    06-16 Task 2: every request's wall time is `cpu_ns` (this thread's own
    `time.thread_time_ns()` delta -- genuinely on-CPU) plus `lock_wait_ns`
    (accumulated from every `_db_lock` acquisition this request made) plus
    `other_off_cpu_ns` -- the remainder, `wall_ns` minus the other two,
    clamped at zero. That summing identity holds by construction and is
    reported for readability only; it is never cited as accuracy evidence
    (`D-DEBT-06-10`). `other_off_cpu_ns` also contains genuine I/O wait plus
    scheduler delay, not GIL contention alone -- the GIL's contribution is
    the EXCESS of a concurrency-8 run's value over the same route's
    concurrency-1 value, never the raw figure.
    """

    requests: int = 0
    wall_ns_total: int = 0
    cpu_ns_total: int = 0
    lock_wait_ns_total: int = 0
    other_off_cpu_ns_total: int = 0
    wall_ns_max: int = 0
    cpu_ns_max: int = 0
    wall_histogram: list = dataclasses.field(
        default_factory=lambda: [0] * (len(WALL_HISTOGRAM_EDGES_NS) + 1)
    )
    cpu_histogram: list = dataclasses.field(
        default_factory=lambda: [0] * (len(CPU_HISTOGRAM_EDGES_NS) + 1)
    )


def _copy_request_stats(stats):
    """Plain-dict, JSON-serializable copy of one RequestStats -- no encoder."""
    return {
        'requests': stats.requests,
        'wall_ns_total': stats.wall_ns_total,
        'cpu_ns_total': stats.cpu_ns_total,
        'lock_wait_ns_total': stats.lock_wait_ns_total,
        'other_off_cpu_ns_total': stats.other_off_cpu_ns_total,
        'wall_ns_max': stats.wall_ns_max,
        'cpu_ns_max': stats.cpu_ns_max,
        'wall_histogram': list(stats.wall_histogram),
        'cpu_histogram': list(stats.cpu_histogram),
    }


def _accumulate_request(stats, wall_ns, cpu_ns, lock_wait_ns, other_off_cpu_ns):
    stats.requests += 1
    stats.wall_ns_total += wall_ns
    stats.cpu_ns_total += cpu_ns
    stats.lock_wait_ns_total += lock_wait_ns
    stats.other_off_cpu_ns_total += other_off_cpu_ns
    if wall_ns > stats.wall_ns_max:
        stats.wall_ns_max = wall_ns
    if cpu_ns > stats.cpu_ns_max:
        stats.cpu_ns_max = cpu_ns
    stats.wall_histogram[_bucket_index(wall_ns, WALL_HISTOGRAM_EDGES_NS)] += 1
    stats.cpu_histogram[_bucket_index(cpu_ns, CPU_HISTOGRAM_EDGES_NS)] += 1


class LockProfileCollector:
    """Owns the per-route table and the global totals for one process."""

    def __init__(self):
        # Named distinctly from every wrapped `_db_lock` so it is never
        # confused with the lock this module instruments.
        self._collector_lock = threading.Lock()
        self._routes = {}
        self._total = RouteStats()
        self.route_overflow = False
        # 06-16: SQL issued while no thread-local `held` flag is set --
        # outside any `_db_lock` critical section. Never inflates any
        # route's held-SQL share.
        self.sql_outside_lock_ns = 0
        # A non-zero count means the measured parts (connect + sql_execute +
        # sql_fetch) exceeded the measured whole (hold_ns) for at least one
        # acquisition -- a real defect (leaked thread-local, double-counted
        # timer, misattributed SQL), never silently absorbed.
        self.clamped_python_count = 0
        # 06-16 Task 2: the per-route request table, parallel to _routes/
        # _total above but keyed by wall-time decomposition instead of
        # lock wait/hold. Cardinality-bounded the same way.
        self._requests = {}
        self._request_total = RequestStats()
        self.request_route_overflow = False
        # A non-zero count means lock_wait_ns exceeded off_cpu_ns for at
        # least one request -- the two clocks (time.thread_time_ns() and the
        # monotonic wall timer) disagreeing, or accounting leaking across
        # threads. Never silently absorbed.
        self.clamped_off_cpu_count = 0

    def record_acquisition(
        self, route_label, wait_ns, hold_ns,
        connect_ns=0, lease_ns=0, sql_execute_ns=0, sql_fetch_ns=0,
    ):
        python_ns = hold_ns - connect_ns - sql_execute_ns - sql_fetch_ns
        clamped = python_ns < 0
        if clamped:
            python_ns = 0
        with self._collector_lock:
            if clamped:
                self.clamped_python_count += 1
            stats = self._routes.get(route_label)
            if stats is None:
                if len(self._routes) >= MAX_TRACKED_ROUTES:
                    self.route_overflow = True
                    route_label = OVERFLOW_ROUTE_LABEL
                    stats = self._routes.get(route_label)
                if stats is None:
                    stats = RouteStats()
                    self._routes[route_label] = stats
            _accumulate(stats, wait_ns, hold_ns, connect_ns, lease_ns, sql_execute_ns, sql_fetch_ns, python_ns)
            _accumulate(self._total, wait_ns, hold_ns, connect_ns, lease_ns, sql_execute_ns, sql_fetch_ns, python_ns)

    def add_sql_outside_lock(self, elapsed_ns):
        with self._collector_lock:
            self.sql_outside_lock_ns += elapsed_ns

    def record_request(self, route_label, wall_ns, cpu_ns, lock_wait_ns, other_off_cpu_ns, clamped):
        with self._collector_lock:
            if clamped:
                self.clamped_off_cpu_count += 1
            stats = self._requests.get(route_label)
            if stats is None:
                if len(self._requests) >= MAX_TRACKED_ROUTES:
                    self.request_route_overflow = True
                    route_label = OVERFLOW_ROUTE_LABEL
                    stats = self._requests.get(route_label)
                if stats is None:
                    stats = RequestStats()
                    self._requests[route_label] = stats
            _accumulate_request(stats, wall_ns, cpu_ns, lock_wait_ns, other_off_cpu_ns)
            _accumulate_request(self._request_total, wall_ns, cpu_ns, lock_wait_ns, other_off_cpu_ns)

    def snapshot(self):
        # Hold the collector's own lock only long enough to copy scalar
        # counters and histogram lists (T-06-77b) -- no formatting here.
        with self._collector_lock:
            routes = {
                label: _copy_route_stats(stats)
                for label, stats in self._routes.items()
            }
            total = _copy_route_stats(self._total)
            route_overflow = self.route_overflow
            sql_outside_lock_ns = self.sql_outside_lock_ns
            clamped_python_count = self.clamped_python_count
            requests = {
                label: _copy_request_stats(stats)
                for label, stats in self._requests.items()
            }
            request_total = _copy_request_stats(self._request_total)
            request_route_overflow = self.request_route_overflow
            clamped_off_cpu_count = self.clamped_off_cpu_count
        return {
            'routes': routes,
            'lock': total,
            'route_overflow': route_overflow,
            'sql_outside_lock_ns': sql_outside_lock_ns,
            'clamped_python_count': clamped_python_count,
            'requests': requests,
            'requests_total': request_total,
            'request_route_overflow': request_route_overflow,
            'clamped_off_cpu_count': clamped_off_cpu_count,
        }

    def reset(self):
        """Return the collector to its initial state. Tests only."""
        with self._collector_lock:
            self._routes = {}
            self._total = RouteStats()
            self.route_overflow = False
            self.sql_outside_lock_ns = 0
            self.clamped_python_count = 0
            self._requests = {}
            self._request_total = RequestStats()
            self.request_route_overflow = False
            self.clamped_off_cpu_count = 0


# The one collector this process uses.
COLLECTOR = LockProfileCollector()

# Per-thread lock-acquisition timestamps (InstrumentedLock) and per-thread
# request route labels (begin_request/end_request/current_route_label) are
# kept in separate threading.local() instances -- distinct concerns, no
# shared attribute names to collide.
_ACQUIRE_STATE = threading.local()
_REQUEST_STATE = threading.local()


class InstrumentedLock:
    """Wraps a real ``threading.Lock``, timing wait and hold per acquisition.

    Implements every way a ``threading.Lock`` can legally be used --
    ``__enter__``/``__exit__``, ``acquire``/``release``, ``locked`` -- so it
    is a drop-in replacement even though all 28 current ``with _db_lock``
    call sites use only the context-manager form.
    """

    def __init__(self, raw_lock):
        self.raw = raw_lock

    def __enter__(self):
        start_ns = _timer_ns()
        self.raw.acquire()
        acquired_ns = _timer_ns()
        _ACQUIRE_STATE.acquired_ns = acquired_ns
        _ACQUIRE_STATE.wait_ns = acquired_ns - start_ns
        self._begin_held_region()
        return True

    def __exit__(self, exc_type, exc_value, traceback):
        self._release_and_record()
        return False

    def acquire(self, blocking=True, timeout=-1):
        start_ns = _timer_ns()
        acquired = self.raw.acquire(blocking, timeout)
        if acquired:
            acquired_ns = _timer_ns()
            _ACQUIRE_STATE.acquired_ns = acquired_ns
            _ACQUIRE_STATE.wait_ns = acquired_ns - start_ns
            self._begin_held_region()
        return acquired

    def release(self):
        self._release_and_record()

    def _begin_held_region(self):
        # 06-16: zeroes this thread's per-acquisition SQL/connect
        # accumulators and sets the `held` flag `holding_lock()` consults --
        # ManagedConnection.execute/executemany and TimingCursor.fetch*
        # attribute their timing here rather than to `sql_outside_lock_ns`
        # while this flag is set.
        _ACQUIRE_STATE.held = True
        _ACQUIRE_STATE.connect_ns = 0
        _ACQUIRE_STATE.lease_ns = 0
        _ACQUIRE_STATE.sql_execute_ns = 0
        _ACQUIRE_STATE.sql_fetch_ns = 0

    def _release_and_record(self):
        release_ns = _timer_ns()
        # Degenerate case: __exit__/release running on a thread with no
        # recorded acquisition (e.g. this InstrumentedLock was released
        # without going through acquire()/__enter__ on this thread) records
        # a zero wait/hold rather than raising.
        acquired_ns = getattr(_ACQUIRE_STATE, 'acquired_ns', release_ns)
        wait_ns = getattr(_ACQUIRE_STATE, 'wait_ns', 0)
        hold_ns = release_ns - acquired_ns
        connect_ns = getattr(_ACQUIRE_STATE, 'connect_ns', 0)
        lease_ns = getattr(_ACQUIRE_STATE, 'lease_ns', 0)
        sql_execute_ns = getattr(_ACQUIRE_STATE, 'sql_execute_ns', 0)
        sql_fetch_ns = getattr(_ACQUIRE_STATE, 'sql_fetch_ns', 0)
        # held is cleared before release so any SQL that races the release
        # (there should be none -- this is the same thread) attributes
        # outside the lock rather than into a region that no longer exists.
        _ACQUIRE_STATE.held = False
        # Release before record: the collector's own bookkeeping must never
        # run inside _db_lock's critical section.
        self.raw.release()
        COLLECTOR.record_acquisition(
            current_route_label(), wait_ns, hold_ns,
            connect_ns, lease_ns, sql_execute_ns, sql_fetch_ns,
        )
        # 06-16 Task 2: accumulate this acquisition's wait/hold onto the
        # calling thread's REQUEST totals (zeroed by begin_request), if any
        # -- lets end_request subtract lock_wait_ns out of off-CPU time.
        _REQUEST_STATE.lock_wait_ns = getattr(_REQUEST_STATE, 'lock_wait_ns', 0) + wait_ns
        _REQUEST_STATE.lock_hold_ns = getattr(_REQUEST_STATE, 'lock_hold_ns', 0) + hold_ns

    def locked(self):
        return self.raw.locked()

    def __repr__(self):
        return f'<InstrumentedLock wrapping {self.raw!r}>'


def install(lock):
    """Wrap ``lock`` and flip the module on. Returns the InstrumentedLock."""
    global ENABLED
    ENABLED = True
    return InstrumentedLock(lock)


def begin_request(route_label):
    """Bind the calling thread's route label and start its per-request
    wall/CPU accounting for the duration of a request.

    06-16 Task 2: also records `wall_start_ns` (`_timer_ns()`) and
    `cpu_start_ns` (`time.thread_time_ns()`, the one per-thread CPU clock
    the stdlib provides) and zeroes the per-request `lock_wait_ns` /
    `lock_hold_ns` accumulators that `InstrumentedLock._release_and_record`
    adds to on every `_db_lock` acquisition this request makes.
    """
    _REQUEST_STATE.route_label = route_label
    _REQUEST_STATE.wall_start_ns = _timer_ns()
    _REQUEST_STATE.cpu_start_ns = time.thread_time_ns()
    _REQUEST_STATE.lock_wait_ns = 0
    _REQUEST_STATE.lock_hold_ns = 0


def end_request():
    """Close the calling thread's request accounting region and clear its
    route label.

    Computes `wall_ns` (elapsed since `begin_request`), `cpu_ns` (this
    thread's own CPU time since `begin_request`), `off_cpu_ns = wall_ns -
    cpu_ns`, and `other_off_cpu_ns = off_cpu_ns - lock_wait_ns` -- the
    portion of off-CPU time NOT already accounted for by blocking on
    `_db_lock`. Clock granularity can make this negative for a
    sub-millisecond request; when it does, it is clamped to zero and
    counted via `clamped_off_cpu_count` rather than silently absorbed.

    `other_off_cpu_ns` also contains genuine I/O wait and scheduler delay,
    not GIL contention alone -- see `RequestStats`' docstring: the GIL's
    contribution is the concurrency-8 EXCESS over the same route's
    concurrency-1 value, never this raw figure.

    A no-op if `begin_request` was never called on this thread (or was
    already closed), matching `_release_and_record`'s tolerant handling of
    the degenerate case.
    """
    wall_start_ns = getattr(_REQUEST_STATE, 'wall_start_ns', None)
    if wall_start_ns is not None:
        # Sampled in this order -- cpu_end BEFORE wall_end, mirroring
        # begin_request's wall_start-before-cpu_start -- so the CPU-time
        # measurement window is strictly nested inside the wall-time window
        # ([wall_start <= cpu_start, cpu_end <= wall_end]) rather than merely
        # overlapping it. Sampling wall_end first (the naive order) lets
        # cpu_end creep a few instructions past wall_end, which can push
        # cpu_ns fractionally above wall_ns for a tight, low-overhead
        # request and trip the clamp below on ordinary correct behaviour,
        # not just genuine clock-granularity noise.
        cpu_start_ns = getattr(_REQUEST_STATE, 'cpu_start_ns', 0)
        cpu_ns = time.thread_time_ns() - cpu_start_ns
        wall_ns = _timer_ns() - wall_start_ns
        lock_wait_ns = getattr(_REQUEST_STATE, 'lock_wait_ns', 0)
        off_cpu_ns = wall_ns - cpu_ns
        other_off_cpu_ns = off_cpu_ns - lock_wait_ns
        clamped = other_off_cpu_ns < 0
        if clamped:
            other_off_cpu_ns = 0
        route_label = getattr(_REQUEST_STATE, 'route_label', None) or NO_REQUEST_ROUTE_LABEL
        COLLECTOR.record_request(route_label, wall_ns, cpu_ns, lock_wait_ns, other_off_cpu_ns, clamped)
    _REQUEST_STATE.route_label = None
    _REQUEST_STATE.wall_start_ns = None


def current_route_label():
    """The calling thread's bound route label, or NO_REQUEST_ROUTE_LABEL."""
    return getattr(_REQUEST_STATE, 'route_label', None) or NO_REQUEST_ROUTE_LABEL


def holding_lock():
    """True when the calling thread is inside an InstrumentedLock's critical
    section -- decides whether record_sql/record_connect attribute to the
    current held region or to the outside-lock buckets."""
    return getattr(_ACQUIRE_STATE, 'held', False)


def record_sql(kind, elapsed_ns):
    """Attribute one query or fetch's elapsed nanoseconds.

    Inside a held region (`holding_lock()` true) this accumulates onto the
    current acquisition's per-region totals, which `InstrumentedLock.
    _release_and_record` passes to `record_acquisition` alongside wait and
    hold. Outside any held region it accumulates onto the collector's
    `sql_outside_lock_ns` global instead, so it never inflates a route's
    held-SQL share. Returns immediately when ENABLED is false, before any
    timing work -- callers in dashboard/beacon/db.py check ENABLED first,
    but this is defense in depth for any other caller.
    """
    if not ENABLED:
        return
    if holding_lock():
        if kind == SQL_KIND_FETCH:
            _ACQUIRE_STATE.sql_fetch_ns = getattr(_ACQUIRE_STATE, 'sql_fetch_ns', 0) + elapsed_ns
        else:
            _ACQUIRE_STATE.sql_execute_ns = getattr(_ACQUIRE_STATE, 'sql_execute_ns', 0) + elapsed_ns
    else:
        COLLECTOR.add_sql_outside_lock(elapsed_ns)


def record_connect(total_ns, lease_ns):
    """Attribute one connection-setup span: `total_ns` is the whole
    `_acquire_lock` + `sqlite3.connect` + PRAGMA sequence; `lease_ns` is the
    `_acquire_lock` portion alone, reported separately so lease contention
    is distinguishable from the rest of connection setup. Only meaningful
    inside a held region -- every production `connect_db` call happens
    inside `_db_lock` -- so this is a no-op when `holding_lock()` is false.
    Returns immediately when ENABLED is false, before any timing work.
    """
    if not ENABLED:
        return
    if holding_lock():
        _ACQUIRE_STATE.connect_ns = getattr(_ACQUIRE_STATE, 'connect_ns', 0) + total_ns
        _ACQUIRE_STATE.lease_ns = getattr(_ACQUIRE_STATE, 'lease_ns', 0) + lease_ns


def snapshot():
    """A JSON-serializable readout: per-route totals, global totals, metadata."""
    result = COLLECTOR.snapshot()
    result['schema_version'] = SNAPSHOT_SCHEMA_VERSION
    result['enabled'] = ENABLED
    result['captured_monotonic_ns'] = _timer_ns()
    result['captured_epoch'] = time.time()
    return result
