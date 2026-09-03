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
SNAPSHOT_SCHEMA_VERSION = 1

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
    """One route's counters plus its two fixed-edge histograms."""

    acquisitions: int = 0
    wait_ns_total: int = 0
    hold_ns_total: int = 0
    wait_ns_max: int = 0
    hold_ns_max: int = 0
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
        'wait_histogram': list(stats.wait_histogram),
        'hold_histogram': list(stats.hold_histogram),
    }


def _accumulate(stats, wait_ns, hold_ns):
    stats.acquisitions += 1
    stats.wait_ns_total += wait_ns
    stats.hold_ns_total += hold_ns
    if wait_ns > stats.wait_ns_max:
        stats.wait_ns_max = wait_ns
    if hold_ns > stats.hold_ns_max:
        stats.hold_ns_max = hold_ns
    stats.wait_histogram[_bucket_index(wait_ns, WAIT_HISTOGRAM_EDGES_NS)] += 1
    stats.hold_histogram[_bucket_index(hold_ns, HOLD_HISTOGRAM_EDGES_NS)] += 1


class LockProfileCollector:
    """Owns the per-route table and the global totals for one process."""

    def __init__(self):
        # Named distinctly from every wrapped `_db_lock` so it is never
        # confused with the lock this module instruments.
        self._collector_lock = threading.Lock()
        self._routes = {}
        self._total = RouteStats()
        self.route_overflow = False

    def record_acquisition(self, route_label, wait_ns, hold_ns):
        with self._collector_lock:
            stats = self._routes.get(route_label)
            if stats is None:
                if len(self._routes) >= MAX_TRACKED_ROUTES:
                    self.route_overflow = True
                    route_label = OVERFLOW_ROUTE_LABEL
                    stats = self._routes.get(route_label)
                if stats is None:
                    stats = RouteStats()
                    self._routes[route_label] = stats
            _accumulate(stats, wait_ns, hold_ns)
            _accumulate(self._total, wait_ns, hold_ns)

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
        return {
            'routes': routes,
            'lock': total,
            'route_overflow': route_overflow,
        }

    def reset(self):
        """Return the collector to its initial state. Tests only."""
        with self._collector_lock:
            self._routes = {}
            self._total = RouteStats()
            self.route_overflow = False


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
        return acquired

    def release(self):
        self._release_and_record()

    def _release_and_record(self):
        release_ns = _timer_ns()
        # Degenerate case: __exit__/release running on a thread with no
        # recorded acquisition (e.g. this InstrumentedLock was released
        # without going through acquire()/__enter__ on this thread) records
        # a zero wait/hold rather than raising.
        acquired_ns = getattr(_ACQUIRE_STATE, 'acquired_ns', release_ns)
        wait_ns = getattr(_ACQUIRE_STATE, 'wait_ns', 0)
        hold_ns = release_ns - acquired_ns
        # Release before record: the collector's own bookkeeping must never
        # run inside _db_lock's critical section.
        self.raw.release()
        COLLECTOR.record_acquisition(current_route_label(), wait_ns, hold_ns)

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
    """Bind the calling thread's route label for the duration of a request."""
    _REQUEST_STATE.route_label = route_label


def end_request():
    """Clear the calling thread's route label."""
    _REQUEST_STATE.route_label = None


def current_route_label():
    """The calling thread's bound route label, or NO_REQUEST_ROUTE_LABEL."""
    return getattr(_REQUEST_STATE, 'route_label', None) or NO_REQUEST_ROUTE_LABEL


def snapshot():
    """A JSON-serializable readout: per-route totals, global totals, metadata."""
    result = COLLECTOR.snapshot()
    result['schema_version'] = SNAPSHOT_SCHEMA_VERSION
    result['enabled'] = ENABLED
    result['captured_monotonic_ns'] = _timer_ns()
    result['captured_epoch'] = time.time()
    return result
