"""Round-4 diagnostic tracer coverage for `_db_lock` instrumentation (06-15).

`06-VERIFICATION.md` Truth 5's first `missing:` item asks for exactly one
thing: the measurement that converts the `_db_lock` attribution from strong
inference (`06-DEBT.md` D-DEBT-06-09) into direct evidence, or refutes it.
This module proves the instrument built to answer that -- `dashboard/beacon/
lockprofile.py` -- is accurate when on, inert when off, and never widens
`_db_lock`'s scope.

Every millisecond figure this module's tests produce is developer-machine
evidence, never Pi latency evidence (`PROH-OPS-07-09`). Where a figure must
be portable across hosts, the test asserts a same-run ratio or a derived
per-acquisition nanosecond cost instead of an absolute millisecond threshold
(`06-REVIEW-ROUND3.md` WR-03).
"""

import ast
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from dashboard.beacon import lockprofile
from tests.helpers import cleanup_db, load_app


class _InstrumentedLockTestCase(unittest.TestCase):
    """Shared fixture: wrap a fresh app's `_db_lock` in an InstrumentedLock.

    Enabled by calling `lockprofile.install()` directly on the app's own
    lock and flipping the app's `ENABLE_LOCK_PROFILE` flag -- never by
    mutating process environment after import, so no other test module's
    app reload is affected by an env var this module set.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.original_lock = self.appmod._db_lock
        self.appmod._db_lock = lockprofile.install(self.original_lock)
        self.appmod.ENABLE_LOCK_PROFILE = True
        lockprofile.COLLECTOR.reset()
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        self.appmod._db_lock = self.original_lock
        self.appmod.ENABLE_LOCK_PROFILE = False
        lockprofile.ENABLED = False
        lockprofile.COLLECTOR.reset()
        cleanup_db(self.db_path)


class LockInstrumentationTests(_InstrumentedLockTestCase):
    """Tracer coverage: one request produces a per-route wait/hold number a
    reader can fetch over HTTP, and the numbers are real durations."""

    def test_get_services_reports_acquisitions_and_hold(self):
        resp = self.client.get('/api/services')
        self.assertEqual(resp.status_code, 200)

        snap_resp = self.client.get('/api/diagnostics/lock-profile')
        self.assertEqual(snap_resp.status_code, 200)
        snap = snap_resp.get_json()

        route = snap['routes']['/api/services']
        self.assertGreaterEqual(route['acquisitions'], 1)
        self.assertGreater(route['hold_ns_total'], 0)

    def test_scan_status_hold_matches_a_known_sleep(self):
        """A critical section held for a known SLEEP_S reports a hold within
        [SLEEP_S, SLEEP_S * 1.5 + 5ms] -- the actually-elapsed duration, not
        an arbitrary number."""
        SLEEP_S = 0.05
        original_read_scan_state = self.appmod._read_scan_state

        def slow_read_scan_state(*args, **kwargs):
            time.sleep(SLEEP_S)
            return original_read_scan_state(*args, **kwargs)

        self.appmod._read_scan_state = slow_read_scan_state
        try:
            resp = self.client.get('/api/scan-status')
            self.assertEqual(resp.status_code, 200)
        finally:
            self.appmod._read_scan_state = original_read_scan_state

        snap = self.client.get('/api/diagnostics/lock-profile').get_json()
        hold_ns_max = snap['routes']['/api/scan-status']['hold_ns_max']
        self.assertGreaterEqual(hold_ns_max, SLEEP_S * 1_000_000_000)
        self.assertLessEqual(hold_ns_max, SLEEP_S * 1.5 * 1_000_000_000 + 5_000_000)

    def test_wait_ns_reflects_real_blocking(self):
        """A thread blocked behind a known-duration holder records a
        wait_ns_max at least 80% of that duration. Wait time is real."""
        HOLD_S = 0.2
        holder_ready = threading.Event()
        waiter_started = threading.Event()

        def holder():
            with self.appmod._db_lock:
                holder_ready.set()
                waiter_started.wait(2)
                time.sleep(HOLD_S)

        holder_thread = threading.Thread(target=holder)
        holder_thread.start()
        self.assertTrue(holder_ready.wait(2), 'holder failed to acquire the lock in time')

        result = {}

        def waiter():
            waiter_started.set()
            result['resp'] = self.client.get('/api/scan-status')

        waiter_thread = threading.Thread(target=waiter)
        waiter_thread.start()
        holder_thread.join(5)
        waiter_thread.join(5)

        self.assertEqual(result['resp'].status_code, 200)
        snap = self.client.get('/api/diagnostics/lock-profile').get_json()
        wait_ns_max = snap['routes']['/api/scan-status']['wait_ns_max']
        self.assertGreaterEqual(wait_ns_max, 0.8 * HOLD_S * 1_000_000_000)

    def test_summing_identity_matches_global_total(self):
        """Per-route totals sum exactly to the global total. Nothing is
        dropped between the per-route and global views."""
        self.client.get('/api/services')
        self.client.get('/api/scan-status')
        self.client.get('/api/history')

        snap = self.client.get('/api/diagnostics/lock-profile').get_json()
        total_hold = sum(route['hold_ns_total'] for route in snap['routes'].values())
        total_acquisitions = sum(route['acquisitions'] for route in snap['routes'].values())
        self.assertEqual(total_hold, snap['lock']['hold_ns_total'])
        self.assertEqual(total_acquisitions, snap['lock']['acquisitions'])

    def test_route_labels_collapse_to_one_key_per_flask_rule(self):
        """Every route label the acceptance harness exercises appears as its
        own key, and the thumbnail rule appears as ONE key across three
        different ports, not three."""
        self.client.get('/api/services')
        self.client.get('/api/scan-status')
        self.client.get('/api/thumbnail-status')
        self.client.get('/api/history')
        self.client.get('/api/thumbnail/9001')
        self.client.get('/api/thumbnail/9002')
        self.client.get('/api/thumbnail/9003')

        snap = self.client.get('/api/diagnostics/lock-profile').get_json()
        route_labels = set(snap['routes'].keys()) - {lockprofile.NO_REQUEST_ROUTE_LABEL}
        expected = {
            '/api/services',
            '/api/scan-status',
            '/api/thumbnail-status',
            '/api/history',
            '/api/thumbnail/<int:port>',
        }
        self.assertEqual(route_labels, expected)
        self.assertEqual(snap['routes']['/api/thumbnail/<int:port>']['acquisitions'], 3)

    def test_no_request_context_attributed_to_no_request_label(self):
        """An acquisition from a thread with no Flask request context is
        attributed to NO_REQUEST_ROUTE_LABEL and still counts toward the
        global total."""
        with self.appmod._db_lock:
            pass

        snap = lockprofile.snapshot()
        self.assertIn(lockprofile.NO_REQUEST_ROUTE_LABEL, snap['routes'])
        self.assertGreaterEqual(
            snap['routes'][lockprofile.NO_REQUEST_ROUTE_LABEL]['acquisitions'], 1,
        )
        self.assertGreaterEqual(snap['lock']['acquisitions'], 1)

    def test_route_overflow_bucket_and_summing_identity_still_holds(self):
        """With MAX_TRACKED_ROUTES patched to 2 and three labels driven,
        route_overflow is true, the third label lands under
        OVERFLOW_ROUTE_LABEL, and the summing identity still holds exactly."""
        with mock.patch.object(lockprofile, 'MAX_TRACKED_ROUTES', 2):
            for label in ('routeA', 'routeB', 'routeC'):
                lockprofile.begin_request(label)
                with self.appmod._db_lock:
                    pass
                lockprofile.end_request()

        snap = lockprofile.snapshot()
        self.assertTrue(snap['route_overflow'])
        self.assertIn(lockprofile.OVERFLOW_ROUTE_LABEL, snap['routes'])
        total_hold = sum(route['hold_ns_total'] for route in snap['routes'].values())
        total_acquisitions = sum(route['acquisitions'] for route in snap['routes'].values())
        self.assertEqual(total_hold, snap['lock']['hold_ns_total'])
        self.assertEqual(total_acquisitions, snap['lock']['acquisitions'])

    def test_utilisation_within_tolerance_of_a_known_fraction(self):
        """Utilisation computed from two snapshots -- (hold_ns_total delta) /
        (captured_monotonic_ns delta) -- is within 0.05 of a known held
        fraction. This is the arithmetic 06-VERIFICATION.md's second
        `missing:` item needs."""
        HOLD_FRACTION = 0.5
        CYCLE_S = 0.02
        CYCLES = 40

        snap_before = lockprofile.snapshot()
        for _ in range(CYCLES):
            with self.appmod._db_lock:
                time.sleep(CYCLE_S * HOLD_FRACTION)
            time.sleep(CYCLE_S * (1 - HOLD_FRACTION))
        snap_after = lockprofile.snapshot()

        hold_delta = snap_after['lock']['hold_ns_total'] - snap_before['lock']['hold_ns_total']
        time_delta = snap_after['captured_monotonic_ns'] - snap_before['captured_monotonic_ns']
        utilisation = hold_delta / time_delta
        self.assertAlmostEqual(utilisation, HOLD_FRACTION, delta=0.05)


class HoldDecompositionTests(_InstrumentedLockTestCase):
    """06-16 Task 1: decompose the held critical section into connection
    setup, SQL and Python. Every millisecond and every share this class
    produces is developer-machine evidence, never Pi evidence
    (`PROH-OPS-07-09`)."""

    def _run_in_held_region(self, route_label, work_fn):
        lockprofile.begin_request(route_label)
        try:
            with self.appmod._db_lock:
                work_fn()
        finally:
            lockprofile.end_request()

    def test_two_directional_sql_share_of_the_held_region(self):
        """A critical section dominated by a known, deliberately slow SQL
        statement reports a SQL share within 0.15 of the known share; a
        section dominated by Python reports a share below 0.15. Both
        directions -- the instrument measures, it does not merely
        partition."""
        from dashboard.beacon.db import connect_db

        conn = connect_db(self.db_path)
        try:
            SLOW_S = 0.05
            conn.create_function('slow_step_06_16', 0, lambda: (time.sleep(SLOW_S), 1)[1])

            self._run_in_held_region(
                'sql-dominated-06-16',
                lambda: conn.execute('SELECT slow_step_06_16()').fetchall(),
            )

            PY_S = 0.05

            def python_heavy():
                conn.execute('SELECT 1').fetchall()
                time.sleep(PY_S)

            self._run_in_held_region('python-dominated-06-16', python_heavy)
        finally:
            conn.close()

        snap = lockprofile.snapshot()
        sql_route = snap['routes']['sql-dominated-06-16']
        sql_hold = sql_route['hold_ns_total']
        sql_share = (
            sql_route['sql_execute_ns_total'] + sql_route['sql_fetch_ns_total']
        ) / sql_hold
        self.assertGreaterEqual(
            sql_share, 0.85,
            f'SQL-dominated section reported SQL share {sql_share:.3f}, expected '
            'within 0.15 of the known ~1.0 share -- the instrument is not '
            'tracking SQL time in the direction it should.',
        )

        py_route = snap['routes']['python-dominated-06-16']
        py_hold = py_route['hold_ns_total']
        py_share = (
            py_route['sql_execute_ns_total'] + py_route['sql_fetch_ns_total']
        ) / py_hold
        self.assertLess(
            py_share, 0.15,
            f'Python-dominated section reported SQL share {py_share:.3f}, '
            'expected below 0.15 -- the instrument is not tracking Python time '
            'in the direction it should.',
        )

    def test_fetchall_on_managed_connection_records_nonzero_fetch(self):
        """Guard for the CPython `Connection.execute` routes-through-`self.
        cursor()` assumption (`D-DEBT-06-10`): if `ManagedConnection.cursor`
        is not overridden, fetch time silently lands in the Python bucket
        instead of here, and this assertion catches it."""
        from dashboard.beacon.db import connect_db

        conn = connect_db(self.db_path)
        try:
            conn.execute('CREATE TABLE _t_06_16_fetch(v INTEGER)')
            conn.executemany(
                'INSERT INTO _t_06_16_fetch(v) VALUES (?)', [(i,) for i in range(2000)],
            )
            conn.commit()

            rows = {}

            def work():
                rows['result'] = conn.execute('SELECT v FROM _t_06_16_fetch').fetchall()

            self._run_in_held_region('fetch-guard-06-16', work)
            self.assertEqual(len(rows['result']), 2000)
        finally:
            conn.close()

        snap = lockprofile.snapshot()
        self.assertGreater(snap['routes']['fetch-guard-06-16']['sql_fetch_ns_total'], 0)

    def test_identity_holds_by_construction_reported_for_readability(self):
        """Not a guard -- python_ns_total is defined as the remainder, so
        this identity cannot fail. Reported for readability only, never
        cited as accuracy evidence (`D-DEBT-06-10`)."""
        from dashboard.beacon.db import connect_db

        conn = connect_db(self.db_path)
        try:
            def work():
                conn.execute('SELECT 1').fetchall()
                time.sleep(0.01)

            self._run_in_held_region('identity-06-16', work)
        finally:
            conn.close()

        route = lockprofile.snapshot()['routes']['identity-06-16']
        self.assertEqual(
            route['connect_ns_total'] + route['sql_execute_ns_total']
            + route['sql_fetch_ns_total'] + route['python_ns_total'],
            route['hold_ns_total'],
        )

    def test_clamped_python_count_is_zero_across_the_workload(self):
        """Load-bearing: the derived Python remainder never goes negative
        across a representative mixed workload -- no measurement error is
        silently absorbed into it. Mutation target: double-counting
        `record_connect`.

        Each iteration opens its OWN connection INSIDE the held region --
        the real production shape (`with _db_lock, database_access(DB_PATH)
        as conn:` opens a fresh connection every time) -- so a
        double-counted `record_connect` is actually exercised here, not
        just a double-counted `record_sql`.
        """
        from dashboard.beacon.db import connect_db

        setup_conn = connect_db(self.db_path)
        try:
            setup_conn.execute('CREATE TABLE _t_06_16_clamp(v INTEGER)')
            setup_conn.executemany(
                'INSERT INTO _t_06_16_clamp(v) VALUES (?)', [(i,) for i in range(500)],
            )
            setup_conn.commit()
        finally:
            setup_conn.close()

        for i in range(20):
            label = f'clamp-workload-06-16-{i % 3}'
            opened = {}

            def work():
                opened['conn'] = connect_db(self.db_path)
                opened['conn'].execute('SELECT v FROM _t_06_16_clamp').fetchall()

            self._run_in_held_region(label, work)
            opened['conn'].close()

        snap = lockprofile.snapshot()
        self.assertEqual(snap['clamped_python_count'], 0)

    def test_connection_setup_measured_and_lease_isolated_under_contention(self):
        """Connection setup (`connect_ns_total`) is non-zero, and its
        `flock` lease portion (`lease_ns_total`) rises under artificial
        maintenance-lease contention while the rest of connect setup does
        not rise materially in the same comparison."""
        import fcntl
        import threading as _threading

        from dashboard.beacon.db import connect_db, maintenance_lock_path

        baseline = {}

        def baseline_connect():
            baseline['conn'] = connect_db(self.db_path)

        self._run_in_held_region('connect-baseline-06-16', baseline_connect)
        baseline['conn'].close()

        baseline_route = lockprofile.snapshot()['routes']['connect-baseline-06-16']
        self.assertGreater(baseline_route['connect_ns_total'], 0)

        lock_path = maintenance_lock_path(self.db_path)
        contend_handle = lock_path.open('a+')
        fcntl.flock(contend_handle.fileno(), fcntl.LOCK_EX)
        CONTEND_S = 0.15
        release_at = time.monotonic() + CONTEND_S

        def releaser():
            remaining = release_at - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            fcntl.flock(contend_handle.fileno(), fcntl.LOCK_UN)
            contend_handle.close()

        releaser_thread = _threading.Thread(target=releaser, daemon=True)
        releaser_thread.start()

        contended = {}

        def contended_connect():
            contended['conn'] = connect_db(self.db_path)

        self._run_in_held_region('connect-contended-06-16', contended_connect)
        releaser_thread.join(5)
        contended['conn'].close()

        contended_route = lockprofile.snapshot()['routes']['connect-contended-06-16']
        self.assertGreater(
            contended_route['lease_ns_total'], baseline_route['lease_ns_total'],
            'lease_ns_total did not rise under artificial maintenance-lease '
            'contention -- the lease portion is not being isolated.',
        )
        baseline_nonlease = baseline_route['connect_ns_total'] - baseline_route['lease_ns_total']
        contended_nonlease = contended_route['connect_ns_total'] - contended_route['lease_ns_total']
        self.assertLess(
            contended_nonlease, baseline_nonlease * 5 + 20_000_000,
            f'non-lease connect cost rose from {baseline_nonlease}ns to '
            f'{contended_nonlease}ns under lease contention -- the lease is not '
            'isolated from the rest of connection setup.',
        )

    def test_sql_outside_any_held_region_lands_in_its_own_bucket(self):
        """SQL performed OUTSIDE any held region is attributed to
        `sql_outside_lock_ns` and touches no route's held-SQL share."""
        from dashboard.beacon.db import connect_db

        conn = connect_db(self.db_path)
        try:
            conn.execute('SELECT 1').fetchall()
        finally:
            conn.close()

        snap = lockprofile.snapshot()
        self.assertGreater(snap['sql_outside_lock_ns'], 0)
        self.assertEqual(snap['routes'], {})

    def test_disabled_profile_never_touches_record_sql_or_record_connect(self):
        """With the profile disabled, counting stubs over `record_sql` and
        `record_connect` register exactly 0 calls across 50 queries and 10
        connections, and `ManagedConnection` returns ordinary results.

        `ENABLED` is one process-wide flag, and this class's own fixture
        (`_InstrumentedLockTestCase.setUp`) already flipped it True via
        `lockprofile.install()` for `self.appmod`'s lock. This test exercises
        a deliberately different, never-installed app, so it must flip
        `ENABLED` back to False itself rather than rely on the shared
        fixture -- tearDown resets it to False afterward either way.
        """
        appmod, db_path = load_app()
        try:
            self.assertFalse(appmod.ENABLE_LOCK_PROFILE)
            lockprofile.ENABLED = False
            from dashboard.beacon.db import connect_db

            call_count = {'sql': 0, 'connect': 0}
            original_record_sql = lockprofile.record_sql
            original_record_connect = lockprofile.record_connect

            def counting_record_sql(kind, elapsed_ns):
                call_count['sql'] += 1
                return original_record_sql(kind, elapsed_ns)

            def counting_record_connect(total_ns, lease_ns):
                call_count['connect'] += 1
                return original_record_connect(total_ns, lease_ns)

            with mock.patch.object(lockprofile, 'record_sql', counting_record_sql), \
                 mock.patch.object(lockprofile, 'record_connect', counting_record_connect):
                conn = connect_db(db_path)
                try:
                    for _ in range(50):
                        result = conn.execute('SELECT 1').fetchall()
                        self.assertEqual([tuple(row) for row in result], [(1,)])
                finally:
                    conn.close()
                for _ in range(9):
                    extra_conn = connect_db(db_path)
                    extra_conn.close()

            self.assertEqual(call_count['sql'], 0)
            self.assertEqual(call_count['connect'], 0)
        finally:
            cleanup_db(db_path)


class LockProfileInertnessTests(unittest.TestCase):
    """Turning the diagnostic off returns the deployment to a state
    indistinguishable from today's, and turning it on costs a bounded,
    measured amount -- never distorting what it measures beyond that bound.

    PROH-OPS-07-09: every millisecond figure in this class is
    developer-machine evidence. Ratios and the derived
    `instrument_cost_ns_per_acquisition` are the portable figures.
    """

    def setUp(self):
        lockprofile.COLLECTOR.reset()
        lockprofile.ENABLED = False

    def tearDown(self):
        lockprofile.COLLECTOR.reset()
        lockprofile.ENABLED = False

    def test_zero_timing_work_when_disabled(self):
        """With the profile off, a counting stub over lockprofile._timer_ns
        records exactly 0 calls across 25 driven requests, and
        lockprofile.snapshot() reports enabled: false with zero
        acquisitions and an empty route table.

        Also wraps begin_request/end_request with counting stubs -- the
        app.py action's own requirement is that the disabled before_request/
        teardown_request fast path returns "before touching the lockprofile
        module at all", not merely before calling its timer. A guard that
        touches begin_request/end_request without touching _timer_ns would
        pass a _timer_ns-only check while still violating that requirement,
        so this test is deliberately sensitive to both.
        """
        appmod, db_path = load_app()
        try:
            self.assertFalse(appmod.ENABLE_LOCK_PROFILE)
            call_count = {'timer': 0, 'begin_request': 0, 'end_request': 0}
            original_timer = lockprofile._timer_ns
            original_begin_request = lockprofile.begin_request
            original_end_request = lockprofile.end_request

            def counting_timer():
                call_count['timer'] += 1
                return original_timer()

            def counting_begin_request(route_label):
                call_count['begin_request'] += 1
                return original_begin_request(route_label)

            def counting_end_request():
                call_count['end_request'] += 1
                return original_end_request()

            client = appmod.app.test_client()
            routes = ('/api/services', '/api/scan-status', '/api/history')
            with mock.patch.object(lockprofile, '_timer_ns', counting_timer), \
                 mock.patch.object(lockprofile, 'begin_request', counting_begin_request), \
                 mock.patch.object(lockprofile, 'end_request', counting_end_request):
                for i in range(25):
                    resp = client.get(routes[i % len(routes)])
                    self.assertEqual(resp.status_code, 200)

            self.assertEqual(
                call_count['timer'], 0,
                'disabled path performed timing work: lockprofile._timer_ns was '
                f"called {call_count['timer']} times across 25 requests",
            )
            self.assertEqual(
                call_count['begin_request'], 0,
                'disabled before_request fast path touched lockprofile.begin_request '
                f"{call_count['begin_request']} times across 25 requests -- it must "
                'return before touching the lockprofile module at all',
            )
            self.assertEqual(
                call_count['end_request'], 0,
                'disabled teardown_request fast path touched lockprofile.end_request '
                f"{call_count['end_request']} times across 25 requests -- it must "
                'return before touching the lockprofile module at all',
            )
            snap = lockprofile.snapshot()
            self.assertFalse(snap['enabled'])
            self.assertEqual(snap['lock']['acquisitions'], 0)
            self.assertEqual(snap['routes'], {})
        finally:
            cleanup_db(db_path)

    def test_disabled_surface_returns_404_through_security_headers(self):
        """With the profile off, GET /api/diagnostics/lock-profile returns
        404 with an empty body and still carries add_security_headers'
        X-Content-Type-Options -- proving it passed through the existing
        middleware rather than around it."""
        appmod, db_path = load_app()
        try:
            client = appmod.app.test_client()
            resp = client.get('/api/diagnostics/lock-profile')
            self.assertEqual(resp.status_code, 404)
            self.assertEqual(resp.data, b'')
            self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')
        finally:
            cleanup_db(db_path)

    def test_disabled_wrapper_path_costs_nothing_measurable(self):
        """The same interleaved ABAB comparison, but against the exact
        _db_lock a flag-off deployment uses (never wrapped), asserts the
        same 1.02x bound -- guarding against a future regression that
        wraps the lock even when the flag is off."""
        appmod, db_path = load_app()
        try:
            self.assertFalse(appmod.ENABLE_LOCK_PROFILE)
            disabled_lock = appmod._db_lock
            raw_lock = threading.Lock()

            def reference_work():
                total = 0
                for i in range(50_000):
                    total += i * i
                return total

            iterations = 30
            bare_total_ns = 0
            disabled_total_ns = 0
            for _ in range(iterations):
                start = time.perf_counter_ns()
                with raw_lock:
                    reference_work()
                bare_total_ns += time.perf_counter_ns() - start

                start = time.perf_counter_ns()
                with disabled_lock:
                    reference_work()
                disabled_total_ns += time.perf_counter_ns() - start

            ratio = disabled_total_ns / bare_total_ns
            self.assertLessEqual(
                ratio, 1.02,
                "flag-off deployment's _db_lock totalled "
                f'{ratio:.4f}x a bare threading.Lock over {iterations} interleaved '
                f'iterations (bare={bare_total_ns}ns disabled={disabled_total_ns}ns) '
                '-- this means _db_lock is being wrapped even when '
                'ENABLE_LOCK_PROFILE is off, defeating the disabled-by-default '
                'guarantee.',
            )
        finally:
            cleanup_db(db_path)

    def test_millisecond_scale_overhead_ratio(self):
        """A reference critical section costing ~1ms is run interleaved
        (bare, instrumented, bare, instrumented, ...) so drift affects both
        arms equally. Per WR-03 / D-DEBT-06-10, no absolute millisecond
        threshold appears -- only the same-run ratio."""
        raw_lock = threading.Lock()
        instrumented_lock = lockprofile.install(raw_lock)
        lockprofile.begin_request('millisecond-overhead-bench')
        try:
            def reference_work():
                total = 0
                for i in range(50_000):
                    total += i * i
                return total

            iterations = 30
            bare_total_ns = 0
            instrumented_total_ns = 0
            for _ in range(iterations):
                start = time.perf_counter_ns()
                with raw_lock:
                    reference_work()
                bare_total_ns += time.perf_counter_ns() - start

                start = time.perf_counter_ns()
                with instrumented_lock:
                    reference_work()
                instrumented_total_ns += time.perf_counter_ns() - start

            ratio = instrumented_total_ns / bare_total_ns
            self.assertLessEqual(
                ratio, 1.02,
                f'WR-03 / D-DEBT-06-10: instrumented arm totalled {ratio:.4f}x the '
                f'bare arm over {iterations} interleaved iterations '
                f'(bare={bare_total_ns}ns instrumented={instrumented_total_ns}ns) '
                '-- exceeds the 1.02x ceiling, meaning the instrument is too '
                'expensive to trust, not that the host is slow.',
            )
        finally:
            lockprofile.end_request()
            lockprofile.ENABLED = False
            lockprofile.COLLECTOR.reset()

    def test_microsecond_scale_derives_instrument_cost_per_acquisition(self):
        """A second interleaved arm at tens-of-microseconds scale asserts NO
        ratio -- a tight ratio there would be dishonest or vacuous. It
        derives instrument_cost_ns_per_acquisition and asserts only a
        generous 328us ceiling (one tenth of /api/scan-status' 3.281ms
        control-pass cost). This number is the error bar 06-18 must carry
        beside every reported hold."""
        raw_lock = threading.Lock()
        instrumented_lock = lockprofile.install(raw_lock)
        lockprofile.begin_request('microsecond-overhead-bench')
        try:
            def reference_work():
                total = 0
                for i in range(1_000):
                    total += i * i
                return total

            iterations = 500
            bare_total_ns = 0
            instrumented_total_ns = 0
            for _ in range(iterations):
                start = time.perf_counter_ns()
                with raw_lock:
                    reference_work()
                bare_total_ns += time.perf_counter_ns() - start

                start = time.perf_counter_ns()
                with instrumented_lock:
                    reference_work()
                instrumented_total_ns += time.perf_counter_ns() - start

            snap = lockprofile.snapshot()
            acquisitions = snap['lock']['acquisitions']
            self.assertEqual(acquisitions, iterations)

            instrument_cost_ns_per_acquisition = (
                (instrumented_total_ns - bare_total_ns) / acquisitions
            )
            # Surfaced through test output (recorded verbatim in
            # 06-15-SUMMARY.md); 06-18 Sec.1 must carry this figure beside
            # every reported hold as its error bar (D-DEBT-06-10) -- it
            # matters most exactly where the prediction is
            # "/api/scan-status will show ~0ms hold".
            print(
                'instrument_cost_ns_per_acquisition = '
                f'{instrument_cost_ns_per_acquisition:.1f} ns '
                f'(bare={bare_total_ns}ns instrumented={instrumented_total_ns}ns '
                f'over {acquisitions} acquisitions; developer-machine evidence, '
                'PROH-OPS-07-09)',
            )
            self.assertLess(
                instrument_cost_ns_per_acquisition, 328_000,
                f'instrument_cost_ns_per_acquisition {instrument_cost_ns_per_acquisition:.1f}ns '
                'exceeds the 328,000ns ceiling (one tenth of /api/scan-status\' 3.281ms '
                'control-pass cost) -- the instrument is too expensive at microsecond '
                'scale to trust its hold figures there.',
            )
        finally:
            lockprofile.end_request()
            lockprofile.ENABLED = False
            lockprofile.COLLECTOR.reset()

    def test_mutual_exclusion_survives_instrumentation(self):
        """Twelve threads x 200 entries each: a plain int guarded by
        nothing but the instrumented lock itself never reaches occupancy > 1,
        and the collector's recorded acquisitions equals 2400 exactly."""
        raw_lock = threading.Lock()
        instrumented_lock = lockprofile.install(raw_lock)
        lockprofile.begin_request('mutual-exclusion-bench')
        try:
            thread_count = 12
            entries_per_thread = 200
            barrier = threading.Barrier(thread_count)
            state = {'occupancy': 0, 'max_occupancy': 0}

            def worker():
                barrier.wait()
                for _ in range(entries_per_thread):
                    with instrumented_lock:
                        # Guarded by nothing but instrumented_lock itself --
                        # the whole point is that _db_lock is the only thing
                        # preventing overlap here.
                        state['occupancy'] += 1
                        if state['occupancy'] > state['max_occupancy']:
                            state['max_occupancy'] = state['occupancy']
                        state['occupancy'] -= 1

            # daemon=True is load-bearing, not hygiene. join(10) below already
            # bounds the WAIT, so a lock that loses mutual exclusion still
            # reaches the assertions -- but a non-daemon worker blocked forever
            # on a never-released lock prevents the INTERPRETER from exiting,
            # so pytest prints its result and then hangs. That is exactly what
            # happened while mutation-verifying this test during 06-15: the
            # release-skipping mutation deadlocked the run for ~8 minutes and
            # stalled the executor, which is a far worse failure mode than a
            # red test. A mutation test that hangs instead of failing cannot be
            # trusted in a suite.
            threads = [threading.Thread(target=worker, daemon=True) for _ in range(thread_count)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)

            self.assertEqual(
                state['max_occupancy'], 1,
                f"observed max concurrent occupancy {state['max_occupancy']} != 1 "
                '-- InstrumentedLock lost mutual exclusion',
            )
            snap = lockprofile.snapshot()
            self.assertEqual(
                snap['lock']['acquisitions'], thread_count * entries_per_thread,
            )
        finally:
            lockprofile.end_request()
            lockprofile.ENABLED = False
            lockprofile.COLLECTOR.reset()

    def test_enable_lock_profile_defaults_off_and_reads_env(self):
        """load_settings({}) yields enable_lock_profile is False;
        load_settings({'ENABLE_LOCK_PROFILE': '1'}) yields True."""
        from dashboard.beacon.config import load_settings

        self.assertFalse(load_settings({}).enable_lock_profile)
        self.assertTrue(load_settings({'ENABLE_LOCK_PROFILE': '1'}).enable_lock_profile)


def _call_target_name(call_node):
    """Dotted-name string for a Call node's callee: 'foo' or 'mod.attr'."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        node = func.value
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))
    return None


def _find_function_def(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _find_db_lock_with(func_node):
    for node in ast.walk(func_node):
        if isinstance(node, ast.With):
            for item in node.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Name) and ctx.id == '_db_lock':
                    return node
    return None


class LockScopePreservationTests(unittest.TestCase):
    """Pins `_db_lock`'s SCOPE, not merely its call-site count (06-CONTEXT.md
    D-01, PROH-OPS-04-02). If a test in this class fails: `_db_lock`'s scope
    changed. Go to D-DEBT-06-01 in 06-DEBT.md and re-examine the decision to
    defer narrowing it -- do not edit these assertions to make the test
    pass. This is the routing convention
    `test_the_deployment_pins_its_gunicorn_concurrency_model` established
    for D-DEBT-06-07.

    This class pins that THIS ROUND did not narrow the lock. It is not a
    claim that narrowing is wrong -- when the round-5 fix decision is taken
    against this round's measurements, whoever narrows the lock updates
    these tests deliberately, with D-DEBT-06-01's reopening conditions and
    PROH-OPS-04-05's audit list in hand.
    """

    def setUp(self):
        self.source = Path('dashboard/app.py').read_text(encoding='utf-8')
        self.tree = ast.parse(self.source)

    def test_call_site_count_and_shape(self):
        combined_marker = 'with _db_lock, database_access(DB_PATH) as conn:'
        bare_count = 0
        combined_count = 0
        for line in self.source.splitlines():
            stripped = line.strip()
            if not stripped.startswith('with _db_lock'):
                continue
            if stripped == combined_marker:
                combined_count += 1
            elif stripped == 'with _db_lock:':
                bare_count += 1
        self.assertEqual(
            bare_count, 3,
            f'expected 3 bare "with _db_lock:" call sites, found {bare_count} -- '
            "_db_lock's SCOPE/call-site count changed. See D-DEBT-06-01.",
        )
        self.assertEqual(
            combined_count, 25,
            f'expected 25 combined "{combined_marker}" call sites, found '
            f"{combined_count} -- _db_lock's SCOPE/call-site count changed. "
            'See D-DEBT-06-01.',
        )
        self.assertEqual(bare_count + combined_count, 28)

    def test_api_services_lock_scope_containment_and_termination(self):
        """Pins the SCOPE, not merely the count, using ast. Fails on all
        three mutations that matter: deleting a call site, dedenting one
        statement out of the block, and moving one of the four expensive
        computations outside the with-block (the round-5 narrowing shape
        this pin exists to catch)."""
        func = _find_function_def(self.tree, 'api_services')
        self.assertIsNotNone(func, 'api_services function not found in dashboard/app.py')

        with_node = _find_db_lock_with(func)
        self.assertIsNotNone(
            with_node, "api_services no longer has a `with _db_lock` block -- "
            "_db_lock's SCOPE changed. See D-DEBT-06-01.",
        )

        # Containment: locate every call inside the _db_lock with-block
        # (bounded by the With node's own subtree / end_lineno) and confirm
        # all four expensive computations are among them. Matched by
        # name/attribute, never by line number, so this survives ordinary
        # edits above the function.
        found_calls = {
            _call_target_name(node)
            for node in ast.walk(with_node)
            if isinstance(node, ast.Call)
        }
        required_calls = {
            '_uptime_summary',
            'beacon_maintenance.coverage',
            'beacon_maintenance.attributed_downtime_seconds',
            'beacon_repositories.offline_intervals_from_points_by_port',
        }
        missing = required_calls - found_calls
        self.assertFalse(
            missing,
            f"_db_lock's SCOPE changed: {sorted(missing)} no longer execute inside "
            "api_services' _db_lock with-block (bounded by end_lineno "
            f'{with_node.end_lineno}). D-01 and PROH-OPS-04-02 fence exactly this '
            'scope. See D-DEBT-06-01 before editing this assertion.',
        )

        # Nothing escaped: the only function-level statement after the
        # with-block is the terminal `return jsonify(result)`. That return
        # IS a function-level statement after the with, and that is
        # expected -- an earlier draft of this plan asserted no statement
        # followed the block at all, which is false at HEAD and
        # unsatisfiable. Encoding the real shape (with, then exactly one
        # return, nothing else) is what makes this guard catch a narrowing
        # rather than force it to be weakened.
        body = func.body
        with_index = body.index(with_node)
        self.assertEqual(
            with_index, len(body) - 2,
            "_db_lock's SCOPE changed: a statement other than the terminal return "
            "now follows api_services' with-block (or a statement was dedented out "
            'of it). D-01 and PROH-OPS-04-02 fence exactly this scope. See '
            'D-DEBT-06-01 before editing this assertion.',
        )
        self.assertIsInstance(
            body[-1], ast.Return,
            "_db_lock's SCOPE changed: api_services no longer ends with a single "
            'terminal return statement after its with-block. See D-DEBT-06-01.',
        )
