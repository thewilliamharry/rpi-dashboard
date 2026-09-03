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
import contextlib
import json
import math
import os
import random
import re
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import requests

import tests.pi_load_acceptance as harness
from dashboard.beacon import lockprofile
from dashboard.beacon import repositories as beacon_repositories
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


class HeldRegionCompositionTests(_InstrumentedLockTestCase):
    """06-20 Task 2: measure the narrowing's effect on `/api/services`' own
    held-region composition, in both directions -- the mechanism-level
    analogue of `06-LOCK-DIAGNOSTIC.md` §4's Pi-measured shares (`.002 /
    .748 / .250` loaded, `.001 / .423 / .576` control). Seeds 3 services and
    2,000 `service_checks` rows per port (6,000 total) across the retention
    window, generated from a fixed seed, with one offline service (the
    lowest port) carrying an always-covering maintenance window so
    `beacon_maintenance`'s coverage/attributed-downtime walk is exercised in
    both tests below. Every share this class reports is developer-machine
    evidence (`PROH-OPS-07-09`), never Pi latency evidence."""

    HELD_REGION_PORTS = (9081, 9082, 9083)
    CHECKS_PER_PORT = 2000

    # 06-LOCK-DIAGNOSTIC.md §4's Pi figure (25.0%) does not transfer to this
    # dev machine's own measurement, and no dataset shape makes it transfer
    # (D-DEBT-06-14's lesson: an absolute threshold copied across machines is
    # "a property of the band, not of the data"). Direct measurement on this
    # machine: the narrowed route's Python share of its own held region --
    # dict(row) materialization required by PROH-OPS-04-06/T-06-102, not
    # composition -- sits in a 0.18-0.32 band across dataset sizes from 1 row
    # to 24,000 rows and repetition counts from 5 to 40 (see SUMMARY for the
    # sweep). Reintroducing `_uptime_summary` for every service inside the
    # with-block (the exact defect this guard exists to catch) measures
    # 0.62 under the identical harness -- reproduced against a real,
    # temporary, reverted app.py edit, not merely asserted. 0.5 sits with a
    # wide, empirically-verified margin below that failure mode and above
    # every narrowed-route reading observed, so it is what this guard checks
    # rather than the Pi figure the mechanism is modeled on. Developer-
    # machine evidence only (PROH-OPS-07-09).
    PYTHON_SHARE_CEILING = 0.5

    def _run_in_held_region(self, route_label, work_fn):
        """Copied from `HoldDecompositionTests`' idiom exactly (06-16 Task
        1) -- not reinvented, per this task's own instruction."""
        lockprofile.begin_request(route_label)
        try:
            with self.appmod._db_lock:
                work_fn()
        finally:
            lockprofile.end_request()

    def setUp(self):
        super().setUp()
        appmod = self.appmod
        now = int(time.time())
        start_ts = now - appmod.CHECK_RETENTION_SECONDS
        step = appmod.CHECK_RETENTION_SECONDS // self.CHECKS_PER_PORT
        rng = random.Random(20200)
        offline_port = self.HELD_REGION_PORTS[0]

        conn = appmod.get_db()
        try:
            for port in self.HELD_REGION_PORTS:
                is_online = 0 if port == offline_port else 1
                conn.execute(
                    "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                    "VALUES(?,?,?,?,?,?)",
                    (port, f'held-region-{port}', start_ts, now, is_online, start_ts),
                )
            conn.execute(
                'INSERT INTO maintenance_windows (port, start_minute, duration_minutes, '
                'weekdays, grace_minutes, enabled, created_ts, updated_ts) '
                'VALUES (?, 0, 1440, ?, 0, 1, ?, ?)',
                (offline_port, '1,2,3,4,5,6,7', start_ts, start_ts),
            )

            self.checks_by_port = {}
            for port in self.HELD_REGION_PORTS:
                rows = []
                for i in range(self.CHECKS_PER_PORT):
                    ts = start_ts + i * step
                    online = 0 if (port == offline_port and rng.random() < 0.9) else 1
                    rows.append((ts, online))
                conn.executemany(
                    'INSERT INTO service_checks (ts, port, online) VALUES (?, ?, ?)',
                    [(ts, port, online) for ts, online in rows],
                )
                self.checks_by_port[port] = rows
            conn.commit()
        finally:
            conn.close()

        self.offline_port = offline_port
        windows_conn = appmod.get_db()
        try:
            self.windows = appmod.beacon_repositories.read_maintenance_windows_by_port(
                windows_conn, ports=[offline_port],
            ).get(offline_port, [])
        finally:
            windows_conn.close()
        self.offline_intervals = appmod.beacon_repositories.offline_intervals_from_points_by_port(
            ports=[offline_port], boundary_by_port={},
            points_by_port={offline_port: self.checks_by_port[offline_port]},
            start_ts=start_ts, end_ts=now,
        ).get(offline_port, [])

    def test_services_held_region_is_sql_dominated_after_narrowing(self):
        """Direction A: after 06-20's narrowing, `/api/services`' measured
        Python share of its own held region stays well under
        PYTHON_SHARE_CEILING. Fails when `_uptime_summary` (or any of the
        other three moved computations) is moved back inside the
        with-block -- see PYTHON_SHARE_CEILING's own docstring for the
        measured before/after values that calibrated it."""
        for _ in range(5):
            response = self.client.get('/api/services')
            self.assertEqual(response.status_code, 200)

        snap = lockprofile.snapshot()
        route = snap['routes']['/api/services']
        python_share = route['python_ns_total'] / route['hold_ns_total']
        self.assertLess(
            python_share, self.PYTHON_SHARE_CEILING,
            f"/api/services' held-region Python share measured {python_share:.4f} -- "
            f'a share at or above {self.PYTHON_SHARE_CEILING} means a computation moved '
            'back inside the critical section (D-DEBT-06-01, PROH-OPS-04-06). '
            'Developer-machine evidence (PROH-OPS-07-09), not Pi evidence.',
        )
        self.assertEqual(
            snap['clamped_python_count'], 0,
            f"clamped_python_count is {snap['clamped_python_count']}, not 0 -- the derived "
            'python_ns_total remainder is untrustworthy in this snapshot, so the measured '
            'share above cannot be trusted either (D-DEBT-06-10).',
        )

    def test_the_moved_work_still_registers_as_python_when_run_inside_a_held_region(self):
        """Direction B: the instrument's sensitivity, not the fix. Running
        the SAME moved work (over the SAME seeded data) inside a synthetic
        held region reports a HIGH Python share -- proving direction A's low
        share is a measured absence of this work, not a blind spot in the
        instrument itself."""
        appmod = self.appmod
        checks = self.checks_by_port[self.offline_port]
        windows = self.windows
        offline_intervals = self.offline_intervals
        now = int(time.time())

        from dashboard.beacon.db import connect_db

        conn = connect_db(self.db_path)
        try:
            def work():
                conn.execute('SELECT 1').fetchall()
                appmod._uptime_summary(checks, now)
                appmod.beacon_maintenance.attributed_downtime_seconds(
                    offline_intervals, windows, appmod.SETTINGS.timezone,
                )

            self._run_in_held_region('synthetic-python-06-20', work)
        finally:
            conn.close()

        snap = lockprofile.snapshot()
        route = snap['routes']['synthetic-python-06-20']
        python_share = route['python_ns_total'] / route['hold_ns_total']
        self.assertGreater(
            python_share, 0.75,
            f'synthetic held region running the moved work reported Python share '
            f'{python_share:.4f}, expected above 0.75 -- the instrument is not tracking '
            "this work's cost in the direction it should, which would make direction "
            "A's low share meaningless rather than reassuring.",
        )


class RequestAccountingTests(_InstrumentedLockTestCase):
    """06-16 Task 2: decompose every request's wall time into on-CPU,
    lock-wait, and other-off-CPU. Every millisecond figure here is
    developer-machine evidence, never Pi evidence (`PROH-OPS-07-09`).

    Probe routes are registered directly on this test's own throwaway Flask
    app instance -- `_InstrumentedLockTestCase.setUp` (via `load_app()`)
    reloads `dashboard.app` fresh for every single test method, so a probe
    route added here never reaches `dashboard/app.py`'s committed source and
    cannot leak into any other test's app object.
    """

    SLEEP_S = 0.05
    LOCK_HOLD_S = 0.1

    def setUp(self):
        super().setUp()
        app = self.appmod.app

        def sleeping_view():
            time.sleep(self.SLEEP_S)
            return self.appmod.jsonify({'ok': True})

        def cpu_view():
            total = 0
            for i in range(3_000_000):
                total += i * i
            return self.appmod.jsonify({'total': total})

        def lock_wait_view():
            with self.appmod._db_lock:
                pass
            return self.appmod.jsonify({'ok': True})

        def raising_view():
            raise RuntimeError('06-16 probe error')

        app.add_url_rule('/test-06-16/sleep', 'test_06_16_sleep', sleeping_view)
        app.add_url_rule('/test-06-16/cpu', 'test_06_16_cpu', cpu_view)
        app.add_url_rule('/test-06-16/lock-wait', 'test_06_16_lock_wait', lock_wait_view)
        app.add_url_rule('/test-06-16/raise', 'test_06_16_raise', raising_view)

    def test_sleeping_lock_free_route_reports_off_cpu_within_tolerance(self):
        """A route that sleeps a known duration and takes no lock reports
        `other_off_cpu_ns_total` within 20% of the sleep and `cpu_ns_total`
        well below it -- off-CPU time is measured, not assumed."""
        resp = self.client.get('/test-06-16/sleep')
        self.assertEqual(resp.status_code, 200)

        route = lockprofile.snapshot()['requests']['/test-06-16/sleep']
        sleep_ns = self.SLEEP_S * 1_000_000_000
        self.assertGreaterEqual(
            route['other_off_cpu_ns_total'], sleep_ns * 0.8,
            f"other_off_cpu_ns_total {route['other_off_cpu_ns_total']} below 80% of the "
            f'known {sleep_ns:.0f}ns sleep',
        )
        self.assertLessEqual(
            route['other_off_cpu_ns_total'], sleep_ns * 1.2 + 10_000_000,
            f"other_off_cpu_ns_total {route['other_off_cpu_ns_total']} exceeds 120% of the "
            f'known {sleep_ns:.0f}ns sleep plus 10ms slack',
        )
        self.assertLess(route['cpu_ns_total'], sleep_ns * 0.5)

    def test_cpu_bound_lock_free_route_reports_high_on_cpu_fraction(self):
        """A route that does a fixed CPU-bound computation and takes no lock
        reports `cpu_ns_total` at least 70% of `wall_ns_total` -- the
        instrument distinguishes on-CPU from off-CPU in both directions."""
        resp = self.client.get('/test-06-16/cpu')
        self.assertEqual(resp.status_code, 200)

        route = lockprofile.snapshot()['requests']['/test-06-16/cpu']
        self.assertGreaterEqual(
            route['cpu_ns_total'], 0.7 * route['wall_ns_total'],
            f"cpu_ns_total {route['cpu_ns_total']} is below 70% of "
            f"wall_ns_total {route['wall_ns_total']} for a CPU-bound route",
        )

    def test_lock_wait_is_subtracted_out_of_other_off_cpu(self):
        """A request blocked behind a known-duration `_db_lock` holder
        reports `lock_wait_ns_total` within 20% of that duration, and
        `other_off_cpu_ns_total` that does NOT include it -- lock wait is
        subtracted out, so what remains is attributable to something else
        (`D-DEBT-06-09`: the GIL and the lock are measured independently,
        never inferred from each other)."""
        holder_ready = threading.Event()
        waiter_started = threading.Event()

        def holder():
            with self.appmod._db_lock:
                holder_ready.set()
                waiter_started.wait(2)
                time.sleep(self.LOCK_HOLD_S)

        holder_thread = threading.Thread(target=holder, daemon=True)
        holder_thread.start()
        self.assertTrue(holder_ready.wait(2), 'holder failed to acquire the lock in time')

        result = {}

        def waiter():
            waiter_started.set()
            result['resp'] = self.client.get('/test-06-16/lock-wait')

        waiter_thread = threading.Thread(target=waiter, daemon=True)
        waiter_thread.start()
        holder_thread.join(5)
        waiter_thread.join(5)

        self.assertEqual(result['resp'].status_code, 200)
        route = lockprofile.snapshot()['requests']['/test-06-16/lock-wait']
        hold_ns = self.LOCK_HOLD_S * 1_000_000_000
        self.assertGreaterEqual(
            route['lock_wait_ns_total'], 0.8 * hold_ns,
            f"lock_wait_ns_total {route['lock_wait_ns_total']} below 80% of the known "
            f'{hold_ns:.0f}ns holder duration',
        )
        self.assertLess(
            route['other_off_cpu_ns_total'], 0.5 * hold_ns,
            f"other_off_cpu_ns_total {route['other_off_cpu_ns_total']} is a large fraction "
            f'of the {hold_ns:.0f}ns lock-wait duration -- lock wait was not subtracted out',
        )

    def test_identity_holds_by_construction_reported_for_readability(self):
        """Not a guard -- `other_off_cpu_ns_total` is defined as the
        remainder, so this identity cannot fail. Reported for readability
        only, never cited as accuracy evidence (`D-DEBT-06-10`)."""
        resp = self.client.get('/test-06-16/sleep')
        self.assertEqual(resp.status_code, 200)

        route = lockprofile.snapshot()['requests']['/test-06-16/sleep']
        self.assertEqual(
            route['cpu_ns_total'] + route['lock_wait_ns_total'] + route['other_off_cpu_ns_total'],
            route['wall_ns_total'],
        )

    def test_lock_free_route_appears_with_zero_lock_wait(self):
        """`/api/advanced/current` -- the sole exercised route holding no
        lock (`dashboard/beacon/diagnosis.py` has zero `_db_lock`
        references) -- appears in the request table with a non-zero
        `requests` count and zero `lock_wait_ns_total`: the structural
        precondition the GIL probe depends on."""
        resp = self.client.get('/api/advanced/current')
        self.assertEqual(resp.status_code, 200)

        route = lockprofile.snapshot()['requests']['/api/advanced/current']
        self.assertGreater(route['requests'], 0)
        self.assertEqual(route['lock_wait_ns_total'], 0)

    def test_raising_handler_still_closes_its_accounting_region(self):
        """A request that raises inside the handler still closes its
        accounting region -- `teardown_request` runs on the error path --
        and the route's `requests` count includes it.

        `PROPAGATE_EXCEPTIONS=True` is set for the duration of this one
        request: with it off (Flask's normal non-debug default), Flask
        itself converts an unhandled exception into a 500 response BEFORE
        invoking `after_request` handlers, so an `end_request` registered on
        `after_request` would still fire in that case and this test would
        not distinguish the two hooks. With it on, Flask lets the exception
        propagate WITHOUT building a response at all -- `after_request`
        handlers never run, but `teardown_request` handlers still do. This
        is the scenario that actually requires `end_request` to be wired to
        `teardown_request`, confirmed directly against this interpreter's
        Flask before relying on it."""
        self.appmod.app.config['PROPAGATE_EXCEPTIONS'] = True
        try:
            with self.assertRaises(RuntimeError):
                self.client.get('/test-06-16/raise')
        finally:
            self.appmod.app.config['PROPAGATE_EXCEPTIONS'] = False

        route = lockprofile.snapshot()['requests']['/test-06-16/raise']
        self.assertGreaterEqual(route['requests'], 1)

    def test_clamped_off_cpu_count_is_zero_across_the_workload(self):
        """Load-bearing: no measurement error is silently absorbed into
        `other_off_cpu_ns` across a representative mixed workload. A
        non-zero count would mean lock-wait exceeded off-CPU time -- the two
        clocks disagreeing or accounting leaking across threads."""
        self.client.get('/test-06-16/sleep')
        self.client.get('/test-06-16/cpu')
        self.client.get('/api/scan-status')
        self.client.get('/api/services')

        self.assertEqual(lockprofile.snapshot()['clamped_off_cpu_count'], 0)

    def test_disabled_profile_timer_stays_at_zero_across_25_requests(self):
        """With the profile disabled, the counting stub over
        `lockprofile._timer_ns` remains at exactly 0 calls across 25 driven
        requests -- unchanged from `06-15`'s inertness guarantee."""
        appmod, db_path = load_app()
        try:
            self.assertFalse(appmod.ENABLE_LOCK_PROFILE)
            lockprofile.ENABLED = False
            call_count = {'timer': 0}
            original_timer = lockprofile._timer_ns

            def counting_timer():
                call_count['timer'] += 1
                return original_timer()

            client = appmod.app.test_client()
            routes = ('/api/services', '/api/scan-status', '/api/history')
            with mock.patch.object(lockprofile, '_timer_ns', counting_timer):
                for i in range(25):
                    resp = client.get(routes[i % len(routes)])
                    self.assertEqual(resp.status_code, 200)
            self.assertEqual(call_count['timer'], 0)
        finally:
            cleanup_db(db_path)


class ConcurrentRehearsalTests(_InstrumentedLockTestCase):
    """06-16 Task 3: rehearse at concurrency 8 against the real Flask app,
    using the acceptance harness's own route rotation, and prove every one
    of `06-VERIFICATION.md` Truth 5's measurement questions is answerable
    from a single snapshot pair. Every figure this class prints or asserts
    on is developer-machine evidence, never Pi evidence (`PROH-OPS-07-09`).

    Does not import `tests/pi_load_acceptance.py` (`PROH-OPS-07-01`, and
    that module's CLI has side effects on import in some configurations) --
    the rotation order is read from its source via `ast` and compared
    against a literal list kept here, so this rehearsal cannot silently
    drift from the real harness without failing loudly.
    """

    PORTS = (9900, 9901, 9902)
    THREAD_COUNT = 8
    DURATION_S = 3.0

    # Mirrors _routes_for_ports' literal tuple in tests/pi_load_acceptance.py
    # -- verified against that file's own source in
    # test_rotation_matches_pi_load_acceptance below, not merely assumed.
    LITERAL_ROUTE_LABELS = (
        '/api/services', '/api/scan-status', '/api/thumbnail-status',
        '/api/history', '/api/advanced/current',
    )

    def setUp(self):
        super().setUp()
        self._seed_representative_services()

    def _seed_representative_services(self):
        """Enough services and stored checks that /api/services does real
        work rather than returning an empty result -- the idiom
        tests/test_services_route_scaling.py::ServiceCountScalingTests
        establishes."""
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                for port in self.PORTS:
                    conn.execute(
                        "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                        "VALUES(?,?,?,?,?,?)",
                        (port, f'Service {port}', now - 3600, now, 1, now - 60),
                    )
                    for j in range(30):
                        ts = now - (30 - j) * 30
                        conn.execute(
                            'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                            (ts, port, 1 if j % 5 else 0),
                        )
                conn.commit()
            finally:
                conn.close()

    def _rotation_urls(self):
        return list(self.LITERAL_ROUTE_LABELS) + [f'/api/thumbnail/{port}' for port in self.PORTS]

    def _run_rotation_workers(self):
        """Starts THREAD_COUNT daemon workers walking the rotation
        closed-loop for DURATION_S, joins them, and returns any server
        errors observed. daemon=True for the same reason 06-15's mutual-
        exclusion test uses it: join() already bounds the wait, so a lock
        that loses mutual exclusion still reaches the assertions, but a
        non-daemon worker blocked forever would prevent the interpreter
        from exiting."""
        urls = self._rotation_urls()
        errors = []
        errors_lock = threading.Lock()

        def worker():
            client = self.appmod.app.test_client()
            index = 0
            deadline = time.monotonic() + self.DURATION_S
            while time.monotonic() < deadline:
                url = urls[index % len(urls)]
                index += 1
                try:
                    resp = client.get(url)
                    if resp.status_code >= 500:
                        with errors_lock:
                            errors.append((url, resp.status_code))
                except Exception as exc:
                    with errors_lock:
                        errors.append((url, repr(exc)))

        threads = [
            threading.Thread(target=worker, daemon=True) for _ in range(self.THREAD_COUNT)
        ]
        start = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(self.DURATION_S + 15)
        elapsed = time.monotonic() - start
        return errors, elapsed

    def test_rotation_matches_pi_load_acceptance(self):
        """The literal rotation this rehearsal drives matches the order
        `_routes_for_ports` actually builds -- read from that file's own
        source, never imported (`PROH-OPS-07-01`). Fails loudly if the
        harness's rotation changes without this test being updated."""
        source = Path('tests/pi_load_acceptance.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        func = _find_function_def(tree, '_routes_for_ports')
        self.assertIsNotNone(func, '_routes_for_ports not found in tests/pi_load_acceptance.py')

        labels = None
        for node in ast.walk(func):
            if isinstance(node, ast.comprehension) and isinstance(node.iter, ast.Tuple):
                labels = tuple(elt.value for elt in node.iter.elts)
                break
        self.assertIsNotNone(
            labels, 'could not locate the literal route-label tuple in _routes_for_ports',
        )
        self.assertEqual(
            labels, self.LITERAL_ROUTE_LABELS,
            "tests/pi_load_acceptance.py's route rotation changed -- update "
            'LITERAL_ROUTE_LABELS above to match, deliberately.',
        )

    def test_eight_thread_rehearsal_answers_every_truth_5_question(self):
        """Drives the real Flask app from 8 threads in a closed loop, using
        the same route rotation `_routes_for_ports` builds, for a bounded
        interval. Asserts the snapshot pair answers every one of Truth 5's
        measurement questions."""
        snap_before = lockprofile.snapshot()
        errors, elapsed = self._run_rotation_workers()

        self.assertEqual(errors, [], f'{len(errors)} server errors during the rehearsal: {errors[:5]}')
        self.assertLess(elapsed, 30, f'rehearsal took {elapsed:.1f}s, expected under 30s')

        snap_after = lockprofile.snapshot()
        routes = snap_after['routes']
        requests = snap_after['requests']

        # Item 1 (wait vs hold, per route): every lock-taking rotation route
        # appears with acquisitions > 0, wait_ns_total >= 0, hold_ns_total > 0.
        for label in self.LITERAL_ROUTE_LABELS:
            if label == '/api/advanced/current':
                continue
            route = routes.get(label)
            self.assertIsNotNone(route, f'{label} missing from acquisition table')
            self.assertGreater(route['acquisitions'], 0, f'{label} acquisitions == 0')
            self.assertGreaterEqual(route['wait_ns_total'], 0)
            self.assertGreater(route['hold_ns_total'], 0, f'{label} hold_ns_total == 0')
        thumbnail_route = routes.get('/api/thumbnail/<int:port>')
        self.assertIsNotNone(thumbnail_route, 'thumbnail route missing from acquisition table')
        self.assertGreater(thumbnail_route['acquisitions'], 0)

        # Item 2 (utilisation): in [0, 1], > 0 under this load, and the
        # per-route hold totals sum exactly to the global hold total.
        hold_delta = snap_after['lock']['hold_ns_total'] - snap_before['lock']['hold_ns_total']
        time_delta = snap_after['captured_monotonic_ns'] - snap_before['captured_monotonic_ns']
        utilisation = hold_delta / time_delta
        self.assertGreaterEqual(utilisation, 0)
        self.assertLessEqual(utilisation, 1)
        self.assertGreater(utilisation, 0)
        total_hold = sum(route['hold_ns_total'] for route in routes.values())
        self.assertEqual(total_hold, snap_after['lock']['hold_ns_total'])

        # Item 4 (SQL share of the critical section): /api/services' shares
        # sum to 1 (by construction), and are reported, never pinned to
        # 06-PROFILE.md's laptop-under-cProfile figure (PROH-OPS-07-09).
        services_route = routes['/api/services']
        hold = services_route['hold_ns_total']
        sql_share = (services_route['sql_execute_ns_total'] + services_route['sql_fetch_ns_total']) / hold
        connect_share = services_route['connect_ns_total'] / hold
        python_share = services_route['python_ns_total'] / hold
        self.assertAlmostEqual(sql_share + connect_share + python_share, 1.0, places=6)
        print(
            '06-16 rehearsal (developer-machine evidence, PROH-OPS-07-09): '
            f'/api/services sql_share={sql_share:.4f} connect_share={connect_share:.4f} '
            f'python_share={python_share:.4f} utilisation={utilisation:.4f}',
        )

        # Item 3 (GIL separated from lock): /api/advanced/current -- the one
        # exercised route holding no lock -- has lock_wait_ns_total == 0 and
        # a non-zero other_off_cpu_ns_total, independently populated.
        advanced_current = requests.get('/api/advanced/current')
        self.assertIsNotNone(advanced_current, '/api/advanced/current missing from request table')
        self.assertEqual(advanced_current['lock_wait_ns_total'], 0)
        self.assertGreater(advanced_current['other_off_cpu_ns_total'], 0)
        total_requests = snap_after['requests_total']['requests']
        print(
            f"06-16 rehearsal: clamped_off_cpu_count={snap_after['clamped_off_cpu_count']} "
            f"clamped_python_count={snap_after['clamped_python_count']} "
            f'of {total_requests} requests / {snap_after["lock"]["acquisitions"]} acquisitions',
        )

        # Self-consistency under real concurrency. clamped_python_count is
        # load-bearing at exactly 0 -- observed stable at 0 across every
        # rehearsal run during development, and mutation-verified below to
        # jump to over 20% under real thread-local corruption.
        # clamped_off_cpu_count is bounded, not zero -- see
        # test_self_consistency_survives_eight_threads for why: it is a
        # small (~1-3%), reproducible artifact of comparing two independent
        # stdlib clocks (_timer_ns()/monotonic_ns vs time.thread_time_ns())
        # under closed-loop, zero-think-time 8-thread contention on this
        # development machine, discovered and characterised while writing
        # this test -- not the >20% signal a genuine defect produces
        # (mutation-verified below).
        self.assertEqual(snap_after['clamped_python_count'], 0)
        self.assertLess(
            snap_after['clamped_off_cpu_count'], 0.10 * total_requests,
            f"clamped_off_cpu_count {snap_after['clamped_off_cpu_count']} exceeds 10% of "
            f'{total_requests} requests -- see test_self_consistency_survives_eight_threads '
            'for the expected small baseline versus a genuine defect.',
        )

        # Bounded cost: reader knows what a 600s hardware run will look like.
        serialized_size = len(json.dumps(snap_after))
        self.assertLess(serialized_size, 5_000_000, 'snapshot JSON size unexpectedly large')
        self.assertLessEqual(len(routes), lockprofile.MAX_TRACKED_ROUTES)
        print(
            f'06-16 rehearsal: snapshot JSON size={serialized_size} bytes, '
            f'route table size={len(routes)}',
        )

        # Per-route wait/hold, for the SUMMARY's laptop-rehearsal baseline.
        for label in ('/api/services', '/api/scan-status'):
            route = routes[label]
            print(
                f'06-16 rehearsal: {label} acquisitions={route["acquisitions"]} '
                f'wait_ns_total={route["wait_ns_total"]} hold_ns_total={route["hold_ns_total"]}',
            )

    def test_self_consistency_survives_eight_threads(self):
        """`sum(per-route hold) == global hold` holds exactly under real
        eight-thread contention. In THIS collector's design that identity
        holds by construction -- `record_acquisition` updates the per-route
        bucket and the global total from the SAME values in one call under
        one lock, so it cannot diverge regardless of which thread or which
        route the values belong to. Kept as a sanity check, but -- per
        `D-DEBT-06-10`'s own instruction not to cite a by-construction
        identity as accuracy evidence -- it is NOT this test's real
        concurrency guard; confirmed directly by running the mutation named
        below (against the actual source, via Edit, not a monkeypatch) and
        observing this specific identity still hold exactly
        (2,494,319,763 == 2,494,319,763 in the mutation-verification run)
        even while it was actively corrupting other numbers.

        `clamped_python_count` and `clamped_off_cpu_count` ARE the real
        concurrency guards: the single-threaded unit tests in
        HoldDecompositionTests/RequestAccountingTests cannot exercise the
        cross-thread races that push them up. `clamped_python_count` is
        asserted at exactly 0 -- observed stable at 0 across every
        development rehearsal run. `clamped_off_cpu_count` is bounded, not
        zero: comparing two independent stdlib clocks
        (`time.monotonic_ns()` for wait/hold vs `time.thread_time_ns()` for
        CPU time) under zero-think-time 8-thread contention on this
        development machine produces a small (~1-3% of requests),
        reproducible clock-resolution artifact -- exactly the "clock
        granularity" scenario `end_request`'s own docstring names and the
        clamp mechanism exists to make visible rather than silently absorb,
        not a correctness defect. 10% is a generous ceiling well above that
        baseline and well below what the real defect below produces.

        Mutation target: `_ACQUIRE_STATE` and `_REQUEST_STATE` (both
        `threading.local()`) temporarily replaced with a single shared
        plain-object namespace, simulating a thread-local leak. Under eight
        threads this corrupts cross-thread attribution in a way no
        single-threaded test can see: mutation-verified against the actual
        source (dashboard/beacon/lockprofile.py, reverted after) --
        observed `clamped_python_count` jump from 0 to 706/3255
        acquisitions (21.7%) and `clamped_off_cpu_count` jump from ~1-3% to
        2505/3712 requests (67.5%) -- both far past the bounds asserted
        below. `sum(per-route hold) == global hold` did NOT break under
        this mutation (2,494,319,763 == 2,494,319,763), confirming the
        docstring paragraph above."""
        errors, elapsed = self._run_rotation_workers()
        self.assertEqual(errors, [], f'{len(errors)} server errors during the rehearsal: {errors[:5]}')
        self.assertLess(elapsed, 30)

        snap = lockprofile.snapshot()
        total_hold = sum(route['hold_ns_total'] for route in snap['routes'].values())
        self.assertEqual(total_hold, snap['lock']['hold_ns_total'])
        total_requests = snap['requests_total']['requests']
        self.assertEqual(snap['clamped_python_count'], 0)
        self.assertLess(
            snap['clamped_off_cpu_count'], 0.10 * total_requests,
            f"clamped_off_cpu_count {snap['clamped_off_cpu_count']} exceeds 10% of "
            f'{total_requests} requests -- see this test\'s own docstring for the '
            'expected small baseline versus a genuine thread-local-leak defect.',
        )


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
        """The same interleaved ABAB comparison, against the exact _db_lock a
        flag-off deployment uses, asserting the same 1.02x bound.

        WHAT THIS TEST DOES **NOT** DO, corrected after measurement: an
        earlier docstring claimed it guarded "against a future regression
        that wraps the lock even when the flag is off". It does not, and
        cannot. Mutating dashboard/app.py's `if ENABLE_LOCK_PROFILE:` to
        `if True:` -- the exact regression named -- leaves this test GREEN,
        because a disabled InstrumentedLock adds roughly 0.1% while
        reference_work() below costs milliseconds. The signal is buried
        under the fixture.

        That regression IS caught, by six tests including
        test_zero_timing_work_when_disabled and
        test_disabled_profile_timer_stays_at_zero_across_25_requests --
        the zero-timer-call checks 06-15 deliberately chose over an
        isinstance shape check. Verified by running that mutation.

        What this test actually asserts is narrower and still worth having:
        the flag-off lock's cost is indistinguishable from a bare
        threading.Lock at best-of-N. Read it as a cost check, not a
        wrapping check, and do not let its green reassure you about
        wrapping."""
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

            # Compare MINIMA, not sums. When the flag is off `_db_lock` IS a
            # bare threading.Lock, so the true ratio is 1.000 and anything
            # above it is measurement noise. Summing 30 timed iterations
            # accumulates that noise, and it is one-sided -- a scheduler
            # hiccup only ever ADDS time, never removes it -- so the summed
            # ratio drifted past the 1.02 bound on roughly 3 runs in 5 while
            # the real overhead is ~0.1%. The minimum of N samples is the
            # standard estimator for exactly this reason: it is the sample
            # least contaminated by one-sided noise. Alternating order within
            # each pair also removes the position bias the original had, where
            # the disabled arm always ran second.
            iterations = 30
            bare_samples = []
            disabled_samples = []

            def _time_once(lock):
                start = time.perf_counter_ns()
                with lock:
                    reference_work()
                return time.perf_counter_ns() - start

            for index in range(iterations):
                if index % 2 == 0:
                    bare_samples.append(_time_once(raw_lock))
                    disabled_samples.append(_time_once(disabled_lock))
                else:
                    disabled_samples.append(_time_once(disabled_lock))
                    bare_samples.append(_time_once(raw_lock))

            bare_min_ns = min(bare_samples)
            disabled_min_ns = min(disabled_samples)
            ratio = disabled_min_ns / bare_min_ns
            self.assertLessEqual(
                ratio, 1.02,
                "flag-off deployment's _db_lock cost "
                f'{ratio:.4f}x a bare threading.Lock at best-of-{iterations} '
                f'(bare_min={bare_min_ns}ns disabled_min={disabled_min_ns}ns) '
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

            # Compare MINIMA, not sums -- identical reasoning to
            # test_disabled_wrapper_path_costs_nothing_measurable, whose
            # summed form failed 3 runs in 5 in isolation. Measurement noise
            # here is one-sided (a scheduler hiccup only ADDS time), so a sum
            # accumulates it while the minimum of N samples does not. Order
            # alternates within each pair so neither arm systematically runs
            # second. Still a same-run ratio, never an absolute wall-clock
            # threshold (WR-03).
            iterations = 30
            bare_samples = []
            instrumented_samples = []

            def _time_once(lock):
                start = time.perf_counter_ns()
                with lock:
                    reference_work()
                return time.perf_counter_ns() - start

            for index in range(iterations):
                if index % 2 == 0:
                    bare_samples.append(_time_once(raw_lock))
                    instrumented_samples.append(_time_once(instrumented_lock))
                else:
                    instrumented_samples.append(_time_once(instrumented_lock))
                    bare_samples.append(_time_once(raw_lock))

            bare_total_ns = min(bare_samples)
            instrumented_total_ns = min(instrumented_samples)
            ratio = instrumented_total_ns / bare_total_ns
            self.assertLessEqual(
                ratio, 1.02,
                f'WR-03 / D-DEBT-06-10: instrumented arm cost {ratio:.4f}x the '
                f'bare arm at best-of-{iterations} interleaved iterations '
                f'(bare_min={bare_total_ns}ns instrumented_min={instrumented_total_ns}ns) '
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


# ---------------------------------------------------------------------------
# 06-20 Task 1: golden-output equivalence across the api_services narrowing.
#
# T-06-105: a fixture regenerated to match a changed output converts this
# guard into a rubber stamp. `_REGENERATE_GOLDEN_FIXTURES` is read by
# `generate_golden_fixtures()` alone -- no test in this module reads it, so
# a normal test run can never silently regenerate a fixture.
# ---------------------------------------------------------------------------

_GOLDEN_FIXTURES_DIR = Path('tests/fixtures')
_GOLDEN_MAINTENANCE_PATH_FIXTURE = _GOLDEN_FIXTURES_DIR / 'api_services_pre_narrowing_golden.json'
_GOLDEN_OVER_CAP_FIXTURE = _GOLDEN_FIXTURES_DIR / 'api_services_pre_narrowing_over_cap_golden.json'
_GOLDEN_EMPTY_FIXTURE = _GOLDEN_FIXTURES_DIR / 'api_services_pre_narrowing_empty_golden.json'
_REGENERATE_GOLDEN_FIXTURES = False

# Frozen clock for every golden case -- Tuesday 2023-11-14 22:13:20 UTC.
# CHECK_RETENTION_SECONDS at the test env's default EXPIRE_DAYS=7 is fixed
# (UPTIME_WINDOW_SECONDS + 86400 = 691200), independent of EXPIRE_DAYS.
_GOLDEN_FROZEN_NOW = 1700000000
_GOLDEN_CHECK_RETENTION_SECONDS = 691200
_ALWAYS_COVERING_WINDOW = dict(
    start_minute=0, duration_minutes=1440, weekdays='1,2,3,4,5,6,7', grace_minutes=0,
)


def _golden_insert_service(conn, *, port, title, first_seen, last_seen, is_online, state_since,
                            last_latency_ms, last_error, display_name, url, critical, pinned_order,
                            tags, healthy_statuses):
    conn.execute(
        'INSERT INTO services (port, title, first_seen, last_seen, is_online, state_since, '
        'last_latency_ms, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (port, title, first_seen, last_seen, is_online, state_since, last_latency_ms, last_error),
    )
    conn.execute(
        'INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags, '
        'healthy_statuses) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (port, display_name, url, critical, pinned_order, tags, healthy_statuses),
    )


def _golden_insert_window(conn, *, port, created_ts):
    conn.execute(
        'INSERT INTO maintenance_windows (port, start_minute, duration_minutes, weekdays, '
        'grace_minutes, enabled, created_ts, updated_ts) VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
        (port, _ALWAYS_COVERING_WINDOW['start_minute'], _ALWAYS_COVERING_WINDOW['duration_minutes'],
         _ALWAYS_COVERING_WINDOW['weekdays'], _ALWAYS_COVERING_WINDOW['grace_minutes'],
         created_ts, created_ts),
    )


def _golden_insert_checks(conn, *, port, rows):
    """``rows`` is an iterable of ``(ts, online)`` pairs."""
    conn.executemany(
        'INSERT INTO service_checks (ts, port, online) VALUES (?, ?, ?)',
        [(ts, port, online) for ts, online in rows],
    )


def _seed_maintenance_path_case(conn):
    """Three services comfortably under `_OFFLINE_INTERVALS_BULK_ROW_LIMIT`:
    one online (8081, has_thumb, a ready preview, tags, critical), one
    offline and covered by an always-on maintenance window for its entire
    stored history (8082, maintenance_attributed_seconds=691200,
    maintenance_until set), one offline with NO maintenance window (8083,
    real unattributed downtime, alternating uptime buckets). Exercises
    ordinary composition: uptime_pct, buckets, availability, preview and
    thumbnail fields (06-CONTEXT.md D-02)."""
    now = _GOLDEN_FROZEN_NOW
    start_ts = now - _GOLDEN_CHECK_RETENTION_SECONDS

    _golden_insert_service(
        conn, port=8081, title='alpha', first_seen=start_ts - 100000, last_seen=now,
        is_online=1, state_since=start_ts, last_latency_ms=12.5, last_error=None,
        display_name='Alpha', url='http://127.0.0.1:8081', critical=1, pinned_order=1,
        tags='web,critical', healthy_statuses='200-399',
    )
    _golden_insert_service(
        conn, port=8082, title='beta', first_seen=start_ts - 100000, last_seen=now,
        is_online=0, state_since=start_ts + 10000, last_latency_ms=None, last_error='timeout',
        display_name='Beta', url='http://127.0.0.1:8082', critical=0, pinned_order=2,
        tags='', healthy_statuses='200-399',
    )
    _golden_insert_service(
        conn, port=8083, title='gamma', first_seen=start_ts - 100000, last_seen=now,
        is_online=0, state_since=start_ts + 20000, last_latency_ms=None, last_error='connection refused',
        display_name='', url='http://127.0.0.1:8083', critical=0, pinned_order=3,
        tags='infra', healthy_statuses='200-299',
    )

    _golden_insert_window(conn, port=8082, created_ts=start_ts)

    checks_8081 = []
    t, i = start_ts, 0
    while t <= now:
        checks_8081.append((t, 0 if i % 47 == 0 else 1))
        t += 3600
        i += 1
    _golden_insert_checks(conn, port=8081, rows=checks_8081)

    _golden_insert_checks(conn, port=8082, rows=[(start_ts - 3600, 0)])
    checks_8082 = []
    t = start_ts
    while t <= now:
        checks_8082.append((t, 0))
        t += 3600
    _golden_insert_checks(conn, port=8082, rows=checks_8082)

    checks_8083 = []
    t, i = start_ts, 0
    while t <= now:
        checks_8083.append((t, 1 if (i // 12) % 2 == 0 else 0))
        t += 3600
        i += 1
    _golden_insert_checks(conn, port=8083, rows=checks_8083)

    conn.execute(
        'INSERT INTO thumbnails (port, data, mime, captured_ts, source, expires_ts) '
        'VALUES (8081, ?, ?, ?, ?, NULL)',
        (b'\x89PNG\r\n', 'image/png', now - 500, 'screenshot'),
    )
    conn.execute(
        'INSERT INTO preview_requests (port, requested_ts, deadline_ts, status, error, revision) '
        'VALUES (8081, ?, ?, ?, NULL, ?)',
        (now - 60, now + 1740, 'ready', 3),
    )
    conn.execute(
        'INSERT INTO preview_requests (port, requested_ts, deadline_ts, status, error, revision) '
        'VALUES (8082, ?, ?, ?, NULL, ?)',
        (now - 30, now + 1770, 'queued', 1),
    )
    conn.commit()


# Over-cap case ports/shape: 8081 (low port) alone carries more in-window
# rows than `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` (20000), so it exhausts the
# whole budget by itself -- 8090 (high port, the shed region) is processed
# entirely AFTER the budget is spent (`ORDER BY port ASC, ts ASC`), so every
# one of its points is shed under the current cap and admitted in full under
# the required mutation. 8090 carries both a covering maintenance window and
# an offline transition inside the shed region, so the required mutation
# (removing the decrement or its `> 0` guard) is observed to change
# maintenance_attributed_seconds for port 8090 from 0 to a large nonzero
# value -- verified interactively before this fixture was committed (see
# SUMMARY). Port 8081's own maintenance_attributed_seconds (34000, from an
# offline stretch entirely inside the admitted portion) is unaffected by the
# mutation and is the fixture's cap-INsensitive nonzero value.
_OVER_CAP_PORT_LOW = 8081
_OVER_CAP_PORT_HIGH = 8090
_OVER_CAP_LOW_ROW_COUNT = 20200
_OVER_CAP_LOW_STEP = 34
_OVER_CAP_LOW_OFFLINE_ROWS = 1000
_OVER_CAP_HIGH_ROW_COUNT = 60
_OVER_CAP_HIGH_OFFLINE_FROM = 55


def _seed_over_cap_case(conn):
    """20,260 in-window `service_checks` rows across two ports -- strictly
    more than `_OFFLINE_INTERVALS_BULK_ROW_LIMIT` (20000) -- with the excess
    concentrated on the higher-numbered port, per the ``port ASC, ts ASC``
    shedding order. See the module comment above for why port 8090 is the
    cap-sensitive value and port 8081 is the cap-insensitive one."""
    now = _GOLDEN_FROZEN_NOW
    start_ts = now - _GOLDEN_CHECK_RETENTION_SECONDS
    high_step = _GOLDEN_CHECK_RETENTION_SECONDS // _OVER_CAP_HIGH_ROW_COUNT

    _golden_insert_service(
        conn, port=_OVER_CAP_PORT_LOW, title='low', first_seen=start_ts - 100000, last_seen=now,
        is_online=1, state_since=start_ts + _OVER_CAP_LOW_OFFLINE_ROWS * _OVER_CAP_LOW_STEP,
        last_latency_ms=5.0, last_error=None,
        display_name='Low', url='http://127.0.0.1:8081', critical=0, pinned_order=1,
        tags='', healthy_statuses='200-399',
    )
    _golden_insert_service(
        conn, port=_OVER_CAP_PORT_HIGH, title='high', first_seen=start_ts - 100000, last_seen=now,
        is_online=0, state_since=start_ts + _OVER_CAP_HIGH_OFFLINE_FROM * high_step,
        last_latency_ms=None, last_error='timeout',
        display_name='High', url='http://127.0.0.1:8090', critical=0, pinned_order=2,
        tags='', healthy_statuses='200-399',
    )

    _golden_insert_window(conn, port=_OVER_CAP_PORT_LOW, created_ts=start_ts)
    _golden_insert_window(conn, port=_OVER_CAP_PORT_HIGH, created_ts=start_ts)

    # Low port: boundary offline, transitions online at row
    # _OVER_CAP_LOW_OFFLINE_ROWS -- comfortably inside the admitted
    # (pre-shed) portion of the budget regardless of the cap's correctness.
    _golden_insert_checks(conn, port=_OVER_CAP_PORT_LOW, rows=[(start_ts - 100, 0)])
    rows_low = [
        (start_ts + i * _OVER_CAP_LOW_STEP, 0 if i < _OVER_CAP_LOW_OFFLINE_ROWS else 1)
        for i in range(_OVER_CAP_LOW_ROW_COUNT)
    ]
    assert rows_low[-1][0] <= now, 'low-port fixture rows must stay inside the window'
    _golden_insert_checks(conn, port=_OVER_CAP_PORT_LOW, rows=rows_low)

    # High port: boundary online, transitions offline near the end -- the
    # shed region once the low port alone exhausts the budget.
    _golden_insert_checks(conn, port=_OVER_CAP_PORT_HIGH, rows=[(start_ts - 100, 1)])
    rows_high = [
        (start_ts + j * high_step, 0 if j >= _OVER_CAP_HIGH_OFFLINE_FROM else 1)
        for j in range(_OVER_CAP_HIGH_ROW_COUNT)
    ]
    assert rows_high[-1][0] <= now, 'high-port fixture rows must stay inside the window'
    _golden_insert_checks(conn, port=_OVER_CAP_PORT_HIGH, rows=rows_high)

    conn.commit()


def _seed_empty_case(conn):
    """Zero services -- the `if services:` guard's empty path, where
    `result` must still be bound and serialize as `[]`."""
    conn.commit()


_GOLDEN_CASES = {
    'maintenance_path': (_seed_maintenance_path_case, _GOLDEN_MAINTENANCE_PATH_FIXTURE),
    'over_cap': (_seed_over_cap_case, _GOLDEN_OVER_CAP_FIXTURE),
    'empty': (_seed_empty_case, _GOLDEN_EMPTY_FIXTURE),
}


def _capture_golden_response(seed_fn):
    """Fresh app, seeded via ``seed_fn``, one frozen-clock `/api/services`
    request. Returns the raw response body text -- the same text a fixture
    file stores and an equality test compares against."""
    appmod, db_path = load_app()
    try:
        conn = appmod.get_db()
        seed_fn(conn)
        conn.close()
        with mock.patch('time.time', return_value=float(_GOLDEN_FROZEN_NOW)):
            client = appmod.app.test_client()
            response = client.get('/api/services')
            assert response.status_code == 200, response.status_code
            return response.get_data(as_text=True)
    finally:
        cleanup_db(db_path)


def generate_golden_fixtures():
    """Regenerate all three golden fixture files from the CURRENT code.

    Deliberately not called by any test in this module (T-06-105) and not
    reachable through `_REGENERATE_GOLDEN_FIXTURES` alone -- a caller must
    invoke this function directly, by name, to regenerate a fixture. Used
    exactly once, against unmodified pre-narrowing code, to capture the
    three committed fixtures this class compares against; SUMMARY.md
    records the fixtures' `sha256` from that capture.
    """
    _GOLDEN_FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for seed_fn, path in _GOLDEN_CASES.values():
        path.write_text(_capture_golden_response(seed_fn), encoding='utf-8')


class ApiServicesOutputEquivalenceTests(unittest.TestCase):
    """06-20 Task 1: `/api/services` returns byte-identical output across the
    `_db_lock` narrowing (`PROH-OPS-07-05`). Three fixtures, not one --
    the maintenance-path case cannot see the `offline_points_budget` cap's
    behavior (inert below `_OFFLINE_INTERVALS_BULK_ROW_LIMIT`) or the
    empty-services `result`-binding path; each needs its own case. See
    D-DEBT-06-10 and T-06-105 before editing this class."""

    def test_narrowed_route_reproduces_the_pre_narrowing_response_bytes(self):
        for case_name, (seed_fn, fixture_path) in _GOLDEN_CASES.items():
            with self.subTest(case=case_name):
                self.assertTrue(
                    fixture_path.exists(),
                    f'{fixture_path} is missing -- golden fixtures must be generated once, '
                    'from unmodified pre-narrowing code, and committed alongside the '
                    'narrowing itself. See generate_golden_fixtures().',
                )
                expected = fixture_path.read_text(encoding='utf-8')
                actual = _capture_golden_response(seed_fn)
                self.assertEqual(
                    actual, expected,
                    f'/api/services response bytes changed for the {case_name!r} case -- '
                    'the narrowing must be a scope change, never an output change '
                    '(PROH-OPS-07-05). See D-DEBT-06-01 and T-06-105 before editing this '
                    'assertion or regenerating the fixture.',
                )


class LockScopePreservationTests(unittest.TestCase):
    """Pins `_db_lock`'s SCOPE, not merely its call-site count (06-CONTEXT.md
    D-01, PROH-OPS-04-02). If a test in this class fails: `_db_lock`'s scope
    changed. Go to D-DEBT-06-01 in 06-DEBT.md and re-examine the decision
    before editing these assertions to make the test pass. This is the
    routing convention `test_the_deployment_pins_its_gunicorn_concurrency_model`
    established for D-DEBT-06-07.

    The lock WAS narrowed by `06-20`, under the user's `fix-now` decision at
    `06-18` Task 3 -- `api_services` now holds `_db_lock` across database
    reads only. This class pins THAT narrowed shape. A failure here means
    the shape moved again -- most likely one of the four computations
    `06-20` moved out (`_uptime_summary`, `beacon_maintenance.coverage`,
    `beacon_maintenance.attributed_downtime_seconds`,
    `beacon_repositories.offline_intervals_from_points_by_port`) got moved
    back in, silently undoing the fix without changing output (`T-06-101`).
    Go to `D-DEBT-06-01` and `PROH-OPS-04-06` before editing an assertion in
    this class.
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

    def test_api_services_lock_scope_is_database_reads_only(self):
        """Pins the NARROWED shape `06-20` created, using ast. If this test
        fails: `_db_lock`'s scope moved again. Go to `D-DEBT-06-01` and
        `PROH-OPS-04-06` before editing an assertion here -- do not loosen
        this test to make it pass (`T-06-101`)."""
        func = _find_function_def(self.tree, 'api_services')
        self.assertIsNotNone(func, 'api_services function not found in dashboard/app.py')

        with_node = _find_db_lock_with(func)
        self.assertIsNotNone(
            with_node, "api_services no longer has a `with _db_lock` block -- "
            "_db_lock's SCOPE changed. See D-DEBT-06-01.",
        )

        calls_inside_with = {
            _call_target_name(node)
            for node in ast.walk(with_node)
            if isinstance(node, ast.Call)
        }
        required_inside = {
            'beacon_repositories.read_maintenance_windows_by_port',
            'beacon_repositories.read_service_offline_interval_boundaries_by_port',
            'beacon_repositories.get_runtime_state',
        }
        missing_inside = required_inside - calls_inside_with
        self.assertFalse(
            missing_inside,
            f"_db_lock's SCOPE changed: {sorted(missing_inside)} no longer execute inside "
            "api_services' _db_lock with-block. PROH-OPS-04-06 requires every database "
            'read to stay inside the lock. See D-DEBT-06-01 before editing this assertion.',
        )

        forbidden_inside = {
            '_uptime_summary',
            'beacon_maintenance.coverage',
            'beacon_maintenance.attributed_downtime_seconds',
            'beacon_repositories.offline_intervals_from_points_by_port',
        }
        reintroduced = forbidden_inside & calls_inside_with
        self.assertFalse(
            reintroduced,
            f"_db_lock's SCOPE changed: {sorted(reintroduced)} execute INSIDE "
            "api_services' _db_lock with-block again -- one of the four computations "
            '06-20 moved out was moved back in, silently undoing the narrowing without '
            'changing output (T-06-101). See D-DEBT-06-01 and PROH-OPS-04-06 before '
            'editing this assertion.',
        )

        # A computation that vanished entirely (rather than merely moving)
        # would also satisfy "not inside the with-block" -- so each of the
        # four must still appear SOMEWHERE in the function, outside the
        # with-block's own subtree, to catch that failure mode too.
        with_subtree_ids = {id(node) for node in ast.walk(with_node)}
        calls_outside_with = {
            _call_target_name(node)
            for node in ast.walk(func)
            if isinstance(node, ast.Call) and id(node) not in with_subtree_ids
        }
        vanished = forbidden_inside - calls_outside_with
        self.assertFalse(
            vanished,
            f"_db_lock's SCOPE changed: {sorted(vanished)} no longer execute ANYWHERE "
            'in api_services -- a computation vanished entirely rather than merely '
            'moving out of the lock. See D-DEBT-06-01 before editing this assertion.',
        )

        self.assertIsInstance(
            func.body[-1], ast.Return,
            "_db_lock's SCOPE changed: api_services no longer ends with a single "
            'terminal return statement. See D-DEBT-06-01. (This test deliberately does '
            "NOT assert the with-block's index within the function body -- several "
            'statements legitimately follow it now that the narrowing has landed.)',
        )


# ---------------------------------------------------------------------------
# 06-19: the invariant T-06-24 is actually about (06-SECURITY.md), asserted
# directly rather than via LockScopePreservationTests' frozen-scope proxy --
# no route gains unserialized database access. PROH-OPS-04-05 prerequisite 1
# (the per-call-site review of all 28 with-_db_lock sites) lives in
# 06-LOCK-AUDIT.md; the tests below are what stop that document silently
# going stale.
# ---------------------------------------------------------------------------

_DB_LOCK_ESCAPE_CALL_NAMES = {
    'connect_db', 'get_db', 'database_access', 'read_transaction', 'write_transaction',
}


def _db_lock_with_nodes(subtree):
    """Every ``ast.With`` node in ``subtree`` whose items bind the bare
    ``_db_lock`` name -- a function may own more than one:
    ``process_preview_requests`` and ``api_service_meta`` each own two,
    which is why the 28 sites live in only 26 distinct functions. Do NOT
    reuse ``_find_db_lock_with``, which returns the first match only."""
    found = []
    for node in ast.walk(subtree):
        if isinstance(node, ast.With):
            for item in node.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Name) and ctx.id == '_db_lock':
                    found.append(node)
                    break
    return found


def _db_lock_owning_functions(tree):
    """``(FunctionDef, [With, ...])`` for every function -- at any nesting
    depth, so a closure defined inside a _db_lock-owning function is
    inspected as part of its owner -- that owns at least one
    ``with _db_lock`` block. ``api_advanced_current`` (AR-03-01, the one
    route already outside `_db_lock` by accepted decision) owns none and so
    never appears here."""
    owning = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            withs = _db_lock_with_nodes(node)
            if withs:
                owning.append((node, withs))
    return owning


def _bound_connection_names(with_nodes):
    """Union of the identifiers ``database_access(...) as <name>`` binds
    across ``with_nodes`` (normally just ``{'conn'}``)."""
    names = set()
    for with_node in with_nodes:
        for item in with_node.items:
            ctx = item.context_expr
            if (
                isinstance(ctx, ast.Call) and _call_target_name(ctx) == 'database_access'
                and isinstance(item.optional_vars, ast.Name)
            ):
                names.add(item.optional_vars.id)
    return names


def _rebinding_with_subtrees(func_node, bound_names):
    """Every ``ast.With`` node anywhere in ``func_node`` -- _db_lock-owning
    or not -- that itself binds one of ``bound_names``. Its subtree is a
    fresh scope for that name: a sibling ``with _worker_write_transaction(
    ...) as conn:`` block that reuses the identifier ``conn`` for an
    unrelated, independently-opened connection is not an escape of the
    _db_lock connection the name shadows -- it is a different connection
    that happens to share a variable name."""
    subtrees = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name) and item.optional_vars.id in bound_names:
                    subtrees.append(node)
                    break
    return subtrees


def _db_lock_escapes(func_node, with_nodes):
    """Every database access in ``func_node`` that happens outside the
    union of its own ``with _db_lock`` blocks: a load of a name one of
    those blocks bound to a connection, or a call to a function that itself
    opens or borrows a connection (``connect_db``, ``get_db``,
    ``database_access``, ``read_transaction``, ``write_transaction``).
    Returns ``(function_name, lineno, what_escaped)`` tuples."""
    bound_names = _bound_connection_names(with_nodes)
    excluded_ids = {id(n) for w in with_nodes for n in ast.walk(w)}
    for rebinding_with in _rebinding_with_subtrees(func_node, bound_names):
        excluded_ids.update(id(n) for n in ast.walk(rebinding_with))
    violations = []
    for node in ast.walk(func_node):
        if id(node) in excluded_ids:
            continue
        if isinstance(node, ast.Name) and node.id in bound_names and isinstance(node.ctx, ast.Load):
            violations.append((func_node.name, node.lineno, node.id))
        elif isinstance(node, ast.Call):
            target = _call_target_name(node)
            if target in _DB_LOCK_ESCAPE_CALL_NAMES:
                violations.append((func_node.name, node.lineno, target))
    return violations


_AUDIT_TABLE_ROW_RE = re.compile(
    r'^\|\s*\d+\s*\|\s*`(?P<function>[A-Za-z_][A-Za-z0-9_]*)`[^|]*\|\s*(?P<line>\d+)\s*\|'
)


def _audit_table_site_pairs(audit_text):
    """``(function, line)`` pairs parsed out of 06-LOCK-AUDIT.md's per-site
    table, keyed exactly the way the AST derivation below is keyed -- never
    on function name alone, since two functions in this codebase own two
    sites each and a name-keyed set would have 26 members against 28
    sites."""
    pairs = set()
    for line in audit_text.splitlines():
        match = _AUDIT_TABLE_ROW_RE.match(line.strip())
        if match:
            pairs.add((match.group('function'), int(match.group('line'))))
    return pairs


class LockScopeInvariantTests(unittest.TestCase):
    """06-19: the invariant `T-06-24` (`06-SECURITY.md`) is actually about --
    no route gains unserialized database access -- asserted directly rather
    than via `LockScopePreservationTests`' frozen-scope proxy above. `06-20`
    retires that proxy deliberately, in the same commit as the narrowing;
    this class does not, and must not, fail when that happens, because
    `06-20` moves computation out of the critical section, never a database
    call out of it.

    `PROH-OPS-04-05` prerequisite 1 (the per-call-site review of all 28
    `with _db_lock` sites) is `06-LOCK-AUDIT.md`. This class is what stops
    that document silently going stale: `test_every_db_lock_site_is_
    covered_by_the_audit` fails the moment a site's `(function, line)` pair
    drifts from what the table names.
    """

    def setUp(self):
        self.source = Path('dashboard/app.py').read_text(encoding='utf-8')
        self.tree = ast.parse(self.source)
        self.owning = _db_lock_owning_functions(self.tree)

    def test_no_database_access_escapes_the_db_lock(self):
        # T-06-97: a rule that silently matches nothing would pass
        # vacuously and give false assurance. This function count must be
        # recorded (SUMMARY) as evidence the walk matched real sites.
        self.assertGreater(
            len(self.owning), 0,
            'no _db_lock-owning function was found at all -- the AST walk matched '
            'nothing, which would make this invariant pass vacuously (T-06-97).',
        )
        violations = []
        for func_node, with_nodes in self.owning:
            violations.extend(_db_lock_escapes(func_node, with_nodes))
        self.assertFalse(
            violations,
            'database access escaped its owning _db_lock block: '
            f'{violations} -- see D-DEBT-06-01, PROH-OPS-04-05 and 06-SECURITY.md T-06-24 '
            'before editing this assertion. If this fails at HEAD (not against a hand-applied '
            'mutation), the defect is in this rule, never in dashboard/app.py.',
        )

    def test_no_database_access_escapes_the_db_lock_covers_both_two_block_functions(self):
        """`process_preview_requests` and `api_service_meta` each own two
        `_db_lock` blocks. A rule built over a single block (via
        `_find_db_lock_with`, which returns first-match only) would read
        the second block's `conn` as an escape and fail at HEAD on both.
        Neither is excluded, special-cased, or allow-listed here -- both
        are checked by the exact same union-based rule every other site
        uses."""
        owning_by_name = {func.name: withs for func, withs in self.owning}
        for name in ('process_preview_requests', 'api_service_meta'):
            self.assertIn(
                name, owning_by_name, f'{name} not found as a _db_lock-owning function',
            )
            self.assertEqual(
                len(owning_by_name[name]), 2,
                f'{name} expected to own exactly two _db_lock blocks, found '
                f'{len(owning_by_name[name])} -- the two-block shape this test exists to cover.',
            )
        for func_node, with_nodes in self.owning:
            if func_node.name in ('process_preview_requests', 'api_service_meta'):
                violations = _db_lock_escapes(func_node, with_nodes)
                self.assertFalse(
                    violations,
                    f'{func_node.name} (two _db_lock blocks) reported an escape: {violations} -- '
                    'a single-block rule would fail here at HEAD; that is a defect in the rule, '
                    'never in dashboard/app.py. Relax nothing; take the union.',
                )

    def test_api_advanced_current_is_not_reported_as_a_violation(self):
        """AR-03-01: the one route already outside `_db_lock` by accepted
        decision. It owns no `_db_lock` block at all, so it must never
        appear in the owning-function set this invariant walks, and cannot
        appear in any violation list."""
        owning_names = {func.name for func, _ in self.owning}
        self.assertNotIn(
            'api_advanced_current', owning_names,
            'api_advanced_current owns a _db_lock block -- AR-03-01 no longer holds; this is '
            'news, not a test bug.',
        )

    def test_every_db_lock_site_is_covered_by_the_audit(self):
        ast_pairs = {
            (func_node.name, with_node.lineno)
            for func_node, with_nodes in self.owning
            for with_node in with_nodes
        }
        audit_path = Path('.planning/phases/06-workload-resilience-pi-acceptance/06-LOCK-AUDIT.md')
        audit_text = audit_path.read_text(encoding='utf-8')
        audit_pairs = _audit_table_site_pairs(audit_text)

        missing_from_audit = ast_pairs - audit_pairs
        self.assertFalse(
            missing_from_audit,
            f'_db_lock site(s) not named in 06-LOCK-AUDIT.md: {sorted(missing_from_audit)}',
        )
        stale_in_audit = audit_pairs - ast_pairs
        self.assertFalse(
            stale_in_audit,
            f'06-LOCK-AUDIT.md names site(s) that no longer exist in dashboard/app.py: '
            f'{sorted(stale_in_audit)}',
        )

        # Asserted separately and by different names -- conflating row count
        # with distinct-function count is the arithmetic error this
        # criterion exists to prevent (process_preview_requests and
        # api_service_meta each own two sites).
        self.assertEqual(
            len(audit_pairs), 28,
            f'expected 28 rows in 06-LOCK-AUDIT.md (one per _db_lock site), found {len(audit_pairs)}',
        )
        distinct_functions = {name for name, _ in audit_pairs}
        self.assertEqual(
            len(distinct_functions), 26,
            f'expected 26 distinct functions named in 06-LOCK-AUDIT.md, found '
            f'{len(distinct_functions)}',
        )


# ---------------------------------------------------------------------------
# 06-17: coverage for tests/pi_load_acceptance.py's lock-profile collection,
# verdict, and rehearsal. Every millisecond/nanosecond figure these tests
# print is developer-machine evidence, never Pi evidence (PROH-OPS-07-09).
# ---------------------------------------------------------------------------

_HISTOGRAM_LENGTH = len(lockprofile.WAIT_HISTOGRAM_EDGES_NS) + 1


def _bucket(index, count, length=_HISTOGRAM_LENGTH):
    """A histogram list of `length` zeroed buckets with `count` at `index`."""
    histogram = [0] * length
    histogram[index] = count
    return histogram


def _stub_route_stats(**overrides):
    base = {
        'acquisitions': 0, 'wait_ns_total': 0, 'hold_ns_total': 0, 'wait_ns_max': 0,
        'hold_ns_max': 0, 'connect_ns_total': 0, 'lease_ns_total': 0,
        'sql_execute_ns_total': 0, 'sql_fetch_ns_total': 0, 'python_ns_total': 0,
        'wait_histogram': [0] * _HISTOGRAM_LENGTH, 'hold_histogram': [0] * _HISTOGRAM_LENGTH,
    }
    base.update(overrides)
    return base


def _stub_request_stats(**overrides):
    base = {
        'requests': 0, 'wall_ns_total': 0, 'cpu_ns_total': 0, 'lock_wait_ns_total': 0,
        'other_off_cpu_ns_total': 0, 'wall_ns_max': 0, 'cpu_ns_max': 0,
        'wall_histogram': [0] * _HISTOGRAM_LENGTH, 'cpu_histogram': [0] * _HISTOGRAM_LENGTH,
    }
    base.update(overrides)
    return base


def _stub_snapshot(
    *, captured_monotonic_ns, routes=None, lock=None, requests=None, requests_total=None,
    route_overflow=False, request_route_overflow=False, sql_outside_lock_ns=0,
    clamped_python_count=0, clamped_off_cpu_count=0,
    schema_version=harness.LOCK_PROFILE_SCHEMA_VERSION,
):
    """A literal, JSON-shaped stand-in for `lockprofile.snapshot()`'s return
    value, so `diff_lock_profile`/`summarize_lock_profile` tests are
    deterministic and reviewable rather than depending on real timing."""
    return {
        'captured_monotonic_ns': captured_monotonic_ns,
        'captured_epoch': 0.0,
        'schema_version': schema_version,
        'enabled': True,
        'routes': routes or {},
        'lock': lock or _stub_route_stats(),
        'route_overflow': route_overflow,
        'requests': requests or {},
        'requests_total': requests_total or _stub_request_stats(),
        'request_route_overflow': request_route_overflow,
        'sql_outside_lock_ns': sql_outside_lock_ns,
        'clamped_python_count': clamped_python_count,
        'clamped_off_cpu_count': clamped_off_cpu_count,
    }


@contextlib.contextmanager
def _live_beacon_server(*, enable_lock_profile, service_url=None):
    """Start a real Flask app on a real werkzeug server -- the same idiom
    `pi_load_acceptance.run_self_test` uses -- so these tests drive
    `fetch_lock_profile` over real HTTP rather than through the Flask test
    client, and can point `pi_load_acceptance.run_acceptance` at a real
    `--base-url`.

    `ENABLE_LOCK_PROFILE` is set in the environment BEFORE `load_app`'s
    `importlib.reload` (via `extra_env`), the same way it will be set on the
    Pi, rather than by patching the module's attributes after import
    (mirrors `HarnessRehearsalTests`' own rehearsal, and 06-15/06-16's
    `_InstrumentedLockTestCase` idiom for the parts that DO need to patch
    after import).
    """
    from werkzeug.serving import make_server

    appmod, db_path = load_app(
        extra_env={'ENABLE_LOCK_PROFILE': '1' if enable_lock_profile else '0'},
    )
    if enable_lock_profile:
        lockprofile.COLLECTOR.reset()

    now = int(time.time())
    with appmod._db_lock:
        conn = appmod.get_db()
        conn.execute(
            "INSERT INTO services (port, title, first_seen, last_seen, is_online, "
            "last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
            (9950, 'Lock-profile harness fixture', now - 120, now, 1, 12.0, None),
        )
        if service_url is not None:
            conn.execute(
                'INSERT INTO service_meta (port, display_name, url) VALUES (?,?,?)',
                (9950, 'Lock-profile harness fixture', service_url),
            )
        for job_id in harness.ESSENTIAL_JOB_IDS:
            beacon_repositories.record_background_job_succeeded(conn, job_id, now=now)
        conn.commit()
        conn.close()

    server = make_server('127.0.0.1', 0, appmod.app, threaded=True)
    server_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        yield appmod, db_path, f'http://127.0.0.1:{server_port}'
    finally:
        server.shutdown()
        server_thread.join(timeout=5)
        if enable_lock_profile:
            lockprofile.ENABLED = False
            lockprofile.COLLECTOR.reset()
        cleanup_db(db_path)


class LockProfileCollectionTests(unittest.TestCase):
    """06-17 Task 1: the harness collects the lock-profile snapshot pair
    around exactly its own load window, and requesting that measurement can
    never move the run's verdict (PROH-OPS-07-12, T-06-86)."""

    def test_reachable_collection_produces_a_populated_block(self):
        with _live_beacon_server(enable_lock_profile=True) as (appmod, db_path, base_url):
            scenario = harness.LoadScenario(
                duration_seconds=2, base_url=base_url, db_path=db_path, concurrency=2,
                self_test=True, collect_lock_profile=True,
            )
            report = harness.run_acceptance(scenario)

        lock_profile = report.lock_profile
        self.assertTrue(lock_profile['collected'])
        self.assertTrue(lock_profile['instrumented'])
        expected_window_ns = scenario.duration_seconds * 1_000_000_000
        self.assertLess(
            abs(lock_profile['window_ns'] - expected_window_ns), 0.25 * expected_window_ns,
            f"window_ns {lock_profile['window_ns']} not within 25% of {expected_window_ns}",
        )
        for label in ('/api/services', '/api/scan-status'):
            self.assertIn(label, lock_profile['routes'], f'{label} missing from lock_profile routes')
            self.assertGreater(lock_profile['routes'][label]['acquisitions'], 0)

    def test_deterministic_arm_the_collection_block_never_moves_the_verdict(self):
        """T-06-86, the arm that actually proves PROH-OPS-07-12: within ONE
        run, with lock-profile collection failing (the diagnostic endpoint
        disabled) and a deliberately non-empty `failure_reasons` (an
        unopenable `--db` path), `overall_passed`/`failure_reasons`
        captured immediately before the collection block are identical to
        the same two values captured immediately after it.

        Comparing two empty lists would prove nothing -- and here BOTH
        captures ARE empty, because `run_acceptance`'s database-oracle read
        (the one that appends the seeded failure) executes AFTER both
        capture points, not before. This is the orchestrator's correction
        after plan-check revision 1: without an additional assertion, this
        arm silently degenerates into exactly the vacuous comparison it was
        written to avoid. So this test ALSO asserts the run's FINAL
        `failure_reasons` is non-empty, proving the seeded oracle failure
        genuinely occurred and this was a realistic failing run.
        """
        captures = []

        def observer(failure_reasons, overall_passed):
            captures.append((failure_reasons, overall_passed))

        with _live_beacon_server(enable_lock_profile=False) as (appmod, db_path, base_url):
            unopenable_db_path = os.path.join(db_path, 'does-not-exist', 'dashboard.db')
            scenario = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=unopenable_db_path, concurrency=2,
                self_test=True, collect_lock_profile=True, observer=observer,
            )
            report = harness.run_acceptance(scenario)

        self.assertEqual(len(captures), 2, 'observer must fire exactly once before and once after')
        self.assertEqual(
            captures[0], captures[1],
            'overall_passed/failure_reasons moved across the lock-profile collection block',
        )
        self.assertTrue(
            report.failure_reasons,
            'the seeded failing oracle produced no failure_reasons -- this run was vacuous, not '
            "a genuine failing run (see this test's own docstring).",
        )
        self.assertFalse(report.overall_passed)
        self.assertFalse(report.lock_profile['collected'])

    def test_structural_arm_lock_profile_never_feeds_the_verdict(self):
        """T-06-86, structural half: no expression contributing to
        `report.overall_passed` or `report.failure_reasons` anywhere in
        `tests/pi_load_acceptance.py` references `lock_profile` -- proven
        by `ast`, not by two runs happening to agree."""
        source = Path('tests/pi_load_acceptance.py').read_text(encoding='utf-8')
        tree = ast.parse(source)

        def references_lock_profile(node):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name) and 'lock_profile' in sub.id:
                    return True
                if isinstance(sub, ast.Attribute) and 'lock_profile' in sub.attr:
                    return True
            return False

        offending = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == 'overall_passed':
                        if references_lock_profile(node.value):
                            offending.append(('overall_passed assignment', node.lineno))
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute) and func.attr in ('append', 'extend')
                    and isinstance(func.value, ast.Attribute) and func.value.attr == 'failure_reasons'
                ):
                    if any(references_lock_profile(arg) for arg in node.args):
                        offending.append(('failure_reasons mutation', node.lineno))

        self.assertEqual(
            offending, [],
            f'lock_profile leaked into a verdict-affecting expression: {offending} (PROH-OPS-07-12).',
        )

    def test_disabled_endpoint_matches_the_same_run_without_collection(self):
        """Cross-check, smoke-level (not the primary T-06-86 evidence --
        see the deterministic and structural arms above): two separate live
        runs against a profile-disabled server produce the same verdict
        whether or not collection is requested, and the requested run's
        `lock_profile` names the 404."""
        with _live_beacon_server(enable_lock_profile=False) as (appmod, db_path, base_url):
            scenario_without = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
            )
            report_without = harness.run_acceptance(scenario_without)

            scenario_with = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
                collect_lock_profile=True,
            )
            report_with = harness.run_acceptance(scenario_with)

        self.assertEqual(report_with.overall_passed, report_without.overall_passed)
        self.assertEqual(report_with.failure_reasons, report_without.failure_reasons)
        self.assertFalse(report_with.lock_profile['collected'])
        self.assertIn('404', report_with.lock_profile['reason'])

    def test_schema_mismatch_matches_the_same_run_without_collection(self):
        """Same cross-check, forcing a schema_version this harness does not
        understand by patching the constant it checks against -- the real
        endpoint's own snapshot is untouched, so this exercises the real
        HTTP round trip with only the harness's expectation changed."""
        with _live_beacon_server(enable_lock_profile=True) as (appmod, db_path, base_url):
            scenario_without = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
            )
            report_without = harness.run_acceptance(scenario_without)

            scenario_with = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
                collect_lock_profile=True,
            )
            with mock.patch.object(harness, 'LOCK_PROFILE_SCHEMA_VERSION', 999):
                report_with = harness.run_acceptance(scenario_with)

        self.assertEqual(report_with.overall_passed, report_without.overall_passed)
        self.assertEqual(report_with.failure_reasons, report_without.failure_reasons)
        self.assertFalse(report_with.lock_profile['collected'])
        self.assertIn('schema_version', report_with.lock_profile['reason'])

    def test_timeout_matches_the_same_run_without_collection(self):
        with _live_beacon_server(enable_lock_profile=True) as (appmod, db_path, base_url):
            scenario_without = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
            )
            report_without = harness.run_acceptance(scenario_without)

            scenario_with = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
                collect_lock_profile=True,
            )
            with mock.patch.object(
                harness, 'fetch_lock_profile',
                side_effect=requests.exceptions.Timeout('lock-profile fetch timed out'),
            ):
                report_with = harness.run_acceptance(scenario_with)

        self.assertEqual(report_with.overall_passed, report_without.overall_passed)
        self.assertEqual(report_with.failure_reasons, report_without.failure_reasons)
        self.assertFalse(report_with.lock_profile['collected'])

    def test_no_collection_requested_makes_zero_requests_and_reports_empty(self):
        with _live_beacon_server(enable_lock_profile=True) as (appmod, db_path, base_url):
            scenario = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2,
                self_test=True, collect_lock_profile=False,
            )
            with mock.patch.object(harness, 'fetch_lock_profile') as mock_fetch:
                report = harness.run_acceptance(scenario)

        mock_fetch.assert_not_called()
        self.assertEqual(report.lock_profile, {})

    # -- Pure-function unit coverage over literal synthetic snapshots -----

    def test_diff_lock_profile_reproduces_exact_arithmetic_difference(self):
        before = _stub_snapshot(
            captured_monotonic_ns=1_000_000_000,
            routes={'/api/services': _stub_route_stats(
                acquisitions=10, wait_ns_total=1_000, hold_ns_total=2_000,
                wait_histogram=_bucket(0, 1), hold_histogram=_bucket(0, 2),
            )},
            lock=_stub_route_stats(
                acquisitions=10, wait_ns_total=1_000, hold_ns_total=2_000,
                wait_histogram=_bucket(0, 1), hold_histogram=_bucket(0, 2),
            ),
            requests={'/api/services': _stub_request_stats(requests=10, wall_ns_total=5_000)},
            requests_total=_stub_request_stats(requests=10, wall_ns_total=5_000),
            sql_outside_lock_ns=500, clamped_python_count=1, clamped_off_cpu_count=2,
        )
        after = _stub_snapshot(
            captured_monotonic_ns=6_000_000_000,
            routes={'/api/services': _stub_route_stats(
                acquisitions=25, wait_ns_total=4_000, hold_ns_total=9_000,
                wait_histogram=_bucket(0, 4), hold_histogram=_bucket(0, 9),
            )},
            lock=_stub_route_stats(
                acquisitions=25, wait_ns_total=4_000, hold_ns_total=9_000,
                wait_histogram=_bucket(0, 4), hold_histogram=_bucket(0, 9),
            ),
            requests={'/api/services': _stub_request_stats(requests=25, wall_ns_total=13_000)},
            requests_total=_stub_request_stats(requests=25, wall_ns_total=13_000),
            sql_outside_lock_ns=900, clamped_python_count=3, clamped_off_cpu_count=5,
        )

        diff = harness.diff_lock_profile(before, after)

        self.assertEqual(diff['window_ns'], 5_000_000_000)
        self.assertEqual(diff['routes']['/api/services']['acquisitions'], 15)
        self.assertEqual(diff['routes']['/api/services']['wait_ns_total'], 3_000)
        self.assertEqual(diff['routes']['/api/services']['hold_ns_total'], 7_000)
        self.assertEqual(diff['routes']['/api/services']['wait_histogram'][0], 3)
        self.assertEqual(diff['routes']['/api/services']['hold_histogram'][0], 7)
        self.assertEqual(diff['lock']['acquisitions'], 15)
        self.assertEqual(diff['requests']['/api/services']['requests'], 15)
        self.assertEqual(diff['requests_total']['wall_ns_total'], 8_000)
        self.assertEqual(diff['sql_outside_lock_ns'], 400)
        self.assertEqual(diff['clamped_python_count'], 2)
        self.assertEqual(diff['clamped_off_cpu_count'], 3)

    def test_diff_lock_profile_raises_a_named_error_when_counters_go_backwards(self):
        before = _stub_snapshot(
            captured_monotonic_ns=1_000_000_000,
            routes={'/api/services': _stub_route_stats(acquisitions=20)},
        )
        after = _stub_snapshot(
            captured_monotonic_ns=2_000_000_000,
            routes={'/api/services': _stub_route_stats(acquisitions=5)},
        )
        with self.assertRaises(harness.LockProfileCounterWentBackwardsError):
            harness.diff_lock_profile(before, after)

    def test_percentile_from_histogram_brackets_a_known_distribution(self):
        edges = (10, 20, 30, 40, 50)
        counts = [0, 0, 100, 0, 0, 0]  # every observation lands in bucket (20, 30]
        self.assertEqual(harness.percentile_from_histogram(counts, edges, 50), (20, 30))

    def test_percentile_from_histogram_overflow_bucket_has_an_infinite_upper_bound(self):
        edges = (10, 20, 30, 40, 50)
        counts = [0, 0, 0, 0, 0, 100]  # every observation past the last edge
        lower, upper = harness.percentile_from_histogram(counts, edges, 50)
        self.assertEqual(lower, 50)
        self.assertEqual(upper, math.inf)

    def test_percentile_from_histogram_empty_returns_zero_zero(self):
        edges = (10, 20, 30, 40, 50)
        self.assertEqual(harness.percentile_from_histogram([0] * 6, edges, 50), (0, 0))

    def test_utilisation_matches_a_known_held_fraction(self):
        window_ns = 10_000_000_000
        hold_ns = 3_000_000_000  # exactly 30% of the window
        before = _stub_snapshot(captured_monotonic_ns=0, lock=_stub_route_stats(hold_ns_total=0))
        after = _stub_snapshot(
            captured_monotonic_ns=window_ns, lock=_stub_route_stats(hold_ns_total=hold_ns),
        )
        summary = harness.summarize_lock_profile(before, after)
        self.assertAlmostEqual(summary['utilisation'], 0.3, places=9)


def _confirmed_world():
    """The world in which the `_db_lock` attribution holds: `/api/scan-status`
    holds briefly and waits behind a full `/api/services` critical section;
    `/api/services`' hold sits in the predicted band; utilisation is high."""
    return {
        'utilisation': 0.9,
        'route_overflow': False,
        'request_route_overflow': False,
        'routes': {
            '/api/services': {'acquisitions': 500, 'hold_ns_total': 500 * 300_000_000},
            '/api/scan-status': {
                'acquisitions': 500,
                'hold_ns_total': 500 * 1_000_000,
                'wait_ns_total': 500 * 200_000_000,
            },
        },
        'requests': {
            '/api/scan-status': {
                'requests': 500,
                'wall_ns_total': 500 * 240_000_000,
                'lock_wait_ns_total': 500 * 200_000_000,
            },
        },
    }


def _refuted_world():
    """The world in which the attribution does NOT hold, built from
    06-ACCEPTANCE-ROUND3.md's OWN hardware figures (/api/scan-status
    acceptance p50 242.614ms) with the lock-wait component set to a
    negligible share -- the concrete counterfactual `evaluate_lock_attribution`
    must be able to detect. This is the test the round exists for."""
    return {
        'utilisation': 0.9,
        'route_overflow': False,
        'request_route_overflow': False,
        'routes': {
            '/api/services': {'acquisitions': 500, 'hold_ns_total': 500 * 300_000_000},
            '/api/scan-status': {
                'acquisitions': 500,
                'hold_ns_total': 500 * 500_000,
                'wait_ns_total': 500 * 1_000_000,
            },
        },
        'requests': {
            '/api/scan-status': {
                'requests': 500,
                # 242.614ms median wall time, matching 06-ACCEPTANCE-ROUND3.md's
                # acceptance-pass p50 for /api/scan-status.
                'wall_ns_total': 500 * 242_614_000,
                # Negligible lock-wait share of that wall time (~0.4%): the
                # slowdown is real but _db_lock provably is not why.
                'lock_wait_ns_total': 500 * 1_000_000,
            },
        },
    }


def _inconclusive_world_too_few_acquisitions():
    """Too few acquisitions to read a median -- a missing measurement must
    never read as REFUTED."""
    return {
        'utilisation': 0.9,
        'route_overflow': False,
        'request_route_overflow': False,
        'routes': {
            '/api/services': {'acquisitions': 5, 'hold_ns_total': 5 * 300_000_000},
            '/api/scan-status': {
                'acquisitions': 5, 'hold_ns_total': 5 * 1_000_000, 'wait_ns_total': 5 * 200_000_000,
            },
        },
        'requests': {
            '/api/scan-status': {
                'requests': 5, 'wall_ns_total': 5 * 240_000_000, 'lock_wait_ns_total': 5 * 200_000_000,
            },
        },
    }


class LockAttributionVerdictTests(unittest.TestCase):
    """06-17 Task 2: `evaluate_lock_attribution` reaches all three verdicts,
    proven by driving it there from literal, reviewable synthetic summaries
    built from the hardware run's own figures."""

    def test_attribution_holds_world_yields_confirmed(self):
        result = harness.evaluate_lock_attribution(_confirmed_world())
        self.assertEqual(result['verdict'], 'CONFIRMED')
        self.assertTrue(result['checks'])
        for check in result['checks']:
            self.assertTrue(check['held'], check)
            self.assertIn('measured', check)

    def test_attribution_fails_world_yields_refuted(self):
        """The test the round exists for: if this cannot be made to pass,
        the verdict logic cannot refute and the diagnostic is worthless."""
        result = harness.evaluate_lock_attribution(_refuted_world())
        self.assertEqual(result['verdict'], 'REFUTED')
        self.assertIn('lock-wait share', result['reason'])
        self.assertTrue(any(not check['held'] for check in result['checks']))

    def test_under_determined_world_yields_inconclusive_never_refuted(self):
        result = harness.evaluate_lock_attribution(_inconclusive_world_too_few_acquisitions())
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')
        self.assertIn('too few acquisitions', result['reason'])

    def test_route_overflow_yields_inconclusive(self):
        world = _confirmed_world()
        world['route_overflow'] = True
        result = harness.evaluate_lock_attribution(world)
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_collected_false_yields_inconclusive(self):
        result = harness.evaluate_lock_attribution({'collected': False})
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_missing_route_yields_inconclusive(self):
        world = _confirmed_world()
        del world['routes']['/api/scan-status']
        result = harness.evaluate_lock_attribution(world)
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_predictions_match_the_verification_reports_own_stated_figures(self):
        """06-VERIFICATION.md Truth 5's `missing:` items originally stated
        "~200-500ms hold" for /api/services as an absolute band; D-DEBT-06-14
        retired that band (it failed under dataset growth) in favour of
        `services_min_hold_over_scan_status_hold_ratio`, a same-run ratio
        calibrated to round 4's own measured figures (596.245ms / 2.532ms =
        235.5 against the 20.0 floor). The "~0.85" utilisation threshold is
        unchanged. Asserted by full key-set equality, deliberately -- an
        absence check for the two retired keys could pass on a typo; a
        key-set mismatch cannot."""
        predictions = harness.LOCK_ATTRIBUTION_PREDICTIONS
        self.assertEqual(
            set(predictions.keys()),
            {
                'scan_status_max_median_hold_ns',
                'services_min_hold_over_scan_status_hold_ratio',
                'scan_status_min_wait_over_services_hold_fraction',
                'utilisation_superlinear_threshold',
                'min_acquisitions_for_median',
                'min_lock_wait_share_of_wall_for_confirmation',
                'scan_status_slow_wall_threshold_ns',
            },
        )
        self.assertEqual(predictions['services_min_hold_over_scan_status_hold_ratio'], 20.0)
        self.assertEqual(predictions['utilisation_superlinear_threshold'], 0.85)

    def test_evaluate_lock_attribution_is_pure_and_deterministic(self):
        world = _confirmed_world()
        result1 = harness.evaluate_lock_attribution(world)
        result2 = harness.evaluate_lock_attribution(world)
        self.assertEqual(result1, result2)

    def test_round_4_measured_hold_figures_hold_against_the_renamed_ratio_check(self):
        """06-19/D-DEBT-06-14: round 4's own measured hold figures --
        596,245,129ns for /api/services, 2,531,729ns for /api/scan-status
        (06-LOCK-DIAGNOSTIC.md) -- replayed through the renamed
        `services_hold_dominates_scan_status_hold` check must still HOLD.
        This is the demonstration that the retired band's failure was a
        property of the band, not of the data: the same measured reality
        that failed the absolute band (596.2ms outside [200ms, 500ms])
        passes the same-run ratio comfortably."""
        world = {
            'utilisation': 0.9,
            'route_overflow': False,
            'request_route_overflow': False,
            'routes': {
                '/api/services': {'acquisitions': 882, 'hold_ns_total': 882 * 596_245_129},
                '/api/scan-status': {
                    'acquisitions': 880,
                    'hold_ns_total': 880 * 2_531_729,
                    'wait_ns_total': 880 * 2_531_729,
                },
            },
            'requests': {
                '/api/scan-status': {
                    'requests': 880,
                    'wall_ns_total': 880 * 272_392_500,
                    'lock_wait_ns_total': 880 * 269_736_400,
                },
            },
        }
        result = harness.evaluate_lock_attribution(world)
        ratio_check = next(
            check for check in result['checks']
            if check['name'] == 'services_hold_dominates_scan_status_hold'
        )
        self.assertTrue(ratio_check['held'], ratio_check)
        self.assertGreater(ratio_check['measured'], ratio_check['threshold'])
        self.assertAlmostEqual(ratio_check['measured'], 235.5, delta=0.1)


def _confirmed_narrowing_world():
    """The world in which 06-20's narrowing achieved its predicted effect:
    `/api/services`' held region is almost entirely SQL, `python_share`
    well under the confirmation threshold, and utilisation below the
    post-narrowing superlinear threshold."""
    return {
        'collected': True,
        'route_overflow': False,
        'request_route_overflow': False,
        'utilisation': 0.5,
        'clamped_python_count': 0,
        'routes': {
            '/api/services': {
                'acquisitions': 500,
                'python_share': 0.05,
                'sql_share': 0.93,
            },
        },
    }


def _refuted_narrowing_world():
    """`python_share` still at the pre-fix baseline (round 4 measured
    25.0%) -- the Python work provably did not leave the critical
    section."""
    return {
        'collected': True,
        'route_overflow': False,
        'request_route_overflow': False,
        'utilisation': 0.5,
        'clamped_python_count': 0,
        'routes': {
            '/api/services': {
                'acquisitions': 500,
                'python_share': 0.25,
                'sql_share': 0.75,
            },
        },
    }


class NarrowingOutcomeVerdictTests(unittest.TestCase):
    """06-19 Task 3: `evaluate_narrowing_outcome` reaches all three
    verdicts, proven from literal, reviewable synthetic summaries, and its
    verdict never contributes to the run's actual pass/fail oracle
    (`PROH-OPS-07-13`)."""

    def test_confirmed_world_yields_confirmed(self):
        result = harness.evaluate_narrowing_outcome(_confirmed_narrowing_world())
        self.assertEqual(result['verdict'], 'CONFIRMED')
        self.assertTrue(result['checks'])
        for check in result['checks']:
            self.assertTrue(check['held'], check)
            self.assertIn('measured', check)

    def test_refuted_world_yields_refuted(self):
        """The test this round exists for: if this cannot be made to pass,
        the verdict logic cannot refute and the prediction is worthless."""
        result = harness.evaluate_narrowing_outcome(_refuted_narrowing_world())
        self.assertEqual(result['verdict'], 'REFUTED')
        self.assertIn('did not move', result['reason'])
        self.assertTrue(any(not check['held'] for check in result['checks']))

    def test_missing_route_yields_inconclusive(self):
        result = harness.evaluate_narrowing_outcome({
            'collected': True, 'route_overflow': False, 'request_route_overflow': False,
            'routes': {},
        })
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')
        self.assertIn("routes['/api/services']", result['reason'])

    def test_under_sampled_route_yields_inconclusive_never_refuted(self):
        world = _confirmed_narrowing_world()
        world['routes']['/api/services']['acquisitions'] = 5
        result = harness.evaluate_narrowing_outcome(world)
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')
        self.assertIn('too few acquisitions', result['reason'])

    def test_nonzero_clamped_python_count_yields_inconclusive_never_confirmed(self):
        """D-DEBT-06-10: a suspect measurement -- the derived python_share
        remainder went negative at least once -- must never read as
        success, however good the shares themselves look."""
        world = _confirmed_narrowing_world()
        world['clamped_python_count'] = 3
        result = harness.evaluate_narrowing_outcome(world)
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')
        self.assertIn('clamped_python_count', result['reason'])

    def test_collected_false_yields_inconclusive(self):
        result = harness.evaluate_narrowing_outcome({'collected': False})
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_evaluate_narrowing_outcome_is_pure_and_deterministic(self):
        world = _confirmed_narrowing_world()
        result1 = harness.evaluate_narrowing_outcome(world)
        result2 = harness.evaluate_narrowing_outcome(world)
        self.assertEqual(result1, result2)

    def test_structural_arm_narrowing_outcome_never_feeds_the_verdict(self):
        """`PROH-OPS-07-13`, the same shape
        `test_structural_arm_lock_profile_never_feeds_the_verdict` uses: no
        expression contributing to `report.overall_passed` or
        `report.failure_reasons` anywhere in `tests/pi_load_acceptance.py`
        references `narrowing_outcome` -- proven by `ast`, not by two runs
        happening to agree."""
        source = Path('tests/pi_load_acceptance.py').read_text(encoding='utf-8')
        tree = ast.parse(source)

        def references_narrowing_outcome(node):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name) and 'narrowing_outcome' in sub.id:
                    return True
                if isinstance(sub, ast.Attribute) and 'narrowing_outcome' in sub.attr:
                    return True
            return False

        offending = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == 'overall_passed':
                        if references_narrowing_outcome(node.value):
                            offending.append(('overall_passed assignment', node.lineno))
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute) and func.attr in ('append', 'extend')
                    and isinstance(func.value, ast.Attribute) and func.value.attr == 'failure_reasons'
                ):
                    if any(references_narrowing_outcome(arg) for arg in node.args):
                        offending.append(('failure_reasons mutation', node.lineno))

        self.assertEqual(
            offending, [],
            f'narrowing_outcome leaked into a verdict-affecting expression: {offending} '
            '(PROH-OPS-07-13).',
        )

    def test_forced_refuted_narrowing_verdict_matches_the_same_run_without_the_block(self):
        """The behavioral half of `PROH-OPS-07-13`, mirroring
        `test_disabled_endpoint_matches_the_same_run_without_collection`'s
        shape: forcing `evaluate_narrowing_outcome` to return REFUTED for a
        genuinely live run must not move `overall_passed` or
        `failure_reasons` relative to the same run without the diagnostic
        block requested at all."""
        with _live_beacon_server(enable_lock_profile=True) as (appmod, db_path, base_url):
            scenario_without = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
            )
            report_without = harness.run_acceptance(scenario_without)

            scenario_with = harness.LoadScenario(
                duration_seconds=1, base_url=base_url, db_path=db_path, concurrency=2, self_test=True,
                collect_lock_profile=True,
            )
            forced_refuted = {
                'verdict': 'REFUTED', 'reason': 'forced for PROH-OPS-07-13 structural proof',
                'checks': [],
            }
            with mock.patch.object(harness, 'evaluate_narrowing_outcome', return_value=forced_refuted):
                report_with = harness.run_acceptance(scenario_with)

        self.assertEqual(report_with.overall_passed, report_without.overall_passed)
        self.assertEqual(report_with.failure_reasons, report_without.failure_reasons)
        self.assertTrue(report_with.lock_profile.get('collected'))
        self.assertEqual(report_with.lock_profile['narrowing_outcome']['verdict'], 'REFUTED')


def _run_self_test_reliably(**kwargs):
    """`run_self_test` starts its own werkzeug server and issues several
    real HTTP round trips against it in quick succession. Under a
    full-suite run's heavy thread/socket load this occasionally hits one of
    two transient, environment-level failures rather than any defect in the
    collection code: an honest 'target unreachable' early return before the
    accept() backlog is serviced (empty `lock_profile`), or -- observed on
    this development machine -- `errno 49 Can't assign requested address`
    from local ephemeral-port pressure across many short-lived 127.0.0.1
    connections in the same process. Both are the same full-suite-only
    flakiness shape D-DEBT-06-13 documents elsewhere in this suite. Retried
    a bounded few times rather than asserted flaky; reliable every time
    observed in isolation. Any OTHER `collected: False` reason (a genuine
    404, schema mismatch, etc.) is NOT retried -- only these two named
    transient strings are."""
    report = None
    for _ in range(5):
        report = harness.run_self_test(**kwargs)
        target_unreachable = any('target unreachable' in reason for reason in report.failure_reasons)
        lock_profile_reason = report.lock_profile.get('reason') or ''
        transient_lock_profile_failure = (
            kwargs.get('collect_lock_profile')
            and report.lock_profile.get('collected') is False
            and "Can't assign requested address" in lock_profile_reason
        )
        if not target_unreachable and not transient_lock_profile_failure:
            return report
    return report


class HarnessRehearsalTests(unittest.TestCase):
    """06-17 Task 3: rehearses the operator's exact `--lock-profile` command
    path end to end on the developer machine, through `run_self_test` --
    never a substitute for Pi evidence (PROH-OPS-07-09, PROH-OPS-07-11)."""

    def setUp(self):
        self._original_enable = os.environ.get('ENABLE_LOCK_PROFILE')

    def tearDown(self):
        if self._original_enable is None:
            os.environ.pop('ENABLE_LOCK_PROFILE', None)
        else:
            os.environ['ENABLE_LOCK_PROFILE'] = self._original_enable
        lockprofile.ENABLED = False
        lockprofile.COLLECTOR.reset()

    def test_profile_enabled_self_test_returns_a_populated_diagnostic_block(self):
        os.environ['ENABLE_LOCK_PROFILE'] = '1'
        report = _run_self_test_reliably(collect_lock_profile=True)

        self.assertEqual(report.run_kind, 'smoke')
        self.assertTrue(report.lock_profile['collected'])
        self.assertTrue(report.lock_profile['instrumented'])
        self.assertIn(
            report.lock_profile['attribution']['verdict'], {'CONFIRMED', 'REFUTED', 'INCONCLUSIVE'},
        )

    def test_profile_disabled_self_test_matches_the_enabled_runs_overall_passed(self):
        """Enabling collection must not change a run's verdict.

        The cross-run comparison below is retried on DISAGREEMENT, not on a
        named transient. Two separate self-test runs each generate their own
        real HTTP load, so a slow run can trip a latency budget the other
        did not and flip `overall_passed` for reasons that have nothing to do
        with the lock profile -- observed failing 1 run in 3 in isolation
        after 06-20, with the failing run taking 23s against 11s for a
        passing one. That is the same "compares two separate live runs"
        weakness the round-4 plan check raised against 06-17's
        verdict-equivalence arm.

        WHAT THIS TEST DOES **NOT** DO, established by measurement rather
        than assumed. Injecting a deterministic leak into `run_acceptance`
        (`if report.lock_profile.get('collected'): report.overall_passed =
        False`, verified in place) leaves this test GREEN: in the suite's
        context the enabled run's collection does not reach that path, so
        both verdicts stay True and the equality holds trivially. Do not
        read this test's green as evidence that collection cannot influence
        a verdict.

        The guarantee is carried by PROH-OPS-07-13's structural `ast` arm --
        nothing feeding `overall_passed`/`failure_reasons` references
        `lock_profile` -- and by 06-19's behavioral pair test, both
        mutation-verified by their own plans. What THIS test actually
        asserts is the deterministic half below: a disabled run produces an
        empty `lock_profile`. The retry above keeps that half from being
        lost to timing noise; it does not turn the cross-run comparison into
        a leak detector.
        """
        os.environ['ENABLE_LOCK_PROFILE'] = '1'
        attempts = []
        for _ in range(3):
            enabled_report = _run_self_test_reliably(collect_lock_profile=True)
            disabled_report = _run_self_test_reliably(collect_lock_profile=False)
            attempts.append((enabled_report.overall_passed, disabled_report.overall_passed))
            if enabled_report.overall_passed == disabled_report.overall_passed:
                break

        self.assertTrue(
            any(enabled == disabled for enabled, disabled in attempts),
            'enabling lock-profile collection changed overall_passed on every attempt '
            f'{attempts} -- a real leak is deterministic, so this is not timing noise. '
            'See PROH-OPS-07-13 and its structural ast arm.',
        )
        self.assertEqual(disabled_report.lock_profile, {})

    def test_report_round_trips_through_to_json_and_json_loads(self):
        os.environ['ENABLE_LOCK_PROFILE'] = '1'
        report = _run_self_test_reliably(collect_lock_profile=True)

        round_tripped = json.loads(report.to_json())
        self.assertTrue(round_tripped['lock_profile']['collected'])
        self.assertIn(
            round_tripped['lock_profile']['attribution']['verdict'],
            {'CONFIRMED', 'REFUTED', 'INCONCLUSIVE'},
        )

    def test_no_operator_data_leaks_into_the_serialized_report(self):
        """T-06-29, extended to the new block: a distinctive seeded service
        URL, constructed here (never written into a source comment, so the
        assertion cannot be satisfied or defeated by unrelated text), must
        not appear anywhere in the serialized report."""
        distinctive = 'https://lockprofile-t06-29-sentinel-' + str(id(self)) + '.example.invalid/meta'
        os.environ['ENABLE_LOCK_PROFILE'] = '1'

        from werkzeug.serving import make_server

        appmod, db_path = load_app()
        now = int(time.time())
        port = 8080
        with appmod._db_lock:
            conn = appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, "
                "last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (port, 'Self-test smoke service', now - 120, now, 1, 12.0, None),
            )
            conn.execute(
                'INSERT INTO service_meta (port, display_name, url) VALUES (?,?,?)',
                (port, 'Self-test smoke service', distinctive),
            )
            for job_id in harness.ESSENTIAL_JOB_IDS:
                beacon_repositories.record_background_job_succeeded(conn, job_id, now=now)
            conn.commit()
            conn.close()

        server = make_server('127.0.0.1', 0, appmod.app, threaded=True)
        server_port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            scenario = harness.LoadScenario(
                duration_seconds=harness.SELF_TEST_DURATION_SECONDS,
                base_url=f'http://127.0.0.1:{server_port}',
                db_path=db_path,
                concurrency=harness.SELF_TEST_CONCURRENCY,
                self_test=True,
                collect_lock_profile=True,
            )
            report = harness.run_acceptance(scenario)
        finally:
            server.shutdown()
            server_thread.join(timeout=5)
            cleanup_db(db_path)

        serialized = report.to_json()
        self.assertNotIn(distinctive, serialized)
