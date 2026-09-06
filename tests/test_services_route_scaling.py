"""Equivalence, scaling and query-count guards for the /api/services route.

These guards descend from a direct hardware measurement (06-UAT.md,
"Confirmed root cause"): at --concurrency 1 on Pi-class hardware,
/api/services cost p50 2504.6ms / p95 2523.3ms / max 2529.8ms while every
other route measured 3-98ms. The cause was a nested loop in
`_legacy_uptime_summary` that rescanned every stored check interval once per
hourly bucket (168 buckets x ~2,000-10,000 intervals x 8 services), plus a
per-service offline-interval read inside the route's result loop. This file
pins the exact output of the fix and the scaling/query-count properties the
fix depends on, so a regression back to either shape fails a test rather than
waiting for the next hardware run.
"""

import math
import random
import re
import sqlite3
import time
import unittest
from contextlib import contextmanager
from unittest import mock

import cProfile

from dashboard.beacon import repositories as beacon_repositories
from tests import services_route_profile
from tests.helpers import cleanup_db, load_app


UPTIME_WINDOW_SECONDS = 7 * 86400
UPTIME_BUCKETS = 168


def _reference_uptime_summary(checks, now):
    """Verbatim copy of the pre-optimization `_legacy_uptime_summary`.

    This is the equivalence oracle for the sweep-based rewrite under test.
    It must NEVER be edited to agree with the implementation under test --
    the moment it is "tidied" to match the new algorithm, it stops being
    independent evidence that the two agree and every green run of this
    file becomes meaningless. It is deliberately the O(buckets x intervals)
    nested-loop shape the rewrite replaces.
    """
    start = int(now) - UPTIME_WINDOW_SECONDS
    points = sorted((int(ts), 1 if int(online) else 0) for ts, online in checks if int(ts) <= int(now))
    boundary = None
    in_window = []
    for point in points:
        if point[0] < start:
            boundary = point
        else:
            in_window.append(point)

    intervals = []
    if boundary is not None:
        cursor, state = start, boundary[1]
    elif in_window:
        cursor, state = in_window[0][0], in_window[0][1]
        in_window = in_window[1:]
    else:
        return None, [-1] * UPTIME_BUCKETS

    for ts, next_state in in_window:
        ts = min(max(ts, start), int(now))
        if ts > cursor:
            intervals.append((cursor, ts, state))
        cursor, state = ts, next_state
    if cursor < int(now):
        intervals.append((cursor, int(now), state))

    observed = sum(end - begin for begin, end, _ in intervals)
    online_time = sum((end - begin) for begin, end, online in intervals if online)
    if observed > 0:
        raw_uptime = (online_time / observed) * 100
        uptime = round(raw_uptime, 3)
        if raw_uptime < 100 and uptime == 100:
            uptime = 99.999
    else:
        uptime = None

    bucket_seconds = UPTIME_WINDOW_SECONDS / UPTIME_BUCKETS
    buckets = []
    for idx in range(UPTIME_BUCKETS):
        bucket_start = start + int(idx * bucket_seconds)
        bucket_end = start + int((idx + 1) * bucket_seconds)
        if idx == UPTIME_BUCKETS - 1:
            bucket_end = int(now)
        bucket_observed = 0
        bucket_online = 0
        for begin, end, online in intervals:
            overlap = max(0, min(end, bucket_end) - max(begin, bucket_start))
            bucket_observed += overlap
            if online:
                bucket_online += overlap
        buckets.append(-1 if bucket_observed == 0 else round(bucket_online / bucket_observed, 3))
    return uptime, buckets


class UptimeSummaryDifferentialTests(unittest.TestCase):
    """The sweep-based rewrite must match the pinned reference for every input."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _assert_matches_reference(self, checks, now):
        expected = _reference_uptime_summary(checks, now)
        actual = self.appmod._uptime_summary(checks, now)
        self.assertEqual(actual, expected)

    def test_randomized_histories_match_the_reference(self):
        # Seeded so a failure is reproducible (06-08-PLAN.md Task 1).
        rng = random.Random(20260901)
        base_now = 1_700_000_000
        bucket_seconds = UPTIME_WINDOW_SECONDS / UPTIME_BUCKETS
        for _ in range(400):
            now = base_now + rng.randint(-10_000, 10_000)
            if rng.random() < 0.25:
                # A fractional `now`: the production caller passes
                # int(time.time()), but _calc_uptime_pct passes time.time()
                # unrounded, so a float `now` is a real input. This settles
                # the int(now) truncation question by measurement.
                now += rng.random()
            window_start = now - UPTIME_WINDOW_SECONDS

            sample_count = rng.randint(0, 80)
            checks = []
            state = rng.randint(0, 1)
            ts = window_start - rng.randint(0, UPTIME_WINDOW_SECONDS // 2)
            for _ in range(sample_count):
                if rng.random() < 0.5:
                    state = 1 - state
                checks.append((ts, state))
                choice = rng.random()
                if choice < 0.1:
                    # Land exactly on a bucket boundary.
                    idx = rng.randint(0, UPTIME_BUCKETS)
                    ts = int(window_start + int(idx * bucket_seconds))
                elif choice < 0.2:
                    # Leave a gap.
                    ts += rng.randint(1, UPTIME_WINDOW_SECONDS // 4 + 1)
                else:
                    ts += rng.randint(1, UPTIME_WINDOW_SECONDS // 40 + 1)
            # Points may arrive from storage in any order; the function
            # sorts them itself, so shuffling exercises that sort.
            rng.shuffle(checks)

            self._assert_matches_reference(checks, now)

    def test_no_checks_at_all(self):
        now = 10_000_000
        self._assert_matches_reference([], now)
        pct, buckets = self.appmod._uptime_summary([], now)
        self.assertIsNone(pct)
        self.assertEqual(buckets, [-1] * UPTIME_BUCKETS)

    def test_a_single_sample_before_the_window(self):
        now = 10_000_000
        start = now - UPTIME_WINDOW_SECONDS
        checks = [(start - 500, 1)]
        self._assert_matches_reference(checks, now)
        pct, buckets = self.appmod._uptime_summary(checks, now)
        self.assertEqual(pct, 100.0)
        self.assertTrue(all(value == 1.0 for value in buckets))

    def test_a_single_sample_inside_the_window(self):
        now = 10_000_000
        start = now - UPTIME_WINDOW_SECONDS
        checks = [(start + 3600, 1)]
        self._assert_matches_reference(checks, now)

    def test_a_history_that_is_entirely_offline(self):
        now = 10_000_000
        start = now - UPTIME_WINDOW_SECONDS
        checks = [(start - 10, 0)]
        self._assert_matches_reference(checks, now)
        pct, buckets = self.appmod._uptime_summary(checks, now)
        self.assertEqual(pct, 0.0)
        self.assertTrue(all(value == 0.0 for value in buckets))

    def test_a_history_producing_at_least_one_sentinel_bucket(self):
        now = 10_000_000
        checks = [(now - 60, 1)]
        self._assert_matches_reference(checks, now)
        _, buckets = self.appmod._uptime_summary(checks, now)
        self.assertEqual(buckets[:-1], [-1] * (UPTIME_BUCKETS - 1))
        self.assertNotEqual(buckets[-1], -1)

    def test_the_99_999_clamp_case(self):
        now = 20_000_000
        start = now - UPTIME_WINDOW_SECONDS
        checks = [(start - 1, 1), (now - 2, 0), (now - 1, 1)]
        self._assert_matches_reference(checks, now)
        pct, _ = self.appmod._uptime_summary(checks, now)
        self.assertLess(pct, 100)
        self.assertEqual(pct, 99.999)


class UptimeSummaryScalingTests(unittest.TestCase):
    """A regression that reintroduces the nested per-bucket rescan fails here."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_a_20000_interval_history_computes_well_inside_budget(self):
        now = 1_700_000_000
        start = now - UPTIME_WINDOW_SECONDS
        # 20,000 alternating checks spread evenly across the 7-day window.
        # The sizing is the point: the previous nested-loop implementation
        # needs 168 x 20,000 = 3,360,000 inner iterations for this fixture
        # and cannot meet a 500ms budget on any machine, while the sweep
        # needs roughly 20,000 + 168, leaving a margin wide enough that this
        # is a genuine algorithmic guard rather than a machine-speed one.
        count = 20_000
        step = UPTIME_WINDOW_SECONDS / count
        checks = [(int(start + i * step), i % 2) for i in range(count)]

        started = time.perf_counter()
        _, buckets = self.appmod._uptime_summary(checks, now)
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.5)
        self.assertEqual(len(buckets), UPTIME_BUCKETS)

        # Confirm this guard cannot pass by accidentally computing nothing:
        # the implementation must still agree with the (slow) reference on a
        # much smaller fixture the reference can compute quickly.
        small_checks = checks[:200]
        expected = _reference_uptime_summary(small_checks, now)
        actual = self.appmod._uptime_summary(small_checks, now)
        self.assertEqual(actual, expected)


class OfflineIntervalsBulkReadTests(unittest.TestCase):
    """read_service_offline_intervals_by_port must match the single-port reader."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_check(self, port, ts, online):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                (ts, port, int(online)),
            )
            conn.commit()
            conn.close()

    def _bulk(self, ports, start_ts, end_ts):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            result = beacon_repositories.read_service_offline_intervals_by_port(
                conn, ports=ports, start_ts=start_ts, end_ts=end_ts,
            )
            conn.close()
        return result

    def _single(self, port, start_ts, end_ts):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            intervals = beacon_repositories.read_service_offline_intervals(
                conn, port, start_ts=start_ts, end_ts=end_ts,
            )
            conn.close()
        return intervals

    def test_the_bulk_result_matches_the_single_port_result_per_port(self):
        base = 1_700_000_000
        start_ts, end_ts = base, base + 100_000

        port_no_checks = 9801
        port_boundary_only = 9802
        self._insert_check(port_boundary_only, start_ts - 500, 0)
        port_straddles_the_window_boundary = 9803
        self._insert_check(port_straddles_the_window_boundary, start_ts - 200, 0)
        self._insert_check(port_straddles_the_window_boundary, start_ts + 400, 1)
        # `service_checks` carries PRIMARY KEY (ts, port), so two rows for
        # the SAME port can never share a ts -- confirmed below -- which
        # makes the single-port boundary query's bare `ORDER BY ts DESC
        # LIMIT 1` unambiguous by construction. This port instead pins that
        # the bulk read's window-function boundary selection still picks
        # the correct, most-recent-before-the-window sample among several
        # closely spaced pre-window samples for one port.
        port_near_boundary = 9804
        self._insert_check(port_near_boundary, start_ts - 2, 1)
        self._insert_check(port_near_boundary, start_ts - 1, 0)
        port_online_throughout = 9805
        self._insert_check(port_online_throughout, start_ts - 100, 1)
        self._insert_check(port_online_throughout, start_ts + 500, 1)

        ports = [
            port_no_checks, port_boundary_only, port_straddles_the_window_boundary,
            port_near_boundary, port_online_throughout,
        ]
        bulk = self._bulk(ports, start_ts, end_ts)
        for port in ports:
            self.assertEqual(
                bulk.get(port, []), self._single(port, start_ts, end_ts),
                f'port {port} bulk result diverged from the single-port result',
            )

    def test_the_schema_makes_a_true_same_port_boundary_tie_impossible(self):
        # Direct evidence for the invariant the previous test's docstring
        # relies on: PRIMARY KEY (ts, port) rejects a second row at the same
        # (port, ts) pair, so no genuine boundary tie can ever be stored for
        # one port.
        port = 9806
        self._insert_check(port, 1_700_000_000, 1)
        with self.assertRaises(Exception):
            self._insert_check(port, 1_700_000_000, 0)

    def test_a_port_with_no_offline_intervals_is_absent_not_empty(self):
        port = 9807
        base = 1_700_000_000
        self._insert_check(port, base - 100, 1)
        bulk = self._bulk([port], base, base + 1000)
        self.assertNotIn(port, bulk)

    def test_an_empty_port_list_returns_an_empty_mapping_with_no_query(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            statements = []
            conn.set_trace_callback(lambda sql: statements.append(sql))
            result = beacon_repositories.read_service_offline_intervals_by_port(
                conn, ports=[], start_ts=0, end_ts=1,
            )
            conn.set_trace_callback(None)
            conn.close()
        self.assertEqual(result, {})
        self.assertEqual(statements, [])

    def test_the_bulk_read_is_bounded(self):
        port = 9808
        base = 1_700_000_000
        for i in range(20):
            self._insert_check(port, base + i * 10, i % 2)
        with mock.patch.object(beacon_repositories, '_OFFLINE_INTERVALS_BULK_ROW_LIMIT', 5):
            bulk = self._bulk([port], base, base + 1000)
        # A bounded read must not raise and must still return a well-formed
        # mapping -- the row limit's at-limit behavior (silently dropping
        # the tail of in-window rows) is documented on the constant itself,
        # matching the maintenance-window precedent.
        self.assertIsInstance(bulk, dict)

    def test_the_route_does_not_bound_the_uptime_read_with_the_interval_row_cap(self):
        """/api/services must remain bounded in service_checks rows read per
        request on whatever path it uses for offline-interval reconstruction
        (06-13-PLAN.md Task 2's unconditional row-bound requirement).

        06-13 removed the route's call to read_service_offline_intervals_by_port
        (06-PROFILE.md: sql_fetch 15.620% share, offline_intervals_read
        10.266% share, both confirmed 79.1% duplicate reads of the same
        service_checks rows at the profiled 8-service/8-day shape) and
        reconstructs offline intervals from the checks_by_port query
        api_services already issues for the uptime sweep instead. That query
        therefore now carries _OFFLINE_INTERVALS_BULK_ROW_LIMIT's own LIMIT
        -- bound to the same named constant, not a second, drifting literal
        -- so the 20,000-row cap does not silently disappear as a side
        effect of no longer duplicating the read. Proven through the route
        itself (test_client().get), not at the repository layer, because
        that is the layer that would actually lose the bound if a future
        change reintroduced an unbounded query here.
        """
        appmod = self.appmod
        port = 9897
        now = int(time.time())
        with appmod._db_lock:
            conn = appmod.get_db()
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                "VALUES(?,?,?,?,?,?)",
                (port, 'Bound', now - 3600, now, 1, now - 60),
            )
            for i in range(20):
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (now - 3600 + i * 10, port, i % 2),
                )
            conn.commit()
            conn.close()

        statements = []
        real_database_access = appmod.database_access

        @contextmanager
        def counting_database_access(settings_or_path):
            with real_database_access(settings_or_path) as conn:
                conn.set_trace_callback(lambda sql: statements.append(sql))
                try:
                    yield conn
                finally:
                    conn.set_trace_callback(None)

        appmod.database_access = counting_database_access
        try:
            with mock.patch.object(beacon_repositories, '_OFFLINE_INTERVALS_BULK_ROW_LIMIT', 5):
                response = appmod.app.test_client().get('/api/services')
        finally:
            appmod.database_access = real_database_access

        self.assertEqual(response.status_code, 200)
        # The route must NOT push the offline-interval row cap down into the
        # checks_by_port SQL. 06-13 did exactly that, to satisfy a plan clause
        # requiring "/api/services must remain bounded in rows read per request
        # on whatever path it uses" -- a requirement that wrongly treated the
        # route's two consumers of these rows as one. The uptime sweep had
        # never been bounded and must not be (D-DEBT-06-10); only the
        # offline-interval reconstruction tolerates truncation, and its cap is
        # now applied in Python, after the rows are read.
        #
        # This assertion is deliberately the inverse of the one it replaces.
        # The original asserted `LIMIT 5` appeared in the checks SQL, which is
        # green in exactly the state that reports a service with 10% downtime
        # as 100.0% up.
        checks_statements = [
            sql for sql in statements
            if 'FROM service_checks' in sql and 'port IN (' in sql and 'ts >=' in sql
        ]
        self.assertTrue(
            checks_statements,
            f'expected the route to issue a checks_by_port read: {statements}',
        )
        self.assertFalse(
            [sql for sql in checks_statements if 'LIMIT' in sql],
            'the checks_by_port query must not carry a LIMIT -- it feeds _uptime_summary, '
            'which requires every in-window row. Bound the offline-interval reconstruction '
            f'in Python instead (D-DEBT-06-10): {checks_statements}',
        )

    def test_uptime_pct_is_not_affected_by_the_offline_interval_row_cap(self):
        """uptime_pct must be computed from ALL in-window rows, never a
        truncated subset.

        06-13 applied _OFFLINE_INTERVALS_BULK_ROW_LIMIT to the checks_by_port
        query, which feeds _uptime_summary. That read had never been bounded.
        The result was silent falsification rather than graceful degradation:
        the truncated set keeps each port's EARLIEST rows (ORDER BY port ASC,
        ts ASC), so a service that goes offline late loses exactly the samples
        that record it, and reports a confident 100.0% with a fully populated
        168-hour bar and no truncation signal anywhere on the response.
        See D-DEBT-06-10.

        The fixture matters: uptime is TIME-WEIGHTED from the first sample to
        `now`, so dropping trailing rows that carry no state change is a
        no-op. A first attempt at this test seeded a late-online history and
        passed against the bug (99.583 both ways) -- it proved nothing. The
        truncated-away rows MUST contain the transition. Here rows 0-179 are
        online and 180-199 are offline, so the full read sees ~10% downtime
        and any capped read sees an unbroken online history.
        """
        appmod = self.appmod
        port = 9811
        now = int(time.time())
        span = 6000
        with appmod._db_lock:
            conn = appmod.get_db()
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                "VALUES(?,?,?,?,?,?)",
                (port, 'CapUptime', now - span, now, 0, now - 600),
            )
            for i in range(200):
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (now - span + i * 30, port, 0 if i >= 180 else 1),
                )
            conn.commit()
            conn.close()

        def _uptime_for():
            response = appmod.app.test_client().get('/api/services')
            self.assertEqual(response.status_code, 200)
            for entry in response.get_json():
                if entry['port'] == port:
                    return entry.get('uptime_pct')
            self.fail(f'port {port} absent from /api/services')

        full = _uptime_for()
        with mock.patch.object(beacon_repositories, '_OFFLINE_INTERVALS_BULK_ROW_LIMIT', 5):
            capped = _uptime_for()

        # Guard the fixture itself: if this ever reaches 100 the history has
        # stopped exercising truncation and the test below is vacuous.
        self.assertIsNotNone(full, 'uptime_pct should be computed for a service with checks')
        self.assertLess(
            full, 99.0,
            f'fixture no longer produces observable downtime (full={full}); this test '
            f'cannot detect truncation without it',
        )
        self.assertEqual(
            full, capped,
            f'uptime_pct changed when the offline-interval row cap was lowered '
            f'(full={full}, capped={capped}) -- the cap has reached the uptime path '
            f'again. It must bound only the offline-interval reconstruction '
            f'(D-DEBT-06-10).',
        )

    def test_attributed_downtime_is_unchanged_through_the_route(self):
        # /api/services must return the same maintenance-attributed downtime
        # values as before for every service -- exercised end-to-end here
        # rather than only at the repository layer.
        appmod = self.appmod
        now = int(time.time())
        port = 9809
        with appmod._db_lock:
            conn = appmod.get_db()
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                "VALUES(?,?,?,?,?,?)",
                (port, 'Demo', now - 3600, now, 0, now - 120),
            )
            conn.execute(
                'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                (now - 120, port, 0),
            )
            conn.commit()
            conn.close()

        response = appmod.app.test_client().get('/api/services')
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        matching = [svc for svc in body if svc['port'] == port]
        self.assertEqual(len(matching), 1)
        self.assertIn('maintenance_attributed_seconds', matching[0])


class OfflineIntervalsFromPointsTests(unittest.TestCase):
    """offline_intervals_from_points_by_port (06-13, OPS-07 gap closure) must
    match the single-port oracle exactly when fed the same already-fetched
    points a caller like api_services holds, proving the route's new
    reconstruction path -- built to replace the duplicate
    read_service_offline_intervals_by_port call this same file's
    OfflineIntervalsBulkReadTests guards -- cannot drift from what that
    removed call used to guarantee. read_service_offline_intervals_by_port
    itself is untouched and still used by its other caller; this class pins
    the new caller-supplied-points path specifically.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_check(self, port, ts, online):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                (ts, port, int(online)),
            )
            conn.commit()
            conn.close()

    def _single(self, port, start_ts, end_ts):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            intervals = beacon_repositories.read_service_offline_intervals(
                conn, port, start_ts=start_ts, end_ts=end_ts,
            )
            conn.close()
        return intervals

    def test_reconstruction_from_already_fetched_points_matches_the_single_port_oracle(self):
        base = 1_700_000_000
        start_ts, end_ts = base, base + 100_000

        port_no_checks = 9821
        port_boundary_only = 9822
        self._insert_check(port_boundary_only, start_ts - 500, 0)
        port_straddles_the_window_boundary = 9823
        self._insert_check(port_straddles_the_window_boundary, start_ts - 200, 0)
        self._insert_check(port_straddles_the_window_boundary, start_ts + 400, 1)
        port_multi_transition = 9824
        self._insert_check(port_multi_transition, start_ts - 50, 1)
        self._insert_check(port_multi_transition, start_ts + 100, 0)
        self._insert_check(port_multi_transition, start_ts + 5000, 1)
        self._insert_check(port_multi_transition, start_ts + 9000, 0)
        port_online_throughout = 9825
        self._insert_check(port_online_throughout, start_ts - 100, 1)
        self._insert_check(port_online_throughout, start_ts + 500, 1)

        ports = [
            port_no_checks, port_boundary_only, port_straddles_the_window_boundary,
            port_multi_transition, port_online_throughout,
        ]

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            boundary_by_port = beacon_repositories.read_service_offline_interval_boundaries_by_port(
                conn, ports=ports, start_ts=start_ts,
            )
            # Mimic api_services's own checks_by_port construction exactly:
            # the in-window rows the route already fetches for the uptime
            # sweep, not a second, separately-shaped query.
            placeholders = ','.join('?' * len(ports))
            rows = conn.execute(
                f"SELECT port, ts, online FROM service_checks "
                f"WHERE port IN ({placeholders}) AND ts >= ? AND ts <= ? "
                f"ORDER BY port ASC, ts ASC",
                (*ports, start_ts, end_ts),
            ).fetchall()
            conn.close()
        points_by_port = {}
        for row in rows:
            points_by_port.setdefault(row['port'], []).append(
                (int(row['ts']), 1 if int(row['online']) else 0),
            )

        reconstructed = beacon_repositories.offline_intervals_from_points_by_port(
            ports=ports, boundary_by_port=boundary_by_port, points_by_port=points_by_port,
            start_ts=start_ts, end_ts=end_ts,
        )
        for port in ports:
            self.assertEqual(
                reconstructed.get(port, []), self._single(port, start_ts, end_ts),
                f'port {port} reconstruction from points diverged from the single-port oracle',
            )

    def test_a_port_with_no_offline_intervals_is_absent_not_empty(self):
        port = 9826
        base = 1_700_000_000
        self._insert_check(port, base - 100, 1)
        reconstructed = beacon_repositories.offline_intervals_from_points_by_port(
            ports=[port], boundary_by_port={port: 1}, points_by_port={}, start_ts=base, end_ts=base + 1000,
        )
        self.assertNotIn(port, reconstructed)


class ServiceCountQueryGuardTests(unittest.TestCase):
    """/api/services must issue the same query count regardless of service count.

    Guards the measurement that motivated this whole plan: at --concurrency 1
    on Pi hardware, /api/services cost p50 2504.6ms / p95 2523.3ms /
    max 2529.8ms while every other route measured 3-98ms -- the signature of
    per-service database work whose cost scaled with the number of
    configured services. A reader who trips this test needs to know it is
    protecting that hardware-measured outcome, not a stylistic preference.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _seed_services(self, count, checks_per_service=20):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for i in range(count):
                port = 9900 + i
                conn.execute(
                    "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                    "VALUES(?,?,?,?,?,?)",
                    (port, f'Service {port}', now - 3600, now, 1, now - 60),
                )
                for j in range(checks_per_service):
                    ts = now - (checks_per_service - j) * 30
                    conn.execute(
                        'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                        (ts, port, 1 if j % 3 else 0),
                    )
            conn.commit()
            conn.close()

    def _request_statement_count(self):
        """Count the SQL statements one /api/services request issues.

        Instruments the connection the route actually opens -- via
        dashboard.beacon.db's ``database_access`` seam -- with sqlite3's own
        ``set_trace_callback``, rather than a mocking framework that would
        couple this test to the route's internal call order.
        """
        appmod = self.appmod
        real_database_access = appmod.database_access
        statements = []

        @contextmanager
        def counting_database_access(settings_or_path):
            with real_database_access(settings_or_path) as conn:
                conn.set_trace_callback(lambda sql: statements.append(sql))
                try:
                    yield conn
                finally:
                    conn.set_trace_callback(None)

        appmod.database_access = counting_database_access
        try:
            response = appmod.app.test_client().get('/api/services')
        finally:
            appmod.database_access = real_database_access
        self.assertEqual(response.status_code, 200)
        return len(statements), response.get_json()

    def test_query_count_is_independent_of_service_count(self):
        self._seed_services(1)
        one_service_count, one_service_body = self._request_statement_count()

        # A fresh app/db so the two requests are otherwise comparable --
        # neither shares connection or cache state with the other.
        cleanup_db(self.db_path)
        self.appmod, self.db_path = load_app({})
        self._seed_services(8)
        eight_service_count, eight_service_body = self._request_statement_count()

        self.assertEqual(
            one_service_count, eight_service_count,
            'query count must not grow with service count (OPS-07: measured '
            'p50 2504.6ms on Pi hardware at --concurrency 1 while every '
            'other route was single-digit milliseconds)',
        )
        self.assertEqual(len(one_service_body), 1)
        self.assertEqual(len(eight_service_body), 8)
        for svc in one_service_body + eight_service_body:
            self.assertIn('uptime_pct', svc)
            self.assertIn('uptime_buckets', svc)


class ServicesRouteProfilerGuardTests(unittest.TestCase):
    """Guards for tests/services_route_profile.py (06-12, OPS-07 gap closure).

    The profiler instrument must never alter what it measures (the route's
    output and its query count), and its growth measurement must genuinely
    discriminate a bucket proportional to stored check count from one that
    is not -- not merely report the same ratio for every bucket. A small,
    fast fixture (2 services, 1-versus-4 days) keeps the suite's runtime
    unchanged; the real 8-service/8-day attribution and growth runs belong
    to Task 3 of 06-12-PLAN.md, which needs their numbers for
    06-PROFILE.md. ``repeats=20`` (rather than the shape-gate convention of
    2) is deliberate here, not a stylistic choice: at 2 repeats, a
    check-count-independent bucket like maintenance_windows_read costs
    under 0.02ms per run, close enough to timer-resolution noise that the
    discrimination assertion below flaked (~1 run in 5, confirmed by direct
    repetition while writing this test). 20 repeats keeps that bucket's
    accumulated tottime an order of magnitude further from the noise floor
    while still completing in low single-digit seconds.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _small_growth_report(self):
        return services_route_profile.profile_growth(
            lambda: load_app({}),
            small_days=1, large_days=4, repeats=20, seed=20260901, services=2,
        )

    def test_growth_ratios_are_reported_for_every_shared_bucket(self):
        report = self._small_growth_report()
        self.assertGreater(report['check_row_ratio'], 1.0)
        shared_bucket_names = set(report['small_profile']['phases']) & set(report['large_profile']['phases'])
        self.assertTrue(shared_bucket_names)
        self.assertEqual(set(report['buckets']), shared_bucket_names)
        for bucket, data in report['buckets'].items():
            self.assertTrue(
                math.isfinite(data['growth_ratio']),
                f'{bucket} growth_ratio is not finite: {data["growth_ratio"]!r}',
            )

    def test_a_check_count_independent_bucket_does_not_track_the_check_row_ratio(self):
        report = self._small_growth_report()
        # maintenance_windows_read reads a per-port window table untouched by
        # check volume -- its growth ratio must stay well below the check-row
        # ratio, proving the measurement discriminates rather than reporting
        # the same ratio for every bucket.
        bucket = report['buckets']['maintenance_windows_read']
        self.assertLess(bucket['growth_ratio'], report['check_row_ratio'] / 2.0)

    def test_profiling_does_not_change_the_route_response(self):
        services_route_profile.seed_pi_representative_dataset(
            self.appmod, services=2, days=1, seed=20260901,
        )
        client = self.appmod.app.test_client()

        plain_response = client.get('/api/services')
        self.assertEqual(plain_response.status_code, 200)
        plain_body = plain_response.get_json()

        profiler = cProfile.Profile()
        profiler.enable()
        profiled_response = client.get('/api/services')
        profiler.disable()
        self.assertEqual(profiled_response.status_code, 200)
        profiled_body = profiled_response.get_json()

        self.assertEqual(plain_body, profiled_body)

    def _count_statements(self, *, profiled):
        appmod = self.appmod
        real_database_access = appmod.database_access
        statements = []

        @contextmanager
        def counting_database_access(settings_or_path):
            with real_database_access(settings_or_path) as conn:
                conn.set_trace_callback(lambda sql: statements.append(sql))
                try:
                    yield conn
                finally:
                    conn.set_trace_callback(None)

        appmod.database_access = counting_database_access
        try:
            if profiled:
                profiler = cProfile.Profile()
                profiler.enable()
                response = appmod.app.test_client().get('/api/services')
                profiler.disable()
            else:
                response = appmod.app.test_client().get('/api/services')
        finally:
            appmod.database_access = real_database_access
        self.assertEqual(response.status_code, 200)
        return len(statements)

    def test_profiling_does_not_change_the_route_query_count(self):
        services_route_profile.seed_pi_representative_dataset(
            self.appmod, services=2, days=1, seed=20260901,
        )
        plain_count = self._count_statements(profiled=False)
        profiled_count = self._count_statements(profiled=True)
        self.assertEqual(plain_count, profiled_count)

    def test_maintenance_coverage_cost_is_no_longer_dominated_by_unmemoized_occurrence_walks(self):
        """06-PROFILE.md named maintenance_coverage as effectively tied with
        uptime_sweep for the single largest bucket (29.649% share of
        /api/services's measured residual cost) and the only bucket whose
        growth ratio (7.564) *exceeded* the measured check_row_ratio
        (4.249) -- driven by ~5,997 uncached beacon_maintenance.coverage()
        calls per request at that shape, each re-walking
        MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS + 1 calendar days of fold-aware
        datetime construction, with no memoization across the thousands of
        calls one request makes for the same window.

        06-13 added a request-scoped memo (keyed on (window, the calendar
        date `now_epoch` resolves to, timezone) -- the exact granularity at
        which _local_occurrence_epochs's result is provably invariant, not
        an approximation -- plus a request-scoped cache for the
        per-call window_from_row() re-parse/re-validate work coverage() and
        attributed_downtime_seconds() both repeat on every call). This
        collapses the absolute cost dramatically: at this class's fast shape
        (2 services, 1-vs-4 days, seed 20260901, 20 repeats), directly
        disabling both call sites' `cache=` argument in dashboard/app.py and
        re-running this exact profile (verified by hand while writing this
        test, recorded in 06-13-SUMMARY.md) measured maintenance_coverage at
        small=276.221ms / large=1322.387ms; with the memo wired through
        /api/services as shipped, the same shape measures roughly
        small=30ms / large=133ms -- close to a 9-10x absolute reduction.

        This guard asserts that absolute reduction directly, with a wide
        margin above the shipped measurement and a wide margin below the
        unmemoized measurement, rather than the profiler's own
        growth-ratio classification: growth_ratio stays
        "proportional_to_check_count" even after this fix, because CALL
        COUNT into coverage() -- not per-call cost -- still scales with
        retained days. That count is driven by the number of discrete
        stored-check-derived offline intervals attributed_downtime_seconds
        must process one at a time (06-PROFILE.md's seeded shape produces
        over a thousand short intervals from J3/J4-cadence sampling for the
        one port carrying a window); collapsing that further would mean
        changing _offline_intervals_from_points's interval-merging
        behavior, which is out of this round's scope and risks the
        byte-identical output guarantee PROH-OPS-07-05 protects. See
        06-13-SUMMARY.md's Deviations section for the full accounting of
        why this guard measures absolute cost rather than the ratio Task
        2's plan text named.
        """
        report = self._small_growth_report()
        bucket = report['buckets']['maintenance_coverage']
        self.assertLess(
            bucket['small_tottime_ms'], 100.0,
            f"maintenance_coverage's small-shape cost regressed toward the unmemoized "
            f"baseline (276.221ms): {bucket}",
        )
        self.assertLess(
            bucket['large_tottime_ms'], 400.0,
            f"maintenance_coverage's large-shape cost regressed toward the unmemoized "
            f"baseline (1322.387ms): {bucket}",
        )


# ---------------------------------------------------------------------------
# 06-25 (OPS-07 gap closure): the agreement invariant PROH-OPS-07-16
# requires between the new bulk SQL uptime-strip reader
# (beacon_repositories.read_uptime_strips_by_port) and the two existing
# Python producers it replaces inside api_services -- _legacy_uptime_summary
# (the current sweep) and _reference_uptime_summary (the pinned
# pre-optimization nested-loop oracle above). PROH-OPS-07-22: every oracle
# call in this file goes through _route_input_rows, never the full inserted
# set -- an oracle fed a superset agrees by construction and proves nothing
# about the retention floor. Mutation (e) below demonstrates this directly.
# ---------------------------------------------------------------------------

class UptimeStripSqlDifferentialTests(unittest.TestCase):
    """The bulk SQL uptime-strip reader must agree with both existing
    producers on exactly the input the route itself would have passed --
    the ``ts >= now - CHECK_RETENTION_SECONDS`` subset -- never the full
    inserted set (PROH-OPS-07-22).
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_checks(self, port, rows):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for ts, online in rows:
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (ts, port, online),
                )
            conn.commit()
            conn.close()

    def _route_input_rows(self, inserted, port, now):
        """The route's own retention-floored input subset (PROH-OPS-07-22):
        exactly the predicate ``all_checks`` applies at
        ``dashboard/app.py:2896`` (``ts >= now - CHECK_RETENTION_SECONDS``).
        Every oracle call in this class MUST be routed through this helper
        -- an oracle fed the full inserted set agrees by construction and
        proves nothing about the retention floor; mutation (e) in
        06-25-SUMMARY.md demonstrates exactly that. The constant is read
        off the app module rather than restated here.
        """
        floor = now - self.appmod.CHECK_RETENTION_SECONDS
        return [(ts, online) for ts, online in inserted.get(port, []) if ts >= floor]

    def _read_strips(self, ports, now):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            result = beacon_repositories.read_uptime_strips_by_port(
                conn, ports=ports, now=now, window_seconds=UPTIME_WINDOW_SECONDS,
                bucket_count=UPTIME_BUCKETS, retention_seconds=self.appmod.CHECK_RETENTION_SECONDS,
            )
            conn.close()
        return result

    def test_randomized_histories_agree_with_the_legacy_sweep_on_the_route_subset(self):
        # Fresh seed (not 20260901 -- that seed belongs to
        # UptimeSummaryDifferentialTests above and reusing it here would
        # make a failure ambiguous about which class's fixture produced it).
        rng = random.Random(20260925)
        base_now = 1_700_000_000
        crossed_retention_count = 0
        total_histories = 0

        for trial in range(400):
            now = base_now + rng.randint(-10_000, 10_000)
            port_count = rng.randint(1, 8)
            port_base = 40000 + trial * 10
            ports = list(range(port_base, port_base + port_count))
            inserted = {}
            for port in ports:
                total_histories += 1
                window_start = now - UPTIME_WINDOW_SECONDS
                sample_count = rng.randint(0, 40)
                checks = []
                state = rng.randint(0, 1)
                if rng.random() < 0.25:
                    # Deliberately starts before the retention floor, so at
                    # least one in four histories crosses it under
                    # randomized pressure (06-25-PLAN.md Task 2 behaviour),
                    # not only the enumerated beyond-retention cases below.
                    ts = now - self.appmod.CHECK_RETENTION_SECONDS - rng.randint(1, UPTIME_WINDOW_SECONDS)
                else:
                    ts = window_start - rng.randint(0, UPTIME_WINDOW_SECONDS // 2)
                for _ in range(sample_count):
                    if rng.random() < 0.5:
                        state = 1 - state
                    checks.append((ts, state))
                    choice = rng.random()
                    if choice < 0.1:
                        idx = rng.randint(0, UPTIME_BUCKETS)
                        ts = int(window_start + idx * (UPTIME_WINDOW_SECONDS / UPTIME_BUCKETS))
                    elif choice < 0.2:
                        ts += rng.randint(1, UPTIME_WINDOW_SECONDS // 4 + 1)
                    else:
                        ts += rng.randint(1, UPTIME_WINDOW_SECONDS // 40 + 1)
                # De-duplicate timestamps for this port -- PRIMARY KEY
                # (ts, port) makes a genuine duplicate schema-impossible, so
                # the generator must not attempt to produce one.
                seen = set()
                deduped = []
                for ts_i, state_i in checks:
                    if ts_i not in seen:
                        seen.add(ts_i)
                        deduped.append((ts_i, state_i))
                inserted[port] = deduped
                if any(ts_i < now - self.appmod.CHECK_RETENTION_SECONDS for ts_i, _ in deduped):
                    crossed_retention_count += 1
                self._insert_checks(port, deduped)

            actual = self._read_strips(ports, now)
            for port in ports:
                route_rows = self._route_input_rows(inserted, port, now)
                expected = self.appmod._legacy_uptime_summary(route_rows, now)
                self.assertEqual(
                    actual[port], expected,
                    f'trial {trial} port {port}: SQL reader diverged from '
                    f'_legacy_uptime_summary on the route-input subset',
                )

        self.assertGreaterEqual(
            crossed_retention_count, 100,
            f'expected at least 100 of {total_histories} randomized histories to cross '
            f'the retention floor, got {crossed_retention_count} -- the floor is not '
            f'under enough randomized pressure',
        )

    def test_bulk_call_equals_the_single_port_call_per_port(self):
        now = 1_700_000_000
        ports = list(range(41000, 41008))
        for i, port in enumerate(ports):
            self._insert_checks(port, [(now - 1000 - i * 100, i % 2), (now - 100, 1)])
        bulk = self._read_strips(ports, now)
        for port in ports:
            single = self._read_strips([port], now)
            self.assertEqual(
                bulk[port], single[port],
                f'port {port}: bulk-call result diverged from the single-port call',
            )

    def test_no_checks_at_all(self):
        now = 10_000_000
        port = 42001
        actual = self._read_strips([port], now)
        self.assertEqual(actual[port], (None, [-1] * UPTIME_BUCKETS))
        expected = self.appmod._legacy_uptime_summary(
            self._route_input_rows({}, port, now), now,
        )
        self.assertEqual(actual[port], expected)
        self.assertEqual(actual[port], _reference_uptime_summary(
            self._route_input_rows({}, port, now), now,
        ))

    def test_boundary_sample_establishes_state_across_the_whole_window(self):
        now = 20_000_000
        start = now - UPTIME_WINDOW_SECONDS
        port = 42002
        # Inside retention, strictly before the window, and nothing inside
        # the window at all.
        rows = [(start - 500, 1)]
        self._insert_checks(port, rows)
        actual = self._read_strips([port], now)
        route_rows = self._route_input_rows({port: rows}, port, now)
        expected = self.appmod._legacy_uptime_summary(route_rows, now)
        self.assertEqual(actual[port], expected)
        self.assertEqual(actual[port], _reference_uptime_summary(route_rows, now))
        pct, buckets = actual[port]
        self.assertEqual(pct, 100.0)
        self.assertTrue(all(value == 1.0 for value in buckets))

    def test_first_check_mid_window_with_no_earlier_boundary(self):
        now = 20_000_000
        start = now - UPTIME_WINDOW_SECONDS
        port = 42003
        rows = [(start + 3600, 1)]
        self._insert_checks(port, rows)
        actual = self._read_strips([port], now)
        route_rows = self._route_input_rows({port: rows}, port, now)
        expected = self.appmod._legacy_uptime_summary(route_rows, now)
        self.assertEqual(actual[port], expected)
        self.assertEqual(actual[port], _reference_uptime_summary(route_rows, now))
        # Observation starts at the first check, not the window start.
        _, buckets = actual[port]
        self.assertEqual(buckets[0], -1)

    def test_a_24_hour_observation_gap(self):
        """A "24-hour observation gap" in this algorithm is the unobserved
        PREFIX before the first established state -- there is no concept of
        a mid-stream unknown region once a boundary or first check
        establishes coverage, because every subsequent interval is
        contiguous through to `now` (read off `_legacy_uptime_summary`:
        once `cursor` is set, either at `start` via a boundary sample or at
        the first in-window check, every later point falls inside some
        interval). A first attempt at this test placed the "gap" in the
        middle of an otherwise-covered history and asserted -1 there; that
        assertion was wrong about what the algorithm computes (confirmed by
        running it against both oracles, which agreed with each other and
        disagreed with the wrong assertion) rather than a property either
        producer has ever had.
        """
        now = 30_000_000
        start = now - UPTIME_WINDOW_SECONDS
        port = 42004
        bucket_seconds = UPTIME_WINDOW_SECONDS // UPTIME_BUCKETS
        gap_bucket_count = 24
        first_check_ts = start + gap_bucket_count * bucket_seconds + 5
        rows = [(first_check_ts, 1), (now - 100, 0)]
        self._insert_checks(port, rows)
        actual = self._read_strips([port], now)
        route_rows = self._route_input_rows({port: rows}, port, now)
        expected = self.appmod._legacy_uptime_summary(route_rows, now)
        self.assertEqual(actual[port], expected)
        self.assertEqual(actual[port], _reference_uptime_summary(route_rows, now))
        _, buckets = actual[port]
        self.assertEqual(buckets[:gap_bucket_count], [-1] * gap_bucket_count)
        for idx in range(gap_bucket_count, UPTIME_BUCKETS):
            self.assertNotEqual(buckets[idx], -1, f'bucket {idx} unexpectedly unobserved')

    def test_one_second_offline_yields_the_99_999_clamp(self):
        now = 20_000_000
        start = now - UPTIME_WINDOW_SECONDS
        port = 42005
        rows = [(start - 1, 1), (now - 2, 0), (now - 1, 1)]
        self._insert_checks(port, rows)
        actual = self._read_strips([port], now)
        route_rows = self._route_input_rows({port: rows}, port, now)
        expected = self.appmod._legacy_uptime_summary(route_rows, now)
        self.assertEqual(actual[port], expected)
        self.assertEqual(actual[port], _reference_uptime_summary(route_rows, now))
        pct, _ = actual[port]
        self.assertEqual(pct, 99.999)

    def test_beyond_retention_sole_row_renders_the_pre_change_sentinel(self):
        """A port whose only check is older than CHECK_RETENTION_SECONDS
        establishes no boundary -- exactly what HEAD renders today, because
        all_checks (dashboard/app.py:2896) has never been able to see that
        row. Asserted as a literal expected strip, not merely as agreement
        with an oracle, so this case still fails if a future change feeds
        the oracle the wrong subset (PROH-OPS-07-22).
        """
        now = 1_700_000_000
        port = 42006
        rows = [(now - 10 * 86400, 1)]
        self._insert_checks(port, rows)
        actual = self._read_strips([port], now)
        self.assertEqual(actual[port], (None, [-1] * UPTIME_BUCKETS))

    def test_beyond_retention_plus_mid_window_rows_establishes_no_boundary(self):
        """A port with an out-of-retention row PLUS in-window rows behaves
        exactly as if the out-of-retention row did not exist: every bucket
        wholly before the first in-window check is -1, and observation
        starts there, not at the window start.
        """
        now = 1_700_000_000
        start = now - UPTIME_WINDOW_SECONDS
        port = 42007
        first_in_window_ts = now - 3 * 86400
        rows = [(now - 10 * 86400, 1), (first_in_window_ts, 0), (first_in_window_ts + 100, 1)]
        self._insert_checks(port, rows)
        actual = self._read_strips([port], now)
        route_rows = self._route_input_rows({port: rows}, port, now)
        expected = self.appmod._legacy_uptime_summary(route_rows, now)
        self.assertEqual(actual[port], expected)
        self.assertEqual(actual[port], _reference_uptime_summary(route_rows, now))

        bucket_seconds = UPTIME_WINDOW_SECONDS // UPTIME_BUCKETS
        first_in_window_bucket = (first_in_window_ts - start) // bucket_seconds
        _, buckets = actual[port]
        self.assertEqual(
            buckets[:first_in_window_bucket], [-1] * first_in_window_bucket,
            'buckets wholly before the first in-window check must be unobserved',
        )
        self.assertNotEqual(
            buckets[first_in_window_bucket], -1,
            'observation must start at the first in-window check',
        )

    def test_duplicate_timestamps_are_rejected_by_the_schema(self):
        """``service_checks`` declares ``PRIMARY KEY (ts, port)``
        (``dashboard/beacon/migrations.py:119-120``), so two rows at one
        timestamp for one port cannot be stored -- the reader's
        ``(ts, online)`` segment ordering tiebreak this schema makes
        unreachable through the route is therefore defensive against a
        future primary-key widening, not a property any input can exercise
        today. A plain ``INSERT`` (no ``OR IGNORE``, no ``OR REPLACE``) is
        the correct way to pin this: either recovery mechanism would yield
        a single stored row and a test that passes vacuously while reading
        as though it exercised the tie-break.
        """
        port = 42008
        ts = 1_700_000_000
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)', (ts, port, 1),
            )
            conn.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)', (ts, port, 0),
                )
            conn.close()

    def test_null_online_makes_both_producers_raise(self):
        now = 1_700_000_000
        port = 42009
        rows = [(now - 100, None)]
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)', (now - 100, port, None),
            )
            conn.commit()
            conn.close()
        with self.assertRaises(ValueError):
            self._read_strips([port], now)
        route_rows = self._route_input_rows({port: rows}, port, now)
        with self.assertRaises(TypeError):
            # _legacy_uptime_summary's `1 if int(online) else 0` raises
            # TypeError on a None -- the two producers refuse the same
            # input, even though the exception type each raises differs
            # (ValueError naming the port here vs. int(None)'s TypeError
            # there). Both refuse; neither renders a number.
            self.appmod._legacy_uptime_summary(route_rows, now)

    def test_float_now_matches_int_now_truncation(self):
        """/api/services passes int(time.time()), but _legacy_calc_uptime_pct
        passes an unrounded float, so a float `now` is a real input this
        reader must define behaviour for. Settled by measurement: the
        reader truncates via int(now), matching _legacy_uptime_summary's
        own int(now) truncation, rather than raising.
        """
        now_int = 1_700_000_123
        port = 42010
        rows = [(now_int - 1000, 1), (now_int - 10, 0)]
        self._insert_checks(port, rows)
        with_int = self._read_strips([port], now_int)
        with_float = self._read_strips([port], now_int + 0.9)
        self.assertEqual(with_int[port], with_float[port])


class UptimeStripBoundednessTests(unittest.TestCase):
    """The cost-model and safety properties PROH-OPS-07-17 requires: one
    query regardless of port count, and a materialized row count
    independent of stored check volume.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_checks(self, port, rows):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for ts, online in rows:
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (ts, port, online),
                )
            conn.commit()
            conn.close()

    def _query_count(self, ports, now):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            statements = []
            conn.set_trace_callback(lambda sql: statements.append(sql))
            beacon_repositories.read_uptime_strips_by_port(
                conn, ports=ports, now=now, window_seconds=UPTIME_WINDOW_SECONDS,
                bucket_count=UPTIME_BUCKETS, retention_seconds=self.appmod.CHECK_RETENTION_SECONDS,
            )
            conn.set_trace_callback(None)
            conn.close()
        return len(statements)

    def test_one_query_regardless_of_port_count(self):
        now = 1_700_000_000
        self.assertEqual(self._query_count([50000], now), 1)
        self.assertEqual(self._query_count(list(range(50000, 50008)), now), 1)

    def _materialized_row_count(self, ports, now):
        # sqlite3.Cursor is a C-extension type -- its `fetchall` attribute
        # cannot be monkeypatched per-instance (`AttributeError: ...
        # attribute 'fetchall' is read-only`). A thin Python-level proxy
        # around the real cursor, returned in place of it, is what makes
        # counting `.fetchall()`'s result length possible without changing
        # `read_uptime_strips_by_port` itself.
        class _CountingCursor:
            def __init__(self, cursor, counts):
                self._cursor = cursor
                self._counts = counts

            def fetchall(self):
                rows = self._cursor.fetchall()
                self._counts.append(len(rows))
                return rows

            def __getattr__(self, name):
                return getattr(self._cursor, name)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            original_execute = conn.execute
            counts = []

            def spy_execute(*args, **kwargs):
                return _CountingCursor(original_execute(*args, **kwargs), counts)

            conn.execute = spy_execute
            beacon_repositories.read_uptime_strips_by_port(
                conn, ports=ports, now=now, window_seconds=UPTIME_WINDOW_SECONDS,
                bucket_count=UPTIME_BUCKETS, retention_seconds=self.appmod.CHECK_RETENTION_SECONDS,
            )
            conn.execute = original_execute
            conn.close()
        return sum(counts)

    def test_materialized_row_count_is_independent_of_stored_check_volume(self):
        now = 1_700_000_000
        ports = list(range(51000, 51003))
        for port in ports:
            for i in range(200):
                self._insert_checks(port, [(now - i * 30, i % 2)])
        small_count = self._materialized_row_count(ports, now)

        cleanup_db(self.db_path)
        self.appmod, self.db_path = load_app({})
        for port in ports:
            for i in range(800):
                self._insert_checks(port, [(now - i * 30, i % 2)])
        large_count = self._materialized_row_count(ports, now)

        expected = len(ports) * UPTIME_BUCKETS
        self.assertEqual(small_count, expected)
        self.assertEqual(large_count, expected)

    def test_a_port_exceeding_the_offline_intervals_row_limit_still_returns_an_untruncated_strip(self):
        """PROH-OPS-07-17's falsifier: this reader must never reuse
        _OFFLINE_INTERVALS_BULK_ROW_LIMIT (D-DEBT-06-10's defect class
        checked at this new door). The limit is patched down to a small
        value so the test seeds a fast, small-but-over-cap history rather
        than the literal 20,000+ rows the production constant would
        require, matching the existing at-limit test idiom in this file
        (OfflineIntervalsBulkReadTests.test_the_bulk_read_is_bounded).
        """
        now = 1_700_000_000
        port = 52000
        with mock.patch.object(beacon_repositories, '_OFFLINE_INTERVALS_BULK_ROW_LIMIT', 50):
            rows = [(now - i * 30, i % 3 != 0) for i in range(51)]
            int_rows = [(ts, int(online)) for ts, online in rows]
            self._insert_checks(port, int_rows)
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                actual = beacon_repositories.read_uptime_strips_by_port(
                    conn, ports=[port], now=now, window_seconds=UPTIME_WINDOW_SECONDS,
                    bucket_count=UPTIME_BUCKETS, retention_seconds=self.appmod.CHECK_RETENTION_SECONDS,
                )
                conn.close()
        expected = self.appmod._legacy_uptime_summary(int_rows, now)
        self.assertEqual(
            actual[port][0], expected[0],
            'uptime_pct must be unaffected by _OFFLINE_INTERVALS_BULK_ROW_LIMIT -- that '
            'constant belongs only to offline-interval reconstruction, never to the '
            'uptime strip (D-DEBT-06-10)',
        )
        self.assertEqual(len(actual[port][1]), UPTIME_BUCKETS)


# ---------------------------------------------------------------------------
# 06-26 (OPS-07 gap closure, Task 2): pin the cost-model claim that is
# actually true about read_uptime_strips_by_port. 06-25 did NOT stop SQLite
# scanning service_checks -- the aggregation still scans the same
# retention-floored rows, and api_services still reads a second, independent
# set of rows for points_by_port (unaffected by this plan). What changed is
# that the uptime path's PYTHON-SIDE row count and statement count became
# independent of stored check volume. Built relationally (D-DEBT-06-14):
# every assertion below compares two measurements taken inside one test
# run against each other, never against a literal row count or millisecond
# figure, because an absolute-band prediction calibrated to today's seeded
# dataset size is a mechanism-shaped commitment that fails for reasons
# unrelated to whether the property it names is still true the moment the
# suite's fixtures grow.
# ---------------------------------------------------------------------------

class UptimeStripCostModelTests(unittest.TestCase):
    """The true half of 06-25's cost-model claim, pinned relationally.

    SQLite still scans every `service_checks` row `read_uptime_strips_by_port`
    admits -- this class asserts nothing to the contrary, and a later reader
    must not mistake a green run here for "the route stopped scanning rows".
    What this class pins is narrower and true: the reader always
    materializes exactly `len(ports) * UPTIME_BUCKETS` rows into Python and
    always executes exactly one SQL statement to do it, regardless of how
    many rows are stored for those ports. Both measurements are taken at two
    different stored-check volumes over the SAME ports inside one test
    method, and compared to each other -- never against a literal number of
    rows or a wall-clock duration. The wall-time question this cost model
    cannot answer belongs to `06-PROFILE-3.md` (a dev-host measurement) and
    to `06-27`'s Pi run, never to this suite: a timing assertion here would
    be a flaky guard on a shared runner (`deferred-items.md` Entry 2 records
    what that already cost once).
    """

    def _insert_checks(self, appmod, port, rows):
        with appmod._db_lock:
            conn = appmod.get_db()
            for ts, online in rows:
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (ts, port, online),
                )
            conn.commit()
            conn.close()

    def _service_checks_count(self, appmod):
        with appmod._db_lock:
            conn = appmod.get_db()
            count = conn.execute('SELECT COUNT(*) AS c FROM service_checks').fetchone()['c']
            conn.close()
        return count

    def _measure(self, appmod, ports, now):
        """Return (materialized_row_count, statement_count) for one call to
        read_uptime_strips_by_port against appmod's live connection.

        sqlite3.Cursor.fetchall cannot be monkeypatched per-instance (a
        read-only C-extension attribute) -- the same constraint
        UptimeStripBoundednessTests._materialized_row_count documents --
        so a thin Python-level proxy wraps the real cursor exactly as it
        does there. Statement count is read from set_trace_callback,
        matching UptimeStripBoundednessTests._query_count.
        """
        class _CountingCursor:
            def __init__(self, cursor, counts):
                self._cursor = cursor
                self._counts = counts

            def fetchall(self):
                rows = self._cursor.fetchall()
                self._counts.append(len(rows))
                return rows

            def __getattr__(self, name):
                return getattr(self._cursor, name)

        with appmod._db_lock:
            conn = appmod.get_db()
            row_counts = []
            statements = []
            conn.set_trace_callback(lambda sql: statements.append(sql))
            original_execute = conn.execute

            def spy_execute(*args, **kwargs):
                return _CountingCursor(original_execute(*args, **kwargs), row_counts)

            conn.execute = spy_execute
            beacon_repositories.read_uptime_strips_by_port(
                conn, ports=ports, now=now, window_seconds=UPTIME_WINDOW_SECONDS,
                bucket_count=UPTIME_BUCKETS, retention_seconds=appmod.CHECK_RETENTION_SECONDS,
            )
            conn.execute = original_execute
            conn.set_trace_callback(None)
            conn.close()
        return sum(row_counts), len(statements)

    def test_python_side_row_and_statement_counts_are_independent_of_stored_check_volume(self):
        now = 1_700_000_000
        ports = list(range(53000, 53003))

        # Small volume: a 2-day, 5-minute-cadence history per port.
        small_appmod, small_db_path = load_app({})
        for port in ports:
            self._insert_checks(
                small_appmod, port,
                [(now - i * 300, i % 2) for i in range(2 * 288)],
            )
        small_stored = self._service_checks_count(small_appmod)
        small_rows, small_statements = self._measure(small_appmod, ports, now)
        cleanup_db(small_db_path)

        # Large volume: the SAME ports, the SAME cadence, 4x the retained days.
        large_appmod, large_db_path = load_app({})
        for port in ports:
            self._insert_checks(
                large_appmod, port,
                [(now - i * 300, i % 2) for i in range(8 * 288)],
            )
        large_stored = self._service_checks_count(large_appmod)
        large_rows, large_statements = self._measure(large_appmod, ports, now)
        cleanup_db(large_db_path)

        # Vacuity guard: a seeding failure must fail the test outright, not
        # pass it by comparing two zeros.
        self.assertGreater(small_rows, 0, 'small-volume run materialized zero rows -- seeding failed')
        self.assertGreater(large_rows, 0, 'large-volume run materialized zero rows -- seeding failed')

        # The growth factor this test method actually achieved, measured
        # from the stored service_checks counts it just read back -- never
        # assumed from the 2-vs-8 day multiplier used to seed it.
        growth_factor = large_stored / small_stored
        self.assertGreater(
            growth_factor, 1.0,
            f'test fixture did not actually grow the stored dataset: '
            f'small_stored={small_stored}, large_stored={large_stored}',
        )

        self.assertEqual(
            small_rows, large_rows,
            f'Python-side materialized row count moved with stored check volume (measured '
            f'{growth_factor:.3f}x growth in stored service_checks rows: small_stored='
            f'{small_stored}, large_stored={large_stored}) -- small_rows={small_rows}, '
            f'large_rows={large_rows}. read_uptime_strips_by_port must materialize exactly '
            f'len(ports) * UPTIME_BUCKETS rows regardless of how many rows are stored; SQLite '
            f'itself still scans the stored rows to build the aggregation -- only the '
            f'Python-side count is claimed to be bounded here.',
        )
        expected_rows = len(ports) * UPTIME_BUCKETS
        self.assertEqual(
            small_rows, expected_rows,
            f'materialized row count is not len(ports) * UPTIME_BUCKETS: '
            f'expected {expected_rows}, got {small_rows}',
        )

        self.assertEqual(
            small_statements, large_statements,
            f'statement count moved with stored check volume (measured {growth_factor:.3f}x '
            f'growth in stored service_checks rows): small={small_statements}, '
            f'large={large_statements} -- read_uptime_strips_by_port must issue exactly one '
            f'statement regardless of stored volume',
        )
        self.assertEqual(small_statements, 1)


# ---------------------------------------------------------------------------
# 06-29 (OPS-07 gap closure, Task 2): guards for the reshaped
# UPTIME_STRIP_QUERY (Task 1's index-arithmetic + recursive-expansion
# replacement of the range-join bucket_totals). UptimeStripSqlTextGuardTests
# is the narrowed rounding guard 06-25 specified but never shipped
# (PROH-OPS-07-23). UptimeStripRowEmissionTests pins mutation (b)'s finding
# from 06-25-SUMMARY.md: a row-drop in the aggregation does not only break
# boundedness, it silently makes the null_counts left join unreachable for a
# NULL-only port, disabling the NULL guard as a side effect (PROH-OPS-07-25).
# ---------------------------------------------------------------------------

class UptimeStripSqlTextGuardTests(unittest.TestCase):
    """The narrowed rounding guard.

    06-25-PLAN.md (lines 505-525) specified, but never shipped, a criterion
    reading "the query text contains no division character" -- an
    over-broad proxy for the actual hazard. The actual hazard, demonstrated
    concretely by 06-25's 400-trial randomized differential (mutation (c),
    caught at trial 33, port 40331): SQLite computing a rendered ratio in
    SQL produces `ROUND(1.0 * online_seconds / (online_seconds +
    offline_seconds), 3) == 0.063` where Python's `round(online_seconds /
    observed, 3) == 0.062` for a ratio near one sixteenth, because SQLite's
    ROUND() rounds half away from zero while Python's round() rounds half
    to even. Banning every division character in the query text ALSO
    forbids bucket-index arithmetic on values that select an array
    position and are never rendered -- exactly what this plan's Task 1
    index-arithmetic reshape needs (`(seg_start - start) / bucket_seconds`
    and `(seg_end - 1 - start) / bucket_seconds`).

    This guard is narrowed from "no division character anywhere" to "no
    SQL rounding call, and every division belongs to an enumerated pair of
    bucket-index expressions" (PROH-OPS-07-23) because the original proxy
    was WRONG about what it protected, never because the reshaped code
    could not meet the original criterion. PROH-OPS-07-01 (the
    differential's own correctness mandate -- SQLite must never compute a
    rendered value) is unaffected: rounding and the final ratio still
    happen only in Python, over the integer second totals this query
    returns; the allowlist below is what the constant's OWN two divisions
    are permitted to be, not a relaxation of where rounding may occur.
    Mutations (c), (c-prime) and (c-double-prime) -- run by hand against
    this narrowed form and reverted before commit -- are recorded verbatim
    in 06-29-SUMMARY.md and prove the narrowed guard still catches
    everything the original division ban caught, and nothing it did not.
    """

    # Declared once, as data (bare expression text, no comment or docstring
    # -- verbatim substrings of UPTIME_STRIP_QUERY itself). Adding a third
    # permitted expression requires an explicit edit here.
    PERMITTED_DIVISION_EXPRESSIONS = (
        '(seg_start - ?) / ?',    # spans.first_idx
        '(seg_end - 1 - ?) / ?',  # spans.last_idx
    )

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_no_sql_rounding_call(self):
        self.assertIsNone(
            re.search(r'\bround\s*\(', beacon_repositories.UPTIME_STRIP_QUERY, re.IGNORECASE),
            'UPTIME_STRIP_QUERY must contain no SQL rounding call -- rounding happens '
            'only in Python, over the integer second totals this query returns '
            '(SQLite ROUND() rounds half away from zero; Python round() rounds half '
            'to even, PROH-OPS-07-15/07-23)',
        )

    def test_every_division_belongs_to_the_permitted_pair(self):
        query = beacon_repositories.UPTIME_STRIP_QUERY
        for expr in self.PERMITTED_DIVISION_EXPRESSIONS:
            self.assertEqual(
                query.count(expr), 1,
                f'expected exactly one occurrence of the permitted expression {expr!r} '
                f'in UPTIME_STRIP_QUERY',
            )
        permitted_division_count = sum(
            expr.count('/') for expr in self.PERMITTED_DIVISION_EXPRESSIONS
        )
        self.assertEqual(
            query.count('/'), permitted_division_count,
            'a division character exists in UPTIME_STRIP_QUERY outside the enumerated '
            'first_idx/last_idx bucket-index pair -- a division added anywhere else (a '
            'projected column, a CASE arm, a join predicate) must fail this assertion',
        )

    def test_projected_columns_and_value_types(self):
        """The semantic half of the guard: the text checks above say no
        rounding and no stray division exist in the query text, and this
        check says nothing the reader consumes ever arrives as a
        SQLite-computed real -- read from a live execution's
        cursor.description and value types, not the query text.
        """
        port = 70001
        now = 1_700_000_000
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                (now - 1000, port, 1),
            )
            conn.commit()

            # sqlite3.Cursor.fetchall cannot be monkeypatched per-instance (a
            # read-only C-extension attribute) -- same constraint documented
            # by UptimeStripBoundednessTests._materialized_row_count. This
            # proxy additionally captures cursor.description, which is
            # populated immediately after execute() and does not require
            # consuming the cursor.
            class _CapturingCursor:
                def __init__(self, cursor, captured):
                    self._cursor = cursor
                    self._captured = captured
                    self._captured['description'] = cursor.description

                def fetchall(self):
                    rows = self._cursor.fetchall()
                    self._captured['rows'] = rows
                    return rows

                def __getattr__(self, name):
                    return getattr(self._cursor, name)

            captured = {}
            original_execute = conn.execute

            def spy_execute(*args, **kwargs):
                return _CapturingCursor(original_execute(*args, **kwargs), captured)

            conn.execute = spy_execute
            beacon_repositories.read_uptime_strips_by_port(
                conn, ports=[port], now=now, window_seconds=UPTIME_WINDOW_SECONDS,
                bucket_count=UPTIME_BUCKETS, retention_seconds=self.appmod.CHECK_RETENTION_SECONDS,
            )
            conn.execute = original_execute
            conn.close()

        column_names = [d[0] for d in captured['description']]
        self.assertEqual(
            column_names, ['port', 'idx', 'online_seconds', 'offline_seconds', 'null_count'],
            'the projected column set must be exactly the five the reader consumes',
        )
        self.assertGreater(len(captured['rows']), 0, 'seeding failed -- no rows returned')
        for row in captured['rows']:
            for key in ('online_seconds', 'offline_seconds', 'null_count'):
                value = row[key]
                self.assertIsInstance(value, int, f'{key} must be int, got {type(value)}')
                self.assertNotIsInstance(
                    value, float, f'{key} must never arrive as a SQLite-computed float',
                )

    def test_no_row_dropping_clause_and_left_join_present(self):
        query = beacon_repositories.UPTIME_STRIP_QUERY
        self.assertIsNone(
            re.search(r'\bhaving\b', query, re.IGNORECASE),
            'UPTIME_STRIP_QUERY must contain no HAVING clause -- a row-dropping '
            'predicate on the aggregate breaks boundedness and can silently disable '
            'the unrelated NULL guard (PROH-OPS-07-25)',
        )
        self.assertIn(
            'LEFT JOIN bucket_sums bs ON bs.port = rp.port AND bs.idx = bk.idx',
            query,
            'the scaffold must LEFT JOIN onto bucket_sums, never an inner join '
            '(PROH-OPS-07-25)',
        )


class UptimeStripRowEmissionTests(unittest.TestCase):
    """Mutation (b)'s finding, pinned as a standing test
    (06-25-SUMMARY.md, Mutation Verification (b)): dropping bucket rows
    from the aggregation does not only break boundedness -- it silently
    makes the null_counts left join unreachable for a port whose only row
    is NULL, disabling the NULL guard as a side effect of a mutation aimed
    at something else entirely. A per-port row-count TALLY, never a
    total-row assertion, is what catches a mutation that drops one port's
    rows while another port still supplies the total.

    Deliberately run against a SPARSE four-port fixture (PROH-OPS-07-25):
    on a dense multi-day dataset every (port, idx) pair already has an
    aggregate row, so an inner-join mutation of the scaffold's LEFT JOIN
    returns the full ports x UPTIME_BUCKETS set and falsely appears to
    pass -- confirmed directly in 06-29-SUMMARY.md's mutation verification,
    which also records the same mutation collapsing the sparse fixture's
    row count with the zero-row port vanishing entirely.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_checks(self, port, rows):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for ts, online in rows:
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (ts, port, online),
                )
            conn.commit()
            conn.close()

    def _execute_uptime_strip_query_directly(self, ports, now, retention_seconds):
        """Execute UPTIME_STRIP_QUERY directly over the connection, bypassing
        read_uptime_strips_by_port's NULL-refusal so a NULL-only port's rows
        can still be counted -- the reader aborts with ValueError before the
        caller ever sees them. Mirrors read_uptime_strips_by_port's own
        param construction (dashboard/beacon/repositories.py) -- intentional
        duplication so this guard can inspect the raw rows the reader
        itself never returns.
        """
        now = int(now)
        window_seconds = int(UPTIME_WINDOW_SECONDS)
        bucket_count = int(UPTIME_BUCKETS)
        retention_seconds = int(retention_seconds)
        bucket_seconds = window_seconds // bucket_count
        start = now - window_seconds
        retention_floor = now - retention_seconds
        placeholders = ','.join('?' * len(ports))
        port_values = ','.join('(?)' for _ in ports)
        query = beacon_repositories.UPTIME_STRIP_QUERY.format(
            placeholders=placeholders, port_values=port_values,
        )
        params = (
            *ports, retention_floor, now,
            start,
            start,
            start,
            now,
            *ports,
            start,
            bucket_seconds,
            bucket_count,
            start, now,
            start, bucket_seconds,
            start, bucket_seconds,
            start, bucket_seconds, start, bucket_seconds,
            start, bucket_seconds, start, bucket_seconds,
        )
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = conn.execute(query, params).fetchall()
            conn.close()
        return rows

    def test_every_requested_port_emits_exactly_uptime_buckets_rows(self):
        now = 1_700_000_000
        dense_port = 71001
        null_port = 71002
        empty_port = 71003
        sparse_port = 71004
        ports = [dense_port, null_port, empty_port, sparse_port]

        self._insert_checks(dense_port, [(now - i * 1800, i % 2) for i in range(300)])
        self._insert_checks(null_port, [(now - 100, None)])
        bucket_seconds = UPTIME_WINDOW_SECONDS // UPTIME_BUCKETS
        self._insert_checks(
            sparse_port,
            [(now - 2 * bucket_seconds - 10, 1), (now - bucket_seconds - 5, 0)],
        )
        # empty_port has no rows inserted at all.

        rows = self._execute_uptime_strip_query_directly(
            ports, now, self.appmod.CHECK_RETENTION_SECONDS,
        )

        tally = {port: 0 for port in ports}
        null_counts_for_null_port = []
        for row in rows:
            tally[row['port']] += 1
            if row['port'] == null_port:
                null_counts_for_null_port.append(row['null_count'])

        for port in ports:
            self.assertEqual(
                tally[port], UPTIME_BUCKETS,
                f'port {port} emitted {tally[port]} rows, expected exactly '
                f'{UPTIME_BUCKETS} -- a per-port tally is required because a '
                f'mutation can drop one port while another still supplies the total',
            )
        self.assertEqual(len(null_counts_for_null_port), UPTIME_BUCKETS)
        self.assertTrue(
            all(count > 0 for count in null_counts_for_null_port),
            'the NULL-only port must carry a non-zero null_count on every one of its rows',
        )

    def test_reader_raises_naming_the_null_only_port(self):
        now = 1_700_000_000
        null_port = 71012
        self._insert_checks(null_port, [(now - 100, None)])
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            with self.assertRaises(ValueError) as ctx:
                beacon_repositories.read_uptime_strips_by_port(
                    conn, ports=[null_port], now=now, window_seconds=UPTIME_WINDOW_SECONDS,
                    bucket_count=UPTIME_BUCKETS, retention_seconds=self.appmod.CHECK_RETENTION_SECONDS,
                )
            conn.close()
        self.assertIn(str(null_port), str(ctx.exception))


# ---------------------------------------------------------------------------
# 06-31 (input-reduction remediation, OPS-07): 06-GUARD-DECISION.md §8's
# scoped rollup remedy is refuted on evidence (D-DEBT-06-21, PROH-OPS-07-29)
# -- service_rollups holds zero rows inside the strip window, and an
# hour-aligned rollup could not render the strip's sliding boundaries even if
# populated (PROH-OPS-07-15). The cheaper remedy instead reduces
# checks_by_port to state-change points only, inside api_services' existing
# loop (dashboard/app.py, the `for row in all_checks` block around
# `last_state_by_port`). Two guards below prove this reduction together:
# UptimeStripCoalescingDifferentialTests proves it is output-identical and
# never coalesces a NULL row away (PROH-OPS-07-28); UptimeStripInputReduction
# GuardTests proves the reduction is actually PRESENT, because a differential
# alone cannot detect its absence -- unreduced input trivially agrees with
# itself (mutation m3, recorded in 06-31-SUMMARY.md at 0/N divergences).
# ---------------------------------------------------------------------------

def _reduce_to_state_changes(rows):
    """Mirrors api_services' checks_by_port reduction rule (dashboard/app.py
    line ~2968 onward, the `for row in all_checks` loop body around
    `last_state_by_port`, 06-31) over a single port's `(ts, online)` rows,
    already ordered by `ts` the way the route's own SQL orders them
    (`ORDER BY port ASC, ts ASC`).

    Kept as a free function here rather than imported, because the
    reduction lives inline in api_services' loop body, not as a separate
    callable -- there is nothing importable to call instead.
    `UptimeStripCoalescingDifferentialTests.test_mirror_agrees_with_the_route_on_its_own_loop`
    drives the real route through a real database and proves this mirror
    matches what api_services actually hands `_uptime_summary`, so a
    divergence between this function and dashboard/app.py's inline logic
    cannot silently pass this file's other assertions.
    """
    reduced = []
    last_state = None
    for ts, online in rows:
        if online is None:
            reduced.append((ts, online))
            last_state = None
        else:
            state = 1 if online else 0
            if last_state != state:
                reduced.append((ts, online))
                last_state = state
    return reduced


class UptimeStripCoalescingDifferentialTests(unittest.TestCase):
    """The reduction is output-identical to `_legacy_uptime_summary`'s own
    output over the unreduced route-input subset, and never coalesces a NULL
    row away (`PROH-OPS-07-28`). Every oracle call goes through this class's
    own `_route_input_rows`, reusing `UptimeStripSqlDifferentialTests`'
    contract exactly -- the route's own retention-floored subset, never the
    full inserted set (`PROH-OPS-07-22`); restated here rather than shared
    across TestCase classes so this class's failures are self-contained.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _route_input_rows(self, inserted, port, now):
        floor = now - self.appmod.CHECK_RETENTION_SECONDS
        return [(ts, online) for ts, online in inserted.get(port, []) if ts >= floor]

    def _call_and_capture(self, rows, now):
        """Both the reduced and raw forms must either return the same tuple
        or both raise the same exception TYPE -- a raised TypeError is an
        outcome to be compared, never an error to be swallowed
        (`PROH-OPS-07-28`'s NULL case surfaces exactly this way).
        """
        try:
            return ('ok', self.appmod._legacy_uptime_summary(rows, now))
        except TypeError as exc:
            return ('TypeError', type(exc))

    def test_randomized_histories_agree_between_reduced_and_raw_route_input(self):
        # Own seed -- not 20260925 (UptimeStripSqlDifferentialTests) and not
        # 20260901 (UptimeSummaryDifferentialTests) -- so a failure is
        # unambiguous about which class's fixture produced it.
        rng = random.Random(20260931)
        base_now = 1_700_000_000
        total_cases = 0
        null_cases = 0
        total_raw_points = 0
        total_reduced_points = 0

        for trial in range(400):
            now = base_now + rng.randint(-10_000, 10_000)
            port_count = rng.randint(1, 8)
            port_base = 60000 + trial * 10
            ports = list(range(port_base, port_base + port_count))
            inserted = {}
            for port in ports:
                total_cases += 1
                window_start = now - UPTIME_WINDOW_SECONDS
                sample_count = rng.randint(0, 40)
                checks = []
                state = rng.randint(0, 1)
                if rng.random() < 0.25:
                    # Deliberately starts before the retention floor, so at
                    # least one in four histories crosses it under
                    # randomized pressure, matching the same pressure
                    # UptimeStripSqlDifferentialTests applies.
                    ts = now - self.appmod.CHECK_RETENTION_SECONDS - rng.randint(1, UPTIME_WINDOW_SECONDS)
                else:
                    ts = window_start - rng.randint(0, UPTIME_WINDOW_SECONDS // 2)
                for _ in range(sample_count):
                    if rng.random() < 0.5:
                        state = 1 - state
                    checks.append((ts, state))
                    choice = rng.random()
                    if choice < 0.1:
                        idx = rng.randint(0, UPTIME_BUCKETS)
                        ts = int(window_start + idx * (UPTIME_WINDOW_SECONDS / UPTIME_BUCKETS))
                    elif choice < 0.2:
                        ts += rng.randint(1, UPTIME_WINDOW_SECONDS // 4 + 1)
                    else:
                        ts += rng.randint(1, UPTIME_WINDOW_SECONDS // 40 + 1)
                # Roughly one case in twenty seeds a NULL row immediately
                # after the run, at a guaranteed-unique, guaranteed-later
                # timestamp, to exercise the NULL-preservation rule under
                # the same randomized pressure as every other case
                # (PROH-OPS-07-28).
                if checks and rng.random() < 0.05:
                    checks.append((checks[-1][0] + 1, None))
                    null_cases += 1
                seen = set()
                deduped = []
                for ts_i, state_i in checks:
                    if ts_i not in seen:
                        seen.add(ts_i)
                        deduped.append((ts_i, state_i))
                inserted[port] = deduped

            for port in ports:
                route_rows = sorted(self._route_input_rows(inserted, port, now), key=lambda r: r[0])
                reduced_rows = _reduce_to_state_changes(route_rows)
                total_raw_points += len(route_rows)
                total_reduced_points += len(reduced_rows)

                raw_outcome = self._call_and_capture(route_rows, now)
                reduced_outcome = self._call_and_capture(reduced_rows, now)
                self.assertEqual(
                    raw_outcome, reduced_outcome,
                    f'trial {trial} port {port}: reduced input diverged from raw '
                    f'route input on _legacy_uptime_summary '
                    f'(raw={route_rows}, reduced={reduced_rows})',
                )

        self.assertGreaterEqual(
            total_cases, 1500,
            f'expected at least 1,500 cases exercised, got {total_cases} -- a '
            f'generator change emptied this class',
        )
        self.assertGreaterEqual(
            null_cases, 50,
            f'expected at least 50 cases carrying a NULL row, got {null_cases} -- '
            f'a generator change stopped exercising the NULL-preservation rule',
        )
        self.assertGreater(total_raw_points, 0, 'no raw points were generated at all -- seeding failed')
        self.assertLess(
            total_reduced_points, total_raw_points,
            'the reduction did not shrink the input at all across this transition-'
            'dense case space -- something is wrong with either the generator or '
            'the reduction',
        )

    def test_null_after_a_same_state_run_is_never_coalesced_away(self):
        """The specific case the plan calls out: a NULL following an
        already-offline run. Naive falsy-coalescing drops it and the
        producer then returns a number where the correct form raises
        (`PROH-OPS-07-28`).
        """
        now = 1_700_000_000
        rows = [(now - 3000, 0), (now - 2000, 0), (now - 100, None)]
        reduced = _reduce_to_state_changes(rows)
        self.assertEqual(
            len(reduced), 2,
            f'expected the NULL row to survive reduction alongside one run-'
            f'starting row, got {reduced}',
        )
        self.assertIsNone(reduced[-1][1], 'the NULL row itself must be the last retained row')
        with self.assertRaises(TypeError):
            self.appmod._legacy_uptime_summary(reduced, now)
        with self.assertRaises(TypeError):
            self.appmod._legacy_uptime_summary(rows, now)

    def test_mirror_agrees_with_the_route_on_its_own_loop(self):
        """Proves `_reduce_to_state_changes` (this file's mirror) matches
        what api_services' own inline loop actually hands `_uptime_summary`
        -- driven through the real database and the real route, not
        reimplemented a second time. This is the "companion assertion" the
        plan requires because Task 2 left the reduction inline rather than
        as an importable function.
        """
        appmod = self.appmod
        port = 91001
        now = int(time.time())
        rows = [
            (now - 6000, 1), (now - 5900, 1), (now - 5800, 1),
            (now - 5000, 0), (now - 4900, 0),
            (now - 4000, 1),
            (now - 2000, 0), (now - 1900, 0),
        ]
        with appmod._db_lock:
            conn = appmod.get_db()
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                "VALUES(?,?,?,?,?,?)",
                (port, 'Mirror', now - 6000, now, 1, now - 60),
            )
            for ts, online in rows:
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (ts, port, online),
                )
            conn.commit()
            conn.close()

        captured = []
        original = appmod._uptime_summary

        def spy(checks, spy_now):
            captured.append((spy_now, list(checks)))
            return original(checks, spy_now)

        with mock.patch.object(appmod, '_uptime_summary', side_effect=spy):
            response = appmod.app.test_client().get('/api/services')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(captured), 1, 'expected exactly one _uptime_summary call for one seeded service')
        _route_now, route_checks = captured[0]

        expected = _reduce_to_state_changes(sorted(rows, key=lambda r: r[0]))
        self.assertEqual(
            sorted(route_checks, key=lambda r: r[0]), expected,
            "this file's mirror of the reduction rule diverged from what "
            'api_services actually handed _uptime_summary',
        )


class UptimeStripInputReductionGuardTests(unittest.TestCase):
    """Pins that api_services' input to the strip producer is a function of
    STATE TRANSITIONS, never of stored check volume -- the property a
    correctness differential cannot detect the absence of (mutation m3 in
    `UptimeStripCoalescingDifferentialTests`: removing the reduction
    diverges 0 cases, because unreduced input trivially agrees with
    itself). Run against both a dense fixture and a fixture whose window is
    mostly unobserved (`PROH-OPS-07-25`): a row-count guard verified only on
    a dense dataset can falsely appear to pass.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _seed_service_and_checks(self, appmod, port, rows, now, title):
        with appmod._db_lock:
            conn = appmod.get_db()
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) "
                "VALUES(?,?,?,?,?,?)",
                (port, title, (rows[0][0] if rows else now - 3600), now, 1, now - 60),
            )
            for ts, online in rows:
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                    (ts, port, online),
                )
            conn.commit()
            conn.close()

    def _measured_input_count(self, appmod):
        """Return the length of the `checks` list api_services actually
        hands `_uptime_summary` -- observed by wrapping the real producer
        through the real route, never re-derived, so a reduction that
        silently disappeared cannot hide behind a re-implementation of the
        rule under test.
        """
        captured = []
        original = appmod._uptime_summary

        def spy(checks, now):
            captured.append(len(checks))
            return original(checks, now)

        with mock.patch.object(appmod, '_uptime_summary', side_effect=spy):
            response = appmod.app.test_client().get('/api/services')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            len(captured), 1,
            'expected exactly one _uptime_summary call for one seeded service',
        )
        return captured[0]

    def test_reduced_input_count_tracks_transitions_not_stored_volume(self):
        # Real wall-clock `now`, not a fixed historical epoch: the route
        # filters `services` on `last_seen >= now - EXPIRE_DAYS * 86400`
        # against the CURRENT time at request time, so a seeded `last_seen`
        # far in the past would silently exclude the service from the
        # response and this class's own vacuity guard would never fire.
        now = int(time.time())
        window_start = now - UPTIME_WINDOW_SECONDS
        # Six state-schedule points (5 transitions -> 6 retained points),
        # spread evenly across the window.
        transition_ts = [
            int(window_start + frac * UPTIME_WINDOW_SECONDS) + 10
            for frac in (0, 1 / 6, 2 / 6, 3 / 6, 4 / 6, 5 / 6)
        ]
        state_schedule = [1, 0, 1, 0, 1, 0]

        def state_at(ts):
            state = state_schedule[0]
            for boundary_ts, boundary_state in zip(transition_ts, state_schedule):
                if ts >= boundary_ts:
                    state = boundary_state
            return state

        sparse_rows = list(zip(transition_ts, state_schedule))
        # Dense cadence: a check every 5 minutes for the whole window,
        # following the IDENTICAL online/offline schedule as the sparse
        # fixture -- same transitions, ~336x the stored volume.
        dense_rows = [(ts, state_at(ts)) for ts in range(window_start + 60, now, 300)]

        sparse_appmod, sparse_db_path = load_app({})
        self._seed_service_and_checks(sparse_appmod, 81001, sparse_rows, now, 'Sparse')
        sparse_count = self._measured_input_count(sparse_appmod)
        cleanup_db(sparse_db_path)

        dense_appmod, dense_db_path = load_app({})
        self._seed_service_and_checks(dense_appmod, 81002, dense_rows, now, 'Dense')
        dense_count = self._measured_input_count(dense_appmod)
        cleanup_db(dense_db_path)

        dense_stored = len(dense_rows)
        self.assertGreater(
            dense_stored, dense_count * 10,
            f'test fixture did not actually store substantially more rows than '
            f'the reduced count: dense_stored={dense_stored}, dense_count={dense_count}',
        )
        self.assertEqual(
            sparse_count, dense_count,
            f"the strip producer's input count moved with stored check volume: "
            f'sparse_count={sparse_count} (stored={len(sparse_rows)}), '
            f'dense_count={dense_count} (stored={dense_stored}) -- the strip\'s '
            f'Python input must be a function of state transitions, and a count '
            f'that tracks stored volume means the reduction is gone',
        )
        self.assertEqual(
            sparse_count, len(transition_ts),
            f'expected the reduced count to equal the number of state-change '
            f'points ({len(transition_ts)}), got {sparse_count}',
        )
        self.assertLess(
            dense_count, dense_stored,
            f'the reduced count ({dense_count}) is not strictly below the dense '
            f"fixture's stored row count ({dense_stored}) -- the strip's Python "
            f'input must be a function of state transitions, and a count that '
            f'tracks stored volume means the reduction is gone',
        )

    def test_reduced_input_count_holds_on_a_mostly_unobserved_window(self):
        """`PROH-OPS-07-25`: a row-count guard verified only on a dense
        dataset can falsely appear to pass. This fixture's window is mostly
        unobserved -- three checks in the final 300 seconds of a 7-day
        window -- so the reduction's floor (transitions + 1) must hold here
        too, not only on a dense fixture.
        """
        now = int(time.time())
        port = 81003
        rows = [(now - 300, 1), (now - 200, 0), (now - 100, 0)]
        self._seed_service_and_checks(self.appmod, port, rows, now, 'Sparse-window')
        count = self._measured_input_count(self.appmod)
        self.assertEqual(
            count, 2,
            f'expected exactly 2 retained points (the run-starting online point '
            f'plus the online->offline transition), got {count} -- the reduction '
            f'must still coalesce the repeated offline check even on a mostly-'
            f'unobserved window',
        )
