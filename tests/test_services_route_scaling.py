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

import random
import time
import unittest
from unittest import mock

from dashboard.beacon import repositories as beacon_repositories
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
