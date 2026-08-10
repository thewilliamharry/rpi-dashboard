import time
import unittest

from dashboard.beacon import repositories as telemetry_repositories
from dashboard.beacon import telemetry
from tests.helpers import cleanup_db, load_app


class HistoricalTelemetryApiTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.client = self.appmod.app.test_client()
        self.now = int(time.time())

    def tearDown(self):
        cleanup_db(self.db_path)

    def _seed_host_rows(self, rows):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.executemany(
                    "INSERT INTO stats_history(ts, cpu, ram, disk, temp) VALUES(?,?,?,?,?)",
                    rows,
                )
                conn.commit()
            finally:
                conn.close()

    def _request(self, metric='cpu', start_ts=None, end_ts=None, kind='host'):
        start_ts = self.now - 300 if start_ts is None else start_ts
        end_ts = self.now - 60 if end_ts is None else end_ts
        return self.client.get('/api/telemetry/history', query_string={
            'kind': kind,
            'metric': metric,
            'start_ts': str(start_ts),
            'end_ts': str(end_ts),
        })

    def test_real_sqlite_rows_return_ordered_bounded_history(self):
        start_ts = self.now - 300
        end_ts = self.now - 60
        self._seed_host_rows([
            (self.now - 240, 30.0, 40.0, 50.0, 60.0),
            (self.now - 180, 10.0, 20.0, 30.0, 40.0),
            (self.now - 120, 20.0, 30.0, 40.0, 50.0),
        ])

        response = self._request(start_ts=start_ts, end_ts=end_ts)

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['requested'], {'start_ts': start_ts, 'end_ts': end_ts})
        self.assertEqual(payload['effective_resolution_seconds'], 60)
        self.assertEqual(payload['point_budget'], 2048)
        self.assertEqual(payload['source_resolutions_seconds'], [60])
        self.assertEqual(
            payload['points'],
            [
                {'ts': self.now - 240, 'value': 30.0},
                {'ts': self.now - 180, 'value': 10.0},
                {'ts': self.now - 120, 'value': 20.0},
            ],
        )
        self.assertLessEqual(len(payload['points']), payload['point_budget'])
        self.assertEqual(payload['coverage'], [
            {'start_ts': start_ts, 'end_ts': self.now - 240, 'state': 'not_yet_monitored'},
            {'start_ts': self.now - 240, 'end_ts': end_ts, 'state': 'unknown'},
        ])

    def test_empty_and_single_sample_ranges_preserve_missing_history(self):
        start_ts = self.now - 300
        end_ts = self.now - 60

        empty = self._request(start_ts=start_ts, end_ts=end_ts)
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.get_json()['points'], [])
        self.assertEqual(empty.get_json()['coverage'], [
            {'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'},
        ])

        self._seed_host_rows([(self.now - 180, 10.0, 20.0, 30.0, 40.0)])
        single = self._request(start_ts=start_ts, end_ts=end_ts)
        self.assertEqual(single.status_code, 200)
        self.assertEqual(single.get_json()['points'], [
            {'ts': self.now - 180, 'value': 10.0},
        ])
        self.assertEqual(single.get_json()['coverage'], [
            {'start_ts': start_ts, 'end_ts': self.now - 180, 'state': 'not_yet_monitored'},
            {'start_ts': self.now - 180, 'end_ts': end_ts, 'state': 'unknown'},
        ])

    def test_invalid_selectors_and_bounds_are_rejected_before_history_read(self):
        cases = [
            {'kind': 'service', 'metric': 'cpu', 'start_ts': str(self.now - 120), 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'load', 'start_ts': str(self.now - 120), 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': 'true', 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': '1.5', 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': str(self.now - 60), 'end_ts': str(self.now - 120)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': str(self.now - 90 * 86400 - 2), 'end_ts': str(self.now - 1)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': str(self.now - 60), 'end_ts': str(self.now + 1)},
        ]
        for query in cases:
            with self.subTest(query=query):
                response = self.client.get('/api/telemetry/history', query_string=query)
                self.assertEqual(response.status_code, 400)

    def test_repository_merges_each_retained_host_tier_without_boundary_duplicates(self):
        """Raw, five-minute, and hourly evidence stays distinguishable after re-bucketing."""
        raw_cutoff = self.now - 7 * 86400
        five_minute_cutoff = self.now - 30 * 86400
        start_ts = five_minute_cutoff - 3600
        end_ts = raw_cutoff + 3600
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    "INSERT INTO stats_history(ts, cpu, ram, disk, temp) VALUES(?,?,?,?,?)",
                    (raw_cutoff + 60, 12.0, 0.0, 0.0, 0.0),
                )
                conn.execute(
                    "INSERT INTO host_metric_rollups("
                    "metric, bucket_start, bucket_seconds, min_value, max_value, avg_value, latest_value, "
                    "sample_count, observed_seconds, gap_seconds, unknown_seconds) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    ("cpu", raw_cutoff - 300, 300, 8.0, 10.0, 9.0, 10.0, 2, 300, 0, 0),
                )
                conn.execute(
                    "INSERT INTO host_metric_rollups("
                    "metric, bucket_start, bucket_seconds, min_value, max_value, avg_value, latest_value, "
                    "sample_count, observed_seconds, gap_seconds, unknown_seconds) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    ("cpu", five_minute_cutoff - 3600, 3600, 1.0, 4.0, 2.5, 4.0, 4, 3600, 0, 0),
                )
                conn.commit()
                segments = telemetry_repositories.get_host_telemetry(
                    conn,
                    "cpu",
                    start_ts,
                    end_ts,
                    3600,
                    telemetry.POINT_BUDGET + 1,
                    {
                        "raw_start_ts": raw_cutoff,
                        "five_minute_start_ts": five_minute_cutoff,
                    },
                )
            finally:
                conn.close()

        response = telemetry.compose_historical_response(segments, "host")
        self.assertEqual(response["source_resolutions_seconds"], [60, 300, 3600])
        # The raw and five-minute slices share a display bucket, so a truthful
        # server aggregation returns one merged bucket rather than duplicates.
        self.assertEqual(len(response["points"]), 2)
        self.assertEqual(
            [point["ts"] for point in response["points"]],
            sorted(point["ts"] for point in response["points"]),
        )
        self.assertTrue(all("sample_count" in point for point in response["points"]))

    def test_repository_merges_service_durations_and_latency_across_tiers(self):
        raw_cutoff = self.now - 7 * 86400
        five_minute_cutoff = self.now - 30 * 86400
        start_ts = five_minute_cutoff - 3600
        end_ts = raw_cutoff + 3600
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    "INSERT INTO service_checks(ts, port, online, latency_ms, error_class) VALUES(?,?,?,?,?)",
                    (raw_cutoff + 60, 8080, 1, 40.0, None),
                )
                conn.execute(
                    "INSERT INTO service_rollups("
                    "service_port, bucket_start, bucket_seconds, online_seconds, offline_seconds, "
                    "unknown_seconds, gap_seconds, latency_min, latency_max, latency_avg, "
                    "latency_sample_count, check_count, failure_class_counts_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (8080, raw_cutoff - 300, 300, 300, 0, 0, 0, 20.0, 30.0, 25.0, 2, 2, "{}"),
                )
                conn.execute(
                    "INSERT INTO service_rollups("
                    "service_port, bucket_start, bucket_seconds, online_seconds, offline_seconds, "
                    "unknown_seconds, gap_seconds, latency_min, latency_max, latency_avg, "
                    "latency_sample_count, check_count, failure_class_counts_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (8080, five_minute_cutoff - 3600, 3600, 0, 3600, 0, 0, 70.0, 90.0, 80.0, 2, 2, '{"timeout":2}'),
                )
                conn.commit()
                segments = telemetry_repositories.get_service_telemetry(
                    conn, 8080, start_ts, end_ts, 3600, telemetry.POINT_BUDGET + 1,
                    {"raw_start_ts": raw_cutoff, "five_minute_start_ts": five_minute_cutoff},
                )
            finally:
                conn.close()

        response = telemetry.compose_historical_response(segments, "service")
        self.assertEqual(response["source_resolutions_seconds"], [60, 300, 3600])
        self.assertLessEqual(len(response["points"]), 4)
        hourly = next(point for point in response["points"] if point["offline_seconds"] == 3600)
        self.assertEqual(hourly["failure_class_counts"], {"timeout": 2})
