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
        self.assertEqual([point['latest_value'] for point in payload['points']], [30.0, 10.0, 20.0])
        self.assertTrue(all({
            'min_value', 'max_value', 'avg_value', 'latest_value', 'sample_count',
            'observed_seconds', 'gap_seconds', 'unknown_seconds',
        }.issubset(point) for point in payload['points']))
        self.assertLessEqual(len(payload['points']), payload['point_budget'])
        self.assertEqual(payload['coverage'], [
            {'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'},
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
        self.assertEqual(len(single.get_json()['points']), 1)
        self.assertEqual(single.get_json()['points'][0]['latest_value'], 10.0)
        self.assertEqual(single.get_json()['coverage'], [
            {'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'},
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

    def test_history_contract_partitions_coverage_and_discloses_pending_aggregation(self):
        start_ts = self.now - 300
        end_ts = self.now - 60
        self._seed_host_rows([(start_ts, 12.0, 0.0, 0.0, 0.0)])
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    "INSERT INTO telemetry_streams("
                    "stream_kind, stream_key, started_ts, cadence_seconds, last_observed_ts, consecutive_misses) "
                    "VALUES(?,?,?,?,?,0)",
                    ("host", "cpu", start_ts, 60, self.now - 120),
                )
                conn.execute(
                    "INSERT INTO telemetry_coverage("
                    "stream_kind, stream_key, start_ts, end_ts, reason, detail) VALUES(?,?,?,?,?,?)",
                    ("host", "cpu", self.now - 240, self.now - 180, "collection_gap", "storage_pressure"),
                )
                conn.execute(
                    "INSERT INTO telemetry_rollup_jobs("
                    "stream_kind, stream_key, bucket_start, bucket_seconds, state, attempt_count, "
                    "next_retry_ts, last_error_class, updated_ts) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("host", "cpu", self.now - 180, 300, "failed", 2, self.now + 60, "sqlite_busy", self.now),
                )
                conn.commit()
            finally:
                conn.close()

        response = self._request(start_ts=start_ts, end_ts=end_ts)

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["selector"], {"kind": "host", "metric": "cpu"})
        self.assertEqual(payload["coverage"], [
            {"start_ts": start_ts, "end_ts": self.now - 240, "state": "observed"},
            {
                "start_ts": self.now - 240,
                "end_ts": self.now - 180,
                "state": "collection_gap",
                "detail": "storage_pressure",
            },
            {"start_ts": self.now - 180, "end_ts": end_ts, "state": "unknown"},
        ])
        self.assertEqual(payload["aggregation_pending"], [{
            "start_ts": self.now - 180,
            "end_ts": self.now + 120,
            "state": "failed",
            "attempt_count": 2,
            "next_retry_ts": self.now + 60,
            "error_class": "sqlite_busy",
        }])

    def test_history_contract_rejects_duplicate_or_mixed_selectors(self):
        query = [
            ("kind", "host"),
            ("metric", "cpu"),
            ("metric", "ram"),
            ("port", "8080"),
            ("start_ts", str(self.now - 120)),
            ("end_ts", str(self.now - 60)),
        ]
        response = self.client.get('/api/telemetry/history', query_string=query)
        self.assertEqual(response.status_code, 400)

    def test_partition_coverage_tiles_all_states_without_overlap(self):
        sources = (
            telemetry.SourceSegment(60, ({"bucket_start": 20, "first_ts": 20, "observed_seconds": 20},)),
            telemetry.SourceSegment(60, ({"bucket_start": 55, "first_ts": 55, "observed_seconds": 5},)),
        )
        coverage = telemetry.partition_coverage(
            0,
            100,
            retention_start_ts=10,
            stream={"started_ts": 20, "cadence_seconds": 10, "last_observed_ts": 60},
            persisted_intervals=(
                {"start_ts": 40, "end_ts": 50, "reason": "collection_gap", "detail": "storage_pressure"},
                {"start_ts": 50, "end_ts": 55, "reason": "unknown", "detail": "retrying"},
            ),
            source_segments=sources,
        )

        self.assertEqual([interval.as_dict() for interval in coverage], [
            {"start_ts": 0, "end_ts": 10, "state": "expired"},
            {"start_ts": 10, "end_ts": 20, "state": "not_yet_monitored"},
            {"start_ts": 20, "end_ts": 40, "state": "observed"},
            {"start_ts": 40, "end_ts": 50, "state": "collection_gap", "detail": "storage_pressure"},
            {"start_ts": 50, "end_ts": 55, "state": "unknown", "detail": "retrying"},
            {"start_ts": 55, "end_ts": 60, "state": "observed"},
            {"start_ts": 60, "end_ts": 100, "state": "unknown"},
        ])
        self.assertEqual(sum(interval.end_ts - interval.start_ts for interval in coverage), 100)

    def test_service_history_accepts_only_a_range_checked_port_selector(self):
        start_ts = self.now - 180
        end_ts = self.now - 60
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    "INSERT INTO service_checks(ts, port, online, latency_ms, error_class) VALUES(?,?,?,?,?)",
                    (start_ts, 8080, 1, 12.5, None),
                )
                conn.execute(
                    "INSERT INTO telemetry_streams("
                    "stream_kind, stream_key, started_ts, cadence_seconds, last_observed_ts, consecutive_misses) "
                    "VALUES(?,?,?,?,?,0)",
                    ("service", "8080", start_ts, 60, start_ts),
                )
                conn.commit()
            finally:
                conn.close()

        response = self.client.get('/api/telemetry/history', query_string={
            'kind': 'service', 'port': '8080', 'start_ts': str(start_ts), 'end_ts': str(end_ts),
        })
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['selector'], {'kind': 'service', 'port': 8080})
        self.assertLessEqual(len(payload['points']), payload['point_budget'])
        self.assertEqual(payload['points'][0]['latency_avg'], 12.5)
