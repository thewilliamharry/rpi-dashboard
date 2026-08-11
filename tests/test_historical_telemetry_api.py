import time
import unittest
from unittest import mock

from dashboard.beacon import queues
from dashboard.beacon import repositories as telemetry_repositories
from dashboard.beacon import telemetry
from dashboard.beacon.worker_authority import WorkerAuthority
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
        # Keep the two sources inside one hourly display bucket regardless of
        # the wall-clock minute when this regression runs.
        raw_cutoff = (self.now // 3600) * 3600 + 1800
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

    def test_host_raw_fallback_is_observed_until_a_completed_rollup_owns_it(self):
        """A retained raw point stays visible past its normal age band."""
        cutoffs = {'raw_start_ts': 100, 'five_minute_start_ts': 0}
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    'INSERT INTO stats_history(ts, cpu, ram, disk, temp) VALUES(?,?,?,?,?)',
                    (60, 12.0, 22.0, 32.0, 42.0),
                )
                conn.execute(
                    'INSERT INTO telemetry_streams('
                    'stream_kind, stream_key, started_ts, cadence_seconds, last_observed_ts, consecutive_misses) '
                    'VALUES(?,?,?,?,?,0)',
                    ('host', 'cpu', 0, 60, 60),
                )
                conn.commit()
                fallback = telemetry_repositories.get_host_telemetry(
                    conn, 'cpu', 0, 100, 60, telemetry.POINT_BUDGET + 1, cutoffs,
                )
                coverage_data = telemetry_repositories.get_telemetry_coverage(
                    conn, 'host', 'cpu', 0, 100, telemetry.POINT_BUDGET + 1,
                )
            finally:
                conn.close()

        history = telemetry.compose_historical_response(fallback, 'host')
        self.assertEqual(history['source_resolutions_seconds'], [60])
        self.assertEqual([point['latest_value'] for point in history['points']], [12.0])
        coverage = telemetry.partition_coverage(
            0,
            100,
            retention_start_ts=0,
            stream=coverage_data['stream'],
            persisted_intervals=coverage_data['intervals'],
            source_segments=fallback,
        )
        self.assertEqual([interval.as_dict() for interval in coverage], [
            {'start_ts': 0, 'end_ts': 60, 'state': 'unknown'},
            {'start_ts': 60, 'end_ts': 100, 'state': 'observed'},
        ])

    def test_host_completed_rollup_suppresses_raw_fallback_and_shared_job_overrides_pending(self):
        """Higher completed evidence owns a bucket; raw-host work is shared by metric."""
        cutoffs = {'raw_start_ts': 100, 'five_minute_start_ts': 0}
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    'INSERT INTO stats_history(ts, cpu, ram, disk, temp) VALUES(?,?,?,?,?)',
                    (60, 12.0, 22.0, 32.0, 42.0),
                )
                conn.execute(
                    'INSERT INTO host_metric_rollups('
                    'metric, bucket_start, bucket_seconds, min_value, max_value, avg_value, latest_value, '
                    'sample_count, observed_seconds, gap_seconds, unknown_seconds) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    ('cpu', 0, 300, 9.0, 9.0, 9.0, 9.0, 1, 60, 0, 0),
                )
                conn.execute(
                    'INSERT INTO telemetry_rollup_jobs('
                    'stream_kind, stream_key, bucket_start, bucket_seconds, state, attempt_count, '
                    'next_retry_ts, last_error_class, updated_ts) VALUES(?,?,?,?,?,?,?,?,?)',
                    ('host', 'host', 0, 300, 'failed', 2, 180, 'sqlite_busy', 120),
                )
                conn.commit()
                fallback = telemetry_repositories.get_host_telemetry(
                    conn, 'cpu', 0, 100, 60, telemetry.POINT_BUDGET + 1, cutoffs,
                )
                pending = telemetry_repositories.get_pending_aggregation(
                    conn,
                    'host',
                    'cpu',
                    0,
                    100,
                    60,
                    telemetry.POINT_BUDGET + 1,
                    cutoffs,
                )
            finally:
                conn.close()

        history = telemetry.compose_historical_response(fallback, 'host')
        self.assertEqual(history['source_resolutions_seconds'], [300])
        self.assertEqual([point['latest_value'] for point in history['points']], [9.0])
        self.assertEqual(pending, ({
            'start_ts': 0,
            'end_ts': 300,
            'state': 'failed',
            'attempt_count': 2,
            'next_retry_ts': 180,
            'error_class': 'sqlite_busy',
        },))

    def test_host_five_minute_fallback_and_exact_cutoffs_have_one_owner(self):
        cutoffs = {'raw_start_ts': 1000, 'five_minute_start_ts': 500}
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    'INSERT INTO host_metric_rollups('
                    'metric, bucket_start, bucket_seconds, min_value, max_value, avg_value, latest_value, '
                    'sample_count, observed_seconds, gap_seconds, unknown_seconds) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    ('cpu', 300, 300, 5.0, 5.0, 5.0, 5.0, 1, 300, 0, 0),
                )
                conn.commit()
                fallback = telemetry_repositories.get_host_telemetry(
                    conn, 'cpu', 0, 1000, 300, telemetry.POINT_BUDGET + 1, cutoffs,
                )
                conn.execute(
                    'INSERT INTO host_metric_rollups('
                    'metric, bucket_start, bucket_seconds, min_value, max_value, avg_value, latest_value, '
                    'sample_count, observed_seconds, gap_seconds, unknown_seconds) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    ('cpu', 0, 3600, 7.0, 7.0, 7.0, 7.0, 1, 3600, 0, 0),
                )
                conn.commit()
                replacement = telemetry_repositories.get_host_telemetry(
                    conn, 'cpu', 0, 1000, 300, telemetry.POINT_BUDGET + 1, cutoffs,
                )
            finally:
                conn.close()

        self.assertEqual(
            telemetry.compose_historical_response(fallback, 'host')['source_resolutions_seconds'],
            [300],
        )
        replaced = telemetry.compose_historical_response(replacement, 'host')
        self.assertEqual(replaced['source_resolutions_seconds'], [3600])
        self.assertEqual([point['latest_value'] for point in replaced['points']], [7.0])

    def test_host_raw_fallback_is_metric_specific_but_raw_pending_is_shared(self):
        cutoffs = {'raw_start_ts': 100, 'five_minute_start_ts': 0}
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    'INSERT INTO stats_history(ts, cpu, ram, disk, temp) VALUES(?,?,?,?,?)',
                    (60, 12.0, 22.0, 32.0, 42.0),
                )
                conn.commit()
                histories = {
                    metric: telemetry.compose_historical_response(
                        telemetry_repositories.get_host_telemetry(
                            conn, metric, 0, 100, 60, telemetry.POINT_BUDGET + 1, cutoffs,
                        ),
                        'host',
                    )
                    for metric in ('cpu', 'ram', 'disk', 'temp')
                }
                pending = telemetry_repositories.get_pending_aggregation(
                    conn, 'host', 'ram', 0, 100, 60, telemetry.POINT_BUDGET + 1, cutoffs,
                )
            finally:
                conn.close()

        self.assertEqual(
            [history['points'][0]['latest_value'] for history in histories.values()],
            [12.0, 22.0, 32.0, 42.0],
        )
        self.assertEqual(pending, ({
            'start_ts': 0,
            'end_ts': 300,
            'state': 'pending',
            'attempt_count': 0,
            'next_retry_ts': None,
            'error_class': None,
        },))

    def test_service_raw_fallback_preserves_offline_evidence_and_durable_failure(self):
        cutoffs = {'raw_start_ts': 100, 'five_minute_start_ts': 0}
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    'INSERT INTO service_checks(ts, port, online, latency_ms, error_class) VALUES(?,?,?,?,?)',
                    (60, 8080, 0, 12.5, 'timeout'),
                )
                conn.execute(
                    'INSERT INTO telemetry_streams('
                    'stream_kind, stream_key, started_ts, cadence_seconds, last_observed_ts, consecutive_misses) '
                    'VALUES(?,?,?,?,?,0)',
                    ('service', '8080', 0, 60, 60),
                )
                conn.commit()
                fallback = telemetry_repositories.get_service_telemetry(
                    conn, 8080, 0, 100, 60, telemetry.POINT_BUDGET + 1, cutoffs,
                )
                conn.execute(
                    'INSERT INTO telemetry_rollup_jobs('
                    'stream_kind, stream_key, bucket_start, bucket_seconds, state, attempt_count, '
                    'next_retry_ts, last_error_class, updated_ts) VALUES(?,?,?,?,?,?,?,?,?)',
                    ('service', '8080', 0, 300, 'failed', 3, 180, 'sqlite_busy', 120),
                )
                conn.commit()
                pending = telemetry_repositories.get_pending_aggregation(
                    conn, 'service', '8080', 0, 100, 60, telemetry.POINT_BUDGET + 1, cutoffs,
                )
            finally:
                conn.close()

        history = telemetry.compose_historical_response(fallback, 'service')
        self.assertEqual(history['source_resolutions_seconds'], [60])
        self.assertEqual(history['points'][0]['offline_seconds'], 40)
        self.assertEqual(history['points'][0]['latency_avg'], 12.5)
        self.assertEqual(history['points'][0]['check_count'], 1)
        self.assertEqual(history['points'][0]['failure_class_counts'], {'timeout': 1})
        self.assertEqual(pending, ({
            'start_ts': 0,
            'end_ts': 300,
            'state': 'failed',
            'attempt_count': 3,
            'next_retry_ts': 180,
            'error_class': 'sqlite_busy',
        },))

    def test_service_five_minute_fallback_yields_to_hourly_replacement(self):
        cutoffs = {'raw_start_ts': 1000, 'five_minute_start_ts': 500}
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    'INSERT INTO service_rollups('
                    'service_port, bucket_start, bucket_seconds, online_seconds, offline_seconds, '
                    'unknown_seconds, gap_seconds, latency_min, latency_max, latency_avg, '
                    'latency_sample_count, check_count, failure_class_counts_json) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (8080, 300, 300, 0, 300, 0, 0, 10.0, 10.0, 10.0, 1, 1, '{"timeout":1}'),
                )
                conn.commit()
                fallback = telemetry_repositories.get_service_telemetry(
                    conn, 8080, 0, 1000, 300, telemetry.POINT_BUDGET + 1, cutoffs,
                )
                conn.execute(
                    'INSERT INTO service_rollups('
                    'service_port, bucket_start, bucket_seconds, online_seconds, offline_seconds, '
                    'unknown_seconds, gap_seconds, latency_min, latency_max, latency_avg, '
                    'latency_sample_count, check_count, failure_class_counts_json) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (8080, 0, 3600, 3600, 0, 0, 0, 20.0, 20.0, 20.0, 1, 1, '{}'),
                )
                conn.commit()
                replacement = telemetry_repositories.get_service_telemetry(
                    conn, 8080, 0, 1000, 300, telemetry.POINT_BUDGET + 1, cutoffs,
                )
            finally:
                conn.close()

        self.assertEqual(
            telemetry.compose_historical_response(fallback, 'service')['source_resolutions_seconds'],
            [300],
        )
        replaced = telemetry.compose_historical_response(replacement, 'service')
        self.assertEqual(replaced['source_resolutions_seconds'], [3600])
        self.assertEqual(replaced['points'][0]['online_seconds'], 3600)


class ConfiguredTelemetryPolicyApiTests(unittest.TestCase):
    """The API and worker must consume the one deployed telemetry policy."""

    def setUp(self):
        self.appmod, self.db_path = load_app(extra_env={
            'TELEMETRY_RAW_DAYS': '8',
            'TELEMETRY_FIVE_MINUTE_DAYS': '31',
            'TELEMETRY_RETENTION_DAYS': '91',
            'TELEMETRY_POINT_BUDGET': '2',
        })
        self.client = self.appmod.app.test_client()
        self.now = int(time.time())

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_configured_policy_controls_worker_and_history_route(self):
        policy = telemetry.RetentionPolicy.from_settings(self.appmod.SETTINGS)
        self.assertEqual(policy.raw_days, 8)
        self.assertEqual(policy.five_minute_days, 31)
        self.assertEqual(policy.retention_days, 91)
        self.assertEqual(policy.point_budget, 2)
        self.assertEqual(self.appmod._telemetry_policy(), policy)

        raw_ts = self.now - (7 * 86400) - 180
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.executemany(
                    'INSERT INTO stats_history(ts, cpu, ram, disk, temp) VALUES(?,?,?,?,?)',
                    [
                        (raw_ts, 10.0, 20.0, 30.0, 40.0),
                        (raw_ts + 60, 11.0, 21.0, 31.0, 41.0),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

        with mock.patch.object(
            self.appmod.beacon_repositories,
            'get_host_telemetry',
            wraps=self.appmod.beacon_repositories.get_host_telemetry,
        ) as read_history:
            response = self.client.get('/api/telemetry/history', query_string={
                'kind': 'host',
                'metric': 'cpu',
                'start_ts': str(raw_ts - 60),
                'end_ts': str(raw_ts + 120),
            })

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['point_budget'], policy.point_budget)
        self.assertLessEqual(len(payload['points']), policy.point_budget)
        self.assertEqual(payload['source_resolutions_seconds'], [60])
        self.assertEqual(read_history.call_args.args[5], policy.point_budget + 1)

        lease = queues.acquire_worker_lease(self.db_path, 'policy-worker', now=self.now)
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: self.now)
        snapshot = telemetry.StorageSnapshot(
            database_bytes=0,
            wal_bytes=0,
            shm_bytes=0,
            free_bytes=policy.min_free_bytes + policy.backlog_reserve_bytes + 1,
        )
        with (
            mock.patch.object(self.appmod.beacon_telemetry, 'measure_storage', return_value=snapshot),
            mock.patch.object(self.appmod.beacon_telemetry, 'run_retention_batch') as cleanup,
        ):
            self.appmod.worker_cleanup_history(authority, now=self.now)
        self.assertEqual(cleanup.call_args.kwargs['policy'], policy)
