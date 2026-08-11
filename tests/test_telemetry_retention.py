import time
import types
import unittest
from unittest import mock

from dashboard.beacon import queues
from dashboard.beacon import telemetry
from dashboard.beacon.config import load_settings
from dashboard.beacon.telemetry import (
    CoverageInterval,
    POINT_BUDGET,
    coalesce_coverage,
    select_resolution,
)
from dashboard.beacon.worker_authority import WorkerAuthority
from tests.helpers import cleanup_db, load_app
from tests.test_migrations import snapshot_legacy_rows


UTC_NOW = 1_800_000_000
SEVEN_DAYS = 7 * 86400
THIRTY_DAYS = 30 * 86400
NINETY_DAYS = 90 * 86400
EXACT_CUTOFFS = {
    '7_days': UTC_NOW - SEVEN_DAYS,
    '30_days': UTC_NOW - THIRTY_DAYS,
    '90_days': UTC_NOW - NINETY_DAYS,
}


class UtcClock:
    """A small injected UTC clock for retention and worker-epoch tests."""

    def __init__(self, now=UTC_NOW):
        self.now = int(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += int(seconds)
        return self.now


def seed_host_rows(conn, rows):
    conn.executemany(
        'INSERT INTO stats_history(ts, cpu, ram, disk, temp) VALUES(?,?,?,?,?)',
        rows,
    )


def seed_service_checks(conn, rows):
    for ts, port, online, latency_ms, error_class in rows:
        conn.execute(
            'INSERT OR IGNORE INTO services(port, title, first_seen, last_seen, is_online) '
            'VALUES(?,?,?,?,?)',
            (port, f'Service {port}', ts, ts, int(bool(online))),
        )
        conn.execute(
            'INSERT INTO service_checks(ts, port, online, latency_ms, error_class) '
            'VALUES(?,?,?,?,?)',
            (ts, port, online, latency_ms, error_class),
        )


def seed_events(conn, rows):
    conn.executemany(
        'INSERT INTO events(ts, port, event_type, online, previous_online, latency_ms, '
        'error_class, alert_status, details) VALUES(?,?,?,?,?,?,?,?,?)',
        rows,
    )


def seed_coverage(*intervals):
    return tuple(CoverageInterval(*interval) for interval in intervals)


def seed_successive_worker_epochs(db_path, clock, *, lease_seconds=10):
    """Acquire Worker A and then deterministically replace it with Worker B."""
    first = queues.acquire_worker_lease(
        db_path, 'worker-a', now=clock(), lease_seconds=lease_seconds,
    )
    authority_a = WorkerAuthority.from_lease(first, db_path, clock=clock)
    clock.advance(lease_seconds + 1)
    second = queues.acquire_worker_lease(
        db_path, 'worker-b', now=clock(), lease_seconds=lease_seconds,
    )
    authority_b = WorkerAuthority.from_lease(second, db_path, clock=clock)
    return authority_a, authority_b


class TelemetryRetentionFixturesTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.clock = UtcClock()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_exact_cutoffs_and_seed_helpers_are_deterministic(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                seed_host_rows(conn, [
                    (EXACT_CUTOFFS['90_days'], 1.0, 2.0, 3.0, 4.0),
                    (EXACT_CUTOFFS['30_days'], 5.0, 6.0, 7.0, 8.0),
                    (EXACT_CUTOFFS['7_days'], 9.0, 10.0, 11.0, 12.0),
                ])
                seed_service_checks(conn, [
                    (EXACT_CUTOFFS['7_days'], 8080, 1, 4.5, None),
                ])
                seed_events(conn, [
                    (EXACT_CUTOFFS['30_days'], 8080, 'state_change', 1, 0, 4.5, None, 'none', '{}'),
                ])
                conn.commit()
                snapshot = snapshot_legacy_rows(conn)
            finally:
                conn.close()

        self.assertEqual(EXACT_CUTOFFS['7_days'], UTC_NOW - SEVEN_DAYS)
        self.assertEqual(EXACT_CUTOFFS['30_days'], UTC_NOW - THIRTY_DAYS)
        self.assertEqual(EXACT_CUTOFFS['90_days'], UTC_NOW - NINETY_DAYS)
        self.assertEqual(snapshot['stats_history'][0][0], EXACT_CUTOFFS['90_days'])
        self.assertEqual(snapshot['service_checks'], [(EXACT_CUTOFFS['7_days'], 8080, 1, 4.5, None)])
        self.assertEqual(snapshot['events'][0][1], EXACT_CUTOFFS['30_days'])

        authority_a, authority_b = seed_successive_worker_epochs(self.db_path, self.clock)
        self.assertEqual((authority_a.worker_id, authority_b.worker_id), ('worker-a', 'worker-b'))
        self.assertNotEqual(authority_a.owner_token, authority_b.owner_token)

    def test_half_open_bucket_arithmetic_selects_the_next_ladder_rung_only_when_needed(self):
        start_ts = UTC_NOW - (POINT_BUDGET * 60)
        self.assertEqual(select_resolution(start_ts, UTC_NOW), 60)
        self.assertEqual(select_resolution(start_ts - 1, UTC_NOW), 300)

    def test_coverage_coalescing_is_stable_at_equal_and_adjacent_boundaries(self):
        intervals = seed_coverage(
            (20, 30, 'unknown'),
            (0, 10, 'not_yet_monitored'),
            (10, 20, 'not_yet_monitored'),
            (30, 40, 'unknown'),
            (40, 50, 'expired'),
        )

        self.assertEqual(
            coalesce_coverage(intervals),
            (
                CoverageInterval(0, 20, 'not_yet_monitored'),
                CoverageInterval(20, 40, 'unknown'),
                CoverageInterval(40, 50, 'expired'),
            ),
        )


class RetentionRollupContractTests(unittest.TestCase):
    """Executable D-01 through D-04 and D-09 retention contract."""

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.now = UTC_NOW

    def tearDown(self):
        cleanup_db(self.db_path)

    def _connection(self):
        return self.appmod.get_db()

    def test_retention_engine_exports_canonical_bucket_and_batch_contract(self):
        required = (
            'RetentionPolicy',
            'bucket_start',
            'bucket_is_complete',
            'build_host_rollup',
            'build_service_rollup',
            'record_coverage_interval',
            'run_retention_batch',
        )
        self.assertTrue(all(hasattr(telemetry, name) for name in required))

        policy = telemetry.RetentionPolicy()
        cutoff = self.now - policy.raw_days * 86400
        self.assertEqual(telemetry.bucket_start(cutoff + 299, 300), cutoff)
        self.assertTrue(telemetry.bucket_is_complete(cutoff - 300, 300, cutoff))
        self.assertFalse(telemetry.bucket_is_complete(cutoff, 300, cutoff))

    def test_complete_host_bucket_is_verified_before_exact_source_deletion(self):
        policy = telemetry.RetentionPolicy(rollup_batch_buckets=4)
        cutoff = self.now - policy.raw_days * 86400
        start = telemetry.bucket_start(cutoff - 300, 300)
        conn = self._connection()
        try:
            seed_host_rows(conn, [
                (start, 1.0, None, None, None),
                (start + 100, 3.0, None, None, None),
                (start + 200, 2.0, None, None, None),
            ])
            conn.commit()
            result = telemetry.run_retention_batch(conn, now=self.now, policy=policy)
            row = conn.execute(
                'SELECT min_value, max_value, avg_value, latest_value, sample_count '
                'FROM host_metric_rollups WHERE metric=? AND bucket_start=? AND bucket_seconds=300',
                ('cpu', start),
            ).fetchone()
            self.assertEqual(tuple(row), (1.0, 3.0, 2.0, 2.0, 3))
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM stats_history').fetchone()[0], 0)
            self.assertEqual(result['rolled_buckets'], 1)
        finally:
            conn.close()


class StoragePressureContractTests(unittest.TestCase):
    """Executable D-10 through D-12 settings and no-flap state contract."""

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.now = UTC_NOW

    def tearDown(self):
        cleanup_db(self.db_path)

    def _connection(self):
        return self.appmod.get_db()


    def test_settings_and_pressure_policy_exports_have_safe_defaults(self):
        self.assertTrue(hasattr(telemetry, 'evaluate_storage_pressure'))
        self.assertTrue(hasattr(telemetry, 'historical_persistence_allowed'))

        settings = load_settings({
            'TELEMETRY_RAW_DAYS': '8',
            'TELEMETRY_FIVE_MINUTE_DAYS': '31',
            'TELEMETRY_RETENTION_DAYS': '91',
            'TELEMETRY_POINT_BUDGET': '1024',
            'TELEMETRY_DB_MAX_BYTES': '1000',
            'TELEMETRY_MIN_FREE_BYTES': '2000',
            'TELEMETRY_PRESSURE_WARNING_PERCENT': '81',
            'TELEMETRY_PRESSURE_HARD_PERCENT': '91',
            'TELEMETRY_PRESSURE_RECOVERY_PERCENT': '76',
            'TELEMETRY_BACKLOG_RESERVE_BYTES': '100',
            'TELEMETRY_ROLLUP_BATCH_BUCKETS': '16',
            'TELEMETRY_RETRY_BASE_SECONDS': '301',
            'TELEMETRY_RETRY_MAX_SECONDS': '3601',
        })
        self.assertEqual(
            (settings.telemetry_raw_days, settings.telemetry_five_minute_days,
             settings.telemetry_retention_days, settings.telemetry_point_budget,
             settings.telemetry_db_max_bytes, settings.telemetry_min_free_bytes,
             settings.telemetry_pressure_warning_percent, settings.telemetry_pressure_hard_percent,
             settings.telemetry_pressure_recovery_percent, settings.telemetry_backlog_reserve_bytes,
             settings.telemetry_rollup_batch_buckets, settings.telemetry_retry_base_seconds,
             settings.telemetry_retry_max_seconds),
            (8, 31, 91, 1024, 1000, 2000, 81, 91, 76, 100, 16, 301, 3601),
        )
        invalid = load_settings({'TELEMETRY_RAW_DAYS': '30'})
        self.assertEqual(
            (invalid.telemetry_raw_days, invalid.telemetry_five_minute_days, invalid.telemetry_retention_days),
            (7, 30, 90),
        )
        malformed = load_settings({
            'TELEMETRY_DB_MAX_BYTES': 'zero',
            'TELEMETRY_PRESSURE_WARNING_PERCENT': '90',
            'TELEMETRY_PRESSURE_HARD_PERCENT': '80',
            'TELEMETRY_RETRY_BASE_SECONDS': '3601',
            'TELEMETRY_RETRY_MAX_SECONDS': '300',
        })
        self.assertEqual(malformed.telemetry_db_max_bytes, 536_870_912)
        self.assertEqual(
            (malformed.telemetry_pressure_recovery_percent,
             malformed.telemetry_pressure_warning_percent,
             malformed.telemetry_pressure_hard_percent),
            (75, 80, 90),
        )
        self.assertEqual(
            (malformed.telemetry_retry_base_seconds, malformed.telemetry_retry_max_seconds),
            (300, 3_600),
        )

    def test_storage_pressure_counts_database_wal_shm_and_requires_two_condition_recovery(self):
        policy = telemetry.RetentionPolicy(db_max_bytes=1_000, min_free_bytes=2_000, backlog_reserve_bytes=100)
        warning = telemetry.StorageSnapshot(700, 50, 50, 3_000)
        decision = telemetry.evaluate_storage_pressure('normal', warning, policy)
        self.assertEqual((decision.previous_state, decision.state, decision.reason), ('normal', 'pressure', 'allocation_warning'))
        self.assertTrue(telemetry.historical_persistence_allowed(decision))

        hard = telemetry.evaluate_storage_pressure(
            'normal', telemetry.StorageSnapshot(850, 50, 0, 3_000), policy,
        )
        self.assertEqual((hard.state, hard.reason), ('pressure', 'allocation_hard'))
        free_reserve = telemetry.evaluate_storage_pressure(
            'normal', telemetry.StorageSnapshot(0, 0, 0, 2_100), policy,
        )
        self.assertEqual((free_reserve.state, free_reserve.reason), ('pressure', 'free_space_reserve'))

        suspended = telemetry.evaluate_storage_pressure(
            decision.state, telemetry.StorageSnapshot(900, 100, 100, 3_000), policy,
        )
        self.assertEqual(suspended.state, 'suspended')
        self.assertFalse(telemetry.historical_persistence_allowed(suspended))
        self.assertTrue(telemetry.historical_persistence_allowed('pressure'))

        no_flap = telemetry.evaluate_storage_pressure(
            'suspended', telemetry.StorageSnapshot(700, 0, 0, 2_099), policy,
        )
        self.assertEqual(no_flap.state, 'suspended')
        recovered = telemetry.evaluate_storage_pressure(
            'suspended', telemetry.StorageSnapshot(700, 0, 0, 2_100), policy,
        )
        self.assertEqual(recovered.state, 'normal')

    def test_cutoff_ownership_keeps_partial_raw_and_exact_hourly_boundaries(self):
        policy = telemetry.RetentionPolicy(rollup_batch_buckets=4)
        raw_cutoff = self.now - policy.raw_days * 86400
        hourly_cutoff = self.now - policy.retention_days * 86400
        complete_start = telemetry.bucket_start(raw_cutoff - 1, 300)
        partial_start = telemetry.bucket_start(raw_cutoff, 300)
        conn = self._connection()
        try:
            seed_host_rows(conn, [
                (complete_start, 1.0, None, None, None),
                (partial_start, 2.0, None, None, None),
                (partial_start + 1, None, None, None, None),
            ])
            conn.execute(
                'INSERT INTO host_metric_rollups VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                ('cpu', hourly_cutoff - 3600, 3600, 1.0, 1.0, 1.0, 1.0, 1, 3600, 0, 0),
            )
            conn.execute(
                'INSERT INTO host_metric_rollups VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                ('cpu', hourly_cutoff, 3600, 2.0, 2.0, 2.0, 2.0, 1, 3600, 0, 0),
            )
            conn.commit()
            telemetry.run_retention_batch(conn, now=self.now, policy=policy)
            self.assertEqual(
                [row['ts'] for row in conn.execute('SELECT ts FROM stats_history ORDER BY ts')],
                [partial_start, partial_start + 1],
            )
            self.assertEqual(
                [row['bucket_start'] for row in conn.execute(
                    'SELECT bucket_start FROM host_metric_rollups WHERE bucket_seconds=3600 ORDER BY bucket_start'
                )],
                [hourly_cutoff],
            )
        finally:
            conn.close()

    def test_empty_host_bucket_neither_rolls_nor_deletes_its_source(self):
        policy = telemetry.RetentionPolicy()
        cutoff = self.now - policy.raw_days * 86400
        start = telemetry.bucket_start(cutoff - 300, 300)
        conn = self._connection()
        try:
            seed_host_rows(conn, [(start, None, None, None, None)])
            conn.commit()
            result = telemetry.run_retention_batch(conn, now=self.now, policy=policy)
            self.assertEqual(result['rolled_buckets'], 0)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM stats_history').fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM host_metric_rollups').fetchone()[0], 0)
        finally:
            conn.close()

    def test_service_rollup_is_time_weighted_and_failure_counts_are_stable(self):
        policy = telemetry.RetentionPolicy(rollup_batch_buckets=4)
        cutoff = self.now - policy.raw_days * 86400
        start = telemetry.bucket_start(cutoff - 300, 300)
        conn = self._connection()
        try:
            seed_service_checks(conn, [
                (start, 8080, 1, 10.0, 'zeta'),
                (start + 100, 8080, 0, 30.0, 'alpha'),
                (start + 200, 8080, None, None, 'alpha'),
            ])
            conn.commit()
            telemetry.run_retention_batch(conn, now=self.now, policy=policy)
            row = conn.execute(
                'SELECT online_seconds, offline_seconds, unknown_seconds, gap_seconds, '
                'latency_min, latency_max, latency_avg, check_count, failure_class_counts_json '
                'FROM service_rollups WHERE service_port=8080 AND bucket_start=? AND bucket_seconds=300',
                (start,),
            ).fetchone()
            self.assertEqual(tuple(row), (100, 100, 100, 0, 10.0, 30.0, 20.0, 3, '{"alpha":2,"zeta":1}'))
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM service_checks').fetchone()[0], 0)
        finally:
            conn.close()

    def test_failed_rollup_preserves_sources_retries_once_and_events_expire_strictly(self):
        policy = telemetry.RetentionPolicy(rollup_batch_buckets=4)
        cutoff = self.now - policy.raw_days * 86400
        start = telemetry.bucket_start(cutoff - 300, 300)
        conn = self._connection()
        try:
            seed_host_rows(conn, [(start, 1.0, None, None, None)])
            seed_events(conn, [
                (self.now - policy.retention_days * 86400 - 1, None, 'old', None, None, None, None, 'none', '{}'),
                (self.now + 300 - policy.retention_days * 86400, None, 'edge', None, None, None, None, 'none', '{}'),
            ])
            conn.commit()
            with self.assertRaises(RuntimeError):
                telemetry.run_retention_batch(
                    conn, now=self.now, policy=policy, before_verify=lambda *_: (_ for _ in ()).throw(RuntimeError('injected')),
                    raise_on_failure=True,
                )
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM stats_history').fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM host_metric_rollups').fetchone()[0], 0)
            job = conn.execute(
                "SELECT state, attempt_count, next_retry_ts, last_error_class FROM telemetry_rollup_jobs"
            ).fetchone()
            self.assertEqual(tuple(job), ('failed', 1, self.now + 300, 'RuntimeError'))
            telemetry.run_retention_batch(conn, now=self.now + 300, policy=policy)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM host_metric_rollups').fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM telemetry_rollup_jobs').fetchone()[0], 1)
            self.assertEqual(
                [tuple(row) for row in conn.execute('SELECT event_type FROM events ORDER BY ts').fetchall()],
                [('edge',)],
            )
        finally:
            conn.close()


class WorkerTelemetryObservationContractTests(unittest.TestCase):
    """Executable D-06 and D-11 evidence through real telemetry tables."""

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.clock = UtcClock()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_observation_contract_closes_confirmed_gap_and_preserves_tri_state(self):
        required = (
            'record_observation',
            'detect_collection_gaps',
            'read_retention_state',
            'write_retention_state',
            'close_storage_pressure_gap',
        )
        self.assertTrue(all(hasattr(telemetry, name) for name in required))
        conn = self.appmod.get_db()
        try:
            telemetry.record_observation(
                conn, 'service', '8080', ts=0, cadence_seconds=300,
                state=True, expected_cadence=True,
            )
            telemetry.detect_collection_gaps(conn, now=600)
            telemetry.record_observation(
                conn, 'service', '8080', ts=750, cadence_seconds=300,
                state=False, expected_cadence=True,
            )
            telemetry.record_observation(
                conn, 'service', '8081', ts=750, cadence_seconds=300,
                state=None, expected_cadence=True,
            )
            coverage = conn.execute(
                'SELECT stream_key, start_ts, end_ts, reason, detail FROM telemetry_coverage '
                'ORDER BY stream_key, start_ts'
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in coverage],
                [('8080', 300, 750, 'collection_gap', None),
                 ('8081', 750, 1050, 'unknown', None)],
            )
            stream = conn.execute(
                "SELECT last_observed_ts, consecutive_misses, open_gap_start_ts "
                "FROM telemetry_streams WHERE stream_kind='service' AND stream_key='8080'"
            ).fetchone()
            self.assertEqual(tuple(stream), (750, 0, None))
        finally:
            conn.close()

    def test_worker_cleanup_retention_is_epoch_fenced_and_keeps_events_for_ninety_days(self):
        authority_a, authority_b = seed_successive_worker_epochs(self.db_path, self.clock)
        conn = self.appmod.get_db()
        try:
            seed_events(conn, [
                (self.clock() - 30 * 86400, None, 'still_retained', None, None, None, None, 'none', '{}'),
            ])
            conn.commit()
        finally:
            conn.close()

    def test_real_worker_samples_use_metric_streams_and_close_pressure_gaps(self):
        """The worker's four host values must be readable through their API streams."""
        self.clock = UtcClock(int(time.time()) - 600)
        authority_a, authority_b = seed_successive_worker_epochs(
            self.db_path, self.clock, lease_seconds=3_000,
        )
        policy = self.appmod._telemetry_policy()
        normal = telemetry.StorageSnapshot(
            database_bytes=0,
            wal_bytes=0,
            shm_bytes=0,
            free_bytes=policy.min_free_bytes + policy.backlog_reserve_bytes + 1,
        )
        suspended = telemetry.StorageSnapshot(
            database_bytes=policy.db_max_bytes + policy.backlog_reserve_bytes,
            wal_bytes=0,
            shm_bytes=0,
            free_bytes=policy.min_free_bytes + policy.backlog_reserve_bytes + 1,
        )
        memory = types.SimpleNamespace(
            available=700,
            total=1_000,
            used=300,
        )
        disk = types.SimpleNamespace(percent=40.0, used=400, total=1_000)
        with (
            mock.patch.object(self.appmod.psutil, 'cpu_percent', return_value=12.5),
            mock.patch.object(self.appmod.psutil, 'virtual_memory', return_value=memory),
            mock.patch.object(self.appmod.psutil, 'disk_usage', return_value=disk),
            mock.patch.object(self.appmod, 'get_temp', return_value=55.0),
            mock.patch.object(self.appmod.beacon_telemetry, 'measure_storage', return_value=normal),
        ):
            first_ts = self.clock()
            self.appmod.worker_collect_system_stats(authority_b, now=first_ts, persist_history=True)
            self.clock.advance(self.appmod.METRIC_HISTORY_SECONDS)
            suspend_ts = self.clock()
            with mock.patch.object(
                self.appmod.beacon_telemetry, 'measure_storage', return_value=suspended,
            ):
                self.appmod.worker_collect_system_stats(
                    authority_b, now=suspend_ts, persist_history=True,
                )
            self.clock.advance(self.appmod.METRIC_HISTORY_SECONDS)
            recovered_ts = self.clock()
            self.appmod.worker_collect_system_stats(authority_b, now=recovered_ts, persist_history=True)

            with self.assertRaises(queues.LeaseLost):
                self.appmod.worker_collect_system_stats(
                    authority_a, now=recovered_ts + self.appmod.METRIC_HISTORY_SECONDS,
                    persist_history=True,
                )

        conn = self.appmod.get_db()
        try:
            streams = [tuple(row) for row in conn.execute(
                "SELECT stream_kind, stream_key FROM telemetry_streams "
                "WHERE stream_kind='host' ORDER BY stream_key"
            )]
            gaps = [tuple(row) for row in conn.execute(
                "SELECT stream_key, start_ts, end_ts, reason, detail FROM telemetry_coverage "
                "WHERE stream_kind='host' ORDER BY stream_key"
            )]
        finally:
            conn.close()

        self.assertEqual(
            streams,
            [('host', metric) for metric in telemetry.HOST_METRICS],
        )
        self.assertEqual(
            gaps,
            [
                (metric, suspend_ts, recovered_ts, 'collection_gap', 'storage_pressure')
                for metric in telemetry.HOST_METRICS
            ],
        )

        client = self.appmod.app.test_client()
        for metric in telemetry.HOST_METRICS:
            with self.subTest(metric=metric):
                response = client.get('/api/telemetry/history', query_string={
                    'kind': 'host',
                    'metric': metric,
                    'start_ts': str(first_ts),
                    'end_ts': str(recovered_ts + self.appmod.METRIC_HISTORY_SECONDS),
                })
                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertTrue(payload['points'])
                self.assertIn(
                    {
                        'start_ts': suspend_ts,
                        'end_ts': recovered_ts,
                        'state': 'collection_gap',
                        'detail': 'storage_pressure',
                    },
                    payload['coverage'],
                )

        with self.assertRaises(queues.LeaseLost):
            self.appmod.worker_cleanup_history(authority_a, now=self.clock())
        self.appmod.worker_cleanup_history(authority_b, now=self.clock())

        conn = self.appmod.get_db()
        try:
            self.assertEqual(
                [row['event_type'] for row in conn.execute('SELECT event_type FROM events')],
                ['still_retained'],
            )
            state = self.appmod._get_runtime_state('telemetry_retention_state', {}, conn=conn)
            self.assertEqual(state.get('state'), 'normal')
        finally:
            conn.close()


if __name__ == '__main__':
    unittest.main()
