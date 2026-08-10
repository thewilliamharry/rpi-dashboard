import unittest

from dashboard.beacon import queues
from dashboard.beacon import telemetry
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
                (self.now - policy.retention_days * 86400, None, 'edge', None, None, None, None, 'none', '{}'),
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
                conn.execute('SELECT event_type FROM events ORDER BY ts').fetchall(),
                [('edge',)],
            )
        finally:
            conn.close()


if __name__ == '__main__':
    unittest.main()
