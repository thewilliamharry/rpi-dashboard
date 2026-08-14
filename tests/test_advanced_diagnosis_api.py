import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from dashboard.beacon import migrations, queues, repositories, worker_main
from dashboard.beacon.worker_authority import WorkerAuthority
from tests.helpers import cleanup_db, load_app


class AdvancedDiagnosisApiTests(unittest.TestCase):
    """Tracer coverage for the bounded current-host advanced diagnosis API."""

    def setUp(self):
        self.appmod, self.db_path = load_app({'METRIC_SAMPLE_SECONDS': '5'})
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _seed_host(self, sample_ts=1_700_000_000):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO system_stats('
                'id,sample_ts,cpu,ram,ram_used,ram_available,ram_used_strict,ram_total,'
                'disk,disk_used,disk_total,temp,hostname'
                ') VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)',
                (
                    sample_ts, 21.5, 42.0, 420, 580, 420, 1000,
                    63.0, 630, 1000, 51.25, 'beacon-pi',
                ),
            )
            conn.commit()
            conn.close()

    def test_host_tracer_returns_one_current_snapshot_with_server_freshness(self):
        self._seed_host(sample_ts=1_700_000_000)
        self.appmod.time.time = lambda: 1_700_000_005

        response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        payload = response.get_json()
        self.assertEqual(payload['schema_version'], 1)
        self.assertEqual(payload['generated_ts'], 1_700_000_005)
        self.assertEqual(payload['host']['identity']['hostname'], 'beacon-pi')
        self.assertEqual(payload['host']['metrics']['cpu'], {'value': 21.5, 'unit': 'percent'})
        self.assertEqual(payload['host']['metrics']['memory']['used_bytes'], 420)
        self.assertEqual(payload['host']['metrics']['disk']['total_bytes'], 1000)
        self.assertEqual(payload['host']['metrics']['temperature'], {'value': 51.25, 'unit': 'celsius'})
        self.assertEqual(payload['host']['sample_ts'], 1_700_000_000)
        self.assertEqual(payload['host']['expected_cadence_seconds'], 5)
        self.assertEqual(
            payload['host']['freshness'],
            {'state': 'fresh', 'age_seconds': 5},
        )

    def test_host_tracer_returns_truthful_unknown_host_evidence(self):
        self.appmod.time.time = lambda: 1_700_000_005

        response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 200)
        host = response.get_json()['host']
        self.assertIsNone(host['identity']['hostname'])
        self.assertIsNone(host['metrics']['cpu']['value'])
        self.assertIsNone(host['metrics']['temperature']['value'])
        self.assertIsNone(host['sample_ts'])
        self.assertEqual(host['freshness'], {'state': 'unknown', 'age_seconds': None})

    def test_host_freshness_boundaries_and_invalid_evidence(self):
        freshness_state = self.appmod.beacon_diagnosis.freshness_state
        now = 1_700_000_100
        cases = [
            (now - 5, 5, {'state': 'fresh', 'age_seconds': 5}),
            (now - 6, 5, {'state': 'aging', 'age_seconds': 6}),
            (now - 20, 5, {'state': 'aging', 'age_seconds': 20}),
            (now - 21, 5, {'state': 'stale', 'age_seconds': 21}),
            (now + 10, 5, {'state': 'fresh', 'age_seconds': 0}),
            (None, 5, {'state': 'unknown', 'age_seconds': None}),
            (now - 1, 0, {'state': 'unknown', 'age_seconds': None}),
            (now - 1, 'five', {'state': 'unknown', 'age_seconds': None}),
        ]
        for sample_ts, cadence, expected in cases:
            with self.subTest(sample_ts=sample_ts, cadence=cadence):
                self.assertEqual(freshness_state(now, sample_ts, cadence), expected)

    def test_worker_safety_uses_the_immutable_heartbeat_cadence(self):
        """J1 remains a five-second heartbeat even when host metrics are slower."""
        appmod, db_path = load_app({'METRIC_SAMPLE_SECONDS': '37'})
        client = appmod.app.test_client()
        now = 1_700_000_100
        try:
            with appmod._db_lock:
                conn = appmod.get_db()
                conn.execute(
                    'INSERT INTO runtime_state(key,value,updated_ts) VALUES(?,?,?) '
                    'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts',
                    ('worker_heartbeat', json.dumps({'ts': now}), now),
                )
                conn.commit()
                conn.close()
            for age, expected_state, expected_warning in (
                (5, 'fresh', False),
                (20, 'aging', False),
                (21, 'stale', True),
            ):
                with self.subTest(age=age):
                    appmod.time.time = lambda: now + age
                    payload = client.get('/api/advanced/current').get_json()
                    worker = payload['pipeline']['worker']
                    self.assertEqual(worker['expected_cadence_seconds'], 5)
                    self.assertEqual(worker['freshness'], {'state': expected_state, 'age_seconds': age})
                    self.assertEqual(payload['safety']['worker_stale'], expected_warning)
        finally:
            cleanup_db(db_path)

    def test_direct_route_tracer_preserves_middleware_assets_and_get_only_api(self):
        asset_directory = Path(self.appmod.__file__).resolve().parent
        for path, mimetype, filename in [
            ('/advanced', 'text/html', 'advanced.html'),
            ('/advanced.js', 'application/javascript', 'advanced.js'),
            ('/advanced.css', 'text/css', 'advanced.css'),
        ]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(mimetype, response.content_type)
                self.assertEqual(response.data, (asset_directory / filename).read_bytes())
                self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
                self.assertIn("default-src 'self'", response.headers['Content-Security-Policy'])

        self.assertEqual(
            self.client.get('/advanced', headers={'Host': 'evil.example'}).status_code,
            400,
        )
        for method in ('post', 'put', 'patch', 'delete'):
            with self.subTest(method=method):
                self.assertIn(
                    getattr(self.client, method)('/api/advanced/current').status_code,
                    (403, 405),
                )

    def test_migration_eight_adds_only_job_health_evidence(self):
        """The approved Migration 8 remains additive over the supported schema."""
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            tables = {
                row['name'] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            columns = {
                row['name'] for row in conn.execute(
                    'PRAGMA table_info(background_job_health)'
                )
            }
            versions = [
                row['version'] for row in conn.execute(
                    'SELECT version FROM schema_migrations ORDER BY version'
                )
            ]
            conn.close()

        self.assertIn('background_job_health', tables)
        self.assertEqual(
            columns,
            {
                'job_id', 'last_started_ts', 'last_finished_ts',
                'last_success_ts', 'state', 'error_class', 'updated_ts',
            },
        )
        self.assertEqual(migrations.MIGRATIONS[-1].version, 8)
        self.assertIn(8, versions)

    def test_job_health_transitions_preserve_success_and_bound_failure_class(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            repositories.record_background_job_started(conn, 'J2', now=100)
            repositories.record_background_job_succeeded(conn, 'J2', now=101)
            repositories.record_background_job_failed(
                conn, 'J2', now=102, error_class='SecretError: do not persist this message',
            )
            row = conn.execute(
                'SELECT * FROM background_job_health WHERE job_id=?', ('J2',)
            ).fetchone()
            conn.commit()
            conn.close()

        self.assertEqual(row['state'], 'failed')
        self.assertEqual(row['last_started_ts'], 100)
        self.assertEqual(row['last_finished_ts'], 102)
        self.assertEqual(row['last_success_ts'], 101)
        self.assertEqual(row['error_class'], 'SecretError')

    def test_callback_outcome_false_and_exception_never_claim_success(self):
        now = 100
        lease = queues.acquire_worker_lease(
            self.db_path, 'job-health-worker', now=now, lease_seconds=30,
        )
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: now)

        def services_for(result):
            return SimpleNamespace(
                settings=SimpleNamespace(db_path=self.db_path),
                authority=authority,
                clock=lambda: now,
                admission=worker_main.WorkerAdmission(),
                collect_system_stats=lambda _authority: (
                    (_ for _ in ()).throw(result)
                    if isinstance(result, BaseException) else result
                ),
            )

        self.assertFalse(worker_main.dispatch_callback(services_for(False), 'J2'))
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            false_row = conn.execute(
                'SELECT state,last_success_ts,error_class FROM background_job_health WHERE job_id=?',
                ('J2',),
            ).fetchone()
            conn.close()
        self.assertEqual(tuple(false_row), ('failed', None, 'CallbackReturnedFalse'))

        class DeliberateFailure(RuntimeError):
            pass

        with self.assertRaises(DeliberateFailure):
            worker_main.dispatch_callback(services_for(DeliberateFailure('secret message')), 'J2')
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            exception_row = conn.execute(
                'SELECT state,last_success_ts,error_class FROM background_job_health WHERE job_id=?',
                ('J2',),
            ).fetchone()
            conn.close()
        self.assertEqual(tuple(exception_row), ('failed', None, 'DeliberateFailure'))

    def test_stale_worker_cannot_change_job_health_evidence(self):
        now = 100
        lease_a = queues.acquire_worker_lease(
            self.db_path, 'job-health-worker-a', now=now, lease_seconds=1,
        )
        authority_a = WorkerAuthority.from_lease(lease_a, self.db_path, clock=lambda: now)
        with self.assertRaises(queues.LeaseLost):
            worker_main._write_job_health_transition(
                SimpleNamespace(
                    settings=SimpleNamespace(db_path=self.db_path),
                    authority=authority_a,
                    clock=lambda: now + 2,
                ),
                'J2', 'started',
            )

        lease_b = queues.acquire_worker_lease(
            self.db_path, 'job-health-worker-b', now=now + 2, lease_seconds=30,
        )
        authority_b = WorkerAuthority.from_lease(lease_b, self.db_path, clock=lambda: now + 2)
        worker_main._write_job_health_transition(
            SimpleNamespace(
                settings=SimpleNamespace(db_path=self.db_path),
                authority=authority_b,
                clock=lambda: now + 2,
            ),
            'J2', 'succeeded',
        )
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                'SELECT state,last_success_ts FROM background_job_health WHERE job_id=?', ('J2',),
            ).fetchone()
            conn.close()
        self.assertEqual(tuple(row), ('succeeded', now + 2))

    def test_services_pipeline_and_settings_are_present_in_one_current_snapshot(self):
        now = 1_700_000_000
        self._seed_host(sample_ts=now)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,last_error,state_since) '
                'VALUES(?,?,?,?,?,?,?,?)',
                (8080, 'Service', now - 20, now, 0, None, 'ConnectionRefused', now - 10),
            )
            conn.execute(
                'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,healthy_statuses) '
                'VALUES(?,?,?,?,?,?,?)',
                (8080, 'Beacon service', 'http://127.0.0.1:8080', 1, 3, 'core,lan', '200-399'),
            )
            conn.execute(
                'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) VALUES(?,?,?,?,?)',
                (now, 8080, 0, None, 'ConnectionRefused'),
            )
            conn.commit()
            conn.close()
        self.appmod.time.time = lambda: now

        payload = self.client.get('/api/advanced/current').get_json()

        self.assertEqual(payload['services'][0]['port'], 8080)
        self.assertEqual(payload['services'][0]['name'], 'Beacon service')
        self.assertEqual(payload['services'][0]['availability'], 'offline')
        self.assertTrue(payload['services'][0]['critical'])
        self.assertEqual(payload['services'][0]['freshness']['state'], 'fresh')
        self.assertIn('retention', payload['pipeline'])
        self.assertIn('worker', payload['pipeline'])
        self.assertIn('jobs', payload['pipeline'])
        self.assertNotIn('alert_webhook_url', payload['settings'])
        self.assertTrue(any(item['kind'] == 'critical_service_offline' for item in payload['exceptions']))

    def test_service_cadence_uses_down_recheck_only_for_definitive_offline_state(self):
        now = 1_700_000_000
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for port, online in ((8100, None), (8101, 1), (8102, 0)):
                conn.execute(
                    'INSERT INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,last_error,state_since) '
                    'VALUES(?,?,?,?,?,?,?,?)',
                    (port, f'Service {port}', now - 20, now, online, None, None, now - 10),
                )
                conn.execute(
                    'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,healthy_statuses) '
                    'VALUES(?,?,?,?,?,?,?)',
                    (port, f'Service {port}', f'http://127.0.0.1:{port}', 0, port, '', '200-399'),
                )
                if online is not None:
                    conn.execute(
                        'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) VALUES(?,?,?,?,?)',
                        (now, port, online, None, None),
                    )
            conn.commit()
            conn.close()
        self.appmod.time.time = lambda: now

        services = {service['port']: service for service in self.client.get('/api/advanced/current').get_json()['services']}

        self.assertEqual(services[8100]['availability'], 'unknown')
        self.assertEqual(services[8100]['expected_cadence_seconds'], 300)
        self.assertEqual(services[8100]['freshness'], {'state': 'unknown', 'age_seconds': None})
        self.assertEqual(services[8101]['expected_cadence_seconds'], 300)
        self.assertEqual(services[8102]['expected_cadence_seconds'], 60)

    def test_pinned_order_corruption_is_safe_and_get_only(self):
        now = 1_700_000_000
        fixtures = (
            (8200, 0, 0),
            (8201, 65535, 65535),
            (8202, None, 8202),
            (8203, 65536, 8203),
            (8204, 'not-an-order', 8204),
        )
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for port, pinned_order, _expected in fixtures:
                conn.execute(
                    'INSERT INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,last_error,state_since) '
                    'VALUES(?,?,?,?,?,?,?,?)',
                    (port, f'Service {port}', now - 20, now, 1, 1.0, None, now - 10),
                )
                conn.execute(
                    'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,healthy_statuses) '
                    'VALUES(?,?,?,?,?,?,?)',
                    (port, f'Service {port}', f'http://127.0.0.1:{port}', 0, pinned_order, '', '200-399'),
                )
                conn.execute(
                    'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) VALUES(?,?,?,?,?)',
                    (now, port, 1, 1.0, None),
                )
            before = [tuple(row) for row in conn.execute(
                'SELECT port,pinned_order,typeof(pinned_order) FROM service_meta ORDER BY port'
            )]
            conn.commit()
            conn.close()
        self.appmod.time.time = lambda: now

        response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 200)
        services = {service['port']: service for service in response.get_json()['services']}
        self.assertEqual(
            {port: services[port]['pinned_order'] for port, _value, _expected in fixtures},
            {port: expected for port, _value, expected in fixtures},
        )
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            after = [tuple(row) for row in conn.execute(
                'SELECT port,pinned_order,typeof(pinned_order) FROM service_meta ORDER BY port'
            )]
            conn.close()
        self.assertEqual(after, before)
        safe_pinned_order = self.appmod.beacon_diagnosis._safe_pinned_order
        for value in (True, False, -1, 65536, '12', 'bad'):
            with self.subTest(value=value):
                self.assertEqual(safe_pinned_order(value, 8205), 8205)

    def test_gap_truncation_uses_one_sentinel_beyond_the_response_cap(self):
        now = 1_700_000_000
        self.appmod.time.time = lambda: now
        for count in (0, 1, 48, 49):
            with self.subTest(count=count):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM telemetry_coverage')
                    conn.executemany(
                        'INSERT INTO telemetry_coverage(stream_kind,stream_key,start_ts,end_ts,reason,detail) '
                        'VALUES(?,?,?,?,?,?)',
                        [
                            ('host', 'cpu', now - 1_000 - index, now - index, 'collection_gap', f'gap-{index}')
                            for index in range(count)
                        ],
                    )
                    conn.commit()
                    conn.close()

                gaps = self.client.get('/api/advanced/current').get_json()['pipeline']['gaps']

                self.assertEqual(len(gaps['items']), min(count, 48))
                self.assertEqual(gaps['count'], min(count, 48))
                self.assertEqual(gaps['truncated'], count > 48)
                self.assertEqual(
                    [item['detail'] for item in gaps['items']],
                    [f'gap-{index}' for index in range(min(count, 48))],
                )

    def test_advanced_snapshot_rejects_query_arguments_before_reading_sqlite(self):
        response = self.client.get('/api/advanced/current?unexpected=1')

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {'error': 'unexpected query parameters'})


if __name__ == '__main__':
    unittest.main()
