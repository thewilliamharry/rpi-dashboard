import unittest

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

    def test_direct_route_tracer_preserves_middleware_assets_and_get_only_api(self):
        for path, mimetype in [
            ('/advanced', 'text/html'),
            ('/advanced.js', 'application/javascript'),
            ('/advanced.css', 'text/css'),
        ]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(mimetype, response.content_type)
                self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
                self.assertIn("default-src 'self'", response.headers['Content-Security-Policy'])

        self.assertEqual(
            self.client.get('/advanced', headers={'Host': 'evil.example'}).status_code,
            400,
        )
        for method in ('post', 'put', 'patch', 'delete'):
            with self.subTest(method=method):
                self.assertEqual(getattr(self.client, method)('/api/advanced/current').status_code, 405)


if __name__ == '__main__':
    unittest.main()
