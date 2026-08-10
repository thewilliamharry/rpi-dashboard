import time
import unittest

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
            {'start_ts': start_ts, 'end_ts': end_ts, 'state': 'unknown'},
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
            {'start_ts': start_ts, 'end_ts': end_ts, 'state': 'unknown'},
        ])

    def test_invalid_selectors_and_bounds_are_rejected_before_history_read(self):
        cases = [
            {'kind': 'service', 'metric': 'cpu', 'start_ts': str(self.now - 120), 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'load', 'start_ts': str(self.now - 120), 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': 'true', 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': '1.5', 'end_ts': str(self.now - 60)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': str(self.now - 60), 'end_ts': str(self.now - 120)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': str(self.now - 90 * 86400 - 1), 'end_ts': str(self.now - 1)},
            {'kind': 'host', 'metric': 'cpu', 'start_ts': str(self.now - 60), 'end_ts': str(self.now + 1)},
        ]
        for query in cases:
            with self.subTest(query=query):
                response = self.client.get('/api/telemetry/history', query_string=query)
                self.assertEqual(response.status_code, 400)

