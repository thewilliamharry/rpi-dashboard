import time
import unittest

from tests.helpers import cleanup_db, load_app


class ApiAndAuthTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app({
            'TRIGGER_SCAN_TOKEN': 'secret-token',
            'TRIGGER_SCAN_RATE_LIMIT': '1',
            'TRIGGER_SCAN_WINDOW_SECONDS': '60',
        })
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_trigger_scan_requires_token(self):
        r = self.client.post('/api/trigger-scan')
        self.assertEqual(r.status_code, 401)

    def test_trigger_scan_rate_limit(self):
        self.appmod.trigger_discovery = lambda: True

        r1 = self.client.post('/api/trigger-scan', headers={'X-Scan-Token': 'secret-token'})
        self.assertEqual(r1.status_code, 200)
        self.assertTrue(r1.get_json()['started'])

        r2 = self.client.post('/api/trigger-scan', headers={'X-Scan-Token': 'secret-token'})
        self.assertEqual(r2.status_code, 429)
        self.assertEqual(r2.get_json()['reason'], 'rate_limited')

    def test_services_and_events_contract_fields(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (8080, 'Demo Service', now - 120, now, 1, 45.2, None),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (8080, 'Friendly Demo', 'http://127.0.0.1:8080', 1, 1, 'core,prod'),
            )
            conn.execute(
                "INSERT INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                (now - 10, 8080, 1, 45.2, None),
            )
            conn.execute(
                "INSERT INTO events (ts, port, event_type, online, previous_online, details) VALUES (?,?,?,?,?,?)",
                (now, 8080, 'state_change', 1, 0, 'service recovered'),
            )
            conn.commit()
            conn.close()

        services_resp = self.client.get('/api/services')
        self.assertEqual(services_resp.status_code, 200)
        services = services_resp.get_json()
        self.assertEqual(len(services), 1)
        svc = services[0]

        for key in ['latency_ms', 'last_error', 'critical', 'display_name', 'url', 'uptime_buckets', 'uptime_pct']:
            self.assertIn(key, svc)
        self.assertIsInstance(svc['uptime_buckets'], list)
        self.assertEqual(svc['display_name'], 'Friendly Demo')
        self.assertTrue(svc['critical'])

        events_resp = self.client.get('/api/events?limit=5')
        self.assertEqual(events_resp.status_code, 200)
        events = events_resp.get_json()
        self.assertGreaterEqual(len(events), 1)
        evt = events[0]
        for key in ['event_type', 'ts', 'service_name', 'details']:
            self.assertIn(key, evt)


if __name__ == '__main__':
    unittest.main()
