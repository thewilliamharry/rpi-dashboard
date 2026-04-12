import time
import unittest

from tests.helpers import cleanup_db, load_app


class ApiAndAuthTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app({
            'TRIGGER_SCAN_RATE_LIMIT': '1',
            'TRIGGER_SCAN_WINDOW_SECONDS': '60',
        })
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_service(self, port=8080, url='http://127.0.0.1:8080'):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (port, 'Demo Service', now - 120, now, 1, 45.2, None),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (port, 'Friendly Demo', url, 1, 1, 'core,prod'),
            )
            conn.execute(
                "INSERT INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                (now - 10, port, 1, 45.2, None),
            )
            conn.commit()
            conn.close()

    def test_trigger_scan_no_auth_required(self):
        self.appmod.trigger_discovery = lambda: True
        r = self.client.post('/api/trigger-scan')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['started'])

    def test_trigger_scan_rate_limit(self):
        self.appmod.trigger_discovery = lambda: True

        r1 = self.client.post('/api/trigger-scan')
        self.assertEqual(r1.status_code, 200)
        self.assertTrue(r1.get_json()['started'])

        r2 = self.client.post('/api/trigger-scan')
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

        for key in ['latency_ms', 'last_error', 'critical', 'display_name', 'url', 'path', 'uptime_buckets', 'uptime_pct']:
            self.assertIn(key, svc)
        self.assertIsInstance(svc['uptime_buckets'], list)
        self.assertEqual(svc['display_name'], 'Friendly Demo')
        self.assertTrue(svc['critical'])
        self.assertEqual(svc['path'], '/')

        events_resp = self.client.get('/api/events?limit=5')
        self.assertEqual(events_resp.status_code, 200)
        events = events_resp.get_json()
        self.assertGreaterEqual(len(events), 1)
        evt = events[0]
        for key in ['event_type', 'ts', 'service_name', 'details']:
            self.assertIn(key, evt)

    def test_service_meta_path_normalization_variants(self):
        self._insert_service()
        cases = [
            ('', '/'),
            ('/app', '/app'),
            ('app', '/app'),
            ('/app?x=1', '/app?x=1'),
            ('/app#tab', '/app#tab'),
            ('/app?x=1#tab', '/app?x=1#tab'),
        ]

        for raw, expected in cases:
            r = self.client.put(
                '/api/service-meta/8080',
                json={'path': raw},
            )
            self.assertEqual(r.status_code, 200)
            body = r.get_json()
            self.assertEqual(body['path'], expected)

            g = self.client.get('/api/service-meta/8080')
            self.assertEqual(g.status_code, 200)
            self.assertEqual(g.get_json()['path'], expected)

    def test_service_meta_path_merge_rules(self):
        self._insert_service(url='http://127.0.0.1:8080/root')

        url_only = self.client.put('/api/service-meta/8080', json={'url': 'http://127.0.0.1:8080/alpha'})
        self.assertEqual(url_only.status_code, 200)
        self.assertEqual(url_only.get_json()['path'], '/alpha')

        path_only = self.client.put('/api/service-meta/8080', json={'path': '/beta?x=1'})
        self.assertEqual(path_only.status_code, 200)
        self.assertEqual(path_only.get_json()['path'], '/beta?x=1')
        self.assertTrue(path_only.get_json()['url'].startswith('http://127.0.0.1:8080/'))

        both = self.client.put(
            '/api/service-meta/8080',
            json={'url': 'http://127.0.0.1:9090/ignored', 'path': '/gamma#frag'},
        )
        self.assertEqual(both.status_code, 200)
        both_json = both.get_json()
        self.assertEqual(both_json['path'], '/gamma#frag')
        self.assertEqual(both_json['url'], 'http://127.0.0.1:9090/gamma#frag')


if __name__ == '__main__':
    unittest.main()
