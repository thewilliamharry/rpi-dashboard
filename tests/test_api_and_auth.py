import time
import unittest

from tests.helpers import cleanup_db, load_app


class FakeResponse:
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


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

    def test_service_meta_refresh_success_updates_title_and_thumbnail(self):
        self._insert_service(url='http://127.0.0.1:8080/root')

        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail
        seen_probe = []
        seen_thumb = []

        def fake_probe(url, *_args, **_kwargs):
            seen_probe.append(url)
            return True, 12.4, None, FakeResponse(
                text='<html><head><title>Path Title</title></head><body></body></html>',
                status_code=200,
                headers={'Content-Type': 'text/html'},
            )

        def fake_thumb(port, service_url=None):
            seen_thumb.append((port, service_url))
            return b'png-bytes', 'image/png'

        self.appmod._probe_http = fake_probe
        self.appmod.fetch_thumbnail = fake_thumb

        try:
            r = self.client.put('/api/service-meta/8080', json={'path': '/app?view=1'})
        finally:
            self.appmod._probe_http = original_probe
            self.appmod.fetch_thumbnail = original_thumb

        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['path'], '/app?view=1')
        self.assertIsNone(body['refresh_warning'])
        self.assertEqual(seen_probe[-1], 'http://127.0.0.1:8080/app?view=1')
        self.assertIn((8080, 'http://127.0.0.1:8080/app?view=1'), seen_thumb)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT title, thumb_data, thumb_mime FROM services WHERE port=8080"
            ).fetchone()
            conn.close()

        self.assertEqual(row['title'], 'Path Title')
        self.assertIsNotNone(row['thumb_data'])
        self.assertEqual(row['thumb_mime'], 'image/png')

    def test_service_meta_refresh_failure_keeps_existing_values_and_warns(self):
        self._insert_service(url='http://127.0.0.1:8080/root')
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "UPDATE services SET title=?, thumb_data=?, thumb_mime=?, thumb_ts=? WHERE port=?",
                ('Existing Title', b'old-bytes', 'image/png', 12345, 8080),
            )
            conn.commit()
            conn.close()

        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail

        def fake_probe(url, *_args, **_kwargs):
            _ = url
            return False, None, 'connection_error', None

        def fake_thumb(*_args, **_kwargs):
            raise AssertionError('thumbnail refresh should be skipped when path probe fails')

        self.appmod._probe_http = fake_probe
        self.appmod.fetch_thumbnail = fake_thumb

        try:
            r = self.client.put('/api/service-meta/8080', json={'path': '/broken'})
        finally:
            self.appmod._probe_http = original_probe
            self.appmod.fetch_thumbnail = original_thumb

        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['path'], '/broken')
        self.assertIsInstance(body.get('refresh_warning'), str)
        self.assertIn('title refresh failed', body['refresh_warning'])
        self.assertIn('thumbnail refresh skipped', body['refresh_warning'])

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT title, thumb_data, thumb_mime FROM services WHERE port=8080"
            ).fetchone()
            conn.close()

        self.assertEqual(row['title'], 'Existing Title')
        self.assertEqual(bytes(row['thumb_data']), b'old-bytes')
        self.assertEqual(row['thumb_mime'], 'image/png')


if __name__ == '__main__':
    unittest.main()
