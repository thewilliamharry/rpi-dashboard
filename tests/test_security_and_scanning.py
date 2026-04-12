import time
import unittest

from tests.helpers import cleanup_db, load_app


class FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = ''


class SecurityAndScanningTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_probe_blocks_offhost_redirect_for_loopback_mode(self):
        original_get = self.appmod.requests.get

        def fake_get(url, timeout, verify, allow_redirects):
            _ = (url, timeout, verify, allow_redirects)
            return FakeResponse(status_code=302, headers={'Location': 'http://example.com/'})

        self.appmod.requests.get = fake_get
        try:
            ok, latency, error_class, _ = self.appmod._probe_http(
                'http://127.0.0.1:3001',
                timeout=2,
                allow_remote=False,
            )
        finally:
            self.appmod.requests.get = original_get

        self.assertFalse(ok)
        self.assertIsNotNone(latency)
        self.assertEqual(error_class, 'redirect_offhost')

    def test_probe_allows_redirect_response_when_remote_allowed(self):
        original_get = self.appmod.requests.get

        def fake_get(url, timeout, verify, allow_redirects):
            _ = (url, timeout, verify, allow_redirects)
            return FakeResponse(status_code=302, headers={'Location': 'http://example.com/'})

        self.appmod.requests.get = fake_get
        try:
            ok, _, error_class, resp = self.appmod._probe_http(
                'http://127.0.0.1:3001',
                timeout=2,
                allow_remote=True,
            )
        finally:
            self.appmod.requests.get = original_get

        self.assertTrue(ok)
        self.assertIsNone(error_class)
        self.assertEqual(resp.status_code, 302)

    def test_discovery_finally_clears_scanning_state_after_error(self):
        original_range = self.appmod.range if hasattr(self.appmod, 'range') else None
        original_sleep = self.appmod.time.sleep
        original_socket_create = self.appmod.socket.create_connection
        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail

        class DummySock:
            def close(self):
                return

        self.appmod.range = lambda a, b, c: [3000]
        self.appmod.time.sleep = lambda _secs: None
        self.appmod.socket.create_connection = lambda *_args, **_kwargs: DummySock()
        self.appmod._probe_http = lambda *_args, **_kwargs: (True, 12.0, None, FakeResponse(200, {'Content-Type': 'text/html'}))
        self.appmod.fetch_thumbnail = lambda _port, _service_url=None: (_ for _ in ()).throw(RuntimeError('thumb-failure'))

        self.appmod._scanning = True
        try:
            self.appmod.do_discovery(source='manual')
        finally:
            if original_range is None:
                delattr(self.appmod, 'range')
            else:
                self.appmod.range = original_range
            self.appmod.time.sleep = original_sleep
            self.appmod.socket.create_connection = original_socket_create
            self.appmod._probe_http = original_probe
            self.appmod.fetch_thumbnail = original_thumb

        self.assertFalse(self.appmod._scanning)

    def test_discovery_uses_existing_service_path_for_probe_and_thumbnail(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online) VALUES (?,?,?,?,?)",
                (3000, 'Path App', now - 120, now, 1),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (3000, 'Path App', 'http://127.0.0.1:3000/app', 0, 3000, ''),
            )
            conn.commit()
            conn.close()

        original_range = self.appmod.range if hasattr(self.appmod, 'range') else None
        original_sleep = self.appmod.time.sleep
        original_socket_create = self.appmod.socket.create_connection
        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail

        captured_probe_urls = []
        captured_thumb = []

        class DummySock:
            def close(self):
                return

        self.appmod.range = lambda a, b, c: [3000]
        self.appmod.time.sleep = lambda _secs: None
        self.appmod.socket.create_connection = lambda *_args, **_kwargs: DummySock()

        def fake_probe(url, *_args, **_kwargs):
            captured_probe_urls.append(url)
            return True, 8.2, None, FakeResponse(200, {'Content-Type': 'text/html'})

        def fake_thumbnail(port, service_url=None):
            captured_thumb.append((port, service_url))
            return None, None

        self.appmod._probe_http = fake_probe
        self.appmod.fetch_thumbnail = fake_thumbnail
        self.appmod._scanning = True

        try:
            self.appmod.do_discovery(source='manual')
        finally:
            if original_range is None:
                delattr(self.appmod, 'range')
            else:
                self.appmod.range = original_range
            self.appmod.time.sleep = original_sleep
            self.appmod.socket.create_connection = original_socket_create
            self.appmod._probe_http = original_probe
            self.appmod.fetch_thumbnail = original_thumb

        self.assertIn('http://127.0.0.1:3000/app', captured_probe_urls)
        self.assertIn((3000, 'http://127.0.0.1:3000/app'), captured_thumb)


if __name__ == '__main__':
    unittest.main()
