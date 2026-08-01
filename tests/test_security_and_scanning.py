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
        class Transport:
            def request(self, *_args, **_kwargs):
                return FakeResponse(status_code=302, headers={'Location': 'http://example.com/'}), None

        original_transport = self.appmod._outbound_transport
        self.appmod._outbound_transport = lambda: Transport()
        try:
            ok, latency, error_class, _ = self.appmod._probe_http(
                'http://127.0.0.1:3001',
                timeout=2,
                allow_remote=False,
            )
        finally:
            self.appmod._outbound_transport = original_transport

        self.assertFalse(ok)
        self.assertIsNotNone(latency)
        self.assertEqual(error_class, 'redirect_offhost')

    def test_probe_rejects_offhost_redirect_even_with_legacy_flag(self):
        class Transport:
            def request(self, *_args, **_kwargs):
                return FakeResponse(status_code=302, headers={'Location': 'http://example.com/'}), None

        original_transport = self.appmod._outbound_transport
        self.appmod._outbound_transport = lambda: Transport()
        try:
            ok, _, error_class, resp = self.appmod._probe_http(
                'http://127.0.0.1:3001',
                timeout=2,
                allow_remote=True,
            )
        finally:
            self.appmod._outbound_transport = original_transport

        self.assertFalse(ok)
        self.assertEqual(error_class, 'redirect_offhost')
        self.assertEqual(resp.status_code, 302)

    def test_preview_errors_are_stable_and_do_not_reflect_destination_details(self):
        error = self.appmod._thumb_error(RuntimeError('connect 192.168.1.45:8443 failed'))

        self.assertEqual(error, 'preview_error')
        self.assertNotIn('192.168.1.45', error)

    def test_metadata_mutation_runs_policy_before_persistence(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO services(port,title,first_seen,last_seen,is_online) VALUES(?,?,?,?,?)',
                (8100, 'Policy target', now - 1, now, 1),
            )
            conn.commit()
            conn.close()

        calls = []
        policy_error = self.appmod.OutboundPolicyError

        class BlockedPolicy:
            def plan(self, url, purpose, **_kwargs):
                calls.append((url, purpose))
                raise policy_error('target_not_allowed')

        original = self.appmod._outbound_policy
        self.appmod._outbound_policy = lambda: BlockedPolicy()
        try:
            response = self.appmod.app.test_client().put(
                '/api/service-meta/8100',
                json={'url': 'http://127.0.0.1:8100'},
                headers={'X-Beacon-UI': '1'},
            )
        finally:
            self.appmod._outbound_policy = original

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'policy_error')
        self.assertEqual(len(calls), 1)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            self.assertIsNone(conn.execute('SELECT 1 FROM service_meta WHERE port=8100').fetchone())
            conn.close()

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

        def fake_create_connection(address, *_args, **_kwargs):
            if address[1] != 3000:
                raise OSError('closed')
            return DummySock()

        self.appmod.socket.create_connection = fake_create_connection
        self.appmod._probe_http = lambda *_args, **_kwargs: (True, 12.0, None, FakeResponse(200, {'Content-Type': 'text/html'}))
        self.appmod.fetch_thumbnail = lambda _port, _service_url=None, **_kwargs: (_ for _ in ()).throw(RuntimeError('thumb-failure'))

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

        self.assertFalse(self.appmod._read_scan_state()['scanning'])

    def test_discovery_uses_existing_path_and_queues_preview(self):
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

        def fake_create_connection(address, *_args, **_kwargs):
            if address[1] != 3000:
                raise OSError('closed')
            return DummySock()

        self.appmod.socket.create_connection = fake_create_connection

        def fake_probe(url, *_args, **_kwargs):
            captured_probe_urls.append(url)
            return True, 8.2, None, FakeResponse(200, {'Content-Type': 'text/html'})

        def fake_thumbnail(port, service_url=None):
            captured_thumb.append((port, service_url))
            return None, None, None, 'screenshot failed'

        self.appmod._probe_http = fake_probe
        self.appmod.fetch_thumbnail = fake_thumbnail
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
        self.assertEqual(captured_thumb, [])
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            preview = conn.execute("SELECT status FROM preview_requests WHERE port=3000").fetchone()
            conn.close()
        self.assertEqual(preview['status'], 'queued')

    def test_discovery_queues_legacy_thumbnail_without_source(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, thumb_data, thumb_mime, thumb_ts) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (3000, 'Legacy Thumb', now - 120, now, 1, b'old-bytes', 'image/png', now),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (3000, 'Legacy Thumb', 'http://127.0.0.1:3000/app', 0, 3000, ''),
            )
            conn.commit()
            conn.close()

        original_range = self.appmod.range if hasattr(self.appmod, 'range') else None
        original_sleep = self.appmod.time.sleep
        original_socket_create = self.appmod.socket.create_connection
        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail
        captured_thumb = []

        class DummySock:
            def close(self):
                return

        self.appmod.range = lambda a, b, c: [3000]
        self.appmod.time.sleep = lambda _secs: None

        def fake_create_connection(address, *_args, **_kwargs):
            if address[1] != 3000:
                raise OSError('closed')
            return DummySock()

        self.appmod.socket.create_connection = fake_create_connection
        self.appmod._probe_http = lambda *_args, **_kwargs: (True, 8.2, None, FakeResponse(200, {'Content-Type': 'text/html'}))

        def fake_thumbnail(port, service_url=None):
            captured_thumb.append((port, service_url))
            return b'new-bytes', 'image/png', 'screenshot', None

        self.appmod.fetch_thumbnail = fake_thumbnail
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

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT thumb_data, thumb_mime, thumb_source FROM services WHERE port=3000"
            ).fetchone()
            conn.close()

        self.assertEqual(captured_thumb, [])
        self.assertEqual(bytes(row['thumb_data']), b'old-bytes')
        self.assertIsNone(row['thumb_source'])
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            preview = conn.execute("SELECT status FROM preview_requests WHERE port=3000").fetchone()
            conn.close()
        self.assertEqual(preview['status'], 'queued')

    def test_discovery_skips_recent_screenshot_thumbnail(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, thumb_data, thumb_mime, thumb_ts, thumb_source) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (3000, 'Fresh Thumb', now - 120, now, 1, b'fresh-bytes', 'image/png', now, 'screenshot'),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (3000, 'Fresh Thumb', 'http://127.0.0.1:3000/app', 0, 3000, ''),
            )
            conn.commit()
            conn.close()

        original_range = self.appmod.range if hasattr(self.appmod, 'range') else None
        original_sleep = self.appmod.time.sleep
        original_socket_create = self.appmod.socket.create_connection
        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail
        captured_thumb = []

        class DummySock:
            def close(self):
                return

        self.appmod.range = lambda a, b, c: [3000]
        self.appmod.time.sleep = lambda _secs: None

        def fake_create_connection(address, *_args, **_kwargs):
            if address[1] != 3000:
                raise OSError('closed')
            return DummySock()

        self.appmod.socket.create_connection = fake_create_connection
        self.appmod._probe_http = lambda *_args, **_kwargs: (True, 8.2, None, FakeResponse(200, {'Content-Type': 'text/html'}))
        self.appmod.fetch_thumbnail = lambda *args, **kwargs: captured_thumb.append((args, kwargs)) or (b'unexpected', 'image/png', 'screenshot', None)
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

        self.assertEqual(captured_thumb, [])


if __name__ == '__main__':
    unittest.main()
