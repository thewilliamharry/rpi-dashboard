import time
import unittest

from tests.helpers import cleanup_db, load_app


class FakeResponse:
    def __init__(self, text='', headers=None):
        self.text = text
        self.headers = headers or {}


class UptimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_service(self, probe_url):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online) VALUES (?,?,?,?,?)",
                (2500, 'Integration Service', now - 60, now, 0),
            )
            conn.execute(
                "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?)",
                (2500, 'Integration Service', probe_url, 1, 1, 'integration'),
            )
            conn.commit()
            conn.close()

    def test_uptime_check_tracks_transitions_and_errors(self):
        self._insert_service('http://127.0.0.1:4100')

        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail
        probe_results = [
            (True, 15.3, None, None),
            (False, None, 'connection_error', None),
        ]

        def fake_probe(*_args, **_kwargs):
            if probe_results:
                return probe_results.pop(0)
            return False, None, 'connection_error', None

        self.appmod._probe_http = fake_probe
        self.appmod.fetch_thumbnail = lambda _port, _service_url=None, **_kwargs: (None, None, None)

        self.appmod.do_uptime_check(only_down=False)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT is_online, last_latency_ms, last_error FROM services WHERE port=2500"
            ).fetchone()
            conn.close()

        self.assertEqual(row['is_online'], 1)
        self.assertIsNotNone(row['last_latency_ms'])
        self.assertIsNone(row['last_error'])

        self.appmod.do_uptime_check(only_down=False)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT is_online, last_error FROM services WHERE port=2500"
            ).fetchone()
            events = conn.execute(
                "SELECT event_type, online, previous_online FROM events WHERE port=2500 ORDER BY id ASC"
            ).fetchall()
            conn.close()

        self.assertEqual(row['is_online'], 0)
        self.assertIn(row['last_error'], {'connection_error', 'timeout', 'request_error', 'probe_error'})

        transition_events = [e for e in events if e['event_type'] == 'state_change']
        self.assertGreaterEqual(len(transition_events), 2)
        self.assertEqual(transition_events[0]['online'], 1)
        self.assertEqual(transition_events[-1]['online'], 0)

        self.appmod._probe_http = original_probe
        self.appmod.fetch_thumbnail = original_thumb

    def test_uptime_check_uses_path_for_probe_and_thumbnail(self):
        self._insert_service('http://127.0.0.1:2500/app?view=1')

        original_probe = self.appmod._probe_http
        original_thumb = self.appmod.fetch_thumbnail
        seen_probe = []
        seen_thumb = []

        def fake_probe(url, *_args, **_kwargs):
            seen_probe.append(url)
            return True, 12.6, None, FakeResponse(
                text='<html><head><title>Path Service</title></head><body></body></html>',
                headers={'Content-Type': 'text/html'},
            )

        def fake_thumb(port, service_url=None, **kwargs):
            seen_thumb.append((port, service_url, kwargs.get('allow_remote')))
            return None, None, None

        self.appmod._probe_http = fake_probe
        self.appmod.fetch_thumbnail = fake_thumb

        try:
            self.appmod.do_uptime_check(only_down=False)
        finally:
            self.appmod._probe_http = original_probe
            self.appmod.fetch_thumbnail = original_thumb

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT title FROM services WHERE port=2500"
            ).fetchone()
            conn.close()

        self.assertEqual(row['title'], 'Path Service')
        self.assertEqual(seen_probe[0], 'http://127.0.0.1:2500/app?view=1')
        self.assertIn((2500, 'http://127.0.0.1:2500/app?view=1', True), seen_thumb)


if __name__ == '__main__':
    unittest.main()
