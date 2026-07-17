import threading
import time
import unittest
from unittest import mock

from tests.helpers import cleanup_db, load_app


class ReleaseContractTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app({
            'TRUSTED_HOSTS': 'raspi.local,localhost,127.0.0.1,::1',
            'LOCAL_SERVICE_HOSTS': 'raspi.local',
        })
        self.client = self.appmod.app.test_client()
        self.ui = {'X-Beacon-UI': '1'}

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_ram_pressure_bytes_and_cached_stats_reconcile(self):
        class Memory:
            total = 8 * 1024 ** 3
            available = 5 * 1024 ** 3
            used = 2 * 1024 ** 3

        original = self.appmod.psutil.virtual_memory
        self.appmod.psutil.virtual_memory = lambda: Memory()
        try:
            sample = self.appmod.collect_system_stats(now=1234, persist_history=True)
        finally:
            self.appmod.psutil.virtual_memory = original

        self.assertEqual(sample['ram_used'], 3 * 1024 ** 3)
        self.assertEqual(sample['ram_available'], 5 * 1024 ** 3)
        self.assertEqual(sample['ram_used_strict'], 2 * 1024 ** 3)
        self.assertEqual(sample['ram'], 37.5)
        body = self.client.get('/api/stats').get_json()
        self.assertEqual(body['sample_ts'], 1234)
        self.assertEqual(body['ram_used'] + body['ram_available'], body['ram_total'])

    def test_time_weighted_uptime_preserves_boundary_and_fractional_bucket(self):
        now = 10_000_000
        start = now - self.appmod.UPTIME_WINDOW_SECONDS
        checks = [
            (start - 30, 1),
            (start + 3600, 0),
            (start + 5400, 1),
        ]
        pct, buckets = self.appmod._uptime_summary(checks, now)
        expected = round(((self.appmod.UPTIME_WINDOW_SECONDS - 1800) / self.appmod.UPTIME_WINDOW_SECONDS) * 100, 3)
        self.assertEqual(pct, expected)
        self.assertEqual(buckets[0], 1.0)
        self.assertEqual(buckets[1], 0.5)
        self.assertTrue(all(value == 1.0 for value in buckets[2:]))

    def test_tiny_outage_never_rounds_to_exact_100(self):
        now = 20_000_000
        start = now - self.appmod.UPTIME_WINDOW_SECONDS
        pct, _ = self.appmod._uptime_summary([
            (start - 1, 1),
            (now - 2, 0),
            (now - 1, 1),
        ], now)
        self.assertLess(pct, 100)
        self.assertEqual(pct, 99.999)

    def test_status_ranges_and_http_500(self):
        self.assertTrue(self.appmod._status_is_healthy(399, '200-399'))
        self.assertTrue(self.appmod._status_is_healthy(401, '200-399,401'))
        self.assertFalse(self.appmod._status_is_healthy(500, '200-399'))
        with self.assertRaises(ValueError):
            self.appmod._parse_healthy_statuses('99-700')

    def test_service_meta_validates_health_ranges_and_local_targets(self):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) VALUES(?,?,?,?,?,?)",
                (8100, 'BlueMap', now, now, 1, now),
            )
            conn.commit()
            conn.close()
        valid = self.client.put(
            '/api/service-meta/8100', json={'url': 'http://raspi.local:8100', 'healthy_statuses': '200-399,401'},
            headers=self.ui,
        )
        self.assertEqual(valid.status_code, 200)
        self.assertEqual(valid.get_json()['url'], 'http://127.0.0.1:8100')
        self.assertEqual(valid.get_json()['healthy_statuses'], '200-399,401')
        self.assertEqual(
            self.client.put('/api/service-meta/8100', json={'url': 'http://example.com'}, headers=self.ui).status_code,
            400,
        )
        self.assertEqual(
            self.client.put('/api/service-meta/8100', json={'healthy_statuses': '600'}, headers=self.ui).status_code,
            400,
        )

    def test_alias_is_canonicalized_and_remote_targets_are_rejected(self):
        self.assertEqual(
            self.appmod._normalize_service_url('http://raspi.local:8100/maps?x=1', 8100),
            'http://127.0.0.1:8100/maps?x=1',
        )
        for target in ['http://example.com:8100', 'http://user@raspi.local:8100', 'file:///tmp/a']:
            with self.assertRaises(ValueError):
                self.appmod._normalize_service_url(target, 8100)

    def test_mutation_origin_and_host_protection(self):
        self.assertEqual(self.client.post('/api/trigger-scan').status_code, 403)
        self.assertEqual(
            self.client.post('/api/trigger-scan', headers={**self.ui, 'Origin': 'http://evil.test'}).status_code,
            403,
        )
        self.assertEqual(
            self.client.post('/api/trigger-scan', headers={**self.ui, 'Origin': 'http://localhost:9999'}).status_code,
            403,
        )
        self.assertEqual(self.client.get('/healthz', headers={'Host': 'evil.test'}).status_code, 400)
        accepted = self.client.post('/api/trigger-scan', headers={**self.ui, 'Origin': 'http://localhost'})
        self.assertEqual(accepted.status_code, 202)

    def test_state_since_migration_uses_latest_matching_event(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services(port,title,first_seen,last_seen,is_online,state_since) VALUES(?,?,?,?,?,NULL)",
                (8123, 'state', 100, 300, 1),
            )
            conn.execute(
                "INSERT INTO events(ts,port,event_type,online) VALUES(?,?,?,?)",
                (250, 8123, 'state_change', 1),
            )
            conn.commit()
            conn.close()
        self.appmod.init_db()
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            value = conn.execute("SELECT state_since FROM services WHERE port=8123").fetchone()['state_since']
            conn.close()
        self.assertEqual(value, 250)

    def test_worker_heartbeat_readiness(self):
        self.assertEqual(self.client.get('/readyz').status_code, 503)
        self.appmod.update_worker_heartbeat()
        self.assertEqual(self.client.get('/readyz').status_code, 200)
        status = self.client.get('/api/scan-status').get_json()
        self.assertTrue(status['worker_ready'])

    def test_worker_restart_requeues_interrupted_work(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO scan_requests(requested_ts,requested_by,status,started_ts) VALUES(?,?,?,?)",
                (10, 'test', 'running', 11),
            )
            self.appmod._set_runtime_state('scan_state', {'scanning': True, 'stage': 'probing'}, conn=conn)
            conn.commit()
            conn.close()
        self.appmod.recover_worker_state()
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            request_status = conn.execute("SELECT status FROM scan_requests").fetchone()['status']
            state = self.appmod._read_scan_state(conn)
            conn.close()
        self.assertEqual(request_status, 'queued')
        self.assertFalse(state['scanning'])
        self.assertEqual(state['stage'], 'queued')

    def test_web_worker_manual_scan_coordination_through_sqlite(self):
        request_id = self.appmod.queue_discovery_request('test-client')
        self.assertIsNotNone(request_id)
        original = self.appmod.do_discovery

        def fake_discovery(source):
            self.assertEqual(source, f'manual:{request_id}')
            self.appmod._update_scan_state(
                stage='idle', scanning=False, progress=1.0,
                last_completed_found=1, current_found=0, last_error=None,
            )
            return True

        self.appmod.do_discovery = fake_discovery
        try:
            self.assertTrue(self.appmod.process_scan_requests())
        finally:
            self.appmod.do_discovery = original
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute("SELECT status,completed_ts,error FROM scan_requests WHERE id=?", (request_id,)).fetchone()
            conn.close()
        self.assertEqual(row['status'], 'completed')
        self.assertIsNotNone(row['completed_ts'])
        self.assertIsNone(row['error'])

    def test_manual_scan_stays_queued_when_discovery_is_busy(self):
        request_id = self.appmod.queue_discovery_request('test-client')
        self.assertIsNotNone(request_id)
        self.assertTrue(self.appmod._scan_lock.acquire(blocking=False))
        try:
            self.assertFalse(self.appmod.process_scan_requests())
        finally:
            self.appmod._scan_lock.release()

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                "SELECT status,started_ts,completed_ts,error FROM scan_requests WHERE id=?",
                (request_id,),
            ).fetchone()
            conn.close()
        self.assertEqual(row['status'], 'queued')
        self.assertIsNone(row['started_ts'])
        self.assertIsNone(row['completed_ts'])
        self.assertIsNone(row['error'])

    def test_all_discovery_entry_points_share_one_mutex(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []
        original = self.appmod.do_discovery

        def slow_discovery(source):
            calls.append(source)
            entered.set()
            release.wait(timeout=2)
            return True

        self.appmod.do_discovery = slow_discovery
        try:
            first_result = []
            thread = threading.Thread(
                target=lambda: first_result.append(self.appmod.run_discovery('scheduled')),
            )
            thread.start()
            self.assertTrue(entered.wait(timeout=1))
            self.assertEqual(self.appmod.run_discovery('startup'), 'busy')
            release.set()
            thread.join(timeout=2)
            self.assertEqual(first_result, ['completed'])
            self.assertEqual(calls, ['scheduled'])
        finally:
            release.set()
            self.appmod.do_discovery = original

    def test_alert_webhook_keeps_tls_verification_enabled(self):
        self.appmod.ALERT_WEBHOOK_URL = 'https://alerts.example.test/beacon'
        response = mock.Mock(status_code=204, text='')
        with mock.patch.object(self.appmod.requests, 'post', return_value=response) as post:
            self.appmod._send_transition_alert(
                now=int(time.time()), port=8100, previous_online=0, online=1,
                title='BlueMap', display_name='', url='http://127.0.0.1:8100',
                critical=0, latency_ms=4.2, error_class=None,
            )
        self.assertEqual(post.call_args.kwargs['timeout'], 4)
        self.assertNotIn('verify', post.call_args.kwargs)

    def test_metrics_collection_is_not_blocked_by_preview_capture(self):
        entered = threading.Event()
        release = threading.Event()
        original = self.appmod._screenshot_service

        def slow_preview(*_args, **_kwargs):
            entered.set()
            release.wait(timeout=2)
            return None, None, 'timeout'

        self.appmod._screenshot_service = slow_preview
        thread = threading.Thread(target=self.appmod.fetch_thumbnail, args=(8100, 'http://127.0.0.1:8100'))
        thread.start()
        self.assertTrue(entered.wait(timeout=1))
        started = time.monotonic()
        self.appmod.collect_system_stats(persist_history=True)
        elapsed = time.monotonic() - started
        release.set()
        thread.join(timeout=2)
        self.appmod._screenshot_service = original
        self.assertLess(elapsed, 0.5)

    def test_browser_process_is_reused_across_previews(self):
        import playwright.sync_api

        calls = {'start': 0, 'launch': 0, 'close': 0, 'stop': 0}

        class Browser:
            def is_connected(self):
                return True

            def close(self):
                calls['close'] += 1

        browser = Browser()

        class Chromium:
            def launch(self, **_kwargs):
                calls['launch'] += 1
                return browser

        class Driver:
            chromium = Chromium()

            def stop(self):
                calls['stop'] += 1

        class Starter:
            def start(self):
                calls['start'] += 1
                return Driver()

        original = playwright.sync_api.sync_playwright
        playwright.sync_api.sync_playwright = lambda: Starter()
        self.appmod._browser_playwright = None
        self.appmod._browser_instance = None
        try:
            self.assertIs(self.appmod._get_browser(), browser)
            self.assertIs(self.appmod._get_browser(), browser)
            self.assertEqual(calls['start'], 1)
            self.assertEqual(calls['launch'], 1)
            self.appmod.shutdown_browser()
        finally:
            playwright.sync_api.sync_playwright = original
            self.appmod._browser_playwright = None
            self.appmod._browser_instance = None

    def test_security_headers_and_optional_metrics(self):
        response = self.client.get('/')
        self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.assertEqual(self.client.get('/metrics').status_code, 404)


if __name__ == '__main__':
    unittest.main()
