import pathlib
import functools
import http.server
import threading
import unittest
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


ROOT = pathlib.Path(__file__).resolve().parents[1]


class UiStateTests(unittest.TestCase):
    """Browser-source contracts for the Phase 1 safety presentation.

    The dashboard has no client framework, so these tests intentionally assert the
    stable DOM hooks and rendering branches that a Playwright smoke harness uses.
    They keep safety copy and accessible state separation from quietly regressing.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / 'dashboard/index.html').read_text(encoding='utf-8')
        cls.js = (ROOT / 'dashboard/app.js').read_text(encoding='utf-8')
        cls.css = (ROOT / 'dashboard/style.css').read_text(encoding='utf-8')

    def test_warning_cluster_has_locked_connection_worker_recovery_order(self):
        self.assertIn('id="safety-warning-cluster"', self.html)
        self.assertIn('id="connection-banner"', self.html)
        self.assertIn('id="worker-warning"', self.html)
        self.assertIn('id="recovery-warning"', self.html)
        self.assertLess(
            self.html.index('id="connection-banner"'),
            self.html.index('id="worker-warning"'),
        )
        self.assertLess(
            self.html.index('id="worker-warning"'),
            self.html.index('id="recovery-warning"'),
        )
        self.assertIn('Monitoring resumed. The outage was recorded in Events.', self.js)
        app = (ROOT / 'dashboard/app.py').read_text(encoding='utf-8')
        self.assertIn("(Path(DB_PATH).parent / RECOVERY_MARKER).is_file()", app)

    def test_scan_and_preview_queue_copy_is_truthful_and_nonblocking(self):
        for copy in [
            'Scan queued — runs when monitoring resumes',
            'Scan request expired — it was not run. Scan again.',
            'Preview refresh queued',
            'Refreshing preview',
            'Preview refresh failed — saved settings are unaffected',
            'Preview refresh expired — save service details to request a new preview.',
        ]:
            self.assertIn(copy, self.js)
        self.assertIn("data.stage === 'running'", self.js)
        self.assertIn("requestStatus === 'expired'", self.js)

    def test_metadata_outage_flow_preserves_focus_and_uses_safe_copy(self):
        self.assertIn('Monitoring is paused. Your service details will be saved now; preview refresh will run after recovery.', self.html)
        self.assertIn('Service details saved. Preview refresh queued.', self.js)
        self.assertIn('Beacon could not use that destination. Review the service details and try again.', self.js)
        self.assertIn("$('meta-error').focus()", self.js)
        self.assertIn("focusTarget?.focus()", self.js)

    def test_tls_badge_is_independent_from_availability_and_edit_is_explicit(self):
        self.assertIn("service.tls_unverified", self.js)
        self.assertIn('TLS unverified', self.js)
        self.assertIn('TLS certificate is not verified for this trusted local service.', self.js)
        self.assertIn("textContent: 'Edit service'", self.js)

    def test_both_themes_and_narrow_actions_keep_safety_content_readable(self):
        for selector in [
            'html.light .safety-warning',
            '.svc-tls-unverified',
            '.svc-preview-status',
            '.meta-stale-warning',
            '.meta-btn { width: 100%; min-height: 44px;',
        ]:
            self.assertIn(selector, self.css)
        self.assertIn('No HTTP services discovered', self.js)
        self.assertIn('Run a scan to look for configured services.', self.js)
        self.assertIn('no recent incidents', self.js)


class UiStateBrowserTests(unittest.TestCase):
    """Exercise the dependency-free dashboard against deterministic API fixtures."""

    @classmethod
    def setUpClass(cls):
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT / 'dashboard'))
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(executable_path=cls.playwright.chromium.executable_path)
        cls.base_url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    @staticmethod
    def _service(port, *, online=True, tls=False):
        return {
            'port': port, 'title': f'Service {port}', 'display_name': f'Service {port}',
            'is_online': online, 'has_thumb': False, 'latency_ms': 8,
            'state_since': 1_700_000_000, 'url': f'http://127.0.0.1:{port}',
            'path': '/', 'tags': ['local'], 'critical': False,
            'healthy_statuses': '200-399', 'tls_unverified': tls,
            'uptime_pct': 100, 'uptime_buckets': [1, 1, 1],
            'preview_status': 'queued',
        }

    def test_playwright_zero_one_many_states_in_dark_light_and_narrow_layout(self):
        fixture = {'services': [], 'events': []}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})

        def route_api(route):
            path = urlparse(route.request.url).path
            payloads = {
                '/api/stats': {'hostname': 'beacon', 'sample_ts': 1_700_000_000, 'cpu': 1, 'ram': 2, 'disk': 3, 'ram_used': 1, 'ram_total': 2, 'disk_used': 1, 'disk_total': 2, 'temp': 40},
                '/api/history': [],
                '/api/scan-status': {'worker_ready': True, 'worker_stale': False, 'recovery_required': False, 'stage': 'idle', 'scanning': False, 'last_completed_found': len(fixture['services']), 'last_discovery': 1_700_000_000},
                '/api/services': fixture['services'],
                '/api/events': fixture['events'],
            }
            route.fulfill(status=200, json=payloads.get(path, {}))

        page.route('**/api/**', route_api)
        try:
            page.goto(self.base_url, wait_until='networkidle')
            self.assertEqual(page.locator('.svc-empty strong').text_content(), 'No HTTP services discovered')
            self.assertIn('Run a scan to look for configured services.', page.locator('.svc-empty').text_content())

            fixture['services'] = [self._service(8100, tls=True)]
            page.reload(wait_until='networkidle')
            self.assertEqual(page.locator('.svc-card').count(), 1)
            self.assertEqual(page.locator('.svc-tls-unverified').get_attribute('title'), 'TLS certificate is not verified for this trusted local service.')
            self.assertEqual(page.locator('.svc-edit').text_content(), 'Edit service')
            self.assertIn('ONLINE', page.locator('.svc-status-row').text_content())
            self.assertIn('Preview refresh queued', page.locator('.svc-preview-status').text_content())

            page.set_viewport_size({'width': 720, 'height': 800})
            page.locator('.svc-edit').click()
            self.assertGreaterEqual(page.locator('.meta-btn').first.bounding_box()['height'], 44)
            page.locator('#meta-cancel').click()
            page.locator('#toggle').click()
            self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))

            fixture['services'] = [self._service(8100, tls=True), self._service(8101), self._service(8102, online=False)]
            fixture['events'] = [{'event_type': 'monitoring_gap', 'details': '{"start_ts": 10, "end_ts": 80}', 'ts': 1_700_000_000, 'online': None}]
            page.reload(wait_until='networkidle')
            self.assertEqual(page.locator('.svc-card').count(), 3)
            self.assertIn('Monitoring gap recorded', page.locator('#events-panel').text_content())
            self.assertIn('Worker unavailable for', page.locator('#events-panel').text_content())
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
