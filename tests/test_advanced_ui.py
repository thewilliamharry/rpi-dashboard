import functools
import http.server
import pathlib
import threading
import unittest
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


ROOT = pathlib.Path(__file__).resolve().parents[1]


class _AdvancedFixtureHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'dashboard'), **kwargs)

    def do_GET(self):
        if self.path.split('?', 1)[0] == '/advanced':
            self.path = '/advanced.html'
        return super().do_GET()

    def log_message(self, format, *args):
        return


class AdvancedUiTests(unittest.TestCase):
    """Fixture-routed browser tracer for the dependency-free advanced document."""

    @classmethod
    def setUpClass(cls):
        handler = functools.partial(_AdvancedFixtureHandler)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            executable_path=cls.playwright.chromium.executable_path,
        )
        cls.base_url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    @staticmethod
    def _snapshot():
        return {
            'schema_version': 1,
            'generated_ts': 1_700_000_005,
            'host': {
                'identity': {'hostname': 'beacon-pi'},
                'metrics': {
                    'cpu': {'value': 21.5, 'unit': 'percent'},
                    'memory': {'value': 42.0, 'unit': 'percent', 'used_bytes': 420, 'available_bytes': 580, 'total_bytes': 1000},
                    'disk': {'value': 63.0, 'unit': 'percent', 'used_bytes': 630, 'total_bytes': 1000},
                    'temperature': {'value': 51.25, 'unit': 'celsius'},
                },
                'sample_ts': 1_700_000_000,
                'expected_cadence_seconds': 5,
                'freshness': {'state': 'fresh', 'age_seconds': 5},
            },
        }

    def test_direct_route_tracer_shows_loading_then_host_and_retains_last_success_on_failure(self):
        fixture = {'payload': self._snapshot(), 'fail': False}
        page = self.browser.new_page()

        def route_api(route):
            if urlparse(route.request.url).path != '/api/advanced/current':
                route.fallback()
                return
            if fixture['fail']:
                route.fulfill(status=503, json={'error': 'offline'})
            else:
                route.fulfill(status=200, json=fixture['payload'])

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-testid="host-summary"]').wait_for(timeout=5_000)
            self.assertIn('beacon-pi', page.locator('[data-testid="host-summary"]').text_content())
            first_success = page.locator('#advanced-last-success').text_content()
            fixture['fail'] = True
            page.locator('#advanced-refresh').click()
            page.locator('#advanced-refresh-error').wait_for(state='visible', timeout=5_000)
            self.assertIn('Beacon could not refresh current diagnosis.', page.locator('#advanced-refresh-error').text_content())
            self.assertIn('beacon-pi', page.locator('[data-testid="host-summary"]').text_content())
            self.assertEqual(page.locator('#advanced-last-success').text_content(), first_success)
        finally:
            page.close()

    def test_advanced_controller_tracer_is_same_origin_get_only_and_text_safe(self):
        html = (ROOT / 'dashboard/advanced.html').read_text(encoding='utf-8')
        js = (ROOT / 'dashboard/advanced.js').read_text(encoding='utf-8')
        self.assertIn('Advanced diagnosis', html)
        self.assertIn('Loading current diagnosis…', html)
        self.assertIn('id="connection-banner"', html)
        self.assertLess(html.index('id="connection-banner"'), html.index('id="worker-warning"'))
        self.assertLess(html.index('id="worker-warning"'), html.index('id="recovery-warning"'))
        self.assertIn("fetch('/api/advanced/current'", js)
        self.assertIn("cache: 'no-store'", js)
        self.assertIn('.textContent', js)
        self.assertIn('.replaceChildren(', js)
        for forbidden in ('POST', 'PUT', 'PATCH', 'DELETE', 'thumbnail', 'history', 'http://', 'https://', 'worker_', 'run_discovery'):
            self.assertNotIn(forbidden, js)


if __name__ == '__main__':
    unittest.main()
