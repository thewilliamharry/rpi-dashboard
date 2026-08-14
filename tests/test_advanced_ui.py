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
        for forbidden in ('POST', 'PUT', 'PATCH', 'DELETE', 'thumbnail', 'history', 'http://', 'https://', 'run_discovery'):
            self.assertNotIn(forbidden, js)

    def test_workspace_sections_overview_and_host_states(self):
        payload = self._snapshot()
        payload.update({
            'safety': {'connection': False, 'worker_stale': False, 'recovery_required': False},
            'exceptions': [],
            'services': [],
            'pipeline': {},
            'settings': {},
        })
        page = self.browser.new_page(viewport={'width': 959, 'height': 800})

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('#overview-section').wait_for(timeout=5_000)
            self.assertEqual(
                [link.text_content() for link in page.locator('#section-navigation button').all()],
                ['Overview', 'Host', 'Services', 'Pipeline', 'Settings'],
            )
            self.assertIn('No active exceptions', page.locator('#overview-section').text_content())
            self.assertIn(
                'Host, services, and collection pipeline are reporting normally.',
                page.locator('#overview-section').text_content(),
            )
            page.locator('[data-section="host"]').click()
            self.assertEqual(page.locator('#host-heading').evaluate('(node) => document.activeElement === node'), True)
            host_text = page.locator('#host-section').text_content()
            for label in ('beacon-pi', 'CPU', 'Memory', 'Disk', 'Temperature', 'Expected cadence', 'fresh'):
                self.assertIn(label, host_text)
        finally:
            page.close()

    def test_workspace_loading_and_partial_overview_use_truthful_evidence(self):
        payload = self._snapshot()
        payload.update({
            'exceptions': [
                {'kind': 'service', 'label': 'Critical web service down', 'section': 'services', 'priority': 1},
                {'kind': 'stream', 'label': 'very-long-stream-' + ('evidence-' * 18), 'section': 'pipeline', 'priority': 2},
            ],
            'services': None,
            'pipeline': None,
            'settings': {},
        })
        page = self.browser.new_page(viewport={'width': 360, 'height': 800})
        seen_loading = {'value': False}

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                seen_loading['value'] = True
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('#overview-section').wait_for(timeout=5_000)
            self.assertTrue(seen_loading['value'])
            overview = page.locator('#overview-section').text_content()
            self.assertIn('2 active exceptions', overview)
            self.assertIn('Critical web service down', overview)
            self.assertIn('Unknown', overview)
            self.assertIn('Some current-state evidence is unavailable.', overview)
            self.assertLessEqual(page.evaluate('document.documentElement.scrollWidth'), 360)
        finally:
            page.close()

    def test_pipeline_and_settings_render_independent_truthful_regions(self):
        payload = self._snapshot()
        payload.update({
            'services': [],
            'exceptions': [],
            'pipeline': {
                'retention': {'raw_days': 7, 'five_minute_days': 30, 'retention_days': 90, 'point_budget': 2048},
                'resolution_policy': {'raw_seconds': 60, 'five_minute_seconds': 300, 'hourly_seconds': 3600},
                'database_pressure': {'state': 'warning', 'reason': 'very-long-pressure-reason-' + ('evidence-' * 12), 'snapshot': {'bytes': 1}},
                'worker': {'heartbeat_ts': 1_700_000_000, 'expected_cadence_seconds': 5, 'freshness': {'state': 'fresh', 'age_seconds': 5}, 'lease_until': 1_700_000_010},
                'streams': [{'stream_kind': 'host', 'stream_key': 'beacon', 'last_observed_ts': 1_699_999_900, 'cadence_seconds': 5, 'freshness': {'state': 'stale', 'age_seconds': 105}}],
                'gaps': {'items': [], 'count': 0, 'truncated': False},
                'aggregation_pending': {'items': [{'stream_key': 'host:beacon'}], 'count': 1, 'truncated': False},
                'jobs': [],
            },
            'settings': {
                'sampling': {'metric_sample_seconds': 5},
                'probes': {'full_probe_seconds': 300, 'down_recheck_seconds': 60},
                'discovery_cleanup': {'discovery_timeout_seconds': 60, 'expire_days': 30},
                'retention': {'raw_days': 7, 'five_minute_days': 30, 'retention_days': 90, 'point_budget': 2048},
                'pressure': {'db_max_bytes': None},
                'alerting_enabled': False,
            },
        })
        page = self.browser.new_page(viewport={'width': 360, 'height': 800})

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="pipeline"]').click()
            pipeline = page.locator('#pipeline-section').text_content()
            for copy in (
                '7-day raw', '5-minute through day 30', 'hourly through day 90',
                'Database pressure', 'Worker heartbeat', 'Streams', 'No active collection gaps',
                'Pending aggregation', 'No background jobs are configured',
                'This stream is stale. Its last sample was',
                'The worker heartbeat is fresh, but this stream is stale.',
            ):
                self.assertIn(copy, pipeline)
            page.locator('[data-section="settings"]').click()
            settings = page.locator('#settings-section').text_content()
            self.assertIn('Local presentation preferences', settings)
            self.assertIn('Not configured', settings)
            self.assertIn('Unknown', settings)
            self.assertLessEqual(page.evaluate('document.documentElement.scrollWidth'), 360)
        finally:
            page.close()

    def test_refresh_pause_and_allowlisted_preferences_are_local_and_defensive(self):
        payload = self._snapshot()
        payload.update({'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': []})
        fixture = {'calls': 0}
        page = self.browser.new_page()
        page.add_init_script("""
            localStorage.setItem('beacon-theme', 'light');
            localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify({
              refreshSeconds: 5, paused: true, density: 'comfortable', range: '24h',
              filters: {status: 'fresh'}, snapshot: {secret: 'must-not-restore'}, extra: 'ignored'
            }));
        """)

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                fixture['calls'] += 1
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('#overview-section').wait_for(timeout=5_000)
            self.assertEqual(page.locator('#refresh-interval').input_value(), '5')
            self.assertEqual(page.locator('#pause-updates').text_content(), 'Resume updates')
            self.assertIn('Updates paused', page.locator('#advanced-last-success').text_content())
            self.assertTrue(page.locator('body').evaluate('(node) => node.classList.contains("density-comfortable")'))
            initial_calls = fixture['calls']
            page.locator('#advanced-refresh').click()
            page.wait_for_timeout(100)
            self.assertEqual(fixture['calls'], initial_calls + 1)
            stored = page.evaluate("JSON.parse(localStorage.getItem('beacon-advanced-preferences-v1'))")
            self.assertEqual(set(stored), {'refreshSeconds', 'paused', 'density', 'range', 'filters'})
            self.assertNotIn('snapshot', stored)
        finally:
            page.close()

    def test_corrupt_preferences_use_safe_defaults(self):
        payload = self._snapshot()
        payload.update({'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': []})
        page = self.browser.new_page()
        page.add_init_script("localStorage.setItem('beacon-advanced-preferences-v1', '{not-json');")

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('#overview-section').wait_for(timeout=5_000)
            self.assertEqual(page.locator('#refresh-interval').input_value(), '15')
            self.assertEqual(page.locator('#pause-updates').text_content(), 'Pause updates')
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
