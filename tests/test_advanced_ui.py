import pathlib
import threading
import unittest
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.helpers import cleanup_db, load_app


ROOT = pathlib.Path(__file__).resolve().parents[1]
UI_CONSIDERATIONS = tuple(f'UI-{number:02d}' for number in range(1, 37))


class AdvancedUiTests(unittest.TestCase):
    """Production-route browser coverage for the dependency-free advanced document."""

    @classmethod
    def setUpClass(cls):
        cls.appmod, cls.db_path = load_app({'METRIC_SAMPLE_SECONDS': '5'})
        cls.server = make_server('127.0.0.1', 0, cls.appmod.app, threaded=True)
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
        cleanup_db(cls.db_path)

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

    def test_connection_warning_retains_last_success_and_keeps_server_safety_independent(self):
        healthy = self._snapshot()
        healthy.update({
            'safety': {'worker_stale': False, 'recovery_required': False},
            'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': [],
        })
        unhealthy = self._snapshot()
        unhealthy.update({
            'safety': {'worker_stale': True, 'recovery_required': True},
            'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': [],
        })
        fixture = {'payload': unhealthy, 'fail': False}
        page = self.browser.new_page()

        def route_api(route):
            if urlparse(route.request.url).path != '/api/advanced/current':
                route.fallback()
                return
            if fixture['fail']:
                route.fulfill(status=503, json={'error': 'offline'})
            else:
                route.fulfill(status=200, json=fixture['payload'])

        page.route('**/api/advanced/current', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-testid="host-summary"]').wait_for(timeout=5_000)
            first_success = page.locator('#advanced-last-success').text_content()
            self.assertTrue(page.locator('#worker-warning').is_visible())
            self.assertTrue(page.locator('#recovery-warning').is_visible())
            self.assertFalse(page.locator('#connection-banner').is_visible())

            fixture['fail'] = True
            page.locator('#advanced-refresh').click()
            page.locator('#advanced-refresh-error').wait_for(state='visible', timeout=5_000)
            self.assertTrue(page.locator('#connection-banner').is_visible())
            self.assertTrue(page.locator('#worker-warning').is_visible())
            self.assertTrue(page.locator('#recovery-warning').is_visible())
            self.assertEqual(page.locator('#advanced-last-success').text_content(), first_success)
            self.assertIn('beacon-pi', page.locator('[data-testid="host-summary"]').text_content())

            fixture.update({'fail': False, 'payload': healthy})
            page.locator('#advanced-refresh').click()
            page.locator('#connection-banner').wait_for(state='hidden', timeout=5_000)
            self.assertFalse(page.locator('#worker-warning').is_visible())
            self.assertFalse(page.locator('#recovery-warning').is_visible())
        finally:
            page.close()

    def test_safety_combinations_render_in_approved_order(self):
        for connection, worker, recovery in (
            (False, False, False), (False, False, True), (False, True, False), (False, True, True),
            (True, False, False), (True, False, True), (True, True, False), (True, True, True),
        ):
            with self.subTest(connection=connection, worker=worker, recovery=recovery):
                page = self.browser.new_page()
                fixture = {
                    **self._snapshot(),
                    'safety': {'worker_stale': worker, 'recovery_required': recovery},
                    'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': [],
                }
                page.route(
                    '**/api/advanced/current',
                    lambda route: route.fulfill(status=200, json=fixture),
                )
                try:
                    page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
                    page.locator('[data-testid="host-summary"]').wait_for(timeout=5_000)
                    page.wait_for_timeout(50)
                    if connection:
                        page.unroute('**/api/advanced/current')
                        page.route(
                            '**/api/advanced/current',
                            lambda route: route.fulfill(status=503, json={'error': 'offline'}),
                        )
                        page.locator('#advanced-refresh').click()
                        page.locator('#advanced-refresh-error').wait_for(state='visible', timeout=5_000)
                    expected = [connection, worker, recovery]
                    actual = [
                        page.locator('#connection-banner').is_visible(),
                        page.locator('#worker-warning').is_visible(),
                        page.locator('#recovery-warning').is_visible(),
                    ]
                    self.assertEqual(actual, expected)
                finally:
                    page.close()

    def test_production_routes_serve_the_advanced_document_bundle(self):
        page = self.browser.new_page()
        responses = []
        page.on('response', lambda response: responses.append(response))
        try:
            response = page.goto(f'{self.base_url}/advanced', wait_until='networkidle')
            self.assertEqual(response.status, 200)
            by_path = {urlparse(item.url).path: item for item in responses}
            for path, content_type in (
                ('/advanced', 'text/html'),
                ('/advanced.js', 'application/javascript'),
                ('/advanced.css', 'text/css'),
            ):
                with self.subTest(path=path):
                    asset = by_path[path]
                    self.assertIn(content_type, asset.headers['content-type'])
                    self.assertGreater(len(asset.body()), 0)
                    self.assertEqual(asset.headers['x-frame-options'], 'DENY')
                    self.assertIn("default-src 'self'", asset.headers['content-security-policy'])
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

    def test_services_filters_sort_and_multi_disclosure_contract(self):
        payload = self._snapshot()
        payload.update({
            'exceptions': [],
            'pipeline': {},
            'settings': {},
            'services': [
                {
                    'port': 443,
                    'name': 'Critical gateway with an intentionally long diagnostic name',
                    'status': 'down',
                    'failure_class': 'connection refused',
                    'latency_ms': None,
                    'state_since_ts': 1_699_999_900,
                    'critical': True,
                    'pinned_order': 2,
                    'tags': ['edge', 'critical'],
                    'health_rule': '200-399',
                    'last_probe_ts': 1_700_000_000,
                    'expected_cadence_seconds': 5,
                    'freshness': {'state': 'fresh', 'age_seconds': 5},
                    'tls': {'posture': 'trusted LAN; certificate verification disabled'},
                    'last_error': 'connection refused',
                    'collection_gap': {'state': 'none'},
                },
                {
                    'port': 80,
                    'name': 'Healthy web',
                    'status': 'up',
                    'latency_ms': 12.5,
                    'state_since_ts': 1_699_999_950,
                    'critical': False,
                    'pinned_order': 1,
                    'tags': ['web'],
                    'health_rule': '200-399',
                    'last_probe_ts': 1_700_000_000,
                    'expected_cadence_seconds': 5,
                    'freshness': {'state': 'fresh', 'age_seconds': 5},
                    'tls': {'posture': 'not applicable'},
                    'last_error': None,
                    'collection_gap': {'state': 'none'},
                },
            ],
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
            page.locator('[data-section="services"]').click()
            page.locator('#services-table').wait_for(timeout=5_000)
            self.assertEqual(page.locator('#matching-service-count').text_content(), '2 of 2 services')
            self.assertEqual(page.locator('#services-table tbody > tr.service-row').count(), 2)
            self.assertIn('443', page.locator('#services-table tbody > tr.service-row').first.text_content())
            page.locator('#service-search').fill('web')
            self.assertEqual(page.locator('#matching-service-count').text_content(), '1 of 2 services')
            self.assertEqual(page.locator('#services-table tbody > tr.service-row').count(), 1)
            page.locator('#clear-service-filters').click()
            details = page.locator('.service-details-toggle')
            details.nth(0).click()
            details.nth(1).click()
            self.assertEqual(page.locator('.service-details-toggle[aria-expanded="true"]').count(), 2)
            self.assertTrue(page.locator('#collapse-service-details').is_visible())
            page.locator('#collapse-service-details').click()
            self.assertEqual(page.locator('.service-details-toggle[aria-expanded="true"]').count(), 0)
            page.locator('#service-sort-latency').press('Enter')
            self.assertEqual(page.locator('#service-sort-latency').get_attribute('aria-sort'), 'ascending')
        finally:
            page.close()

    def test_services_source_contract_uses_a_real_table_and_local_only_controls(self):
        html = (ROOT / 'dashboard/advanced.html').read_text(encoding='utf-8')
        js = (ROOT / 'dashboard/advanced.js').read_text(encoding='utf-8')
        css = (ROOT / 'dashboard/advanced.css').read_text(encoding='utf-8')
        for hook in (
            'id="service-search"', 'id="service-status-filter"',
            'id="service-criticality-filter"', 'id="service-freshness-filter"',
            'id="service-tag-filter"', 'id="services-table"',
            'id="matching-service-count"', 'id="clear-service-filters"',
        ):
            self.assertIn(hook, html)
        for function_name in (
            'applyServiceFilters', 'operationalServiceCompare', 'stableServiceSort',
            'renderServices', 'toggleServiceDetails', 'collapseAllDetails',
            'resetOperationalOrder', 'updateMatchingCount',
        ):
            self.assertIn(f'function {function_name}', js)
        self.assertIn('position: sticky', css)
        self.assertIn('@media (max-width: 959px)', css)
        self.assertNotIn('/api/service', js)

    def test_theme_or_return_round_trip_preserves_theme_and_consumes_scroll_once(self):
        payload = self._snapshot()
        payload.update({'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': []})
        page = self.browser.new_page(viewport={'width': 800, 'height': 400})
        page.add_init_script("localStorage.setItem('beacon-theme', 'light');")

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(self.base_url, wait_until='domcontentloaded')
            page.locator('#advanced-diagnosis-link').wait_for(timeout=5_000)
            page.evaluate('window.scrollTo(0, Math.min(120, document.documentElement.scrollHeight))')
            page.locator('#advanced-diagnosis-link').click()
            page.locator('#advanced-dashboard').wait_for(timeout=5_000)
            self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))
            page.locator('#advanced-dashboard').click()
            page.locator('#advanced-diagnosis-link').wait_for(timeout=5_000)
            page.wait_for_timeout(100)
            self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))
            self.assertIsNone(page.evaluate("sessionStorage.getItem('beacon-dashboard-scroll-position')"))
        finally:
            page.close()

    def test_dashboard_navigation_source_contract_is_same_tab_and_tab_local(self):
        html = (ROOT / 'dashboard/index.html').read_text(encoding='utf-8')
        js = (ROOT / 'dashboard/app.js').read_text(encoding='utf-8')
        advanced_html = (ROOT / 'dashboard/advanced.html').read_text(encoding='utf-8')
        self.assertIn('id="advanced-diagnosis-link"', html)
        self.assertIn('href="/advanced"', html)
        self.assertIn('Advanced diagnosis', html)
        self.assertIn('id="advanced-dashboard"', advanced_html)
        self.assertIn('function captureDashboardScroll', js)
        self.assertIn('function restoreDashboardScroll', js)
        self.assertIn("sessionStorage", js)
        self.assertIn("beacon-dashboard-scroll-position", js)
        self.assertNotIn('beacon-dashboard-scroll-position', advanced_html)

    def test_open_stream_gap_renders_as_pipeline_and_overview_evidence(self):
        """A synthesized open-stream gap must replace the false 'reporting normally' claim."""
        gap = {
            'stream_kind': 'host', 'stream_key': 'cpu',
            'start_ts': 1_699_999_900, 'end_ts': 1_700_000_005,
            'reason': 'collection_gap', 'detail': None,
            'open': True, 'actionable': True,
        }
        payload = self._snapshot()
        payload.update({
            'services': [],
            'settings': {},
            'exceptions': [{'kind': 'collection_gap', 'section': 'pipeline', 'priority': 5, **gap}],
            'pipeline': {
                'retention': {}, 'database_pressure': {}, 'worker': {},
                'gaps': {'items': [gap], 'count': 1, 'truncated': False},
                'aggregation_pending': {'items': [], 'count': 0, 'truncated': False},
                'jobs': [],
            },
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
            overview = page.locator('#overview-section').text_content()
            self.assertIn('1 active exception', overview)
            self.assertIn('collection_gap', overview)
            self.assertNotIn('No active exceptions', overview)
            self.assertNotIn(
                'Host, services, and collection pipeline are reporting normally.', overview,
            )
            page.locator('[data-section="pipeline"]').click()
            pipeline = page.locator('#pipeline-section').text_content()
            self.assertIn('Collection gaps (1 gap)', pipeline)
            self.assertIn('host: cpu \u2014 Open actionable gap.', pipeline)
            self.assertNotIn('No active collection gaps', pipeline)
        finally:
            page.close()

    def test_ui_consideration_inventory_is_complete_and_unique(self):
        self.assertEqual(len(UI_CONSIDERATIONS), 36)
        self.assertEqual(len(set(UI_CONSIDERATIONS)), 36)
        self.assertEqual(UI_CONSIDERATIONS, tuple(f'UI-{number:02d}' for number in range(1, 37)))

    def test_breakpoint_boundary_and_accessibility_contract(self):
        payload = self._snapshot()
        payload.update({
            'exceptions': [], 'pipeline': {}, 'settings': {},
            'services': [{'port': 8080, 'name': 'Beacon service', 'availability': 'online', 'latency_ms': 12.25,
                          'state_duration_seconds': 20, 'critical': False, 'pinned_order': 1, 'tags': ['core'],
                          'effective_health_rule': '200-399', 'last_probe_ts': 1_700_000_000,
                          'expected_cadence_seconds': 5, 'freshness': {'state': 'fresh', 'age_seconds': 5},
                          'tls_unverified': True, 'last_error': None, 'collection_gaps': []}],
        })

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        for width, expected_direction in ((960, 'column'), (959, 'row')):
            page = self.browser.new_page(viewport={'width': width, 'height': 800})
            page.route('**/api/**', route_api)
            try:
                page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
                page.locator('[data-section="services"]').click()
                page.locator('#services-table').wait_for(timeout=5_000)
                self.assertEqual(page.locator('#section-navigation').evaluate('(node) => getComputedStyle(node).flexDirection'), expected_direction)
                if width == 959:
                    self.assertEqual(page.locator('.service-identity').evaluate('(node) => getComputedStyle(node).position'), 'sticky')
                self.assertGreaterEqual(page.locator('#service-search').bounding_box()['height'], 44)
                self.assertGreaterEqual(page.locator('.service-row').bounding_box()['height'], 44)
            finally:
                page.close()

        for width, expected_columns in ((720, 3), (719, 1)):
            page = self.browser.new_page(viewport={'width': width, 'height': 800})
            page.route('**/api/**', route_api)
            try:
                page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
                self.assertEqual(
                    page.locator('.summary-grid').evaluate('(node) => getComputedStyle(node).gridTemplateColumns.split(" ").length'),
                    expected_columns,
                )
            finally:
                page.close()

    def test_precision_and_accessible_service_source_contract(self):
        html = (ROOT / 'dashboard/advanced.html').read_text(encoding='utf-8')
        js = (ROOT / 'dashboard/advanced.js').read_text(encoding='utf-8')
        css = (ROOT / 'dashboard/advanced.css').read_text(encoding='utf-8')
        self.assertIn('aria-sort', html)
        self.assertIn('aria-expanded', js)
        self.assertIn('position: sticky', css)
        self.assertIn('@media (max-width: 719px)', css)
        self.assertIn('state_duration_seconds', js)
        self.assertIn('expected_cadence_seconds', js)
        self.assertIn('TLS trust annotation', js)


if __name__ == '__main__':
    unittest.main()
