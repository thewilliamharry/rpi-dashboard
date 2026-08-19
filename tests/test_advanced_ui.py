import pathlib
import threading
import unittest
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.helpers import cleanup_db, load_app


ROOT = pathlib.Path(__file__).resolve().parents[1]
UI_CONSIDERATIONS = tuple(f'UI-{number:02d}' for number in range(1, 37))


def gap_item(port, *, open_gap, detail=None):
    """One composed gap item in the shape the server's per-stream list carries."""
    return {
        'stream_kind': 'service', 'stream_key': str(port),
        'start_ts': 1_699_999_000, 'end_ts': 1_699_999_900,
        'reason': 'collection_gap', 'detail': detail,
        'open': open_gap, 'actionable': open_gap,
    }


def gap_block(evidence, items=()):
    """Build the per-service gap block the server now joins onto every service.

    The count and the open count are derived from the same item list they are
    presented beside, so a fixture can never describe a population it does not
    carry.
    """
    items = list(items)
    return {
        'items': items,
        'count': len(items),
        'open_count': sum(1 for item in items if item.get('open') is True),
        'evidence': evidence,
    }


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
            'schema_version': 3,
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
                {'kind': 'critical_service_offline', 'section': 'services', 'priority': 2,
                 'port': 443, 'name': 'Critical web service'},
                {'kind': 'collection_gap', 'section': 'pipeline', 'priority': 5,
                 'stream_kind': 'host', 'stream_key': 'very-long-stream-' + ('evidence-' * 18),
                 'start_ts': 1_699_999_900, 'end_ts': 1_700_000_005,
                 'reason': 'collection_gap', 'detail': None, 'open': True, 'actionable': True},
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
            self.assertIn('Critical service offline \u2014 Critical web service on port 443', overview)
            self.assertIn('Open collection gap \u2014 host: very-long-stream-', overview)
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
                'streams': {
                    'items': [{'stream_kind': 'host', 'stream_key': 'beacon', 'last_observed_ts': 1_699_999_900, 'cadence_seconds': 5, 'freshness': {'state': 'stale', 'age_seconds': 105}}],
                    'count': 1, 'truncated': False,
                },
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
                'Database pressure', 'Worker heartbeat', 'Streams (1 stream)', 'No active collection gaps',
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
                    'collection_gaps': gap_block(
                        'possibly_incomplete', [gap_item(443, open_gap=True)],
                    ),
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
                    'collection_gaps': gap_block('complete'),
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
            self.assertIn('Open collection gap \u2014 host: cpu', overview)
            self.assertNotIn('collection_gap', overview)
            self.assertNotIn('Unknown evidence', overview)
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

    def test_resolved_history_never_renders_as_an_open_collection_gap(self):
        """Resolved and retention-expired intervals must read as history, never as open faults."""
        open_gap = {
            'stream_kind': 'host', 'stream_key': 'cpu',
            'start_ts': 1_699_999_900, 'end_ts': 1_700_000_005,
            'reason': 'collection_gap', 'detail': None,
            'open': True, 'actionable': True,
        }
        resolved_gap = {
            'stream_kind': 'host', 'stream_key': 'cpu',
            'start_ts': 1_697_400_000, 'end_ts': 1_697_400_600,
            'reason': 'collection_gap', 'detail': 'resolved-30-days-ago',
            'open': False, 'actionable': False,
        }
        payload = self._snapshot()
        payload.update({
            'services': [],
            'settings': {},
            'exceptions': [
                {'kind': 'collection_gap', 'section': 'pipeline', 'priority': 5, **open_gap},
            ],
            'pipeline': {
                'retention': {}, 'database_pressure': {}, 'worker': {},
                'gaps': {'items': [open_gap, resolved_gap], 'count': 2, 'truncated': False},
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
            self.assertNotIn('2 active exceptions', overview)
            page.locator('[data-section="pipeline"]').click()
            pipeline = page.locator('#pipeline-section').text_content()
            self.assertIn('Collection gaps (2 gaps)', pipeline)
            self.assertIn('host: cpu \u2014 Open actionable gap.', pipeline)
            self.assertIn('host: cpu \u2014 Resolved historical gap.', pipeline)
            self.assertEqual(
                pipeline.count('Open actionable gap.'), 1,
            )
        finally:
            page.close()

    def test_stream_truncation_and_host_exception_replace_the_normal_claim(self):
        """A capped stream read and a stale host must both be disclosed, never summarised as normal."""
        payload = self._snapshot()
        payload.update({
            'services': [],
            'settings': {},
            'exceptions': [
                {'kind': 'host_freshness', 'section': 'host', 'priority': 1, 'state': 'stale'},
            ],
            'pipeline': {
                'retention': {}, 'database_pressure': {}, 'worker': {},
                'streams': {
                    'items': [
                        {'stream_kind': 'host', 'stream_key': 'cpu', 'last_observed_ts': 1_700_000_000,
                         'cadence_seconds': 5, 'freshness': {'state': 'fresh', 'age_seconds': 5}},
                        {'stream_kind': 'host', 'stream_key': 'ram', 'last_observed_ts': 1_700_000_000,
                         'cadence_seconds': 5, 'freshness': {'state': 'fresh', 'age_seconds': 5}},
                    ],
                    'count': 2, 'truncated': True,
                },
                'gaps': {'items': [], 'count': 0, 'truncated': False},
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
            self.assertIn('Host evidence is stale', overview)
            self.assertNotIn('host_freshness', overview)
            self.assertNotIn('Unknown evidence', overview)
            self.assertNotIn('No active exceptions', overview)
            self.assertNotIn(
                'Host, services, and collection pipeline are reporting normally.', overview,
            )
            page.locator('[data-section="pipeline"]').click()
            pipeline = page.locator('#pipeline-section').text_content()
            self.assertIn('Streams (2 streams, truncated)', pipeline)
            self.assertIn('host: cpu', pipeline)
            self.assertIn('host: ram', pipeline)
            self.assertNotIn('No pipeline streams are configured', pipeline)
        finally:
            page.close()

    # Every kind compose_active_exceptions can emit, with exactly the fields
    # each one carries. Kept beside the renderer regressions so a new server
    # kind that arrives without operator copy fails here.
    EMITTED_EXCEPTIONS = (
        {'kind': 'recovery_required', 'section': 'pipeline', 'priority': 0},
        {'kind': 'host_freshness', 'section': 'host', 'priority': 1, 'state': 'stale'},
        {'kind': 'worker_freshness', 'section': 'pipeline', 'priority': 1, 'state': 'unknown'},
        {'kind': 'critical_service_offline', 'section': 'services', 'priority': 2,
         'port': 443, 'name': 'Critical gateway'},
        {'kind': 'service_offline', 'section': 'services', 'priority': 3,
         'port': 8080, 'name': 'Media server'},
        {'kind': 'service_freshness', 'section': 'services', 'priority': 4,
         'port': 9090, 'state': 'stale'},
        {'kind': 'collection_gap', 'section': 'pipeline', 'priority': 5,
         'stream_kind': 'host', 'stream_key': 'cpu',
         'start_ts': 1_699_999_900, 'end_ts': 1_700_000_005,
         'reason': 'collection_gap', 'detail': None, 'open': True, 'actionable': True},
        {'kind': 'coverage_unknown', 'section': 'pipeline', 'priority': 5,
         'stream_kind': 'host', 'stream_key': 'ram',
         'start_ts': 1_699_998_000, 'end_ts': 1_699_999_000,
         'reason': 'indeterminate', 'detail': None, 'open': False, 'actionable': True},
        {'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, 'job_id': 'J8-cleanup'},
        {'kind': 'database_pressure', 'section': 'pipeline', 'priority': 7},
    )

    def _overview_page(self, exceptions):
        payload = self._snapshot()
        payload.update({
            'services': [], 'settings': {},
            'pipeline': {
                'retention': {}, 'database_pressure': {}, 'worker': {},
                'gaps': {'items': [], 'count': 0, 'truncated': False},
                'aggregation_pending': {'items': [], 'count': 0, 'truncated': False},
                'jobs': [],
            },
            'exceptions': exceptions,
        })
        page = self.browser.new_page(viewport={'width': 959, 'height': 800})

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('#overview-section').wait_for(timeout=5_000)
        return page

    def test_every_emitted_exception_kind_renders_operator_copy(self):
        """Each server kind must read as a sentence naming its host, service, stream or job."""
        page = self._overview_page(list(self.EMITTED_EXCEPTIONS))
        try:
            cards = page.locator('#overview-content > section article.diagnosis-card')
            overview = page.locator('#overview-section').text_content()
            self.assertIn('10 active exceptions', overview)
            self.assertEqual(cards.count(), len(self.EMITTED_EXCEPTIONS))
            headings = [
                cards.nth(index).locator('h3').text_content()
                for index in range(cards.count())
            ]
            bare_kinds = {item['kind'] for item in self.EMITTED_EXCEPTIONS}
            for heading in headings:
                with self.subTest(heading=heading):
                    self.assertNotIn(heading, bare_kinds)
                    self.assertNotEqual(heading.strip(), '')
            for expected in (
                'Database recovery required',
                'Host evidence is stale',
                'Worker heartbeat is unknown',
                'Critical service offline \u2014 Critical gateway on port 443',
                'Service offline \u2014 Media server on port 8080',
                'Service evidence is stale \u2014 port 9090',
                'Open collection gap \u2014 host: cpu',
                'Coverage could not be determined \u2014 host: ram',
                'Background job failed \u2014 J8-cleanup',
                'Database pressure is not normal',
            ):
                with self.subTest(expected=expected):
                    self.assertIn(expected, headings)
            self.assertNotIn('Unknown evidence', overview)
            self.assertNotIn('Unknown exception', overview)
            self.assertNotIn('Unrecognised exception', overview)
            for item in self.EMITTED_EXCEPTIONS:
                with self.subTest(kind=item['kind']):
                    self.assertNotIn(item['kind'], overview)
            bodies = [
                cards.nth(index).locator('p').first.text_content()
                for index in range(cards.count())
            ]
            for body in bodies:
                with self.subTest(body=body):
                    self.assertNotEqual(body.strip(), '')
                    self.assertNotIn('Unknown evidence', body)
        finally:
            page.close()

    def test_indeterminate_coverage_exception_is_never_worded_as_a_failure(self):
        """coverage_unknown states that coverage is undetermined, never that collection failed."""
        page = self._overview_page([
            item for item in self.EMITTED_EXCEPTIONS if item['kind'] == 'coverage_unknown'
        ])
        try:
            card = page.locator('#overview-content > section article.diagnosis-card').first
            heading = card.locator('h3').text_content()
            body = card.locator('p').first.text_content()
            self.assertIn('Coverage could not be determined', heading)
            self.assertIn('host: ram', heading)
            self.assertIn('could not determine coverage', body)
            for forbidden in ('gap', 'fail', 'lost', 'missing'):
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden, f'{heading} {body}'.lower())
        finally:
            page.close()

    def test_unrecognised_exception_kind_still_renders_and_is_counted(self):
        """A kind the page has never seen must be visible, counted, and non-fatal."""
        page = self._overview_page([
            {'kind': 'host_freshness', 'section': 'host', 'priority': 1, 'state': 'stale'},
            {'kind': 'quantum_flux', 'section': 'pipeline', 'priority': 9,
             'detail': 'server-supplied evidence'},
        ])
        try:
            cards = page.locator('#overview-content > section article.diagnosis-card')
            overview = page.locator('#overview-section').text_content()
            self.assertIn('2 active exceptions', overview)
            self.assertEqual(cards.count(), 2)
            self.assertIn('Unrecognised exception \u2014 quantum_flux', overview)
            self.assertIn('quantum_flux', overview)
            self.assertIn('Host evidence is stale', overview)
            self.assertNotIn('No active exceptions', overview)
            self.assertNotIn('Unknown evidence', overview)
        finally:
            page.close()

    def test_refresh_error_names_the_server_supplied_reason(self):
        """A non-ok JSON body carrying an error must not read as a connection problem alone."""
        payload = self._snapshot()
        payload.update({'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': []})
        fixture = {'fail': False}
        page = self.browser.new_page()

        def route_api(route):
            if urlparse(route.request.url).path != '/api/advanced/current':
                route.fallback()
            elif fixture['fail']:
                route.fulfill(status=503, json={'error': 'scheduled maintenance in progress'})
            else:
                route.fulfill(status=200, json=payload)

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-testid="host-summary"]').wait_for(timeout=5_000)
            fixture['fail'] = True
            page.locator('#advanced-refresh').click()
            page.locator('#advanced-refresh-error').wait_for(state='visible', timeout=5_000)
            message = page.locator('#advanced-refresh-error').text_content()
            self.assertIn('Beacon could not refresh current diagnosis.', message)
            self.assertIn('Check the connection warning, then try again.', message)
            self.assertIn('scheduled maintenance in progress', message)
        finally:
            page.close()

    # Sort is session-local memory state (D-14 does not persist it), so these
    # fixtures set only the documented preference keys and never a sort.
    SORTABLE_SERVICES = (
        {
            'port': 443, 'name': 'Critical gateway', 'status': 'down',
            'failure_class': 'connection refused', 'latency_ms': None,
            'state_duration_seconds': 900, 'critical': True, 'pinned_order': 2,
            'tags': ['edge'], 'effective_health_rule': '200-399',
            'last_probe_ts': 1_700_000_000, 'expected_cadence_seconds': 5,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'tls': {'posture': 'not applicable'}, 'last_error': 'connection refused',
            'collection_gaps': gap_block('complete', [gap_item(443, open_gap=True)]),
        },
        {
            'port': 80, 'name': 'Healthy web', 'status': 'up', 'latency_ms': 12.5,
            'state_duration_seconds': 60, 'critical': False, 'pinned_order': 1,
            'tags': ['web'], 'effective_health_rule': '200-399',
            'last_probe_ts': 1_700_000_000, 'expected_cadence_seconds': 5,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'tls': {'posture': 'not applicable'}, 'last_error': None,
            'collection_gaps': gap_block('absent'),
        },
    )

    def _sortable_services_page(self, refresh_seconds=5):
        counter = {'value': 0}
        page = self.browser.new_page(viewport={'width': 959, 'height': 800})
        page.add_init_script(
            "localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify("
            f"{{refreshSeconds: {refresh_seconds}, paused: false, density: null, "
            "range: '24h', filters: {}}))"
        )

        def route_api(route):
            if urlparse(route.request.url).path != '/api/advanced/current':
                route.fallback()
                return
            counter['value'] += 1
            payload = self._snapshot()
            payload['generated_ts'] = 1_700_000_005 + counter['value'] * 60
            payload.update({
                'exceptions': [], 'pipeline': {}, 'settings': {},
                'services': [dict(service) for service in self.SORTABLE_SERVICES],
            })
            route.fulfill(status=200, json=payload)

        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="services"]').click()
        page.locator('#services-table').wait_for(timeout=5_000)
        return page

    @staticmethod
    def _first_service_row(page):
        return page.locator('#services-table tbody > tr.service-row').first.text_content()

    @staticmethod
    def _await_new_snapshot(page, prior):
        page.wait_for_function(
            "(prior) => document.getElementById('advanced-last-success').textContent !== prior",
            arg=prior, timeout=15_000,
        )

    def test_service_sort_survives_automatic_poll_and_manual_refresh(self):
        """An automatic poll must never discard the operator's chosen presentation order."""
        page = self._sortable_services_page()
        try:
            self.assertIn('443', self._first_service_row(page))
            page.locator('#service-sort-duration').click()
            self.assertEqual(page.locator('#service-sort-duration').get_attribute('aria-sort'), 'ascending')
            self.assertIn(':80', self._first_service_row(page))
            self.assertTrue(page.locator('#reset-service-order').is_visible())

            prior = page.locator('#advanced-last-success').text_content()
            self._await_new_snapshot(page, prior)
            self.assertIn(':80', self._first_service_row(page))
            self.assertEqual(page.locator('#service-sort-duration').get_attribute('aria-sort'), 'ascending')
            self.assertTrue(page.locator('#reset-service-order').is_visible())

            prior = page.locator('#advanced-last-success').text_content()
            page.locator('#advanced-refresh').click()
            self._await_new_snapshot(page, prior)
            self.assertIn(':80', self._first_service_row(page))
            self.assertEqual(page.locator('#service-sort-duration').get_attribute('aria-sort'), 'ascending')
            self.assertTrue(page.locator('#reset-service-order').is_visible())

            page.locator('#service-sort-duration').click()
            self.assertEqual(page.locator('#service-sort-duration').get_attribute('aria-sort'), 'descending')
            self.assertIn('443', self._first_service_row(page))
        finally:
            page.close()

    def test_deliberate_controls_still_clear_the_service_sort(self):
        """Reset operational order and Clear all filters remain the only clearing paths."""
        page = self._sortable_services_page(refresh_seconds=60)
        try:
            page.locator('#service-sort-duration').click()
            self.assertIn(':80', self._first_service_row(page))
            page.locator('#reset-service-order').click()
            self.assertIn('443', self._first_service_row(page))
            self.assertEqual(page.locator('#service-sort-duration').get_attribute('aria-sort'), 'none')
            self.assertFalse(page.locator('#reset-service-order').is_visible())

            page.locator('#service-sort-duration').click()
            self.assertIn(':80', self._first_service_row(page))
            page.locator('#clear-service-filters').click()
            self.assertIn('443', self._first_service_row(page))
            self.assertEqual(page.locator('#service-sort-duration').get_attribute('aria-sort'), 'none')
            self.assertFalse(page.locator('#reset-service-order').is_visible())

            stored = page.evaluate("localStorage.getItem('beacon-advanced-preferences-v1')")
            self.assertNotIn('serviceSort', stored)
            self.assertNotIn('sort', stored)
        finally:
            page.close()

    # An absent measurement and a real zero must stay distinguishable: the server
    # sets latency_ms=None for every non-online service by construction, so these
    # fixtures carry both an unmeasured service and a genuine zero measurement.
    UNMEASURED_SERVICES = (
        {
            'port': 9090, 'name': 'Broken service', 'status': 'down',
            'failure_class': 'ConnectionRefused', 'latency_ms': None,
            'state_duration_seconds': None, 'critical': True, 'pinned_order': 1,
            'tags': ['edge'], 'effective_health_rule': '200-399',
            'last_probe_ts': 1_700_000_000, 'expected_cadence_seconds': 5,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'tls': {'posture': 'not applicable'}, 'last_error': 'connection refused',
            'collection_gaps': gap_block('not_established'),
        },
        {
            'port': 7070, 'name': 'Unknown service', 'status': 'unknown',
            'failure_class': None, 'latency_ms': None,
            'state_duration_seconds': None, 'critical': False, 'pinned_order': 2,
            'tags': ['lan'], 'effective_health_rule': '200-399',
            'last_probe_ts': 1_700_000_000, 'expected_cadence_seconds': 5,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'tls': {'posture': 'not applicable'}, 'last_error': None,
            'collection_gaps': gap_block('absent'),
        },
        {
            'port': 8080, 'name': 'Fast service', 'status': 'up',
            'failure_class': None, 'latency_ms': 12,
            'state_duration_seconds': 60, 'critical': False, 'pinned_order': 3,
            'tags': ['web'], 'effective_health_rule': '200-399',
            'last_probe_ts': 1_700_000_000, 'expected_cadence_seconds': 5,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'tls': {'posture': 'not applicable'}, 'last_error': None,
            'collection_gaps': gap_block('complete', [
                gap_item(8080, open_gap=True), gap_item(8080, open_gap=False, detail='closed'),
            ]),
        },
        {
            'port': 8081, 'name': 'Instant service', 'status': 'up',
            'failure_class': None, 'latency_ms': 0,
            'state_duration_seconds': 30, 'critical': False, 'pinned_order': 4,
            'tags': ['web'], 'effective_health_rule': '200-399',
            'last_probe_ts': 1_700_000_000, 'expected_cadence_seconds': 5,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'tls': {'posture': 'not applicable'}, 'last_error': None,
            'collection_gaps': gap_block('complete'),
        },
    )

    def _unmeasured_services_page(self, refresh_seconds=5):
        counter = {'value': 0}
        page = self.browser.new_page(viewport={'width': 959, 'height': 800})
        page.add_init_script(
            "localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify("
            f"{{refreshSeconds: {refresh_seconds}, paused: false, density: null, "
            "range: '24h', filters: {}}))"
        )

        def route_api(route):
            if urlparse(route.request.url).path != '/api/advanced/current':
                route.fallback()
                return
            counter['value'] += 1
            payload = self._snapshot()
            payload['generated_ts'] = 1_700_000_005 + counter['value'] * 60
            payload.update({
                'exceptions': [], 'pipeline': {}, 'settings': {},
                'services': [dict(service) for service in self.UNMEASURED_SERVICES],
            })
            route.fulfill(status=200, json=payload)

        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="services"]').click()
        page.locator('#services-table').wait_for(timeout=5_000)
        return page

    @staticmethod
    def _service_row_cells(page, port):
        """Read one live service row's cells from the DOM, located by its port."""
        row = page.locator('#services-table tbody > tr.service-row').filter(
            has=page.locator('.service-port', has_text=f':{port}'),
        )
        cells = row.locator('th, td')
        return [cells.nth(index).text_content() for index in range(cells.count())]

    @classmethod
    def _service_latency_cell(cls, page, port):
        return cls._service_row_cells(page, port)[2]

    @classmethod
    def _service_duration_cell(cls, page, port):
        return cls._service_row_cells(page, port)[3]

    @staticmethod
    def _service_port_order(page):
        rows = page.locator('#services-table tbody > tr.service-row')
        return [
            rows.nth(index).locator('.service-port').text_content().lstrip(':')
            for index in range(rows.count())
        ]

    def test_unmeasured_service_shows_its_failure_class_instead_of_a_fabricated_latency(self):
        """A latency the server never sent must never reach the operator as a number."""
        page = self._unmeasured_services_page()
        try:
            self.assertEqual(page.locator('#services-table tbody > tr.service-row').count(), 4)
            self.assertIn('ConnectionRefused', self._service_latency_cell(page, 9090))
            unknown_cell = self._service_latency_cell(page, 7070)
            self.assertEqual(unknown_cell, 'Unknown')
            self.assertNotRegex(unknown_cell, r'\d')
            self.assertEqual(self._service_latency_cell(page, 8080), '12 ms')
            self.assertEqual(self._service_latency_cell(page, 8081), '0 ms')
        finally:
            page.close()

    def test_unmeasured_latency_and_duration_never_rank_or_read_as_zero(self):
        """An unmeasured latency is deliberately ranked as an extreme in both directions.

        Ascending it sorts after every real measurement and descending it sorts before
        them, exactly as the existing state-duration sort treats an unknown duration.
        It is never ranked as zero, because zero is a measurement the server can send
        and an absent value is not. A state duration the server never established
        reads `Unknown duration` rather than `0 seconds` for the same reason.
        """
        page = self._unmeasured_services_page()
        try:
            page.locator('#service-sort-latency').click()
            self.assertEqual(page.locator('#service-sort-latency').get_attribute('aria-sort'), 'ascending')
            self.assertEqual(self._service_port_order(page), ['8081', '8080', '9090', '7070'])

            page.locator('#service-sort-latency').click()
            self.assertEqual(page.locator('#service-sort-latency').get_attribute('aria-sort'), 'descending')
            self.assertEqual(self._service_port_order(page)[:2], ['9090', '7070'])

            self.assertEqual(self._service_duration_cell(page, 9090), 'Unknown duration')
            self.assertEqual(self._service_duration_cell(page, 7070), 'Unknown duration')
            measured_duration = self._service_duration_cell(page, 8080)
            self.assertNotEqual(measured_duration, 'Unknown duration')
            self.assertIn('minutes', measured_duration)

            prior = page.locator('#advanced-last-success').text_content()
            self._await_new_snapshot(page, prior)
            self.assertEqual(page.locator('#service-sort-latency').get_attribute('aria-sort'), 'descending')
            self.assertTrue(page.locator('#reset-service-order').is_visible())
            self.assertEqual(self._service_port_order(page)[:2], ['9090', '7070'])
        finally:
            page.close()

    @classmethod
    def _gap_evidence_services(cls):
        """Cover every branch of the per-service gap-evidence formatter.

        A raw container must never reach the operator, and an absence the server
        never established must read differently from one it derived.
        """
        def service(port, name, block, omit=False):
            row = {
                'port': port, 'name': name, 'status': 'up', 'latency_ms': 5,
                'state_duration_seconds': 60, 'critical': False, 'pinned_order': port,
                'tags': ['gap'], 'effective_health_rule': '200-399',
                'last_probe_ts': 1_700_000_000, 'expected_cadence_seconds': 5,
                'freshness': {'state': 'fresh', 'age_seconds': 5},
                'tls': {'posture': 'not applicable'}, 'last_error': None,
            }
            if not omit:
                row['collection_gaps'] = block
            return row

        return (
            service(9001, 'Never established', {
                'items': [], 'count': 0, 'open_count': 0, 'evidence': 'not_established',
            }),
            service(9002, 'Derivably absent', {
                'items': [], 'count': 0, 'open_count': 0, 'evidence': 'absent',
            }),
            service(9003, 'Complete and empty', {
                'items': [], 'count': 0, 'open_count': 0, 'evidence': 'complete',
            }),
            service(9004, 'Exactly one gap', {
                'items': [gap_item(9004, open_gap=True, detail=None)],
                'count': 1, 'open_count': 1, 'evidence': 'complete',
            }),
            service(9005, 'Several gaps', {
                'items': [
                    gap_item(9005, open_gap=True, detail=None),
                    gap_item(9005, open_gap=True, detail='second'),
                    gap_item(9005, open_gap=False, detail='closed'),
                ],
                'count': 3, 'open_count': 2, 'evidence': 'complete',
            }),
            service(9006, 'Possibly incomplete', {
                'items': [
                    gap_item(9006, open_gap=True, detail=None),
                    gap_item(9006, open_gap=False, detail='closed'),
                ],
                'count': 2, 'open_count': 1, 'evidence': 'possibly_incomplete',
            }),
            service(9007, 'Block omitted', None, omit=True),
            service(9008, 'Legacy container', []),
        )

    def _gap_evidence_page(self):
        page = self.browser.new_page(viewport={'width': 959, 'height': 800})
        payload = self._snapshot()
        payload.update({
            'exceptions': [], 'pipeline': {}, 'settings': {},
            'services': list(self._gap_evidence_services()),
        })

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="services"]').click()
        page.locator('#services-table').wait_for(timeout=5_000)
        return page

    @staticmethod
    def _service_detail_evidence(page, port, label):
        """Read one expanded detail row's evidence value from the live DOM."""
        row = page.locator(f'#service-detail-{port} .evidence-row').filter(
            has=page.locator('strong', has_text=f'{label}: '),
        )
        return row.locator('span').text_content()

    def test_service_detail_gap_evidence_reads_as_operator_copy(self):
        """The operator reads a sentence about gap evidence, never a data structure.

        Singular and plural count copy follow the same rule the Pipeline
        collection-gaps region already uses, and a state the server never
        established reads differently from an absence it derived.
        """
        page = self._gap_evidence_page()
        try:
            self.assertEqual(page.locator('#services-table tbody > tr.service-row').count(), 8)
            toggles = page.locator('.service-details-toggle')
            for index in range(toggles.count()):
                toggles.nth(index).click()
            self.assertEqual(page.locator('.service-details-toggle[aria-expanded="true"]').count(), 8)

            expected = {
                9001: 'Gap evidence unavailable',
                9002: 'No gap evidence',
                9003: 'No gap evidence',
                9004: '1 gap (1 open)',
                9005: '3 gaps (2 open)',
                9006: '2 gaps (1 open); more gap evidence may exist',
                9007: 'Gap evidence unavailable',
                9008: 'Gap evidence unavailable',
            }
            rendered = {
                port: self._service_detail_evidence(page, port, 'Collection-gap evidence')
                for port in expected
            }
            self.assertEqual(rendered, expected)

            # No serialized container may reach the operator on this surface.
            for port, line in rendered.items():
                with self.subTest(port=port):
                    self.assertNotRegex(line, r'[\[\]{}"]')

            # A malformed or absent block must never blank the table.
            self.assertEqual(page.locator('#services-table tbody > tr.service-row').count(), 8)
            self.assertEqual(
                self._service_detail_evidence(page, 9008, 'Complete service name'),
                'Legacy container',
            )
        finally:
            page.close()

    def test_unknown_section_value_never_blanks_the_workspace(self):
        """A server section with no matching heading must not hide every section."""
        payload = self._snapshot()
        payload.update({
            'services': [], 'pipeline': {}, 'settings': {},
            'exceptions': [
                {'kind': 'host_freshness', 'section': 'nowhere', 'priority': 1, 'state': 'stale'},
                {'kind': 'worker_freshness', 'section': 'host', 'priority': 1, 'state': 'stale'},
            ],
        })
        page = self.browser.new_page(viewport={'width': 959, 'height': 800})
        errors = []
        page.on('pageerror', lambda failure: errors.append(str(failure)))

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=payload)
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('#overview-section').wait_for(timeout=5_000)
            page.locator('#overview-content > section a:has-text("View nowhere")').click()
            page.wait_for_timeout(250)
            self.assertEqual(errors, [])
            self.assertTrue(page.locator('#overview-section').is_visible())
            self.assertTrue(page.locator('#overview-content').is_visible())
            self.assertIn('2 active exceptions', page.locator('#overview-section').text_content())
            self.assertEqual(
                page.locator('#section-navigation button[aria-selected="true"]').text_content(),
                'Overview',
            )

            page.locator('#overview-content > section a:has-text("View host")').click()
            page.locator('#host-section').wait_for(state='visible', timeout=5_000)
            self.assertFalse(page.locator('#overview-section').is_visible())
            self.assertEqual(page.locator('#host-heading').evaluate('(node) => document.activeElement === node'), True)
            self.assertEqual(errors, [])
        finally:
            page.close()

    # Test-owned instrumentation: holds only the first in-flight request so a
    # slower older refresh can be released after a faster newer one has applied.
    REVERSE_ORDER_HARNESS = """
        localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify({
          refreshSeconds: 60, paused: true, density: null, range: '24h', filters: {}
        }));
        window.__heldReleases = [];
        window.__fetchCount = 0;
        const realFetch = window.fetch.bind(window);
        window.fetch = (...args) => {
          const index = window.__fetchCount++;
          const pending = realFetch(...args);
          if (index !== 0) return pending;
          return new Promise((resolve, reject) => {
            window.__heldReleases.push(() => pending.then(resolve, reject));
          });
        };
    """

    def test_reverse_order_refresh_success_never_regresses_newer_evidence(self):
        """A slower older success must never overwrite already-applied newer evidence."""
        older = self._snapshot()
        older['generated_ts'] = 1_700_000_001
        older['host']['identity']['hostname'] = 'beacon-older'
        older['host']['freshness'] = {'state': 'stale', 'age_seconds': 900}
        older.update({
            'services': [], 'pipeline': {}, 'settings': {},
            'safety': {'worker_stale': True, 'recovery_required': False},
            'exceptions': [
                {'kind': 'host_freshness', 'section': 'host', 'priority': 1, 'state': 'stale'},
            ],
        })
        newer = self._snapshot()
        newer['generated_ts'] = 1_700_009_000
        newer['host']['identity']['hostname'] = 'beacon-newer'
        newer.update({
            'services': [], 'pipeline': {}, 'settings': {},
            'safety': {'worker_stale': False, 'recovery_required': False},
            'exceptions': [],
        })
        fixture = {'payload': older}
        page = self.browser.new_page()
        page.add_init_script(self.REVERSE_ORDER_HARNESS)

        def route_api(route):
            if urlparse(route.request.url).path == '/api/advanced/current':
                route.fulfill(status=200, json=fixture['payload'])
            else:
                route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.wait_for_function('window.__heldReleases.length === 1', timeout=5_000)
            fixture['payload'] = newer
            page.locator('#advanced-refresh').click()
            page.locator('[data-testid="host-summary"]').wait_for(timeout=5_000)
            self.assertIn('beacon-newer', page.locator('[data-testid="host-summary"]').text_content())
            newer_success = page.locator('#advanced-last-success').text_content()
            self.assertFalse(page.locator('#worker-warning').is_visible())

            page.evaluate('window.__heldReleases.forEach((release) => release())')
            page.wait_for_timeout(250)

            self.assertIn('beacon-newer', page.locator('[data-testid="host-summary"]').text_content())
            self.assertNotIn('beacon-older', page.locator('#overview-section').text_content())
            self.assertEqual(page.locator('#advanced-last-success').text_content(), newer_success)
            self.assertIn('No active exceptions', page.locator('#overview-section').text_content())
            self.assertFalse(page.locator('#worker-warning').is_visible())
            self.assertEqual(page.evaluate('window.__fetchCount'), 2)
        finally:
            page.close()

    def test_reverse_order_refresh_failure_never_raises_a_superseded_warning(self):
        """A slower older failure must never flip the connection or refresh-error evidence."""
        newer = self._snapshot()
        newer['generated_ts'] = 1_700_009_000
        newer['host']['identity']['hostname'] = 'beacon-newer'
        newer.update({
            'services': [], 'pipeline': {}, 'settings': {},
            'safety': {'worker_stale': False, 'recovery_required': False},
            'exceptions': [],
        })
        fixture = {'fail': True}
        page = self.browser.new_page()
        page.add_init_script(self.REVERSE_ORDER_HARNESS)

        def route_api(route):
            if urlparse(route.request.url).path != '/api/advanced/current':
                route.fallback()
            elif fixture['fail']:
                route.fulfill(status=503, json={'error': 'offline'})
            else:
                route.fulfill(status=200, json=newer)

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.wait_for_function('window.__heldReleases.length === 1', timeout=5_000)
            fixture['fail'] = False
            page.locator('#advanced-refresh').click()
            page.locator('[data-testid="host-summary"]').wait_for(timeout=5_000)
            newer_success = page.locator('#advanced-last-success').text_content()

            page.evaluate('window.__heldReleases.forEach((release) => release())')
            page.wait_for_timeout(250)

            self.assertFalse(page.locator('#connection-banner').is_visible())
            self.assertFalse(page.locator('#advanced-refresh-error').is_visible())
            self.assertIn('beacon-newer', page.locator('[data-testid="host-summary"]').text_content())
            self.assertEqual(page.locator('#advanced-last-success').text_content(), newer_success)
        finally:
            page.close()

    def test_refresh_generation_guard_is_declared_in_the_advanced_controller(self):
        """The ordering guard is memory-only state applied on both refresh branches."""
        js = (ROOT / 'dashboard/advanced.js').read_text(encoding='utf-8')
        self.assertIn('requestGeneration: 0', js)
        self.assertIn('const requestId = ++state.requestGeneration;', js)
        self.assertEqual(js.count('if (requestId !== state.requestGeneration) return;'), 2)
        self.assertNotIn('AbortController', js)
        self.assertEqual(js.count("fetch('/api/advanced/current'"), 1)

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
                          'tls_unverified': True, 'last_error': None,
                          'collection_gaps': gap_block(
                              'possibly_incomplete', [gap_item(8080, open_gap=False)],
                          )}],
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
