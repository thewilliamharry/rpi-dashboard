import json
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
        self.assertIn("textContent: 'TLS'", self.js)
        self.assertIn('TLS certificate is not verified for this trusted local service.', self.js)
        self.assertIn("textContent: 'Edit'", self.js)
        self.assertIn("edit.setAttribute('aria-label', 'Edit service')", self.js)

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

    @staticmethod
    def _service_meta(port, *, windows=None, display_name='', critical=False, tags=None, healthy_statuses='200-399', suggestion=None):
        return {
            'port': port, 'display_name': display_name, 'url': f'http://127.0.0.1:{port}',
            'path': '/', 'critical': critical, 'pinned_order': port,
            'tags': tags or [], 'healthy_statuses': healthy_statuses,
            'windows': windows or [], 'suggestion': suggestion,
        }

    @staticmethod
    def _event(*, ts, event_type='state_change', online=None, previous_online=None,
               service_name='Service', suppressed_reason=None, details=None,
               down_since_ts=None, error_class=None):
        return {
            'event_type': event_type, 'ts': ts, 'online': online,
            'previous_online': previous_online, 'service_name': service_name,
            'suppressed_reason': suppressed_reason, 'details': details,
            'down_since_ts': down_since_ts, 'error_class': error_class,
            'maintenance_grace_until': None,
        }

    @staticmethod
    def _overrun_event(*, ts, down_since_ts, service_name='Service'):
        return {
            'event_type': 'maintenance_overrun', 'ts': ts, 'online': None,
            'previous_online': None, 'service_name': service_name,
            'suppressed_reason': None,
            'details': 'Down since 2024-01-01 00:00 UTC; window and grace expired at 2024-01-01 01:00 UTC.',
            'down_since_ts': down_since_ts, 'error_class': None,
            'maintenance_grace_until': None,
        }

    def _maintenance_route(self, fixture):
        """Build a route handler stubbing /api/service-meta/<port> GET/PUT for the maintenance editor tests."""
        def route_api(route):
            path = urlparse(route.request.url).path
            method = route.request.method
            if path.startswith('/api/service-meta/'):
                port = int(path.rsplit('/', 1)[-1])
                if method == 'GET' and fixture.get('get_error'):
                    route.fulfill(status=500, json={'error': 'boom'})
                    return
                if method == 'PUT':
                    fixture.setdefault('put_calls', []).append({'port': port, 'body': None})
                    put_error = fixture.get('put_error')
                    if put_error:
                        route.fulfill(status=put_error.get('status', 400), json={'error': put_error['message']})
                        return
                    body = json.loads(route.request.post_data or '{}')
                    fixture['put_calls'][-1]['body'] = body
                    meta = dict(fixture['service_meta'].get(port) or self._service_meta(port))
                    meta['windows'] = body.get('maintenance_windows', [])
                    meta['preview_queued'] = True
                    fixture['service_meta'][port] = meta
                    route.fulfill(status=200, json=meta)
                    return
                meta = fixture['service_meta'].get(port) or self._service_meta(port)
                route.fulfill(status=200, json=meta)
                return
            payloads = {
                '/api/stats': {'hostname': 'beacon', 'sample_ts': 1_700_000_000, 'cpu': 1, 'ram': 2, 'disk': 3, 'ram_used': 1, 'ram_total': 2, 'disk_used': 1, 'disk_total': 2, 'temp': 40},
                '/api/history': [],
                '/api/scan-status': {'worker_ready': True, 'worker_stale': False, 'recovery_required': False, 'stage': 'idle', 'scanning': False, 'last_completed_found': len(fixture['services']), 'last_discovery': 1_700_000_000},
                '/api/services': fixture['services'],
                '/api/events': fixture.get('events', []),
            }
            route.fulfill(status=200, json=payloads.get(path, {}))
        return route_api

    def test_a_service_with_no_windows_shows_the_empty_state_and_the_add_control(self):
        fixture = {
            'services': [self._service(8200)],
            'service_meta': {8200: self._service_meta(8200, windows=[])},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-window-empty').wait_for(state='visible', timeout=8_000)
            self.assertFalse(page.locator('#meta-window-count').is_visible())
            self.assertIn('No maintenance windows yet', page.locator('#meta-window-empty').text_content())
            add_button = page.locator('#meta-window-add')
            self.assertTrue(add_button.is_visible())
            self.assertTrue(add_button.is_enabled())
        finally:
            page.close()

    def test_one_window_renders_the_singular_count_and_many_render_the_plural(self):
        one_window = [{'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True}]
        three_windows = [
            {'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True},
            {'start_minute': 120, 'duration_minutes': 15, 'weekdays': [2], 'grace_minutes': 10, 'enabled': True},
            {'start_minute': 180, 'duration_minutes': 45, 'weekdays': [3], 'grace_minutes': 20, 'enabled': False},
        ]
        fixture = {
            'services': [self._service(8201), self._service(8202)],
            'service_meta': {
                8201: self._service_meta(8201, windows=one_window),
                8202: self._service_meta(8202, windows=three_windows),
            },
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').nth(0).click()
            page.locator('#meta-window-count').wait_for(state='visible', timeout=8_000)
            singular = page.locator('#meta-window-count').text_content()
            self.assertEqual(singular, '1 maintenance window')
            self.assertNotEqual(singular, '0 maintenance windows')
            page.locator('#meta-cancel').click()

            page.locator('.svc-edit').nth(1).click()
            page.locator('#meta-window-count').wait_for(state='visible', timeout=8_000)
            plural = page.locator('#meta-window-count').text_content()
            self.assertEqual(plural, '3 maintenance windows')
            self.assertNotEqual(plural, '0 maintenance windows')
        finally:
            page.close()

    def test_adding_a_row_prefills_the_default_grace_and_focuses_the_start_field(self):
        fixture = {
            'services': [self._service(8203)],
            'service_meta': {8203: self._service_meta(8203, windows=[])},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-window-empty').wait_for(state='visible', timeout=8_000)
            page.locator('#meta-window-add').click()
            row = page.locator('.meta-window-row').first
            row.wait_for(state='visible', timeout=4_000)
            self.assertEqual(row.locator('.meta-window-grace').input_value(), '15')
            self.assertTrue(row.locator('.meta-window-start').evaluate('(node) => document.activeElement === node'))
        finally:
            page.close()

    def test_a_weekday_chip_toggles_its_pressed_state_and_carries_a_full_day_label(self):
        fixture = {
            'services': [self._service(8204)],
            'service_meta': {8204: self._service_meta(8204, windows=[])},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-window-empty').wait_for(state='visible', timeout=8_000)
            page.locator('#meta-window-add').click()
            chip = page.locator('.meta-window-row').first.locator('.meta-weekday-chip').first
            chip.wait_for(state='visible', timeout=4_000)
            self.assertEqual(chip.get_attribute('aria-pressed'), 'false')
            self.assertEqual(chip.get_attribute('aria-label'), 'Monday')
            chip.click()
            self.assertEqual(chip.get_attribute('aria-pressed'), 'true')
            chip.click()
            self.assertEqual(chip.get_attribute('aria-pressed'), 'false')
        finally:
            page.close()

    def test_unchecking_enabled_dims_the_row_without_hiding_any_field(self):
        windows = [{'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True}]
        fixture = {
            'services': [self._service(8205)],
            'service_meta': {8205: self._service_meta(8205, windows=windows)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            row = page.locator('.meta-window-row').first
            row.wait_for(state='visible', timeout=8_000)
            self.assertFalse(row.evaluate('(node) => node.classList.contains("is-disabled")'))
            row.locator('.meta-window-enabled').uncheck()
            self.assertTrue(row.evaluate('(node) => node.classList.contains("is-disabled")'))
            for selector in ['.meta-window-start', '.meta-window-duration', '.meta-weekday-chip', '.meta-window-grace', '.meta-window-remove']:
                self.assertTrue(row.locator(selector).first.is_visible(), selector)
        finally:
            page.close()

    def test_removing_a_window_requires_two_activations(self):
        windows = [{'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True}]
        fixture = {
            'services': [self._service(8206)],
            'service_meta': {8206: self._service_meta(8206, windows=windows)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            row = page.locator('.meta-window-row').first
            row.wait_for(state='visible', timeout=8_000)
            remove_button = row.locator('.meta-window-remove')
            self.assertEqual(remove_button.text_content(), 'Remove')
            remove_button.click()
            self.assertEqual(remove_button.text_content(), 'Confirm remove')
            self.assertEqual(page.locator('.meta-window-row').count(), 1)
            remove_button.click()
            self.assertEqual(page.locator('.meta-window-row').count(), 0)
            self.assertTrue(page.locator('#meta-window-empty').is_visible())
        finally:
            page.close()

    def test_a_server_validation_message_is_shown_verbatim_in_the_shared_error_region(self):
        windows = [{'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True}]
        fixture = {
            'services': [self._service(8207)],
            'service_meta': {8207: self._service_meta(8207, windows=windows)},
            'put_error': {'status': 400, 'message': 'Window 1: Duration must be at least 1 minute.'},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('.meta-window-row').first.wait_for(state='visible', timeout=8_000)
            page.locator('#meta-form').evaluate('(form) => form.requestSubmit()')
            page.locator('#meta-error').wait_for(state='visible', timeout=8_000)
            self.assertEqual(
                page.locator('#meta-error').text_content(),
                'Window 1: Duration must be at least 1 minute.',
            )
            self.assertTrue(page.locator('#meta-modal').is_visible())
            self.assertEqual(page.locator('.meta-window-row').count(), 1)
        finally:
            page.close()

    def test_the_window_list_scrolls_rather_than_growing_past_four_rows(self):
        windows = [
            {'start_minute': i * 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True}
            for i in range(6)
        ]
        fixture = {
            'services': [self._service(8208)],
            'service_meta': {8208: self._service_meta(8208, windows=windows)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('.meta-window-row').nth(5).wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.meta-window-row').count(), 6)
            scroll_height = page.locator('#meta-window-list').evaluate('(node) => node.scrollHeight')
            client_height = page.locator('#meta-window-list').evaluate('(node) => node.clientHeight')
            self.assertGreater(scroll_height, client_height)
        finally:
            page.close()

    def test_every_added_control_meets_the_narrow_viewport_touch_target(self):
        windows = [{'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True}]
        fixture = {
            'services': [self._service(8209)],
            'service_meta': {8209: self._service_meta(8209, windows=windows)},
        }
        page = self.browser.new_page(viewport={'width': 360, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            row = page.locator('.meta-window-row').first
            row.wait_for(state='visible', timeout=8_000)
            for selector in [
                '.meta-window-start', '.meta-window-duration', '.meta-weekday-chip',
                '.meta-window-grace', '.meta-checkbox', '.meta-window-remove',
            ]:
                box = row.locator(selector).first.bounding_box()
                self.assertGreaterEqual(box['height'], 44, selector)
                self.assertGreaterEqual(box['width'], 44, selector)
            add_box = page.locator('#meta-window-add').bounding_box()
            self.assertGreaterEqual(add_box['height'], 44)
        finally:
            page.close()

    def test_the_modal_focus_trap_still_reaches_the_new_controls(self):
        windows = [{'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True}]
        fixture = {
            'services': [self._service(8210)],
            'service_meta': {8210: self._service_meta(8210, windows=windows)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('.meta-window-row').first.wait_for(state='visible', timeout=8_000)
            result = page.locator('#meta-modal').evaluate(
                """(modal) => {
                    const focusable = [...modal.querySelectorAll('button,input,summary,[href],[tabindex]:not([tabindex="-1"])')]
                      .filter((el) => !el.disabled);
                    return {
                      hasChip: focusable.some((el) => el.classList.contains('meta-weekday-chip')),
                      hasAdd: focusable.some((el) => el.id === 'meta-window-add'),
                      hasRemove: focusable.some((el) => el.classList.contains('meta-window-remove')),
                    };
                }"""
            )
            self.assertTrue(result['hasChip'])
            self.assertTrue(result['hasAdd'])
            self.assertTrue(result['hasRemove'])
        finally:
            page.close()

    def test_no_suggestion_renders_no_card_and_no_empty_state_message(self):
        fixture = {
            'services': [self._service(8211)],
            'service_meta': {8211: self._service_meta(8211, windows=[], suggestion=None)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-window-empty').wait_for(state='visible', timeout=8_000)
            self.assertFalse(page.locator('#meta-suggestion').is_visible())
            self.assertNotIn('Suggested window', page.locator('.meta-maintenance').inner_text())
        finally:
            page.close()

    def test_the_empty_state_is_hidden_once_the_service_has_windows(self):
        """A service with windows must not also show the no-windows message.

        `.meta-window-empty` sets `display: flex`, which outranks the UA
        stylesheet's `[hidden] { display: none }`, so setting the `hidden`
        attribute alone does not hide it. Without an explicit
        `.meta-window-empty[hidden]` override the editor renders both the
        window list and 'No maintenance windows yet' at the same time.
        """
        windows = [
            {'start_minute': 120, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 15, 'enabled': True},
        ]
        fixture = {
            'services': [self._service(8231)],
            'service_meta': {8231: self._service_meta(8231, windows=windows)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('.meta-window-row').first.wait_for(state='visible', timeout=8_000)
            self.assertTrue(page.locator('#meta-window-empty').is_hidden())
            self.assertEqual(
                page.locator('#meta-window-empty').evaluate(
                    'el => getComputedStyle(el).display'
                ),
                'none',
            )
        finally:
            page.close()

    def test_a_failed_metadata_fetch_renders_no_suggestion_and_no_error_copy(self):
        fixture = {
            'services': [self._service(8212)],
            'service_meta': {8212: self._service_meta(8212, windows=[])},
            'get_error': True,
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-window-empty').wait_for(state='visible', timeout=8_000)
            self.assertFalse(page.locator('#meta-suggestion').is_visible())
            self.assertFalse(page.locator('#meta-error').is_visible())
        finally:
            page.close()

    def test_a_suggestion_renders_the_observed_evidence_sentence(self):
        suggestion = {'occurrence_count': 4, 'start_minute': 120, 'duration_minutes': 30, 'weekdays': [1, 2, 3, 4, 5, 6, 7]}
        fixture = {
            'services': [self._service(8213)],
            'service_meta': {8213: self._service_meta(8213, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)
            self.assertEqual(
                page.locator('#meta-suggestion-evidence').text_content(),
                'Beacon observed 4 similar restarts recently, typically around 02:00–02:30 '
                'on Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday.',
            )
        finally:
            page.close()

    def test_the_suggestion_card_exposes_exactly_two_actions(self):
        suggestion = {'occurrence_count': 3, 'start_minute': 60, 'duration_minutes': 20, 'weekdays': [1, 2, 3]}
        fixture = {
            'services': [self._service(8214)],
            'service_meta': {8214: self._service_meta(8214, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)
            buttons = page.locator('#meta-suggestion button')
            self.assertEqual(buttons.count(), 2)
            labels = [buttons.nth(i).text_content() for i in range(2)]
            self.assertEqual(labels, ['Confirm', 'Adjust'])
            for label in labels:
                self.assertNotIn('dismiss', label.lower())
                self.assertNotIn('not now', label.lower())
        finally:
            page.close()

    def test_confirm_appends_an_unsaved_row_and_writes_nothing(self):
        suggestion = {'occurrence_count': 5, 'start_minute': 90, 'duration_minutes': 45, 'weekdays': [6, 7]}
        fixture = {
            'services': [self._service(8215)],
            'service_meta': {8215: self._service_meta(8215, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)
            page.locator('#meta-suggestion-confirm').click()
            self.assertEqual(page.locator('.meta-window-row').count(), 1)
            self.assertEqual(page.locator('#meta-window-count').text_content(), '1 maintenance window')
            self.assertFalse(page.locator('#meta-suggestion').is_visible())
            self.assertEqual(fixture.get('put_calls', []), [])
        finally:
            page.close()

    def test_adjust_appends_the_row_and_focuses_its_start_field(self):
        suggestion = {'occurrence_count': 3, 'start_minute': 300, 'duration_minutes': 15, 'weekdays': [1]}
        fixture = {
            'services': [self._service(8216)],
            'service_meta': {8216: self._service_meta(8216, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)
            page.locator('#meta-suggestion-adjust').click()
            row = page.locator('.meta-window-row').first
            row.wait_for(state='visible', timeout=4_000)
            self.assertTrue(row.locator('.meta-window-start').evaluate('(node) => document.activeElement === node'))
            self.assertFalse(page.locator('#meta-suggestion').is_visible())
            self.assertEqual(fixture.get('put_calls', []), [])
        finally:
            page.close()

    def test_a_confirmed_row_is_saved_only_by_the_existing_save_control(self):
        suggestion = {'occurrence_count': 4, 'start_minute': 120, 'duration_minutes': 30, 'weekdays': [1, 2, 3, 4, 5, 6, 7]}
        fixture = {
            'services': [self._service(8217)],
            'service_meta': {8217: self._service_meta(8217, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)
            page.locator('#meta-suggestion-confirm').click()
            page.locator('.meta-window-row').first.wait_for(state='visible', timeout=4_000)
            self.assertEqual(fixture.get('put_calls', []), [])
            page.locator('#meta-form').evaluate('(form) => form.requestSubmit()')
            page.locator('#meta-modal').wait_for(state='hidden', timeout=4_000)
            self.assertEqual(len(fixture.get('put_calls', [])), 1)
            body = fixture['put_calls'][0]['body']
            saved = body['maintenance_windows'][0]
            self.assertEqual(saved['start_minute'], 120)
            self.assertEqual(saved['duration_minutes'], 30)
            self.assertEqual(saved['weekdays'], [1, 2, 3, 4, 5, 6, 7])
            self.assertEqual(saved['grace_minutes'], 15)
            self.assertTrue(saved['enabled'])
        finally:
            page.close()

    def test_long_evidence_prose_wraps_and_is_not_truncated(self):
        suggestion = {'occurrence_count': 12, 'start_minute': 1320, 'duration_minutes': 90, 'weekdays': [1, 2, 3, 4, 5, 6, 7]}
        fixture = {
            'services': [self._service(8218)],
            'service_meta': {8218: self._service_meta(8218, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 360, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)
            card = page.locator('#meta-suggestion')
            scroll_width = card.evaluate('(node) => node.scrollWidth')
            client_width = card.evaluate('(node) => node.clientWidth')
            self.assertLessEqual(scroll_width, client_width)
            expected = (
                'Beacon observed 12 similar restarts recently, typically around 22:00–23:30 '
                'on Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday.'
            )
            self.assertEqual(page.locator('#meta-suggestion-evidence').text_content(), expected)
        finally:
            page.close()

    def test_the_card_uses_neither_the_maintenance_nor_the_warning_colour(self):
        suggestion = {'occurrence_count': 3, 'start_minute': 60, 'duration_minutes': 20, 'weekdays': [1, 2, 3]}
        fixture = {
            'services': [self._service(8219)],
            'service_meta': {8219: self._service_meta(8219, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)

            def read_colours():
                return page.evaluate(
                    """() => {
                        const probe = document.createElement('span');
                        document.body.appendChild(probe);
                        probe.style.color = 'var(--accent2)';
                        const accent2 = getComputedStyle(probe).color;
                        probe.style.color = 'var(--accent3)';
                        const accent3 = getComputedStyle(probe).color;
                        probe.remove();
                        const card = getComputedStyle(document.getElementById('meta-suggestion'));
                        const evidence = getComputedStyle(document.getElementById('meta-suggestion-evidence'));
                        return {
                            accent2, accent3,
                            borderColor: card.borderTopColor,
                            textColor: evidence.color,
                        };
                    }"""
                )

            dark = read_colours()
            self.assertNotEqual(dark['borderColor'], dark['accent2'])
            self.assertNotEqual(dark['borderColor'], dark['accent3'])
            self.assertNotEqual(dark['textColor'], dark['accent2'])
            self.assertNotEqual(dark['textColor'], dark['accent3'])

            page.locator('#toggle').evaluate('(node) => node.click()')
            self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))
            light = read_colours()
            self.assertNotEqual(light['borderColor'], light['accent2'])
            self.assertNotEqual(light['borderColor'], light['accent3'])
            self.assertNotEqual(light['textColor'], light['accent2'])
            self.assertNotEqual(light['textColor'], light['accent3'])
        finally:
            page.close()

    def test_the_suggestion_never_appears_on_a_service_card(self):
        suggestion = {'occurrence_count': 4, 'start_minute': 120, 'duration_minutes': 30, 'weekdays': [1, 2, 3, 4, 5, 6, 7]}
        fixture = {
            'services': [self._service(8220)],
            'service_meta': {8220: self._service_meta(8220, windows=[], suggestion=suggestion)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-edit').click()
            page.locator('#meta-suggestion').wait_for(state='visible', timeout=8_000)
            evidence_text = page.locator('#meta-suggestion-evidence').text_content()
            main_text = page.locator('main').text_content()
            self.assertNotIn(evidence_text, main_text)
        finally:
            page.close()

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
            self.assertEqual(page.locator('.svc-tls-unverified').text_content(), 'TLS')
            self.assertEqual(page.locator('.svc-tls-unverified').get_attribute('title'), 'TLS certificate is not verified for this trusted local service.')
            self.assertEqual(page.locator('.svc-tls-unverified').get_attribute('aria-label'), 'TLS certificate is not verified for this trusted local service.')
            self.assertEqual(page.locator('.svc-edit').text_content(), 'Edit')
            self.assertEqual(page.locator('.svc-edit').get_attribute('aria-label'), 'Edit service')
            self.assertIn('ONLINE', page.locator('.svc-status-row').text_content())
            self.assertIn('Preview refresh queued', page.locator('.svc-preview-status').text_content())

            page.set_viewport_size({'width': 720, 'height': 800})
            page.locator('.svc-edit').click()
            self.assertGreaterEqual(page.locator('#meta-cancel').bounding_box()['height'], 44)
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

    def test_safety_matrix_keeps_recovery_tls_errors_and_narrow_controls_distinct(self):
        long_value = 'https://[fd00:beacon:very:long:trusted:local:service:address]:8100/' + ('path' * 28)
        fixture = {
            'worker_stale': True,
            'recovery_required': True,
            'latest_request_status': 'expired',
            'disconnected': False,
            'services': [
                {
                    **self._service(8100, online=True, tls=True),
                    'display_name': 'online-' + ('unbroken-name-' * 18),
                    'url': long_value,
                    'tags': ['tag-' + ('unbroken-' * 24)],
                    'preview_status': 'failed',
                },
                {
                    **self._service(8101, online=False, tls=True),
                    'display_name': 'offline-' + ('unbroken-name-' * 18),
                    'url': long_value,
                    'last_error': 'blocked-' + ('detail-' * 32),
                    'preview_status': 'expired',
                },
            ],
            'events': [
                {
                    'event_type': 'monitoring_gap',
                    'details': '{"start_ts":10,"end_ts":80}',
                    'ts': 1_700_000_000,
                    'online': None,
                },
            ],
        }
        page = self.browser.new_page(viewport={'width': 360, 'height': 800})

        def route_api(route):
            path = urlparse(route.request.url).path
            if fixture['disconnected'] and path in {'/api/stats', '/api/scan-status'}:
                route.abort()
                return
            if path == '/api/service-meta/8100' and route.request.method == 'PUT':
                route.fulfill(status=400, json={'error': 'policy_error'})
                return
            payloads = {
                '/api/stats': {'hostname': 'beacon', 'sample_ts': 1_700_000_000, 'cpu': 1, 'ram': 2, 'disk': 3, 'ram_used': 1, 'ram_total': 2, 'disk_used': 1, 'disk_total': 2, 'temp': 40},
                '/api/history': [],
                '/api/scan-status': {
                    'worker_ready': not fixture['worker_stale'],
                    'worker_stale': fixture['worker_stale'],
                    'recovery_required': fixture['recovery_required'],
                    'stage': 'idle', 'scanning': False, 'last_completed_found': 1,
                    'last_discovery': 1_700_000_000,
                    'latest_request_status': fixture['latest_request_status'],
                },
                '/api/services': fixture['services'],
                '/api/events': fixture['events'],
            }
            route.fulfill(status=200, json=payloads.get(path, {}))

        page.route('**/api/**', route_api)
        try:
            page.goto(self.base_url, wait_until='networkidle')
            self.assertTrue(page.locator('#worker-warning').is_visible())
            self.assertTrue(page.locator('#recovery-warning').is_visible())
            self.assertIn('Scan request expired', page.locator('#scan-label').text_content())
            self.assertIn('ONLINE', page.locator('.svc-card').first.locator('.svc-status-row').text_content())
            self.assertIn('OFFLINE', page.locator('.svc-card').nth(1).locator('.svc-status-row').text_content())
            self.assertEqual(page.locator('.svc-tls-unverified').count(), 2)
            self.assertIn('Preview refresh failed', page.locator('.svc-card').first.text_content())
            self.assertIn('Preview refresh expired', page.locator('.svc-card').nth(1).text_content())

            page.locator('.svc-edit').first.click()
            page.locator('#meta-form').evaluate('(form) => form.requestSubmit()')
            self.assertTrue(page.locator('#meta-error').is_visible())
            self.assertIn('Beacon could not use that destination', page.locator('#meta-error').text_content())
            self.assertEqual(page.locator('#meta-error').evaluate('(node) => document.activeElement === node'), True)
            for selector in ['#meta-save', '#meta-cancel']:
                self.assertGreaterEqual(page.locator(selector).bounding_box()['height'], 44)
            page.locator('#meta-cancel').click()

            for selector in ['.btn-scan', '#toggle', '.svc-edit']:
                box = page.locator(selector).first.bounding_box()
                self.assertGreaterEqual(box['height'], 44, selector)
                self.assertGreaterEqual(box['width'], 44, selector)
            self.assertLessEqual(page.evaluate('document.documentElement.scrollWidth'), 360)
            for card in page.locator('.svc-card').all():
                card_box = card.bounding_box()
                for child in card.locator('.svc-title, .svc-tags, .svc-error, .svc-preview-status').all():
                    box = child.bounding_box()
                    self.assertGreaterEqual(box['x'], card_box['x'] - 1)
                    self.assertLessEqual(box['x'] + box['width'], card_box['x'] + card_box['width'] + 1)

            page.locator('#toggle').click()
            self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))
            self.assertTrue(page.locator('#worker-warning').is_visible())
            self.assertTrue(page.locator('#recovery-warning').is_visible())
            self.assertEqual(page.locator('.svc-tls-unverified').count(), 2)

            fixture['worker_stale'] = False
            fixture['recovery_required'] = False
            page.locator('#worker-warning').wait_for(state='hidden', timeout=8_000)
            self.assertFalse(page.locator('#recovery-warning').is_visible())
            self.assertEqual(
                page.locator('#dashboard-feedback').text_content(),
                'Monitoring resumed. The outage was recorded in Events.',
            )

            fixture['disconnected'] = True
            page.locator('#connection-banner').wait_for(state='visible', timeout=8_000)
            self.assertIn('Beacon is disconnected', page.locator('#connection-banner').text_content())

            page.set_viewport_size({'width': 1440, 'height': 900})
            self.assertLessEqual(page.evaluate('document.documentElement.scrollWidth'), 1440)
            self.assertIn('Monitoring gap recorded', page.locator('#events-panel').text_content())
        finally:
            page.close()

    # -- Phase 03.1 Plan 09: the in-maintenance card and its disclosure -----

    def test_a_covered_offline_service_renders_the_calm_maintenance_card(self):
        service = {**self._service(8221, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        fixture = {'services': [service], 'service_meta': {8221: self._service_meta(8221)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.svc-maintenance-status').text_content(), 'MAINTENANCE')

            def read_colours():
                return page.evaluate(
                    """() => {
                        const probe = document.createElement('span');
                        document.body.appendChild(probe);
                        probe.style.color = 'var(--accent3)';
                        const accent3 = getComputedStyle(probe).color;
                        probe.remove();
                        const card = getComputedStyle(document.querySelector('.svc-maintenance'));
                        return {accent3, opacity: card.opacity, filter: card.filter};
                    }"""
                )

            colours = read_colours()
            self.assertEqual(
                page.locator('.svc-maintenance-status').evaluate('(node) => getComputedStyle(node).color'),
                colours['accent3'],
            )
        finally:
            page.close()

    def test_the_maintenance_card_never_carries_the_offline_class(self):
        service = {**self._service(8222, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        fixture = {'services': [service], 'service_meta': {8222: self._service_meta(8222)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            class_list = page.locator('.svc-card').first.get_attribute('class')
            self.assertIn('svc-maintenance', class_list)
            self.assertNotIn('offline', class_list.split())

            online_card = {**self._service(8100, online=True)}
            online_fixture = {'services': [online_card], 'service_meta': {}}
            page.route('**/api/**', self._maintenance_route(online_fixture))
            page.reload(wait_until='networkidle')
            healthy_opacity = page.locator('.svc-card').first.evaluate('(node) => getComputedStyle(node).opacity')

            page.route('**/api/**', self._maintenance_route(fixture))
            page.reload(wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            maintenance_opacity = page.locator('.svc-maintenance').evaluate('(node) => getComputedStyle(node).opacity')
            maintenance_filter = page.locator('.svc-maintenance').evaluate('(node) => getComputedStyle(node).filter')
            self.assertEqual(maintenance_opacity, healthy_opacity)
            self.assertIn(maintenance_filter, ('none', 'none 0 0'))
        finally:
            page.close()

    def test_the_maintenance_card_keeps_the_true_down_since_line(self):
        maintenance_service = {
            **self._service(8223, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600,
        }
        offline_service = {**self._service(8224, online=False)}
        fixture = {
            'services': [maintenance_service, offline_service],
            'service_meta': {8223: self._service_meta(8223), 8224: self._service_meta(8224)},
        }
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            maintenance_since = page.locator('.svc-maintenance .svc-since').text_content()
            offline_since = page.locator('.svc-card.offline .svc-since').text_content()
            self.assertEqual(maintenance_since, offline_since)
        finally:
            page.close()

    def test_the_maintenance_status_pip_does_not_animate(self):
        service = {**self._service(8225, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        fixture = {'services': [service], 'service_meta': {8225: self._service_meta(8225)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            animation_name = page.locator('.svc-maintenance-status .status-pip').evaluate(
                '(node) => getComputedStyle(node).animationName'
            )
            self.assertEqual(animation_name, 'none')
        finally:
            page.close()

    def test_the_maintenance_card_discloses_its_derivation_in_a_title_attribute(self):
        service = {**self._service(8226, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        fixture = {'services': [service], 'service_meta': {8226: self._service_meta(8226)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            title = page.locator('.svc-maintenance-status').get_attribute('title')
            self.assertTrue(title)
            self.assertIn('Offline and covered by a confirmed maintenance window until', title)
            self.assertIn('Downtime is still counted in the 7-day availability figure.', title)
        finally:
            page.close()

    def test_the_card_reverts_to_offline_once_coverage_lapses(self):
        service = {**self._service(8227, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        fixture = {'services': [service], 'service_meta': {8227: self._service_meta(8227)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)

            fixture['services'] = [{**service, 'availability': 'offline', 'maintenance_until': None}]
            page.evaluate('() => loadServices()')
            page.locator('.svc-card.offline').wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.svc-maintenance').count(), 0)
            self.assertIn('OFFLINE', page.locator('.svc-status-row').text_content())
        finally:
            page.close()

    def test_the_status_row_wraps_rather_than_clipping_at_a_narrow_viewport(self):
        service = {**self._service(8228, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        fixture = {'services': [service], 'service_meta': {8228: self._service_meta(8228)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            wrap = page.locator('.svc-status-row').first.evaluate('(node) => getComputedStyle(node).flexWrap')
            self.assertEqual(wrap, 'wrap')
            result = page.locator('.svc-status-row').first.evaluate(
                """(node) => {
                    node.style.width = '40px';
                    const status = node.querySelector('.svc-maintenance-status');
                    const since = node.querySelector('.svc-since');
                    return {statusTop: status.getBoundingClientRect().top, sinceTop: since.getBoundingClientRect().top};
                }"""
            )
            self.assertGreater(result['sinceTop'], result['statusTop'])
        finally:
            page.close()

    def test_the_maintenance_status_word_does_not_wrap_at_ordinary_widths(self):
        service = {**self._service(8230, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        fixture = {'services': [service], 'service_meta': {8230: self._service_meta(8230)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.svc-maintenance').wait_for(state='visible', timeout=8_000)
            result = page.locator('.svc-maintenance-status').first.evaluate(
                """(node) => {
                    const pip = node.querySelector('.status-pip');
                    const word = node.querySelector('span:last-child');
                    return {pipRect: pip.getBoundingClientRect(), wordRect: word.getBoundingClientRect()};
                }"""
            )
            # Same row: their vertical spans overlap (align-items: center keeps
            # them on one line at this width, unlike the forced-narrow case).
            pip, word = result['pipRect'], result['wordRect']
            self.assertLess(pip['top'], word['bottom'])
            self.assertLess(word['top'], pip['bottom'])
        finally:
            page.close()

    # -- Phase 03.1 Plan 09: the suppressed-entries reveal control -----------

    def test_suppressed_entries_are_hidden_by_default_but_still_present_in_the_data(self):
        events = [
            self._event(ts=4000, event_type='state_change', online=False, service_name='Alpha', suppressed_reason='maintenance', details='service went down'),
            self._event(ts=3000, event_type='state_change', online=True, service_name='Alpha', suppressed_reason='maintenance', details='service recovered'),
            self._event(ts=2000, event_type='state_change', online=False, service_name='Beta', suppressed_reason='maintenance', details='service went down'),
            self._event(ts=1000, event_type='state_change', online=False, service_name='Gamma', suppressed_reason=None, details='service went down'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.evt-reveal').text_content(), 'Show 3 suppressed entries')
            self.assertEqual(page.locator('.evt-pill-expected').count(), 0)
            self.assertEqual(page.locator('.evt-row').count(), 1)
            self.assertIn('Gamma went down', page.locator('.evt-row').first.text_content())
        finally:
            page.close()

    def test_the_reveal_control_states_the_singular_count(self):
        events = [
            self._event(ts=2000, event_type='state_change', online=False, service_name='Alpha', suppressed_reason='maintenance', details='service went down'),
            self._event(ts=1000, event_type='state_change', online=False, service_name='Beta', suppressed_reason=None, details='service went down'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.evt-reveal').text_content(), 'Show 1 suppressed entry')
        finally:
            page.close()

    def test_the_reveal_control_states_the_plural_count(self):
        events = [
            self._event(ts=3000, event_type='state_change', online=False, service_name='Alpha', suppressed_reason='maintenance', details='service went down'),
            self._event(ts=2000, event_type='state_change', online=True, service_name='Alpha', suppressed_reason='maintenance', details='service recovered'),
            self._event(ts=1000, event_type='state_change', online=False, service_name='Beta', suppressed_reason='maintenance', details='service went down'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.evt-reveal').text_content(), 'Show 3 suppressed entries')
        finally:
            page.close()

    def test_no_reveal_control_exists_when_nothing_is_suppressed(self):
        events = [
            self._event(ts=1000, event_type='state_change', online=False, service_name='Beta', suppressed_reason=None, details='service went down'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-row').wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.evt-reveal').count(), 0)
        finally:
            page.close()

    def test_revealing_renders_suppressed_rows_inline_in_chronological_order(self):
        events = [
            self._event(ts=4000, event_type='state_change', online=False, service_name='Delta', suppressed_reason=None, details='service went down'),
            self._event(ts=3000, event_type='state_change', online=False, service_name='Alpha', suppressed_reason='maintenance', details='service went down'),
            self._event(ts=2000, event_type='state_change', online=True, service_name='Alpha', suppressed_reason='maintenance', details='service recovered'),
            self._event(ts=1000, event_type='state_change', online=False, service_name='Beta', suppressed_reason=None, details='service went down'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            page.locator('.evt-reveal').click()
            page.locator('.evt-pill-expected').first.wait_for(state='visible', timeout=8_000)
            titles = page.locator('.evt-title').all_text_contents()
            self.assertEqual(titles, ['Delta went down', 'Alpha went down', 'Alpha recovered', 'Beta went down'])
            self.assertEqual(page.locator('.evt-pill-expected').count(), 2)
            self.assertEqual(page.locator('.evt-reveal').text_content(), 'Hide suppressed entries')
        finally:
            page.close()

    def test_a_revealed_suppressed_recovery_keeps_its_recovery_colour_and_gains_the_pill(self):
        events = [
            self._event(ts=2000, event_type='state_change', online=True, service_name='Alpha', suppressed_reason='maintenance', details='service recovered'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            page.locator('.evt-reveal').click()
            row = page.locator('.evt-row').first
            row.wait_for(state='visible', timeout=8_000)
            self.assertIn('evt-up', row.get_attribute('class'))
            pill = row.locator('.evt-pill-expected')
            self.assertEqual(pill.count(), 1)
            self.assertEqual(pill.text_content(), 'Expected')

            def read_colours():
                return page.evaluate(
                    """() => {
                        const probe = document.createElement('span');
                        document.body.appendChild(probe);
                        probe.style.color = 'var(--green)';
                        const green = getComputedStyle(probe).color;
                        probe.remove();
                        const title = document.querySelector('.evt-up .evt-title');
                        return {green, titleColor: getComputedStyle(title).color};
                    }"""
                )

            colours = read_colours()
            self.assertEqual(colours['titleColor'], colours['green'])
        finally:
            page.close()

    def test_the_reveal_state_is_not_persisted_across_a_reload(self):
        events = [
            self._event(ts=1000, event_type='state_change', online=False, service_name='Alpha', suppressed_reason='maintenance', details='service went down'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            page.locator('.evt-reveal').click()
            self.assertEqual(page.locator('.evt-reveal').text_content(), 'Hide suppressed entries')
            page.reload(wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            self.assertEqual(page.locator('.evt-reveal').text_content(), 'Show 1 suppressed entry')
        finally:
            page.close()

    def test_the_reveal_control_survives_a_failed_refresh_with_its_count_unchanged(self):
        events = [
            self._event(ts=3000, event_type='state_change', online=False, service_name='Alpha', suppressed_reason='maintenance', details='service went down'),
            self._event(ts=2000, event_type='state_change', online=True, service_name='Alpha', suppressed_reason='maintenance', details='service recovered'),
            self._event(ts=1000, event_type='state_change', online=False, service_name='Beta', suppressed_reason='maintenance', details='service went down'),
        ]
        fail = {'value': False}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/events' and fail['value']:
                route.fulfill(status=500, json={'error': 'boom'})
                return
            payloads = {
                '/api/stats': {'hostname': 'beacon', 'sample_ts': 1_700_000_000, 'cpu': 1, 'ram': 2, 'disk': 3, 'ram_used': 1, 'ram_total': 2, 'disk_used': 1, 'disk_total': 2, 'temp': 40},
                '/api/history': [],
                '/api/scan-status': {'worker_ready': True, 'worker_stale': False, 'recovery_required': False, 'stage': 'idle', 'scanning': False, 'last_completed_found': 0, 'last_discovery': 1_700_000_000},
                '/api/services': [],
                '/api/events': events,
            }
            route.fulfill(status=200, json=payloads.get(path, {}))

        page.route('**/api/**', route_api)
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            label_before = page.locator('.evt-reveal').text_content()
            fail['value'] = True
            page.evaluate('() => loadEvents()')
            page.wait_for_timeout(300)
            self.assertTrue(page.locator('.evt-reveal').is_visible())
            self.assertEqual(page.locator('.evt-reveal').text_content(), label_before)
        finally:
            page.close()

    # -- Phase 03.1 Plan 09: the overrun outage entry -------------------------

    def test_the_overrun_entry_renders_unmuted_and_without_the_pill(self):
        events = [
            self._overrun_event(ts=5000, down_since_ts=1000, service_name='Alpha'),
            self._event(ts=4000, event_type='state_change', online=False, service_name='Beta', details='service went down'),
        ]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-row').first.wait_for(state='visible', timeout=8_000)
            rows = page.locator('.evt-row.evt-down')
            self.assertEqual(rows.count(), 2)
            overrun_row = rows.filter(has_text='still down past maintenance')
            ordinary_row = rows.filter(has_text='Beta went down')
            self.assertEqual(overrun_row.count(), 1)
            self.assertEqual(ordinary_row.count(), 1)
            self.assertEqual(overrun_row.locator('.evt-pill').count(), 0)
            overrun_colour = overrun_row.locator('.evt-title').evaluate('(node) => getComputedStyle(node).color')
            ordinary_colour = ordinary_row.locator('.evt-title').evaluate('(node) => getComputedStyle(node).color')
            self.assertEqual(overrun_colour, ordinary_colour)
        finally:
            page.close()

    def test_the_overrun_entry_renders_both_timestamps_as_separate_values(self):
        events = [self._overrun_event(ts=5000, down_since_ts=1000, service_name='Alpha')]
        fixture = {'services': [], 'events': events, 'service_meta': {}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            row = page.locator('.evt-row').first
            row.wait_for(state='visible', timeout=8_000)
            subs = row.locator('.evt-sub').all_text_contents()
            self.assertEqual(len(subs), 2)
            self.assertNotEqual(subs[0], subs[1])
            self.assertNotIn(subs[0], subs[1])
            self.assertNotIn(subs[1], subs[0])
        finally:
            page.close()

    # -- Phase 03.1 Plan 09: the maintenance colour reservation ---------------

    def test_the_maintenance_colour_is_applied_to_no_interactive_element(self):
        service = {**self._service(8229, online=False), 'availability': 'maintenance', 'maintenance_until': 1_700_003_600}
        events = [
            self._event(ts=1000, event_type='state_change', online=False, service_name='Beta', suppressed_reason='maintenance', details='service went down'),
        ]
        fixture = {'services': [service], 'events': events, 'service_meta': {8229: self._service_meta(8229)}}
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        page.route('**/api/**', self._maintenance_route(fixture))
        try:
            page.goto(self.base_url, wait_until='networkidle')
            page.locator('.evt-reveal').wait_for(state='visible', timeout=8_000)
            accent3 = page.evaluate(
                """() => {
                    const probe = document.createElement('span');
                    document.body.appendChild(probe);
                    probe.style.color = 'var(--accent3)';
                    const value = getComputedStyle(probe).color;
                    probe.remove();
                    return value;
                }"""
            )
            for element in page.locator('button, a').all():
                if not element.is_visible():
                    continue
                rest_colour = element.evaluate('(node) => getComputedStyle(node).color')
                self.assertNotEqual(rest_colour, accent3)
                try:
                    element.hover(timeout=2_000)
                except Exception:
                    continue
                hover_colour = element.evaluate('(node) => getComputedStyle(node).color')
                self.assertNotEqual(hover_colour, accent3)
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
