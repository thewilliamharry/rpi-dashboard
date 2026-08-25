import calendar
import re
import threading
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.helpers import cleanup_db, load_app

# D-02's exact preset ladder in seconds -- the span every request must equal.
HISTORY_PRESET_SPANS = {
    '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000, '90d': 7776000,
}


class HistoryInvestigationUiTests(unittest.TestCase):
    """Browser coverage for the History section's gap-honest CPU chart (04-01).

    Follows the exact harness of tests/test_advanced_ui.py: load_app +
    werkzeug.serving.make_server + sync_playwright + page.route fixtures.
    The app is loaded once with TZ=Australia/Sydney for the whole module so
    every test can prove D-05 (Pi-configured local time, not the browser's).
    """

    @classmethod
    def setUpClass(cls):
        cls.appmod, cls.db_path = load_app({'TZ': 'Australia/Sydney'})
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
        """The minimal /api/advanced/current payload the Overview tracer needs.

        History does not consume this snapshot; it exists only so the page's
        own periodic refreshCurrentDiagnosis() call has a well-formed fixture
        to land on instead of an unhandled route.
        """
        return {
            'schema_version': 3,
            'generated_ts': 1_700_000_005,
            'host': {
                'identity': {'hostname': 'beacon-pi'},
                'metrics': {
                    'cpu': {'value': 21.5, 'unit': 'percent'},
                    'memory': {'value': 42.0, 'unit': 'percent'},
                    'disk': {'value': 63.0, 'unit': 'percent'},
                    'temperature': {'value': 51.25, 'unit': 'celsius'},
                },
                'sample_ts': 1_700_000_000,
                'expected_cadence_seconds': 5,
                'freshness': {'state': 'fresh', 'age_seconds': 5},
            },
            'services': [], 'pipeline': {}, 'settings': {}, 'exceptions': [],
        }

    @staticmethod
    def _config_fixture():
        return {
            'timezone': 'Australia/Sydney', 'alerting_enabled': False,
            'uptime_buckets': [], 'trigger_rate_limit': 4, 'trigger_rate_window_seconds': 60,
        }

    @staticmethod
    def _point(ts, avg_value):
        return {
            'ts': ts, 'min_value': avg_value, 'max_value': avg_value, 'avg_value': avg_value,
            'latest_value': avg_value, 'sample_count': 1, 'observed_seconds': 60,
            'gap_seconds': 0, 'unknown_seconds': 0,
        }

    @classmethod
    def _history_fixture(cls):
        """One observed span, a storage_pressure gap, an expired span, then a
        second observed span -- deliberately built so the series must break
        (D-06) at both non-observed intervals and the strip must carry exactly
        two segments (the observed spans render no segment at all).
        """
        return {
            'requested': {'start_ts': 1_700_000_000, 'end_ts': 1_700_080_000},
            'selector': {'kind': 'host', 'metric': 'cpu'},
            'effective_resolution_seconds': 60,
            'point_budget': 2048,
            'source_resolutions_seconds': [60],
            'points': [
                cls._point(1_700_000_000, 10.0),
                cls._point(1_700_010_000, 20.0),
                cls._point(1_700_070_000, 70.0),
                cls._point(1_700_075_000, 75.0),
            ],
            'coverage': [
                {'start_ts': 1_700_000_000, 'end_ts': 1_700_020_000, 'state': 'observed'},
                {'start_ts': 1_700_020_000, 'end_ts': 1_700_040_000, 'state': 'collection_gap', 'detail': 'storage_pressure'},
                {'start_ts': 1_700_040_000, 'end_ts': 1_700_060_000, 'state': 'expired'},
                {'start_ts': 1_700_060_000, 'end_ts': 1_700_080_000, 'state': 'observed'},
            ],
            'aggregation_pending': [],
        }

    @staticmethod
    def _empty_history_fixture(start_ts, end_ts, resolution_seconds=3600):
        """A minimal, well-formed /api/telemetry/history response for a given
        requested span -- used where the test only cares about the requested
        bounds and the preset-toggle/persistence behavior, not chart content.
        """
        return {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'selector': {'kind': 'host', 'metric': 'cpu'},
            'effective_resolution_seconds': resolution_seconds,
            'point_budget': 2048,
            'source_resolutions_seconds': [resolution_seconds],
            'points': [],
            'coverage': [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'}],
            'aggregation_pending': [],
        }

    def test_all_six_presets_request_the_documented_span_and_toggle_aria_pressed(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                start_ts = int(query['start_ts'][0])
                end_ts = int(query['end_ts'][0])
                route.fulfill(status=200, json=self._empty_history_fixture(start_ts, end_ts))
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-section').wait_for(state='visible', timeout=5_000)

            for preset, span in HISTORY_PRESET_SPANS.items():
                with self.subTest(preset=preset):
                    with page.expect_request(
                        lambda request: urlparse(request.url).path == '/api/telemetry/history',
                    ) as request_info:
                        page.locator(f'#range-preset-{preset}').click()
                    query = parse_qs(urlparse(request_info.value.url).query)
                    start_ts = int(query['start_ts'][0])
                    end_ts = int(query['end_ts'][0])
                    self.assertEqual(end_ts - start_ts, span)
                    for candidate in HISTORY_PRESET_SPANS:
                        expected = 'true' if candidate == preset else 'false'
                        self.assertEqual(
                            page.locator(f'#range-preset-{candidate}').get_attribute('aria-pressed'),
                            expected,
                        )
        finally:
            page.close()

    def test_7d_preset_renders_one_coordinate_per_point_with_no_duplicate_ts(self):
        # A fixture whose points straddle the raw/5-minute tier seam --
        # two adjacent source_resolutions_seconds values -- proving the
        # renderer draws exactly one coordinate per returned point and never
        # duplicates a bucket at the seam.
        span = HISTORY_PRESET_SPANS['7d']
        end_ts = 2_000_000_000
        start_ts = end_ts - span
        points = [
            self._point(start_ts, 10.0),
            self._point(start_ts + 60, 20.0),
            self._point(start_ts + 120, 15.0),
            self._point(start_ts + 500_000, 55.0),
            self._point(start_ts + 500_300, 60.0),
            self._point(start_ts + 604_700, 90.0),
        ]
        fixture = {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'selector': {'kind': 'host', 'metric': 'cpu'},
            'effective_resolution_seconds': 300,
            'point_budget': 2048,
            'source_resolutions_seconds': [60, 300],
            'points': points,
            'coverage': [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'observed'}],
            'aggregation_pending': [],
        }
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-section').wait_for(state='visible', timeout=5_000)
            page.locator('#range-preset-7d').click()
            page.wait_for_function(
                "() => { const d = document.querySelector('#chart-cpu path').getAttribute('d') || ''; "
                "return d.length > 0; }",
                timeout=5_000,
            )
            d_attribute = page.locator('#chart-cpu path').get_attribute('d') or ''
            coordinates = re.findall(r'[ML]([-\d.]+),([-\d.]+)', d_attribute)
            self.assertEqual(len(coordinates), len(points))
            x_values = [x for x, _y in coordinates]
            self.assertEqual(len(x_values), len(set(x_values)))
        finally:
            page.close()

    def test_hostile_stored_history_range_falls_back_to_24h_default(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        hostile_seeds = {
            'array': "JSON.stringify({refreshSeconds: 15, historyRange: ['24h']})",
            'unknown_preset': "JSON.stringify({refreshSeconds: 15, historyRange: {preset: '../../etc'}})",
            'non_object_json': "JSON.stringify('not-an-object')",
        }
        for label, seed_expression in hostile_seeds.items():
            with self.subTest(seed=label):
                page = self.browser.new_page()
                page.add_init_script(
                    f"localStorage.setItem('beacon-advanced-preferences-v1', {seed_expression});",
                )

                def route_api(route):
                    path = urlparse(route.request.url).path
                    if path == '/api/config':
                        route.fulfill(status=200, json=config_fixture)
                        return
                    if path == '/api/telemetry/history':
                        query = parse_qs(urlparse(route.request.url).query)
                        start_ts = int(query['start_ts'][0])
                        end_ts = int(query['end_ts'][0])
                        route.fulfill(status=200, json=self._empty_history_fixture(start_ts, end_ts))
                        return
                    if path == '/api/advanced/current':
                        route.fulfill(status=200, json=snapshot)
                        return
                    route.fallback()

                page.route('**/api/**', route_api)
                try:
                    page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
                    # Loading without error: the section becomes reachable and
                    # the default preset renders as pressed with no thrown error.
                    with page.expect_request(
                        lambda request: urlparse(request.url).path == '/api/telemetry/history',
                    ) as request_info:
                        page.locator('[data-section="history"]').click()
                    query = parse_qs(urlparse(request_info.value.url).query)
                    start_ts = int(query['start_ts'][0])
                    end_ts = int(query['end_ts'][0])
                    self.assertEqual(end_ts - start_ts, HISTORY_PRESET_SPANS['24h'])
                    self.assertEqual(page.locator('#range-preset-24h').get_attribute('aria-pressed'), 'true')
                finally:
                    page.close()

    def test_history_section_breaks_gaps_labels_coverage_and_renders_local_time_axis(self):
        history_fixture = self._history_fixture()
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        # The browser context is pinned to UTC; the server is configured for
        # Australia/Sydney. If the axis ever renders in the browser's zone
        # instead of the fetched cfg.timezone, this pin makes that visible.
        page = self.browser.new_page(timezone_id='UTC')

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=history_fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-section').wait_for(state='visible', timeout=5_000)

            # (a) The series path must break rather than bridge the gap --
            # more than one M (move-to) command proves at least one break.
            page.wait_for_function(
                "() => { const d = document.querySelector('#chart-cpu path').getAttribute('d') || ''; "
                "return (d.match(/M/g) || []).length > 1; }",
                timeout=5_000,
            )
            d_attribute = page.locator('#chart-cpu path').get_attribute('d') or ''
            self.assertGreater(d_attribute.count('M'), 1)

            # (b) Exactly two coverage-strip segments, each labelled with the
            # exact UI-SPEC vocabulary string -- the two observed spans in the
            # fixture must render no segment at all.
            segments = page.locator('#strip-cpu .hist-coverage-segment')
            segments.first.wait_for(timeout=5_000)
            self.assertEqual(segments.count(), 2)
            titles = [segments.nth(i).locator('title').text_content() for i in range(segments.count())]
            self.assertIn('Storage pressure (no persistence)', titles)
            self.assertIn('Expired (outside retention)', titles)

            # (c) The shared axis renders in the Pi's configured Sydney time,
            # not the browser's pinned UTC context. 1_700_000_000 is
            # 2023-11-14 22:13 UTC but 2023-11-15 09:13 in Australia/Sydney
            # (AEDT, UTC+11) -- the day digit alone distinguishes the two.
            axis_texts = page.locator('#history-time-axis text')
            axis_texts.first.wait_for(timeout=5_000)
            first_tick = axis_texts.first.text_content()
            self.assertIn('15', first_tick)
            self.assertNotIn('14', first_tick)
        finally:
            page.close()

    def test_empty_response_renders_empty_copy_and_still_renders_coverage_strip(self):
        start_ts = 1_700_000_000
        end_ts = 1_700_086_400
        fixture = {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'selector': {'kind': 'host', 'metric': 'cpu'},
            'effective_resolution_seconds': 3600,
            'point_budget': 2048,
            'source_resolutions_seconds': [3600],
            'points': [],
            'coverage': [
                {'start_ts': start_ts, 'end_ts': start_ts + 40_000, 'state': 'not_yet_monitored'},
                {'start_ts': start_ts + 40_000, 'end_ts': end_ts, 'state': 'unknown'},
            ],
            'aggregation_pending': [],
        }
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-cpu-empty').wait_for(state='visible', timeout=5_000)
            self.assertIn('No CPU data in this range.', page.locator('#history-cpu-empty').text_content())
            segments = page.locator('#strip-cpu .hist-coverage-segment')
            segments.first.wait_for(timeout=5_000)
            self.assertEqual(segments.count(), 2)
        finally:
            page.close()

    def test_error_response_renders_server_reason_and_keeps_shared_axis(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=503, json={'error': 'telemetry unavailable'})
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-cpu-error').wait_for(state='visible', timeout=5_000)
            error_text = page.locator('#history-cpu-error').text_content()
            self.assertIn('This chart could not load.', error_text)
            self.assertIn('telemetry unavailable', error_text)
            # The shared axis element stays in the DOM even though every
            # metric's fetch failed -- a per-metric failure never disappears
            # the shared correlation surface around it.
            self.assertEqual(page.locator('#history-time-axis').count(), 1)
        finally:
            page.close()

    # Same fetch-holding idiom as AdvancedUiTests.REVERSE_ORDER_HARNESS: the
    # network response can complete immediately (fulfilled by the Python route
    # handler), while the *JS Promise* the page code awaits is deliberately
    # held back until the test explicitly releases it. This avoids blocking
    # the Playwright driver's single-threaded sync-API connection, which a
    # Python-side time.sleep() inside a route handler would otherwise starve.
    # 04-03 fetches all four host metrics in parallel, so the harness must hold
    # (and later release) all four concurrent /api/telemetry/history fetches,
    # not just one -- collecting them in an array rather than a single slot.
    HISTORY_FETCH_HOLD_HARNESS = """
        window.__heldHistoryReleases = [];
        const realFetch = window.fetch.bind(window);
        window.fetch = (...args) => {
          const url = String(args[0] || '');
          if (!url.includes('/api/telemetry/history')) return realFetch(...args);
          const pending = realFetch(...args);
          return new Promise((resolve, reject) => {
            window.__heldHistoryReleases.push(() => pending.then(resolve, reject));
          });
        };
        window.__releaseAllHeldHistoryFetches = () => {
          const releases = window.__heldHistoryReleases;
          window.__heldHistoryReleases = [];
          releases.forEach((release) => release());
        };
    """

    def test_pending_request_shows_skeleton_and_draws_no_chart_path(self):
        start_ts = 1_700_000_000
        end_ts = 1_700_086_400
        fixture = {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'selector': {'kind': 'host', 'metric': 'cpu'},
            'effective_resolution_seconds': 3600,
            'point_budget': 2048,
            'source_resolutions_seconds': [3600],
            'points': [self._point(start_ts, 10.0)],
            'coverage': [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'observed'}],
            'aggregation_pending': [],
        }
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.add_init_script(self.HISTORY_FETCH_HOLD_HARNESS)
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-cpu-loading').wait_for(state='visible', timeout=5_000)
            page.wait_for_function('window.__heldHistoryReleases.length === 4', timeout=5_000)
            path_d = page.locator('#chart-cpu path').get_attribute('d')
            self.assertFalse(path_d)
            # Now release all four held fetches and confirm the loading
            # skeleton clears and the chart draws.
            page.evaluate('window.__releaseAllHeldHistoryFetches()')
            page.locator('#history-cpu-loading').wait_for(state='hidden', timeout=5_000)
            self.assertTrue(page.locator('#chart-cpu path').get_attribute('d'))
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-03: memory, disk, and temperature join CPU on the shared axis.
    # ------------------------------------------------------------------

    def _metric_fixture(self, metric, points, start_ts=1_700_000_000, end_ts=None, coverage=None):
        end_ts = end_ts if end_ts is not None else start_ts + 3600
        return {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'selector': {'kind': 'host', 'metric': metric},
            'effective_resolution_seconds': 60,
            'point_budget': 2048,
            'source_resolutions_seconds': [60],
            'points': points,
            'coverage': coverage if coverage is not None else [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'observed'}],
            'aggregation_pending': [],
        }

    def test_four_charts_render_in_fixed_order_with_independent_coverage_strips(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        per_metric_points = {
            'cpu': [self._point(start_ts, 10.0), self._point(start_ts + 60, 20.0)],
            'ram': [self._point(start_ts, 30.0), self._point(start_ts + 60, 40.0)],
            'disk': [self._point(start_ts, 50.0), self._point(start_ts + 60, 55.0)],
            'temp': [self._point(start_ts, 41.0), self._point(start_ts + 60, 42.0)],
        }
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                metric = query['metric'][0]
                route.fulfill(status=200, json=self._metric_fixture(metric, per_metric_points[metric], start_ts, end_ts))
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            for metric in ('cpu', 'ram', 'disk', 'temp'):
                page.wait_for_function(
                    "() => { const d = document.querySelector('#chart-%s path').getAttribute('d') || ''; "
                    "return d.length > 0; }" % metric,
                    timeout=5_000,
                )
            chart_ids = page.eval_on_selector_all('.hist-plot', 'nodes => nodes.map(n => n.id)')
            self.assertEqual(chart_ids, ['chart-cpu', 'chart-ram', 'chart-disk', 'chart-temp'])
            strip_ids = page.eval_on_selector_all('.hist-coverage-strip', 'nodes => nodes.map(n => n.id)')
            self.assertEqual(strip_ids, ['strip-cpu', 'strip-ram', 'strip-disk', 'strip-temp'])
            self.assertEqual(page.locator('#history-time-axis').count(), 1)
            self.assertEqual(page.locator('#unit-cpu').text_content(), '%')
            self.assertEqual(page.locator('#unit-ram').text_content(), '%')
            self.assertEqual(page.locator('#unit-disk').text_content(), '%')
            self.assertEqual(page.locator('#unit-temp').text_content(), '°C')
        finally:
            page.close()

    def test_temperature_failure_isolates_other_three_charts(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        ok_fixture = self._metric_fixture('cpu', [self._point(start_ts, 10.0), self._point(start_ts + 60, 20.0)], start_ts, end_ts)
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                metric = query['metric'][0]
                if metric == 'temp':
                    route.fulfill(status=503, json={'error': 'temperature sensor unavailable'})
                    return
                route.fulfill(status=200, json=ok_fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-temp-error').wait_for(state='visible', timeout=5_000)
            for metric in ('cpu', 'ram', 'disk'):
                page.wait_for_function(
                    "() => { const d = document.querySelector('#chart-%s path').getAttribute('d') || ''; "
                    "return d.length > 0; }" % metric,
                    timeout=5_000,
                )
            self.assertTrue(page.locator('#history-cpu-error').is_hidden())
            self.assertTrue(page.locator('#history-ram-error').is_hidden())
            self.assertTrue(page.locator('#history-disk-error').is_hidden())
            error_text = page.locator('#history-temp-error').text_content()
            self.assertIn('This chart could not load.', error_text)
            self.assertIn('temperature sensor unavailable', error_text)
        finally:
            page.close()

    def test_disk_empty_response_keeps_chart_frame_present(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        ok_fixture = self._metric_fixture('cpu', [self._point(start_ts, 10.0)], start_ts, end_ts)
        empty_disk_fixture = self._metric_fixture(
            'disk', [], start_ts, end_ts,
            coverage=[{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'}],
        )
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                metric = query['metric'][0]
                route.fulfill(status=200, json=empty_disk_fixture if metric == 'disk' else ok_fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-disk-empty').wait_for(state='visible', timeout=5_000)
            self.assertIn('No Disk data in this range.', page.locator('#history-disk-empty').text_content())
            self.assertEqual(page.locator('#chart-disk').count(), 1)
        finally:
            page.close()

    def test_narrow_viewport_keeps_four_charts_full_width_with_scrollable_axis(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                start_ts = int(query['start_ts'][0])
                end_ts = int(query['end_ts'][0])
                route.fulfill(status=200, json=self._empty_history_fixture(start_ts, end_ts))
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page(viewport={'width': 400, 'height': 900})
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-section').wait_for(state='visible', timeout=5_000)
            for metric in ('cpu', 'ram', 'disk', 'temp'):
                box = page.locator(f'#chart-{metric}').bounding_box()
                self.assertIsNotNone(box)
                self.assertGreater(box['width'], 300)
            scroll = page.locator('#history-axis-scroll')
            self.assertEqual(scroll.get_attribute('role'), 'region')
            self.assertEqual(scroll.get_attribute('aria-label'), 'Shared history time axis')
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-03: threshold lines drawn only where a documented hardware or
    # filesystem fact exists.
    # ------------------------------------------------------------------

    def test_temperature_and_disk_thresholds_carry_provenance_cpu_ram_carry_none(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        fixtures = {
            'cpu': self._metric_fixture('cpu', [self._point(start_ts, 10.0)], start_ts, end_ts),
            'ram': self._metric_fixture('ram', [self._point(start_ts, 20.0)], start_ts, end_ts),
            'disk': self._metric_fixture('disk', [self._point(start_ts, 30.0)], start_ts, end_ts),
            'temp': self._metric_fixture('temp', [self._point(start_ts, 41.0)], start_ts, end_ts),
        }
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                metric = query['metric'][0]
                route.fulfill(status=200, json=fixtures[metric])
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#chart-temp .hist-threshold').first.wait_for(state='attached', timeout=5_000)
            temp_thresholds = page.locator('#chart-temp .hist-threshold')
            self.assertEqual(temp_thresholds.count(), 2)
            expected_temp = (
                'Raspberry Pi documented default soft/hard thermal throttle point '
                '— not a Beacon-configured alert.'
            )
            titles = [temp_thresholds.nth(i).locator('title').text_content() for i in range(2)]
            self.assertEqual(titles, [expected_temp, expected_temp])
            disk_thresholds = page.locator('#chart-disk .hist-threshold')
            self.assertEqual(disk_thresholds.count(), 1)
            self.assertEqual(
                disk_thresholds.first.locator('title').text_content(),
                'Filesystem-reported total capacity — the disk cannot exceed this line.',
            )
            self.assertEqual(page.locator('#chart-cpu .hist-threshold').count(), 0)
            self.assertEqual(page.locator('#chart-ram .hist-threshold').count(), 0)
            stroke = page.eval_on_selector('#chart-temp .hist-threshold', 'el => getComputedStyle(el).stroke')
            self.assertNotEqual(stroke, 'none')
        finally:
            page.close()

    def test_temperature_domain_includes_85_even_when_observed_max_is_41(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        fixture = self._metric_fixture('temp', [self._point(start_ts, 41.0)], start_ts, end_ts)
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#chart-temp .hist-threshold').first.wait_for(state='attached', timeout=5_000)
            ys = page.eval_on_selector_all(
                '#chart-temp .hist-threshold',
                'nodes => nodes.map(n => parseFloat(n.getAttribute("y1")))',
            )
            self.assertEqual(len(ys), 2)
            for y in ys:
                self.assertGreaterEqual(y, 0)
                self.assertLessEqual(y, 96)
            # The 85-degree line renders strictly above (smaller y) the
            # 80-degree line -- proving the domain grew to include both
            # rather than clipping the higher one off-screen.
            self.assertLess(min(ys), max(ys))
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-03: point tooltips and honest sub-pixel segment disclosure.
    # ------------------------------------------------------------------

    def test_point_tooltip_discloses_value_unit_and_local_timestamp(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        fixture = self._metric_fixture('temp', [self._point(start_ts, 41.5)], start_ts, end_ts)
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        # Browser pinned to UTC; server configured for Australia/Sydney --
        # 1_700_000_000 is 2023-11-15 in Sydney, 2023-11-14 in UTC (D-05).
        page = self.browser.new_page(timezone_id='UTC')
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#chart-temp .hist-point-target').first.wait_for(timeout=5_000)
            page.locator('#chart-temp .hist-point-target').first.hover()
            page.locator('#history-chart-tooltip').wait_for(state='visible', timeout=5_000)
            text = page.locator('#history-chart-tooltip').text_content()
            self.assertIn('41.5', text)
            self.assertIn('°C', text)
            self.assertIn('15', text)
            self.assertNotIn('14', text)
        finally:
            page.close()

    def test_merged_subpixel_segments_disclose_true_count_and_duration(self):
        span = HISTORY_PRESET_SPANS['90d']
        end_ts = 3_000_000_000
        start_ts = end_ts - span
        gap_start = start_ts + 1000
        coverage = [{'start_ts': start_ts, 'end_ts': gap_start, 'state': 'observed'}]
        cursor = gap_start
        for _ in range(4):
            coverage.append({'start_ts': cursor, 'end_ts': cursor + 90, 'state': 'collection_gap'})
            cursor += 90
        coverage.append({'start_ts': cursor, 'end_ts': end_ts, 'state': 'observed'})
        fixture = self._metric_fixture(
            'cpu', [self._point(start_ts, 10.0), self._point(end_ts - 60, 20.0)], start_ts, end_ts, coverage=coverage,
        )
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            with page.expect_request(lambda r: urlparse(r.url).path == '/api/telemetry/history'):
                page.locator('#range-preset-90d').click()
            page.locator('#strip-cpu .hist-coverage-segment').first.wait_for(timeout=5_000)
            segments = page.locator('#strip-cpu .hist-coverage-segment')
            self.assertEqual(segments.count(), 1)
            title = segments.first.locator('title').text_content()
            self.assertEqual(title, 'Collection gap — 4 intervals, 6 minutes total')
            width = float(segments.first.get_attribute('width'))
            self.assertGreaterEqual(width, 3)
        finally:
            page.close()

    def test_adjacent_subpixel_different_reasons_do_not_merge(self):
        span = HISTORY_PRESET_SPANS['90d']
        end_ts = 3_100_000_000
        start_ts = end_ts - span
        mid = start_ts + 1000
        coverage = [
            {'start_ts': start_ts, 'end_ts': mid, 'state': 'observed'},
            {'start_ts': mid, 'end_ts': mid + 30, 'state': 'collection_gap'},
            {'start_ts': mid + 30, 'end_ts': mid + 60, 'state': 'expired'},
            {'start_ts': mid + 60, 'end_ts': end_ts, 'state': 'observed'},
        ]
        fixture = self._metric_fixture(
            'cpu', [self._point(start_ts, 10.0), self._point(end_ts - 60, 20.0)], start_ts, end_ts, coverage=coverage,
        )
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            with page.expect_request(lambda r: urlparse(r.url).path == '/api/telemetry/history'):
                page.locator('#range-preset-90d').click()
            page.locator('#strip-cpu .hist-coverage-segment').first.wait_for(timeout=5_000)
            segments = page.locator('#strip-cpu .hist-coverage-segment')
            self.assertEqual(segments.count(), 2)
            titles = [segments.nth(i).locator('title').text_content() for i in range(2)]
            self.assertIn('Collection gap', titles)
            self.assertIn('Expired (outside retention)', titles)
        finally:
            page.close()

    def test_tooltip_updates_without_regenerating_chart_paths_on_pointer_moves(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        points = [self._point(start_ts + i * 300, 10.0 + i) for i in range(6)]
        fixture = self._metric_fixture('cpu', points, start_ts, end_ts)
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#chart-cpu .hist-point-target').first.wait_for(timeout=5_000)
            initial_d = page.locator('#chart-cpu path').get_attribute('d')
            targets = page.locator('#chart-cpu .hist-point-target')
            count = targets.count()
            self.assertGreaterEqual(count, 5)
            tooltip_texts = set()
            for index in range(min(6, count)):
                targets.nth(index).hover()
                page.locator('#history-chart-tooltip').wait_for(state='visible', timeout=5_000)
                tooltip_texts.add(page.locator('#history-chart-tooltip').text_content())
            final_d = page.locator('#chart-cpu path').get_attribute('d')
            self.assertEqual(initial_d, final_d)
            self.assertGreater(len(tooltip_texts), 1)
        finally:
            page.close()

    def test_four_chart_stack_render_is_measured_and_bounded_r01(self):
        """R-01: a measured wall-clock render figure for the full four-chart
        stack at the 90d preset with 2048 points/series and >=50 non-observed
        coverage intervals, captured via window.__historyStackRenderMs. The
        assertion is that a measurement was taken and is finite/bounded, not
        that it clears a threshold invented here -- see 04-03-SUMMARY.md for
        the recorded baseline (developer machine, not Pi-class; OPS-01 owns
        the Pi-hardware verdict).
        """
        span = HISTORY_PRESET_SPANS['90d']
        end_ts = 4_000_000_000
        start_ts = end_ts - span
        total_points = 2048
        step = max(1, (end_ts - start_ts) // total_points)
        points = [self._point(start_ts + i * step, float(i % 100)) for i in range(total_points)]
        coverage = []
        gap_count = 60
        gap_step = max(2, (end_ts - start_ts) // (gap_count * 2))
        cursor = start_ts
        for _ in range(gap_count):
            gap_end = cursor + gap_step
            coverage.append({'start_ts': cursor, 'end_ts': gap_end, 'state': 'collection_gap'})
            observed_end = gap_end + gap_step
            coverage.append({'start_ts': gap_end, 'end_ts': observed_end, 'state': 'observed'})
            cursor = observed_end
        coverage.append({'start_ts': cursor, 'end_ts': end_ts, 'state': 'observed'})
        fixture = self._metric_fixture('cpu', points, start_ts, end_ts, coverage=coverage)
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            with page.expect_request(lambda r: urlparse(r.url).path == '/api/telemetry/history'):
                page.locator('#range-preset-90d').click()
            page.wait_for_function(
                "() => typeof window.__historyStackRenderMs === 'number' "
                "&& Number.isFinite(window.__historyStackRenderMs)",
                timeout=20_000,
            )
            render_ms = page.evaluate('window.__historyStackRenderMs')
            self.assertIsInstance(render_ms, (int, float))
            self.assertGreaterEqual(render_ms, 0)
            print(
                f"\nR-01 baseline: four-chart stack render at 90d preset, "
                f"2048 pts/series, {gap_count} non-observed intervals: "
                f"{render_ms:.2f}ms (developer machine, not Pi-class)"
            )
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-04 Task 1: least-squares trend with three honest confidence tiers
    # (D-08, D-09, HIS-06). window.__historyTrendTestHooks is the same
    # test-only-global pattern as window.__historyStackRenderMs -- the two
    # functions under test are otherwise private to the advanced.js IIFE.
    # ------------------------------------------------------------------

    def _trend_page(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                route.fulfill(status=200, json=self._empty_history_fixture(1_700_000_000, 1_700_003_600))
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        return page

    @staticmethod
    def _trend_point(ts, avg_value):
        return {'ts': ts, 'avg_value': avg_value}

    def test_least_squares_slope_over_exact_gradient_returns_that_gradient(self):
        page = self._trend_page()
        try:
            gradient = 0.002  # value units per second
            points = [self._trend_point(1_700_000_000 + i * 3600, 10.0 + gradient * i * 3600) for i in range(5)]
            slope = page.evaluate(
                '(points) => window.__historyTrendTestHooks.leastSquaresSlope(points)', points,
            )
            self.assertAlmostEqual(slope, gradient, places=6)
        finally:
            page.close()

    def test_least_squares_slope_over_flat_series_returns_zero(self):
        page = self._trend_page()
        try:
            points = [self._trend_point(1_700_000_000 + i * 3600, 42.0) for i in range(5)]
            slope = page.evaluate(
                '(points) => window.__historyTrendTestHooks.leastSquaresSlope(points)', points,
            )
            self.assertEqual(slope, 0)
        finally:
            page.close()

    def test_least_squares_slope_skips_null_avg_value_points(self):
        page = self._trend_page()
        try:
            gradient = 0.001
            base_points = [self._trend_point(1_700_000_000 + i * 3600, 10.0 + gradient * i * 3600) for i in range(6)]
            with_nulls = base_points[:2] + [self._trend_point(1_700_000_000 + 2 * 3600, None)] + base_points[2:]
            slope_with_nulls = page.evaluate(
                '(points) => window.__historyTrendTestHooks.leastSquaresSlope(points)', with_nulls,
            )
            slope_without_nulls = page.evaluate(
                '(points) => window.__historyTrendTestHooks.leastSquaresSlope(points)', base_points,
            )
            self.assertAlmostEqual(slope_with_nulls, slope_without_nulls, places=9)
        finally:
            page.close()

    def test_trend_display_withheld_below_three_usable_points_regardless_of_slope(self):
        page = self._trend_page()
        try:
            points = [self._trend_point(1_700_000_000, 10.0), self._trend_point(1_700_003_600, 90.0)]
            result = page.evaluate(
                "(points) => window.__historyTrendTestHooks.trendDisplay('disk', points, 86400)", points,
            )
            self.assertEqual(result, 'Not enough data for a trend')
        finally:
            page.close()

    def test_trend_display_low_confidence_at_three_and_nine_points(self):
        page = self._trend_page()
        try:
            for count in (3, 9):
                with self.subTest(count=count):
                    points = [self._trend_point(1_700_000_000 + i * 3600, 10.0 + i) for i in range(count)]
                    result = page.evaluate(
                        "(points) => window.__historyTrendTestHooks.trendDisplay('disk', points, 86400)", points,
                    )
                    self.assertTrue(result.endswith(f'(low confidence — {count} points)'))
        finally:
            page.close()

    def test_trend_display_no_qualifier_at_ten_points(self):
        page = self._trend_page()
        try:
            points = [self._trend_point(1_700_000_000 + i * 3600, 10.0 + i) for i in range(10)]
            result = page.evaluate(
                "(points) => window.__historyTrendTestHooks.trendDisplay('disk', points, 86400)", points,
            )
            self.assertNotIn('low confidence', result)
        finally:
            page.close()

    def test_trend_display_steady_band_has_no_sign_or_arrow(self):
        page = self._trend_page()
        try:
            points = [self._trend_point(1_700_000_000 + i * 3600, 42.0) for i in range(10)]
            result = page.evaluate(
                "(points) => window.__historyTrendTestHooks.trendDisplay('disk', points, 86400)", points,
            )
            self.assertIn('steady', result)
            self.assertNotIn('+', result)
            self.assertNotIn('-', result)
            self.assertNotIn('↑', result)
            self.assertNotIn('↓', result)
        finally:
            page.close()

    def test_trend_display_uses_hourly_unit_at_24h_and_daily_unit_just_beyond(self):
        page = self._trend_page()
        try:
            points = [self._trend_point(1_700_000_000 + i * 3600, 10.0 + i) for i in range(10)]
            hourly = page.evaluate(
                "(points) => window.__historyTrendTestHooks.trendDisplay('disk', points, 86400)", points,
            )
            daily = page.evaluate(
                "(points) => window.__historyTrendTestHooks.trendDisplay('disk', points, 86401)", points,
            )
            self.assertIn('/hour', hourly)
            self.assertIn('/day', daily)
        finally:
            page.close()

    def test_trend_display_never_contains_a_projection(self):
        page = self._trend_page()
        try:
            points = [self._trend_point(1_700_000_000 + i * 3600, 10.0 + i) for i in range(10)]
            result = page.evaluate(
                "(points) => window.__historyTrendTestHooks.trendDisplay('disk', points, 86400)", points,
            )
            for forbidden in ('will reach', 'projected', 'forecast', 'days remaining', 'until full'):
                self.assertNotIn(forbidden, result.lower())
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-04 Task 2: the comparison row -- latest, minimum, maximum, average
    # and trend, all describing the same selected-range window (D-08, D-09).
    # ------------------------------------------------------------------

    @staticmethod
    def _bucket_point(ts, min_value, max_value, avg_value, latest_value, sample_count=1):
        return {
            'ts': ts, 'min_value': min_value, 'max_value': max_value, 'avg_value': avg_value,
            'latest_value': latest_value, 'sample_count': sample_count, 'observed_seconds': 60,
            'gap_seconds': 0, 'unknown_seconds': 0,
        }

    def _comparison_page(self, cpu_fixture, start_ts, end_ts):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                metric = query['metric'][0]
                route.fulfill(
                    status=200,
                    json=cpu_fixture if metric == 'cpu' else self._empty_history_fixture(start_ts, end_ts),
                )
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="history"]').click()
        page.wait_for_function(
            "() => (document.querySelector('#comparison-cpu').textContent || '').includes('Latest')",
            timeout=5_000,
        )
        return page

    def test_comparison_row_ids_present_for_all_four_metrics(self):
        page = self._trend_page()
        try:
            page.locator('[data-section="history"]').click()
            page.locator('#history-section').wait_for(state='visible', timeout=5_000)
            for metric in ('cpu', 'ram', 'disk', 'temp'):
                self.assertEqual(page.locator(f'#comparison-{metric}').count(), 1)
        finally:
            page.close()

    def test_comparison_row_reports_known_minimum_maximum_and_weighted_average(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        points = [
            self._bucket_point(start_ts, 10.0, 20.0, 15.0, 15.0, sample_count=2),
            self._bucket_point(start_ts + 1800, 5.0, 30.0, 25.0, 25.0, sample_count=6),
        ]
        # weighted average = (15*2 + 25*6) / 8 = 22.5
        fixture = self._metric_fixture('cpu', points, start_ts, end_ts)
        page = self._comparison_page(fixture, start_ts, end_ts)
        try:
            text = page.locator('#comparison-cpu').text_content()
            self.assertIn('Minimum: 5.0%', text)
            self.assertIn('Maximum: 30.0%', text)
            self.assertIn('Average: 22.5%', text)
            self.assertIn('Latest: 25.0%', text)
        finally:
            page.close()

    def test_comparison_row_latest_never_reads_as_current_for_past_ending_range(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        points = [self._bucket_point(start_ts, 10.0, 10.0, 10.0, 10.0)]
        fixture = self._metric_fixture('cpu', points, start_ts, end_ts)
        page = self._comparison_page(fixture, start_ts, end_ts)
        try:
            text = page.locator('#comparison-cpu').text_content()
            self.assertIn('Latest: 10.0% (as of', text)
        finally:
            page.close()

    def test_comparison_row_empty_range_renders_unknown_not_zero(self):
        start_ts = 1_700_000_000
        end_ts = start_ts + 3600
        fixture = self._metric_fixture(
            'cpu', [], start_ts, end_ts,
            coverage=[{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'}],
        )
        page = self._comparison_page(fixture, start_ts, end_ts)
        try:
            text = page.locator('#comparison-cpu').text_content()
            self.assertIn('Latest: Unknown', text)
            self.assertIn('Minimum: Unknown', text)
            self.assertIn('Maximum: Unknown', text)
            self.assertIn('Average: Unknown', text)
            self.assertIn('Not enough data for a trend', text)
            self.assertNotIn('0%', text)
        finally:
            page.close()

    def test_comparison_row_equal_min_max_still_renders_all_values_with_steady_trend(self):
        start_ts = 1_700_000_000
        points = [self._bucket_point(start_ts + i * 600, 50.0, 50.0, 50.0, 50.0) for i in range(10)]
        end_ts = start_ts + 600 * 10
        fixture = self._metric_fixture('cpu', points, start_ts, end_ts)
        page = self._comparison_page(fixture, start_ts, end_ts)
        try:
            text = page.locator('#comparison-cpu').text_content()
            self.assertIn('Minimum: 50.0%', text)
            self.assertIn('Maximum: 50.0%', text)
            self.assertIn('Average: 50.0%', text)
            self.assertIn('Latest: 50.0%', text)
            self.assertIn('steady', text)
        finally:
            page.close()


class HistoryDstAnnotationLondonTests(unittest.TestCase):
    """04-04 Task 3: a zone that observes DST annotates its two transitions.

    A separate class (own app/server instance, own TZ) rather than reusing
    HistoryInvestigationUiTests -- that class's app is loaded once for
    Australia/Sydney via a module-level importlib.reload() in load_app(),
    and reloading dashboard.app again mid-class would rewrite the shared
    module namespace every already-bound route handler on that class's
    still-running server reads its SETTINGS from.
    """

    @classmethod
    def setUpClass(cls):
        cls.appmod, cls.db_path = load_app({'TZ': 'Europe/London'})
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
    def _last_sunday(year, month):
        last_day = calendar.monthrange(year, month)[1]
        date = datetime(year, month, last_day, tzinfo=timezone.utc)
        offset = (date.weekday() - 6) % 7  # weekday(): Monday=0 .. Sunday=6
        return date - timedelta(days=offset)

    @classmethod
    def _spring_forward_epoch(cls, year=2024):
        # UK/EU rule: clocks spring forward at 01:00 UTC on the last Sunday
        # of March. Computed from the calendar, not a hard-coded date.
        return int(cls._last_sunday(year, 3).replace(hour=1, minute=0, second=0).timestamp())

    @classmethod
    def _fall_back_epoch(cls, year=2024):
        # UK/EU rule: clocks fall back at 01:00 UTC on the last Sunday of
        # October.
        return int(cls._last_sunday(year, 10).replace(hour=1, minute=0, second=0).timestamp())

    @staticmethod
    def _dst_fixture(metric, start_ts, end_ts):
        return {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'selector': {'kind': 'host', 'metric': metric},
            'effective_resolution_seconds': 3600,
            'point_budget': 2048,
            'source_resolutions_seconds': [3600],
            'points': [],
            'coverage': [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'}],
            'aggregation_pending': [],
        }

    @staticmethod
    def _config_fixture(tz):
        return {
            'timezone': tz, 'alerting_enabled': False,
            'uptime_buckets': [], 'trigger_rate_limit': 4, 'trigger_rate_window_seconds': 60,
        }

    def _load_history_with_range(self, start_ts, end_ts, tz='Europe/London'):
        snapshot = HistoryInvestigationUiTests._snapshot()
        config_fixture = self._config_fixture(tz)

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                metric = query.get('metric', ['cpu'])[0]
                route.fulfill(status=200, json=self._dst_fixture(metric, start_ts, end_ts))
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="history"]').click()
        page.locator('#history-time-axis text').first.wait_for(timeout=5_000)
        return page

    def test_spring_forward_annotates_exactly_one_tick_naming_absent_hour(self):
        transition = self._spring_forward_epoch()
        page = self._load_history_with_range(transition - 3 * 3600, transition + 3 * 3600)
        try:
            annotated = page.locator('#history-time-axis .hist-dst-tick')
            self.assertEqual(annotated.count(), 1)
            # text_content() concatenates the <title> child's text too --
            # startswith isolates the tick's own visible label.
            self.assertTrue(annotated.first.text_content().startswith('⚠ DST transition'))
            self.assertIn('absent', annotated.first.locator('title').text_content().lower())
            self.assertEqual(page.locator('#history-time-axis text').count(), 7)
        finally:
            page.close()

    def test_fall_back_annotates_the_two_identical_local_label_ticks(self):
        transition = self._fall_back_epoch()
        page = self._load_history_with_range(transition - 3 * 3600, transition + 3 * 3600)
        try:
            annotated = page.locator('#history-time-axis .hist-dst-tick')
            self.assertEqual(annotated.count(), 2)
            for index in range(2):
                self.assertTrue(annotated.nth(index).text_content().startswith('⚠ DST transition'))
                self.assertIn('twice', annotated.nth(index).locator('title').text_content().lower())
            self.assertEqual(page.locator('#history-time-axis text').count(), 7)
        finally:
            page.close()


class HistoryDstAnnotationUtcTests(unittest.TestCase):
    """04-04 Task 3: UTC never observes DST, so no annotation can ever fire
    -- same two ranges as HistoryDstAnnotationLondonTests, different zone.
    """

    @classmethod
    def setUpClass(cls):
        cls.appmod, cls.db_path = load_app({'TZ': 'UTC'})
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

    def _load_history_with_range(self, start_ts, end_ts):
        snapshot = HistoryInvestigationUiTests._snapshot()
        config_fixture = HistoryDstAnnotationLondonTests._config_fixture('UTC')

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                metric = query.get('metric', ['cpu'])[0]
                route.fulfill(
                    status=200,
                    json=HistoryDstAnnotationLondonTests._dst_fixture(metric, start_ts, end_ts),
                )
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="history"]').click()
        page.locator('#history-time-axis text').first.wait_for(timeout=5_000)
        return page

    def test_spring_forward_range_under_utc_has_no_annotation(self):
        transition = HistoryDstAnnotationLondonTests._spring_forward_epoch()
        page = self._load_history_with_range(transition - 3 * 3600, transition + 3 * 3600)
        try:
            self.assertEqual(page.locator('#history-time-axis .hist-dst-tick').count(), 0)
            self.assertEqual(page.locator('#history-time-axis text').count(), 7)
        finally:
            page.close()

    def test_fall_back_range_under_utc_has_no_annotation(self):
        transition = HistoryDstAnnotationLondonTests._fall_back_epoch()
        page = self._load_history_with_range(transition - 3 * 3600, transition + 3 * 3600)
        try:
            self.assertEqual(page.locator('#history-time-axis .hist-dst-tick').count(), 0)
            self.assertEqual(page.locator('#history-time-axis text').count(), 7)
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
