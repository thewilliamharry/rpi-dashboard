import calendar
import pathlib
import re
import threading
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.helpers import cleanup_db, load_app

ROOT = pathlib.Path(__file__).resolve().parents[1]

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

    @staticmethod
    def _service(port, name='Test Service', **overrides):
        """A minimal well-formed services[] entry (04-06): the fields
        renderServices/serviceAvailability/serviceFreshness/serviceDuration
        each read, with the rest defaulted so a test only names what it
        actually varies.
        """
        service = {
            'port': port, 'name': name, 'availability': 'online', 'latency_ms': 12.0,
            'critical': False, 'tags': [], 'pinned_order': port,
            'state_duration_seconds': 120,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'expected_cadence_seconds': 300, 'last_probe_ts': 1_700_000_000,
        }
        service.update(overrides)
        return service

    @staticmethod
    def _service_history_fixture(start_ts, end_ts, points=None):
        return {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'selector': {'kind': 'service', 'port': 8080},
            'effective_resolution_seconds': 60,
            'point_budget': 2048,
            'source_resolutions_seconds': [60],
            'points': points if points is not None else [],
            'coverage': [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'not_yet_monitored'}],
            'aggregation_pending': [],
        }

    @staticmethod
    def _events_history_fixture(start_ts, end_ts, episodes=None, events=None):
        return {
            'requested': {'start_ts': start_ts, 'end_ts': end_ts},
            'filters': {'maintenance': 'include'},
            'episodes': episodes if episodes is not None else [],
            'events': events if events is not None else [],
            'flapping_groups': [],
            'row_budget': 2048,
            'truncated': False,
            'matched_count': 0,
        }

    @staticmethod
    def _service_point(
        ts, *, online_seconds=0, offline_seconds=0, unknown_seconds=0, gap_seconds=0,
        latency_min=None, latency_max=None, latency_avg=None, check_count=0,
        failure_class_counts=None,
    ):
        """One `_compose_service_bucket`-shaped point (04-06 Task 2/3)."""
        return {
            'ts': ts, 'online_seconds': online_seconds, 'offline_seconds': offline_seconds,
            'unknown_seconds': unknown_seconds, 'gap_seconds': gap_seconds,
            'latency_min': latency_min, 'latency_max': latency_max, 'latency_avg': latency_avg,
            'check_count': check_count, 'failure_class_counts': failure_class_counts or {},
        }

    @staticmethod
    def _episode(
        port, down_ts, recovered_ts=None, *, suppressed_reason=None,
        maintenance_grace_until=None, overrun=False, grace_seconds=0, fault_seconds=None,
        **overrides,
    ):
        """One `group_episodes`/`split_overrun_span`-shaped episode (04-06 Task 2)."""
        open_episode = recovered_ts is None
        duration = None if open_episode else recovered_ts - down_ts
        default_fault = None
        if duration is not None:
            default_fault = fault_seconds if fault_seconds is not None else max(0, duration - grace_seconds)
        episode = {
            'port': port, 'service_name': 'Test Service', 'critical': False,
            'down_ts': down_ts, 'raised_ts': down_ts, 'recovered_ts': recovered_ts,
            'open': open_episode, 'duration_seconds': duration,
            'failure_class': None, 'suppressed_reason': suppressed_reason,
            'maintenance_grace_until': maintenance_grace_until,
            'transitions': [], 'overrun': overrun, 'grace_seconds': grace_seconds,
            'fault_seconds': default_fault, 'flapping_group_id': None,
        }
        episode.update(overrides)
        return episode

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
            # Scoped to #history-content (04-06 adds a fifth .hist-plot/.hist-coverage-strip
            # pair -- #service-latency-chart/#strip-service-latency -- reusing these same
            # classes verbatim for the selected-service view, which lives in its own
            # #service-history-group sibling rather than this host stack).
            chart_ids = page.eval_on_selector_all('#history-content .hist-plot', 'nodes => nodes.map(n => n.id)')
            self.assertEqual(chart_ids, ['chart-cpu', 'chart-ram', 'chart-disk', 'chart-temp'])
            strip_ids = page.eval_on_selector_all('#history-content .hist-coverage-strip', 'nodes => nodes.map(n => n.id)')
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

    # ------------------------------------------------------------------
    # 04-05 Task 1: canonical local-time custom range entry, validated
    # against exactly the server's own bounds before anything is fetched
    # (D-03). start_ts/end_ts fixtures below are 2024 dates -- far enough in
    # the past that they can never accidentally collide with "in the future"
    # regardless of when this suite runs, and far enough from any DST
    # transition boundary that Sydney's offset is unambiguous.
    # ------------------------------------------------------------------

    def _history_page_with_request_counter(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        counters = {'history': 0}

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                counters['history'] += 1
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
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="history"]').click()
        page.locator('#history-section').wait_for(state='visible', timeout=5_000)
        return page, counters

    def test_apply_custom_range_control_exact_text_and_ids_present(self):
        page, _counters = self._history_page_with_request_counter()
        try:
            self.assertEqual(page.locator('#range-start').count(), 1)
            self.assertEqual(page.locator('#range-end').count(), 1)
            self.assertEqual(page.locator('#apply-custom-range').count(), 1)
            self.assertEqual(page.locator('#apply-custom-range').text_content(), 'Apply custom range')
        finally:
            page.close()

    def test_blank_start_field_renders_message_and_issues_zero_requests(self):
        page, counters = self._history_page_with_request_counter()
        try:
            page.locator('#range-start').fill('')
            page.locator('#range-end').fill('2024-01-15 14:00')
            before = counters['history']
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#range-error').text_content(), 'Enter both a start and an end time.')
            self.assertEqual(counters['history'], before)
        finally:
            page.close()

    def test_whitespace_only_field_renders_message_and_issues_zero_requests(self):
        page, counters = self._history_page_with_request_counter()
        try:
            page.locator('#range-start').fill('   ')
            page.locator('#range-end').fill('2024-01-15 14:00')
            before = counters['history']
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#range-error').text_content(), 'Enter both a start and an end time.')
            self.assertEqual(counters['history'], before)
        finally:
            page.close()

    def test_equal_start_and_end_renders_server_message_and_issues_zero_requests(self):
        page, counters = self._history_page_with_request_counter()
        try:
            page.locator('#range-start').fill('2024-01-15 10:00')
            page.locator('#range-end').fill('2024-01-15 10:00')
            before = counters['history']
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#range-error').text_content(), 'start_ts must be before end_ts')
            self.assertEqual(counters['history'], before)
        finally:
            page.close()

    def test_reversed_start_and_end_rejected_values_not_swapped(self):
        page, counters = self._history_page_with_request_counter()
        try:
            page.locator('#range-start').fill('2024-01-15 14:00')
            page.locator('#range-end').fill('2024-01-15 10:00')
            before = counters['history']
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#range-error').text_content(), 'start_ts must be before end_ts')
            self.assertEqual(counters['history'], before)
            # The operator's own entered text is never swapped back at them.
            self.assertEqual(page.locator('#range-start').input_value(), '2024-01-15 14:00')
            self.assertEqual(page.locator('#range-end').input_value(), '2024-01-15 10:00')
            # And the governing range itself is unchanged -- still the 24h default.
            self.assertEqual(page.locator('#range-preset-24h').get_attribute('aria-pressed'), 'true')
        finally:
            page.close()

    def test_span_over_90_days_renders_server_message_and_issues_zero_requests(self):
        page, counters = self._history_page_with_request_counter()
        try:
            page.locator('#range-start').fill('2024-01-01 00:00')
            page.locator('#range-end').fill('2024-04-15 00:00')
            before = counters['history']
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#range-error').text_content(), 'requested span exceeds 90 days')
            self.assertEqual(counters['history'], before)
        finally:
            page.close()

    def test_future_end_renders_server_message_and_issues_zero_requests(self):
        page, counters = self._history_page_with_request_counter()
        try:
            page.locator('#range-start').fill('2098-12-01 00:00')
            page.locator('#range-end').fill('2099-01-01 00:00')
            before = counters['history']
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#range-error').text_content(), 'end_ts must not be in the future')
            self.assertEqual(counters['history'], before)
        finally:
            page.close()

    def test_valid_custom_range_issues_request_with_parsed_bounds_in_configured_timezone(self):
        page, _counters = self._history_page_with_request_counter()
        try:
            page.locator('#range-start').fill('2024-01-15 10:00')
            page.locator('#range-end').fill('2024-01-15 14:00')
            with page.expect_request(
                lambda request: urlparse(request.url).path == '/api/telemetry/history',
            ) as request_info:
                page.locator('#apply-custom-range').click()
            query = parse_qs(urlparse(request_info.value.url).query)
            # 2024-01-15 10:00/14:00 Australia/Sydney (AEDT, UTC+11 in January).
            self.assertEqual(int(query['start_ts'][0]), 1_705_273_200)
            self.assertEqual(int(query['end_ts'][0]), 1_705_287_600)
            self.assertTrue(page.locator('#range-error').is_hidden())
            # Applying a valid custom range clears any preset's selected state.
            for preset in HISTORY_PRESET_SPANS:
                self.assertEqual(page.locator(f'#range-preset-{preset}').get_attribute('aria-pressed'), 'false')
        finally:
            page.close()

    def test_fields_populated_after_preset_click_custom_apply_and_reload_with_stored_custom(self):
        page, _counters = self._history_page_with_request_counter()
        try:
            # (a) After a preset click, the fields state that preset's own span.
            page.locator('#range-preset-6h').click()
            page.wait_for_function(
                "() => /^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$/.test(document.getElementById('range-start').value)",
                timeout=5_000,
            )
            start_text = page.locator('#range-start').input_value()
            end_text = page.locator('#range-end').input_value()
            hooks = 'window.__historyRangeTestHooks'
            start_parsed = page.evaluate(f"{hooks}.parseLocalRangeInput({start_text!r})")
            end_parsed = page.evaluate(f"{hooks}.parseLocalRangeInput({end_text!r})")
            self.assertEqual(end_parsed - start_parsed, HISTORY_PRESET_SPANS['6h'])

            # (b) After a custom apply, the fields show exactly what was applied.
            page.locator('#range-start').fill('2024-01-15 10:00')
            page.locator('#range-end').fill('2024-01-15 14:00')
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='hidden', timeout=5_000)
            self.assertEqual(page.locator('#range-start').input_value(), '2024-01-15 10:00')
            self.assertEqual(page.locator('#range-end').input_value(), '2024-01-15 14:00')
        finally:
            page.close()

    def test_fields_populated_after_reload_with_stored_custom_range(self):
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
        page.add_init_script(
            "localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify("
            "{refreshSeconds: 15, historyRange: {custom: {start_ts: 1705273200, end_ts: 1705287600}}}));",
        )
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-section').wait_for(state='visible', timeout=5_000)
            page.wait_for_function(
                "() => document.getElementById('range-start').value === '2024-01-15 10:00'",
                timeout=5_000,
            )
            self.assertEqual(page.locator('#range-start').input_value(), '2024-01-15 10:00')
            self.assertEqual(page.locator('#range-end').input_value(), '2024-01-15 14:00')
            for preset in HISTORY_PRESET_SPANS:
                self.assertEqual(page.locator(f'#range-preset-{preset}').get_attribute('aria-pressed'), 'false')
        finally:
            page.close()

    def test_hostile_stored_custom_range_yields_24h_default(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        hostile_customs = {
            'strings': "{start_ts: 'a', end_ts: 'b'}",
            'nulls': '{start_ts: null, end_ts: null}',
            'inverted_pair': '{start_ts: 2000, end_ts: 1000}',
        }
        for label, custom_expression in hostile_customs.items():
            with self.subTest(custom=label):
                page = self.browser.new_page()
                page.add_init_script(
                    "localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify("
                    f"{{refreshSeconds: 15, historyRange: {{custom: {custom_expression}}}}}));",
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

    def test_apply_button_disabled_while_in_flight_fields_stay_visible(self):
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
        page.add_init_script(self.HISTORY_FETCH_HOLD_HARNESS)
        page.route('**/api/**', route_api)
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.wait_for_function('window.__heldHistoryReleases.length === 4', timeout=5_000)
            page.evaluate('window.__releaseAllHeldHistoryFetches()')
            page.locator('#apply-custom-range').wait_for(state='attached', timeout=5_000)
            page.wait_for_function(
                "() => document.getElementById('apply-custom-range').disabled === false",
                timeout=5_000,
            )

            page.locator('#range-start').fill('2024-01-15 10:00')
            page.locator('#range-end').fill('2024-01-15 14:00')
            page.evaluate('window.__heldHistoryReleases = []')
            page.locator('#apply-custom-range').click()
            page.wait_for_function('window.__heldHistoryReleases.length === 4', timeout=5_000)
            self.assertTrue(page.locator('#apply-custom-range').is_disabled())
            self.assertTrue(page.locator('#range-start').is_visible())
            self.assertTrue(page.locator('#range-end').is_visible())
            page.evaluate('window.__releaseAllHeldHistoryFetches()')
            page.wait_for_function(
                "() => document.getElementById('apply-custom-range').disabled === false",
                timeout=5_000,
            )
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-05 Task 2: one navigation stack for every narrowing gesture (D-15).
    # The stack's own contract (push/pop/no-op/limit/Back rendering) is
    # independent of which gesture triggers a push, so it is exercised here
    # directly through window.__historyRangeTestHooks.setInvestigationRange
    # -- the exact same entry point Task 3's drag-to-select and plan 04-07's
    # incident focus both call.
    # ------------------------------------------------------------------

    def test_range_back_absent_when_stack_empty_present_after_one_push(self):
        page, _counters = self._history_page_with_request_counter()
        try:
            self.assertEqual(page.locator('#range-back').count(), 0)
            page.evaluate(
                "window.__historyRangeTestHooks.setInvestigationRange("
                "{start_ts: 1700000000, end_ts: 1700003600, origin: 'drag', label: 'test range'})",
            )
            page.locator('#range-back').wait_for(state='attached', timeout=5_000)
            self.assertEqual(page.locator('#range-back').count(), 1)
        finally:
            page.close()

    def test_three_pushes_and_three_backs_restore_original_range_exactly(self):
        page, _counters = self._history_page_with_request_counter()
        hooks = 'window.__historyRangeTestHooks'
        try:
            original_start = page.locator('#range-start').input_value()
            original_end = page.locator('#range-end').input_value()
            # Minute-aligned (a multiple of 60): #range-start/#range-end format
            # at minute precision (YYYY-MM-DD HH:MM), so a sub-minute epoch
            # value cannot round-trip through the fields losslessly -- that is
            # a field-precision property, not a stack-restoration defect, and
            # is sidestepped here by choosing values with zero seconds.
            pushes = [
                (1_699_999_980, 1_700_003_580),
                (1_700_100_000, 1_700_103_600),
                (1_700_199_960, 1_700_203_560),
            ]
            for start_ts, end_ts in pushes:
                page.evaluate(
                    f"{hooks}.setInvestigationRange({{start_ts: {start_ts}, end_ts: {end_ts}, "
                    "origin: 'drag', label: 'pushed'})",
                )
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), 3)
            # LIFO: popping restores, in order, the range each push LEFT --
            # the second push's own bounds, then the first push's own
            # bounds, then the original range the first push left.
            expected_after_pop = [pushes[1], pushes[0], None]
            for expected in expected_after_pop:
                page.locator('#range-back').click()
                if expected is None:
                    self.assertEqual(page.locator('#range-start').input_value(), original_start)
                    self.assertEqual(page.locator('#range-end').input_value(), original_end)
                else:
                    start_text = page.locator('#range-start').input_value()
                    end_text = page.locator('#range-end').input_value()
                    start_parsed = page.evaluate(f"{hooks}.parseLocalRangeInput({start_text!r})")
                    end_parsed = page.evaluate(f"{hooks}.parseLocalRangeInput({end_text!r})")
                    self.assertEqual(start_parsed, expected[0])
                    self.assertEqual(end_parsed, expected[1])
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), 0)
            self.assertEqual(page.locator('#range-back').count(), 0)
        finally:
            page.close()

    def test_push_of_identical_range_creates_no_entry(self):
        page, _counters = self._history_page_with_request_counter()
        hooks = 'window.__historyRangeTestHooks'
        try:
            current = page.evaluate(f'{hooks}.resolveRangeBounds()')
            page.evaluate(
                f"{hooks}.setInvestigationRange({{start_ts: {current['start_ts']}, "
                f"end_ts: {current['end_ts']}, origin: 'drag', label: 'same'}})",
            )
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), 0)
            self.assertEqual(page.locator('#range-back').count(), 0)
        finally:
            page.close()

    def test_preset_after_pushes_clears_stack_and_adopts_preset(self):
        page, _counters = self._history_page_with_request_counter()
        hooks = 'window.__historyRangeTestHooks'
        try:
            for i in range(2):
                page.evaluate(
                    f"{hooks}.setInvestigationRange({{start_ts: {1_700_000_000 + i}, "
                    f"end_ts: {1_700_003_600 + i}, origin: 'drag', label: 'pushed'}})",
                )
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), 2)
            page.locator('#range-preset-6h').click()
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), 0)
            self.assertEqual(page.locator('#range-back').count(), 0)
            self.assertEqual(page.locator('#range-preset-6h').get_attribute('aria-pressed'), 'true')
        finally:
            page.close()

    def test_custom_apply_after_pushes_clears_stack(self):
        page, _counters = self._history_page_with_request_counter()
        hooks = 'window.__historyRangeTestHooks'
        try:
            for i in range(2):
                page.evaluate(
                    f"{hooks}.setInvestigationRange({{start_ts: {1_700_000_000 + i}, "
                    f"end_ts: {1_700_003_600 + i}, origin: 'drag', label: 'pushed'}})",
                )
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), 2)
            page.locator('#range-start').fill('2024-01-15 10:00')
            page.locator('#range-end').fill('2024-01-15 14:00')
            page.locator('#apply-custom-range').click()
            page.locator('#range-error').wait_for(state='hidden', timeout=5_000)
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), 0)
            self.assertEqual(page.locator('#range-back').count(), 0)
        finally:
            page.close()

    def test_range_back_text_and_title_match_back_to_label(self):
        page, _counters = self._history_page_with_request_counter()
        hooks = 'window.__historyRangeTestHooks'
        try:
            page.evaluate(
                f"{hooks}.setInvestigationRange({{start_ts: 1700000000, end_ts: 1700003600, "
                "origin: 'drag', label: 'a distinctive label'})",
            )
            page.locator('#range-back').wait_for(state='attached', timeout=5_000)
            self.assertEqual(page.locator('#range-back').text_content(), 'Back to a distinctive label')
            self.assertEqual(page.locator('#range-back').get_attribute('title'), 'Back to a distinctive label')
        finally:
            page.close()

    def test_stack_never_exceeds_range_stack_limit(self):
        page, _counters = self._history_page_with_request_counter()
        hooks = 'window.__historyRangeTestHooks'
        try:
            limit = page.evaluate(f'{hooks}.RANGE_STACK_LIMIT')
            for i in range(limit + 10):
                page.evaluate(
                    f"{hooks}.setInvestigationRange({{start_ts: {1_700_000_000 + i}, "
                    f"end_ts: {1_700_003_600 + i}, origin: 'drag', label: 'pushed ' + {i}}})",
                )
            self.assertEqual(page.evaluate(f'{hooks}.rangeStack().length'), limit)
        finally:
            page.close()

    def test_incident_pad_constants_declared_with_documented_values(self):
        js = (ROOT / 'dashboard/advanced.js').read_text(encoding='utf-8')
        self.assertRegex(js, r'INCIDENT_PAD_FRACTION\s*=\s*0\.15')
        self.assertRegex(js, r'INCIDENT_PAD_FLOOR_SECONDS\s*=\s*300')

    def test_range_stack_never_reaches_the_url_or_browser_history_api(self):
        js = (ROOT / 'dashboard/advanced.js').read_text(encoding='utf-8')
        for forbidden in ('pushState', 'replaceState', 'location.search'):
            self.assertNotIn(forbidden, js)

    # ------------------------------------------------------------------
    # 04-05 Task 3: drag-to-select across any host chart, landing on exactly
    # the same range state the fields describe (D-03), without regenerating
    # a single chart <path> during the gesture (R-01/Research Pitfall 3).
    # ------------------------------------------------------------------

    def _drag_ready_page(self):
        """A page whose requested range is fixed and known to the test (not
        a live Date.now()-derived preset), so drag fractions can be computed
        against a domain the test itself controls."""
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        start_ts = 1_700_000_000
        end_ts = start_ts + 86_400
        fixture = self._empty_history_fixture(start_ts, end_ts)
        fixture['points'] = [self._point(start_ts, 10.0), self._point(end_ts - 60, 20.0)]
        fixture['coverage'] = [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'observed'}]
        counters = {'history': 0}

        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                counters['history'] += 1
                route.fulfill(status=200, json=fixture)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()

        page = self.browser.new_page()
        page.route('**/api/**', route_api)
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="history"]').click()
        page.locator('#history-section').wait_for(state='visible', timeout=5_000)
        page.wait_for_function(
            "() => !!document.querySelector('#chart-cpu path').getAttribute('d')",
            timeout=5_000,
        )
        return page, start_ts, end_ts, counters

    def test_drag_across_chart_applies_fraction_of_rendered_span(self):
        page, start_ts, end_ts, _counters = self._drag_ready_page()
        try:
            box = page.locator('#chart-cpu').bounding_box()
            x1 = box['x'] + box['width'] * 0.25
            x2 = box['x'] + box['width'] * 0.75
            y = box['y'] + box['height'] / 2
            page.mouse.move(x1, y)
            page.mouse.down()
            page.mouse.move((x1 + x2) / 2, y)
            with page.expect_request(
                lambda request: urlparse(request.url).path == '/api/telemetry/history',
            ) as request_info:
                page.mouse.move(x2, y)
                page.mouse.up()
            query = parse_qs(urlparse(request_info.value.url).query)
            span = end_ts - start_ts
            expected_start = start_ts + span * 0.25
            expected_end = start_ts + span * 0.75
            self.assertAlmostEqual(int(query['start_ts'][0]), expected_start, delta=3_600)
            self.assertAlmostEqual(int(query['end_ts'][0]), expected_end, delta=3_600)
            page.locator('#range-back').wait_for(state='attached', timeout=5_000)
        finally:
            page.close()

    def test_right_to_left_drag_produces_identical_range_to_left_to_right(self):
        page, start_ts, end_ts, _counters = self._drag_ready_page()
        try:
            box = page.locator('#chart-cpu').bounding_box()
            x1 = box['x'] + box['width'] * 0.75
            x2 = box['x'] + box['width'] * 0.25
            y = box['y'] + box['height'] / 2
            page.mouse.move(x1, y)
            page.mouse.down()
            with page.expect_request(
                lambda request: urlparse(request.url).path == '/api/telemetry/history',
            ) as request_info:
                page.mouse.move(x2, y)
                page.mouse.up()
            query = parse_qs(urlparse(request_info.value.url).query)
            span = end_ts - start_ts
            expected_start = start_ts + span * 0.25
            expected_end = start_ts + span * 0.75
            self.assertAlmostEqual(int(query['start_ts'][0]), expected_start, delta=3_600)
            self.assertAlmostEqual(int(query['end_ts'][0]), expected_end, delta=3_600)
        finally:
            page.close()

    def test_click_without_movement_applies_no_range_and_leaves_back_absent(self):
        page, _start_ts, _end_ts, counters = self._drag_ready_page()
        try:
            box = page.locator('#chart-cpu').bounding_box()
            x = box['x'] + box['width'] / 2
            y = box['y'] + box['height'] / 2
            before = counters['history']
            page.mouse.move(x, y)
            page.mouse.down()
            page.mouse.up()
            page.wait_for_timeout(200)
            self.assertEqual(counters['history'], before)
            self.assertEqual(page.locator('#range-back').count(), 0)
        finally:
            page.close()

    def test_escape_during_drag_cancels_no_range_change_and_overlay_hidden(self):
        page, _start_ts, _end_ts, counters = self._drag_ready_page()
        try:
            box = page.locator('#chart-cpu').bounding_box()
            x1 = box['x'] + box['width'] * 0.25
            x2 = box['x'] + box['width'] * 0.75
            y = box['y'] + box['height'] / 2
            before = counters['history']
            page.mouse.move(x1, y)
            page.mouse.down()
            page.mouse.move(x2, y)
            page.locator('#history-drag-overlay').wait_for(state='visible', timeout=5_000)
            page.keyboard.press('Escape')
            page.locator('#history-drag-overlay').wait_for(state='hidden', timeout=5_000)
            page.mouse.up()
            page.wait_for_timeout(200)
            self.assertEqual(counters['history'], before)
            self.assertEqual(page.locator('#range-back').count(), 0)
        finally:
            page.close()

    def test_five_pointer_moves_leave_chart_paths_unchanged_while_overlay_moves(self):
        page, _start_ts, _end_ts, _counters = self._drag_ready_page()
        try:
            initial_d = {
                metric: page.locator(f'#chart-{metric} path').get_attribute('d')
                for metric in ('cpu', 'ram', 'disk', 'temp')
            }
            box = page.locator('#chart-cpu').bounding_box()
            y = box['y'] + box['height'] / 2
            page.mouse.move(box['x'] + box['width'] * 0.1, y)
            page.mouse.down()
            widths = []
            for fraction in (0.2, 0.35, 0.5, 0.65, 0.8):
                page.mouse.move(box['x'] + box['width'] * fraction, y)
                page.wait_for_timeout(30)
                widths.append(page.locator('#history-drag-overlay').bounding_box()['width'])
            for metric, d in initial_d.items():
                self.assertEqual(page.locator(f'#chart-{metric} path').get_attribute('d'), d)
            self.assertGreater(len(set(round(w) for w in widths)), 1)
            page.mouse.up()
        finally:
            page.close()

    def test_drag_overlay_border_resolves_accent_and_fill_is_not_solid(self):
        page, _start_ts, _end_ts, _counters = self._drag_ready_page()
        try:
            box = page.locator('#chart-cpu').bounding_box()
            x1 = box['x'] + box['width'] * 0.3
            x2 = box['x'] + box['width'] * 0.6
            y = box['y'] + box['height'] / 2
            page.mouse.move(x1, y)
            page.mouse.down()
            page.mouse.move(x2, y)
            page.locator('#history-drag-overlay').wait_for(state='visible', timeout=5_000)
            accent = page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()")
            expected_rgb = page.evaluate(
                "(hex) => { const p = document.createElement('div'); p.style.color = hex; "
                "document.body.appendChild(p); const rgb = getComputedStyle(p).color; p.remove(); return rgb; }",
                accent,
            )
            border_color = page.evaluate(
                "getComputedStyle(document.getElementById('history-drag-overlay')).borderTopColor",
            )
            background = page.evaluate(
                "getComputedStyle(document.getElementById('history-drag-overlay')).backgroundColor",
            )
            # color-mix() can serialize as either rgba(...) or the CSS Color 4
            # color(srgb r g b / a) form depending on engine version -- read
            # the real alpha channel back via a 1x1 canvas rather than
            # pattern-matching a specific serialization string.
            alpha = page.evaluate(
                "(bg) => { const c = document.createElement('canvas'); c.width = 1; c.height = 1; "
                "const ctx = c.getContext('2d'); ctx.fillStyle = bg; ctx.fillRect(0, 0, 1, 1); "
                "return ctx.getImageData(0, 0, 1, 1).data[3]; }",
                background,
            )
            page.mouse.up()
            self.assertEqual(border_color, expected_rgb)
            self.assertGreater(alpha, 0)
            self.assertLess(alpha, 255)
            self.assertNotEqual(background, expected_rgb)
        finally:
            page.close()

    def test_drag_entry_point_documents_missing_keyboard_equivalent_as_phase5_debt(self):
        js = (ROOT / 'dashboard/advanced.js').read_text(encoding='utf-8')
        self.assertIn('Phase 5 / UX-06', js)

    # ------------------------------------------------------------------
    # 04-06 Task 1: one carried, read-only service selection (D-16).
    # ------------------------------------------------------------------

    SERVICE_HISTORY_HOLD_HARNESS = """
        window.__heldServiceReleases = [];
        const realFetch = window.fetch.bind(window);
        window.fetch = (...args) => {
          const url = String(args[0] || '');
          const isServiceTelemetry = url.includes('/api/telemetry/history') && url.includes('kind=service');
          const isServiceEvents = url.includes('/api/events/history');
          if (!isServiceTelemetry && !isServiceEvents) return realFetch(...args);
          const pending = realFetch(...args);
          return new Promise((resolve, reject) => {
            window.__heldServiceReleases.push(() => pending.then(resolve, reject));
          });
        };
        window.__releaseAllHeldServiceFetches = () => {
          const releases = window.__heldServiceReleases;
          window.__heldServiceReleases = [];
          releases.forEach((release) => release());
        };
    """

    def _service_selection_route(
        self, snapshot, config_fixture, *,
        service_status=200, events_status=200,
        service_payload_fn=None, events_payload_fn=None,
        recorded_current=None, recorded_service_kinds=None,
    ):
        def route_api(route):
            path = urlparse(route.request.url).path
            if path == '/api/config':
                route.fulfill(status=200, json=config_fixture)
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(route.request.url).query)
                start_ts = int(query['start_ts'][0])
                end_ts = int(query['end_ts'][0])
                if query.get('kind', [''])[0] == 'service':
                    if recorded_service_kinds is not None:
                        recorded_service_kinds.append(route.request.url)
                    if service_status != 200:
                        route.fulfill(status=service_status, json={'error': 'service history unavailable'})
                        return
                    payload = (
                        service_payload_fn(start_ts, end_ts) if service_payload_fn
                        else self._service_history_fixture(start_ts, end_ts)
                    )
                    route.fulfill(status=200, json=payload)
                    return
                route.fulfill(status=200, json=self._empty_history_fixture(start_ts, end_ts))
                return
            if path == '/api/events/history':
                if events_status != 200:
                    route.fulfill(status=events_status, json={'error': 'events unavailable'})
                    return
                query = parse_qs(urlparse(route.request.url).query)
                start_ts = int(query['start_ts'][0])
                end_ts = int(query['end_ts'][0])
                payload = (
                    events_payload_fn(start_ts, end_ts) if events_payload_fn
                    else self._events_history_fixture(start_ts, end_ts)
                )
                route.fulfill(status=200, json=payload)
                return
            if path == '/api/advanced/current':
                if recorded_current is not None:
                    recorded_current.append((route.request.url, route.request.method))
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()
        return route_api

    def test_selecting_service_in_table_sets_indicator_and_carries_to_history_picker(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        page = self.browser.new_page()
        page.route('**/api/**', self._service_selection_route(snapshot, config_fixture))
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="services"]').click()
            page.locator('#service-investigate-8080').wait_for(state='visible', timeout=5_000)
            page.locator('#service-investigate-8080').click()
            page.wait_for_function(
                "() => document.getElementById('investigating-service').textContent === 'Investigating: Test Service'",
                timeout=5_000,
            )
            self.assertIsNone(page.locator('#investigating-service').get_attribute('hidden'))
            page.locator('[data-section="history"]').click()
            page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#history-service-picker').input_value(), '8080')
        finally:
            page.close()

    def test_selecting_service_in_history_picker_shows_selected_in_services_table(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        page = self.browser.new_page()
        page.route('**/api/**', self._service_selection_route(snapshot, config_fixture))
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
            page.locator('#history-service-picker').select_option('8080')
            page.locator('[data-section="services"]').click()
            page.locator('#service-investigate-8080').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#service-investigate-8080').get_attribute('aria-pressed'), 'true')
            self.assertIn('Stop investigating', page.locator('#service-investigate-8080').get_attribute('aria-label'))
        finally:
            page.close()

    def test_advanced_current_request_byte_identical_before_and_after_selection(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        recorded = []
        page = self.browser.new_page()
        page.route('**/api/**', self._service_selection_route(snapshot, config_fixture, recorded_current=recorded))
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="services"]').click()
            page.locator('#service-investigate-8080').wait_for(state='visible', timeout=5_000)
            recorded.clear()
            with page.expect_request(lambda r: urlparse(r.url).path == '/api/advanced/current'):
                page.locator('#advanced-refresh').click()
            before = recorded[-1]
            page.locator('#service-investigate-8080').click()
            page.wait_for_function(
                "() => document.getElementById('investigating-service').textContent === 'Investigating: Test Service'",
                timeout=5_000,
            )
            with page.expect_request(lambda r: urlparse(r.url).path == '/api/advanced/current'):
                page.locator('#advanced-refresh').click()
            after = recorded[-1]
            self.assertEqual(before, after)
            self.assertNotIn('?', before[0])
        finally:
            page.close()

    def test_clear_selected_service_leaves_range_fields_unchanged(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        page = self.browser.new_page()
        page.route('**/api/**', self._service_selection_route(snapshot, config_fixture))
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
            page.wait_for_function(
                "() => /^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$/.test(document.getElementById('range-start').value)",
                timeout=5_000,
            )
            start_before = page.locator('#range-start').input_value()
            end_before = page.locator('#range-end').input_value()
            page.locator('#history-service-picker').select_option('8080')
            page.wait_for_function(
                "() => document.getElementById('clear-selected-service').hidden === false",
                timeout=5_000,
            )
            page.locator('#clear-selected-service').click()
            page.wait_for_function(
                "() => document.getElementById('investigating-service').hidden === true",
                timeout=5_000,
            )
            self.assertEqual(page.locator('#range-start').input_value(), start_before)
            self.assertEqual(page.locator('#range-end').input_value(), end_before)
        finally:
            page.close()

    def test_hostile_stored_selected_service_values_resolve_to_no_selection(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        hostile_values = {
            'string_port': "'8080'",
            'negative': '-1',
            'out_of_range': '70000',
            'object': '{}',
            'array': '[]',
        }
        for label, value_expression in hostile_values.items():
            with self.subTest(selectedService=label):
                page = self.browser.new_page()
                page.add_init_script(
                    "localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify("
                    f"{{refreshSeconds: 15, selectedService: {value_expression}}}));",
                )
                recorded_kinds = []
                page.route(
                    '**/api/**',
                    self._service_selection_route(
                        snapshot, config_fixture, recorded_service_kinds=recorded_kinds,
                    ),
                )
                try:
                    page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
                    page.locator('[data-section="history"]').click()
                    page.locator('#service-history-empty').wait_for(state='visible', timeout=5_000)
                    self.assertEqual(
                        page.locator('#service-history-empty').text_content(),
                        'Select a service to view its history',
                    )
                    self.assertIsNotNone(page.locator('#investigating-service').get_attribute('hidden'))
                    self.assertEqual(recorded_kinds, [])
                finally:
                    page.close()

    def test_no_selection_renders_placeholder_and_issues_no_service_request(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        recorded_kinds = []
        page = self.browser.new_page()
        page.route(
            '**/api/**',
            self._service_selection_route(snapshot, config_fixture, recorded_service_kinds=recorded_kinds),
        )
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#service-history-empty').wait_for(state='visible', timeout=5_000)
            self.assertEqual(
                page.locator('#service-history-empty').text_content(),
                'Select a service to view its history',
            )
            # Give any (incorrect) service request a chance to have fired.
            page.locator('#chart-cpu path').wait_for(state='attached', timeout=5_000)
            self.assertEqual(recorded_kinds, [])
        finally:
            page.close()

    def test_indicator_and_clear_present_and_operable_while_service_request_pending(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        page = self.browser.new_page()
        page.add_init_script(self.SERVICE_HISTORY_HOLD_HARNESS)
        page.route('**/api/**', self._service_selection_route(snapshot, config_fixture))
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
            page.locator('#history-service-picker').select_option('8080')
            page.wait_for_function('window.__heldServiceReleases.length === 2', timeout=5_000)
            self.assertEqual(
                page.locator('#investigating-service').text_content(), 'Investigating: Test Service',
            )
            self.assertIsNone(page.locator('#investigating-service').get_attribute('hidden'))
            self.assertFalse(page.locator('#clear-selected-service').is_disabled())
            page.locator('#clear-selected-service').click()
            page.wait_for_function(
                "() => document.getElementById('investigating-service').hidden === true",
                timeout=5_000,
            )
            page.evaluate('window.__releaseAllHeldServiceFetches()')
        finally:
            page.close()

    def test_indicator_and_clear_present_and_operable_after_service_request_fails(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        page = self.browser.new_page()
        page.route(
            '**/api/**',
            self._service_selection_route(
                snapshot, config_fixture, service_status=503, events_status=503,
            ),
        )
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
            page.locator('#history-service-picker').select_option('8080')
            page.locator('#service-history-error').wait_for(state='visible', timeout=5_000)
            self.assertEqual(
                page.locator('#investigating-service').text_content(), 'Investigating: Test Service',
            )
            self.assertIsNone(page.locator('#investigating-service').get_attribute('hidden'))
            page.locator('#clear-selected-service').click()
            page.wait_for_function(
                "() => document.getElementById('investigating-service').hidden === true",
                timeout=5_000,
            )
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-06 Task 2: the state band and its latency chart (D-11).
    # ------------------------------------------------------------------

    def _select_service_page(self, snapshot, config_fixture, **route_kwargs):
        page = self.browser.new_page()
        page.route('**/api/**', self._service_selection_route(snapshot, config_fixture, **route_kwargs))
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="history"]').click()
        page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
        page.locator('#history-service-picker').select_option('8080')
        return page

    def test_one_uninterrupted_online_range_renders_one_full_width_segment(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            # A single bucket whose own resolution equals the full
            # requested span -- three consecutive same-resolution buckets
            # would each render at a fraction of the 1000px chart width and
            # not, on their own, prove the *merged* segment spans the full
            # band; merging three same-state buckets is covered by its own
            # dedicated test below.
            span = end_ts - start_ts
            fixture = self._service_history_fixture(
                start_ts, end_ts, points=[self._service_point(start_ts, online_seconds=span)],
            )
            fixture['effective_resolution_seconds'] = span
            return fixture

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            segments = page.locator('#service-state-band rect')
            self.assertEqual(segments.count(), 1)
            self.assertEqual(segments.first.get_attribute('class'), 'hist-band-segment hist-band-online')
            width = float(segments.first.get_attribute('width'))
            self.assertGreater(width, 990)
        finally:
            page.close()

    def test_zero_online_and_zero_offline_bucket_renders_unknown_not_blank(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [
                self._service_point(start_ts, online_seconds=60),
                self._service_point(start_ts + 60, unknown_seconds=60),
                self._service_point(start_ts + 120, online_seconds=60),
            ]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            segments = page.locator('#service-state-band rect')
            self.assertEqual(segments.count(), 3)
            self.assertIn('hist-band-unknown', segments.nth(1).get_attribute('class'))
        finally:
            page.close()

    def test_three_consecutive_same_state_buckets_merge_into_one_segment(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [
                self._service_point(start_ts + offset, offline_seconds=60)
                for offset in (0, 60, 120)
            ]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            segments = page.locator('#service-state-band rect')
            self.assertEqual(segments.count(), 1)
            self.assertIn('hist-band-offline', segments.first.get_attribute('class'))
        finally:
            page.close()

    def test_alternating_subpixel_states_never_merge(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [
                self._service_point(start_ts, online_seconds=60),
                self._service_point(start_ts + 60, offline_seconds=60),
                self._service_point(start_ts + 120, online_seconds=60),
            ]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self.browser.new_page()
        page.route(
            '**/api/**',
            self._service_selection_route(snapshot, config_fixture, service_payload_fn=service_payload_fn),
        )
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            # A 90-day requested span with three 60-second buckets clustered
            # at its start renders each bucket at a sub-pixel fraction of
            # the 1000px chart width, exercising the never-merge-different-
            # states rule under exactly the condition it exists for.
            page.locator('#range-preset-90d').click()
            page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
            page.locator('#history-service-picker').select_option('8080')
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            segments = page.locator('#service-state-band rect')
            self.assertEqual(segments.count(), 3)
            classes = [segments.nth(index).get_attribute('class') for index in range(3)]
            self.assertIn('hist-band-online', classes[0])
            self.assertIn('hist-band-offline', classes[1])
            self.assertIn('hist-band-online', classes[2])
        finally:
            page.close()

    def test_offline_overlapping_maintenance_suppressed_episode_renders_maintenance(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(start_ts, offline_seconds=60)]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        def events_payload_fn(start_ts, end_ts):
            episode = self._episode(
                8080, start_ts, start_ts + 60, suppressed_reason='maintenance_window',
            )
            return self._events_history_fixture(start_ts, end_ts, episodes=[episode])

        page = self._select_service_page(
            snapshot, config_fixture,
            service_payload_fn=service_payload_fn, events_payload_fn=events_payload_fn,
        )
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            segments = page.locator('#service-state-band rect')
            self.assertEqual(segments.count(), 1)
            self.assertIn('hist-band-maintenance', segments.first.get_attribute('class'))
        finally:
            page.close()

    def test_mixed_bucket_segment_title_discloses_exact_counts_and_ordering_caveat(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(start_ts, online_seconds=40, offline_seconds=20)]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            segments = page.locator('#service-state-band rect')
            self.assertEqual(segments.count(), 2)
            title_texts = [segments.nth(index).locator('title').text_content() for index in range(2)]
            combined = ' '.join(title_texts)
            self.assertIn('online 40s, offline 20s', combined)
            self.assertIn('ordering within the bucket is below the displayed resolution', combined)
        finally:
            page.close()

    def test_latency_chart_breaks_at_non_observed_coverage_and_strip_renders_two_segments(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [
                self._service_point(start_ts, online_seconds=60, latency_avg=10.0),
                self._service_point(start_ts + 10_000, online_seconds=60, latency_avg=20.0),
                self._service_point(start_ts + 70_000, online_seconds=60, latency_avg=70.0),
                self._service_point(start_ts + 75_000, online_seconds=60, latency_avg=75.0),
            ]
            coverage = [
                {'start_ts': start_ts, 'end_ts': start_ts + 20_000, 'state': 'observed'},
                {'start_ts': start_ts + 20_000, 'end_ts': start_ts + 40_000, 'state': 'collection_gap'},
                {'start_ts': start_ts + 40_000, 'end_ts': start_ts + 60_000, 'state': 'expired'},
                {'start_ts': start_ts + 60_000, 'end_ts': start_ts + 80_000, 'state': 'observed'},
            ]
            fixture = self._service_history_fixture(start_ts, end_ts, points=points)
            fixture['coverage'] = coverage
            return fixture

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            path_d = page.locator('#service-latency-chart path').get_attribute('d')
            self.assertEqual(path_d.count('M'), 2)
            self.assertEqual(page.locator('#strip-service-latency rect').count(), 2)
        finally:
            page.close()

    def test_latency_plot_background_matches_plain_plot_background_in_both_themes(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(start_ts, online_seconds=60, latency_avg=10.0)]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        for theme in ('dark', 'light'):
            with self.subTest(theme=theme):
                page = self.browser.new_page()
                if theme == 'light':
                    page.add_init_script("localStorage.setItem('beacon-theme', 'light');")
                page.route(
                    '**/api/**',
                    self._service_selection_route(snapshot, config_fixture, service_payload_fn=service_payload_fn),
                )
                try:
                    page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
                    page.locator('[data-section="history"]').click()
                    page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
                    page.locator('#history-service-picker').select_option('8080')
                    page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
                    latency_bg = page.locator('#service-latency-chart').evaluate(
                        '(node) => getComputedStyle(node).backgroundColor',
                    )
                    plain_bg = page.locator('#chart-cpu').evaluate(
                        '(node) => getComputedStyle(node).backgroundColor',
                    )
                    self.assertEqual(latency_bg, plain_bg)
                    band_bg = page.locator('#service-state-band').evaluate(
                        '(node) => getComputedStyle(node).backgroundColor',
                    )
                    self.assertNotEqual(band_bg, 'rgb(0, 255, 136)')
                finally:
                    page.close()

    # ------------------------------------------------------------------
    # 04-06 Task 3: time-weighted availability and failure classes (D-09).
    # ------------------------------------------------------------------

    def test_900_online_100_offline_renders_90_percent(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(start_ts, online_seconds=900, offline_seconds=100)]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            self.assertIn('90.0%', page.locator('#service-availability').text_content())
        finally:
            page.close()

    def test_adding_unknown_seconds_leaves_availability_unchanged_and_discloses_in_detail(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [
                self._service_point(start_ts, online_seconds=900, offline_seconds=100, unknown_seconds=500),
            ]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            self.assertIn('90.0%', page.locator('#service-availability').text_content())
            detail_text = page.locator('#service-availability-detail-body').text_content()
            self.assertIn('500 seconds', detail_text)
        finally:
            page.close()

    def test_zero_online_and_zero_offline_renders_unknown_never_0_or_100_percent(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(start_ts, unknown_seconds=600)]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            text = page.locator('#service-availability').text_content()
            self.assertIn('Unknown', text)
            self.assertNotIn('0%', text)
            self.assertNotIn('100%', text)
        finally:
            page.close()

    def test_reversed_bucket_order_produces_identical_availability(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        results = {}
        for label, order in (('forward', (0, 1)), ('reversed', (1, 0))):
            def service_payload_fn(start_ts, end_ts, order=order):
                raw = [
                    self._service_point(start_ts, online_seconds=300, offline_seconds=100),
                    self._service_point(start_ts + 60, online_seconds=600, offline_seconds=0),
                ]
                return self._service_history_fixture(start_ts, end_ts, points=[raw[order[0]], raw[order[1]]])

            page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
            try:
                page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
                results[label] = page.locator('#service-availability').text_content()
            finally:
                page.close()
        self.assertEqual(results['forward'], results['reversed'])

    def test_maintenance_suppressed_downtime_still_counts_in_headline(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(start_ts, online_seconds=900, offline_seconds=100)]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        def events_payload_fn(start_ts, end_ts):
            episode = self._episode(
                8080, start_ts, start_ts + 100, suppressed_reason='maintenance_window',
            )
            return self._events_history_fixture(start_ts, end_ts, episodes=[episode])

        page = self._select_service_page(
            snapshot, config_fixture,
            service_payload_fn=service_payload_fn, events_payload_fn=events_payload_fn,
        )
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            self.assertIn('90.0%', page.locator('#service-availability').text_content())
            detail_text = page.locator('#service-availability-detail-body').text_content()
            self.assertIn('100 seconds', detail_text)
        finally:
            page.close()

    def test_two_equal_count_failure_classes_render_in_ascending_name_order(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(
                start_ts, offline_seconds=100,
                failure_class_counts={'timeout': 2, 'connection_error': 2, 'not_responding': 5},
            )]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            chips = page.locator('.hist-failure-chip')
            self.assertEqual(chips.count(), 3)
            texts = [chips.nth(index).text_content() for index in range(3)]
            self.assertEqual(texts, ['not_responding: 5', 'connection_error: 2', 'timeout: 2'])
        finally:
            page.close()

    def test_no_failures_renders_zero_failure_classes(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(start_ts, online_seconds=60)]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self._select_service_page(snapshot, config_fixture, service_payload_fn=service_payload_fn)
        try:
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('.hist-failure-chip-count').text_content(), '0 failure classes')
            self.assertEqual(page.locator('.hist-failure-chip').count(), 0)
        finally:
            page.close()

    def test_failure_class_chip_list_wraps_at_narrow_viewport(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()

        def service_payload_fn(start_ts, end_ts):
            points = [self._service_point(
                start_ts, offline_seconds=100,
                failure_class_counts={
                    'timeout': 3, 'connection_error': 2, 'not_responding': 4,
                    'request_error': 1, 'probe_error': 1, 'invalid_target': 1,
                },
            )]
            return self._service_history_fixture(start_ts, end_ts, points=points)

        page = self.browser.new_page(viewport={'width': 400, 'height': 800})
        page.route(
            '**/api/**',
            self._service_selection_route(snapshot, config_fixture, service_payload_fn=service_payload_fn),
        )
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            page.locator('[data-section="history"]').click()
            page.locator('#history-service-picker').wait_for(state='visible', timeout=5_000)
            page.locator('#history-service-picker').select_option('8080')
            page.locator('#service-history-content').wait_for(state='visible', timeout=5_000)
            chips = page.locator('.hist-failure-chip')
            self.assertEqual(chips.count(), 6)
            tops = sorted({round(chips.nth(index).bounding_box()['y']) for index in range(6)})
            self.assertGreater(len(tops), 1)
            for index in range(6):
                box = chips.nth(index).bounding_box()
                self.assertLessEqual(box['x'] + box['width'], 400 + 1)
        finally:
            page.close()

    # ------------------------------------------------------------------
    # 04-07: the Incidents section -- shared range header, four filters,
    # incident-row anatomy (open/overrun/expected/flapping), and
    # focusIncident's investigation-context handoff.
    # ------------------------------------------------------------------

    def _incidents_route(
        self, snapshot, config_fixture, *,
        events_payload_fn=None, events_status=200, record_events_urls=None,
    ):
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
            if path == '/api/events/history':
                if record_events_urls is not None:
                    record_events_urls.append(route.request.url)
                if events_status != 200:
                    route.fulfill(status=events_status, json={'error': 'incidents unavailable'})
                    return
                query = parse_qs(urlparse(route.request.url).query)
                start_ts = int(query['start_ts'][0])
                end_ts = int(query['end_ts'][0])
                payload = (
                    events_payload_fn(start_ts, end_ts, query) if events_payload_fn
                    else self._events_history_fixture(start_ts, end_ts)
                )
                route.fulfill(status=200, json=payload)
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=snapshot)
                return
            route.fallback()
        return route_api

    def _goto_incidents(self, page):
        page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
        page.locator('[data-section="incidents"]').click()
        page.locator('#incidents-section').wait_for(state='visible', timeout=5_000)

    def test_incidents_nav_reveals_section_and_shares_one_range_header(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture))
        try:
            page.goto(f'{self.base_url}/advanced', wait_until='domcontentloaded')
            self.assertIsNotNone(page.locator('#investigation-header').get_attribute('hidden'))
            self.assertEqual(page.locator('#investigation-range').count(), 1)
            page.locator('[data-section="history"]').click()
            page.locator('#history-section').wait_for(state='visible', timeout=5_000)
            self.assertIsNone(page.locator('#investigation-header').get_attribute('hidden'))
            page.locator('[data-section="incidents"]').click()
            page.locator('#incidents-section').wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.evaluate('document.activeElement.id'), 'incidents-heading')
            self.assertIsNone(page.locator('#investigation-header').get_attribute('hidden'))
            page.locator('[data-section="services"]').click()
            page.locator('#services-section').wait_for(state='visible', timeout=5_000)
            self.assertIsNotNone(page.locator('#investigation-header').get_attribute('hidden'))
            self.assertEqual(page.locator('#investigation-range').count(), 1)
        finally:
            page.close()

    def test_incident_criticality_filter_issues_request_and_narrows_count(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        standard_episode = self._episode(8080, 1_700_000_000, 1_700_000_060)
        critical_episode = self._episode(8081, 1_700_000_100, 1_700_000_160, critical=True)

        def events_payload_fn(start_ts, end_ts, query):
            if query.get('criticality', [''])[0] == 'critical':
                return self._events_history_fixture(start_ts, end_ts, episodes=[critical_episode])
            return self._events_history_fixture(start_ts, end_ts, episodes=[critical_episode, standard_episode])

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('.incident-row').count(), 2)
            with page.expect_request(
                lambda request: urlparse(request.url).path == '/api/events/history'
                and parse_qs(urlparse(request.url).query).get('criticality', [''])[0] == 'critical',
            ):
                page.locator('#incident-criticality-filter').select_option('critical')
            page.wait_for_function("() => document.querySelectorAll('.incident-row').length === 1", timeout=5_000)
            self.assertEqual(page.locator('#matching-incident-count').inner_text(), '1 of 2 incidents')
        finally:
            page.close()

    def test_incident_filters_persist_across_reload_and_hostile_stored_value_falls_back(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        episode = self._episode(8080, 1_700_000_000, 1_700_000_060, critical=True)
        recorded = []

        def events_payload_fn(start_ts, end_ts, query):
            recorded.append(dict(query))
            return self._events_history_fixture(start_ts, end_ts, episodes=[episode])

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            page.locator('#incident-criticality-filter').select_option('critical')
            page.locator('#incident-event-type-filter').select_option('event_type:state_change')
            page.wait_for_timeout(50)

            page.reload(wait_until='domcontentloaded')
            page.locator('[data-section="incidents"]').click()
            page.locator('#incidents-section').wait_for(state='visible', timeout=5_000)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#incident-criticality-filter').input_value(), 'critical')
            self.assertEqual(page.locator('#incident-event-type-filter').input_value(), 'event_type:state_change')

            # T-04-04: a hostile stored historyFilters value -- outside
            # CRITICALITY_VALUES/EVENT_TYPES -- resolves to the documented
            # default rather than ever reaching a request URL.
            recorded.clear()
            page.evaluate("""
                const stored = JSON.parse(localStorage.getItem('beacon-advanced-preferences-v1'));
                stored.historyFilters = {service: null, criticality: 'lethal', eventType: 'event_type:not_a_real_type'};
                localStorage.setItem('beacon-advanced-preferences-v1', JSON.stringify(stored));
            """)
            page.reload(wait_until='domcontentloaded')
            page.locator('[data-section="incidents"]').click()
            page.locator('#incidents-section').wait_for(state='visible', timeout=5_000)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            self.assertEqual(page.locator('#incident-criticality-filter').input_value(), '')
            self.assertEqual(page.locator('#incident-event-type-filter').input_value(), '')
            for query in recorded:
                self.assertNotIn('criticality', query)
                self.assertNotIn('event_type', query)
        finally:
            page.close()

    def test_maintenance_visibility_options_issue_maintenance_param_and_default_shows_suppressed(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        suppressed_episode = self._episode(8080, 1_700_000_000, 1_700_000_060, suppressed_reason='confirmed_maintenance')
        plain_episode = self._episode(8081, 1_700_000_100, 1_700_000_160)

        def events_payload_fn(start_ts, end_ts, query):
            maintenance = query.get('maintenance', [''])[0]
            if maintenance == 'exclude':
                return self._events_history_fixture(start_ts, end_ts, episodes=[plain_episode])
            if maintenance == 'only':
                return self._events_history_fixture(start_ts, end_ts, episodes=[suppressed_episode])
            return self._events_history_fixture(start_ts, end_ts, episodes=[suppressed_episode, plain_episode])

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            # Default: no maintenance param needed to see suppressed evidence
            # by default (D-13) -- the opposite of the main dashboard's feed.
            self.assertEqual(page.locator('.incident-chip-expected').count(), 1)
            with page.expect_request(
                lambda request: urlparse(request.url).path == '/api/events/history'
                and parse_qs(urlparse(request.url).query).get('maintenance', [''])[0] == 'exclude',
            ):
                page.locator('#incident-event-type-filter').select_option('maintenance:exclude')
            page.wait_for_function("() => document.querySelectorAll('.incident-row').length === 1", timeout=5_000)
            self.assertEqual(page.locator('.incident-chip-expected').count(), 0)
            with page.expect_request(
                lambda request: urlparse(request.url).path == '/api/events/history'
                and parse_qs(urlparse(request.url).query).get('maintenance', [''])[0] == 'only',
            ):
                page.locator('#incident-event-type-filter').select_option('maintenance:only')
            page.wait_for_function("() => document.querySelectorAll('.incident-chip-expected').length === 1", timeout=5_000)
        finally:
            page.close()

    def test_combining_criticality_and_event_type_filters_issues_one_request_with_both(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        episode = self._episode(8080, 1_700_000_000, 1_700_000_060, critical=True)

        def events_payload_fn(start_ts, end_ts, query):
            return self._events_history_fixture(start_ts, end_ts, episodes=[episode])

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            page.locator('#incident-criticality-filter').select_option('critical')
            page.wait_for_timeout(50)
            with page.expect_request(
                lambda request: urlparse(request.url).path == '/api/events/history'
                and parse_qs(urlparse(request.url).query).get('criticality', [''])[0] == 'critical'
                and parse_qs(urlparse(request.url).query).get('event_type', [''])[0] == 'state_change',
            ):
                page.locator('#incident-event-type-filter').select_option('event_type:state_change')
        finally:
            page.close()

    def test_clear_all_incident_filters_resets_and_leaves_range_unchanged(self):
        snapshot = self._snapshot()
        snapshot['services'] = [self._service(8080, 'Test Service')]
        config_fixture = self._config_fixture()
        episode = self._episode(8080, 1_700_000_000, 1_700_000_060, critical=True)

        def events_payload_fn(start_ts, end_ts, query):
            return self._events_history_fixture(start_ts, end_ts, episodes=[episode])

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            page.locator('#incident-criticality-filter').select_option('critical')
            page.locator('#incident-event-type-filter').select_option('maintenance:exclude')
            page.locator('#incident-service-filter').select_option('8080')
            page.wait_for_timeout(50)
            range_start_before = page.locator('#range-start').input_value()
            range_end_before = page.locator('#range-end').input_value()
            with page.expect_request(lambda request: urlparse(request.url).path == '/api/events/history') as request_info:
                page.locator('#clear-incident-filters').click()
            query = parse_qs(urlparse(request_info.value.url).query)
            self.assertNotIn('criticality', query)
            self.assertNotIn('maintenance', query)
            self.assertNotIn('port', query)
            self.assertEqual(page.locator('#incident-criticality-filter').input_value(), '')
            self.assertEqual(page.locator('#incident-event-type-filter').input_value(), '')
            self.assertEqual(page.locator('#incident-service-filter').input_value(), '')
            self.assertEqual(page.locator('#range-start').input_value(), range_start_before)
            self.assertEqual(page.locator('#range-end').input_value(), range_end_before)
        finally:
            page.close()

    def test_zero_match_incidents_renders_empty_copy_and_matching_count(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        episode = self._episode(8080, 1_700_000_000, 1_700_000_060)

        def events_payload_fn(start_ts, end_ts, query):
            if query.get('criticality', [''])[0] == 'critical':
                return self._events_history_fixture(start_ts, end_ts, episodes=[])
            return self._events_history_fixture(start_ts, end_ts, episodes=[episode])

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            page.locator('#incident-criticality-filter').select_option('critical')
            page.locator('#incidents-empty').wait_for(state='visible', timeout=5_000)
            self.assertIn(
                'No incidents match this range and these filters.',
                page.locator('#incidents-empty').inner_text(),
            )
            self.assertIn('Clear filters to see every recorded incident in this range.', page.locator('#incidents-empty').inner_text())
            self.assertEqual(page.locator('#matching-incident-count').inner_text(), '0 of 1 incidents')
            self.assertEqual(page.locator('.incident-row').count(), 0)
        finally:
            page.close()

    def test_incidents_fetch_failure_renders_error_and_keeps_filters_enabled(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_status=503))
        try:
            self._goto_incidents(page)
            page.locator('#incidents-error').wait_for(state='visible', timeout=5_000)
            self.assertIn(
                'Beacon could not load incidents for this range.',
                page.locator('#incidents-error').inner_text(),
            )
            self.assertFalse(page.locator('#incident-criticality-filter').is_disabled())
            self.assertFalse(page.locator('#incident-event-type-filter').is_disabled())
            self.assertFalse(page.locator('#incident-service-filter').is_disabled())
            self.assertFalse(page.locator('#clear-incident-filters').is_disabled())
        finally:
            page.close()

    def test_truncated_incidents_response_renders_disclosure(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        episode = self._episode(8080, 1_700_000_000, 1_700_000_060)

        def events_payload_fn(start_ts, end_ts, query):
            fixture = self._events_history_fixture(start_ts, end_ts, episodes=[episode])
            fixture['truncated'] = True
            return fixture

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('#incidents-truncated').wait_for(state='visible', timeout=5_000)
        finally:
            page.close()

    def test_incidents_section_has_no_action_affordances(self):
        snapshot = self._snapshot()
        config_fixture = self._config_fixture()
        episode = self._episode(8080, 1_700_000_000, 1_700_000_060, suppressed_reason='confirmed_maintenance')

        def events_payload_fn(start_ts, end_ts, query):
            return self._events_history_fixture(start_ts, end_ts, episodes=[episode])

        page = self.browser.new_page()
        page.route('**/api/**', self._incidents_route(snapshot, config_fixture, events_payload_fn=events_payload_fn))
        try:
            self._goto_incidents(page)
            page.locator('.incident-row').first.wait_for(state='visible', timeout=5_000)
            forbidden = re.compile(r'restart|stop|retry|\bfix\b|remediate', re.IGNORECASE)
            elements = page.locator(
                '#incidents-section button, #incidents-section a, #incidents-section input, #incidents-section select',
            )
            count = elements.count()
            self.assertGreater(count, 0)
            for index in range(count):
                el = elements.nth(index)
                name = ' '.join(filter(None, [
                    el.get_attribute('aria-label'), el.text_content(), el.get_attribute('title'),
                ]))
                self.assertNotRegex(name, forbidden)
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
