import threading
import unittest
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.helpers import cleanup_db, load_app


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


if __name__ == '__main__':
    unittest.main()
