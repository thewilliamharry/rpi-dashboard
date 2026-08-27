"""Phase 5's dedicated cross-surface, dual-theme UI contract (05-06, OPS-06/UX-05).

The main dashboard (``/``) and the advanced workspace (``/advanced``) are asserted to
share one narrow layout boundary, and every layout the responsive contract calls
at-risk is proven to scroll rather than hide content at that boundary, in both
themes. Every assertion in this module reads DOM presence, displayed state,
geometry, or a computed layout property -- never a pixel-snapshot baseline. This
project has no baseline-review workflow, targets Raspberry Pi-class rendering where
font/GPU output differs from a developer machine, and a contract assertion can
express a role, an accessible name, or a text claim a pixel diff cannot (A-31).

``tests/test_ui_states.py``/``tests/test_advanced_ui.py`` each already carry
single-document dual-theme coverage; this module is deliberately cross-surface --
the same viewport width applied to both documents in both themes -- which is why it
gets its own module rather than being split across the two single-document ones
(A-32).
"""
import pathlib
import re
import threading
import unittest
from collections import Counter
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from tests.helpers import cleanup_db, load_app

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A-30/E10: the one shared narrow boundary. Every viewport width this module uses
# derives from this constant -- a future boundary change is a one-line edit here,
# and no test body can silently keep asserting the old value.
NARROW_BOUNDARY_PX = 720

# The widest the advanced workspace's own `max-width: 1440px` renders -- the most
# reflow headroom available, and therefore the genuine "desktop" comparison point
# for the filter-group wrap assertions (keeps the comparison robust against the
# font-metric differences A-31 warns about).
DESKTOP_WIDTH_PX = 1440

# Matches an `@media (max-width: Npx)` prelude anywhere in a stylesheet, tolerant of
# any other conditions sharing the same parenthesised query (none exist today, but
# the pattern does not assume it). `prefers-reduced-motion` queries carry no
# `max-width` term and are correctly skipped.
_MEDIA_MAX_WIDTH_RE = re.compile(r'@media[^{]*?max-width:\s*(\d+)px')

# The JS evaluated against `#service-filters`/`#incident-filters`: every displayed
# control's height and right edge (for the 44px hit-target and no-overflow claims),
# the group's own scroll/client width (for the no-overflow claim) and rendered
# height (for the boundary-vs-desktop comparison), and the number of distinct rows
# among the group's own displayed direct children. Rows are counted by rounded
# bounding-box **bottom** edge, not top: `align-items: end` aligns bottoms, so top
# edges differ within a single row and would miscount.
_MEASURE_FILTER_GROUP_JS = """
(node) => {
    const style = getComputedStyle(node);
    const rect = node.getBoundingClientRect();
    const paddingRight = parseFloat(style.paddingRight) || 0;
    const borderRight = parseFloat(style.borderRightWidth) || 0;
    const contentRight = rect.right - paddingRight - borderRight;
    const directChildren = Array.from(node.children).filter((el) => el.offsetParent !== null);
    const rowBottoms = new Set(directChildren.map((el) => Math.round(el.getBoundingClientRect().bottom)));
    const controls = Array.from(node.querySelectorAll('input, select, button'))
        .filter((el) => el.offsetParent !== null);
    return {
        height: rect.height,
        scrollWidth: node.scrollWidth,
        clientWidth: node.clientWidth,
        contentRight: contentRight,
        rows: rowBottoms.size,
        controlCount: controls.length,
        controlHeights: controls.map((el) => el.getBoundingClientRect().height),
        controlRights: controls.map((el) => el.getBoundingClientRect().right),
    };
}
"""

# The descriptor rule this plan states in full (deliberately duplicated from
# plan 05-05's identical rule rather than shared -- 05-05 is the same wave and its
# helper is not guaranteed to exist when this executes): a control's descriptor is
# its `id` when it has one, otherwise its tag name, its class list and its
# zero-based index among its parent element's children, joined.
_DESCRIPTOR_JS = """
() => {
    function descriptor(el) {
        if (el.id) return el.id;
        const parent = el.parentElement;
        const index = parent ? Array.prototype.indexOf.call(parent.children, el) : -1;
        return [el.tagName, Array.from(el.classList).join('.'), index].join('|');
    }
    return Array.from(document.querySelectorAll('input, select, button'))
        .filter((el) => el.offsetParent !== null)
        .map(descriptor);
}
"""


class NarrowBoundaryPinTests(unittest.TestCase):
    """T-05-23: pins the reconciled narrow breakpoint at source level.

    A bare membership check would pass against a stylesheet that also still
    declared an off-by-one neighbour (e.g. 719px) alongside the correct value, so
    this also asserts no other declared max-width falls within ten pixels of
    NARROW_BOUNDARY_PX -- the assertion that actually catches an off-by-one
    reintroduction.
    """

    def test_both_stylesheets_declare_the_same_narrow_boundary(self):
        style_css = (ROOT / 'dashboard/style.css').read_text(encoding='utf-8')
        advanced_css = (ROOT / 'dashboard/advanced.css').read_text(encoding='utf-8')

        style_values = [int(value) for value in _MEDIA_MAX_WIDTH_RE.findall(style_css)]
        advanced_values = [int(value) for value in _MEDIA_MAX_WIDTH_RE.findall(advanced_css)]

        # Pattern self-check: a broken expression that matched nothing (or matched
        # only one value) must not let this pin pass vacuously -- advanced.css
        # genuinely declares two distinct narrow boundaries today (the 959px
        # nav-rail collapse and NARROW_BOUNDARY_PX itself).
        self.assertGreaterEqual(
            len(set(advanced_values)), 2,
            'pattern self-check: expected at least two distinct max-width values '
            'extracted from dashboard/advanced.css -- the extraction regex may be broken',
        )

        self.assertIn(NARROW_BOUNDARY_PX, set(style_values))
        self.assertIn(NARROW_BOUNDARY_PX, set(advanced_values))

        for label, values in (
            ('dashboard/style.css', style_values),
            ('dashboard/advanced.css', advanced_values),
        ):
            for value in set(values):
                if value == NARROW_BOUNDARY_PX:
                    continue
                self.assertGreater(
                    abs(value - NARROW_BOUNDARY_PX), 10,
                    f'{label} declares a near-neighbour max-width ({value}px) within 10px '
                    f'of the shared {NARROW_BOUNDARY_PX}px boundary -- an off-by-one '
                    'reintroduction would pass a bare membership check but must fail this one',
                )


class ThemeParityUiTests(unittest.TestCase):
    """Cross-surface, dual-theme browser coverage: the shared boundary applies
    identically on both documents in both themes (T-05-24), and every at-risk
    narrow layout scrolls rather than hides content (T-05-25), in both themes.

    Harness copied in shape from tests/test_advanced_ui.py: load_app +
    werkzeug.serving.make_server + sync_playwright, against the real Flask routes
    for both `/` and `/advanced`, with every `/api/**` call intercepted by
    `_route_all` so every layout assertion runs against a deterministic payload.
    """

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

    # ------------------------------------------------------------------
    # Fixtures
    # ------------------------------------------------------------------

    @staticmethod
    def _dashboard_service(port, name, *, online=True):
        return {
            'port': port, 'title': name, 'display_name': name,
            'is_online': online, 'has_thumb': False, 'latency_ms': 8,
            'state_since': 1_700_000_000, 'url': f'http://127.0.0.1:{port}',
            'path': '/', 'tags': ['local'], 'critical': False,
            'healthy_statuses': '200-399', 'tls_unverified': False,
            'uptime_pct': 100, 'uptime_buckets': [1, 1, 1],
            'preview_status': 'queued',
        }

    @staticmethod
    def _advanced_service(port, name, *, availability='online'):
        return {
            'port': port, 'name': name, 'availability': availability,
            'latency_ms': 5 if availability == 'online' else None,
            'failure_class': None if availability == 'online' else 'connection refused',
            'state_duration_seconds': 120, 'critical': False,
            'pinned_order': port, 'tags': [], 'effective_health_rule': '200-399',
            'last_probe_ts': 1_700_000_000,
            'expected_cadence_seconds': 300 if availability == 'online' else 60,
            'freshness': {'state': 'fresh', 'age_seconds': 5},
            'tls_unverified': False, 'last_error': None,
            'collection_gaps': {'items': [], 'count': 0, 'open_count': 0, 'evidence': 'complete'},
            'maintenance': {'active': False, 'window': None, 'covered_until_ts': None},
            'maintenance_attribution': {'attributed_seconds': 0, 'period_seconds': 604_800},
        }

    @classmethod
    def _build_fixture(cls, *, dashboard_services=None):
        """The shared fixture for every test in this module.

        `worker_degraded`/`worker_freshness` are always in their not-degraded
        values on both surfaces -- no layout assertion in this module depends on
        the degraded/aging state. Three services are seeded by default so the
        "many" case is exercised; a caller passing `dashboard_services=[]`
        exercises the "zero" case instead (Task 3's empty-services assertion).
        """
        if dashboard_services is None:
            dashboard_services = [
                cls._dashboard_service(8500, 'Service A', online=True),
                cls._dashboard_service(8501, 'Service B', online=True),
                cls._dashboard_service(8502, 'Service C', online=False),
            ]
        advanced_services = [
            cls._advanced_service(8500, 'Service A', availability='online'),
            cls._advanced_service(8501, 'Service B', availability='online'),
            cls._advanced_service(8502, 'Service C', availability='offline'),
        ]
        # A populated points array so the History section's four-chart stack has
        # real geometry to measure, not an empty-state placeholder.
        points = [
            {
                'ts': 1_700_000_000 + (index * 60),
                'min_value': float(index), 'max_value': float(index), 'avg_value': float(index),
                'latest_value': float(index), 'sample_count': 1,
                'observed_seconds': 60, 'gap_seconds': 0, 'unknown_seconds': 0,
            }
            for index in range(30)
        ]
        return {
            'dashboard_services': dashboard_services,
            'dashboard_events': [],
            'history_points': points,
            'advanced_current': {
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
                'services': advanced_services,
                'pipeline': {}, 'settings': {}, 'exceptions': [],
                'safety': {'worker_stale': False, 'worker_degraded': False, 'recovery_required': False},
            },
            'config': {
                'timezone': 'UTC', 'alerting_enabled': False,
                'uptime_buckets': [], 'trigger_rate_limit': 4, 'trigger_rate_window_seconds': 60,
            },
        }

    def _route_all(self, fixture):
        """A route handler that fulfils every endpoint both documents call --
        the main dashboard's stats/history/scan-status/services/events endpoints,
        and the advanced workspace's current-diagnosis/config/telemetry-history/
        events-history endpoints -- falling back for anything else.
        """
        def route_api(route):
            request = route.request
            path = urlparse(request.url).path
            if path == '/api/stats':
                route.fulfill(status=200, json={
                    'hostname': 'beacon', 'sample_ts': 1_700_000_000,
                    'cpu': 42, 'ram': 55, 'disk': 61,
                    'ram_used': 1, 'ram_total': 2, 'disk_used': 1, 'disk_total': 2, 'temp': 40,
                })
                return
            if path == '/api/history':
                route.fulfill(status=200, json=[])
                return
            if path == '/api/scan-status':
                route.fulfill(status=200, json={
                    'worker_ready': True, 'worker_stale': False, 'recovery_required': False,
                    'worker_degraded': False,
                    'worker_freshness': {'state': 'fresh', 'age_seconds': 5},
                    'stage': 'idle', 'scanning': False,
                    'last_completed_found': len(fixture['dashboard_services']),
                    'last_discovery': 1_700_000_000,
                })
                return
            if path == '/api/services':
                route.fulfill(status=200, json=fixture['dashboard_services'])
                return
            if path == '/api/events':
                route.fulfill(status=200, json=fixture['dashboard_events'])
                return
            if path == '/api/advanced/current':
                route.fulfill(status=200, json=fixture['advanced_current'])
                return
            if path == '/api/config':
                route.fulfill(status=200, json=fixture['config'])
                return
            if path == '/api/telemetry/history':
                query = parse_qs(urlparse(request.url).query)
                start_ts = int(query['start_ts'][0])
                end_ts = int(query['end_ts'][0])
                route.fulfill(status=200, json={
                    'requested': {'start_ts': start_ts, 'end_ts': end_ts},
                    'selector': {
                        'kind': query.get('kind', ['host'])[0],
                        'metric': query.get('metric', [''])[0],
                    },
                    'effective_resolution_seconds': 60,
                    'point_budget': 2048,
                    'source_resolutions_seconds': [60],
                    'points': fixture['history_points'],
                    'coverage': [{'start_ts': start_ts, 'end_ts': end_ts, 'state': 'observed'}],
                    'aggregation_pending': [],
                })
                return
            if path == '/api/events/history':
                query = parse_qs(urlparse(request.url).query)
                start_ts = int(query['start_ts'][0])
                end_ts = int(query['end_ts'][0])
                route.fulfill(status=200, json={
                    'requested': {'start_ts': start_ts, 'end_ts': end_ts},
                    'filters': {'maintenance': 'include'},
                    'episodes': [], 'events': [], 'flapping_groups': [],
                    'row_budget': 2048, 'truncated': False, 'matched_count': 0,
                    'episode_scope': {'grouped_from': 'all_state_changes_in_range', 'narrowed_by': []},
                })
                return
            route.fallback()
        return route_api

    def _open(self, theme, path, width, fixture):
        """Open a page at the given viewport width, applying the light theme via
        the established `add_init_script` localStorage idiom before navigation
        when the theme is light, installing the route handler, and navigating.
        """
        page = self.browser.new_page(viewport={'width': width, 'height': 900})
        if theme == 'light':
            page.add_init_script("localStorage.setItem('beacon-theme', 'light');")
        page.route('**/api/**', self._route_all(fixture))
        page.goto(f'{self.base_url}{path}', wait_until='domcontentloaded')
        return page

    # ------------------------------------------------------------------
    # Task 2: the boundary behaves identically on both documents, in both themes
    # ------------------------------------------------------------------

    def test_the_shared_boundary_produces_the_narrow_layout_on_both_documents_in_both_themes(self):
        fixture = self._build_fixture()
        # For the main dashboard, .metrics-row resolves 3 tracks desktop / 1 narrow
        # (style.css:239,1250). For the advanced workspace, .summary-grid resolves
        # 3 tracks desktop / 1 narrow (advanced.css:20,116) -- both are grids the
        # narrow query genuinely changes, not a container with no tracks at all.
        grid_selector = {'/': '.metrics-row', '/advanced': '.summary-grid'}
        resolved_colors = {}

        for theme in ('dark', 'light'):
            for path in ('/', '/advanced'):
                with self.subTest(theme=theme, path=path):
                    selector = grid_selector[path]

                    narrow_page = self._open(theme, path, NARROW_BOUNDARY_PX, fixture)
                    try:
                        narrow_page.locator(selector).wait_for(timeout=5_000)
                        narrow_tracks = narrow_page.locator(selector).evaluate(
                            "(node) => getComputedStyle(node).gridTemplateColumns.trim().split(/\\s+/).length"
                        )
                        if path == '/':
                            resolved_colors[theme] = narrow_page.evaluate(
                                "getComputedStyle(document.body).backgroundColor"
                            )
                    finally:
                        narrow_page.close()

                    wide_page = self._open(theme, path, NARROW_BOUNDARY_PX + 1, fixture)
                    try:
                        wide_page.locator(selector).wait_for(timeout=5_000)
                        wide_tracks = wide_page.locator(selector).evaluate(
                            "(node) => getComputedStyle(node).gridTemplateColumns.trim().split(/\\s+/).length"
                        )
                    finally:
                        wide_page.close()

                    self.assertEqual(
                        narrow_tracks, 1,
                        f'{path} in {theme} theme should resolve exactly one grid track '
                        f'at {NARROW_BOUNDARY_PX}px',
                    )
                    self.assertGreater(
                        wide_tracks, 1,
                        f'{path} in {theme} theme should resolve more than one grid track '
                        f'at {NARROW_BOUNDARY_PX + 1}px',
                    )

        # T-05-26: a light run that silently failed to apply must fail loudly
        # rather than pass the layout assertions above by accident.
        self.assertNotEqual(resolved_colors['dark'], resolved_colors['light'])

    # ------------------------------------------------------------------
    # Task 3: at the narrow boundary, content scrolls -- it never disappears
    # ------------------------------------------------------------------

    def test_at_risk_narrow_layouts_scroll_rather_than_hide_in_both_themes(self):
        fixture = self._build_fixture()

        for theme in ('dark', 'light'):
            with self.subTest(theme=theme, surface='advanced'):
                page = self._open(theme, '/advanced', NARROW_BOUNDARY_PX, fixture)
                try:
                    page.locator('.summary-grid').wait_for(timeout=5_000)

                    # -- Four-chart host stack + marker rail --
                    page.locator('[data-section="history"]').click()
                    page.locator('#history-section').wait_for(state='visible', timeout=5_000)

                    chart_tops = []
                    for metric in ('cpu', 'ram', 'disk', 'temp'):
                        locator = page.locator(f'#chart-{metric}')
                        self.assertTrue(locator.is_visible(), f'#chart-{metric} not displayed ({theme})')
                        box = locator.bounding_box()
                        self.assertIsNotNone(box, f'#chart-{metric} has no bounding box ({theme})')
                        self.assertGreater(box['width'], 0, f'#chart-{metric} has zero width ({theme})')
                        chart_tops.append(round(box['y']))
                    self.assertEqual(
                        len(chart_tops), len(set(chart_tops)),
                        f'two or more host charts share a bounding-box top coordinate ({theme}) -- '
                        'they must be stacked, never side by side',
                    )

                    axis_scroll = page.locator('#history-axis-scroll')
                    axis_metrics = axis_scroll.evaluate(
                        '(node) => ({scrollWidth: node.scrollWidth, clientWidth: node.clientWidth})'
                    )
                    self.assertGreaterEqual(axis_metrics['scrollWidth'], axis_metrics['clientWidth'])

                    marker_rail = page.locator('#incident-marker-rail')
                    self.assertTrue(marker_rail.is_visible(), f'marker rail not displayed ({theme})')
                    rail_box = marker_rail.bounding_box()
                    self.assertIsNotNone(rail_box, f'marker rail has no bounding box ({theme})')
                    self.assertGreater(rail_box['width'], 0, f'marker rail has zero width ({theme})')
                    self.assertTrue(
                        marker_rail.evaluate("(node) => !!node.closest('#history-axis-scroll')"),
                        f'marker rail is not a descendant of the shared axis scroll container ({theme})',
                    )

                    # -- Services table + service-identity sticky column --
                    page.locator('[data-section="services"]').click()
                    page.locator('#services-table-body tr.service-row').first.wait_for(timeout=5_000)
                    self.assertEqual(page.locator('#services-table-body tr.service-row').count(), 3)

                    table_scroll = page.locator('.services-table-scroll')
                    boundary_table_metrics = table_scroll.evaluate(
                        '(node) => ({scrollWidth: node.scrollWidth, clientWidth: node.clientWidth})'
                    )
                    self.assertGreater(
                        boundary_table_metrics['scrollWidth'], boundary_table_metrics['clientWidth'],
                        f'services table does not overflow (scroll) at the boundary ({theme})',
                    )
                    boundary_header_count = page.locator('#services-table thead th').count()
                    identity_position = page.locator('.service-identity').first.evaluate(
                        '(node) => getComputedStyle(node).position'
                    )
                    self.assertEqual(identity_position, 'sticky', f'.service-identity not sticky ({theme})')

                    service_filters_boundary = page.locator('#service-filters').evaluate(_MEASURE_FILTER_GROUP_JS)
                    boundary_descriptors = Counter(page.evaluate(_DESCRIPTOR_JS))

                    # -- Resize to desktop width (same page, same DOM) --
                    page.set_viewport_size({'width': DESKTOP_WIDTH_PX, 'height': 900})
                    desktop_header_count = page.locator('#services-table thead th').count()
                    service_filters_desktop = page.locator('#service-filters').evaluate(_MEASURE_FILTER_GROUP_JS)
                    desktop_descriptors = Counter(page.evaluate(_DESCRIPTOR_JS))

                    self.assertEqual(
                        boundary_header_count, desktop_header_count,
                        f'services table header cell count changed between widths ({theme}) -- '
                        'a column was dropped rather than reached by scrolling',
                    )

                    # Nothing hidden to fit (T-05-25): the boundary collection must be a
                    # superset of the desktop collection, with both non-empty. A "not a
                    # strict subset" check would pass while one control was lost and an
                    # unrelated one gained; an empty-vs-empty comparison would pass
                    # trivially. The superset-on-non-empty form closes both.
                    self.assertTrue(len(desktop_descriptors) > 0 and len(boundary_descriptors) > 0)
                    self.assertTrue(
                        desktop_descriptors <= boundary_descriptors,
                        f'a control present at desktop width is missing at the narrow boundary ({theme})',
                    )

                    # -- Filter groups: #service-filters (still on Services section) --
                    self.assertEqual(service_filters_boundary['controlCount'], 6)
                    self.assertEqual(service_filters_desktop['controlCount'], 6)
                    for height in service_filters_boundary['controlHeights']:
                        self.assertGreaterEqual(height, 44)
                    self.assertLessEqual(
                        service_filters_boundary['scrollWidth'], service_filters_boundary['clientWidth'],
                    )
                    for right in service_filters_boundary['controlRights']:
                        self.assertLessEqual(right, service_filters_boundary['contentRight'] + 1)
                    self.assertGreaterEqual(service_filters_boundary['height'], service_filters_desktop['height'])
                    self.assertGreater(
                        service_filters_boundary['height'], service_filters_desktop['height'],
                        f'#service-filters is not strictly taller at the boundary than at desktop ({theme})',
                    )
                    self.assertGreater(
                        service_filters_boundary['rows'], service_filters_desktop['rows'],
                        f'#service-filters does not occupy strictly more rows at the boundary ({theme})',
                    )

                    # -- Resize back to the boundary before switching sections --
                    page.set_viewport_size({'width': NARROW_BOUNDARY_PX, 'height': 900})

                    # -- Filter groups: #incident-filters (Incidents section) --
                    page.locator('[data-section="incidents"]').click()
                    page.locator('#incident-filters').wait_for(state='visible', timeout=5_000)
                    incident_filters_boundary = page.locator('#incident-filters').evaluate(_MEASURE_FILTER_GROUP_JS)

                    page.set_viewport_size({'width': DESKTOP_WIDTH_PX, 'height': 900})
                    incident_filters_desktop = page.locator('#incident-filters').evaluate(_MEASURE_FILTER_GROUP_JS)
                    page.set_viewport_size({'width': NARROW_BOUNDARY_PX, 'height': 900})

                    self.assertEqual(incident_filters_boundary['controlCount'], 4)
                    self.assertEqual(incident_filters_desktop['controlCount'], 4)
                    for height in incident_filters_boundary['controlHeights']:
                        self.assertGreaterEqual(height, 44)
                    self.assertLessEqual(
                        incident_filters_boundary['scrollWidth'], incident_filters_boundary['clientWidth'],
                    )
                    for right in incident_filters_boundary['controlRights']:
                        self.assertLessEqual(right, incident_filters_boundary['contentRight'] + 1)
                    self.assertGreaterEqual(
                        incident_filters_boundary['height'], incident_filters_desktop['height'],
                    )
                    self.assertGreaterEqual(
                        incident_filters_boundary['rows'], incident_filters_desktop['rows'],
                    )
                    # Deliberately no strict-inequality claim for #incident-filters: it
                    # stays on one row at the boundary in the sans-serif light theme
                    # while wrapping to two in the monospace dark theme, so only the
                    # >= claim holds for it (05-06-PLAN.md Task 3).
                finally:
                    page.close()

        # -- The zero and many cases at the boundary, on the main dashboard --
        for theme in ('dark', 'light'):
            with self.subTest(theme=theme, surface='dashboard-empty'):
                empty_fixture = self._build_fixture(dashboard_services=[])
                page = self._open(theme, '/', NARROW_BOUNDARY_PX, empty_fixture)
                try:
                    page.locator('.svc-empty').wait_for(state='visible', timeout=5_000)
                    box = page.locator('.svc-empty').bounding_box()
                    self.assertIsNotNone(box)
                    self.assertGreater(box['width'] * box['height'], 0)
                finally:
                    page.close()

            with self.subTest(theme=theme, surface='dashboard-many'):
                many_fixture = self._build_fixture()
                page = self._open(theme, '/', NARROW_BOUNDARY_PX, many_fixture)
                try:
                    page.locator('.svc-card').first.wait_for(timeout=5_000)
                    self.assertEqual(page.locator('.svc-card').count(), 3)
                finally:
                    page.close()


if __name__ == '__main__':
    unittest.main()
