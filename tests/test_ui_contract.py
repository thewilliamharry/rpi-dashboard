import pathlib
import unittest


class UiContractTests(unittest.TestCase):
    def test_dashboard_markup_contains_events_panel(self):
        html = pathlib.Path('dashboard/index.html').read_text(encoding='utf-8')
        js = pathlib.Path('dashboard/app.js').read_text(encoding='utf-8')
        self.assertIn('id="events-panel"', html)
        self.assertIn('openMetaEditor', js)
        self.assertNotIn('scan_token', html)
        self.assertIn('id="meta-modal"', html)
        self.assertIn('id="meta-path"', html)
        self.assertIn('id="meta-url"', html)
        self.assertIn('refresh_warning', js)
        self.assertIn("fallback.style.display = 'flex';", js)
        self.assertIn("rounded >= 100 ? '99.99'", js)
        self.assertNotIn('<script>', html)
        self.assertNotIn("prompt('Display name'", html)
        self.assertNotIn("prompt('URL override", html)

    def test_styles_include_events_and_service_ops_classes(self):
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        for token in ['.events-panel', '.evt-row', '.svc-critical', '.svc-edit', '.svc-detail-row', '.meta-modal-window', '.meta-modal-backdrop[hidden]', '.meta-btn-primary', '.meta-error.meta-warning']:
            self.assertIn(token, css)


if __name__ == '__main__':
    unittest.main()
