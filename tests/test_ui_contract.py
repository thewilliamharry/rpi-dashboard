import pathlib
import unittest


class UiContractTests(unittest.TestCase):
    def test_dashboard_markup_contains_events_panel(self):
        html = pathlib.Path('dashboard/index.html').read_text(encoding='utf-8')
        self.assertIn('id="events-panel"', html)
        self.assertIn('openMetaEditor', html)
        self.assertIn('scan_token', html)

    def test_styles_include_events_and_service_ops_classes(self):
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        for token in ['.events-panel', '.evt-row', '.svc-critical', '.svc-edit', '.svc-detail-row']:
            self.assertIn(token, css)


if __name__ == '__main__':
    unittest.main()
