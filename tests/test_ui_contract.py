import json
import pathlib
import subprocess
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
        self.assertIn('<span class="metric-name">RAM</span>', html)
        self.assertNotIn('RAM pressure', html)
        self.assertNotIn('id="cpu-sub"', html)
        self.assertNotIn('% load', js)
        self.assertNotIn('ram_available)} available', js)
        self.assertNotIn('id="temp-ts"', html)
        self.assertNotIn('sampled ${fmtAgo', js)

    def test_styles_include_events_and_service_ops_classes(self):
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        for token in ['.events-panel', '.evt-row', '.svc-critical', '.svc-edit', '.svc-detail-row', '.meta-modal-window', '.meta-modal-backdrop[hidden]', '.meta-btn-primary', '.meta-error.meta-warning']:
            self.assertIn(token, css)

    def test_decimal_metric_formatters(self):
        script = """
require('./dashboard/app.js');
const f = globalThis.BeaconFormatters;
console.log(JSON.stringify({
  zero: f.fmtDecimalBytes(0),
  invalid: f.fmtDecimalBytes('not-a-number'),
  ram: f.fmtRamPair(2814754816, 8454012928),
  diskGb: f.fmtDiskPair(125000000000, 500000000000),
  belowTb: f.fmtDiskPair(100000000000, 999999999999),
  atTb: f.fmtDiskPair(100000000000, 1000000000000),
  productionDisk: f.fmtDiskPair(104505466880, 1968387354624),
}));
"""
        output = subprocess.check_output(['node', '-e', script], text=True)
        values = json.loads(output)
        self.assertEqual(values['zero'], '0.0 GB')
        self.assertEqual(values['invalid'], '0.0 GB')
        self.assertEqual(values['ram'], '2.8 GB / 8.5 GB')
        self.assertEqual(values['diskGb'], '125.0 GB / 500.0 GB')
        self.assertEqual(values['belowTb'], '100.0 GB / 1000.0 GB')
        self.assertEqual(values['atTb'], '0.1 TB / 1.0 TB')
        self.assertEqual(values['productionDisk'], '0.1 TB / 2.0 TB')

    def test_compose_data_initializer_is_constrained(self):
        compose = pathlib.Path('docker-compose.yml').read_text(encoding='utf-8')
        for token in [
            'data-init:', 'image: beacon:2.0.1', 'user: "0:0"',
            'command: ["chown", "-R", "10001:10001", "/data"]',
            'network_mode: none', 'cap_drop: [ALL]', 'cap_add: [CHOWN]',
            'condition: service_completed_successfully', 'pull_policy: never',
        ]:
            self.assertIn(token, compose)


if __name__ == '__main__':
    unittest.main()
