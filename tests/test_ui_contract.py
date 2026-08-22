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

    def test_phase_one_tls_and_safe_error_contracts_are_accessible(self):
        js = pathlib.Path('dashboard/app.js').read_text(encoding='utf-8')
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        self.assertIn("textContent: 'TLS'", js)
        self.assertIn("tls.setAttribute('aria-label', 'TLS certificate is not verified for this trusted local service.')", js)
        self.assertIn("textContent: 'Edit'", js)
        self.assertIn("edit.setAttribute('aria-label', 'Edit service')", js)
        self.assertIn("Beacon could not use that destination. Review the service details and try again.", js)
        self.assertIn("$('meta-error').focus()", js)
        self.assertIn('.svc-tls-unverified', css)
        self.assertIn('.meta-btn { width: 100%; min-height: 44px;', css)

    def test_dark_mode_sparklines_have_visible_lines_and_fills(self):
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        js = pathlib.Path('dashboard/app.js').read_text(encoding='utf-8')
        for token in [
            '.cpu .sp-fill', '.cpu .sp-line', '.ram .sp-fill',
            '.ram .sp-line', '.disk .sp-fill', '.disk .sp-line',
        ]:
            self.assertIn(token, css)
        self.assertIn("$(`${key}-sparkfill`).setAttribute('d'", js)
        self.assertIn('L200,40 Z', js)

    def test_thumbnail_capture_waits_five_seconds_with_bounded_budget(self):
        source = pathlib.Path('dashboard/app.py').read_text(encoding='utf-8')
        self.assertIn('PREVIEW_SETTLE_MS = 5_000', source)
        self.assertIn('PREVIEW_BROWSER_BUDGET_MS = 27_000', source)
        self.assertIn('page.wait_for_timeout(PREVIEW_SETTLE_MS)', source)
        self.assertGreaterEqual(source.count("int((deadline - time.monotonic()) * 1000)"), 3)

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
            'network_mode: none', 'cap_drop: [ALL]',
            'cap_add: [CHOWN, DAC_READ_SEARCH]',
            'condition: service_completed_successfully', 'pull_policy: never',
            '192.168.0.0/16',
        ]:
            self.assertIn(token, compose)
        data_init_block = compose.split('\n  data-init:\n', 1)[1].split('\n  worker:\n', 1)[0]
        self.assertNotIn('DAC_OVERRIDE', data_init_block)

    def test_compose_recovery_is_isolated_and_web_starts_without_worker_health(self):
        compose = pathlib.Path('docker-compose.yml').read_text(encoding='utf-8')
        for token in [
            'recovery:', 'command: ["python", "-m", "beacon.recovery"]',
            'restart: "no"', 'network_mode: none', 'mem_limit: 256m',
            'pids_limit: 64', 'user: "10001:10001"', 'read_only: true',
            'cap_drop: [ALL]', 'no-new-privileges:true', 'dashboard-data:/data',
        ]:
            self.assertIn(token, compose)
        web_block = compose.split('\n  web:\n', 1)[1].split('\nvolumes:', 1)[0]
        self.assertIn('data-init:', web_block)
        self.assertIn('condition: service_completed_successfully', web_block)
        self.assertNotIn('worker:', web_block)

    def test_maintenance_window_editor_markup_has_stable_hooks_and_one_error_region(self):
        html = pathlib.Path('dashboard/index.html').read_text(encoding='utf-8')
        for hook in [
            'id="meta-window-list"', 'id="meta-window-add"', 'id="meta-window-empty"',
            'id="meta-window-count"', 'id="meta-suggestion"',
        ]:
            self.assertEqual(html.count(hook), 1, hook)
        self.assertEqual(html.count('id="meta-error"'), 1)

    def test_maintenance_window_editor_copywriting_contract_strings_appear_verbatim(self):
        html = pathlib.Path('dashboard/index.html').read_text(encoding='utf-8')
        js = pathlib.Path('dashboard/app.js').read_text(encoding='utf-8')
        self.assertIn('+ Add window', html)
        self.assertIn('No maintenance windows yet', html)
        self.assertIn('Add a window to suppress expected restarts without hiding real failures.', html)
        self.assertIn(
            'How long the service may stay down after this window ends before Beacon raises a real outage.',
            js,
        )

    def test_maintenance_window_stylesheet_declares_bounded_list_and_chip_wrap(self):
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        self.assertIn('.meta-weekday-chips {\n  display: flex;\n  flex-wrap: wrap;', css)
        self.assertIn('max-height: 280px', css)
        self.assertIn('.meta-window-list {', css)

    def test_readme_has_one_offline_recovery_command_and_safe_ordering(self):
        readme = pathlib.Path('README.md').read_text(encoding='utf-8')
        status = 'docker compose run --rm --no-deps recovery python -m beacon.recovery status'
        restore = 'docker compose run --rm --no-deps recovery python -m beacon.recovery restore --latest'
        self.assertEqual(readme.count(status), 1)
        self.assertEqual(readme.count(restore), 1)
        for token in [
            'docker compose stop web worker',
            'The restore command refuses a fresh worker',
            'never accepts a backup path',
            'upgrade lock followed by the exclusive database-maintenance barrier',
            'dashboard.db-wal and dashboard.db-shm',
            'External operator verification: deployed and retained Pi databases',
            'repository automation cannot establish the set of databases held outside the repository',
            'stop the upgrade for an unknown fingerprint',
            'tests/fixtures/legacy/operator/',
            'Restart worker only after deploying a migration-fixed or prior compatible image',
        ]:
            self.assertIn(token, readme)


if __name__ == '__main__':
    unittest.main()
