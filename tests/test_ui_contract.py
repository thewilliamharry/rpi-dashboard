import json
import pathlib
import re
import subprocess
import unittest


# The exhaustive, self-maintaining theme-gated visibility inventory (05-03).
#
# Each key is a theme-scoped selector (a selector beginning with `html.light` or
# `html:not(.light)`) whose declaration block sets `display: none` somewhere in the
# project's stylesheets. `extract_theme_gated_hidden_selectors` derives this set from
# the stylesheet text at test time so the inventory can never drift silently from the
# CSS it describes — a ninth rule appearing anywhere fails
# `test_every_theme_gated_visibility_rule_is_enumerated_and_classified` until it is
# classified here.
#
# Classification is exactly one of two values, recorded as a decision record rather
# than a bare list:
#   - "decorative": the rule hides a purely cosmetic flourish with no informational
#     content of its own (or, for `.corner`/`.offline-badge`, is a dead rule that no
#     document or script currently renders at all — see DEAD_THEME_HIDDEN_SELECTORS).
#   - "deliberate-calm": the rule hides a genuine informational surface in light mode
#     as a considered calm-reading choice (05-CONTEXT.md D-03 and its A-13 extension),
#     with a recorded light-mode substitute or accepted exception (A-15).
THEME_HIDDEN_RULES = {
    '.arc-unit': 'decorative',           # gauge unit label ("%") — cosmetic, not a fact
    '.sparkline': 'deliberate-calm',     # per-service trend line — D-03: gauges alone satisfy UX-01
    '.temp-row': 'deliberate-calm',      # temperature readout row — D-03 calm reading
    '.corner': 'decorative',             # dark HUD-corner flourish — dead rule (A-14), renders nowhere
    '.svc-preview': 'deliberate-calm',   # service thumbnail — A-15: the one accepted exception
    '.svc-uptime-pct': 'deliberate-calm',  # per-service 7d uptime % text — A-13 extends D-03
    '.uptime-labels': 'deliberate-calm',   # uptime-strip day labels — D-03 calm reading
    '.offline-badge': 'decorative',      # offline badge — dead rule (A-14), renders nowhere
}

# The two decorative classifications the audit found are dead rules: no element
# carrying either class is rendered by any document or script (A-14). Pinned here
# rather than deleted from the stylesheet — pinning means a future phase that starts
# rendering either class must re-classify it before its markup can land.
DEAD_THEME_HIDDEN_SELECTORS = {'.corner', '.offline-badge'}

# Matches a top-level "selector { declarations }" block. Tolerant of an @media
# wrapper around it (the outer @media selector-like text never resolves to a
# "html.light "/"html:not(.light) " prefix followed by a bare braces body, so it is
# skipped automatically; the nested rule inside the @media block is matched on its
# own pass).
_RULE_BLOCK_RE = re.compile(r'([^{}]+)\{([^{}]*)\}')
# A theme-scoped selector begins with the light-theme class or the not-light negation,
# followed by whitespace and the rest of the selector (tolerant of extra internal
# whitespace, which is normalized before this pattern is applied).
_THEME_SCOPED_SELECTOR_RE = re.compile(r'^(html\.light|html:not\(\.light\))\s+(.+)$')
# Tolerant of whitespace around the colon and an optional trailing semicolon; matches
# the declaration wherever it appears in the block, not only as the first or only rule.
_DISPLAY_NONE_RE = re.compile(r'display\s*:\s*none\s*;?')


def extract_theme_gated_hidden_selectors(css_text):
    """Derive every theme-scoped selector whose declaration block sets display: none.

    A selector is "theme-scoped" if it begins with the light-theme class (html.light)
    or the not-light negation (html:not(.light)). Tolerant of the file's existing
    formatting variations — whitespace around the colon and the brace, and the
    display:none declaration appearing anywhere in the block alongside other
    declarations.
    """
    selectors = set()
    for raw_selector, body in _RULE_BLOCK_RE.findall(css_text):
        selector = ' '.join(raw_selector.split())
        match = _THEME_SCOPED_SELECTOR_RE.match(selector)
        if not match:
            continue
        if _DISPLAY_NONE_RE.search(body):
            selectors.add(match.group(2))
    return selectors


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
        self.assertIn('migrate:', web_block)
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

    def test_dashboard_maintenance_card_and_events_reveal_copywriting_contract_strings_appear_verbatim(self):
        js = pathlib.Path('dashboard/app.js').read_text(encoding='utf-8')
        self.assertIn("'MAINTENANCE'", js)
        self.assertIn('Show 1 suppressed entry', js)
        self.assertIn('suppressed entries', js)
        self.assertIn('Hide suppressed entries', js)
        self.assertIn("'Expected'", js)
        self.assertIn('still down past maintenance', js)
        self.assertIn('Down since', js)
        self.assertIn('Raised at', js)
        self.assertIn(
            'Offline and covered by a confirmed maintenance window until',
            js,
        )
        self.assertIn('Downtime is still counted in the 7-day availability figure.', js)

    def test_dashboard_maintenance_and_reveal_stylesheet_declares_required_classes(self):
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        for token in [
            '.svc-maintenance', '.svc-maintenance-status', '.evt-pill',
            '.evt-pill-expected', '.evt-reveal',
        ]:
            self.assertIn(token, css)
        self.assertIn('.svc-status-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; }', css)

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

    def test_every_theme_gated_visibility_rule_is_enumerated_and_classified(self):
        css = pathlib.Path('dashboard/style.css').read_text(encoding='utf-8')
        extracted = extract_theme_gated_hidden_selectors(css)

        # Pattern self-check: a broken expression that matched nothing must not let
        # this test pass vacuously.
        self.assertTrue(extracted, 'pattern self-check: the extraction regex matched zero rules')

        self.assertEqual(extracted, set(THEME_HIDDEN_RULES.keys()))
        self.assertEqual(len(extracted), 8)
        for selector, classification in THEME_HIDDEN_RULES.items():
            self.assertIn(
                classification, ('deliberate-calm', 'decorative'),
                f'{selector} has an unrecognised classification: {classification!r}',
            )

    def test_advanced_workspace_hides_nothing_by_theme(self):
        css = pathlib.Path('dashboard/advanced.css').read_text(encoding='utf-8')
        extracted = extract_theme_gated_hidden_selectors(css)
        self.assertEqual(
            extracted, set(),
            'The advanced workspace must render from one DOM tree in both themes; a '
            'theme-gated visibility rule there is a capability-parity defect, not a '
            f'density choice. Found: {sorted(extracted)}',
        )

    def test_decorative_theme_gated_rules_are_dead_and_render_nothing(self):
        documents = {
            'dashboard/index.html': pathlib.Path('dashboard/index.html').read_text(encoding='utf-8'),
            'dashboard/advanced.html': pathlib.Path('dashboard/advanced.html').read_text(encoding='utf-8'),
            'dashboard/app.js': pathlib.Path('dashboard/app.js').read_text(encoding='utf-8'),
            'dashboard/advanced.js': pathlib.Path('dashboard/advanced.js').read_text(encoding='utf-8'),
        }
        for dead_selector in DEAD_THEME_HIDDEN_SELECTORS:
            class_name = dead_selector.lstrip('.')
            for doc_name, content in documents.items():
                self.assertNotIn(
                    class_name, content,
                    f'{class_name} is pinned as a dead rule but appears in {doc_name}; '
                    'it must be re-classified before this markup can land',
                )
        # .arc-unit, the third decorative entry, IS rendered — keeping the two
        # categories (dead vs. decorative-but-live) distinguishable.
        self.assertIn('arc-unit', documents['dashboard/index.html'])


if __name__ == '__main__':
    unittest.main()
