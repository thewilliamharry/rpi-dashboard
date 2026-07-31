import pathlib
import unittest


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
        self.assertIn('TLS unverified', self.js)
        self.assertIn('TLS certificate is not verified for this trusted local service.', self.js)
        self.assertIn("textContent: 'Edit service'", self.js)

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


if __name__ == '__main__':
    unittest.main()
