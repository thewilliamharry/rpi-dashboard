import importlib
import os
import pathlib
import shutil
import tempfile
import threading
import time
import unittest

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCTION_FIXTURE = ROOT / 'tests/fixtures/legacy/operator/production.db'


class UiSafetyIntegrationTests(unittest.TestCase):
    """Exercise stale monitoring and durable work through the real Flask page."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix='beacon-ui-safety-')
        self.db_path = pathlib.Path(self.tmpdir.name) / 'dashboard.db'
        shutil.copy2(PRODUCTION_FIXTURE, self.db_path)
        self.original_db_path = os.environ.get('DB_PATH')
        os.environ['DB_PATH'] = str(self.db_path)

        import dashboard.app as appmod

        self.appmod = importlib.reload(appmod)
        self.appmod.init_db()
        self.now = int(time.time())
        self._seed_service()
        self.appmod.collect_system_stats(now=self.now, persist_history=False)
        self.appmod.update_worker_heartbeat(
            now=self.now - self.appmod.WORKER_READY_SECONDS - 1,
        )

        self.server = make_server('127.0.0.1', 0, self.appmod.app)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.base_url = f'http://127.0.0.1:{self.server.server_port}'
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            executable_path=self.playwright.chromium.executable_path,
        )

    def tearDown(self):
        self.browser.close()
        self.playwright.stop()
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)
        if self.original_db_path is None:
            os.environ.pop('DB_PATH', None)
        else:
            os.environ['DB_PATH'] = self.original_db_path
        self.tmpdir.cleanup()

    def _seed_service(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    "INSERT INTO services(port, title, first_seen, last_seen, is_online, "
                    "state_since, last_latency_ms) VALUES(?,?,?,?,?,?,?)",
                    (8100, 'Fixture service', self.now, self.now, 1, self.now, 12.0),
                )
                conn.commit()
            finally:
                conn.close()

    def _request_rows(self, table):
        ordering = 'port' if table == 'service_meta' else 'id'
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                return [dict(row) for row in conn.execute(f'SELECT * FROM {table} ORDER BY {ordering}')]
            finally:
                conn.close()

    def test_stale_to_fresh_page_persists_actions_and_records_recovery(self):
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        try:
            page.goto(self.base_url, wait_until='networkidle')
            warning = page.locator('#worker-warning')
            self.assertTrue(warning.is_visible())
            self.assertIn('Monitoring paused', warning.text_content())
            self.assertFalse(page.locator('#connection-banner').is_visible())

            page.locator('#toggle').click()
            self.assertTrue(page.locator('html').evaluate('(node) => node.classList.contains("light")'))
            self.assertTrue(page.locator('.svc-title-link').is_visible())

            page.locator('.svc-edit').click()
            self.assertTrue(page.locator('#meta-stale-warning').is_visible())
            page.locator('#meta-display-name').fill('Saved during worker outage')
            page.locator('#meta-form').evaluate('(form) => form.requestSubmit()')
            expect(page.locator('#dashboard-feedback')).to_have_text(
                'Service details saved. Preview refresh queued.',
            )
            self.assertEqual(
                self._request_rows('service_meta')[0]['display_name'],
                'Saved during worker outage',
            )
            preview_rows = self._request_rows('preview_requests')
            self.assertEqual(preview_rows[-1]['status'], 'queued')

            page.locator('.btn-scan').click()
            expect(page.locator('#scan-label')).to_contain_text('Scan queued')
            scan_rows = self._request_rows('scan_requests')
            self.assertEqual(scan_rows[-1]['status'], 'queued')
            self.assertIsNone(scan_rows[-1]['lease_owner'])

            self.appmod.recover_worker_state(now=self.now)
            self.appmod.update_worker_heartbeat(now=self.now)
            owner = self.appmod.beacon_queues.acquire_worker_lease(
                self.appmod.DB_PATH, 'ui-recovery-worker', now=self.now,
            )
            scan_claim = self.appmod.beacon_queues.claim_scan(
                self.appmod.DB_PATH, owner.worker_id,
                worker_owner_token=owner.owner_token, now=self.now + 1,
            )
            self.assertIsNotNone(scan_claim)
            self.appmod.beacon_queues.finish_scan(
                self.appmod.DB_PATH, scan_claim.request_id, scan_claim.lease_owner,
                worker_id=owner.worker_id, worker_owner_token=owner.owner_token,
                result='{}', now=self.now + 2,
            )
            preview_claim = self.appmod.beacon_queues.claim_preview(
                self.appmod.DB_PATH, owner.worker_id,
                worker_owner_token=owner.owner_token, now=self.now + 1,
            )
            self.assertIsNotNone(preview_claim)
            self.appmod.beacon_queues.finish_preview(
                self.appmod.DB_PATH, preview_claim.request_id, owner.worker_id,
                worker_owner_token=owner.owner_token,
                revision=preview_claim.revision, result='{}', now=self.now + 2,
            )
            self.appmod.beacon_queues.enqueue_scan(
                self.appmod.DB_PATH, 'expired-ui-request', now=self.now - 901,
            )
            self.appmod.beacon_queues.recover_queues(self.appmod.DB_PATH, now=self.now + 3)

            warning.wait_for(state='hidden', timeout=8_000)
            self.assertIn(
                'Monitoring resumed. The outage was recorded in Events.',
                page.locator('#dashboard-feedback').text_content(),
            )
            page.get_by_text('Scan request expired — it was not run. Scan again.').wait_for(
                timeout=18_000,
            )
            self.assertIn('Scan request expired', page.locator('#scan-label').text_content())
            page.get_by_text('Monitoring gap recorded').wait_for(timeout=18_000)
            self.assertIn('Worker unavailable for', page.locator('#events-panel').text_content())

            self.assertEqual(self._request_rows('scan_requests')[0]['status'], 'completed')
            self.assertEqual(self._request_rows('scan_requests')[-1]['status'], 'expired')
            self.assertEqual(self._request_rows('preview_requests')[-1]['status'], 'completed')
        finally:
            page.close()

    def test_degraded_banner_reads_identically_in_both_themes_on_both_documents(self):
        """A real aging heartbeat raises one identically-worded banner, unstubbed, both themes."""
        cadence = self.appmod.beacon_diagnosis.worker_heartbeat_cadence_seconds(self.appmod.SETTINGS)
        age = 2 * cadence
        # Deriving the age from the shared classifier (rather than a hard-coded
        # second count) is what stops this test from re-encoding a threshold of
        # its own; a future settings change that breaks this bound fails loudly
        # instead of silently drifting the seeded heartbeat into another tier.
        self.assertGreater(age, cadence)
        self.assertLessEqual(age, self.appmod.SETTINGS.worker_ready_seconds)

        def seed_aging_heartbeat():
            # Re-seeded against a freshly read clock immediately before each
            # subtest's navigation -- ``self.now`` was captured in ``setUp``
            # before the (comparatively slow) Playwright/Chromium launch, and
            # four sequential real browser navigations each take real wall
            # time, so a heartbeat seeded once up front can drift out of the
            # `aging` tier and into `stale` before the last subtest runs.
            live_now = int(time.time())
            heartbeat_ts = live_now - age
            self.appmod.update_worker_heartbeat(now=heartbeat_ts)
            freshness = self.appmod.beacon_diagnosis.worker_freshness(
                live_now, heartbeat_ts, self.appmod.SETTINGS,
            )
            self.assertEqual(freshness['state'], 'aging')

        expected_text = (
            "Degraded — Beacon's worker heartbeat is aging. Monitoring continues; this is not a failure."
        )

        def computed(locator, prop):
            return locator.evaluate(f'(node) => getComputedStyle(node)[{prop!r}]')

        degraded_colors = {}
        for theme in ('dark', 'light'):
            for path in ('/', '/advanced'):
                with self.subTest(theme=theme, path=path):
                    seed_aging_heartbeat()
                    page = self.browser.new_page(viewport={'width': 1280, 'height': 900})
                    if theme == 'light':
                        page.add_init_script("localStorage.setItem('beacon-theme', 'light');")
                    try:
                        page.goto(f'{self.base_url}{path}', wait_until='domcontentloaded')
                        banner = page.locator('#degraded-warning')
                        banner.wait_for(state='visible', timeout=8_000)
                        self.assertEqual(banner.text_content(), expected_text)

                        self.assertFalse(page.locator('#worker-warning').is_visible())
                        self.assertFalse(page.locator('#recovery-warning').is_visible())

                        self.assertEqual(computed(banner, 'borderBottomStyle'), 'none')
                        self.assertEqual(
                            computed(page.locator('#recovery-warning'), 'borderBottomStyle'), 'solid',
                        )

                        degraded_color = computed(banner, 'color')
                        body_color = computed(page.locator('body'), 'color')
                        self.assertTrue(degraded_color)
                        self.assertNotEqual(degraded_color, body_color)
                        degraded_colors[theme] = degraded_color
                    finally:
                        page.close()

        self.assertNotEqual(degraded_colors['dark'], degraded_colors['light'])

    def test_stale_heartbeat_shows_worker_banner_and_not_the_degraded_banner(self):
        """Exclusivity pinned from the rendered page, not only from the payload."""
        page = self.browser.new_page(viewport={'width': 1100, 'height': 800})
        try:
            page.goto(self.base_url, wait_until='domcontentloaded')
            page.locator('#worker-warning').wait_for(state='visible', timeout=8_000)
            self.assertTrue(page.locator('#worker-warning').is_visible())
            self.assertFalse(page.locator('#degraded-warning').is_visible())
        finally:
            page.close()


if __name__ == '__main__':
    unittest.main()
