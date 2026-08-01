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
            scan_claim = self.appmod.beacon_queues.claim_scan(
                self.appmod.DB_PATH, 'ui-recovery-worker', now=self.now + 1,
            )
            self.assertIsNotNone(scan_claim)
            self.appmod.beacon_queues.finish_scan(
                self.appmod.DB_PATH, scan_claim.request_id, scan_claim.lease_owner,
                result='{}', now=self.now + 2,
            )
            preview_claim = self.appmod.beacon_queues.claim_preview(
                self.appmod.DB_PATH, 'ui-recovery-worker', now=self.now + 1,
            )
            self.assertIsNotNone(preview_claim)
            self.appmod.beacon_queues.finish_preview(
                self.appmod.DB_PATH, preview_claim.request_id, 'ui-recovery-worker',
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


if __name__ == '__main__':
    unittest.main()
