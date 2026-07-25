import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from tests.helpers import cleanup_db, load_app


class RuntimeOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.appmod, self.db_path = load_app()
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)
        self.tmpdir.cleanup()

    def test_fresh_imports_do_not_start_runtime_or_create_database(self):
        project_root = Path(__file__).resolve().parents[1]
        sentinel = Path(self.tmpdir.name) / 'sentinel.db'
        env = os.environ.copy()
        env.update({
            'DB_PATH': str(sentinel),
            'PYTHONPATH': str(project_root / 'dashboard'),
        })
        result = subprocess.run(
            [sys.executable, '-c', 'import app; import worker; print("imported")'],
            cwd=project_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('imported', result.stdout)
        self.assertFalse(sentinel.exists())

    def test_stale_heartbeat_is_reported_without_unhealthy_web_process(self):
        now = 10_000
        self.appmod.update_worker_heartbeat(now=now - self.appmod.WORKER_READY_SECONDS - 1)
        with mock.patch.object(self.appmod.time, 'time', return_value=now):
            status = self.client.get('/api/scan-status')
        payload = status.get_json()
        self.assertEqual(status.status_code, 200)
        self.assertEqual(self.client.get('/healthz').status_code, 200)
        self.assertTrue(payload['worker_stale'])
        self.assertEqual(payload['worker_heartbeat_ts'], now - self.appmod.WORKER_READY_SECONDS - 1)
        self.assertEqual(payload['worker_heartbeat_age_seconds'], self.appmod.WORKER_READY_SECONDS + 1)
        self.assertTrue(payload['recovery_required'])

    def test_recovery_records_one_bounded_monitoring_gap(self):
        start = 1_000
        recovered_at = start + self.appmod.WORKER_READY_SECONDS + 9
        self.appmod.update_worker_heartbeat(now=start)
        self.appmod.recover_worker_state(now=recovered_at)
        self.appmod.update_worker_heartbeat(now=recovered_at)
        self.appmod.recover_worker_state(now=recovered_at + 1)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = conn.execute(
                "SELECT ts, event_type, details FROM events WHERE event_type='monitoring_gap'"
            ).fetchall()
            conn.close()
        self.assertEqual(len(rows), 1)
        details = json.loads(rows[0]['details'])
        self.assertEqual(rows[0]['ts'], recovered_at)
        self.assertEqual(details, {'start_ts': start, 'end_ts': recovered_at})

    def test_worker_main_is_the_only_startup_path_and_is_idempotent(self):
        sys.modules.pop('worker', None)
        worker = importlib.import_module('worker')
        started = []

        class FakeScheduler:
            def start(self):
                started.append('start')

            def shutdown(self, wait=False):
                started.append('shutdown')

        with (
            mock.patch.object(worker.beacon, 'init_db') as init_db,
            mock.patch.object(worker.beacon, 'recover_worker_state') as recover,
            mock.patch.object(worker.beacon, 'update_worker_heartbeat') as heartbeat,
            mock.patch.object(worker, 'build_scheduler', return_value=FakeScheduler()),
            mock.patch.object(worker.signal, 'signal') as register_signal,
        ):
            worker.main()
            worker.main()

        self.assertEqual(init_db.call_count, 1)
        self.assertEqual(recover.call_count, 1)
        self.assertEqual(heartbeat.call_count, 1)
        self.assertEqual(started, ['start'])
        self.assertEqual(register_signal.call_count, 2)


if __name__ == '__main__':
    unittest.main()
