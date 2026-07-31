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

from dashboard.beacon import worker_main
from dashboard.beacon import queues
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
        env.pop('DISABLE_BACKGROUND', None)
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

    def test_worker_services_are_built_without_starting_worker_lifecycle(self):
        """Composition is pure; lifecycle work is reserved for worker_main.main."""
        with (
            mock.patch.object(worker_main, 'prepare_database') as prepare,
            mock.patch.object(worker_main, 'recover_worker_state') as recover,
            mock.patch.object(worker_main, 'update_worker_heartbeat') as heartbeat,
        ):
            services = worker_main.build_worker_services()
        self.assertIsNotNone(services.settings)
        prepare.assert_not_called()
        recover.assert_not_called()
        heartbeat.assert_not_called()

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
        sys.modules.pop('dashboard.worker', None)
        worker = importlib.import_module('dashboard.worker')
        started = []
        lifecycle = []

        class FakeScheduler:
            def start(self):
                started.append('start')

            def shutdown(self, wait=False):
                started.append('shutdown')

        services = mock.Mock()
        services.settings = mock.Mock()
        services.prepare_database.side_effect = lambda _settings: lifecycle.append('prepare')
        services.recover_worker_state.side_effect = lambda: lifecycle.append('recover')
        services.update_worker_heartbeat.side_effect = lambda: lifecycle.append('heartbeat')
        services.collect_system_stats.side_effect = lambda: lifecycle.append('metrics')
        services.shutdown_browser.side_effect = lambda: lifecycle.append('shutdown')

        worker_main._worker_started = False
        worker_main.scheduler = None
        with (
            mock.patch.object(worker_main, 'build_worker_services', return_value=services),
            mock.patch.object(worker_main, 'build_scheduler', return_value=FakeScheduler()) as build_scheduler,
            mock.patch.object(worker_main.signal, 'signal') as register_signal,
        ):
            worker.main()
            worker.main()

        self.assertEqual(lifecycle[:4], ['prepare', 'recover', 'heartbeat', 'metrics'])
        self.assertEqual(build_scheduler.call_count, 1)
        self.assertEqual(started, ['start'])
        self.assertEqual(register_signal.call_count, 2)

    def test_dashboard_keeps_connection_and_worker_warning_states_separate(self):
        script = Path('dashboard/app.js').read_text(encoding='utf-8')
        styles = Path('dashboard/style.css').read_text(encoding='utf-8')
        self.assertIn("setConnectionState(false);", script)
        self.assertIn("updateWorkerWarning(Boolean(data.worker_stale));", script)
        self.assertIn(
            'Monitoring paused — worker unavailable. Dashboard data may be stale; service settings changes are still saved.',
            script,
        )
        self.assertIn('Monitoring resumed. The outage was recorded in Events.', script)
        self.assertIn("'monitoring_gap'", script)
        self.assertIn('.worker-warning', styles)

    def test_worker_lease_is_atomic_and_stale_owners_cannot_renew(self):
        """A persisted owner lease, rather than a process lock, owns scheduling."""
        now = 10_000
        first = queues.acquire_worker_lease(self.db_path, 'worker-a', now=now, lease_seconds=30)
        self.assertEqual(first.worker_id, 'worker-a')

        with self.assertRaises(queues.LeaseHeld):
            queues.acquire_worker_lease(self.db_path, 'worker-b', now=now + 1, lease_seconds=30)

        successor = queues.acquire_worker_lease(self.db_path, 'worker-b', now=now + 31, lease_seconds=30)
        self.assertEqual(successor.worker_id, 'worker-b')
        with self.assertRaises(queues.LeaseLost):
            queues.renew_worker_lease(self.db_path, 'worker-a', now=now + 32, lease_seconds=30)

    def test_lease_takeover_records_one_monitoring_gap(self):
        started = 1_000
        recovered = started + self.appmod.WORKER_READY_SECONDS + 9
        queues.acquire_worker_lease(self.db_path, 'worker-a', now=started, lease_seconds=10)
        queues.renew_worker_lease(self.db_path, 'worker-a', now=started, lease_seconds=10)

        queues.acquire_worker_lease(self.db_path, 'worker-b', now=recovered, lease_seconds=10)
        queues.acquire_worker_lease(self.db_path, 'worker-c', now=recovered + 11, lease_seconds=10)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = conn.execute(
                "SELECT details FROM events WHERE event_type='monitoring_gap'"
            ).fetchall()
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['details']), {'start_ts': started, 'end_ts': recovered})


if __name__ == '__main__':
    unittest.main()
