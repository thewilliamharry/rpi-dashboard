import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from dashboard.beacon import worker_main
from dashboard.beacon import queues
from dashboard.beacon.worker_authority import WorkerAuthority
from tests.helpers import cleanup_db, load_app


class RuntimeOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.appmod, self.db_path = load_app()
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        self._reset_worker_globals()
        cleanup_db(self.db_path)
        self.tmpdir.cleanup()

    def _reset_worker_globals(self):
        worker_main.scheduler = None
        worker_main._worker_started = False
        worker_main._active_services = None
        worker_main._active_worker_id = None

    def _worker_operations(self, *, recover=None, update_heartbeat=None,
                           collect_metrics=None, shutdown_browser=None,
                           release_worker_lease=None, calls=None):
        """Build worker collaborators that use this test's real SQLite lease."""
        calls = calls if calls is not None else []

        def acquire_worker_lease(db_path, worker_id):
            calls.append(('acquire', worker_id))
            return queues.acquire_worker_lease(db_path, worker_id)

        def renew_worker_lease(authority):
            calls.append(('renew', authority.worker_id))
            return queues.renew_worker_authority(authority)

        def real_release_worker_lease(authority):
            calls.append(('release', authority.worker_id))
            return queues.release_worker_authority(authority)

        return worker_main.WorkerOperations(
            prepare_database=lambda _settings: calls.append(('prepare', None)),
            recover_worker_state=recover or (lambda _authority: calls.append(('recover', None))),
            update_worker_heartbeat=update_heartbeat or (
                lambda _authority: calls.append(('heartbeat', None))
            ),
            collect_system_stats=collect_metrics or (lambda _authority: calls.append(('metrics', None))),
            read_scan_state=lambda: {},
            run_discovery=lambda _authority, **_kwargs: None,
            do_uptime_check=lambda _authority, **_kwargs: None,
            process_scan_requests=lambda _authority: None,
            process_preview_requests=lambda _authority: None,
            cleanup_history=lambda _authority: None,
            shutdown_browser=shutdown_browser or (lambda: calls.append(('shutdown_browser', None))),
            acquire_worker_lease=acquire_worker_lease,
            renew_worker_lease=renew_worker_lease,
            release_worker_lease=release_worker_lease or real_release_worker_lease,
        )

    def _assert_immediate_replacement(self, name):
        self.assertIsNone(worker_main.scheduler)
        self.assertFalse(worker_main._worker_started)
        self.assertIsNone(worker_main._active_services)
        self.assertIsNone(worker_main._active_worker_id)
        replacement_id = f'replacement-{name}'
        lease = queues.acquire_worker_lease(self.db_path, replacement_id)
        queues.release_worker_lease(self.db_path, replacement_id, lease.owner_token)

    def _run_worker_with_scheduler(self, operations, fake_scheduler, *, signal_side_effect=None):
        settings = SimpleNamespace(db_path=self.db_path)
        with (
            mock.patch.object(worker_main, 'build_scheduler', return_value=fake_scheduler),
            mock.patch.object(worker_main.signal, 'signal', side_effect=signal_side_effect),
        ):
            return worker_main.run_worker(operations, settings)

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

    def test_malformed_integer_environment_uses_settings_defaults_without_import_crash(self):
        project_root = Path(__file__).resolve().parents[1]
        defaults = {
            'EXPIRE_DAYS': 7,
            'THUMB_REFRESH_DAYS': 1,
            'METRIC_SAMPLE_SECONDS': 5,
            'METRIC_HISTORY_SECONDS': 60,
            'WORKER_READY_SECONDS': 20,
            'DISCOVERY_TIMEOUT_SECONDS': 180,
            'TRIGGER_SCAN_RATE_LIMIT': 4,
            'TRIGGER_SCAN_WINDOW_SECONDS': 60,
            'ALERT_COOLDOWN_SECONDS': 300,
        }
        for key, default in defaults.items():
            for value in ('not-an-int', '', '0', '-1'):
                with self.subTest(key=key, value=value):
                    env = os.environ.copy()
                    env.update({'PYTHONPATH': str(project_root / 'dashboard'), key: value})
                    result = subprocess.run(
                        [sys.executable, '-c', f'import app; print(app.{key})'],
                        cwd=project_root,
                        env=env,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertEqual(result.stdout.strip(), str(default))

        for key in defaults:
            with self.subTest(key=key, value='42'):
                env = os.environ.copy()
                env.update({'PYTHONPATH': str(project_root / 'dashboard'), key: '42'})
                result = subprocess.run(
                    [sys.executable, '-c', f'import app; print(app.{key})'],
                    cwd=project_root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), '42')

    def test_worker_services_are_built_without_starting_worker_lifecycle(self):
        """Composition is pure; lifecycle work is reserved for worker_main.main."""
        operations = mock.Mock()
        settings = mock.Mock()
        services = worker_main.build_worker_services(operations, settings)
        self.assertIs(services.settings, settings)
        operations.prepare_database.assert_not_called()
        operations.recover_worker_state.assert_not_called()
        operations.update_worker_heartbeat.assert_not_called()

    def test_worker_shim_constructs_and_injects_legacy_operations(self):
        """Only the executable shim may join compatibility code to the package."""
        sys.modules.pop('dashboard.worker', None)
        worker = importlib.import_module('dashboard.worker')

        operations = worker.build_worker_operations()

        self.assertIs(operations.recover_worker_state, worker.beacon.worker_recover_worker_state)
        self.assertIs(operations.process_preview_requests, worker.beacon.worker_process_preview_requests)
        self.assertIs(operations.acquire_worker_lease, queues.acquire_worker_lease)

    def test_thumbnail_repository_persists_success_and_failure_for_api_reads(self):
        from dashboard.beacon.repositories import ThumbnailStoreRepository

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, last_latency_ms, last_error) "
                "VALUES (?,?,?,?,?,?,?)",
                (8080, 'Preview service', 1, 1, 1, 1.0, None),
            )
            # A TTL far larger than any real deployment's so the stored
            # expires_ts stays in the future relative to the wall-clock ``now``
            # `/api/thumbnail/<port>` reads later in this test, even though the
            # captured_ts values below are deliberately small, fixed literals.
            repository = ThumbnailStoreRepository(ttl_seconds=10**10)
            repository.store_thumbnail_result(
                conn, 8080, None, None, None, 'x' * 300, ts=111,
            )
            failed = conn.execute(
                "SELECT thumb_ts, thumb_source, thumb_attempt_ts, thumb_error "
                "FROM services WHERE port=8080"
            ).fetchone()
            failed_thumbnail = conn.execute(
                "SELECT 1 FROM thumbnails WHERE port=8080"
            ).fetchone()
            repository.store_thumbnail_result(
                conn, 8080, b'png-bytes', 'image/png', 'screenshot', None, ts=222,
            )
            succeeded = conn.execute(
                "SELECT thumb_ts, thumb_source, thumb_attempt_ts, thumb_error "
                "FROM services WHERE port=8080"
            ).fetchone()
            succeeded_thumbnail = conn.execute(
                "SELECT data, mime FROM thumbnails WHERE port=8080"
            ).fetchone()
            conn.commit()
            conn.close()

        self.assertEqual(
            tuple(failed),
            (None, None, 111, 'x' * 240),
        )
        self.assertIsNone(failed_thumbnail)
        self.assertEqual(
            tuple(succeeded),
            (222, 'screenshot', 222, None),
        )
        self.assertEqual(tuple(succeeded_thumbnail), (b'png-bytes', 'image/png'))
        thumbnail = self.client.get('/api/thumbnail/8080')
        self.assertEqual(thumbnail.status_code, 200)
        self.assertEqual(thumbnail.data, b'png-bytes')

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

    def test_worker_main_is_the_only_startup_path_and_normal_return_allows_replacement(self):
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
        services.admission = worker_main.WorkerAdmission()
        services.prepare_database.side_effect = lambda _settings: lifecycle.append('prepare')
        services.recover_worker_state.side_effect = lambda _authority: lifecycle.append('recover')
        services.update_worker_heartbeat.side_effect = lambda _authority: lifecycle.append('heartbeat')
        services.collect_system_stats.side_effect = lambda _authority: lifecycle.append('metrics')
        services.shutdown_browser.side_effect = lambda: lifecycle.append('shutdown')

        worker_main._worker_started = False
        worker_main.scheduler = None
        with (
            mock.patch.object(worker_main, 'build_worker_services', return_value=services),
            mock.patch.object(worker_main, 'build_scheduler', return_value=FakeScheduler()) as build_scheduler,
            mock.patch.object(worker_main.signal, 'signal') as register_signal,
        ):
            worker.main()
            # Production builds a fresh service graph per lifecycle; this test
            # intentionally reuses a mock graph to observe both calls.
            services.admission = worker_main.WorkerAdmission()
            worker.main()

        self.assertEqual(lifecycle[:4], ['prepare', 'recover', 'heartbeat', 'metrics'])
        self.assertEqual(build_scheduler.call_count, 2)
        self.assertEqual(started, ['start', 'start'])
        self.assertEqual(register_signal.call_count, 4)

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
            queues.renew_worker_lease(
                self.db_path, 'worker-a', first.owner_token, now=now + 32, lease_seconds=30,
            )

    def test_lease_takeover_records_one_monitoring_gap(self):
        started = 1_000
        recovered = started + self.appmod.WORKER_READY_SECONDS + 9
        first = queues.acquire_worker_lease(self.db_path, 'worker-a', now=started, lease_seconds=10)
        queues.renew_worker_lease(
            self.db_path, 'worker-a', first.owner_token, now=started, lease_seconds=10,
        )

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

    def test_lease_contender_never_constructs_scheduler(self):
        services = mock.Mock()
        services.settings = mock.Mock(db_path=self.db_path)
        services.acquire_worker_lease.side_effect = queues.LeaseHeld('owned elsewhere')
        worker_main._worker_started = False
        worker_main.scheduler = None
        with (
            mock.patch.object(worker_main, 'build_worker_services', return_value=services),
            mock.patch.object(worker_main, 'build_scheduler') as build_scheduler,
        ):
            worker_main.run_worker(mock.Mock())
        build_scheduler.assert_not_called()
        services.shutdown_browser.assert_not_called()

    def test_worker_releases_lease_and_allows_immediate_successor_after_terminal_paths(self):
        """Every scheduler terminal result ends the matching durable ownership."""
        terminal_cases = (
            ('normal_return', None, None),
            ('system_exit', SystemExit('stop'), None),
            ('keyboard_interrupt', KeyboardInterrupt(), None),
            ('scheduler_error', RuntimeError('scheduler failed'), RuntimeError),
        )

        for name, start_side_effect, expected_exception in terminal_cases:
            with self.subTest(name=name):
                self._reset_worker_globals()
                calls = []

                class FakeScheduler:
                    def start(self):
                        if start_side_effect:
                            raise start_side_effect

                    def shutdown(self, wait=False):
                        calls.append(('scheduler_shutdown', wait))

                operations = self._worker_operations(calls=calls)
                if expected_exception:
                    with self.assertRaises(expected_exception):
                        self._run_worker_with_scheduler(operations, FakeScheduler())
                else:
                    self._run_worker_with_scheduler(operations, FakeScheduler())

                self.assertEqual(len([call for call in calls if call[0] == 'release']), 1)
                self._assert_immediate_replacement(name)

    def test_worker_releases_lease_after_post_acquisition_startup_failures(self):
        """No startup failure after acquisition may make a replacement wait for expiry."""
        failure = RuntimeError('post-acquisition failure')
        startup_cases = (
            ('recovery', {'recover': mock.Mock(side_effect=failure)}, None),
            ('initial_heartbeat', {'update_heartbeat': mock.Mock(side_effect=failure)}, None),
            ('initial_metrics', {'collect_metrics': mock.Mock(side_effect=failure)}, None),
            ('scheduler_build', {}, failure),
            ('first_signal', {}, None),
            ('second_signal', {}, None),
            ('browser_shutdown', {'shutdown_browser': mock.Mock(side_effect=failure)}, None),
        )

        for name, operation_overrides, scheduler_build_error in startup_cases:
            with self.subTest(name=name):
                self._reset_worker_globals()
                calls = []

                class FakeScheduler:
                    def start(self):
                        return None

                    def shutdown(self, wait=False):
                        calls.append(('scheduler_shutdown', wait))

                operations = self._worker_operations(calls=calls, **operation_overrides)
                signal_side_effect = None
                if name == 'first_signal':
                    signal_side_effect = failure
                elif name == 'second_signal':
                    signal_side_effect = (None, failure)
                with mock.patch.object(
                    worker_main, 'build_scheduler',
                    side_effect=scheduler_build_error or (lambda _services: FakeScheduler()),
                ):
                    with mock.patch.object(worker_main.signal, 'signal', side_effect=signal_side_effect):
                        with self.assertRaises(RuntimeError):
                            worker_main.run_worker(
                                operations, SimpleNamespace(db_path=self.db_path),
                            )

                self._assert_immediate_replacement(name)

    def test_startup_lease_loss_aborts_before_scheduler_construction(self):
        """S1/S2/S3 loss must close admission and never start stale scheduling."""
        cases = (
            ('S1', {'recover': mock.Mock(side_effect=queues.LeaseLost('lost'))}),
            ('S2', {'update_heartbeat': mock.Mock(side_effect=queues.LeaseLost('lost'))}),
            ('S3', {'collect_metrics': mock.Mock(side_effect=queues.LeaseLost('lost'))}),
        )
        for stage, overrides in cases:
            with self.subTest(stage=stage):
                self._reset_worker_globals()
                operations = self._worker_operations(**overrides)
                with mock.patch.object(worker_main, 'build_scheduler') as build_scheduler:
                    worker_main.run_worker(operations, SimpleNamespace(db_path=self.db_path))
                build_scheduler.assert_not_called()
                self._assert_immediate_replacement(f'{stage.lower()}-loss')

    def test_worker_finalizer_suppresses_only_lease_lost_and_always_clears_globals(self):
        """An old worker cannot disturb a successor, but other release failures surface."""
        self._reset_worker_globals()
        acquired_worker_ids = []
        acquired_leases = []
        successor_lease = []

        def acquire_worker_lease(db_path, worker_id):
            acquired_worker_ids.append(worker_id)
            lease = queues.acquire_worker_lease(db_path, worker_id)
            acquired_leases.append(lease)
            return lease

        def transfer_to_successor():
            queues.release_worker_lease(
                self.db_path, acquired_worker_ids[0], acquired_leases[0].owner_token,
            )
            successor_lease.append(
                queues.acquire_worker_lease(self.db_path, 'seeded-successor')
            )

        class FakeScheduler:
            def start(self):
                return None

            def shutdown(self, wait=False):
                return None

        operations = self._worker_operations(shutdown_browser=transfer_to_successor)
        operations = worker_main.replace(operations, acquire_worker_lease=acquire_worker_lease)
        self._run_worker_with_scheduler(operations, FakeScheduler())
        self.assertIsNone(worker_main.scheduler)
        self.assertFalse(worker_main._worker_started)
        self.assertIsNone(worker_main._active_services)
        self.assertIsNone(worker_main._active_worker_id)
        with self.assertRaises(queues.LeaseHeld):
            queues.acquire_worker_lease(self.db_path, 'different-replacement')
        queues.release_worker_lease(
            self.db_path, 'seeded-successor', successor_lease[0].owner_token,
        )
        self._assert_immediate_replacement('after-lost-owner')

        self._reset_worker_globals()
        release_error = RuntimeError('release failed')
        failing_operations = self._worker_operations(
            release_worker_lease=mock.Mock(side_effect=release_error),
        )
        with self.assertRaisesRegex(RuntimeError, 'release failed'):
            self._run_worker_with_scheduler(failing_operations, FakeScheduler())
        self.assertIsNone(worker_main.scheduler)
        self.assertFalse(worker_main._worker_started)
        self.assertIsNone(worker_main._active_services)
        self.assertIsNone(worker_main._active_worker_id)

    def test_stop_worker_defers_release_until_scheduler_unwinds(self):
        """Signals request scheduler shutdown; only lifecycle unwinding releases ownership."""
        self._reset_worker_globals()
        calls = []
        test_case = self

        class FakeScheduler:
            def start(self):
                worker_main.stop_worker()
                with test_case.assertRaises(queues.LeaseHeld):
                    queues.acquire_worker_lease(test_case.db_path, 'signal-replacement')

            def shutdown(self, wait=False):
                calls.append(('scheduler_shutdown', wait))

        self._run_worker_with_scheduler(self._worker_operations(calls=calls), FakeScheduler())
        self.assertIn(('scheduler_shutdown', False), calls)
        self.assertLess(
            calls.index(('scheduler_shutdown', False)),
            next(index for index, call in enumerate(calls) if call[0] == 'release'),
        )
        self._assert_immediate_replacement('signal')

    def test_lease_loss_drains_active_jobs_before_browser_cleanup(self):
        """Loss revokes admission immediately but drains from the lifecycle thread."""
        self._reset_worker_globals()
        calls = []
        preview_started = threading.Event()
        allow_preview_exit = threading.Event()
        admission = worker_main.WorkerAdmission()

        def renew(_authority):
            raise queues.LeaseLost('lost')

        def preview(_authority):
            preview_started.set()
            allow_preview_exit.wait(timeout=2)
            calls.append(('preview_exit', None))

        lease = queues.acquire_worker_lease(self.db_path, 'worker-a', lease_seconds=30)
        services = worker_main.WorkerServices(
            settings=SimpleNamespace(db_path=self.db_path),
            prepare_database=lambda _settings: None,
            recover_worker_state=lambda _authority: None,
            update_worker_heartbeat=lambda _authority: calls.append(('heartbeat', None)),
            collect_system_stats=lambda _authority: None,
            read_scan_state=lambda: {},
            run_discovery=lambda _authority, **_kwargs: None,
            do_uptime_check=lambda _authority, **_kwargs: None,
            process_scan_requests=lambda *_args: calls.append(('scan', None)),
            process_preview_requests=preview,
            cleanup_history=lambda _authority: None,
            shutdown_browser=lambda: calls.append(('browser_shutdown', None)),
            clock=time.time,
            acquire_worker_lease=lambda *_args: None,
            renew_worker_lease=renew,
            release_worker_lease=lambda *_args: calls.append(('release', None)),
            authority=WorkerAuthority.from_lease(lease, self.db_path),
            admission=admission,
        )

        class FakeScheduler:
            def shutdown(self, wait=False):
                calls.append(('scheduler_shutdown', wait))

        worker_main.scheduler = FakeScheduler()
        preview_thread = threading.Thread(target=worker_main.process_previews, args=(services,))
        preview_thread.start()
        self.assertTrue(preview_started.wait(timeout=1))
        self.assertFalse(worker_main.heartbeat(services))
        self.assertIn(('scheduler_shutdown', False), calls)
        self.assertIsNone(worker_main.process_scans(services))
        self.assertNotIn(('scan', None), calls)

        finalizer = threading.Thread(
            target=worker_main._finalize_worker_lifecycle,
            args=(services,),
        )
        finalizer.start()
        self.assertNotIn(('browser_shutdown', None), calls)
        allow_preview_exit.set()
        preview_thread.join(timeout=1)
        finalizer.join(timeout=1)
        self.assertFalse(preview_thread.is_alive())
        self.assertFalse(finalizer.is_alive())
        self.assertLess(calls.index(('preview_exit', None)), calls.index(('browser_shutdown', None)))
        self.assertLess(calls.index(('browser_shutdown', None)), calls.index(('release', None)))

    def test_universal_admission_rejects_each_inventory_callback_after_closure(self):
        """Every post-acquisition callback is refused once a stale worker closes."""
        admission = worker_main.WorkerAdmission()
        categories = {
            row.admission_category
            for row in worker_main.WORKER_CALLBACK_INVENTORY
            if row.ownership_required
        }
        self.assertEqual(set(admission.active_counts), categories)
        admission.close_admission()
        for category in categories:
            with self.subTest(category=category):
                with admission.admit(category) as admitted:
                    self.assertFalse(admitted)
        self.assertEqual(admission.active_counts, {category: 0 for category in categories})

    def test_inventory_dispatch_closes_all_categories_when_any_callback_loses_authority(self):
        """Lease loss from a startup or job path revokes all future work before stop."""
        self._reset_worker_globals()
        calls = []
        admission = worker_main.WorkerAdmission()

        services = worker_main.WorkerServices(
            settings=SimpleNamespace(db_path=self.db_path),
            prepare_database=lambda _settings: None,
            recover_worker_state=lambda _authority: (_ for _ in ()).throw(queues.LeaseLost('lost')),
            update_worker_heartbeat=lambda _authority: None,
            collect_system_stats=lambda _authority: None,
            read_scan_state=lambda: {},
            run_discovery=lambda _authority, **_kwargs: None,
            do_uptime_check=lambda _authority, **_kwargs: None,
            process_scan_requests=lambda _authority: calls.append('scan'),
            process_preview_requests=lambda _authority: calls.append('preview'),
            cleanup_history=lambda _authority: None,
            shutdown_browser=lambda: None,
            clock=time.time,
            acquire_worker_lease=lambda *_args: None,
            renew_worker_lease=lambda _authority: None,
            release_worker_lease=lambda *_args: None,
            authority=WorkerAuthority(self.db_path, 'worker-a', 'epoch-a'),
            admission=admission,
        )

        class FakeScheduler:
            def shutdown(self, wait=False):
                calls.append(('scheduler_shutdown', wait))

        worker_main.scheduler = FakeScheduler()
        self.assertFalse(worker_main.dispatch_callback(services, 'S1'))
        self.assertIn(('scheduler_shutdown', False), calls)
        self.assertIsNone(worker_main.dispatch_callback(services, 'J5'))
        self.assertIsNone(worker_main.dispatch_callback(services, 'J6'))
        self.assertEqual(calls, [('scheduler_shutdown', False)])

    def test_thumbnail_capture_keeps_events_in_memory_until_fenced_publication(self):
        """The browser helper cannot publish a capture event before worker fencing."""
        with (
            mock.patch.object(self.appmod, '_screenshot_service', return_value=(b'png', 'image/png', None)),
            mock.patch.object(self.appmod, '_record_event') as record_event,
        ):
            result = self.appmod._legacy_fetch_thumbnail(8080, 'http://127.0.0.1:8080')
        self.assertEqual(result, (b'png', 'image/png', 'screenshot', None))
        record_event.assert_not_called()

    def test_worker_lease_contender_leaves_process_state_untouched(self):
        """A failed acquisition has no acquired-lifecycle cleanup to perform."""
        self._reset_worker_globals()
        queues.acquire_worker_lease(self.db_path, 'already-owned')
        calls = []
        operations = self._worker_operations(calls=calls)
        with mock.patch.object(worker_main, 'build_scheduler') as build_scheduler:
            worker_main.run_worker(operations, SimpleNamespace(db_path=self.db_path))
        build_scheduler.assert_not_called()
        self.assertEqual(calls, [('prepare', None), ('acquire', mock.ANY)])
        self.assertIsNone(worker_main.scheduler)
        self.assertFalse(worker_main._worker_started)
        self.assertIsNone(worker_main._active_services)
        self.assertIsNone(worker_main._active_worker_id)


if __name__ == '__main__':
    unittest.main()
