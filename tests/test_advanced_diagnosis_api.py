import json
import logging
import sqlite3
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from dashboard.beacon import migrations, queues, repositories, worker_main
from dashboard.beacon.worker_authority import WorkerAuthority
from tests.helpers import cleanup_db, load_app


class AdvancedDiagnosisApiTests(unittest.TestCase):
    """Tracer coverage for the bounded current-host advanced diagnosis API."""

    def setUp(self):
        self._clock = {'now': None}
        self._clock_patcher = None
        self.appmod, self.db_path = load_app({'METRIC_SAMPLE_SECONDS': '5'})
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _freeze_clock(self, value):
        """Freeze the process-global ``time.time`` for this test only.

        The patch is installed once per test and unwound by ``addCleanup`` even
        when the test fails, so no frozen instant can outlive the test that set
        it.  Calling this again inside the same test re-points the instant
        rather than stacking a second patcher.
        """
        self._clock['now'] = value
        if self._clock_patcher is None:
            real_time = time.time
            patcher = mock.patch(
                'time.time',
                lambda: real_time() if self._clock['now'] is None else self._clock['now'],
            )
            patcher.start()
            self.addCleanup(patcher.stop)
            self._clock_patcher = patcher
        return value

    def _seed_host(self, sample_ts=1_700_000_000):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO system_stats('
                'id,sample_ts,cpu,ram,ram_used,ram_available,ram_used_strict,ram_total,'
                'disk,disk_used,disk_total,temp,hostname'
                ') VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)',
                (
                    sample_ts, 21.5, 42.0, 420, 580, 420, 1000,
                    63.0, 630, 1000, 51.25, 'beacon-pi',
                ),
            )
            conn.commit()
            conn.close()

    def test_host_tracer_returns_one_current_snapshot_with_server_freshness(self):
        self._seed_host(sample_ts=1_700_000_000)
        self._freeze_clock(1_700_000_005)

        response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        payload = response.get_json()
        self.assertEqual(payload['schema_version'], 3)
        self.assertEqual(payload['generated_ts'], 1_700_000_005)
        self.assertEqual(payload['host']['identity']['hostname'], 'beacon-pi')
        self.assertEqual(payload['host']['metrics']['cpu'], {'value': 21.5, 'unit': 'percent'})
        self.assertEqual(payload['host']['metrics']['memory']['used_bytes'], 420)
        self.assertEqual(payload['host']['metrics']['disk']['total_bytes'], 1000)
        self.assertEqual(payload['host']['metrics']['temperature'], {'value': 51.25, 'unit': 'celsius'})
        self.assertEqual(payload['host']['sample_ts'], 1_700_000_000)
        self.assertEqual(payload['host']['expected_cadence_seconds'], 5)
        self.assertEqual(
            payload['host']['freshness'],
            {'state': 'fresh', 'age_seconds': 5},
        )

    def test_host_tracer_returns_truthful_unknown_host_evidence(self):
        self._freeze_clock(1_700_000_005)

        response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 200)
        host = response.get_json()['host']
        self.assertIsNone(host['identity']['hostname'])
        self.assertIsNone(host['metrics']['cpu']['value'])
        self.assertIsNone(host['metrics']['temperature']['value'])
        self.assertIsNone(host['sample_ts'])
        self.assertEqual(host['freshness'], {'state': 'unknown', 'age_seconds': None})

    def test_host_freshness_boundaries_and_invalid_evidence(self):
        freshness_state = self.appmod.beacon_diagnosis.freshness_state
        now = 1_700_000_100
        cases = [
            (now - 5, 5, {'state': 'fresh', 'age_seconds': 5}),
            (now - 6, 5, {'state': 'aging', 'age_seconds': 6}),
            (now - 20, 5, {'state': 'aging', 'age_seconds': 20}),
            (now - 21, 5, {'state': 'stale', 'age_seconds': 21}),
            (now + 10, 5, {'state': 'fresh', 'age_seconds': 0}),
            (None, 5, {'state': 'unknown', 'age_seconds': None}),
            (now - 1, 0, {'state': 'unknown', 'age_seconds': None}),
            (now - 1, 'five', {'state': 'unknown', 'age_seconds': None}),
        ]
        for sample_ts, cadence, expected in cases:
            with self.subTest(sample_ts=sample_ts, cadence=cadence):
                self.assertEqual(freshness_state(now, sample_ts, cadence), expected)

    def test_worker_safety_uses_the_immutable_heartbeat_cadence(self):
        """J1 remains a five-second heartbeat even when host metrics are slower."""
        appmod, db_path = load_app({'METRIC_SAMPLE_SECONDS': '37'})
        client = appmod.app.test_client()
        now = 1_700_000_100
        try:
            with appmod._db_lock:
                conn = appmod.get_db()
                conn.execute(
                    'INSERT INTO runtime_state(key,value,updated_ts) VALUES(?,?,?) '
                    'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts',
                    ('worker_heartbeat', json.dumps({'ts': now}), now),
                )
                conn.commit()
                conn.close()
            for age, expected_state, expected_warning in (
                (5, 'fresh', False),
                (20, 'aging', False),
                (21, 'stale', True),
            ):
                with self.subTest(age=age):
                    self._freeze_clock(now + age)
                    payload = client.get('/api/advanced/current').get_json()
                    worker = payload['pipeline']['worker']
                    self.assertEqual(worker['expected_cadence_seconds'], 5)
                    self.assertEqual(worker['freshness'], {'state': expected_state, 'age_seconds': age})
                    self.assertEqual(payload['safety']['worker_stale'], expected_warning)
        finally:
            cleanup_db(db_path)

    def test_direct_route_tracer_preserves_middleware_assets_and_get_only_api(self):
        asset_directory = Path(self.appmod.__file__).resolve().parent
        for path, mimetype, filename in [
            ('/advanced', 'text/html', 'advanced.html'),
            ('/advanced.js', 'application/javascript', 'advanced.js'),
            ('/advanced.css', 'text/css', 'advanced.css'),
        ]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(mimetype, response.content_type)
                self.assertEqual(response.data, (asset_directory / filename).read_bytes())
                self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
                self.assertIn("default-src 'self'", response.headers['Content-Security-Policy'])

        self.assertEqual(
            self.client.get('/advanced', headers={'Host': 'evil.example'}).status_code,
            400,
        )
        for method in ('post', 'put', 'patch', 'delete'):
            with self.subTest(method=method):
                self.assertIn(
                    getattr(self.client, method)('/api/advanced/current').status_code,
                    (403, 405),
                )

    def test_migration_eight_adds_only_job_health_evidence(self):
        """The approved Migration 8 remains additive over the supported schema."""
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            tables = {
                row['name'] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            columns = {
                row['name'] for row in conn.execute(
                    'PRAGMA table_info(background_job_health)'
                )
            }
            versions = [
                row['version'] for row in conn.execute(
                    'SELECT version FROM schema_migrations ORDER BY version'
                )
            ]
            conn.close()

        self.assertIn('background_job_health', tables)
        self.assertEqual(
            columns,
            {
                'job_id', 'last_started_ts', 'last_finished_ts',
                'last_success_ts', 'state', 'error_class', 'updated_ts',
            },
        )
        self.assertEqual(migrations.MIGRATIONS[-1].version, 8)
        self.assertIn(8, versions)

    def test_job_health_transitions_preserve_success_and_bound_failure_class(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            repositories.record_background_job_started(conn, 'J2', now=100)
            repositories.record_background_job_succeeded(conn, 'J2', now=101)
            repositories.record_background_job_failed(
                conn, 'J2', now=102, error_class='SecretError: do not persist this message',
            )
            row = conn.execute(
                'SELECT * FROM background_job_health WHERE job_id=?', ('J2',)
            ).fetchone()
            conn.commit()
            conn.close()

        self.assertEqual(row['state'], 'failed')
        self.assertEqual(row['last_started_ts'], 100)
        self.assertEqual(row['last_finished_ts'], 102)
        self.assertEqual(row['last_success_ts'], 101)
        self.assertEqual(row['error_class'], 'SecretError')

    def test_callback_outcome_false_and_exception_never_claim_success(self):
        now = 100
        lease = queues.acquire_worker_lease(
            self.db_path, 'job-health-worker', now=now, lease_seconds=30,
        )
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: now)

        def services_for(result):
            return SimpleNamespace(
                settings=SimpleNamespace(db_path=self.db_path),
                authority=authority,
                clock=lambda: now,
                admission=worker_main.WorkerAdmission(),
                collect_system_stats=lambda _authority: (
                    (_ for _ in ()).throw(result)
                    if isinstance(result, BaseException) else result
                ),
            )

        self.assertFalse(worker_main.dispatch_callback(services_for(False), 'J2'))
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            false_row = conn.execute(
                'SELECT state,last_success_ts,error_class FROM background_job_health WHERE job_id=?',
                ('J2',),
            ).fetchone()
            conn.close()
        self.assertEqual(tuple(false_row), ('failed', None, 'CallbackReturnedFalse'))

        class DeliberateFailure(RuntimeError):
            pass

        with self.assertRaises(DeliberateFailure):
            worker_main.dispatch_callback(services_for(DeliberateFailure('secret message')), 'J2')
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            exception_row = conn.execute(
                'SELECT state,last_success_ts,error_class FROM background_job_health WHERE job_id=?',
                ('J2',),
            ).fetchone()
            conn.close()
        self.assertEqual(tuple(exception_row), ('failed', None, 'DeliberateFailure'))

    def test_a_succeeded_callback_never_records_durable_failed_evidence(self):
        """Gap B: a failed bookkeeping write must never become a verdict on the work."""
        now = 100
        lease = queues.acquire_worker_lease(
            self.db_path, 'job-health-bookkeeping', now=now, lease_seconds=30,
        )
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: now)
        services = SimpleNamespace(
            settings=SimpleNamespace(db_path=self.db_path),
            authority=authority,
            clock=lambda: now,
            admission=worker_main.WorkerAdmission(),
            collect_system_stats=lambda _authority: True,
        )

        real_write = worker_main._write_job_health_transition
        recorded = []

        def recording_write(write_services, callback_id, transition, *, error_class=None):
            recorded.append((transition, error_class))
            if transition == 'succeeded':
                raise sqlite3.OperationalError('database is locked')
            return real_write(
                write_services, callback_id, transition, error_class=error_class,
            )

        worker_main._write_job_health_transition = recording_write
        self.addCleanup(
            setattr, worker_main, '_write_job_health_transition', real_write,
        )

        with self.assertRaises(worker_main.JobHealthBookkeepingError) as raised:
            worker_main.dispatch_callback(services, 'J2')

        # The work returned, so no failure transition may have been attempted at all.
        self.assertEqual([transition for transition, _ in recorded], ['started', 'succeeded'])

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                'SELECT state,error_class FROM background_job_health WHERE job_id=?',
                ('J2',),
            ).fetchone()
            conn.close()
        self.assertNotEqual(row['state'], 'failed')
        self.assertIsNone(row['error_class'])

        diagnosis = self.appmod.beacon_diagnosis
        payload = diagnosis.get_current_diagnosis(self.db_path, self.appmod.SETTINGS, now)
        self.assertEqual(
            [
                item for item in payload['exceptions']
                if item['kind'] == 'job_failed' and item.get('job_id') == 'J2'
            ],
            [],
        )

        message = str(raised.exception)
        self.assertIn('J2', message)
        self.assertIn('OperationalError', message)
        self.assertNotIn('database is locked', message)
        self.assertIsInstance(raised.exception.__cause__, sqlite3.OperationalError)

    def _job_health_row(self, job_id):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                'SELECT state,last_success_ts,error_class FROM background_job_health '
                'WHERE job_id=?',
                (job_id,),
            ).fetchone()
            conn.close()
        return row

    def test_outcome_paths_survive_the_bookkeeping_split(self):
        """The three outcomes that were already correct must not have moved."""
        # The lease-loss subtest below reaches stop_worker, which reads the worker
        # scheduler module global.  Own the reset here rather than depending on
        # another test module's teardown having run first.
        self.addCleanup(self._reset_worker_globals)
        now = 100
        lease = queues.acquire_worker_lease(
            self.db_path, 'job-health-outcomes', now=now, lease_seconds=30,
        )
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: now)

        class DeliberateOutcomeFailure(RuntimeError):
            pass

        def services_with(admission, **operations):
            return SimpleNamespace(
                settings=SimpleNamespace(db_path=self.db_path),
                authority=authority,
                clock=lambda: now,
                admission=admission,
                **operations,
            )

        def raiser(error):
            return lambda _authority: (_ for _ in ()).throw(error)

        admission = worker_main.WorkerAdmission()
        services = services_with(
            admission,
            collect_system_stats=lambda _authority: False,
            cleanup_history=raiser(DeliberateOutcomeFailure('secret message')),
            process_preview_requests=lambda _authority: True,
        )

        with self.subTest(outcome='returned_false'):
            self.assertFalse(worker_main.dispatch_callback(services, 'J2'))
            self.assertEqual(
                tuple(self._job_health_row('J2')),
                ('failed', None, 'CallbackReturnedFalse'),
            )

        with self.subTest(outcome='raised'):
            with self.assertRaises(DeliberateOutcomeFailure):
                worker_main.dispatch_callback(services, 'J8')
            self.assertEqual(
                tuple(self._job_health_row('J8')),
                ('failed', None, 'DeliberateOutcomeFailure'),
            )

        with self.subTest(outcome='succeeded'):
            self.assertTrue(worker_main.dispatch_callback(services, 'J6'))
            self.assertEqual(
                tuple(self._job_health_row('J6')), ('succeeded', now, None),
            )

        with self.subTest(outcome='lease_lost'):
            lease_admission = worker_main.WorkerAdmission()
            lease_services = services_with(
                lease_admission,
                process_scan_requests=raiser(queues.LeaseLost('lost')),
            )

            self.assertFalse(worker_main.dispatch_callback(lease_services, 'J5'))

            row = self._job_health_row('J5')
            self.assertNotEqual(row['state'], 'failed')
            self.assertIsNone(row['error_class'])
            self.assertIsNone(row['last_success_ts'])
            with lease_admission.admit('scheduled') as admitted:
                self.assertFalse(admitted, 'lease loss must leave admission closed')

    def test_a_failed_callback_survives_a_failing_outcome_write(self):
        """B5: a work failure and the failure to record it must both be reported."""
        now = 100
        lease = queues.acquire_worker_lease(
            self.db_path, 'job-health-compound', now=now, lease_seconds=30,
        )
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: now)

        class WorkBlewUp(RuntimeError):
            pass

        work_message = 'the real cause nobody was told about'
        write_message = 'database is locked'

        def services_for(outcome):
            def operation(_authority):
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

            return SimpleNamespace(
                settings=SimpleNamespace(db_path=self.db_path),
                authority=authority,
                clock=lambda: now,
                admission=worker_main.WorkerAdmission(),
                collect_system_stats=operation,
                process_preview_requests=operation,
            )

        real_write = worker_main._write_job_health_transition
        recorded = []

        def recorder_failing_on(blocked_transition):
            def recording_write(write_services, callback_id, transition, *, error_class=None):
                recorded.append((transition, error_class))
                if transition == blocked_transition:
                    raise sqlite3.OperationalError(write_message)
                return real_write(
                    write_services, callback_id, transition, error_class=error_class,
                )

            return recording_write

        self.addCleanup(
            setattr, worker_main, '_write_job_health_transition', real_write,
        )

        def reachable(error):
            """Every exception the raised condition's own chain still reaches."""
            found, pending, seen = [], [error], set()
            while pending:
                current = pending.pop()
                if current is None or id(current) in seen:
                    continue
                seen.add(id(current))
                found.append(current)
                pending.extend([current.__cause__, current.__context__])
            return found

        worker_main._write_job_health_transition = recorder_failing_on('failed')
        with self.assertLogs('beacon.worker', level='ERROR') as captured:
            with self.assertRaises(worker_main.JobHealthBookkeepingError) as raised:
                worker_main.dispatch_callback(services_for(WorkBlewUp(work_message)), 'J2')

        condition = raised.exception

        # Channel 1: the condition carries the work's own bounded class.
        self.assertEqual(condition.work_error_class, 'WorkBlewUp')
        self.assertEqual(condition.error_class, 'OperationalError')

        # Channel 2: the object graph, not the message string, still reaches both.
        self.assertIsInstance(condition.__cause__, WorkBlewUp)
        chain = reachable(condition)
        self.assertTrue(
            any(isinstance(link, WorkBlewUp) for link in chain),
            'the work failure must stay reachable through the raised chain',
        )
        self.assertTrue(
            any(isinstance(link, sqlite3.OperationalError) for link in chain),
            'the bookkeeping failure must stay reachable through the raised chain',
        )

        message = str(condition)
        self.assertIn('J2', message)
        self.assertIn('WorkBlewUp', message)
        self.assertIn('OperationalError', message)
        self.assertNotIn(work_message, message)
        self.assertNotIn(write_message, message)

        # Channel 3: the container log states the work failure before the raise.
        work_records = [
            record.getMessage() for record in captured.records
            if record.levelno == logging.ERROR and 'WorkBlewUp' in record.getMessage()
        ]
        self.assertTrue(
            work_records, 'the work failure must be logged at error level',
        )
        for text in work_records:
            self.assertNotIn(work_message, text)
            self.assertNotIn(write_message, text)

        self.assertEqual([transition for transition, _ in recorded], ['started', 'failed'])

        # The false positive 03-12 closed stays closed: no durable verdict either way.
        row = self._job_health_row('J2')
        self.assertNotEqual(row['state'], 'failed')
        self.assertNotEqual(row['state'], 'succeeded')

        with self.subTest(case='work_returned_and_outcome_write_failed'):
            recorded.clear()
            worker_main._write_job_health_transition = recorder_failing_on('succeeded')
            with self.assertRaises(worker_main.JobHealthBookkeepingError) as control:
                worker_main.dispatch_callback(services_for(True), 'J6')

            self.assertIsNone(control.exception.work_error_class)
            self.assertEqual(control.exception.error_class, 'OperationalError')
            self.assertNotIn('work_error_class', str(control.exception))
            self.assertEqual(
                [transition for transition, _ in recorded], ['started', 'succeeded'],
            )
            control_row = self._job_health_row('J6')
            self.assertNotEqual(control_row['state'], 'failed')
            self.assertNotEqual(control_row['state'], 'succeeded')

    def _reset_worker_globals(self):
        """Own the worker module globals this module's tests touch."""
        worker_main.scheduler = None
        worker_main._worker_started = False
        worker_main._active_services = None
        worker_main._active_worker_id = None

    def test_startup_survives_a_bookkeeping_failure(self):
        """A failure to record that a startup job began must not stop Beacon running."""
        self.addCleanup(self._reset_worker_globals)
        calls = []

        operations = worker_main.WorkerOperations(
            prepare_database=lambda _settings: calls.append('prepare'),
            recover_worker_state=lambda _authority: calls.append('recover'),
            update_worker_heartbeat=lambda _authority: calls.append('heartbeat'),
            collect_system_stats=lambda _authority: calls.append('metrics'),
            read_scan_state=lambda: {},
            run_discovery=lambda _authority, **_kwargs: None,
            do_uptime_check=lambda _authority, **_kwargs: None,
            process_scan_requests=lambda _authority: None,
            process_preview_requests=lambda _authority: None,
            cleanup_history=lambda _authority: None,
            shutdown_browser=lambda: calls.append('shutdown_browser'),
            acquire_worker_lease=queues.acquire_worker_lease,
            renew_worker_lease=queues.renew_worker_authority,
            release_worker_lease=queues.release_worker_authority,
        )

        real_write = worker_main._write_job_health_transition
        attempted = []

        def recording_write(write_services, callback_id, transition, *, error_class=None):
            attempted.append((callback_id, transition))
            if callback_id == 'S1':
                raise sqlite3.OperationalError('database is locked')
            return real_write(
                write_services, callback_id, transition, error_class=error_class,
            )

        worker_main._write_job_health_transition = recording_write
        self.addCleanup(
            setattr, worker_main, '_write_job_health_transition', real_write,
        )

        observed = {}

        class FakeScheduler:
            def start(inner_self):
                observed['worker_started'] = worker_main._worker_started
                observed['worker_id'] = worker_main._active_worker_id

            def shutdown(inner_self, wait=False):
                observed['shutdown'] = True

        with (
            mock.patch.object(worker_main, 'build_scheduler', return_value=FakeScheduler()),
            mock.patch.object(worker_main.signal, 'signal'),
        ):
            with self.assertLogs('beacon.worker', level='WARNING') as captured:
                worker_main.run_worker(
                    operations, SimpleNamespace(db_path=self.db_path),
                )

        # The named condition was decided about, not allowed to escape run_worker.
        warnings = [
            record.getMessage() for record in captured.records
            if record.levelno == logging.WARNING and 'S1' in record.getMessage()
        ]
        self.assertTrue(
            warnings, 'the bookkeeping condition must be logged with its callback',
        )
        for text in warnings:
            self.assertIn('OperationalError', text)
            self.assertNotIn('database is locked', text)

        # Startup proceeded past the failing dispatch: the later startup jobs ran
        # and the scheduler was built and started with a real epoch.
        self.assertEqual(('S1', 'started'), attempted[0])
        self.assertIn('heartbeat', calls)
        self.assertIn('metrics', calls)
        self.assertTrue(observed.get('worker_started'))
        self.assertIsNotNone(observed.get('worker_id'))
        # S1's own work is skipped, exactly as a failed started write requires.
        self.assertNotIn('recover', calls)

    def test_stale_worker_cannot_change_job_health_evidence(self):
        now = 100
        lease_a = queues.acquire_worker_lease(
            self.db_path, 'job-health-worker-a', now=now, lease_seconds=1,
        )
        authority_a = WorkerAuthority.from_lease(lease_a, self.db_path, clock=lambda: now)
        with self.assertRaises(queues.LeaseLost):
            worker_main._write_job_health_transition(
                SimpleNamespace(
                    settings=SimpleNamespace(db_path=self.db_path),
                    authority=authority_a,
                    clock=lambda: now + 2,
                ),
                'J2', 'started',
            )

        lease_b = queues.acquire_worker_lease(
            self.db_path, 'job-health-worker-b', now=now + 2, lease_seconds=30,
        )
        authority_b = WorkerAuthority.from_lease(lease_b, self.db_path, clock=lambda: now + 2)
        worker_main._write_job_health_transition(
            SimpleNamespace(
                settings=SimpleNamespace(db_path=self.db_path),
                authority=authority_b,
                clock=lambda: now + 2,
            ),
            'J2', 'succeeded',
        )
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = conn.execute(
                'SELECT state,last_success_ts FROM background_job_health WHERE job_id=?', ('J2',),
            ).fetchone()
            conn.close()
        self.assertEqual(tuple(row), ('succeeded', now + 2))

    def test_services_pipeline_and_settings_are_present_in_one_current_snapshot(self):
        now = 1_700_000_000
        self._seed_host(sample_ts=now)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,last_error,state_since) '
                'VALUES(?,?,?,?,?,?,?,?)',
                (8080, 'Service', now - 20, now, 0, None, 'ConnectionRefused', now - 10),
            )
            conn.execute(
                'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,healthy_statuses) '
                'VALUES(?,?,?,?,?,?,?)',
                (8080, 'Beacon service', 'http://127.0.0.1:8080', 1, 3, 'core,lan', '200-399'),
            )
            conn.execute(
                'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) VALUES(?,?,?,?,?)',
                (now, 8080, 0, None, 'ConnectionRefused'),
            )
            conn.commit()
            conn.close()
        self._freeze_clock(now)

        payload = self.client.get('/api/advanced/current').get_json()

        self.assertEqual(payload['services'][0]['port'], 8080)
        self.assertEqual(payload['services'][0]['name'], 'Beacon service')
        self.assertEqual(payload['services'][0]['availability'], 'offline')
        self.assertTrue(payload['services'][0]['critical'])
        self.assertEqual(payload['services'][0]['freshness']['state'], 'fresh')
        self.assertIn('retention', payload['pipeline'])
        self.assertIn('worker', payload['pipeline'])
        self.assertIn('jobs', payload['pipeline'])
        self.assertNotIn('alert_webhook_url', payload['settings'])
        self.assertTrue(any(item['kind'] == 'critical_service_offline' for item in payload['exceptions']))

    def test_service_cadence_uses_down_recheck_only_for_definitive_offline_state(self):
        now = 1_700_000_000
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for port, online in ((8100, None), (8101, 1), (8102, 0)):
                conn.execute(
                    'INSERT INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,last_error,state_since) '
                    'VALUES(?,?,?,?,?,?,?,?)',
                    (port, f'Service {port}', now - 20, now, online, None, None, now - 10),
                )
                conn.execute(
                    'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,healthy_statuses) '
                    'VALUES(?,?,?,?,?,?,?)',
                    (port, f'Service {port}', f'http://127.0.0.1:{port}', 0, port, '', '200-399'),
                )
                if online is not None:
                    conn.execute(
                        'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) VALUES(?,?,?,?,?)',
                        (now, port, online, None, None),
                    )
            conn.commit()
            conn.close()
        self._freeze_clock(now)

        services = {service['port']: service for service in self.client.get('/api/advanced/current').get_json()['services']}

        self.assertEqual(services[8100]['availability'], 'unknown')
        self.assertEqual(services[8100]['expected_cadence_seconds'], 300)
        self.assertEqual(services[8100]['freshness'], {'state': 'unknown', 'age_seconds': None})
        self.assertEqual(services[8101]['expected_cadence_seconds'], 300)
        self.assertEqual(services[8102]['expected_cadence_seconds'], 60)

    def test_pinned_order_corruption_is_safe_and_get_only(self):
        now = 1_700_000_000
        fixtures = (
            (8200, 0, 0),
            (8201, 65535, 65535),
            (8202, None, 8202),
            (8203, 65536, 8203),
            (8204, 'not-an-order', 8204),
        )
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for port, pinned_order, _expected in fixtures:
                conn.execute(
                    'INSERT INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,last_error,state_since) '
                    'VALUES(?,?,?,?,?,?,?,?)',
                    (port, f'Service {port}', now - 20, now, 1, 1.0, None, now - 10),
                )
                conn.execute(
                    'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,healthy_statuses) '
                    'VALUES(?,?,?,?,?,?,?)',
                    (port, f'Service {port}', f'http://127.0.0.1:{port}', 0, pinned_order, '', '200-399'),
                )
                conn.execute(
                    'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) VALUES(?,?,?,?,?)',
                    (now, port, 1, 1.0, None),
                )
            before = [tuple(row) for row in conn.execute(
                'SELECT port,pinned_order,typeof(pinned_order) FROM service_meta ORDER BY port'
            )]
            conn.commit()
            conn.close()
        self._freeze_clock(now)

        response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 200)
        services = {service['port']: service for service in response.get_json()['services']}
        self.assertEqual(
            {port: services[port]['pinned_order'] for port, _value, _expected in fixtures},
            {port: expected for port, _value, expected in fixtures},
        )
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            after = [tuple(row) for row in conn.execute(
                'SELECT port,pinned_order,typeof(pinned_order) FROM service_meta ORDER BY port'
            )]
            conn.close()
        self.assertEqual(after, before)
        safe_pinned_order = self.appmod.beacon_diagnosis._safe_pinned_order
        for value in (True, False, -1, 65536, '12', 'bad'):
            with self.subTest(value=value):
                self.assertEqual(safe_pinned_order(value, 8205), 8205)

    def test_gap_truncation_uses_one_sentinel_beyond_the_response_cap(self):
        now = 1_700_000_000
        self._freeze_clock(now)
        for count in (0, 1, 48, 49):
            with self.subTest(count=count):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM telemetry_coverage')
                    conn.executemany(
                        'INSERT INTO telemetry_coverage(stream_kind,stream_key,start_ts,end_ts,reason,detail) '
                        'VALUES(?,?,?,?,?,?)',
                        [
                            ('host', 'cpu', now - 1_000 - index, now - index, 'collection_gap', f'gap-{index}')
                            for index in range(count)
                        ],
                    )
                    conn.commit()
                    conn.close()

                gaps = self.client.get('/api/advanced/current').get_json()['pipeline']['gaps']

                self.assertEqual(len(gaps['items']), min(count, 48))
                self.assertEqual(gaps['count'], min(count, 48))
                self.assertEqual(gaps['truncated'], count > 48)
                self.assertEqual(
                    [item['detail'] for item in gaps['items']],
                    [f'gap-{index}' for index in range(min(count, 48))],
                )

    def _seed_stream(
        self, conn, stream_kind, stream_key, *, now,
        cadence=60, open_gap_start_ts=None, last_observed_ts=None,
    ):
        """Seed one durable telemetry stream row without inventing coverage evidence."""
        conn.execute(
            'INSERT INTO telemetry_streams('
            'stream_kind,stream_key,started_ts,cadence_seconds,last_observed_ts,'
            'consecutive_misses,open_gap_start_ts) VALUES(?,?,?,?,?,?,?)',
            (
                stream_kind, stream_key, now - 10_000, cadence,
                now if last_observed_ts is None else last_observed_ts,
                0 if open_gap_start_ts is None else 2,
                open_gap_start_ts,
            ),
        )

    def test_open_stream_gap_is_synthesized_merged_and_promoted(self):
        """An active stream gap is durable evidence even with zero coverage rows."""
        now = 1_700_000_000
        self._freeze_clock(now)
        cases = (
            ('open_gap_without_any_coverage_row', now - 100, ()),
            ('no_open_gap_and_no_coverage_row', None, ()),
            (
                'open_gap_merged_with_closed_historical_coverage',
                now - 100,
                ((now - 5_000, now - 4_000, 'collection_gap', 'historical-gap'),),
            ),
        )
        for label, open_gap_start_ts, coverage in cases:
            with self.subTest(case=label):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM telemetry_streams')
                    conn.execute('DELETE FROM telemetry_coverage')
                    self._seed_stream(
                        conn, 'host', 'cpu', now=now, open_gap_start_ts=open_gap_start_ts,
                    )
                    conn.executemany(
                        'INSERT INTO telemetry_coverage('
                        'stream_kind,stream_key,start_ts,end_ts,reason,detail) '
                        'VALUES(?,?,?,?,?,?)',
                        [('host', 'cpu', *row) for row in coverage],
                    )
                    conn.commit()
                    conn.close()

                payload = self.client.get('/api/advanced/current').get_json()
                gaps = payload['pipeline']['gaps']
                collection_gaps = [
                    item for item in payload['exceptions'] if item['kind'] == 'collection_gap'
                ]

                if open_gap_start_ts is None:
                    self.assertEqual(gaps['items'], [])
                    self.assertEqual(gaps['count'], 0)
                    self.assertEqual(collection_gaps, [])
                    continue

                synthesized = [item for item in gaps['items'] if item['start_ts'] == now - 100]
                self.assertEqual(len(synthesized), 1)
                self.assertEqual(
                    synthesized[0],
                    {
                        'stream_kind': 'host', 'stream_key': 'cpu',
                        'start_ts': now - 100, 'end_ts': now,
                        'reason': 'collection_gap', 'detail': None,
                        'open': True, 'actionable': True,
                    },
                )
                self.assertEqual(len(gaps['items']), 1 + len(coverage))
                self.assertEqual(gaps['count'], 1 + len(coverage))
                self.assertEqual(gaps['items'][0]['start_ts'], now - 100)
                self.assertEqual(len(collection_gaps), 1)
                self.assertTrue(any(
                    item['start_ts'] == now - 100 and item['open'] and item['actionable']
                    for item in collection_gaps
                ))
                for start_ts, end_ts, reason, detail in coverage:
                    historical = [
                        item for item in gaps['items'] if item['detail'] == detail
                    ]
                    self.assertEqual(len(historical), 1)
                    self.assertEqual(
                        (
                            historical[0]['start_ts'], historical[0]['end_ts'],
                            historical[0]['reason'], historical[0]['detail'],
                            historical[0]['open'], historical[0]['actionable'],
                        ),
                        (start_ts, end_ts, reason, detail, False, False),
                    )

    def test_open_stream_gap_is_reported_per_stream_without_borrowing_evidence(self):
        """Only the stream that actually carries an open gap gets a synthesized item."""
        now = 1_700_000_000
        self._freeze_clock(now)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute('DELETE FROM telemetry_streams')
            conn.execute('DELETE FROM telemetry_coverage')
            self._seed_stream(conn, 'host', 'cpu', now=now, open_gap_start_ts=now - 300)
            self._seed_stream(conn, 'host', 'ram', now=now, open_gap_start_ts=None)
            conn.commit()
            conn.close()

        payload = self.client.get('/api/advanced/current').get_json()
        gaps = payload['pipeline']['gaps']

        self.assertEqual(
            [(item['stream_kind'], item['stream_key']) for item in gaps['items']],
            [('host', 'cpu')],
        )
        self.assertEqual(gaps['count'], 1)
        self.assertFalse(gaps['truncated'])
        self.assertEqual(
            [item['stream_key'] for item in payload['exceptions'] if item['kind'] == 'collection_gap'],
            ['cpu'],
        )

    def test_persisted_coverage_rows_are_never_open_regardless_of_stream_state(self):
        """A persisted coverage row is a closed interval; a stream-level open gap is not its own."""
        now = 1_700_000_000
        self._freeze_clock(now)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute('DELETE FROM telemetry_streams')
            conn.execute('DELETE FROM telemetry_coverage')
            self._seed_stream(conn, 'host', 'cpu', now=now, open_gap_start_ts=now - 100)
            conn.executemany(
                'INSERT INTO telemetry_coverage('
                'stream_kind,stream_key,start_ts,end_ts,reason,detail) VALUES(?,?,?,?,?,?)',
                [
                    (
                        'host', 'cpu', now - 30 * 86_400 - 600, now - 30 * 86_400,
                        'collection_gap', 'resolved-30-days-ago',
                    ),
                    (
                        'host', 'cpu', now - 40 * 86_400 - 600, now - 40 * 86_400,
                        'expired', 'retention-expired',
                    ),
                ],
            )
            conn.commit()
            conn.close()

        payload = self.client.get('/api/advanced/current').get_json()
        gaps = payload['pipeline']['gaps']

        self.assertEqual(gaps['count'], 3)
        self.assertEqual(len(gaps['items']), 3)
        open_items = [item for item in gaps['items'] if item['open']]
        self.assertEqual(len(open_items), 1)
        self.assertEqual(open_items[0]['start_ts'], now - 100)
        self.assertTrue(open_items[0]['actionable'])
        historical = {
            item['detail']: item for item in gaps['items'] if item['detail'] is not None
        }
        self.assertEqual(
            sorted(historical), ['resolved-30-days-ago', 'retention-expired'],
        )
        for detail, item in historical.items():
            with self.subTest(detail=detail):
                self.assertFalse(item['open'])
                self.assertFalse(item['actionable'])
        collection_gaps = [
            item for item in payload['exceptions'] if item['kind'] == 'collection_gap'
        ]
        self.assertEqual(len(collection_gaps), 1)
        self.assertEqual(collection_gaps[0]['start_ts'], now - 100)

    def test_persisted_coverage_actionability_boundary_is_the_recent_window(self):
        """A coverage row exactly on the recent-window edge is actionable; one second older is not."""
        now = 1_700_000_000
        self._freeze_clock(now)
        recent_window = 3_600
        cases = (
            ('exactly_on_the_recent_window_boundary', now - recent_window, True),
            ('one_second_beyond_the_recent_window', now - recent_window - 1, False),
        )
        for label, end_ts, expected_actionable in cases:
            with self.subTest(case=label):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM telemetry_streams')
                    conn.execute('DELETE FROM telemetry_coverage')
                    self._seed_stream(conn, 'host', 'cpu', now=now, cadence=60)
                    conn.execute(
                        'INSERT INTO telemetry_coverage('
                        'stream_kind,stream_key,start_ts,end_ts,reason,detail) '
                        'VALUES(?,?,?,?,?,?)',
                        ('host', 'cpu', end_ts - 600, end_ts, 'collection_gap', 'boundary'),
                    )
                    conn.commit()
                    conn.close()

                gaps = self.client.get('/api/advanced/current').get_json()['pipeline']['gaps']

                self.assertEqual(len(gaps['items']), 1)
                self.assertFalse(gaps['items'][0]['open'])
                self.assertEqual(gaps['items'][0]['actionable'], expected_actionable)

    def test_coverage_reason_maps_to_its_own_exception_kind(self):
        """Each durable coverage reason promotes as itself, or as lifecycle evidence not at all."""
        now = 1_700_000_000
        self._freeze_clock(now)
        cases = (
            ('collection_gap', 'collection_gap', True),
            ('unknown', 'coverage_unknown', True),
            ('expired', None, False),
            ('not_yet_monitored', None, False),
        )
        for reason, expected_kind, expected_actionable in cases:
            with self.subTest(reason=reason):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM telemetry_streams')
                    conn.execute('DELETE FROM telemetry_coverage')
                    self._seed_stream(conn, 'host', 'cpu', now=now, cadence=60)
                    conn.execute(
                        'INSERT INTO telemetry_coverage('
                        'stream_kind,stream_key,start_ts,end_ts,reason,detail) '
                        'VALUES(?,?,?,?,?,?)',
                        ('host', 'cpu', now - 700, now - 100, reason, 'recent-interval'),
                    )
                    conn.commit()
                    conn.close()

                payload = self.client.get('/api/advanced/current').get_json()
                gaps = payload['pipeline']['gaps']
                pipeline_exceptions = [
                    item for item in payload['exceptions'] if item['section'] == 'pipeline'
                    and item['kind'] in {'collection_gap', 'coverage_unknown'}
                ]

                self.assertEqual(len(gaps['items']), 1)
                self.assertEqual(gaps['items'][0]['reason'], reason)
                self.assertFalse(gaps['items'][0]['open'])
                self.assertEqual(gaps['items'][0]['actionable'], expected_actionable)
                if expected_kind is None:
                    self.assertEqual(pipeline_exceptions, [])
                    continue
                self.assertEqual(len(pipeline_exceptions), 1)
                self.assertEqual(pipeline_exceptions[0]['kind'], expected_kind)
                self.assertEqual(pipeline_exceptions[0]['reason'], reason)

    def test_coverage_reason_outside_the_durable_enum_surfaces_as_indeterminate(self):
        """An unrecognised reason must never be dropped nor reported as a collection failure."""
        diagnosis = self.appmod.beacon_diagnosis
        unmapped = 'schema_skew_reason'

        self.assertEqual(diagnosis.gap_exception_kind(unmapped), 'coverage_unknown')
        self.assertEqual(diagnosis.gap_exception_kind('collection_gap'), 'collection_gap')
        self.assertEqual(diagnosis.gap_exception_kind('unknown'), 'coverage_unknown')
        self.assertIsNone(diagnosis.gap_exception_kind('expired'))
        self.assertIsNone(diagnosis.gap_exception_kind('not_yet_monitored'))

        pipeline = {
            'worker': {'freshness': {'state': 'fresh', 'age_seconds': 1}},
            'gaps': {
                'items': [{
                    'stream_kind': 'host', 'stream_key': 'cpu',
                    'start_ts': 1_699_999_400, 'end_ts': 1_699_999_900,
                    'reason': unmapped, 'detail': None,
                    'open': False, 'actionable': True,
                }],
                'count': 1, 'truncated': False,
            },
            'jobs': [],
            'database_pressure': {'state': 'normal'},
        }
        host = {'freshness': {'state': 'fresh', 'age_seconds': 1}}

        exceptions = diagnosis.compose_active_exceptions(
            host, [], pipeline, recovery_required=False, now=1_700_000_000,
        )

        self.assertEqual(len(exceptions), 1)
        self.assertEqual(exceptions[0]['kind'], 'coverage_unknown')
        self.assertEqual(exceptions[0]['reason'], unmapped)

    def _jobs_pipeline(self, job):
        """One pipeline shape carrying exactly one durable job row."""
        return {
            'worker': {'freshness': {'state': 'fresh', 'age_seconds': 1}},
            'gaps': {'items': [], 'count': 0, 'truncated': False},
            'jobs': [job],
            'database_pressure': {'state': 'normal'},
        }

    def test_a_job_stuck_without_an_outcome_becomes_an_operator_exception(self):
        """A job that started and was never recorded finishing must be actionable."""
        diagnosis = self.appmod.beacon_diagnosis
        host = {'freshness': {'state': 'fresh', 'age_seconds': 1}}
        now = 1_700_000_000
        cadence = 60

        def compose(job):
            return diagnosis.compose_active_exceptions(
                host, [], self._jobs_pipeline(job), recovery_required=False, now=now,
            )

        def job_row(**overrides):
            row = {
                'job_id': 'J2',
                'state': 'running',
                'last_started_ts': now - 5 * cadence,
                'cadence_seconds': cadence,
            }
            row.update(overrides)
            return row

        with self.subTest(case='overdue_running_job_promotes_once'):
            exceptions = compose(job_row())
            unrecorded = [
                item for item in exceptions
                if item['kind'] == 'job_outcome_unrecorded'
            ]
            self.assertEqual(len(unrecorded), 1)
            self.assertEqual(unrecorded[0]['job_id'], 'J2')
            self.assertEqual(unrecorded[0]['section'], 'pipeline')
            self.assertEqual(
                [item for item in exceptions if item['kind'] == 'job_failed'], [],
            )

        with self.subTest(case='running_inside_its_cadence_window_promotes_nothing'):
            self.assertEqual(compose(job_row(last_started_ts=now - cadence)), [])

        with self.subTest(case='unknown_state_promotes_nothing'):
            self.assertEqual(
                compose(job_row(state='unknown', last_started_ts=None)), [],
            )

        with self.subTest(case='absent_cadence_promotes_nothing'):
            self.assertEqual(compose(job_row(cadence_seconds=None)), [])

        with self.subTest(case='non_integer_start_promotes_nothing'):
            self.assertEqual(compose(job_row(last_started_ts=None)), [])

        with self.subTest(case='failed_job_still_promotes_only_the_failed_kind'):
            exceptions = compose(job_row(state='failed'))
            self.assertEqual([item['kind'] for item in exceptions], ['job_failed'])
            self.assertEqual(exceptions[0]['job_id'], 'J2')

    def _reset_gap_evidence(self, conn):
        conn.execute('DELETE FROM telemetry_streams')
        conn.execute('DELETE FROM telemetry_coverage')

    def test_gap_count_and_truncated_describe_the_same_population(self):
        """The gaps disclosure must never claim a completeness or an incompleteness it lacks."""
        now = 1_700_000_000
        self._freeze_clock(now)
        gap_limit = 48

        with self.subTest(case='no_streams_and_no_coverage'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                conn.commit()
                conn.close()

            gaps = self.client.get('/api/advanced/current').get_json()['pipeline']['gaps']

            self.assertEqual(gaps, {'items': [], 'count': 0, 'truncated': False})

        with self.subTest(case='sixty_five_open_gap_streams_and_no_coverage'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                for index in range(65):
                    self._seed_stream(
                        conn, 'host', f'stream-{index:02d}', now=now,
                        open_gap_start_ts=now - 100 - index,
                    )
                conn.commit()
                conn.close()

            payload = self.client.get('/api/advanced/current').get_json()
            gaps = payload['pipeline']['gaps']

            self.assertTrue(gaps['truncated'])
            self.assertLessEqual(gaps['count'], gap_limit)
            self.assertEqual(gaps['count'], len(gaps['items']))
            self.assertTrue(all(item['open'] for item in gaps['items']))

        with self.subTest(case='sixty_five_streams_with_only_two_open_gaps'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                for index in range(65):
                    self._seed_stream(
                        conn, 'host', f'stream-{index:02d}', now=now,
                        open_gap_start_ts=(now - 100 if index < 2 else None),
                    )
                conn.executemany(
                    'INSERT INTO telemetry_coverage('
                    'stream_kind,stream_key,start_ts,end_ts,reason,detail) '
                    'VALUES(?,?,?,?,?,?)',
                    [
                        ('host', 'stream-00', now - 1_000 - index, now - index,
                         'collection_gap', f'coverage-{index}')
                        for index in range(5)
                    ],
                )
                conn.commit()
                conn.close()

            pipeline = self.client.get('/api/advanced/current').get_json()['pipeline']

            self.assertEqual(pipeline['gaps']['count'], 7)
            self.assertEqual(len(pipeline['gaps']['items']), 7)
            self.assertFalse(pipeline['gaps']['truncated'])
            self.assertTrue(pipeline['streams']['truncated'])

        with self.subTest(case='sixty_four_open_gap_streams_and_sixty_coverage_rows'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                for index in range(64):
                    self._seed_stream(
                        conn, 'host', f'stream-{index:02d}', now=now,
                        open_gap_start_ts=now - 100 - index,
                    )
                conn.executemany(
                    'INSERT INTO telemetry_coverage('
                    'stream_kind,stream_key,start_ts,end_ts,reason,detail) '
                    'VALUES(?,?,?,?,?,?)',
                    [
                        ('host', 'stream-00', now - 1_000 - index, now - index,
                         'collection_gap', f'coverage-{index}')
                        for index in range(60)
                    ],
                )
                conn.commit()
                conn.close()

            gaps = self.client.get('/api/advanced/current').get_json()['pipeline']['gaps']

            self.assertLessEqual(gaps['count'], gap_limit)
            self.assertEqual(gaps['count'], len(gaps['items']))
            self.assertTrue(gaps['truncated'])
            self.assertTrue(all(item['open'] for item in gaps['items']))

    def test_gap_ordering_puts_open_and_actionable_evidence_first(self):
        """Open evidence outranks actionable history, which outranks resolved history."""
        now = 1_700_000_000
        self._freeze_clock(now)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            self._reset_gap_evidence(conn)
            self._seed_stream(
                conn, 'host', 'cpu', now=now, cadence=60, open_gap_start_ts=now - 100,
            )
            conn.executemany(
                'INSERT INTO telemetry_coverage('
                'stream_kind,stream_key,start_ts,end_ts,reason,detail) VALUES(?,?,?,?,?,?)',
                [
                    ('host', 'cpu', now - 800, now - 200, 'collection_gap', 'recent-a'),
                    ('host', 'cpu', now - 900, now - 300, 'collection_gap', 'recent-b'),
                    ('host', 'cpu', now - 100_600, now - 100_000, 'collection_gap', 'old-c'),
                ],
            )
            conn.commit()
            conn.close()

        gaps = self.client.get('/api/advanced/current').get_json()['pipeline']['gaps']

        self.assertEqual(gaps['count'], 4)
        self.assertFalse(gaps['truncated'])
        self.assertEqual(
            [item['detail'] for item in gaps['items']],
            [None, 'recent-a', 'recent-b', 'old-c'],
        )
        self.assertEqual(
            [(item['open'], item['actionable']) for item in gaps['items']],
            [(True, True), (False, True), (False, True), (False, False)],
        )

    def _seed_service(self, conn, port, *, now, online=1):
        """Seed one active service row so the composer emits it in the read model."""
        conn.execute(
            'INSERT INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,'
            'last_error,state_since) VALUES(?,?,?,?,?,?,?,?)',
            (port, f'Service {port}', now - 20, now, online, 1.0, None, now - 10),
        )
        conn.execute(
            'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,'
            'healthy_statuses) VALUES(?,?,?,?,?,?,?)',
            (port, f'Service {port}', f'http://127.0.0.1:{port}', 0, port, '', '200-399'),
        )
        conn.execute(
            'INSERT INTO service_checks(ts,port,online,latency_ms,error_class) VALUES(?,?,?,?,?)',
            (now, port, online, 1.0, None),
        )

    def _reset_service_evidence(self, conn):
        conn.execute('DELETE FROM service_checks')
        conn.execute('DELETE FROM service_meta')
        conn.execute('DELETE FROM services')

    def test_service_collection_gap_evidence_is_joined_and_discloses_its_completeness(self):
        """A service's gap evidence is joined from its own stream and states its completeness.

        Each of the four states is grounded in a durable read fact: the gap read's
        own truncation flag decides complete versus possibly incomplete for a
        matched stream, and the stream read's own truncation flag decides
        derivably absent versus not established for an unmatched one. The join
        must leave the top-level bounded gap projection -- the population whose
        count and truncation flag 03-08 made describe one population -- unchanged.
        """
        now = 1_700_000_000
        self._freeze_clock(now)

        with self.subTest(case='matched_stream_with_complete_gap_evidence'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                self._reset_service_evidence(conn)
                self._seed_service(conn, 8080, now=now)
                self._seed_stream(conn, 'service', '8080', now=now, open_gap_start_ts=now - 100)
                conn.execute(
                    'INSERT INTO telemetry_coverage('
                    'stream_kind,stream_key,start_ts,end_ts,reason,detail) VALUES(?,?,?,?,?,?)',
                    ('service', '8080', now - 800, now - 200, 'collection_gap', 'closed-a'),
                )
                conn.commit()
                conn.close()

            payload = self.client.get('/api/advanced/current').get_json()
            block = {row['port']: row for row in payload['services']}[8080]['collection_gaps']

            self.assertEqual(block['evidence'], 'complete')
            self.assertEqual(block['count'], 2)
            self.assertEqual(block['open_count'], 1)
            self.assertEqual(block['count'], len(block['items']))
            self.assertEqual(
                [(item['detail'], item['open']) for item in block['items']],
                [('closed-a', False), (None, True)],
            )
            self.assertEqual(
                {(item['stream_kind'], item['stream_key']) for item in block['items']},
                {('service', '8080')},
            )
            self.assertFalse(payload['pipeline']['streams']['truncated'])
            self.assertFalse(payload['pipeline']['streams']['gap_evidence_truncated'])
            # The join is additive: the bounded top-level projection is untouched.
            gaps = payload['pipeline']['gaps']
            self.assertEqual(gaps['count'], 2)
            self.assertEqual(gaps['count'], len(gaps['items']))
            self.assertFalse(gaps['truncated'])

        with self.subTest(case='matched_stream_with_truncated_gap_evidence'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                self._reset_service_evidence(conn)
                self._seed_service(conn, 8080, now=now)
                self._seed_stream(conn, 'service', '8080', now=now, open_gap_start_ts=now - 100)
                self._seed_stream(conn, 'host', 'cpu', now=now)
                conn.execute(
                    'INSERT INTO telemetry_coverage('
                    'stream_kind,stream_key,start_ts,end_ts,reason,detail) VALUES(?,?,?,?,?,?)',
                    ('service', '8080', now - 800, now - 200, 'collection_gap', 'closed-a'),
                )
                # Older host coverage pushes the durable gap read past its own cap
                # without displacing this service's newer row out of that read.
                conn.executemany(
                    'INSERT INTO telemetry_coverage('
                    'stream_kind,stream_key,start_ts,end_ts,reason,detail) VALUES(?,?,?,?,?,?)',
                    [
                        ('host', 'cpu', now - 100_000 - index * 10,
                         now - 99_000 - index * 10, 'collection_gap', f'host-{index:02d}')
                        for index in range(60)
                    ],
                )
                conn.commit()
                conn.close()

            payload = self.client.get('/api/advanced/current').get_json()
            block = {row['port']: row for row in payload['services']}[8080]['collection_gaps']

            self.assertEqual(block['evidence'], 'possibly_incomplete')
            self.assertEqual(block['count'], 2)
            self.assertEqual(block['open_count'], 1)
            self.assertEqual(
                [(item['detail'], item['open']) for item in block['items']],
                [('closed-a', False), (None, True)],
            )
            self.assertTrue(payload['pipeline']['streams']['gap_evidence_truncated'])
            self.assertFalse(payload['pipeline']['streams']['truncated'])
            gaps = payload['pipeline']['gaps']
            self.assertTrue(gaps['truncated'])
            self.assertEqual(gaps['count'], len(gaps['items']))
            self.assertLessEqual(gaps['count'], 48)

        with self.subTest(case='unmatched_stream_in_a_complete_stream_list'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                self._reset_service_evidence(conn)
                self._seed_service(conn, 8081, now=now)
                self._seed_stream(conn, 'host', 'cpu', now=now)
                conn.commit()
                conn.close()

            payload = self.client.get('/api/advanced/current').get_json()
            block = {row['port']: row for row in payload['services']}[8081]['collection_gaps']

            self.assertFalse(payload['pipeline']['streams']['truncated'])
            self.assertEqual(block['evidence'], 'absent')
            self.assertEqual(block['items'], [])
            self.assertEqual(block['count'], 0)
            self.assertEqual(block['open_count'], 0)

        with self.subTest(case='unmatched_stream_in_a_truncated_stream_list'):
            with self.appmod._db_lock:
                conn = self.appmod.get_db()
                self._reset_gap_evidence(conn)
                self._reset_service_evidence(conn)
                self._seed_service(conn, 8082, now=now)
                for index in range(65):
                    self._seed_stream(conn, 'host', f'stream-{index:02d}', now=now)
                conn.commit()
                conn.close()

            payload = self.client.get('/api/advanced/current').get_json()
            block = {row['port']: row for row in payload['services']}[8082]['collection_gaps']

            self.assertTrue(payload['pipeline']['streams']['truncated'])
            self.assertEqual(block['evidence'], 'not_established')
            self.assertEqual(block['items'], [])
            self.assertEqual(block['count'], 0)
            self.assertEqual(block['open_count'], 0)

    def test_service_gap_completeness_never_defaults_to_an_unestablished_absence(self):
        """A truncation flag that is missing or not a boolean resolves to not established.

        An absence the workspace never established must never be reported as a
        derived absence, so only a real ``False`` may produce the absent state.
        """
        attach = self.appmod.beacon_diagnosis.attach_service_collection_gaps

        unmatched_cases = (
            ({'items': [], 'count': 0, 'truncated': False}, 'absent'),
            ({'items': [], 'count': 0, 'truncated': True}, 'not_established'),
            ({'items': [], 'count': 0, 'truncated': None}, 'not_established'),
            ({'items': [], 'count': 0, 'truncated': 'no'}, 'not_established'),
            ({'items': [], 'count': 0}, 'not_established'),
        )
        for streams, expected in unmatched_cases:
            with self.subTest(unmatched=streams):
                services = [{'port': 8080}]
                attach(services, {'streams': dict(streams)})
                block = services[0]['collection_gaps']
                self.assertEqual(block['evidence'], expected)
                self.assertEqual(block, {
                    'items': [], 'count': 0, 'open_count': 0, 'evidence': expected,
                })

        matched_cases = (
            ({'truncated': False, 'gap_evidence_truncated': False}, 'complete'),
            ({'truncated': False, 'gap_evidence_truncated': True}, 'possibly_incomplete'),
            ({'truncated': False, 'gap_evidence_truncated': None}, 'not_established'),
            ({'truncated': False, 'gap_evidence_truncated': 'yes'}, 'not_established'),
            ({'truncated': False}, 'not_established'),
        )
        for flags, expected in matched_cases:
            with self.subTest(matched=flags):
                stream = {
                    'stream_kind': 'service', 'stream_key': '8080',
                    'gaps': [{'open': False}, {'open': True}],
                }
                streams = {'items': [stream], 'count': 1, **flags}
                services = [{'port': 8080}]
                attach(services, {'streams': streams})
                block = services[0]['collection_gaps']
                self.assertEqual(block['evidence'], expected)
                self.assertEqual(block['count'], 2)
                self.assertEqual(block['open_count'], 1)
                # The join copies the composed order and never reorders or filters.
                self.assertEqual(block['items'], stream['gaps'])

    def test_host_freshness_becomes_an_active_exception_when_evidence_is_not_fresh(self):
        """Missing or stale host evidence must never be summarised as normal."""
        now = 1_700_000_000
        self._freeze_clock(now)
        cases = (
            ('missing_system_stats_row', None, 'unknown'),
            ('stale_beyond_four_cadences', now - 21, 'stale'),
            ('fresh_within_one_cadence', now - 5, None),
        )
        for label, sample_ts, expected_state in cases:
            with self.subTest(case=label):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM system_stats')
                    conn.commit()
                    conn.close()
                if sample_ts is not None:
                    self._seed_host(sample_ts=sample_ts)

                payload = self.client.get('/api/advanced/current').get_json()
                host_exceptions = [
                    item for item in payload['exceptions'] if item['kind'] == 'host_freshness'
                ]

                if expected_state is None:
                    self.assertEqual(host_exceptions, [])
                    continue
                self.assertEqual(
                    host_exceptions,
                    [{
                        'kind': 'host_freshness', 'section': 'host',
                        'priority': 1, 'state': expected_state,
                    }],
                )
                self.assertEqual(payload['host']['freshness']['state'], expected_state)

    def test_pending_truncation_uses_one_sentinel_beyond_the_response_cap(self):
        """Pending aggregation must not claim truncation at exactly its cap."""
        now = 1_700_000_000
        self._freeze_clock(now)
        for count in (0, 31, 32, 33):
            with self.subTest(count=count):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM telemetry_rollup_jobs')
                    conn.executemany(
                        'INSERT INTO telemetry_rollup_jobs('
                        'stream_kind,stream_key,bucket_start,bucket_seconds,state,'
                        'attempt_count,next_retry_ts,last_error_class,updated_ts) '
                        'VALUES(?,?,?,?,?,?,?,?,?)',
                        [
                            ('host', 'cpu', now - 3600 * (index + 1), 3600, 'pending',
                             0, None, None, now - index)
                            for index in range(count)
                        ],
                    )
                    conn.commit()
                    conn.close()

                pending = self.client.get('/api/advanced/current').get_json()['pipeline']['aggregation_pending']

                self.assertEqual(len(pending['items']), min(count, 32))
                self.assertEqual(pending['count'], min(count, 32))
                self.assertEqual(pending['truncated'], count > 32)

    def test_stream_truncation_uses_a_sentinel_and_keeps_active_evidence(self):
        """Stream reads disclose truncation exactly at the cap and never drop an open gap."""
        now = 1_700_000_000
        self._freeze_clock(now)
        for count in (0, 64, 65):
            with self.subTest(count=count):
                with self.appmod._db_lock:
                    conn = self.appmod.get_db()
                    conn.execute('DELETE FROM telemetry_streams')
                    conn.execute('DELETE FROM telemetry_coverage')
                    for index in range(count):
                        self._seed_stream(
                            conn, 'host', f'stream-{index:02d}', now=now,
                            open_gap_start_ts=(now - 100 if index == count - 1 else None),
                        )
                    conn.commit()
                    conn.close()

                streams = self.client.get('/api/advanced/current').get_json()['pipeline']['streams']
                keys = [item['stream_key'] for item in streams['items']]

                self.assertEqual(len(keys), min(count, 64))
                self.assertEqual(streams['count'], min(count, 64))
                self.assertEqual(streams['truncated'], count > 64)
                if count:
                    self.assertIn(f'stream-{count - 1:02d}', keys)

    def test_stream_truncation_ranks_stale_evidence_ahead_of_quiet_streams(self):
        """A stale stream must survive the cap ahead of alphabetically earlier quiet ones."""
        now = 1_700_000_000
        self._freeze_clock(now)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute('DELETE FROM telemetry_streams')
            conn.execute('DELETE FROM telemetry_coverage')
            for index in range(65):
                self._seed_stream(
                    conn, 'host', f'stream-{index:02d}', now=now,
                    cadence=60,
                    last_observed_ts=(now - 1_000 if index == 64 else now),
                )
            conn.commit()
            conn.close()

        streams = self.client.get('/api/advanced/current').get_json()['pipeline']['streams']
        keys = [item['stream_key'] for item in streams['items']]

        self.assertTrue(streams['truncated'])
        self.assertEqual(len(keys), 64)
        self.assertEqual(keys[0], 'stream-64')
        self.assertEqual(
            [item['freshness']['state'] for item in streams['items'] if item['stream_key'] == 'stream-64'],
            ['stale'],
        )

    def test_advanced_snapshot_rejects_query_arguments_before_reading_sqlite(self):
        response = self.client.get('/api/advanced/current?unexpected=1')

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {'error': 'unexpected query parameters'})


    def test_maintenance_window_reaches_the_operator_as_a_named_cause(self):
        """A maintenance lease failure is parseable JSON naming its cause, not an HTML 500."""
        with mock.patch.object(
            self.appmod.beacon_diagnosis,
            'get_current_diagnosis',
            side_effect=self.appmod.MaintenanceBusy('database maintenance lease is busy'),
        ):
            response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 503)
        self.assertIn('application/json', response.content_type)
        payload = response.get_json()
        self.assertEqual(set(payload), {'error'})
        self.assertIn('maintenance', payload['error'].lower())
        self.assertNotIn('lease is busy', response.get_data(as_text=True))

    def test_database_unavailable_never_reveals_exception_detail(self):
        """An operational SQLite failure returns a fixed message with nothing leaked."""
        leaky = sqlite3.OperationalError(
            'no such table: telemetry_streams in /home/pi/beacon/dashboard.db '
            'while running SELECT stream_key FROM telemetry_streams'
        )
        with mock.patch.object(
            self.appmod.beacon_diagnosis, 'get_current_diagnosis', side_effect=leaky,
        ):
            response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 503)
        self.assertIn('application/json', response.content_type)
        payload = response.get_json()
        self.assertEqual(set(payload), {'error'})
        body = response.get_data(as_text=True)
        for fragment in (
            'no such table', 'telemetry_streams', '/home/pi', 'SELECT',
            'OperationalError', 'Traceback', 'dashboard.db',
        ):
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, body)

    def test_unexpected_failure_stays_loud_instead_of_becoming_a_service_unavailable(self):
        """No catch-all: an unmodelled failure class must not hide behind a 503."""
        self.appmod.app.config['PROPAGATE_EXCEPTIONS'] = False
        with mock.patch.object(
            self.appmod.beacon_diagnosis,
            'get_current_diagnosis',
            side_effect=ValueError('a real defect'),
        ):
            response = self.client.get('/api/advanced/current')

        self.assertEqual(response.status_code, 500)

class ClockIsolationTests(unittest.TestCase):
    """The phase module must leave the process-global clock exactly as it found it."""

    def test_a_frozen_clock_never_outlives_the_test_that_froze_it(self):
        """WR-05: a frozen November-2023 clock must not survive into any later module."""
        probe = AdvancedDiagnosisApiTests(
            'test_host_tracer_returns_truthful_unknown_host_evidence'
        )
        result = unittest.TestResult()
        probe.run(result)

        self.assertEqual([], result.errors + result.failures)
        self.assertGreater(
            time.time(),
            1_750_000_000,
            'the frozen test clock leaked past the test that installed it',
        )


if __name__ == '__main__':
    unittest.main()
