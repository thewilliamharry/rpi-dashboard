"""Static closure checks and intentionally RED real-SQLite takeover matrix.

The dynamic assertions are a regression contract, not a production workaround:
they must fail until Plans 01-22/23 thread durable authority through every
worker-only mutation and non-SQL effect boundary.
"""

from dataclasses import fields, replace
import importlib
import os
import sqlite3
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from dashboard.beacon import queues, worker_main
from dashboard.beacon.worker_authority import WorkerAuthority
from tests.helpers import cleanup_db, load_app
from tests.worker_ownership_contract import (
    DATABASE_SURFACES,
    EFFECT_PRODUCERS,
    EFFECT_SURFACES,
    OPERATION_FIELD_CLASSIFICATIONS,
    PRODUCTION_OWNERSHIP_INVENTORY,
    TAKEOVER_CASE_REGISTRY,
)


EXPECTED_CALLBACK_IDS = ('P0', 'S1', 'S2', 'S3', 'J1', 'J2', 'J3', 'J4', 'J5', 'J6', 'J7', 'J8', 'J9', 'L1')
SCHEDULER_JOB_IDS = {
    'heartbeat': 'J1', 'metrics': 'J2', 'uptime_all': 'J3', 'uptime_down': 'J4',
    'scan_requests': 'J5', 'preview_requests': 'J6', 'scheduled_discovery': 'J7',
    'cleanup': 'J8', 'startup_discovery': 'J9',
}


class WorkerOwnershipStaticContractTests(unittest.TestCase):
    def test_inventory_contains_each_callback_exactly_once(self):
        ids = tuple(row.identifier for row in PRODUCTION_OWNERSHIP_INVENTORY)
        self.assertEqual(ids, EXPECTED_CALLBACK_IDS)
        self.assertEqual(len(ids), len(set(ids)), f'duplicate ownership IDs: {ids}')

    def test_registry_declares_every_required_database_and_effect_surface(self):
        declared_databases = {surface for row in PRODUCTION_OWNERSHIP_INVENTORY for surface in row.database_surfaces}
        declared_effects = {surface for row in PRODUCTION_OWNERSHIP_INVENTORY for surface in row.effect_surfaces}
        self.assertTrue(DATABASE_SURFACES <= declared_databases, DATABASE_SURFACES - declared_databases)
        self.assertEqual(declared_databases - DATABASE_SURFACES, set())
        self.assertTrue(EFFECT_SURFACES <= declared_effects, EFFECT_SURFACES - declared_effects)
        self.assertEqual(set(EFFECT_PRODUCERS), set(EFFECT_SURFACES))
        self.assertEqual(EFFECT_PRODUCERS['filesystem_publication'], frozenset())

    def test_inventory_or_registry_rows_have_complete_closure_identifiers(self):
        self.assertEqual(set(TAKEOVER_CASE_REGISTRY), {row.identifier for row in PRODUCTION_OWNERSHIP_INVENTORY if row.ownership_required})
        for row in PRODUCTION_OWNERSHIP_INVENTORY:
            with self.subTest(row=row.identifier):
                self.assertTrue(row.operation_fields)
                self.assertTrue(row.pause_boundaries)
                self.assertTrue(row.regression_contracts)
                if row.ownership_required:
                    self.assertTrue(row.takeover_assertion_ids)
                    self.assertTrue(row.transaction_assertion_ids)
                    self.assertTrue(row.admission_assertion_ids)
                    self.assertTrue(row.effect_assertion_ids)
                    self.assertIsNotNone(row.current_b_control_id)
                else:
                    self.assertFalse(row.takeover_assertion_ids)
                    self.assertIsNone(row.current_b_control_id)

    def test_callback_coverage_matches_worker_operations_and_production_bindings(self):
        worker = importlib.import_module('dashboard.worker')
        operation_fields = {field.name for field in fields(worker_main.WorkerOperations)}
        self.assertEqual(set(OPERATION_FIELD_CLASSIFICATIONS), operation_fields)
        inventory_fields = {field for row in PRODUCTION_OWNERSHIP_INVENTORY for field in row.operation_fields}
        self.assertTrue(inventory_fields <= operation_fields)
        operations = worker.build_worker_operations()
        missing = [field for field in operation_fields if not callable(getattr(operations, field))]
        self.assertEqual(missing, [], f'production bindings missing for: {missing}')

    def test_callback_coverage_preserves_startup_scheduler_and_lifecycle_wiring(self):
        source = open(worker_main.__file__, encoding='utf-8').read()
        for row_id, marker in {
            'P0': 'services.prepare_database', 'S1': 'services.recover_worker_state',
            'S2': 'heartbeat(services)', 'S3': 'sample_metrics(services)',
            'L1': '_finalize_worker_lifecycle',
        }.items():
            with self.subTest(row_id=row_id):
                self.assertIn(marker, source)
        for job_id, row_id in SCHEDULER_JOB_IDS.items():
            with self.subTest(row_id=row_id, job_id=job_id):
                self.assertIn(f"id='{job_id}'", source)

    def test_plan19_authority_shape_has_no_split_worker_credentials(self):
        service_fields = {field.name for field in fields(worker_main.WorkerServices)}
        self.assertIn('authority', service_fields)
        self.assertNotIn('worker_id', service_fields)
        self.assertNotIn('owner_token', service_fields)

    def test_actual_production_inventory_is_bijective_with_the_immutable_contract(self):
        """Drift in callbacks, effects, admission, or scheduler metadata is fatal."""
        production = {row.identifier: row for row in worker_main.WORKER_CALLBACK_INVENTORY}
        contract = {row.identifier: row for row in PRODUCTION_OWNERSHIP_INVENTORY}
        self.assertEqual(set(production), set(contract))
        self.assertEqual(set(production), set(worker_main._CALLBACKS_BY_ID))
        for identifier, expected in contract.items():
            actual = production[identifier]
            with self.subTest(identifier=identifier):
                self.assertEqual(actual.operation_fields, expected.operation_fields)
                self.assertEqual(actual.admission_category, expected.admission_category)
                self.assertEqual(actual.database_surfaces, expected.database_surfaces)
                self.assertEqual(actual.effect_surfaces, expected.effect_surfaces)
                self.assertEqual(actual.ownership_required, expected.ownership_required)
                self.assertEqual(
                    actual.scheduler_metadata['id'] if actual.scheduler_id else None,
                    actual.scheduler_id,
                )
        scheduled = [row for row in production.values() if row.scheduler_id]
        self.assertEqual({row.scheduler_metadata['id'] for row in scheduled}, set(SCHEDULER_JOB_IDS))
        self.assertEqual(
            {row.identifier for row in production.values() if row.ownership_required},
            set(TAKEOVER_CASE_REGISTRY),
        )
        worker = importlib.import_module('dashboard.worker')
        services = worker_main.build_worker_services(
            worker.build_worker_operations(),
            SimpleNamespace(db_path=':memory:', metric_sample_seconds=60),
        )
        scheduler = worker_main.build_scheduler(services)
        jobs = {job.id: job for job in scheduler.get_jobs()}
        self.assertEqual(set(jobs), set(SCHEDULER_JOB_IDS))
        for callback in scheduled:
            with self.subTest(scheduler_callback=callback.identifier):
                self.assertEqual(jobs[callback.scheduler_id].func.args[-1], callback.identifier)


class WorkerOwnershipTakeoverMatrixTests(unittest.TestCase):
    """Real-file SQLite A→B matrix; failures name stale authority, not setup."""

    def setUp(self):
        self.appmod, self.db_path = load_app({'METRIC_HISTORY_SECONDS': '1'})
        self.worker = importlib.reload(importlib.import_module('dashboard.worker'))
        self.operations = self.worker.build_worker_operations()
        # The durable queue processors intentionally read the production clock,
        # so keep the injected clock close to it while still advancing it only
        # through explicit lease arguments.
        self.now = int(__import__('time').time())

    def tearDown(self):
        cleanup_db(self.db_path)

    def _owner_a_then_b(self):
        owner_a = queues.acquire_worker_lease(self.db_path, 'matrix-worker-a', now=self.now - 2, lease_seconds=1)
        owner_b = queues.acquire_worker_lease(self.db_path, 'matrix-worker-b', now=self.now, lease_seconds=30)
        return owner_a, owner_b

    def _authority(self, lease):
        return WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: self.now)

    def _fresh_case_database(self):
        """Each matrix row gets a fresh persisted owner, never a recycled B lease."""
        cleanup_db(self.db_path)
        self.appmod, self.db_path = load_app({'METRIC_HISTORY_SECONDS': '1'})
        self.worker = importlib.reload(importlib.import_module('dashboard.worker'))
        self.operations = self.worker.build_worker_operations()

    def _seed_service(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT OR REPLACE INTO services(port,title,first_seen,last_seen,is_online,last_latency_ms,last_error) VALUES(?,?,?,?,?,?,?)",
                (8080, 'Matrix service', self.now - 1, self.now - 1, 0, None, 'old'),
            )
            conn.execute(
                "INSERT OR REPLACE INTO service_meta(port,url,critical,pinned_order,tags,healthy_statuses) VALUES(?,?,?,?,?,?)",
                (8080, 'http://127.0.0.1:8080', 0, 8080, '', '200-399'),
            )
            conn.commit()
            conn.close()

    def _snapshot(self):
        tables = (
            'services', 'service_meta', 'service_checks', 'events', 'system_stats', 'stats_history',
            'scan_requests', 'preview_requests', 'scan_rate_hits',
        )
        with sqlite3.connect(self.db_path) as conn:
            snapshots = {}
            for table in tables:
                snapshots[table] = tuple(conn.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall())
            runtime = conn.execute(
                "SELECT key,value,updated_ts FROM runtime_state WHERE key != 'worker_owner' ORDER BY key"
            ).fetchall()
            owner = conn.execute("SELECT value FROM runtime_state WHERE key='worker_owner'").fetchone()
        return snapshots, runtime, owner[0] if owner else None

    def _assert_b_is_current(self, owner_b):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT value FROM runtime_state WHERE key='worker_owner'").fetchone()
        self.assertIsNotNone(row)
        self.assertIn('matrix-worker-b', row[0])
        self.assertNotIn(owner_b.owner_token, self.id())  # never include opaque tokens in diagnostics

    def _run_after_takeover(self, row_id, setup, stale_callback, current_b_callback):
        self._fresh_case_database()
        setup()
        _owner_a, owner_b = self._owner_a_then_b()
        before, runtime_before, _ = self._snapshot()
        stale_callback()
        after, runtime_after, _ = self._snapshot()
        self._assert_b_is_current(owner_b)
        self.assertEqual(
            (after, runtime_after), (before, runtime_before),
            f'{row_id}: stale-A ownership/admission/effect boundary changed after Worker B acquired',
        )
        current_b_callback(owner_b)
        current, runtime_current, _ = self._snapshot()
        self.assertNotEqual(
            (current, runtime_current), (before, runtime_before),
            f'{row_id}: current-B control suppressed all work',
        )

    def _services(self, owner):
        services = worker_main.build_worker_services(
            self.operations,
            type('Settings', (), {'db_path': self.db_path, 'metric_sample_seconds': 1})(),
        )
        return replace(services, authority=self._authority(owner))

    def _fake_probe(self, *args, **kwargs):
        return True, 7.5, None, object()

    def _run_uptime(self, authority, only_down):
        with (
            mock.patch.object(self.appmod.time, 'time', return_value=self.now),
            mock.patch.object(self.appmod, '_legacy_probe_http', self._fake_probe),
            mock.patch.object(self.appmod, '_legacy_extract_title', return_value='Matrix title'),
        ):
            return self.operations.do_uptime_check(authority, only_down=only_down)

    def _run_metrics(self, authority):
        with mock.patch.object(self.appmod.time, 'time', return_value=self.now):
            return self.operations.collect_system_stats(authority)

    def _seed_recovery(self):
        self.appmod.update_worker_heartbeat(now=self.now - 100)

    def _run_recovery(self, authority):
        return self.operations.recover_worker_state(authority)

    def _seed_cleanup(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute('INSERT INTO stats_history(ts,cpu,ram,disk,temp) VALUES(?,?,?,?,?)', (1, 1, 1, 1, 1))
            conn.execute("INSERT INTO events(ts,event_type) VALUES(?, 'old')", (1,))
            conn.execute("INSERT INTO scan_rate_hits(client_key,ts) VALUES('matrix',1)")
            conn.commit()
            conn.close()

    def _run_cleanup(self, authority):
        with mock.patch.object(self.appmod.time, 'time', return_value=self.now + 100_000):
            return self.operations.cleanup_history(authority)

    def _run_discovery(self, authority, source):
        class FakeSocket:
            def close(self):
                return None

        def connect(address, timeout):
            if address[1] == 8080:
                return FakeSocket()
            raise OSError('closed')

        with (
            mock.patch.object(self.appmod.time, 'time', return_value=self.now),
            mock.patch.object(self.appmod.socket, 'create_connection', side_effect=connect),
            mock.patch.object(self.appmod, '_legacy_probe_http', self._fake_probe),
            mock.patch.object(self.appmod, '_legacy_extract_title', return_value='Discovered'),
        ):
            return self.operations.run_discovery(authority, source=source)

    def _seed_scan(self):
        queues.enqueue_scan(self.db_path, 'matrix', now=self.now)

    def _run_scan(self, owner):
        with mock.patch.object(self.appmod, 'run_discovery', return_value='completed'):
            return self.operations.process_scan_requests(self._authority(owner), now_fn=lambda: self.now)

    def _seed_preview(self):
        self._seed_service()
        queues.enqueue_preview(self.db_path, 8080, now=self.now)

    def _run_preview(self, owner):
        with mock.patch.object(self.appmod, '_legacy_refresh_service_preview', return_value=('Preview', b'png', 'image/png', 'screenshot', None, None)):
            return self.operations.process_preview_requests(self._authority(owner))

    def test_database_takeover_matrix_fences_every_callback(self):
        """Plan 01-22 makes the SQLite subset green without shrinking the registry."""
        cases = (
            ('S1', self._seed_recovery, lambda: self._run_recovery(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})())), lambda b: self._run_recovery(self._authority(b))),
            ('S2', lambda: None, lambda: worker_main.heartbeat(self._services(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})())), lambda b: worker_main.heartbeat(self._services(b))),
            ('S3', lambda: None, lambda: self._run_metrics(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})())), lambda b: self._run_metrics(self._authority(b))),
            ('J1', lambda: None, lambda: worker_main.heartbeat(self._services(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})())), lambda b: worker_main.heartbeat(self._services(b))),
            ('J2', lambda: None, lambda: self._run_metrics(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})())), lambda b: self._run_metrics(self._authority(b))),
            ('J3', self._seed_service, lambda: self._run_uptime(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})()), False), lambda b: self._run_uptime(self._authority(b), False)),
            ('J4', self._seed_service, lambda: self._run_uptime(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})()), True), lambda b: self._run_uptime(self._authority(b), True)),
            ('J5', self._seed_scan, lambda: self._run_scan(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})()), lambda b: self._run_scan(b)),
            ('J6', self._seed_preview, lambda: self._run_preview(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})()), lambda b: self._run_preview(b)),
            ('J7', self._seed_service, lambda: self._run_discovery(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})()), 'scheduled'), lambda b: self._run_discovery(self._authority(b), 'scheduled')),
            ('J8', self._seed_cleanup, lambda: self._run_cleanup(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})())), lambda b: self._run_cleanup(self._authority(b))),
            ('J9', self._seed_service, lambda: self._run_discovery(self._authority(type('Owner', (), {'worker_id': 'matrix-worker-a', 'owner_token': 'stale'})()), 'startup'), lambda b: self._run_discovery(self._authority(b), 'startup')),
        )
        self.assertEqual(tuple(case[0] for case in cases), tuple(TAKEOVER_CASE_REGISTRY))
        for row_id, setup, stale_callback, current_b_callback in cases:
            with self.subTest(row_id=row_id):
                self._run_after_takeover(row_id, setup, stale_callback, current_b_callback)

    def test_preview_capture_publication_is_fenced_after_a_real_sqlite_takeover(self):
        """J6 may capture in memory, but only current B can publish its result."""
        self._fresh_case_database()
        self._seed_preview()
        owner_a = queues.acquire_worker_lease(
            self.db_path, 'matrix-worker-a', now=self.now - 2, lease_seconds=2,
        )
        capture_started = threading.Event()
        release_capture = threading.Event()
        effects = []
        clock = {'now': self.now - 1}

        def paused_capture(*_args, **_kwargs):
            if not effects:
                capture_started.set()
                self.assertTrue(release_capture.wait(timeout=2), 'matrix release was not signalled')
                effects.append('a')
            else:
                effects.append('b')
            return 'Preview', b'png', 'image/png', 'screenshot', None, None

        with (
            mock.patch.object(self.appmod.time, 'time', side_effect=lambda: clock['now']),
            mock.patch.object(self.appmod, '_legacy_refresh_service_preview', side_effect=paused_capture),
        ):
            stale = threading.Thread(
                target=lambda: self.operations.process_preview_requests(
                    WorkerAuthority.from_lease(
                        owner_a, self.db_path, clock=lambda: clock['now'],
                    ),
                ),
                daemon=True,
            )
            stale.start()
            self.assertTrue(capture_started.wait(timeout=2), 'preview never reached capture boundary')
            clock['now'] = self.now
            owner_b = queues.acquire_worker_lease(
                self.db_path, 'matrix-worker-b', now=self.now, lease_seconds=30,
            )
            release_capture.set()
            stale.join(timeout=2)
            self.assertFalse(stale.is_alive(), 'preview callback did not drain')

            # A new revision is a real current-B success control; it must be
            # allowed even though A's old result is rejected by queue fencing.
            queues.enqueue_preview(self.db_path, 8080, now=self.now)
            self.operations.process_preview_requests(self._authority(owner_b))

        self._assert_b_is_current(owner_b)
        self.assertEqual(effects, ['a', 'b'])
        with sqlite3.connect(self.db_path) as conn:
            published = conn.execute(
                "SELECT event_type FROM events WHERE event_type IN ('preview_capture', 'preview_complete') "
                "ORDER BY id"
            ).fetchall()
        self.assertEqual(
            [row[0] for row in published], ['preview_capture', 'preview_complete'],
            'J6: stale-A browser output published after Worker B acquired',
        )


if __name__ == '__main__':
    unittest.main()
