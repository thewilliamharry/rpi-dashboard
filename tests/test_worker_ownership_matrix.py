"""Static closure checks and intentionally RED real-SQLite takeover matrix.

The dynamic assertions are a regression contract, not a production workaround:
they must fail until Plans 01-22/23 thread durable authority through every
worker-only mutation and non-SQL effect boundary.
"""

from dataclasses import fields, replace
from contextlib import contextmanager
import importlib
import json
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
DYNAMIC_MATRIX_ROW_IDS = ('S1', 'S2', 'S3', 'J1', 'J2', 'J3', 'J4', 'J5', 'J6', 'J7', 'J8', 'J9')
# OPS-01: the single declared source of lane truth. A future lane change
# (e.g. Branch B's 'queues' lane for J5, see 06-04-PLAN.md Task 2) must move
# this map in the same commit as the code, or this contract goes red.
EXPECTED_EXECUTOR_LANES = {
    'J1': 'metrics', 'J2': 'metrics', 'J3': 'probes', 'J4': 'probes',
    'J5': 'probes', 'J6': 'screenshots', 'J7': 'probes', 'J8': 'cleanup', 'J9': 'probes',
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
        self.assertEqual(
            DYNAMIC_MATRIX_ROW_IDS, tuple(TAKEOVER_CASE_REGISTRY),
            'dynamic takeover rows must cover every ownership-required registry row',
        )
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

    def test_every_scheduled_callback_declares_its_expected_executor_lane(self):
        """OPS-01: the essential 'metrics' lane is claimed by J1 and J2 alone.

        A future regression -- quietly parking another job on the essential
        lane, or dropping the dedicated 'cleanup' lane -- must fail this test
        loudly rather than only showing up as a timing symptom under load.
        """
        scheduled = {
            callback.identifier: callback
            for callback in worker_main.WORKER_CALLBACK_INVENTORY
            if callback.scheduler_id
        }
        self.assertEqual(set(scheduled), set(EXPECTED_EXECUTOR_LANES))
        for identifier, expected_lane in EXPECTED_EXECUTOR_LANES.items():
            with self.subTest(identifier=identifier):
                self.assertEqual(scheduled[identifier].executor, expected_lane)

        worker = importlib.import_module('dashboard.worker')
        services = worker_main.build_worker_services(
            worker.build_worker_operations(),
            SimpleNamespace(db_path=':memory:', metric_sample_seconds=60),
        )
        built_scheduler = worker_main.build_scheduler(services)
        declared_lanes = {callback.executor for callback in scheduled.values()}
        self.assertLessEqual(declared_lanes, set(built_scheduler._executors))

        metrics_lane_claimants = {
            identifier for identifier, callback in scheduled.items()
            if callback.executor == 'metrics'
        }
        self.assertEqual(metrics_lane_claimants, {'J1', 'J2'})


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

    def _run_current_a_pause_then_takeover(self, row_id, setup):
        """Exercise the real check-to-write interval, not a synthetic token."""
        self._fresh_case_database()
        setup()
        owner_a = queues.acquire_worker_lease(
            self.db_path, 'matrix-worker-a', now=self.now, lease_seconds=1,
        )
        authority_a = self._authority(owner_a)
        services_a = self._services(owner_a)
        paused = threading.Event()
        release = threading.Event()
        original_transaction = self.appmod._worker_write_transaction
        paused_once = False

        @contextmanager
        def pause_before_authoritative_commit(authority, **kwargs):
            nonlocal paused_once
            if authority == authority_a and not paused_once:
                paused_once = True
                paused.set()
                self.assertTrue(release.wait(timeout=2), f'{row_id}: takeover release was not signalled')
            with original_transaction(authority, **kwargs) as conn:
                yield conn

        with mock.patch.object(
            self.appmod, '_worker_write_transaction', pause_before_authoritative_commit,
        ):
            stale_result = []
            stale = threading.Thread(
                target=lambda: stale_result.append(worker_main.dispatch_callback(services_a, row_id)),
                daemon=True,
            )
            stale.start()
            self.assertTrue(paused.wait(timeout=2), f'{row_id}: A never reached an authoritative write')
            self.now += 2
            owner_b = queues.acquire_worker_lease(
                self.db_path, 'matrix-worker-b', now=self.now, lease_seconds=30,
            )
            before_release, runtime_before_release, _ = self._snapshot()
            release.set()
            stale.join(timeout=2)

        self.assertFalse(stale.is_alive(), f'{row_id}: stale callback did not drain')
        self.assertEqual(stale_result, [False], f'{row_id}: LeaseLost did not reach universal dispatch')
        self.assertFalse(services_a.admission._accepting, f'{row_id}: admission remained open after lease loss')
        after, runtime_after, _ = self._snapshot()
        self.assertEqual(
            (after, runtime_after), (before_release, runtime_before_release),
            f'{row_id}: current A committed after B acquired the durable lease',
        )
        self._assert_b_is_current(owner_b)
        if row_id == 'J5':
            # A's scan-row claim predates takeover and keeps its independent
            # Wave-14 lease.  B becomes the queue processor once that row
            # lease expires, while B's worker epoch is still current.
            self.now += 29
        current_b = worker_main.dispatch_callback(self._services(owner_b), row_id)
        self.assertIsNot(current_b, False, f'{row_id}: current-B control did not run')

    def test_current_a_takeover_before_authoritative_commits_is_fenced(self):
        """Every legacy worker path must reject a real A→B handoff at its write."""
        class FakeSocket:
            def close(self):
                return None

        def connect(address, timeout):
            if address[1] == 8080:
                return FakeSocket()
            raise OSError('closed')

        cases = (
            ('S1', self._seed_recovery), ('S3', lambda: None), ('J2', lambda: None),
            ('J3', self._seed_service), ('J4', self._seed_service), ('J5', self._seed_scan),
            ('J7', self._seed_service), ('J8', self._seed_cleanup), ('J9', self._seed_service),
        )
        with (
            mock.patch.object(self.appmod.socket, 'create_connection', side_effect=connect),
            mock.patch.object(self.appmod, '_legacy_probe_http', self._fake_probe),
            mock.patch.object(self.appmod, '_legacy_extract_title', return_value='Matrix title'),
            mock.patch.object(self.appmod.time, 'time', side_effect=lambda: self.now),
        ):
            for row_id, setup in cases:
                with self.subTest(row_id=row_id):
                    self._run_current_a_pause_then_takeover(row_id, setup)

    def test_heartbeat_renewal_to_persistence_handoff_is_fenced(self):
        """S2/J1 must reject B takeover after A renewed but before it writes heartbeat."""
        for row_id in ('S2', 'J1'):
            with self.subTest(row_id=row_id):
                self._fresh_case_database()
                owner_a = queues.acquire_worker_lease(
                    self.db_path, 'matrix-worker-a', now=self.now, lease_seconds=1,
                )
                authority_a = self._authority(owner_a)
                services_a = self._services(owner_a)
                paused = threading.Event()
                release = threading.Event()
                stop_requests = []
                original_transaction = self.appmod._worker_write_transaction

                @contextmanager
                def pause_before_compatibility_heartbeat(authority, **kwargs):
                    if authority == authority_a:
                        paused.set()
                        self.assertTrue(
                            release.wait(timeout=2),
                            f'{row_id}: heartbeat takeover release was not signalled',
                        )
                    with original_transaction(authority, **kwargs) as conn:
                        yield conn

                class FakeScheduler:
                    def shutdown(self, wait=False):
                        stop_requests.append(wait)

                with (
                    mock.patch.object(
                        self.appmod, '_worker_write_transaction', pause_before_compatibility_heartbeat,
                    ),
                    mock.patch.object(worker_main, 'scheduler', FakeScheduler()),
                ):
                    stale_result = []
                    stale = threading.Thread(
                        target=lambda: stale_result.append(worker_main.dispatch_callback(services_a, row_id)),
                        daemon=True,
                    )
                    stale.start()
                    self.assertTrue(paused.wait(timeout=2), f'{row_id}: A never reached heartbeat persistence')
                    with sqlite3.connect(self.db_path) as conn:
                        owner = json.loads(conn.execute(
                            "SELECT value FROM runtime_state WHERE key='worker_owner'"
                        ).fetchone()[0])
                    self.assertGreater(owner['lease_until'], self.now + 1, f'{row_id}: renewal did not commit')
                    self.now += 16
                    owner_b = queues.acquire_worker_lease(
                        self.db_path, 'matrix-worker-b', now=self.now, lease_seconds=30,
                    )
                    before_release, runtime_before_release, _ = self._snapshot()
                    release.set()
                    stale.join(timeout=2)

                self.assertFalse(stale.is_alive(), f'{row_id}: stale heartbeat did not drain')
                self.assertEqual(stale_result, [False], f'{row_id}: stale heartbeat did not report lease loss')
                self.assertFalse(services_a.admission._accepting, f'{row_id}: admission remained open')
                self.assertEqual(stop_requests, [False], f'{row_id}: scheduler stop was not requested')
                after, runtime_after, _ = self._snapshot()
                self.assertEqual(
                    (after, runtime_after), (before_release, runtime_before_release),
                    f'{row_id}: stale A wrote worker_heartbeat after B acquired',
                )
                self._assert_b_is_current(owner_b)
                self.assertIsNot(
                    worker_main.dispatch_callback(self._services(owner_b), row_id), False,
                    f'{row_id}: current-B heartbeat control did not run',
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

        def run_stale_preview():
            try:
                self.operations.process_preview_requests(
                    WorkerAuthority.from_lease(
                        owner_a, self.db_path, clock=lambda: clock['now'],
                    ),
                )
            except queues.LeaseLost:
                pass

        with (
            mock.patch.object(self.appmod.time, 'time', side_effect=lambda: clock['now']),
            mock.patch.object(self.appmod, '_legacy_refresh_service_preview', side_effect=paused_capture),
        ):
            stale = threading.Thread(target=run_stale_preview, daemon=True)
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
