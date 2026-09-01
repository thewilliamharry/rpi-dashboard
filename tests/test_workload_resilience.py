"""Phase 6 (Workload Resilience & Pi Acceptance) integration suite.

Covers OPS-01 (cadence under contention), OPS-02 (bounded preview retry),
OPS-03 (bounded thumbnail store), and OPS-04 (WAL, concurrency, restart
recovery) end-to-end, against the running product rather than individual
units. Later plans in this phase append to this file in turn: 06-02 (TTL and
byte budget), 06-03 (bounded preview retry), 06-04 (cadence under
contention), 06-05 (WAL, concurrency, restart recovery), 06-06 (harness
self-test).

06-01 seeds this file with the OPS-03 thumbnail relocation tracer: a captured
thumbnail is stored in, and served from, the bounded ``thumbnails`` store.

06-04 adds ``CadenceUnderContentionTests`` for OPS-01: J1/J2 keep their
cadence, judged by ``freshness_state``, while cleanup, discovery, queue-drain
and preview work all run concurrently on their own lane-isolated executors.

06-05 adds ``WalModeTests`` (WAL from either starting mode -- the rollout
logic proven against synthetic fixtures) and ``ConcurrentAccessTests``
(concurrent web/worker writers and worker-restart fencing under WAL) for
OPS-04.

06-06 adds ``PiLoadAcceptanceHarnessTests`` for OPS-07: the Pi-class load
acceptance harness's (``tests/pi_load_acceptance.py``) three internal
oracles -- ``parse_compose_memory_limits``, ``assert_cadence``,
``assert_resource_budget`` -- are exercised directly here so the harness
stays honest without needing hardware.
"""

import importlib
import os
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from shutil import copy2
from types import SimpleNamespace
from unittest import mock

import psutil

from dashboard.beacon import diagnosis as beacon_diagnosis
from dashboard.beacon import queues
from dashboard.beacon import repositories as beacon_repositories
from dashboard.beacon import telemetry as beacon_telemetry
from dashboard.beacon import worker_main
from dashboard.beacon.config import Settings, load_settings
from dashboard.beacon.db import (
    ManagedConnection,
    configured_journal_mode,
    connect_db,
    exclusive_database_maintenance,
    write_transaction,
)
from dashboard.beacon.migrations import MIGRATIONS, run_migrations
from dashboard.beacon.repositories import ThumbnailStoreRepository
from dashboard.beacon.worker_authority import WorkerAuthority
from tests import pi_load_acceptance
from tests.helpers import cleanup_db, load_app


FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'legacy'


class ThumbnailRelocationTests(unittest.TestCase):
    """OPS-03: thumbnail blobs are stored in, and served from, the bounded store."""

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_service(self, port=8080):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, "
                "last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (port, 'Preview service', now - 120, now, 1, 12.0, None),
            )
            conn.commit()
            conn.close()

    def test_thumbnail_is_stored_in_and_served_from_the_bounded_store(self):
        port = 8080
        self._insert_service(port)
        store = ThumbnailStoreRepository(ttl_seconds=self.appmod.THUMBNAIL_TTL_SECONDS)

        # A successful capture writes the blob to `thumbnails` (upsert on port)
        # and leaves `services.thumb_data` untouched (the column is never
        # written by the new store at all).
        captured_ts = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            store.store_thumbnail_result(
                conn, port, b'png-bytes', 'image/png', 'screenshot', None, ts=captured_ts,
            )
            conn.commit()
            row = conn.execute(
                'SELECT thumb_data, thumb_ts, thumb_source, thumb_attempt_ts, thumb_error '
                'FROM services WHERE port=?', (port,),
            ).fetchone()
            thumbnail_row = conn.execute(
                'SELECT data, mime, source, expires_ts FROM thumbnails WHERE port=?', (port,),
            ).fetchone()
            conn.close()

        self.assertIsNone(row['thumb_data'])
        self.assertEqual(row['thumb_ts'], captured_ts)
        self.assertEqual(row['thumb_source'], 'screenshot')
        self.assertEqual(row['thumb_attempt_ts'], captured_ts)
        self.assertIsNone(row['thumb_error'])
        self.assertEqual(tuple(thumbnail_row)[:3], (b'png-bytes', 'image/png', 'screenshot'))
        self.assertEqual(
            thumbnail_row['expires_ts'], captured_ts + self.appmod.THUMBNAIL_TTL_SECONDS,
        )

        # GET /api/thumbnail/<port> returns those exact bytes with the stored
        # mime as Content-Type.
        response = self.client.get(f'/api/thumbnail/{port}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'png-bytes')
        self.assertEqual(response.headers['Content-Type'], 'image/png')

        # GET /api/services reports has_thumb: true for that port while the row
        # has not expired.
        services = self.client.get('/api/services').get_json()
        service = next(item for item in services if item['port'] == port)
        self.assertTrue(service['has_thumb'])

        # Once the row's expires_ts is in the past, both the byte read and the
        # has_thumb projection stop serving it.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'UPDATE thumbnails SET expires_ts=? WHERE port=?', (1, port),
            )
            conn.commit()
            conn.close()

        expired_response = self.client.get(f'/api/thumbnail/{port}')
        self.assertEqual(expired_response.status_code, 404)
        services_after_expiry = self.client.get('/api/services').get_json()
        service_after_expiry = next(
            item for item in services_after_expiry if item['port'] == port
        )
        self.assertFalse(service_after_expiry['has_thumb'])

    def test_a_failed_capture_records_diagnostics_without_an_orphan_thumbnail_row(self):
        port = 8081
        self._insert_service(port)
        store = ThumbnailStoreRepository(ttl_seconds=self.appmod.THUMBNAIL_TTL_SECONDS)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            store.store_thumbnail_result(
                conn, port, None, None, None, 'capture failed', ts=2_000,
            )
            conn.commit()
            row = conn.execute(
                'SELECT thumb_data, thumb_ts, thumb_source, thumb_attempt_ts, thumb_error '
                'FROM services WHERE port=?', (port,),
            ).fetchone()
            orphan = conn.execute(
                'SELECT 1 FROM thumbnails WHERE port=?', (port,),
            ).fetchone()
            conn.close()

        self.assertIsNone(row['thumb_data'])
        self.assertIsNone(row['thumb_ts'])
        self.assertIsNone(row['thumb_source'])
        self.assertEqual(row['thumb_attempt_ts'], 2_000)
        self.assertEqual(row['thumb_error'], 'capture failed')
        self.assertIsNone(orphan)

        response = self.client.get(f'/api/thumbnail/{port}')
        self.assertEqual(response.status_code, 404)


class ThumbnailMigrationTests(unittest.TestCase):
    """OPS-03: a tracked lineage at the previous version upgrades cleanly."""

    def _carry_lineage_to(self, fixture_name, version, directory):
        target = Path(directory) / 'dashboard.db'
        copy2(FIXTURE_DIR / fixture_name, target)
        settings = Settings(db_path=str(target))
        with mock.patch(
            'dashboard.beacon.migrations.MIGRATIONS',
            tuple(m for m in MIGRATIONS if m.version <= version),
        ):
            run_migrations(settings)
        return target, settings

    def test_migration_ten_moves_existing_blobs_off_services(self):
        newest = MIGRATIONS[-1].version
        with tempfile.TemporaryDirectory() as directory:
            target, settings = self._carry_lineage_to(
                'operator/production.db', newest - 1, directory,
            )
            with sqlite3.connect(target) as conn:
                conn.execute(
                    'INSERT INTO services(port, title, first_seen, last_seen, is_online, '
                    'thumb_data, thumb_mime, thumb_ts, thumb_source) VALUES(?,?,?,?,?,?,?,?,?)',
                    (8090, 'Deployed preview service', 1_700_000_000, 1_700_000_010, 1,
                     b'deployed-thumbnail-bytes', 'image/png', 1_700_000_010, 'screenshot'),
                )
                conn.commit()

            result = run_migrations(settings)
            self.assertEqual(result.applied_versions, (newest,))

            with sqlite3.connect(target) as conn:
                self.assertIsNone(
                    conn.execute(
                        'SELECT thumb_data FROM services WHERE port=?', (8090,),
                    ).fetchone()[0],
                )
                self.assertEqual(
                    conn.execute(
                        'SELECT data, mime FROM thumbnails WHERE port=?', (8090,),
                    ).fetchone(),
                    (b'deployed-thumbnail-bytes', 'image/png'),
                )


class ThumbnailBudgetTests(unittest.TestCase):
    """OPS-03: the thumbnail store is bounded by a TTL and a total-byte budget."""

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_service(self, port):
        now = int(time.time())
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, "
                "last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (port, 'Preview service', now - 120, now, 1, 12.0, None),
            )
            conn.commit()
            conn.close()

    def _seed_thumbnail(self, conn, port, size_bytes, *, captured_ts, expires_ts):
        conn.execute(
            'INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts) '
            'VALUES(?,?,?,?,?,?)',
            (port, b'x' * size_bytes, 'image/png', captured_ts, 'screenshot', expires_ts),
        )

    def test_thumbnail_store_stays_within_ttl_and_byte_budget(self):
        now = int(time.time())
        one_mib = 1024 * 1024

        # Behavior: delete_expired_thumbnails removes exactly the rows whose
        # expires_ts has passed; NULL or future expires_ts survive.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            self._seed_thumbnail(conn, 8001, 10, captured_ts=now - 100, expires_ts=now - 1)
            self._seed_thumbnail(conn, 8002, 10, captured_ts=now - 100, expires_ts=now + 1_000)
            self._seed_thumbnail(conn, 8003, 10, captured_ts=now - 100, expires_ts=None)
            conn.commit()
            removed = beacon_repositories.delete_expired_thumbnails(conn, now=now)
            conn.commit()
            remaining_ports = {row['port'] for row in conn.execute('SELECT port FROM thumbnails')}
            conn.close()
        self.assertEqual(removed, 1)
        self.assertEqual(remaining_ports, {8002, 8003})

        # Behavior: thumbnail_store_bytes sums LENGTH(data); 0 for an empty store.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute('DELETE FROM thumbnails')
            conn.commit()
            self.assertEqual(beacon_repositories.thumbnail_store_bytes(conn), 0)
            self._seed_thumbnail(conn, 8004, 100, captured_ts=now, expires_ts=now + 1_000)
            self._seed_thumbnail(conn, 8005, 200, captured_ts=now, expires_ts=now + 1_000)
            conn.commit()
            self.assertEqual(beacon_repositories.thumbnail_store_bytes(conn), 300)
            conn.close()

        # OPS-03 backstop: a store already under the byte budget is not evicted.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            evicted = beacon_repositories.evict_thumbnails_over_budget(conn, max_bytes=1_000_000)
            conn.commit()
            remaining = {row['port'] for row in conn.execute('SELECT port FROM thumbnails')}
            conn.close()
        self.assertEqual(evicted, 0)
        self.assertEqual(remaining, {8004, 8005})

        # Behavior: evict_thumbnails_over_budget deletes oldest-captured_ts-first
        # until at or below max_bytes -- a three-row 1 MiB-each store bounded at
        # 2 MiB retains exactly the two newest rows.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute('DELETE FROM thumbnails')
            self._seed_thumbnail(conn, 8010, one_mib, captured_ts=now - 300, expires_ts=now + 10_000)
            self._seed_thumbnail(conn, 8011, one_mib, captured_ts=now - 200, expires_ts=now + 10_000)
            self._seed_thumbnail(conn, 8012, one_mib, captured_ts=now - 100, expires_ts=now + 10_000)
            conn.commit()
            evicted = beacon_repositories.evict_thumbnails_over_budget(conn, max_bytes=2 * one_mib)
            conn.commit()
            remaining = {row['port'] for row in conn.execute('SELECT port FROM thumbnails')}
            conn.close()
        self.assertEqual(evicted, 1)
        self.assertEqual(remaining, {8011, 8012})

        # Behavior: the eviction walk is bounded by scan_limit and converges
        # across passes -- scan_limit=1 against a three-row over-budget store
        # deletes exactly one row per call, emptying the store after three calls.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute('DELETE FROM thumbnails')
            self._seed_thumbnail(conn, 8020, one_mib, captured_ts=now - 300, expires_ts=now + 10_000)
            self._seed_thumbnail(conn, 8021, one_mib, captured_ts=now - 200, expires_ts=now + 10_000)
            self._seed_thumbnail(conn, 8022, one_mib, captured_ts=now - 100, expires_ts=now + 10_000)
            conn.commit()
            first = beacon_repositories.evict_thumbnails_over_budget(conn, max_bytes=0, scan_limit=1)
            conn.commit()
            after_first = conn.execute('SELECT COUNT(*) AS n FROM thumbnails').fetchone()['n']
            second = beacon_repositories.evict_thumbnails_over_budget(conn, max_bytes=0, scan_limit=1)
            conn.commit()
            after_second = conn.execute('SELECT COUNT(*) AS n FROM thumbnails').fetchone()['n']
            third = beacon_repositories.evict_thumbnails_over_budget(conn, max_bytes=0, scan_limit=1)
            conn.commit()
            after_third = conn.execute('SELECT COUNT(*) AS n FROM thumbnails').fetchone()['n']
            conn.close()
        self.assertEqual((first, after_first), (1, 2))
        self.assertEqual((second, after_second), (1, 1))
        self.assertEqual((third, after_third), (1, 0))

        # Behavior: a non-positive or unparseable THUMBNAIL_TTL_DAYS /
        # THUMBNAIL_STORE_MAX_BYTES falls back to the documented default,
        # never to "no limit" (PROH-OPS-03-04).
        self.assertEqual(load_settings({'THUMBNAIL_TTL_DAYS': '0'}).thumbnail_ttl_days, 7)
        self.assertEqual(load_settings({'THUMBNAIL_TTL_DAYS': 'abc'}).thumbnail_ttl_days, 7)
        self.assertEqual(
            load_settings({'THUMBNAIL_STORE_MAX_BYTES': '0'}).thumbnail_store_max_bytes, 67_108_864,
        )
        self.assertEqual(
            load_settings({'THUMBNAIL_STORE_MAX_BYTES': 'abc'}).thumbnail_store_max_bytes, 67_108_864,
        )

        # Behavior + OPS-03 backstop: a J8 run deletes expired rows and enforces
        # the byte budget inside its existing transaction, evicting an
        # over-budget-but-unexpired row even though nothing has expired for it
        # -- proving the two bounds interact independently. Once evicted,
        # GET /api/services reports has_thumb falsy for that port on the very
        # next read (PROH-OPS-03-03).
        port = 8080
        self._insert_service(port)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            self._seed_thumbnail(conn, 9001, 10, captured_ts=now - 100, expires_ts=now - 1)
            over_budget_bytes = self.appmod.THUMBNAIL_STORE_MAX_BYTES + 1
            self._seed_thumbnail(
                conn, port, over_budget_bytes, captured_ts=now - 50, expires_ts=now + 10_000,
            )
            conn.commit()
            conn.close()

        lease = queues.acquire_worker_lease(self.db_path, 'thumbnail-budget-test', now=now)
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=lambda: now)
        snapshot = beacon_telemetry.StorageSnapshot(
            database_bytes=0, wal_bytes=0, shm_bytes=0, free_bytes=10 ** 9,
        )
        with (
            mock.patch.object(self.appmod.beacon_telemetry, 'measure_storage', return_value=snapshot),
            mock.patch.object(self.appmod.beacon_telemetry, 'run_retention_batch'),
        ):
            self.appmod.worker_cleanup_history(authority, now=now)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            remaining_after_j8 = {row['port'] for row in conn.execute('SELECT port FROM thumbnails')}
            conn.close()
        self.assertNotIn(9001, remaining_after_j8)
        self.assertNotIn(port, remaining_after_j8)

        services = self.client.get('/api/services').get_json()
        service = next(item for item in services if item['port'] == port)
        self.assertFalse(service['has_thumb'])


class _MutableClock:
    """A deterministic, externally-advanceable clock for authority injection."""

    def __init__(self, now):
        self.now_ts = int(now)

    def __call__(self):
        return self.now_ts


class PreviewRetryTests(unittest.TestCase):
    """OPS-02: a repeatedly-failing preview exhausts a bounded budget without
    ever blocking the essential J1-J4 lanes.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_service(self, port, *, now):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online, "
                "last_latency_ms, last_error) VALUES (?,?,?,?,?,?,?)",
                (port, 'Flaky preview service', now - 120, now, 1, 12.0, None),
            )
            conn.commit()
            conn.close()

    def test_preview_retry_bounded_reaches_degraded_without_blocking_essential_jobs(self):
        port = 8080
        now = int(time.time())
        self._insert_service(port, now=now)
        queues.enqueue_preview(self.db_path, port, now=now)

        lease = queues.acquire_worker_lease(
            self.db_path, 'preview-retry-worker', now=now, lease_seconds=3_600,
        )
        clock = _MutableClock(now)
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=clock)

        # The essential J1-J4 lanes already carry durable evidence of success
        # -- the assertion below is that a bounded, exhausting J6 retry run
        # never disturbs a single one of these rows while it runs.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for job_id in ('J1', 'J2', 'J3', 'J4'):
                beacon_repositories.record_background_job_succeeded(conn, job_id, now=now)
            conn.commit()
            essential_before = {
                row['job_id']: row
                for row in beacon_repositories.read_background_job_health(conn)
                if row['job_id'] in {'J1', 'J2', 'J3', 'J4'}
            }
            conn.close()

        services = SimpleNamespace(
            settings=SimpleNamespace(db_path=self.db_path),
            authority=authority,
            clock=clock,
            admission=worker_main.WorkerAdmission(),
            process_preview_requests=self.appmod.worker_process_preview_requests,
        )

        max_attempts = self.appmod.PREVIEW_MAX_ATTEMPTS
        base_seconds = self.appmod.PREVIEW_RETRY_BASE_SECONDS
        max_seconds = self.appmod.PREVIEW_RETRY_MAX_SECONDS

        for attempt in range(1, max_attempts + 1):
            with mock.patch.object(
                self.appmod, '_legacy_refresh_service_preview',
                return_value=(None, None, None, None, None, 'capture failed'),
            ):
                self.assertIs(worker_main.dispatch_callback(services, 'J6'), True)

            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    'SELECT status, attempt_count, next_attempt_ts FROM preview_requests '
                    'WHERE port=?', (port,),
                ).fetchone()
            status, attempt_count, next_attempt_ts = row
            self.assertEqual(attempt_count, attempt)

            if attempt < max_attempts:
                # Below the budget: bounded-retry-pending with real elapsed
                # backoff, and /api/services must not yet report degraded.
                expected_backoff = min(base_seconds * (2 ** (attempt - 1)), max_seconds)
                self.assertEqual(status, 'queued')
                self.assertEqual(next_attempt_ts, clock.now_ts + expected_backoff)

                api_services = self.client.get('/api/services').get_json()
                api_service = next(item for item in api_services if item['port'] == port)
                self.assertNotEqual(api_service['preview_status'], queues.PREVIEW_STATUS_DEGRADED)

                # Not claimable before the backoff elapses...
                self.assertIsNone(queues.claim_preview_for_worker(authority, now=next_attempt_ts - 1))
                # ...advance the clock exactly to next_attempt_ts for the next attempt.
                clock.now_ts = next_attempt_ts
            else:
                # Budget exhausted: a distinct terminal state, never a silent
                # extra retry and never fewer than PREVIEW_MAX_ATTEMPTS claims.
                self.assertEqual(status, queues.PREVIEW_STATUS_DEGRADED)

                api_services = self.client.get('/api/services').get_json()
                api_service = next(item for item in api_services if item['port'] == port)
                self.assertEqual(api_service['preview_status'], queues.PREVIEW_STATUS_DEGRADED)

        # The J6 exhaustion above never touched J1-J4's own durable evidence.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            essential_after = {
                row['job_id']: row
                for row in beacon_repositories.read_background_job_health(conn)
                if row['job_id'] in {'J1', 'J2', 'J3', 'J4'}
            }
            conn.close()
        self.assertEqual(essential_after, essential_before)
        for job_id in ('J1', 'J2', 'J3', 'J4'):
            self.assertEqual(essential_after[job_id]['state'], 'succeeded')


class CadenceUnderContentionTests(unittest.TestCase):
    """OPS-01: J1/J2 keep their cadence -- judged only by the product's own
    freshness_state classifier -- while cleanup, discovery, queue-drain and
    preview work all run concurrently through real, lane-isolated
    ThreadPoolExecutors built by build_scheduler.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.worker = importlib.reload(importlib.import_module('dashboard.worker'))
        self.operations = self.worker.build_worker_operations()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_essential_cadence_under_contention(self):
        now = int(time.time())
        metric_sample_seconds = 1
        settings = SimpleNamespace(db_path=self.db_path, metric_sample_seconds=metric_sample_seconds)

        lease = queues.acquire_worker_lease(
            self.db_path, 'cadence-contention-worker', now=now, lease_seconds=3_600,
        )
        authority = WorkerAuthority.from_lease(lease, self.db_path, clock=time.time)
        base_services = worker_main.build_worker_services(self.operations, settings)
        services = replace(base_services, authority=authority)

        # Build the scheduler purely to harvest its real, lane-isolated
        # executors -- driving jobs through dispatch_callback directly (not
        # APScheduler's own timing) keeps this deterministic while still
        # exercising the exact ThreadPoolExecutor objects production uses.
        # Each pool is resolved from that job's own declared `executor`
        # field, not a lane name assumed by this test: if J8 is ever
        # reassigned back onto 'metrics', `_pool_for('J8')` below resolves
        # to the very same single thread as J1/J2 and the contention this
        # test proves away comes right back.
        built_scheduler = worker_main.build_scheduler(services)

        def _pool_for(job_id):
            lane = worker_main._CALLBACKS_BY_ID[job_id].executor
            return built_scheduler._executors[lane]._pool

        cleanup_pool = _pool_for('J8')
        metrics_pool = _pool_for('J1')
        probes_pool = _pool_for('J3')
        screenshots_pool = _pool_for('J6')

        cleanup_sleep_seconds = 8
        discovery_sleep_seconds = 3

        def slow_cleanup(_authority):
            time.sleep(cleanup_sleep_seconds)
            return True

        def slow_discovery(_authority, source='scheduled'):
            time.sleep(discovery_sleep_seconds)
            return 'completed'

        cleanup_services = replace(services, cleanup_history=slow_cleanup)
        discovery_services = replace(
            services, run_discovery=slow_discovery, read_scan_state=lambda: {},
        )

        # Occupy both threads of the shared 'probes' lane with slow
        # discovery-shaped stand-ins for J7 and J9, the way a real 180s
        # discovery pass would.
        discovery_future_j7 = probes_pool.submit(
            worker_main.dispatch_callback, discovery_services, 'J7',
        )
        discovery_future_j9 = probes_pool.submit(
            worker_main.dispatch_callback, discovery_services, 'J9',
        )
        time.sleep(0.2)
        self.assertFalse(discovery_future_j7.done())
        self.assertFalse(discovery_future_j9.done())

        # J3 and J4 still dispatch while the probes lane is fully contended
        # by the two discovery stand-ins above, within their own declared
        # misfire_grace_time -- read from the inventory, not a literal here.
        j3_grace_seconds = worker_main._CALLBACKS_BY_ID['J3'].misfire_grace_time
        j4_grace_seconds = worker_main._CALLBACKS_BY_ID['J4'].misfire_grace_time
        j3_future = probes_pool.submit(worker_main.dispatch_callback, services, 'J3')
        j4_future = probes_pool.submit(worker_main.dispatch_callback, services, 'J4')
        self.assertIsNot(j4_future.result(timeout=j4_grace_seconds), False)
        self.assertIsNot(j3_future.result(timeout=j3_grace_seconds), False)

        # J5 (queue drain) and J6 (preview) round out the best-effort
        # workload named in this task's behavior; both durable queues are
        # empty, so these are quick, real polls on their own lanes.
        j5_future = probes_pool.submit(worker_main.dispatch_callback, services, 'J5')
        j6_future = screenshots_pool.submit(worker_main.dispatch_callback, services, 'J6')
        self.assertIsNot(j5_future.result(timeout=10), False)
        self.assertIsNot(j6_future.result(timeout=10), False)

        # J8's own single-thread 'cleanup' lane absorbs a deliberately slow
        # pass -- one that sleeps well past both J1's and J2's cadence.
        # Submitted immediately before the wall-clock loop below so the
        # full sleep window lines up against it: if J8 is ever reassigned
        # back onto 'metrics', this submission lands in the very same
        # single thread the loop's J1/J2 submissions queue behind.
        cleanup_future = cleanup_pool.submit(
            worker_main.dispatch_callback, cleanup_services, 'J8',
        )

        # J1 and J2 keep dispatching on their own dedicated 'metrics' lane,
        # wall-clock, for as long as J8's slow cleanup pass runs on its own
        # 'cleanup' lane. If J8 ever shares 'metrics' again, these
        # submissions queue behind it on the single thread and this
        # `.result(timeout=...)` call times out well before the cleanup
        # pass completes.
        while not cleanup_future.done():
            j1_future = metrics_pool.submit(worker_main.dispatch_callback, services, 'J1')
            j2_future = metrics_pool.submit(worker_main.dispatch_callback, services, 'J2')
            self.assertIsNot(j1_future.result(timeout=5), False)
            self.assertIsNot(j2_future.result(timeout=5), False)
            time.sleep(0.3)

        self.assertIsNot(cleanup_future.result(timeout=5), False)
        self.assertIsNot(discovery_future_j7.result(timeout=5), False)
        self.assertIsNot(discovery_future_j9.result(timeout=5), False)

        now_final = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            health = {
                row['job_id']: dict(row)
                for row in beacon_repositories.read_background_job_health(conn, limit=32)
            }

        # Assertion 4 (PROH-OPS-01-02): every dispatched best-effort job still
        # left a durable background_job_health row -- deferral is observable,
        # never silent.
        for job_id in ('J1', 'J2', 'J3', 'J4', 'J5', 'J6', 'J7', 'J8', 'J9'):
            self.assertIn(job_id, health, f'{job_id} missing from background_job_health')

        # Assertion 1.
        self.assertEqual(health['J1']['state'], 'succeeded')
        self.assertEqual(health['J2']['state'], 'succeeded')

        # Assertion 2: the oracle is freshness_state itself, fed each job's
        # own cadence read from the production inventory -- never a numeric
        # threshold invented here.
        j1_cadence_seconds = dict(worker_main._CALLBACKS_BY_ID['J1'].trigger_kwargs)['seconds']
        j1_freshness = beacon_diagnosis.freshness_state(
            now_final, health['J1']['last_success_ts'], j1_cadence_seconds,
        )
        j2_freshness = beacon_diagnosis.freshness_state(
            now_final, health['J2']['last_success_ts'], metric_sample_seconds,
        )
        self.assertIn(j1_freshness['state'], {'fresh', 'aging'})
        self.assertIn(j2_freshness['state'], {'fresh', 'aging'})

        # Branch outcome (06-RESEARCH.md assumption A2): assertion 3 above
        # (J3/J4 dispatching while the probes lane was fully contended)
        # passed without needing a dedicated 'queues' lane for J5 -- the
        # cleanup lane alone was sufficient. A2 is CONFIRMED. The lane-name
        # set below is read off the production inventory, not asserted from
        # a literal, so Branch B (a 'queues' lane) would change this set
        # itself rather than invalidate the assertion.
        lane_names = {
            callback.executor for callback in worker_main.WORKER_CALLBACK_INVENTORY
            if callback.scheduler_id
        }
        self.assertEqual(lane_names, {'metrics', 'probes', 'screenshots', 'cleanup'})


class WalModeTests(unittest.TestCase):
    """OPS-04: every connect_db() connection runs in WAL, whichever mode the
    database started in -- the rollout logic proven against synthetic
    fixtures rather than assumed from a single starting shape.
    """

    def test_connections_run_in_wal_mode_from_either_starting_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            # Starting mode 1: SQLite's own default (rollback journal) -- a
            # fresh database that has never had journal_mode touched.
            default_mode_db = Path(directory) / 'default-mode.db'
            sqlite3.connect(default_mode_db).close()
            conn = connect_db(str(default_mode_db))
            try:
                self.assertEqual(configured_journal_mode(conn), 'wal')
            finally:
                conn.close()

            # Starting mode 2: already in WAL before connect_db ever sees it.
            already_wal_db = Path(directory) / 'already-wal.db'
            with sqlite3.connect(already_wal_db) as seed:
                self.assertEqual(seed.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
            conn = connect_db(str(already_wal_db))
            try:
                self.assertEqual(configured_journal_mode(conn), 'wal')
            finally:
                conn.close()

    def test_connect_db_releases_flock_and_reraises_when_the_wal_pragma_fails(self):
        """The existing except-Exception branch covers the new PRAGMA too --
        a failure setting journal mode must still release the shared
        maintenance lease and propagate, never leave a dangling lock or a
        silently-not-WAL connection.
        """
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'wal-pragma-failure.db'
            sqlite3.connect(target).close()
            # sqlite3.Connection itself is an immutable C type and cannot be
            # monkeypatched; ManagedConnection is the plain Python subclass
            # connect_db actually instantiates (factory=ManagedConnection),
            # so patching its bound execute is both possible and exact.
            original_execute = ManagedConnection.execute

            def failing_execute(self, sql, *args, **kwargs):
                if isinstance(sql, str) and sql.startswith('PRAGMA journal_mode='):
                    raise sqlite3.OperationalError('synthetic PRAGMA failure')
                return original_execute(self, sql, *args, **kwargs)

            with mock.patch.object(ManagedConnection, 'execute', failing_execute):
                with self.assertRaises(sqlite3.OperationalError):
                    connect_db(str(target))

            # If the failure path had not released the shared lease, this
            # exclusive maintenance acquisition would be excluded by the
            # dead connection's dangling flock.
            with exclusive_database_maintenance(str(target), timeout_seconds=0):
                pass


class ConcurrentAccessTests(unittest.TestCase):
    """OPS-04: concurrent web/worker SQLite access and worker restart
    recovery under WAL -- now the default for every connect_db() connection,
    so these are genuine WAL-mode regressions, not journal-mode-agnostic
    coverage that happened to run under WAL.
    """

    def setUp(self):
        self.appmod, self.db_path = load_app()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_concurrent_web_and_worker_writers_are_corruption_free(self):
        """OPS-04 evidence for concurrent access. PROH-OPS-04-01: every write
        this stress run reports as committed is readable afterwards, and a
        write that did not commit is never reported -- or durably recorded --
        as having succeeded.
        """
        iterations_per_thread = 20
        web_thread_count = 8
        errors = []
        errors_lock = threading.Lock()
        committed_markers = set()
        committed_lock = threading.Lock()

        def web_worker(thread_index):
            try:
                for i in range(iterations_per_thread):
                    marker = f'web-{thread_index}-{i}'
                    with self.appmod._db_lock, self.appmod.database_access(self.db_path) as conn:
                        conn.execute(
                            "INSERT INTO events(ts, port, event_type, details) VALUES(?,?,?,?)",
                            (int(time.time()), 0, 'stress_probe', marker),
                        )
                        conn.commit()
                    with committed_lock:
                        committed_markers.add(marker)
            except Exception as exc:  # noqa: BLE001 -- every thread's failure must surface
                with errors_lock:
                    errors.append(exc)

        def worker_writer():
            try:
                for i in range(iterations_per_thread):
                    marker = f'worker-{i}'
                    with write_transaction(self.db_path) as conn:
                        conn.execute(
                            "INSERT INTO events(ts, port, event_type, details) VALUES(?,?,?,?)",
                            (int(time.time()), 0, 'stress_probe', marker),
                        )
                    with committed_lock:
                        committed_markers.add(marker)
            except Exception as exc:  # noqa: BLE001
                with errors_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=web_worker, args=(index,)) for index in range(web_thread_count)
        ]
        threads.append(threading.Thread(target=worker_writer))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])

        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            recorded = {
                row[0] for row in conn.execute(
                    "SELECT details FROM events WHERE event_type='stress_probe'"
                )
            }
        self.assertEqual(recorded, committed_markers)

        # Companion assertion, same PROH-OPS-04-01: a write_transaction body
        # that raises rolls back and propagates -- never a partial row.
        with self.assertRaises(sqlite3.OperationalError):
            with write_transaction(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO events(ts, port, event_type, details) VALUES(?,?,?,?)",
                    (int(time.time()), 0, 'stress_probe', 'never-committed'),
                )
                conn.execute('SELECT * FROM this_table_does_not_exist')
        with sqlite3.connect(self.db_path) as conn:
            self.assertIsNone(
                conn.execute(
                    "SELECT 1 FROM events WHERE details='never-committed'"
                ).fetchone()
            )

    def test_worker_restart_recovery_fences_the_dead_epoch(self):
        """The restart_recovery evidence 06-VALIDATION.md maps to OPS-04.

        A worker claims a preview, then a hard restart is simulated by a new
        epoch acquiring the durable worker lease without the old epoch ever
        releasing it -- the existing takeover pattern from
        tests/test_durable_queues.py and tests/test_worker_ownership_matrix.py.
        recover_queues_for_worker under the new epoch must un-claim the dead
        epoch's row, the new epoch must be able to claim and complete it, the
        dead epoch's own terminal write must be rejected and change nothing,
        and background_job_health must reflect the true outcome rather than a
        stale 'running' state.
        """
        port = 8090
        now = 1_000
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services (port, title, first_seen, last_seen, is_online) "
                "VALUES (?,?,?,?,?)",
                (port, 'Restart recovery probe', now - 120, now, 1),
            )
            conn.commit()
            conn.close()

        lease_a = queues.acquire_worker_lease(self.db_path, 'worker-a', now=now, lease_seconds=30)
        authority_a = WorkerAuthority.from_lease(lease_a, self.db_path, clock=lambda: now)
        queues.enqueue_preview(self.db_path, port, now=now)

        claim = queues.claim_preview_for_worker(authority_a, now=now, lease_seconds=60)
        self.assertIsNotNone(claim)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            beacon_repositories.record_background_job_started(conn, 'J6', now=now)
            conn.commit()
            conn.close()

        # Hard restart: worker-a's dead epoch is never released. A new epoch
        # can only acquire the durable lease once worker-a's own lease has
        # expired (lease_seconds=30 above), and this restart point is also
        # past the preview lease worker-a's claim holds (lease_seconds=60) --
        # exactly what a real crash-and-restart leaves behind.
        restart_now = now + 70
        lease_b = queues.acquire_worker_lease(
            self.db_path, 'worker-b', now=restart_now, lease_seconds=3_600,
        )
        authority_b = WorkerAuthority.from_lease(lease_b, self.db_path, clock=lambda: restart_now)

        queues.recover_queues_for_worker(authority_b, now=restart_now)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            recovered_row = conn.execute(
                'SELECT status, lease_owner FROM preview_requests WHERE id=?', (claim.request_id,),
            ).fetchone()
        self.assertEqual(recovered_row['status'], 'queued')
        self.assertIsNone(recovered_row['lease_owner'])

        successor_claim = queues.claim_preview_for_worker(authority_b, now=restart_now)
        self.assertIsNotNone(successor_claim)
        self.assertEqual(successor_claim.request_id, claim.request_id)

        with self.appmod._worker_write_transaction(authority_b, now=restart_now) as conn:
            queues.finish_preview_for_worker_in_transaction(
                conn, authority_b, successor_claim.request_id,
                revision=successor_claim.revision, status='completed', now=restart_now,
            )
            beacon_repositories.record_background_job_succeeded(conn, 'J6', now=restart_now)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            final_row = conn.execute(
                'SELECT status, lease_owner FROM preview_requests WHERE id=?', (claim.request_id,),
            ).fetchone()
        self.assertEqual(final_row['status'], 'completed')
        self.assertIsNone(final_row['lease_owner'])

        # The dead epoch is no longer the current worker authority at all --
        # its terminal write is rejected outright and changes nothing.
        with self.assertRaises(queues.LeaseLost):
            with self.appmod._worker_write_transaction(authority_a, now=restart_now) as conn:
                queues.finish_preview_for_worker_in_transaction(
                    conn, authority_a, claim.request_id,
                    revision=claim.revision, status='completed', now=restart_now,
                )

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            unchanged_row = conn.execute(
                'SELECT status FROM preview_requests WHERE id=?', (claim.request_id,),
            ).fetchone()
        self.assertEqual(unchanged_row['status'], 'completed')

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            health = {
                row['job_id']: dict(row)
                for row in beacon_repositories.read_background_job_health(conn)
            }
        self.assertEqual(health['J6']['state'], 'succeeded')


class PiLoadAcceptanceHarnessTests(unittest.TestCase):
    """OPS-07: the Pi-class load acceptance harness's oracles are the
    product's own -- proven here without needing hardware. The harness's
    own CLI paths (--self-test, --help, an unreachable-target run) are
    exercised directly by 06-06-PLAN.md's <verify> command and
    06-VALIDATION.md, not duplicated as pytest assertions here.
    """

    def test_pi_load_acceptance_oracles_are_the_products_own(self):
        # parse_compose_memory_limits reads the declared budget straight out
        # of the real docker-compose.yml -- never a duplicated constant.
        limits = pi_load_acceptance.parse_compose_memory_limits(
            Path(__file__).parent.parent / 'docker-compose.yml',
        )
        self.assertEqual(limits['worker'], 1_073_741_824)
        self.assertEqual(limits['web'], 268_435_456)

        # assert_cadence delegates the fresh/aging/stale boundary entirely to
        # freshness_state (PROH-OPS-07-01): a synthetic J1 row aged to
        # exactly four times its own cadence passes; one aged one second
        # past that boundary fails.
        settings = load_settings({})
        now = int(time.time())
        j1_cadence_seconds = beacon_diagnosis.callback_schedule_evidence(
            worker_main._CALLBACKS_BY_ID['J1'], settings,
        )['cadence_seconds']

        at_boundary = pi_load_acceptance.assert_cadence(
            {'J1': {'state': 'succeeded', 'last_success_ts': now - 4 * j1_cadence_seconds}},
            settings, now=now, required_job_ids=('J1',),
        )
        self.assertTrue(at_boundary['passed'], at_boundary['failures'])

        past_boundary = pi_load_acceptance.assert_cadence(
            {'J1': {'state': 'succeeded', 'last_success_ts': now - 4 * j1_cadence_seconds - 1}},
            settings, now=now, required_job_ids=('J1',),
        )
        self.assertFalse(past_boundary['passed'])

        # assert_resource_budget fails for a sampled RSS above the parsed
        # limit, and passes at or under it.
        over_budget = pi_load_acceptance.assert_resource_budget(
            limits['worker'] + 1, limits['worker'], role='worker',
        )
        self.assertFalse(over_budget['passed'])
        within_budget = pi_load_acceptance.assert_resource_budget(
            limits['worker'], limits['worker'], role='worker',
        )
        self.assertTrue(within_budget['passed'])

    # -- 06-07: container-derived resource-target resolution (OPS-07) --
    #
    # The harness previously resolved its resource-sampling targets by
    # scanning every process on the host for a command-line substring
    # match. On real hardware that matched an unrelated co-tenant
    # application's gunicorn master instead of Beacon's own web tier
    # (06-UAT.md "Second defect"). These tests drive the replacement --
    # resolution derived from the Beacon containers themselves via a
    # stubbed `docker inspect` seam -- without requiring docker, a
    # container, root, or Pi hardware.

    def test_container_root_pid_resolves_from_successful_inspect(self):
        stub_runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout='4242\n', stderr='',
        ))
        pid, reason = pi_load_acceptance._container_root_pid('beacon-web', runner=stub_runner)
        self.assertEqual(pid, 4242)
        self.assertIsNone(reason)
        stub_runner.assert_called_once()
        invoked_argv = stub_runner.call_args[0][0]
        self.assertEqual(invoked_argv[:2], ['docker', 'inspect'])
        self.assertIn('beacon-web', invoked_argv)

    def test_container_root_pid_fails_on_nonzero_return_code(self):
        stub_runner = mock.Mock(return_value=SimpleNamespace(
            returncode=1, stdout='', stderr='Error: No such object: beacon-web',
        ))
        pid, reason = pi_load_acceptance._container_root_pid('beacon-web', runner=stub_runner)
        self.assertIsNone(pid)
        self.assertIsNotNone(reason)
        self.assertIn('beacon-web', reason)

    def test_container_root_pid_fails_when_docker_binary_absent(self):
        stub_runner = mock.Mock(side_effect=FileNotFoundError('docker'))
        pid, reason = pi_load_acceptance._container_root_pid('beacon-web', runner=stub_runner)
        self.assertIsNone(pid)
        self.assertIsNotNone(reason)

    def test_container_root_pid_fails_on_timeout(self):
        stub_runner = mock.Mock(
            side_effect=subprocess.TimeoutExpired(cmd='docker', timeout=10),
        )
        pid, reason = pi_load_acceptance._container_root_pid('beacon-web', runner=stub_runner)
        self.assertIsNone(pid)
        self.assertIsNotNone(reason)

    def test_container_root_pid_fails_on_unparseable_output(self):
        stub_runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout='not-a-pid\n', stderr='',
        ))
        pid, reason = pi_load_acceptance._container_root_pid('beacon-web', runner=stub_runner)
        self.assertIsNone(pid)
        self.assertIsNotNone(reason)

    def test_container_root_pid_fails_on_reported_pid_zero(self):
        # Docker reports PID 0 for a container that exists but is not
        # currently running -- must never be mistaken for a valid target.
        stub_runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout='0\n', stderr='',
        ))
        pid, reason = pi_load_acceptance._container_root_pid('beacon-web', runner=stub_runner)
        self.assertIsNone(pid)
        self.assertIsNotNone(reason)

    def test_container_root_pid_rejects_invalid_name_before_any_runner_call(self):
        stub_runner = mock.Mock()
        with self.assertRaises(ValueError):
            pi_load_acceptance._container_root_pid('beacon-web; rm -rf /', runner=stub_runner)
        stub_runner.assert_not_called()

    def test_resolve_container_process_tree_returns_root_and_children(self):
        current_pid = os.getpid()
        stub_runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=f'{current_pid}\n', stderr='',
        ))
        processes, reason = pi_load_acceptance.resolve_container_process_tree(
            'beacon-web', runner=stub_runner,
        )
        self.assertIsNone(reason)
        self.assertTrue(processes)
        self.assertEqual(processes[0].pid, current_pid)

    def test_resolve_container_process_tree_propagates_inspect_failure(self):
        stub_runner = mock.Mock(return_value=SimpleNamespace(
            returncode=1, stdout='', stderr='Error: No such object',
        ))
        processes, reason = pi_load_acceptance.resolve_container_process_tree(
            'beacon-web', runner=stub_runner,
        )
        self.assertEqual(processes, [])
        self.assertIsNotNone(reason)

    def test_resource_targets_self_test_returns_current_process_for_both_roles(self):
        targets = pi_load_acceptance._resource_targets(self_test=True)
        current_pid = os.getpid()
        self.assertEqual(targets['worker'].root_pid, current_pid)
        self.assertEqual(targets['web'].root_pid, current_pid)
        self.assertIsNone(targets['worker'].reason)
        self.assertIsNone(targets['web'].reason)
        self.assertEqual(targets['worker'].method, 'self_test')

    def test_resource_targets_acceptance_resolves_from_containers(self):
        current_pid = os.getpid()

        def fake_runner(argv, **kwargs):
            name = argv[-1]
            pid = current_pid if name == 'beacon-web' else current_pid
            return SimpleNamespace(returncode=0, stdout=f'{pid}\n', stderr='')

        targets = pi_load_acceptance._resource_targets(
            self_test=False, runner=fake_runner,
        )
        self.assertIsNone(targets['worker'].reason)
        self.assertIsNone(targets['web'].reason)
        self.assertEqual(targets['worker'].container, 'beacon-worker')
        self.assertEqual(targets['web'].container, 'beacon-web')
        self.assertEqual(targets['worker'].method, 'docker_container_tree')

    def test_resource_targets_acceptance_names_reason_when_unresolved(self):
        stub_runner = mock.Mock(return_value=SimpleNamespace(
            returncode=1, stdout='', stderr='Error: No such object',
        ))
        targets = pi_load_acceptance._resource_targets(self_test=False, runner=stub_runner)
        self.assertIsNotNone(targets['worker'].reason)
        self.assertIsNotNone(targets['web'].reason)
        self.assertEqual(targets['worker'].processes, [])
        self.assertEqual(targets['web'].processes, [])

    # -- 06-07 Task 2: an unresolvable role is an honest, run-failing outcome --
    #
    # Under the old command-line matcher both roles resolved to *some*
    # process (even if the wrong one), so the previous `all(proc is None
    # ...)` guard never fired in practice. Under container resolution a
    # partial failure -- one role resolved, one not -- becomes the
    # realistic case, and that guard would let it pass silently. These
    # tests drive the per-role replacement directly.

    def test_resource_unavailable_reason_none_when_resolved_and_sampled(self):
        target = pi_load_acceptance.ResourceTarget(
            role='worker', container='beacon-worker', method='docker_container_tree',
            root_pid=4242, processes=[object()], reason=None,
        )
        reason = pi_load_acceptance._resource_unavailable_reason('worker', target, sample_count=3)
        self.assertIsNone(reason)

    def test_resource_unavailable_reason_names_role_and_cause_when_unresolved(self):
        target = pi_load_acceptance.ResourceTarget(
            role='web', container='beacon-web', method='docker_container_tree',
            root_pid=None, processes=[], reason='beacon-web: docker binary not found',
        )
        reason = pi_load_acceptance._resource_unavailable_reason('web', target, sample_count=0)
        self.assertIsNotNone(reason)
        self.assertIn('web', reason)
        self.assertIn('docker binary not found', reason)

    def test_resource_unavailable_reason_explains_absence_when_resolved_but_unsampled(self):
        target = pi_load_acceptance.ResourceTarget(
            role='worker', container='beacon-worker', method='docker_container_tree',
            root_pid=4242, processes=[object()], reason=None,
        )
        reason = pi_load_acceptance._resource_unavailable_reason('worker', target, sample_count=0)
        self.assertIsNotNone(reason)
        self.assertIn('worker', reason)
        self.assertIn('beacon-worker', reason)

    def test_resource_unavailable_reason_both_roles_unresolved_yields_two_distinct_reasons(self):
        worker_target = pi_load_acceptance.ResourceTarget(
            role='worker', container='beacon-worker', method='docker_container_tree',
            root_pid=None, processes=[], reason='beacon-worker: docker binary not found',
        )
        web_target = pi_load_acceptance.ResourceTarget(
            role='web', container='beacon-web', method='docker_container_tree',
            root_pid=None, processes=[], reason='beacon-web: docker binary not found',
        )
        worker_reason = pi_load_acceptance._resource_unavailable_reason(
            'worker', worker_target, sample_count=0,
        )
        web_reason = pi_load_acceptance._resource_unavailable_reason('web', web_target, sample_count=0)
        self.assertIsNotNone(worker_reason)
        self.assertIsNotNone(web_reason)
        self.assertNotEqual(worker_reason, web_reason)
        self.assertIn('worker', worker_reason)
        self.assertIn('web', web_reason)

    def test_run_acceptance_fails_when_one_role_unresolved_but_other_resolves(self):
        # Under the OLD `all(proc is None ...)` guard this scenario -- one
        # role resolved, one not -- would pass silently: `all()` requires
        # BOTH to be unresolved. That is precisely the defect this task
        # closes: one role resolving must never excuse the other. Patches
        # resolve_container_process_tree directly (rather than
        # subprocess.run) because _container_root_pid's `runner`
        # parameter defaults to `subprocess.run` bound at def time, so
        # patching the module attribute afterward would not reach calls
        # made through that default.
        appmod, db_path = load_app()
        try:
            now = int(time.time())
            with appmod._db_lock:
                conn = appmod.get_db()
                for job_id in pi_load_acceptance.ESSENTIAL_JOB_IDS:
                    beacon_repositories.record_background_job_succeeded(conn, job_id, now=now)
                conn.commit()
                conn.close()

            from werkzeug.serving import make_server
            server = make_server('127.0.0.1', 0, appmod.app, threaded=True)
            server_port = server.server_address[1]
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            try:
                current_process = psutil.Process()

                def one_role_resolves(name, *, runner=None):
                    if name == 'beacon-worker':
                        return [current_process], None
                    return [], 'beacon-web: docker inspect failed (rc=1): no such object'

                scenario = pi_load_acceptance.LoadScenario(
                    duration_seconds=1,
                    base_url=f'http://127.0.0.1:{server_port}',
                    db_path=db_path,
                    concurrency=1,
                    self_test=False,
                )
                with mock.patch.object(
                    pi_load_acceptance, 'resolve_container_process_tree',
                    side_effect=one_role_resolves,
                ):
                    report = pi_load_acceptance.run_acceptance(scenario)
            finally:
                server.shutdown()
                server_thread.join(timeout=5)
        finally:
            cleanup_db(db_path)

        self.assertFalse(report.overall_passed)
        web_reasons = [
            r for r in report.failure_reasons if 'web' in r and 'resource oracle unavailable' in r
        ]
        self.assertTrue(web_reasons, report.failure_reasons)
        self.assertFalse(
            any('worker' in r and 'resource oracle unavailable' in r for r in report.failure_reasons),
            report.failure_reasons,
        )


if __name__ == '__main__':
    unittest.main()
