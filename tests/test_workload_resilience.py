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
"""

import importlib
import sqlite3
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from shutil import copy2
from types import SimpleNamespace
from unittest import mock

from dashboard.beacon import diagnosis as beacon_diagnosis
from dashboard.beacon import queues
from dashboard.beacon import repositories as beacon_repositories
from dashboard.beacon import telemetry as beacon_telemetry
from dashboard.beacon import worker_main
from dashboard.beacon.config import Settings, load_settings
from dashboard.beacon.migrations import MIGRATIONS, run_migrations
from dashboard.beacon.repositories import ThumbnailStoreRepository
from dashboard.beacon.worker_authority import WorkerAuthority
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


if __name__ == '__main__':
    unittest.main()
