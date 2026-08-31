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
"""

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from shutil import copy2
from unittest import mock

from dashboard.beacon.config import Settings
from dashboard.beacon.migrations import MIGRATIONS, run_migrations
from dashboard.beacon.repositories import ThumbnailStoreRepository
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


if __name__ == '__main__':
    unittest.main()
