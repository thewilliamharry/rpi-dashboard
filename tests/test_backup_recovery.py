import json
import fcntl
import sqlite3
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from shutil import copy2
from unittest import mock

from dashboard.beacon.config import Settings
from dashboard.beacon import db
from dashboard.beacon.migrations import create_verified_backup, run_migrations
from dashboard.beacon.recovery import RecoveryError, list_verified_backups, restore_backup
from tests.helpers import cleanup_db, load_app


FIXTURE = Path(__file__).parent / 'fixtures' / 'legacy' / 'initial-2026-04.db'


class BackupRecoveryTests(unittest.TestCase):
    def _backup_from_fixture(self, directory, filename='initial-2026-04.db'):
        database = Path(directory) / 'dashboard.db'
        copy2(Path(__file__).parent / 'fixtures' / 'legacy' / filename, database)
        backup = create_verified_backup(database, target_version=1)
        return database, backup

    def test_online_backup_is_verified_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'dashboard.db'
            copy2(FIXTURE, database)
            backup = create_verified_backup(database, target_version=1)
            self.assertFalse(backup.name.endswith('.partial'))
            with sqlite3.connect(backup) as conn:
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM services').fetchone()[0], 1)

    def test_repeated_automatic_backups_are_unique_and_retained_at_three(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'dashboard.db'
            copy2(FIXTURE, database)
            backups = [create_verified_backup(database, target_version=1) for _ in range(5)]
            retained = sorted((database.parent / 'backups').glob('*.db'))
            self.assertEqual(len(retained), 3)
            self.assertEqual(len({backup.name for backup in backups}), 5)
            self.assertFalse(list((database.parent / 'backups').glob('*.partial')))

    def test_successful_migration_clears_existing_recovery_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'dashboard.db'
            copy2(FIXTURE, database)
            marker = database.parent / 'recovery-required.json'
            marker.write_text(json.dumps({'failed_target_version': 1}))
            run_migrations(Settings(db_path=str(database)))
            self.assertFalse(marker.exists())

    def test_restore_latest_uses_verified_catalog_and_returns_safe_result(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            with sqlite3.connect(database) as conn:
                conn.execute("UPDATE services SET title='changed after backup'")
            (database.parent / 'recovery-required.json').write_text('{}', encoding='utf-8')

            records = list_verified_backups(database.parent)
            self.assertEqual([record.catalog_id for record in records], [backup.name])
            result = restore_backup(database.parent, records[-1].catalog_id)

            self.assertTrue(result.completed)
            self.assertEqual(result.catalog_id, backup.name)
            self.assertIsInstance(result.backup_timestamp, str)
            self.assertEqual(len(result.schema_fingerprint), 64)
            self.assertFalse((database.parent / 'recovery-required.json').exists())
            with sqlite3.connect(database) as conn:
                self.assertEqual(conn.execute('SELECT title FROM services').fetchone()[0], 'Sample Service')
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_restoring_same_catalog_twice_preserves_representative_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory, 'metadata-events-2026-04.db')
            before = {
                table: sqlite3.connect(backup).execute(
                    'SELECT COUNT(*) FROM {}'.format(table)
                ).fetchone()[0]
                for table in ('services', 'service_meta', 'events')
            }
            first = restore_backup(database.parent, backup.name)
            second = restore_backup(database.parent, backup.name)
            self.assertEqual(first.catalog_id, second.catalog_id)
            with sqlite3.connect(database) as conn:
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(
                    {table: conn.execute('SELECT COUNT(*) FROM {}'.format(table)).fetchone()[0]
                     for table in before},
                    before,
                )

    def test_interruption_before_replace_keeps_original_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            with sqlite3.connect(database) as conn:
                conn.execute("UPDATE services SET title='live database'")
            original = database.read_bytes()

            with mock.patch('dashboard.beacon.recovery.os.replace', side_effect=OSError('interrupted')):
                with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                    restore_backup(database.parent, backup.name)

            self.assertEqual(database.read_bytes(), original)
            self.assertFalse(list(database.parent.glob('.dashboard.db.restore-*.partial')))

    def test_restore_rejects_live_worker_lock_and_unsafe_catalog_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            with sqlite3.connect(database) as conn:
                conn.execute(
                    'CREATE TABLE runtime_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_ts INTEGER NOT NULL)'
                )
                conn.execute(
                    "INSERT INTO runtime_state VALUES ('worker_heartbeat', ?, 0)",
                    (json.dumps({'ts': 4_102_444_800}),),
                )
            with self.assertRaisesRegex(RecoveryError, 'stop Beacon services'):
                restore_backup(database.parent, backup.name, now=lambda: 4_102_444_800)

            with sqlite3.connect(database) as conn:
                conn.execute("DELETE FROM runtime_state WHERE key='worker_heartbeat'")
            lock_path = database.parent / '.beacon-upgrade.lock'
            with lock_path.open('a+') as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(RecoveryError, 'another upgrade or recovery'):
                    restore_backup(database.parent, backup.name, lock_timeout_seconds=0)

            escaped = database.parent / 'outside.db'
            escaped.write_bytes(backup.read_bytes())
            (database.parent / 'backups' / 'dashboard-20260101T000000000000Z-forged-pre-v1.db').symlink_to(escaped)
            (database.parent / 'backups' / 'dashboard-20260101T000000000001Z-corrupt-pre-v1.db').write_bytes(b'bad')
            with self.assertRaises(RecoveryError):
                restore_backup(database.parent, '../outside.db')
            with self.assertRaises(RecoveryError):
                restore_backup(database.parent, 'dashboard-20260101T000000000000Z-forged-pre-v1.db')
            with self.assertRaises(RecoveryError):
                restore_backup(database.parent, 'dashboard-20260101T000000000001Z-corrupt-pre-v1.db')

    def test_recovery_cli_restores_latest_catalog_without_a_path_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            database, _ = self._backup_from_fixture(directory)
            with sqlite3.connect(database) as conn:
                conn.execute("UPDATE services SET title='changed after backup'")
            result = subprocess.run(
                [sys.executable, '-m', 'beacon.recovery', 'restore', '--latest'],
                env={**os.environ, 'PYTHONPATH': 'dashboard', 'DB_PATH': str(database)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['completed'])
            with sqlite3.connect(database) as conn:
                self.assertEqual(conn.execute('SELECT title FROM services').fetchone()[0], 'Sample Service')

    def test_latest_verified_automatic_migration_backup_is_restoreable(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'dashboard.db'
            copy2(FIXTURE, database)
            run_migrations(Settings(db_path=str(database)))
            records = list_verified_backups(database.parent)
            self.assertEqual(len(records), 3)
            latest = records[-1]
            with sqlite3.connect(database) as conn:
                conn.execute("UPDATE services SET title='post-upgrade change'")

            restore_backup(database.parent, latest.catalog_id)

            with sqlite3.connect(database) as conn:
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(conn.execute('SELECT title FROM services').fetchone()[0], 'Sample Service')

    def test_managed_connection_blocks_exclusive_maintenance_until_close(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'dashboard.db'
            connection = db.connect_db(database)
            entered = []
            try:
                with self.assertRaises(db.MaintenanceBusy):
                    with db.exclusive_database_maintenance(database, timeout_seconds=0):
                        entered.append(True)
                self.assertEqual(entered, [])
            finally:
                connection.close()

            with db.exclusive_database_maintenance(database, timeout_seconds=0):
                entered.append(True)
            self.assertEqual(entered, [True])

    def test_open_flask_metadata_transaction_excludes_maintenance(self):
        appmod, database = load_app()
        entered_write = threading.Event()
        release_write = threading.Event()
        original_upsert = appmod.beacon_repositories.upsert_service_metadata
        try:
            with appmod._db_lock:
                conn = appmod.get_db()
                conn.execute(
                    "INSERT INTO services(port, title, first_seen, last_seen, is_online) VALUES(?,?,?,?,?)",
                    (8080, 'Demo', 1, 1, 1),
                )
                conn.commit()
                conn.close()

            def blocked_upsert(*args, **kwargs):
                entered_write.set()
                self.assertTrue(release_write.wait(2))
                return original_upsert(*args, **kwargs)

            appmod.beacon_repositories.upsert_service_metadata = blocked_upsert
            result = {}

            def submit_metadata():
                result['response'] = appmod.app.test_client().put(
                    '/api/service-meta/8080',
                    json={'display_name': 'Blocked write', 'url': 'http://127.0.0.1:8080'},
                    headers={'X-Beacon-UI': '1'},
                )

            writer = threading.Thread(target=submit_metadata)
            writer.start()
            self.assertTrue(entered_write.wait(2))
            with self.assertRaises(db.MaintenanceBusy):
                with db.exclusive_database_maintenance(database, timeout_seconds=0):
                    self.fail('maintenance entered while metadata was uncommitted')
            release_write.set()
            writer.join(timeout=2)
            self.assertFalse(writer.is_alive())
            self.assertEqual(result['response'].status_code, 200)
            with db.exclusive_database_maintenance(database, timeout_seconds=0):
                pass
        finally:
            appmod.beacon_repositories.upsert_service_metadata = original_upsert
            cleanup_db(database)

    def test_restore_discards_retained_wal_and_shm_before_replacement(self):
        """A WAL captured after the backup must not replay over the replacement."""
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            wal = Path(str(database) + '-wal')
            shm = Path(str(database) + '-shm')
            retained_wal = database.parent / 'retained-wal'
            retained_shm = database.parent / 'retained-shm'
            with sqlite3.connect(database) as writer:
                self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
                writer.execute("UPDATE services SET title='live-wal-state'")
                writer.commit()
                copy2(wal, retained_wal)
                copy2(shm, retained_shm)
            copy2(retained_wal, wal)
            copy2(retained_shm, shm)

            restore_backup(database.parent, backup.name)

            self.assertFalse(wal.exists())
            self.assertFalse(shm.exists())
            with sqlite3.connect(database) as conn:
                self.assertEqual(
                    conn.execute('SELECT title FROM services').fetchone()[0],
                    'Sample Service',
                )

    def test_restore_refuses_busy_wal_checkpoint_before_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            with sqlite3.connect(database) as writer:
                writer.execute('PRAGMA journal_mode=WAL')
                writer.execute("UPDATE services SET title='newer-wal-state'")
                writer.commit()
                reader = sqlite3.connect(database)
                try:
                    reader.execute('BEGIN')
                    reader.execute('SELECT title FROM services').fetchone()
                    original = database.read_bytes()
                    with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                        restore_backup(database.parent, backup.name)
                    self.assertEqual(database.read_bytes(), original)
                finally:
                    reader.close()

    def test_interruption_after_replace_leaves_verified_database_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            marker = database.parent / 'recovery-required.json'
            marker.write_text('{}', encoding='utf-8')
            original_validate = __import__(
                'dashboard.beacon.recovery', fromlist=['_validate_supported_database'],
            )._validate_supported_database
            calls = []

            def interrupt_after_replacement(path, catalog_id=None):
                calls.append(Path(path))
                if Path(path) == database and len(calls) > 1:
                    raise OSError('interrupted after replacement')
                return original_validate(path, catalog_id)

            with mock.patch(
                'dashboard.beacon.recovery._validate_supported_database',
                side_effect=interrupt_after_replacement,
            ):
                with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                    restore_backup(database.parent, backup.name)

            with sqlite3.connect(database) as conn:
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(
                    conn.execute('SELECT title FROM services').fetchone()[0],
                    'Sample Service',
                )
            self.assertTrue(marker.exists())
