import json
import fcntl
import sqlite3
import tempfile
import unittest
from pathlib import Path
from shutil import copy2
from unittest import mock

from dashboard.beacon.config import Settings
from dashboard.beacon.migrations import create_verified_backup, run_migrations
from dashboard.beacon.recovery import RecoveryError, list_verified_backups, restore_backup


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
