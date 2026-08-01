import json
import fcntl
import sqlite3
import os
import subprocess
import sys
import tempfile
import threading
import time
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

    def _write_recovery_marker(self, database, backup, *, target_version=1, **overrides):
        payload = {
            'failed_target_version': target_version,
            'reason_class': 'MigrationPreparationError',
            'backup_catalog_id': backup.name,
            'timestamp': int(time.time()),
        }
        payload.update(overrides)
        (database.parent / 'recovery-required.json').write_text(
            json.dumps(payload),
            encoding='utf-8',
        )

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
            self._write_recovery_marker(database, backup)

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
            self._write_recovery_marker(database, backup)
            first = restore_backup(database.parent, backup.name)
            restored = database.read_bytes()
            with self.assertRaisesRegex(RecoveryError, 'recovery is not authorized'):
                restore_backup(database.parent, backup.name)
            self.assertEqual(database.read_bytes(), restored)
            self.assertEqual(first.catalog_id, backup.name)
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
            self._write_recovery_marker(database, backup)

            with mock.patch('dashboard.beacon.recovery.os.replace', side_effect=OSError('interrupted')):
                with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                    restore_backup(database.parent, backup.name)

            self.assertEqual(database.read_bytes(), original)
            self.assertFalse(list(database.parent.glob('.dashboard.db.restore-*.partial')))

    def test_restore_rejects_live_worker_lock_and_unsafe_catalog_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            self._write_recovery_marker(database, backup)
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

            self._write_recovery_marker(database, latest, target_version=3)
            with self.assertRaisesRegex(RecoveryError, 'recovery is not authorized'):
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
            self._write_recovery_marker(database, backup)

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
            self._write_recovery_marker(database, backup)
            with sqlite3.connect(database) as writer:
                writer.execute('PRAGMA journal_mode=WAL')
                writer.execute("UPDATE services SET title='newer-wal-state'")
                writer.commit()
                reader = sqlite3.connect(database)
                try:
                    reader.execute('BEGIN')
                    reader.execute('SELECT title FROM services').fetchone()
                    with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                        restore_backup(database.parent, backup.name)
                    with sqlite3.connect(database) as conn:
                        self.assertEqual(
                            conn.execute('SELECT title FROM services').fetchone()[0],
                            'newer-wal-state',
                        )
                    self.assertFalse(list(database.parent.glob('.dashboard.db.restore-*.partial')))
                finally:
                    reader.close()

    def test_restore_fsyncs_stage_sidecar_replacement_and_marker_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            self._write_recovery_marker(database, backup)
            recovery = __import__('dashboard.beacon.recovery', fromlist=['_fsync_directory'])
            with mock.patch('dashboard.beacon.recovery.os.fsync', wraps=os.fsync) as sync, mock.patch(
                'dashboard.beacon.recovery._fsync_directory',
                wraps=recovery._fsync_directory,
            ) as sync_directory:
                restore_backup(database.parent, backup.name)

            self.assertGreaterEqual(sync.call_count, 4)
            self.assertGreaterEqual(sync_directory.call_count, 5)

    def test_sidecar_cleanup_or_staging_failure_cannot_replace_target(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            original = database.read_bytes()
            self._write_recovery_marker(database, backup)
            with mock.patch(
                'dashboard.beacon.recovery._checkpoint_and_remove_sidecars',
                side_effect=RecoveryError('restore did not complete'),
            ), mock.patch('dashboard.beacon.recovery.os.replace') as replace:
                with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                    restore_backup(database.parent, backup.name)
            replace.assert_not_called()
            self.assertEqual(database.read_bytes(), original)

            with mock.patch(
                'dashboard.beacon.recovery._copy_and_fsync',
                side_effect=OSError('staging unavailable'),
            ), mock.patch('dashboard.beacon.recovery.os.replace') as replace:
                with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                    restore_backup(database.parent, backup.name)
            replace.assert_not_called()
            self.assertEqual(database.read_bytes(), original)

    def test_interruption_after_replace_leaves_verified_database_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            marker = database.parent / 'recovery-required.json'
            self._write_recovery_marker(database, backup)
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

            restore_backup(database.parent, backup.name)
            self.assertFalse(marker.exists())

    def test_restore_without_marker_refuses_before_database_or_sidecar_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            wal = Path(str(database) + '-wal')
            shm = Path(str(database) + '-shm')
            with sqlite3.connect(database) as conn:
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute("UPDATE services SET title='healthy current'")
                conn.commit()
            original = database.read_bytes()
            original_wal = wal.read_bytes()
            original_shm = shm.read_bytes()

            with mock.patch(
                'dashboard.beacon.recovery._checkpoint_and_remove_sidecars',
            ) as checkpoint, mock.patch(
                'dashboard.beacon.recovery._acquire_upgrade_lock',
            ) as acquire_lock:
                with self.assertRaisesRegex(RecoveryError, 'recovery is not authorized'):
                    restore_backup(database.parent, backup.name)

            checkpoint.assert_not_called()
            acquire_lock.assert_not_called()
            self.assertEqual(database.read_bytes(), original)
            self.assertEqual(wal.read_bytes(), original_wal)
            self.assertEqual(shm.read_bytes(), original_shm)
            self.assertFalse((database.parent / 'recovery-required.json').exists())

    def test_restore_rejects_invalid_marker_matrix_without_mutation(self):
        invalid_payloads = (
            {},
            {'failed_target_version': True, 'reason_class': 'failure', 'backup_catalog_id': 'x', 'timestamp': 1},
            {'failed_target_version': 1, 'reason_class': '', 'backup_catalog_id': 'x', 'timestamp': 1},
            {'failed_target_version': 1, 'reason_class': 'failure', 'backup_catalog_id': None, 'timestamp': 1},
            {'failed_target_version': 1, 'reason_class': 'failure', 'backup_catalog_id': 'x', 'timestamp': 0},
            {'failed_target_version': 1, 'reason_class': 'failure', 'backup_catalog_id': 'x', 'timestamp': int(time.time()) + 60},
            {'failed_target_version': 1, 'reason_class': 'failure', 'backup_catalog_id': 'x', 'timestamp': 1, 'extra': True},
        )
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            original = database.read_bytes()
            marker = database.parent / 'recovery-required.json'
            for payload in invalid_payloads:
                with self.subTest(payload=payload):
                    marker.write_text(json.dumps(payload), encoding='utf-8')
                    with self.assertRaisesRegex(RecoveryError, 'recovery is not authorized'):
                        restore_backup(database.parent, backup.name)
                    self.assertEqual(database.read_bytes(), original)

    def test_restore_requires_exact_marker_catalog_and_current_pre_version(self):
        with tempfile.TemporaryDirectory() as directory:
            database, backup = self._backup_from_fixture(directory)
            other = create_verified_backup(database, target_version=1)
            original = database.read_bytes()
            self._write_recovery_marker(database, backup)
            with self.assertRaisesRegex(RecoveryError, 'recovery is not authorized'):
                restore_backup(database.parent, other.name)
            self.assertEqual(database.read_bytes(), original)

            with sqlite3.connect(database) as conn:
                conn.execute('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)')
                conn.execute('INSERT INTO schema_migrations(version) VALUES(1)')
            with self.assertRaisesRegex(RecoveryError, 'recovery is not authorized'):
                restore_backup(database.parent, backup.name)

    def test_stale_worker_metadata_writer_blocks_restore_until_commit(self):
        """The maintenance lease, not heartbeat freshness, excludes web writes."""
        appmod, loaded_database = load_app()
        entered_write = threading.Event()
        release_write = threading.Event()
        original_upsert = appmod.beacon_repositories.upsert_service_metadata
        cleanup_db(loaded_database)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'dashboard.db'
            copy2(FIXTURE, database)
            appmod.DB_PATH = str(database)
            backup = create_verified_backup(database, target_version=1)
            self._write_recovery_marker(database, backup, timestamp=1)
            with sqlite3.connect(database) as conn:
                conn.execute(
                    'CREATE TABLE runtime_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_ts INTEGER NOT NULL)'
                )
                conn.execute(
                    "CREATE TABLE service_meta (port INTEGER PRIMARY KEY, display_name TEXT, url TEXT, "
                    "critical INTEGER DEFAULT 0, pinned_order INTEGER DEFAULT 0, tags TEXT DEFAULT '', "
                    "healthy_statuses TEXT DEFAULT '200-399')"
                )
                conn.execute(
                    "CREATE TABLE preview_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, port INTEGER NOT NULL, "
                    "requested_ts INTEGER NOT NULL, deadline_ts INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued', "
                    "error TEXT, revision INTEGER NOT NULL DEFAULT 1, lease_owner TEXT, lease_until INTEGER, "
                    "attempt_count INTEGER NOT NULL DEFAULT 0, started_ts INTEGER, completed_ts INTEGER, "
                    "terminal_ts INTEGER, result TEXT)"
                )
                conn.execute(
                    'CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, '
                    'port INTEGER, event_type TEXT NOT NULL, online INTEGER, previous_online INTEGER, '
                    'latency_ms REAL, error_class TEXT, alert_status TEXT, details TEXT)'
                )
            writer = None
            try:
                appmod._set_runtime_state('worker_heartbeat', {'ts': 0}, now=0)

                def blocked_upsert(*args, **kwargs):
                    entered_write.set()
                    self.assertTrue(release_write.wait(2))
                    return original_upsert(*args, **kwargs)

                appmod.beacon_repositories.upsert_service_metadata = blocked_upsert
                result = {}

                def submit_metadata(name):
                    result[name] = appmod.app.test_client().put(
                        '/api/service-meta/8080',
                        json={'display_name': name, 'url': 'http://127.0.0.1:8080'},
                        headers={'X-Beacon-UI': '1'},
                    )

                writer = threading.Thread(target=submit_metadata, args=('Blocked write',))
                writer.start()
                self.assertTrue(entered_write.wait(2))
                with mock.patch(
                    'dashboard.beacon.recovery._checkpoint_and_remove_sidecars',
                ) as checkpoint, mock.patch('dashboard.beacon.recovery.os.replace') as replace:
                    with self.assertRaisesRegex(RecoveryError, 'restore did not complete'):
                        restore_backup(
                            database.parent,
                            backup.name,
                            now=lambda: 1_000_000,
                            lock_timeout_seconds=0,
                        )
                checkpoint.assert_not_called()
                replace.assert_not_called()

                release_write.set()
                writer.join(timeout=2)
                self.assertFalse(writer.is_alive())
                self.assertEqual(result['Blocked write'].status_code, 200)

                restore_backup(database.parent, backup.name, now=lambda: 1_000_000)
                appmod.init_db()
                submit_metadata('Restored write')
                self.assertEqual(result['Restored write'].status_code, 200)
                with sqlite3.connect(database) as conn:
                    self.assertEqual(
                        conn.execute(
                            'SELECT display_name FROM service_meta WHERE port=8080'
                        ).fetchone()[0],
                        'Restored write',
                    )
            finally:
                release_write.set()
                if writer is not None:
                    writer.join(timeout=2)
                appmod.beacon_repositories.upsert_service_metadata = original_upsert
