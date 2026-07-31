import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from shutil import copy2

from dashboard.beacon.config import Settings
from dashboard.beacon.migrations import create_verified_backup, run_migrations


FIXTURE = Path(__file__).parent / 'fixtures' / 'legacy' / 'initial-2026-04.db'


class BackupRecoveryTests(unittest.TestCase):
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
