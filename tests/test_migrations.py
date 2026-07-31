import json
import multiprocessing
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from shutil import copy2
from unittest import mock
from pathlib import Path

from dashboard.beacon.config import Settings
from dashboard.beacon.db import prepare_database
from dashboard.beacon.inventory import InventoryError, classify_schema, collect_inventory
from dashboard.beacon.migrations import (
    MIGRATIONS,
    Migration,
    MigrationPreparationError,
    UnsupportedSchemaError,
    run_migrations,
)


FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'legacy'
OPERATOR_FIXTURE_DIR = FIXTURE_DIR / 'operator'
FIXTURES = {
    'initial-2026-04.db': {'services', 'service_checks', 'stats_history'},
    'metadata-events-2026-04.db': {'services', 'service_meta', 'events'},
    'runtime-queues-2026-07.db': {
        'schema_migrations',
        'runtime_state',
        'scan_requests',
        'preview_requests',
    },
}
EXPECTED_FINGERPRINTS = {
    'initial-2026-04.db': '4330feaa6a22043681d7d55fec900b3279fec9302f68e41417df29653c7cf906',
    'metadata-events-2026-04.db': '8ac9833951d13e2b02deffd4be57f0bec8ce9e8d4771224d1a0fbbc07274abef',
    'runtime-queues-2026-07.db': '791e5c1d380fb38b62e8c284349affb248acfaf5dbbd0e93a07b929b2ef59c91',
}


def _run_migration_process(db_path, start_event, result_queue):
    """Run in a separate process so flock exercises the production lock boundary."""
    start_event.wait(timeout=5)
    result_queue.put(run_migrations(Settings(db_path=db_path)).applied_versions)


class MigrationTests(unittest.TestCase):
    """The migration floor must retain legacy data while becoming current once."""

    def _copied_fixture(self, directory, filename):
        target = Path(directory) / filename
        copy2(FIXTURE_DIR / filename, target)
        return target

    def test_support_floor_covers_history_and_confirmed_operator_evidence(self):
        manifest = json.loads((FIXTURE_DIR / 'support-floor.json').read_text(encoding='utf-8'))
        supported = {entry['fingerprint']: entry for entry in manifest['supported_schemas']}
        expected = set(EXPECTED_FINGERPRINTS.values()) | {
            json.loads((OPERATOR_FIXTURE_DIR / 'production.json').read_text())['schema_fingerprint'],
        }
        self.assertEqual(set(supported), expected)
        for entry in supported.values():
            self.assertIn('fixture', entry)
            self.assertIn('source', entry)
            self.assertIn('minimum_schema_version', entry)
            self.assertEqual(entry['target_version'], MIGRATIONS[-1].version)

    def test_each_supported_fixture_upgrades_once_preserving_representative_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename in (*FIXTURES, 'operator/production.db'):
                source_name = filename.replace('/', '-')
                source = FIXTURE_DIR / filename
                target = Path(directory) / source_name
                copy2(source, target)
                with sqlite3.connect(target) as before_conn:
                    service_rows = before_conn.execute('SELECT COUNT(*) FROM services').fetchone()[0]
                    event_rows = (
                        before_conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
                        if 'events' in {row[0] for row in before_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                        else 0
                    )
                result = run_migrations(Settings(db_path=str(target)))
                self.assertTrue(result.applied_versions)
                with sqlite3.connect(target) as conn:
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM services').fetchone()[0], service_rows)
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], event_rows)
                    self.assertEqual(
                        conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0],
                        MIGRATIONS[-1].version,
                    )

    def test_current_rerun_is_a_no_op_without_a_new_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            settings = Settings(db_path=str(target))
            run_migrations(settings)
            before_bytes = target.read_bytes()
            backups_before = list((target.parent / 'backups').glob('*.db'))
            result = run_migrations(settings)
            self.assertEqual(result.applied_versions, ())
            self.assertEqual(target.read_bytes(), before_bytes)
            self.assertEqual(list((target.parent / 'backups').glob('*.db')), backups_before)

    def test_unknown_fingerprint_fails_before_backup_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'unknown.db'
            with sqlite3.connect(target) as conn:
                conn.execute('CREATE TABLE unknown_shape (id INTEGER PRIMARY KEY)')
            before = target.read_bytes()
            with self.assertRaises(UnsupportedSchemaError):
                run_migrations(Settings(db_path=str(target)))
            self.assertEqual(target.read_bytes(), before)
            self.assertFalse((target.parent / 'backups').exists())

    def test_prepare_database_propagates_migration_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'unknown.db'
            with sqlite3.connect(target) as conn:
                conn.execute('CREATE TABLE unknown_shape (id INTEGER PRIMARY KEY)')
            with self.assertRaises(UnsupportedSchemaError):
                prepare_database(Settings(db_path=str(target)))

    def test_compatibility_initializer_uses_the_migration_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'unknown.db'
            with sqlite3.connect(target) as conn:
                conn.execute('CREATE TABLE unknown_shape (id INTEGER PRIMARY KEY)')
            from dashboard import app as compatibility_app
            original_path = compatibility_app.DB_PATH
            try:
                compatibility_app.DB_PATH = str(target)
                with self.assertRaises(UnsupportedSchemaError):
                    compatibility_app.init_db()
            finally:
                compatibility_app.DB_PATH = original_path

    def test_failed_migration_rolls_back_and_keeps_redacted_recovery_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            before = target.read_bytes()

            def fail_after_write(conn):
                conn.execute('CREATE TABLE migration_should_rollback (id INTEGER)')
                raise RuntimeError('sensitive implementation detail')

            broken = Migration(1, 'forced_failure', True, fail_after_write)
            with mock.patch('dashboard.beacon.migrations.MIGRATIONS', (broken,)):
                with self.assertRaises(MigrationPreparationError):
                    run_migrations(Settings(db_path=str(target)))

            self.assertEqual(target.read_bytes(), before)
            marker = json.loads((target.parent / 'recovery-required.json').read_text())
            self.assertEqual(marker['failed_target_version'], 1)
            self.assertEqual(marker['reason_class'], 'RuntimeError')
            self.assertNotIn('sensitive implementation detail', json.dumps(marker))
            self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), 1)

    def test_concurrent_contender_observes_current_state_without_duplicate_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            context = multiprocessing.get_context('spawn')
            start_event = context.Event()
            result_queue = context.Queue()
            runners = [
                context.Process(target=_run_migration_process, args=(str(target), start_event, result_queue))
                for _ in range(2)
            ]
            for runner in runners:
                runner.start()
            start_event.set()
            for runner in runners:
                runner.join(timeout=10)
                self.assertEqual(runner.exitcode, 0)
            results = sorted(result_queue.get(timeout=2) for _ in runners)
            self.assertEqual(results, [(), (1, 2, 3)])
            self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), 3)


class InventoryTests(unittest.TestCase):
    def test_inventory_reports_only_structural_metadata(self):
        report = collect_inventory(FIXTURE_DIR / 'runtime-queues-2026-07.db')

        self.assertEqual(report['format'], 'beacon-schema-inventory/v1')
        self.assertIn('schema_fingerprint', report)
        self.assertIn('page', report)
        self.assertIn('database_bytes', report)
        self.assertIn('wal_bytes', report)
        self.assertEqual(report['journal_mode'], 'delete')
        self.assertEqual(report['migration_versions'], [1])
        self.assertIn('services', {table['name'] for table in report['tables']})
        services = next(table for table in report['tables'] if table['name'] == 'services')
        self.assertEqual(services['columns'][0], {
            'cid': 0,
            'name': 'port',
            'type': 'INTEGER',
            'not_null': False,
            'default': None,
            'primary_key': 1,
        })
        encoded = json.dumps(report, sort_keys=True)
        for secret in ('Example service', 'http://example.test', 'private-tag', 'event-details', 'thumbnail-bytes'):
            self.assertNotIn(secret, encoded)

    def test_history_fixtures_have_stable_distinct_fingerprints(self):
        fingerprints = {}
        for filename, expected_tables in FIXTURES.items():
            path = FIXTURE_DIR / filename
            with sqlite3.connect(path) as conn:
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            first = collect_inventory(path)
            second = collect_inventory(path)
            self.assertEqual(first['schema_fingerprint'], second['schema_fingerprint'])
            self.assertEqual(first['schema_fingerprint'], EXPECTED_FINGERPRINTS[filename])
            self.assertEqual(
                expected_tables,
                expected_tables.intersection({table['name'] for table in first['tables']}),
            )
            fingerprints[filename] = classify_schema(first)
        self.assertEqual(len(set(fingerprints.values())), len(FIXTURES))

    def test_malformed_targets_fail_read_only_without_creating_or_changing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'missing.db'
            with self.assertRaisesRegex(InventoryError, 'unable to inspect SQLite database'):
                collect_inventory(missing)
            self.assertFalse(missing.exists())

            malformed = Path(directory) / 'malformed.db'
            malformed.write_bytes(b'not a sqlite database')
            before = malformed.stat()
            with self.assertRaisesRegex(InventoryError, 'unable to inspect SQLite database'):
                collect_inventory(malformed)
            after = malformed.stat()
            self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))

    def test_cli_writes_sanitized_report_without_changing_source(self):
        source = FIXTURE_DIR / 'metadata-events-2026-04.db'
        before = source.stat()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'operator-report.json'
            result = subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'beacon.inventory',
                    '--db',
                    str(source),
                    '--output',
                    str(output),
                ],
                env={**os.environ, 'PYTHONPATH': 'dashboard'},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.exists())
            self.assertEqual(
                json.loads(output.read_text(encoding='utf-8'))['schema_fingerprint'],
                collect_inventory(source)['schema_fingerprint'],
            )
        after = source.stat()
        self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))

    def test_operator_fixture_matches_report_schema_without_operational_records(self):
        report = json.loads(
            (OPERATOR_FIXTURE_DIR / 'production.json').read_text(encoding='utf-8')
        )
        fixture = OPERATOR_FIXTURE_DIR / 'production.db'

        with sqlite3.connect(fixture) as conn:
            self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            for table in report['tables']:
                quoted_name = '"{}"'.format(table['name'].replace('"', '""'))
                self.assertEqual(
                    conn.execute('SELECT COUNT(*) FROM {}'.format(quoted_name)).fetchone()[0],
                    0,
                    table['name'],
                )

        fixture_report = collect_inventory(fixture)
        self.assertEqual(
            fixture_report['schema_fingerprint'], report['schema_fingerprint']
        )
        self.assertEqual(fixture_report['migration_versions'], [])


if __name__ == '__main__':
    unittest.main()
