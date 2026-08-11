import json
import multiprocessing
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from shutil import copy2
from unittest import mock
from pathlib import Path

from dashboard.beacon.config import Settings
from dashboard.beacon.db import connect_db, prepare_database
from dashboard.beacon.inventory import InventoryError, classify_schema, collect_inventory
from dashboard.beacon.migrations import (
    MIGRATIONS,
    Migration,
    MigrationPreparationError,
    UnsupportedSchemaError,
    _migration_7_canonical_host_streams,
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
CURRENT_V4_FIXTURE = 'current-v4.db'
CURRENT_V6_FIXTURE = 'current-v6.db'
EXPECTED_FINGERPRINTS = {
    'initial-2026-04.db': '4330feaa6a22043681d7d55fec900b3279fec9302f68e41417df29653c7cf906',
    'metadata-events-2026-04.db': '8ac9833951d13e2b02deffd4be57f0bec8ce9e8d4771224d1a0fbbc07274abef',
    'runtime-queues-2026-07.db': '791e5c1d380fb38b62e8c284349affb248acfaf5dbbd0e93a07b929b2ef59c91',
}

_LEGACY_PRESERVATION_COLUMNS = {
    'services': ('port', 'title', 'first_seen', 'last_seen', 'is_online'),
    'service_meta': ('port', 'display_name', 'url', 'critical', 'pinned_order', 'tags'),
    'stats_history': ('ts', 'cpu', 'ram', 'disk', 'temp'),
    'service_checks': ('ts', 'port', 'online', 'latency_ms', 'error_class'),
    'events': (
        'id', 'ts', 'port', 'event_type', 'online', 'previous_online',
        'latency_ms', 'error_class', 'alert_status', 'details',
    ),
    'scan_requests': ('id', 'requested_ts', 'requested_by', 'status', 'started_ts', 'completed_ts', 'error'),
    'preview_requests': ('port', 'requested_ts', 'status', 'error'),
}


@dataclass(frozen=True)
class LegacyRowSnapshot:
    rows: dict
    columns: dict

    def __getitem__(self, table):
        return self.rows[table]


def snapshot_legacy_rows(conn, columns_by_table=None):
    """Capture stable legacy values for later migration-preservation assertions."""
    table_names = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    snapshots = {}
    selected_columns = {}
    source_columns = columns_by_table or _LEGACY_PRESERVATION_COLUMNS
    for table, columns in source_columns.items():
        if table not in table_names:
            continue
        available = {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}
        selected = tuple(columns) if columns_by_table else tuple(
            column for column in columns if column in available
        )
        if not selected:
            continue
        if not set(selected).issubset(available):
            raise AssertionError(f'legacy columns missing after migration: {table}')
        column_sql = ', '.join(f'"{column}"' for column in selected)
        order_sql = ', '.join(f'"{column}"' for column in selected)
        snapshots[table] = [
            tuple(row) for row in conn.execute(
                f'SELECT {column_sql} FROM "{table}" ORDER BY {order_sql}'
            )
        ]
        selected_columns[table] = selected
    return LegacyRowSnapshot(snapshots, selected_columns)


def assert_legacy_rows_preserved(test_case, before_rows, conn):
    """Assert every pre-migration legacy row keeps both its values and count."""
    after_rows = snapshot_legacy_rows(conn, before_rows.columns)
    test_case.assertEqual(after_rows.rows, before_rows.rows)


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
            collect_inventory(FIXTURE_DIR / CURRENT_V4_FIXTURE)['schema_fingerprint'],
            collect_inventory(FIXTURE_DIR / CURRENT_V6_FIXTURE)['schema_fingerprint'],
        }
        self.assertEqual(set(supported), expected)
        for entry in supported.values():
            self.assertIn('fixture', entry)
            self.assertIn('source', entry)
            self.assertIn('minimum_schema_version', entry)
            self.assertEqual(entry['target_version'], MIGRATIONS[-1].version)

        packaged_manifest = json.loads(
            Path('dashboard/beacon/support_floor.json').read_text(encoding='utf-8')
        )
        self.assertEqual(packaged_manifest, manifest)

    def test_current_v4_fixture_is_canonical_and_migrates_preserving_rows(self):
        source = FIXTURE_DIR / CURRENT_V4_FIXTURE
        inventory = collect_inventory(source)
        self.assertEqual(inventory['migration_versions'], [1, 2, 3, 4])
        with sqlite3.connect(source) as before_conn:
            before_rows = snapshot_legacy_rows(before_conn)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / CURRENT_V4_FIXTURE
            copy2(source, target)
            result = run_migrations(Settings(db_path=str(target)))
            self.assertEqual(result.applied_versions, (5, 6, 7))
            with sqlite3.connect(target) as conn:
                assert_legacy_rows_preserved(self, before_rows, conn)
                self._assert_telemetry_schema(conn)
                self._assert_telemetry_tables_empty(conn)

    def test_current_v6_legacy_host_state_migrates_once_without_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            settings = Settings(db_path=str(target))

            result = run_migrations(settings)
            self.assertEqual(result.applied_versions, (7,))
            self.assertEqual(len(result.backups), 1)

            with sqlite3.connect(target) as conn:
                streams = list(conn.execute(
                    'SELECT stream_key, started_ts, cadence_seconds, last_observed_ts, '
                    'consecutive_misses, open_gap_start_ts FROM telemetry_streams '
                    "WHERE stream_kind='host' ORDER BY stream_key"
                ))
                self.assertEqual(streams, [
                    (metric, 1700000000, 60, 1700000700, 3, 1700000650)
                    for metric in ('cpu', 'disk', 'ram', 'temp')
                ])
                for metric in ('disk', 'ram', 'temp'):
                    self.assertEqual(list(conn.execute(
                        'SELECT start_ts, end_ts, reason, detail FROM telemetry_coverage '
                        'WHERE stream_kind=? AND stream_key=? ORDER BY start_ts, end_ts, id',
                        ('host', metric),
                    )), [
                        (1700000000, 1700000200, 'collection_gap', 'legacy collector outage'),
                        (1700000200, 1700000300, 'unknown', 'legacy unknown'),
                    ])
                self.assertEqual(list(conn.execute(
                    'SELECT start_ts, end_ts, reason, detail FROM telemetry_coverage '
                    'WHERE stream_kind=? AND stream_key=? ORDER BY start_ts, end_ts, id',
                    ('host', 'cpu'),
                )), [
                    (1700000000, 1700000050, 'collection_gap', 'legacy collector outage'),
                    (1700000050, 1700000150, 'collection_gap', 'cpu authoritative'),
                    (1700000150, 1700000200, 'collection_gap', 'legacy collector outage'),
                    (1700000200, 1700000300, 'unknown', 'legacy unknown'),
                ])
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM telemetry_streams WHERE stream_kind='host' AND stream_key='host'"
                ).fetchone()[0], 0)
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM telemetry_coverage WHERE stream_kind='host' AND stream_key='host'"
                ).fetchone()[0], 0)
                state = json.loads(conn.execute(
                    "SELECT value FROM runtime_state WHERE key='telemetry_retention_state'"
                ).fetchone()[0])
                self.assertEqual(state['pressure_gaps'], {
                    'host:cpu': 1700000300,
                    'host:disk': 1700000300,
                    'host:ram': 1700000300,
                    'host:temp': 1700000300,
                    'service:8080': 1700000350,
                })
                self.assertEqual(state['unrelated'], {'keep': 'value'})
                self.assertEqual(conn.execute(
                    'SELECT stream_kind, stream_key, bucket_start, bucket_seconds, state, '
                    'attempt_count, next_retry_ts, last_error_class, updated_ts '
                    'FROM telemetry_rollup_jobs'
                ).fetchall(), [
                    ('host', 'host', 1700000000, 300, 'pending', 2, 1700000900, 'sqlite_busy', 1700000700),
                ])

                before_reentry = (
                    list(conn.execute('SELECT * FROM telemetry_streams ORDER BY stream_kind, stream_key')),
                    list(conn.execute('SELECT * FROM telemetry_coverage ORDER BY stream_kind, stream_key, start_ts, end_ts, id')),
                    conn.execute("SELECT value FROM runtime_state WHERE key='telemetry_retention_state'").fetchone()[0],
                )
                _migration_7_canonical_host_streams(conn)
                after_reentry = (
                    list(conn.execute('SELECT * FROM telemetry_streams ORDER BY stream_kind, stream_key')),
                    list(conn.execute('SELECT * FROM telemetry_coverage ORDER BY stream_kind, stream_key, start_ts, end_ts, id')),
                    conn.execute("SELECT value FROM runtime_state WHERE key='telemetry_retention_state'").fetchone()[0],
                )
                self.assertEqual(after_reentry, before_reentry)

            before_rerun = target.read_bytes()
            backup_count = len(list((target.parent / 'backups').glob('*.db')))
            self.assertEqual(run_migrations(settings).applied_versions, ())
            self.assertEqual(target.read_bytes(), before_rerun)
            self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), backup_count)

    def test_migration_seven_failure_rolls_back_legacy_host_state(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            with sqlite3.connect(target) as conn:
                before = (
                    list(conn.execute('SELECT * FROM telemetry_streams ORDER BY stream_kind, stream_key')),
                    list(conn.execute('SELECT * FROM telemetry_coverage ORDER BY id')),
                    conn.execute("SELECT value FROM runtime_state WHERE key='telemetry_retention_state'").fetchone()[0],
                    list(conn.execute('SELECT * FROM telemetry_rollup_jobs')),
                )
            original = MIGRATIONS[-1]

            def fail_after_transform(conn):
                original.apply(conn)
                raise RuntimeError('migration seven sensitive failure')

            broken = Migration(7, 'canonical_host_streams', True, fail_after_transform)
            with mock.patch('dashboard.beacon.migrations.MIGRATIONS', (*MIGRATIONS[:-1], broken)):
                with self.assertRaises(MigrationPreparationError):
                    run_migrations(Settings(db_path=str(target)))

            with sqlite3.connect(target) as conn:
                after = (
                    list(conn.execute('SELECT * FROM telemetry_streams ORDER BY stream_kind, stream_key')),
                    list(conn.execute('SELECT * FROM telemetry_coverage ORDER BY id')),
                    conn.execute("SELECT value FROM runtime_state WHERE key='telemetry_retention_state'").fetchone()[0],
                    list(conn.execute('SELECT * FROM telemetry_rollup_jobs')),
                )
                self.assertEqual(after, before)
                self.assertEqual(conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 6)
            marker = json.loads((target.parent / 'recovery-required.json').read_text())
            self.assertEqual(marker['failed_target_version'], 7)
            self.assertEqual(marker['reason_class'], 'RuntimeError')
            self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), 1)

    def test_migration_seven_rejects_malformed_legacy_pressure_state(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            with sqlite3.connect(target) as conn:
                conn.execute(
                    "UPDATE runtime_state SET value=? WHERE key='telemetry_retention_state'",
                    (json.dumps({
                        'state': 'pressure',
                        'pressure_gaps': {'host:host': True},
                        'unrelated': {'keep': 'value'},
                    }),),
                )
                conn.commit()

            with self.assertRaises(MigrationPreparationError):
                run_migrations(Settings(db_path=str(target)))

            with sqlite3.connect(target) as conn:
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM telemetry_streams WHERE stream_kind='host' AND stream_key='host'"
                ).fetchone()[0], 1)
                self.assertEqual(conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 6)
            marker = json.loads((target.parent / 'recovery-required.json').read_text())
            self.assertEqual(marker['failed_target_version'], 7)
            self.assertEqual(marker['reason_class'], 'ValueError')

    def test_operator_service_port_remains_the_service_rollup_stream_key(self):
        source = OPERATOR_FIXTURE_DIR / 'production.db'
        with sqlite3.connect(source) as before_conn:
            checks_columns = {
                row[1] for row in before_conn.execute('PRAGMA table_info(service_checks)')
            }
            service_columns = {
                row[1] for row in before_conn.execute('PRAGMA table_info(services)')
            }
        self.assertIn('port', checks_columns)
        self.assertIn('port', service_columns)

    def test_migration_five_failure_rolls_back_telemetry_schema_and_keeps_recovery_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            original = MIGRATIONS[4]

            def fail_migration_five(conn):
                original.apply(conn)
                raise RuntimeError('migration five sensitive failure')

            broken = Migration(5, 'bounded_telemetry', True, fail_migration_five)
            with mock.patch('dashboard.beacon.migrations.MIGRATIONS', (*MIGRATIONS[:4], broken)):
                with self.assertRaises(MigrationPreparationError):
                    run_migrations(Settings(db_path=str(target)))

            with sqlite3.connect(target) as conn:
                tables = {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )}
                self.assertFalse(tables.intersection({
                    'telemetry_streams',
                    'host_metric_rollups',
                    'service_rollups',
                    'telemetry_coverage',
                    'telemetry_rollup_jobs',
                }))
                versions = {row[0] for row in conn.execute('SELECT version FROM schema_migrations')}
                self.assertNotIn(5, versions)
            marker = json.loads((target.parent / 'recovery-required.json').read_text())
            self.assertEqual(marker['failed_target_version'], 5)
            self.assertEqual(marker['reason_class'], 'RuntimeError')
            backups = list((target.parent / 'backups').glob('*.db'))
            self.assertEqual(len(backups), 3)
            self.assertIn(marker['backup_catalog_id'], {backup.name for backup in backups})

    def _assert_telemetry_schema(self, conn):
        expected_columns = {
            'telemetry_streams': (
                'stream_kind', 'stream_key', 'started_ts', 'cadence_seconds',
                'last_observed_ts', 'consecutive_misses', 'open_gap_start_ts',
            ),
            'host_metric_rollups': (
                'metric', 'bucket_start', 'bucket_seconds', 'min_value', 'max_value',
                'avg_value', 'latest_value', 'sample_count', 'observed_seconds',
                'gap_seconds', 'unknown_seconds',
            ),
            'service_rollups': (
                'service_port', 'bucket_start', 'bucket_seconds', 'online_seconds',
                'offline_seconds', 'unknown_seconds', 'gap_seconds', 'latency_min',
                'latency_max', 'latency_avg', 'check_count', 'failure_class_counts_json',
                'latency_sample_count',
            ),
            'telemetry_coverage': (
                'id', 'stream_kind', 'stream_key', 'start_ts', 'end_ts', 'reason', 'detail',
            ),
            'telemetry_rollup_jobs': (
                'stream_kind', 'stream_key', 'bucket_start', 'bucket_seconds', 'state',
                'attempt_count', 'next_retry_ts', 'last_error_class', 'updated_ts',
            ),
        }
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertTrue(set(expected_columns).issubset(tables))
        expected_primary_keys = {
            'telemetry_streams': ('stream_kind', 'stream_key'),
            'host_metric_rollups': ('metric', 'bucket_start', 'bucket_seconds'),
            'service_rollups': ('service_port', 'bucket_start', 'bucket_seconds'),
            'telemetry_coverage': ('id',),
            'telemetry_rollup_jobs': (
                'stream_kind', 'stream_key', 'bucket_start', 'bucket_seconds',
            ),
        }
        for table, columns in expected_columns.items():
            info = list(conn.execute(f'PRAGMA table_info("{table}")'))
            self.assertEqual(tuple(row[1] for row in info), columns)
            primary_key = tuple(
                row[1] for row in sorted(info, key=lambda row: row[5]) if row[5]
            )
            self.assertEqual(primary_key, expected_primary_keys[table])

        schema_sql = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table' "
                "AND name LIKE 'telemetry_%'"
            )
        }
        self.assertIn('CHECK (end_ts > start_ts)', schema_sql['telemetry_coverage'])
        self.assertIn("'collection_gap', 'unknown', 'expired', 'not_yet_monitored'", schema_sql['telemetry_coverage'])
        self.assertIn("'pending', 'failed', 'succeeded'", schema_sql['telemetry_rollup_jobs'])
        indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        self.assertTrue({
            'idx_checks_port_ts',
            'idx_host_rollups_range',
            'idx_service_rollups_range',
            'idx_telemetry_coverage_range',
            'idx_telemetry_rollup_jobs_due',
        }.issubset(indexes))
        expected_index_columns = {
            'idx_checks_port_ts': ('port', 'ts'),
            'idx_host_rollups_range': ('metric', 'bucket_seconds', 'bucket_start'),
            'idx_service_rollups_range': ('service_port', 'bucket_seconds', 'bucket_start'),
            'idx_telemetry_coverage_range': ('stream_kind', 'stream_key', 'start_ts', 'end_ts'),
            'idx_telemetry_rollup_jobs_due': ('state', 'next_retry_ts', 'updated_ts'),
        }
        for index, columns in expected_index_columns.items():
            self.assertEqual(
                tuple(row[2] for row in conn.execute(f'PRAGMA index_info("{index}")')),
                columns,
            )

    def _assert_telemetry_tables_empty(self, conn):
        for table in (
            'telemetry_streams',
            'host_metric_rollups',
            'service_rollups',
            'telemetry_coverage',
            'telemetry_rollup_jobs',
        ):
            self.assertEqual(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0], 0)

    def test_each_supported_fixture_upgrades_once_preserving_representative_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename in (*FIXTURES, 'operator/production.db'):
                source_name = filename.replace('/', '-')
                source = FIXTURE_DIR / filename
                target = Path(directory) / source_name
                copy2(source, target)
                with sqlite3.connect(target) as before_conn:
                    before_rows = snapshot_legacy_rows(before_conn)
                result = run_migrations(Settings(db_path=str(target)))
                self.assertTrue(result.applied_versions)
                with sqlite3.connect(target) as conn:
                    assert_legacy_rows_preserved(self, before_rows, conn)
                    self._assert_telemetry_schema(conn)
                    self._assert_telemetry_tables_empty(conn)
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
            self.assertEqual(results, [(), tuple(migration.version for migration in MIGRATIONS)])
            self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), 3)

    def test_ordinary_access_blocks_migration_before_any_backup_or_marker_write(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'production.db'
            copy2(OPERATOR_FIXTURE_DIR / 'production.db', target)
            before = target.read_bytes()
            access = connect_db(target)
            try:
                with self.assertRaisesRegex(MigrationPreparationError, 'maintenance'):
                    run_migrations(Settings(db_path=str(target)), lock_timeout_seconds=0)
            finally:
                access.close()

            self.assertEqual(target.read_bytes(), before)
            self.assertFalse((target.parent / 'backups').exists())
            self.assertFalse((target.parent / 'recovery-required.json').exists())
            self.assertFalse((target.parent / 'production.db-wal').exists())
            self.assertFalse((target.parent / 'production.db-shm').exists())

    def test_migration_source_declares_upgrade_then_maintenance_lock_order(self):
        source = Path('dashboard/beacon/migrations.py').read_text(encoding='utf-8')
        migration_body = source[source.index('def run_migrations'):]
        upgrade = migration_body.index('fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX')
        maintenance = migration_body.index('exclusive_database_maintenance')
        self.assertLess(upgrade, maintenance)


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
