import json
import multiprocessing
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
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
    MigrationContended,
    MigrationPreparationError,
    READ_BUSY_TIMEOUT_SECONDS,
    UnsupportedSchemaError,
    _migration_7_canonical_host_streams,
    _migration_9_planned_maintenance,
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
OPERATOR_V7_FINGERPRINT = '3f88834a2cfacc2bbecac2424a3bc36955f7a81727132ba18cbc88c7bb85f7f7'
# Every tracked lineage carried forward to schema version 8 -- the shape a deployment
# of the previous release actually sits at when migration 9 arrives.  Three lineages
# converge on one v8 shape; the operator lineage keeps its own.  These are hashes of
# raw sqlite_master DDL text, so they cannot be reasoned about -- only recomputed.
V8_FINGERPRINTS = {
    'initial-2026-04.db': 'c6278d881afc30573db03391377be3f075d3698eb28d3ecc0ddf98e251548d5a',
    'current-v4.db': 'c6278d881afc30573db03391377be3f075d3698eb28d3ecc0ddf98e251548d5a',
    'current-v6.db': 'c6278d881afc30573db03391377be3f075d3698eb28d3ecc0ddf98e251548d5a',
    'metadata-events-2026-04.db': '2f254a793516fc8ff7c543d91c0f0814c4cb423f08c4d60982f33a1568b4fb98',
    'runtime-queues-2026-07.db': '33f50b9b569c66a0340f230aac615440211166b849db22c40d01bdfc889f921c',
    'operator/production.db': 'f8d977dedd2fb494d7c94899b40639bed3c717238c049f1f70064c4a80c4075f',
}
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

    def _migration_seven_evidence_snapshot(self, conn):
        """Capture all version-6 evidence Migration 7 must preserve on failure."""
        return (
            list(conn.execute('SELECT * FROM telemetry_streams ORDER BY stream_kind, stream_key')),
            list(conn.execute('SELECT * FROM telemetry_coverage ORDER BY id')),
            conn.execute(
                "SELECT value FROM runtime_state WHERE key='telemetry_retention_state'"
            ).fetchone()[0],
            list(conn.execute(
                'SELECT * FROM telemetry_rollup_jobs ORDER BY '
                'stream_kind, stream_key, bucket_start, bucket_seconds'
            )),
            list(conn.execute('SELECT * FROM schema_migrations ORDER BY version')),
        )

    def test_support_floor_covers_history_and_confirmed_operator_evidence(self):
        manifest = json.loads((FIXTURE_DIR / 'support-floor.json').read_text(encoding='utf-8'))
        supported = {entry['fingerprint']: entry for entry in manifest['supported_schemas']}
        expected = set(EXPECTED_FINGERPRINTS.values()) | {
            json.loads((OPERATOR_FIXTURE_DIR / 'production.json').read_text())['schema_fingerprint'],
            collect_inventory(FIXTURE_DIR / CURRENT_V4_FIXTURE)['schema_fingerprint'],
            collect_inventory(FIXTURE_DIR / CURRENT_V6_FIXTURE)['schema_fingerprint'],
            OPERATOR_V7_FINGERPRINT,
        } | set(V8_FINGERPRINTS.values())
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

    def test_operator_production_path_to_v7_is_admitted_and_migration_eight_preserves_rows(self):
        """The exact deployed V7 shape comes only from canonical migrations 2-7."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'operator-production-v7.db'
            copy2(OPERATOR_FIXTURE_DIR / 'production.db', target)
            settings = Settings(db_path=str(target))

            with mock.patch('dashboard.beacon.migrations.MIGRATIONS', MIGRATIONS[:7]):
                self.assertEqual(
                    run_migrations(settings).applied_versions,
                    (2, 3, 4, 5, 6, 7),
                )

            self.assertEqual(
                collect_inventory(target)['schema_fingerprint'],
                OPERATOR_V7_FINGERPRINT,
            )
            with sqlite3.connect(target) as conn:
                conn.execute(
                    'INSERT INTO services(port, title, first_seen, last_seen, is_online) '
                    'VALUES(?,?,?,?,?)',
                    (8100, 'Canonical operator service', 1_700_000_000, 1_700_000_010, 1),
                )
                conn.execute(
                    'INSERT INTO service_meta(port, display_name, url, critical, pinned_order, tags) '
                    'VALUES(?,?,?,?,?,?)',
                    (8100, 'Operator service', 'http://127.0.0.1:8100', 1, 1, 'operator'),
                )
                conn.execute(
                    'INSERT INTO events(ts, port, event_type, online, previous_online) '
                    'VALUES(?,?,?,?,?)',
                    (1_700_000_010, 8100, 'state_change', 1, 0),
                )
                conn.commit()
                before_rows = snapshot_legacy_rows(conn)

            self.assertEqual(run_migrations(settings).applied_versions, (8, 9))
            with sqlite3.connect(target) as conn:
                assert_legacy_rows_preserved(self, before_rows, conn)
                self.assertEqual(
                    conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0],
                    9,
                )
                self.assertEqual(
                    conn.execute('SELECT COUNT(*) FROM background_job_health').fetchone()[0],
                    0,
                )

    def _carry_lineage_to(self, fixture_name, version, directory):
        """Copy a tracked lineage fixture and migrate it up to ``version`` only."""
        target = Path(directory) / 'dashboard.db'
        copy2(FIXTURE_DIR / fixture_name, target)
        settings = Settings(db_path=str(target))
        with mock.patch(
            'dashboard.beacon.migrations.MIGRATIONS',
            tuple(m for m in MIGRATIONS if m.version <= version),
        ):
            run_migrations(settings)
        return target, settings

    def test_support_floor_admits_every_tracked_lineage_at_the_previous_version(self):
        """A deployment of the previous release must be admitted by the newest one.

        The floor is only consulted for a NON-empty database below the target
        version, so the shape that matters in production is each tracked lineage
        carried to ``MIGRATIONS[-1].version - 1``.  Migration 9 shipped without
        those entries and no test caught it, because the suite only ever exercised
        v7 -> (8, 9) in a single run and never a deployment already sitting at v8.
        This guard fails the moment migration N ships without its N-1 entries.
        """
        newest = MIGRATIONS[-1].version
        floor = {
            entry['fingerprint']
            for entry in json.loads(
                Path('dashboard/beacon/support_floor.json').read_text(encoding='utf-8')
            )['supported_schemas']
        }
        missing = {}
        for fixture_name in V8_FINGERPRINTS:
            with tempfile.TemporaryDirectory() as directory:
                target, _ = self._carry_lineage_to(fixture_name, newest - 1, directory)
                fingerprint = collect_inventory(target)['schema_fingerprint']
                self.assertEqual(fingerprint, V8_FINGERPRINTS[fixture_name])
                if fingerprint not in floor:
                    missing[fixture_name] = fingerprint
        self.assertEqual(
            missing,
            {},
            f'support_floor.json has no entry for these lineages at schema version '
            f'{newest - 1}; a deployment of the previous release cannot upgrade: {missing}',
        )

    def test_a_deployment_already_at_v8_applies_only_migration_nine(self):
        """The real upgrade path: already at 8, not arriving from 7 in one run.

        Regression for the operator report where every live deployment failed with
        UnsupportedSchemaError because its v8 fingerprint was absent from the floor.
        """
        with tempfile.TemporaryDirectory() as directory:
            target, settings = self._carry_lineage_to('operator/production.db', 8, directory)
            self.assertEqual(collect_inventory(target)['migration_versions'], [2, 3, 4, 5, 6, 7, 8])
            self.assertEqual(
                collect_inventory(target)['schema_fingerprint'],
                V8_FINGERPRINTS['operator/production.db'],
            )
            with sqlite3.connect(target) as conn:
                conn.execute(
                    'INSERT INTO services(port, title, first_seen, last_seen, is_online) '
                    'VALUES(?,?,?,?,?)',
                    (8100, 'Deployed service', 1_700_000_000, 1_700_000_010, 1),
                )
                conn.execute(
                    'INSERT INTO events(ts, port, event_type, online, previous_online) '
                    'VALUES(?,?,?,?,?)',
                    (1_700_000_010, 8100, 'state_change', 1, 0),
                )
                conn.commit()
                before_rows = snapshot_legacy_rows(conn)

            self.assertEqual(run_migrations(settings).applied_versions, (9,))

            with sqlite3.connect(target) as conn:
                assert_legacy_rows_preserved(self, before_rows, conn)
                self.assertEqual(
                    conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 9
                )
                self.assertTrue(conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='maintenance_windows'"
                ).fetchone())

    def test_unsupported_schema_error_names_the_fingerprint_and_the_evidence_command(self):
        """An operator cannot supply floor evidence for a shape the error never names."""
        with tempfile.TemporaryDirectory() as directory:
            target, settings = self._carry_lineage_to('operator/production.db', 8, directory)
            fingerprint = collect_inventory(target)['schema_fingerprint']
            with mock.patch('dashboard.beacon.migrations._support_floor', return_value={}):
                with self.assertRaises(UnsupportedSchemaError) as raised:
                    run_migrations(settings)
        message = str(raised.exception)
        self.assertIn(fingerprint, message)
        self.assertIn('schema version 8', message)
        self.assertIn('beacon.inventory', message)

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
            self.assertEqual(result.applied_versions, (5, 6, 7, 8, 9))
            with sqlite3.connect(target) as conn:
                assert_legacy_rows_preserved(self, before_rows, conn)
                self._assert_telemetry_schema(conn)
                self._assert_telemetry_tables_empty(conn)

    def test_current_v6_legacy_host_state_migrates_once_without_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            settings = Settings(db_path=str(target))

            result = run_migrations(settings)
            self.assertEqual(result.applied_versions, (7, 8, 9))
            self.assertEqual(len(result.backups), 3)

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
                before = self._migration_seven_evidence_snapshot(conn)
            original = next(migration for migration in MIGRATIONS if migration.version == 7)

            def fail_after_transform(conn):
                original.apply(conn)
                raise RuntimeError('migration seven sensitive failure')

            broken = Migration(7, 'canonical_host_streams', True, fail_after_transform)
            with mock.patch(
                'dashboard.beacon.migrations.MIGRATIONS',
                (*(migration for migration in MIGRATIONS if migration.version < 7), broken),
            ):
                with self.assertRaises(MigrationPreparationError):
                    run_migrations(Settings(db_path=str(target)))

            with sqlite3.connect(target) as conn:
                after = self._migration_seven_evidence_snapshot(conn)
                self.assertEqual(after, before)
                self.assertEqual(conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 6)
            marker = json.loads((target.parent / 'recovery-required.json').read_text())
            self.assertEqual(marker['failed_target_version'], 7)
            self.assertEqual(marker['reason_class'], 'RuntimeError')
            self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), 1)

    def test_migration_seven_rejects_json_null_legacy_pressure_state_without_partial_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            with sqlite3.connect(target) as conn:
                state = json.loads(conn.execute(
                    "SELECT value FROM runtime_state WHERE key='telemetry_retention_state'"
                ).fetchone()[0])
                state['pressure_gaps']['host:host'] = None
                conn.execute(
                    "UPDATE runtime_state SET value=? WHERE key='telemetry_retention_state'",
                    (json.dumps(state, separators=(',', ':'), sort_keys=True),),
                )
                conn.commit()
                before = self._migration_seven_evidence_snapshot(conn)

            with self.assertRaises(MigrationPreparationError):
                run_migrations(Settings(db_path=str(target)))

            with sqlite3.connect(target) as conn:
                self.assertEqual(self._migration_seven_evidence_snapshot(conn), before)
                self.assertEqual(conn.execute(
                    'SELECT MAX(version) FROM schema_migrations'
                ).fetchone()[0], 6)
            marker = json.loads((target.parent / 'recovery-required.json').read_text())
            self.assertEqual(marker['failed_target_version'], 7)
            self.assertEqual(marker['reason_class'], 'ValueError')
            self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), 1)

    def test_migration_seven_rejects_remaining_malformed_legacy_pressure_values(self):
        malformed_values = (True, False, '1700000300', 1700000300.5, [], {})
        for malformed_value in malformed_values:
            with self.subTest(malformed_value=malformed_value):
                with tempfile.TemporaryDirectory() as directory:
                    target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
                    with sqlite3.connect(target) as conn:
                        state = json.loads(conn.execute(
                            "SELECT value FROM runtime_state WHERE key='telemetry_retention_state'"
                        ).fetchone()[0])
                        state['pressure_gaps']['host:host'] = malformed_value
                        conn.execute(
                            "UPDATE runtime_state SET value=? WHERE key='telemetry_retention_state'",
                            (json.dumps(state, separators=(',', ':'), sort_keys=True),),
                        )
                        conn.commit()
                        before = self._migration_seven_evidence_snapshot(conn)

                    with self.assertRaises(MigrationPreparationError):
                        run_migrations(Settings(db_path=str(target)))

                    with sqlite3.connect(target) as conn:
                        self.assertEqual(self._migration_seven_evidence_snapshot(conn), before)
                        self.assertEqual(conn.execute(
                            'SELECT MAX(version) FROM schema_migrations'
                        ).fetchone()[0], 6)
                    marker = json.loads((target.parent / 'recovery-required.json').read_text())
                    self.assertEqual(marker['failed_target_version'], 7)
                    self.assertEqual(marker['reason_class'], 'ValueError')
                    self.assertEqual(len(list((target.parent / 'backups').glob('*.db'))), 1)

    def test_migration_seven_absent_legacy_pressure_key_is_a_successful_no_op(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            with sqlite3.connect(target) as conn:
                state = json.loads(conn.execute(
                    "SELECT value FROM runtime_state WHERE key='telemetry_retention_state'"
                ).fetchone()[0])
                del state['pressure_gaps']['host:host']
                expected_state = json.dumps(state, separators=(',', ':'), sort_keys=True)
                conn.execute(
                    "UPDATE runtime_state SET value=? WHERE key='telemetry_retention_state'",
                    (expected_state,),
                )
                conn.commit()

            self.assertEqual(run_migrations(Settings(db_path=str(target))).applied_versions, (7, 8, 9))

            with sqlite3.connect(target) as conn:
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM telemetry_streams WHERE stream_kind='host' AND stream_key='host'"
                ).fetchone()[0], 0)
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM telemetry_coverage WHERE stream_kind='host' AND stream_key='host'"
                ).fetchone()[0], 0)
                self.assertEqual(conn.execute(
                    "SELECT value FROM runtime_state WHERE key='telemetry_retention_state'"
                ).fetchone()[0], expected_state)
                self.assertEqual(conn.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0], 9)

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
                # Zero budget preserves the single-attempt behaviour this test
                # exercised before contention retry existed -- without it, the
                # suite would hang for the whole default contention budget
                # rather than fail fast.
                with self.assertRaisesRegex(MigrationContended, 'another Beacon process'):
                    run_migrations(
                        Settings(db_path=str(target)),
                        lock_timeout_seconds=0,
                        contention_budget_seconds=0,
                    )
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

    # -- G-03.1-2 gap-closure regressions: contention survival, real-error
    # -- fidelity, the pending-work fast path, and its two newly exposed
    # -- failure modes (racing a live writer, leaking a handle). --

    def test_a_contention_window_that_ends_is_survived_rather_than_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            settings = Settings(db_path=str(target))
            ready_event = threading.Event()

            def hold_shared_lease_then_release():
                # Opened and closed in the same thread: SQLite connections
                # (and their held flock lease) are thread-affine.
                access = connect_db(target)
                ready_event.set()
                time.sleep(0.2)
                access.close()

            holder = threading.Thread(target=hold_shared_lease_then_release)
            holder.start()
            self.assertTrue(ready_event.wait(timeout=5))
            try:
                with self.assertLogs('beacon.migrations', level='WARNING') as logs:
                    result = run_migrations(
                        settings, lock_timeout_seconds=0.05, contention_budget_seconds=5,
                    )
            finally:
                holder.join(timeout=5)

            self.assertEqual(result.applied_versions[-1], MIGRATIONS[-1].version)
            self.assertTrue(
                any('busy' in message.lower() for message in logs.output),
                logs.output,
            )

    def test_a_real_schema_refusal_is_never_displaced_by_the_contention_message(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            with sqlite3.connect(target) as conn:
                conn.execute('CREATE TABLE unmapped_extra_table (id INTEGER PRIMARY KEY)')
            settings = Settings(db_path=str(target))
            ready_event = threading.Event()

            def hold_shared_lease_then_release():
                access = connect_db(target)
                ready_event.set()
                time.sleep(0.2)
                access.close()

            holder = threading.Thread(target=hold_shared_lease_then_release)
            holder.start()
            self.assertTrue(ready_event.wait(timeout=5))
            try:
                with self.assertRaises(UnsupportedSchemaError) as raised:
                    run_migrations(
                        settings, lock_timeout_seconds=0.05, contention_budget_seconds=5,
                    )
            finally:
                holder.join(timeout=5)

            fingerprint = collect_inventory(target)['schema_fingerprint']
            message = str(raised.exception)
            self.assertIn(fingerprint, message)
            self.assertIn('beacon.inventory', message)
            self.assertNotIn('lock', message.lower())
            self.assertNotIn('timeout', message.lower())

    def test_an_already_current_database_never_requests_the_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            settings = Settings(db_path=str(target))
            run_migrations(settings)

            access = connect_db(target)
            try:
                result = run_migrations(
                    settings, lock_timeout_seconds=0, contention_budget_seconds=0,
                )
                self.assertEqual(result.applied_versions, ())

                marker_path = target.parent / 'recovery-required.json'
                marker_path.write_text('{}', encoding='utf-8')

                def _never_called(*args, **kwargs):
                    self.fail(
                        'exclusive_database_maintenance must not be entered when '
                        'nothing is pending'
                    )

                with mock.patch(
                    'dashboard.beacon.migrations.exclusive_database_maintenance',
                    side_effect=_never_called,
                ):
                    result = run_migrations(
                        settings, lock_timeout_seconds=0, contention_budget_seconds=0,
                    )
                self.assertEqual(result.applied_versions, ())
                self.assertFalse(marker_path.exists())
            finally:
                access.close()

    def test_the_pending_work_check_waits_out_a_writer_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            settings = Settings(db_path=str(target))
            run_migrations(settings)

            def hold_writer(ready_event, release_event):
                # Opened inside the thread that uses it: SQLite connections
                # are thread-affine, and BEGIN EXCLUSIVE (never BEGIN
                # IMMEDIATE -- see the plan's rationale) is what actually
                # excludes the fast path's SELECT-only readers.
                writer = connect_db(target)
                try:
                    writer.execute('BEGIN EXCLUSIVE')
                    ready_event.set()
                    release_event.wait(timeout=5)
                finally:
                    writer.rollback()
                    writer.close()

            # Positive control: constant patched ABOVE the writer's hold. On
            # its own this proves the tolerance is real, but would also pass
            # against unhardened code -- it detects nothing by itself.
            ready_event = threading.Event()
            release_event = threading.Event()
            holder = threading.Thread(target=hold_writer, args=(ready_event, release_event))
            holder.start()
            try:
                self.assertTrue(ready_event.wait(timeout=5))
                releaser = threading.Timer(0.2, release_event.set)
                releaser.start()
                with mock.patch('dashboard.beacon.migrations.READ_BUSY_TIMEOUT_SECONDS', 2):
                    result = run_migrations(settings, lock_timeout_seconds=5)
            finally:
                release_event.set()
                holder.join(timeout=5)
            self.assertEqual(result.applied_versions, ())

            # Detector: constant patched BELOW the writer's hold. Hardened
            # code reads the patched constant and gives up inside the hold;
            # unhardened code ignores it, takes the stdlib default, waits the
            # hold out, and would fail this assertion by succeeding instead.
            ready_event = threading.Event()
            release_event = threading.Event()
            holder = threading.Thread(target=hold_writer, args=(ready_event, release_event))
            holder.start()
            try:
                self.assertTrue(ready_event.wait(timeout=5))
                releaser = threading.Timer(0.2, release_event.set)
                releaser.start()
                with mock.patch('dashboard.beacon.migrations.READ_BUSY_TIMEOUT_SECONDS', 0):
                    with self.assertRaises(sqlite3.OperationalError):
                        run_migrations(settings, lock_timeout_seconds=5)
            finally:
                release_event.set()
                holder.join(timeout=5)

            # Pin the shipped value against a fact owned by db.py: it must be
            # at least the busy timeout an ordinary Beacon connection gets.
            probe = connect_db(target)
            try:
                configured_ms = probe.execute('PRAGMA busy_timeout').fetchone()[0]
            finally:
                probe.close()
            self.assertGreaterEqual(READ_BUSY_TIMEOUT_SECONDS * 1000, configured_ms)

    def test_the_pending_work_check_closes_every_connection_it_opens(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, CURRENT_V6_FIXTURE)
            settings = Settings(db_path=str(target))
            run_migrations(settings)

            opened = []
            real_connect = sqlite3.connect

            def spy_connect(*args, **kwargs):
                conn = real_connect(*args, **kwargs)
                opened.append(conn)
                return conn

            with mock.patch(
                'dashboard.beacon.migrations.sqlite3.connect', side_effect=spy_connect,
            ):
                result = run_migrations(settings)

            self.assertEqual(result.applied_versions, ())
            self.assertTrue(opened)
            for conn in opened:
                with self.assertRaises(sqlite3.ProgrammingError):
                    conn.execute('SELECT 1')

    def test_exhausted_contention_is_reported_as_contention_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            before = target.read_bytes()
            access = connect_db(target)
            try:
                with self.assertRaises(MigrationContended) as raised:
                    run_migrations(
                        Settings(db_path=str(target)),
                        lock_timeout_seconds=0,
                        contention_budget_seconds=0.2,
                    )
            finally:
                access.close()

            message = str(raised.exception)
            self.assertIn('another Beacon process', message)
            self.assertRegex(message, r'\d')
            self.assertEqual(target.read_bytes(), before)
            self.assertFalse((target.parent / 'backups').exists())
            self.assertFalse((target.parent / 'recovery-required.json').exists())


# Every legacy fixture the suite tracks, plus the operator production fixture --
# the same set exercised by test_each_supported_fixture_upgrades_once_preserving_representative_rows,
# extended with the CURRENT_V4/V6 "already partially current" fixtures so migration 9 is proven
# against a legacy-from-scratch database and a database that already carries several prior
# migrations. This is the suite's own notion of "every legacy fixture" advancing to version 9.
_MIGRATION_NINE_FIXTURES = (
    *FIXTURES,
    'operator/production.db',
    CURRENT_V4_FIXTURE,
    CURRENT_V6_FIXTURE,
)


class MigrationNineTests(unittest.TestCase):
    """Migration 9 (planned maintenance) is additive and idempotent against every legacy fixture."""

    def _copied_fixture(self, directory, filename):
        source_name = filename.replace('/', '-')
        target = Path(directory) / source_name
        copy2(FIXTURE_DIR / filename, target)
        return target

    def test_migration_nine_applies_to_every_legacy_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename in _MIGRATION_NINE_FIXTURES:
                target = self._copied_fixture(directory, filename)
                run_migrations(Settings(db_path=str(target)))
                with sqlite3.connect(target) as conn:
                    window_columns = {row[1] for row in conn.execute('PRAGMA table_info(maintenance_windows)')}
                    self.assertEqual(
                        window_columns,
                        {
                            'id', 'port', 'start_minute', 'duration_minutes', 'weekdays',
                            'grace_minutes', 'enabled', 'created_ts', 'updated_ts',
                        },
                        f'{filename}: maintenance_windows columns missing after migration',
                    )
                    event_columns = {row[1] for row in conn.execute('PRAGMA table_info(events)')}
                    self.assertTrue(
                        {'suppressed_reason', 'maintenance_grace_until', 'down_since_ts'} <= event_columns,
                        f'{filename}: events suppression columns missing after migration',
                    )
                    service_columns = {row[1] for row in conn.execute('PRAGMA table_info(services)')}
                    self.assertIn(
                        'overrun_raised_ts', service_columns,
                        f'{filename}: services.overrun_raised_ts missing after migration',
                    )

    def test_migration_nine_preserves_pre_existing_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename in _MIGRATION_NINE_FIXTURES:
                target = self._copied_fixture(directory, filename)
                with sqlite3.connect(target) as before_conn:
                    before_rows = snapshot_legacy_rows(before_conn, {
                        'services': _LEGACY_PRESERVATION_COLUMNS['services'],
                        'events': _LEGACY_PRESERVATION_COLUMNS['events'],
                    })
                run_migrations(Settings(db_path=str(target)))
                with sqlite3.connect(target) as conn:
                    assert_legacy_rows_preserved(self, before_rows, conn)

    def test_migration_nine_is_a_no_op_on_re_application(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self._copied_fixture(directory, 'initial-2026-04.db')
            run_migrations(Settings(db_path=str(target)))
            with sqlite3.connect(target) as conn:
                before_event_columns = sorted(row[1] for row in conn.execute('PRAGMA table_info(events)'))
                before_service_columns = sorted(row[1] for row in conn.execute('PRAGMA table_info(services)'))
                before_window_count = conn.execute('SELECT COUNT(*) FROM maintenance_windows').fetchone()[0]

                _migration_9_planned_maintenance(conn)  # must not raise

                after_event_columns = sorted(row[1] for row in conn.execute('PRAGMA table_info(events)'))
                after_service_columns = sorted(row[1] for row in conn.execute('PRAGMA table_info(services)'))
                after_window_count = conn.execute('SELECT COUNT(*) FROM maintenance_windows').fetchone()[0]

                self.assertEqual(before_event_columns, after_event_columns)
                self.assertEqual(before_service_columns, after_service_columns)
                self.assertEqual(before_window_count, after_window_count)

    def test_migration_nine_declares_itself_schema_changing(self):
        migration_nine = next(migration for migration in MIGRATIONS if migration.version == 9)
        self.assertTrue(migration_nine.schema_changing)


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
