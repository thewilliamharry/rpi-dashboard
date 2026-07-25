import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dashboard.beacon.inventory import InventoryError, classify_schema, collect_inventory


FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'legacy'
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


if __name__ == '__main__':
    unittest.main()
