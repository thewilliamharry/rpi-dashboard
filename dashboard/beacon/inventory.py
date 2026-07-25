"""Read-only, sanitized SQLite schema inventory for Beacon operators.

The report deliberately contains schema structure and bounded counts only.  It
never reads service metadata, event details, thumbnail data, configuration, or
any other application row values.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys


INVENTORY_FORMAT = 'beacon-schema-inventory/v1'
COUNT_LIMIT = 10_000


class InventoryError(RuntimeError):
    """A safe diagnostic for inputs that cannot be inspected as SQLite."""


def _quote_identifier(identifier):
    return '"{}"'.format(identifier.replace('"', '""'))


def _readonly_connection(db_path):
    resolved = Path(db_path).expanduser().resolve(strict=False)
    if not resolved.is_file():
        raise InventoryError('unable to inspect SQLite database')
    try:
        return sqlite3.connect(resolved.as_uri() + '?mode=ro', uri=True)
    except (OSError, sqlite3.Error) as exc:
        raise InventoryError('unable to inspect SQLite database') from exc


def _tables(conn):
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    result = []
    for name, sql in rows:
        quoted_name = _quote_identifier(name)
        columns = [
            {
                'cid': row[0],
                'name': row[1],
                'type': row[2] or '',
                'not_null': bool(row[3]),
                'default': row[4],
                'primary_key': row[5],
            }
            for row in conn.execute('PRAGMA table_info({})'.format(quoted_name))
        ]
        count = conn.execute(
            'SELECT COUNT(*) FROM (SELECT 1 FROM {} LIMIT ?)'.format(quoted_name),
            (COUNT_LIMIT + 1,),
        ).fetchone()[0]
        indexes = []
        for index_row in conn.execute('PRAGMA index_list({})'.format(quoted_name)):
            index_name = index_row[1]
            indexes.append(
                {
                    'name': index_name,
                    'unique': bool(index_row[2]),
                    'origin': index_row[3],
                    'partial': bool(index_row[4]),
                    'columns': [
                        item[2]
                        for item in conn.execute(
                            'PRAGMA index_info({})'.format(_quote_identifier(index_name))
                        )
                    ],
                }
            )
        result.append(
            {
                'name': name,
                'sql': sql or '',
                'columns': columns,
                'indexes': sorted(indexes, key=lambda index: index['name']),
                'row_count': min(count, COUNT_LIMIT),
                'row_count_capped': count > COUNT_LIMIT,
            }
        )
    return result


def _migration_versions(conn, table_names):
    if 'schema_migrations' not in table_names:
        return []
    columns = {
        row[1] for row in conn.execute('PRAGMA table_info("schema_migrations")')
    }
    if 'version' not in columns:
        return []
    return [
        row[0]
        for row in conn.execute(
            'SELECT version FROM "schema_migrations" ORDER BY version LIMIT ?',
            (COUNT_LIMIT,),
        )
    ]


def _fingerprint_payload(tables):
    """Exclude volatile counts, storage metrics, and migration state from identity."""
    return [
        {
            'name': table['name'],
            'sql': table['sql'],
            'columns': table['columns'],
            'indexes': table['indexes'],
        }
        for table in tables
    ]


def collect_inventory(db_path):
    """Collect an allowlisted structural report without modifying ``db_path``."""
    path = Path(db_path).expanduser()
    try:
        before = path.stat()
        conn = _readonly_connection(path)
        try:
            tables = _tables(conn)
            table_names = {table['name'] for table in tables}
            page_size = conn.execute('PRAGMA page_size').fetchone()[0]
            page_count = conn.execute('PRAGMA page_count').fetchone()[0]
            freelist_count = conn.execute('PRAGMA freelist_count').fetchone()[0]
            journal_mode = conn.execute('PRAGMA journal_mode').fetchone()[0]
            payload = _fingerprint_payload(tables)
            canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
            report = {
                'format': INVENTORY_FORMAT,
                'schema_fingerprint': hashlib.sha256(canonical.encode('utf-8')).hexdigest(),
                'tables': tables,
                'migration_versions': _migration_versions(conn, table_names),
                'page': {
                    'page_size': page_size,
                    'page_count': page_count,
                    'freelist_count': freelist_count,
                },
                'journal_mode': journal_mode,
                'database_bytes': before.st_size,
                'wal_bytes': os.path.getsize(str(path) + '-wal') if Path(str(path) + '-wal').is_file() else 0,
            }
        finally:
            conn.close()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise InventoryError('unable to inspect SQLite database')
        return report
    except InventoryError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise InventoryError('unable to inspect SQLite database') from exc


def classify_schema(report):
    """Return the deterministic schema identity used by the later support floor."""
    try:
        fingerprint = report['schema_fingerprint']
    except (KeyError, TypeError) as exc:
        raise InventoryError('invalid inventory report') from exc
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise InventoryError('invalid inventory report')
    return fingerprint


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Produce a sanitized, read-only Beacon SQLite schema inventory.',
        epilog=(
            'Operator command: PYTHONPATH=dashboard dashboard/.venv/bin/python '
            '-m beacon.inventory --db /absolute/path/to/deployed/dashboard.db '
            '--output tests/fixtures/legacy/operator/<deployment-label>.json\n\n'
            'Create the paired sanitized fixture separately at '
            'tests/fixtures/legacy/operator/<deployment-label>.db. This command does not '
            'select a migration support floor and never emits row values.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--db', required=True, help='absolute path to an existing Beacon SQLite database')
    parser.add_argument('--output', required=True, help='path for the sanitized JSON report')
    args = parser.parse_args(argv)
    try:
        report = collect_inventory(args.db)
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    except InventoryError as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    sys.exit(main())
