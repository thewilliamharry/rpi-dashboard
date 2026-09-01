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

# Human-readable description of which _readonly_connection attempt produced a
# reading, recorded in the report alongside journal_mode. The immutable
# strategy's description carries its own caveat inline -- ignoring the -wal
# file means such a reading may omit committed but not-yet-checkpointed WAL
# transactions -- so an operator meets the disclosure at the point they read
# the strategy, not only in this module's comments.
_CONNECTION_STRATEGY_DESCRIPTIONS = {
    'mode_ro': 'mode=ro',
    'query_only': 'query_only (opened writable, restricted via PRAGMA query_only=ON)',
    'immutable': (
        'mode=ro&immutable=1 -- ignores the -wal file; a reading taken this way '
        'may omit committed but not-yet-checkpointed WAL transactions'
    ),
}


class InventoryError(RuntimeError):
    """A safe diagnostic for inputs that cannot be inspected as SQLite."""


def _quote_identifier(identifier):
    return '"{}"'.format(identifier.replace('"', '""'))


def _validated(conn):
    """Force any lazy WAL/``-shm`` initialization onto this attempt's own
    exception handling, then return the same connection -- never a new
    binding. Some SQLite builds only attempt the ``-shm`` mapping a WAL
    database needs at first *statement execution*, not at ``connect()`` time;
    without this probe such an attempt would appear to succeed here and defer
    its failure to the caller's first real query, entirely outside every
    attempt's ``except`` clause below, silently defeating the fallback chain.
    Closes ``conn`` before re-raising on failure so a probe failure never
    leaks the connection this attempt opened.

    Kept as a pass-through-and-return helper (not an inline assignment in
    ``_readonly_connection``) so the module-boundary connection-ownership
    gate sees ownership transferring directly through the caller's own
    ``return``, exactly like the ``mode=ro&immutable=1`` path's bare
    ``sqlite3.connect(...)`` return does.
    """
    try:
        conn.execute('SELECT 1')
    except sqlite3.Error:
        conn.close()
        raise
    return conn


def _query_only(conn):
    """Configure, validate, and return the same connection -- never a new
    binding -- so the connection-ownership gate sees ownership transferring
    directly through this pass-through helper's own return.
    """
    conn.execute('PRAGMA query_only=ON')
    return _validated(conn)


def _readonly_connection(db_path, strategy=None):
    """Establish a read-only connection for inspection, trying progressively
    more permissive attempts in a fixed order that must not be reordered or
    shortened (PROH-OPS-04-03): ``mode=ro`` first, then a writable connection
    restricted by ``PRAGMA query_only=ON``, and only then ``mode=ro&immutable=1``.
    Reordering the immutable attempt earlier would change which connection the
    live, writable ``/data`` upgrade path receives.

    When ``strategy`` is a dict, its ``'value'`` key is set to which attempt
    produced the returned connection, so the caller can record how a given
    reading was taken.
    """
    resolved = Path(db_path).expanduser().resolve(strict=False)
    if not resolved.is_file():
        raise InventoryError('unable to inspect SQLite database')
    try:
        if strategy is not None:
            strategy['value'] = 'mode_ro'
        return _validated(sqlite3.connect(resolved.as_uri() + '?mode=ro', uri=True))
    except sqlite3.Error:
        # A mode=ro URI connection cannot initialize the -shm shared-memory
        # file a WAL-mode database needs, so schema inspection of a WAL
        # database fails through the URI path above (on some SQLite builds
        # only once a statement actually executes, which is why the attempt
        # above is validated rather than merely connected). Fall back to a
        # normal connection with PRAGMA query_only=ON, which forbids writes
        # at the SQL level while still permitting the -shm mapping WAL
        # requires -- but establishing that connection still needs write
        # access to the source *directory* to map -shm, which a locked-down
        # archival copy will not have.
        try:
            if strategy is not None:
                strategy['value'] = 'query_only'
            return _query_only(sqlite3.connect(resolved))
        except (OSError, sqlite3.Error):
            # Both write-requiring attempts above have failed, which confines
            # this final attempt to media that cannot be hosting a live
            # deployment. immutable=1 tells SQLite the file will not change,
            # so it reads the main database file directly and never attempts
            # to map the -shm sidecar -- exactly why it succeeds here, with no
            # deferred failure left to validate. Being last bounds the hazard
            # but does not eliminate it: an archival copy taken from a running
            # database can carry committed but not-yet-checkpointed
            # transactions in its -wal file, and immutable=1 ignores that file
            # entirely. The recorded strategy discloses this caveat rather
            # than assuming it away.
            try:
                if strategy is not None:
                    strategy['value'] = 'immutable'
                return sqlite3.connect(
                    resolved.as_uri() + '?mode=ro&immutable=1', uri=True,
                )
            except (OSError, sqlite3.Error) as exc:
                raise InventoryError('unable to inspect SQLite database') from exc
    except OSError as exc:
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
        strategy = {}
        conn = _readonly_connection(path, strategy=strategy)
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
                'connection_strategy': _CONNECTION_STRATEGY_DESCRIPTIONS.get(
                    strategy.get('value'), strategy.get('value'),
                ),
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
