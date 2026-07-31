"""Versioned, locked SQLite migrations with verified recovery snapshots."""

from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Callable
from uuid import uuid4

from .inventory import collect_inventory, classify_schema


BACKUP_RETENTION = 3
LOCK_NAME = '.beacon-upgrade.lock'
RECOVERY_MARKER = 'recovery-required.json'
SUPPORT_FLOOR_PATH = Path(__file__).with_name('support_floor.json')


class UnsupportedSchemaError(RuntimeError):
    """The local database was not present in the evidence-backed support floor."""


class MigrationPreparationError(RuntimeError):
    """A migration failed after its verified recovery snapshot was created."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    schema_changing: bool
    apply: Callable[[sqlite3.Connection], None]


@dataclass(frozen=True)
class MigrationResult:
    applied_versions: tuple[int, ...]
    backups: tuple[Path, ...]


def _column_names(conn, table):
    quoted = '"{}"'.format(table.replace('"', '""'))
    return {row[1] for row in conn.execute('PRAGMA table_info({})'.format(quoted))}


def _add_column(conn, table, column_sql):
    column_name = column_sql.split()[0]
    if column_name not in _column_names(conn, table):
        conn.execute('ALTER TABLE {} ADD COLUMN {}'.format(table, column_sql))


def _migration_1_baseline(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, applied_ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stats_history (
            ts INTEGER PRIMARY KEY, cpu REAL, ram REAL, disk REAL, temp REAL
        );
        CREATE TABLE IF NOT EXISTS system_stats (
            id INTEGER PRIMARY KEY CHECK (id = 1), sample_ts INTEGER NOT NULL,
            cpu REAL NOT NULL, ram REAL NOT NULL, ram_used INTEGER NOT NULL,
            ram_available INTEGER NOT NULL, ram_used_strict INTEGER NOT NULL,
            ram_total INTEGER NOT NULL, disk REAL NOT NULL, disk_used INTEGER NOT NULL,
            disk_total INTEGER NOT NULL, temp REAL, hostname TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS services (
            port INTEGER PRIMARY KEY, title TEXT, first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL, is_online INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS service_meta (
            port INTEGER PRIMARY KEY, display_name TEXT, url TEXT,
            critical INTEGER DEFAULT 0, pinned_order INTEGER DEFAULT 0, tags TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS service_checks (
            ts INTEGER, port INTEGER, online INTEGER, PRIMARY KEY (ts, port)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, port INTEGER,
            event_type TEXT NOT NULL, online INTEGER, previous_online INTEGER,
            latency_ms REAL, error_class TEXT, alert_status TEXT, details TEXT
        );
        CREATE TABLE IF NOT EXISTS runtime_state (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, requested_ts INTEGER NOT NULL,
            requested_by TEXT, status TEXT NOT NULL DEFAULT 'queued', started_ts INTEGER,
            completed_ts INTEGER, error TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_rate_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT, client_key TEXT NOT NULL, ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS preview_requests (
            port INTEGER PRIMARY KEY, requested_ts INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued', error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats_history(ts);
        CREATE INDEX IF NOT EXISTS idx_checks_ts ON service_checks(ts);
        CREATE INDEX IF NOT EXISTS idx_checks_port ON service_checks(port);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_port_ts ON events(port, ts);
        CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status, requested_ts);
        CREATE INDEX IF NOT EXISTS idx_scan_rate_hits_client_ts ON scan_rate_hits(client_key, ts);
    """)


def _migration_2_service_diagnostics(conn):
    for column in (
        'thumb_data BLOB', 'thumb_mime TEXT DEFAULT \'image/jpeg\'', 'thumb_ts INTEGER',
        'thumb_source TEXT', 'thumb_attempt_ts INTEGER', 'thumb_error TEXT',
        'last_latency_ms REAL', 'last_error TEXT', 'state_since INTEGER',
    ):
        _add_column(conn, 'services', column)
    _add_column(conn, 'service_checks', 'latency_ms REAL')
    _add_column(conn, 'service_checks', 'error_class TEXT')


def _migration_3_metadata_and_state(conn):
    _add_column(conn, 'service_meta', "healthy_statuses TEXT DEFAULT '200-399'")
    conn.execute(
        "UPDATE services SET thumb_data=NULL, thumb_mime='image/jpeg', thumb_ts=NULL, thumb_source=NULL "
        "WHERE thumb_source='fallback'"
    )
    conn.execute(
        "INSERT OR IGNORE INTO service_meta (port, url, critical, pinned_order, tags, healthy_statuses) "
        "SELECT port, 'http://127.0.0.1:' || port, 0, port, '', '200-399' FROM services"
    )
    conn.execute("""
        UPDATE services
           SET state_since = COALESCE(
               (SELECT MAX(e.ts) FROM events e
                 WHERE e.port = services.port AND e.event_type = 'state_change'
                   AND e.online = services.is_online),
               CASE WHEN services.is_online = 1 THEN services.first_seen ELSE services.last_seen END
           )
         WHERE state_since IS NULL
    """)


MIGRATIONS = (
    Migration(1, 'baseline_schema', True, _migration_1_baseline),
    Migration(2, 'service_diagnostics', True, _migration_2_service_diagnostics),
    Migration(3, 'metadata_and_state', True, _migration_3_metadata_and_state),
)


def _storage_paths(db_path):
    database = Path(db_path).expanduser().resolve(strict=False)
    data_dir = database.parent
    return database, data_dir / 'backups', data_dir / LOCK_NAME, data_dir / RECOVERY_MARKER


def _verified_backups(backup_dir):
    return sorted(backup_dir.glob('dashboard-*-pre-v*.db'), key=lambda item: item.stat().st_mtime_ns)


def _retain_verified_backups(backup_dir):
    for backup in _verified_backups(backup_dir)[:-BACKUP_RETENTION]:
        backup.unlink()


def create_verified_backup(db_path, *, target_version, clock=time.time):
    """Create, integrity-check, atomically admit, and retain a local snapshot."""
    database, backup_dir, _, _ = _storage_paths(db_path)
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    timestamp = datetime.fromtimestamp(clock(), tz=timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    token = uuid4().hex[:12]
    final_path = backup_dir / 'dashboard-{}-{}-pre-v{}.db'.format(timestamp, token, target_version)
    partial_path = final_path.with_suffix('.db.partial')
    try:
        with sqlite3.connect(database, timeout=30) as source:
            with sqlite3.connect(partial_path) as destination:
                source.backup(destination)
        with sqlite3.connect('file:{}?mode=ro'.format(partial_path), uri=True) as check:
            integrity = check.execute('PRAGMA integrity_check').fetchone()[0]
        if integrity != 'ok':
            raise MigrationPreparationError('backup integrity validation failed')
        os.replace(partial_path, final_path)
        _retain_verified_backups(backup_dir)
        return final_path
    except Exception:
        partial_path.unlink(missing_ok=True)
        raise


def _support_floor():
    try:
        payload = json.loads(SUPPORT_FLOOR_PATH.read_text(encoding='utf-8'))
        return {entry['fingerprint']: entry for entry in payload['supported_schemas']}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise MigrationPreparationError('migration support floor is unavailable') from exc


def _recorded_version(database):
    with sqlite3.connect(database) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'schema_migrations' not in tables:
            return 0
        return conn.execute('SELECT COALESCE(MAX(version), 0) FROM schema_migrations').fetchone()[0]


def _write_recovery_marker(marker_path, *, target_version, reason_class, backup):
    payload = {
        'failed_target_version': target_version,
        'reason_class': reason_class,
        'backup_catalog_id': backup.name if backup else None,
        'timestamp': int(time.time()),
    }
    temporary = marker_path.with_suffix('.json.partial')
    temporary.write_text(json.dumps(payload, sort_keys=True) + '\n', encoding='utf-8')
    os.replace(temporary, marker_path)


def _is_empty_database(database):
    if not database.exists() or database.stat().st_size == 0:
        return True
    with sqlite3.connect(database) as conn:
        return not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()


def run_migrations(settings, *, clock=time.time, lock_timeout_seconds=30):
    """Upgrade a supported database while holding the process-wide upgrade lock."""
    database, _, lock_path, marker_path = _storage_paths(settings.db_path)
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path.touch(mode=0o600, exist_ok=True)
    deadline = time.monotonic() + lock_timeout_seconds
    with lock_path.open('a+') as lock_handle:
        while True:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise MigrationPreparationError('migration lock timeout')
                time.sleep(0.05)
        try:
            new_database = _is_empty_database(database)
            if new_database:
                sqlite3.connect(database).close()
                version = 0
            else:
                version = _recorded_version(database)
                if version < MIGRATIONS[-1].version:
                    fingerprint = classify_schema(collect_inventory(database))
                    floor_entry = _support_floor().get(fingerprint)
                    if not floor_entry:
                        raise UnsupportedSchemaError('unsupported Beacon database schema')
                    # Sanitized fixtures intentionally contain no operational migration
                    # rows.  The evidence-backed floor supplies the compatible starting
                    # point only after an exact structural fingerprint match.
                    version = max(version, floor_entry['minimum_schema_version'])
            pending = tuple(migration for migration in MIGRATIONS if migration.version > version)
            if not pending:
                marker_path.unlink(missing_ok=True)
                return MigrationResult((), ())
            applied = []
            backups = []
            for migration in pending:
                backup = None
                try:
                    if migration.schema_changing and not new_database:
                        backup = create_verified_backup(database, target_version=migration.version, clock=clock)
                        backups.append(backup)
                    with sqlite3.connect(database, timeout=30) as conn:
                        conn.execute('PRAGMA foreign_keys=ON')
                        conn.execute('BEGIN IMMEDIATE')
                        migration.apply(conn)
                        conn.execute(
                            'INSERT INTO schema_migrations(version, applied_ts) VALUES(?, ?)',
                            (migration.version, int(clock())),
                        )
                        conn.commit()
                    applied.append(migration.version)
                    new_database = False
                except Exception as exc:
                    _write_recovery_marker(
                        marker_path,
                        target_version=migration.version,
                        reason_class=type(exc).__name__,
                        backup=backup,
                    )
                    if isinstance(exc, (UnsupportedSchemaError, MigrationPreparationError)):
                        raise
                    raise MigrationPreparationError('migration preparation failed') from exc
            marker_path.unlink(missing_ok=True)
            return MigrationResult(tuple(applied), tuple(backups))
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
