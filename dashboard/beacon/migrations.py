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

from .db import (
    MaintenanceBusy,
    UPGRADE_LOCK_NAME,
    exclusive_database_maintenance,
    upgrade_lock_path,
)
from .inventory import collect_inventory, classify_schema


BACKUP_RETENTION = 3
LOCK_NAME = UPGRADE_LOCK_NAME
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


def _migration_4_durable_work_queues(conn):
    """Add durable lease/deadline state without discarding queued legacy work."""
    for column in (
        'deadline_ts INTEGER', 'lease_owner TEXT', 'lease_until INTEGER',
        'attempt_count INTEGER NOT NULL DEFAULT 0', 'terminal_ts INTEGER',
        'result TEXT',
    ):
        _add_column(conn, 'scan_requests', column)
    conn.execute(
        "UPDATE scan_requests SET deadline_ts=requested_ts + 900 WHERE deadline_ts IS NULL"
    )

    preview_columns = _column_names(conn, 'preview_requests')
    if 'revision' not in preview_columns:
        conn.execute('ALTER TABLE preview_requests RENAME TO preview_requests_legacy')
        conn.execute("""
            CREATE TABLE preview_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port INTEGER NOT NULL,
                requested_ts INTEGER NOT NULL,
                deadline_ts INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                error TEXT,
                revision INTEGER NOT NULL,
                lease_owner TEXT,
                lease_until INTEGER,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                started_ts INTEGER,
                completed_ts INTEGER,
                terminal_ts INTEGER,
                result TEXT
            )
        """)
        conn.execute("""
            INSERT INTO preview_requests(
                port, requested_ts, deadline_ts, status, error, revision
            )
            SELECT port, requested_ts, requested_ts + 1800, status, error, 1
              FROM preview_requests_legacy
        """)
        conn.execute('DROP TABLE preview_requests_legacy')
    else:
        for column in (
            'deadline_ts INTEGER', 'lease_owner TEXT', 'lease_until INTEGER',
            'attempt_count INTEGER NOT NULL DEFAULT 0', 'started_ts INTEGER',
            'completed_ts INTEGER', 'terminal_ts INTEGER', 'result TEXT',
        ):
            _add_column(conn, 'preview_requests', column)
        conn.execute(
            "UPDATE preview_requests SET deadline_ts=requested_ts + 1800 WHERE deadline_ts IS NULL"
        )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_preview_requests_claim '
        'ON preview_requests(status, deadline_ts, requested_ts)'
    )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_preview_requests_port_revision '
        'ON preview_requests(port, revision DESC)'
    )


def _migration_5_bounded_telemetry(conn):
    """Add the durable, empty telemetry evidence store without rewriting history."""
    statements = (
        """CREATE TABLE telemetry_streams (
            stream_kind TEXT NOT NULL,
            stream_key TEXT NOT NULL,
            started_ts INTEGER NOT NULL,
            cadence_seconds INTEGER NOT NULL CHECK (cadence_seconds > 0),
            last_observed_ts INTEGER,
            consecutive_misses INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_misses >= 0),
            open_gap_start_ts INTEGER,
            PRIMARY KEY (stream_kind, stream_key)
        )""",
        """CREATE TABLE host_metric_rollups (
            metric TEXT NOT NULL,
            bucket_start INTEGER NOT NULL,
            bucket_seconds INTEGER NOT NULL CHECK (bucket_seconds > 0),
            min_value REAL,
            max_value REAL,
            avg_value REAL,
            latest_value REAL,
            sample_count INTEGER NOT NULL CHECK (sample_count >= 0),
            observed_seconds INTEGER NOT NULL CHECK (observed_seconds >= 0),
            gap_seconds INTEGER NOT NULL CHECK (gap_seconds >= 0),
            unknown_seconds INTEGER NOT NULL CHECK (unknown_seconds >= 0),
            PRIMARY KEY (metric, bucket_start, bucket_seconds)
        )""",
        """CREATE TABLE service_rollups (
            service_port INTEGER NOT NULL,
            bucket_start INTEGER NOT NULL,
            bucket_seconds INTEGER NOT NULL CHECK (bucket_seconds > 0),
            online_seconds INTEGER NOT NULL CHECK (online_seconds >= 0),
            offline_seconds INTEGER NOT NULL CHECK (offline_seconds >= 0),
            unknown_seconds INTEGER NOT NULL CHECK (unknown_seconds >= 0),
            gap_seconds INTEGER NOT NULL CHECK (gap_seconds >= 0),
            latency_min REAL,
            latency_max REAL,
            latency_avg REAL,
            check_count INTEGER NOT NULL CHECK (check_count >= 0),
            failure_class_counts_json TEXT NOT NULL,
            PRIMARY KEY (service_port, bucket_start, bucket_seconds)
        )""",
        """CREATE TABLE telemetry_coverage (
            id INTEGER PRIMARY KEY,
            stream_kind TEXT NOT NULL,
            stream_key TEXT NOT NULL,
            start_ts INTEGER NOT NULL,
            end_ts INTEGER NOT NULL CHECK (end_ts > start_ts),
            reason TEXT NOT NULL CHECK (reason IN (
                'collection_gap', 'unknown', 'expired', 'not_yet_monitored'
            )),
            detail TEXT
        )""",
        """CREATE TABLE telemetry_rollup_jobs (
            stream_kind TEXT NOT NULL,
            stream_key TEXT NOT NULL,
            bucket_start INTEGER NOT NULL,
            bucket_seconds INTEGER NOT NULL CHECK (bucket_seconds > 0),
            state TEXT NOT NULL CHECK (state IN ('pending', 'failed', 'succeeded')),
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
            next_retry_ts INTEGER,
            last_error_class TEXT,
            updated_ts INTEGER NOT NULL,
            PRIMARY KEY (stream_kind, stream_key, bucket_start, bucket_seconds)
        )""",
        'CREATE INDEX idx_checks_port_ts ON service_checks(port, ts)',
        'CREATE INDEX idx_host_rollups_range '
        'ON host_metric_rollups(metric, bucket_seconds, bucket_start)',
        'CREATE INDEX idx_service_rollups_range '
        'ON service_rollups(service_port, bucket_seconds, bucket_start)',
        'CREATE INDEX idx_telemetry_coverage_range '
        'ON telemetry_coverage(stream_kind, stream_key, start_ts, end_ts)',
        'CREATE INDEX idx_telemetry_rollup_jobs_due '
        'ON telemetry_rollup_jobs(state, next_retry_ts, updated_ts)',
    )
    for statement in statements:
        conn.execute(statement)


def _migration_6_rollup_latency_counts(conn):
    """Store the denominator required for exact cross-tier latency averages."""
    _add_column(
        conn,
        'service_rollups',
        'latency_sample_count INTEGER NOT NULL DEFAULT 0 CHECK (latency_sample_count >= 0)',
    )


_CANONICAL_HOST_METRICS = ('cpu', 'ram', 'disk', 'temp')


def _subtract_covered_segments(start_ts, end_ts, blockers):
    """Return half-open fragments not covered by the supplied half-open blockers."""
    fragments = [(int(start_ts), int(end_ts))]
    for blocker_start, blocker_end in sorted(blockers):
        next_fragments = []
        for fragment_start, fragment_end in fragments:
            if blocker_end <= fragment_start or blocker_start >= fragment_end:
                next_fragments.append((fragment_start, fragment_end))
                continue
            if fragment_start < blocker_start:
                next_fragments.append((fragment_start, blocker_start))
            if blocker_end < fragment_end:
                next_fragments.append((blocker_end, fragment_end))
        fragments = next_fragments
        if not fragments:
            break
    return tuple(fragments)


def _coalesce_coverage_segments(segments):
    """Coalesce only equal-reason/detail canonical coverage segments."""
    merged = []
    for start_ts, end_ts, reason, detail in sorted(
        segments,
        key=lambda segment: (
            segment[0], segment[1], segment[2],
            segment[3] is not None, str(segment[3] or ''),
        ),
    ):
        if (
            merged
            and merged[-1][2:] == (reason, detail)
            and start_ts <= merged[-1][1]
        ):
            merged[-1] = (merged[-1][0], max(merged[-1][1], end_ts), reason, detail)
        else:
            merged.append((start_ts, end_ts, reason, detail))
    return tuple(merged)


def _canonical_host_coverage(conn, metric, legacy_rows):
    """Return metric-specific coverage with canonical rows taking precedence."""
    existing_rows = conn.execute(
        'SELECT id, start_ts, end_ts, reason, detail FROM telemetry_coverage '
        'WHERE stream_kind=? AND stream_key=? ORDER BY start_ts, end_ts, id',
        ('host', metric),
    ).fetchall()
    segments = []
    blockers = []
    for _, start_ts, end_ts, reason, detail in (*existing_rows, *legacy_rows):
        for fragment_start, fragment_end in _subtract_covered_segments(
            start_ts, end_ts, blockers,
        ):
            segments.append((fragment_start, fragment_end, reason, detail))
            blockers.append((fragment_start, fragment_end))
    return _coalesce_coverage_segments(segments)


def _migration_7_canonical_host_streams(conn):
    """Expand the obsolete shared host availability identity into fixed metrics."""
    legacy_stream = conn.execute(
        'SELECT started_ts, cadence_seconds, last_observed_ts, consecutive_misses, '
        'open_gap_start_ts FROM telemetry_streams WHERE stream_kind=? AND stream_key=?',
        ('host', 'host'),
    ).fetchone()
    legacy_coverage = conn.execute(
        'SELECT id, start_ts, end_ts, reason, detail FROM telemetry_coverage '
        'WHERE stream_kind=? AND stream_key=? ORDER BY start_ts, end_ts, id',
        ('host', 'host'),
    ).fetchall()
    state_row = conn.execute(
        'SELECT value FROM runtime_state WHERE key=?', ('telemetry_retention_state',),
    ).fetchone()

    state = None
    pressure_gaps = None
    if state_row is not None:
        try:
            state = json.loads(state_row[0])
        except (TypeError, ValueError) as exc:
            raise ValueError('invalid telemetry retention state') from exc
        if not isinstance(state, dict) or not isinstance(state.get('pressure_gaps'), dict):
            raise ValueError('invalid telemetry retention state')
        pressure_gaps = dict(state['pressure_gaps'])
        legacy_pressure_start = pressure_gaps.get('host:host')
        if legacy_pressure_start is not None and (
            isinstance(legacy_pressure_start, bool) or not isinstance(legacy_pressure_start, int)
        ):
            raise ValueError('invalid legacy host pressure gap')
    else:
        legacy_pressure_start = None

    if legacy_stream is not None:
        for metric in _CANONICAL_HOST_METRICS:
            existing_stream = conn.execute(
                'SELECT started_ts, cadence_seconds, last_observed_ts, consecutive_misses, '
                'open_gap_start_ts FROM telemetry_streams WHERE stream_kind=? AND stream_key=?',
                ('host', metric),
            ).fetchone()
            if existing_stream is None:
                merged = legacy_stream
            else:
                legacy_observed = legacy_stream[2]
                existing_observed = existing_stream[2]
                use_legacy_state = (
                    legacy_observed is not None
                    and (existing_observed is None or legacy_observed > existing_observed)
                )
                state_source = legacy_stream if use_legacy_state else existing_stream
                observed_candidates = [
                    value for value in (legacy_observed, existing_observed) if value is not None
                ]
                merged = (
                    min(legacy_stream[0], existing_stream[0]),
                    state_source[1],
                    max(observed_candidates) if observed_candidates else None,
                    state_source[3],
                    state_source[4],
                )
            conn.execute(
                'INSERT INTO telemetry_streams('
                'stream_kind, stream_key, started_ts, cadence_seconds, last_observed_ts, '
                'consecutive_misses, open_gap_start_ts) VALUES(?,?,?,?,?,?,?) '
                'ON CONFLICT(stream_kind, stream_key) DO UPDATE SET '
                'started_ts=excluded.started_ts, cadence_seconds=excluded.cadence_seconds, '
                'last_observed_ts=excluded.last_observed_ts, '
                'consecutive_misses=excluded.consecutive_misses, '
                'open_gap_start_ts=excluded.open_gap_start_ts',
                ('host', metric, *merged),
            )

    if legacy_coverage:
        for metric in _CANONICAL_HOST_METRICS:
            segments = _canonical_host_coverage(conn, metric, legacy_coverage)
            conn.execute(
                'DELETE FROM telemetry_coverage WHERE stream_kind=? AND stream_key=?',
                ('host', metric),
            )
            conn.executemany(
                'INSERT INTO telemetry_coverage('
                'stream_kind, stream_key, start_ts, end_ts, reason, detail) '
                'VALUES(?,?,?,?,?,?)',
                [
                    ('host', metric, start_ts, end_ts, reason, detail)
                    for start_ts, end_ts, reason, detail in segments
                ],
            )

    if legacy_pressure_start is not None:
        for metric in _CANONICAL_HOST_METRICS:
            key = 'host:{}'.format(metric)
            existing_start = pressure_gaps.get(key)
            if existing_start is not None and (
                isinstance(existing_start, bool) or not isinstance(existing_start, int)
            ):
                raise ValueError('invalid canonical host pressure gap')
            pressure_gaps[key] = min(
                legacy_pressure_start,
                existing_start if existing_start is not None else legacy_pressure_start,
            )
        pressure_gaps.pop('host:host')
        state['pressure_gaps'] = pressure_gaps
        conn.execute(
            'UPDATE runtime_state SET value=? WHERE key=?',
            (json.dumps(state, separators=(',', ':'), sort_keys=True), 'telemetry_retention_state'),
        )

    conn.execute(
        'DELETE FROM telemetry_streams WHERE stream_kind=? AND stream_key=?', ('host', 'host'),
    )
    conn.execute(
        'DELETE FROM telemetry_coverage WHERE stream_kind=? AND stream_key=?', ('host', 'host'),
    )


MIGRATIONS = (
    Migration(1, 'baseline_schema', True, _migration_1_baseline),
    Migration(2, 'service_diagnostics', True, _migration_2_service_diagnostics),
    Migration(3, 'metadata_and_state', True, _migration_3_metadata_and_state),
    Migration(4, 'durable_work_queues', True, _migration_4_durable_work_queues),
    Migration(5, 'bounded_telemetry', True, _migration_5_bounded_telemetry),
    Migration(6, 'rollup_latency_counts', True, _migration_6_rollup_latency_counts),
    Migration(7, 'canonical_host_streams', True, _migration_7_canonical_host_streams),
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
    database, _, _, marker_path = _storage_paths(
        getattr(settings, 'db_path', settings)
    )
    lock_path = upgrade_lock_path(database)
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
            # Every operation which can inspect, create, alter, back up, or mark the
            # database runs only after the fixed upgrade -> maintenance lock order.
            with exclusive_database_maintenance(database, lock_timeout_seconds):
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
        except MaintenanceBusy as exc:
            raise MigrationPreparationError('migration maintenance lock timeout') from exc
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
