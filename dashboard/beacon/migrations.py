"""Versioned, locked SQLite migrations with verified recovery snapshots."""

from contextlib import ExitStack, closing
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import logging
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


log = logging.getLogger('beacon.migrations')

BACKUP_RETENTION = 3
LOCK_NAME = UPGRADE_LOCK_NAME
RECOVERY_MARKER = 'recovery-required.json'
SUPPORT_FLOOR_PATH = Path(__file__).with_name('support_floor.json')

# connect_db (db.py) grants each ordinary Beacon connection up to a 30-second
# flock wait (db.py's _acquire_lock default timeout for the shared maintenance
# lease) plus a 30-second SQLite busy timeout (connect_db's own
# PRAGMA busy_timeout=30000) -- so one worst-case ordinary connection can
# occupy the database for up to 60 seconds. The compose web healthcheck
# (docker-compose.yml) opens a fresh connection every 10 seconds. This budget
# spans four worst-case ordinary connections (4 * 60s = 240s) and twenty-four
# healthcheck cycles (24 * 10s = 240s). This budget is enforced as a hard
# ceiling: the retry loop below caps every per-attempt exclusive-maintenance
# timeout at whatever remains of it, so it is binding, not aspirational.
CONTENTION_BUDGET_SECONDS = 240

# connect_db (db.py) sets PRAGMA busy_timeout=30000 (30 seconds) on every
# ordinary Beacon connection; the pre-escalation read helpers below match
# that exact convention so a live ordinary writer is waited out instead of
# racing it and raising a locked-database error.
READ_BUSY_TIMEOUT_SECONDS = 30


class UnsupportedSchemaError(RuntimeError):
    """The local database was not present in the evidence-backed support floor."""


class MigrationPreparationError(RuntimeError):
    """A migration failed after its verified recovery snapshot was created."""


class MigrationContended(RuntimeError):
    """Ordinary Beacon database access never yielded the exclusive maintenance
    lease within the contention budget.

    This is NOT a migration failure: no verified backup was created, no
    recovery marker was written, and the database bytes are untouched. It
    means another Beacon process -- an ordinary web request, a healthcheck
    connection, or a second migrator -- held the database for the whole
    contention budget.
    """


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
    has_legacy_pressure = False
    legacy_pressure_start = None
    if state_row is not None:
        try:
            state = json.loads(state_row[0])
        except (TypeError, ValueError) as exc:
            raise ValueError('invalid telemetry retention state') from exc
        if not isinstance(state, dict) or not isinstance(state.get('pressure_gaps'), dict):
            raise ValueError('invalid telemetry retention state')
        pressure_gaps = dict(state['pressure_gaps'])
        has_legacy_pressure = 'host:host' in pressure_gaps
        legacy_pressure_start = pressure_gaps.get('host:host')
        if has_legacy_pressure and (
            isinstance(legacy_pressure_start, bool) or not isinstance(legacy_pressure_start, int)
        ):
            raise ValueError('invalid legacy host pressure gap')

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

    if has_legacy_pressure:
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


def _migration_8_background_job_health(conn):
    """Add durable, bounded worker callback outcome evidence.

    The migration is intentionally additive: existing telemetry and service
    evidence remains untouched, while the primary key preserves one current
    row for each immutable worker callback identifier.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS background_job_health ("
        "job_id TEXT PRIMARY KEY, "
        "last_started_ts INTEGER, "
        "last_finished_ts INTEGER, "
        "last_success_ts INTEGER, "
        "state TEXT NOT NULL CHECK (state IN ('running', 'succeeded', 'failed')), "
        "error_class TEXT, "
        "updated_ts INTEGER NOT NULL"
        ")"
    )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_background_job_health_state_updated '
        'ON background_job_health(state, updated_ts DESC)'
    )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_background_job_health_updated '
        'ON background_job_health(updated_ts DESC)'
    )


def _migration_9_planned_maintenance(conn):
    """Add operator-managed maintenance windows and suppression/overrun bookkeeping.

    Additive only: no existing table is altered destructively, matching every
    prior migration's compatibility contract. No FOREIGN KEY is declared on
    ``port`` -- no existing port-keyed table in this file declares one either.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS maintenance_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port INTEGER NOT NULL,
            start_minute INTEGER NOT NULL CHECK (start_minute >= 0 AND start_minute < 1440),
            duration_minutes INTEGER NOT NULL CHECK (duration_minutes >= 1),
            weekdays TEXT NOT NULL,
            grace_minutes INTEGER NOT NULL CHECK (grace_minutes >= 0),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_ts INTEGER NOT NULL,
            updated_ts INTEGER NOT NULL
        )
    """)
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_maintenance_windows_port '
        'ON maintenance_windows(port, enabled)'
    )
    for column in (
        'suppressed_reason TEXT',
        'maintenance_grace_until INTEGER',
        'down_since_ts INTEGER',
    ):
        _add_column(conn, 'events', column)
    _add_column(conn, 'services', 'overrun_raised_ts INTEGER')


# The phase's chosen default backfill TTL (D-02): 7 days. The runtime-configurable
# THUMBNAIL_TTL_DAYS setting lands in 06-02; this constant only seeds expires_ts for
# thumbnail rows that existed before that setting did, so a pre-migration blob is not
# retained indefinitely just because it predates the configurable TTL.
THUMBNAIL_BACKFILL_TTL_SECONDS = 7 * 86400


def _migration_10_bounded_thumbnail_store(conn):
    """Relocate preview thumbnail blobs off the primary services telemetry table.

    OPS-03: a 2 MiB BLOB column on ``services`` -- the row every scheduled sampling
    job (J3, J4, J5, discovery) reads and writes for basic online/offline state -- is
    exactly the "large preview blobs on the primary telemetry path" OPS-03 forbids.
    This migration creates a dedicated, TTL-expiring ``thumbnails`` table, backfills
    every existing captured blob into it, and empties the blob columns on
    ``services``. The backfill INSERT and the emptying UPDATE run inside the same
    ``BEGIN IMMEDIATE`` transaction ``_apply_pending_migrations`` already wraps every
    migration in, so a failure at any point leaves ``services.thumb_data`` untouched
    (PROH-OPS-03-01). ``services.thumb_ts``, ``thumb_source``, ``thumb_attempt_ts``
    and ``thumb_error`` stay in place and still written -- they are small per-service
    diagnostic facts read by ``/api/thumbnail-status`` and the discovery refresh
    gate; only the blob and its content type leave the primary table.

    A fourth, unrelated step -- adding ``preview_requests.next_attempt_ts`` -- rides
    in this same migration deliberately. Adding a second migration version would
    force a second full support-floor fingerprint round (six lineage fingerprints
    across two JSON manifests plus the test_migrations.py guard) for no schema
    benefit; the column stays unused until 06-03 wires bounded preview retry.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS thumbnails (
            port INTEGER PRIMARY KEY,
            data BLOB,
            mime TEXT,
            captured_ts INTEGER,
            source TEXT,
            expires_ts INTEGER
        )
    """)
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_thumbnails_expires ON thumbnails(expires_ts)'
    )
    conn.execute(
        'INSERT OR IGNORE INTO thumbnails(port, data, mime, captured_ts, source, expires_ts) '
        'SELECT port, thumb_data, thumb_mime, thumb_ts, thumb_source, COALESCE(thumb_ts, 0) + ? '
        'FROM services WHERE thumb_data IS NOT NULL',
        (THUMBNAIL_BACKFILL_TTL_SECONDS,),
    )
    conn.execute(
        'UPDATE services SET thumb_data=NULL, thumb_mime=NULL WHERE thumb_data IS NOT NULL'
    )
    _add_column(conn, 'preview_requests', 'next_attempt_ts INTEGER')


MIGRATIONS = (
    Migration(1, 'baseline_schema', True, _migration_1_baseline),
    Migration(2, 'service_diagnostics', True, _migration_2_service_diagnostics),
    Migration(3, 'metadata_and_state', True, _migration_3_metadata_and_state),
    Migration(4, 'durable_work_queues', True, _migration_4_durable_work_queues),
    Migration(5, 'bounded_telemetry', True, _migration_5_bounded_telemetry),
    Migration(6, 'rollup_latency_counts', True, _migration_6_rollup_latency_counts),
    Migration(7, 'canonical_host_streams', True, _migration_7_canonical_host_streams),
    Migration(8, 'background_job_health', True, _migration_8_background_job_health),
    Migration(9, 'planned_maintenance', True, _migration_9_planned_maintenance),
    Migration(10, 'bounded_thumbnail_store', True, _migration_10_bounded_thumbnail_store),
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
        with closing(sqlite3.connect(database, timeout=30)) as source:
            with closing(sqlite3.connect(partial_path)) as destination:
                source.backup(destination)
        with closing(sqlite3.connect('file:{}?mode=ro'.format(partial_path), uri=True)) as check:
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
    # An explicit busy timeout (matching connect_db's own convention) and a
    # finally-scoped close: the standard library's connection context manager
    # commits/rolls back but does NOT close, which would leak a handle on
    # this hot path once it is called from outside exclusive maintenance.
    conn = sqlite3.connect(database, timeout=READ_BUSY_TIMEOUT_SECONDS)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'schema_migrations' not in tables:
            return 0
        return conn.execute('SELECT COALESCE(MAX(version), 0) FROM schema_migrations').fetchone()[0]
    finally:
        conn.close()


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
    # Guarded above: existence and size are checked before opening anything,
    # so a non-existent or zero-byte database is never brought into being by
    # this read-only check. An explicit busy timeout and a finally-scoped
    # close mirror _recorded_version's hardening for the same reason.
    conn = sqlite3.connect(database, timeout=READ_BUSY_TIMEOUT_SECONDS)
    try:
        return not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
    finally:
        conn.close()


def _apply_pending_migrations(database, marker_path, clock):
    """Run the full inspect/back-up/apply sequence inside exclusive maintenance.

    Moved verbatim out of ``run_migrations`` so the contention retry below can
    wrap only the exclusive-maintenance acquisition, never this work.
    """
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
                # Name the fingerprint and the command that produces it: the
                # operator cannot otherwise tell which shape was rejected, nor
                # supply the evidence a new support floor entry requires.
                raise UnsupportedSchemaError(
                    'unsupported Beacon database schema '
                    f'(schema version {version}, fingerprint {fingerprint}). '
                    'Capture evidence with: python -m beacon.inventory '
                    '--db <database> --output <report.json>'
                )
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
            with closing(sqlite3.connect(database, timeout=30)) as conn:
                with conn:
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


def run_migrations(
    settings,
    *,
    clock=time.time,
    lock_timeout_seconds=30,
    contention_budget_seconds=CONTENTION_BUDGET_SECONDS,
):
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
            #
            # Pending-work fast path: read-only, and it runs only under the
            # upgrade lock -- no other migrator or restorer can be inside
            # exclusive maintenance while that lock is held, which is exactly
            # the invariant that makes reading the recorded version here safe
            # without ever escalating to the exclusive lock.
            if not _is_empty_database(database):
                if _recorded_version(database) >= MIGRATIONS[-1].version:
                    marker_path.unlink(missing_ok=True)
                    return MigrationResult((), ())

            contention_started = time.monotonic()
            contention_deadline = contention_started + contention_budget_seconds
            attempt = 0
            while True:
                with ExitStack() as stack:
                    # Only the acquisition sits inside this handler -- the work
                    # function below is invoked outside the try, so a real error
                    # it raises can never be caught here and reported as
                    # contention. The per-attempt timeout is capped at whatever
                    # budget actually remains (floored at zero) so a contended
                    # start can never block past contention_deadline by up to
                    # one further lock_timeout_seconds (03.1-REVIEW.md WR-01).
                    remaining_budget = max(0.0, contention_deadline - time.monotonic())
                    try:
                        stack.enter_context(
                            exclusive_database_maintenance(
                                database, min(lock_timeout_seconds, remaining_budget)
                            )
                        )
                    except MaintenanceBusy:
                        elapsed = time.monotonic() - contention_started
                        if time.monotonic() >= contention_deadline:
                            raise MigrationContended(
                                'exclusive database maintenance was busy for '
                                f'{elapsed:.1f}s: another Beacon process is holding '
                                'an ordinary database connection'
                            )
                        attempt += 1
                        log.warning(
                            'migration maintenance lock busy after %.1fs (attempt '
                            '%d); another Beacon process is holding an ordinary '
                            'connection, waiting and retrying',
                            elapsed, attempt,
                        )
                        time.sleep(min(0.1 * (2 ** (attempt - 1)), 2.0))
                        continue
                    return _apply_pending_migrations(database, marker_path, clock)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
