"""Parameterized SQLite queries used by thin Beacon adapters.

Repository functions receive an already-open connection.  They deliberately do
not own Flask request state, network clients, browsers, or connection lifetime.
"""

import json
import time

from .queues import enqueue_preview_in_transaction


HOST_METRIC_COLUMNS = {
    'cpu': 'cpu',
    'ram': 'ram',
    'disk': 'disk',
    'temp': 'temp',
}


def get_host_metric_history(conn, metric, start_ts, end_ts, limit):
    """Return one allowlisted raw metric stream in ascending half-open order."""
    column = HOST_METRIC_COLUMNS.get(metric)
    if column is None:
        raise ValueError('invalid host metric')
    return conn.execute(
        f'SELECT ts, {column} AS value FROM stats_history '
        'WHERE ts >= ? AND ts < ? ORDER BY ts ASC LIMIT ?',
        (start_ts, end_ts, limit),
    ).fetchall()


def get_host_stream_bounds(conn):
    """Return the first and last raw host observations without retaining a cursor."""
    row = conn.execute(
        'SELECT MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM stats_history'
    ).fetchone()
    return (row['first_ts'], row['last_ts']) if row and row['first_ts'] is not None else None


class ThumbnailRepository:
    """Own thumbnail result persistence while callers retain transaction scope."""

    def store_thumbnail_result(
        self, conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts=None,
    ):
        timestamp = int(time.time()) if ts is None else int(ts)
        if thumb_data and thumb_source == 'screenshot':
            conn.execute(
                "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=?, thumb_source=?, "
                "thumb_attempt_ts=?, thumb_error=NULL WHERE port=?",
                (thumb_data, thumb_mime, timestamp, thumb_source, timestamp, port),
            )
            return
        conn.execute(
            "UPDATE services SET thumb_data=NULL, thumb_mime='image/jpeg', thumb_ts=NULL, thumb_source=NULL, "
            "thumb_attempt_ts=?, thumb_error=? WHERE port=?",
            (timestamp, (thumb_error or 'screenshot failed')[:240], port),
        )


def get_service_metadata(conn, port):
    row = conn.execute(
        "SELECT m.port, COALESCE(m.display_name, '') AS display_name, "
        "COALESCE(m.url, '') AS url, COALESCE(m.critical, 0) AS critical, "
        "COALESCE(m.pinned_order, s.port) AS pinned_order, "
        "COALESCE(m.tags, '') AS tags, "
        "COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
        "FROM services s LEFT JOIN service_meta m ON m.port = s.port "
        "WHERE s.port = ?",
        (port,),
    ).fetchone()
    return dict(row) if row else None


def get_service_metadata_values(conn, port):
    row = conn.execute(
        "SELECT display_name, url, critical, pinned_order, tags, healthy_statuses "
        "FROM service_meta WHERE port=?",
        (port,),
    ).fetchone()
    return dict(row) if row else None


def service_exists(conn, port):
    return conn.execute('SELECT 1 FROM services WHERE port=?', (port,)).fetchone() is not None


def upsert_service_metadata(
    conn, *, port, display_name, url, critical, pinned_order, tags,
    healthy_statuses, requested_ts,
):
    """Persist metadata and its durable preview request in the caller's transaction."""
    conn.execute(
        "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags, healthy_statuses) "
        "VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(port) DO UPDATE SET display_name=excluded.display_name, url=excluded.url, "
        "critical=excluded.critical, pinned_order=excluded.pinned_order, tags=excluded.tags, "
        "healthy_statuses=excluded.healthy_statuses",
        (port, display_name, url, int(bool(critical)), pinned_order, tags, healthy_statuses),
    )
    return enqueue_preview_in_transaction(conn, port, now=requested_ts)


def get_runtime_state(conn, key, default=None):
    row = conn.execute('SELECT value FROM runtime_state WHERE key=?', (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row['value'])
    except (TypeError, ValueError):
        return default


def set_runtime_state(conn, key, value, updated_ts):
    conn.execute(
        "INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts",
        (key, json.dumps(value, separators=(',', ':')), updated_ts),
    )


def set_service_tls_posture(conn, port, tls_unverified, updated_ts):
    """Persist trust posture separately from service reachability fields."""
    current = get_runtime_state(conn, 'service_tls_posture', {})
    current = current if isinstance(current, dict) else {}
    current[str(int(port))] = bool(tls_unverified)
    set_runtime_state(conn, 'service_tls_posture', current, updated_ts)


def get_service_tls_posture(conn, port):
    current = get_runtime_state(conn, 'service_tls_posture', {})
    return bool(current.get(str(int(port)), False)) if isinstance(current, dict) else False


def get_events(conn, limit, since_ts=None):
    query = (
        "SELECT e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
        "e.latency_ms, e.error_class, e.alert_status, e.details, "
        "COALESCE(m.display_name, s.title, ':' || e.port) AS service_name "
        "FROM events e LEFT JOIN services s ON s.port=e.port "
        "LEFT JOIN service_meta m ON m.port=e.port "
    )
    if since_ts is None:
        return conn.execute(query + 'ORDER BY e.ts DESC, e.id DESC LIMIT ?', (limit,)).fetchall()
    return conn.execute(
        query + 'WHERE e.ts > ? ORDER BY e.ts DESC, e.id DESC LIMIT ?',
        (since_ts, limit),
    ).fetchall()
