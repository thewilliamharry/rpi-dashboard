"""Parameterized SQLite queries used by thin Beacon adapters.

Repository functions receive an already-open connection.  They deliberately do
not own Flask request state, network clients, browsers, or connection lifetime.
"""

import json


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
    conn.execute(
        "INSERT INTO preview_requests(port, requested_ts, status, error) VALUES(?,?,'queued',NULL) "
        "ON CONFLICT(port) DO UPDATE SET requested_ts=excluded.requested_ts, status='queued', error=NULL",
        (port, requested_ts),
    )


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
