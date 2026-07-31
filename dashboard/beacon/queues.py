"""Durable SQLite ownership leases and worker queues.

All cross-process coordination is guarded by short ``BEGIN IMMEDIATE``
transactions.  Process-local locks may reduce contention but never decide who
owns a worker or queue row.
"""

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import time

from .migrations import RECOVERY_MARKER


WORKER_OWNER_KEY = 'worker_owner'


class LeaseHeld(RuntimeError):
    """Another unexpired worker owns the durable worker lease."""


class LeaseLost(RuntimeError):
    """A caller no longer owns the worker lease it is trying to renew."""


@dataclass(frozen=True)
class WorkerLease:
    worker_id: str
    acquired_ts: int
    heartbeat_ts: int
    lease_until: int


@dataclass(frozen=True)
class QueueRequest:
    """A durable scan or preview row returned by enqueue/claim operations."""

    request_id: int
    status: str
    requested_ts: int
    deadline_ts: int
    lease_owner: str | None = None
    lease_until: int | None = None
    port: int | None = None
    revision: int | None = None
    coalesced: bool = False


def _connect(db_path):
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=30000')
    return conn


def _now(now):
    return int(time.time()) if now is None else int(now)


def _load_owner(conn):
    row = conn.execute(
        'SELECT value FROM runtime_state WHERE key=?', (WORKER_OWNER_KEY,)
    ).fetchone()
    if not row:
        return None
    try:
        value = json.loads(row['value'])
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _save_owner(conn, owner, now):
    conn.execute(
        "INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts",
        (WORKER_OWNER_KEY, json.dumps(owner, separators=(',', ':')), now),
    )


def _record_gap(conn, previous, now, ready_seconds):
    heartbeat_ts = previous.get('heartbeat_ts')
    try:
        heartbeat_ts = int(heartbeat_ts)
    except (TypeError, ValueError):
        return previous.get('last_monitoring_gap_end')
    if now - heartbeat_ts <= ready_seconds:
        return previous.get('last_monitoring_gap_end')
    last_end = previous.get('last_monitoring_gap_end')
    if last_end == now:
        return last_end
    details = json.dumps({'start_ts': heartbeat_ts, 'end_ts': now}, separators=(',', ':'))
    conn.execute(
        "INSERT INTO events(ts, event_type, details) VALUES(?, 'monitoring_gap', ?)",
        (now, details),
    )
    return now


def acquire_worker_lease(db_path, worker_id, *, now=None, lease_seconds=15, ready_seconds=20):
    """Atomically acquire the one persisted worker-owner lease."""
    now = _now(now)
    if (Path(db_path).parent / RECOVERY_MARKER).exists():
        raise LeaseHeld('database recovery is required')
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        previous = _load_owner(conn)
        if previous:
            previous_until = int(previous.get('lease_until') or 0)
            if previous_until > now and previous.get('worker_id') != worker_id:
                raise LeaseHeld('worker lease is held')
        gap_end = _record_gap(conn, previous, now, ready_seconds) if previous else None
        owner = {
            'worker_id': str(worker_id),
            'acquired_ts': now,
            'heartbeat_ts': now,
            'lease_until': now + int(lease_seconds),
            'last_monitoring_gap_end': gap_end,
        }
        _save_owner(conn, owner, now)
        conn.commit()
        return WorkerLease(
            worker_id=owner['worker_id'], acquired_ts=owner['acquired_ts'],
            heartbeat_ts=owner['heartbeat_ts'], lease_until=owner['lease_until'],
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def renew_worker_lease(db_path, worker_id, *, now=None, lease_seconds=15):
    """Renew only the matching owner; stale workers receive ``LeaseLost``."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        owner = _load_owner(conn)
        if (
            not owner or owner.get('worker_id') != worker_id
            or int(owner.get('lease_until') or 0) <= now
        ):
            raise LeaseLost('worker lease was lost')
        owner['heartbeat_ts'] = now
        owner['lease_until'] = now + int(lease_seconds)
        _save_owner(conn, owner, now)
        conn.commit()
        return WorkerLease(
            worker_id=str(worker_id), acquired_ts=int(owner['acquired_ts']),
            heartbeat_ts=now, lease_until=int(owner['lease_until']),
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def release_worker_lease(db_path, worker_id, *, now=None):
    """Release only a matching worker owner; a successor is never disturbed."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        owner = _load_owner(conn)
        if not owner or owner.get('worker_id') != worker_id:
            raise LeaseLost('worker lease was lost')
        conn.execute('DELETE FROM runtime_state WHERE key=?', (WORKER_OWNER_KEY,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _queue_request(row, *, coalesced=False):
    return QueueRequest(
        request_id=int(row['id']), status=str(row['status']),
        requested_ts=int(row['requested_ts']), deadline_ts=int(row['deadline_ts']),
        lease_owner=row['lease_owner'], lease_until=row['lease_until'],
        port=row['port'] if 'port' in row.keys() else None,
        revision=row['revision'] if 'revision' in row.keys() else None,
        coalesced=coalesced,
    )


def expire_scan_requests(db_path, *, now=None):
    """Persist terminal expiry for stale scan work; terminal rows stay untouched."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        updated = conn.execute(
            "UPDATE scan_requests SET status='expired', terminal_ts=?, completed_ts=?, "
            "lease_owner=NULL, lease_until=NULL, error='expired' "
            "WHERE status IN ('queued', 'running') AND deadline_ts <= ?",
            (now, now, now),
        ).rowcount
        conn.commit()
        return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def enqueue_scan(db_path, requested_by, *, now=None):
    """Persist one 15-minute manual scan, coalescing a still-queued request."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute(
            'UPDATE scan_requests SET deadline_ts=requested_ts + 900 WHERE deadline_ts IS NULL'
        )
        conn.execute(
            'UPDATE preview_requests SET deadline_ts=requested_ts + 1800 WHERE deadline_ts IS NULL'
        )
        conn.execute(
            "UPDATE scan_requests SET status='expired', terminal_ts=?, completed_ts=?, error='expired' "
            "WHERE status='queued' AND deadline_ts <= ?",
            (now, now, now),
        )
        row = conn.execute(
            "SELECT id, status, requested_ts, deadline_ts, lease_owner, lease_until "
            "FROM scan_requests WHERE status='queued' AND deadline_ts > ? "
            "ORDER BY requested_ts, id LIMIT 1",
            (now,),
        ).fetchone()
        if row:
            conn.commit()
            return _queue_request(row, coalesced=True)
        cur = conn.execute(
            "INSERT INTO scan_requests(requested_ts, requested_by, deadline_ts, status, attempt_count) "
            "VALUES(?,?,?,'queued',0)",
            (now, str(requested_by)[:120], now + 900),
        )
        row = conn.execute(
            "SELECT id, status, requested_ts, deadline_ts, lease_owner, lease_until "
            "FROM scan_requests WHERE id=?", (cur.lastrowid,),
        ).fetchone()
        conn.commit()
        return _queue_request(row)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def claim_scan(db_path, worker_id, *, now=None, lease_seconds=30):
    """Claim one non-expired queued scan using a conditional write transaction."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute(
            "UPDATE scan_requests SET status='expired', terminal_ts=?, completed_ts=?, error='expired' "
            "WHERE status='queued' AND deadline_ts <= ?", (now, now, now),
        )
        row = conn.execute(
            "SELECT id FROM scan_requests WHERE status='queued' AND deadline_ts > ? "
            "ORDER BY requested_ts, id LIMIT 1", (now,),
        ).fetchone()
        if not row:
            conn.commit()
            return None
        request_id = int(row['id'])
        changed = conn.execute(
            "UPDATE scan_requests SET status='running', started_ts=?, lease_owner=?, lease_until=?, "
            "attempt_count=attempt_count + 1, error=NULL "
            "WHERE id=? AND status='queued' AND deadline_ts > ?",
            (now, str(worker_id), now + int(lease_seconds), request_id, now),
        ).rowcount
        if not changed:
            conn.commit()
            return None
        claimed = conn.execute(
            "SELECT id, status, requested_ts, deadline_ts, lease_owner, lease_until "
            "FROM scan_requests WHERE id=?", (request_id,),
        ).fetchone()
        conn.commit()
        return _queue_request(claimed)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def renew_scan_lease(db_path, request_id, worker_id, *, now=None, lease_seconds=30):
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        changed = conn.execute(
            "UPDATE scan_requests SET lease_until=? WHERE id=? AND status='running' "
            "AND lease_owner=? AND lease_until > ? AND deadline_ts > ?",
            (now + int(lease_seconds), request_id, str(worker_id), now, now),
        ).rowcount
        if not changed:
            raise LeaseLost('scan lease was lost')
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _finish_scan(db_path, request_id, worker_id, *, status, error=None, result=None, now=None):
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        changed = conn.execute(
            "UPDATE scan_requests SET status=?, completed_ts=?, terminal_ts=?, error=?, result=?, "
            "lease_owner=NULL, lease_until=NULL WHERE id=? AND status='running' "
            "AND lease_owner=? AND lease_until > ? AND deadline_ts > ?",
            (status, now, now, error, result, request_id, str(worker_id), now, now),
        ).rowcount
        if not changed:
            raise LeaseLost('scan lease was lost')
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finish_scan(db_path, request_id, worker_id, *, result=None, now=None):
    _finish_scan(db_path, request_id, worker_id, status='completed', result=result, now=now)


def fail_scan(db_path, request_id, worker_id, error, *, now=None):
    _finish_scan(db_path, request_id, worker_id, status='failed', error=str(error)[:240], now=now)


def requeue_scan(db_path, request_id, worker_id, *, now=None):
    """Return a still-owned scan to queued when local discovery is busy."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        changed = conn.execute(
            "UPDATE scan_requests SET status='queued', started_ts=NULL, lease_owner=NULL, lease_until=NULL "
            "WHERE id=? AND status='running' AND lease_owner=? AND lease_until > ? AND deadline_ts > ?",
            (request_id, str(worker_id), now, now),
        ).rowcount
        if not changed:
            raise LeaseLost('scan lease was lost')
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def recover_queues(db_path, *, now=None):
    """Recover only lease-expired still-relevant work after a worker restart."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute(
            'UPDATE scan_requests SET deadline_ts=requested_ts + 900 WHERE deadline_ts IS NULL'
        )
        conn.execute(
            'UPDATE preview_requests SET deadline_ts=requested_ts + 1800 WHERE deadline_ts IS NULL'
        )
        conn.execute(
            "UPDATE scan_requests SET status='expired', terminal_ts=?, completed_ts=?, "
            "lease_owner=NULL, lease_until=NULL, error='expired' "
            "WHERE status IN ('queued', 'running') AND deadline_ts <= ?",
            (now, now, now),
        )
        conn.execute(
            "UPDATE scan_requests SET status='queued', started_ts=NULL, lease_owner=NULL, lease_until=NULL "
            "WHERE status='running' AND (lease_until IS NULL OR lease_until <= ?) AND deadline_ts > ?",
            (now, now),
        )
        conn.execute(
            "UPDATE preview_requests SET status='expired', terminal_ts=?, completed_ts=?, "
            "lease_owner=NULL, lease_until=NULL, error='expired' "
            "WHERE status IN ('queued', 'running') AND deadline_ts <= ?",
            (now, now, now),
        )
        conn.execute("""
            UPDATE preview_requests AS stale
               SET status='superseded', terminal_ts=?, lease_owner=NULL, lease_until=NULL,
                   error='superseded'
             WHERE stale.status='running' AND (stale.lease_until IS NULL OR stale.lease_until <= ?)
               AND EXISTS (
                   SELECT 1 FROM preview_requests newer
                    WHERE newer.port=stale.port AND newer.revision > stale.revision
               )
        """, (now, now))
        conn.execute("""
            UPDATE preview_requests AS current
               SET status='queued', started_ts=NULL, lease_owner=NULL, lease_until=NULL
             WHERE current.status='running' AND (current.lease_until IS NULL OR current.lease_until <= ?)
               AND current.deadline_ts > ?
               AND NOT EXISTS (
                   SELECT 1 FROM preview_requests newer
                    WHERE newer.port=current.port AND newer.revision > current.revision
               )
        """, (now, now))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _enqueue_preview_in_transaction(conn, port, *, now):
    conn.execute(
        "UPDATE preview_requests SET status='expired', terminal_ts=?, completed_ts=?, error='expired' "
        "WHERE port=? AND status='queued' AND deadline_ts <= ?",
        (now, now, port, now),
    )
    revision = conn.execute(
        'SELECT COALESCE(MAX(revision), 0) + 1 AS revision FROM preview_requests WHERE port=?',
        (port,),
    ).fetchone()['revision']
    conn.execute(
        "UPDATE preview_requests SET status='superseded', terminal_ts=?, error='superseded' "
        "WHERE port=? AND status='queued'",
        (now, port),
    )
    cur = conn.execute(
        "INSERT INTO preview_requests(port, requested_ts, deadline_ts, status, revision, attempt_count) "
        "VALUES(?,?,?,'queued',?,0)",
        (port, now, now + 1800, revision),
    )
    row = conn.execute(
        "SELECT id, port, revision, status, requested_ts, deadline_ts, lease_owner, lease_until "
        "FROM preview_requests WHERE id=?", (cur.lastrowid,),
    ).fetchone()
    return _queue_request(row)


def enqueue_preview_in_transaction(conn, port, *, now=None):
    """Add a latest preview revision inside a caller-owned metadata transaction."""
    return _enqueue_preview_in_transaction(conn, int(port), now=_now(now))


def enqueue_preview(db_path, port, *, now=None):
    """Persist a 30-minute latest-revision preview request."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        request = _enqueue_preview_in_transaction(conn, int(port), now=now)
        conn.commit()
        return request
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def claim_preview(db_path, worker_id, *, now=None, lease_seconds=60):
    """Claim the latest non-expired preview revision, if any."""
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute(
            "UPDATE preview_requests SET status='expired', terminal_ts=?, completed_ts=?, error='expired' "
            "WHERE status='queued' AND deadline_ts <= ?", (now, now, now),
        )
        row = conn.execute("""
            SELECT p.id FROM preview_requests p
             WHERE p.status='queued' AND p.deadline_ts > ?
               AND NOT EXISTS (
                   SELECT 1 FROM preview_requests newer
                    WHERE newer.port=p.port AND newer.revision > p.revision
               )
             ORDER BY p.requested_ts, p.id LIMIT 1
        """, (now,)).fetchone()
        if not row:
            conn.commit()
            return None
        request_id = int(row['id'])
        changed = conn.execute(
            "UPDATE preview_requests SET status='running', started_ts=?, lease_owner=?, lease_until=?, "
            "attempt_count=attempt_count + 1, error=NULL WHERE id=? AND status='queued' AND deadline_ts > ?",
            (now, str(worker_id), now + int(lease_seconds), request_id, now),
        ).rowcount
        if not changed:
            conn.commit()
            return None
        claimed = conn.execute(
            "SELECT id, port, revision, status, requested_ts, deadline_ts, lease_owner, lease_until "
            "FROM preview_requests WHERE id=?", (request_id,),
        ).fetchone()
        conn.commit()
        return _queue_request(claimed)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def renew_preview_lease(db_path, request_id, worker_id, *, revision, now=None, lease_seconds=60):
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        changed = conn.execute(
            "UPDATE preview_requests SET lease_until=? WHERE id=? AND revision=? AND status='running' "
            "AND lease_owner=? AND lease_until > ? AND deadline_ts > ?",
            (now + int(lease_seconds), request_id, revision, str(worker_id), now, now),
        ).rowcount
        if not changed:
            raise LeaseLost('preview lease was lost')
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finish_preview_in_transaction(conn, request_id, worker_id, *, revision, status='completed', error=None, result=None, now=None):
    """Finish only a current revision while the caller holds its write transaction."""
    now = _now(now)
    row = conn.execute(
        'SELECT port FROM preview_requests WHERE id=? AND revision=?', (request_id, revision),
    ).fetchone()
    if not row:
        raise LeaseLost('preview request no longer exists')
    newer = conn.execute(
        'SELECT 1 FROM preview_requests WHERE port=? AND revision > ? LIMIT 1',
        (row['port'], revision),
    ).fetchone()
    if newer:
        raise LeaseLost('preview revision was superseded')
    changed = conn.execute(
        "UPDATE preview_requests SET status=?, completed_ts=?, terminal_ts=?, error=?, result=?, "
        "lease_owner=NULL, lease_until=NULL WHERE id=? AND revision=? AND status='running' "
        "AND lease_owner=? AND lease_until > ? AND deadline_ts > ?",
        (status, now, now, error, result, request_id, revision, str(worker_id), now, now),
    ).rowcount
    if not changed:
        raise LeaseLost('preview lease was lost')


def finish_preview(db_path, request_id, worker_id, *, revision, result=None, now=None):
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        finish_preview_in_transaction(
            conn, request_id, worker_id, revision=revision, result=result, now=now,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def fail_preview(db_path, request_id, worker_id, error, *, revision, now=None):
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        finish_preview_in_transaction(
            conn, request_id, worker_id, revision=revision, status='failed',
            error=str(error)[:240], now=now,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def expire_preview_requests(db_path, *, now=None):
    now = _now(now)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        changed = conn.execute(
            "UPDATE preview_requests SET status='expired', terminal_ts=?, completed_ts=?, "
            "lease_owner=NULL, lease_until=NULL, error='expired' "
            "WHERE status IN ('queued', 'running') AND deadline_ts <= ?",
            (now, now, now),
        ).rowcount
        conn.commit()
        return changed
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
