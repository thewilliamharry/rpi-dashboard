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
