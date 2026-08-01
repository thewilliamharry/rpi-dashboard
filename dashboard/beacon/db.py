"""Small, explicit SQLite connection and transaction boundaries."""

from contextlib import contextmanager
import fcntl
from pathlib import Path
import sqlite3
import time


MAINTENANCE_LOCK_NAME = '.beacon-maintenance.lock'


class MaintenanceBusy(RuntimeError):
    """Exclusive database maintenance could not safely exclude normal access."""


class ManagedConnection(sqlite3.Connection):
    """SQLite connection that owns its shared maintenance lease until close."""

    def _set_maintenance_handle(self, handle):
        self._maintenance_handle = handle

    def close(self):
        handle = getattr(self, '_maintenance_handle', None)
        try:
            return super().close()
        finally:
            if handle is not None:
                self._maintenance_handle = None
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()


def prepare_database(settings):
    """Prepare persisted state before the worker starts any durable operation."""
    from .migrations import run_migrations

    return run_migrations(settings)


def _db_path(settings_or_path):
    return getattr(settings_or_path, 'db_path', settings_or_path)


def maintenance_lock_path(settings_or_path):
    """Return the sibling lock file independent of the database inode."""
    return Path(_db_path(settings_or_path)).parent / MAINTENANCE_LOCK_NAME


def _acquire_lock(lock_path, mode, timeout_seconds):
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = lock_path.open('a+')
    deadline = time.monotonic() + max(0, timeout_seconds)
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), mode | fcntl.LOCK_NB)
                return handle
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise MaintenanceBusy('database maintenance lease is busy')
                time.sleep(0.01)
    except Exception:
        handle.close()
        raise


def connect_db(settings_or_path):
    """Open a configured SQLite connection while holding a shared access lease."""
    handle = _acquire_lock(maintenance_lock_path(settings_or_path), fcntl.LOCK_SH, 30)
    try:
        conn = sqlite3.connect(
            _db_path(settings_or_path), timeout=30, factory=ManagedConnection,
        )
        conn._set_maintenance_handle(handle)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn
    except Exception:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
        raise


@contextmanager
def database_access(settings_or_path):
    """Yield one shared-lease SQLite connection for ordinary Beacon access."""
    conn = connect_db(settings_or_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def exclusive_database_maintenance(settings_or_path, timeout_seconds=30):
    """Exclude every managed Beacon connection for a bounded maintenance interval."""
    handle = _acquire_lock(
        maintenance_lock_path(settings_or_path), fcntl.LOCK_EX, timeout_seconds,
    )
    try:
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


@contextmanager
def read_transaction(settings_or_path):
    with database_access(settings_or_path) as conn:
        yield conn


@contextmanager
def write_transaction(settings_or_path):
    with database_access(settings_or_path) as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
