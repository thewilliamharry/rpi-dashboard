"""Small, explicit SQLite connection and transaction boundaries."""

from contextlib import contextmanager
import sqlite3


def _db_path(settings_or_path):
    return getattr(settings_or_path, 'db_path', settings_or_path)


def connect_db(settings_or_path):
    """Open a configured SQLite connection without performing migrations."""
    conn = sqlite3.connect(_db_path(settings_or_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


@contextmanager
def read_transaction(settings_or_path):
    conn = connect_db(settings_or_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def write_transaction(settings_or_path):
    conn = connect_db(settings_or_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
