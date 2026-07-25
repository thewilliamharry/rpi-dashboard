"""Small, explicit SQLite connection and transaction boundaries."""

from contextlib import contextmanager
import sqlite3


def prepare_database(settings):
    """Run the existing schema initializer only at an explicit worker boundary.

    The compatibility application remains the temporary home of the version-one
    schema definition.  Importing it is side-effect free; initialization is not.
    """
    try:
        from .. import app as compatibility_app
    except ImportError:  # ``python worker.py`` from the dashboard directory.
        import app as compatibility_app

    original_path = compatibility_app.DB_PATH
    try:
        compatibility_app.DB_PATH = _db_path(settings)
        compatibility_app.init_db()
    finally:
        compatibility_app.DB_PATH = original_path


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
