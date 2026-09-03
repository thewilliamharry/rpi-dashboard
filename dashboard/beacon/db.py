"""Small, explicit SQLite connection and transaction boundaries."""

from contextlib import contextmanager
import fcntl
from pathlib import Path
import sqlite3
import time

# 06-16: the one-way edge -- lockprofile imports nothing from the beacon
# package, db.py imports lockprofile. Every hot-path caller below checks
# lockprofile.ENABLED first, so the disabled path never does timing work.
from . import lockprofile


MAINTENANCE_LOCK_NAME = '.beacon-maintenance.lock'
UPGRADE_LOCK_NAME = '.beacon-upgrade.lock'

# D-01: WAL, and only WAL, this phase. WAL lets readers proceed without
# blocking on a writer -- exactly what OPS-01's "analytics queries active"
# clause and the AR-03-01 accepted-risk note both need. journal_mode is
# persisted in the database file's header, so issuing this PRAGMA on every
# connection is idempotent: a database already in WAL simply confirms it, and
# one still on the default rollback journal converts on first connection. The
# flock sibling lease below is orthogonal and stays exactly as it is -- it
# protects the *maintenance exclusion* (schema upgrades, restore), not
# ordinary read/write concurrency, which is what WAL governs.
JOURNAL_MODE = 'WAL'


class MaintenanceBusy(RuntimeError):
    """Exclusive database maintenance could not safely exclude normal access."""


class TimingCursor(sqlite3.Cursor):
    """A ``sqlite3.Cursor`` that times ``fetchall``/``fetchone``/``fetchmany``.

    06-16 Task 1's fetch bucket: ``ManagedConnection.execute`` times the
    query compile-and-step; this times draining the remaining rows. Each
    override returns immediately to the superclass when
    ``lockprofile.ENABLED`` is false, before any timing work -- part of the
    zero-overhead-when-disabled guarantee ``db.py`` makes.
    """

    def fetchall(self):
        if not lockprofile.ENABLED:
            return super().fetchall()
        start_ns = time.perf_counter_ns()
        result = super().fetchall()
        lockprofile.record_sql(lockprofile.SQL_KIND_FETCH, time.perf_counter_ns() - start_ns)
        return result

    def fetchone(self):
        if not lockprofile.ENABLED:
            return super().fetchone()
        start_ns = time.perf_counter_ns()
        result = super().fetchone()
        lockprofile.record_sql(lockprofile.SQL_KIND_FETCH, time.perf_counter_ns() - start_ns)
        return result

    def fetchmany(self, size=-1):
        if not lockprofile.ENABLED:
            return super().fetchmany() if size == -1 else super().fetchmany(size)
        start_ns = time.perf_counter_ns()
        result = super().fetchmany() if size == -1 else super().fetchmany(size)
        lockprofile.record_sql(lockprofile.SQL_KIND_FETCH, time.perf_counter_ns() - start_ns)
        return result


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

    def cursor(self, factory=None):
        # 06-16: a TimingCursor when enabled, so fetchall/fetchone/fetchmany
        # on any cursor this connection produces -- including the one
        # execute() creates internally -- are timed into the fetch bucket.
        if not lockprofile.ENABLED:
            return super().cursor(factory) if factory is not None else super().cursor()
        return super().cursor(factory if factory is not None else TimingCursor)

    def execute(self, sql, parameters=()):
        # 06-16 Task 1's outcome guard, and the finding it exists to catch:
        # CPython's Connection.execute does NOT route through self.cursor()
        # -- verified directly (a probe against this interpreter shows the
        # base sqlite3.Cursor returned, not a subclass override), not merely
        # assumed. Delegating to super().execute() would therefore return a
        # bare Cursor whose fetchall/fetchone/fetchmany are never timed, and
        # sql_fetch_ns_total would silently stay zero -- exactly what
        # test_fetchall_on_managed_connection_records_nonzero_fetch guards.
        # So this replicates Connection.execute's own documented behaviour
        # (new cursor, call execute on it, return the cursor) explicitly
        # through self.cursor(), which IS overridden below.
        if not lockprofile.ENABLED:
            return super().execute(sql, parameters)
        start_ns = time.perf_counter_ns()
        cursor = self.cursor()
        result = cursor.execute(sql, parameters)
        lockprofile.record_sql(lockprofile.SQL_KIND_EXECUTE, time.perf_counter_ns() - start_ns)
        return result

    def executemany(self, sql, parameters):
        if not lockprofile.ENABLED:
            return super().executemany(sql, parameters)
        start_ns = time.perf_counter_ns()
        cursor = self.cursor()
        result = cursor.executemany(sql, parameters)
        lockprofile.record_sql(lockprofile.SQL_KIND_EXECUTE, time.perf_counter_ns() - start_ns)
        return result


def prepare_database(settings):
    """Prepare persisted state before the worker starts any durable operation."""
    from .migrations import run_migrations

    return run_migrations(settings)


def _db_path(settings_or_path):
    return getattr(settings_or_path, 'db_path', settings_or_path)


def maintenance_lock_path(settings_or_path):
    """Return the sibling lock file independent of the database inode."""
    return Path(_db_path(settings_or_path)).parent / MAINTENANCE_LOCK_NAME


def upgrade_lock_path(settings_or_path):
    """Return the shared first lock for upgrade and recovery operations."""
    return Path(_db_path(settings_or_path)).parent / UPGRADE_LOCK_NAME


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
    """Open a configured SQLite connection while holding a shared access lease.

    06-16: every ``with _db_lock, database_access(DB_PATH) as conn:`` site
    opens a fresh connection *inside* the critical section, so connection
    setup -- the shared ``flock`` lease plus ``sqlite3.connect`` -- is part
    of what ``_db_lock`` serializes, not free. Whether that cost is material
    is exactly what is unmeasured on Pi hardware under load; this timing
    block answers it without touching any of the 28 call sites' scope
    (``D-01`` / ``PROH-OPS-04-02``).

    The lease is timed separately from the rest of connect so contention on
    the maintenance lease is distinguishable from the rest of connection
    setup. ``record_connect``'s span deliberately ENDS before the three
    PRAGMA calls below: those go through ``conn.execute`` -- the normal,
    timed ``ManagedConnection.execute`` override, unchanged from any other
    caller (this also keeps the failure-injection seam
    ``tests/test_workload_resilience.py::WalModeTests`` patches on
    ``ManagedConnection.execute`` working) -- and are recorded as ordinary
    ``sql_execute_ns_total`` instead. Folding them into ``record_connect``'s
    own span as well would double-count that time into both buckets, which
    would push the derived ``python_ns_total`` negative for no real
    measurement reason -- exactly the defect class ``clamped_python_count``
    exists to catch.
    """
    timing = lockprofile.ENABLED
    total_start_ns = time.perf_counter_ns() if timing else None
    handle = _acquire_lock(maintenance_lock_path(settings_or_path), fcntl.LOCK_SH, 30)
    lease_ns = (time.perf_counter_ns() - total_start_ns) if timing else 0
    try:
        conn = sqlite3.connect(
            _db_path(settings_or_path), timeout=30, factory=ManagedConnection,
        )
        conn._set_maintenance_handle(handle)
        conn.row_factory = sqlite3.Row
        if timing:
            lockprofile.record_connect(time.perf_counter_ns() - total_start_ns, lease_ns)
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA journal_mode=' + JOURNAL_MODE)
        return conn
    except Exception:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
        raise


def configured_journal_mode(conn):
    """Return the journal mode actually in force, read from the database.

    SQLite silently declines a journal_mode switch if another connection
    holds a lock, so this reads back the mode in effect rather than trusting
    the PRAGMA request in ``connect_db``.
    """
    return str(conn.execute('PRAGMA journal_mode').fetchone()[0]).lower()


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
