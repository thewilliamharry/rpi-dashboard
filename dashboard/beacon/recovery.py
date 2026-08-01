"""Offline, catalog-constrained recovery of verified Beacon migration backups."""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from uuid import uuid4

from .config import load_settings
from .db import MaintenanceBusy, exclusive_database_maintenance, upgrade_lock_path
from .inventory import InventoryError, classify_schema, collect_inventory
from .migrations import LOCK_NAME, MIGRATIONS, RECOVERY_MARKER, SUPPORT_FLOOR_PATH


BACKUP_PREFIX = 'dashboard-'
BACKUP_SUFFIX = '.db'
STAGING_PREFIX = '.dashboard.db.restore-'


class RecoveryError(RuntimeError):
    """A redacted operational refusal for the offline recovery command."""


@dataclass(frozen=True)
class BackupRecord:
    """Safe metadata for one verified automatic migration backup."""

    catalog_id: str
    backup_timestamp: str
    schema_fingerprint: str


@dataclass(frozen=True)
class RestoreResult:
    """Safe, non-row-bearing result returned by a completed restore."""

    catalog_id: str
    backup_timestamp: str
    schema_fingerprint: str
    completed: bool


def _support_fingerprints():
    try:
        payload = json.loads(SUPPORT_FLOOR_PATH.read_text(encoding='utf-8'))
        return {entry['fingerprint'] for entry in payload['supported_schemas']}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise RecoveryError('recovery support information is unavailable') from exc


def _backup_timestamp(catalog_id):
    try:
        raw = catalog_id.split('-')[1]
        return datetime.strptime(raw, '%Y%m%dT%H%M%S%fZ').replace(
            tzinfo=timezone.utc
        ).isoformat()
    except (IndexError, ValueError):
        raise RecoveryError('backup is not available')


def _is_catalog_name(catalog_id):
    if not isinstance(catalog_id, str) or Path(catalog_id).name != catalog_id:
        return False
    if not catalog_id.startswith(BACKUP_PREFIX) or not catalog_id.endswith(BACKUP_SUFFIX):
        return False
    return '-pre-v' in catalog_id and catalog_id.rsplit('-pre-v', 1)[1][:-3].isdigit()


def _catalog_target_version(catalog_id):
    if not _is_catalog_name(catalog_id):
        raise RecoveryError('backup is not available')
    return int(catalog_id.rsplit('-pre-v', 1)[1][:-3])


def _regular_catalog_path(backup_dir, catalog_id):
    if not _is_catalog_name(catalog_id):
        raise RecoveryError('backup is not available')
    candidate = backup_dir / catalog_id
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise RecoveryError('backup is not available') from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RecoveryError('backup is not available')
    try:
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError as exc:
        raise RecoveryError('backup is not available') from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_ino != metadata.st_ino:
            raise RecoveryError('backup is not available')
    finally:
        os.close(descriptor)
    return candidate


def _validated_migration_transition(conn, catalog_id):
    """Accept only a known pre-version state written by the migration catalog."""
    target_version = _catalog_target_version(catalog_id)
    if target_version not in {migration.version for migration in MIGRATIONS}:
        return False
    table_names = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if target_version == 1:
        return 'schema_migrations' not in table_names
    if 'schema_migrations' not in table_names:
        return False
    versions = [
        row[0] for row in conn.execute('SELECT version FROM schema_migrations ORDER BY version')
    ]
    return versions == list(range(1, target_version))


def _validate_supported_database(path, catalog_id=None):
    try:
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as conn:
            integrity = conn.execute('PRAGMA integrity_check').fetchone()
            if not integrity or integrity[0] != 'ok':
                raise RecoveryError('backup is not available')
            catalog_transition = (
                _validated_migration_transition(conn, catalog_id)
                if catalog_id is not None else False
            )
        fingerprint = classify_schema(collect_inventory(path))
    except (InventoryError, OSError, sqlite3.Error, ValueError) as exc:
        raise RecoveryError('backup is not available') from exc
    if fingerprint not in _support_fingerprints() and not catalog_transition:
        raise RecoveryError('backup is not available')
    return fingerprint


def _record_for_catalog_id(backup_dir, catalog_id):
    path = _regular_catalog_path(backup_dir, catalog_id)
    return BackupRecord(
        catalog_id=catalog_id,
        backup_timestamp=_backup_timestamp(catalog_id),
        schema_fingerprint=_validate_supported_database(path, catalog_id),
    ), path


def list_verified_backups(data_dir):
    """Return only regular, integrity-checked, support-floor catalog entries."""
    backup_dir = Path(data_dir) / 'backups'
    try:
        candidates = sorted(backup_dir.iterdir(), key=lambda item: item.name)
    except OSError:
        return []
    records = []
    for candidate in candidates:
        try:
            record, _ = _record_for_catalog_id(backup_dir, candidate.name)
        except RecoveryError:
            continue
        records.append(record)
    return records


def _worker_is_stale(database, *, now, worker_ready_seconds):
    try:
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if 'runtime_state' not in tables:
                return True
            row = conn.execute(
                "SELECT value FROM runtime_state WHERE key='worker_heartbeat'"
            ).fetchone()
    except sqlite3.Error as exc:
        raise RecoveryError('recovery cannot verify that Beacon services are stopped') from exc
    if not row:
        return True
    try:
        timestamp = float(json.loads(row[0])['ts'])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return True
    return now() - timestamp > worker_ready_seconds


def _fsync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_and_fsync(source, staging):
    with source.open('rb') as reader, staging.open('xb') as writer:
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk:
                break
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())


def _checkpoint_and_remove_sidecars(database):
    """Quiesce the current SQLite inode before it can be replaced."""
    try:
        with sqlite3.connect(database) as conn:
            checkpoint = conn.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        if not checkpoint or checkpoint[0] != 0:
            raise RecoveryError('restore did not complete')
        _fsync_file(database)
        for suffix in ('-wal', '-shm'):
            Path(str(database) + suffix).unlink(missing_ok=True)
        _fsync_directory(database.parent)
    except RecoveryError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise RecoveryError('restore did not complete') from exc


def _write_recovery_marker(root):
    marker = root / RECOVERY_MARKER
    try:
        with marker.open('w', encoding='utf-8') as handle:
            json.dump({'restore_in_progress': True}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        _fsync_directory(root)
    except OSError as exc:
        raise RecoveryError('restore did not complete') from exc


def _acquire_upgrade_lock(lock_path, timeout_seconds):
    lock_path.touch(mode=0o600, exist_ok=True)
    handle = lock_path.open('a+')
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return handle
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RecoveryError('another upgrade or recovery is already active')
                time.sleep(0.05)
    except Exception:
        handle.close()
        raise


def restore_backup(
    data_dir,
    catalog_id,
    *,
    require_worker_stale=True,
    worker_ready_seconds=None,
    lock_timeout_seconds=30,
    now=time.time,
):
    """Atomically restore one verified catalog entry while Beacon writers are stopped."""
    root = Path(data_dir)
    database = root / 'dashboard.db'
    backup_dir = root / 'backups'
    if worker_ready_seconds is None:
        try:
            worker_ready_seconds = max(1, int(os.environ.get('WORKER_READY_SECONDS', '20')))
        except (TypeError, ValueError):
            worker_ready_seconds = 20
    record, source = _record_for_catalog_id(backup_dir, catalog_id)
    if not database.is_file() or database.is_symlink():
        raise RecoveryError('recovery cannot verify that Beacon services are stopped')

    lock_handle = _acquire_upgrade_lock(upgrade_lock_path(database), lock_timeout_seconds)
    staging = root / '{}{}.partial'.format(STAGING_PREFIX, uuid4().hex)
    try:
        if require_worker_stale and not _worker_is_stale(
            database,
            now=now,
            worker_ready_seconds=worker_ready_seconds,
        ):
            raise RecoveryError('stop Beacon services before running recovery')
        try:
            with exclusive_database_maintenance(database, lock_timeout_seconds):
                _checkpoint_and_remove_sidecars(database)
                try:
                    _copy_and_fsync(source, staging)
                    _fsync_directory(root)
                    if _validate_supported_database(staging, record.catalog_id) != record.schema_fingerprint:
                        raise RecoveryError('restore did not complete')
                    _write_recovery_marker(root)
                    os.replace(staging, database)
                    _fsync_file(database)
                    _fsync_directory(root)
                except RecoveryError:
                    raise
                except (OSError, sqlite3.Error) as exc:
                    raise RecoveryError('restore did not complete') from exc
                try:
                    if _validate_supported_database(database, record.catalog_id) != record.schema_fingerprint:
                        raise RecoveryError('restore did not complete')
                    if any(Path(str(database) + suffix).exists() for suffix in ('-wal', '-shm')):
                        raise RecoveryError('restore did not complete')
                except RecoveryError:
                    raise
                except (OSError, sqlite3.Error) as exc:
                    raise RecoveryError('restore did not complete') from exc
                (root / RECOVERY_MARKER).unlink(missing_ok=True)
                _fsync_directory(root)
        except MaintenanceBusy as exc:
            raise RecoveryError('restore did not complete') from exc
        return RestoreResult(
            catalog_id=record.catalog_id,
            backup_timestamp=record.backup_timestamp,
            schema_fingerprint=record.schema_fingerprint,
            completed=True,
        )
    finally:
        staging.unlink(missing_ok=True)
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


def _data_dir_from_environment():
    return Path(load_settings().db_path).parent


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline Beacon verified-backup recovery')
    subcommands = parser.add_subparsers(dest='command', required=True)
    subcommands.add_parser('status')
    subcommands.add_parser('list')
    restore = subcommands.add_parser('restore')
    group = restore.add_mutually_exclusive_group(required=True)
    group.add_argument('--latest', action='store_true')
    group.add_argument('--id', dest='catalog_id')
    arguments = parser.parse_args(argv)
    data_dir = _data_dir_from_environment()
    try:
        if arguments.command == 'status':
            print(json.dumps({'recovery_required': (data_dir / RECOVERY_MARKER).is_file()}))
        elif arguments.command == 'list':
            print(json.dumps([asdict(record) for record in list_verified_backups(data_dir)]))
        else:
            records = list_verified_backups(data_dir)
            catalog_id = records[-1].catalog_id if arguments.latest and records else arguments.catalog_id
            if not catalog_id:
                raise RecoveryError('backup is not available')
            print(json.dumps(asdict(restore_backup(data_dir, catalog_id)), sort_keys=True))
    except RecoveryError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
