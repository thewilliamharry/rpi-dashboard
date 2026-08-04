"""Worker-only composition root for Beacon's scheduled operations."""

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
import logging
import signal
import threading
import time
from uuid import uuid4

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler

from .config import load_settings
from . import queues


log = logging.getLogger('beacon.worker')
logging.getLogger('apscheduler').setLevel(logging.WARNING)


@dataclass(frozen=True)
class WorkerOperations:
    """Runtime operations explicitly supplied by an executable composition root."""

    prepare_database: object
    recover_worker_state: object
    update_worker_heartbeat: object
    collect_system_stats: object
    read_scan_state: object
    run_discovery: object
    do_uptime_check: object
    process_scan_requests: object
    process_preview_requests: object
    cleanup_history: object
    shutdown_browser: object
    acquire_worker_lease: object
    renew_worker_lease: object
    release_worker_lease: object


class WorkerAdmission:
    """Process-local cancellation and drain aid; SQLite remains authoritative."""

    def __init__(self):
        self._condition = threading.Condition()
        self._accepting = True
        self._active = {'scan': 0, 'preview': 0}

    @contextmanager
    def admit(self, kind):
        with self._condition:
            if not self._accepting:
                yield False
                return
            self._active[kind] += 1
        try:
            yield True
        finally:
            with self._condition:
                self._active[kind] -= 1
                self._condition.notify_all()

    def close_admission(self):
        with self._condition:
            self._accepting = False
            self._condition.notify_all()

    def drain(self):
        with self._condition:
            while any(self._active.values()):
                self._condition.wait()


@dataclass(frozen=True)
class WorkerServices:
    """Bound settings and operations used by the package-owned scheduler."""

    settings: object
    prepare_database: object
    recover_worker_state: object
    update_worker_heartbeat: object
    collect_system_stats: object
    read_scan_state: object
    run_discovery: object
    do_uptime_check: object
    process_scan_requests: object
    process_preview_requests: object
    cleanup_history: object
    shutdown_browser: object
    clock: object
    acquire_worker_lease: object
    renew_worker_lease: object
    release_worker_lease: object
    worker_id: str | None = None
    owner_token: str | None = None
    admission: WorkerAdmission = field(default_factory=WorkerAdmission)


def build_worker_services(operations, settings=None):
    """Bind settings without touching SQLite, scheduler, or Chromium."""
    settings = settings or load_settings()
    return WorkerServices(
        settings=settings,
        prepare_database=operations.prepare_database,
        recover_worker_state=operations.recover_worker_state,
        update_worker_heartbeat=operations.update_worker_heartbeat,
        collect_system_stats=operations.collect_system_stats,
        read_scan_state=operations.read_scan_state,
        run_discovery=operations.run_discovery,
        do_uptime_check=operations.do_uptime_check,
        process_scan_requests=operations.process_scan_requests,
        process_preview_requests=operations.process_preview_requests,
        cleanup_history=operations.cleanup_history,
        shutdown_browser=operations.shutdown_browser,
        clock=time.time,
        acquire_worker_lease=operations.acquire_worker_lease,
        renew_worker_lease=operations.renew_worker_lease,
        release_worker_lease=operations.release_worker_lease,
    )


def heartbeat(services):
    if services.worker_id and services.owner_token:
        try:
            services.renew_worker_lease(
                services.settings.db_path, services.worker_id, services.owner_token,
            )
        except queues.LeaseLost:
            log.error('Beacon worker lease lost; stopping stale scheduler')
            services.admission.close_admission()
            stop_worker()
            return False
    services.update_worker_heartbeat()
    return True


def sample_metrics(services):
    services.collect_system_stats()


def process_scans(services):
    with services.admission.admit('scan') as admitted:
        if not admitted:
            return None
        return services.process_scan_requests(services.worker_id, services.owner_token)


def process_previews(services):
    with services.admission.admit('preview') as admitted:
        if not admitted:
            return None
        return services.process_preview_requests(services.worker_id, services.owner_token)


def scheduled_discovery(services):
    state = services.read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        return
    services.run_discovery(source='scheduled')


def startup_discovery(services):
    state = services.read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        return
    last = state.get('last_discovery')
    if not last or int(services.clock()) - int(last) >= 300:
        services.run_discovery(source='startup')


scheduler = None
_worker_started = False
_worker_start_lock = threading.Lock()
_active_services = None
_active_worker_id = None


def stop_worker(*_args):
    """Request scheduler shutdown without transferring durable ownership early."""
    if scheduler is not None:
        scheduler.shutdown(wait=False)


def build_scheduler(services):
    """Create the bounded UTC scheduler without starting it."""
    executors = {
        'default': ThreadPoolExecutor(1),
        'metrics': ThreadPoolExecutor(1),
        'probes': ThreadPoolExecutor(2),
        'screenshots': ThreadPoolExecutor(1),
    }
    job_defaults = {
        'coalesce': True,
        'max_instances': 1,
        'misfire_grace_time': 15,
    }
    built_scheduler = BlockingScheduler(executors=executors, job_defaults=job_defaults, timezone='UTC')
    built_scheduler.add_job(heartbeat, 'interval', args=(services,), seconds=5, executor='metrics', id='heartbeat')
    built_scheduler.add_job(
        sample_metrics, 'interval', args=(services,), seconds=services.settings.metric_sample_seconds,
        executor='metrics', id='metrics', misfire_grace_time=10,
    )
    built_scheduler.add_job(
        services.do_uptime_check, 'interval', minutes=5, kwargs={'only_down': False},
        executor='probes', id='uptime_all', misfire_grace_time=60,
    )
    built_scheduler.add_job(
        services.do_uptime_check, 'interval', minutes=1, kwargs={'only_down': True},
        executor='probes', id='uptime_down', misfire_grace_time=30,
    )
    built_scheduler.add_job(
        process_scans, 'interval', args=(services,), seconds=2,
        executor='probes', id='scan_requests', misfire_grace_time=10,
    )
    built_scheduler.add_job(
        process_previews, 'interval', args=(services,), seconds=2,
        executor='screenshots', id='preview_requests', misfire_grace_time=10,
    )
    built_scheduler.add_job(
        scheduled_discovery, 'interval', args=(services,), hours=24, executor='probes',
        id='scheduled_discovery', misfire_grace_time=300,
    )
    built_scheduler.add_job(
        services.cleanup_history, 'interval', hours=1, executor='metrics',
        id='cleanup', misfire_grace_time=300,
    )
    built_scheduler.add_job(
        startup_discovery, 'date', args=(services,), run_date=None, executor='probes',
        id='startup_discovery', misfire_grace_time=300,
    )
    return built_scheduler


def _finalize_worker_lifecycle(services, worker_id, owner_token):
    """Release a completed worker lease and clear all process-local ownership state."""
    global scheduler, _worker_started, _active_services, _active_worker_id
    try:
        services.admission.close_admission()
        services.admission.drain()
        try:
            services.shutdown_browser()
        finally:
            try:
                services.release_worker_lease(
                    services.settings.db_path, worker_id, owner_token,
                )
            except queues.LeaseLost:
                pass
    finally:
        scheduler = None
        _worker_started = False
        _active_services = None
        _active_worker_id = None


def run_worker(operations, settings=None):
    """Start worker-owned lifecycle in the required durable-state order."""
    global scheduler, _worker_started, _active_services, _active_worker_id
    with _worker_start_lock:
        if _worker_started:
            return
        services = build_worker_services(operations, settings)
        services.prepare_database(services.settings)
        worker_id = uuid4().hex
        try:
            lease = services.acquire_worker_lease(services.settings.db_path, worker_id)
        except queues.LeaseHeld:
            log.info('Beacon worker lease is already owned; not starting scheduler')
            return
        lease_acquired = True
        if isinstance(services, WorkerServices):
            services = replace(
                services, worker_id=lease.worker_id, owner_token=lease.owner_token,
            )
    try:
        with _worker_start_lock:
            services.recover_worker_state()
            if not heartbeat(services):
                return
            sample_metrics(services)
            scheduler = build_scheduler(services)
            _active_services = services
            _active_worker_id = worker_id
            signal.signal(signal.SIGTERM, stop_worker)
            signal.signal(signal.SIGINT, stop_worker)
            _worker_started = True

        log.info('Beacon worker starting')
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if lease_acquired:
            _finalize_worker_lifecycle(services, worker_id, lease.owner_token)
