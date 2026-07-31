"""Worker-only composition root for Beacon's scheduled operations."""

import atexit
from dataclasses import dataclass, replace
import logging
import signal
import threading
import time
from uuid import uuid4

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler

from .config import load_settings
from .db import prepare_database
from . import queues

try:
    from .. import app as beacon
except ImportError:  # ``python worker.py`` from the dashboard directory.
    import app as beacon


# Compatibility operations are bound here, not invoked here.  Keeping these
# seams named makes worker composition independently testable.
recover_worker_state = beacon.recover_worker_state
update_worker_heartbeat = beacon.update_worker_heartbeat
collect_system_stats = beacon.collect_system_stats
read_scan_state = beacon._read_scan_state
run_discovery = beacon.run_discovery
do_uptime_check = beacon.do_uptime_check
process_scan_requests = beacon.process_scan_requests
process_preview_requests = beacon.process_preview_requests
cleanup_history = beacon.cleanup_history
shutdown_browser = beacon.shutdown_browser
acquire_worker_lease = queues.acquire_worker_lease
renew_worker_lease = queues.renew_worker_lease
release_worker_lease = queues.release_worker_lease


log = logging.getLogger('beacon.worker')
logging.getLogger('apscheduler').setLevel(logging.WARNING)


@dataclass(frozen=True)
class WorkerServices:
    """All dependencies owned by the worker composition root."""

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


def build_worker_services(settings=None):
    """Assemble dependencies without touching SQLite, scheduler, or Chromium."""
    settings = settings or load_settings()
    return WorkerServices(
        settings=settings,
        prepare_database=prepare_database,
        recover_worker_state=recover_worker_state,
        update_worker_heartbeat=update_worker_heartbeat,
        collect_system_stats=collect_system_stats,
        read_scan_state=read_scan_state,
        run_discovery=run_discovery,
        do_uptime_check=do_uptime_check,
        process_scan_requests=process_scan_requests,
        process_preview_requests=process_preview_requests,
        cleanup_history=cleanup_history,
        shutdown_browser=shutdown_browser,
        clock=time.time,
        acquire_worker_lease=acquire_worker_lease,
        renew_worker_lease=renew_worker_lease,
        release_worker_lease=release_worker_lease,
    )


def heartbeat(services):
    if services.worker_id:
        try:
            services.renew_worker_lease(services.settings.db_path, services.worker_id)
        except queues.LeaseLost:
            log.error('Beacon worker lease lost; stopping stale scheduler')
            stop_worker()
            return False
    services.update_worker_heartbeat()
    return True


def sample_metrics(services):
    services.collect_system_stats()


def process_scans(services):
    return services.process_scan_requests(services.worker_id)


def process_previews(services):
    return services.process_preview_requests(services.worker_id)


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
    global _active_worker_id
    if _active_services is not None:
        _active_services.shutdown_browser()
        if _active_worker_id:
            try:
                _active_services.release_worker_lease(
                    _active_services.settings.db_path, _active_worker_id,
                )
            except queues.LeaseLost:
                pass
            _active_worker_id = None
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


def main(settings=None):
    """Start worker-owned lifecycle in the required durable-state order."""
    global scheduler, _worker_started, _active_services, _active_worker_id
    with _worker_start_lock:
        if _worker_started:
            return
        services = build_worker_services(settings)
        services.prepare_database(services.settings)
        worker_id = uuid4().hex
        try:
            services.acquire_worker_lease(services.settings.db_path, worker_id)
        except queues.LeaseHeld:
            log.info('Beacon worker lease is already owned; not starting scheduler')
            return
        if isinstance(services, WorkerServices):
            services = replace(services, worker_id=worker_id)
        services.recover_worker_state()
        if not heartbeat(services):
            return
        sample_metrics(services)
        scheduler = build_scheduler(services)
        _active_services = services
        _active_worker_id = worker_id
        atexit.register(services.shutdown_browser)
        signal.signal(signal.SIGTERM, stop_worker)
        signal.signal(signal.SIGINT, stop_worker)
        _worker_started = True

    log.info('Beacon worker starting')
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        services.shutdown_browser()
