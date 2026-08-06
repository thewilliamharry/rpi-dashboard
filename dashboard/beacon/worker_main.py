"""Worker-only composition root for Beacon's scheduled operations."""

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from functools import partial
import logging
import signal
import threading
import time
from uuid import uuid4

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler

from .config import load_settings
from . import queues
from .worker_authority import WorkerAuthority


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


@dataclass(frozen=True)
class WorkerCallback:
    """One immutable, production-dispatched callback boundary."""

    identifier: str
    operation_fields: tuple[str, ...]
    handler: str
    admission_category: str
    database_surfaces: tuple[str, ...]
    effect_surfaces: tuple[str, ...]
    ownership_required: bool = True
    scheduler_id: str | None = None
    trigger: str | None = None
    trigger_kwargs: tuple[tuple[str, object], ...] = ()
    executor: str | None = None
    misfire_grace_time: int | None = None

    @property
    def scheduler_metadata(self):
        """The complete declarative scheduler identity used by build_scheduler."""
        if self.scheduler_id is None:
            return {}
        return {
            'id': self.scheduler_id,
            'trigger': self.trigger,
            'trigger_kwargs': self.trigger_kwargs,
            'executor': self.executor,
            'misfire_grace_time': self.misfire_grace_time,
        }


# This is production data, not a duplicate test fixture.  The registry is the
# only post-acquisition dispatch source for startup work and scheduler jobs.
WORKER_CALLBACK_INVENTORY = (
    WorkerCallback('P0', ('prepare_database',), 'prepare', 'pre_epoch_preparation', (), ('filesystem_publication',), False),
    WorkerCallback('S1', ('recover_worker_state',), 'recover', 'startup', ('scan_requests', 'preview_requests', 'events', 'scan_state'), ()),
    WorkerCallback('S2', ('update_worker_heartbeat', 'renew_worker_lease'), 'heartbeat', 'startup', ('worker_owner', 'worker_heartbeat'), ('browser_resource_lifecycle',)),
    WorkerCallback('S3', ('collect_system_stats',), 'metrics', 'startup', ('system_stats', 'stats_history'), ()),
    WorkerCallback('J1', ('update_worker_heartbeat', 'renew_worker_lease'), 'heartbeat', 'scheduled', ('worker_owner', 'worker_heartbeat'), ('browser_resource_lifecycle',), scheduler_id='heartbeat', trigger='interval', trigger_kwargs=(('seconds', 5),), executor='metrics'),
    WorkerCallback('J2', ('collect_system_stats',), 'metrics', 'scheduled', ('system_stats', 'stats_history'), (), scheduler_id='metrics', trigger='interval', trigger_kwargs=(('seconds', None),), executor='metrics', misfire_grace_time=10),
    WorkerCallback('J3', ('do_uptime_check',), 'uptime_all', 'scheduled', ('services', 'service_checks', 'service_tls_posture', 'preview_requests', 'events', 'scan_state'), ('webhook_delivery',), scheduler_id='uptime_all', trigger='interval', trigger_kwargs=(('minutes', 5),), executor='probes', misfire_grace_time=60),
    WorkerCallback('J4', ('do_uptime_check',), 'uptime_down', 'scheduled', ('services', 'service_checks', 'service_tls_posture', 'preview_requests', 'events', 'scan_state'), ('webhook_delivery',), scheduler_id='uptime_down', trigger='interval', trigger_kwargs=(('minutes', 1),), executor='probes', misfire_grace_time=30),
    WorkerCallback('J5', ('process_scan_requests',), 'scan', 'scheduled', ('scan_requests', 'scan_state', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'events', 'preview_requests'), ('webhook_delivery',), scheduler_id='scan_requests', trigger='interval', trigger_kwargs=(('seconds', 2),), executor='probes', misfire_grace_time=10),
    WorkerCallback('J6', ('process_preview_requests',), 'preview', 'scheduled', ('preview_requests', 'services', 'events'), ('thumbnail_publication', 'browser_resource_lifecycle'), scheduler_id='preview_requests', trigger='interval', trigger_kwargs=(('seconds', 2),), executor='screenshots', misfire_grace_time=10),
    WorkerCallback('J7', ('run_discovery', 'read_scan_state'), 'scheduled_discovery', 'scheduled', ('scan_state', 'events', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'preview_requests'), ('webhook_delivery',), scheduler_id='scheduled_discovery', trigger='interval', trigger_kwargs=(('hours', 24),), executor='probes', misfire_grace_time=300),
    WorkerCallback('J8', ('cleanup_history',), 'cleanup', 'scheduled', ('stats_history', 'service_checks', 'events', 'scan_rate_hits'), (), scheduler_id='cleanup', trigger='interval', trigger_kwargs=(('hours', 1),), executor='metrics', misfire_grace_time=300),
    WorkerCallback('J9', ('run_discovery', 'read_scan_state'), 'startup_discovery', 'scheduled', ('scan_state', 'events', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'preview_requests'), ('webhook_delivery',), scheduler_id='startup_discovery', trigger='date', trigger_kwargs=(('run_date', None),), executor='probes', misfire_grace_time=300),
    WorkerCallback('L1', ('shutdown_browser', 'release_worker_lease'), 'finalize', 'lifecycle_finalization', ('worker_owner',), ('browser_resource_lifecycle',), False),
)
_CALLBACKS_BY_ID = {callback.identifier: callback for callback in WORKER_CALLBACK_INVENTORY}


class WorkerAdmission:
    """Process-local cancellation and drain aid; SQLite remains authoritative."""

    def __init__(self):
        self._condition = threading.Condition()
        self._accepting = True
        self._active = {
            callback.admission_category: 0
            for callback in WORKER_CALLBACK_INVENTORY
            if callback.ownership_required
        }

    @property
    def active_counts(self):
        with self._condition:
            return dict(self._active)

    @contextmanager
    def admit(self, kind):
        with self._condition:
            if kind not in self._active:
                raise ValueError(f'unknown worker admission category: {kind}')
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
    authority: WorkerAuthority | None = None
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


def _run_scheduled_discovery(services):
    state = services.read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        return
    services.run_discovery(services.authority, source='scheduled')


def _run_startup_discovery(services):
    state = services.read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        return
    last = state.get('last_discovery')
    if not last or int(services.clock()) - int(last) >= 300:
        services.run_discovery(services.authority, source='startup')


def _invoke_callback(services, callback):
    """Invoke a declared operation without admission bookkeeping."""
    if callback.handler == 'prepare':
        return services.prepare_database(services.settings)
    if callback.handler == 'recover':
        return services.recover_worker_state(services.authority)
    if callback.handler == 'heartbeat':
        if services.authority:
            services.renew_worker_lease(services.authority)
            services.update_worker_heartbeat(services.authority)
        return True
    if callback.handler == 'metrics':
        return services.collect_system_stats(services.authority)
    if callback.handler == 'uptime_all':
        return services.do_uptime_check(services.authority, only_down=False)
    if callback.handler == 'uptime_down':
        return services.do_uptime_check(services.authority, only_down=True)
    if callback.handler == 'scan':
        return services.process_scan_requests(services.authority)
    if callback.handler == 'preview':
        return services.process_preview_requests(services.authority)
    if callback.handler == 'scheduled_discovery':
        return _run_scheduled_discovery(services)
    if callback.handler == 'startup_discovery':
        return _run_startup_discovery(services)
    if callback.handler == 'cleanup':
        return services.cleanup_history(services.authority)
    raise ValueError(f'callback {callback.identifier} cannot be dispatched')


def dispatch_callback(services, callback_id):
    """Admit one real callback and revoke all work on durable lease loss."""
    callback = _CALLBACKS_BY_ID[callback_id]
    if not callback.ownership_required:
        return _invoke_callback(services, callback)
    with services.admission.admit(callback.admission_category) as admitted:
        if not admitted:
            return None
        try:
            return _invoke_callback(services, callback)
        except queues.LeaseLost:
            log.error('Beacon worker lease lost; stopping stale scheduler')
            services.admission.close_admission()
            stop_worker()
            return False


# Compatibility exports retain their former call shapes, but all post-acquisition
# work now enters the one inventory-driven admission wrapper.
def heartbeat(services):
    return dispatch_callback(services, 'J1')


def sample_metrics(services):
    return dispatch_callback(services, 'J2')


def process_scans(services):
    return dispatch_callback(services, 'J5')


def process_previews(services):
    return dispatch_callback(services, 'J6')


def scheduled_discovery(services):
    return dispatch_callback(services, 'J7')


def startup_discovery(services):
    return dispatch_callback(services, 'J9')


def uptime_check(services, *, only_down):
    return dispatch_callback(services, 'J4' if only_down else 'J3')


def cleanup(services):
    return dispatch_callback(services, 'J8')


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
    for callback in WORKER_CALLBACK_INVENTORY:
        if callback.scheduler_id is None:
            continue
        trigger_kwargs = dict(callback.trigger_kwargs)
        if callback.identifier == 'J2':
            trigger_kwargs['seconds'] = services.settings.metric_sample_seconds
        built_scheduler.add_job(
            partial(dispatch_callback, services, callback.identifier),
            callback.trigger,
            executor=callback.executor,
            id=callback.scheduler_id,
            misfire_grace_time=callback.misfire_grace_time,
            **trigger_kwargs,
        )
    return built_scheduler


def _finalize_worker_lifecycle(services):
    """Release a completed worker lease and clear all process-local ownership state."""
    global scheduler, _worker_started, _active_services, _active_worker_id
    try:
        services.admission.close_admission()
        services.admission.drain()
        try:
            services.shutdown_browser()
        finally:
            try:
                if services.authority:
                    services.release_worker_lease(services.authority)
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
        dispatch_callback(services, 'P0')
        worker_id = uuid4().hex
        try:
            lease = services.acquire_worker_lease(services.settings.db_path, worker_id)
        except queues.LeaseHeld:
            log.info('Beacon worker lease is already owned; not starting scheduler')
            return
        lease_acquired = True
        if isinstance(services, WorkerServices):
            services = replace(
                services,
                authority=WorkerAuthority.from_lease(
                    lease, services.settings.db_path, clock=services.clock,
                ),
            )
    try:
        with _worker_start_lock:
            dispatch_callback(services, 'S1')
            if not dispatch_callback(services, 'S2'):
                return
            dispatch_callback(services, 'S3')
            scheduler = build_scheduler(services)
            _active_services = services
            _active_worker_id = services.authority.worker_id
            signal.signal(signal.SIGTERM, stop_worker)
            signal.signal(signal.SIGINT, stop_worker)
            _worker_started = True

        log.info('Beacon worker starting')
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if lease_acquired:
            _finalize_worker_lifecycle(services)
