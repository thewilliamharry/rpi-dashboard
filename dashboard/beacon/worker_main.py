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
from . import repositories
from .db import write_transaction
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
    WorkerCallback('S3', ('collect_system_stats',), 'metrics', 'startup', ('system_stats', 'stats_history', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'), ()),
    WorkerCallback('J1', ('update_worker_heartbeat', 'renew_worker_lease'), 'heartbeat', 'scheduled', ('worker_owner', 'worker_heartbeat'), ('browser_resource_lifecycle',), scheduler_id='heartbeat', trigger='interval', trigger_kwargs=(('seconds', 5),), executor='metrics'),
    WorkerCallback('J2', ('collect_system_stats',), 'metrics', 'scheduled', ('system_stats', 'stats_history', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'), (), scheduler_id='metrics', trigger='interval', trigger_kwargs=(('seconds', None),), executor='metrics', misfire_grace_time=10),
    WorkerCallback('J3', ('do_uptime_check',), 'uptime_all', 'scheduled', ('services', 'service_checks', 'service_tls_posture', 'preview_requests', 'events', 'scan_state', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'), ('webhook_delivery',), scheduler_id='uptime_all', trigger='interval', trigger_kwargs=(('minutes', 5),), executor='probes', misfire_grace_time=60),
    WorkerCallback('J4', ('do_uptime_check',), 'uptime_down', 'scheduled', ('services', 'service_checks', 'service_tls_posture', 'preview_requests', 'events', 'scan_state', 'telemetry_streams', 'telemetry_coverage', 'runtime_state'), ('webhook_delivery',), scheduler_id='uptime_down', trigger='interval', trigger_kwargs=(('minutes', 1),), executor='probes', misfire_grace_time=30),
    WorkerCallback('J5', ('process_scan_requests',), 'scan', 'scheduled', ('scan_requests', 'scan_state', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'events', 'preview_requests'), ('webhook_delivery',), scheduler_id='scan_requests', trigger='interval', trigger_kwargs=(('seconds', 2),), executor='probes', misfire_grace_time=10),
    WorkerCallback('J6', ('process_preview_requests',), 'preview', 'scheduled', ('preview_requests', 'services', 'events'), ('thumbnail_publication', 'browser_resource_lifecycle'), scheduler_id='preview_requests', trigger='interval', trigger_kwargs=(('seconds', 2),), executor='screenshots', misfire_grace_time=10),
    WorkerCallback('J7', ('run_discovery', 'read_scan_state'), 'scheduled_discovery', 'scheduled', ('scan_state', 'events', 'services', 'service_meta', 'service_checks', 'service_tls_posture', 'preview_requests'), ('webhook_delivery',), scheduler_id='scheduled_discovery', trigger='interval', trigger_kwargs=(('hours', 24),), executor='probes', misfire_grace_time=300),
    WorkerCallback('J8', ('cleanup_history',), 'cleanup', 'scheduled', ('stats_history', 'service_checks', 'events', 'scan_rate_hits', 'host_metric_rollups', 'service_rollups', 'telemetry_streams', 'telemetry_coverage', 'telemetry_rollup_jobs', 'runtime_state'), (), scheduler_id='cleanup', trigger='interval', trigger_kwargs=(('hours', 1),), executor='metrics', misfire_grace_time=300),
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
    """Return None only for a genuine skip; otherwise carry discovery's own verdict."""
    state = services.read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        # No work was due.  None is reserved for exactly this, so dispatch_callback
        # records a completed poll rather than a fabricated failure.
        return None
    outcome = services.run_discovery(services.authority, source='scheduled')
    # run_discovery's contract is exactly 'busy' | 'completed' | 'failed', so this
    # is False only for a genuine failure -- never discarded behind an implicit None.
    return outcome != 'failed'


def _run_startup_discovery(services):
    """Return None only for a genuine skip; otherwise carry discovery's own verdict."""
    state = services.read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        return None
    last = state.get('last_discovery')
    if not last or int(services.clock()) - int(last) >= 300:
        outcome = services.run_discovery(services.authority, source='startup')
        return outcome != 'failed'
    # A discovery already ran inside the recency window: the second genuine skip,
    # which used to fall off the end with no return statement at all.
    return None


def _invoke_callback(services, callback):
    """Invoke a declared operation without admission bookkeeping."""
    if callback.handler == 'prepare':
        return services.prepare_database(services.settings)
    if callback.handler == 'recover':
        return services.recover_worker_state(services.authority)
    if callback.handler == 'heartbeat':
        if services.authority:
            services.renew_worker_lease(services.authority)
            return services.update_worker_heartbeat(services.authority)
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


def _job_error_class(error):
    """Keep durable failure evidence free of messages and opaque authority data."""
    return type(error).__name__[:96] or 'CallbackFailed'


class JobHealthBookkeepingError(RuntimeError):
    """A durable job-health write failed for a reason that is not lease loss.

    Its own message and arguments carry the callback identifier, the transition
    that could not be written, and bounded class names only, so the no-message
    discipline `_job_error_class` enforces for durable rows also holds for
    everything this condition itself states.  Chaining is deliberately separate:
    the underlying exceptions stay attached so a maintainer reading a traceback
    keeps the detail, which is the intended debuggability channel and is not
    governed by this class's own no-message rule.

    Recording a job's outcome can fail on its own; that is a fact about the
    recording, never a verdict on the work.  When the write that failed was
    trying to record a work failure, `work_error_class` names that work
    failure's own bounded class, so separating the two conditions costs neither
    of them its visibility.
    """

    def __init__(self, callback_id, transition, error_class, *, work_error_class=None):
        self.callback_id = callback_id
        self.transition = transition
        self.error_class = error_class
        self.work_error_class = work_error_class
        message = (
            f'background job health write failed: callback={callback_id} '
            f'transition={transition} error_class={error_class}'
        )
        if work_error_class is not None:
            message = f'{message} work_error_class={work_error_class}'
        super().__init__(message)


def _write_job_health_transition(services, callback_id, transition, *, error_class=None):
    """Publish one outcome only while the exact worker epoch still owns SQLite."""
    now = int(services.clock())
    with write_transaction(services.settings.db_path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        queues.assert_current_worker_authority(conn, services.authority, now)
        if transition == 'started':
            repositories.record_background_job_started(conn, callback_id, now=now)
        elif transition == 'succeeded':
            repositories.record_background_job_succeeded(conn, callback_id, now=now)
        elif transition == 'failed':
            repositories.record_background_job_failed(
                conn, callback_id, now=now, error_class=error_class,
            )
        else:
            raise ValueError(f'unknown background job transition: {transition}')


def dispatch_callback(services, callback_id):
    """Admit one real callback and revoke all work on durable lease loss."""
    callback = _CALLBACKS_BY_ID[callback_id]
    if not callback.ownership_required:
        return _invoke_callback(services, callback)
    with services.admission.admit(callback.admission_category) as admitted:
        if not admitted:
            return None
        # Compatibility/inventory tests may exercise dispatch with a skeletal
        # collaborator before a real epoch exists.  Production WorkerServices
        # always carries the immutable authority after acquisition; only that
        # path may publish durable job health.
        if not isinstance(getattr(services, 'authority', None), WorkerAuthority):
            return _invoke_callback(services, callback)
        try:
            _write_job_health_transition(services, callback_id, 'started')
        except queues.LeaseLost:
            log.error('Beacon worker lease lost; stopping stale scheduler')
            services.admission.close_admission()
            stop_worker()
            return False
        except Exception as exc:
            # The work never ran, so there is no work outcome to record.
            raise JobHealthBookkeepingError(
                callback_id, 'started', _job_error_class(exc),
            ) from exc

        # Decide the outcome in its own scope.  Nothing here writes, so a failure
        # of the recording can never be mistaken for a failure of the work.
        work_error = None
        try:
            result = _invoke_callback(services, callback)
        except queues.LeaseLost:
            log.error('Beacon worker lease lost; stopping stale scheduler')
            services.admission.close_admission()
            stop_worker()
            return False
        except Exception as exc:
            work_error = exc
            result = None
            transition, error_class = 'failed', _job_error_class(exc)
        else:
            if result is False:
                transition, error_class = 'failed', 'CallbackReturnedFalse'
            else:
                transition, error_class = 'succeeded', None

        try:
            _write_job_health_transition(
                services, callback_id, transition, error_class=error_class,
            )
        except queues.LeaseLost:
            log.error(
                'Beacon worker lease lost while recording a callback outcome; '
                'stopping stale scheduler: callback=%s transition=%s',
                callback_id, transition,
            )
            services.admission.close_admission()
            stop_worker()
            return False
        except Exception as exc:
            # No corrective or retried write: republishing here is exactly how a
            # bookkeeping failure used to masquerade as a work failure.  But the
            # work's own failure must not vanish with the record of it, so it is
            # stated in the log, carried on the condition, and bound as the
            # explicit cause.  Python has already bound the write error as the
            # implicit context, so chaining from the work error is what keeps
            # both reachable; chaining from the write error keeps only one.
            work_error_class = (
                _job_error_class(work_error) if work_error is not None else None
            )
            if work_error is not None:
                log.error(
                    'Beacon worker could not record a callback failure; reporting '
                    'the work failure here: callback=%s transition=%s '
                    'work_error_class=%s write_error_class=%s',
                    callback_id, transition, work_error_class, _job_error_class(exc),
                )
            raise JobHealthBookkeepingError(
                callback_id, transition, _job_error_class(exc),
                work_error_class=work_error_class,
            ) from (work_error if work_error is not None else exc)
        if work_error is not None:
            raise work_error
        return result


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
            for startup_callback_id in ('S1', 'S2', 'S3'):
                try:
                    if dispatch_callback(services, startup_callback_id) is False:
                        return
                except JobHealthBookkeepingError as bookkeeping_error:
                    if bookkeeping_error.work_error_class is not None:
                        # The startup work itself failed and the write that would
                        # have recorded that failure also failed, so nothing has
                        # confirmed the state Beacon would carry forward.  Continuing
                        # here runs the worker on state nothing confirmed, and the
                        # operator sees a warning that never names the work failure.
                        # Fail loudly instead.
                        raise
                    # A failure to record that a startup job began is a fact about
                    # the recording, never a verdict on whether Beacon should run.
                    # Left unhandled, a transient database lock could stop the
                    # worker from starting at all, which is strictly worse for the
                    # operator than an unrecorded start.  Lease loss still aborts
                    # startup through the `is False` return above.
                    log.warning(
                        'Beacon worker could not record a startup job; continuing '
                        'startup: callback=%s error_class=%s',
                        startup_callback_id, bookkeeping_error.error_class,
                    )
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
