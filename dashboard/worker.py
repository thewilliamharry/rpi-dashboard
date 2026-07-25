import atexit
import logging
import os
import signal
import sys
import threading
import time

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler

try:
    from . import app as beacon
except ImportError:
    import app as beacon


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('beacon.worker')
logging.getLogger('apscheduler').setLevel(logging.WARNING)


scheduler = None
_worker_started = False
_worker_start_lock = threading.Lock()


def heartbeat():
    beacon.update_worker_heartbeat()


def sample_metrics():
    beacon.collect_system_stats()


def scheduled_discovery():
    state = beacon._read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        return
    beacon.run_discovery(source='scheduled')


def startup_discovery():
    state = beacon._read_scan_state()
    if state.get('scanning') or state.get('stage') == 'queued':
        return
    last = state.get('last_discovery')
    if not last or int(time.time()) - int(last) >= 300:
        beacon.run_discovery(source='startup')


def stop_worker(*_args):
    beacon.shutdown_browser()
    if scheduler is not None:
        scheduler.shutdown(wait=False)


def build_scheduler():
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
    built_scheduler.add_job(heartbeat, 'interval', seconds=5, executor='metrics', id='heartbeat')
    built_scheduler.add_job(
        sample_metrics, 'interval', seconds=beacon.METRIC_SAMPLE_SECONDS,
        executor='metrics', id='metrics', misfire_grace_time=10,
    )
    built_scheduler.add_job(
        beacon.do_uptime_check, 'interval', minutes=5, kwargs={'only_down': False},
        executor='probes', id='uptime_all', misfire_grace_time=60,
    )
    built_scheduler.add_job(
        beacon.do_uptime_check, 'interval', minutes=1, kwargs={'only_down': True},
        executor='probes', id='uptime_down', misfire_grace_time=30,
    )
    built_scheduler.add_job(
        beacon.process_scan_requests, 'interval', seconds=2,
        executor='probes', id='scan_requests', misfire_grace_time=10,
    )
    built_scheduler.add_job(
        beacon.process_preview_requests, 'interval', seconds=2,
        executor='screenshots', id='preview_requests', misfire_grace_time=10,
    )
    built_scheduler.add_job(
        scheduled_discovery, 'interval', hours=24, executor='probes',
        id='scheduled_discovery', misfire_grace_time=300,
    )
    built_scheduler.add_job(
        beacon.cleanup_history, 'interval', hours=1, executor='metrics',
        id='cleanup', misfire_grace_time=300,
    )
    built_scheduler.add_job(
        startup_discovery, 'date', run_date=None, executor='probes',
        id='startup_discovery', misfire_grace_time=300,
    )
    return built_scheduler


def main():
    global scheduler, _worker_started
    with _worker_start_lock:
        if _worker_started:
            return
        beacon.init_db()
        beacon.recover_worker_state()
        heartbeat()
        sample_metrics()
        scheduler = build_scheduler()
        atexit.register(beacon.shutdown_browser)
        signal.signal(signal.SIGTERM, stop_worker)
        signal.signal(signal.SIGINT, stop_worker)
        _worker_started = True

    log.info('Beacon worker starting')
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        beacon.shutdown_browser()

if __name__ == '__main__':
    main()
