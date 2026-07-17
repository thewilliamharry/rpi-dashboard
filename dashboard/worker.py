import atexit
import logging
import os
import signal
import sys
import time

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler

import app as beacon


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('beacon.worker')
logging.getLogger('apscheduler').setLevel(logging.WARNING)


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
    scheduler.shutdown(wait=False)


beacon.init_db()
beacon.recover_worker_state()
heartbeat()
sample_metrics()

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
scheduler = BlockingScheduler(executors=executors, job_defaults=job_defaults, timezone='UTC')

scheduler.add_job(heartbeat, 'interval', seconds=5, executor='metrics', id='heartbeat')
scheduler.add_job(
    sample_metrics, 'interval', seconds=beacon.METRIC_SAMPLE_SECONDS,
    executor='metrics', id='metrics', misfire_grace_time=10,
)
scheduler.add_job(
    beacon.do_uptime_check, 'interval', minutes=5, kwargs={'only_down': False},
    executor='probes', id='uptime_all', misfire_grace_time=60,
)
scheduler.add_job(
    beacon.do_uptime_check, 'interval', minutes=1, kwargs={'only_down': True},
    executor='probes', id='uptime_down', misfire_grace_time=30,
)
scheduler.add_job(
    beacon.process_scan_requests, 'interval', seconds=2,
    executor='probes', id='scan_requests', misfire_grace_time=10,
)
scheduler.add_job(
    beacon.process_preview_requests, 'interval', seconds=2,
    executor='screenshots', id='preview_requests', misfire_grace_time=10,
)
scheduler.add_job(
    scheduled_discovery, 'interval', hours=24, executor='probes',
    id='scheduled_discovery', misfire_grace_time=300,
)
scheduler.add_job(
    beacon.cleanup_history, 'interval', hours=1, executor='metrics',
    id='cleanup', misfire_grace_time=300,
)
scheduler.add_job(
    startup_discovery, 'date', run_date=None, executor='probes',
    id='startup_discovery', misfire_grace_time=300,
)

atexit.register(beacon.shutdown_browser)
signal.signal(signal.SIGTERM, stop_worker)
signal.signal(signal.SIGINT, stop_worker)

if __name__ == '__main__':
    log.info('Beacon worker starting')
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        beacon.shutdown_browser()
