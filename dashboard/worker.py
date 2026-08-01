"""Compatibility command for the worker-only Beacon composition root."""

try:
    from .beacon import worker_main
    from .beacon import queues
    from .beacon.db import prepare_database
    from . import app as beacon
except ImportError:  # ``python worker.py`` from the dashboard directory.
    from beacon import worker_main
    from beacon import queues
    from beacon.db import prepare_database
    import app as beacon


# Retain import-level names used by deployment diagnostics and older tests.
heartbeat = worker_main.heartbeat
sample_metrics = worker_main.sample_metrics
scheduled_discovery = worker_main.scheduled_discovery
startup_discovery = worker_main.startup_discovery
stop_worker = worker_main.stop_worker
build_scheduler = worker_main.build_scheduler


def build_worker_operations():
    """Join legacy compatibility operations to the independent worker runtime."""
    return worker_main.WorkerOperations(
        prepare_database=prepare_database,
        recover_worker_state=beacon.recover_worker_state,
        update_worker_heartbeat=beacon.update_worker_heartbeat,
        collect_system_stats=beacon.collect_system_stats,
        read_scan_state=beacon._read_scan_state,
        run_discovery=beacon.run_discovery,
        do_uptime_check=beacon.do_uptime_check,
        process_scan_requests=beacon.process_scan_requests,
        process_preview_requests=beacon.process_preview_requests,
        cleanup_history=beacon.cleanup_history,
        shutdown_browser=beacon.shutdown_browser,
        acquire_worker_lease=queues.acquire_worker_lease,
        renew_worker_lease=queues.renew_worker_lease,
        release_worker_lease=queues.release_worker_lease,
    )


def main(settings=None):
    return worker_main.run_worker(build_worker_operations(), settings=settings)


if __name__ == '__main__':
    main()
