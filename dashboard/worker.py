"""Compatibility command for the worker-only Beacon composition root."""

try:
    from .beacon import worker_main
except ImportError:  # ``python worker.py`` from the dashboard directory.
    from beacon import worker_main


# Retain import-level names used by deployment diagnostics and older tests.
beacon = worker_main.beacon
heartbeat = worker_main.heartbeat
sample_metrics = worker_main.sample_metrics
scheduled_discovery = worker_main.scheduled_discovery
startup_discovery = worker_main.startup_discovery
stop_worker = worker_main.stop_worker
build_scheduler = worker_main.build_scheduler
main = worker_main.main


if __name__ == '__main__':
    main()
