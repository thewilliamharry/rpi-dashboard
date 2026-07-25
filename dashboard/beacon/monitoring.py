"""Framework-free monitoring operation interfaces.

The worker owns composition.  This module only receives callables for persistence,
network transport, and clocks, which keeps it importable by jobs and unit tests
without creating Flask, schedulers, or browser processes.
"""

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class MonitoringOperations:
    """Explicit monitoring collaborators supplied by a composition root."""

    probe_http: Callable
    insert_event: Callable
    record_event: Callable
    should_send_alert: Callable
    send_transition_alert: Callable
    handle_state_transition: Callable
    uptime_summary: Callable
    build_uptime_buckets: Callable
    calc_uptime_pct: Callable
    collect_system_stats: Callable
    cleanup_history: Callable
    do_discovery: Callable
    run_discovery: Callable
    do_uptime_check: Callable


def probe_http(operations, url, timeout=2.5, allow_remote=False, healthy_statuses='200-399'):
    return operations.probe_http(url, timeout, allow_remote, healthy_statuses)


def insert_event(operations, conn, **kwargs):
    return operations.insert_event(conn, **kwargs)


def record_event(operations, *args, **kwargs):
    return operations.record_event(*args, **kwargs)


def should_send_alert(operations, port, online, now):
    return operations.should_send_alert(port, online, now)


def send_transition_alert(operations, **kwargs):
    return operations.send_transition_alert(**kwargs)


def handle_state_transition(operations, **kwargs):
    return operations.handle_state_transition(**kwargs)


def uptime_summary(operations, checks, now):
    return operations.uptime_summary(checks, now)


def build_uptime_buckets(operations, checks, now):
    return operations.build_uptime_buckets(checks, now)


def calc_uptime_pct(operations, checks, now=None):
    return operations.calc_uptime_pct(checks, now)


def collect_system_stats(operations, now=None, persist_history=None):
    return operations.collect_system_stats(now, persist_history)


def cleanup_history(operations, now=None):
    return operations.cleanup_history(now)


def do_discovery(operations, source='scheduled'):
    return operations.do_discovery(source)


def run_discovery(operations, source='scheduled'):
    return operations.run_discovery(source)


def do_uptime_check(operations, only_down=False):
    return operations.do_uptime_check(only_down)
