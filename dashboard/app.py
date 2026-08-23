import logging
import os
import json
import hashlib
import ipaddress
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import psutil
import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, make_response, request, send_file

try:
    from .beacon.config import load_settings
    from .beacon import repositories as beacon_repositories
    from .beacon import diagnosis as beacon_diagnosis
    from .beacon import maintenance as beacon_maintenance
    from .beacon import telemetry as beacon_telemetry
    from .beacon import web as beacon_web
    from .beacon import monitoring as beacon_monitoring
    from .beacon import previews as beacon_previews
    from .beacon import queues as beacon_queues
    from .beacon import worker_main as beacon_worker_main
    from .beacon.db import connect_db, database_access, MaintenanceBusy
    from .beacon.migrations import RECOVERY_MARKER
    from .beacon.outbound import OutboundPolicy, OutboundPolicyError, OutboundPurpose, OutboundTransport
except ImportError:  # Gunicorn imports ``app`` from dashboard/ directly.
    from beacon.config import load_settings
    from beacon import repositories as beacon_repositories
    from beacon import diagnosis as beacon_diagnosis
    from beacon import maintenance as beacon_maintenance
    from beacon import telemetry as beacon_telemetry
    from beacon import web as beacon_web
    from beacon import monitoring as beacon_monitoring
    from beacon import previews as beacon_previews
    from beacon import queues as beacon_queues
    from beacon import worker_main as beacon_worker_main
    from beacon.db import connect_db, database_access, MaintenanceBusy
    from beacon.migrations import RECOVERY_MARKER
    from beacon.outbound import OutboundPolicy, OutboundPolicyError, OutboundPurpose, OutboundTransport

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)

app = Flask(__name__)

SETTINGS = load_settings()
DB_PATH = SETTINGS.db_path
EXPIRE_DAYS = SETTINGS.expire_days
THUMB_MAX_BYTES = 2 * 1024 * 1024
THUMB_REFRESH_DAYS = SETTINGS.thumb_refresh_days
PREVIEW_SETTLE_MS = 5_000
PREVIEW_BROWSER_BUDGET_MS = 27_000
# Sentinel that survives both of _legacy_screenshot_service's and
# _legacy_refresh_service_preview's blanket `except Exception` handlers
# unmodified, because it travels through the already-existing
# thumb_error/screenshot_error return slot, never through a raised exception.
THUMB_ERROR_BROWSER_UNAVAILABLE = 'browser_unavailable'
UPTIME_WINDOW_SECONDS = 7 * 86400
UPTIME_BUCKETS = 168
CHECK_RETENTION_SECONDS = UPTIME_WINDOW_SECONDS + 86400
METRIC_SAMPLE_SECONDS = SETTINGS.metric_sample_seconds
METRIC_HISTORY_SECONDS = SETTINGS.metric_history_seconds
WORKER_READY_SECONDS = SETTINGS.worker_ready_seconds
DISCOVERY_TIMEOUT_SECONDS = SETTINGS.discovery_timeout_seconds
ENABLE_PROMETHEUS = SETTINGS.enable_prometheus

DEFAULT_TRUSTED_HOSTS = (
    "raspi.local,raspi,localhost,127.0.0.1,::1,"
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7"
)


def _parse_trusted_hosts(value):
    hosts = set()
    networks = set()
    for raw_item in value.split(','):
        item = raw_item.strip().lower().strip('[]')
        if not item:
            continue
        if '/' in item:
            networks.add(ipaddress.ip_network(item, strict=False))
        else:
            hosts.add(item)
    return hosts, networks


TRUSTED_HOSTS = set(SETTINGS.trusted_hosts)
TRUSTED_HOST_NETWORKS = set(SETTINGS.trusted_host_networks)
LOCAL_SERVICE_HOSTS = set(SETTINGS.local_service_hosts)
EXTRA_SCAN_PORTS = set(SETTINGS.extra_scan_ports)
TRIGGER_SCAN_RATE_LIMIT = SETTINGS.trigger_scan_rate_limit
TRIGGER_SCAN_WINDOW_SECONDS = SETTINGS.trigger_scan_window_seconds
ALERT_WEBHOOK_URL = SETTINGS.alert_webhook_url
ALERT_COOLDOWN_SECONDS = SETTINGS.alert_cooldown_seconds
ALERT_ONLY_CRITICAL = SETTINGS.alert_only_critical
# Event-vocabulary constant so no call site spells the MNT-04 overrun literal twice.
MAINTENANCE_OVERRUN_EVENT_TYPE = 'maintenance_overrun'

_db_lock = threading.Lock()
_scan_lock = threading.Lock()
_startup_lock = threading.Lock()
_screenshot_sem = threading.Semaphore(1)
_uptime_lock = threading.Lock()
_browser_lock = threading.Lock()
_worker_effect_authority = ContextVar('worker_effect_authority', default=None)
_worker_mutation_authority = ContextVar('worker_mutation_authority', default=None)
_browser_playwright = None
_browser_instance = None
_preview_context = threading.local()

_bg_started = False


def get_db():
    """Open one connection outside the shared-lease seam; owned by tests that call it directly."""
    return connect_db(DB_PATH)


def _table_columns(conn, table_name):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def init_db():
    """Compatibility entry point for the single migration preparation boundary."""
    try:
        from .beacon.db import prepare_database
    except ImportError:  # ``python app.py`` from the dashboard directory.
        from beacon.db import prepare_database

    with _db_lock:
        result = prepare_database(DB_PATH)
        # Preserve the established compatibility repair for records written by
        # older web processes.  Schema/data upgrades themselves remain owned by
        # the versioned migration runner above.
        with database_access(DB_PATH) as conn:
            conn.execute("""
                UPDATE services
                   SET state_since = COALESCE(
                       (SELECT MAX(e.ts) FROM events e
                         WHERE e.port = services.port
                           AND e.event_type = 'state_change'
                           AND e.online = services.is_online),
                       CASE WHEN services.is_online = 1 THEN services.first_seen ELSE services.last_seen END
                   )
                 WHERE state_since IS NULL
            """)
            conn.commit()
        return result


def _write_runtime_state_row(conn, key, value, now):
    conn.execute(
        "INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts",
        (key, json.dumps(value, separators=(',', ':')), now),
    )


def _set_runtime_state(key, value, *, conn=None, now=None):
    now = int(time.time()) if now is None else int(now)
    if conn is not None:
        _write_runtime_state_row(conn, key, value, now)
        return
    with database_access(DB_PATH) as conn:
        _write_runtime_state_row(conn, key, value, now)
        conn.commit()


def _read_runtime_state_row(conn, key):
    return conn.execute("SELECT value, updated_ts FROM runtime_state WHERE key=?", (key,)).fetchone()


def _get_runtime_state(key, default=None, *, conn=None):
    if conn is not None:
        row = _read_runtime_state_row(conn, key)
    else:
        with database_access(DB_PATH) as conn:
            row = _read_runtime_state_row(conn, key)
    if not row:
        return default
    try:
        return json.loads(row['value'])
    except (TypeError, ValueError):
        return default


def update_worker_heartbeat(now=None):
    now = int(time.time()) if now is None else int(now)
    with _db_lock:
        _set_runtime_state('worker_heartbeat', {'ts': now}, now=now)


def recover_worker_state(now=None):
    """Requeue work interrupted by a worker/container restart."""
    now = int(time.time()) if now is None else int(now)
    beacon_queues.recover_queues(DB_PATH, now=now)
    with _db_lock, database_access(DB_PATH) as conn:
        heartbeat = _get_runtime_state('worker_heartbeat', {}, conn=conn)
        heartbeat_ts = heartbeat.get('ts') if isinstance(heartbeat, dict) else None
        try:
            heartbeat_ts = int(heartbeat_ts) if heartbeat_ts is not None else None
        except (TypeError, ValueError):
            heartbeat_ts = None
        if heartbeat_ts is not None and now - heartbeat_ts > WORKER_READY_SECONDS:
            details = json.dumps({'start_ts': heartbeat_ts, 'end_ts': now}, separators=(',', ':'))
            recorded = conn.execute(
                "SELECT 1 FROM events WHERE event_type='monitoring_gap' AND details=? LIMIT 1",
                (details,),
            ).fetchone()
            if not recorded:
                _insert_event(
                    conn,
                    ts=now,
                    event_type='monitoring_gap',
                    details=details,
                )
        state = _read_scan_state(conn)
        queued = conn.execute("SELECT 1 FROM scan_requests WHERE status='queued' LIMIT 1").fetchone()
        state.update({
            'stage': 'queued' if queued else 'idle',
            'scanning': False,
            'progress': 0.0,
            'current_found': 0,
            'last_error': 'worker restarted during active scan' if state.get('scanning') else state.get('last_error'),
        })
        _set_runtime_state('scan_state', state, conn=conn)
        conn.commit()


@contextmanager
def _worker_write_transaction(authority, *, now=None):
    """Open one worker-owned SQLite write transaction on the authority path."""
    conn = connect_db(authority.db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        beacon_queues.assert_current_worker_authority(conn, authority, now)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def _mutation_write_transaction(authority=None, *, now=None):
    """Use the worker epoch for worker-originated writes, web lock otherwise."""
    if authority is not None:
        # A supplied timestamp may describe sampled data, but it must never
        # become the authority clock for a later write transaction.
        with _worker_write_transaction(authority) as conn:
            yield conn
        return
    with _db_lock, database_access(DB_PATH) as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def worker_recover_worker_state(authority, now=None):
    """Recover queues and runtime state with an assertion in every transaction."""
    now = authority.now() if now is None else int(now)
    try:
        beacon_queues.recover_queues_for_worker(authority, now=now)
        with _worker_write_transaction(authority) as conn:
            heartbeat = _get_runtime_state('worker_heartbeat', {}, conn=conn)
            heartbeat_ts = heartbeat.get('ts') if isinstance(heartbeat, dict) else None
            try:
                heartbeat_ts = int(heartbeat_ts) if heartbeat_ts is not None else None
            except (TypeError, ValueError):
                heartbeat_ts = None
            if heartbeat_ts is not None and now - heartbeat_ts > WORKER_READY_SECONDS:
                details = json.dumps({'start_ts': heartbeat_ts, 'end_ts': now}, separators=(',', ':'))
                if not conn.execute(
                    "SELECT 1 FROM events WHERE event_type='monitoring_gap' AND details=? LIMIT 1",
                    (details,),
                ).fetchone():
                    _insert_event(conn, ts=now, event_type='monitoring_gap', details=details)
            state = _read_scan_state(conn)
            queued = conn.execute("SELECT 1 FROM scan_requests WHERE status='queued' LIMIT 1").fetchone()
            state.update({
                'stage': 'queued' if queued else 'idle', 'scanning': False, 'progress': 0.0,
                'current_found': 0,
                'last_error': 'worker restarted during active scan' if state.get('scanning') else state.get('last_error'),
            })
            _set_runtime_state('scan_state', state, conn=conn, now=now)
    except beacon_queues.LeaseLost:
        raise
    return True


def worker_update_worker_heartbeat(authority, now=None):
    now = authority.now() if now is None else int(now)
    try:
        with _worker_write_transaction(authority) as conn:
            _set_runtime_state('worker_heartbeat', {'ts': now}, conn=conn, now=now)
    except beacon_queues.LeaseLost:
        raise
    return True


def _default_scan_state():
    return {
        'stage': 'idle',
        'scanning': False,
        'progress': 0.0,
        'current_candidates': 0,
        'current_found': 0,
        'last_completed_found': 0,
        'last_discovery': None,
        'last_uptime_check': None,
        'last_down_check': None,
        'timings': {},
        'last_error': None,
    }


def _read_scan_state(conn=None):
    state = _default_scan_state()
    stored = _get_runtime_state('scan_state', {}, conn=conn)
    if isinstance(stored, dict):
        state.update(stored)
    return state


def _update_scan_state(**changes):
    authority = _worker_mutation_authority.get()
    if authority is not None:
        with _worker_write_transaction(authority) as conn:
            state = _read_scan_state(conn)
            state.update(changes)
            _set_runtime_state('scan_state', state, conn=conn, now=authority.now())
        return
    with _db_lock, database_access(DB_PATH) as conn:
        state = _read_scan_state(conn)
        state.update(changes)
        _set_runtime_state('scan_state', state, conn=conn)
        conn.commit()
    return state


def get_temp():
    try:
        temps = psutil.sensors_temperatures()
        for key in ["cpu_thermal", "coretemp", "cpu-thermal", "bcm2835_thermal"]:
            if key in temps and temps[key]:
                return temps[key][0].current
    except Exception:
        pass
    return None


def _is_loopback_host(host):
    if not host:
        return False
    host = str(host).lower().strip('[]')
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == 'localhost'


def _is_local_service_host(host):
    if not host:
        return False
    host = str(host).lower().rstrip('.').strip('[]')
    return _is_loopback_host(host) or host in {item.rstrip('.') for item in LOCAL_SERVICE_HOSTS}


def _is_trusted_request_host(host):
    if _is_local_service_host(host):
        return True
    try:
        address = ipaddress.ip_address(str(host).lower().strip('[]'))
    except ValueError:
        return False
    return any(address in network for network in TRUSTED_HOST_NETWORKS)


def _is_localhost_url(url):
    try:
        host = urlparse(url).hostname or ''
        return _is_local_service_host(host)
    except Exception:
        return False


def _default_service_url(port):
    return f"http://127.0.0.1:{port}"


def _normalize_service_url(value, port):
    if value is None or str(value).strip() == '':
        return _default_service_url(port)
    raw = str(value).strip()
    parsed = urlparse(raw if '://' in raw else f"http://{raw}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must use http:// or https://")
    if not parsed.hostname:
        raise ValueError("URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not include user information")
    if not _is_local_service_host(parsed.hostname):
        raise ValueError("URL target must be this Pi or a configured local alias")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is invalid") from exc
    if parsed_port is None:
        parsed_port = int(port)
    canonical_host = '127.0.0.1'
    netloc = f"{canonical_host}:{parsed_port}"
    normalized = urlunparse((parsed.scheme.lower(), netloc, parsed.path or '', '', parsed.query, parsed.fragment)).rstrip('/')
    return normalized


def _safe_service_url(value, port):
    try:
        return _normalize_service_url(value, port)
    except ValueError:
        return _default_service_url(port)


def _normalize_service_path(value):
    if value is None or str(value).strip() == '':
        return '/'
    raw = str(value).strip()
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Path must not include scheme or host")

    path = parsed.path or '/'
    if not path.startswith('/'):
        path = '/' + path

    normalized = path
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"
    return normalized


def _service_url_with_path(base_url, path, port):
    base = _normalize_service_url(base_url, port)
    normalized_path = _normalize_service_path(path)
    base_parsed = urlparse(base)
    path_parsed = urlparse(normalized_path)
    return urlunparse(
        (
            base_parsed.scheme,
            base_parsed.netloc,
            path_parsed.path or '/',
            '',
            path_parsed.query,
            path_parsed.fragment,
        )
    )


def _service_path_from_url(url, port):
    normalized = _safe_service_url(url, port)
    parsed = urlparse(normalized)
    path = parsed.path or '/'
    if not path.startswith('/'):
        path = '/' + path
    normalized_path = path
    if parsed.query:
        normalized_path += f"?{parsed.query}"
    if parsed.fragment:
        normalized_path += f"#{parsed.fragment}"
    return normalized_path


def _discovery_probe_url(port, existing_url):
    if not existing_url:
        return _default_service_url(port)
    normalized = _safe_service_url(existing_url, port)
    if _is_localhost_url(normalized):
        return normalized
    return _default_service_url(port)


def _parse_tags(tags):
    if not tags:
        return []
    if isinstance(tags, list):
        return [str(t).strip() for t in tags if str(t).strip()]
    return [p.strip() for p in str(tags).split(',') if p.strip()]


def _tags_to_db(tags):
    return ','.join(_parse_tags(tags))


def _parse_healthy_statuses(value):
    raw = str(value or '200-399').strip()
    if not raw:
        raise ValueError('healthy_statuses must not be empty')
    ranges = []
    normalized = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            raise ValueError('healthy_statuses contains an empty value')
        if '-' in item:
            parts = item.split('-', 1)
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError as exc:
                raise ValueError('healthy_statuses must contain HTTP codes or ranges') from exc
        else:
            try:
                start = end = int(item)
            except ValueError as exc:
                raise ValueError('healthy_statuses must contain HTTP codes or ranges') from exc
        if start < 100 or end > 599 or start > end:
            raise ValueError('healthy_statuses values must be between 100 and 599')
        ranges.append((start, end))
        normalized.append(str(start) if start == end else f'{start}-{end}')
    return ranges, ','.join(normalized)


def _status_is_healthy(status, healthy_statuses='200-399'):
    ranges, _ = _parse_healthy_statuses(healthy_statuses)
    return any(start <= int(status) <= end for start, end in ranges)


# Seven days -- the bound that keeps the occurrence search finite (see
# 03.1-PLAN.md Task 2, step 2's duration_minutes/grace_minutes bound).
_MAINTENANCE_WINDOW_MAX_MINUTES = 10080


def _validate_maintenance_windows(payload_value, *, max_windows):
    """Validate and normalise the ``maintenance_windows`` PUT payload field.

    Returns ``(normalised_windows, error)`` where exactly one of the two is
    ``None``. Runs before any database connection is opened, so a rejection
    never touches storage. Every numeric/type check is identity-based
    (``type(x) is int``, not ``isinstance``) in the style of the existing
    ``pinned_order`` check, so a Python ``bool`` -- itself an ``int``
    subclass -- is never silently accepted where an integer is required.
    Every rejection message matches the Copywriting Contract character for
    character, including the 1-based window index prefix; the array-shape
    and per-service-cap messages are planner-authored, since the contract
    does not cover those two cases.
    """
    if not isinstance(payload_value, list):
        return None, 'maintenance_windows must be an array'
    if len(payload_value) > max_windows:
        return None, f'A service may have at most {max_windows} maintenance windows.'

    normalised = []
    for index, window in enumerate(payload_value, start=1):
        if not isinstance(window, dict):
            return None, f'Window {index}: Start time is required.'

        start_minute = window.get('start_minute')
        if type(start_minute) is not int or not 0 <= start_minute <= 1439:
            return None, f'Window {index}: Start time is required.'

        duration_minutes = window.get('duration_minutes')
        if (
            type(duration_minutes) is not int
            or duration_minutes < 1
            or duration_minutes > _MAINTENANCE_WINDOW_MAX_MINUTES
        ):
            return None, f'Window {index}: Duration must be at least 1 minute.'

        weekdays = window.get('weekdays')
        if (
            not isinstance(weekdays, list)
            or not weekdays
            or any(type(day) is not int or not 1 <= day <= 7 for day in weekdays)
            or len(set(weekdays)) != len(weekdays)
        ):
            return None, f'Window {index}: Select at least one weekday.'

        grace_minutes = window.get('grace_minutes')
        if (
            type(grace_minutes) is not int
            or grace_minutes < 0
            or grace_minutes > _MAINTENANCE_WINDOW_MAX_MINUTES
        ):
            return None, f'Window {index}: Grace period is required and must be 0 minutes or more.'

        normalised.append({
            'start_minute': start_minute,
            'duration_minutes': duration_minutes,
            'weekdays': set(weekdays),
            'grace_minutes': grace_minutes,
            'enabled': bool(window.get('enabled', True)),
        })

    return normalised, None


def _outbound_policy():
    """Build a fresh immutable policy so tests and config reloads never share TLS state."""
    return OutboundPolicy(replace(load_settings(), alert_webhook_url=ALERT_WEBHOOK_URL))


def _outbound_transport():
    return OutboundTransport(_outbound_policy())


def _safe_policy_error(error, *, redirect=False):
    if redirect or error.reason == 'redirect_not_allowed':
        return 'redirect_offhost'
    return {
        'scheme_not_allowed': 'invalid_target',
        'credentials_not_allowed': 'invalid_target',
        'port_not_allowed': 'invalid_target',
        'target_not_allowed': 'invalid_target',
        'resolved_address_not_allowed': 'invalid_target',
        'resolution_failed': 'invalid_target',
        'tls_required': 'invalid_target',
    }.get(error.reason, 'policy_error')


def _legacy_probe_http(url, timeout=2.5, allow_remote=False, healthy_statuses='200-399'):
    start = None
    try:
        _parse_healthy_statuses(healthy_statuses)
        start = time.monotonic()
        resp, plan = _outbound_transport().request(
            url, OutboundPurpose.SERVICE_PROBE,
        )
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        if not _status_is_healthy(resp.status_code, healthy_statuses):
            return False, latency_ms, f"http_{resp.status_code}", resp
        return True, latency_ms, None, resp
    except OutboundPolicyError as exc:
        latency_ms = round((time.monotonic() - start) * 1000, 1) if start is not None else None
        return False, latency_ms, _safe_policy_error(exc), getattr(exc, 'response', None)
    except ValueError:
        return False, None, "invalid_target", None
    except requests.exceptions.Timeout:
        return False, None, "timeout", None
    except requests.exceptions.ConnectionError:
        return False, None, "connection_error", None
    except requests.exceptions.RequestException:
        return False, None, "request_error", None
    except Exception:
        return False, None, "probe_error", None


def _is_html_content_type(content_type):
    ctype = (content_type or '').split(';')[0].strip().lower()
    return ctype in ("text/html", "application/xhtml+xml")


def _legacy_fetch_html_response(url, timeout=3, allow_remote=False):
    try:
        resp, plan = _outbound_transport().request(
            url, OutboundPurpose.HTML_PREVIEW,
        )
        final_url = plan.url
        if not _is_html_content_type(resp.headers.get('Content-Type', '')):
            return False, "non_html", resp, final_url
        return True, None, resp, final_url
    except OutboundPolicyError as exc:
        return False, _safe_policy_error(exc), None, None
    except ValueError:
        return False, "invalid_target", None, url
    except requests.exceptions.Timeout:
        return False, "timeout", None, url
    except requests.exceptions.ConnectionError:
        return False, "connection_error", None, url
    except requests.exceptions.RequestException:
        return False, "request_error", None, url
    except Exception:
        return False, "probe_error", None, url


def _legacy_extract_title(resp, port):
    if not resp:
        return f":{port}"
    if not _is_html_content_type(resp.headers.get('Content-Type', '')):
        return f":{port}"
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.title.get_text(strip=True) if soup.title else ""
        if title:
            return title

        meta_candidates = [
            ('meta', {'property': 'og:title'}),
            ('meta', {'name': 'og:title'}),
            ('meta', {'name': 'title'}),
            ('meta', {'property': 'title'}),
            ('meta', {'name': 'application-name'}),
            ('meta', {'name': 'apple-mobile-web-app-title'}),
        ]
        for tag, attrs in meta_candidates:
            el = soup.find(tag, attrs=attrs)
            if not el:
                continue
            content = (el.get('content') or '').strip()
            if content:
                return content

        for heading in soup.find_all(['h1', 'h2'], limit=2):
            text = heading.get_text(" ", strip=True)
            if text:
                return text[:120]

        return f":{port}"
    except Exception:
        return f":{port}"


def _legacy_get_browser():
    global _browser_playwright, _browser_instance
    with _browser_lock:
        if _browser_instance is not None and _browser_instance.is_connected():
            return _browser_instance
        if _browser_playwright is not None:
            try:
                _browser_playwright.stop()
            except Exception:
                pass
            _browser_playwright = None
        from playwright.sync_api import sync_playwright
        launch_started = time.monotonic()
        try:
            _browser_playwright = sync_playwright().start()
            _browser_instance = _browser_playwright.chromium.launch(
                timeout=15_000,
                args=['--disable-dev-shm-usage'],
            )
        except Exception:
            if _browser_playwright is not None:
                try:
                    _browser_playwright.stop()
                except Exception:
                    pass
            _browser_playwright = None
            _browser_instance = None
            raise
        if hasattr(_preview_context, 'timings'):
            _preview_context.timings['browser_launch_ms'] = round((time.monotonic() - launch_started) * 1000, 1)
        return _browser_instance


def _legacy_shutdown_browser():
    global _browser_playwright, _browser_instance
    with _browser_lock:
        if _browser_instance is not None:
            try:
                _browser_instance.close()
            except Exception:
                pass
        if _browser_playwright is not None:
            try:
                _browser_playwright.stop()
            except Exception:
                pass
        _browser_instance = None
        _browser_playwright = None


def _legacy_insert_event(conn, *, ts, event_type, port=None, online=None, previous_online=None,
                  latency_ms=None, error_class=None, alert_status=None, details=None,
                  suppressed_reason=None, maintenance_grace_until=None, down_since_ts=None):
    conn.execute(
        "INSERT INTO events (ts, port, event_type, online, previous_online, latency_ms, error_class, "
        "alert_status, details, suppressed_reason, maintenance_grace_until, down_since_ts) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            ts,
            port,
            event_type,
            online,
            previous_online,
            latency_ms,
            (error_class or '')[:64] if error_class else None,
            (alert_status or '')[:64] if alert_status else None,
            (details or '')[:400] if details else None,
            (suppressed_reason or '')[:64] if suppressed_reason else None,
            maintenance_grace_until,
            down_since_ts,
        )
    )


def _legacy_record_event(event_type, port=None, online=None, previous_online=None,
                  latency_ms=None, error_class=None, alert_status=None, details=None):
    authority = _worker_mutation_authority.get()
    now = authority.now() if authority is not None else int(time.time())
    if authority is not None:
        with _worker_write_transaction(authority) as conn:
            _insert_event(
                conn, ts=now, event_type=event_type, port=port, online=online,
                previous_online=previous_online, latency_ms=latency_ms,
                error_class=error_class, alert_status=alert_status, details=details,
            )
        return
    with _db_lock, database_access(DB_PATH) as conn:
        _insert_event(
            conn,
            ts=now,
            event_type=event_type,
            port=port,
            online=online,
            previous_online=previous_online,
            latency_ms=latency_ms,
            error_class=error_class,
            alert_status=alert_status,
            details=details,
        )
        conn.commit()


def _legacy_should_send_alert(port, online, now):
    with _db_lock, database_access(DB_PATH) as conn:
        row = conn.execute(
            "SELECT ts FROM events WHERE port=? AND event_type='alert_sent' AND online=? "
            "ORDER BY ts DESC LIMIT 1",
            (port, online),
        ).fetchone()
    if not row:
        return True
    return (now - int(row['ts'])) >= ALERT_COOLDOWN_SECONDS


def _legacy_send_transition_alert(*, now, port, previous_online, online, title, display_name,
                           url, critical, latency_ms, error_class):
    if not ALERT_WEBHOOK_URL:
        return
    if ALERT_ONLY_CRITICAL and not critical:
        return
    if not _should_send_alert(port, online, now):
        return

    payload = {
        "timestamp": now,
        "port": port,
        "service": display_name or title or f":{port}",
        "title": title,
        "url": url,
        "critical": bool(critical),
        "previous_online": bool(previous_online),
        "online": bool(online),
        "latency_ms": latency_ms,
        "error_class": error_class,
        "event": "service_recovered" if online else "service_down",
    }

    try:
        r, _plan = _outbound_transport().request(
            ALERT_WEBHOOK_URL,
            OutboundPurpose.WEBHOOK,
            method='POST',
            json=payload,
        )
        if 200 <= r.status_code < 300:
            _record_event(
                "alert_sent",
                port=port,
                online=online,
                previous_online=previous_online,
                latency_ms=latency_ms,
                error_class=error_class,
                alert_status=f"http_{r.status_code}",
                details="webhook delivered",
            )
        else:
            _record_event(
                "alert_failed",
                port=port,
                online=online,
                previous_online=previous_online,
                latency_ms=latency_ms,
                error_class=error_class,
                alert_status=f"http_{r.status_code}",
                details='webhook delivery rejected',
            )
    except OutboundPolicyError as exc:
        _record_event(
            "alert_failed",
            port=port,
            online=online,
            previous_online=previous_online,
            latency_ms=latency_ms,
            error_class=error_class,
            alert_status='policy_' + exc.reason,
            details='webhook policy rejected',
        )
    except Exception:
        _record_event(
            "alert_failed",
            port=port,
            online=online,
            previous_online=previous_online,
            latency_ms=latency_ms,
            error_class=error_class,
            alert_status="delivery_error",
            details='webhook delivery failed',
        )


def _maintenance_suppression_decision(conn, port, *, online, now):
    """Decide the maintenance suppression tag for one transition.

    Shares the caller's own transaction -- no transaction is opened here. A
    down transition asks whether an enabled window covers ``now`` right now,
    via ``beacon_maintenance``'s coverage function. A recovery inherits its
    tag from the down period's own opening event row rather than
    re-deriving live coverage (D-08 non-inference) -- it must never call
    that coverage function itself.

    Returns a two-tuple of suppression reason (or ``None``) and frozen grace
    epoch (or ``None``).
    """
    if not online:
        windows = beacon_repositories.get_maintenance_windows(conn, port)
        covered, grace_until = beacon_maintenance.coverage(windows, now, SETTINGS.timezone)
        if covered:
            return beacon_maintenance.MAINTENANCE_REASON, grace_until
        return None, None
    opening = beacon_repositories.get_open_down_transition(conn, port)
    if opening and opening.get('suppressed_reason') == beacon_maintenance.MAINTENANCE_REASON:
        return beacon_maintenance.MAINTENANCE_REASON, None
    return None, None


def _overrun_detail(down_since_ts, raised_ts):
    """Render the Copywriting Contract's overrun detail string.

    Both instants are formatted in the configured local timezone so the
    stored text reads the way an operator expects; the durable
    ``down_since_ts``/``ts`` columns on the event row remain the
    authoritative machine-readable instants (D-08), never this string.
    """
    zone = beacon_maintenance.resolve_timezone(SETTINGS.timezone)
    down_str = datetime.fromtimestamp(down_since_ts, tz=zone).strftime('%Y-%m-%d %H:%M %Z')
    raised_str = datetime.fromtimestamp(raised_ts, tz=zone).strftime('%Y-%m-%d %H:%M %Z')
    return f"Down since {down_str}; window and grace expired at {raised_str}."


def _legacy_handle_state_transition(*, port, previous_online, online, title, display_name,
                             url, critical, latency_ms, error_class):
    now = int(time.time())
    msg = "service recovered" if online else "service went down"
    with _mutation_write_transaction() as conn:
        suppressed_reason, grace_until = _maintenance_suppression_decision(
            conn, port, online=online, now=now,
        )
        _insert_event(
            conn,
            ts=now,
            event_type="state_change",
            port=port,
            online=online,
            previous_online=previous_online,
            latency_ms=latency_ms,
            error_class=error_class,
            details=msg,
            suppressed_reason=suppressed_reason,
            maintenance_grace_until=grace_until,
        )
    if suppressed_reason is not None:
        # Written and tagged, never withheld (D-10) -- but no alert is
        # attempted at all, so nothing is recorded as sent or failed for it.
        return
    _send_transition_alert(
        now=now,
        port=port,
        previous_online=previous_online,
        online=online,
        title=title,
        display_name=display_name,
        url=url,
        critical=critical,
        latency_ms=latency_ms,
        error_class=error_class,
    )


def _thumb_error(exc):
    _ = exc
    return 'preview_error'


def _legacy_screenshot_service(port, target_url=None):
    """Capture a service screenshot using Chromium. Returns (bytes, mime, error)."""
    _screenshot_sem.acquire()
    policy = _outbound_policy()
    try:
        navigate_url = _normalize_service_url(target_url, port) if target_url else _default_service_url(port)
        initial_plan = policy.plan(navigate_url, OutboundPurpose.BROWSER_PREVIEW)
        navigate_url = initial_plan.url
    except OutboundPolicyError:
        return None, None, 'policy_error'
    except ValueError:
        navigate_url = _default_service_url(port)
    context = None
    started = time.monotonic()
    deadline = started + PREVIEW_BROWSER_BUDGET_MS / 1000
    _preview_context.timings = {}
    _preview_context.page_title = None
    try:
        # A browser that cannot even launch, or that launches but can no longer
        # open a new page on it, is the shared machinery J6 owns (its
        # browser_resource_lifecycle effect surface) -- Chromium missing or
        # unable to launch, or a browser that can no longer open a page at all,
        # are the same fault whichever service triggered this poll, never a
        # fact about the service itself -- reported through a sentinel, before
        # any per-service navigation is attempted, so the blanket handler below
        # cannot fold it into an ordinary per-service warning. A rarer failure
        # while browser_proxy_context itself is entering (browser.new_context(),
        # evaluated before the `with` body ever starts) is NOT distinguished
        # here and still falls through to the per-service classification below
        # -- a known, smaller residual this deliberately leaves open rather
        # than claim coverage the code does not have.
        try:
            browser = _get_browser()
        except Exception:
            return None, None, THUMB_ERROR_BROWSER_UNAVAILABLE
        context_started = time.monotonic()
        with beacon_previews.browser_proxy_context(
                browser,
                policy,
                viewport={'width': 1280, 'height': 800},
                ignore_https_errors=not initial_plan.tls.verify_certificate,
        ) as context:
            try:
                page = context.new_page()
            except Exception:
                return None, None, THUMB_ERROR_BROWSER_UNAVAILABLE
            _preview_context.timings['context_ms'] = round((time.monotonic() - context_started) * 1000, 1)
            remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
            if remaining_ms <= 0:
                return None, None, 'preview timeout'
            navigation_started = time.monotonic()
            page.goto(navigate_url, timeout=min(15_000, remaining_ms), wait_until='domcontentloaded')
            _preview_context.timings['navigation_ms'] = round((time.monotonic() - navigation_started) * 1000, 1)
            if not _is_localhost_url(page.url):
                return None, None, 'redirect_offhost'
            _preview_context.page_title = (page.title() or '').strip() or None
            # HTML probing consumes up to three seconds before capture. The browser
            # gets 27 seconds, including a five-second post-DOM rendering window,
            # keeping the complete preview within an approximately 30-second cap.
            remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
            if remaining_ms <= PREVIEW_SETTLE_MS:
                return None, None, 'preview timeout'
            settle_started = time.monotonic()
            page.wait_for_timeout(PREVIEW_SETTLE_MS)
            _preview_context.timings['settle_ms'] = round((time.monotonic() - settle_started) * 1000, 1)
            remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
            if remaining_ms <= 0:
                return None, None, 'preview timeout'
            screenshot_started = time.monotonic()
            data = page.screenshot(type='png', timeout=remaining_ms)
            _preview_context.timings['screenshot_ms'] = round((time.monotonic() - screenshot_started) * 1000, 1)
            if len(data) <= THUMB_MAX_BYTES:
                return data, 'image/png', None
            log.warning("Screenshot for port %d too large (%d bytes)", port, len(data))
            return None, None, f"screenshot too large ({len(data)} bytes)"
    except Exception as exc:
        log.warning("Screenshot failed for port %d (%s)", port, exc.__class__.__name__)
        return None, None, _thumb_error(exc)
    finally:
        _screenshot_sem.release()
    return None, None, "screenshot failed"


def _legacy_fetch_thumbnail(port, service_url=None):
    """Capture a page thumbnail with Playwright. Returns (bytes, mime, source, error)."""
    try:
        base_url = _normalize_service_url(service_url, port) if service_url else _default_service_url(port)
    except ValueError:
        base_url = _default_service_url(port)

    _preview_context.timings = {}
    started = time.monotonic()
    screenshot_data, screenshot_mime, screenshot_error = _screenshot_service(port, base_url)
    timings = dict(getattr(_preview_context, 'timings', {}))
    timings['total_ms'] = round((time.monotonic() - started) * 1000, 1)
    timings['success'] = bool(screenshot_data)
    log.info('preview_capture %s', json.dumps({'port': port, **timings}, sort_keys=True))
    if screenshot_data:
        return screenshot_data, screenshot_mime, 'screenshot', None
    return None, None, None, screenshot_error or "screenshot failed"


def _legacy_refresh_service_preview(port, service_url):
    warnings = []
    next_title = None
    thumb_data = None
    thumb_mime = None
    thumb_source = None
    thumb_error = None

    try:
        ok, error_class, resp, final_url = _fetch_html_response(service_url, timeout=3)
        if ok and resp is not None:
            extracted = _extract_title(resp, port)
            if extracted and extracted != f":{port}":
                next_title = extracted

            thumb_data, thumb_mime, thumb_source, thumb_error = fetch_thumbnail(port, final_url or service_url)
            if not next_title:
                next_title = getattr(_preview_context, 'page_title', None)
                if not next_title:
                    warnings.append("title not found at configured path")
            if not thumb_data:
                warnings.append("thumbnail refresh failed")
        else:
            warnings.append(f"title refresh failed ({error_class or 'probe_failed'})")
            warnings.append("thumbnail refresh skipped")
    except Exception:
        warnings.append("title refresh failed (exception)")
        warnings.append("thumbnail refresh skipped")

    return next_title, thumb_data, thumb_mime, thumb_source, thumb_error, ('; '.join(warnings) if warnings else None)


def _legacy_uptime_summary(checks, now):
    """Return time-weighted 7-day uptime and hourly availability buckets.

    A sample before the window establishes boundary state. Time before the first
    in-window observation is unknown when no boundary exists.
    """
    start = int(now) - UPTIME_WINDOW_SECONDS
    points = sorted((int(ts), 1 if int(online) else 0) for ts, online in checks if int(ts) <= int(now))
    boundary = None
    in_window = []
    for point in points:
        if point[0] < start:
            boundary = point
        else:
            in_window.append(point)

    intervals = []
    if boundary is not None:
        cursor, state = start, boundary[1]
    elif in_window:
        cursor, state = in_window[0][0], in_window[0][1]
        in_window = in_window[1:]
    else:
        return None, [-1] * UPTIME_BUCKETS

    for ts, next_state in in_window:
        ts = min(max(ts, start), int(now))
        if ts > cursor:
            intervals.append((cursor, ts, state))
        cursor, state = ts, next_state
    if cursor < int(now):
        intervals.append((cursor, int(now), state))

    observed = sum(end - begin for begin, end, _ in intervals)
    online_time = sum((end - begin) for begin, end, online in intervals if online)
    if observed > 0:
        raw_uptime = (online_time / observed) * 100
        uptime = round(raw_uptime, 3)
        if raw_uptime < 100 and uptime == 100:
            uptime = 99.999
    else:
        uptime = None

    bucket_seconds = UPTIME_WINDOW_SECONDS / UPTIME_BUCKETS
    buckets = []
    for idx in range(UPTIME_BUCKETS):
        bucket_start = start + int(idx * bucket_seconds)
        bucket_end = start + int((idx + 1) * bucket_seconds)
        if idx == UPTIME_BUCKETS - 1:
            bucket_end = int(now)
        bucket_observed = 0
        bucket_online = 0
        for begin, end, online in intervals:
            overlap = max(0, min(end, bucket_end) - max(begin, bucket_start))
            bucket_observed += overlap
            if online:
                bucket_online += overlap
        buckets.append(-1 if bucket_observed == 0 else round(bucket_online / bucket_observed, 3))
    return uptime, buckets


def _legacy_build_uptime_buckets(checks, now):
    return _uptime_summary(checks, now)[1]


def _legacy_calc_uptime_pct(checks, now=None):
    return _uptime_summary(checks, int(time.time()) if now is None else now)[0]


def _legacy_collect_system_stats(now=None, persist_history=None):
    now = int(time.time()) if now is None else int(now)
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    temp = get_temp()
    ram_available = int(ram.available)
    ram_total = int(ram.total)
    ram_used = max(0, ram_total - ram_available)
    ram_used_strict = int(ram.used)
    ram_pct = (ram_used / ram_total * 100) if ram_total else 0.0
    sample = {
        'sample_ts': now,
        'cpu': round(float(cpu), 1),
        'ram': round(float(ram_pct), 1),
        'ram_used': ram_used,
        'ram_available': ram_available,
        'ram_used_strict': ram_used_strict,
        'ram_total': ram_total,
        'disk': round(float(disk.percent), 1),
        'disk_used': int(disk.used),
        'disk_total': int(disk.total),
        'temp': temp,
        'hostname': socket.gethostname(),
    }
    with _db_lock, database_access(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO system_stats(id,sample_ts,cpu,ram,ram_used,ram_available,ram_used_strict,ram_total,disk,disk_used,disk_total,temp,hostname) "
            "VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "sample_ts=excluded.sample_ts,cpu=excluded.cpu,ram=excluded.ram,ram_used=excluded.ram_used,"
            "ram_available=excluded.ram_available,ram_used_strict=excluded.ram_used_strict,ram_total=excluded.ram_total,"
            "disk=excluded.disk,disk_used=excluded.disk_used,disk_total=excluded.disk_total,temp=excluded.temp,hostname=excluded.hostname",
            (sample['sample_ts'], sample['cpu'], sample['ram'], sample['ram_used'], sample['ram_available'],
             sample['ram_used_strict'], sample['ram_total'], sample['disk'], sample['disk_used'], sample['disk_total'],
             sample['temp'], sample['hostname']),
        )
        if persist_history is None:
            last = conn.execute("SELECT MAX(ts) AS ts FROM stats_history").fetchone()['ts']
            persist_history = last is None or now - int(last) >= METRIC_HISTORY_SECONDS
        if persist_history:
            conn.execute(
                "INSERT OR REPLACE INTO stats_history(ts,cpu,ram,disk,temp) VALUES(?,?,?,?,?)",
                (now, sample['cpu'], sample['ram'], sample['disk'], sample['temp']),
            )
        conn.commit()
    return sample


def _legacy_cleanup_history(now=None):
    now = int(time.time()) if now is None else int(now)
    with _db_lock, database_access(DB_PATH) as conn:
        conn.execute("DELETE FROM stats_history WHERE ts < ?", (now - 86400,))
        conn.execute("DELETE FROM service_checks WHERE ts < ?", (now - CHECK_RETENTION_SECONDS,))
        conn.execute("DELETE FROM events WHERE ts < ?", (now - (14 * 86400),))
        conn.execute("DELETE FROM scan_rate_hits WHERE ts < ?", (now - TRIGGER_SCAN_WINDOW_SECONDS,))
        conn.commit()


def _legacy_do_discovery(source='scheduled'):
    scan_started = time.monotonic()
    timings = {}
    discovered = {}
    try:
        now = int(time.time())
        _record_event("scan_start", details=f"source={source}")
        _update_scan_state(
            stage='port_scan', scanning=True, progress=0.0, current_candidates=0,
            current_found=0, timings={}, last_error=None,
        )

        common_ports = {3001, 8080, 8443, 8888, 9090}
        ports_to_scan = sorted(set(range(2000, 10000, 100)) | common_ports | EXTRA_SCAN_PORTS)
        open_ports = []

        phase = time.monotonic()
        for idx, port in enumerate(ports_to_scan):
            if time.monotonic() - scan_started >= DISCOVERY_TIMEOUT_SECONDS:
                raise TimeoutError('discovery deadline exceeded during port scan')
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.15)
                s.close()
                open_ports.append(port)
            except Exception:
                pass
            if idx % 10 == 0:
                _update_scan_state(progress=round(0.35 * (idx + 1) / len(ports_to_scan), 3), current_candidates=len(open_ports))
        timings['port_scan_ms'] = round((time.monotonic() - phase) * 1000, 1)
        _update_scan_state(stage='probing', progress=0.35, current_candidates=len(open_ports), timings=timings)

        existing_probe_urls = {}
        with _db_lock, database_access(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT s.port, COALESCE(m.url, '') AS url, COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port"
            ).fetchall()
        for row in rows:
            existing_probe_urls[int(row['port'])] = (
                _discovery_probe_url(int(row['port']), row['url']), row['healthy_statuses']
            )

        phase = time.monotonic()
        title_ms = 0.0
        for idx, port in enumerate(open_ports):
            if time.monotonic() - scan_started >= DISCOVERY_TIMEOUT_SECONDS:
                raise TimeoutError('discovery deadline exceeded during HTTP probes')
            probe_url, healthy_statuses = existing_probe_urls.get(port, (_default_service_url(port), '200-399'))
            online, latency_ms, error_class, resp = _probe_http(
                probe_url, timeout=2.5, healthy_statuses=healthy_statuses,
            )
            if not online:
                _update_scan_state(progress=round(0.35 + 0.25 * (idx + 1) / max(1, len(open_ports)), 3))
                continue
            title_started = time.monotonic()
            title = _extract_title(resp, port)
            title_ms += (time.monotonic() - title_started) * 1000
            discovered[port] = {
                "title": title,
                "latency_ms": latency_ms,
                "error_class": error_class,
                "url": probe_url,
            }
            _update_scan_state(
                progress=round(0.35 + 0.25 * (idx + 1) / max(1, len(open_ports)), 3),
                current_found=len(discovered),
            )
        timings['probe_ms'] = round((time.monotonic() - phase) * 1000, 1)
        timings['title_extraction_ms'] = round(title_ms, 1)
        _update_scan_state(stage='database', progress=0.62, current_found=len(discovered), timings=timings)

        now = int(time.time())
        refresh_cutoff = now - THUMB_REFRESH_DAYS * 86400
        expire_cutoff = now - EXPIRE_DAYS * 86400
        discovered_ports = set(discovered.keys())

        transitions = []
        existing = {}

        phase = time.monotonic()
        authority = _worker_mutation_authority.get()
        with _mutation_write_transaction(authority, now=now) as conn:
            existing_rows = conn.execute(
                "SELECT s.port, s.title, s.is_online, s.thumb_ts, s.thumb_source, "
                "(s.thumb_data IS NOT NULL AND s.thumb_source='screenshot') AS has_thumb, "
                "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
                "COALESCE(m.critical, 0) AS critical "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port"
            ).fetchall()
            existing = {row['port']: dict(row) for row in existing_rows}

            for port, data in discovered.items():
                if port in existing:
                    state_changed = int(existing[port]['is_online'] or 0) != 1
                    conn.execute(
                        "UPDATE services SET title=?, last_seen=?, is_online=1, last_latency_ms=?, last_error=NULL, "
                        "state_since=CASE WHEN ? THEN ? ELSE state_since END WHERE port=?",
                        (data['title'], now, data['latency_ms'], state_changed, now, port),
                    )
                else:
                    conn.execute(
                        "INSERT INTO services (port, title, first_seen, last_seen, is_online, state_since, last_latency_ms, last_error) "
                        "VALUES (?,?,?,?,1,?,?,NULL)",
                        (port, data['title'], now, now, now, data['latency_ms']),
                    )

                conn.execute(
                    "INSERT OR IGNORE INTO service_meta (port, url, critical, pinned_order, tags, healthy_statuses) VALUES (?,?,?,?,?,?)",
                    (port, data['url'], 0, port, '', '200-399'),
                )

            for port in set(existing.keys()) - discovered_ports:
                conn.execute(
                    "UPDATE services SET is_online=0, last_error=?, last_latency_ms=NULL, "
                    "state_since=CASE WHEN is_online != 0 THEN ? ELSE state_since END WHERE port=?",
                    ("not_responding", now, port),
                )

            all_known = set(existing.keys()) | discovered_ports
            for port in all_known:
                if port in discovered:
                    online = 1
                    latency = discovered[port]['latency_ms']
                    error_class = None
                else:
                    online = 0
                    latency = None
                    error_class = "not_responding"

                conn.execute(
                    "INSERT OR REPLACE INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                    (now, port, online, latency, error_class),
                )

                if port in existing:
                    previous_online = int(existing[port]['is_online'] or 0)
                    if previous_online != online:
                        transitions.append({
                            "port": port,
                            "previous_online": previous_online,
                            "online": online,
                            "latency_ms": latency,
                            "error_class": error_class,
                            "title": discovered.get(port, {}).get('title') or existing[port].get('title') or f":{port}",
                            "display_name": existing[port].get('display_name') or '',
                            "url": existing[port].get('url') or _default_service_url(port),
                            "critical": int(existing[port].get('critical') or 0),
                        })

            conn.execute("DELETE FROM services WHERE last_seen < ?", (expire_cutoff,))
            conn.execute("DELETE FROM service_meta WHERE port NOT IN (SELECT port FROM services)")
        timings['database_ms'] = round((time.monotonic() - phase) * 1000, 1)

        _update_scan_state(stage='previews', progress=0.68, timings=timings)
        phase = time.monotonic()
        for idx, port in enumerate(discovered_ports):
            if time.monotonic() - scan_started >= DISCOVERY_TIMEOUT_SECONDS:
                log.warning('Discovery preview deadline reached; preserving %d services', len(discovered_ports))
                break
            ex = existing.get(port, {})
            thumb_ts = ex.get('thumb_ts') or 0
            thumb_source = ex.get('thumb_source')
            if ex.get('has_thumb') and thumb_ts >= refresh_cutoff and thumb_source == 'screenshot':
                continue
            with _mutation_write_transaction(authority, now=now) as conn:
                if authority is None:
                    beacon_queues.enqueue_preview_in_transaction(conn, port, now=now)
                else:
                    beacon_queues.enqueue_preview_for_worker_in_transaction(
                        conn, authority, port, now=now,
                    )
            _update_scan_state(progress=round(0.68 + 0.30 * (idx + 1) / max(1, len(discovered_ports)), 3))
        timings['previews_ms'] = round((time.monotonic() - phase) * 1000, 1)

        for t in transitions:
            _handle_state_transition(**t)

        found_count = len(discovered_ports)
        timings['total_ms'] = round((time.monotonic() - scan_started) * 1000, 1)
        _update_scan_state(
            stage='idle', scanning=False, progress=1.0, current_candidates=len(open_ports),
            current_found=0, last_completed_found=found_count, last_discovery=now,
            last_uptime_check=now, last_down_check=now, timings=timings, last_error=None,
        )
        _record_event("scan_complete", details=f"source={source}; found={found_count}")
        log.info("Discovery complete: %d HTTP services found", found_count)
        return True
    except beacon_queues.LeaseLost:
        raise
    except Exception as exc:
        log.exception("Discovery failed unexpectedly: %s", exc)
        timings['total_ms'] = round((time.monotonic() - scan_started) * 1000, 1)
        _update_scan_state(
            stage='failed', scanning=False, current_found=len(discovered),
            timings=timings, last_error=f'{exc.__class__.__name__}: {exc}'[:240],
        )
        _record_event("scan_failed", details=str(exc)[:200])
        return False


def _legacy_run_discovery(source='scheduled'):
    """Run one discovery owner at a time across every scheduler entry point."""
    if not _scan_lock.acquire(blocking=False):
        return 'busy'
    try:
        return 'completed' if do_discovery(source=source) else 'failed'
    finally:
        _scan_lock.release()


def _legacy_do_uptime_check(only_down=False):
    if not _uptime_lock.acquire(blocking=False):
        # Another run already owns this work -- yielding here is not a job failure,
        # so this still records succeeded, never a fabricated job_failed.  That is
        # NOT the same claim as "the two runs are equivalent": J3 (only_down=False,
        # every 5 min) and J4 (only_down=True, every 1 min) share this lock and
        # collide by construction every fifth J4 tick, because 300 is a multiple of
        # 60.  A down-only holder does not perform a full sweep -- it never advances
        # last_uptime_check.  When J3 is the loser, that cycle's full-service
        # coverage is skipped, not covered; the telemetry-coverage surface is what
        # must disclose a real gap, never this return value.
        return None
    now = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400
    transitions = []
    overruns = []
    authority = _worker_mutation_authority.get()
    snapshot = beacon_telemetry.measure_storage(authority.db_path) if authority is not None else None
    try:
        with _db_lock, database_access(DB_PATH) as conn:
            where = "WHERE s.last_seen >= ? AND s.is_online = 0" if only_down else "WHERE s.last_seen >= ?"
            rows = conn.execute(
                "SELECT s.port, s.title, s.is_online, s.state_since, "
                "(s.thumb_data IS NOT NULL AND s.thumb_source='screenshot') AS has_thumb, "
                "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
                "COALESCE(m.critical, 0) AS critical, COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port " + where,
                (expire_cutoff,),
            ).fetchall()

        # Network I/O is deliberately outside the SQLite lock so the metrics
        # executor can keep its five-second cadence during slow probes.
        for row in rows:
            port = int(row['port'])
            previous_online = int(row['is_online'] or 0)
            try:
                service_url = _normalize_service_url(row['url'], port)
                service_plan = _outbound_policy().plan(service_url, OutboundPurpose.SERVICE_PROBE)
                online, latency_ms, error_class, resp = _probe_http(
                    service_url, timeout=2.0, healthy_statuses=row['healthy_statuses'],
                )
            except ValueError:
                service_url = _default_service_url(port)
                service_plan = None
                online = False
                latency_ms = None
                error_class = 'invalid_url'
                resp = None
            online_int = 1 if online else 0
            title_update = _extract_title(resp, port) if online and resp is not None else ''

            overrun_alert_kwargs = None
            with _mutation_write_transaction(authority, now=now) as conn:
                decision = None
                if authority is not None:
                    decision = _telemetry_persistence_decision(conn, now=now, snapshot=snapshot)
                if online and title_update and title_update != f":{port}":
                    conn.execute(
                        "UPDATE services SET title=?, is_online=1, last_seen=?, last_latency_ms=?, last_error=NULL, "
                        "state_since=CASE WHEN is_online != 1 THEN ? ELSE state_since END, "
                        "overrun_raised_ts=CASE WHEN is_online != 1 THEN NULL ELSE overrun_raised_ts END "
                        "WHERE port=?",
                        (title_update, now, latency_ms, now, port),
                    )
                elif online:
                    conn.execute(
                        "UPDATE services SET is_online=1, last_seen=?, last_latency_ms=?, last_error=NULL, "
                        "state_since=CASE WHEN is_online != 1 THEN ? ELSE state_since END, "
                        "overrun_raised_ts=CASE WHEN is_online != 1 THEN NULL ELSE overrun_raised_ts END "
                        "WHERE port=?",
                        (now, latency_ms, now, port),
                    )
                else:
                    conn.execute(
                        "UPDATE services SET is_online=0, last_latency_ms=NULL, last_error=?, "
                        "state_since=CASE WHEN is_online != 0 THEN ? ELSE state_since END, "
                        "overrun_raised_ts=CASE WHEN is_online != 0 THEN NULL ELSE overrun_raised_ts END "
                        "WHERE port=?",
                        (error_class or 'probe_failed', now, port),
                    )
                if previous_online == 0 and online_int == 0:
                    # Still down, no transition this poll (RESEARCH Pitfall 8) --
                    # the only case the transition funnel cannot see.
                    opening = beacon_repositories.get_open_down_transition(conn, port)
                    if (
                        opening
                        and opening.get('suppressed_reason') == beacon_maintenance.MAINTENANCE_REASON
                        and opening.get('maintenance_grace_until') is not None
                        and now >= opening['maintenance_grace_until']
                        and not beacon_repositories.overrun_already_raised(conn, port)
                    ):
                        down_since_ts = row['state_since']
                        _insert_event(
                            conn,
                            ts=now,
                            event_type=MAINTENANCE_OVERRUN_EVENT_TYPE,
                            port=port,
                            online=0,
                            previous_online=0,
                            down_since_ts=down_since_ts,
                            details=_overrun_detail(down_since_ts, now),
                        )
                        beacon_repositories.mark_overrun_raised(conn, port, now)
                        overrun_alert_kwargs = {
                            "port": port,
                            "previous_online": 0,
                            "online": 0,
                            "title": row['title'] or f":{port}",
                            "display_name": row['display_name'] or '',
                            "url": service_url,
                            "critical": int(row['critical'] or 0),
                            "latency_ms": latency_ms,
                            "error_class": error_class,
                        }
                if decision is None or decision.historical_persistence_allowed:
                    conn.execute(
                        "INSERT OR REPLACE INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                        (now, port, online_int, latency_ms, error_class),
                    )
                    if authority is not None:
                        state = beacon_telemetry.close_storage_pressure_gap(
                            conn, 'service', str(port), now=now,
                        )
                        beacon_telemetry.record_observation(
                            conn, 'service', str(port), ts=now, cadence_seconds=300,
                            state=(True if online is True else False if online is False else None),
                            expected_cadence=not only_down,
                        )
                        state['state'] = decision.state
                        beacon_telemetry.write_retention_state(conn, state, now=now)
                elif authority is not None:
                    state = beacon_telemetry.open_storage_pressure_gap(
                        conn, 'service', str(port), now=now,
                    )
                    state['state'] = decision.state
                    beacon_telemetry.write_retention_state(conn, state, now=now)
                beacon_repositories.set_service_tls_posture(
                    conn, port, bool(service_plan and service_plan.tls.tls_unverified), now,
                )
                if online and not row['has_thumb']:
                    if authority is None:
                        beacon_queues.enqueue_preview_in_transaction(conn, port, now=now)
                    else:
                        beacon_queues.enqueue_preview_for_worker_in_transaction(
                            conn, authority, port, now=now,
                        )

            if previous_online != online_int:
                transitions.append({
                    "port": port,
                    "previous_online": previous_online,
                    "online": online_int,
                    "latency_ms": latency_ms,
                    "error_class": error_class,
                    "title": row['title'] or f":{port}",
                    "display_name": row['display_name'] or '',
                    "url": service_url,
                    "critical": int(row['critical'] or 0),
                })

            if overrun_alert_kwargs is not None:
                overruns.append(overrun_alert_kwargs)

        for transition in transitions:
            _handle_state_transition(**transition)

        for overrun in overruns:
            # The webhook effect stays outside any open write transaction,
            # exactly as the existing transition alerts already are (T-03.1-17).
            _dispatch_overrun_alert(now=now, **overrun)

        state_changes = {'last_down_check': now}
        if not only_down:
            state_changes['last_uptime_check'] = now
        _update_scan_state(**state_changes)
        log.info(
            "Uptime check complete (%s): %d services checked",
            'down-only' if only_down else 'all', len(rows),
        )
        return True
    finally:
        _uptime_lock.release()


def _monitoring_operations():
    """Bind compatibility globals at the edge; monitoring itself owns no Flask state."""
    return beacon_monitoring.MonitoringOperations(
        probe_http=_legacy_probe_http,
        insert_event=_legacy_insert_event,
        record_event=_legacy_record_event,
        should_send_alert=_legacy_should_send_alert,
        send_transition_alert=_legacy_send_transition_alert,
        handle_state_transition=_legacy_handle_state_transition,
        uptime_summary=_legacy_uptime_summary,
        build_uptime_buckets=_legacy_build_uptime_buckets,
        calc_uptime_pct=_legacy_calc_uptime_pct,
        collect_system_stats=_legacy_collect_system_stats,
        cleanup_history=_legacy_cleanup_history,
        do_discovery=_legacy_do_discovery,
        run_discovery=_legacy_run_discovery,
        do_uptime_check=_legacy_do_uptime_check,
    )


def _preview_operations():
    """Bind legacy browser storage details without importing them in worker modules."""
    return beacon_previews.PreviewOperations(
        fetch_html_response=_legacy_fetch_html_response,
        extract_title=_legacy_extract_title,
        get_browser=_legacy_get_browser,
        shutdown_browser=_legacy_shutdown_browser,
        screenshot_service=_legacy_screenshot_service,
        fetch_thumbnail=_legacy_fetch_thumbnail,
        thumbnail_repository=beacon_repositories.ThumbnailRepository(),
        refresh_service_preview=_legacy_refresh_service_preview,
    )


def _probe_http(url, timeout=2.5, allow_remote=False, healthy_statuses='200-399'):
    return beacon_monitoring.probe_http(
        _monitoring_operations(), url, timeout, allow_remote, healthy_statuses,
    )


def _fetch_html_response(url, timeout=3, allow_remote=False):
    return beacon_previews.fetch_html_response(_preview_operations(), url, timeout, allow_remote)


def _extract_title(response, port):
    return beacon_previews.extract_title(_preview_operations(), response, port)


def _get_browser():
    return beacon_previews.get_browser(_preview_operations())


def shutdown_browser():
    return beacon_previews.shutdown_browser(_preview_operations())


def _insert_event(conn, **kwargs):
    return beacon_monitoring.insert_event(_monitoring_operations(), conn, **kwargs)


def _record_event(*args, **kwargs):
    return beacon_monitoring.record_event(_monitoring_operations(), *args, **kwargs)


def _should_send_alert(port, online, now):
    return beacon_monitoring.should_send_alert(_monitoring_operations(), port, online, now)


def _send_transition_alert(**kwargs):
    return beacon_monitoring.send_transition_alert(_monitoring_operations(), **kwargs)


def _handle_state_transition(**kwargs):
    authority = _worker_effect_authority.get()
    if authority is not None:
        return worker_handle_state_transition(authority, **kwargs)
    return beacon_monitoring.handle_state_transition(_monitoring_operations(), **kwargs)


def _dispatch_overrun_alert(**kwargs):
    """Send the overrun's alert through the same sender a transition uses.

    No event is inserted here -- the ``maintenance_overrun`` row was already
    written inside the write transaction that raised it; this call performs
    only the webhook effect, gated by the existing cooldown/critical-only
    filters rather than a parallel mechanism (MNT-04).
    """
    authority = _worker_effect_authority.get()
    if authority is not None:
        return worker_send_transition_alert(authority, **kwargs)
    return _send_transition_alert(**kwargs)


def _screenshot_service(port, target_url=None):
    return beacon_previews.screenshot_service(_preview_operations(), port, target_url)


def fetch_thumbnail(port, service_url=None):
    return beacon_previews.fetch_thumbnail(_preview_operations(), port, service_url)


def _store_thumbnail_result(conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts=None):
    return beacon_previews.store_thumbnail_result(
        _preview_operations(), conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts,
    )


def _refresh_service_preview(port, service_url):
    return beacon_previews.refresh_service_preview(_preview_operations(), port, service_url)


def _uptime_summary(checks, now):
    return beacon_monitoring.uptime_summary(_monitoring_operations(), checks, now)


def _build_uptime_buckets(checks, now):
    return beacon_monitoring.build_uptime_buckets(_monitoring_operations(), checks, now)


def _calc_uptime_pct(checks, now=None):
    return beacon_monitoring.calc_uptime_pct(_monitoring_operations(), checks, now)


def collect_system_stats(now=None, persist_history=None):
    return beacon_monitoring.collect_system_stats(_monitoring_operations(), now, persist_history)


def cleanup_history(now=None):
    return beacon_monitoring.cleanup_history(_monitoring_operations(), now)


def do_discovery(source='scheduled'):
    return beacon_monitoring.do_discovery(_monitoring_operations(), source)


def run_discovery(source='scheduled'):
    return beacon_monitoring.run_discovery(_monitoring_operations(), source)


def do_uptime_check(only_down=False):
    return beacon_monitoring.do_uptime_check(_monitoring_operations(), only_down)


def _assert_worker_callback_authority(authority):
    """Fence callbacks which delegate multiple bounded legacy transactions.

    The concrete queue/publication transactions use ``_worker_write_transaction``
    or queue worker variants.  This early check keeps expensive probe/browser
    work from starting after a successor has taken the durable epoch.
    """
    with _worker_write_transaction(authority):
        pass


def _worker_record_event(authority, event_type, **kwargs):
    """Persist an effect outcome only while the exact worker epoch is current."""
    with _worker_write_transaction(authority) as conn:
        _insert_event(conn, ts=authority.now(), event_type=event_type, **kwargs)


def _worker_alert_is_due(authority, port, online, now):
    with _worker_write_transaction(authority) as conn:
        row = conn.execute(
            "SELECT ts FROM events WHERE port=? AND event_type='alert_sent' AND online=? "
            "ORDER BY ts DESC LIMIT 1",
            (port, online),
        ).fetchone()
    return not row or now - int(row['ts']) >= ALERT_COOLDOWN_SECONDS


def worker_send_transition_alert(authority, *, now, port, previous_online, online, title,
                                 display_name, url, critical, latency_ms, error_class):
    """Make the single bounded webhook effect while its epoch remains reserved."""
    if not ALERT_WEBHOOK_URL or (ALERT_ONLY_CRITICAL and not critical):
        return False
    if not _worker_alert_is_due(authority, port, online, now):
        return False
    payload = {
        'timestamp': now, 'port': port, 'service': display_name or title or f':{port}',
        'title': title, 'url': url, 'critical': bool(critical),
        'previous_online': bool(previous_online), 'online': bool(online),
        'latency_ms': latency_ms, 'error_class': error_class,
        'event': 'service_recovered' if online else 'service_down',
    }
    plan = _outbound_transport().policy.plan(ALERT_WEBHOOK_URL, OutboundPurpose.WEBHOOK)
    # Reserve enough durable lease for the immutable strict transport budget.
    beacon_queues.renew_worker_authority(
        authority, now=now, lease_seconds=int(plan.connect_timeout + plan.read_timeout) + 2,
    )
    key_material = f'{now}:{port}:{int(bool(previous_online))}:{int(bool(online))}'.encode('ascii')
    headers = {'Idempotency-Key': hashlib.sha256(key_material).hexdigest()}
    try:
        response = _outbound_transport().request_plan(
            plan, method='POST', json=payload, headers=headers,
        )
        status = f'http_{response.status_code}'
        event_type = 'alert_sent' if 200 <= response.status_code < 300 else 'alert_failed'
        details = 'webhook delivered' if event_type == 'alert_sent' else 'webhook delivery rejected'
    except OutboundPolicyError as exc:
        event_type, status, details = 'alert_failed', 'policy_' + exc.reason, 'webhook policy rejected'
    except Exception:
        event_type, status, details = 'alert_failed', 'delivery_error', 'webhook delivery failed'
    try:
        _worker_record_event(
            authority, event_type, port=port, online=online, previous_online=previous_online,
            latency_ms=latency_ms, error_class=error_class, alert_status=status, details=details,
        )
    except beacon_queues.LeaseLost:
        raise
    return event_type == 'alert_sent'


def worker_handle_state_transition(authority, **kwargs):
    """Fence transition persistence and its optional external delivery separately.

    The maintenance window read, the suppression decision, and the tagged
    ``state_change`` INSERT all happen inside ONE opened
    ``_worker_write_transaction`` block. ``_worker_record_event`` is not used
    on this path because it opens its own transaction -- nesting it here
    would re-enter ``BEGIN IMMEDIATE`` on a second connection (Pitfall 6).
    """
    now = int(authority.now())
    with _worker_write_transaction(authority) as conn:
        suppressed_reason, grace_until = _maintenance_suppression_decision(
            conn, kwargs['port'], online=kwargs['online'], now=now,
        )
        _insert_event(
            conn,
            ts=now,
            event_type='state_change',
            port=kwargs['port'],
            online=kwargs['online'],
            previous_online=kwargs['previous_online'],
            latency_ms=kwargs['latency_ms'],
            error_class=kwargs['error_class'],
            details='service recovered' if kwargs['online'] else 'service went down',
            suppressed_reason=suppressed_reason,
            maintenance_grace_until=grace_until,
        )
    if suppressed_reason is not None:
        # Written and tagged, never withheld (D-10) -- but no alert is
        # attempted at all, so nothing is recorded as sent or failed for it.
        return False
    return worker_send_transition_alert(authority, now=now, **kwargs)


def _telemetry_policy():
    """Compose retention policy once from the validated process settings."""
    return beacon_telemetry.RetentionPolicy.from_settings(SETTINGS)


def _telemetry_persistence_decision(conn, *, now, snapshot):
    """Persist the storage transition after worker authority has been asserted."""
    previous = beacon_telemetry.read_retention_state(conn)
    decision = beacon_telemetry.evaluate_storage_pressure(
        previous['state'], snapshot, _telemetry_policy(),
    )
    state = dict(previous)
    state.update({
        'state': decision.state,
        'reason': decision.reason,
        'snapshot': {
            'database_bytes': snapshot.database_bytes,
            'wal_bytes': snapshot.wal_bytes,
            'shm_bytes': snapshot.shm_bytes,
            'free_bytes': snapshot.free_bytes,
        },
    })
    beacon_telemetry.write_retention_state(conn, state, now=now)
    return decision


def worker_collect_system_stats(authority, now=None, persist_history=None):
    """Collect outside SQLite, then publish under the current worker epoch."""
    now = authority.now() if now is None else int(now)
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    ram_available = int(ram.available)
    ram_total = int(ram.total)
    ram_used = max(0, ram_total - ram_available)
    sample = {
        'sample_ts': now, 'cpu': round(float(cpu), 1),
        'ram': round((ram_used / ram_total * 100) if ram_total else 0.0, 1),
        'ram_used': ram_used, 'ram_available': ram_available,
        'ram_used_strict': int(ram.used), 'ram_total': ram_total,
        'disk': round(float(disk.percent), 1), 'disk_used': int(disk.used),
        'disk_total': int(disk.total), 'temp': get_temp(), 'hostname': socket.gethostname(),
    }
    snapshot = beacon_telemetry.measure_storage(authority.db_path)
    with _worker_write_transaction(authority) as conn:
        decision = _telemetry_persistence_decision(conn, now=now, snapshot=snapshot)
        conn.execute(
            "INSERT INTO system_stats(id,sample_ts,cpu,ram,ram_used,ram_available,ram_used_strict,ram_total,disk,disk_used,disk_total,temp,hostname) "
            "VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "sample_ts=excluded.sample_ts,cpu=excluded.cpu,ram=excluded.ram,ram_used=excluded.ram_used,"
            "ram_available=excluded.ram_available,ram_used_strict=excluded.ram_used_strict,ram_total=excluded.ram_total,"
            "disk=excluded.disk,disk_used=excluded.disk_used,disk_total=excluded.disk_total,temp=excluded.temp,hostname=excluded.hostname",
            (sample['sample_ts'], sample['cpu'], sample['ram'], sample['ram_used'], sample['ram_available'],
             sample['ram_used_strict'], sample['ram_total'], sample['disk'], sample['disk_used'], sample['disk_total'],
             sample['temp'], sample['hostname']),
        )
        if persist_history is None:
            last = conn.execute('SELECT MAX(ts) AS ts FROM stats_history').fetchone()['ts']
            persist_history = last is None or now - int(last) >= METRIC_HISTORY_SECONDS
        if decision.historical_persistence_allowed and persist_history:
            conn.execute('INSERT OR REPLACE INTO stats_history(ts,cpu,ram,disk,temp) VALUES(?,?,?,?,?)',
                         (now, sample['cpu'], sample['ram'], sample['disk'], sample['temp']))
            state = beacon_telemetry.read_retention_state(conn)
            for metric in beacon_telemetry.HOST_METRICS:
                stream_key = beacon_telemetry.host_stream_key(metric)
                had_pressure_gap = f'host:{stream_key}' in state['pressure_gaps']
                state = beacon_telemetry.close_storage_pressure_gap(
                    conn, 'host', stream_key, now=now, state=state,
                )
                beacon_telemetry.record_observation(
                    conn, 'host', stream_key, ts=now,
                    cadence_seconds=METRIC_HISTORY_SECONDS,
                    state=True if sample[metric] is not None else None,
                    known_gap=had_pressure_gap,
                )
            beacon_telemetry.write_retention_state(conn, state, now=now)
        elif not decision.historical_persistence_allowed:
            state = beacon_telemetry.read_retention_state(conn)
            for metric in beacon_telemetry.HOST_METRICS:
                stream_key = beacon_telemetry.host_stream_key(metric)
                state = beacon_telemetry.open_storage_pressure_gap(
                    conn, 'host', stream_key, now=now, state=state,
                )
            state['state'] = decision.state
            beacon_telemetry.write_retention_state(conn, state, now=now)
    return sample


def worker_cleanup_history(authority, now=None):
    now = authority.now() if now is None else int(now)
    snapshot = beacon_telemetry.measure_storage(authority.db_path)
    with _worker_write_transaction(authority, now=now) as conn:
        _telemetry_persistence_decision(conn, now=now, snapshot=snapshot)
        beacon_telemetry.run_retention_batch(conn, now=now, policy=_telemetry_policy())
        beacon_telemetry.detect_collection_gaps(conn, now=now)
        conn.execute('DELETE FROM scan_rate_hits WHERE ts < ?', (now - TRIGGER_SCAN_WINDOW_SECONDS,))
    return True


def worker_run_discovery(authority, source='scheduled'):
    effect_token = _worker_effect_authority.set(authority)
    mutation_token = _worker_mutation_authority.set(authority)
    try:
        return run_discovery(source=source)
    finally:
        _worker_mutation_authority.reset(mutation_token)
        _worker_effect_authority.reset(effect_token)


def worker_do_uptime_check(authority, only_down=False):
    effect_token = _worker_effect_authority.set(authority)
    mutation_token = _worker_mutation_authority.set(authority)
    try:
        return do_uptime_check(only_down=only_down)
    finally:
        _worker_mutation_authority.reset(mutation_token)
        _worker_effect_authority.reset(effect_token)


def queue_discovery_request(client_key):
    request = beacon_queues.enqueue_scan(DB_PATH, client_key)
    _update_scan_state(stage='queued', scanning=False, progress=0.0, current_found=0, last_error=None)
    return request.request_id


def worker_process_scan_requests(authority, *, now_fn=None, lease_seconds=30, heartbeat_factory=None):
    """Run a claimed manual scan without reconstructing worker credentials."""
    now_fn = now_fn or authority.now
    try:
        claim = beacon_queues.claim_scan_for_worker(
            authority, now=int(now_fn()), lease_seconds=lease_seconds,
        )
    except beacon_queues.LeaseLost:
        raise
    if not claim:
        # An empty durable queue is a completed poll, not a failure. Returning
        # anything other than a literal False here means dispatch_callback records
        # this outcome as succeeded, not a fabricated job_failed -- see
        # dispatch_callback's `if result is False:` branch, which is otherwise
        # unchanged. The busy branch below records this same non-fault outcome
        # (deferred-items.md row 9), except when the lease is confirmed lost --
        # see WR-04 in 03-19-REVIEW.md.
        return None
    heartbeat_factory = heartbeat_factory or beacon_queues.WorkerScanLeaseHeartbeat
    heartbeat = heartbeat_factory(
        authority, claim.request_id, claim.lease_owner,
        lease_seconds=lease_seconds, now=now_fn,
    )
    heartbeat.start()
    try:
        outcome = worker_run_discovery(authority, source=f'manual:{claim.request_id}')
        # The same membership check J7/J9 already use; its boolean return is
        # discarded here because the busy-vs-completed branch below still needs
        # the literal itself, not a collapsed boolean -- this call exists only
        # to raise ValueError on an outcome outside the documented contract,
        # letting this function's own existing except Exception handler
        # durably record the failure exactly as it already does for
        # run_discovery raising directly.
        beacon_worker_main._discovery_outcome_verdict(outcome)
        if outcome == 'busy':
            if heartbeat.lost:
                # A lost lease is a lost lease on this path too: do not requeue a
                # claim we no longer own, and do not report the poll as clean.
                raise beacon_queues.LeaseLost('worker scan lease was lost')
            beacon_queues.requeue_scan_for_worker(
                authority, claim.request_id, claim.lease_owner, now=int(now_fn()),
            )
            # Another run already owns this work -- a busy discovery lock is not a
            # job failure. The claim was just returned to queued above; the next
            # scheduled poll picks it up. Returning anything other than a literal
            # False means dispatch_callback records this as succeeded, not a
            # fabricated job_failed.
            return None
        state = _read_scan_state()
        status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'
        error = state.get('last_error') if status == 'failed' else None
    except beacon_queues.LeaseLost:
        raise
    except Exception as exc:
        status, error = 'failed', str(exc)[:240]
    finally:
        heartbeat.stop()
    if heartbeat.lost:
        raise beacon_queues.LeaseLost('worker scan lease was lost')
    try:
        if status == 'completed':
            beacon_queues.finish_scan_for_worker(
                authority, claim.request_id, claim.lease_owner, now=int(now_fn()),
            )
        else:
            beacon_queues.fail_scan_for_worker(
                authority, claim.request_id, claim.lease_owner, error or 'scan failed', now=int(now_fn()),
            )
    except beacon_queues.LeaseLost:
        raise
    # Return the verdict this function itself just computed and durably recorded
    # -- not a constant. status is already 'failed' here on every path that
    # reached fail_scan_for_worker above: the outcome=='failed' branch, a queued
    # discovery whose state carries last_error, and the caught exception above.
    # Returning anything else discards a fault dispatch_callback would otherwise
    # report faithfully.
    return status == 'completed'


def process_scan_requests(worker_id, worker_owner_token, *, now_fn=None, lease_seconds=30, heartbeat_factory=None):
    now_fn = now_fn or time.time
    try:
        claim = beacon_queues.claim_scan(
            DB_PATH, worker_id, worker_owner_token=worker_owner_token,
            now=int(now_fn()), lease_seconds=lease_seconds,
        )
    except beacon_queues.LeaseLost:
        return False
    if not claim:
        return False
    request_id = claim.request_id
    owner_token = claim.lease_owner
    heartbeat_factory = heartbeat_factory or beacon_queues.ScanLeaseHeartbeat
    heartbeat = heartbeat_factory(
        DB_PATH, request_id, owner_token, worker_id, worker_owner_token,
        lease_seconds=lease_seconds, now=now_fn,
    )
    heartbeat.start()

    try:
        outcome = run_discovery(source=f'manual:{request_id}')
        # The same membership check J7/J9 already use; its boolean return is
        # discarded here because the busy-vs-completed branch below still needs
        # the literal itself, not a collapsed boolean -- this call exists only
        # to raise ValueError on an outcome outside the documented contract,
        # letting this function's own existing except Exception handler
        # durably record the failure exactly as it already does for
        # run_discovery raising directly.
        beacon_worker_main._discovery_outcome_verdict(outcome)
        if outcome == 'busy':
            if heartbeat.lost:
                log.warning('scan lease lost before requeue for request %s', request_id)
                return False
            beacon_queues.requeue_scan(
                DB_PATH, request_id, owner_token, worker_id=worker_id,
                worker_owner_token=worker_owner_token, now=int(now_fn()),
            )
            return False
        state = _read_scan_state()
        status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'
        error = state.get('last_error') if status == 'failed' else None
    except Exception as exc:
        status, error = 'failed', str(exc)[:240]
    finally:
        heartbeat.stop()

    if heartbeat.lost:
        log.warning('scan lease lost before terminal transition for request %s', request_id)
        return False

    try:
        if status == 'completed':
            beacon_queues.finish_scan(
                DB_PATH, request_id, owner_token, worker_id=worker_id,
                worker_owner_token=worker_owner_token, now=int(now_fn()),
            )
        else:
            beacon_queues.fail_scan(
                DB_PATH, request_id, owner_token, error or 'scan failed', worker_id=worker_id,
                worker_owner_token=worker_owner_token, now=int(now_fn()),
            )
    except beacon_queues.LeaseLost:
        return False
    return True


def process_preview_requests(worker_id, worker_owner_token):
    try:
        claim = beacon_queues.claim_preview(
            DB_PATH, worker_id, worker_owner_token=worker_owner_token,
        )
    except beacon_queues.LeaseLost:
        return False
    if not claim:
        return False
    port = claim.port
    with _db_lock, database_access(DB_PATH) as conn:
        row = conn.execute(
            "SELECT COALESCE(url, '') AS url FROM service_meta WHERE port=?", (port,)
        ).fetchone()
    url = _safe_service_url(row['url'] if row else '', port)
    started = time.monotonic()
    title, data, mime, source, thumb_error, warning = _refresh_service_preview(port, url)
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    with _db_lock, database_access(DB_PATH) as conn:
        try:
            conn.execute('BEGIN IMMEDIATE')
            beacon_queues.finish_preview_in_transaction(
                conn, claim.request_id, worker_id, worker_owner_token=worker_owner_token,
                revision=claim.revision,
                status='failed' if warning else 'completed', error=warning,
            )
            if title:
                conn.execute("UPDATE services SET title=? WHERE port=?", (title, port))
            if data or thumb_error:
                _store_thumbnail_result(conn, port, data, mime, source, thumb_error)
            _insert_event(
                conn, ts=int(time.time()), event_type='preview_complete', port=port,
                error_class=thumb_error,
                details=json.dumps(
                    {'total_ms': elapsed_ms, 'success': not bool(warning)},
                    separators=(',', ':'),
                ),
            )
            conn.commit()
        except beacon_queues.LeaseLost:
            conn.rollback()
            return False
    return True


def worker_process_preview_requests(authority):
    """Publish preview results only in an authority-asserted transaction."""
    try:
        claim = beacon_queues.claim_preview_for_worker(authority)
    except beacon_queues.LeaseLost:
        raise
    if not claim:
        # An empty durable queue is a completed poll, not a failure -- see
        # worker_process_scan_requests for the full reasoning.
        return None
    with database_access(authority.db_path) as conn:
        row = conn.execute(
            "SELECT COALESCE(url, '') AS url FROM service_meta WHERE port=?", (claim.port,)
        ).fetchone()
    url = _safe_service_url(row['url'] if row else '', claim.port)
    started = time.monotonic()
    title, data, mime, source, thumb_error, warning = _refresh_service_preview(claim.port, url)
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    try:
        with _worker_write_transaction(authority) as conn:
            # Browser output is only an in-memory candidate until this same
            # authority-plus-row/revision transaction succeeds.
            _insert_event(
                conn, ts=authority.now(), event_type='preview_capture', port=claim.port,
                error_class=thumb_error,
                details=json.dumps(
                    {'total_ms': elapsed_ms, 'success': bool(data)},
                    separators=(',', ':'), sort_keys=True,
                ),
            )
            beacon_queues.finish_preview_for_worker_in_transaction(
                conn, authority, claim.request_id, revision=claim.revision,
                status='failed' if warning else 'completed', error=warning,
            )
            if title:
                conn.execute("UPDATE services SET title=? WHERE port=?", (title, claim.port))
            if data or thumb_error:
                _store_thumbnail_result(conn, claim.port, data, mime, source, thumb_error)
            _insert_event(
                conn, ts=authority.now(), event_type='preview_complete', port=claim.port,
                error_class=thumb_error,
                details=json.dumps({'total_ms': elapsed_ms, 'success': not bool(warning)}, separators=(',', ':')),
            )
    except beacon_queues.LeaseLost:
        raise
    # The per-request row above is already durable and complete
    # (preview_requests reads its own real status='failed' text, and the
    # preview_capture event carries error_class=THUMB_ERROR_BROWSER_UNAVAILABLE)
    # -- but a browser that could not even launch is a fault of the machinery
    # this job owns, not of the previewed service, and warning cannot carry
    # that distinction; dispatch_callback records this as a genuine job_failed
    # for J6, exactly as it already does for J5/J7/J9's own genuine failures.
    if thumb_error == THUMB_ERROR_BROWSER_UNAVAILABLE:
        raise beacon_previews.PreviewCaptureUnavailable(THUMB_ERROR_BROWSER_UNAVAILABLE)
    # J6's job outcome answers one question only: did the poller claim a
    # request, attempt a capture, and durably record its own verdict inside an
    # authority-asserted transaction? Reaching this line means yes, regardless
    # of what the capture found. warning is already durable on
    # preview_requests.status and on the preview_complete event above -- it
    # describes the monitored service's own health, not the poller's, and must
    # never again decide this return value (03-19-REVIEW.md CR-01). A genuine
    # J6 job fault is now handled by the check just above, by LeaseLost, or by
    # any other uncaught exception dispatch_callback converts to a real failed
    # row.
    return True


def _check_scan_rate_limit(client_key):
    now = int(time.time())
    with _db_lock, database_access(DB_PATH) as conn:
        cutoff = now - TRIGGER_SCAN_WINDOW_SECONDS
        conn.execute("DELETE FROM scan_rate_hits WHERE ts < ?", (cutoff,))
        rows = conn.execute(
            "SELECT ts FROM scan_rate_hits WHERE client_key=? ORDER BY ts ASC",
            (client_key,),
        ).fetchall()
        if len(rows) >= TRIGGER_SCAN_RATE_LIMIT:
            retry_after = TRIGGER_SCAN_WINDOW_SECONDS - (now - int(rows[0]['ts']))
            conn.commit()
            return False, max(1, retry_after)
        conn.execute("INSERT INTO scan_rate_hits(client_key, ts) VALUES(?,?)", (client_key, now))
        conn.commit()
        return True, 0


def _service_meta_row(conn, port):
    return beacon_web.metadata_response(
        conn,
        port,
        safe_url=_safe_service_url,
        path_from_url=_service_path_from_url,
        parse_tags=_parse_tags,
        now_epoch=int(time.time()),
        tz_name=SETTINGS.timezone,
        start_tolerance_seconds=SETTINGS.maintenance_start_tolerance_seconds,
        duration_tolerance_seconds=SETTINGS.maintenance_duration_tolerance_seconds,
        lookback_days=SETTINGS.maintenance_suggestion_lookback_days,
    )


def _ensure_runtime_started():
    global _bg_started
    with _startup_lock:
        if _bg_started:
            return

        os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
        init_db()
        _bg_started = True


def _request_host():
    host = (request.host or '').strip().lower()
    if host.startswith('['):
        return host.split(']', 1)[0].lstrip('[')
    return host.rsplit(':', 1)[0]


def _origin_is_same_host():
    origin = request.headers.get('Origin')
    if not origin:
        return True
    try:
        parsed = urlparse(origin)
        request_parsed = urlparse(f'//{request.host}', scheme=request.scheme)
        origin_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        request_port = request_parsed.port or (443 if request.scheme == 'https' else 80)
        return bool(
            parsed.scheme == request.scheme
            and parsed.hostname
            and parsed.hostname.lower().rstrip('.') == _request_host().rstrip('.')
            and origin_port == request_port
        )
    except Exception:
        return False


@app.before_request
def enforce_request_security():
    if not _is_trusted_request_host(_request_host()):
        return jsonify({'error': 'untrusted host'}), 400
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        if request.headers.get('X-Beacon-UI') != '1':
            return jsonify({'error': 'missing Beacon UI header'}), 403
        if not _origin_is_same_host():
            return jsonify({'error': 'unexpected origin'}), 403


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    return response


@app.route("/")
def index():
    return send_file("index.html", mimetype="text/html")


@app.route('/advanced')
def advanced_index():
    return send_file('advanced.html', mimetype='text/html')


@app.route("/style.css")
def serve_css():
    return send_file("style.css", mimetype="text/css")


@app.route('/advanced.css')
def serve_advanced_css():
    return send_file('advanced.css', mimetype='text/css')


@app.route("/app.js")
def serve_js():
    return send_file("app.js", mimetype="application/javascript")


@app.route('/advanced.js')
def serve_advanced_js():
    return send_file('advanced.js', mimetype='application/javascript')


@app.route('/api/advanced/current')
def api_advanced_current():
    if request.args:
        return jsonify({'error': 'unexpected query parameters'}), 400
    try:
        payload = beacon_diagnosis.get_current_diagnosis(
            DB_PATH,
            SETTINGS,
            int(time.time()),
        )
    except MaintenanceBusy:
        # Name the real cause: without this the browser reports a connection
        # failure for what is actually a scheduled maintenance window.
        return jsonify({'error': 'database maintenance in progress'}), 503
    except sqlite3.OperationalError as exc:
        # The detail belongs in the server log, never in the response body.
        log.warning('advanced diagnosis read unavailable (%s)', exc.__class__.__name__)
        return jsonify({'error': 'diagnosis database is temporarily unavailable'}), 503
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route("/api/config")
def api_config():
    return jsonify({
        "alerting_enabled": bool(ALERT_WEBHOOK_URL),
        "uptime_buckets": UPTIME_BUCKETS,
        "trigger_rate_limit": TRIGGER_SCAN_RATE_LIMIT,
        "trigger_rate_window_seconds": TRIGGER_SCAN_WINDOW_SECONDS,
    })


@app.route("/api/stats")
def api_stats():
    with _db_lock, database_access(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM system_stats WHERE id=1").fetchone()
    if row is None:
        return jsonify({'error': 'metrics not yet sampled'}), 503
    payload = dict(row)
    payload.pop('id', None)
    return jsonify(payload)


@app.route("/api/history")
def api_history():
    now = int(time.time())
    with _db_lock, database_access(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT ts, cpu, ram, disk, temp FROM stats_history WHERE ts >= ? ORDER BY ts ASC",
            (now - 86400,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


def _parse_history_timestamp(name):
    values = request.args.getlist(name)
    if len(values) != 1:
        raise ValueError(f'{name} must be supplied exactly once')
    value = values[0]
    if value is None or not value.isascii() or not value.isdecimal():
        raise ValueError(f'{name} must be a decimal integer')
    return int(value)


def _history_selector():
    """Validate one fixed, non-ambiguous telemetry selector before opening SQLite."""
    kinds = request.args.getlist('kind')
    if len(kinds) != 1:
        raise ValueError('kind must be supplied exactly once')
    kind = kinds[0]
    metrics = request.args.getlist('metric')
    ports = request.args.getlist('port')
    if kind == 'host':
        if len(metrics) != 1 or ports:
            raise ValueError('invalid host selector')
        return kind, beacon_telemetry.host_stream_key(metrics[0]), None
    if kind == 'service':
        if metrics or len(ports) != 1:
            raise ValueError('invalid service selector')
        value = ports[0]
        if not value.isascii() or not value.isdecimal():
            raise ValueError('port must be a decimal integer')
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError('port must be between 1 and 65535')
        return kind, None, port
    raise ValueError('invalid telemetry kind')


@app.route('/api/telemetry/history')
def api_telemetry_history():
    """Serve bounded, mixed-tier telemetry without changing the legacy history route."""
    try:
        kind, metric, port = _history_selector()
        requested = beacon_telemetry.HistoricalRange(
            _parse_history_timestamp('start_ts'),
            _parse_history_timestamp('end_ts'),
        )
        now = int(time.time())
        if requested.end_ts > now:
            raise ValueError('end_ts must not be in the future')
        policy = _telemetry_policy()
        resolution = beacon_telemetry.select_resolution(
            requested.start_ts,
            requested.end_ts,
            policy.point_budget,
        )
        cutoffs = {
            'raw_start_ts': now - policy.raw_days * 86400,
            'five_minute_start_ts': now - policy.five_minute_days * 86400,
        }
        stream_key = beacon_telemetry.host_stream_key(metric) if kind == 'host' else str(port)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    try:
        with _db_lock, database_access(DB_PATH) as conn:
            if kind == 'host':
                sources = beacon_repositories.get_host_telemetry(
                    conn, metric, requested.start_ts, requested.end_ts, resolution,
                    policy.point_budget + 1, cutoffs,
                )
            else:
                sources = beacon_repositories.get_service_telemetry(
                    conn, port, requested.start_ts, requested.end_ts, resolution,
                    policy.point_budget + 1, cutoffs,
                )
            coverage_data = beacon_repositories.get_telemetry_coverage(
                conn, kind, stream_key, requested.start_ts, requested.end_ts,
                policy.point_budget + 1,
            )
            pending = beacon_repositories.get_pending_aggregation(
                conn, kind, stream_key, requested.start_ts, requested.end_ts,
                resolution, policy.point_budget + 1, cutoffs,
            )
        history = beacon_telemetry.compose_historical_response(sources, kind)
        if len(history['points']) > policy.point_budget:
            raise ValueError('telemetry result exceeds point budget')
        coverage = [interval.as_dict() for interval in beacon_telemetry.partition_coverage(
            requested.start_ts,
            requested.end_ts,
            retention_start_ts=now - policy.retention_days * 86400,
            stream=coverage_data['stream'],
            persisted_intervals=coverage_data['intervals'],
            source_segments=sources,
        )]
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    selector = {'kind': kind}
    if kind == 'host':
        selector['metric'] = metric
    else:
        selector['port'] = port
    return jsonify({
        'requested': {'start_ts': requested.start_ts, 'end_ts': requested.end_ts},
        'selector': selector,
        'effective_resolution_seconds': resolution,
        'point_budget': policy.point_budget,
        'source_resolutions_seconds': history['source_resolutions_seconds'],
        'points': history['points'],
        'coverage': coverage,
        'aggregation_pending': list(pending),
    })


@app.route("/api/services")
def api_services():
    now = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400

    with _db_lock, database_access(DB_PATH) as conn:
        services = conn.execute(
            "SELECT s.port, s.title, s.first_seen, s.last_seen, s.is_online, s.state_since, "
            "(s.thumb_data IS NOT NULL AND s.thumb_source='screenshot') AS has_thumb, "
            "s.last_latency_ms, s.last_error, "
            "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
            "COALESCE(m.critical, 0) AS critical, COALESCE(m.pinned_order, s.port) AS pinned_order, "
            "COALESCE(m.tags, '') AS tags, COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
            "FROM services s LEFT JOIN service_meta m ON m.port = s.port "
            "WHERE s.last_seen >= ? "
            "ORDER BY COALESCE(m.pinned_order, s.port) ASC, s.port ASC",
            (expire_cutoff,),
        ).fetchall()

        checks_by_port = defaultdict(list)
        windows_by_port = {}
        if services:
            ports = [s['port'] for s in services]
            placeholders = ','.join('?' * len(ports))
            all_checks = conn.execute(
                f"SELECT ts, port, online FROM service_checks "
                f"WHERE port IN ({placeholders}) AND ts >= ? ORDER BY ts ASC",
                (*ports, now - CHECK_RETENTION_SECONDS),
            ).fetchall()
            for row in all_checks:
                checks_by_port[row['port']].append((row['ts'], row['online']))
            # One bulk read for the whole list rather than one per-service window
            # query inside this loop (T-03.1-29) -- every service's coverage
            # derivation below shares this single read.
            windows_by_port = beacon_repositories.read_maintenance_windows_by_port(conn, ports=ports)
        tls_posture = beacon_repositories.get_runtime_state(conn, 'service_tls_posture', {})
        tls_posture = tls_posture if isinstance(tls_posture, dict) else {}
        preview_rows = conn.execute(
            "SELECT port, status, deadline_ts, revision FROM preview_requests "
            "WHERE id IN (SELECT MAX(id) FROM preview_requests GROUP BY port)"
        ).fetchall()
        previews_by_port = {row['port']: row for row in preview_rows}

        result = []
        for svc in services:
            checks = checks_by_port.get(svc['port'], [])
            uptime_pct, uptime_buckets = _uptime_summary(checks, now)
            effective_url = _safe_service_url(svc['url'], svc['port'])
            preview = previews_by_port.get(svc['port'])
            port_windows = windows_by_port.get(svc['port'], [])

            # The maintenance literal is derived here, additively, from the same
            # coverage rule the suppression write path calls -- never a second
            # percentage, never a change to is_online/state_since/last_error
            # below, which stay the true stored facts (D-06, D-09).
            availability = 'online' if svc['is_online'] else 'offline'
            maintenance_until = None
            if not svc['is_online']:
                covered, grace_until = beacon_maintenance.coverage(
                    port_windows, now, SETTINGS.timezone,
                )
                if covered:
                    availability = beacon_diagnosis.MAINTENANCE_AVAILABILITY
                    maintenance_until = grace_until
            offline_intervals = beacon_repositories.read_service_offline_intervals(
                conn, svc['port'], start_ts=now - CHECK_RETENTION_SECONDS, end_ts=now,
            )
            maintenance_attributed_seconds = beacon_maintenance.attributed_downtime_seconds(
                offline_intervals, port_windows, SETTINGS.timezone,
            )

            result.append({
                "port": svc['port'],
                "title": svc['title'],
                "display_name": svc['display_name'] or None,
                "first_seen": svc['first_seen'],
                "last_seen": svc['last_seen'],
                "state_since": svc['state_since'],
                "is_online": svc['is_online'],
                "has_thumb": svc['has_thumb'],
                "latency_ms": svc['last_latency_ms'],
                "last_error": svc['last_error'],
                "critical": bool(svc['critical']),
                "url": effective_url,
                "path": _service_path_from_url(effective_url, svc['port']),
                "tags": _parse_tags(svc['tags']),
                "pinned_order": svc['pinned_order'],
                "healthy_statuses": svc['healthy_statuses'],
                "tls_unverified": bool(tls_posture.get(str(svc['port']), False)),
                "preview_status": preview['status'] if preview else None,
                "preview_revision": preview['revision'] if preview else None,
                "preview_deadline_ts": preview['deadline_ts'] if preview else None,
                "uptime_pct": uptime_pct,
                "uptime_buckets": uptime_buckets,
                "availability": availability,
                "maintenance_until": maintenance_until,
                "maintenance_attributed_seconds": maintenance_attributed_seconds,
            })

    return jsonify(result)


@app.route("/api/events")
def api_events():
    try:
        limit = int(request.args.get('limit', 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    since = request.args.get('since')
    since_ts = None
    if since is not None:
        try:
            since_ts = int(since)
        except ValueError:
            since_ts = None

    with _db_lock, database_access(DB_PATH) as conn:
        if since_ts is None:
            rows = conn.execute(
                "SELECT e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
                "e.latency_ms, e.error_class, e.alert_status, e.details, "
                "e.suppressed_reason, e.maintenance_grace_until, e.down_since_ts, "
                "COALESCE(m.display_name, s.title, ':' || e.port) AS service_name "
                "FROM events e "
                "LEFT JOIN services s ON s.port = e.port "
                "LEFT JOIN service_meta m ON m.port = e.port "
                "ORDER BY e.ts DESC, e.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
                "e.latency_ms, e.error_class, e.alert_status, e.details, "
                "e.suppressed_reason, e.maintenance_grace_until, e.down_since_ts, "
                "COALESCE(m.display_name, s.title, ':' || e.port) AS service_name "
                "FROM events e "
                "LEFT JOIN services s ON s.port = e.port "
                "LEFT JOIN service_meta m ON m.port = e.port "
                "WHERE e.ts > ? "
                "ORDER BY e.ts DESC, e.id DESC LIMIT ?",
                (since_ts, limit),
            ).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route('/api/service-meta/<int:port>', methods=['GET', 'PUT'])
def api_service_meta(port):
    if request.method == 'GET':
        with _db_lock, database_access(DB_PATH) as conn:
            row = _service_meta_row(conn, port)
        if not row:
            return jsonify({"error": "service not found"}), 404
        return jsonify(row)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({'error': 'metadata payload must be an object'}), 400
    allowed_fields = {
        'display_name', 'url', 'path', 'critical', 'pinned_order', 'tags', 'healthy_statuses',
        'maintenance_windows',
    }
    unknown = [k for k in payload.keys() if k not in allowed_fields]
    if unknown:
        return jsonify({"error": f"unknown fields: {', '.join(unknown)}"}), 400
    for field in {'display_name', 'url', 'path', 'tags', 'healthy_statuses'}:
        if field in payload and not isinstance(payload[field], str):
            return jsonify({'error': f'{field} must be a string'}), 400
    if 'critical' in payload and type(payload['critical']) is not bool:
        return jsonify({'error': 'critical must be a boolean'}), 400
    if (
        'pinned_order' in payload
        and (
            type(payload['pinned_order']) is not int
            or not 0 <= payload['pinned_order'] <= 65535
        )
    ):
        return jsonify({
            'error': 'pinned_order must be an integer between 0 and 65535',
        }), 400

    maintenance_windows_normalised = None
    if 'maintenance_windows' in payload:
        maintenance_windows_normalised, maintenance_windows_error = _validate_maintenance_windows(
            payload['maintenance_windows'], max_windows=SETTINGS.maintenance_windows_per_port_max,
        )
        if maintenance_windows_error:
            return jsonify({'error': maintenance_windows_error}), 400

    next_url = None
    with _db_lock, database_access(DB_PATH) as conn:
        if not beacon_repositories.service_exists(conn, port):
            return jsonify({"error": "service not found"}), 404

        current = beacon_repositories.get_service_metadata_values(conn, port)
        current = current if current else {
            "display_name": "",
            "url": _default_service_url(port),
            "critical": 0,
            "pinned_order": port,
            "tags": "",
            "healthy_statuses": "200-399",
        }

        next_display_name = current['display_name'] if 'display_name' not in payload else (payload.get('display_name') or '').strip()
        next_critical = int(bool(current['critical'])) if 'critical' not in payload else int(payload['critical'])
        next_pinned_order = current['pinned_order'] if 'pinned_order' not in payload else payload['pinned_order']
        next_tags = current['tags'] if 'tags' not in payload else _tags_to_db(payload.get('tags'))
        try:
            _, next_healthy_statuses = _parse_healthy_statuses(
                current.get('healthy_statuses', '200-399') if 'healthy_statuses' not in payload else payload.get('healthy_statuses')
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        has_url = 'url' in payload
        has_path = 'path' in payload
        base_url_input = payload.get('url') if has_url else current.get('url')
        try:
            base_url = _normalize_service_url(base_url_input, port)
            if has_path:
                next_url = _service_url_with_path(base_url, payload.get('path'), port)
            else:
                next_url = base_url
            _outbound_policy().plan(next_url, OutboundPurpose.SERVICE_PROBE)
        except OutboundPolicyError:
            return jsonify({'error': 'policy_error'}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        try:
            now_ts = int(time.time())
            preview_request = beacon_repositories.upsert_service_metadata(
                conn,
                port=port,
                display_name=next_display_name,
                url=next_url,
                critical=next_critical,
                pinned_order=next_pinned_order,
                tags=next_tags,
                healthy_statuses=next_healthy_statuses,
                requested_ts=now_ts,
            )
            if maintenance_windows_normalised is not None:
                beacon_repositories.upsert_maintenance_windows(
                    conn, port=port, windows=maintenance_windows_normalised, now=now_ts,
                )
            row = _service_meta_row(conn, port)
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            return jsonify({'error': 'unable to save service metadata'}), 503

    _record_event('meta_updated', port=port, details='service metadata updated')
    payload = dict(row or {})
    payload['refresh_warning'] = None
    payload['preview_queued'] = True
    payload['preview_status'] = preview_request.status
    payload['preview_revision'] = preview_request.revision
    payload['preview_deadline_ts'] = preview_request.deadline_ts
    return jsonify(payload)


@app.route("/api/thumbnail/<int:port>")
def api_thumbnail(port):
    with _db_lock, database_access(DB_PATH) as conn:
        row = conn.execute(
            "SELECT thumb_data, thumb_mime FROM services WHERE port=? AND thumb_source='screenshot'",
            (port,),
        ).fetchone()

    if row and row['thumb_data']:
        resp = make_response(bytes(row['thumb_data']))
        resp.headers['Content-Type'] = row['thumb_mime'] or 'image/jpeg'
        resp.headers['Cache-Control'] = 'public, max-age=300'
        return resp

    return '', 404


@app.route("/api/thumbnail-status")
def api_thumbnail_status():
    with _db_lock, database_access(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT s.port, s.thumb_source, s.thumb_ts, s.thumb_attempt_ts, s.thumb_error, "
            "COALESCE(m.url, '') AS url "
            "FROM services s LEFT JOIN service_meta m ON m.port = s.port "
            "ORDER BY s.port ASC"
        ).fetchall()

    result = []
    for row in rows:
        port = int(row['port'])
        effective_url = _safe_service_url(row['url'], port)
        result.append({
            "port": port,
            "url": effective_url,
            "thumb_source": row['thumb_source'],
            "thumb_ts": row['thumb_ts'],
            "thumb_attempt_ts": row['thumb_attempt_ts'],
            "thumb_error": row['thumb_error'],
        })
    return jsonify(result)


@app.route("/api/scan-status")
def api_scan_status():
    now = int(time.time())
    with _db_lock, database_access(DB_PATH) as conn:
        state = _read_scan_state(conn)
        heartbeat = _get_runtime_state('worker_heartbeat', {}, conn=conn)
        owner = _get_runtime_state('worker_owner', {}, conn=conn)
        queued = conn.execute("SELECT COUNT(*) AS n FROM scan_requests WHERE status='queued'").fetchone()['n']
        latest_request = conn.execute(
            "SELECT id, status, deadline_ts, error FROM scan_requests ORDER BY id DESC LIMIT 1"
        ).fetchone()
    heartbeat_ts = owner.get('heartbeat_ts') if isinstance(owner, dict) else None
    if heartbeat_ts is None:
        heartbeat_ts = heartbeat.get('ts') if isinstance(heartbeat, dict) else None
    try:
        heartbeat_ts = int(heartbeat_ts) if heartbeat_ts is not None else None
    except (TypeError, ValueError):
        heartbeat_ts = None
    heartbeat_age_seconds = max(0, now - heartbeat_ts) if heartbeat_ts is not None else None
    worker_stale = heartbeat_age_seconds is None or heartbeat_age_seconds > WORKER_READY_SECONDS
    state['worker_heartbeat'] = heartbeat_ts
    state['worker_ready'] = not worker_stale
    state['worker_stale'] = worker_stale
    state['worker_heartbeat_ts'] = heartbeat_ts
    state['worker_heartbeat_age_seconds'] = heartbeat_age_seconds
    state['worker_lease_until'] = owner.get('lease_until') if isinstance(owner, dict) else None
    state['recovery_required'] = worker_stale or (Path(DB_PATH).parent / RECOVERY_MARKER).is_file()
    state['queued_requests'] = int(queued)
    if latest_request:
        state['latest_request_id'] = int(latest_request['id'])
        state['latest_request_status'] = latest_request['status']
        state['latest_request_deadline_ts'] = latest_request['deadline_ts']
        state['latest_request_error_class'] = latest_request['error']
    state['found'] = state['current_found'] if state.get('scanning') else state['last_completed_found']
    return jsonify(state)


@app.route("/api/trigger-scan", methods=["POST"])
def api_trigger_scan():
    client_key = request.remote_addr or 'unknown'
    allowed, retry_after = _check_scan_rate_limit(client_key)
    if not allowed:
        return jsonify({"started": False, "reason": "rate_limited", "retry_after": retry_after}), 429

    queued = beacon_queues.enqueue_scan(DB_PATH, client_key)
    _update_scan_state(stage='queued', scanning=False, progress=0.0, current_found=0, last_error=None)
    return jsonify({
        "queued": True,
        "request_id": queued.request_id,
        "status": queued.status,
        "coalesced": queued.coalesced,
        "deadline_ts": queued.deadline_ts,
    }), 202


@app.route('/healthz')
def healthz():
    try:
        with _db_lock, database_access(DB_PATH) as conn:
            conn.execute('SELECT 1').fetchone()
        return jsonify({'status': 'ok'})
    except Exception as exc:
        return jsonify({'status': 'error', 'error': exc.__class__.__name__}), 503


@app.route('/readyz')
def readyz():
    now = int(time.time())
    with _db_lock:
        heartbeat = _get_runtime_state('worker_heartbeat', {})
    heartbeat_ts = heartbeat.get('ts') if isinstance(heartbeat, dict) else None
    ready = bool(heartbeat_ts and now - int(heartbeat_ts) <= WORKER_READY_SECONDS)
    return jsonify({'ready': ready, 'worker_heartbeat': heartbeat_ts}), (200 if ready else 503)


@app.route('/metrics')
def prometheus_metrics():
    if not ENABLE_PROMETHEUS:
        return '', 404
    with _db_lock, database_access(DB_PATH) as conn:
        stats = conn.execute('SELECT * FROM system_stats WHERE id=1').fetchone()
        online = conn.execute('SELECT COUNT(*) AS n FROM services WHERE is_online=1').fetchone()['n']
        total = conn.execute('SELECT COUNT(*) AS n FROM services').fetchone()['n']
    if stats is None:
        return '# metrics are not ready\n', 503, {'Content-Type': 'text/plain; version=0.0.4'}
    lines = [
        '# TYPE beacon_cpu_percent gauge', f"beacon_cpu_percent {stats['cpu']}",
        '# TYPE beacon_ram_pressure_percent gauge', f"beacon_ram_pressure_percent {stats['ram']}",
        '# TYPE beacon_ram_used_bytes gauge', f"beacon_ram_used_bytes {stats['ram_used']}",
        '# TYPE beacon_disk_percent gauge', f"beacon_disk_percent {stats['disk']}",
        '# TYPE beacon_services_online gauge', f'beacon_services_online {online}',
        '# TYPE beacon_services_total gauge', f'beacon_services_total {total}',
    ]
    return '\n'.join(lines) + '\n', 200, {'Content-Type': 'text/plain; version=0.0.4; charset=utf-8'}


# Gunicorn keeps importing ``app:app`` while composition moves behind the
# factory.  The legacy object is passed only to preserve decorators and test
# monkeypatch seams during the staged extraction.
app = beacon_web.create_app(load_settings(), legacy_app=app)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
