import logging
import os
import json
import ipaddress
import socket
import sqlite3
import threading
import time
from collections import defaultdict
from urllib.parse import urljoin, urlparse, urlunparse

import psutil
import requests
import urllib3
from bs4 import BeautifulSoup
from flask import Flask, jsonify, make_response, request, send_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/dashboard.db")
EXPIRE_DAYS = int(os.environ.get("EXPIRE_DAYS", 7))
THUMB_MAX_BYTES = 2 * 1024 * 1024
THUMB_REFRESH_DAYS = int(os.environ.get("THUMB_REFRESH_DAYS", 1))
PREVIEW_SETTLE_MS = 5_000
PREVIEW_BROWSER_BUDGET_MS = 27_000
UPTIME_WINDOW_SECONDS = 7 * 86400
UPTIME_BUCKETS = 168
CHECK_RETENTION_SECONDS = UPTIME_WINDOW_SECONDS + 86400
METRIC_SAMPLE_SECONDS = int(os.environ.get("METRIC_SAMPLE_SECONDS", 5))
METRIC_HISTORY_SECONDS = int(os.environ.get("METRIC_HISTORY_SECONDS", 60))
WORKER_READY_SECONDS = int(os.environ.get("WORKER_READY_SECONDS", 20))
DISCOVERY_TIMEOUT_SECONDS = int(os.environ.get("DISCOVERY_TIMEOUT_SECONDS", 180))
ENABLE_PROMETHEUS = os.environ.get("ENABLE_PROMETHEUS", "0") in ("1", "true", "TRUE", "yes", "on")

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


TRUSTED_HOSTS, TRUSTED_HOST_NETWORKS = _parse_trusted_hosts(
    os.environ.get("TRUSTED_HOSTS", DEFAULT_TRUSTED_HOSTS)
)
LOCAL_SERVICE_HOSTS = TRUSTED_HOSTS | {
    item.strip().lower().strip('[]')
    for item in os.environ.get("LOCAL_SERVICE_HOSTS", "").split(',')
    if item.strip()
}
try:
    LOCAL_SERVICE_HOSTS.add(socket.gethostname().lower())
except Exception:
    pass

EXTRA_SCAN_PORTS = set()
for _port_text in os.environ.get("EXTRA_SCAN_PORTS", "8100").split(','):
    try:
        _extra_port = int(_port_text.strip())
        if 1 <= _extra_port <= 65535:
            EXTRA_SCAN_PORTS.add(_extra_port)
    except (TypeError, ValueError):
        pass

TRIGGER_SCAN_RATE_LIMIT = int(os.environ.get("TRIGGER_SCAN_RATE_LIMIT", 4))
TRIGGER_SCAN_WINDOW_SECONDS = int(os.environ.get("TRIGGER_SCAN_WINDOW_SECONDS", 60))

ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", 300))
ALERT_ONLY_CRITICAL = os.environ.get("ALERT_ONLY_CRITICAL", "0") in ("1", "true", "TRUE", "yes", "on")

_db_lock = threading.Lock()
_scan_lock = threading.Lock()
_startup_lock = threading.Lock()
_screenshot_sem = threading.Semaphore(1)
_uptime_lock = threading.Lock()
_browser_lock = threading.Lock()
_browser_playwright = None
_browser_instance = None
_preview_context = threading.local()

_bg_started = False


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _table_columns(conn, table_name):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def init_db():
    with _db_lock:
        conn = get_db()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version     INTEGER PRIMARY KEY,
                applied_ts  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS stats_history (
                ts      INTEGER PRIMARY KEY,
                cpu     REAL,
                ram     REAL,
                disk    REAL,
                temp    REAL
            );

            CREATE TABLE IF NOT EXISTS system_stats (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                sample_ts       INTEGER NOT NULL,
                cpu             REAL NOT NULL,
                ram             REAL NOT NULL,
                ram_used        INTEGER NOT NULL,
                ram_available   INTEGER NOT NULL,
                ram_used_strict INTEGER NOT NULL,
                ram_total       INTEGER NOT NULL,
                disk            REAL NOT NULL,
                disk_used       INTEGER NOT NULL,
                disk_total      INTEGER NOT NULL,
                temp            REAL,
                hostname        TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS services (
                port             INTEGER PRIMARY KEY,
                title            TEXT,
                first_seen       INTEGER NOT NULL,
                last_seen        INTEGER NOT NULL,
                is_online        INTEGER DEFAULT 1,
                thumb_data       BLOB,
                thumb_mime       TEXT DEFAULT 'image/jpeg',
                thumb_ts         INTEGER,
                thumb_source     TEXT,
                thumb_attempt_ts INTEGER,
                thumb_error      TEXT,
                last_latency_ms  REAL,
                last_error       TEXT
            );

            CREATE TABLE IF NOT EXISTS service_meta (
                port          INTEGER PRIMARY KEY,
                display_name  TEXT,
                url           TEXT,
                critical      INTEGER DEFAULT 0,
                pinned_order  INTEGER DEFAULT 0,
                tags          TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS service_checks (
                ts          INTEGER,
                port        INTEGER,
                online      INTEGER,
                latency_ms  REAL,
                error_class TEXT,
                PRIMARY KEY (ts, port)
            );

            CREATE TABLE IF NOT EXISTS events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                ts             INTEGER NOT NULL,
                port           INTEGER,
                event_type     TEXT NOT NULL,
                online         INTEGER,
                previous_online INTEGER,
                latency_ms     REAL,
                error_class    TEXT,
                alert_status   TEXT,
                details        TEXT
            );

            CREATE TABLE IF NOT EXISTS runtime_state (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                updated_ts  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_requests (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_ts  INTEGER NOT NULL,
                requested_by  TEXT,
                status        TEXT NOT NULL DEFAULT 'queued',
                started_ts    INTEGER,
                completed_ts  INTEGER,
                error         TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_rate_hits (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                client_key  TEXT NOT NULL,
                ts          INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS preview_requests (
                port          INTEGER PRIMARY KEY,
                requested_ts  INTEGER NOT NULL,
                status        TEXT NOT NULL DEFAULT 'queued',
                error         TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_stats_ts        ON stats_history(ts);
            CREATE INDEX IF NOT EXISTS idx_checks_ts       ON service_checks(ts);
            CREATE INDEX IF NOT EXISTS idx_checks_port     ON service_checks(port);
            CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_port_ts  ON events(port, ts);
            CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status, requested_ts);
            CREATE INDEX IF NOT EXISTS idx_scan_rate_hits_client_ts ON scan_rate_hits(client_key, ts);
        """)

        # Migration for older services table
        svc_cols = _table_columns(conn, "services")
        if 'thumb_data' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_data BLOB")
        if 'thumb_mime' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_mime TEXT DEFAULT 'image/jpeg'")
        if 'thumb_ts' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_ts INTEGER")
        if 'thumb_source' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_source TEXT")
        if 'thumb_attempt_ts' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_attempt_ts INTEGER")
        if 'thumb_error' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_error TEXT")
        if 'last_latency_ms' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN last_latency_ms REAL")
        if 'last_error' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN last_error TEXT")
        if 'state_since' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN state_since INTEGER")

        meta_cols = _table_columns(conn, "service_meta")
        if 'healthy_statuses' not in meta_cols:
            conn.execute("ALTER TABLE service_meta ADD COLUMN healthy_statuses TEXT DEFAULT '200-399'")

        conn.execute(
            "UPDATE services SET thumb_data=NULL, thumb_mime='image/jpeg', thumb_ts=NULL, thumb_source=NULL "
            "WHERE thumb_source='fallback'"
        )

        checks_cols = _table_columns(conn, "service_checks")
        if 'latency_ms' not in checks_cols:
            conn.execute("ALTER TABLE service_checks ADD COLUMN latency_ms REAL")
        if 'error_class' not in checks_cols:
            conn.execute("ALTER TABLE service_checks ADD COLUMN error_class TEXT")

        # Ensure metadata exists for previously discovered services
        conn.execute(
            "INSERT OR IGNORE INTO service_meta (port, url, critical, pinned_order, tags, healthy_statuses) "
            "SELECT port, 'http://127.0.0.1:' || port, 0, port, '', '200-399' FROM services"
        )

        # Initialize state_since once from the latest matching transition. Older
        # binaries simply ignore this additive column.
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
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_ts) VALUES(1, ?)",
            (int(time.time()),),
        )

        conn.commit()
        conn.close()


def _set_runtime_state(key, value, *, conn=None, now=None):
    owns_conn = conn is None
    if owns_conn:
        conn = get_db()
    now = int(time.time()) if now is None else int(now)
    conn.execute(
        "INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts",
        (key, json.dumps(value, separators=(',', ':')), now),
    )
    if owns_conn:
        conn.commit()
        conn.close()


def _get_runtime_state(key, default=None, *, conn=None):
    owns_conn = conn is None
    if owns_conn:
        conn = get_db()
    row = conn.execute("SELECT value, updated_ts FROM runtime_state WHERE key=?", (key,)).fetchone()
    if owns_conn:
        conn.close()
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
    with _db_lock:
        conn = get_db()
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
        conn.execute("UPDATE scan_requests SET status='queued', started_ts=NULL WHERE status='running'")
        conn.execute("UPDATE preview_requests SET status='queued' WHERE status='running'")
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
        conn.close()


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
    with _db_lock:
        conn = get_db()
        state = _read_scan_state(conn)
        state.update(changes)
        _set_runtime_state('scan_state', state, conn=conn)
        conn.commit()
        conn.close()
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


def _probe_http(url, timeout=2.5, allow_remote=False, healthy_statuses='200-399'):
    try:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        url = _normalize_service_url(url, port)
        _parse_healthy_statuses(healthy_statuses)

        start = time.monotonic()
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        latency_ms = round((time.monotonic() - start) * 1000, 1)

        # Redirects are not followed; enforce loopback target when probing loopback.
        if 300 <= resp.status_code < 400:
            location = resp.headers.get('Location')
            if location:
                redirect_url = urljoin(url, location)
                redirect_parsed = urlparse(redirect_url)
                if redirect_parsed.username is not None or redirect_parsed.password is not None:
                    return False, latency_ms, "redirect_userinfo", resp
                if not _is_local_service_host(redirect_parsed.hostname):
                    return False, latency_ms, "redirect_offhost", resp

        if not _status_is_healthy(resp.status_code, healthy_statuses):
            return False, latency_ms, f"http_{resp.status_code}", resp
        return True, latency_ms, None, resp
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


def _fetch_html_response(url, timeout=3, allow_remote=False):
    try:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        url = _normalize_service_url(url, port)
        final_url = url
        resp = None
        for _ in range(6):
            current = urlparse(final_url)
            current_port = current.port or (443 if current.scheme == 'https' else 80)
            final_url = _normalize_service_url(final_url, current_port)
            resp = requests.get(final_url, timeout=timeout, verify=False, allow_redirects=False)
            if not (300 <= resp.status_code < 400) or not resp.headers.get('Location'):
                break
            candidate = urljoin(final_url, resp.headers['Location'])
            candidate_parsed = urlparse(candidate)
            if candidate_parsed.username is not None or candidate_parsed.password is not None:
                return False, "redirect_userinfo", None, candidate
            if not _is_local_service_host(candidate_parsed.hostname):
                return False, "redirect_offhost", None, candidate
            final_url = candidate
        else:
            return False, 'too_many_redirects', None, final_url
        if not _is_html_content_type(resp.headers.get('Content-Type', '')):
            return False, "non_html", resp, final_url
        return True, None, resp, final_url
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


def _extract_title(resp, port):
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


def _get_browser():
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


def shutdown_browser():
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


def _insert_event(conn, *, ts, event_type, port=None, online=None, previous_online=None,
                  latency_ms=None, error_class=None, alert_status=None, details=None):
    conn.execute(
        "INSERT INTO events (ts, port, event_type, online, previous_online, latency_ms, error_class, alert_status, details) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
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
        )
    )


def _record_event(event_type, port=None, online=None, previous_online=None,
                  latency_ms=None, error_class=None, alert_status=None, details=None):
    now = int(time.time())
    with _db_lock:
        conn = get_db()
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
        conn.close()


def _should_send_alert(port, online, now):
    with _db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT ts FROM events WHERE port=? AND event_type='alert_sent' AND online=? "
            "ORDER BY ts DESC LIMIT 1",
            (port, online),
        ).fetchone()
        conn.close()
    if not row:
        return True
    return (now - int(row['ts'])) >= ALERT_COOLDOWN_SECONDS


def _send_transition_alert(*, now, port, previous_online, online, title, display_name,
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
        r = requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=4)
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
                details=(r.text or "")[:200],
            )
    except Exception as exc:
        _record_event(
            "alert_failed",
            port=port,
            online=online,
            previous_online=previous_online,
            latency_ms=latency_ms,
            error_class=error_class,
            alert_status="exception",
            details=str(exc)[:200],
        )


def _handle_state_transition(*, port, previous_online, online, title, display_name,
                             url, critical, latency_ms, error_class):
    now = int(time.time())
    msg = "service recovered" if online else "service went down"
    _record_event(
        "state_change",
        port=port,
        online=online,
        previous_online=previous_online,
        latency_ms=latency_ms,
        error_class=error_class,
        details=msg,
    )
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
    text = str(exc).strip() or exc.__class__.__name__
    return f"{exc.__class__.__name__}: {text}"[:240]


def _screenshot_service(port, target_url=None):
    """Capture a service screenshot using Chromium. Returns (bytes, mime, error)."""
    _screenshot_sem.acquire()
    try:
        navigate_url = _normalize_service_url(target_url, port) if target_url else _default_service_url(port)
    except ValueError:
        navigate_url = _default_service_url(port)
    context = None
    started = time.monotonic()
    deadline = started + PREVIEW_BROWSER_BUDGET_MS / 1000
    _preview_context.timings = {}
    _preview_context.page_title = None
    try:
        browser = _get_browser()
        context_started = time.monotonic()
        context = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = context.new_page()
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
        log.warning("Screenshot failed for port %d: %s", port, exc)
        return None, None, _thumb_error(exc)
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        _screenshot_sem.release()
    return None, None, "screenshot failed"


def fetch_thumbnail(port, service_url=None):
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
    try:
        _record_event(
            'preview_capture', port=port, error_class=screenshot_error,
            details=json.dumps(timings, separators=(',', ':'), sort_keys=True),
        )
    except Exception:
        log.exception('Could not persist preview timing for port %d', port)
    if screenshot_data:
        return screenshot_data, screenshot_mime, 'screenshot', None
    return None, None, None, screenshot_error or "screenshot failed"


def _store_thumbnail_result(conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts=None):
    ts = ts or int(time.time())
    if thumb_data and thumb_source == 'screenshot':
        conn.execute(
            "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=?, thumb_source=?, "
            "thumb_attempt_ts=?, thumb_error=NULL WHERE port=?",
            (thumb_data, thumb_mime, ts, thumb_source, ts, port),
        )
    else:
        conn.execute(
            "UPDATE services SET thumb_data=NULL, thumb_mime='image/jpeg', thumb_ts=NULL, thumb_source=NULL, "
            "thumb_attempt_ts=?, thumb_error=? WHERE port=?",
            (ts, (thumb_error or 'screenshot failed')[:240], port),
        )


def _refresh_service_preview(port, service_url):
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


def _uptime_summary(checks, now):
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


def _build_uptime_buckets(checks, now):
    return _uptime_summary(checks, now)[1]


def _calc_uptime_pct(checks, now=None):
    return _uptime_summary(checks, int(time.time()) if now is None else now)[0]


def collect_system_stats(now=None, persist_history=None):
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
    with _db_lock:
        conn = get_db()
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
        conn.close()
    return sample


def cleanup_history(now=None):
    now = int(time.time()) if now is None else int(now)
    with _db_lock:
        conn = get_db()
        conn.execute("DELETE FROM stats_history WHERE ts < ?", (now - 86400,))
        conn.execute("DELETE FROM service_checks WHERE ts < ?", (now - CHECK_RETENTION_SECONDS,))
        conn.execute("DELETE FROM events WHERE ts < ?", (now - (14 * 86400),))
        conn.execute("DELETE FROM scan_rate_hits WHERE ts < ?", (now - TRIGGER_SCAN_WINDOW_SECONDS,))
        conn.commit()
        conn.close()


def do_discovery(source='scheduled'):
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
        with _db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT s.port, COALESCE(m.url, '') AS url, COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port"
            ).fetchall()
            conn.close()
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
        with _db_lock:
            conn = get_db()
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
            conn.commit()
            conn.close()
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
            with _db_lock:
                conn = get_db()
                conn.execute(
                    "INSERT INTO preview_requests(port, requested_ts, status, error) VALUES(?,?,'queued',NULL) "
                    "ON CONFLICT(port) DO UPDATE SET requested_ts=excluded.requested_ts, status='queued', error=NULL",
                    (port, int(time.time())),
                )
                conn.commit()
                conn.close()
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
    except Exception as exc:
        log.exception("Discovery failed unexpectedly: %s", exc)
        timings['total_ms'] = round((time.monotonic() - scan_started) * 1000, 1)
        _update_scan_state(
            stage='failed', scanning=False, current_found=len(discovered),
            timings=timings, last_error=f'{exc.__class__.__name__}: {exc}'[:240],
        )
        _record_event("scan_failed", details=str(exc)[:200])
        return False


def run_discovery(source='scheduled'):
    """Run one discovery owner at a time across every scheduler entry point."""
    if not _scan_lock.acquire(blocking=False):
        return 'busy'
    try:
        return 'completed' if do_discovery(source=source) else 'failed'
    finally:
        _scan_lock.release()


def do_uptime_check(only_down=False):
    if not _uptime_lock.acquire(blocking=False):
        return False
    now = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400
    transitions = []
    try:
        with _db_lock:
            conn = get_db()
            where = "WHERE s.last_seen >= ? AND s.is_online = 0" if only_down else "WHERE s.last_seen >= ?"
            rows = conn.execute(
                "SELECT s.port, s.title, s.is_online, "
                "(s.thumb_data IS NOT NULL AND s.thumb_source='screenshot') AS has_thumb, "
                "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
                "COALESCE(m.critical, 0) AS critical, COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port " + where,
                (expire_cutoff,),
            ).fetchall()
            conn.close()

        # Network I/O is deliberately outside the SQLite lock so the metrics
        # executor can keep its five-second cadence during slow probes.
        for row in rows:
            port = int(row['port'])
            previous_online = int(row['is_online'] or 0)
            try:
                service_url = _normalize_service_url(row['url'], port)
                online, latency_ms, error_class, resp = _probe_http(
                    service_url, timeout=2.0, healthy_statuses=row['healthy_statuses'],
                )
            except ValueError:
                service_url = _default_service_url(port)
                online = False
                latency_ms = None
                error_class = 'invalid_url'
                resp = None
            online_int = 1 if online else 0
            title_update = _extract_title(resp, port) if online and resp is not None else ''

            with _db_lock:
                conn = get_db()
                if online and title_update and title_update != f":{port}":
                    conn.execute(
                        "UPDATE services SET title=?, is_online=1, last_seen=?, last_latency_ms=?, last_error=NULL, "
                        "state_since=CASE WHEN is_online != 1 THEN ? ELSE state_since END WHERE port=?",
                        (title_update, now, latency_ms, now, port),
                    )
                elif online:
                    conn.execute(
                        "UPDATE services SET is_online=1, last_seen=?, last_latency_ms=?, last_error=NULL, "
                        "state_since=CASE WHEN is_online != 1 THEN ? ELSE state_since END WHERE port=?",
                        (now, latency_ms, now, port),
                    )
                else:
                    conn.execute(
                        "UPDATE services SET is_online=0, last_latency_ms=NULL, last_error=?, "
                        "state_since=CASE WHEN is_online != 0 THEN ? ELSE state_since END WHERE port=?",
                        (error_class or 'probe_failed', now, port),
                    )
                conn.execute(
                    "INSERT OR REPLACE INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                    (now, port, online_int, latency_ms, error_class),
                )
                if online and not row['has_thumb']:
                    conn.execute(
                        "INSERT INTO preview_requests(port, requested_ts, status, error) VALUES(?,?,'queued',NULL) "
                        "ON CONFLICT(port) DO UPDATE SET requested_ts=excluded.requested_ts, status='queued', error=NULL",
                        (port, now),
                    )
                conn.commit()
                conn.close()

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

        for transition in transitions:
            _handle_state_transition(**transition)

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


def queue_discovery_request(client_key):
    now = int(time.time())
    with _db_lock:
        conn = get_db()
        active = conn.execute(
            "SELECT id FROM scan_requests WHERE status IN ('queued','running') ORDER BY id LIMIT 1"
        ).fetchone()
        scan_state = _read_scan_state(conn)
        if active or scan_state.get('scanning'):
            conn.close()
            return None
        cur = conn.execute(
            "INSERT INTO scan_requests(requested_ts, requested_by, status) VALUES(?,?,'queued')",
            (now, str(client_key)[:120]),
        )
        request_id = cur.lastrowid
        conn.commit()
        conn.close()
    _update_scan_state(stage='queued', scanning=False, progress=0.0, current_found=0, last_error=None)
    return request_id


def process_scan_requests():
    with _db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT id FROM scan_requests WHERE status='queued' ORDER BY requested_ts, id LIMIT 1"
        ).fetchone()
        if not row:
            conn.close()
            return False
        request_id = int(row['id'])
        now = int(time.time())
        conn.execute(
            "UPDATE scan_requests SET status='running', started_ts=? WHERE id=? AND status='queued'",
            (now, request_id),
        )
        conn.commit()
        conn.close()

    try:
        outcome = run_discovery(source=f'manual:{request_id}')
        if outcome == 'busy':
            with _db_lock:
                conn = get_db()
                conn.execute(
                    "UPDATE scan_requests SET status='queued', started_ts=NULL WHERE id=?",
                    (request_id,),
                )
                conn.commit()
                conn.close()
            return False
        state = _read_scan_state()
        status = 'failed' if outcome == 'failed' or state.get('last_error') else 'completed'
        error = state.get('last_error') if status == 'failed' else None
    except Exception as exc:
        status, error = 'failed', str(exc)[:240]

    with _db_lock:
        conn = get_db()
        conn.execute(
            "UPDATE scan_requests SET status=?, completed_ts=?, error=? WHERE id=?",
            (status, int(time.time()), error, request_id),
        )
        conn.commit()
        conn.close()
    return True


def process_preview_requests():
    with _db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT p.port, COALESCE(m.url, '') AS url FROM preview_requests p "
            "LEFT JOIN service_meta m ON m.port=p.port WHERE p.status='queued' ORDER BY p.requested_ts LIMIT 1"
        ).fetchone()
        if not row:
            conn.close()
            return False
        port = int(row['port'])
        url = _safe_service_url(row['url'], port)
        conn.execute("UPDATE preview_requests SET status='running', error=NULL WHERE port=?", (port,))
        conn.commit()
        conn.close()
    started = time.monotonic()
    title, data, mime, source, thumb_error, warning = _refresh_service_preview(port, url)
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    with _db_lock:
        conn = get_db()
        if title:
            conn.execute("UPDATE services SET title=? WHERE port=?", (title, port))
        if data or thumb_error:
            _store_thumbnail_result(conn, port, data, mime, source, thumb_error)
        conn.execute(
            "UPDATE preview_requests SET status=?, error=? WHERE port=?",
            ('failed' if warning else 'completed', warning, port),
        )
        conn.commit()
        conn.close()
    _record_event(
        'preview_complete', port=port, error_class=thumb_error,
        details=json.dumps({'total_ms': elapsed_ms, 'success': not bool(warning)}, separators=(',', ':')),
    )
    return True


def _check_scan_rate_limit(client_key):
    now = int(time.time())
    with _db_lock:
        conn = get_db()
        cutoff = now - TRIGGER_SCAN_WINDOW_SECONDS
        conn.execute("DELETE FROM scan_rate_hits WHERE ts < ?", (cutoff,))
        rows = conn.execute(
            "SELECT ts FROM scan_rate_hits WHERE client_key=? ORDER BY ts ASC",
            (client_key,),
        ).fetchall()
        if len(rows) >= TRIGGER_SCAN_RATE_LIMIT:
            retry_after = TRIGGER_SCAN_WINDOW_SECONDS - (now - int(rows[0]['ts']))
            conn.commit()
            conn.close()
            return False, max(1, retry_after)
        conn.execute("INSERT INTO scan_rate_hits(client_key, ts) VALUES(?,?)", (client_key, now))
        conn.commit()
        conn.close()
        return True, 0


def _service_meta_row(conn, port):
    row = conn.execute(
        "SELECT m.port, COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
        "COALESCE(m.critical, 0) AS critical, COALESCE(m.pinned_order, s.port) AS pinned_order, "
        "COALESCE(m.tags, '') AS tags, COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
        "FROM services s LEFT JOIN service_meta m ON m.port = s.port WHERE s.port = ?",
        (port,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d['url'] = _safe_service_url(d.get('url'), port)
    d['path'] = _service_path_from_url(d['url'], port)
    d['tags'] = _parse_tags(d.get('tags'))
    d['critical'] = bool(d.get('critical'))
    return d


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


@app.route("/style.css")
def serve_css():
    return send_file("style.css", mimetype="text/css")


@app.route("/app.js")
def serve_js():
    return send_file("app.js", mimetype="application/javascript")


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
    with _db_lock:
        conn = get_db()
        row = conn.execute("SELECT * FROM system_stats WHERE id=1").fetchone()
        conn.close()
    if row is None:
        return jsonify({'error': 'metrics not yet sampled'}), 503
    payload = dict(row)
    payload.pop('id', None)
    return jsonify(payload)


@app.route("/api/history")
def api_history():
    now = int(time.time())
    with _db_lock:
        conn = get_db()
        rows = conn.execute(
            "SELECT ts, cpu, ram, disk, temp FROM stats_history WHERE ts >= ? ORDER BY ts ASC",
            (now - 86400,),
        ).fetchall()
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/services")
def api_services():
    now = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400

    with _db_lock:
        conn = get_db()
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

        result = []
        for svc in services:
            checks = checks_by_port.get(svc['port'], [])
            uptime_pct, uptime_buckets = _uptime_summary(checks, now)
            effective_url = _safe_service_url(svc['url'], svc['port'])
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
                "uptime_pct": uptime_pct,
                "uptime_buckets": uptime_buckets,
            })

        conn.close()

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

    with _db_lock:
        conn = get_db()
        if since_ts is None:
            rows = conn.execute(
                "SELECT e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
                "e.latency_ms, e.error_class, e.alert_status, e.details, "
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
                "COALESCE(m.display_name, s.title, ':' || e.port) AS service_name "
                "FROM events e "
                "LEFT JOIN services s ON s.port = e.port "
                "LEFT JOIN service_meta m ON m.port = e.port "
                "WHERE e.ts > ? "
                "ORDER BY e.ts DESC, e.id DESC LIMIT ?",
                (since_ts, limit),
            ).fetchall()
        conn.close()

    return jsonify([dict(r) for r in rows])


@app.route('/api/service-meta/<int:port>', methods=['GET', 'PUT'])
def api_service_meta(port):
    if request.method == 'GET':
        with _db_lock:
            conn = get_db()
            row = _service_meta_row(conn, port)
            conn.close()
        if not row:
            return jsonify({"error": "service not found"}), 404
        return jsonify(row)

    payload = request.get_json(silent=True) or {}
    allowed_fields = {'display_name', 'url', 'path', 'critical', 'pinned_order', 'tags', 'healthy_statuses'}
    unknown = [k for k in payload.keys() if k not in allowed_fields]
    if unknown:
        return jsonify({"error": f"unknown fields: {', '.join(unknown)}"}), 400

    next_url = None
    with _db_lock:
        conn = get_db()
        svc = conn.execute("SELECT port FROM services WHERE port=?", (port,)).fetchone()
        if not svc:
            conn.close()
            return jsonify({"error": "service not found"}), 404

        current = conn.execute(
            "SELECT display_name, url, critical, pinned_order, tags, healthy_statuses FROM service_meta WHERE port=?",
            (port,),
        ).fetchone()
        current = dict(current) if current else {
            "display_name": "",
            "url": _default_service_url(port),
            "critical": 0,
            "pinned_order": port,
            "tags": "",
            "healthy_statuses": "200-399",
        }

        next_display_name = current['display_name'] if 'display_name' not in payload else (payload.get('display_name') or '').strip()
        next_critical = int(bool(current['critical'])) if 'critical' not in payload else int(bool(payload.get('critical')))
        try:
            next_pinned_order = int(current['pinned_order']) if 'pinned_order' not in payload else int(payload.get('pinned_order'))
        except (TypeError, ValueError):
            conn.close()
            return jsonify({"error": "pinned_order must be an integer"}), 400
        next_tags = current['tags'] if 'tags' not in payload else _tags_to_db(payload.get('tags'))
        try:
            _, next_healthy_statuses = _parse_healthy_statuses(
                current.get('healthy_statuses', '200-399') if 'healthy_statuses' not in payload else payload.get('healthy_statuses')
            )
        except ValueError as exc:
            conn.close()
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
        except ValueError as exc:
            conn.close()
            return jsonify({"error": str(exc)}), 400

        conn.execute(
            "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags, healthy_statuses) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(port) DO UPDATE SET display_name=excluded.display_name, url=excluded.url, "
            "critical=excluded.critical, pinned_order=excluded.pinned_order, tags=excluded.tags, "
            "healthy_statuses=excluded.healthy_statuses",
            (port, next_display_name, next_url, next_critical, next_pinned_order, next_tags, next_healthy_statuses),
        )
        conn.commit()
        conn.close()

    with _db_lock:
        conn = get_db()
        conn.execute(
            "INSERT INTO preview_requests(port, requested_ts, status, error) VALUES(?,?,'queued',NULL) "
            "ON CONFLICT(port) DO UPDATE SET requested_ts=excluded.requested_ts, status='queued', error=NULL",
            (port, int(time.time())),
        )
        conn.commit()
        row = _service_meta_row(conn, port)
        conn.close()

    _record_event('meta_updated', port=port, details='service metadata updated')
    payload = dict(row or {})
    payload['refresh_warning'] = None
    payload['preview_queued'] = True
    return jsonify(payload)


@app.route("/api/thumbnail/<int:port>")
def api_thumbnail(port):
    with _db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT thumb_data, thumb_mime FROM services WHERE port=? AND thumb_source='screenshot'",
            (port,),
        ).fetchone()
        conn.close()

    if row and row['thumb_data']:
        resp = make_response(bytes(row['thumb_data']))
        resp.headers['Content-Type'] = row['thumb_mime'] or 'image/jpeg'
        resp.headers['Cache-Control'] = 'public, max-age=300'
        return resp

    return '', 404


@app.route("/api/thumbnail-status")
def api_thumbnail_status():
    with _db_lock:
        conn = get_db()
        rows = conn.execute(
            "SELECT s.port, s.thumb_source, s.thumb_ts, s.thumb_attempt_ts, s.thumb_error, "
            "COALESCE(m.url, '') AS url "
            "FROM services s LEFT JOIN service_meta m ON m.port = s.port "
            "ORDER BY s.port ASC"
        ).fetchall()
        conn.close()

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
    with _db_lock:
        conn = get_db()
        state = _read_scan_state(conn)
        heartbeat = _get_runtime_state('worker_heartbeat', {}, conn=conn)
        queued = conn.execute("SELECT COUNT(*) AS n FROM scan_requests WHERE status='queued'").fetchone()['n']
        conn.close()
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
    state['recovery_required'] = worker_stale
    state['queued_requests'] = int(queued)
    state['found'] = state['current_found'] if state.get('scanning') else state['last_completed_found']
    return jsonify(state)


@app.route("/api/trigger-scan", methods=["POST"])
def api_trigger_scan():
    client_key = request.remote_addr or 'unknown'
    allowed, retry_after = _check_scan_rate_limit(client_key)
    if not allowed:
        return jsonify({"started": False, "reason": "rate_limited", "retry_after": retry_after}), 429

    request_id = queue_discovery_request(client_key)
    if request_id is not None:
        return jsonify({"queued": True, "request_id": request_id}), 202
    return jsonify({"queued": False, "reason": "already_queued_or_running"}), 409


@app.route('/healthz')
def healthz():
    try:
        with _db_lock:
            conn = get_db()
            conn.execute('SELECT 1').fetchone()
            conn.close()
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
    with _db_lock:
        conn = get_db()
        stats = conn.execute('SELECT * FROM system_stats WHERE id=1').fetchone()
        online = conn.execute('SELECT COUNT(*) AS n FROM services WHERE is_online=1').fetchone()['n']
        total = conn.execute('SELECT COUNT(*) AS n FROM services').fetchone()['n']
        conn.close()
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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
