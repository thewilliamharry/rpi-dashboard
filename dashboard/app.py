import logging
import os
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

DB_PATH = "/data/dashboard.db"
EXPIRE_DAYS = int(os.environ.get("EXPIRE_DAYS", 7))
THUMB_MAX_BYTES = 2 * 1024 * 1024
THUMB_REFRESH_DAYS = int(os.environ.get("THUMB_REFRESH_DAYS", 1))
UPTIME_WINDOW_SECONDS = 7 * 86400
UPTIME_BUCKETS = 168

TRIGGER_SCAN_RATE_LIMIT = int(os.environ.get("TRIGGER_SCAN_RATE_LIMIT", 4))
TRIGGER_SCAN_WINDOW_SECONDS = int(os.environ.get("TRIGGER_SCAN_WINDOW_SECONDS", 60))

ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", 300))
ALERT_ONLY_CRITICAL = os.environ.get("ALERT_ONLY_CRITICAL", "0") in ("1", "true", "TRUE", "yes", "on")

_db_lock = threading.Lock()
_scan_lock = threading.Lock()
_startup_lock = threading.Lock()
_rate_lock = threading.Lock()
_screenshot_sem = threading.Semaphore(1)

# Scan state
_last_discovery = None
_last_uptime_check = None
_last_down_check = None
_scanning = False
_found = 0
_bg_started = False

_trigger_hits = {}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn, table_name):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def init_db():
    with _db_lock:
        conn = get_db()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS stats_history (
                ts      INTEGER PRIMARY KEY,
                cpu     REAL,
                ram     REAL,
                disk    REAL,
                temp    REAL
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

            CREATE INDEX IF NOT EXISTS idx_stats_ts        ON stats_history(ts);
            CREATE INDEX IF NOT EXISTS idx_checks_ts       ON service_checks(ts);
            CREATE INDEX IF NOT EXISTS idx_checks_port     ON service_checks(port);
            CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_port_ts  ON events(port, ts);
        """)

        # Migration for older services table
        svc_cols = _table_columns(conn, "services")
        if 'thumb_data' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_data BLOB")
        if 'thumb_mime' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_mime TEXT DEFAULT 'image/jpeg'")
        if 'thumb_ts' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_ts INTEGER")
        if 'last_latency_ms' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN last_latency_ms REAL")
        if 'last_error' not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN last_error TEXT")

        checks_cols = _table_columns(conn, "service_checks")
        if 'latency_ms' not in checks_cols:
            conn.execute("ALTER TABLE service_checks ADD COLUMN latency_ms REAL")
        if 'error_class' not in checks_cols:
            conn.execute("ALTER TABLE service_checks ADD COLUMN error_class TEXT")

        # Ensure metadata exists for previously discovered services
        conn.execute(
            "INSERT OR IGNORE INTO service_meta (port, url, critical, pinned_order, tags) "
            "SELECT port, 'http://127.0.0.1:' || port, 0, port, '' FROM services"
        )

        conn.commit()
        conn.close()


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
    return host in ("127.0.0.1", "localhost", "::1")


def _is_localhost_url(url):
    try:
        host = urlparse(url).hostname or ''
        return _is_loopback_host(host)
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
    normalized = parsed.geturl().rstrip('/')
    return normalized


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
    try:
        normalized = _normalize_service_url(url, port)
    except ValueError:
        normalized = _default_service_url(port)
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
    try:
        normalized = _normalize_service_url(existing_url, port)
    except ValueError:
        return _default_service_url(port)
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


def _probe_http(url, timeout=2.5, allow_remote=False):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, None, "invalid_scheme", None
        if not parsed.hostname:
            return False, None, "invalid_host", None
        if not allow_remote and not _is_loopback_host(parsed.hostname):
            return False, None, "non_loopback", None

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
                if not allow_remote and not _is_localhost_url(redirect_url):
                    return False, latency_ms, "redirect_offhost", resp

        return True, latency_ms, None, resp
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
        if parsed.scheme not in ("http", "https"):
            return False, "invalid_scheme", None, url
        if not parsed.hostname:
            return False, "invalid_host", None, url
        if not allow_remote and not _is_loopback_host(parsed.hostname):
            return False, "non_loopback", None, url

        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        final_url = resp.url or url
        final_host = urlparse(final_url).hostname or ''
        if not allow_remote and not _is_loopback_host(final_host):
            return False, "redirect_offhost", None, final_url
        if not _is_html_content_type(resp.headers.get('Content-Type', '')):
            return False, "non_html", resp, final_url
        return True, None, resp, final_url
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


def _browser_page_title(url):
    if not _screenshot_sem.acquire(blocking=False):
        return None
    try:
        from playwright.sync_api import TimeoutError as PWTimeout
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(args=['--no-sandbox', '--disable-dev-shm-usage'])
            try:
                page = browser.new_page(viewport={'width': 1280, 'height': 800})
                page.goto(url, timeout=15_000, wait_until='domcontentloaded')
                page.wait_for_timeout(1000)
                title = (page.title() or '').strip()
                return title or None
            except PWTimeout:
                return None
            finally:
                browser.close()
    except Exception:
        return None
    finally:
        _screenshot_sem.release()


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
        r = requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=4, verify=False)
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


def _screenshot_service(port, target_url=None):
    """Capture a service screenshot using Chromium. Returns (bytes, mime) or (None, None)."""
    if not _screenshot_sem.acquire(blocking=False):
        log.info("Screenshot for port %d deferred: another screenshot in progress", port)
        return None, None
    try:
        navigate_url = _normalize_service_url(target_url, port) if target_url else _default_service_url(port)
    except ValueError:
        navigate_url = _default_service_url(port)
    try:
        from playwright.sync_api import TimeoutError as PWTimeout
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(args=['--no-sandbox', '--disable-dev-shm-usage'])
            try:
                page = browser.new_page(viewport={'width': 1280, 'height': 800})
                page.goto(navigate_url, timeout=15_000, wait_until='load')
                page.wait_for_timeout(1500)
                data = page.screenshot(type='png')
                if len(data) <= THUMB_MAX_BYTES:
                    return data, 'image/png'
                log.warning("Screenshot for port %d too large (%d bytes)", port, len(data))
            except PWTimeout:
                log.warning("Screenshot timed out for port %d", port)
            finally:
                browser.close()
    except Exception as exc:
        log.warning("Screenshot failed for port %d: %s", port, exc)
    finally:
        _screenshot_sem.release()
    return None, None


def _fetch_image_bytes(img_url, port, allow_remote=False):
    if not allow_remote and not _is_localhost_url(img_url):
        return None, None
    try:
        img_r = requests.get(
            img_url,
            timeout=5,
            verify=False,
            stream=True,
            allow_redirects=True,
        )
        final_url = img_r.url or img_url
        if not allow_remote and not _is_localhost_url(final_url):
            return None, None
        if not img_r.ok:
            return None, None

        ct = img_r.headers.get('Content-Type', 'image/jpeg').split(';')[0].strip()
        if not ct.startswith('image/'):
            return None, None

        declared = int(img_r.headers.get('Content-Length', 0) or 0)
        if declared > THUMB_MAX_BYTES:
            log.warning("image for port %d too large (%d bytes)", port, declared)
            return None, None

        buf = bytearray()
        for chunk in img_r.iter_content(chunk_size=65536):
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) > THUMB_MAX_BYTES:
                log.warning("image for port %d exceeded size cap", port)
                return None, None

        if not buf:
            return None, None
        return bytes(buf), ct
    except Exception:
        return None, None


def fetch_thumbnail(port, service_url=None, allow_remote=False):
    """Try og:image/icon first, then fallback to screenshot."""
    try:
        base_url = _normalize_service_url(service_url, port) if service_url else _default_service_url(port)
    except ValueError:
        base_url = _default_service_url(port)
    final_url = base_url

    try:
        ok, error_class, r, final_url = _fetch_html_response(base_url, timeout=3, allow_remote=allow_remote)
        if not ok or r is None:
            if error_class and error_class not in ('non_html',):
                return _screenshot_service(port, base_url)
            return _screenshot_service(port, final_url or base_url)

        soup = BeautifulSoup(r.text, 'html.parser')

        og = (
            soup.find('meta', property='og:image') or
            soup.find('meta', attrs={'name': 'og:image'})
        )
        if og and og.get('content'):
            img_url = urljoin(final_url or base_url, og['content'])
            data, mime = _fetch_image_bytes(img_url, port, allow_remote=allow_remote)
            if data:
                return data, mime
            if not allow_remote and not _is_localhost_url(img_url):
                log.warning("Skipping non-localhost og:image for port %d: %s", port, img_url)

        icon = soup.find(
            'link',
            attrs={
                'rel': lambda rel: (
                    isinstance(rel, str) and 'icon' in rel.lower()
                ) or (
                    isinstance(rel, list) and any('icon' in str(part).lower() for part in rel)
                )
            },
        )
        if icon and icon.get('href'):
            icon_url = urljoin(final_url or base_url, icon.get('href'))
            data, mime = _fetch_image_bytes(icon_url, port, allow_remote=allow_remote)
            if data:
                return data, mime

        parsed_final = urlparse(final_url or base_url)
        origin = f"{parsed_final.scheme}://{parsed_final.netloc}"
        fallback_icons = [
            urljoin(final_url or base_url, 'favicon.ico'),
            urljoin(origin + '/', 'favicon.ico'),
            urljoin(origin + '/', 'apple-touch-icon.png'),
        ]
        seen = set()
        for candidate in fallback_icons:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            data, mime = _fetch_image_bytes(candidate, port, allow_remote=allow_remote)
            if data:
                return data, mime
    except Exception:
        pass
    return _screenshot_service(port, final_url or base_url)


def _refresh_service_preview(port, service_url):
    warnings = []
    next_title = None
    thumb_data = None
    thumb_mime = None

    try:
        ok, error_class, resp, final_url = _fetch_html_response(service_url, timeout=3, allow_remote=True)
        if ok and resp is not None:
            extracted = _extract_title(resp, port)
            if extracted and extracted != f":{port}":
                next_title = extracted
            else:
                browser_title = _browser_page_title(final_url or service_url)
                if browser_title:
                    next_title = browser_title
                else:
                    warnings.append("title not found at configured path")

            thumb_data, thumb_mime = fetch_thumbnail(port, final_url or service_url, allow_remote=True)
            if not thumb_data:
                warnings.append("thumbnail refresh failed")
        else:
            warnings.append(f"title refresh failed ({error_class or 'probe_failed'})")
            warnings.append("thumbnail refresh skipped")
    except Exception:
        warnings.append("title refresh failed (exception)")
        warnings.append("thumbnail refresh skipped")

    return next_title, thumb_data, thumb_mime, ('; '.join(warnings) if warnings else None)


def _build_uptime_buckets(checks, now):
    bucket_seconds = max(1, UPTIME_WINDOW_SECONDS // UPTIME_BUCKETS)
    buckets = [-1] * UPTIME_BUCKETS
    for ts, online in checks:
        age = now - int(ts)
        if age < 0 or age > UPTIME_WINDOW_SECONDS:
            continue
        idx = UPTIME_BUCKETS - 1 - int(age // bucket_seconds)
        if 0 <= idx < UPTIME_BUCKETS:
            if int(online) == 0:
                buckets[idx] = 0
            elif buckets[idx] == -1:
                buckets[idx] = 1
    return buckets


def _calc_uptime_pct(checks):
    if not checks:
        return None
    total = len(checks)
    up = sum(1 for _, online in checks if int(online) == 1)
    return round((up / total) * 100)


def stats_loop():
    while True:
        try:
            now = int(time.time())
            cpu = psutil.cpu_percent(interval=0.5)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            temp = get_temp()

            with _db_lock:
                conn = get_db()
                conn.execute(
                    "INSERT OR REPLACE INTO stats_history VALUES (?,?,?,?,?)",
                    (now, cpu, ram.percent, disk.percent, temp),
                )
                conn.execute("DELETE FROM stats_history WHERE ts < ?", (now - 86400,))
                conn.execute("DELETE FROM service_checks WHERE ts < ?", (now - UPTIME_WINDOW_SECONDS,))
                conn.execute("DELETE FROM events WHERE ts < ?", (now - (14 * 86400),))
                conn.commit()
                conn.close()
        except Exception as exc:
            log.error("stats_loop error: %s", exc)

        time.sleep(60)


def do_discovery(source='scheduled'):
    global _last_discovery, _last_uptime_check, _last_down_check, _scanning, _found

    try:
        now = int(time.time())
        _record_event("scan_start", details=f"source={source}")

        common_ports = {3001, 8080, 8443, 8888, 9090}
        ports_to_scan = sorted(set(range(2000, 10000, 100)) | common_ports)
        open_ports = []

        for port in ports_to_scan:
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.15)
                s.close()
                open_ports.append(port)
            except Exception:
                pass
            time.sleep(0.05)

        existing_probe_urls = {}
        with _db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT s.port, COALESCE(m.url, '') AS url "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port"
            ).fetchall()
            conn.close()
        for row in rows:
            existing_probe_urls[int(row['port'])] = _discovery_probe_url(int(row['port']), row['url'])

        discovered = {}
        for port in open_ports:
            probe_url = existing_probe_urls.get(port, _default_service_url(port))
            online, latency_ms, error_class, resp = _probe_http(probe_url, timeout=2.5, allow_remote=False)
            if not online:
                continue
            discovered[port] = {
                "title": _extract_title(resp, port),
                "latency_ms": latency_ms,
                "error_class": error_class,
                "url": probe_url,
            }

        now = int(time.time())
        refresh_cutoff = now - THUMB_REFRESH_DAYS * 86400
        expire_cutoff = now - EXPIRE_DAYS * 86400
        discovered_ports = set(discovered.keys())

        transitions = []
        existing = {}

        with _db_lock:
            conn = get_db()
            existing_rows = conn.execute(
                "SELECT s.port, s.title, s.is_online, s.thumb_ts, (s.thumb_data IS NOT NULL) AS has_thumb, "
                "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
                "COALESCE(m.critical, 0) AS critical "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port"
            ).fetchall()
            existing = {row['port']: dict(row) for row in existing_rows}

            for port, data in discovered.items():
                if port in existing:
                    conn.execute(
                        "UPDATE services SET title=?, last_seen=?, is_online=1, last_latency_ms=?, last_error=NULL WHERE port=?",
                        (data['title'], now, data['latency_ms'], port),
                    )
                else:
                    conn.execute(
                        "INSERT INTO services (port, title, first_seen, last_seen, is_online, last_latency_ms, last_error) "
                        "VALUES (?,?,?,?,1,?,NULL)",
                        (port, data['title'], now, now, data['latency_ms']),
                    )

                conn.execute(
                    "INSERT OR IGNORE INTO service_meta (port, url, critical, pinned_order, tags) VALUES (?,?,?,?,?)",
                    (port, data['url'], 0, port, ''),
                )

            for port in set(existing.keys()) - discovered_ports:
                conn.execute(
                    "UPDATE services SET is_online=0, last_error=?, last_latency_ms=NULL WHERE port=?",
                    ("not_responding", port),
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

        for port in discovered_ports:
            ex = existing.get(port, {})
            thumb_ts = ex.get('thumb_ts') or 0
            if ex.get('has_thumb') and thumb_ts >= refresh_cutoff:
                continue
            thumb_data, thumb_mime = fetch_thumbnail(port, discovered[port].get('url'))
            if thumb_data:
                with _db_lock:
                    conn = get_db()
                    conn.execute(
                        "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=? WHERE port=?",
                        (thumb_data, thumb_mime, int(time.time()), port),
                    )
                    conn.commit()
                    conn.close()

        for t in transitions:
            _handle_state_transition(**t)

        _last_discovery = now
        _last_uptime_check = now
        _last_down_check = now
        _found = len(discovered_ports)
        _record_event("scan_complete", details=f"source={source}; found={_found}")
        log.info("Discovery complete: %d HTTP services found", _found)
    except Exception as exc:
        log.exception("Discovery failed unexpectedly: %s", exc)
        _record_event("scan_failed", details=str(exc)[:200])
    finally:
        with _scan_lock:
            _scanning = False


def do_uptime_check(only_down=False):
    global _last_uptime_check, _last_down_check

    now = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400

    transitions = []
    thumb_candidates = []

    with _db_lock:
        conn = get_db()
        if only_down:
            rows = conn.execute(
                "SELECT s.port, s.title, s.is_online, (s.thumb_data IS NOT NULL) AS has_thumb, "
                "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
                "COALESCE(m.critical, 0) AS critical "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port "
                "WHERE s.last_seen >= ? AND s.is_online = 0",
                (expire_cutoff,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT s.port, s.title, s.is_online, (s.thumb_data IS NOT NULL) AS has_thumb, "
                "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
                "COALESCE(m.critical, 0) AS critical "
                "FROM services s LEFT JOIN service_meta m ON m.port = s.port "
                "WHERE s.last_seen >= ?",
                (expire_cutoff,),
            ).fetchall()

        for row in rows:
            port = int(row['port'])
            previous_online = int(row['is_online'] or 0)
            try:
                service_url = _normalize_service_url(row['url'], port)
                online, latency_ms, error_class, resp = _probe_http(service_url, timeout=2.0, allow_remote=True)
            except ValueError:
                service_url = _default_service_url(port)
                online = False
                latency_ms = None
                error_class = 'invalid_url'
                resp = None
            online_int = 1 if online else 0

            if online:
                title_update = _extract_title(resp, port) if resp is not None else ''
                if title_update and title_update != f":{port}":
                    conn.execute(
                        "UPDATE services SET title=?, is_online=1, last_seen=?, last_latency_ms=?, last_error=NULL WHERE port=?",
                        (title_update, now, latency_ms, port),
                    )
                else:
                    conn.execute(
                        "UPDATE services SET is_online=1, last_seen=?, last_latency_ms=?, last_error=NULL WHERE port=?",
                        (now, latency_ms, port),
                    )
                if not row['has_thumb']:
                    thumb_candidates.append((port, service_url))
            else:
                conn.execute(
                    "UPDATE services SET is_online=0, last_latency_ms=NULL, last_error=? WHERE port=?",
                    (error_class or 'probe_failed', port),
                )

            conn.execute(
                "INSERT OR REPLACE INTO service_checks (ts, port, online, latency_ms, error_class) VALUES (?,?,?,?,?)",
                (now, port, online_int, latency_ms, error_class),
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

        conn.commit()
        conn.close()

    for port, service_url in thumb_candidates:
        thumb_data, thumb_mime = fetch_thumbnail(port, service_url, allow_remote=True)
        if thumb_data:
            with _db_lock:
                conn = get_db()
                conn.execute(
                    "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=? WHERE port=?",
                    (thumb_data, thumb_mime, now, port),
                )
                conn.commit()
                conn.close()

    for t in transitions:
        _handle_state_transition(**t)

    _last_down_check = now
    if not only_down:
        _last_uptime_check = now

    log.info(
        "Uptime check complete (%s): %d services checked",
        'down-only' if only_down else 'all',
        len(rows),
    )


def scan_loop():
    global _scanning

    time.sleep(5)

    while True:
        now = int(time.time())

        if _last_discovery is None or now - _last_discovery >= 86400:
            with _scan_lock:
                if not _scanning:
                    _scanning = True
                    run_discovery = True
                else:
                    run_discovery = False
            if run_discovery:
                do_discovery(source='scheduled')
        elif _last_uptime_check is None or now - _last_uptime_check >= 300:
            do_uptime_check(only_down=False)
        elif _last_down_check is None or now - _last_down_check >= 60:
            do_uptime_check(only_down=True)

        time.sleep(10)


def trigger_discovery():
    global _scanning
    with _scan_lock:
        if _scanning:
            return False
        _scanning = True

    t = threading.Thread(target=lambda: do_discovery(source='manual'), daemon=True)
    t.start()
    return True


def _check_scan_rate_limit(client_key):
    now = int(time.time())
    with _rate_lock:
        recent = [ts for ts in _trigger_hits.get(client_key, []) if now - ts < TRIGGER_SCAN_WINDOW_SECONDS]
        if len(recent) >= TRIGGER_SCAN_RATE_LIMIT:
            retry_after = TRIGGER_SCAN_WINDOW_SECONDS - (now - recent[0])
            _trigger_hits[client_key] = recent
            return False, max(1, retry_after)
        recent.append(now)
        _trigger_hits[client_key] = recent
        return True, 0


def _service_meta_row(conn, port):
    row = conn.execute(
        "SELECT m.port, COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
        "COALESCE(m.critical, 0) AS critical, COALESCE(m.pinned_order, s.port) AS pinned_order, "
        "COALESCE(m.tags, '') AS tags "
        "FROM services s LEFT JOIN service_meta m ON m.port = s.port WHERE s.port = ?",
        (port,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d['url'] = _normalize_service_url(d.get('url'), port)
    d['path'] = _service_path_from_url(d['url'], port)
    d['tags'] = _parse_tags(d.get('tags'))
    d['critical'] = bool(d.get('critical'))
    return d


def _ensure_runtime_started():
    global _bg_started
    with _startup_lock:
        if _bg_started:
            return

        os.makedirs('/data', exist_ok=True)
        init_db()

        threading.Thread(target=stats_loop, daemon=True).start()
        threading.Thread(target=scan_loop, daemon=True).start()
        _bg_started = True


@app.route("/")
def index():
    return send_file("index.html", mimetype="text/html")


@app.route("/style.css")
def serve_css():
    return send_file("style.css", mimetype="text/css")


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
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    temp = get_temp()
    return jsonify({
        "cpu": cpu,
        "ram": ram.percent,
        "ram_used": ram.used,
        "ram_total": ram.total,
        "disk": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "temp": temp,
        "hostname": socket.gethostname(),
    })


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
            "SELECT s.port, s.title, s.first_seen, s.last_seen, s.is_online, "
            "(s.thumb_data IS NOT NULL) AS has_thumb, s.last_latency_ms, s.last_error, "
            "COALESCE(m.display_name, '') AS display_name, COALESCE(m.url, '') AS url, "
            "COALESCE(m.critical, 0) AS critical, COALESCE(m.pinned_order, s.port) AS pinned_order, "
            "COALESCE(m.tags, '') AS tags "
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
                (*ports, now - UPTIME_WINDOW_SECONDS),
            ).fetchall()
            for row in all_checks:
                checks_by_port[row['port']].append((row['ts'], row['online']))

        result = []
        for svc in services:
            checks = checks_by_port.get(svc['port'], [])
            effective_url = _normalize_service_url(svc['url'], svc['port'])
            result.append({
                "port": svc['port'],
                "title": svc['title'],
                "display_name": svc['display_name'] or None,
                "first_seen": svc['first_seen'],
                "last_seen": svc['last_seen'],
                "is_online": svc['is_online'],
                "has_thumb": svc['has_thumb'],
                "latency_ms": svc['last_latency_ms'],
                "last_error": svc['last_error'],
                "critical": bool(svc['critical']),
                "url": effective_url,
                "path": _service_path_from_url(effective_url, svc['port']),
                "tags": _parse_tags(svc['tags']),
                "pinned_order": svc['pinned_order'],
                "uptime_pct": _calc_uptime_pct(checks),
                "uptime_buckets": _build_uptime_buckets(checks, now),
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
    allowed_fields = {'display_name', 'url', 'path', 'critical', 'pinned_order', 'tags'}
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
            "SELECT display_name, url, critical, pinned_order, tags FROM service_meta WHERE port=?",
            (port,),
        ).fetchone()
        current = dict(current) if current else {
            "display_name": "",
            "url": _default_service_url(port),
            "critical": 0,
            "pinned_order": port,
            "tags": "",
        }

        next_display_name = current['display_name'] if 'display_name' not in payload else (payload.get('display_name') or '').strip()
        next_critical = int(bool(current['critical'])) if 'critical' not in payload else int(bool(payload.get('critical')))
        try:
            next_pinned_order = int(current['pinned_order']) if 'pinned_order' not in payload else int(payload.get('pinned_order'))
        except (TypeError, ValueError):
            conn.close()
            return jsonify({"error": "pinned_order must be an integer"}), 400
        next_tags = current['tags'] if 'tags' not in payload else _tags_to_db(payload.get('tags'))

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
            "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(port) DO UPDATE SET display_name=excluded.display_name, url=excluded.url, "
            "critical=excluded.critical, pinned_order=excluded.pinned_order, tags=excluded.tags",
            (port, next_display_name, next_url, next_critical, next_pinned_order, next_tags),
        )
        conn.commit()
        conn.close()

    refreshed_title, refreshed_thumb_data, refreshed_thumb_mime, refresh_warning = _refresh_service_preview(port, next_url)

    with _db_lock:
        conn = get_db()
        if refreshed_title:
            conn.execute("UPDATE services SET title=? WHERE port=?", (refreshed_title, port))
        if refreshed_thumb_data:
            conn.execute(
                "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=? WHERE port=?",
                (refreshed_thumb_data, refreshed_thumb_mime, int(time.time()), port),
            )
        conn.commit()
        row = _service_meta_row(conn, port)
        conn.close()

    _record_event('meta_updated', port=port, details='service metadata updated')
    payload = dict(row or {})
    payload['refresh_warning'] = refresh_warning
    return jsonify(payload)


@app.route("/api/thumbnail/<int:port>")
def api_thumbnail(port):
    with _db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT thumb_data, thumb_mime FROM services WHERE port=?",
            (port,),
        ).fetchone()
        conn.close()

    if row and row['thumb_data']:
        resp = make_response(bytes(row['thumb_data']))
        resp.headers['Content-Type'] = row['thumb_mime'] or 'image/jpeg'
        resp.headers['Cache-Control'] = 'public, max-age=300'
        return resp

    return '', 404


@app.route("/api/scan-status")
def api_scan_status():
    return jsonify({
        "last_discovery": _last_discovery,
        "last_uptime_check": _last_uptime_check,
        "last_down_check": _last_down_check,
        "scanning": _scanning,
        "found": _found,
    })


@app.route("/api/trigger-scan", methods=["POST"])
def api_trigger_scan():
    client_key = request.remote_addr or 'unknown'
    allowed, retry_after = _check_scan_rate_limit(client_key)
    if not allowed:
        return jsonify({"started": False, "reason": "rate_limited", "retry_after": retry_after}), 429

    started = trigger_discovery()
    if started:
        return jsonify({"started": True})
    return jsonify({"started": False, "reason": "already_scanning"}), 429


if os.environ.get('DISABLE_BACKGROUND', '0') != '1':
    _ensure_runtime_started()


if __name__ == "__main__":
    _ensure_runtime_started()
    app.run(host="0.0.0.0", port=80)
