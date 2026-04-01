import logging
import os
import time
import socket
import threading
import sqlite3

import psutil
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from flask import Flask, jsonify, send_file, request, make_response

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)

app = Flask(__name__)

DB_PATH     = "/data/dashboard.db"
EXPIRE_DAYS = int(os.environ.get("EXPIRE_DAYS", 7))
THUMB_MAX_BYTES    = 2 * 1024 * 1024  # 2 MB cap on thumbnail images
THUMB_REFRESH_DAYS = 1                # re-screenshot existing thumbnails after this many days

_db_lock        = threading.Lock()
_scan_lock      = threading.Lock()   # guards _scanning state transitions
_screenshot_sem = threading.Semaphore(1)  # max 1 Chromium instance at a time

# Scan state
_last_discovery    = None
_last_uptime_check = None
_last_down_check   = None
_scanning          = False
_found             = 0


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db_lock:
        conn = get_db()
        conn.execute("PRAGMA journal_mode=WAL")   # set once; persists in the DB file
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS stats_history (
                ts      INTEGER PRIMARY KEY,
                cpu     REAL,
                ram     REAL,
                disk    REAL,
                temp    REAL
            );
            CREATE TABLE IF NOT EXISTS services (
                port        INTEGER PRIMARY KEY,
                title       TEXT,
                first_seen  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                is_online   INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS service_checks (
                ts      INTEGER,
                port    INTEGER,
                online  INTEGER,
                PRIMARY KEY (ts, port)
            );
            CREATE INDEX IF NOT EXISTS idx_stats_ts    ON stats_history(ts);
            CREATE INDEX IF NOT EXISTS idx_checks_ts   ON service_checks(ts);
            CREATE INDEX IF NOT EXISTS idx_checks_port ON service_checks(port);
        """)
        conn.commit()

        # Migrate: add thumbnail columns if they don't exist yet
        cols = [r[1] for r in conn.execute("PRAGMA table_info(services)").fetchall()]
        if 'thumb_data' not in cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_data BLOB")
        if 'thumb_mime' not in cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_mime TEXT DEFAULT 'image/jpeg'")
        if 'thumb_ts' not in cols:
            conn.execute("ALTER TABLE services ADD COLUMN thumb_ts INTEGER")
        conn.commit()
        conn.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_temp():
    try:
        temps = psutil.sensors_temperatures()
        for key in ["cpu_thermal", "coretemp", "cpu-thermal", "bcm2835_thermal"]:
            if key in temps and temps[key]:
                return temps[key][0].current
    except Exception:
        pass
    return None


def _is_localhost(url: str) -> bool:
    """Return True only if the URL resolves to a loopback address."""
    try:
        host = urlparse(url).hostname or ''
        return host in ('127.0.0.1', 'localhost', '::1')
    except Exception:
        return False


def _screenshot_service(port: int):
    """Launch a headless Chromium browser and screenshot the service homepage.
    Capped to one concurrent instance via _screenshot_sem so the Pi isn't
    overwhelmed during a discovery run with many services.
    Returns (png_bytes, 'image/png') or (None, None).
    """
    if not _screenshot_sem.acquire(blocking=False):
        log.info("Screenshot for port %d deferred — another screenshot already in progress", port)
        return None, None
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        with sync_playwright() as p:
            browser = p.chromium.launch(
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            try:
                page = browser.new_page(viewport={'width': 1280, 'height': 800})
                page.goto(
                    f'http://127.0.0.1:{port}/',
                    timeout=15_000,
                    wait_until='load',
                )
                # Give JS-heavy SPAs a moment to render after load fires,
                # without getting stuck waiting on open WebSocket/polling connections
                page.wait_for_timeout(1500)
                data = page.screenshot(type='png')
                if len(data) <= THUMB_MAX_BYTES:
                    log.info("Screenshot captured for port %d (%d bytes)", port, len(data))
                    return data, 'image/png'
                log.warning("Screenshot for port %d too large (%d bytes), skipping", port, len(data))
            except PWTimeout:
                log.warning("Screenshot timed out for port %d", port)
            finally:
                browser.close()
    except Exception as e:
        log.warning("Screenshot failed for port %d: %s", port, e)
    finally:
        _screenshot_sem.release()
    return None, None


def fetch_thumbnail(port):
    """Try to fetch og:image for a service. Returns (bytes, mime) or (None, None)."""
    try:
        r = requests.get(
            f"http://127.0.0.1:{port}/",
            timeout=3, verify=False, allow_redirects=True
        )
        if 'text/html' not in r.headers.get('Content-Type', ''):
            # Not HTML — can't parse og:image, but can still screenshot it
            return _screenshot_service(port)
        soup = BeautifulSoup(r.text, 'html.parser')
        og = (
            soup.find('meta', property='og:image') or
            soup.find('meta', attrs={'name': 'og:image'})
        )
        if og and og.get('content'):
            img_url = urljoin(f"http://127.0.0.1:{port}/", og['content'])
            # SSRF guard: only follow URLs that stay on localhost.
            # If the og:image points to an external CDN, skip it and fall
            # through to the screenshot path below instead of returning empty.
            if _is_localhost(img_url):
                img_r = requests.get(img_url, timeout=5, verify=False, stream=True)
                if img_r.ok:
                    ct = img_r.headers.get('Content-Type', 'image/jpeg').split(';')[0].strip()
                    if ct.startswith('image/'):
                        # Size cap: reject images larger than THUMB_MAX_BYTES.
                        # Check Content-Length header first (fast path), then stream
                        # in 64 KB chunks and abort early if the limit is crossed.
                        declared = int(img_r.headers.get('Content-Length', 0))
                        if declared > THUMB_MAX_BYTES:
                            log.warning("og:image for port %d too large (%d bytes), skipping", port, declared)
                        else:
                            buf = bytearray()
                            for chunk in img_r.iter_content(chunk_size=65536):
                                if not chunk:
                                    continue
                                buf.extend(chunk)
                                if len(buf) > THUMB_MAX_BYTES:
                                    log.warning("og:image for port %d exceeded size cap, skipping", port)
                                    buf = None
                                    break
                            if buf:
                                return bytes(buf), ct
            else:
                log.warning("Skipping non-localhost og:image for port %d: %s", port, img_url)
    except Exception:
        pass
    # og:image not found or fetch failed — fall back to headless screenshot
    return _screenshot_service(port)


# ── Background: stats_loop ────────────────────────────────────────────────────

def stats_loop():
    while True:
        try:
            now  = int(time.time())
            cpu  = psutil.cpu_percent(interval=0.5)
            ram  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            temp = get_temp()

            with _db_lock:
                conn = get_db()
                conn.execute(
                    "INSERT OR REPLACE INTO stats_history VALUES (?,?,?,?,?)",
                    (now, cpu, ram.percent, disk.percent, temp)
                )
                conn.execute("DELETE FROM stats_history WHERE ts < ?", (now - 86400,))
                conn.execute("DELETE FROM service_checks WHERE ts < ?", (now - 604800,))
                conn.commit()
                conn.close()
        except Exception as e:
            log.error("stats_loop error: %s", e)

        time.sleep(60)


# ── Background: scan_loop ─────────────────────────────────────────────────────

def do_discovery():
    global _last_discovery, _scanning, _found

    # Scan every 100th port from 2000–9900, plus common self-hosted service
    # ports that fall in the gaps (8080, 8443, 8888, 9090, 3001, etc.)
    _COMMON_PORTS = {3001, 8080, 8443, 8888, 9090}
    ports_to_scan = sorted(set(range(2000, 10000, 100)) | _COMMON_PORTS)
    open_ports = []

    for port in ports_to_scan:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.15)
            s.close()
            open_ports.append(port)
        except Exception:
            pass
        time.sleep(1)   # always sleep, even for closed ports

    http_ports  = []
    port_titles = {}

    for port in open_ports:
        try:
            r = requests.get(
                f"http://127.0.0.1:{port}",
                timeout=2.5, verify=False, allow_redirects=True
            )
            soup  = BeautifulSoup(r.text, "html.parser")
            title = soup.title.get_text(strip=True) if soup.title else ""
            title = title or f":{port}"
            http_ports.append(port)
            port_titles[port] = title
        except Exception:
            pass  # closed or not HTTP — do not upsert

    now           = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400
    http_set      = set(http_ports)

    with _db_lock:
        conn = get_db()
        # Fetch existing services WITHOUT loading thumb_data BLOBs into memory
        existing = {
            row["port"]: dict(row)
            for row in conn.execute(
                "SELECT port, title, first_seen, last_seen, is_online,"
                " thumb_mime, thumb_ts, (thumb_data IS NOT NULL) AS has_thumb"
                " FROM services"
            ).fetchall()
        }

        # Upsert HTTP-responding ports — UPDATE if known, INSERT if new.
        # Using UPDATE/INSERT instead of INSERT OR REPLACE avoids deleting the
        # existing row (which would destroy the stored thumbnail BLOB).
        for port in http_ports:
            if port in existing:
                conn.execute(
                    "UPDATE services SET title=?, last_seen=?, is_online=1 WHERE port=?",
                    (port_titles[port], now, port)
                )
            else:
                conn.execute(
                    "INSERT INTO services (port, title, first_seen, last_seen, is_online)"
                    " VALUES (?,?,?,?,1)",
                    (port, port_titles[port], now, now)
                )

        # Mark missing services offline
        for port in set(existing.keys()) - http_set:
            conn.execute("UPDATE services SET is_online=0 WHERE port=?", (port,))

        # Record check for every known port
        all_known = set(existing.keys()) | http_set
        for port in all_known:
            online = 1 if port in http_set else 0
            conn.execute(
                "INSERT OR REPLACE INTO service_checks (ts, port, online) VALUES (?,?,?)",
                (now, port, online)
            )

        # Expire old services
        conn.execute("DELETE FROM services WHERE last_seen < ?", (expire_cutoff,))
        conn.commit()
        conn.close()

    # Fetch thumbnails: new services always get one; existing thumbnails are
    # refreshed if they are older than THUMB_REFRESH_DAYS.
    refresh_cutoff = now - THUMB_REFRESH_DAYS * 86400
    for port in http_ports:
        ex = existing.get(port, {})
        thumb_ts = ex.get('thumb_ts') or 0
        if ex.get('has_thumb') and thumb_ts >= refresh_cutoff:
            continue  # thumbnail exists and is recent enough
        thumb_data, thumb_mime = fetch_thumbnail(port)
        if thumb_data:
            with _db_lock:
                conn = get_db()
                conn.execute(
                    "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=? WHERE port=?",
                    (thumb_data, thumb_mime, int(time.time()), port)
                )
                conn.commit()
                conn.close()

    _last_discovery    = now
    # Discovery already probed every port, so treat it as an uptime check too
    _last_uptime_check = now
    _last_down_check   = now
    _scanning          = False
    _found             = len(http_ports)
    log.info("Discovery complete: %d HTTP services found", _found)


def do_uptime_check(only_down=False):
    global _last_uptime_check, _last_down_check

    now           = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400

    with _db_lock:
        conn  = get_db()
        if only_down:
            rows = conn.execute(
                "SELECT port, (thumb_data IS NOT NULL) AS has_thumb"
                " FROM services WHERE last_seen >= ? AND is_online = 0",
                (expire_cutoff,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT port, (thumb_data IS NOT NULL) AS has_thumb"
                " FROM services WHERE last_seen >= ?",
                (expire_cutoff,)
            ).fetchall()
        ports_info = [(row[0], row[1]) for row in rows]
        conn.close()

    for port, has_thumb in ports_info:
        try:
            requests.get(f"http://127.0.0.1:{port}", timeout=2.0, verify=False)
            online = 1
        except Exception:
            online = 0

        with _db_lock:
            conn = get_db()
            if online:
                # Bump last_seen only when online so offline services age toward expiry
                conn.execute(
                    "UPDATE services SET is_online=1, last_seen=? WHERE port=?",
                    (now, port)
                )
            else:
                conn.execute("UPDATE services SET is_online=0 WHERE port=?", (port,))
            conn.execute(
                "INSERT OR REPLACE INTO service_checks (ts, port, online) VALUES (?,?,?)",
                (now, port, online)
            )
            conn.commit()
            conn.close()

        # Fetch/refresh thumbnail if service is back online and has no thumbnail yet
        if online and not has_thumb:
            thumb_data, thumb_mime = fetch_thumbnail(port)
            if thumb_data:
                with _db_lock:
                    conn = get_db()
                    conn.execute(
                        "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=? WHERE port=?",
                        (thumb_data, thumb_mime, now, port)
                    )
                    conn.commit()
                    conn.close()

    _last_down_check = now
    if not only_down:
        _last_uptime_check = now
    log.info(
        "Uptime check complete (%s): %d services checked",
        'down-only' if only_down else 'all',
        len(ports_info),
    )


def scan_loop():
    global _scanning

    time.sleep(5)   # give Flask a moment to start

    while True:
        now = int(time.time())

        if _last_discovery is None or now - _last_discovery >= 86400:
            with _scan_lock:
                _scanning = True
            try:
                do_discovery()
            except Exception as e:
                log.error("Discovery failed unexpectedly: %s", e)
                _scanning = False
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
    t = threading.Thread(target=do_discovery, daemon=True)
    t.start()
    return True


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_file("index.html", mimetype="text/html")


@app.route("/style.css")
def serve_css():
    return send_file("style.css", mimetype="text/css")


@app.route("/api/stats")
def api_stats():
    cpu  = psutil.cpu_percent(interval=0.5)
    ram  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    temp = get_temp()
    return jsonify({
        "cpu":       cpu,
        "ram":       ram.percent,
        "ram_used":  ram.used,
        "ram_total": ram.total,
        "disk":      disk.percent,
        "disk_used": disk.used,
        "disk_total":disk.total,
        "temp":      temp,
        "hostname":  socket.gethostname(),
    })


@app.route("/api/history")
def api_history():
    now = int(time.time())
    with _db_lock:
        conn = get_db()
        rows = conn.execute(
            "SELECT ts, cpu, ram, disk, temp FROM stats_history"
            " WHERE ts >= ? ORDER BY ts ASC",
            (now - 86400,)
        ).fetchall()
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/services")
def api_services():
    now           = int(time.time())
    expire_cutoff = now - EXPIRE_DAYS * 86400

    with _db_lock:
        conn     = get_db()
        services = conn.execute(
            "SELECT port, title, first_seen, last_seen, is_online,"
            " (thumb_data IS NOT NULL) AS has_thumb FROM services"
            " WHERE last_seen >= ? ORDER BY port ASC",
            (expire_cutoff,)
        ).fetchall()

        if services:
            # Fetch all checks for all known ports in a single query
            # instead of one query per service (avoids N+1 pattern)
            ports = [s["port"] for s in services]
            placeholders = ",".join("?" * len(ports))
            all_checks = conn.execute(
                f"SELECT ts, port, online FROM service_checks"
                f" WHERE port IN ({placeholders}) AND ts >= ? ORDER BY port ASC, ts ASC",
                (*ports, now - 604800)
            ).fetchall()
            # Group checks by port
            checks_by_port: dict = {}
            for c in all_checks:
                checks_by_port.setdefault(c["port"], []).append(
                    {"ts": c["ts"], "online": c["online"]}
                )
        else:
            checks_by_port = {}

        result = []
        for svc in services:
            d = dict(svc)
            d["checks"] = checks_by_port.get(svc["port"], [])
            result.append(d)
        conn.close()
    return jsonify(result)


@app.route("/api/thumbnail/<int:port>")
def api_thumbnail(port):
    with _db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT thumb_data, thumb_mime FROM services WHERE port=?", (port,)
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
        "last_discovery":    _last_discovery,
        "last_uptime_check": _last_uptime_check,
        "scanning":          _scanning,
        "found":             _found,
    })


@app.route("/api/trigger-scan", methods=["POST"])
def api_trigger_scan():
    started = trigger_discovery()
    if started:
        return jsonify({"started": True})
    return jsonify({"started": False, "reason": "already scanning"}), 429


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("/data", exist_ok=True)
    init_db()

    threading.Thread(target=stats_loop, daemon=True).start()
    threading.Thread(target=scan_loop,  daemon=True).start()

    app.run(host="0.0.0.0", port=80)
