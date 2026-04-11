import contextlib
import http.server
import importlib
import os
import socketserver
import sys
import tempfile
import threading
import types


def _ensure_psutil_stub():
    try:
        import psutil  # noqa: F401
        return
    except Exception:
        pass

    stub = types.ModuleType('psutil')

    class _Mem:
        percent = 42.0
        used = 1024 * 1024 * 256
        total = 1024 * 1024 * 1024

    class _Disk:
        percent = 55.0
        used = 1024 * 1024 * 1024 * 2
        total = 1024 * 1024 * 1024 * 8

    def _cpu_percent(interval=0.5):
        return 12.0

    def _virtual_memory():
        return _Mem()

    def _disk_usage(path):
        return _Disk()

    def _sensors_temperatures():
        return {}

    stub.cpu_percent = _cpu_percent
    stub.virtual_memory = _virtual_memory
    stub.disk_usage = _disk_usage
    stub.sensors_temperatures = _sensors_temperatures
    sys.modules['psutil'] = stub


def load_app(extra_env=None):
    env = {
        'DISABLE_BACKGROUND': '1',
        'TRIGGER_SCAN_TOKEN': 'test-token',
        'TRIGGER_SCAN_RATE_LIMIT': '2',
        'TRIGGER_SCAN_WINDOW_SECONDS': '60',
        'ALERT_WEBHOOK_URL': '',
        'ALERT_COOLDOWN_SECONDS': '60',
        'ALERT_ONLY_CRITICAL': '0',
        'EXPIRE_DAYS': '7',
    }
    if extra_env:
        for key, value in extra_env.items():
            env[key] = str(value)

    for key, value in env.items():
        os.environ[key] = value

    _ensure_psutil_stub()

    fd, db_path = tempfile.mkstemp(prefix='beacon-test-', suffix='.db')
    os.close(fd)

    import dashboard.app as appmod
    appmod = importlib.reload(appmod)
    appmod.DB_PATH = db_path

    appmod._trigger_hits.clear()
    appmod._last_discovery = None
    appmod._last_uptime_check = None
    appmod._last_down_check = None
    appmod._scanning = False
    appmod._found = 0

    appmod.init_db()
    return appmod, db_path


def cleanup_db(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def run_server(handler_cls):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
