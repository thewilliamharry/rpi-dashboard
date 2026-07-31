"""Validated immutable process settings for Beacon composition roots."""

from dataclasses import dataclass
import ipaddress
import os
import socket
from typing import Mapping


DEFAULT_TRUSTED_HOSTS = (
    'raspi.local,raspi,localhost,127.0.0.1,::1,'
    '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7'
)

# Outbound network policy deliberately has its own defaults.  Browser Host and
# Origin validation describe who may talk *to* Beacon; they are not a permit to
# make Beacon talk to the same addresses.
DEFAULT_SERVICE_TARGET_HOSTS = 'raspi.local,raspi,localhost,127.0.0.1,::1'
DEFAULT_SERVICE_TARGET_NETWORKS = (
    '127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,'
    '192.168.0.0/16,100.64.0.0/10,fc00::/7'
)


@dataclass(frozen=True)
class Settings:
    db_path: str = '/data/dashboard.db'
    expire_days: int = 7
    thumb_refresh_days: int = 1
    metric_sample_seconds: int = 5
    metric_history_seconds: int = 60
    worker_ready_seconds: int = 20
    discovery_timeout_seconds: int = 180
    enable_prometheus: bool = False
    trusted_hosts: frozenset[str] = frozenset()
    trusted_host_networks: tuple = ()
    local_service_hosts: frozenset[str] = frozenset()
    service_target_hosts: frozenset[str] = frozenset()
    service_target_networks: tuple = ()
    extra_scan_ports: frozenset[int] = frozenset({8100})
    trigger_scan_rate_limit: int = 4
    trigger_scan_window_seconds: int = 60
    alert_webhook_url: str = ''
    alert_cooldown_seconds: int = 300
    alert_only_critical: bool = False


def _positive_int(environ, key, default):
    try:
        value = int(environ.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _enabled(value):
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


def _trusted_hosts(value):
    hosts = set()
    networks = []
    for raw_item in str(value).split(','):
        item = raw_item.strip().lower().strip('[]')
        if not item:
            continue
        if '/' in item:
            networks.append(ipaddress.ip_network(item, strict=False))
        else:
            hosts.add(item)
    return frozenset(hosts), tuple(networks)


def _scan_ports(value):
    ports = set()
    for raw_item in str(value).split(','):
        try:
            port = int(raw_item.strip())
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return frozenset(ports)


def _outbound_hosts(value):
    return frozenset(
        item.strip().lower().strip('[]').rstrip('.')
        for item in str(value).split(',')
        if item.strip()
    )


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Load deployment strings once, retaining historical defaults on bad values."""
    source = os.environ if environ is None else environ
    trusted_hosts, trusted_networks = _trusted_hosts(
        source.get('TRUSTED_HOSTS', DEFAULT_TRUSTED_HOSTS)
    )
    local_hosts = {
        item.strip().lower().strip('[]')
        for item in source.get('LOCAL_SERVICE_HOSTS', '').split(',')
        if item.strip()
    }
    local_hosts.update(trusted_hosts)
    try:
        local_hosts.add(socket.gethostname().lower())
    except Exception:
        pass
    service_hosts = _outbound_hosts(
        source.get('SERVICE_TARGET_HOSTS', DEFAULT_SERVICE_TARGET_HOSTS)
    )
    _, service_networks = _trusted_hosts(
        source.get('SERVICE_TARGET_NETWORKS', DEFAULT_SERVICE_TARGET_NETWORKS)
    )
    return Settings(
        db_path=source.get('DB_PATH', '/data/dashboard.db'),
        expire_days=_positive_int(source, 'EXPIRE_DAYS', 7),
        thumb_refresh_days=_positive_int(source, 'THUMB_REFRESH_DAYS', 1),
        metric_sample_seconds=_positive_int(source, 'METRIC_SAMPLE_SECONDS', 5),
        metric_history_seconds=_positive_int(source, 'METRIC_HISTORY_SECONDS', 60),
        worker_ready_seconds=_positive_int(source, 'WORKER_READY_SECONDS', 20),
        discovery_timeout_seconds=_positive_int(source, 'DISCOVERY_TIMEOUT_SECONDS', 180),
        enable_prometheus=_enabled(source.get('ENABLE_PROMETHEUS', '0')),
        trusted_hosts=trusted_hosts,
        trusted_host_networks=trusted_networks,
        local_service_hosts=frozenset(local_hosts),
        service_target_hosts=service_hosts,
        service_target_networks=service_networks,
        extra_scan_ports=_scan_ports(source.get('EXTRA_SCAN_PORTS', '8100')),
        trigger_scan_rate_limit=_positive_int(source, 'TRIGGER_SCAN_RATE_LIMIT', 4),
        trigger_scan_window_seconds=_positive_int(source, 'TRIGGER_SCAN_WINDOW_SECONDS', 60),
        alert_webhook_url=source.get('ALERT_WEBHOOK_URL', '').strip(),
        alert_cooldown_seconds=_positive_int(source, 'ALERT_COOLDOWN_SECONDS', 300),
        alert_only_critical=_enabled(source.get('ALERT_ONLY_CRITICAL', '0')),
    )
