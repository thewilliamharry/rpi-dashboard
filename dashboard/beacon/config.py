"""Validated immutable process settings for Beacon composition roots."""

from dataclasses import dataclass
import ipaddress
import os
import socket
from typing import Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


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
    # THUMB_REFRESH_DAYS=1 means a live, discoverable service has its preview
    # re-captured daily, so a 7-day TTL survives six consecutive missed
    # refresh cycles -- a week of worker downtime or an unreachable service --
    # before evicting. It also equals expire_days=7, the horizon after which a
    # service disappears from /api/services entirely, so a thumbnail can never
    # outlive its own service's visibility window (D-02).
    thumbnail_ttl_days: int = 7
    # Worst case without a budget is THUMB_MAX_BYTES (2 MiB) times the ~85
    # ports the discovery sweep can find, roughly 170 MiB on a Pi whose whole
    # telemetry store is capped at telemetry_db_max_bytes = 536_870_912. 64
    # MiB matches the existing telemetry_backlog_reserve_bytes reserve, holds
    # ~32 full-size captures, and keeps the preview store an order of
    # magnitude below the telemetry store it shares a disk with (D-02).
    thumbnail_store_max_bytes: int = 67_108_864
    # D-02: 3 attempts (one initial + two retries) bounds one preview request's
    # worst-case browser occupancy at roughly 3 x PREVIEW_BROWSER_BUDGET_MS
    # (27s) = ~81s, small against the request's own 1800s deadline_ts.
    preview_max_attempts: int = 3
    # D-02: 60s base, doubling per attempt (mirrors the existing
    # telemetry_retry_base_seconds/telemetry_retry_max_seconds exponential-
    # with-cap shape, scaled down because a preview is cheaper and far more
    # visible to the operator than a telemetry rollup). With 3 attempts the
    # total backoff is 60 + 120 = 180s, so the whole retry sequence finishes
    # well inside the 1800s deadline.
    preview_retry_base_seconds: int = 60
    # D-02: 600s cap on the same doubling curve; only binds if an operator
    # raises preview_max_attempts.
    preview_retry_max_seconds: int = 600
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
    telemetry_raw_days: int = 7
    telemetry_five_minute_days: int = 30
    telemetry_retention_days: int = 90
    telemetry_point_budget: int = 2048
    telemetry_db_max_bytes: int = 536_870_912
    telemetry_min_free_bytes: int = 1_073_741_824
    telemetry_pressure_warning_percent: int = 80
    telemetry_pressure_hard_percent: int = 90
    telemetry_pressure_recovery_percent: int = 75
    telemetry_backlog_reserve_bytes: int = 67_108_864
    telemetry_rollup_batch_buckets: int = 32
    telemetry_retry_base_seconds: int = 300
    telemetry_retry_max_seconds: int = 3_600
    timezone: str = 'UTC'
    maintenance_default_grace_minutes: int = 15
    maintenance_windows_per_port_max: int = 50
    # A newly-down service is invisible to the 60s down-only sweep (J4) until
    # the 300s full sweep (J3) catches the flip, so two independently-sampled
    # observations of one true restart time can differ by roughly 300s from
    # polling jitter alone. 900s is a deliberate margin over that noise floor.
    maintenance_start_tolerance_seconds: int = 900
    # Observed durations compound both sides' sampling jitter (up to ~300s on
    # the down side, ~60s on the recovery side), so two measurements of one
    # true restart duration can differ by roughly 360s. 600s is a deliberate
    # margin over that noise floor.
    maintenance_duration_tolerance_seconds: int = 600
    # Long enough to plausibly accumulate three occurrences of a genuinely
    # daily pattern without waiting a full month; short enough to satisfy
    # D-12's "actually been doing lately" framing (RESEARCH A2).
    maintenance_suggestion_lookback_days: int = 21


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


def _resolved_timezone(value):
    """Fail closed to UTC on an empty, malformed, or unresolvable IANA zone name."""
    name = str(value or '').strip()
    if not name:
        return 'UTC'
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return 'UTC'
    return name


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
    telemetry_defaults = {
        'raw_days': 7,
        'five_minute_days': 30,
        'retention_days': 90,
        'point_budget': 2048,
        'db_max_bytes': 536_870_912,
        'min_free_bytes': 1_073_741_824,
        'warning_percent': 80,
        'hard_percent': 90,
        'recovery_percent': 75,
        'backlog_reserve_bytes': 67_108_864,
        'rollup_batch_buckets': 32,
        'retry_base_seconds': 300,
        'retry_max_seconds': 3_600,
    }
    telemetry = {
        'raw_days': _positive_int(source, 'TELEMETRY_RAW_DAYS', telemetry_defaults['raw_days']),
        'five_minute_days': _positive_int(
            source, 'TELEMETRY_FIVE_MINUTE_DAYS', telemetry_defaults['five_minute_days'],
        ),
        'retention_days': _positive_int(
            source, 'TELEMETRY_RETENTION_DAYS', telemetry_defaults['retention_days'],
        ),
        'point_budget': _positive_int(
            source, 'TELEMETRY_POINT_BUDGET', telemetry_defaults['point_budget'],
        ),
        'db_max_bytes': _positive_int(
            source, 'TELEMETRY_DB_MAX_BYTES', telemetry_defaults['db_max_bytes'],
        ),
        'min_free_bytes': _positive_int(
            source, 'TELEMETRY_MIN_FREE_BYTES', telemetry_defaults['min_free_bytes'],
        ),
        'warning_percent': _positive_int(
            source, 'TELEMETRY_PRESSURE_WARNING_PERCENT', telemetry_defaults['warning_percent'],
        ),
        'hard_percent': _positive_int(
            source, 'TELEMETRY_PRESSURE_HARD_PERCENT', telemetry_defaults['hard_percent'],
        ),
        'recovery_percent': _positive_int(
            source, 'TELEMETRY_PRESSURE_RECOVERY_PERCENT', telemetry_defaults['recovery_percent'],
        ),
        'backlog_reserve_bytes': _positive_int(
            source, 'TELEMETRY_BACKLOG_RESERVE_BYTES', telemetry_defaults['backlog_reserve_bytes'],
        ),
        'rollup_batch_buckets': _positive_int(
            source, 'TELEMETRY_ROLLUP_BATCH_BUCKETS', telemetry_defaults['rollup_batch_buckets'],
        ),
        'retry_base_seconds': _positive_int(
            source, 'TELEMETRY_RETRY_BASE_SECONDS', telemetry_defaults['retry_base_seconds'],
        ),
        'retry_max_seconds': _positive_int(
            source, 'TELEMETRY_RETRY_MAX_SECONDS', telemetry_defaults['retry_max_seconds'],
        ),
    }
    if not telemetry['raw_days'] < telemetry['five_minute_days'] < telemetry['retention_days']:
        telemetry.update({key: telemetry_defaults[key] for key in (
            'raw_days', 'five_minute_days', 'retention_days',
        )})
    if not (
        0 < telemetry['recovery_percent'] < telemetry['warning_percent']
        < telemetry['hard_percent'] <= 100
    ):
        telemetry.update({key: telemetry_defaults[key] for key in (
            'warning_percent', 'hard_percent', 'recovery_percent',
        )})
    if telemetry['retry_base_seconds'] > telemetry['retry_max_seconds']:
        telemetry.update({key: telemetry_defaults[key] for key in (
            'retry_base_seconds', 'retry_max_seconds',
        )})
    return Settings(
        db_path=source.get('DB_PATH', '/data/dashboard.db'),
        expire_days=_positive_int(source, 'EXPIRE_DAYS', 7),
        thumb_refresh_days=_positive_int(source, 'THUMB_REFRESH_DAYS', 1),
        thumbnail_ttl_days=_positive_int(source, 'THUMBNAIL_TTL_DAYS', 7),
        thumbnail_store_max_bytes=_positive_int(
            source, 'THUMBNAIL_STORE_MAX_BYTES', 67_108_864,
        ),
        preview_max_attempts=_positive_int(source, 'PREVIEW_MAX_ATTEMPTS', 3),
        preview_retry_base_seconds=_positive_int(source, 'PREVIEW_RETRY_BASE_SECONDS', 60),
        preview_retry_max_seconds=_positive_int(source, 'PREVIEW_RETRY_MAX_SECONDS', 600),
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
        telemetry_raw_days=telemetry['raw_days'],
        telemetry_five_minute_days=telemetry['five_minute_days'],
        telemetry_retention_days=telemetry['retention_days'],
        telemetry_point_budget=telemetry['point_budget'],
        telemetry_db_max_bytes=telemetry['db_max_bytes'],
        telemetry_min_free_bytes=telemetry['min_free_bytes'],
        telemetry_pressure_warning_percent=telemetry['warning_percent'],
        telemetry_pressure_hard_percent=telemetry['hard_percent'],
        telemetry_pressure_recovery_percent=telemetry['recovery_percent'],
        telemetry_backlog_reserve_bytes=telemetry['backlog_reserve_bytes'],
        telemetry_rollup_batch_buckets=telemetry['rollup_batch_buckets'],
        telemetry_retry_base_seconds=telemetry['retry_base_seconds'],
        telemetry_retry_max_seconds=telemetry['retry_max_seconds'],
        timezone=_resolved_timezone(source.get('TZ', 'UTC')),
        maintenance_default_grace_minutes=_positive_int(
            source, 'MAINTENANCE_DEFAULT_GRACE_MINUTES', 15,
        ),
        maintenance_windows_per_port_max=_positive_int(
            source, 'MAINTENANCE_WINDOWS_PER_PORT_MAX', 50,
        ),
        maintenance_start_tolerance_seconds=_positive_int(
            source, 'MAINTENANCE_START_TOLERANCE_SECONDS', 900,
        ),
        maintenance_duration_tolerance_seconds=_positive_int(
            source, 'MAINTENANCE_DURATION_TOLERANCE_SECONDS', 600,
        ),
        maintenance_suggestion_lookback_days=_positive_int(
            source, 'MAINTENANCE_SUGGESTION_LOOKBACK_DAYS', 21,
        ),
    )
