"""Read-only current-diagnosis composition for the advanced workspace."""

import json
from pathlib import Path

from .db import read_transaction
from .migrations import RECOVERY_MARKER
from .repositories import (
    read_current_host, read_current_services, read_pipeline_evidence,
)
from .telemetry import RetentionPolicy
from .worker_main import WORKER_CALLBACK_INVENTORY


SCHEMA_VERSION = 1


def freshness_state(now, sample_ts, cadence_seconds):
    """Classify durable sampling evidence without inferring its cause."""
    if (
        type(now) is not int
        or type(sample_ts) is not int
        or type(cadence_seconds) is not int
        or cadence_seconds <= 0
    ):
        return {'state': 'unknown', 'age_seconds': None}

    age_seconds = max(0, now - sample_ts)
    if age_seconds <= cadence_seconds:
        state = 'fresh'
    elif age_seconds <= 4 * cadence_seconds:
        state = 'aging'
    else:
        state = 'stale'
    return {'state': state, 'age_seconds': age_seconds}


def _host_payload(row, cadence_seconds, now):
    if row is None:
        return {
            'identity': {'hostname': None},
            'metrics': {
                'cpu': {'value': None, 'unit': 'percent'},
                'memory': {
                    'value': None,
                    'unit': 'percent',
                    'used_bytes': None,
                    'available_bytes': None,
                    'total_bytes': None,
                },
                'disk': {
                    'value': None,
                    'unit': 'percent',
                    'used_bytes': None,
                    'total_bytes': None,
                },
                'temperature': {'value': None, 'unit': 'celsius'},
            },
            'sample_ts': None,
            'expected_cadence_seconds': cadence_seconds,
            'freshness': freshness_state(now, None, cadence_seconds),
        }

    sample_ts = row['sample_ts']
    return {
        'identity': {'hostname': row['hostname']},
        'metrics': {
            'cpu': {'value': row['cpu'], 'unit': 'percent'},
            'memory': {
                'value': row['ram'],
                'unit': 'percent',
                'used_bytes': row['ram_used'],
                'available_bytes': row['ram_available'],
                'total_bytes': row['ram_total'],
            },
            'disk': {
                'value': row['disk'],
                'unit': 'percent',
                'used_bytes': row['disk_used'],
                'total_bytes': row['disk_total'],
            },
            'temperature': {'value': row['temp'], 'unit': 'celsius'},
        },
        'sample_ts': sample_ts,
        'expected_cadence_seconds': cadence_seconds,
        'freshness': freshness_state(now, sample_ts, cadence_seconds),
    }


def operational_service_key(service):
    """Return D-06's deterministic default service ordering key."""
    availability = service['availability']
    if availability == 'offline' and service['critical']:
        group = 0
    elif availability == 'offline':
        group = 1
    elif service['freshness']['state'] in {'stale', 'unknown'} or availability == 'unknown':
        group = 2
    else:
        group = 3
    return (group, service['pinned_order'], service['port'])


def _tags(value):
    if not isinstance(value, str):
        return []
    return [tag.strip() for tag in value.split(',') if tag.strip()]


def _safe_pinned_order(value, fallback):
    """Project only validated durable ordering evidence into the read model."""
    if type(value) is int and 0 <= value <= 65535:
        return value
    return fallback


def compose_service_diagnosis(rows, *, now):
    """Project current service evidence without conflating TLS or freshness with availability."""
    services = []
    for row in rows:
        online = row.get('last_probe_online')
        if online is None:
            online = row.get('is_online')
        availability = 'online' if online == 1 else 'offline' if online == 0 else 'unknown'
        probe_ts = row.get('last_probe_ts')
        cadence = 60 if availability == 'offline' else 300
        service = {
            'port': row['port'],
            'name': row.get('display_name') or row.get('title') or f"Port {row['port']}",
            'title': row.get('title'),
            'availability': availability,
            'latency_ms': row.get('probe_latency_ms') if availability == 'online' else None,
            'failure_class': (
                row.get('probe_error_class') or row.get('last_error')
                if availability != 'online' else None
            ),
            'state_since_ts': row.get('state_since'),
            'state_duration_seconds': (
                max(0, now - row['state_since']) if isinstance(row.get('state_since'), int) else None
            ),
            'critical': bool(row.get('critical')),
            'tags': _tags(row.get('tags')),
            'pinned_order': _safe_pinned_order(row.get('pinned_order'), row['port']),
            'effective_health_rule': row.get('healthy_statuses') or '200-399',
            'last_probe_ts': probe_ts,
            'expected_cadence_seconds': cadence,
            'freshness': freshness_state(now, probe_ts, cadence),
            'tls_unverified': bool(row.get('tls_unverified')),
            'last_error': row.get('probe_error_class') or row.get('last_error'),
            'collection_gaps': [],
        }
        services.append(service)
    return sorted(services, key=operational_service_key)


def callback_schedule_evidence(callback, settings):
    """Describe immutable callback cadence without inspecting an APScheduler instance."""
    metadata = dict(callback.trigger_kwargs)
    cadence = None
    if callback.trigger == 'interval':
        cadence = (
            (metadata.get('seconds') or 0) + (metadata.get('minutes') or 0) * 60
            + (metadata.get('hours') or 0) * 3600
        )
        if callback.identifier == 'J2':
            cadence = settings.metric_sample_seconds
    return {
        'job_id': callback.identifier,
        'schedule_kind': callback.admission_category,
        'trigger': callback.trigger,
        'cadence_seconds': cadence or None,
        'next_expected_ts': None,
        'not_scheduled': callback.scheduler_id is None,
    }


def _runtime_timestamp(value, key):
    if not isinstance(value, dict):
        return None
    candidate = value.get(key)
    return candidate if type(candidate) is int else None


def compose_pipeline_diagnosis(evidence, settings, *, now):
    """Keep pressure, gaps, pending work, streams, and job outcomes separately typed."""
    policy = RetentionPolicy.from_settings(settings)
    retention_state = evidence['runtime'].get('telemetry_retention_state')
    if not isinstance(retention_state, dict):
        retention_state = {'state': 'normal', 'pressure_gaps': {}}
    heartbeat_ts = _runtime_timestamp(evidence['runtime'].get('worker_heartbeat'), 'ts')
    heartbeat_callback = next(
        callback for callback in WORKER_CALLBACK_INVENTORY if callback.identifier == 'J1'
    )
    worker_cadence = callback_schedule_evidence(heartbeat_callback, settings)['cadence_seconds']
    stream_records = []
    for stream in evidence['streams']:
        cadence = stream.get('cadence_seconds')
        stream_records.append({
            **stream,
            'freshness': freshness_state(now, stream.get('last_observed_ts'), cadence),
            'gaps': [],
        })
    stream_index = {(row['stream_kind'], str(row['stream_key'])): row for row in stream_records}
    gaps = []
    for gap in evidence['gaps']:
        stream = stream_index.get((gap['stream_kind'], str(gap['stream_key'])))
        cadence = stream.get('cadence_seconds') if stream else None
        open_gap = bool(stream and stream.get('open_gap_start_ts') is not None)
        recent_window = max(3600, 4 * cadence) if isinstance(cadence, int) and cadence > 0 else 3600
        item = {
            **gap,
            'open': open_gap,
            'actionable': open_gap or gap['end_ts'] >= now - recent_window,
        }
        gaps.append(item)
        if stream:
            stream['gaps'].append(item)
    for stream in stream_records:
        open_gap_start_ts = stream.get('open_gap_start_ts')
        if open_gap_start_ts is None:
            continue
        item = {
            'stream_kind': stream['stream_kind'],
            'stream_key': stream['stream_key'],
            'start_ts': open_gap_start_ts,
            'end_ts': max(now, open_gap_start_ts),
            'reason': 'collection_gap',
            'detail': None,
            'open': True,
            'actionable': True,
        }
        gaps.append(item)
        stream['gaps'].append(item)
    durable_jobs = {row['job_id']: row for row in evidence['jobs']}
    jobs = []
    for callback in WORKER_CALLBACK_INVENTORY:
        schedule = callback_schedule_evidence(callback, settings)
        outcome = durable_jobs.get(callback.identifier)
        jobs.append({
            **schedule,
            'state': outcome.get('state') if outcome else 'unknown',
            'last_started_ts': outcome.get('last_started_ts') if outcome else None,
            'last_finished_ts': outcome.get('last_finished_ts') if outcome else None,
            'last_success_ts': outcome.get('last_success_ts') if outcome else None,
            'error_class': outcome.get('error_class') if outcome else None,
            'updated_ts': outcome.get('updated_ts') if outcome else None,
        })
    return {
        'retention': {
            'raw_days': policy.raw_days,
            'five_minute_days': policy.five_minute_days,
            'retention_days': policy.retention_days,
            'point_budget': policy.point_budget,
        },
        'resolution_policy': {'raw_seconds': 60, 'five_minute_seconds': 300, 'hourly_seconds': 3600},
        'database_pressure': {
            'state': retention_state.get('state', 'normal'),
            'reason': retention_state.get('reason'),
            'snapshot': retention_state.get('snapshot'),
            'pressure_gaps': retention_state.get('pressure_gaps', {}),
        },
        'worker': {
            'heartbeat_ts': heartbeat_ts,
            'expected_cadence_seconds': worker_cadence,
            'freshness': freshness_state(now, heartbeat_ts, worker_cadence),
            'lease_until': _runtime_timestamp(evidence['runtime'].get('worker_owner'), 'lease_until'),
        },
        'streams': stream_records,
        'gaps': {
            'items': gaps,
            'count': len(gaps),
            'truncated': bool(evidence.get('gaps_truncated', False)),
        },
        'aggregation_pending': {
            'items': evidence['pending'], 'count': len(evidence['pending']),
            'truncated': len(evidence['pending']) >= 32,
        },
        'jobs': jobs,
    }


def compose_active_exceptions(services, pipeline, *, recovery_required):
    """Produce a safety-first deterministic exception projection without causal inference."""
    exceptions = []
    if recovery_required:
        exceptions.append({'kind': 'recovery_required', 'section': 'pipeline', 'priority': 0})
    worker = pipeline['worker']
    if worker['freshness']['state'] in {'stale', 'unknown'}:
        exceptions.append({'kind': 'worker_freshness', 'section': 'pipeline', 'priority': 1, 'state': worker['freshness']['state']})
    for service in services:
        if service['availability'] == 'offline':
            exceptions.append({
                'kind': 'critical_service_offline' if service['critical'] else 'service_offline',
                'section': 'services', 'priority': 2 if service['critical'] else 3,
                'port': service['port'], 'name': service['name'],
            })
        elif service['freshness']['state'] in {'stale', 'unknown'}:
            exceptions.append({
                'kind': 'service_freshness', 'section': 'services', 'priority': 4,
                'port': service['port'], 'state': service['freshness']['state'],
            })
    for gap in pipeline['gaps']['items']:
        if gap['actionable']:
            exceptions.append({'kind': 'collection_gap', 'section': 'pipeline', 'priority': 5, **gap})
    for job in pipeline['jobs']:
        if job['state'] == 'failed':
            exceptions.append({'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, 'job_id': job['job_id']})
    if pipeline['database_pressure']['state'] != 'normal':
        exceptions.append({'kind': 'database_pressure', 'section': 'pipeline', 'priority': 7})
    return sorted(exceptions, key=lambda item: (item['priority'], item['kind'], item.get('port', -1), item.get('job_id', '')))


def _settings_payload(settings):
    policy = RetentionPolicy.from_settings(settings)
    return {
        'sampling': {'metric_sample_seconds': settings.metric_sample_seconds},
        'probes': {'full_probe_seconds': 300, 'down_recheck_seconds': 60},
        'discovery_cleanup': {
            'discovery_timeout_seconds': settings.discovery_timeout_seconds,
            'expire_days': settings.expire_days,
        },
        'retention': {
            'raw_days': policy.raw_days, 'five_minute_days': policy.five_minute_days,
            'retention_days': policy.retention_days, 'point_budget': policy.point_budget,
        },
        'pressure': {
            'db_max_bytes': policy.db_max_bytes, 'min_free_bytes': policy.min_free_bytes,
            'warning_percent': policy.pressure_warning_percent,
            'hard_percent': policy.pressure_hard_percent,
            'recovery_percent': policy.pressure_recovery_percent,
        },
        'alerting_enabled': bool(settings.alert_webhook_url),
    }


def get_current_diagnosis(db_path, settings, now):
    """Read one versioned current snapshot and close SQLite before serialization."""
    cadence_seconds = settings.metric_sample_seconds
    with read_transaction(db_path) as conn:
        row = read_current_host(conn)
        host = _host_payload(row, cadence_seconds, now)
        services = compose_service_diagnosis(
            read_current_services(conn, cutoff_ts=now - settings.expire_days * 86400), now=now,
        )
        pipeline = compose_pipeline_diagnosis(read_pipeline_evidence(conn, now=now), settings, now=now)
    recovery_required = (Path(db_path).parent / RECOVERY_MARKER).exists()
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_ts': now,
        'host': host,
        'services': services,
        'pipeline': pipeline,
        'settings': _settings_payload(settings),
        'safety': {
            'worker_stale': pipeline['worker']['freshness']['state'] in {'stale', 'unknown'},
            'recovery_required': recovery_required,
        },
        'exceptions': compose_active_exceptions(services, pipeline, recovery_required=recovery_required),
    }
