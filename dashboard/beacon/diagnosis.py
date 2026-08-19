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


SCHEMA_VERSION = 3

# Each telemetry_coverage.reason value in the migrations.py CHECK enum maps to the
# one exception kind it may be promoted as, or to None for lifecycle evidence that
# is never an operator-facing fault.
GAP_REASON_EXCEPTION_KINDS = {
    'collection_gap': 'collection_gap',
    'unknown': 'coverage_unknown',
    'expired': None,
    'not_yet_monitored': None,
}

# A reason the code does not recognise is indeterminate coverage: reporting it as a
# collection failure would assert a cause the row does not carry (D-11), and dropping
# it would hide evidence from the operator.
UNMAPPED_GAP_EXCEPTION_KIND = 'coverage_unknown'

# The durable state literal record_background_job_started writes on a start.
RUNNING_JOB_STATE = 'running'

# A floor no legitimate run can plausibly exceed, never a bare multiple of a job's
# own poll interval: J5 and J6 poll every two seconds precisely because an idle run
# is short while a run that finds work is unboundedly longer.  Fifteen minutes sits
# comfortably above both of connect_db's thirty-second lock waits and above
# discovery's one-hundred-and-eighty-second DEFAULT timeout.  That default is not
# the only value an operator may configure, so _unrecorded_outcome_boundary widens
# this floor further whenever the configured DISCOVERY_TIMEOUT_SECONDS approaches
# or exceeds it: the guarantee is stated against the value actually in force, never
# against the default alone.  The floor widens further only for DISCOVERY_JOB_IDS,
# so this guarantee holds for the jobs it actually describes and never for a
# setting unrelated to the job being measured.
UNRECORDED_OUTCOME_FLOOR_SECONDS = 900

# The only jobs that actually run under the operator's configured
# DISCOVERY_TIMEOUT_SECONDS budget: J5's manual scan, J7's scheduled discovery,
# J9's startup discovery.  Every other job's promotion floor must stay
# independent of a setting that has nothing to do with it -- 03-VERIFICATION.md
# round 7 gap 2 / WR-02's reproduction showed widening the floor globally let a
# configured DISCOVERY_TIMEOUT_SECONDS silently delay wedge detection for J1's
# five-second heartbeat.
DISCOVERY_JOB_IDS = frozenset({'J5', 'J7', 'J9'})


def _unrecorded_outcome_boundary(cadence_seconds, discovery_timeout_seconds, job_id):
    """Resolve how long a start may stand without an outcome before it is a fault.

    The fixed floor is widened, where necessary, to the operator's own
    configured ``DISCOVERY_TIMEOUT_SECONDS`` plus a minute of headroom -- but
    only for a job in ``DISCOVERY_JOB_IDS``, so a discovery that is legitimately
    still working inside its configured budget is never promoted as a
    fabricated fault on a deployment configured above the constant, while every
    other job's floor stays independent of a setting that does not describe it.
    ``discovery_timeout_seconds`` is guarded (``type(...) is int and ... > 0``)
    rather than coerced (``int(...)``), so a malformed value leaves the floor at
    the constant instead of raising out of ``get_current_diagnosis``.
    """
    floor = UNRECORDED_OUTCOME_FLOOR_SECONDS
    if job_id in DISCOVERY_JOB_IDS and type(discovery_timeout_seconds) is int and discovery_timeout_seconds > 0:
        floor = max(floor, discovery_timeout_seconds + 60)
    if type(cadence_seconds) is int and cadence_seconds > 0:
        # freshness_state's own four-times-cadence multiple and strict-integer
        # discipline, reused rather than a second convention.  The larger of the two
        # always wins, so a job whose own cadence exceeds the floor is measured
        # against its cadence and no job is measured below the floor.
        return max(floor, 4 * cadence_seconds)
    # An absent, malformed or non-positive cadence describes a startup or lifecycle
    # callback with no configured interval.  It is measured against the same floor
    # as every other job rather than exempted from the promotion built to catch it.
    return floor


def gap_exception_kind(reason):
    """Resolve a durable coverage reason to its own exception kind, or to no exception."""
    if reason in GAP_REASON_EXCEPTION_KINDS:
        return GAP_REASON_EXCEPTION_KINDS[reason]
    return UNMAPPED_GAP_EXCEPTION_KIND


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
        recent_window = max(3600, 4 * cadence) if isinstance(cadence, int) and cadence > 0 else 3600
        item = {
            **gap,
            # A persisted telemetry_coverage row is a closed interval by construction
            # (its DDL enforces end_ts > start_ts and it is written only once bounded).
            # The stream's open_gap_start_ts describes the stream, never this row.
            'open': False,
            'actionable': (
                gap_exception_kind(gap['reason']) is not None
                and gap['end_ts'] >= now - recent_window
            ),
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
    # Stable priority sort: open evidence first, then actionable evidence. Python's
    # sort is stable, so items of equal priority keep the durable read's existing
    # end_ts DESC / start_ts DESC order.
    gaps.sort(key=lambda item: (not item['open'], not item['actionable']))
    gaps_limit = evidence.get('gaps_limit')
    if not isinstance(gaps_limit, int) or gaps_limit < 0:
        gaps_limit = 48
    bounded_gaps = gaps[:gaps_limit]
    gaps_truncated = bool(
        evidence.get('gaps_truncated', False)
        or evidence.get('open_gap_streams_truncated', False)
        or len(gaps) > gaps_limit
    )
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
        'streams': {
            'items': stream_records,
            'count': len(stream_records),
            'truncated': bool(evidence.get('streams_truncated', False)),
            # The durable gap read's own bound, kept distinct from the stream
            # read's bound above: one describes whether a matched stream's gap
            # evidence is whole, the other whether an unmatched stream was even
            # looked at. Conflating them is how a count and a truncation flag
            # come to describe different populations.
            'gap_evidence_truncated': bool(evidence.get('gaps_truncated', False)),
        },
        'gaps': {
            'items': bounded_gaps,
            'count': len(bounded_gaps),
            'truncated': gaps_truncated,
        },
        'aggregation_pending': {
            'items': evidence['pending'], 'count': len(evidence['pending']),
            'truncated': bool(evidence.get('pending_truncated', False)),
        },
        'jobs': jobs,
    }


# The four states a per-service gap block may disclose. Each is derived from a
# durable read's own truncation flag; none may be defaulted to or inferred.
SERVICE_GAP_EVIDENCE_COMPLETE = 'complete'
SERVICE_GAP_EVIDENCE_POSSIBLY_INCOMPLETE = 'possibly_incomplete'
SERVICE_GAP_EVIDENCE_ABSENT = 'absent'
SERVICE_GAP_EVIDENCE_NOT_ESTABLISHED = 'not_established'

# The durable stream vocabulary: a service stream is keyed by its port as text
# (repositories.get_telemetry_coverage), so the join key must match exactly.
SERVICE_STREAM_KIND = 'service'


def _service_gap_evidence_state(stream, streams_block):
    """Resolve completeness from a durable truncation flag, never from a default."""
    if stream is None:
        # A complete stream list that omits this service is itself evidence of
        # absence. A truncated one establishes nothing about it.
        truncated = streams_block.get('truncated')
        if truncated is False:
            return SERVICE_GAP_EVIDENCE_ABSENT
        return SERVICE_GAP_EVIDENCE_NOT_ESTABLISHED
    gap_truncated = streams_block.get('gap_evidence_truncated')
    if gap_truncated is False:
        return SERVICE_GAP_EVIDENCE_COMPLETE
    if gap_truncated is True:
        return SERVICE_GAP_EVIDENCE_POSSIBLY_INCOMPLETE
    return SERVICE_GAP_EVIDENCE_NOT_ESTABLISHED


def attach_service_collection_gaps(services, pipeline):
    """Join each service to its own stream's composed gaps with an explicit completeness state.

    The items are the composed per-stream list verbatim: not sorted, filtered,
    deduplicated or bounded here, so the order the pipeline composition already
    established is preserved. ``open`` is read from each item's own row, never
    from the stream, preserving the per-row derivation closed by 03-08.
    """
    streams_block = pipeline.get('streams')
    if not isinstance(streams_block, dict):
        streams_block = {}
    stream_items = streams_block.get('items')
    stream_index = {}
    if isinstance(stream_items, list):
        for stream in stream_items:
            if isinstance(stream, dict):
                stream_index[(stream.get('stream_kind'), str(stream.get('stream_key')))] = stream
    for service in services:
        stream = stream_index.get((SERVICE_STREAM_KIND, str(service.get('port'))))
        items = stream.get('gaps') if isinstance(stream, dict) else None
        if not isinstance(items, list):
            items = []
        service['collection_gaps'] = {
            'items': items,
            'count': len(items),
            # The element-level guard the enclosing containers already get: a
            # non-dictionary item here would raise out of the composition and
            # into a request path that catches only database conditions, so the
            # operator would get an unparseable error page instead of the
            # workspace's own bounded error copy.
            'open_count': sum(
                1 for item in items if isinstance(item, dict) and item.get('open') is True
            ),
            'evidence': _service_gap_evidence_state(stream, streams_block),
        }
    return services


def compose_active_exceptions(
    host, services, pipeline, *, recovery_required, now, discovery_timeout_seconds,
):
    """Produce a safety-first deterministic exception projection without causal inference."""
    exceptions = []
    if recovery_required:
        exceptions.append({'kind': 'recovery_required', 'section': 'pipeline', 'priority': 0})
    if host['freshness']['state'] in {'stale', 'unknown'}:
        exceptions.append({'kind': 'host_freshness', 'section': 'host', 'priority': 1, 'state': host['freshness']['state']})
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
        if not gap['actionable']:
            continue
        kind = gap_exception_kind(gap.get('reason'))
        if kind is None:
            continue
        exceptions.append({'kind': kind, 'section': 'pipeline', 'priority': 5, **gap})
    for job in pipeline['jobs']:
        if job['state'] == 'failed':
            exceptions.append({'kind': 'job_failed', 'section': 'pipeline', 'priority': 6, 'job_id': job['job_id']})
        elif (
            # Every input is this job's own durable row: the state literal
            # record_background_job_started writes and its own recorded start.  The
            # boundary is a floor no legitimate run can plausibly cross, raised only
            # for a job whose own cadence already exceeds it -- a poll interval is
            # never read as an upper bound on how long the work may legitimately run.
            # An absent row reads unknown and promotes nothing; an absent cadence is
            # measured against the same floor rather than exempted; and the
            # comparison stays strict, so an age exactly at the boundary favours the
            # non-alarm.
            job['state'] == RUNNING_JOB_STATE
            and type(job.get('last_started_ts')) is int
            and type(now) is int
            and max(0, now - job['last_started_ts'])
            > _unrecorded_outcome_boundary(
                job.get('cadence_seconds'), discovery_timeout_seconds, job['job_id'],
            )
        ):
            # Explicit keys only, never a spread of the durable row, so a future
            # column can neither override this classification nor break the sort.
            exceptions.append({
                'kind': 'job_outcome_unrecorded', 'section': 'pipeline', 'priority': 6,
                'job_id': job['job_id'],
            })
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
    attach_service_collection_gaps(services, pipeline)
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
        'exceptions': compose_active_exceptions(
            host, services, pipeline, recovery_required=recovery_required, now=now,
            discovery_timeout_seconds=settings.discovery_timeout_seconds,
        ),
    }
