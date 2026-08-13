"""Read-only current-diagnosis composition for the advanced workspace."""

from .db import read_transaction
from .repositories import read_current_host


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


def get_current_diagnosis(db_path, settings, now):
    """Read one current host snapshot and close SQLite before serialization."""
    cadence_seconds = settings.metric_sample_seconds
    with read_transaction(db_path) as conn:
        row = read_current_host(conn)
        host = _host_payload(row, cadence_seconds, now)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_ts': now,
        'host': host,
    }
