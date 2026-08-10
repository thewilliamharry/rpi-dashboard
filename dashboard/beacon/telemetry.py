"""Framework-free policy and durable operations for bounded telemetry."""

from dataclasses import dataclass
import json
import math
import os


POINT_BUDGET = 2048
MAX_HISTORY_SECONDS = 90 * 86400
RESOLUTION_LADDER_SECONDS = (60, 300, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400)
_COVERAGE_STATES = {
    'collection_gap',
    'expired',
    'not_yet_monitored',
    'unknown',
}


@dataclass(frozen=True)
class HistoricalRange:
    """A validated, half-open UTC interval requested by a history consumer."""

    start_ts: int
    end_ts: int

    def __post_init__(self):
        for field_name, value in (('start_ts', self.start_ts), ('end_ts', self.end_ts)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f'{field_name} must be an integer')
        if self.start_ts >= self.end_ts:
            raise ValueError('start_ts must be before end_ts')
        if self.end_ts - self.start_ts > MAX_HISTORY_SECONDS:
            raise ValueError('requested span exceeds 90 days')


@dataclass(frozen=True)
class CoverageInterval:
    """One half-open interval whose availability state is known explicitly."""

    start_ts: int
    end_ts: int
    state: str

    def __post_init__(self):
        if self.start_ts >= self.end_ts:
            raise ValueError('coverage interval must not be empty or reversed')
        if self.state not in _COVERAGE_STATES:
            raise ValueError('invalid coverage state')

    def as_dict(self):
        return {
            'start_ts': self.start_ts,
            'end_ts': self.end_ts,
            'state': self.state,
        }


def select_resolution(start_ts, end_ts, point_budget=POINT_BUDGET):
    """Choose the smallest display bucket whose half-open range fits the budget."""
    requested = HistoricalRange(start_ts, end_ts)
    if isinstance(point_budget, bool) or not isinstance(point_budget, int) or point_budget <= 0:
        raise ValueError('point_budget must be a positive integer')
    span = requested.end_ts - requested.start_ts
    for resolution in RESOLUTION_LADDER_SECONDS:
        if (span + resolution - 1) // resolution <= point_budget:
            return resolution
    return RESOLUTION_LADDER_SECONDS[-1]


def coalesce_coverage(intervals):
    """Sort coverage deterministically and merge only touching equal-state intervals."""
    ordered = sorted(intervals, key=lambda item: (item.start_ts, item.end_ts, item.state))
    coalesced = []
    for interval in ordered:
        if not isinstance(interval, CoverageInterval):
            raise ValueError('coverage entries must be CoverageInterval values')
        if coalesced and interval.start_ts < coalesced[-1].end_ts:
            raise ValueError('coverage intervals must not overlap')
        if (
            coalesced
            and interval.start_ts == coalesced[-1].end_ts
            and interval.state == coalesced[-1].state
        ):
            prior = coalesced[-1]
            coalesced[-1] = CoverageInterval(prior.start_ts, interval.end_ts, prior.state)
        else:
            coalesced.append(interval)
    return tuple(coalesced)


@dataclass(frozen=True)
class RetentionPolicy:
    """Validated, immutable retention and pressure values for one worker batch."""

    raw_days: int = 7
    five_minute_days: int = 30
    retention_days: int = 90
    point_budget: int = POINT_BUDGET
    db_max_bytes: int = 536_870_912
    min_free_bytes: int = 1_073_741_824
    pressure_warning_percent: int = 80
    pressure_hard_percent: int = 90
    pressure_recovery_percent: int = 75
    backlog_reserve_bytes: int = 67_108_864
    rollup_batch_buckets: int = 32
    retry_base_seconds: int = 300
    retry_max_seconds: int = 3_600

    def __post_init__(self):
        positive = (
            'raw_days', 'five_minute_days', 'retention_days', 'point_budget',
            'db_max_bytes', 'min_free_bytes', 'backlog_reserve_bytes',
            'rollup_batch_buckets', 'retry_base_seconds', 'retry_max_seconds',
        )
        for name in positive:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f'{name} must be a positive integer')
        if not self.raw_days < self.five_minute_days < self.retention_days:
            raise ValueError('retention tiers must increase strictly')
        if not (
            0 < self.pressure_recovery_percent < self.pressure_warning_percent
            < self.pressure_hard_percent <= 100
        ):
            raise ValueError('pressure thresholds must satisfy recovery < warning < hard <= 100')
        if self.retry_base_seconds > self.retry_max_seconds:
            raise ValueError('retry_base_seconds must not exceed retry_max_seconds')


@dataclass(frozen=True)
class StorageSnapshot:
    """Filesystem state used to decide whether historical writes remain safe."""

    database_bytes: int
    wal_bytes: int
    shm_bytes: int
    free_bytes: int

    def __post_init__(self):
        for name in ('database_bytes', 'wal_bytes', 'shm_bytes', 'free_bytes'):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f'{name} must be a non-negative integer')

    @property
    def footprint_bytes(self):
        return self.database_bytes + self.wal_bytes + self.shm_bytes


@dataclass(frozen=True)
class PressureDecision:
    """A pure storage-pressure transition with a historical-write permission."""

    previous_state: str
    state: str
    reason: str | None

    @property
    def historical_persistence_allowed(self):
        return self.state != 'suspended'


def evaluate_storage_pressure(previous_state, snapshot, policy=None):
    """Return the deterministic historical-storage transition for a filesystem snapshot."""
    policy = policy or RetentionPolicy()
    if previous_state not in {'normal', 'pressure', 'suspended'}:
        raise ValueError('invalid previous storage state')
    if not isinstance(snapshot, StorageSnapshot):
        raise ValueError('snapshot must be a StorageSnapshot')
    footprint = snapshot.footprint_bytes
    recovery_free = policy.min_free_bytes + policy.backlog_reserve_bytes
    recovery_footprint = (policy.db_max_bytes * policy.pressure_recovery_percent) // 100
    if previous_state == 'suspended':
        if footprint <= recovery_footprint and snapshot.free_bytes >= recovery_free:
            return PressureDecision(previous_state, 'normal', 'recovered')
        return PressureDecision(previous_state, 'suspended', 'recovery_pending')
    if footprint >= policy.db_max_bytes + policy.backlog_reserve_bytes:
        return PressureDecision(previous_state, 'suspended', 'allocation_exhausted')
    if snapshot.free_bytes <= policy.min_free_bytes:
        return PressureDecision(previous_state, 'suspended', 'free_space_exhausted')
    if footprint >= (policy.db_max_bytes * policy.pressure_hard_percent) // 100:
        return PressureDecision(previous_state, 'pressure', 'allocation_hard')
    if footprint >= (policy.db_max_bytes * policy.pressure_warning_percent) // 100:
        return PressureDecision(previous_state, 'pressure', 'allocation_warning')
    if snapshot.free_bytes <= recovery_free:
        return PressureDecision(previous_state, 'pressure', 'free_space_reserve')
    return PressureDecision(previous_state, 'normal', None)


def historical_persistence_allowed(decision_or_state):
    """Distinguish only historical persistence from live/current monitoring work."""
    if isinstance(decision_or_state, PressureDecision):
        return decision_or_state.historical_persistence_allowed
    if decision_or_state not in {'normal', 'pressure', 'suspended'}:
        raise ValueError('invalid storage state')
    return decision_or_state != 'suspended'


def measure_storage(db_path):
    """Return one filesystem snapshot without requiring a SQLite connection."""
    path = os.fspath(db_path)
    parent = os.path.dirname(path) or '.'
    stat = os.statvfs(parent)

    def size(candidate):
        try:
            return os.path.getsize(candidate)
        except FileNotFoundError:
            return 0

    return StorageSnapshot(
        size(path), size(path + '-wal'), size(path + '-shm'),
        int(stat.f_bavail) * int(stat.f_frsize),
    )


def _runtime_state(conn, key, default):
    row = conn.execute('SELECT value FROM runtime_state WHERE key=?', (key,)).fetchone()
    if row is None:
        return default
    try:
        value = json.loads(_row_value(row, 'value'))
    except (TypeError, ValueError):
        return default
    return value if isinstance(value, type(default)) else default


def read_retention_state(conn):
    """Read the durable pressure state without a process-local fallback."""
    state = _runtime_state(conn, 'telemetry_retention_state', {})
    if state.get('state') not in {'normal', 'pressure', 'suspended'}:
        return {'state': 'normal', 'pressure_gaps': {}}
    state.setdefault('pressure_gaps', {})
    return state


def write_retention_state(conn, state, *, now):
    """Persist a validated retention state in the caller-owned transaction."""
    value = dict(state)
    if value.get('state') not in {'normal', 'pressure', 'suspended'}:
        raise ValueError('invalid retention state')
    gaps = value.get('pressure_gaps', {})
    if not isinstance(gaps, dict):
        raise ValueError('pressure_gaps must be a mapping')
    value['pressure_gaps'] = {
        str(key): int(start)
        for key, start in gaps.items()
        if isinstance(start, int) and not isinstance(start, bool)
    }
    conn.execute(
        'INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts',
        ('telemetry_retention_state', json.dumps(value, separators=(',', ':'), sort_keys=True), int(now)),
    )
    return value


def _stream_gap_key(stream_kind, stream_key):
    return f'{stream_kind}:{stream_key}'


def open_storage_pressure_gap(conn, stream_kind, stream_key, *, now):
    """Remember a suspended-history interval until normal persistence returns."""
    state = read_retention_state(conn)
    gaps = dict(state['pressure_gaps'])
    gaps.setdefault(_stream_gap_key(stream_kind, stream_key), int(now))
    state['pressure_gaps'] = gaps
    return state


def close_storage_pressure_gap(conn, stream_kind, stream_key, *, now):
    """Close one durable storage-pressure gap without inventing observations."""
    state = read_retention_state(conn)
    gaps = dict(state['pressure_gaps'])
    start = gaps.pop(_stream_gap_key(stream_kind, stream_key), None)
    if start is not None and int(start) < int(now):
        record_coverage_interval(
            conn, stream_kind, stream_key, int(start), int(now),
            'collection_gap', 'storage_pressure',
        )
    state['pressure_gaps'] = gaps
    return state


def bucket_start(ts, seconds):
    """Return the canonical UTC half-open bucket start for an integer timestamp."""
    if isinstance(ts, bool) or not isinstance(ts, int):
        raise ValueError('ts must be an integer')
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds <= 0:
        raise ValueError('seconds must be a positive integer')
    return (ts // seconds) * seconds


def bucket_is_complete(start, seconds, cutoff_ts):
    """Whether a full bucket ends at or before a retention cutoff."""
    return bucket_start(start, seconds) == start and start + seconds <= int(cutoff_ts)


def _row_value(row, name):
    try:
        return row[name]
    except (IndexError, KeyError, TypeError):
        return getattr(row, name)


def _duration_breakdown(start, end, observations, coverage=(), initial_state=None):
    """Resolve observed status intervals, letting persisted gaps override evidence."""
    cursor = start
    state = initial_state
    totals = {'online_seconds': 0, 'offline_seconds': 0, 'unknown_seconds': 0, 'gap_seconds': 0}
    segments = []
    for ts, next_state in sorted(observations, key=lambda item: item[0]):
        ts = min(max(int(ts), start), end)
        if ts > cursor:
            segments.append((cursor, ts, state))
        cursor = ts
        state = next_state
    if cursor < end:
        segments.append((cursor, end, state))
    for segment_start, segment_end, segment_state in segments:
        field = {True: 'online_seconds', False: 'offline_seconds'}.get(segment_state, 'unknown_seconds')
        totals[field] += segment_end - segment_start
    for interval in coverage:
        overlap_start = max(start, int(_row_value(interval, 'start_ts')))
        overlap_end = min(end, int(_row_value(interval, 'end_ts')))
        if overlap_start >= overlap_end:
            continue
        replacement = (
            'gap_seconds' if _row_value(interval, 'reason') == 'collection_gap'
            else 'unknown_seconds'
        )
        for segment_start, segment_end, segment_state in segments:
            overlap = max(0, min(segment_end, overlap_end) - max(segment_start, overlap_start))
            if not overlap:
                continue
            field = {True: 'online_seconds', False: 'offline_seconds'}.get(
                segment_state, 'unknown_seconds',
            )
            totals[field] -= overlap
            totals[replacement] += overlap
    return totals


def build_host_rollup(rows, metric, start, seconds, coverage=()):
    """Build one host rollup from ordered raw values without interpolating gaps."""
    end = start + seconds
    ordered = sorted(rows, key=lambda row: int(_row_value(row, 'ts')))
    samples = [
        (int(_row_value(row, 'ts')), float(_row_value(row, metric)))
        for row in ordered if _row_value(row, metric) is not None
    ]
    if not samples:
        return None
    observed = 0
    for index, (ts, _) in enumerate(samples):
        next_ts = samples[index + 1][0] if index + 1 < len(samples) else end
        observed += max(0, min(end, next_ts) - max(start, ts))
    gap_seconds = 0
    unknown_seconds = max(0, seconds - observed)
    for interval in coverage:
        overlap = max(
            0,
            min(end, int(_row_value(interval, 'end_ts')))
            - max(start, int(_row_value(interval, 'start_ts'))),
        )
        if not overlap:
            continue
        observed = max(0, observed - overlap)
        if _row_value(interval, 'reason') == 'collection_gap':
            gap_seconds += overlap
        else:
            unknown_seconds += overlap
    values = [value for _, value in samples]
    return {
        'metric': metric,
        'bucket_start': start,
        'bucket_seconds': seconds,
        'min_value': min(values),
        'max_value': max(values),
        'avg_value': sum(values) / len(values),
        'latest_value': values[-1],
        'sample_count': len(values),
        'observed_seconds': observed,
        'gap_seconds': gap_seconds,
        'unknown_seconds': unknown_seconds,
    }


def build_service_rollup(rows, service_port, start, seconds, coverage=(), prior_online=None):
    """Build a time-weighted service rollup; false is observed offline, never a gap."""
    end = start + seconds
    ordered = sorted(rows, key=lambda row: int(_row_value(row, 'ts')))
    observations = [
        (int(_row_value(row, 'ts')), _row_value(row, 'online')) for row in ordered
    ]
    durations = _duration_breakdown(start, end, observations, coverage, prior_online)
    latencies = [
        float(_row_value(row, 'latency_ms')) for row in ordered
        if _row_value(row, 'latency_ms') is not None
    ]
    failure_counts = {}
    for row in ordered:
        failure = _row_value(row, 'error_class')
        if failure:
            failure_counts[str(failure)] = failure_counts.get(str(failure), 0) + 1
    return {
        'service_port': int(service_port),
        'bucket_start': start,
        'bucket_seconds': seconds,
        **durations,
        'latency_min': min(latencies) if latencies else None,
        'latency_max': max(latencies) if latencies else None,
        'latency_avg': sum(latencies) / len(latencies) if latencies else None,
        'check_count': len(ordered),
        'failure_class_counts_json': json.dumps(
            failure_counts, separators=(',', ':'), sort_keys=True,
        ),
    }


def record_coverage_interval(conn, stream_kind, stream_key, start_ts, end_ts, reason, detail=None):
    """Insert one sparse interval, coalescing only matching adjacent evidence."""
    interval = CoverageInterval(int(start_ts), int(end_ts), str(reason))
    stream_kind = str(stream_kind)
    stream_key = str(stream_key)
    adjacent = conn.execute(
        'SELECT id, start_ts FROM telemetry_coverage WHERE stream_kind=? AND stream_key=? '
        'AND end_ts=? AND reason=? AND detail IS ? ORDER BY start_ts DESC LIMIT 1',
        (stream_kind, stream_key, interval.start_ts, interval.state, detail),
    ).fetchone()
    if adjacent is not None:
        conn.execute('UPDATE telemetry_coverage SET end_ts=? WHERE id=?', (interval.end_ts, adjacent['id']))
        return
    overlapping = conn.execute(
        'SELECT 1 FROM telemetry_coverage WHERE stream_kind=? AND stream_key=? '
        'AND start_ts < ? AND end_ts > ? LIMIT 1',
        (stream_kind, stream_key, interval.end_ts, interval.start_ts),
    ).fetchone()
    if overlapping is not None:
        raise ValueError('coverage intervals must not overlap')
    conn.execute(
        'INSERT INTO telemetry_coverage(stream_kind, stream_key, start_ts, end_ts, reason, detail) '
        'VALUES(?,?,?,?,?,?)',
        (stream_kind, stream_key, interval.start_ts, interval.end_ts, interval.state, detail),
    )


def detect_collection_gaps(conn, *, now, stream_kind=None, stream_key=None):
    """Confirm gaps only after two expected cadence boundaries have passed."""
    clauses = []
    params = []
    if stream_kind is not None:
        clauses.append('stream_kind=?')
        params.append(str(stream_kind))
    if stream_key is not None:
        clauses.append('stream_key=?')
        params.append(str(stream_key))
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    rows = conn.execute(
        'SELECT stream_kind, stream_key, last_observed_ts, cadence_seconds, open_gap_start_ts '
        'FROM telemetry_streams' + where,
        tuple(params),
    ).fetchall()
    confirmed = 0
    for row in rows:
        last = row['last_observed_ts']
        cadence = int(row['cadence_seconds'])
        if last is None or row['open_gap_start_ts'] is not None:
            continue
        if int(now) >= int(last) + 2 * cadence:
            conn.execute(
                'UPDATE telemetry_streams SET consecutive_misses=2, open_gap_start_ts=? '
                'WHERE stream_kind=? AND stream_key=?',
                (int(last) + cadence, row['stream_kind'], row['stream_key']),
            )
            confirmed += 1
    return confirmed


def record_observation(
    conn, stream_kind, stream_key, *, ts, cadence_seconds, state, expected_cadence=True,
):
    """Advance one stream with explicit True/False/None availability evidence."""
    if state is not True and state is not False and state is not None:
        raise ValueError('state must be True, False, or None')
    stream_kind = str(stream_kind)
    stream_key = str(stream_key)
    ts = int(ts)
    cadence_seconds = int(cadence_seconds)
    if cadence_seconds <= 0:
        raise ValueError('cadence_seconds must be positive')
    row = conn.execute(
        'SELECT started_ts, cadence_seconds, last_observed_ts, open_gap_start_ts '
        'FROM telemetry_streams WHERE stream_kind=? AND stream_key=?',
        (stream_kind, stream_key),
    ).fetchone()
    if row is None:
        conn.execute(
            'INSERT INTO telemetry_streams('
            'stream_kind, stream_key, started_ts, cadence_seconds, last_observed_ts, '
            'consecutive_misses, open_gap_start_ts) VALUES(?,?,?,?,?,0,NULL)',
            (stream_kind, stream_key, ts, cadence_seconds, ts),
        )
    elif expected_cadence:
        if int(row['cadence_seconds']) != cadence_seconds:
            raise ValueError('stream cadence cannot change')
        detect_collection_gaps(
            conn, now=ts, stream_kind=stream_kind, stream_key=stream_key,
        )
        current = conn.execute(
            'SELECT open_gap_start_ts FROM telemetry_streams WHERE stream_kind=? AND stream_key=?',
            (stream_kind, stream_key),
        ).fetchone()
        gap_start = current['open_gap_start_ts']
        if gap_start is not None and int(gap_start) < ts:
            record_coverage_interval(
                conn, stream_kind, stream_key, int(gap_start), ts, 'collection_gap', None,
            )
        conn.execute(
            'UPDATE telemetry_streams SET last_observed_ts=?, consecutive_misses=0, open_gap_start_ts=NULL '
            'WHERE stream_kind=? AND stream_key=?',
            (ts, stream_kind, stream_key),
        )
    if state is None:
        record_coverage_interval(
            conn, stream_kind, stream_key, ts, ts + cadence_seconds, 'unknown', None,
        )


def _coverage_for(conn, stream_kind, stream_key, start, end):
    return conn.execute(
        'SELECT start_ts, end_ts, reason FROM telemetry_coverage '
        'WHERE stream_kind=? AND stream_key=? AND start_ts < ? AND end_ts > ? '
        'ORDER BY start_ts, end_ts',
        (stream_kind, str(stream_key), end, start),
    ).fetchall()


def _upsert_and_verify(conn, table, values, keys):
    columns = tuple(values)
    assignments = ', '.join(f'{column}=excluded.{column}' for column in columns if column not in keys)
    conn.execute(
        f'INSERT INTO {table} ({", ".join(columns)}) VALUES ({", ".join("?" for _ in columns)}) '
        f'ON CONFLICT({", ".join(keys)}) DO UPDATE SET {assignments}',
        tuple(values[column] for column in columns),
    )
    where = ' AND '.join(f'{key}=?' for key in keys)
    stored = conn.execute(
        f'SELECT {", ".join(columns)} FROM {table} WHERE {where}',
        tuple(values[key] for key in keys),
    ).fetchone()
    if stored is None:
        raise AssertionError('aggregate read-back missing')
    for column in columns:
        actual = stored[column]
        expected = values[column]
        if isinstance(expected, float):
            if actual is None or not math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-12):
                raise AssertionError(f'aggregate read-back mismatch for {column}')
        elif actual != expected:
            raise AssertionError(f'aggregate read-back mismatch for {column}')


def _mark_succeeded(conn, stream_kind, stream_key, start, seconds, now):
    conn.execute(
        'INSERT INTO telemetry_rollup_jobs('
        'stream_kind, stream_key, bucket_start, bucket_seconds, state, attempt_count, '
        'next_retry_ts, last_error_class, updated_ts) VALUES(?,?,?,?,\'succeeded\',0,NULL,NULL,?) '
        'ON CONFLICT(stream_kind, stream_key, bucket_start, bucket_seconds) DO UPDATE SET '
        'state=\'succeeded\', next_retry_ts=NULL, last_error_class=NULL, updated_ts=excluded.updated_ts',
        (stream_kind, str(stream_key), start, seconds, now),
    )


def _mark_failed(conn, stream_kind, stream_key, start, seconds, now, policy, error):
    prior = conn.execute(
        'SELECT attempt_count FROM telemetry_rollup_jobs WHERE stream_kind=? AND stream_key=? '
        'AND bucket_start=? AND bucket_seconds=?',
        (stream_kind, str(stream_key), start, seconds),
    ).fetchone()
    attempt = (prior['attempt_count'] if prior else 0) + 1
    delay = min(policy.retry_base_seconds * (2 ** (attempt - 1)), policy.retry_max_seconds)
    conn.execute(
        'INSERT INTO telemetry_rollup_jobs('
        'stream_kind, stream_key, bucket_start, bucket_seconds, state, attempt_count, '
        'next_retry_ts, last_error_class, updated_ts) VALUES(?,?,?,?,\'failed\',?,?,?,?) '
        'ON CONFLICT(stream_kind, stream_key, bucket_start, bucket_seconds) DO UPDATE SET '
        'state=\'failed\', attempt_count=excluded.attempt_count, next_retry_ts=excluded.next_retry_ts, '
        'last_error_class=excluded.last_error_class, updated_ts=excluded.updated_ts',
        (stream_kind, str(stream_key), start, seconds, attempt, now + delay, type(error).__name__, now),
    )


def _raw_candidates(conn, cutoff):
    candidates = []
    for row in conn.execute('SELECT ts FROM stats_history WHERE ts < ? ORDER BY ts', (cutoff,)):
        start = bucket_start(int(row['ts']), 300)
        if bucket_is_complete(start, 300, cutoff):
            candidates.append((start, 300, 'host', 'host'))
    for row in conn.execute(
        'SELECT ts, port FROM service_checks WHERE ts < ? ORDER BY ts, port', (cutoff,),
    ):
        start = bucket_start(int(row['ts']), 300)
        if bucket_is_complete(start, 300, cutoff):
            candidates.append((start, 300, 'service', str(row['port'])))
    return candidates


def _five_minute_candidates(conn, cutoff):
    candidates = []
    for row in conn.execute(
        'SELECT DISTINCT metric, bucket_start FROM host_metric_rollups '
        'WHERE bucket_seconds=300 AND bucket_start + bucket_seconds <= ? ORDER BY bucket_start, metric',
        (cutoff,),
    ):
        start = bucket_start(int(row['bucket_start']), 3600)
        if bucket_is_complete(start, 3600, cutoff):
            candidates.append((start, 3600, 'host_rollup', str(row['metric'])))
    for row in conn.execute(
        'SELECT DISTINCT service_port, bucket_start FROM service_rollups '
        'WHERE bucket_seconds=300 AND bucket_start + bucket_seconds <= ? ORDER BY bucket_start, service_port',
        (cutoff,),
    ):
        start = bucket_start(int(row['bucket_start']), 3600)
        if bucket_is_complete(start, 3600, cutoff):
            candidates.append((start, 3600, 'service_rollup', str(row['service_port'])))
    return candidates


def _roll_host_raw(conn, start, now, policy):
    end = start + 300
    rows = conn.execute(
        'SELECT ts, cpu, ram, disk, temp FROM stats_history WHERE ts >= ? AND ts < ? ORDER BY ts',
        (start, end),
    ).fetchall()
    created = 0
    for metric in ('cpu', 'ram', 'disk', 'temp'):
        aggregate = build_host_rollup(rows, metric, start, 300, _coverage_for(conn, 'host', metric, start, end))
        if aggregate is None:
            continue
        _upsert_and_verify(conn, 'host_metric_rollups', aggregate, ('metric', 'bucket_start', 'bucket_seconds'))
        created += 1
    if not created:
        return False
    _mark_succeeded(conn, 'host', 'host', start, 300, now)
    conn.execute('DELETE FROM stats_history WHERE ts >= ? AND ts < ?', (start, end))
    return True


def _roll_service_raw(conn, port, start, now):
    end = start + 300
    prior = conn.execute(
        'SELECT online FROM service_checks WHERE port=? AND ts < ? ORDER BY ts DESC LIMIT 1',
        (int(port), start),
    ).fetchone()
    rows = conn.execute(
        'SELECT ts, online, latency_ms, error_class FROM service_checks '
        'WHERE port=? AND ts >= ? AND ts < ? ORDER BY ts',
        (int(port), start, end),
    ).fetchall()
    if not rows:
        return False
    aggregate = build_service_rollup(
        rows, int(port), start, 300, _coverage_for(conn, 'service', port, start, end),
        prior_online=None if prior is None else prior['online'],
    )
    _upsert_and_verify(conn, 'service_rollups', aggregate, ('service_port', 'bucket_start', 'bucket_seconds'))
    _mark_succeeded(conn, 'service', port, start, 300, now)
    conn.execute('DELETE FROM service_checks WHERE port=? AND ts >= ? AND ts < ?', (int(port), start, end))
    return True


def _roll_host_five_minutes(conn, metric, start, now):
    end = start + 3600
    rows = conn.execute(
        'SELECT * FROM host_metric_rollups WHERE metric=? AND bucket_seconds=300 '
        'AND bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start',
        (metric, start, end),
    ).fetchall()
    if not rows:
        return False
    count = sum(row['sample_count'] for row in rows)
    aggregate = {
        'metric': metric, 'bucket_start': start, 'bucket_seconds': 3600,
        'min_value': min(row['min_value'] for row in rows if row['min_value'] is not None),
        'max_value': max(row['max_value'] for row in rows if row['max_value'] is not None),
        'avg_value': sum(row['avg_value'] * row['sample_count'] for row in rows if row['avg_value'] is not None) / count,
        'latest_value': rows[-1]['latest_value'], 'sample_count': count,
        'observed_seconds': sum(row['observed_seconds'] for row in rows),
        'gap_seconds': sum(row['gap_seconds'] for row in rows),
        'unknown_seconds': sum(row['unknown_seconds'] for row in rows),
    }
    _upsert_and_verify(conn, 'host_metric_rollups', aggregate, ('metric', 'bucket_start', 'bucket_seconds'))
    _mark_succeeded(conn, 'host', metric, start, 3600, now)
    conn.execute(
        'DELETE FROM host_metric_rollups WHERE metric=? AND bucket_seconds=300 '
        'AND bucket_start >= ? AND bucket_start < ?', (metric, start, end),
    )
    return True


def _roll_service_five_minutes(conn, port, start, now):
    end = start + 3600
    rows = conn.execute(
        'SELECT * FROM service_rollups WHERE service_port=? AND bucket_seconds=300 '
        'AND bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start',
        (int(port), start, end),
    ).fetchall()
    if not rows:
        return False
    latencies = [(row['latency_avg'], row['check_count']) for row in rows if row['latency_avg'] is not None]
    failures = {}
    for row in rows:
        for failure, count in json.loads(row['failure_class_counts_json']).items():
            failures[failure] = failures.get(failure, 0) + int(count)
    checks = sum(row['check_count'] for row in rows)
    aggregate = {
        'service_port': int(port), 'bucket_start': start, 'bucket_seconds': 3600,
        'online_seconds': sum(row['online_seconds'] for row in rows),
        'offline_seconds': sum(row['offline_seconds'] for row in rows),
        'unknown_seconds': sum(row['unknown_seconds'] for row in rows),
        'gap_seconds': sum(row['gap_seconds'] for row in rows),
        'latency_min': min((row['latency_min'] for row in rows if row['latency_min'] is not None), default=None),
        'latency_max': max((row['latency_max'] for row in rows if row['latency_max'] is not None), default=None),
        'latency_avg': (sum(value * count for value, count in latencies) / sum(count for _, count in latencies)) if latencies else None,
        'check_count': checks,
        'failure_class_counts_json': json.dumps(failures, separators=(',', ':'), sort_keys=True),
    }
    _upsert_and_verify(conn, 'service_rollups', aggregate, ('service_port', 'bucket_start', 'bucket_seconds'))
    _mark_succeeded(conn, 'service', port, start, 3600, now)
    conn.execute(
        'DELETE FROM service_rollups WHERE service_port=? AND bucket_seconds=300 '
        'AND bucket_start >= ? AND bucket_start < ?', (int(port), start, end),
    )
    return True


def run_retention_batch(conn, *, now, policy=None, before_verify=None, raise_on_failure=False):
    """Roll at most one deterministic batch inside the caller-owned worker transaction."""
    policy = policy or RetentionPolicy()
    now = int(now)
    raw_cutoff = now - policy.raw_days * 86400
    five_cutoff = now - policy.five_minute_days * 86400
    candidates = _raw_candidates(conn, raw_cutoff) + _five_minute_candidates(conn, five_cutoff)
    ordered = sorted(set(candidates), key=lambda item: (item[0], item[1], item[2], item[3]))
    rolled = 0
    failures = 0
    for index, (start, seconds, kind, stream_key) in enumerate(ordered[:policy.rollup_batch_buckets]):
        savepoint = f'telemetry_bucket_{index}'
        conn.execute(f'SAVEPOINT {savepoint}')
        stream_kind = 'host' if kind.startswith('host') else 'service'
        try:
            if kind == 'host':
                changed = _roll_host_raw(conn, start, now, policy)
            elif kind == 'service':
                changed = _roll_service_raw(conn, stream_key, start, now)
            elif kind == 'host_rollup':
                changed = _roll_host_five_minutes(conn, stream_key, start, now)
            else:
                changed = _roll_service_five_minutes(conn, stream_key, start, now)
            if changed and before_verify is not None:
                before_verify(kind, stream_key, start, seconds)
            conn.execute(f'RELEASE SAVEPOINT {savepoint}')
            rolled += int(bool(changed))
        except Exception as error:
            conn.execute(f'ROLLBACK TO SAVEPOINT {savepoint}')
            conn.execute(f'RELEASE SAVEPOINT {savepoint}')
            _mark_failed(conn, stream_kind, stream_key, start, seconds, now, policy, error)
            failures += 1
            if raise_on_failure:
                raise
    expiry_cutoff = now - policy.retention_days * 86400
    conn.execute('DELETE FROM host_metric_rollups WHERE bucket_seconds=3600 AND bucket_start < ?', (expiry_cutoff,))
    conn.execute('DELETE FROM service_rollups WHERE bucket_seconds=3600 AND bucket_start < ?', (expiry_cutoff,))
    conn.execute('DELETE FROM events WHERE ts < ?', (expiry_cutoff,))
    return {'rolled_buckets': rolled, 'failed_buckets': failures}
