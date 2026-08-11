"""Parameterized SQLite queries used by thin Beacon adapters.

Repository functions receive an already-open connection.  They deliberately do
not own Flask request state, network clients, browsers, or connection lifetime.
"""

import json
import time

from .queues import enqueue_preview_in_transaction
from .telemetry import SourceSegment


HOST_METRIC_COLUMNS = {
    'cpu': 'cpu',
    'ram': 'ram',
    'disk': 'disk',
    'temp': 'temp',
}

# These maps are deliberately constructed from module-owned strings.  Request
# values choose an entry; they never become an SQL identifier.
HOST_QUERY_SHAPES = {
    metric: {
        'raw': (
            'WITH ranked AS ('
            f'SELECT ts, ts - (ts % ?) AS bucket_start, {column} AS value, '
            f'ROW_NUMBER() OVER (PARTITION BY ts - (ts % ?) ORDER BY ts DESC) AS latest_rank '
            f'FROM stats_history WHERE ts >= ? AND ts < ? AND {column} IS NOT NULL'
            ') SELECT bucket_start, MIN(ts) AS first_ts, MIN(value) AS min_value, MAX(value) AS max_value, '
            'AVG(value) AS avg_value, MAX(CASE WHEN latest_rank=1 THEN value END) AS latest_value, '
            'MAX(CASE WHEN latest_rank=1 THEN ts END) AS latest_ts, '
            'COUNT(*) AS sample_count, MIN(COUNT(*) * ?, ?) AS observed_seconds, '
            '0 AS gap_seconds, 0 AS unknown_seconds FROM ranked GROUP BY bucket_start '
            'ORDER BY bucket_start ASC LIMIT ?'
        ),
        'raw_fallback': (
            'WITH ranked AS ('
            f'SELECT ts, ts - (ts % ?) AS bucket_start, {column} AS value, '
            f'ROW_NUMBER() OVER (PARTITION BY ts - (ts % ?) ORDER BY ts DESC) AS latest_rank '
            f'FROM stats_history WHERE ts >= ? AND ts < ? AND {column} IS NOT NULL '
            'AND NOT EXISTS ('
            'SELECT 1 FROM host_metric_rollups replacement WHERE replacement.metric=? '
            'AND replacement.bucket_seconds IN (300, 3600) '
            'AND replacement.bucket_start <= stats_history.ts '
            'AND replacement.bucket_start + replacement.bucket_seconds > stats_history.ts'
            ')'
            ') SELECT bucket_start, MIN(ts) AS first_ts, MIN(value) AS min_value, MAX(value) AS max_value, '
            'AVG(value) AS avg_value, MAX(CASE WHEN latest_rank=1 THEN value END) AS latest_value, '
            'MAX(CASE WHEN latest_rank=1 THEN ts END) AS latest_ts, '
            'COUNT(*) AS sample_count, MIN(COUNT(*) * ?, ?) AS observed_seconds, '
            '0 AS gap_seconds, 0 AS unknown_seconds FROM ranked GROUP BY bucket_start '
            'ORDER BY bucket_start ASC LIMIT ?'
        ),
        'rollup': (
            'WITH ranked AS ('
            'SELECT bucket_start - (bucket_start % ?) AS display_start, min_value, max_value, '
            'avg_value, latest_value, sample_count, observed_seconds, gap_seconds, unknown_seconds, '
            'ROW_NUMBER() OVER (PARTITION BY bucket_start - (bucket_start % ?) '
            'ORDER BY bucket_start DESC) AS latest_rank FROM host_metric_rollups '
            'WHERE metric=? AND bucket_seconds=? AND bucket_start >= ? AND bucket_start < ?'
            ') SELECT display_start AS bucket_start, MIN(display_start) AS first_ts, MIN(min_value) AS min_value, '
            'MAX(max_value) AS max_value, '
            'SUM(avg_value * sample_count) / NULLIF(SUM(sample_count), 0) AS avg_value, '
            'MAX(CASE WHEN latest_rank=1 THEN latest_value END) AS latest_value, '
            'MAX(CASE WHEN latest_rank=1 THEN display_start END) AS latest_ts, '
            'SUM(sample_count) AS sample_count, SUM(observed_seconds) AS observed_seconds, '
            'SUM(gap_seconds) AS gap_seconds, SUM(unknown_seconds) AS unknown_seconds '
            'FROM ranked GROUP BY display_start ORDER BY display_start ASC LIMIT ?'
        ),
        'rollup_fallback': (
            'WITH ranked AS ('
            'SELECT bucket_start - (bucket_start % ?) AS display_start, min_value, max_value, '
            'avg_value, latest_value, sample_count, observed_seconds, gap_seconds, unknown_seconds, '
            'ROW_NUMBER() OVER (PARTITION BY bucket_start - (bucket_start % ?) '
            'ORDER BY bucket_start DESC) AS latest_rank FROM host_metric_rollups '
            'WHERE metric=? AND bucket_seconds=300 AND bucket_start >= ? AND bucket_start < ? '
            'AND NOT EXISTS ('
            'SELECT 1 FROM host_metric_rollups replacement WHERE replacement.metric=host_metric_rollups.metric '
            'AND replacement.bucket_seconds=3600 '
            'AND replacement.bucket_start <= host_metric_rollups.bucket_start '
            'AND replacement.bucket_start + replacement.bucket_seconds > host_metric_rollups.bucket_start'
            ')'
            ') SELECT display_start AS bucket_start, MIN(display_start) AS first_ts, MIN(min_value) AS min_value, '
            'MAX(max_value) AS max_value, '
            'SUM(avg_value * sample_count) / NULLIF(SUM(sample_count), 0) AS avg_value, '
            'MAX(CASE WHEN latest_rank=1 THEN latest_value END) AS latest_value, '
            'MAX(CASE WHEN latest_rank=1 THEN display_start END) AS latest_ts, '
            'SUM(sample_count) AS sample_count, SUM(observed_seconds) AS observed_seconds, '
            'SUM(gap_seconds) AS gap_seconds, SUM(unknown_seconds) AS unknown_seconds '
            'FROM ranked GROUP BY display_start ORDER BY display_start ASC LIMIT ?'
        ),
    }
    for metric, column in HOST_METRIC_COLUMNS.items()
}

SERVICE_QUERY_SHAPES = {
    'raw': (
        'WITH RECURSIVE source_rows AS ('
        'SELECT ts, online, latency_ms, error_class FROM service_checks '
        'WHERE port=? AND ts < ? ORDER BY ts DESC LIMIT 1'
        '), all_rows AS ('
        'SELECT * FROM source_rows UNION ALL '
        'SELECT ts, online, latency_ms, error_class FROM service_checks '
        'WHERE port=? AND ts >= ? AND ts < ?'
        '), segments AS ('
        'SELECT MAX(ts, ?) AS start_ts, MIN(LEAD(ts, 1, ?) OVER (ORDER BY ts), ?) AS end_ts, online '
        'FROM all_rows'
        '), buckets(bucket_start) AS ('
        'SELECT ? - (? % ?) UNION ALL SELECT bucket_start + ? FROM buckets '
        'WHERE bucket_start + ? < ?'
        '), durations AS ('
        'SELECT b.bucket_start, '
        'SUM(CASE WHEN s.online=1 THEN MAX(0, MIN(s.end_ts, b.bucket_start + ?, ?) '
        '- MAX(s.start_ts, b.bucket_start, ?)) ELSE 0 END) AS online_seconds, '
        'SUM(CASE WHEN s.online=0 THEN MAX(0, MIN(s.end_ts, b.bucket_start + ?, ?) '
        '- MAX(s.start_ts, b.bucket_start, ?)) ELSE 0 END) AS offline_seconds, '
        'SUM(CASE WHEN s.online IS NULL THEN MAX(0, MIN(s.end_ts, b.bucket_start + ?, ?) '
        '- MAX(s.start_ts, b.bucket_start, ?)) ELSE 0 END) AS unknown_seconds '
        'FROM buckets b LEFT JOIN segments s ON s.start_ts < MIN(b.bucket_start + ?, ?) '
        'AND s.end_ts > MAX(b.bucket_start, ?) GROUP BY b.bucket_start'
        '), sample_rows AS ('
        'SELECT ts - (ts % ?) AS bucket_start, latency_ms, error_class FROM service_checks '
        'WHERE port=? AND ts >= ? AND ts < ?'
        '), sample_stats AS ('
        'SELECT bucket_start, MIN(latency_ms) AS latency_min, MAX(latency_ms) AS latency_max, '
        'AVG(latency_ms) AS latency_avg, COUNT(*) AS check_count, '
        'SUM(CASE WHEN latency_ms IS NOT NULL THEN 1 ELSE 0 END) AS latency_sample_count '
        'FROM sample_rows GROUP BY bucket_start'
        '), failure_counts AS ('
        'SELECT bucket_start, error_class, COUNT(*) AS count FROM sample_rows '
        'WHERE error_class IS NOT NULL GROUP BY bucket_start, error_class'
        '), failure_json AS ('
        'SELECT bucket_start, json_group_object(error_class, count) AS failure_class_counts_json '
        'FROM failure_counts GROUP BY bucket_start'
        ') SELECT b.bucket_start, COALESCE(d.online_seconds, 0) AS online_seconds, '
        'COALESCE(d.offline_seconds, 0) AS offline_seconds, COALESCE(d.unknown_seconds, 0) AS unknown_seconds, '
        '0 AS gap_seconds, s.latency_min, s.latency_max, s.latency_avg, '
        'COALESCE(s.latency_sample_count, 0) AS latency_sample_count, COALESCE(s.check_count, 0) AS check_count, '
        "COALESCE(f.failure_class_counts_json, '{}') AS failure_class_counts_json "
        'FROM buckets b LEFT JOIN durations d ON d.bucket_start=b.bucket_start '
        'LEFT JOIN sample_stats s ON s.bucket_start=b.bucket_start '
        'LEFT JOIN failure_json f ON f.bucket_start=b.bucket_start '
        'WHERE (COALESCE(d.online_seconds, 0) > 0 OR COALESCE(d.offline_seconds, 0) > 0 '
        'OR COALESCE(d.unknown_seconds, 0) > 0 OR s.bucket_start IS NOT NULL) '
        'AND EXISTS (SELECT 1 FROM all_rows) '
        'ORDER BY b.bucket_start ASC LIMIT ?'
    ),
    'raw_fallback': (
        'WITH RECURSIVE source_rows AS ('
        'SELECT ts, online, latency_ms, error_class FROM service_checks '
        'WHERE port=? AND ts < ? ORDER BY ts DESC LIMIT 1'
        '), all_rows AS ('
        'SELECT * FROM source_rows UNION ALL '
        'SELECT ts, online, latency_ms, error_class FROM service_checks '
        'WHERE port=? AND ts >= ? AND ts < ? AND NOT EXISTS ('
        'SELECT 1 FROM service_rollups replacement WHERE replacement.service_port=service_checks.port '
        'AND replacement.bucket_seconds IN (300, 3600) '
        'AND replacement.bucket_start <= service_checks.ts '
        'AND replacement.bucket_start + replacement.bucket_seconds > service_checks.ts'
        ')'
        '), segments AS ('
        'SELECT MAX(ts, ?) AS start_ts, MIN(LEAD(ts, 1, ?) OVER (ORDER BY ts), ?) AS end_ts, online '
        'FROM all_rows'
        '), buckets(bucket_start) AS ('
        'SELECT ? - (? % ?) UNION ALL SELECT bucket_start + ? FROM buckets '
        'WHERE bucket_start + ? < ?'
        '), durations AS ('
        'SELECT b.bucket_start, '
        'SUM(CASE WHEN s.online=1 THEN MAX(0, MIN(s.end_ts, b.bucket_start + ?, ?) '
        '- MAX(s.start_ts, b.bucket_start, ?)) ELSE 0 END) AS online_seconds, '
        'SUM(CASE WHEN s.online=0 THEN MAX(0, MIN(s.end_ts, b.bucket_start + ?, ?) '
        '- MAX(s.start_ts, b.bucket_start, ?)) ELSE 0 END) AS offline_seconds, '
        'SUM(CASE WHEN s.online IS NULL THEN MAX(0, MIN(s.end_ts, b.bucket_start + ?, ?) '
        '- MAX(s.start_ts, b.bucket_start, ?)) ELSE 0 END) AS unknown_seconds '
        'FROM buckets b LEFT JOIN segments s ON s.start_ts < MIN(b.bucket_start + ?, ?) '
        'AND s.end_ts > MAX(b.bucket_start, ?) GROUP BY b.bucket_start'
        '), sample_rows AS ('
        'SELECT ts - (ts % ?) AS bucket_start, latency_ms, error_class FROM service_checks '
        'WHERE port=? AND ts >= ? AND ts < ? AND NOT EXISTS ('
        'SELECT 1 FROM service_rollups replacement WHERE replacement.service_port=service_checks.port '
        'AND replacement.bucket_seconds IN (300, 3600) '
        'AND replacement.bucket_start <= service_checks.ts '
        'AND replacement.bucket_start + replacement.bucket_seconds > service_checks.ts'
        ')'
        '), sample_stats AS ('
        'SELECT bucket_start, MIN(latency_ms) AS latency_min, MAX(latency_ms) AS latency_max, '
        'AVG(latency_ms) AS latency_avg, COUNT(*) AS check_count, '
        'SUM(CASE WHEN latency_ms IS NOT NULL THEN 1 ELSE 0 END) AS latency_sample_count '
        'FROM sample_rows GROUP BY bucket_start'
        '), failure_counts AS ('
        'SELECT bucket_start, error_class, COUNT(*) AS count FROM sample_rows '
        'WHERE error_class IS NOT NULL GROUP BY bucket_start, error_class'
        '), failure_json AS ('
        'SELECT bucket_start, json_group_object(error_class, count) AS failure_class_counts_json '
        'FROM failure_counts GROUP BY bucket_start'
        ') SELECT b.bucket_start, COALESCE(d.online_seconds, 0) AS online_seconds, '
        'COALESCE(d.offline_seconds, 0) AS offline_seconds, COALESCE(d.unknown_seconds, 0) AS unknown_seconds, '
        '0 AS gap_seconds, s.latency_min, s.latency_max, s.latency_avg, '
        'COALESCE(s.latency_sample_count, 0) AS latency_sample_count, COALESCE(s.check_count, 0) AS check_count, '
        "COALESCE(f.failure_class_counts_json, '{}') AS failure_class_counts_json "
        'FROM buckets b LEFT JOIN durations d ON d.bucket_start=b.bucket_start '
        'LEFT JOIN sample_stats s ON s.bucket_start=b.bucket_start '
        'LEFT JOIN failure_json f ON f.bucket_start=b.bucket_start '
        'WHERE (COALESCE(d.online_seconds, 0) > 0 OR COALESCE(d.offline_seconds, 0) > 0 '
        'OR COALESCE(d.unknown_seconds, 0) > 0 OR s.bucket_start IS NOT NULL) '
        'AND EXISTS (SELECT 1 FROM all_rows) '
        'ORDER BY b.bucket_start ASC LIMIT ?'
    ),
    'rollup': (
        'WITH ranked AS ('
        'SELECT bucket_start - (bucket_start % ?) AS display_start, online_seconds, offline_seconds, '
        'unknown_seconds, gap_seconds, latency_min, latency_max, latency_avg, latency_sample_count, '
        'check_count, failure_class_counts_json, ROW_NUMBER() OVER ('
        'PARTITION BY bucket_start - (bucket_start % ?) ORDER BY bucket_start DESC) AS latest_rank '
        'FROM service_rollups WHERE service_port=? AND bucket_seconds=? '
        'AND bucket_start >= ? AND bucket_start < ?'
        ') SELECT display_start AS bucket_start, SUM(online_seconds) AS online_seconds, '
        'SUM(offline_seconds) AS offline_seconds, SUM(unknown_seconds) AS unknown_seconds, '
        'SUM(gap_seconds) AS gap_seconds, MIN(latency_min) AS latency_min, MAX(latency_max) AS latency_max, '
        'SUM(latency_avg * latency_sample_count) / NULLIF(SUM(latency_sample_count), 0) AS latency_avg, '
        'SUM(latency_sample_count) AS latency_sample_count, SUM(check_count) AS check_count, '
        'json_group_array(failure_class_counts_json) AS failure_class_counts_json '
        'FROM ranked GROUP BY display_start ORDER BY display_start ASC LIMIT ?'
    ),
    'rollup_fallback': (
        'WITH ranked AS ('
        'SELECT bucket_start - (bucket_start % ?) AS display_start, online_seconds, offline_seconds, '
        'unknown_seconds, gap_seconds, latency_min, latency_max, latency_avg, latency_sample_count, '
        'check_count, failure_class_counts_json, ROW_NUMBER() OVER ('
        'PARTITION BY bucket_start - (bucket_start % ?) ORDER BY bucket_start DESC) AS latest_rank '
        'FROM service_rollups WHERE service_port=? AND bucket_seconds=300 '
        'AND bucket_start >= ? AND bucket_start < ? AND NOT EXISTS ('
        'SELECT 1 FROM service_rollups replacement '
        'WHERE replacement.service_port=service_rollups.service_port AND replacement.bucket_seconds=3600 '
        'AND replacement.bucket_start <= service_rollups.bucket_start '
        'AND replacement.bucket_start + replacement.bucket_seconds > service_rollups.bucket_start'
        ')'
        ') SELECT display_start AS bucket_start, SUM(online_seconds) AS online_seconds, '
        'SUM(offline_seconds) AS offline_seconds, SUM(unknown_seconds) AS unknown_seconds, '
        'SUM(gap_seconds) AS gap_seconds, MIN(latency_min) AS latency_min, MAX(latency_max) AS latency_max, '
        'SUM(latency_avg * latency_sample_count) / NULLIF(SUM(latency_sample_count), 0) AS latency_avg, '
        'SUM(latency_sample_count) AS latency_sample_count, SUM(check_count) AS check_count, '
        'json_group_array(failure_class_counts_json) AS failure_class_counts_json '
        'FROM ranked GROUP BY display_start ORDER BY display_start ASC LIMIT ?'
    ),
}


def _cutoff(cutoffs, name):
    try:
        return int(cutoffs[name])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('invalid telemetry cutoffs') from error


def _tier_ranges(start_ts, end_ts, cutoffs):
    raw_start = _cutoff(cutoffs, 'raw_start_ts')
    five_start = _cutoff(cutoffs, 'five_minute_start_ts')
    return (
        ('hourly', 3600, max(start_ts, -(2 ** 63)), min(end_ts, five_start)),
        ('five_minute', 300, max(start_ts, five_start), min(end_ts, raw_start)),
        ('raw', 60, max(start_ts, raw_start), end_ts),
    )


def _fallback_ranges(start_ts, end_ts, cutoffs):
    """Return lower-tier ranges that need evidence until a replacement exists."""
    raw_start = _cutoff(cutoffs, 'raw_start_ts')
    five_start = _cutoff(cutoffs, 'five_minute_start_ts')
    return (
        ('five_minute', 300, int(start_ts), min(int(end_ts), five_start)),
        ('raw', 60, int(start_ts), min(int(end_ts), raw_start)),
    )


def _checked_rows(conn, query, values, limit):
    rows = conn.execute(query, values).fetchall()
    if len(rows) > limit - 1:
        raise ValueError('telemetry query exceeded point budget')
    return tuple(dict(row) for row in rows)


def get_host_telemetry(conn, metric, start_ts, end_ts, display_bucket_seconds, limit, cutoffs):
    """Read an allowlisted host stream from non-overlapping retained tiers."""
    if metric not in HOST_QUERY_SHAPES:
        raise ValueError('invalid host metric')
    if min(int(display_bucket_seconds), int(limit)) <= 0:
        raise ValueError('invalid telemetry query bounds')
    segments = []
    for tier, source_resolution, tier_start, tier_end in _tier_ranges(start_ts, end_ts, cutoffs):
        if tier_start >= tier_end:
            continue
        if tier == 'raw':
            values = (
                display_bucket_seconds, display_bucket_seconds, tier_start, tier_end,
                source_resolution, display_bucket_seconds, limit,
            )
            query = HOST_QUERY_SHAPES[metric]['raw']
        else:
            values = (
                display_bucket_seconds, display_bucket_seconds, metric, source_resolution,
                tier_start, tier_end, limit,
            )
            query = HOST_QUERY_SHAPES[metric]['rollup']
        rows = _checked_rows(conn, query, values, int(limit))
        if rows:
            segments.append(SourceSegment(source_resolution, rows))
    for tier, source_resolution, tier_start, tier_end in _fallback_ranges(start_ts, end_ts, cutoffs):
        if tier_start >= tier_end:
            continue
        if tier == 'raw':
            values = (
                display_bucket_seconds, display_bucket_seconds, tier_start, tier_end, metric,
                source_resolution, display_bucket_seconds, limit,
            )
            query = HOST_QUERY_SHAPES[metric]['raw_fallback']
        else:
            values = (
                display_bucket_seconds, display_bucket_seconds, metric, tier_start, tier_end, limit,
            )
            query = HOST_QUERY_SHAPES[metric]['rollup_fallback']
        rows = _checked_rows(conn, query, values, int(limit))
        if rows:
            segments.append(SourceSegment(source_resolution, rows))
    return tuple(segments)


def get_service_telemetry(conn, port, start_ts, end_ts, display_bucket_seconds, limit, cutoffs):
    """Read one range-checked service stream without materializing raw checks in Python."""
    port = int(port)
    if not 1 <= port <= 65535 or min(int(display_bucket_seconds), int(limit)) <= 0:
        raise ValueError('invalid telemetry query bounds')
    segments = []
    for tier, source_resolution, tier_start, tier_end in _tier_ranges(start_ts, end_ts, cutoffs):
        if tier_start >= tier_end:
            continue
        if tier == 'raw':
            values = (
                port, tier_start, port, tier_start, tier_end, tier_start, tier_end, tier_end,
                tier_start, tier_start, display_bucket_seconds, display_bucket_seconds,
                display_bucket_seconds, tier_end,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, port, tier_start, tier_end, limit,
            )
            query = SERVICE_QUERY_SHAPES['raw']
        else:
            values = (
                display_bucket_seconds, display_bucket_seconds, port, source_resolution,
                tier_start, tier_end, limit,
            )
            query = SERVICE_QUERY_SHAPES['rollup']
        rows = _checked_rows(conn, query, values, int(limit))
        if rows:
            segments.append(SourceSegment(source_resolution, rows))
    for tier, source_resolution, tier_start, tier_end in _fallback_ranges(start_ts, end_ts, cutoffs):
        if tier_start >= tier_end:
            continue
        if tier == 'raw':
            values = (
                port, tier_start, port, tier_start, tier_end, tier_start, tier_end, tier_end,
                tier_start, tier_start, display_bucket_seconds, display_bucket_seconds,
                display_bucket_seconds, tier_end,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, tier_end, tier_start,
                display_bucket_seconds, port, tier_start, tier_end, limit,
            )
            query = SERVICE_QUERY_SHAPES['raw_fallback']
        else:
            values = (
                display_bucket_seconds, display_bucket_seconds, port, tier_start, tier_end, limit,
            )
            query = SERVICE_QUERY_SHAPES['rollup_fallback']
        rows = _checked_rows(conn, query, values, int(limit))
        if rows:
            segments.append(SourceSegment(source_resolution, rows))
    return tuple(segments)


def get_telemetry_coverage(conn, stream_kind, stream_key, start_ts, end_ts, limit):
    """Return stream metadata and sparse unavailable evidence in ascending order."""
    if stream_kind not in ('host', 'service'):
        raise ValueError('invalid telemetry stream')
    stream = conn.execute(
        'SELECT started_ts, cadence_seconds, last_observed_ts FROM telemetry_streams '
        'WHERE stream_kind=? AND stream_key=?',
        (stream_kind, str(stream_key)),
    ).fetchone()
    rows = _checked_rows(
        conn,
        'SELECT start_ts, end_ts, reason, detail FROM telemetry_coverage '
        'WHERE stream_kind=? AND stream_key=? AND start_ts < ? AND end_ts > ? '
        'ORDER BY start_ts ASC, end_ts ASC LIMIT ?',
        (stream_kind, str(stream_key), int(end_ts), int(start_ts), int(limit)),
        int(limit),
    )
    return {
        'stream': dict(stream) if stream else None,
        'intervals': rows,
    }


def _pending_source_rows(conn, stream_kind, stream_key, start_ts, end_ts, cutoffs, limit):
    raw_start = _cutoff(cutoffs, 'raw_start_ts')
    five_start = _cutoff(cutoffs, 'five_minute_start_ts')
    if stream_kind == 'host':
        metric = str(stream_key)
        if metric not in HOST_METRIC_COLUMNS:
            raise ValueError('invalid host metric')
        column = HOST_METRIC_COLUMNS[metric]
        raw_query = (
            f'SELECT ts - (ts % 300) AS start_ts, ts - (ts % 300) + 300 AS end_ts '
            f'FROM stats_history WHERE ts < ? AND ts < ? AND ts >= ? AND {column} IS NOT NULL '
            'AND NOT EXISTS (SELECT 1 FROM host_metric_rollups replacement '
            'WHERE replacement.metric=? AND replacement.bucket_seconds IN (300, 3600) '
            'AND replacement.bucket_start <= stats_history.ts '
            'AND replacement.bucket_start + replacement.bucket_seconds > stats_history.ts) '
            'GROUP BY start_ts ORDER BY start_ts ASC LIMIT ?'
        )
        five_query = (
            'SELECT bucket_start AS start_ts, bucket_start + 3600 AS end_ts FROM host_metric_rollups '
            'WHERE metric=? AND bucket_seconds=300 AND bucket_start < ? AND bucket_start < ? '
            'AND bucket_start + 300 > ? AND NOT EXISTS (SELECT 1 FROM host_metric_rollups replacement '
            'WHERE replacement.metric=host_metric_rollups.metric AND replacement.bucket_seconds=3600 '
            'AND replacement.bucket_start <= host_metric_rollups.bucket_start '
            'AND replacement.bucket_start + replacement.bucket_seconds > host_metric_rollups.bucket_start) '
            'GROUP BY start_ts ORDER BY start_ts ASC LIMIT ?'
        )
        raw_values = (raw_start, int(end_ts), int(start_ts) - 300, metric, int(limit))
        five_values = (metric, five_start, int(end_ts), int(start_ts), int(limit))
    else:
        port = int(stream_key)
        raw_query = (
            'SELECT ts - (ts % 300) AS start_ts, ts - (ts % 300) + 300 AS end_ts FROM service_checks '
            'WHERE port=? AND ts < ? AND ts < ? AND ts >= ? AND NOT EXISTS ('
            'SELECT 1 FROM service_rollups replacement WHERE replacement.service_port=service_checks.port '
            'AND replacement.bucket_seconds IN (300, 3600) '
            'AND replacement.bucket_start <= service_checks.ts '
            'AND replacement.bucket_start + replacement.bucket_seconds > service_checks.ts) '
            'GROUP BY start_ts ORDER BY start_ts ASC LIMIT ?'
        )
        five_query = (
            'SELECT bucket_start AS start_ts, bucket_start + 3600 AS end_ts FROM service_rollups '
            'WHERE service_port=? AND bucket_seconds=300 AND bucket_start < ? AND bucket_start < ? '
            'AND bucket_start + 300 > ? AND NOT EXISTS (SELECT 1 FROM service_rollups replacement '
            'WHERE replacement.service_port=service_rollups.service_port AND replacement.bucket_seconds=3600 '
            'AND replacement.bucket_start <= service_rollups.bucket_start '
            'AND replacement.bucket_start + replacement.bucket_seconds > service_rollups.bucket_start) '
            'GROUP BY start_ts ORDER BY start_ts ASC LIMIT ?'
        )
        raw_values = (port, raw_start, int(end_ts), int(start_ts) - 300, int(limit))
        five_values = (port, five_start, int(end_ts), int(start_ts), int(limit))
    return (
        _checked_rows(conn, raw_query, raw_values, int(limit))
        + _checked_rows(conn, five_query, five_values, int(limit))
    )


def _coalesce_pending(rows):
    result = []
    for row in sorted(rows, key=lambda item: (item['start_ts'], item['end_ts'], item['state'])):
        if (
            result and row['state'] == 'pending' and result[-1]['state'] == 'pending'
            and row['start_ts'] <= result[-1]['end_ts']
        ):
            result[-1]['end_ts'] = max(result[-1]['end_ts'], row['end_ts'])
        else:
            result.append(dict(row))
    return tuple(result)


def get_pending_aggregation(
    conn, stream_kind, stream_key, start_ts, end_ts, display_bucket_seconds, limit, cutoffs,
):
    """Disclose bounded durable and derived rollup work without replacing coverage."""
    if stream_kind not in ('host', 'service') or min(int(display_bucket_seconds), int(limit)) <= 0:
        raise ValueError('invalid telemetry stream')
    keys = (('host', str(stream_key)), ('host', 'host')) if stream_kind == 'host' else (
        ('service', str(int(stream_key))),
    )
    durable_query = (
        'SELECT bucket_start AS start_ts, bucket_start + bucket_seconds AS end_ts, state, '
        'attempt_count, next_retry_ts, last_error_class AS error_class '
        'FROM telemetry_rollup_jobs WHERE ('
        + ' OR '.join('(stream_kind=? AND stream_key=?)' for _ in keys)
        + ") AND state IN ('pending', 'failed') AND bucket_start < ? "
        'AND bucket_start + bucket_seconds > ? ORDER BY bucket_start ASC LIMIT ?'
    )
    durable = _checked_rows(
        conn,
        durable_query,
        tuple(value for key in keys for value in key) + (int(end_ts), int(start_ts), int(limit)),
        int(limit),
    )
    derived = [
        {
            'start_ts': row['start_ts'], 'end_ts': row['end_ts'], 'state': 'pending',
            'attempt_count': 0, 'next_retry_ts': None, 'error_class': None,
        }
        for row in _pending_source_rows(
            conn, stream_kind, stream_key, start_ts, end_ts, cutoffs, limit,
        )
    ]
    durable_keys = {(row['start_ts'], row['end_ts']) for row in durable}
    rows = [row for row in derived if (row['start_ts'], row['end_ts']) not in durable_keys]
    rows.extend(durable)
    result = _coalesce_pending(rows)
    if len(result) > int(limit) - 1:
        raise ValueError('telemetry query exceeded point budget')
    return result


def get_host_metric_history(conn, metric, start_ts, end_ts, limit):
    """Return one allowlisted raw metric stream in ascending half-open order."""
    column = HOST_METRIC_COLUMNS.get(metric)
    if column is None:
        raise ValueError('invalid host metric')
    return conn.execute(
        f'SELECT ts, {column} AS value FROM stats_history '
        'WHERE ts >= ? AND ts < ? ORDER BY ts ASC LIMIT ?',
        (start_ts, end_ts, limit),
    ).fetchall()


def get_host_stream_bounds(conn):
    """Return the first and last raw host observations without retaining a cursor."""
    row = conn.execute(
        'SELECT MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM stats_history'
    ).fetchone()
    return (row['first_ts'], row['last_ts']) if row and row['first_ts'] is not None else None


class ThumbnailRepository:
    """Own thumbnail result persistence while callers retain transaction scope."""

    def store_thumbnail_result(
        self, conn, port, thumb_data, thumb_mime, thumb_source, thumb_error, ts=None,
    ):
        timestamp = int(time.time()) if ts is None else int(ts)
        if thumb_data and thumb_source == 'screenshot':
            conn.execute(
                "UPDATE services SET thumb_data=?, thumb_mime=?, thumb_ts=?, thumb_source=?, "
                "thumb_attempt_ts=?, thumb_error=NULL WHERE port=?",
                (thumb_data, thumb_mime, timestamp, thumb_source, timestamp, port),
            )
            return
        conn.execute(
            "UPDATE services SET thumb_data=NULL, thumb_mime='image/jpeg', thumb_ts=NULL, thumb_source=NULL, "
            "thumb_attempt_ts=?, thumb_error=? WHERE port=?",
            (timestamp, (thumb_error or 'screenshot failed')[:240], port),
        )


def get_service_metadata(conn, port):
    row = conn.execute(
        "SELECT m.port, COALESCE(m.display_name, '') AS display_name, "
        "COALESCE(m.url, '') AS url, COALESCE(m.critical, 0) AS critical, "
        "COALESCE(m.pinned_order, s.port) AS pinned_order, "
        "COALESCE(m.tags, '') AS tags, "
        "COALESCE(m.healthy_statuses, '200-399') AS healthy_statuses "
        "FROM services s LEFT JOIN service_meta m ON m.port = s.port "
        "WHERE s.port = ?",
        (port,),
    ).fetchone()
    return dict(row) if row else None


def get_service_metadata_values(conn, port):
    row = conn.execute(
        "SELECT display_name, url, critical, pinned_order, tags, healthy_statuses "
        "FROM service_meta WHERE port=?",
        (port,),
    ).fetchone()
    return dict(row) if row else None


def service_exists(conn, port):
    return conn.execute('SELECT 1 FROM services WHERE port=?', (port,)).fetchone() is not None


def upsert_service_metadata(
    conn, *, port, display_name, url, critical, pinned_order, tags,
    healthy_statuses, requested_ts,
):
    """Persist metadata and its durable preview request in the caller's transaction."""
    conn.execute(
        "INSERT INTO service_meta (port, display_name, url, critical, pinned_order, tags, healthy_statuses) "
        "VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(port) DO UPDATE SET display_name=excluded.display_name, url=excluded.url, "
        "critical=excluded.critical, pinned_order=excluded.pinned_order, tags=excluded.tags, "
        "healthy_statuses=excluded.healthy_statuses",
        (port, display_name, url, int(bool(critical)), pinned_order, tags, healthy_statuses),
    )
    return enqueue_preview_in_transaction(conn, port, now=requested_ts)


def get_runtime_state(conn, key, default=None):
    row = conn.execute('SELECT value FROM runtime_state WHERE key=?', (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row['value'])
    except (TypeError, ValueError):
        return default


def set_runtime_state(conn, key, value, updated_ts):
    conn.execute(
        "INSERT INTO runtime_state(key, value, updated_ts) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_ts=excluded.updated_ts",
        (key, json.dumps(value, separators=(',', ':')), updated_ts),
    )


def set_service_tls_posture(conn, port, tls_unverified, updated_ts):
    """Persist trust posture separately from service reachability fields."""
    current = get_runtime_state(conn, 'service_tls_posture', {})
    current = current if isinstance(current, dict) else {}
    current[str(int(port))] = bool(tls_unverified)
    set_runtime_state(conn, 'service_tls_posture', current, updated_ts)


def get_service_tls_posture(conn, port):
    current = get_runtime_state(conn, 'service_tls_posture', {})
    return bool(current.get(str(int(port)), False)) if isinstance(current, dict) else False


def get_events(conn, limit, since_ts=None):
    query = (
        "SELECT e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
        "e.latency_ms, e.error_class, e.alert_status, e.details, "
        "COALESCE(m.display_name, s.title, ':' || e.port) AS service_name "
        "FROM events e LEFT JOIN services s ON s.port=e.port "
        "LEFT JOIN service_meta m ON m.port=e.port "
    )
    if since_ts is None:
        return conn.execute(query + 'ORDER BY e.ts DESC, e.id DESC LIMIT ?', (limit,)).fetchall()
    return conn.execute(
        query + 'WHERE e.ts > ? ORDER BY e.ts DESC, e.id DESC LIMIT ?',
        (since_ts, limit),
    ).fetchall()
