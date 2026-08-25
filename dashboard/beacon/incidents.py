"""Framework-free range-and-filter event reads and honest incident grouping.

This module imports nothing from Flask or ``sqlite3`` directly -- it receives
an already-open connection from the caller, matching the shape of
``dashboard/beacon/telemetry.py``. It answers exactly one question: "what
happened to which services, grouped into down-to-recovered episodes, over a
validated range" -- reusing ``dashboard/beacon/telemetry.py``'s
``HistoricalRange`` as the single bounds validator (see the
04-02-PLAN.md ``<assumption_delta_decision>`` block) rather than inventing a
second one.

Grouping here is a *view* over durable ``events`` rows -- it creates no
durable record, merges no rows, and filters nothing out of the underlying
table. An episode with no observed recovery stays open (``recovered_ts``
``None``); it is never backfilled with the query's ``end_ts`` or the current
time (Research Pitfall 4).
"""


# The real event-type values this codebase writes, verified at every
# ``_insert_event``/``event_type=`` call site in ``dashboard/app.py``.
EVENT_TYPES = frozenset({
    'state_change',
    'monitoring_gap',
    'alert_sent',
    'alert_failed',
    'preview_capture',
    'preview_complete',
    'maintenance_overrun',
})

CRITICALITY_VALUES = frozenset({'critical', 'standard'})

# D-13: `/advanced` shows suppressed evidence by default; the filter may
# narrow to only-suppressed or only-unsuppressed rows.
MAINTENANCE_MODES = frozenset({'include', 'exclude', 'only'})
DEFAULT_MAINTENANCE_MODE = 'include'

# Mirrors the telemetry `point_budget` discipline (dashboard/beacon/config.py)
# so a busy 90-day range stays bounded rather than unbounded.
INCIDENT_ROW_BUDGET = 2048

# The UI-SPEC's resolved flapping rule: 3 or more episodes for the same
# service inside any 15-minute span.
FLAPPING_EPISODE_THRESHOLD = 3
FLAPPING_SPAN_SECONDS = 900

# The verbatim column set and joins `api_events` (dashboard/app.py) already
# uses -- reused exactly rather than re-derived, so this module and the
# legacy route can never silently drift apart on what an "event" row means.
EVENT_COLUMNS = (
    "e.id, e.ts, e.port, e.event_type, e.online, e.previous_online, "
    "e.latency_ms, e.error_class, e.alert_status, e.details, "
    "e.suppressed_reason, e.maintenance_grace_until, e.down_since_ts, "
    "COALESCE(m.display_name, s.title, ':' || e.port) AS service_name, "
    "COALESCE(m.critical, 0) AS critical"
)

_EVENT_FROM_JOIN = (
    "FROM events e "
    "LEFT JOIN services s ON s.port = e.port "
    "LEFT JOIN service_meta m ON m.port = e.port "
)


def _validate_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f'{name} must be an integer')
    return value


def read_events_in_range(
    conn, *, start_ts, end_ts, port=None, event_type=None, criticality=None,
    maintenance=DEFAULT_MAINTENANCE_MODE, limit=INCIDENT_ROW_BUDGET,
):
    """Read events in `[start_ts, end_ts)` after allowlisting every filter value.

    Every filter is validated by name before any SQL is built; an
    out-of-allowlist value raises `ValueError` naming the offending
    parameter -- reject, never coerce. Every value reaches SQLite as a bound
    `?` parameter; none is ever concatenated or interpolated into the
    statement text. Returns `(rows, truncated)`, where `truncated` is True
    only when more than `limit` rows matched.
    """
    _validate_int(start_ts, 'start_ts')
    _validate_int(end_ts, 'end_ts')
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError('limit must be a positive integer')

    clauses = ['e.ts >= ?', 'e.ts < ?']
    params = [start_ts, end_ts]

    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('port must be an integer between 1 and 65535')
        clauses.append('e.port = ?')
        params.append(port)

    if event_type is not None:
        if event_type not in EVENT_TYPES:
            raise ValueError('event_type must be one of the recognised event types')
        clauses.append('e.event_type = ?')
        params.append(event_type)

    if criticality is not None:
        if criticality not in CRITICALITY_VALUES:
            raise ValueError('criticality must be "critical" or "standard"')
        clauses.append('COALESCE(m.critical, 0) = ?')
        params.append(1 if criticality == 'critical' else 0)

    if maintenance not in MAINTENANCE_MODES:
        raise ValueError('maintenance must be "include", "exclude", or "only"')
    if maintenance == 'exclude':
        clauses.append('e.suppressed_reason IS NULL')
    elif maintenance == 'only':
        clauses.append('e.suppressed_reason IS NOT NULL')

    where = ' AND '.join(clauses)
    statement = (
        'SELECT ' + EVENT_COLUMNS + ' '
        + _EVENT_FROM_JOIN
        + 'WHERE ' + where + ' '
        'ORDER BY e.ts ASC, e.id ASC LIMIT ?'
    )
    params.append(limit + 1)
    rows = conn.execute(statement, tuple(params)).fetchall()
    truncated = len(rows) > limit
    if truncated:
        rows = rows[:limit]
    return rows, truncated


def read_open_episode_anchors(conn, *, start_ts, ports):
    """Return each port's most recent still-relevant down row before `start_ts`.

    For each port, at most one row is returned: the most recent
    `state_change` with `online = 0` strictly before `start_ts`. This is what
    lets an outage that *began* before the selected range group correctly
    instead of appearing as a recovery with no cause. It reads durable rows
    only and invents nothing. Uses `idx_events_port_ts`.
    """
    _validate_int(start_ts, 'start_ts')
    statement = (
        'SELECT ' + EVENT_COLUMNS + ' '
        + _EVENT_FROM_JOIN
        + 'WHERE e.port = ? AND e.event_type = ? AND e.online = 0 AND e.ts < ? '
        'ORDER BY e.ts DESC, e.id DESC LIMIT 1'
    )
    anchors = []
    for port in ports:
        row = conn.execute(statement, (port, 'state_change', start_ts)).fetchone()
        if row is not None:
            anchors.append(row)
    return anchors


def split_overrun_span(down_ts, recovered_ts, grace_until):
    """Split a down-to-recovered span at `grace_until`, or refuse to guess.

    With no `grace_until`, the whole span is fault and `overrun` is False.
    With a `grace_until`, `grace_seconds` is the portion of the span at or
    before it and `fault_seconds` the portion after; `overrun` is True only
    when `fault_seconds` is greater than zero. When `recovered_ts` is None,
    both `fault_seconds` and `grace_seconds` are None -- an unresolved
    overrun is never measured against a clock the operator did not observe
    (Research Pitfall 4).
    """
    if recovered_ts is None:
        return {'overrun': False, 'grace_seconds': None, 'fault_seconds': None}
    span = recovered_ts - down_ts
    if grace_until is None:
        return {'overrun': False, 'grace_seconds': 0, 'fault_seconds': span}
    grace_seconds = max(0, min(span, grace_until - down_ts))
    fault_seconds = max(0, span - grace_seconds)
    return {
        'overrun': fault_seconds > 0,
        'grace_seconds': grace_seconds,
        'fault_seconds': fault_seconds,
    }


def _finalize_episode(episode):
    episode.update(split_overrun_span(
        episode['down_ts'], episode['recovered_ts'], episode['maintenance_grace_until'],
    ))
    return episode


def group_episodes(rows):
    """Group one port's `state_change` rows (ordered `ts ASC`) into episodes.

    A row with `online = 0` opens an episode; a row with `online = 1` closes
    the currently open one. A closing row with nothing open emits no
    episode -- it stays available in the caller's flat transition list. A
    still-open episode is returned with `recovered_ts = None`,
    `duration_seconds = None`, `open = True` -- never closed against a query
    end or the current time. Rows whose `event_type` is not `state_change`
    never participate in grouping.
    """
    episodes = []
    open_episode = None
    for row in rows:
        if row['event_type'] != 'state_change':
            continue
        online = row['online']
        if online == 0:
            down_since = row['down_since_ts']
            down_ts = int(down_since) if down_since is not None else int(row['ts'])
            open_episode = {
                'port': row['port'],
                'service_name': row['service_name'],
                'critical': bool(row['critical']),
                'down_ts': down_ts,
                'raised_ts': int(row['ts']),
                'recovered_ts': None,
                'open': True,
                'duration_seconds': None,
                'failure_class': row['error_class'],
                'suppressed_reason': row['suppressed_reason'],
                'maintenance_grace_until': row['maintenance_grace_until'],
                'transitions': [row],
            }
        elif online == 1 and open_episode is not None:
            open_episode['recovered_ts'] = int(row['ts'])
            open_episode['open'] = False
            open_episode['duration_seconds'] = (
                open_episode['recovered_ts'] - open_episode['down_ts']
            )
            open_episode['transitions'].append(row)
            episodes.append(_finalize_episode(open_episode))
            open_episode = None
        # online == 1 with nothing open: no episode emitted, row stays flat.
    if open_episode is not None:
        episodes.append(_finalize_episode(open_episode))
    return episodes


def classify_flapping(episodes):
    """Assign a shared `flapping_group_id` to dense runs of same-port episodes.

    A run of `FLAPPING_EPISODE_THRESHOLD` or more episodes for the same port
    whose `down_ts` values all fall inside a `FLAPPING_SPAN_SECONDS` window
    shares one integer id; every other episode gets `None`. This is a
    classification over the rows already returned -- it creates no durable
    record, merges no rows, and filters nothing.
    """
    for episode in episodes:
        episode.setdefault('flapping_group_id', None)

    by_port = {}
    for episode in episodes:
        by_port.setdefault(episode['port'], []).append(episode)

    groups = []
    next_group_id = 1
    for port, port_episodes in by_port.items():
        ordered = sorted(port_episodes, key=lambda item: item['down_ts'])
        count_total = len(ordered)
        index = 0
        while index < count_total:
            end = index
            while (
                end + 1 < count_total
                and ordered[end + 1]['down_ts'] - ordered[index]['down_ts'] <= FLAPPING_SPAN_SECONDS
            ):
                end += 1
            run_count = end - index + 1
            if run_count >= FLAPPING_EPISODE_THRESHOLD:
                group_id = next_group_id
                next_group_id += 1
                span_seconds = ordered[end]['down_ts'] - ordered[index]['down_ts']
                for member in ordered[index:end + 1]:
                    member['flapping_group_id'] = group_id
                groups.append({
                    'id': group_id,
                    'port': port,
                    'count': run_count,
                    'span_seconds': span_seconds,
                })
                index = end + 1
            else:
                index += 1
    return groups


def _opening_event_id(episode):
    transitions = episode.get('transitions') or []
    return int(transitions[0]['id']) if transitions else 0


def compose_incidents_response(rows, anchors, *, start_ts, end_ts, filters, truncated):
    """Compose the full `/api/events/history` response from one query result set.

    Partitions rows by port, prepends each port's anchor row when present,
    groups, applies the overrun split (inside `group_episodes`) and the
    flapping classification, and returns
    `{requested, filters, episodes, events, flapping_groups, row_budget,
    truncated, matched_count}`. `episodes` is ordered open first, then
    `down_ts` descending, then opening event `id` descending -- a total
    order, so equal timestamps never reorder between identical requests.
    `events` is the flat filtered transition list ordered `ts DESC, id DESC`
    -- both projections come from the one query result set.
    """
    anchors_by_port = {anchor['port']: anchor for anchor in anchors}

    rows_by_port = {}
    for row in rows:
        rows_by_port.setdefault(row['port'], []).append(row)

    episodes = []
    for port, port_rows in rows_by_port.items():
        combined = []
        anchor = anchors_by_port.get(port)
        if anchor is not None:
            combined.append(anchor)
        combined.extend(sorted(port_rows, key=lambda row: (row['ts'], row['id'])))
        episodes.extend(group_episodes(combined))

    flapping_groups = classify_flapping(episodes)

    episodes.sort(key=lambda episode: (
        0 if episode['open'] else 1,
        -episode['down_ts'],
        -_opening_event_id(episode),
    ))

    events = sorted(rows, key=lambda row: (-row['ts'], -row['id']))

    return {
        'requested': {'start_ts': start_ts, 'end_ts': end_ts},
        'filters': filters,
        'episodes': episodes,
        'events': [dict(row) for row in events],
        'flapping_groups': flapping_groups,
        'row_budget': INCIDENT_ROW_BUDGET,
        'truncated': truncated,
        'matched_count': len(rows),
    }
