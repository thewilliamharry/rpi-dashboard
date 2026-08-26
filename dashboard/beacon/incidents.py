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

# Published in the `episode_scope.grouped_from` response key: episodes are
# always grouped from every `state_change` in the requested range for the
# in-scope services, never from the row set the `event_type` or
# `maintenance` filter already narrowed (D-12; 04-09-PLAN.md
# <assumption_delta_decision>).
EPISODE_GROUPING_SOURCE = 'all_state_changes_in_range'

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


def build_events_query(
    *, start_ts, end_ts, port=None, event_type=None, criticality=None,
    maintenance=DEFAULT_MAINTENANCE_MODE, limit=INCIDENT_ROW_BUDGET,
):
    """Validate every filter and return `(statement, params)` for the range read.

    Split out from `read_events_in_range` so a caller (a test proving
    Research Assumption A3's index-backed query plan, or a future EXPLAIN
    diagnostic) can inspect the exact statement text without a second,
    possibly-diverging, hand-written copy of it. Every filter value reaches
    SQLite as a bound `?` parameter; none is ever concatenated or
    interpolated into the statement text -- an out-of-allowlist value raises
    `ValueError` naming the offending parameter.
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
    return statement, tuple(params)


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
    statement, params = build_events_query(
        start_ts=start_ts, end_ts=end_ts, port=port, event_type=event_type,
        criticality=criticality, maintenance=maintenance, limit=limit,
    )
    rows = conn.execute(statement, params).fetchall()
    truncated = len(rows) > limit
    if truncated:
        rows = rows[:limit]
    return rows, truncated


def build_open_anchor_query(*, port, start_ts):
    """Return `(statement, params)` for the per-port anchor seek.

    Selects the most recent `state_change` row strictly before `start_ts`
    for the given port, regardless of its `online` value -- the caller
    decides whether it represents an open anchor. Split out so a test can
    inspect the exact statement text (matching `build_events_query`'s
    reason for existing) and so `read_open_ports_as_of` can share it.
    Uses `idx_events_port_ts`.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('port must be an integer between 1 and 65535')
    _validate_int(start_ts, 'start_ts')
    statement = (
        'SELECT ' + EVENT_COLUMNS + ' '
        + _EVENT_FROM_JOIN
        + 'WHERE e.port = ? AND e.event_type = ? AND e.ts < ? '
        'ORDER BY e.ts DESC, e.id DESC LIMIT 1'
    )
    return statement, (port, 'state_change', start_ts)


def build_open_ports_query(*, start_ts):
    """Return `(statement, params)` for the events-derived open-port discovery.

    Selects the distinct ports with a `state_change` row whose `online` is 0
    strictly before `start_ts` -- the candidate universe for an open anchor.
    Reads `events` alone: no join, no subquery, no `services` table (see
    `read_open_ports_as_of`'s docstring for why the universe must not be the
    `services` table).
    """
    _validate_int(start_ts, 'start_ts')
    statement = (
        'SELECT DISTINCT port FROM events '
        'WHERE event_type = ? AND online = 0 AND ts < ? AND port IS NOT NULL '
        'ORDER BY port ASC'
    )
    return statement, ('state_change', start_ts)


def read_open_episode_anchors(conn, *, start_ts, ports, criticality=None):
    """Return each port's most recent still-relevant down row before `start_ts`.

    For each port, at most one row is returned: that port's most recent
    `state_change` strictly before `start_ts`, returned only when its
    `online` is 0 (i.e. the port was still down at `start_ts`) and only when
    it matches the requested `criticality`. A port that went down and
    recovered entirely before the range -- both transitions strictly before
    `start_ts` -- yields no anchor: its most recent prior row is the
    recovery, not the down transition. This is what lets an outage that
    *began* before the selected range group correctly instead of appearing
    as a recovery with no cause, without ever fabricating an anchor for a
    service that already recovered. It reads durable rows only and invents
    nothing. Uses `idx_events_port_ts`.
    """
    _validate_int(start_ts, 'start_ts')
    if criticality is not None and criticality not in CRITICALITY_VALUES:
        raise ValueError('criticality must be "critical" or "standard"')
    wanted_critical = None if criticality is None else (1 if criticality == 'critical' else 0)

    anchors = []
    for port in ports:
        statement, params = build_open_anchor_query(port=port, start_ts=start_ts)
        row = conn.execute(statement, params).fetchone()
        if row is None or row['online'] != 0:
            continue
        if wanted_critical is not None and row['critical'] != wanted_critical:
            continue
        anchors.append(row)
    return anchors


def read_open_ports_as_of(conn, *, start_ts, criticality=None):
    """Return the sorted ports that were still down as of `start_ts`.

    Step one is the candidate universe, read from the durable `events`
    record alone via `build_open_ports_query` -- never from the `services`
    table. A `services` row expires after `EXPIRE_DAYS` (default 7,
    `dashboard/beacon/config.py:230`) via `DELETE FROM services WHERE
    last_seen < ?` (`dashboard/app.py:1420`), which immediately cascades to
    `service_meta`, while `events` are retained far longer
    (`dashboard/beacon/telemetry.py:1061` at the configured retention,
    `dashboard/app.py:1266` at 14 days). A service that went down and was
    never seen again therefore loses both join rows within a week while its
    down transition survives for months -- exactly the long-silent,
    still-open outage CR-01 is about. A `services`-derived universe would
    make that case permanently invisible (D-12: grouping is a view over
    durable rows). This candidate read is a superset filter: it never
    narrows the answer, it only bounds the work.

    Step two calls `read_open_episode_anchors` for each candidate port,
    forwarding `criticality`, and keeps the port only when an anchor came
    back.
    """
    statement, params = build_open_ports_query(start_ts=start_ts)
    candidate_ports = [row['port'] for row in conn.execute(statement, params).fetchall()]
    open_ports = [
        port for port in candidate_ports
        if read_open_episode_anchors(
            conn, start_ts=start_ts, ports=[port], criticality=criticality,
        )
    ]
    return sorted(open_ports)


def anchor_candidate_ports(conn, *, start_ts, port=None, criticality=None, episode_rows):
    """Return the sorted set of ports eligible for an anchor lookup.

    Computed independently of what matched inside the window. When `port`
    is supplied the result is exactly `[port]` -- an explicit per-service
    investigation always reaches the anchor seek whether or not the window
    returned a single row for it, which is the direct CR-01 fix on the
    per-service path. `criticality` is deliberately not applied on either
    path here: `read_open_episode_anchors` applies it to the anchor row
    itself, so `port=X` under a mismatching criticality still reaches the
    seek and is then correctly dropped, and `episodes` can never disagree
    with `events` about which services are in criticality scope.

    When `port` is not supplied the result is the union of the ports
    present in `episode_rows` and `read_open_ports_as_of(conn,
    start_ts=start_ts, criticality=criticality)`. Neither half subsumes the
    other and both are required: `episode_rows` is empty by construction for
    a silently-down service -- that is the definition of CR-01 -- and the
    discovery query alone would miss a port whose down transition falls
    inside the window rather than before it.
    """
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError('port must be an integer between 1 and 65535')
        return [port]

    episode_ports = {row['port'] for row in episode_rows}
    discovered_ports = set(read_open_ports_as_of(conn, start_ts=start_ts, criticality=criticality))
    return sorted(episode_ports | discovered_ports)


def read_episode_state_changes(
    conn, *, start_ts, end_ts, port=None, criticality=None, limit=INCIDENT_ROW_BUDGET,
):
    """Read the `state_change` rows that episodes are grouped from.

    A thin wrapper over `read_events_in_range` that pins `event_type` to
    `'state_change'` and `maintenance` to `'include'`, forwarding only
    `port` and `criticality`. `port` and `criticality` are properties of the
    *service* and therefore scope which state machines are in view, while
    `event_type` and `maintenance` describe *kinds of row* -- narrowing on
    them before grouping would produce a row set that cannot represent a
    state machine (D-12, `04-REVIEW.md` CR-02). Returns `(rows, truncated)`
    exactly as `read_events_in_range` does.
    """
    return read_events_in_range(
        conn, start_ts=start_ts, end_ts=end_ts, port=port,
        event_type='state_change', criticality=criticality,
        maintenance='include', limit=limit,
    )


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
                'transitions': [dict(row)],
            }
        elif online == 1 and open_episode is not None:
            open_episode['recovered_ts'] = int(row['ts'])
            open_episode['open'] = False
            open_episode['duration_seconds'] = (
                open_episode['recovered_ts'] - open_episode['down_ts']
            )
            open_episode['transitions'].append(dict(row))
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


def _episode_is_suppressed(episode):
    """An episode's suppression identity is its opening event's.

    `group_episodes` already assigns the opening (down) row's
    `suppressed_reason` to the episode, which is precisely what makes an
    anchor's suppression authoritative and closes WR-01.
    """
    return episode.get('suppressed_reason') is not None


def _episode_evidence_window(episode, end_ts):
    """Return `(window_start, window_end)` for matching non-state_change evidence.

    `[down_ts, recovered_ts]` for a closed episode, `[down_ts, end_ts)` for
    an open one. Using `end_ts` for an open episode bounds *evidence
    matching only* -- it never becomes `recovered_ts` or `duration_seconds`,
    which stay `None` (D-12/Pitfall 4).
    """
    if episode['open']:
        return episode['down_ts'], end_ts
    return episode['down_ts'], episode['recovered_ts']


def _row_matches_episode_evidence(row, episode, end_ts):
    if row['port'] != episode['port']:
        return False
    window_start, window_end = _episode_evidence_window(episode, end_ts)
    ts = row['ts']
    if episode['open']:
        return window_start <= ts < window_end
    return window_start <= ts <= window_end


def filter_episodes(episodes, *, rows, filters, end_ts):
    """Apply the operator's `maintenance` and `event_type` selections to
    already-grouped episodes.

    Returns `(kept_episodes, narrowed_by)` where `narrowed_by` is a sorted
    list of the filter names that were actually applied on this request.
    Narrowing happens *after* grouping -- episodes are always grouped from
    the durable state_change record (D-12); only which already-grouped
    episodes are kept is decided here.

    `maintenance`: an episode is suppressed when its own `suppressed_reason`
    is not `None`. `exclude` keeps only unsuppressed episodes, `only` keeps
    only suppressed ones, `include` keeps all and does not appear in
    `narrowed_by`.

    `event_type`: when the value is `state_change` or absent, no narrowing
    is applied and the name does not appear in `narrowed_by` -- every
    episode is built from `state_change` rows by definition. For any other
    value, an episode is kept only when at least one row in `rows` has the
    same port and a `ts` inside the episode's evidence window
    (`_episode_evidence_window`).
    """
    narrowed_by = []
    kept = list(episodes)

    maintenance = filters.get('maintenance', DEFAULT_MAINTENANCE_MODE)
    if maintenance == 'exclude':
        kept = [episode for episode in kept if not _episode_is_suppressed(episode)]
        narrowed_by.append('maintenance')
    elif maintenance == 'only':
        kept = [episode for episode in kept if _episode_is_suppressed(episode)]
        narrowed_by.append('maintenance')

    event_type = filters.get('event_type')
    if event_type is not None and event_type != 'state_change':
        kept = [
            episode for episode in kept
            if any(_row_matches_episode_evidence(row, episode, end_ts) for row in rows)
        ]
        narrowed_by.append('event_type')

    return kept, sorted(narrowed_by)


def compose_incidents_response(
    rows, anchors, *, start_ts, end_ts, filters, truncated, episode_rows,
):
    """Compose the full `/api/events/history` response from three query result sets.

    Episodes are grouped from `episode_rows` (every in-range `state_change`
    for the in-scope services) with each port's `anchors` row prepended when
    present -- never from `rows`, which is the already-filtered flat
    transition list. A port whose only evidence is its anchor (no rows at
    all in `episode_rows`) still emits a group -- this is the path that
    makes a silently-down service visible (CR-01). The grouped episodes are
    then narrowed by `filter_episodes` and classified for flapping only
    after narrowing, since the UI-SPEC's flapping rule is defined over "the
    currently filtered list".

    Returns `{requested, filters, episodes, events, flapping_groups,
    row_budget, truncated, matched_count, episode_scope}`. `episodes` is
    ordered open first, then `down_ts` descending, then opening event `id`
    descending -- a total order, so equal timestamps never reorder between
    identical requests. `events` and `matched_count` are derived from `rows`
    exactly as before. `episode_scope` is `{'grouped_from':
    EPISODE_GROUPING_SOURCE, 'narrowed_by': narrowed_by}`.
    """
    anchors_by_port = {anchor['port']: anchor for anchor in anchors}

    episode_rows_by_port = {}
    for row in episode_rows:
        episode_rows_by_port.setdefault(row['port'], []).append(row)

    all_ports = sorted(set(episode_rows_by_port) | set(anchors_by_port))

    episodes = []
    for port in all_ports:
        combined = []
        anchor = anchors_by_port.get(port)
        if anchor is not None:
            combined.append(anchor)
        combined.extend(
            sorted(episode_rows_by_port.get(port, []), key=lambda row: (row['ts'], row['id']))
        )
        episodes.extend(group_episodes(combined))

    kept_episodes, narrowed_by = filter_episodes(
        episodes, rows=rows, filters=filters, end_ts=end_ts,
    )

    flapping_groups = classify_flapping(kept_episodes)

    kept_episodes.sort(key=lambda episode: (
        0 if episode['open'] else 1,
        -episode['down_ts'],
        -_opening_event_id(episode),
    ))

    events = sorted(rows, key=lambda row: (-row['ts'], -row['id']))

    return {
        'requested': {'start_ts': start_ts, 'end_ts': end_ts},
        'filters': filters,
        'episodes': kept_episodes,
        'events': [dict(row) for row in events],
        'flapping_groups': flapping_groups,
        'row_budget': INCIDENT_ROW_BUDGET,
        'truncated': truncated,
        'matched_count': len(rows),
        'episode_scope': {'grouped_from': EPISODE_GROUPING_SOURCE, 'narrowed_by': narrowed_by},
    }
