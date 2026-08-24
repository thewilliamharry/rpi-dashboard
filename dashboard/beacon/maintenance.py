"""Framework-free coverage evaluation for planned maintenance windows.

This module imports only ``dataclasses``, ``datetime``, and ``zoneinfo`` --
no SQLite driver, no Flask, nothing from the application edge module -- which
keeps it importable by worker jobs and unit tests alike, matching the
"operations interface" discipline ``monitoring.py`` already establishes.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import median
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


# The single suppression tag literal every other module references rather
# than re-spelling.
MAINTENANCE_REASON = 'maintenance'

# How many calendar days back from "now" a window's local start time is
# searched for.  Generous enough to cover any duration+grace this UI allows
# while staying a small, bounded, named constant rather than an inline number.
MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS = 2

_ISO_WEEKDAYS = frozenset(range(1, 8))

# MNT-02's literal requirement -- not a tunable, unlike the two tolerances
# and the lookback, which are configurable Settings fields.
MAINTENANCE_MIN_OCCURRENCES = 3

# The suggested weekday set always defaults to all seven ISO weekdays,
# matching MNT-02's "daily" wording (RESEARCH A3); narrowing it is the
# operator's Adjust path, never an inference from which weekdays happened to
# be observed.
MAINTENANCE_SUGGESTION_WEEKDAYS = frozenset(_ISO_WEEKDAYS)


def resolve_timezone(name):
    """Resolve a named IANA zone, failing closed to UTC rather than raising."""
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return ZoneInfo('UTC')


def parse_weekdays(text):
    """Parse a comma-separated ISO weekday string (Mon=1..Sun=7).

    Any unparseable or out-of-range token fails the whole field closed to an
    empty frozenset rather than silently accepting a partial set -- an empty
    result makes the owning window fail ``Window`` validation and be dropped
    by ``window_from_row`` rather than partially matching an operator's intent
    the stored text never actually expressed.
    """
    weekdays = set()
    for token in str(text or '').split(','):
        token = token.strip()
        if not token:
            continue
        try:
            value = int(token)
        except ValueError:
            return frozenset()
        if value not in _ISO_WEEKDAYS:
            return frozenset()
        weekdays.add(value)
    return frozenset(weekdays)


def format_weekdays(weekdays):
    """Return the canonical ascending comma-separated ISO weekday string."""
    return ','.join(str(day) for day in sorted(weekdays))


@dataclass(frozen=True)
class Window:
    """A validated, immutable maintenance window row."""

    id: int
    port: int
    start_minute: int
    duration_minutes: int
    weekdays: frozenset
    grace_minutes: int
    enabled: bool

    def __post_init__(self):
        for field_name in ('id', 'port', 'start_minute', 'duration_minutes', 'grace_minutes'):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f'{field_name} must be an integer')
        if not 0 <= self.start_minute < 1440:
            raise ValueError('start_minute must be within 0..1439')
        if self.duration_minutes < 1:
            raise ValueError('duration_minutes must be at least 1')
        if self.grace_minutes < 0:
            raise ValueError('grace_minutes must be at least 0')
        if not isinstance(self.weekdays, frozenset) or not self.weekdays or not self.weekdays <= _ISO_WEEKDAYS:
            raise ValueError('weekdays must be a non-empty subset of 1..7')
        if not isinstance(self.enabled, bool):
            object.__setattr__(self, 'enabled', bool(self.enabled))


def window_from_row(row):
    """Translate a stored row mapping into a ``Window``, or ``None`` if malformed.

    This is the fail-closed boundary that keeps a corrupt stored row from
    aborting the worker's write transaction: any parsing or validation
    failure here is swallowed and reported as "not a usable window" rather
    than propagated.
    """
    try:
        weekdays = parse_weekdays(row['weekdays'])
        return Window(
            id=int(row['id']),
            port=int(row['port']),
            start_minute=int(row['start_minute']),
            duration_minutes=int(row['duration_minutes']),
            weekdays=weekdays,
            grace_minutes=int(row['grace_minutes']),
            enabled=bool(row['enabled']),
        )
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def _local_occurrence_epochs(window, now_epoch, tz):
    """Yield every UTC epoch at which ``window`` could have started.

    Bounded to ``MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS`` calendar days back
    from "now", honoring D-02's wall-clock literal rule: a candidate whose
    local wall time does not exist (a spring-forward gap) is skipped; a
    candidate whose local wall time is ambiguous (a fall-back repeat) is
    yielded twice, once for each real instant.
    """
    now_local = datetime.fromtimestamp(now_epoch, tz=tz)
    for day_offset in range(MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS + 1):
        candidate_date = (now_local - timedelta(days=day_offset)).date()
        if candidate_date.isoweekday() not in window.weekdays:
            continue
        naive = datetime(
            candidate_date.year, candidate_date.month, candidate_date.day,
            window.start_minute // 60, window.start_minute % 60,
        )
        seen_epochs = set()
        for fold in (0, 1):
            candidate = naive.replace(tzinfo=tz, fold=fold)
            candidate_epoch = int(candidate.timestamp())
            # Round-trip through UTC and back: if the wall-clock time does
            # not exist (spring-forward gap), the round trip will not
            # reproduce the same naive wall time -- the standard zoneinfo
            # idiom for gap detection (PEP 495).
            roundtrip = datetime.fromtimestamp(candidate_epoch, tz=tz)
            if (roundtrip.hour, roundtrip.minute) != (naive.hour, naive.minute):
                continue
            if candidate_epoch in seen_epochs:
                # A non-ambiguous instant: fold=0 and fold=1 agree, so only
                # yield it once.
                continue
            seen_epochs.add(candidate_epoch)
            yield candidate_epoch


def coverage(windows, now_epoch, tz_name):
    """Return ``(covered, grace_until_epoch)`` for a set of stored window rows.

    ``windows`` is a sequence of row-like mappings (as returned by
    ``repositories.get_maintenance_windows``) -- coverage owns turning each
    into a validated ``Window`` via ``window_from_row`` and skips both
    disabled windows and rows that fail validation, so a single corrupt row
    can never abort the caller's transaction. Coverage includes the grace
    period: a window is covering from its start through end+grace. Where
    several windows cover the same instant, the longest grace end wins
    (D-05).
    """
    tz = resolve_timezone(tz_name)
    covering_grace_ends = []
    for row in windows:
        window = window_from_row(row)
        if window is None or not window.enabled:
            continue
        for start_epoch in _local_occurrence_epochs(window, now_epoch, tz):
            raw_end = start_epoch + window.duration_minutes * 60
            grace_end = raw_end + window.grace_minutes * 60
            if start_epoch <= now_epoch < grace_end:
                covering_grace_ends.append(grace_end)
    if not covering_grace_ends:
        return False, None
    return True, max(covering_grace_ends)


_MINUTES_PER_DAY = 1440  # the day length Window.start_minute's own 0..1439 range already assumes


def _circular_minute_distance(a, b):
    """Return the distance in minutes between two clock positions on a dial that closes at one day.

    Both ``a`` and ``b`` are minute-of-day clock positions (0..1439, the same
    unit ``Window.start_minute`` and an observation's ``start_minute`` use).
    The result is bounded by half a day (0..720). Duration is deliberately
    never passed through this helper -- a duration is a magnitude, not a
    position on a dial, and comparing it circularly would make a five-minute
    restart and a near-day-long outage look close together.
    """
    raw = abs(a - b)
    return min(raw, _MINUTES_PER_DAY - raw)


def _observation_from_pair(pair, tz):
    """Translate one down/recovered pair into a clustering observation.

    Returns ``None`` for anything malformed: not a two-element pair, a
    non-integer timestamp (an actual ``int``, never a ``bool``, matching the
    identity-typed discipline the rest of the codebase uses), or a recovery
    that is not strictly after its down. Malformed evidence is dropped, never
    raised on, so a single corrupt row can never break the editor's read.
    """
    try:
        down_ts, recovered_ts = pair
    except (TypeError, ValueError):
        return None
    if isinstance(down_ts, bool) or isinstance(recovered_ts, bool):
        return None
    if not isinstance(down_ts, int) or not isinstance(recovered_ts, int):
        return None
    if recovered_ts <= down_ts:
        return None
    local_down = datetime.fromtimestamp(down_ts, tz=tz)
    return {
        'date': local_down.date(),
        'start_minute': local_down.hour * 60 + local_down.minute,
        'duration_seconds': recovered_ts - down_ts,
    }


def detect_suggestion(
    down_recovered_pairs, tz_name, *, now_epoch, start_tolerance_seconds,
    duration_tolerance_seconds,
):
    """Cluster down/recovered pairs into an inactive candidate window, or ``None``.

    ``down_recovered_pairs`` is a sequence of two-tuples of down and
    recovered epoch timestamps for one port -- the caller (the repository
    read plus the configured lookback) owns bounding how much evidence is
    supplied; this function is a pure computation over whatever it receives,
    with no lookback awareness of its own (Assumption A2's lookback bound is
    a caller-side, named ``Settings`` field, never an inline number here).

    Each pair is converted to a local start-of-day minute and an observed
    duration, then clustered greedily: for every observation used as an
    anchor, every other observation within ``start_tolerance_seconds`` of the
    anchor's start minute *and* within ``duration_tolerance_seconds`` of the
    anchor's duration joins its cluster. Start minutes are compared as clock
    positions on a dial that closes at one day (via
    ``_circular_minute_distance``), so a pattern whose start time itself
    jitters across midnight clusters exactly as the identical jitter around
    any other hour does; durations are compared as plain magnitudes, never
    circularly. Occurrences are counted by distinct local calendar date, not
    by row, so several observations on the same date count once. The largest
    qualifying cluster (by distinct-date count) wins; ties keep the first one
    found. Returns ``None`` when no cluster reaches
    ``MAINTENANCE_MIN_OCCURRENCES``.

    The returned mapping carries only the observed occurrence count, the
    cluster's median start minute and median duration in whole minutes, and
    the all-seven-day weekday set (RESEARCH A3) -- no score, no threshold,
    no internal cluster detail. The reported start minute is the cluster's
    median computed on that same closed dial, relative to the winning
    anchor's own start minute: each member's signed offset to the anchor is
    taken on the dial, the offsets are median-averaged, and the result is
    added back to the anchor and reduced onto the dial before rounding to a
    whole minute. A naive linear median over a midnight-straddling cluster
    would report a time near midday instead of near midnight -- confidently
    wrong rather than merely silent -- so the median must close the dial too,
    not just the distance test.
    """
    tz = resolve_timezone(tz_name)
    observations = []
    for pair in down_recovered_pairs:
        observation = _observation_from_pair(pair, tz)
        if observation is not None:
            observations.append(observation)

    best_cluster = None
    best_anchor = None
    best_occurrence_count = 0
    for anchor in observations:
        cluster = [
            o for o in observations
            if _circular_minute_distance(o['start_minute'], anchor['start_minute']) * 60 <= start_tolerance_seconds
            and abs(o['duration_seconds'] - anchor['duration_seconds']) <= duration_tolerance_seconds
        ]
        occurrence_count = len({o['date'] for o in cluster})
        if occurrence_count >= MAINTENANCE_MIN_OCCURRENCES and occurrence_count > best_occurrence_count:
            best_cluster = cluster
            best_anchor = anchor
            best_occurrence_count = occurrence_count

    if best_cluster is None:
        return None
    anchor_start_minute = best_anchor['start_minute']
    half_day = _MINUTES_PER_DAY // 2
    offsets = [
        ((o['start_minute'] - anchor_start_minute + half_day) % _MINUTES_PER_DAY) - half_day
        for o in best_cluster
    ]
    circular_start_minute = int((anchor_start_minute + median(offsets)) % _MINUTES_PER_DAY)
    return {
        'occurrence_count': best_occurrence_count,
        'start_minute': circular_start_minute,
        'duration_minutes': int(median(o['duration_seconds'] for o in best_cluster) // 60),
        'weekdays': MAINTENANCE_SUGGESTION_WEEKDAYS,
    }


def suggestion_overlaps_enabled_window(suggestion, windows, *, start_tolerance_seconds):
    """Return True when an ENABLED window already covers ``suggestion``.

    ``windows`` is a sequence of raw stored-row mappings (as returned by
    ``repositories.get_maintenance_windows``); each is validated through
    ``window_from_row`` exactly as ``coverage()`` does, so a malformed row
    is skipped rather than raised on. A window overlaps the suggestion when
    it is ENABLED, its start minute is within ``start_tolerance_seconds`` of
    the suggestion's start minute, and its duration is comparable -- within
    that same tolerance, converted to minutes, since no separate duration
    tolerance is threaded through this call. This lets the caller withhold a
    redundant "confirm what you already confirmed" proposal while the
    detector itself still sees the evidence (RESEARCH Q3) -- a disabled
    window is not a confirmed pattern the operator already owns, so it is
    never treated as overlapping. The start comparison closes the dial for
    the same reason ``detect_suggestion``'s does (via
    ``_circular_minute_distance``), so the two agree about what "near"
    means across midnight; the duration comparison deliberately does not.
    """
    if not suggestion:
        return False
    try:
        suggestion_start = int(suggestion['start_minute'])
        suggestion_duration = int(suggestion['duration_minutes'])
    except (KeyError, TypeError, ValueError):
        return False
    tolerance_minutes = max(1, start_tolerance_seconds // 60)
    for row in windows:
        window = window_from_row(row)
        if window is None or not window.enabled:
            continue
        if _circular_minute_distance(window.start_minute, suggestion_start) > tolerance_minutes:
            continue
        if abs(window.duration_minutes - suggestion_duration) > tolerance_minutes:
            continue
        return True
    return False


# A generous, bounded cap on how many times boundary discovery may step its
# search anchor backward for a single window inside a single offline
# interval -- guards against a pathologically long offline interval turning
# attribution into an unbounded loop, while comfortably covering any
# interval this codebase's retention windows can produce (each step covers
# MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS days, so 64 steps covers well over a
# year).
_ATTRIBUTION_MAX_ANCHOR_STEPS = 64


def _covering_boundaries(window, interval_start, interval_end, tz):
    """Yield every start/grace-end epoch of ``window`` that could fall inside
    ``[interval_start, interval_end)``, discovered by stepping the boundary
    search anchor backward in ``MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS``-sized
    strides so an interval spanning more calendar days than one search
    covers is still searched exhaustively, bounded by
    ``_ATTRIBUTION_MAX_ANCHOR_STEPS``.
    """
    seen = set()
    anchor = interval_end
    step_seconds = MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS * 86400
    steps = 0
    while anchor >= interval_start - 86400 and steps < _ATTRIBUTION_MAX_ANCHOR_STEPS:
        for start_epoch in _local_occurrence_epochs(window, anchor, tz):
            grace_end = start_epoch + (window.duration_minutes + window.grace_minutes) * 60
            if grace_end <= interval_start or start_epoch >= interval_end:
                continue
            key = (start_epoch, grace_end)
            if key in seen:
                continue
            seen.add(key)
            yield key
        anchor -= step_seconds
        steps += 1


def attributed_downtime_seconds(intervals, windows, tz_name):
    """Return whole seconds of ``intervals`` that fell inside window coverage.

    ``intervals`` is a sequence of half-open ``(start_epoch, end_epoch)``
    offline intervals (as ``repositories.read_service_offline_intervals``
    returns). ``windows`` is the same raw stored-row sequence ``coverage()``
    accepts. Each interval is split at every coverage boundary a window's
    occurrences introduce inside it -- every occurrence's start epoch and
    grace-end epoch -- and the covered/uncovered state of each resulting
    segment is decided by calling ``coverage()`` itself at the segment's
    start instant, so this function never re-implements the interval-overlap
    rule; it only discovers where to split. Overlapping windows contribute
    their union rather than being double-counted, because ``coverage()``
    already resolves overlapping coverage to a single boolean (D-05's
    longest-grace-wins rule) and every occurrence's boundary from every
    window is included in the split set. A malformed window row is dropped
    by ``window_from_row`` during boundary discovery, exactly as ``coverage()``
    drops it internally, and so contributes no boundaries and no coverage.
    Returns the integer zero, never ``None``, when nothing is attributable.
    """
    tz = resolve_timezone(tz_name)
    total = 0
    for raw_start, raw_end in intervals:
        interval_start = int(raw_start)
        interval_end = int(raw_end)
        if interval_end <= interval_start:
            continue
        boundaries = {interval_start, interval_end}
        for row in windows:
            window = window_from_row(row)
            if window is None or not window.enabled:
                continue
            for start_epoch, grace_end in _covering_boundaries(window, interval_start, interval_end, tz):
                if interval_start < start_epoch < interval_end:
                    boundaries.add(start_epoch)
                if interval_start < grace_end < interval_end:
                    boundaries.add(grace_end)
        ordered = sorted(boundaries)
        for segment_start, segment_end in zip(ordered, ordered[1:]):
            covered, _grace_until = coverage(windows, segment_start, tz_name)
            if covered:
                total += segment_end - segment_start
    return total
