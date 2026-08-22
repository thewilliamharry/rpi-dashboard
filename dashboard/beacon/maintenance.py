"""Framework-free coverage evaluation for planned maintenance windows.

This module imports only ``dataclasses``, ``datetime``, and ``zoneinfo`` --
no SQLite driver, no Flask, nothing from the application edge module -- which
keeps it importable by worker jobs and unit tests alike, matching the
"operations interface" discipline ``monitoring.py`` already establishes.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


# The single suppression tag literal every other module references rather
# than re-spelling.
MAINTENANCE_REASON = 'maintenance'

# How many calendar days back from "now" a window's local start time is
# searched for.  Generous enough to cover any duration+grace this UI allows
# while staying a small, bounded, named constant rather than an inline number.
MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS = 2

_ISO_WEEKDAYS = frozenset(range(1, 8))


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
