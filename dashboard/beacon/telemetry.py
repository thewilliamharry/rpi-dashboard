"""Framework-free policy for bounded historical telemetry responses."""

from dataclasses import dataclass


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
