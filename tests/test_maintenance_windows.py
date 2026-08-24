"""Tracer coverage for planned maintenance window recognition (phase 03.1)."""

import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from dashboard.beacon import maintenance as beacon_maintenance
from dashboard.beacon import queues as beacon_queues
from dashboard.beacon import repositories as beacon_repositories
from dashboard.beacon.config import Settings, load_settings
from dashboard.beacon.migrations import (
    MIGRATIONS,
    _migration_9_planned_maintenance,
    run_migrations,
)
from dashboard.beacon.worker_authority import WorkerAuthority
from tests.helpers import cleanup_db, load_app

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _window_row(
    id=1, port=8080, start_minute=120, duration_minutes=30,
    weekdays='1,2,3,4,5,6,7', grace_minutes=0, enabled=1,
):
    """Build a raw row-like dict matching what get_maintenance_windows returns."""
    return {
        'id': id, 'port': port, 'start_minute': start_minute,
        'duration_minutes': duration_minutes, 'weekdays': weekdays,
        'grace_minutes': grace_minutes, 'enabled': enabled,
        'created_ts': 0, 'updated_ts': 0,
    }


def _epoch(year, month, day, hour, minute, second=0, tz='UTC'):
    return int(datetime(year, month, day, hour, minute, second, tzinfo=ZoneInfo(tz)).timestamp())


def _pair(date_ymd, hour, minute, duration_minutes, tz='UTC'):
    """Build a (down_ts, recovered_ts) tuple for the detector tests."""
    down = _epoch(date_ymd[0], date_ymd[1], date_ymd[2], hour, minute, 0, tz)
    return (down, down + duration_minutes * 60)


class CoverageTests(unittest.TestCase):
    """Pure, framework-free coverage() behavior -- no SQLite, no Flask."""

    def test_an_instant_at_the_window_start_second_is_covered(self):
        start_epoch = _epoch(2026, 1, 5, 2, 0, 0)  # a Monday
        row = _window_row(start_minute=120, duration_minutes=30, weekdays='1', grace_minutes=5)
        covered, grace_until = beacon_maintenance.coverage([row], start_epoch, 'UTC')
        self.assertTrue(covered)
        self.assertEqual(grace_until, start_epoch + 30 * 60 + 5 * 60)

    def test_an_instant_at_the_grace_boundary_second_is_not_covered(self):
        start_epoch = _epoch(2026, 1, 5, 2, 0, 0)
        grace_end = start_epoch + 30 * 60 + 5 * 60
        row = _window_row(start_minute=120, duration_minutes=30, weekdays='1', grace_minutes=5)
        covered, grace_until = beacon_maintenance.coverage([row], grace_end, 'UTC')
        self.assertFalse(covered)
        self.assertIsNone(grace_until)

    def test_no_windows_never_covers(self):
        covered, grace_until = beacon_maintenance.coverage([], _epoch(2026, 1, 5, 2, 0, 0), 'UTC')
        self.assertFalse(covered)
        self.assertIsNone(grace_until)

    def test_a_disabled_window_never_covers(self):
        start_epoch = _epoch(2026, 1, 5, 2, 0, 0)
        row = _window_row(start_minute=120, duration_minutes=30, weekdays='1', enabled=0)
        covered, grace_until = beacon_maintenance.coverage([row], start_epoch, 'UTC')
        self.assertFalse(covered)
        self.assertIsNone(grace_until)

    def test_a_window_outside_its_weekday_set_never_covers(self):
        tuesday_epoch = _epoch(2026, 1, 6, 2, 0, 0)
        row = _window_row(start_minute=120, duration_minutes=30, weekdays='1')
        covered, grace_until = beacon_maintenance.coverage([row], tuesday_epoch, 'UTC')
        self.assertFalse(covered)
        self.assertIsNone(grace_until)

    def test_a_window_crossing_midnight_covers_after_midnight(self):
        after_midnight = _epoch(2026, 1, 6, 0, 5, 0)  # Tuesday, just after midnight
        row = _window_row(start_minute=23 * 60 + 50, duration_minutes=30, weekdays='1')  # Monday 23:50
        covered, grace_until = beacon_maintenance.coverage([row], after_midnight, 'UTC')
        self.assertTrue(covered)
        expected_start = _epoch(2026, 1, 5, 23, 50, 0)
        self.assertEqual(grace_until, expected_start + 30 * 60)

    def test_overlapping_windows_freeze_the_longest_grace(self):
        now = _epoch(2026, 1, 5, 2, 10, 0)
        window_a = _window_row(id=1, start_minute=120, duration_minutes=30, weekdays='1', grace_minutes=5)
        window_b = _window_row(id=2, start_minute=100, duration_minutes=60, weekdays='1', grace_minutes=20)
        expected_grace_until = _epoch(2026, 1, 5, 1, 40, 0) + 60 * 60 + 20 * 60
        covered_ab, grace_ab = beacon_maintenance.coverage([window_a, window_b], now, 'UTC')
        covered_ba, grace_ba = beacon_maintenance.coverage([window_b, window_a], now, 'UTC')
        self.assertTrue(covered_ab)
        self.assertTrue(covered_ba)
        self.assertEqual(grace_ab, expected_grace_until)
        self.assertEqual(grace_ba, expected_grace_until)

    def test_a_malformed_window_row_is_not_covering_and_does_not_raise(self):
        now = _epoch(2026, 1, 5, 2, 0, 0)
        bad_weekdays = _window_row(id=1, start_minute=120, duration_minutes=30, weekdays='not-a-weekday')
        bad_duration = dict(_window_row(id=2, start_minute=120, duration_minutes=30, weekdays='1'))
        bad_duration['duration_minutes'] = 'not-an-int'
        good = _window_row(id=3, start_minute=120, duration_minutes=30, weekdays='1')
        covered, grace_until = beacon_maintenance.coverage(
            [bad_weekdays, bad_duration, good], now, 'UTC',
        )
        self.assertTrue(covered)
        self.assertEqual(grace_until, now + 30 * 60)


class DstCoverageTests(unittest.TestCase):
    """DST-boundary behavior against real IANA transition dates (D-02)."""

    def test_a_nonexistent_spring_forward_start_time_is_skipped(self):
        # 2026-03-08 is the US spring-forward Sunday: 02:00-03:00 local never
        # occurs, so a window starting at 02:30 produces no occurrence at all.
        tz = 'America/New_York'
        row = _window_row(start_minute=2 * 60 + 30, duration_minutes=60, weekdays='7')
        now = _epoch(2026, 3, 8, 3, 15, 0, tz=tz)
        covered, grace_until = beacon_maintenance.coverage([row], now, tz)
        self.assertFalse(covered)
        self.assertIsNone(grace_until)

    def test_an_ambiguous_fall_back_start_time_is_honored_twice(self):
        # 2026-11-01 is the US fall-back Sunday: local 01:30 occurs twice.
        tz = 'America/New_York'
        row = _window_row(start_minute=90, duration_minutes=30, weekdays='7')
        first_instant = int(datetime(2026, 11, 1, 1, 30, tzinfo=ZoneInfo(tz), fold=0).timestamp())
        second_instant = int(datetime(2026, 11, 1, 1, 30, tzinfo=ZoneInfo(tz), fold=1).timestamp())
        self.assertNotEqual(first_instant, second_instant)
        covered_first, _ = beacon_maintenance.coverage([row], first_instant, tz)
        covered_second, _ = beacon_maintenance.coverage([row], second_instant, tz)
        self.assertTrue(covered_first)
        self.assertTrue(covered_second)

    def test_an_unknown_zone_name_falls_back_to_utc_without_raising(self):
        tz = beacon_maintenance.resolve_timezone('Not/ARealZone')
        self.assertEqual(str(tz), 'UTC')


class DetectorTests(unittest.TestCase):
    """Pure, framework-free detect_suggestion() behavior -- no SQLite, no Flask."""

    def _detect(self, pairs, start_tolerance_seconds=900, duration_tolerance_seconds=600):
        return beacon_maintenance.detect_suggestion(
            pairs, 'UTC', now_epoch=0,
            start_tolerance_seconds=start_tolerance_seconds,
            duration_tolerance_seconds=duration_tolerance_seconds,
        )

    def test_three_similar_daily_outages_produce_a_suggestion(self):
        pairs = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 6), 2, 5, 28),
            _pair((2026, 1, 7), 1, 58, 32),
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(result['occurrence_count'], 3)
        self.assertEqual(result['weekdays'], frozenset(range(1, 8)))

    def test_two_similar_outages_produce_nothing(self):
        pairs = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 6), 2, 5, 28),
        ]
        self.assertIsNone(self._detect(pairs))

    def test_three_outages_on_the_same_calendar_date_produce_nothing(self):
        pairs = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 5), 2, 10, 30),
            _pair((2026, 1, 5), 2, 20, 30),
        ]
        self.assertIsNone(self._detect(pairs))

    def test_start_times_outside_the_tolerance_do_not_cluster(self):
        tight = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 6), 2, 5, 30),
            _pair((2026, 1, 7), 2, 10, 30),
        ]
        self.assertIsNotNone(self._detect(tight))

        wide = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 6), 2, 20, 30),
            _pair((2026, 1, 7), 2, 40, 30),
        ]
        self.assertIsNone(self._detect(wide))

    def test_durations_outside_the_tolerance_do_not_cluster(self):
        tight = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 6), 2, 0, 35),
            _pair((2026, 1, 7), 2, 0, 25),
        ]
        self.assertIsNotNone(self._detect(tight))

        wide = [
            _pair((2026, 1, 5), 2, 0, 10),
            _pair((2026, 1, 6), 2, 0, 30),
            _pair((2026, 1, 7), 2, 0, 50),
        ]
        self.assertIsNone(self._detect(wide))

    def test_the_suggested_start_and_duration_are_the_cluster_medians(self):
        pairs = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 6), 2, 0, 30),
            _pair((2026, 1, 7), 2, 10, 38),  # inside tolerance, but an outlier
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(result['start_minute'], 120)
        self.assertEqual(result['duration_minutes'], 30)

    def test_the_suggested_weekday_set_is_all_seven_days(self):
        # All three occurrences happen to fall on a Monday; the suggestion
        # must not narrow to "Mondays only".
        pairs = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 12), 2, 0, 30),
            _pair((2026, 1, 19), 2, 0, 30),
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(result['weekdays'], frozenset(range(1, 8)))

    def test_the_output_carries_no_score_or_threshold_value(self):
        pairs = [
            _pair((2026, 1, 5), 2, 0, 30),
            _pair((2026, 1, 6), 2, 0, 30),
            _pair((2026, 1, 7), 2, 0, 30),
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(
            set(result.keys()),
            {'occurrence_count', 'start_minute', 'duration_minutes', 'weekdays'},
        )

    def test_malformed_evidence_yields_no_suggestion_and_does_not_raise(self):
        malformed = [
            ('not-an-int', 100),
            (200, 100),  # recovery before its down
            (100,),  # missing element
        ]
        try:
            result = self._detect(malformed)
        except Exception as exc:  # pragma: no cover -- the assertion below is the real gate
            self.fail(f'detect_suggestion raised on malformed evidence: {exc!r}')
        self.assertIsNone(result)

    def test_evidence_older_than_the_lookback_is_not_supplied_to_the_detector(self):
        # detect_suggestion has no lookback parameter of its own -- it
        # processes every pair it is given regardless of age. Feed it three
        # occurrences spanning ~90 days (well past the 21-day default
        # lookback) and confirm it still clusters them: bounding by age is
        # the caller's job, expressed as the named Settings field, never an
        # inline number inside this pure function.
        pairs = [
            _pair((2025, 11, 1), 2, 0, 30),
            _pair((2025, 12, 15), 2, 5, 30),
            _pair((2026, 1, 29), 2, 10, 30),
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(result['occurrence_count'], 3)

    def test_a_nightly_pattern_straddling_midnight_clusters_and_names_a_time_near_midnight(self):
        # Start times themselves jitter across midnight: 23:55, 00:00, 00:05,
        # 23:58 on four consecutive calendar dates -- start_minute values
        # [1435, 0, 5, 1438]. The raw (non-circular) maximum pairwise distance
        # is 1438 minutes, far outside the 15-minute tolerance; the circular
        # distance is at most 10 minutes, inside it.
        pairs = [
            _pair((2026, 1, 5), 23, 55, 30),
            _pair((2026, 1, 6), 0, 0, 30),
            _pair((2026, 1, 7), 0, 5, 30),
            _pair((2026, 1, 8), 23, 58, 30),
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(result['occurrence_count'], 4)
        # Exact integer, not a range or a "near midnight" proximity check --
        # the circular median of [1435, 0, 5, 1438] relative to any of the
        # four possible anchors is 1439 (verified by hand for every anchor
        # during planning; re-derived here rather than trusted).
        self.assertEqual(result['start_minute'], 1439)
        self.assertEqual(
            set(result.keys()),
            {'occurrence_count', 'start_minute', 'duration_minutes', 'weekdays'},
        )

    def test_the_same_jitter_away_from_midnight_is_unchanged(self):
        # The identical +-5-minute jitter shape, shifted to a mid-morning
        # hour that never crosses the wrap: 03:55, 04:00, 04:05, 03:58 ->
        # start_minute [235, 240, 245, 238]. This is the control that proves
        # the fix is a no-op off the wrap, and it would catch an
        # implementation that quietly rotates every answer rather than only
        # correcting the midnight case.
        pairs = [
            _pair((2026, 1, 5), 3, 55, 30),
            _pair((2026, 1, 6), 4, 0, 30),
            _pair((2026, 1, 7), 4, 5, 30),
            _pair((2026, 1, 8), 3, 58, 30),
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(result['occurrence_count'], 4)
        self.assertEqual(result['start_minute'], 239)

    def test_a_fixed_time_restart_just_before_midnight_still_clusters(self):
        # Narrowing note: a FIXED-time 23:55 restart already clustered before
        # this fix -- every observation's start_minute is identically 1435,
        # so the raw distance is zero and only the recovery crosses midnight.
        # This case passes before and after; recording it here is what stops
        # a future reader from "widening" the fix to cover a case that never
        # needed it.
        pairs = [
            _pair((2026, 1, 5), 23, 55, 30),
            _pair((2026, 1, 6), 23, 55, 30),
            _pair((2026, 1, 7), 23, 55, 30),
        ]
        result = self._detect(pairs)
        self.assertIsNotNone(result)
        self.assertEqual(result['start_minute'], 1435)

    def test_durations_are_compared_as_magnitudes_not_clock_positions(self):
        # Near-identical start times, but one duration is a handful of
        # minutes and another is close to a full day -- the duration
        # comparison must stay linear, so these must not cluster even though
        # their start times are close on the dial.
        pairs = [
            _pair((2026, 1, 5), 2, 0, 5),
            _pair((2026, 1, 6), 2, 1, 1430),
            _pair((2026, 1, 7), 2, 2, 5),
        ]
        self.assertIsNone(self._detect(pairs))


class SuggestionOverlapTests(unittest.TestCase):
    """Pure, framework-free suggestion_overlaps_enabled_window() behavior."""

    def _suggestion(self, start_minute=120, duration_minutes=30):
        return {
            'occurrence_count': 3, 'start_minute': start_minute,
            'duration_minutes': duration_minutes, 'weekdays': frozenset(range(1, 8)),
        }

    def test_a_cluster_matching_an_enabled_window_is_reported_as_overlapping(self):
        suggestion = self._suggestion()
        window = _window_row(start_minute=125, duration_minutes=32, enabled=1)
        self.assertTrue(
            beacon_maintenance.suggestion_overlaps_enabled_window(
                suggestion, [window], start_tolerance_seconds=900,
            )
        )

    def test_a_cluster_matching_only_a_disabled_window_does_not_overlap(self):
        suggestion = self._suggestion()
        window = _window_row(start_minute=125, duration_minutes=32, enabled=0)
        self.assertFalse(
            beacon_maintenance.suggestion_overlaps_enabled_window(
                suggestion, [window], start_tolerance_seconds=900,
            )
        )

    def test_an_unrelated_second_pattern_on_the_same_port_does_not_overlap(self):
        suggestion = self._suggestion(start_minute=120, duration_minutes=30)
        window = _window_row(start_minute=800, duration_minutes=30, enabled=1)
        self.assertFalse(
            beacon_maintenance.suggestion_overlaps_enabled_window(
                suggestion, [window], start_tolerance_seconds=900,
            )
        )

    def test_a_midnight_straddling_cluster_is_withheld_by_an_enabled_window_across_the_boundary(self):
        # Suggestion at 23:59 (minute 1439), enabled window at midnight
        # (minute 0), comparable durations. Raw distance is 1439 minutes,
        # far outside the 15-minute tolerance; circular distance is 1
        # minute, well inside it. Verified against the shipped code during
        # planning: this pair reports no overlap today.
        suggestion = self._suggestion(start_minute=1439, duration_minutes=30)
        window = _window_row(start_minute=0, duration_minutes=30, enabled=1)
        self.assertTrue(
            beacon_maintenance.suggestion_overlaps_enabled_window(
                suggestion, [window], start_tolerance_seconds=900,
            )
        )

    def test_a_midnight_straddling_cluster_is_still_offered_when_the_window_is_disabled(self):
        # The identical midnight-straddling pair, but the window is
        # disabled -- a disabled window is not a pattern the operator has
        # confirmed, and the circular comparison must not quietly acquire
        # the power to silence one.
        suggestion = self._suggestion(start_minute=1439, duration_minutes=30)
        window = _window_row(start_minute=0, duration_minutes=30, enabled=0)
        self.assertFalse(
            beacon_maintenance.suggestion_overlaps_enabled_window(
                suggestion, [window], start_tolerance_seconds=900,
            )
        )

    def test_a_window_far_from_the_suggestion_on_the_dial_still_does_not_withhold(self):
        suggestion = self._suggestion(start_minute=120, duration_minutes=30)
        window = _window_row(start_minute=800, duration_minutes=30, enabled=1)
        self.assertFalse(
            beacon_maintenance.suggestion_overlaps_enabled_window(
                suggestion, [window], start_tolerance_seconds=900,
            )
        )

    def test_durations_are_compared_as_magnitudes_in_the_withholding_rule(self):
        # Start times a minute apart across the midnight boundary (within
        # the circular tolerance), but durations a full day apart -- the
        # duration comparison here is not circular either, so this must not
        # overlap.
        suggestion = self._suggestion(start_minute=1439, duration_minutes=5)
        window = _window_row(start_minute=0, duration_minutes=1430, enabled=1)
        self.assertFalse(
            beacon_maintenance.suggestion_overlaps_enabled_window(
                suggestion, [window], start_tolerance_seconds=900,
            )
        )


class SettingsDetectorTests(unittest.TestCase):
    """The three detector Settings fields fail closed to their documented defaults."""

    def test_the_three_detector_settings_have_documented_defaults(self):
        settings = load_settings({})
        self.assertEqual(settings.maintenance_start_tolerance_seconds, 900)
        self.assertEqual(settings.maintenance_duration_tolerance_seconds, 600)
        self.assertEqual(settings.maintenance_suggestion_lookback_days, 21)

    def test_a_malformed_detector_setting_retains_its_default(self):
        settings = load_settings({
            'MAINTENANCE_START_TOLERANCE_SECONDS': 'not-an-int',
            'MAINTENANCE_DURATION_TOLERANCE_SECONDS': '-5',
            'MAINTENANCE_SUGGESTION_LOOKBACK_DAYS': '0',
        })
        self.assertEqual(settings.maintenance_start_tolerance_seconds, 900)
        self.assertEqual(settings.maintenance_duration_tolerance_seconds, 600)
        self.assertEqual(settings.maintenance_suggestion_lookback_days, 21)


class MigrationNineTests(unittest.TestCase):
    """Migration 9 applies additively and idempotently."""

    def test_migration_nine_adds_the_table_columns_and_index(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, 'dashboard.db')
            run_migrations(Settings(db_path=db_path))
            conn = sqlite3.connect(db_path)
            try:
                tables = {
                    row[0] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                self.assertIn('maintenance_windows', tables)
                window_columns = {row[1] for row in conn.execute('PRAGMA table_info(maintenance_windows)')}
                self.assertEqual(
                    window_columns,
                    {
                        'id', 'port', 'start_minute', 'duration_minutes', 'weekdays',
                        'grace_minutes', 'enabled', 'created_ts', 'updated_ts',
                    },
                )
                indexes = {
                    row[0] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='index'"
                    )
                }
                self.assertIn('idx_maintenance_windows_port', indexes)
                event_columns = {row[1] for row in conn.execute('PRAGMA table_info(events)')}
                self.assertTrue(
                    {'suppressed_reason', 'maintenance_grace_until', 'down_since_ts'} <= event_columns
                )
                service_columns = {row[1] for row in conn.execute('PRAGMA table_info(services)')}
                self.assertIn('overrun_raised_ts', service_columns)
                self.assertEqual(MIGRATIONS[-1].version, 9)
            finally:
                conn.close()

    def test_migration_nine_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, 'dashboard.db')
            run_migrations(Settings(db_path=db_path))
            conn = sqlite3.connect(db_path)
            try:
                before = sorted(row[1] for row in conn.execute('PRAGMA table_info(events)'))
                _migration_9_planned_maintenance(conn)  # must not raise
                after = sorted(row[1] for row in conn.execute('PRAGMA table_info(events)'))
                self.assertEqual(before, after)
                window_count = conn.execute('SELECT COUNT(*) FROM maintenance_windows').fetchone()[0]
                self.assertEqual(window_count, 0)
            finally:
                conn.close()


def _window_payload(
    start_minute=120, duration_minutes=30, weekdays=(1, 2, 3, 4, 5, 6, 7),
    grace_minutes=0, enabled=True,
):
    """Build a normalised window payload matching upsert_maintenance_windows's input shape."""
    return {
        'start_minute': start_minute, 'duration_minutes': duration_minutes,
        'weekdays': set(weekdays), 'grace_minutes': grace_minutes, 'enabled': enabled,
    }


class WindowPersistenceTests(unittest.TestCase):
    """upsert_maintenance_windows / get_maintenance_windows replace-semantics contract."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _write(self, port, windows, now=1_700_000_000):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            written = beacon_repositories.upsert_maintenance_windows(
                conn, port=port, windows=windows, now=now,
            )
            conn.commit()
            conn.close()
        return written

    def _read(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = beacon_repositories.get_maintenance_windows(conn, port)
            conn.close()
        return rows

    def test_windows_are_replaced_wholesale_for_a_port(self):
        port = 9001
        self._write(port, [_window_payload(start_minute=60), _window_payload(start_minute=120)])
        self.assertEqual(len(self._read(port)), 2)
        self._write(port, [_window_payload(start_minute=180)])
        rows = self._read(port)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['start_minute'], 180)

    def test_an_empty_list_removes_every_window_for_the_port(self):
        port_a, port_b = 9002, 9003
        self._write(port_a, [_window_payload()])
        self._write(port_b, [_window_payload()])
        self._write(port_a, [])
        self.assertEqual(self._read(port_a), [])
        self.assertEqual(len(self._read(port_b)), 1)

    def test_windows_are_read_back_in_deterministic_order(self):
        port = 9004
        self._write(port, [
            _window_payload(start_minute=180),
            _window_payload(start_minute=60),
            _window_payload(start_minute=120),
        ])
        first = self._read(port)
        second = self._read(port)
        self.assertEqual([row['start_minute'] for row in first], [60, 120, 180])
        self.assertEqual(first, second)

    def test_two_identical_writes_produce_the_same_stored_tuple_set(self):
        port = 9005
        windows = [
            _window_payload(start_minute=60, weekdays=(1, 3)),
            _window_payload(start_minute=120),
        ]
        self._write(port, windows)
        first = {
            (r['start_minute'], r['duration_minutes'], r['weekdays'], r['grace_minutes'], bool(r['enabled']))
            for r in self._read(port)
        }
        self._write(port, windows)
        second = {
            (r['start_minute'], r['duration_minutes'], r['weekdays'], r['grace_minutes'], bool(r['enabled']))
            for r in self._read(port)
        }
        self.assertEqual(first, second)

    def test_the_write_uses_the_callers_transaction(self):
        port = 9006
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            beacon_repositories.upsert_maintenance_windows(
                conn, port=port, windows=[_window_payload()], now=1_700_000_000,
            )
            conn.rollback()
            remaining = conn.execute(
                'SELECT COUNT(*) FROM maintenance_windows WHERE port=?', (port,),
            ).fetchone()[0]
            conn.close()
        self.assertEqual(remaining, 0)

    def test_weekday_text_round_trips_through_the_domain_parser(self):
        port = 9007
        self._write(port, [_window_payload(weekdays=(2, 4, 6))])
        row = self._read(port)[0]
        self.assertEqual(beacon_maintenance.parse_weekdays(row['weekdays']), frozenset({2, 4, 6}))


class BulkWindowReadTests(unittest.TestCase):
    """read_maintenance_windows_by_port groups stored windows by port in one query."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _write(self, port, windows, now=1_700_000_000):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            beacon_repositories.upsert_maintenance_windows(conn, port=port, windows=windows, now=now)
            conn.commit()
            conn.close()

    def _bulk(self, ports):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            result = beacon_repositories.read_maintenance_windows_by_port(conn, ports=ports)
            conn.close()
        return result

    def _single(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = beacon_repositories.get_maintenance_windows(conn, port)
            conn.close()
        return rows

    def test_windows_are_returned_grouped_by_port(self):
        self._write(9601, [_window_payload(start_minute=60)])
        self._write(9602, [_window_payload(start_minute=120), _window_payload(start_minute=180)])
        result = self._bulk([9601, 9602, 9603])
        self.assertEqual(len(result.get(9601, [])), 1)
        self.assertEqual(len(result.get(9602, [])), 2)
        # A port with no stored windows is consistently absent-or-empty --
        # never a source of a KeyError for a caller that iterates every
        # requested port.
        self.assertEqual(result.get(9603, []), [])

    def test_the_bulk_read_matches_the_single_port_read(self):
        self._write(9611, [_window_payload(start_minute=60), _window_payload(start_minute=30)])
        self._write(9612, [_window_payload(start_minute=90)])
        result = self._bulk([9611, 9612])
        self.assertEqual(result[9611], self._single(9611))
        self.assertEqual(result[9612], self._single(9612))

    def test_the_bulk_read_is_bounded(self):
        self._write(9621, [_window_payload(start_minute=m) for m in range(0, 300, 30)])
        with mock.patch.object(beacon_repositories, '_MAINTENANCE_WINDOWS_BULK_ROW_LIMIT', 3):
            result = self._bulk([9621])
        self.assertLessEqual(len(result.get(9621, [])), 3)


class OfflineIntervalTests(unittest.TestCase):
    """read_service_offline_intervals reconstructs offline spans from service_checks."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_check(self, port, ts, online):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO service_checks(ts, port, online) VALUES (?,?,?)',
                (ts, port, int(online)),
            )
            conn.commit()
            conn.close()

    def _intervals(self, port, start_ts, end_ts):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            intervals = beacon_repositories.read_service_offline_intervals(
                conn, port, start_ts=start_ts, end_ts=end_ts,
            )
            conn.close()
        return intervals

    def test_offline_intervals_are_reconstructed_from_service_checks(self):
        port = 9701
        base = 1_700_000_000
        self._insert_check(port, base, 1)
        self._insert_check(port, base + 60, 0)
        self._insert_check(port, base + 180, 1)
        intervals = self._intervals(port, base, base + 300)
        self.assertEqual(intervals, [(base + 60, base + 180)])

    def test_an_interval_still_open_at_the_period_end_is_clipped_to_it(self):
        port = 9702
        base = 1_700_000_000
        self._insert_check(port, base, 1)
        self._insert_check(port, base + 60, 0)
        intervals = self._intervals(port, base, base + 300)
        self.assertEqual(intervals, [(base + 60, base + 300)])


class AttributionTests(unittest.TestCase):
    """attributed_downtime_seconds intersects offline intervals with window coverage."""

    def test_an_offline_interval_fully_inside_a_window_is_fully_attributed(self):
        start = _epoch(2026, 1, 5, 2, 0, 0)  # a Monday
        row = _window_row(start_minute=120, duration_minutes=60, weekdays='1', grace_minutes=0)
        interval = (start + 300, start + 600)
        seconds = beacon_maintenance.attributed_downtime_seconds([interval], [row], 'UTC')
        self.assertEqual(seconds, 300)

    def test_an_offline_interval_fully_outside_any_window_attributes_zero(self):
        start = _epoch(2026, 1, 5, 2, 0, 0)
        row = _window_row(start_minute=120, duration_minutes=60, weekdays='1', grace_minutes=0)
        interval = (start - 7200, start - 3600)
        seconds = beacon_maintenance.attributed_downtime_seconds([interval], [row], 'UTC')
        self.assertEqual(seconds, 0)

    def test_an_interval_straddling_a_coverage_boundary_attributes_only_the_covered_part(self):
        start = _epoch(2026, 1, 5, 2, 0, 0)
        row = _window_row(start_minute=120, duration_minutes=60, weekdays='1', grace_minutes=0)
        # The window covers [start, start+3600). This interval straddles that
        # boundary by starting inside coverage and ending well past it.
        interval = (start + 1800, start + 5400)
        seconds = beacon_maintenance.attributed_downtime_seconds([interval], [row], 'UTC')
        self.assertEqual(seconds, 1800)

    def test_overlapping_windows_do_not_double_count_attributed_seconds(self):
        start = _epoch(2026, 1, 5, 2, 0, 0)
        row_a = _window_row(id=1, start_minute=120, duration_minutes=60, weekdays='1', grace_minutes=0)
        row_b = _window_row(id=2, start_minute=150, duration_minutes=60, weekdays='1', grace_minutes=0)
        # row_a covers [start, start+3600); row_b covers [start+1800, start+5400).
        # Their union covers the whole interval with no gap.
        interval = (start, start + 5400)
        seconds = beacon_maintenance.attributed_downtime_seconds([interval], [row_a, row_b], 'UTC')
        self.assertEqual(seconds, 5400)

    def test_attribution_never_exceeds_the_total_offline_seconds_in_the_period(self):
        start = _epoch(2026, 1, 5, 2, 0, 0)
        row = _window_row(
            start_minute=0, duration_minutes=1440, weekdays='1,2,3,4,5,6,7', grace_minutes=0,
        )
        interval = (start, start + 3600)
        seconds = beacon_maintenance.attributed_downtime_seconds([interval], [row], 'UTC')
        self.assertLessEqual(seconds, interval[1] - interval[0])
        self.assertEqual(seconds, 3600)

    def test_zero_attribution_is_reported_as_zero_not_as_absent(self):
        seconds = beacon_maintenance.attributed_downtime_seconds([], [], 'UTC')
        self.assertEqual(seconds, 0)
        self.assertIsNotNone(seconds)

    def test_malformed_windows_attribute_zero_and_do_not_raise(self):
        start = _epoch(2026, 1, 5, 2, 0, 0)
        bad_row = {
            'id': 1, 'port': 8080, 'start_minute': 'nope', 'duration_minutes': 30,
            'weekdays': '1', 'grace_minutes': 0, 'enabled': 1,
        }
        interval = (start, start + 300)
        seconds = beacon_maintenance.attributed_downtime_seconds([interval], [bad_row], 'UTC')
        self.assertEqual(seconds, 0)

    # G-03.1-71 / 03.1-REVIEW.md WR-05: the anchor-step budget used to be a
    # fixed constant (64) that bounded boundary discovery to ~129 days
    # regardless of the interval asked for. These four tests pin the fix: a
    # budget derived from the interval itself, an absolute ceiling that is
    # honest about its reach and reports itself when it binds, and a
    # measured cost bound so correctness at long intervals is not paid for
    # with an unservable endpoint on a Pi.
    #
    # All four use a daily, all-weekday, 60-minute, zero-grace window and an
    # interval that starts and ends at local noon -- a time never covered by
    # this window -- so every occurrence inside the interval is fully
    # contained and the expected total is exactly (interval length in days)
    # hours; the interval's own start instant is provably uncovered, which
    # is what makes the shipped (pre-fix) bound's failure mode an
    # under-count rather than an accidental over-count from a lucky
    # boundary alignment.

    def _noon_aligned_daily_window_interval(self, days):
        start = _epoch(2026, 1, 5, 0, 0, 0) + 43200  # a Monday at local noon
        row = _window_row(
            start_minute=0, duration_minutes=60, weekdays='1,2,3,4,5,6,7', grace_minutes=0,
        )
        return row, (start, start + days * 86400)

    def test_an_offline_interval_longer_than_the_shipped_anchor_bound_is_fully_attributed(self):
        # Planning measured 150d -> 150.0h and 400d -> 400.0h against the
        # fixed derivation below, versus 129.0h for both against the shipped
        # (pre-fix) bound of 64 steps -- the plateau documented in
        # 03.1-REVIEW.md WR-05 and G-03.1-71 (2N+1 = 129 days at N=64;
        # truncation begins at 130 days).
        for days in (150, 400):
            with self.subTest(days=days):
                row, interval = self._noon_aligned_daily_window_interval(days)
                # Expected total derived from the window's own arithmetic:
                # one fully-contained 60-minute occurrence per day across
                # the interval (see the noon-alignment note above), never a
                # pasted number.
                expected_seconds = days * 3600
                seconds = beacon_maintenance.attributed_downtime_seconds(
                    [interval], [row], 'UTC',
                )
                self.assertEqual(seconds, expected_seconds)

    def _natural_anchor_iterations(self, interval_start, interval_end):
        """Independent, non-formula cross-check: literally walk the anchor.

        A separate, deliberately naive re-implementation of
        ``_covering_boundaries``'s own loop condition (not a call to
        ``_anchor_step_budget``), so this test cannot pass merely because it
        recomputes the same closed-form expression the production code
        uses.
        """
        step_seconds = beacon_maintenance.MAINTENANCE_OCCURRENCE_LOOKBACK_DAYS * 86400
        anchor = interval_end
        count = 0
        while anchor >= interval_start - 86400:
            anchor -= step_seconds
            count += 1
        return count

    def test_the_anchor_step_budget_is_derived_from_the_interval_it_must_cover(self):
        interval_end = _epoch(2026, 1, 5, 0, 0, 0) + 43200
        budgets = []
        for days in (7, 30, 150, 400, 1000):
            interval_start = interval_end - days * 86400
            natural = self._natural_anchor_iterations(interval_start, interval_end)
            budget = beacon_maintenance._anchor_step_budget(interval_start, interval_end)
            # Sufficiency: the derived budget must be enough steps that the
            # loop terminates naturally (via its own anchor condition)
            # rather than being cut off by the budget.
            self.assertGreaterEqual(
                budget, natural,
                f'budget {budget} insufficient for a {days}-day interval needing {natural} steps',
            )
            budgets.append(budget)
        # Structural: the budget must actually grow with the interval, not
        # merely be "big enough" for the lengths tested here -- a future
        # change that raises the fixed constant to a bigger fixed number
        # would satisfy the sufficiency assertions above for these specific
        # lengths but fail this one, since a constant does not grow.
        self.assertEqual(budgets, sorted(budgets))
        self.assertLess(budgets[0], budgets[-1])

    def test_an_interval_beyond_the_absolute_ceiling_says_so_instead_of_returning_a_short_number(self):
        row, interval = self._noon_aligned_daily_window_interval(400)
        original_ceiling = beacon_maintenance._ATTRIBUTION_MAX_ANCHOR_STEPS
        # Reduce the ceiling for the duration of this test rather than
        # constructing a multi-decade fixture, and restore it in a finally
        # regardless of outcome.
        beacon_maintenance._ATTRIBUTION_MAX_ANCHOR_STEPS = 3
        try:
            with self.assertLogs('beacon.maintenance', level='WARNING') as captured:
                seconds = beacon_maintenance.attributed_downtime_seconds(
                    [interval], [row], 'UTC',
                )
        finally:
            beacon_maintenance._ATTRIBUTION_MAX_ANCHOR_STEPS = original_ceiling
        # No-raise: attributed_downtime_seconds still returns an integer --
        # both its callers (get_current_diagnosis and app.py's /api/services
        # path) consume an integer, and a live deployment must not acquire
        # a new failure mode from a long retention setting.
        self.assertIsInstance(seconds, int)
        self.assertEqual(len(captured.records), 1)
        message = captured.records[0].getMessage()
        # Non-silence: the warning names both the requested extent (400.0
        # days) and the actually-covered extent (2*3+1 = 7 days at the
        # reduced ceiling of 3 steps), so the log line is diagnostic rather
        # than decorative.
        self.assertIn('400.0 days', message)
        self.assertIn('7 days', message)

    def test_a_long_attribution_stays_within_its_stated_cost_ceiling(self):
        # Planning measured ~0.011s for a single-port 400-day attribution
        # (and ~0.091s for eight ports at that length) on development
        # hardware. A ceiling of 2.0s is roughly two orders of magnitude of
        # headroom for slower ARM hardware while still failing loudly on a
        # quadratic blow-up, which would land in the tens of seconds or
        # worse -- both edges reasoned, not an arbitrary round number.
        cost_ceiling_seconds = 2.0
        row, interval = self._noon_aligned_daily_window_interval(400)
        timings = []
        for _ in range(3):
            started = time.monotonic()
            beacon_maintenance.attributed_downtime_seconds([interval], [row], 'UTC')
            timings.append(time.monotonic() - started)
        for elapsed in timings:
            self.assertLess(elapsed, cost_ceiling_seconds)


class SettingsBoundsTests(unittest.TestCase):
    """The maintenance grace prefill and per-port window cap are safe-default Settings fields.

    These two assertions cover the PARSE only -- that ``Settings`` recovers a safe
    default from a missing or malformed environment value. They do not prove the
    parsed value reaches anything: see ``DefaultGraceMetadataTests`` below for the
    behavioural proof that the configured default grace, and its fail-closed
    fallback, actually reach the metadata payload the editor reads (G-03.1-69).
    """

    def test_the_default_grace_prefill_and_window_cap_have_defaults(self):
        settings = load_settings({})
        self.assertEqual(settings.maintenance_default_grace_minutes, 15)
        self.assertEqual(settings.maintenance_windows_per_port_max, 50)

    def test_a_non_numeric_bound_retains_its_default(self):
        settings = load_settings({
            'MAINTENANCE_DEFAULT_GRACE_MINUTES': 'not-a-number',
            'MAINTENANCE_WINDOWS_PER_PORT_MAX': 'also-not-a-number',
        })
        self.assertEqual(settings.maintenance_default_grace_minutes, 15)
        self.assertEqual(settings.maintenance_windows_per_port_max, 50)


class MetadataPayloadTests(unittest.TestCase):
    """metadata_response carries the port's windows, present and empty when none exist."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_service(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services(port, title, first_seen, last_seen, is_online) "
                "VALUES (?,?,?,?,1)",
                (port, f':{port}', 1_700_000_000, 1_700_000_000),
            )
            conn.commit()
            conn.close()

    def _meta_row(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            row = self.appmod._service_meta_row(conn, port)
            conn.close()
        return row

    def test_the_metadata_response_carries_the_ports_windows(self):
        port = 9101
        self._insert_service(port)

        empty_row = self._meta_row(port)
        self.assertIn('windows', empty_row)
        self.assertEqual(empty_row['windows'], [])

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            beacon_repositories.upsert_maintenance_windows(
                conn, port=port, windows=[_window_payload()], now=1_700_000_000,
            )
            conn.commit()
            conn.close()

        populated_row = self._meta_row(port)
        self.assertEqual(len(populated_row['windows']), 1)
        self.assertIsInstance(populated_row['windows'][0], dict)


class DefaultGraceMetadataTests(unittest.TestCase):
    """The configured default grace reaches the metadata payload the editor reads.

    Each test here reloads the app with its own environment, because the value
    under test (``MAINTENANCE_DEFAULT_GRACE_MINUTES``) must differ per test. The
    environment key is always restored via ``addCleanup`` so no later test -- in
    this class or any other -- inherits a value set here.
    """

    def _load(self, extra_env):
        appmod, db_path = load_app(extra_env)
        self.addCleanup(cleanup_db, db_path)
        for key in extra_env:
            self.addCleanup(os.environ.pop, key, None)
        return appmod

    def _insert_service(self, appmod, port):
        _insert_meta_service(appmod, port)

    def test_the_metadata_response_publishes_the_configured_default_grace(self):
        appmod = self._load({'MAINTENANCE_DEFAULT_GRACE_MINUTES': '45'})
        port = 9301
        self._insert_service(appmod, port)
        client = appmod.app.test_client()

        response = client.get(f'/api/service-meta/{port}')

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body['default_grace_minutes'], 45)
        self.assertIsInstance(body['default_grace_minutes'], int)
        self.assertNotIsInstance(body['default_grace_minutes'], bool)

    def test_a_malformed_default_grace_environment_value_publishes_the_documented_default(self):
        appmod = self._load({'MAINTENANCE_DEFAULT_GRACE_MINUTES': 'not-a-number'})
        port = 9302
        self._insert_service(appmod, port)
        client = appmod.app.test_client()

        response = client.get(f'/api/service-meta/{port}')

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body['default_grace_minutes'], 15)

    def test_a_stored_windows_own_grace_is_not_replaced_by_the_published_default(self):
        appmod = self._load({})
        port = 9303
        self._insert_service(appmod, port)
        with appmod._db_lock:
            conn = appmod.get_db()
            beacon_repositories.upsert_maintenance_windows(
                conn, port=port, windows=[_window_payload(grace_minutes=5)], now=1_700_000_000,
            )
            conn.commit()
            conn.close()
        client = appmod.app.test_client()

        response = client.get(f'/api/service-meta/{port}')

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body['default_grace_minutes'], 15)
        self.assertEqual(len(body['windows']), 1)
        self.assertEqual(body['windows'][0]['grace_minutes'], 5)


def _insert_meta_service(appmod, port):
    with appmod._db_lock:
        conn = appmod.get_db()
        conn.execute(
            "INSERT INTO services(port, title, first_seen, last_seen, is_online) "
            "VALUES (?,?,?,?,1)",
            (port, f':{port}', 1_700_000_000, 1_700_000_000),
        )
        conn.commit()
        conn.close()


class WindowCrudApiTests(unittest.TestCase):
    """PUT /api/service-meta/<port> accepts, edits, disables, and removes windows."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})
        self.client = self.appmod.app.test_client()
        self.ui_headers = {'X-Beacon-UI': '1'}

    def tearDown(self):
        cleanup_db(self.db_path)

    def _put(self, port, payload):
        return self.client.put(f'/api/service-meta/{port}', json=payload, headers=self.ui_headers)

    def _stored_windows(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = beacon_repositories.get_maintenance_windows(conn, port)
            conn.close()
        return rows

    def test_a_valid_window_list_is_accepted_and_returned(self):
        port = 9201
        _insert_meta_service(self.appmod, port)
        window = {
            'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1, 2, 3],
            'grace_minutes': 10, 'enabled': True,
        }
        response = self._put(port, {'maintenance_windows': [window]})
        self.assertEqual(response.status_code, 200)
        windows = response.get_json()['windows']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['start_minute'], 60)
        self.assertEqual(windows[0]['duration_minutes'], 30)
        self.assertEqual(sorted(windows[0]['weekdays']), [1, 2, 3])
        self.assertEqual(windows[0]['grace_minutes'], 10)
        self.assertTrue(windows[0]['enabled'])

    def test_several_windows_per_service_are_accepted(self):
        port = 9202
        _insert_meta_service(self.appmod, port)
        windows_payload = [
            {'start_minute': 0, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 5},
            {'start_minute': 600, 'duration_minutes': 120, 'weekdays': [6, 7], 'grace_minutes': 15},
            {'start_minute': 1000, 'duration_minutes': 15, 'weekdays': [2, 3, 4], 'grace_minutes': 0},
        ]
        response = self._put(port, {'maintenance_windows': windows_payload})
        self.assertEqual(response.status_code, 200)
        windows = response.get_json()['windows']
        self.assertEqual(len(windows), 3)
        self.assertEqual(sorted(w['start_minute'] for w in windows), [0, 600, 1000])

    def test_editing_a_window_replaces_it(self):
        port = 9203
        _insert_meta_service(self.appmod, port)
        self._put(port, {'maintenance_windows': [
            {'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 5},
        ]})
        response = self._put(port, {'maintenance_windows': [
            {'start_minute': 120, 'duration_minutes': 45, 'weekdays': [2], 'grace_minutes': 10},
        ]})
        self.assertEqual(response.status_code, 200)
        windows = response.get_json()['windows']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['start_minute'], 120)
        self.assertEqual(windows[0]['duration_minutes'], 45)

    def test_disabling_a_window_keeps_the_row(self):
        port = 9204
        _insert_meta_service(self.appmod, port)
        response = self._put(port, {'maintenance_windows': [
            {
                'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1],
                'grace_minutes': 5, 'enabled': False,
            },
        ]})
        self.assertEqual(response.status_code, 200)
        windows = response.get_json()['windows']
        self.assertEqual(len(windows), 1)
        self.assertFalse(windows[0]['enabled'])

    def test_an_empty_array_removes_every_window(self):
        port = 9205
        _insert_meta_service(self.appmod, port)
        self._put(port, {'maintenance_windows': [
            {'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 5},
        ]})
        response = self._put(port, {'maintenance_windows': []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['windows'], [])

    def test_omitting_the_key_leaves_existing_windows_untouched(self):
        port = 9206
        _insert_meta_service(self.appmod, port)
        self._put(port, {'maintenance_windows': [
            {'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 5},
        ]})
        response = self._put(port, {'display_name': 'Renamed'})
        self.assertEqual(response.status_code, 200)
        windows = response.get_json()['windows']
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['start_minute'], 60)

    def test_adjacent_windows_both_persist_and_cover_continuously(self):
        port = 9207
        _insert_meta_service(self.appmod, port)
        response = self._put(port, {'maintenance_windows': [
            {'start_minute': 0, 'duration_minutes': 60, 'weekdays': [1], 'grace_minutes': 0},
            {'start_minute': 60, 'duration_minutes': 60, 'weekdays': [1], 'grace_minutes': 0},
        ]})
        self.assertEqual(response.status_code, 200)
        windows = response.get_json()['windows']
        self.assertEqual(len(windows), 2)
        stored = self._stored_windows(port)
        seam_epoch = _epoch(2026, 1, 5, 1, 0, 0)  # Monday 01:00 -- the seam between the two windows
        covered, _ = beacon_maintenance.coverage(stored, seam_epoch, 'UTC')
        self.assertTrue(covered)

    def test_repeating_an_identical_put_is_idempotent(self):
        port = 9208
        _insert_meta_service(self.appmod, port)
        payload = {'maintenance_windows': [
            {'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1, 2], 'grace_minutes': 5},
        ]}
        first = self._put(port, payload)
        second = self._put(port, payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        first_windows = [
            {k: v for k, v in w.items() if k != 'id'} for w in first.get_json()['windows']
        ]
        second_windows = [
            {k: v for k, v in w.items() if k != 'id'} for w in second.get_json()['windows']
        ]
        self.assertEqual(first_windows, second_windows)


class WindowValidationTests(unittest.TestCase):
    """Every maintenance_windows field is bounds-checked server-side before any write."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})
        self.client = self.appmod.app.test_client()
        self.ui_headers = {'X-Beacon-UI': '1'}
        self.port = 9301
        _insert_meta_service(self.appmod, self.port)
        # Seed one known-good window so the "unchanged after rejection" assertions have
        # something concrete to check against.
        seed = self.client.put(
            f'/api/service-meta/{self.port}',
            json={'maintenance_windows': [
                {'start_minute': 480, 'duration_minutes': 60, 'weekdays': [3], 'grace_minutes': 10},
            ]},
            headers=self.ui_headers,
        )
        self.assertEqual(seed.status_code, 200)

    def tearDown(self):
        cleanup_db(self.db_path)

    def _stored_window_count(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            count = conn.execute(
                'SELECT COUNT(*) FROM maintenance_windows WHERE port=?', (self.port,),
            ).fetchone()[0]
            conn.close()
        return count

    def _assert_rejected(self, windows, expected_error):
        before_count = self._stored_window_count()
        response = self.client.put(
            f'/api/service-meta/{self.port}',
            json={'maintenance_windows': windows},
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], expected_error)
        self.assertEqual(self._stored_window_count(), before_count)

    def _valid_window(self, **overrides):
        window = {'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 5}
        window.update(overrides)
        return window

    def test_a_missing_start_time_is_rejected(self):
        window = self._valid_window()
        del window['start_minute']
        self._assert_rejected([window], 'Window 1: Start time is required.')

    def test_a_start_minute_outside_bounds_is_rejected(self):
        self._assert_rejected(
            [self._valid_window(start_minute=1440)], 'Window 1: Start time is required.',
        )

    def test_a_duration_below_one_is_rejected(self):
        self._assert_rejected(
            [self._valid_window(duration_minutes=0)],
            'Window 1: Duration must be at least 1 minute.',
        )

    def test_a_duration_above_the_bound_is_rejected(self):
        self._assert_rejected(
            [self._valid_window(duration_minutes=10081)],
            'Window 1: Duration must be at least 1 minute.',
        )

    def test_an_empty_weekday_list_is_rejected(self):
        self._assert_rejected(
            [self._valid_window(weekdays=[])], 'Window 1: Select at least one weekday.',
        )

    def test_a_weekday_integer_outside_range_is_rejected(self):
        self._assert_rejected(
            [self._valid_window(weekdays=[8])], 'Window 1: Select at least one weekday.',
        )

    def test_a_duplicate_weekday_is_rejected(self):
        self._assert_rejected(
            [self._valid_window(weekdays=[1, 1])], 'Window 1: Select at least one weekday.',
        )

    def test_a_missing_grace_is_rejected(self):
        window = self._valid_window()
        del window['grace_minutes']
        self._assert_rejected(
            [window], 'Window 1: Grace period is required and must be 0 minutes or more.',
        )

    def test_a_negative_grace_is_rejected(self):
        self._assert_rejected(
            [self._valid_window(grace_minutes=-1)],
            'Window 1: Grace period is required and must be 0 minutes or more.',
        )

    def test_a_non_object_list_element_is_rejected(self):
        self._assert_rejected(['not-an-object'], 'Window 1: Start time is required.')

    def test_a_non_list_payload_value_is_rejected(self):
        before_count = self._stored_window_count()
        response = self.client.put(
            f'/api/service-meta/{self.port}',
            json={'maintenance_windows': 'not-a-list'},
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'maintenance_windows must be an array')
        self.assertEqual(self._stored_window_count(), before_count)

    def test_a_list_longer_than_the_per_port_maximum_is_rejected(self):
        max_windows = self.appmod.SETTINGS.maintenance_windows_per_port_max
        windows = [self._valid_window(start_minute=start) for start in range(0, max_windows + 1)]
        before_count = self._stored_window_count()
        response = self.client.put(
            f'/api/service-meta/{self.port}',
            json={'maintenance_windows': windows},
            headers=self.ui_headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()['error'],
            f'A service may have at most {max_windows} maintenance windows.',
        )
        self.assertEqual(self._stored_window_count(), before_count)

    def test_a_boolean_is_not_accepted_where_an_integer_is_required(self):
        self._assert_rejected(
            [self._valid_window(start_minute=True)], 'Window 1: Start time is required.',
        )


class WindowConcurrencyTests(unittest.TestCase):
    """The metadata upsert and the window replacement share one commit."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})
        self.client = self.appmod.app.test_client()
        self.ui_headers = {'X-Beacon-UI': '1'}
        self.port = 9401
        _insert_meta_service(self.appmod, self.port)

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_metadata_and_windows_commit_together(self):
        # Seed a known display name so a rollback of the metadata write is provable too.
        seed = self.client.put(
            f'/api/service-meta/{self.port}',
            json={'display_name': 'Before'},
            headers=self.ui_headers,
        )
        self.assertEqual(seed.status_code, 200)

        with mock.patch.object(
            self.appmod.beacon_repositories, 'upsert_maintenance_windows',
            side_effect=sqlite3.Error('forced failure'),
        ):
            response = self.client.put(
                f'/api/service-meta/{self.port}',
                json={
                    'display_name': 'After',
                    'maintenance_windows': [
                        {'start_minute': 60, 'duration_minutes': 30, 'weekdays': [1], 'grace_minutes': 5},
                    ],
                },
                headers=self.ui_headers,
            )
        self.assertEqual(response.status_code, 503)

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            window_count = conn.execute(
                'SELECT COUNT(*) FROM maintenance_windows WHERE port=?', (self.port,),
            ).fetchone()[0]
            display_name = conn.execute(
                'SELECT display_name FROM service_meta WHERE port=?', (self.port,),
            ).fetchone()[0]
            conn.close()
        self.assertEqual(window_count, 0)
        self.assertEqual(display_name, 'Before')


class ReadOnlyAdvancedTests(unittest.TestCase):
    """The /advanced workspace never gains a mutation endpoint (D-01)."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_no_advanced_route_accepts_a_mutation_method(self):
        safe_methods = {'GET', 'HEAD', 'OPTIONS'}
        advanced_prefixes = ('/advanced', '/api/advanced')
        checked_any = False
        for rule in self.appmod.app.url_map.iter_rules():
            if rule.rule.startswith(advanced_prefixes):
                checked_any = True
                self.assertLessEqual(
                    rule.methods, safe_methods,
                    f'{rule.rule} permits {rule.methods - safe_methods}',
                )
        self.assertTrue(checked_any, 'expected at least one /advanced route to exist')


class SuppressionTracerTests(unittest.TestCase):
    """End-to-end: a real covered restart, tagged, retained, and unalerted."""

    def setUp(self):
        self._clock = {'now': None}
        self._clock_patcher = None
        self.appmod, self.db_path = load_app({'TZ': 'UTC'})
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _freeze_clock(self, value):
        """Freeze the process-global ``time.time`` for this test only.

        The patch is installed once per test and unwound by ``addCleanup`` even
        when the test fails, so no frozen instant can outlive the test that set
        it.  Calling this again inside the same test re-points the instant
        rather than stacking a second patcher.
        """
        self._clock['now'] = value
        if self._clock_patcher is None:
            real_time = time.time
            patcher = mock.patch(
                'time.time',
                lambda: real_time() if self._clock['now'] is None else self._clock['now'],
            )
            patcher.start()
            self.addCleanup(patcher.stop)
            self._clock_patcher = patcher
        return value

    def _authority(self, worker_id='worker-a'):
        now = int(self._clock['now'])
        lease = beacon_queues.acquire_worker_lease(self.db_path, worker_id, now=now, lease_seconds=3600)
        return WorkerAuthority.from_lease(lease, self.db_path)

    def _insert_service(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services(port, title, first_seen, last_seen, is_online) "
                "VALUES (?,?,?,?,1)",
                (port, f':{port}', 1_700_000_000, 1_700_000_000),
            )
            conn.execute(
                "INSERT INTO service_meta(port, display_name, url, critical, pinned_order, tags, healthy_statuses) "
                "VALUES (?,?,?,?,?,?,?)",
                (port, '', f'http://127.0.0.1:{port}', 0, port, '', '200-399'),
            )
            conn.commit()
            conn.close()

    def _insert_window(self, *, port, start_minute, duration_minutes, weekdays, grace_minutes=0, enabled=1):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO maintenance_windows("
                "port, start_minute, duration_minutes, weekdays, grace_minutes, enabled, "
                "created_ts, updated_ts) VALUES (?,?,?,?,?,?,?,?)",
                (port, start_minute, duration_minutes, weekdays, grace_minutes, enabled, 0, 0),
            )
            conn.commit()
            conn.close()

    def _events(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = conn.execute(
                "SELECT * FROM events WHERE port=? ORDER BY ts ASC, id ASC", (port,),
            ).fetchall()
            conn.close()
        return [dict(row) for row in rows]

    def _transition_kwargs(self, port, *, previous_online, online, latency_ms=None, error_class=None):
        return {
            'port': port, 'previous_online': previous_online, 'online': online,
            'title': f':{port}', 'display_name': '', 'url': f'http://127.0.0.1:{port}',
            'critical': 0, 'latency_ms': latency_ms, 'error_class': error_class,
        }

    def test_a_covered_down_transition_is_written_tagged_and_unalerted(self):
        port = 8181
        self._insert_service(port)
        down_now = self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        # Covers [01:40, 02:35) local -- "now" sits inside it.
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        authority = self._authority()
        with mock.patch.object(self.appmod, 'worker_send_transition_alert') as send_alert:
            result = self.appmod.worker_handle_state_transition(
                authority, **self._transition_kwargs(
                    port, previous_online=1, online=0, error_class='connection_refused',
                ),
            )
        send_alert.assert_not_called()
        self.assertFalse(result)

        events = self._events(port)
        state_changes = [e for e in events if e['event_type'] == 'state_change']
        self.assertEqual(len(state_changes), 1)
        self.assertEqual(state_changes[0]['suppressed_reason'], 'maintenance')
        expected_grace_until = _epoch(2026, 1, 5, 1, 40, 0) + 50 * 60 + 5 * 60
        self.assertEqual(state_changes[0]['maintenance_grace_until'], expected_grace_until)
        alert_rows = [e for e in events if e['event_type'] in ('alert_sent', 'alert_failed')]
        self.assertEqual(alert_rows, [])

    def test_the_matching_recovery_of_a_suppressed_down_period_is_also_tagged(self):
        port = 8182
        self._insert_service(port)
        down_now = self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=30,
        )
        authority = self._authority()
        with mock.patch.object(self.appmod, 'worker_send_transition_alert') as send_alert_down:
            self.appmod.worker_handle_state_transition(
                authority, **self._transition_kwargs(
                    port, previous_online=1, online=0, error_class='connection_refused',
                ),
            )
        send_alert_down.assert_not_called()

        self._freeze_clock(down_now + 10 * 60)  # still within grace
        with mock.patch.object(self.appmod, 'worker_send_transition_alert') as send_alert_up:
            self.appmod.worker_handle_state_transition(
                authority, **self._transition_kwargs(
                    port, previous_online=0, online=1, latency_ms=12.0,
                ),
            )
        send_alert_up.assert_not_called()

        events = self._events(port)
        state_changes = [e for e in events if e['event_type'] == 'state_change']
        self.assertEqual(len(state_changes), 2)
        self.assertEqual(state_changes[0]['suppressed_reason'], 'maintenance')
        self.assertEqual(state_changes[1]['suppressed_reason'], 'maintenance')
        alert_rows = [e for e in events if e['event_type'] in ('alert_sent', 'alert_failed')]
        self.assertEqual(alert_rows, [])

    def test_a_recovery_whose_down_period_was_not_suppressed_is_not_tagged(self):
        port = 8183
        self._insert_service(port)
        down_now = self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        authority = self._authority()
        with mock.patch.object(
            self.appmod, 'worker_send_transition_alert', return_value=False,
        ) as send_alert_down:
            self.appmod.worker_handle_state_transition(
                authority, **self._transition_kwargs(
                    port, previous_online=1, online=0, error_class='connection_refused',
                ),
            )
        send_alert_down.assert_called_once()

        # Only now does a window appear that would cover "now" at recovery
        # time -- proving the recovery decision is read off the down period's
        # own opening row and never re-derived from live coverage (D-08).
        self._insert_window(
            port=port, start_minute=0, duration_minutes=1440, weekdays='1,2,3,4,5,6,7',
        )
        self._freeze_clock(down_now + 5 * 60)
        with mock.patch.object(
            self.appmod, 'worker_send_transition_alert', return_value=False,
        ) as send_alert_up:
            self.appmod.worker_handle_state_transition(
                authority, **self._transition_kwargs(
                    port, previous_online=0, online=1, latency_ms=15.0,
                ),
            )
        send_alert_up.assert_called_once()

        events = self._events(port)
        state_changes = [e for e in events if e['event_type'] == 'state_change']
        self.assertEqual(len(state_changes), 2)
        self.assertIsNone(state_changes[0]['suppressed_reason'])
        self.assertIsNone(state_changes[1]['suppressed_reason'])

    def test_an_uncovered_down_transition_is_untagged_and_reaches_the_alert_path(self):
        port = 8184
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        authority = self._authority()
        with mock.patch.object(
            self.appmod, 'worker_send_transition_alert', return_value=False,
        ) as send_alert:
            result = self.appmod.worker_handle_state_transition(
                authority, **self._transition_kwargs(
                    port, previous_online=1, online=0, error_class='connection_refused',
                ),
            )
        send_alert.assert_called_once()
        self.assertFalse(result)

        events = self._events(port)
        state_changes = [e for e in events if e['event_type'] == 'state_change']
        self.assertEqual(len(state_changes), 1)
        self.assertIsNone(state_changes[0]['suppressed_reason'])
        self.assertIsNone(state_changes[0]['maintenance_grace_until'])


class OverrunTests(unittest.TestCase):
    """MNT-04: a service still down past its window's end plus grace raises
    exactly one truthful, untagged outage event -- driven through the real
    down-only probe cycle (``do_uptime_check``) rather than a stub of it."""

    def setUp(self):
        self._clock = {'now': None}
        self._clock_patcher = None
        self.appmod, self.db_path = load_app({'TZ': 'UTC'})
        self.client = self.appmod.app.test_client()
        self._probe_online = False
        self._probe_latency = None
        self._probe_error = 'connection_refused'
        self._original_probe = self.appmod._probe_http
        self.appmod._probe_http = self._fake_probe
        self.addCleanup(self._restore_probe)
        self._next_port = 9200

    def tearDown(self):
        cleanup_db(self.db_path)

    def _restore_probe(self):
        self.appmod._probe_http = self._original_probe

    def _fake_probe(self, *_args, **_kwargs):
        return self._probe_online, self._probe_latency, self._probe_error, None

    def _freeze_clock(self, value):
        """Freeze the process-global ``time.time`` for this test only (see
        ``SuppressionTracerTests._freeze_clock``; identical contract)."""
        self._clock['now'] = value
        if self._clock_patcher is None:
            real_time = time.time
            patcher = mock.patch(
                'time.time',
                lambda: real_time() if self._clock['now'] is None else self._clock['now'],
            )
            patcher.start()
            self.addCleanup(patcher.stop)
            self._clock_patcher = patcher
        return value

    def _allocate_port(self):
        self._next_port += 1
        return self._next_port

    def _insert_service(self, port, *, critical=0):
        now = int(self._clock['now'])
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services(port, title, first_seen, last_seen, is_online, state_since) "
                "VALUES (?,?,?,?,1,?)",
                (port, f':{port}', now, now, now),
            )
            conn.execute(
                "INSERT INTO service_meta(port, display_name, url, critical, pinned_order, tags, healthy_statuses) "
                "VALUES (?,?,?,?,?,?,?)",
                (port, '', f'http://127.0.0.1:{port}', critical, port, '', '200-399'),
            )
            conn.commit()
            conn.close()

    def _insert_window(self, *, port, start_minute, duration_minutes, weekdays, grace_minutes=0, enabled=1):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO maintenance_windows("
                "port, start_minute, duration_minutes, weekdays, grace_minutes, enabled, "
                "created_ts, updated_ts) VALUES (?,?,?,?,?,?,?,?)",
                (port, start_minute, duration_minutes, weekdays, grace_minutes, enabled, 0, 0),
            )
            conn.commit()
            conn.close()

    def _events(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = conn.execute(
                "SELECT * FROM events WHERE port=? ORDER BY ts ASC, id ASC", (port,),
            ).fetchall()
            conn.close()
        return [dict(row) for row in rows]

    def _overrun_rows(self, port):
        return [e for e in self._events(port) if e['event_type'] == 'maintenance_overrun']

    def _grace_until(self, port):
        down_changes = [
            e for e in self._events(port)
            if e['event_type'] == 'state_change' and e['online'] == 0
        ]
        self.assertTrue(down_changes, 'no down transition recorded yet')
        return down_changes[-1]['maintenance_grace_until']

    def _service_checks(self, port):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            rows = conn.execute(
                "SELECT ts, online FROM service_checks WHERE port=? ORDER BY ts ASC", (port,),
            ).fetchall()
            conn.close()
        return [(row['ts'], row['online']) for row in rows]

    def _go_down(self):
        self._probe_online = False
        self._probe_latency = None
        self._probe_error = 'connection_refused'
        self.appmod.do_uptime_check(only_down=False)

    def _go_up(self):
        self._probe_online = True
        self._probe_latency = 5.0
        self._probe_error = None
        self.appmod.do_uptime_check(only_down=False)

    def _poll_down_only(self):
        self._probe_online = False
        self._probe_latency = None
        self._probe_error = 'connection_refused'
        return self.appmod.do_uptime_check(only_down=True)

    def test_a_covered_service_still_down_past_grace_raises_one_outage(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        # Covers [01:40, 02:35) local plus 5 minutes grace -> boundary 02:40.
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary = self._grace_until(port)
        self._freeze_clock(boundary)
        self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 1)

    def test_the_overrun_event_carries_both_timestamps_separately(self):
        port = self._allocate_port()
        down_now = self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary = self._grace_until(port)
        self._freeze_clock(boundary)
        self._poll_down_only()
        rows = self._overrun_rows(port)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['down_since_ts'], down_now)
        self.assertEqual(rows[0]['ts'], boundary)
        self.assertNotEqual(rows[0]['down_since_ts'], rows[0]['ts'])

    def test_the_overrun_event_is_never_tagged_as_suppressed(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary = self._grace_until(port)
        self._freeze_clock(boundary)
        self._poll_down_only()
        rows = self._overrun_rows(port)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]['suppressed_reason'])

    def test_repeated_polls_raise_exactly_one_overrun(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary = self._grace_until(port)
        self._freeze_clock(boundary)
        for _ in range(4):
            self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 1)

    def test_no_overrun_is_raised_one_second_before_the_boundary(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary = self._grace_until(port)
        self._freeze_clock(boundary - 1)
        self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 0)
        self._freeze_clock(boundary)
        self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 1)

    def test_an_unsuppressed_down_period_never_raises_an_overrun(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        # No maintenance window at all for this port.
        self._go_down()
        for offset in (0, 1000, 100_000, 1_000_000):
            self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0) + offset)
            self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 0)

    def test_a_service_that_transitioned_this_poll_is_not_evaluated_for_overrun(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        # Simulate a stale bookkeeping value left behind by an earlier down
        # period -- the guard must ignore it entirely for a service that is
        # only now transitioning down this same poll (Pitfall 8).
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'UPDATE services SET overrun_raised_ts=? WHERE port=?',
                (int(self._clock['now']) - 1000, port),
            )
            conn.commit()
            conn.close()
        self._go_down()
        self.assertEqual(len(self._overrun_rows(port)), 0)

    def test_a_second_down_period_raises_its_own_overrun(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 0, 0, 0))
        self._insert_service(port)
        # All-day window so both down periods in this test stay covered.
        self._insert_window(
            port=port, start_minute=0, duration_minutes=1440,
            weekdays='1,2,3,4,5,6,7', grace_minutes=2,
        )
        self._go_down()
        boundary_1 = self._grace_until(port)
        self._freeze_clock(boundary_1)
        self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 1)

        self._freeze_clock(boundary_1 + 60)
        self._go_up()
        self._freeze_clock(boundary_1 + 120)
        self._go_down()
        boundary_2 = self._grace_until(port)
        self.assertGreater(boundary_2, boundary_1)
        self._freeze_clock(boundary_2)
        self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 2)

    def test_editing_the_window_mid_outage_does_not_move_the_boundary(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        original_boundary = self._grace_until(port)

        # Operator edits the window mid-outage with a much longer grace.
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            beacon_repositories.upsert_maintenance_windows(
                conn, port=port, windows=[{
                    'start_minute': 100, 'duration_minutes': 50,
                    'weekdays': [1], 'grace_minutes': 500, 'enabled': True,
                }], now=int(self._clock['now']),
            )
            conn.commit()
            conn.close()

        self._freeze_clock(original_boundary)
        self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(port)), 1)

    def test_the_overrun_dispatches_through_the_existing_alert_sender(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary = self._grace_until(port)
        self._freeze_clock(boundary)

        self.appmod.ALERT_WEBHOOK_URL = 'https://alerts.example.test/beacon'
        self.appmod.ALERT_ONLY_CRITICAL = False
        with mock.patch.object(self.appmod, '_send_transition_alert') as send_alert:
            self._poll_down_only()
        send_alert.assert_called_once()
        kwargs = send_alert.call_args.kwargs
        self.assertEqual(kwargs['port'], port)
        self.assertEqual(kwargs['online'], 0)
        self.assertEqual(kwargs['previous_online'], 0)

        # The critical-only gate is the same gate the real sender already
        # enforces -- not a parallel one -- so a non-critical service under
        # ALERT_ONLY_CRITICAL never reaches the webhook at all.
        port2 = self._allocate_port()
        self._insert_service(port2, critical=0)
        self._insert_window(
            port=port2, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary2 = self._grace_until(port2)
        self._freeze_clock(boundary2)
        self.appmod.ALERT_ONLY_CRITICAL = True
        fake_transport = mock.Mock()
        with mock.patch.object(self.appmod, '_outbound_transport', return_value=fake_transport):
            self._poll_down_only()
        fake_transport.request.assert_not_called()

    def test_the_alert_is_dispatched_outside_the_write_transaction(self):
        port = self._allocate_port()
        self._freeze_clock(_epoch(2026, 1, 5, 2, 0, 0))
        self._insert_service(port)
        self._insert_window(
            port=port, start_minute=100, duration_minutes=50, weekdays='1', grace_minutes=5,
        )
        self._go_down()
        boundary = self._grace_until(port)
        self._freeze_clock(boundary)

        self.appmod.ALERT_WEBHOOK_URL = 'https://alerts.example.test/beacon'
        lock_was_free = []

        def fake_alert(**_kwargs):
            acquired = self.appmod._db_lock.acquire(blocking=False)
            lock_was_free.append(acquired)
            if acquired:
                self.appmod._db_lock.release()

        with mock.patch.object(self.appmod, '_send_transition_alert', side_effect=fake_alert):
            self._poll_down_only()

        self.assertEqual(lock_was_free, [True])

    def test_availability_is_unchanged_by_an_overrun(self):
        covered_port = self._allocate_port()
        plain_port = self._allocate_port()
        start = _epoch(2026, 1, 5, 2, 0, 0)
        self._freeze_clock(start)
        self._insert_service(covered_port)
        self._insert_service(plain_port)
        self._insert_window(
            port=covered_port, start_minute=100, duration_minutes=50,
            weekdays='1', grace_minutes=5,
        )
        # Both services transition down together, identically.
        self._go_down()
        boundary = self._grace_until(covered_port)
        self._freeze_clock(boundary)
        self._poll_down_only()
        self.assertEqual(len(self._overrun_rows(covered_port)), 1)
        self.assertEqual(len(self._overrun_rows(plain_port)), 0)

        checks_covered = self._service_checks(covered_port)
        checks_plain = self._service_checks(plain_port)
        self.assertEqual(
            [online for _ts, online in checks_covered],
            [online for _ts, online in checks_plain],
        )
        pct_covered = self.appmod._calc_uptime_pct(checks_covered, now=boundary)
        pct_plain = self.appmod._calc_uptime_pct(checks_plain, now=boundary)
        self.assertEqual(pct_covered, pct_plain)


class SuggestionLifecycleTests(unittest.TestCase):
    """GET /api/service-meta/<port> recomputes the MNT-02 suggestion on every read."""

    def setUp(self):
        self._clock = {'now': None}
        self._clock_patcher = None
        self.appmod, self.db_path = load_app({'TZ': 'UTC'})
        self.client = self.appmod.app.test_client()
        self.ui_headers = {'X-Beacon-UI': '1'}

    def tearDown(self):
        cleanup_db(self.db_path)

    def _freeze_clock(self, value):
        """Freeze the process-global ``time.time`` for this test only."""
        self._clock['now'] = value
        if self._clock_patcher is None:
            real_time = time.time
            patcher = mock.patch(
                'time.time',
                lambda: real_time() if self._clock['now'] is None else self._clock['now'],
            )
            patcher.start()
            self.addCleanup(patcher.stop)
            self._clock_patcher = patcher
        return value

    def _insert_service(self, port):
        _insert_meta_service(self.appmod, port)

    def _insert_window(
        self, *, port, start_minute, duration_minutes, weekdays, grace_minutes=0, enabled=1,
    ):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO maintenance_windows("
                "port, start_minute, duration_minutes, weekdays, grace_minutes, enabled, "
                "created_ts, updated_ts) VALUES (?,?,?,?,?,?,?,?)",
                (port, start_minute, duration_minutes, weekdays, grace_minutes, enabled, 0, 0),
            )
            conn.commit()
            conn.close()

    def _seed_occurrence(self, port, date_ymd, hour, minute, duration_minutes, *, suppressed=False):
        down_ts, recovered_ts = _pair(date_ymd, hour, minute, duration_minutes)
        reason = beacon_maintenance.MAINTENANCE_REASON if suppressed else None
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO events(ts, port, event_type, online, previous_online, suppressed_reason) "
                "VALUES (?,?,?,?,?,?)",
                (down_ts, port, 'state_change', 0, 1, reason),
            )
            conn.execute(
                "INSERT INTO events(ts, port, event_type, online, previous_online, suppressed_reason) "
                "VALUES (?,?,?,?,?,?)",
                (recovered_ts, port, 'state_change', 1, 0, reason),
            )
            conn.commit()
            conn.close()

    def _seed_pattern(self, port, *, dates, hour, minute, duration_minutes, suppressed=False):
        for date_ymd in dates:
            self._seed_occurrence(port, date_ymd, hour, minute, duration_minutes, suppressed=suppressed)

    def _get_meta(self, port):
        return self.client.get(f'/api/service-meta/{port}', headers=self.ui_headers)

    def _table_counts(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            tables = [
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            ]
            counts = {
                table: conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                for table in tables
            }
            conn.close()
        return counts

    def test_a_qualifying_pattern_appears_in_the_service_meta_get(self):
        port = 9351
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        self._seed_pattern(
            port, dates=[(2026, 1, 5), (2026, 1, 6), (2026, 1, 7)],
            hour=2, minute=0, duration_minutes=30,
        )
        response = self._get_meta(port)
        self.assertEqual(response.status_code, 200)
        suggestion = response.get_json()['suggestion']
        self.assertIsNotNone(suggestion)
        self.assertEqual(suggestion['occurrence_count'], 3)
        self.assertEqual(suggestion['start_minute'], 120)
        self.assertEqual(suggestion['duration_minutes'], 30)
        self.assertEqual(sorted(suggestion['weekdays']), list(range(1, 8)))

    def test_a_service_with_no_pattern_omits_the_suggestion_field(self):
        port = 9352
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        response = self._get_meta(port)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get_json().get('suggestion'))

    def test_the_suggestion_disappears_when_the_pattern_stops(self):
        port = 9353
        self._insert_service(port)
        base = _epoch(2026, 1, 1, 2, 0, 0)
        self._seed_pattern(
            port, dates=[(2026, 1, 1), (2026, 1, 2), (2026, 1, 3)],
            hour=2, minute=0, duration_minutes=30,
        )
        self._freeze_clock(base + 5 * 86400)  # 5 days later -- still inside the 21-day lookback
        first = self._get_meta(port)
        self.assertIsNotNone(first.get_json()['suggestion'])

        self._freeze_clock(base + 30 * 86400)  # 30 days later -- past the 21-day lookback
        second = self._get_meta(port)
        self.assertIsNone(second.get_json().get('suggestion'))

    def test_the_suggestion_is_recomputed_not_frozen(self):
        port = 9354
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 9, 12, 0, 0))
        self._seed_occurrence(port, (2026, 1, 5), 1, 58, 30)
        self._seed_occurrence(port, (2026, 1, 6), 2, 0, 30)
        self._seed_occurrence(port, (2026, 1, 7), 2, 2, 30)
        first = self._get_meta(port).get_json()['suggestion']
        self.assertIsNotNone(first)
        self.assertEqual(first['start_minute'], 120)

        # A fourth, later occurrence shifts the cluster's median.
        self._seed_occurrence(port, (2026, 1, 8), 2, 12, 30)
        second = self._get_meta(port).get_json()['suggestion']
        self.assertIsNotNone(second)
        self.assertNotEqual(second['start_minute'], first['start_minute'])

    def test_suppressed_transitions_count_as_evidence(self):
        port = 9355
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        self._seed_pattern(
            port, dates=[(2026, 1, 5), (2026, 1, 6), (2026, 1, 7)],
            hour=2, minute=0, duration_minutes=30, suppressed=True,
        )
        suggestion = self._get_meta(port).get_json()['suggestion']
        self.assertIsNotNone(suggestion)
        self.assertEqual(suggestion['occurrence_count'], 3)

    def test_a_pattern_already_covered_by_an_enabled_window_is_withheld(self):
        port = 9356
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        self._seed_pattern(
            port, dates=[(2026, 1, 5), (2026, 1, 6), (2026, 1, 7)],
            hour=2, minute=0, duration_minutes=30,
        )
        self._insert_window(
            port=port, start_minute=120, duration_minutes=30,
            weekdays='1,2,3,4,5,6,7', grace_minutes=0, enabled=1,
        )
        suggestion = self._get_meta(port).get_json().get('suggestion')
        self.assertIsNone(suggestion)

    def test_a_pattern_covered_only_by_a_disabled_window_is_still_offered(self):
        port = 9357
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        self._seed_pattern(
            port, dates=[(2026, 1, 5), (2026, 1, 6), (2026, 1, 7)],
            hour=2, minute=0, duration_minutes=30,
        )
        self._insert_window(
            port=port, start_minute=120, duration_minutes=30,
            weekdays='1,2,3,4,5,6,7', grace_minutes=0, enabled=0,
        )
        suggestion = self._get_meta(port).get_json().get('suggestion')
        self.assertIsNotNone(suggestion)

    def test_a_second_unrelated_pattern_is_still_offered(self):
        port = 9358
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        self._seed_pattern(
            port, dates=[(2026, 1, 5), (2026, 1, 6), (2026, 1, 7)],
            hour=2, minute=0, duration_minutes=30,
        )
        self._insert_window(
            port=port, start_minute=800, duration_minutes=30,
            weekdays='1,2,3,4,5,6,7', grace_minutes=0, enabled=1,
        )
        suggestion = self._get_meta(port).get_json().get('suggestion')
        self.assertIsNotNone(suggestion)
        self.assertEqual(suggestion['start_minute'], 120)

    def test_no_row_is_written_by_computing_a_suggestion(self):
        port = 9359
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        self._seed_pattern(
            port, dates=[(2026, 1, 5), (2026, 1, 6), (2026, 1, 7)],
            hour=2, minute=0, duration_minutes=30,
        )
        before = self._table_counts()
        response = self._get_meta(port)
        self.assertIsNotNone(response.get_json()['suggestion'])
        after = self._table_counts()
        self.assertEqual(before, after)

    def test_the_suggestion_appears_on_no_other_endpoint(self):
        port = 9360
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 8, 12, 0, 0))
        self._seed_pattern(
            port, dates=[(2026, 1, 5), (2026, 1, 6), (2026, 1, 7)],
            hour=2, minute=0, duration_minutes=30,
        )
        self.assertIsNotNone(self._get_meta(port).get_json()['suggestion'])

        services_response = self.client.get('/api/services')
        self.assertEqual(services_response.status_code, 200)
        for service in services_response.get_json():
            self.assertNotIn('suggestion', service)

        advanced_response = self.client.get('/api/advanced/current')
        self.assertEqual(advanced_response.status_code, 200)
        for service in advanced_response.get_json().get('services', []):
            self.assertNotIn('suggestion', service)

    def test_the_detector_and_withholding_rule_agree_across_the_midnight_boundary(self):
        # Proves the detector fix (Task 1) and the withholding fix (Task 2)
        # agree through the live API, not merely in isolation: a
        # midnight-straddling pattern is withheld while a matching enabled
        # window exists, and offered -- with the exact circular start
        # minute Task 1 established -- once that window is disabled.
        port = 9361
        self._insert_service(port)
        self._freeze_clock(_epoch(2026, 1, 13, 12, 0, 0))
        # Spaced two calendar days apart so each occurrence's recovery
        # finishes well before the next one's down transition begins --
        # otherwise the repository's sequential down/recovery pairing would
        # misattribute recoveries across occurrences. The clock-time values
        # (23:55, 00:00, 00:05, 23:58) are what matters for clustering, not
        # the specific dates.
        self._seed_occurrence(port, (2026, 1, 5), 23, 55, 30)
        self._seed_occurrence(port, (2026, 1, 7), 0, 0, 30)
        self._seed_occurrence(port, (2026, 1, 9), 0, 5, 30)
        self._seed_occurrence(port, (2026, 1, 11), 23, 58, 30)
        self._insert_window(
            port=port, start_minute=0, duration_minutes=30,
            weekdays='1,2,3,4,5,6,7', grace_minutes=0, enabled=1,
        )

        withheld_body = self._get_meta(port).get_json()
        self.assertIn('suggestion', withheld_body)
        self.assertIsNone(withheld_body['suggestion'])

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "UPDATE maintenance_windows SET enabled = 0 WHERE port = ?",
                (port,),
            )
            conn.commit()
            conn.close()

        offered_body = self._get_meta(port).get_json()
        offered_suggestion = offered_body.get('suggestion')
        self.assertIsNotNone(offered_suggestion)
        self.assertEqual(offered_suggestion['occurrence_count'], 4)
        self.assertEqual(offered_suggestion['start_minute'], 1439)


class SuggestionEvidenceTests(unittest.TestCase):
    """get_maintenance_suggestion_evidence pairs down/recovered state_change rows."""

    def setUp(self):
        self.appmod, self.db_path = load_app({})

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_state_change(self, port, ts, online):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO events(ts, port, event_type, online, previous_online) "
                "VALUES (?,?,?,?,?)",
                (ts, port, 'state_change', online, 1 - online),
            )
            conn.commit()
            conn.close()

    def _evidence(self, port, since_ts):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            pairs = beacon_repositories.get_maintenance_suggestion_evidence(
                conn, port, since_ts=since_ts,
            )
            conn.close()
        return pairs

    def test_pairs_are_bounded_by_the_configured_lookback(self):
        port = 9401
        old_down, old_recovered = _pair((2026, 1, 1), 2, 0, 30)
        recent_down, recent_recovered = _pair((2026, 1, 20), 2, 0, 30)
        self._insert_state_change(port, old_down, 0)
        self._insert_state_change(port, old_recovered, 1)
        self._insert_state_change(port, recent_down, 0)
        self._insert_state_change(port, recent_recovered, 1)

        since_ts = _epoch(2026, 1, 10, 0, 0, 0)
        pairs = self._evidence(port, since_ts)
        self.assertEqual(pairs, [(recent_down, recent_recovered)])

    def test_an_unrecovered_down_transition_is_not_paired(self):
        port = 9402
        down_ts, recovered_ts = _pair((2026, 1, 5), 2, 0, 30)
        self._insert_state_change(port, down_ts, 0)
        self._insert_state_change(port, recovered_ts, 1)
        trailing_down = recovered_ts + 3600
        self._insert_state_change(port, trailing_down, 0)  # never recovers

        pairs = self._evidence(port, _epoch(2026, 1, 1, 0, 0, 0))
        self.assertEqual(pairs, [(down_ts, recovered_ts)])

    def test_pairs_are_returned_in_chronological_order(self):
        port = 9403
        first_down, first_recovered = _pair((2026, 1, 5), 2, 0, 30)
        second_down, second_recovered = _pair((2026, 1, 6), 2, 0, 30)
        third_down, third_recovered = _pair((2026, 1, 7), 2, 0, 30)
        # Insert out of order to prove the read sorts, not merely echoes insert order.
        self._insert_state_change(port, third_down, 0)
        self._insert_state_change(port, third_recovered, 1)
        self._insert_state_change(port, first_down, 0)
        self._insert_state_change(port, first_recovered, 1)
        self._insert_state_change(port, second_down, 0)
        self._insert_state_change(port, second_recovered, 1)

        pairs = self._evidence(port, _epoch(2026, 1, 1, 0, 0, 0))
        self.assertEqual(
            pairs,
            [
                (first_down, first_recovered),
                (second_down, second_recovered),
                (third_down, third_recovered),
            ],
        )


class ServicesPayloadTests(unittest.TestCase):
    """The main dashboard's /api/services publishes D-06's derived availability."""

    def setUp(self):
        self._clock = {'now': None}
        self._clock_patcher = None
        self.appmod, self.db_path = load_app({})
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _freeze_clock(self, value):
        """Freeze the process-global ``time.time`` for this test only (see
        ``SuppressionTracerTests._freeze_clock``; identical contract)."""
        self._clock['now'] = value
        if self._clock_patcher is None:
            real_time = time.time
            patcher = mock.patch(
                'time.time',
                lambda: real_time() if self._clock['now'] is None else self._clock['now'],
            )
            patcher.start()
            self.addCleanup(patcher.stop)
            self._clock_patcher = patcher
        return value

    def _seed_service(self, port, *, is_online, state_since, last_error=None):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                'INSERT INTO services(port,title,first_seen,last_seen,is_online,'
                'last_latency_ms,last_error,state_since) VALUES(?,?,?,?,?,?,?,?)',
                (
                    port, f'Service {port}', state_since - 100, state_since + 100000,
                    is_online, None, last_error, state_since,
                ),
            )
            conn.execute(
                'INSERT INTO service_meta(port,display_name,url,critical,pinned_order,tags,healthy_statuses) '
                'VALUES(?,?,?,?,?,?,?)',
                (port, f'Service {port}', f'http://127.0.0.1:{port}', 0, port, '', '200-399'),
            )
            conn.commit()
            conn.close()

    def _insert_checks(self, port, checks):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            for ts, online in checks:
                conn.execute(
                    'INSERT INTO service_checks(ts,port,online) VALUES(?,?,?)', (ts, port, online),
                )
            conn.commit()
            conn.close()

    def _write_window(
        self, port, *, start_minute, duration_minutes, weekdays, grace_minutes, enabled=True,
        now=1_700_000_000,
    ):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            beacon_repositories.upsert_maintenance_windows(
                conn, port=port,
                windows=[{
                    'start_minute': start_minute, 'duration_minutes': duration_minutes,
                    'weekdays': set(weekdays), 'grace_minutes': grace_minutes, 'enabled': enabled,
                }],
                now=now,
            )
            conn.commit()
            conn.close()

    def _services(self):
        return self.client.get('/api/services').get_json()

    def _service(self, port):
        return next(s for s in self._services() if s['port'] == port)

    def test_an_offline_covered_service_publishes_the_maintenance_availability(self):
        now = _epoch(2026, 1, 5, 2, 15, 0)  # a Monday, inside a 2:00-3:00 window
        port = 9611
        self._seed_service(port, is_online=0, state_since=now - 900, last_error='ConnectionRefused')
        self._write_window(port, start_minute=120, duration_minutes=60, weekdays=(1,), grace_minutes=10)
        self._freeze_clock(now)

        self.assertEqual(self._service(port)['availability'], 'maintenance')

    def test_the_is_online_field_is_still_false_for_a_covered_service(self):
        now = _epoch(2026, 1, 5, 2, 15, 0)
        port = 9612
        self._seed_service(port, is_online=0, state_since=now - 900)
        self._write_window(port, start_minute=120, duration_minutes=60, weekdays=(1,), grace_minutes=10)
        self._freeze_clock(now)

        service = self._service(port)
        self.assertEqual(service['availability'], 'maintenance')
        self.assertEqual(service['is_online'], 0)

    def test_the_since_and_error_fields_are_the_true_stored_ones(self):
        now = _epoch(2026, 1, 5, 2, 15, 0)
        port = 9613
        self._seed_service(port, is_online=0, state_since=now - 900, last_error='ConnectionRefused')
        self._write_window(port, start_minute=120, duration_minutes=60, weekdays=(1,), grace_minutes=10)
        self._freeze_clock(now)

        service = self._service(port)
        self.assertEqual(service['state_since'], now - 900)
        self.assertEqual(service['last_error'], 'ConnectionRefused')

    def test_the_payload_carries_the_coverage_end_instant_for_the_disclosure(self):
        now = _epoch(2026, 1, 5, 2, 15, 0)
        port = 9614
        self._seed_service(port, is_online=0, state_since=now - 900)
        self._write_window(port, start_minute=120, duration_minutes=60, weekdays=(1,), grace_minutes=10)
        self._freeze_clock(now)

        service = self._service(port)
        self.assertEqual(service['availability'], 'maintenance')
        self.assertIsInstance(service['maintenance_until'], int)
        self.assertEqual(service['maintenance_until'], _epoch(2026, 1, 5, 3, 10, 0))

    def test_an_online_service_publishes_the_online_availability(self):
        now = _epoch(2026, 1, 5, 2, 15, 0)
        port = 9615
        self._seed_service(port, is_online=1, state_since=now - 900)
        self._freeze_clock(now)

        service = self._service(port)
        self.assertEqual(service['availability'], 'online')
        self.assertIsNone(service['maintenance_until'])

    def test_an_offline_uncovered_service_publishes_the_offline_availability(self):
        now = _epoch(2026, 1, 5, 2, 15, 0)
        port = 9616
        self._seed_service(port, is_online=0, state_since=now - 900)
        self._freeze_clock(now)

        service = self._service(port)
        self.assertEqual(service['availability'], 'offline')
        self.assertIsNone(service['maintenance_until'])

    def test_the_uptime_percentage_is_identical_with_and_without_suppression(self):
        now = _epoch(2026, 1, 5, 4, 0, 0)
        port_uncovered, port_covered = 9617, 9618
        checks = [(now - 300, 1), (now - 240, 0), (now - 120, 0), (now, 0)]
        for port in (port_uncovered, port_covered):
            self._seed_service(port, is_online=0, state_since=now - 240)
            self._insert_checks(port, checks)
        self._write_window(
            port_covered, start_minute=120, duration_minutes=180, weekdays=(1,), grace_minutes=60,
        )
        self._freeze_clock(now)

        uncovered = self._service(port_uncovered)
        covered = self._service(port_covered)
        self.assertEqual(uncovered['availability'], 'offline')
        self.assertEqual(covered['availability'], 'maintenance')
        self.assertEqual(uncovered['uptime_pct'], covered['uptime_pct'])
        self.assertEqual(uncovered['uptime_buckets'], covered['uptime_buckets'])

    def test_the_payload_contains_no_second_availability_percentage(self):
        now = _epoch(2026, 1, 5, 4, 0, 0)
        port = 9619
        self._seed_service(port, is_online=1, state_since=now - 900)
        self._insert_checks(port, [(now - 60, 1), (now, 1)])
        self._freeze_clock(now)

        service = self._service(port)
        percent_like_keys = [key for key in service if 'pct' in key.lower() or 'percent' in key.lower()]
        self.assertEqual(percent_like_keys, ['uptime_pct'])

    def test_every_failed_probe_is_still_stored(self):
        now = _epoch(2026, 1, 5, 4, 0, 0)
        port = 9620
        checks = [(now - offset, 0) for offset in (0, 60, 120, 180, 240)]
        self._seed_service(port, is_online=0, state_since=now - 300)
        self._insert_checks(port, checks)
        self._freeze_clock(now)

        self._services()

        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            count = conn.execute(
                'SELECT COUNT(*) FROM service_checks WHERE port=?', (port,),
            ).fetchone()[0]
            conn.close()
        self.assertEqual(count, len(checks))


class TimezoneEnvironmentTests(unittest.TestCase):
    """The IANA time-zone database resolves inside this environment, and the
    operator's TZ value reaches Settings/the containers with a fail-closed
    default (D-02's container gap, closed by plan 03.1-02)."""

    def test_a_named_iana_zone_resolves_in_this_environment(self):
        """Regression for Pitfall 2: this must not be mocked -- it is the one
        test that fails inside a container missing the IANA database."""
        january = datetime(2026, 1, 15, 12, 0, tzinfo=ZoneInfo('America/New_York'))
        july = datetime(2026, 7, 15, 12, 0, tzinfo=ZoneInfo('America/New_York'))
        self.assertNotEqual(january.utcoffset(), july.utcoffset())

        london_january = datetime(2026, 1, 15, 12, 0, tzinfo=ZoneInfo('Europe/London'))
        london_july = datetime(2026, 7, 15, 12, 0, tzinfo=ZoneInfo('Europe/London'))
        self.assertNotEqual(london_january.utcoffset(), london_july.utcoffset())

    def test_load_settings_reads_the_tz_environment_key(self):
        settings = load_settings({'TZ': 'America/New_York'})
        self.assertEqual(settings.timezone, 'America/New_York')

    def test_load_settings_falls_back_to_utc_on_an_unresolvable_zone(self):
        settings = load_settings({'TZ': 'Not/AZone'})
        self.assertEqual(settings.timezone, 'UTC')

    def test_load_settings_falls_back_to_utc_on_an_empty_tz(self):
        self.assertEqual(load_settings({'TZ': ''}).timezone, 'UTC')
        self.assertEqual(load_settings({}).timezone, 'UTC')

    def test_the_compose_file_supplies_tz_to_the_worker_and_web_services(self):
        compose_text = (PROJECT_ROOT / 'docker-compose.yml').read_text()
        services = compose_text.split('\nservices:\n', 1)[1]
        worker_block = services.split('\n  worker:\n', 1)[1].split('\n  recovery:\n', 1)[0]
        web_block = services.split('\n  web:\n', 1)[1]
        self.assertIn('TZ', worker_block)
        self.assertIn('TZ', web_block)

    def test_the_project_pins_the_iana_database_as_a_python_dependency(self):
        pyproject_text = (PROJECT_ROOT / 'dashboard' / 'pyproject.toml').read_text()
        self.assertIn('tzdata', pyproject_text)

        dockerfile_text = (PROJECT_ROOT / 'dashboard' / 'Dockerfile').read_text()
        self.assertNotRegex(dockerfile_text, r'(?i)apt-get.*tzdata')


class ClockIsolationTests(unittest.TestCase):
    """The phase module must leave the process-global clock exactly as it found it."""

    def test_a_frozen_clock_never_outlives_the_test_that_froze_it(self):
        """WR-05: a frozen test clock must not survive into any later module."""
        probe = SuppressionTracerTests(
            'test_a_covered_down_transition_is_written_tagged_and_unalerted'
        )
        result = unittest.TestResult()
        probe.run(result)

        self.assertEqual([], result.errors + result.failures)
        self.assertGreater(
            time.time(),
            1_750_000_000,
            'the frozen test clock leaked past the test that installed it',
        )


if __name__ == '__main__':
    unittest.main()
