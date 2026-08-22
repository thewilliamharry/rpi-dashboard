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


class SettingsBoundsTests(unittest.TestCase):
    """The maintenance grace prefill and per-port window cap are safe-default Settings fields."""

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
