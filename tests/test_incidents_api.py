import time
import unittest

from dashboard.beacon import incidents as beacon_incidents
from tests.helpers import cleanup_db, load_app


def _row(id, ts, *, port=80, online=None, event_type='state_change',
         previous_online=None, latency_ms=None, error_class=None, alert_status=None,
         details=None, suppressed_reason=None, maintenance_grace_until=None,
         down_since_ts=None, service_name='svc', critical=0):
    """Build one full in-memory event-row mapping matching EVENT_COLUMNS' shape."""
    return {
        'id': id, 'ts': ts, 'port': port, 'event_type': event_type, 'online': online,
        'previous_online': previous_online, 'latency_ms': latency_ms,
        'error_class': error_class, 'alert_status': alert_status, 'details': details,
        'suppressed_reason': suppressed_reason,
        'maintenance_grace_until': maintenance_grace_until,
        'down_since_ts': down_since_ts, 'service_name': service_name, 'critical': critical,
    }


class GroupEpisodesTests(unittest.TestCase):
    def test_down_then_up_returns_one_closed_episode(self):
        rows = [_row(1, 100, online=0), _row(2, 200, online=1)]
        episodes = beacon_incidents.group_episodes(rows)
        self.assertEqual(len(episodes), 1)
        episode = episodes[0]
        self.assertEqual(episode['down_ts'], 100)
        self.assertEqual(episode['recovered_ts'], 200)
        self.assertEqual(episode['duration_seconds'], 100)
        self.assertFalse(episode['open'])

    def test_down_alone_returns_open_episode_with_no_synthesized_end(self):
        rows = [_row(1, 100, online=0)]
        episodes = beacon_incidents.group_episodes(rows)
        self.assertEqual(len(episodes), 1)
        episode = episodes[0]
        self.assertTrue(episode['open'])
        self.assertIsNone(episode['recovered_ts'])
        self.assertIsNone(episode['duration_seconds'])

    def test_down_since_ts_used_as_true_down_ts(self):
        rows = [
            _row(1, 100, online=0, down_since_ts=60),
            _row(2, 200, online=1),
        ]
        episodes = beacon_incidents.group_episodes(rows)
        self.assertEqual(len(episodes), 1)
        episode = episodes[0]
        self.assertEqual(episode['down_ts'], 60)
        self.assertEqual(episode['raised_ts'], 100)

    def test_up_with_no_preceding_down_emits_no_episode(self):
        rows = [_row(1, 200, online=1)]
        episodes = beacon_incidents.group_episodes(rows)
        self.assertEqual(episodes, [])

    def test_open_episode_never_produces_synthesized_duration(self):
        # No test fixture can produce a duration equal to end_ts - down_ts
        # for an open episode -- there is no end_ts anywhere in this call.
        rows = [_row(1, 100, online=0)]
        episodes = beacon_incidents.group_episodes(rows)
        self.assertIsNone(episodes[0]['duration_seconds'])

    def test_non_state_change_rows_never_participate_in_grouping(self):
        rows = [
            _row(1, 100, online=0),
            _row(2, 150, online=None, event_type='alert_sent'),
            _row(3, 200, online=1),
        ]
        episodes = beacon_incidents.group_episodes(rows)
        self.assertEqual(len(episodes), 1)
        self.assertEqual(episodes[0]['recovered_ts'], 200)


class SplitOverrunSpanTests(unittest.TestCase):
    def test_overrun_span_splits_at_grace_expiry(self):
        result = beacon_incidents.split_overrun_span(down_ts=100, recovered_ts=400, grace_until=300)
        self.assertEqual(result, {'overrun': True, 'grace_seconds': 200, 'fault_seconds': 100})

    def test_span_fully_inside_grace_is_not_overrun(self):
        result = beacon_incidents.split_overrun_span(down_ts=100, recovered_ts=250, grace_until=300)
        self.assertEqual(result, {'overrun': False, 'grace_seconds': 150, 'fault_seconds': 0})

    def test_open_span_measures_nothing(self):
        result = beacon_incidents.split_overrun_span(down_ts=100, recovered_ts=None, grace_until=300)
        self.assertFalse(result['overrun'])
        self.assertIsNone(result['grace_seconds'])
        self.assertIsNone(result['fault_seconds'])

    def test_no_grace_until_whole_span_is_fault(self):
        result = beacon_incidents.split_overrun_span(down_ts=100, recovered_ts=220, grace_until=None)
        self.assertEqual(result, {'overrun': False, 'grace_seconds': 0, 'fault_seconds': 120})


class ClassifyFlappingTests(unittest.TestCase):
    def _episode(self, port, down_ts):
        return {
            'port': port, 'down_ts': down_ts, 'recovered_ts': down_ts + 10,
            'open': False, 'duration_seconds': 10, 'transitions': [{'id': down_ts}],
        }

    def test_three_or_more_dense_episodes_share_one_group_id(self):
        episodes = [self._episode(80, ts) for ts in (0, 300, 600)]
        groups = beacon_incidents.classify_flapping(episodes)
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(group['port'], 80)
        self.assertEqual(group['count'], 3)
        self.assertEqual(group['span_seconds'], 600)
        for episode in episodes:
            self.assertEqual(episode['flapping_group_id'], group['id'])

    def test_two_dense_episodes_get_no_group(self):
        episodes = [self._episode(80, ts) for ts in (0, 300)]
        groups = beacon_incidents.classify_flapping(episodes)
        self.assertEqual(groups, [])
        for episode in episodes:
            self.assertIsNone(episode['flapping_group_id'])


class ReadEventsInRangeTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.now = int(time.time())

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_event(self, ts, *, port=80, event_type='state_change', online=None,
                       error_class=None, suppressed_reason=None,
                       maintenance_grace_until=None, down_since_ts=None):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    "INSERT INTO events(ts, port, event_type, online, previous_online, "
                    "latency_ms, error_class, alert_status, details, suppressed_reason, "
                    "maintenance_grace_until, down_since_ts) "
                    "VALUES (?,?,?,?,NULL,NULL,?,NULL,NULL,?,?,?)",
                    (ts, port, event_type, online, error_class, suppressed_reason,
                     maintenance_grace_until, down_since_ts),
                )
                conn.commit()
            finally:
                conn.close()

    def test_half_open_bounds_include_start_exclude_end(self):
        self._insert_event(self.now, online=0)
        self._insert_event(self.now + 100, online=1)
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                rows, truncated = beacon_incidents.read_events_in_range(
                    conn, start_ts=self.now, end_ts=self.now + 100,
                )
            finally:
                conn.close()
        self.assertFalse(truncated)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['ts'], self.now)

    def test_invalid_event_type_raises(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                with self.assertRaises(ValueError):
                    beacon_incidents.read_events_in_range(
                        conn, start_ts=self.now, end_ts=self.now + 10, event_type='nonsense',
                    )
            finally:
                conn.close()

    def test_invalid_criticality_raises(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                with self.assertRaises(ValueError):
                    beacon_incidents.read_events_in_range(
                        conn, start_ts=self.now, end_ts=self.now + 10, criticality='nonsense',
                    )
            finally:
                conn.close()

    def test_invalid_port_raises(self):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                with self.assertRaises(ValueError):
                    beacon_incidents.read_events_in_range(
                        conn, start_ts=self.now, end_ts=self.now + 10, port=0,
                    )
                with self.assertRaises(ValueError):
                    beacon_incidents.read_events_in_range(
                        conn, start_ts=self.now, end_ts=self.now + 10, port=70000,
                    )
            finally:
                conn.close()

    def test_no_filter_value_is_interpolated_into_sql_text(self):
        import re
        with open('dashboard/beacon/incidents.py') as handle:
            source = handle.read()
        self.assertIsNone(re.search(r'f"SELECT|f\'SELECT', source))


class EventsHistoryRouteTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()
        self.client = self.appmod.app.test_client()
        self.now = int(time.time())

    def tearDown(self):
        cleanup_db(self.db_path)

    def _insert_event(self, ts, *, port=80, event_type='state_change', online=None,
                       error_class=None, suppressed_reason=None,
                       maintenance_grace_until=None, down_since_ts=None):
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            try:
                conn.execute(
                    "INSERT INTO events(ts, port, event_type, online, previous_online, "
                    "latency_ms, error_class, alert_status, details, suppressed_reason, "
                    "maintenance_grace_until, down_since_ts) "
                    "VALUES (?,?,?,?,NULL,NULL,?,NULL,NULL,?,?,?)",
                    (ts, port, event_type, online, error_class, suppressed_reason,
                     maintenance_grace_until, down_since_ts),
                )
                conn.commit()
            finally:
                conn.close()

    def _get(self, **params):
        query = {'start_ts': str(self.now - 1000), 'end_ts': str(self.now)}
        query.update({key: str(value) for key, value in params.items()})
        return self.client.get('/api/events/history', query_string=query)

    def test_response_shape(self):
        response = self._get()
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        for key in ('requested', 'filters', 'episodes', 'events', 'flapping_groups',
                    'row_budget', 'truncated', 'matched_count'):
            self.assertIn(key, payload)

    def test_db_lock_used(self):
        import inspect
        source = inspect.getsource(self.appmod.api_events_history)
        self.assertIn('with _db_lock, database_access(DB_PATH) as conn:', source)

    def test_closed_episode(self):
        self._insert_event(self.now - 500, port=81, online=0)
        self._insert_event(self.now - 400, port=81, online=1)
        payload = self._get().get_json()
        episodes = [e for e in payload['episodes'] if e['port'] == 81]
        self.assertEqual(len(episodes), 1)
        self.assertFalse(episodes[0]['open'])
        self.assertEqual(episodes[0]['duration_seconds'], 100)

    def test_open_episode(self):
        self._insert_event(self.now - 500, port=82, online=0)
        payload = self._get().get_json()
        episodes = [e for e in payload['episodes'] if e['port'] == 82]
        self.assertEqual(len(episodes), 1)
        self.assertTrue(episodes[0]['open'])
        self.assertIsNone(episodes[0]['recovered_ts'])
        self.assertIsNone(episodes[0]['duration_seconds'])

    def test_overrun_episode_splits_grace_and_fault(self):
        down_since = self.now - 800
        raised_ts = self.now - 700
        grace_until = self.now - 650
        recovered_ts = self.now - 600
        self._insert_event(
            raised_ts, port=83, online=0, down_since_ts=down_since,
            maintenance_grace_until=grace_until,
        )
        self._insert_event(recovered_ts, port=83, online=1)
        payload = self._get().get_json()
        episodes = [e for e in payload['episodes'] if e['port'] == 83]
        self.assertEqual(len(episodes), 1)
        episode = episodes[0]
        self.assertEqual(episode['grace_seconds'] + episode['fault_seconds'], recovered_ts - down_since)

    def test_maintenance_suppressed_row_present_by_default_and_excludable(self):
        self._insert_event(self.now - 500, port=84, online=0, suppressed_reason='maintenance')
        self._insert_event(self.now - 400, port=84, online=1)
        default_payload = self._get().get_json()
        self.assertTrue(any(e['ts'] == self.now - 500 for e in default_payload['events']))
        excluded_payload = self._get(maintenance='exclude').get_json()
        self.assertFalse(any(e['ts'] == self.now - 500 for e in excluded_payload['events']))

    def test_invalid_event_type_returns_400_naming_parameter(self):
        response = self._get(event_type='nonsense')
        self.assertEqual(response.status_code, 400)
        self.assertIn('event_type', response.get_json()['error'])

    def test_invalid_criticality_returns_400_naming_parameter(self):
        response = self._get(criticality='nonsense')
        self.assertEqual(response.status_code, 400)
        self.assertIn('criticality', response.get_json()['error'])

    def test_invalid_port_zero_returns_400(self):
        response = self._get(port='0')
        self.assertEqual(response.status_code, 400)
        self.assertIn('port', response.get_json()['error'])

    def test_invalid_port_too_large_returns_400(self):
        response = self._get(port='70000')
        self.assertEqual(response.status_code, 400)
        self.assertIn('port', response.get_json()['error'])

    def test_repeated_start_ts_returns_400(self):
        response = self.client.get('/api/events/history', query_string=[
            ('start_ts', str(self.now - 1000)),
            ('start_ts', str(self.now - 500)),
            ('end_ts', str(self.now)),
        ])
        self.assertEqual(response.status_code, 400)
        self.assertIn('start_ts', response.get_json()['error'])


if __name__ == '__main__':
    unittest.main()
