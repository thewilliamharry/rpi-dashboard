import concurrent.futures
import sqlite3
import unittest

from dashboard.beacon import queues
from tests.helpers import cleanup_db, load_app


class DurableQueueTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()

    def tearDown(self):
        cleanup_db(self.db_path)

    def test_scan_submissions_coalesce_with_a_fifteen_minute_deadline(self):
        first = queues.enqueue_scan(self.db_path, 'operator-a', now=1_000)
        second = queues.enqueue_scan(self.db_path, 'operator-b', now=1_001)

        self.assertFalse(first.coalesced)
        self.assertTrue(second.coalesced)
        self.assertEqual(second.request_id, first.request_id)
        self.assertEqual(first.deadline_ts, 1_900)

    def test_competing_workers_claim_one_scan_and_stale_owner_cannot_finish(self):
        request = queues.enqueue_scan(self.db_path, 'operator', now=1_000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(executor.map(
                lambda worker: queues.claim_scan(self.db_path, worker, now=1_001, lease_seconds=1),
                ('worker-a', 'worker-b'),
            ))
        claimed = [claim for claim in claims if claim]
        self.assertEqual(len(claimed), 1)
        first = claimed[0]

        queues.recover_queues(self.db_path, now=1_003)
        successor = queues.claim_scan(self.db_path, 'worker-c', now=1_003, lease_seconds=30)
        self.assertEqual(successor.request_id, request.request_id)
        with self.assertRaises(queues.LeaseLost):
            queues.finish_scan(self.db_path, first.request_id, first.lease_owner, now=1_004)

    def test_long_scan_heartbeat_renews_before_expiry_and_completes(self):
        clock = {'now': 1_000}
        events = []
        heartbeats = []
        queues.enqueue_scan(self.db_path, 'operator', now=clock['now'])

        class FakeHeartbeat:
            def __init__(self, db_path, request_id, owner_token, **kwargs):
                self.db_path = db_path
                self.request_id = request_id
                self.owner_token = owner_token
                self.lost = False
                heartbeats.append(self)

            def start(self):
                events.append('heartbeat-started')

            def renew_at(self, now):
                queues.renew_scan_lease(
                    self.db_path, self.request_id, self.owner_token,
                    now=now, lease_seconds=30,
                )
                events.append(('renewed', now))

            def stop(self):
                events.append('heartbeat-stopped')

        def controlled_discovery(source):
            self.assertEqual(events, ['heartbeat-started'])
            for now in (1_020, 1_040, 1_060):
                heartbeats[0].renew_at(now)
            clock['now'] = 1_061
            return 'completed'

        self.appmod.run_discovery = controlled_discovery
        self.assertTrue(self.appmod.process_scan_requests(
            'worker-a', now_fn=lambda: clock['now'], lease_seconds=30,
            heartbeat_factory=FakeHeartbeat,
        ))

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT status, completed_ts, lease_owner, lease_until FROM scan_requests'
            ).fetchone()
        self.assertEqual(row, ('completed', 1_061, None, None))
        self.assertEqual(
            events,
            ['heartbeat-started', ('renewed', 1_020), ('renewed', 1_040),
             ('renewed', 1_060), 'heartbeat-stopped'],
        )

    def test_lost_ownership_suppresses_late_terminal_writes(self):
        clock = {'now': 1_000}
        terminal_calls = []
        queues.enqueue_scan(self.db_path, 'operator', now=clock['now'])

        class FakeHeartbeat:
            def __init__(self, db_path, request_id, owner_token, **kwargs):
                self.db_path = db_path
                self.request_id = request_id
                self.owner_token = owner_token
                self.lost = False

            def start(self):
                return None

            def stop(self):
                return None

        heartbeat = None

        def factory(*args, **kwargs):
            nonlocal heartbeat
            heartbeat = FakeHeartbeat(*args, **kwargs)
            return heartbeat

        def controlled_discovery(source):
            clock['now'] = 1_031
            queues.recover_queues(self.db_path, now=clock['now'])
            successor = queues.claim_scan(
                self.db_path, 'worker-b', now=clock['now'], lease_seconds=30,
            )
            self.assertIsNotNone(successor)
            with self.assertRaises(queues.LeaseLost):
                queues.renew_scan_lease(
                    self.db_path, heartbeat.request_id, heartbeat.owner_token,
                    now=clock['now'], lease_seconds=30,
                )
            heartbeat.lost = True
            return 'completed'

        self.appmod.run_discovery = controlled_discovery
        original_finish = queues.finish_scan
        original_fail = queues.fail_scan
        try:
            queues.finish_scan = lambda *args, **kwargs: terminal_calls.append('finish')
            queues.fail_scan = lambda *args, **kwargs: terminal_calls.append('fail')
            self.assertFalse(self.appmod.process_scan_requests(
                'worker-a', now_fn=lambda: clock['now'], lease_seconds=30,
                heartbeat_factory=factory,
            ))
        finally:
            queues.finish_scan = original_finish
            queues.fail_scan = original_fail

        self.assertEqual(terminal_calls, [])
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute('SELECT status FROM scan_requests').fetchone()
        self.assertEqual(row, ('running',))

    def test_recovery_expires_old_running_scans_without_replaying_them(self):
        request = queues.enqueue_scan(self.db_path, 'operator', now=1_000)
        queues.claim_scan(self.db_path, 'worker-a', now=1_001, lease_seconds=1)

        queues.recover_queues(self.db_path, now=1_901)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT status, terminal_ts FROM scan_requests WHERE id=?',
                (request.request_id,),
            ).fetchone()
        self.assertEqual(row, ('expired', 1_901))

    def test_metadata_save_enqueues_latest_preview_without_a_worker(self):
        now = 1_000
        with self.appmod._db_lock:
            conn = self.appmod.get_db()
            conn.execute(
                "INSERT INTO services(port, title, first_seen, last_seen, is_online) VALUES(?,?,?,?,?)",
                (8080, 'Demo', now, now, 1),
            )
            conn.commit()
            conn.close()

        response = self.appmod.app.test_client().put(
            '/api/service-meta/8080',
            json={'display_name': 'Saved during outage', 'url': 'http://127.0.0.1:8080'},
            headers={'X-Beacon-UI': '1'},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['preview_queued'])
        self.assertEqual(payload['preview_revision'], 1)
        self.assertIn('preview_deadline_ts', payload)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT status, revision, deadline_ts - requested_ts FROM preview_requests WHERE port=8080'
            ).fetchone()
        self.assertEqual(row, ('queued', 1, 1_800))

    def test_newer_preview_supersedes_older_work_and_blocks_stale_finish(self):
        first = queues.enqueue_preview(self.db_path, 8080, now=1_000)
        claimed = queues.claim_preview(self.db_path, 'worker-a', now=1_001, lease_seconds=30)
        second = queues.enqueue_preview(self.db_path, 8080, now=1_002)

        self.assertEqual(second.revision, first.revision + 1)
        with self.assertRaises(queues.LeaseLost):
            queues.finish_preview(
                self.db_path, claimed.request_id, 'worker-a', revision=claimed.revision,
                now=1_003,
            )

        latest = queues.claim_preview(self.db_path, 'worker-b', now=1_003, lease_seconds=30)
        self.assertEqual(latest.revision, second.revision)


if __name__ == '__main__':
    unittest.main()
