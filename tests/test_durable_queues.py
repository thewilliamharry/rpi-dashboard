import concurrent.futures
import sqlite3
import unittest

from dashboard.beacon import queues
from dashboard.beacon.config import load_settings
from dashboard.beacon.worker_authority import WorkerAuthority
from tests.helpers import cleanup_db, load_app


class DurableQueueTests(unittest.TestCase):
    def setUp(self):
        self.appmod, self.db_path = load_app()

    def tearDown(self):
        cleanup_db(self.db_path)

    def _acquire_owner(self, worker_id, now, lease_seconds=15):
        return queues.acquire_worker_lease(
            self.db_path, worker_id, now=now, lease_seconds=lease_seconds,
        )

    def _authority(self, lease, now):
        return WorkerAuthority.from_lease(
            lease, self.db_path, clock=lambda: now,
        )

    def test_worker_authority_requires_the_exact_acquired_epoch_in_transaction(self):
        lease = self._acquire_owner('worker-a', 1_000, lease_seconds=30)
        authority = self._authority(lease, 1_001)
        with queues._connect(self.db_path) as conn:
            conn.execute('BEGIN IMMEDIATE')
            queues.assert_current_worker_authority(conn, authority)
            conn.rollback()

        successor = self._acquire_owner('worker-a', 1_031, lease_seconds=30)
        with queues._connect(self.db_path) as conn:
            conn.execute('BEGIN IMMEDIATE')
            with self.assertRaises(queues.LeaseLost):
                queues.assert_current_worker_authority(conn, authority, now=1_031)
            conn.rollback()
        self.assertNotEqual(lease.owner_token, successor.owner_token)

    def test_web_owner_free_scan_submissions_coalesce_with_a_fifteen_minute_deadline(self):
        first = queues.enqueue_scan(self.db_path, 'operator-a', now=1_000)
        second = queues.enqueue_scan(self.db_path, 'operator-b', now=1_001)

        self.assertFalse(first.coalesced)
        self.assertTrue(second.coalesced)
        self.assertEqual(second.request_id, first.request_id)
        self.assertEqual(first.deadline_ts, 1_900)

    def test_owner_claims_one_scan_and_stale_row_owner_cannot_finish(self):
        request = queues.enqueue_scan(self.db_path, 'operator', now=1_000)
        owner_a = self._acquire_owner('worker-a', 1_001, lease_seconds=1)
        first = queues.claim_scan(
            self.db_path, 'worker-a', worker_owner_token=owner_a.owner_token,
            now=1_001, lease_seconds=1,
        )

        queues.recover_queues(self.db_path, now=1_003)
        owner_c = self._acquire_owner('worker-c', 1_003, lease_seconds=30)
        successor = queues.claim_scan(
            self.db_path, 'worker-c', worker_owner_token=owner_c.owner_token,
            now=1_003, lease_seconds=30,
        )
        self.assertEqual(successor.request_id, request.request_id)
        with self.assertRaises(queues.LeaseLost):
            queues.finish_scan(
                self.db_path, first.request_id, first.lease_owner, worker_id='worker-a',
                worker_owner_token=owner_a.owner_token, now=1_004,
            )

    def test_long_scan_heartbeat_renews_before_expiry_and_completes(self):
        clock = {'now': 1_000}
        events = []
        heartbeats = []
        queues.enqueue_scan(self.db_path, 'operator', now=clock['now'])
        owner = self._acquire_owner('worker-a', clock['now'], lease_seconds=30)

        class FakeHeartbeat:
            def __init__(self, db_path, request_id, owner_token, worker_id, worker_owner_token, **kwargs):
                self.db_path = db_path
                self.request_id = request_id
                self.owner_token = owner_token
                self.worker_id = worker_id
                self.worker_owner_token = worker_owner_token
                self.lost = False
                heartbeats.append(self)

            def start(self):
                events.append('heartbeat-started')

            def renew_at(self, now):
                queues.renew_scan_lease(
                    self.db_path, self.request_id, self.owner_token,
                    worker_id=self.worker_id, worker_owner_token=self.worker_owner_token,
                    now=now, lease_seconds=30,
                )
                queues.renew_worker_lease(
                    self.db_path, self.worker_id, self.worker_owner_token,
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
            'worker-a', owner.owner_token, now_fn=lambda: clock['now'], lease_seconds=30,
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
        owner_a = self._acquire_owner('worker-a', clock['now'], lease_seconds=30)

        class FakeHeartbeat:
            def __init__(self, db_path, request_id, owner_token, worker_id, worker_owner_token, **kwargs):
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
                self.db_path, 'worker-b',
                worker_owner_token=self._acquire_owner('worker-b', clock['now']).owner_token,
                now=clock['now'], lease_seconds=30,
            )
            self.assertIsNotNone(successor)
            with self.assertRaises(queues.LeaseLost):
                queues.renew_scan_lease(
                    self.db_path, heartbeat.request_id, heartbeat.owner_token,
                    worker_id='worker-a', worker_owner_token=owner_a.owner_token,
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
                'worker-a', owner_a.owner_token, now_fn=lambda: clock['now'], lease_seconds=30,
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
        owner = self._acquire_owner('worker-a', 1_001, lease_seconds=1)
        queues.claim_scan(
            self.db_path, 'worker-a', worker_owner_token=owner.owner_token,
            now=1_001, lease_seconds=1,
        )

        queues.recover_queues(self.db_path, now=1_901)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT status, terminal_ts FROM scan_requests WHERE id=?',
                (request.request_id,),
            ).fetchone()
        self.assertEqual(row, ('expired', 1_901))

    def test_claim_recovers_expired_running_scan_and_takes_it_over_same_poll(self):
        request = queues.enqueue_scan(self.db_path, 'operator', now=0)
        owner_a = self._acquire_owner('worker-a', 0, lease_seconds=30)
        first = queues.claim_scan(
            self.db_path, 'worker-a', worker_owner_token=owner_a.owner_token,
            now=0, lease_seconds=30,
        )

        owner_b = self._acquire_owner('worker-b', 31, lease_seconds=30)
        successor = queues.claim_scan(
            self.db_path, 'worker-b', worker_owner_token=owner_b.owner_token,
            now=31, lease_seconds=30,
        )

        self.assertEqual(successor.request_id, request.request_id)
        self.assertNotEqual(successor.lease_owner, first.lease_owner)
        self.assertEqual(successor.status, 'running')

    def test_claim_expires_past_deadline_running_scan_instead_of_reclaiming_it(self):
        request = queues.enqueue_scan(self.db_path, 'operator', now=0)
        owner = self._acquire_owner('worker-a', 0, lease_seconds=30)
        queues.claim_scan(
            self.db_path, 'worker-a', worker_owner_token=owner.owner_token,
            now=0, lease_seconds=30,
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('UPDATE scan_requests SET deadline_ts=31 WHERE id=?', (request.request_id,))
            conn.commit()

        owner_b = self._acquire_owner('worker-b', 31, lease_seconds=30)
        self.assertIsNone(queues.claim_scan(
            self.db_path, 'worker-b', worker_owner_token=owner_b.owner_token,
            now=31, lease_seconds=30,
        ))

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT status, terminal_ts, lease_owner, lease_until FROM scan_requests WHERE id=?',
                (request.request_id,),
            ).fetchone()
        self.assertEqual(row, ('expired', 31, None, None))

    def test_scan_takeover_fencing_allows_only_current_token_terminal_write(self):
        queues.enqueue_scan(self.db_path, 'operator', now=0)
        owner_a = self._acquire_owner('worker-a', 0, lease_seconds=30)
        first = queues.claim_scan(self.db_path, 'worker-a', worker_owner_token=owner_a.owner_token, now=0, lease_seconds=30)
        owner_b = self._acquire_owner('worker-b', 31, lease_seconds=30)
        successor = queues.claim_scan(self.db_path, 'worker-b', worker_owner_token=owner_b.owner_token, now=31, lease_seconds=30)

        for operation in (
            lambda: queues.renew_scan_lease(
                self.db_path, first.request_id, first.lease_owner, worker_id='worker-a', worker_owner_token=owner_a.owner_token, now=31, lease_seconds=30,
            ),
            lambda: queues.finish_scan(
                self.db_path, first.request_id, first.lease_owner, worker_id='worker-a', worker_owner_token=owner_a.owner_token, now=31,
            ),
            lambda: queues.fail_scan(
                self.db_path, first.request_id, first.lease_owner, 'late', worker_id='worker-a', worker_owner_token=owner_a.owner_token, now=31,
            ),
        ):
            with self.assertRaises(queues.LeaseLost):
                operation()

        queues.finish_scan(self.db_path, successor.request_id, successor.lease_owner, worker_id='worker-b', worker_owner_token=owner_b.owner_token, now=32)
        with self.assertRaises(queues.LeaseLost):
            queues.fail_scan(
                self.db_path, successor.request_id, successor.lease_owner, 'late', worker_id='worker-b', worker_owner_token=owner_b.owner_token, now=32,
            )

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute('SELECT status, error FROM scan_requests').fetchone()
        self.assertEqual(row, ('completed', None))

    def test_web_owner_free_metadata_save_enqueues_latest_preview_without_a_worker(self):
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
        owner_a = self._acquire_owner('worker-a', 1_001, lease_seconds=30)
        claimed = queues.claim_preview(self.db_path, 'worker-a', worker_owner_token=owner_a.owner_token, now=1_001, lease_seconds=30)
        second = queues.enqueue_preview(self.db_path, 8080, now=1_002)

        self.assertEqual(second.revision, first.revision + 1)
        with self.assertRaises(queues.LeaseLost):
            queues.finish_preview(
                self.db_path, claimed.request_id, 'worker-a', worker_owner_token=owner_a.owner_token, revision=claimed.revision,
                now=1_003,
            )

        queues.release_worker_lease(self.db_path, 'worker-a', owner_a.owner_token, now=1_003)
        owner_b = self._acquire_owner('worker-b', 1_003, lease_seconds=30)
        latest = queues.claim_preview(self.db_path, 'worker-b', worker_owner_token=owner_b.owner_token, now=1_003, lease_seconds=30)
        self.assertEqual(latest.revision, second.revision)

    def _owner_takeover(self):
        return queues.acquire_worker_lease(
            self.db_path, 'worker-b', now=16, lease_seconds=15,
        )

    def _scan_snapshot(self, request_id):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                'SELECT status, started_ts, completed_ts, terminal_ts, lease_owner, '
                'lease_until, attempt_count, error, result FROM scan_requests WHERE id=?',
                (request_id,),
            ).fetchone()

    def test_stale_worker_takeover_rejects_every_scan_mutation_without_writes(self):
        operations = (
            lambda request, owner: queues.claim_scan(
                self.db_path, owner.worker_id, worker_owner_token=owner.owner_token,
                now=16, lease_seconds=60,
            ),
            lambda request, owner: queues.renew_scan_lease(
                self.db_path, request.request_id, request.lease_owner,
                worker_id=owner.worker_id, worker_owner_token=owner.owner_token,
                now=16, lease_seconds=60,
            ),
            lambda request, owner: queues.requeue_scan(
                self.db_path, request.request_id, request.lease_owner,
                worker_id=owner.worker_id, worker_owner_token=owner.owner_token, now=16,
            ),
            lambda request, owner: queues.finish_scan(
                self.db_path, request.request_id, request.lease_owner,
                worker_id=owner.worker_id, worker_owner_token=owner.owner_token, now=16,
            ),
            lambda request, owner: queues.fail_scan(
                self.db_path, request.request_id, request.lease_owner, 'late',
                worker_id=owner.worker_id, worker_owner_token=owner.owner_token, now=16,
            ),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                cleanup_db(self.db_path)
                self.appmod, self.db_path = load_app()
                owner_a = queues.acquire_worker_lease(
                    self.db_path, 'worker-a', now=0, lease_seconds=15,
                )
                request = queues.enqueue_scan(self.db_path, 'operator', now=0)
                claim = queues.claim_scan(
                    self.db_path, owner_a.worker_id,
                    worker_owner_token=owner_a.owner_token, now=0, lease_seconds=60,
                )
                self.assertEqual(claim.request_id, request.request_id)
                self._owner_takeover()
                snapshot = self._scan_snapshot(request.request_id)
                with self.assertRaises(queues.LeaseLost):
                    operation(claim, owner_a)
                self.assertEqual(self._scan_snapshot(request.request_id), snapshot)

    def test_worker_owner_epoch_rotates_for_same_id_and_rejects_earlier_epoch(self):
        first = queues.acquire_worker_lease(
            self.db_path, 'worker-a', now=0, lease_seconds=15,
        )
        second = queues.acquire_worker_lease(
            self.db_path, 'worker-a', now=16, lease_seconds=15,
        )
        self.assertNotEqual(first.owner_token, second.owner_token)
        queues.enqueue_scan(self.db_path, 'operator', now=16)
        with self.assertRaises(queues.LeaseLost):
            queues.claim_scan(
                self.db_path, 'worker-a', worker_owner_token=first.owner_token,
                now=16,
            )
        self.assertIsNotNone(queues.claim_scan(
            self.db_path, 'worker-a', worker_owner_token=second.owner_token, now=16,
        ))

    def test_stale_worker_takeover_rejects_every_preview_result_write(self):
        operations = ('claim', 'renew', 'finish', 'fail', 'transaction')
        for operation in operations:
            with self.subTest(operation=operation):
                cleanup_db(self.db_path)
                self.appmod, self.db_path = load_app()
                owner_a = queues.acquire_worker_lease(
                    self.db_path, 'worker-a', now=0, lease_seconds=15,
                )
                request = queues.enqueue_preview(self.db_path, 8080, now=0)
                claim = queues.claim_preview(
                    self.db_path, owner_a.worker_id,
                    worker_owner_token=owner_a.owner_token, now=0, lease_seconds=60,
                )
                self.assertEqual(claim.request_id, request.request_id)
                self._owner_takeover()
                with sqlite3.connect(self.db_path) as conn:
                    before = conn.execute(
                        'SELECT status, completed_ts, terminal_ts, lease_owner, lease_until, '
                        'attempt_count, error, result FROM preview_requests WHERE id=?',
                        (request.request_id,),
                    ).fetchone()
                    if operation == 'claim':
                        with self.assertRaises(queues.LeaseLost):
                            queues.claim_preview(
                                self.db_path, owner_a.worker_id,
                                worker_owner_token=owner_a.owner_token, now=16,
                            )
                    elif operation == 'renew':
                        with self.assertRaises(queues.LeaseLost):
                            queues.renew_preview_lease(
                                self.db_path, request.request_id, owner_a.worker_id,
                                worker_owner_token=owner_a.owner_token,
                                revision=claim.revision, now=16,
                            )
                    elif operation == 'finish':
                        with self.assertRaises(queues.LeaseLost):
                            queues.finish_preview(
                                self.db_path, request.request_id, owner_a.worker_id,
                                worker_owner_token=owner_a.owner_token,
                                revision=claim.revision, now=16,
                            )
                    elif operation == 'fail':
                        with self.assertRaises(queues.LeaseLost):
                            queues.fail_preview(
                                self.db_path, request.request_id, owner_a.worker_id, 'late',
                                worker_owner_token=owner_a.owner_token,
                                revision=claim.revision, now=16,
                            )
                    else:
                        conn.row_factory = sqlite3.Row
                        conn.execute('BEGIN IMMEDIATE')
                        with self.assertRaises(queues.LeaseLost):
                            queues.finish_preview_in_transaction(
                                conn, request.request_id, owner_a.worker_id,
                                worker_owner_token=owner_a.owner_token,
                                revision=claim.revision, now=16,
                            )
                        conn.rollback()
                    after = tuple(conn.execute(
                        'SELECT status, completed_ts, terminal_ts, lease_owner, lease_until, '
                        'attempt_count, error, result FROM preview_requests WHERE id=?',
                        (request.request_id,),
                    ).fetchone())
                self.assertEqual(after, before)

    def test_preview_retry_decision_is_bounded_and_capped(self):
        # Pure function, no DB access -- doubling with a cap, terminal at
        # attempt_count >= max_attempts.
        self.assertEqual(
            queues.preview_retry_decision(1, max_attempts=3, base_seconds=60, max_seconds=600), 60,
        )
        self.assertEqual(
            queues.preview_retry_decision(2, max_attempts=3, base_seconds=60, max_seconds=600), 120,
        )
        self.assertIsNone(
            queues.preview_retry_decision(3, max_attempts=3, base_seconds=60, max_seconds=600),
        )
        self.assertIsNone(
            queues.preview_retry_decision(4, max_attempts=3, base_seconds=60, max_seconds=600),
        )
        # Never exceeds max_seconds even when the doubling curve would.
        self.assertEqual(
            queues.preview_retry_decision(5, max_attempts=10, base_seconds=60, max_seconds=600), 600,
        )

        # A non-positive or unparseable PREVIEW_MAX_ATTEMPTS / _BASE_SECONDS /
        # _MAX_SECONDS falls back to the documented default (3 / 60 / 600).
        self.assertEqual(load_settings({'PREVIEW_MAX_ATTEMPTS': '0'}).preview_max_attempts, 3)
        self.assertEqual(load_settings({'PREVIEW_MAX_ATTEMPTS': 'abc'}).preview_max_attempts, 3)
        self.assertEqual(
            load_settings({'PREVIEW_RETRY_BASE_SECONDS': '0'}).preview_retry_base_seconds, 60,
        )
        self.assertEqual(
            load_settings({'PREVIEW_RETRY_MAX_SECONDS': 'abc'}).preview_retry_max_seconds, 600,
        )

    def test_preview_retry_reschedules_with_backoff_and_is_not_claimable_early(self):
        request = queues.enqueue_preview(self.db_path, 8080, now=1_000)
        owner_a = self._acquire_owner('worker-a', 1_001, lease_seconds=120)
        claimed = queues.claim_preview(
            self.db_path, 'worker-a', worker_owner_token=owner_a.owner_token,
            now=1_001, lease_seconds=60,
        )
        self.assertEqual(claimed.request_id, request.request_id)
        self.assertEqual(claimed.attempt_count, 1)

        with queues._connect(self.db_path) as conn:
            conn.execute('BEGIN IMMEDIATE')
            queues.schedule_preview_retry_in_transaction(
                conn, claimed.request_id, 'worker-a', worker_owner_token=owner_a.owner_token,
                revision=claimed.revision, error='capture failed', backoff_seconds=60, now=1_001,
            )
            conn.commit()

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT status, next_attempt_ts, lease_owner, lease_until, started_ts, error, '
                'attempt_count FROM preview_requests WHERE id=?', (claimed.request_id,),
            ).fetchone()
        self.assertEqual(row, ('queued', 1_061, None, None, None, 'capture failed', 1))

        # A retry-pending row is not claimable before its backoff elapses...
        self.assertIsNone(queues.claim_preview(
            self.db_path, 'worker-a', worker_owner_token=owner_a.owner_token, now=1_060,
        ))
        # ...and is claimable exactly once `now` reaches next_attempt_ts, with
        # the post-increment attempt_count carried on the new claim.
        retried = queues.claim_preview(
            self.db_path, 'worker-a', worker_owner_token=owner_a.owner_token, now=1_061,
        )
        self.assertIsNotNone(retried)
        self.assertEqual(retried.request_id, claimed.request_id)
        self.assertEqual(retried.attempt_count, 2)

        # schedule_preview_retry_in_transaction raises LeaseLost under exactly
        # the conditions finish_preview_in_transaction does: here, a revision
        # that has since been superseded by a newer request for the same port.
        queues.enqueue_preview(self.db_path, 8080, now=1_062)
        with queues._connect(self.db_path) as conn:
            conn.execute('BEGIN IMMEDIATE')
            with self.assertRaises(queues.LeaseLost):
                queues.schedule_preview_retry_in_transaction(
                    conn, retried.request_id, 'worker-a', worker_owner_token=owner_a.owner_token,
                    revision=retried.revision, error='capture failed', backoff_seconds=60, now=1_063,
                )
            conn.rollback()


if __name__ == '__main__':
    unittest.main()
