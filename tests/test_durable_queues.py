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

        successor = queues.claim_scan(self.db_path, 'worker-c', now=1_003, lease_seconds=30)
        self.assertEqual(successor.request_id, request.request_id)
        with self.assertRaises(queues.LeaseLost):
            queues.finish_scan(self.db_path, first.request_id, first.lease_owner, now=1_004)

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


if __name__ == '__main__':
    unittest.main()
