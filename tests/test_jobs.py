import random
import unittest
from datetime import datetime, timedelta, timezone

from incogni.crypto import EnvelopeCrypto
from incogni.jobs import DurableJobQueue, operation_idempotency_key
from incogni.models import JobStatus
from incogni.storage import ServiceStore


class Clock:
    def __init__(self):
        self.now = datetime(2026, 8, 26, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


class DurableJobQueueTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.store = ServiceStore(":memory:", EnvelopeCrypto({"test": b"k" * 32}, "test"))
        self.queue = DurableJobQueue(
            self.store, clock=self.clock, random_source=random.Random(0)
        )

    def tearDown(self):
        self.store.close()

    def test_operation_idempotency_uses_every_required_dimension(self):
        base = operation_idempotency_key(
            "profile", "broker", "listing", "flow-1", "submit"
        )
        self.assertEqual(
            base,
            operation_idempotency_key(
                "profile", "broker", "listing", "flow-1", "submit"
            ),
        )
        self.assertNotEqual(
            base,
            operation_idempotency_key(
                "profile", "broker", "listing", "flow-2", "submit"
            ),
        )
        with self.assertRaises(ValueError):
            operation_idempotency_key("", "broker", "listing", "flow", "submit")

    def test_enqueue_is_idempotent_and_payload_encrypted(self):
        first = self.queue.enqueue(
            "scan", {"secret": "synthetic"}, idempotency_key="scan:1",
            profile_id="owner", broker_id="broker",
        )
        second = self.queue.enqueue(
            "scan", {"secret": "other"}, idempotency_key="scan:1"
        )
        self.assertEqual(first, second)
        raw = self.store.conn.execute(
            "SELECT encrypted_payload FROM jobs WHERE id=?", (first,)
        ).fetchone()[0]
        self.assertNotIn("synthetic", raw)

    def test_claim_excludes_same_scope_until_completion(self):
        first = self.queue.enqueue(
            "scan", {}, idempotency_key="1", profile_id="p", broker_id="b"
        )
        self.queue.enqueue(
            "verify", {}, idempotency_key="2", profile_id="p", broker_id="b"
        )
        claimed = self.queue.claim("w1", lease_seconds=60)
        self.assertEqual(claimed.id, first)
        self.assertEqual(claimed.attempts, 1)
        self.assertIsNone(self.queue.claim("w2"))
        self.queue.succeed(first, "w1")
        self.assertIsNotNone(self.queue.claim("w2"))

    def test_expired_lease_is_reclaimed(self):
        job_id = self.queue.enqueue("scan", {}, idempotency_key="1", max_attempts=3)
        self.queue.claim("w1", lease_seconds=10)
        self.clock.now += timedelta(seconds=11)
        claimed = self.queue.claim("w2")
        self.assertEqual(claimed.id, job_id)
        self.assertEqual(claimed.attempts, 2)

    def test_failure_retries_then_dies_and_manual_retry_resets(self):
        job_id = self.queue.enqueue("scan", {}, idempotency_key="1", max_attempts=2)
        self.queue.claim("w1")
        status = self.queue.fail(job_id, "w1", "temporary", base_delay_seconds=0)
        self.assertEqual(status, JobStatus.RETRY_WAIT)
        self.queue.claim("w1")
        status = self.queue.fail(job_id, "w1", "temporary", base_delay_seconds=0)
        self.assertEqual(status, JobStatus.DEAD)
        self.queue.retry(job_id)
        self.assertEqual(self.queue.get(job_id).status, JobStatus.QUEUED)
        self.assertEqual(self.queue.get(job_id).attempts, 0)

    def test_block_requires_manual_retry(self):
        job_id = self.queue.enqueue("scan", {}, idempotency_key="1")
        self.queue.claim("w1")
        self.queue.block(job_id, "w1", "captcha")
        self.assertEqual(self.queue.get(job_id).status, JobStatus.BLOCKED)
        self.queue.retry(job_id)
        self.assertEqual(self.queue.get(job_id).status, JobStatus.QUEUED)


if __name__ == "__main__":
    unittest.main()
