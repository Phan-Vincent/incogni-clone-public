import unittest
from datetime import datetime, timedelta, timezone

from incogni.adapters.guarded import seed_live_broker_flows
from incogni.adapters.service import GuardrailPause
from incogni.broker_guard import BrokerRuntimeGuard
from incogni.crypto import EnvelopeCrypto
from incogni.storage import ServiceStore


class BrokerRuntimeGuardTest(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 26, tzinfo=timezone.utc)
        self.store = ServiceStore(
            ":memory:", EnvelopeCrypto({"test": b"k" * 32}, "test")
        )
        seed_live_broker_flows(self.store)
        self.guard = BrokerRuntimeGuard(self.store, clock=lambda: self.now)

    def tearDown(self):
        self.store.close()

    def test_rate_limit_resets_after_window(self):
        self.guard.acquire("spokeo", per_hour=2)
        self.guard.acquire("spokeo", per_hour=2)
        with self.assertRaisesRegex(GuardrailPause, "broker_rate_limit"):
            self.guard.acquire("spokeo", per_hour=2)
        self.now += timedelta(hours=1, seconds=1)
        self.guard.acquire("spokeo", per_hour=2)

    def test_circuit_opens_and_success_resets(self):
        for _ in range(3):
            self.guard.record_failure("mylife")
        with self.assertRaisesRegex(GuardrailPause, "circuit_open"):
            self.guard.acquire("mylife", per_hour=4)
        self.now += timedelta(minutes=31)
        self.guard.acquire("mylife", per_hour=4)
        self.guard.record_success("mylife")
        row = self.store.conn.execute(
            "SELECT consecutive_failures,circuit_open_until FROM broker_runtime "
            "WHERE broker_id='mylife'"
        ).fetchone()
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertIsNone(row["circuit_open_until"])


if __name__ == "__main__":
    unittest.main()
