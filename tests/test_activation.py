import unittest
from datetime import datetime, timedelta, timezone

from incogni.activation import BrokerActivation
from incogni.adapters.guarded import seed_live_broker_flows
from incogni.crypto import EnvelopeCrypto
from incogni.models import AutomationLevel
from incogni.storage import ServiceStore


class BrokerActivationTest(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 26, tzinfo=timezone.utc)
        self.store = ServiceStore(
            ":memory:", EnvelopeCrypto({"test": b"k" * 32}, "test")
        )
        seed_live_broker_flows(self.store)
        self.activation = BrokerActivation(self.store, clock=lambda: self.now)

    def tearDown(self):
        self.store.close()

    def test_requires_soak_terms_canary_human_and_explicit_resume(self):
        with self.assertRaisesRegex(ValueError, "soak"):
            self.activation.set_level(
                "spokeo", AutomationLevel.APPROVAL_REQUIRED
            )
        self.store.conn.execute(
            "UPDATE broker_flows SET monitor_since=? WHERE broker_id='spokeo'",
            ((self.now - timedelta(days=15)).isoformat(),),
        )
        with self.assertRaisesRegex(ValueError, "terms"):
            self.activation.set_level(
                "spokeo", AutomationLevel.APPROVAL_REQUIRED
            )
        self.activation.record_checkpoint("spokeo", "terms")
        with self.assertRaisesRegex(ValueError, "canary"):
            self.activation.set_level(
                "spokeo", AutomationLevel.APPROVAL_REQUIRED
            )
        self.activation.record_checkpoint("spokeo", "canary")
        self.activation.set_level("spokeo", AutomationLevel.APPROVAL_REQUIRED)
        row = self.store.conn.execute(
            "SELECT automation_level,paused FROM broker_flows WHERE broker_id='spokeo'"
        ).fetchone()
        self.assertEqual(row["automation_level"], "approval_required")
        self.assertEqual(row["paused"], 1)

        with self.assertRaisesRegex(ValueError, "human-reviewed"):
            self.activation.record_checkpoint("spokeo", "human")
        self.store.conn.execute(
            "UPDATE broker_flows SET paused=0 WHERE broker_id='spokeo'"
        )
        self.activation.record_checkpoint("spokeo", "human")
        with self.assertRaisesRegex(ValueError, "operator-performed"):
            self.activation.set_level("spokeo", AutomationLevel.AUTOMATIC)

    def test_automatic_requires_approval_mode_and_human_run(self):
        self.store.conn.execute(
            "UPDATE broker_flows SET monitor_since=? WHERE broker_id='whitepages'",
            ((self.now - timedelta(days=15)).isoformat(),),
        )
        self.activation.record_checkpoint("whitepages", "terms")
        self.activation.record_checkpoint("whitepages", "canary")
        with self.assertRaisesRegex(ValueError, "approval-required mode first"):
            self.activation.set_level("whitepages", AutomationLevel.AUTOMATIC)
        self.activation.set_level("whitepages", AutomationLevel.APPROVAL_REQUIRED)
        with self.assertRaisesRegex(ValueError, "human-reviewed personal run"):
            self.activation.set_level("whitepages", AutomationLevel.AUTOMATIC)
        self.store.conn.execute(
            "UPDATE broker_flows SET paused=0 WHERE broker_id='whitepages'"
        )
        self.activation.record_checkpoint("whitepages", "human")
        self.activation.set_level("whitepages", AutomationLevel.AUTOMATIC)
        row = self.store.conn.execute(
            "SELECT automation_level,paused FROM broker_flows "
            "WHERE broker_id='whitepages'"
        ).fetchone()
        self.assertEqual(row["automation_level"], "automatic")
        self.assertEqual(row["paused"], 1)

    def test_demotion_resets_soak_and_pauses(self):
        self.store.conn.execute(
            "UPDATE broker_flows SET automation_level='automatic',paused=0 "
            "WHERE broker_id='mylife'"
        )
        self.activation.set_level("mylife", AutomationLevel.MONITOR_ONLY)
        row = self.store.conn.execute(
            "SELECT automation_level,paused,monitor_since FROM broker_flows "
            "WHERE broker_id='mylife'"
        ).fetchone()
        self.assertEqual(row["automation_level"], "monitor_only")
        self.assertEqual(row["paused"], 1)
        self.assertEqual(row["monitor_since"], self.now.isoformat())


if __name__ == "__main__":
    unittest.main()
