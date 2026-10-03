import unittest

from incogni.models import OptOutResult, OptOutStatus, ScanResult, ScanStatus
from incogni.tracker import Tracker


class TrackerTest(unittest.TestCase):
    def setUp(self):
        self.tracker = Tracker(":memory:")

    def tearDown(self):
        self.tracker.close()

    def test_record_and_latest_scan(self):
        self.tracker.record_scan(
            ScanResult("b1", ScanStatus.FOUND, matched_fields=["name", "address"])
        )
        scan = self.tracker.latest_scan("b1")
        self.assertIsNotNone(scan)
        self.assertEqual(scan["status"], "found")
        self.assertEqual(scan["matched_fields"], '["name", "address"]')

    def test_latest_scan_is_most_recent(self):
        self.tracker.record_scan(ScanResult("b1", ScanStatus.NOT_FOUND))
        self.tracker.record_scan(ScanResult("b1", ScanStatus.FOUND, matched_fields=["email"]))
        self.assertEqual(self.tracker.latest_scan("b1")["status"], "found")

    def test_optout_upsert(self):
        self.tracker.record_optout(OptOutResult("b1", OptOutStatus.SUBMITTED, confirmation_id="c1"))
        self.tracker.record_optout(OptOutResult("b1", OptOutStatus.CONFIRMED, confirmation_id="c2"))
        self.assertEqual(self.tracker.get_optout("b1")["status"], "confirmed")
        self.assertEqual(self.tracker.get_optout("b1")["confirmation_id"], "c2")
        # One row, not two (UNIQUE on broker_id).
        self.assertEqual(len(self.tracker.list_optouts()), 1)


if __name__ == "__main__":
    unittest.main()
