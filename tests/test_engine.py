import unittest
from datetime import timedelta

from incogni.adapters.mock_backend import search
from incogni.engine import Engine
from incogni.models import OptOutStatus, ScanStatus
from incogni.profile import Address, PersonProfile
from incogni.registry import BrokerRegistry
from incogni.tracker import Tracker


def jane(city: str = "Austin", state: str = "TX") -> PersonProfile:
    return PersonProfile(
        first_name="Jane",
        last_name="Doe",
        emails=["jane.doe@example.com"],
        phones=["(555) 010-0199"],
        addresses=[Address(city=city, state=state)],
    )


class MockBackendTest(unittest.TestCase):
    def test_location_disambiguates_same_name(self):
        # Austin Jane matches the Austin dossier only, not the Dallas one.
        hits = search(jane("Austin", "TX"), "whitepages_like")
        self.assertEqual(len(hits), 1)
        self.assertIn("address", hits[0][1])  # location corroborated

    def test_different_person_not_found(self):
        hits = search(jane("Dallas", "TX"), "peoplefinder_like")
        # The only Dallas "Jane Doe" lives on whitepages_like, not peoplefinder_like.
        self.assertEqual(hits, [])


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.registry = BrokerRegistry.from_file()
        self.tracker = Tracker(":memory:")
        self.engine = Engine(self.registry, self.tracker, jane())

    def tearDown(self):
        self.tracker.close()

    def test_scan_all_statuses(self):
        results = {r.broker_id: r for r in self.engine.scan_all()}
        self.assertEqual(results["peoplefinder_like"].status, ScanStatus.FOUND)
        self.assertEqual(results["mylife_like"].status, ScanStatus.FOUND)
        self.assertEqual(results["instantcheckmate_like"].status, ScanStatus.NOT_FOUND)
        self.assertEqual(results["beenverified_like"].status, ScanStatus.SKIPPED)

    def test_submit_optouts_and_idempotency(self):
        self.engine.scan_all()
        self.assertEqual(
            self.tracker.get_optout("peoplefinder_like")["status"],
            OptOutStatus.PENDING.value,
        )
        self.assertEqual(
            self.tracker.get_optout("instantcheckmate_like")["status"],
            OptOutStatus.NOT_NEEDED.value,
        )
        first = self.engine.submit_optouts()
        by_id = {r.broker_id: r for r in first}
        self.assertEqual(len(first), 4)
        self.assertEqual(by_id["peoplefinder_like"].status, OptOutStatus.CONFIRMED)
        self.assertEqual(by_id["mylife_like"].status, OptOutStatus.SUBMITTED)
        # A second pass is a no-op (confirmed/submitted are not re-submitted).
        self.assertEqual(self.engine.submit_optouts(), [])

    def test_confirm_submitted_optout(self):
        self.engine.scan_all()
        self.engine.submit_optouts()

        result = self.engine.confirm_optout("mylife_like", "case-123")

        self.assertEqual(result.status, OptOutStatus.CONFIRMED)
        self.assertEqual(result.confirmation_id, "case-123")
        self.assertEqual(
            self.tracker.get_optout("mylife_like")["status"],
            OptOutStatus.CONFIRMED.value,
        )
        # Recording the same confirmation again is idempotent.
        again = self.engine.confirm_optout("mylife_like", "ignored")
        self.assertEqual(again.confirmation_id, "case-123")

    def test_confirm_rejects_non_submitted_optout(self):
        self.engine.scan_all()
        with self.assertRaisesRegex(ValueError, "status is pending"):
            self.engine.confirm_optout("peoplefinder_like")

    def test_recheck_due_never_scanned(self):
        # Nothing scanned yet -> every broker is due.
        self.assertEqual(
            set(self.engine.recheck_due(timedelta(days=30))),
            {b.id for b in self.registry},
        )


if __name__ == "__main__":
    unittest.main()
