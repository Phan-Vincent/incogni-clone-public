import os
import tempfile
import unittest

from incogni.crypto import EnvelopeCrypto
from incogni.legacy_import import import_legacy_tracker
from incogni.models import (
    FindingStatus,
    JobStatus,
    OptOutResult,
    OptOutStatus,
    RequestStatus,
    ScanResult,
    ScanStatus,
)
from incogni.state_machine import (
    FINDING_TRANSITIONS,
    JOB_TRANSITIONS,
    REQUEST_TRANSITIONS,
    ensure_finding_transition,
    ensure_job_transition,
    ensure_request_transition,
)
from incogni.storage import ServiceStore
from incogni.tracker import Tracker


class StateMachineTest(unittest.TestCase):
    def test_every_declared_transition_and_self_transition_is_valid(self):
        for transitions, validator in (
            (FINDING_TRANSITIONS, ensure_finding_transition),
            (REQUEST_TRANSITIONS, ensure_request_transition),
            (JOB_TRANSITIONS, ensure_job_transition),
        ):
            for current, targets in transitions.items():
                validator(current, current)
                for target in targets:
                    validator(current, target)

    def test_terminal_and_invalid_transitions_fail(self):
        with self.assertRaises(ValueError):
            ensure_request_transition(RequestStatus.CONFIRMED, RequestStatus.READY)
        with self.assertRaises(ValueError):
            ensure_finding_transition(
                FindingStatus.NOT_FOUND, FindingStatus.SUPPRESSED
            )
        with self.assertRaises(ValueError):
            ensure_job_transition(JobStatus.SUCCEEDED, JobStatus.QUEUED)


class LegacyImportTest(unittest.TestCase):
    def test_import_encrypts_details_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            legacy_path = os.path.join(temp, "legacy.db")
            tracker = Tracker(legacy_path)
            tracker.record_scan(
                ScanResult(
                    "example",
                    ScanStatus.FOUND,
                    matched_fields=["email"],
                    detail="synthetic private detail",
                )
            )
            tracker.record_optout(
                OptOutResult(
                    "example",
                    OptOutStatus.SUBMITTED,
                    confirmation_id="synthetic-case",
                    message="synthetic private message",
                )
            )
            tracker.close()
            service_path = os.path.join(temp, "service.db")
            store = ServiceStore(
                service_path, EnvelopeCrypto({"test": b"k" * 32}, "test")
            )
            try:
                first = import_legacy_tracker(legacy_path, store)
                second = import_legacy_tracker(legacy_path, store)
                self.assertEqual(first, {"scans": 1, "optouts": 1})
                self.assertEqual(second, {"scans": 1, "optouts": 1})
                self.assertEqual(
                    store.conn.execute("SELECT count(*) FROM findings").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    store.conn.execute(
                        "SELECT count(*) FROM removal_requests"
                    ).fetchone()[0],
                    1,
                )
                with open(service_path, "rb") as handle:
                    raw = handle.read()
                self.assertNotIn(b"synthetic private detail", raw)
                self.assertNotIn(b"synthetic private message", raw)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
