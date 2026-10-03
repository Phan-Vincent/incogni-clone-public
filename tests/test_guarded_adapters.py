import unittest
from dataclasses import replace

from incogni.adapters.guarded import (
    LIVE_BROKERS,
    GuardedFixtureAdapter,
    page_fingerprint,
    safety_flags,
)
from incogni.adapters.service import GuardrailPause, RequestResult
from incogni.models import AutomationLevel, FindingStatus, RequestStatus


MATCH = '<html><form id="optout"><input name="record"></form><div data-result="match" data-listing-id="synthetic-1"></div></html>'
CLEAR = '<html><form id="optout"><input name="record"></form><div data-result="none"></div></html>'


class MemoryGuard:
    def __init__(self):
        self.acquired = self.succeeded = self.failed = 0

    def acquire(self, broker_id, *, per_hour):
        del broker_id, per_hour
        self.acquired += 1

    def record_success(self, broker_id):
        del broker_id
        self.succeeded += 1

    def record_failure(self, broker_id):
        del broker_id
        self.failed += 1


class MemoryTransport:
    name = "fixture"

    def __init__(self):
        self.calls = 0

    def execute(self, plan):
        self.calls += 1
        return RequestResult(plan.broker_id, RequestStatus.SUBMITTED, "synthetic-case")


class GuardedAdapterTest(unittest.TestCase):
    def source(self, broker_id, reference, operation):
        del broker_id, reference
        return MATCH if operation in {"discover", "verify"} else CLEAR

    def test_flow_version_change_downgrades_and_pauses(self):
        from incogni.adapters.guarded import seed_live_broker_flows
        from incogni.crypto import EnvelopeCrypto
        from incogni.storage import ServiceStore

        store = ServiceStore(":memory:", EnvelopeCrypto({"test": b"k" * 32}, "test"))
        try:
            seed_live_broker_flows(store)
            store.conn.execute(
                "UPDATE broker_flows SET automation_level='automatic',paused=0,"
                "flow_version='older' WHERE broker_id='spokeo'"
            )
            seed_live_broker_flows(store)
            row = store.conn.execute(
                "SELECT automation_level,paused FROM broker_flows WHERE broker_id='spokeo'"
            ).fetchone()
            self.assertEqual(row["automation_level"], "monitor_only")
            self.assertEqual(row["paused"], 1)
        finally:
            store.close()

    def test_all_five_start_paused_and_monitor_only(self):
        self.assertEqual(len(LIVE_BROKERS), 5)
        for metadata in LIVE_BROKERS:
            self.assertTrue(metadata.paused)
            self.assertIs(metadata.automation_level, AutomationLevel.MONITOR_ONLY)
            adapter = GuardedFixtureAdapter(metadata, self.source)
            result = adapter.discover("encrypted-profile-ref")
            self.assertIs(result.status, FindingStatus.CANDIDATE)
            plan = adapter.prepare_removal("synthetic-finding")
            self.assertFalse(plan.external_side_effects)
            with self.assertRaisesRegex(GuardrailPause, "finding_requires_local_lookup"):
                adapter.execute(plan, "approval")

    def test_captcha_identity_and_fingerprint_drift_pause(self):
        metadata = LIVE_BROKERS[0]
        for marker, expected in (
            ('<div class="g-recaptcha"></div>', "captcha"),
            ("<p>Upload a driver's license</p>", "identity_document"),
        ):
            adapter = GuardedFixtureAdapter(
                metadata, lambda *_args, html=marker: html
            )
            with self.assertRaisesRegex(GuardrailPause, expected):
                adapter.discover("ref")

        stable = page_fingerprint(CLEAR)
        drifted = replace(metadata, expected_page_fingerprint=stable)
        adapter = GuardedFixtureAdapter(
            drifted, lambda *_args: '<form><input name="changed-field"></form>'
        )
        with self.assertRaisesRegex(GuardrailPause, "page_fingerprint_changed"):
            adapter.discover("ref")

    def test_approval_required_can_execute_only_with_token(self):
        transport = MemoryTransport()
        guard = MemoryGuard()
        metadata = replace(
            LIVE_BROKERS[0],
            automation_level=AutomationLevel.APPROVAL_REQUIRED,
            paused=False,
        )
        adapter = GuardedFixtureAdapter(
            metadata,
            self.source,
            transport=transport,
            finding_source=lambda _finding: {"status": "confirmed_match"},
            runtime_guard=guard,
        )
        plan = adapter.prepare_removal("finding")
        with self.assertRaisesRegex(GuardrailPause, "approval_required"):
            adapter.execute(plan, None)
        result = adapter.execute(plan, "one-time-approval")
        self.assertIs(result.status, RequestStatus.SUBMITTED)
        self.assertEqual(transport.calls, 1)
        self.assertEqual((guard.acquired, guard.succeeded, guard.failed), (1, 1, 0))

    def test_fingerprint_ignores_listing_text_but_tracks_form_shape(self):
        first = '<form id="x"><input name="email"></form><p>Alice</p>'
        second = '<form id="x"><input name="email"></form><p>Bob</p>'
        changed = '<form id="x"><input name="phone"></form><p>Bob</p>'
        self.assertEqual(page_fingerprint(first), page_fingerprint(second))
        self.assertNotEqual(page_fingerprint(first), page_fingerprint(changed))
        self.assertEqual(safety_flags(CLEAR), ())


if __name__ == "__main__":
    unittest.main()
