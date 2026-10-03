import unittest
from pathlib import Path

from incogni.adapters.guarded import page_fingerprint
from incogni.adapters.service import GuardrailPause
from incogni.adapters.spokeo import SpokeoFixtureAdapter
from incogni.fixture_redaction import assert_redacted, redact_fixture
from incogni.models import AutomationLevel, FindingStatus, RequestStatus

FIXTURES = Path(__file__).parent / "fixtures" / "spokeo"


def fixture_source(_broker_id, reference, _operation):
    return (FIXTURES / f"{reference}.html").read_text(encoding="utf-8")


class SpokeoFixtureAdapterTest(unittest.TestCase):
    def adapter(self, **kwargs):
        return SpokeoFixtureAdapter(
            fixture_source,
            finding_source=lambda _finding: {"status": "confirmed_match"},
            **kwargs,
        )

    def test_every_fixture_passes_basic_redaction_scan(self):
        for path in FIXTURES.glob("*.html"):
            fixture = redact_fixture(path.read_text(encoding="utf-8"))
            assert_redacted(fixture, sensitive_values=())

    def test_candidate_is_deterministic_and_metadata_stays_monitor_only(self):
        adapter = self.adapter()
        first = adapter.discover("candidate")
        second = adapter.discover("candidate")
        self.assertIs(first.status, FindingStatus.CANDIDATE)
        self.assertEqual(first.listing_fingerprint, second.listing_fingerprint)
        self.assertIs(adapter.metadata.automation_level, AutomationLevel.MONITOR_ONLY)
        self.assertTrue(adapter.metadata.paused)

    def test_not_found_ambiguous_and_missing_selector(self):
        self.assertIs(
            self.adapter().discover("not_found").status, FindingStatus.NOT_FOUND
        )
        ambiguous = self.adapter().discover("ambiguous")
        self.assertIs(ambiguous.status, FindingStatus.AMBIGUOUS)
        duplicate = self.adapter().discover("duplicate")
        self.assertIs(duplicate.status, FindingStatus.AMBIGUOUS)
        self.assertEqual(duplicate.reason_code, "ambiguous_duplicate_results")
        with self.assertRaisesRegex(GuardrailPause, "selector_missing"):
            self.adapter().discover("missing_selector")
        with self.assertRaisesRegex(GuardrailPause, "unknown_discovery_state"):
            self.adapter().discover("unknown_discovery")

    def test_content_broker_and_drift_guardrails_pause(self):
        for name, reason in (
            ("captcha", "captcha"),
            ("identity_document", "identity_document"),
            ("authentication", "authentication"),
            ("paywall", "paywall"),
            ("terms_changed", "terms_changed"),
            ("rate_limited", "broker_rate_limit"),
            ("outage", "broker_outage"),
            ("redirect", "unexpected_redirect"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(GuardrailPause, reason):
                    self.adapter().discover(name)
        expected = page_fingerprint(fixture_source("spokeo", "not_found", "discover"))
        with self.assertRaisesRegex(GuardrailPause, "page_fingerprint_changed"):
            self.adapter(expected_page_fingerprint=expected).discover("candidate")

    def test_prepare_is_side_effect_free_and_execute_is_never_automated(self):
        adapter = self.adapter()
        plan = adapter.prepare_removal("synthetic-finding")
        self.assertFalse(plan.external_side_effects)
        self.assertEqual(plan.transport, "operator_manual")
        self.assertIn("obtain_operator_approval", plan.steps)
        self.assertIn("operator_completes_captcha_and_submits", plan.steps)
        self.assertEqual(adapter.transport.name, "disabled")
        for level in AutomationLevel:
            with self.subTest(level=level):
                active = adapter.with_runtime_policy(
                    automation_level=level, paused=False
                )
                self.assertIsInstance(active, SpokeoFixtureAdapter)
                with self.assertRaisesRegex(GuardrailPause, "operator_manual_only"):
                    active.execute(plan, "synthetic-approval")

    def test_rejects_any_live_transport(self):
        class MemoryTransport:
            name = "memory"

            def execute(self, plan):
                raise AssertionError("must not run")

        with self.assertRaisesRegex(ValueError, "operator-performed"):
            self.adapter(transport=MemoryTransport())

    def test_metadata_pins_reviewed_optout_route(self):
        metadata = self.adapter().metadata
        self.assertEqual(metadata.privacy_url, "https://www.spokeo.com/optout")
        self.assertEqual(metadata.flow_version, "2026-09-manual-1")

    def test_poll_lifecycle(self):
        expected = {
            "poll_verification": RequestStatus.VERIFICATION_REQUIRED,
            "poll_processing": RequestStatus.PROCESSING,
            "poll_confirmed": RequestStatus.CONFIRMED,
            "poll_expired": RequestStatus.FAILED,
        }
        for fixture, status in expected.items():
            with self.subTest(fixture=fixture):
                result = self.adapter().poll(fixture)
                self.assertIs(result.status, status)
        self.assertEqual(
            self.adapter().poll("poll_expired").reason_code,
            "verification_link_expired",
        )
        with self.assertRaisesRegex(GuardrailPause, "unknown_request_state"):
            self.adapter().poll("poll_unknown")

    def test_verify_suppressed_and_reappeared(self):
        suppressed = self.adapter().verify("verify_suppressed")
        self.assertIs(suppressed.status, FindingStatus.SUPPRESSED)
        reappeared = self.adapter().verify("verify_reappeared")
        self.assertIs(reappeared.status, FindingStatus.REAPPEARED)
        self.assertTrue(reappeared.listing_fingerprint.startswith("sha256:"))
        with self.assertRaisesRegex(GuardrailPause, "unknown_verification_state"):
            self.adapter().verify("verify_unknown")


if __name__ == "__main__":
    unittest.main()
