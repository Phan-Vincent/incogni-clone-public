import unittest
from pathlib import Path

from incogni.adapters.guarded import page_fingerprint
from incogni.adapters.service import GuardrailPause
from incogni.adapters.intelius import InteliusFixtureAdapter
from incogni.fixture_redaction import assert_redacted, redact_fixture
from incogni.models import AutomationLevel, FindingStatus, RequestStatus

FIXTURES = Path(__file__).parent / "fixtures" / "intelius"


def fixture_source(_broker_id, reference, _operation):
    return (FIXTURES / f"{reference}.html").read_text(encoding="utf-8")


class InteliusFixtureAdapterTest(unittest.TestCase):
    def adapter(self, **kwargs):
        return InteliusFixtureAdapter(
            fixture_source,
            finding_source=lambda _finding: {"status": "confirmed_match"},
            **kwargs,
        )

    def test_every_fixture_passes_basic_redaction_scan(self):
        for path in FIXTURES.glob("*.html"):
            fixture = redact_fixture(path.read_text(encoding="utf-8"))
            assert_redacted(fixture, sensitive_values=())

    def test_discovery_states_are_explicit_and_deterministic(self):
        adapter = self.adapter()
        first = adapter.discover("candidate")
        second = adapter.discover("candidate")
        self.assertIs(first.status, FindingStatus.CANDIDATE)
        self.assertEqual(first.listing_fingerprint, second.listing_fingerprint)
        self.assertIs(
            adapter.discover("not_found").status, FindingStatus.NOT_FOUND
        )
        self.assertIs(
            adapter.discover("ambiguous").status, FindingStatus.AMBIGUOUS
        )
        duplicate = adapter.discover("duplicate")
        self.assertIs(duplicate.status, FindingStatus.AMBIGUOUS)
        self.assertEqual(duplicate.reason_code, "ambiguous_duplicate_results")
        self.assertIs(adapter.metadata.automation_level, AutomationLevel.MONITOR_ONLY)
        self.assertTrue(adapter.metadata.paused)

    def test_selector_and_unknown_discovery_states_pause(self):
        for fixture, reason in (
            ("missing_selector", "selector_missing"),
            ("unknown_discovery", "unknown_discovery_state"),
        ):
            with self.subTest(fixture=fixture):
                with self.assertRaisesRegex(GuardrailPause, reason):
                    self.adapter().discover(fixture)

    def test_content_and_broker_guardrails_pause(self):
        cases = (
            ("captcha", "captcha"),
            ("identity_document", "identity_document"),
            ("authentication", "authentication"),
            ("paywall", "paywall"),
            ("terms_changed", "terms_changed"),
            ("rate_limited", "broker_rate_limit"),
            ("outage", "broker_outage"),
            ("redirect", "unexpected_redirect"),
        )
        for fixture, reason in cases:
            with self.subTest(fixture=fixture):
                with self.assertRaisesRegex(GuardrailPause, reason):
                    self.adapter().discover(fixture)

    def test_page_fingerprint_drift_pauses(self):
        expected = page_fingerprint(
            fixture_source("intelius", "not_found", "discover")
        )
        with self.assertRaisesRegex(GuardrailPause, "page_fingerprint_changed"):
            self.adapter(expected_page_fingerprint=expected).discover("candidate")

    def test_plan_has_no_side_effect_and_execution_is_blocked(self):
        adapter = self.adapter()
        plan = adapter.prepare_removal("synthetic-finding")
        self.assertFalse(plan.external_side_effects)
        self.assertEqual(plan.transport, "browser_form")
        self.assertIn("obtain_operator_approval", plan.steps)
        self.assertIn("verify_email", plan.steps)
        with self.assertRaisesRegex(GuardrailPause, "broker_paused"):
            adapter.execute(plan, "synthetic-approval")

    def test_poll_states_and_unknown_state(self):
        expected = {
            "poll_verification": RequestStatus.VERIFICATION_REQUIRED,
            "poll_processing": RequestStatus.PROCESSING,
            "poll_confirmed": RequestStatus.CONFIRMED,
            "poll_expired": RequestStatus.FAILED,
        }
        for fixture, status in expected.items():
            with self.subTest(fixture=fixture):
                self.assertIs(self.adapter().poll(fixture).status, status)
        self.assertEqual(
            self.adapter().poll("poll_expired").reason_code,
            "verification_link_expired",
        )
        with self.assertRaisesRegex(GuardrailPause, "unknown_request_state"):
            self.adapter().poll("poll_unknown")

    def test_verification_states_and_unknown_state(self):
        self.assertIs(
            self.adapter().verify("verify_suppressed").status,
            FindingStatus.SUPPRESSED,
        )
        reappeared = self.adapter().verify("verify_reappeared")
        self.assertIs(reappeared.status, FindingStatus.REAPPEARED)
        self.assertTrue(reappeared.listing_fingerprint.startswith("sha256:"))
        with self.assertRaisesRegex(GuardrailPause, "unknown_verification_state"):
            self.adapter().verify("verify_unknown")


if __name__ == "__main__":
    unittest.main()
