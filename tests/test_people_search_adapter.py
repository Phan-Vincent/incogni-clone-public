import unittest
from pathlib import Path

from incogni.adapters.people_search import (
    PeopleSearchFixtureAdapter,
    PeopleSearchFixtureSpec,
)
from incogni.adapters.service import GuardrailPause
from incogni.adapters.spokeo import (
    SPOKEO_METADATA,
    SPOKEO_SPEC,
    SpokeoFixtureAdapter,
)
from incogni.models import AutomationLevel

FIXTURES = Path(__file__).parent / "fixtures" / "spokeo"


def spokeo_source(_broker_id, reference, _operation):
    return (FIXTURES / f"{reference}.html").read_text(encoding="utf-8")


class PeopleSearchFixtureAdapterTest(unittest.TestCase):
    def generic(self):
        return PeopleSearchFixtureAdapter(
            SPOKEO_METADATA,
            spokeo_source,
            SPOKEO_SPEC,
            finding_source=lambda _finding: {"status": "confirmed_match"},
        )

    def specific(self):
        return SpokeoFixtureAdapter(
            spokeo_source,
            finding_source=lambda _finding: {"status": "confirmed_match"},
        )

    def test_spokeo_wrapper_has_behavioral_parity_with_shared_base(self):
        generic = self.generic()
        specific = self.specific()
        for reference in ("candidate", "not_found", "ambiguous"):
            with self.subTest(operation="discover", reference=reference):
                self.assertEqual(
                    generic.discover(reference), specific.discover(reference)
                )
        self.assertEqual(
            generic.prepare_removal("synthetic-finding"),
            specific.prepare_removal("synthetic-finding"),
        )
        for reference in (
            "poll_verification",
            "poll_processing",
            "poll_confirmed",
            "poll_expired",
        ):
            with self.subTest(operation="poll", reference=reference):
                self.assertEqual(generic.poll(reference), specific.poll(reference))
        for reference in ("verify_suppressed", "verify_reappeared"):
            with self.subTest(operation="verify", reference=reference):
                self.assertEqual(generic.verify(reference), specific.verify(reference))

    def test_unknown_states_and_error_codes_fail_closed(self):
        documents = {
            "discover": '<section id="synthetic-results" data-result="mystery"></section>',
            "poll": '<section id="synthetic-status" data-status="mystery"></section>',
            "verify": '<section id="synthetic-listing" data-result="mystery"></section>',
            "error": '<section data-synthetic-error="418"></section>',
        }

        def source(_broker_id, reference, _operation):
            return documents[reference]

        spec = PeopleSearchFixtureSpec(
            results_id="synthetic-results",
            request_status_id="synthetic-status",
            listing_id="synthetic-listing",
            error_attribute="data-synthetic-error",
            redirect_attribute="data-synthetic-redirect",
            removal_steps=("synthetic_step",),
        )
        adapter = PeopleSearchFixtureAdapter(SPOKEO_METADATA, source, spec)
        for operation, reference, reason in (
            (adapter.discover, "discover", "unknown_discovery_state"),
            (adapter.poll, "poll", "unknown_request_state"),
            (adapter.verify, "verify", "unknown_verification_state"),
            (adapter.discover, "error", "unexpected_broker_error"),
        ):
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(GuardrailPause, reason):
                    operation(reference)

    def test_runtime_policy_copy_preserves_spec_and_fixture_source(self):
        adapter = self.generic().with_runtime_policy(
            automation_level=AutomationLevel.APPROVAL_REQUIRED,
            paused=False,
        )
        self.assertIs(adapter.spec, SPOKEO_SPEC)
        self.assertIs(adapter.metadata.automation_level, AutomationLevel.APPROVAL_REQUIRED)
        self.assertFalse(adapter.metadata.paused)
        self.assertEqual(
            adapter.discover("candidate"), self.generic().discover("candidate")
        )

    def test_empty_spec_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-empty"):
            PeopleSearchFixtureSpec(
                results_id="",
                request_status_id="status",
                listing_id="listing",
                error_attribute="error",
                redirect_attribute="redirect",
                removal_steps=("step",),
            )


if __name__ == "__main__":
    unittest.main()
