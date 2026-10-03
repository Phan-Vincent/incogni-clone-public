"""Synthetic-only Whitepages adapter (paused / monitor-only)."""

from __future__ import annotations

from incogni.adapters.guarded import LIVE_BROKER_BY_ID
from incogni.adapters.people_search import (
    PeopleSearchFixtureAdapter,
    PeopleSearchFixtureSpec,
)
from incogni.adapters.service import BrokerMetadata

WHITEPAGES_METADATA = LIVE_BROKER_BY_ID["whitepages"]
WHITEPAGES_REMOVAL_STEPS = (
    "select_suppression_record",
    "prepare_suppression_form",
    "obtain_operator_approval",
    "submit_suppression_form",
    "verify_email",
)
WHITEPAGES_SPEC = PeopleSearchFixtureSpec(
    results_id="whitepages-results",
    request_status_id="whitepages-request-status",
    listing_id="whitepages-listing",
    error_attribute="data-whitepages-error",
    redirect_attribute="data-whitepages-redirect",
    removal_steps=WHITEPAGES_REMOVAL_STEPS,
)


class WhitepagesAdapter(PeopleSearchFixtureAdapter):
    """Fixture-only Whitepages integration with no default live transport."""

    def __init__(
        self,
        fixture_source,
        *,
        metadata: BrokerMetadata | None = None,
        transport=None,
        finding_source=None,
        runtime_guard=None,
        expected_page_fingerprint: str | None = None,
    ):
        super().__init__(
            metadata or WHITEPAGES_METADATA,
            fixture_source,
            WHITEPAGES_SPEC,
            transport=transport,
            finding_source=finding_source,
            runtime_guard=runtime_guard,
            expected_page_fingerprint=expected_page_fingerprint,
        )


WhitepagesFixtureAdapter = WhitepagesAdapter
