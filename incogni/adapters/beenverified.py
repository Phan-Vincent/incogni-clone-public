"""Synthetic-only BeenVerified adapter (paused / monitor-only)."""

from __future__ import annotations

from incogni.adapters.guarded import LIVE_BROKER_BY_ID
from incogni.adapters.people_search import (
    PeopleSearchFixtureAdapter,
    PeopleSearchFixtureSpec,
)
from incogni.adapters.service import BrokerMetadata

BEENVERIFIED_METADATA = LIVE_BROKER_BY_ID["beenverified"]
BEENVERIFIED_REMOVAL_STEPS = (
    "select_opt_out_record",
    "prepare_privacy_request",
    "obtain_operator_approval",
    "submit_privacy_request",
    "verify_email",
)
BEENVERIFIED_SPEC = PeopleSearchFixtureSpec(
    results_id="beenverified-results",
    request_status_id="beenverified-request-status",
    listing_id="beenverified-listing",
    error_attribute="data-beenverified-error",
    redirect_attribute="data-beenverified-redirect",
    removal_steps=BEENVERIFIED_REMOVAL_STEPS,
)


class BeenVerifiedAdapter(PeopleSearchFixtureAdapter):
    """Fixture-only BeenVerified integration with no default live transport."""

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
            metadata or BEENVERIFIED_METADATA,
            fixture_source,
            BEENVERIFIED_SPEC,
            transport=transport,
            finding_source=finding_source,
            runtime_guard=runtime_guard,
            expected_page_fingerprint=expected_page_fingerprint,
        )


BeenVerifiedFixtureAdapter = BeenVerifiedAdapter
