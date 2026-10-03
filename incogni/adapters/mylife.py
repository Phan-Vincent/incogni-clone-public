"""Synthetic-only MyLife adapter (paused / monitor-only)."""

from __future__ import annotations

from incogni.adapters.guarded import LIVE_BROKER_BY_ID
from incogni.adapters.people_search import (
    PeopleSearchFixtureAdapter,
    PeopleSearchFixtureSpec,
)
from incogni.adapters.service import BrokerMetadata

MYLIFE_METADATA = LIVE_BROKER_BY_ID["mylife"]
MYLIFE_REMOVAL_STEPS = (
    "select_local_result",
    "prepare_privacy_form",
    "obtain_operator_approval",
    "submit_privacy_form",
    "verify_email",
)
MYLIFE_SPEC = PeopleSearchFixtureSpec(
    results_id="mylife-results",
    request_status_id="mylife-request-status",
    listing_id="mylife-listing",
    error_attribute="data-mylife-error",
    redirect_attribute="data-mylife-redirect",
    removal_steps=MYLIFE_REMOVAL_STEPS,
)


class MyLifeAdapter(PeopleSearchFixtureAdapter):
    """Fixture-only MyLife integration that never defaults to live transport."""

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
            metadata or MYLIFE_METADATA,
            fixture_source,
            MYLIFE_SPEC,
            transport=transport,
            finding_source=finding_source,
            runtime_guard=runtime_guard,
            expected_page_fingerprint=expected_page_fingerprint,
        )


MyLifeFixtureAdapter = MyLifeAdapter
