"""Synthetic-only Intelius adapter (paused / monitor-only).

Intelius routes opt-outs through PeopleConnect's shared suppression center;
its terms prohibit scraping/robots, so live automation stays prohibited and
the broker remains paused / monitor-only. This adapter only ever interprets
the sanitized synthetic fixture contract.
"""

from __future__ import annotations

from incogni.adapters.guarded import LIVE_BROKER_BY_ID
from incogni.adapters.people_search import (
    PeopleSearchFixtureAdapter,
    PeopleSearchFixtureSpec,
)
from incogni.adapters.service import BrokerMetadata

INTELIUS_METADATA = LIVE_BROKER_BY_ID["intelius"]
INTELIUS_REMOVAL_STEPS = (
    "open_shared_center",
    "verify_email",
    "select_identity",
    "obtain_operator_approval",
    "confirm_suppression_manually",
)
INTELIUS_SPEC = PeopleSearchFixtureSpec(
    results_id="intelius-results",
    request_status_id="intelius-request-status",
    listing_id="intelius-listing",
    error_attribute="data-intelius-error",
    redirect_attribute="data-intelius-redirect",
    removal_steps=INTELIUS_REMOVAL_STEPS,
)


class InteliusAdapter(PeopleSearchFixtureAdapter):
    """Fixture-only Intelius integration with no default live transport."""

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
            metadata or INTELIUS_METADATA,
            fixture_source,
            INTELIUS_SPEC,
            transport=transport,
            finding_source=finding_source,
            runtime_guard=runtime_guard,
            expected_page_fingerprint=expected_page_fingerprint,
        )


InteliusFixtureAdapter = InteliusAdapter
