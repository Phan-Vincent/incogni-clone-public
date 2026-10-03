"""Spokeo adapter: fixture discovery plus an operator-performed removal.

Spokeo's terms prohibit robots and automatic devices, and its opt-out form requires
a CAPTCHA. The service therefore never executes a Spokeo removal itself: after an
approval, :mod:`incogni.manual_assist` hands the operator a checklist and tracks the
steps the operator records.
"""

from __future__ import annotations

from incogni.adapters.guarded import DisabledTransport, LIVE_BROKER_BY_ID
from incogni.adapters.people_search import (
    PeopleSearchFixtureAdapter,
    PeopleSearchFixtureSpec,
)
from incogni.adapters.service import (
    BrokerMetadata,
    GuardrailPause,
    RemovalPlan,
    RequestResult,
)
from incogni.models import AutomationLevel

SPOKEO_METADATA = LIVE_BROKER_BY_ID["spokeo"]
SPOKEO_REMOVAL_STEPS = (
    "select_local_result",
    "obtain_operator_approval",
    "operator_opens_optout_page",
    "operator_completes_captcha_and_submits",
    "operator_opens_email_link",
)
SPOKEO_SPEC = PeopleSearchFixtureSpec(
    results_id="spokeo-results",
    request_status_id="spokeo-request-status",
    listing_id="spokeo-listing",
    error_attribute="data-spokeo-error",
    redirect_attribute="data-spokeo-redirect",
    removal_steps=SPOKEO_REMOVAL_STEPS,
    transport="operator_manual",
)


class SpokeoAdapter(PeopleSearchFixtureAdapter):
    """Fixture-only Spokeo integration whose removals are always operator-performed."""

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
        if transport is not None and not isinstance(transport, DisabledTransport):
            raise ValueError("Spokeo removals are operator-performed only")
        super().__init__(
            metadata or SPOKEO_METADATA,
            fixture_source,
            SPOKEO_SPEC,
            transport=transport,
            finding_source=finding_source,
            runtime_guard=runtime_guard,
            expected_page_fingerprint=expected_page_fingerprint,
        )

    def execute(self, plan: RemovalPlan, approval_token: str | None) -> RequestResult:
        raise GuardrailPause("operator_manual_only")

    def with_runtime_policy(
        self, *, automation_level: AutomationLevel, paused: bool
    ) -> "SpokeoAdapter":
        adapter = super().with_runtime_policy(
            automation_level=automation_level, paused=paused
        )
        return SpokeoAdapter(
            self.fixture_source,
            metadata=adapter.metadata,
            finding_source=self.finding_source,
            runtime_guard=self.runtime_guard,
        )


SpokeoFixtureAdapter = SpokeoAdapter
