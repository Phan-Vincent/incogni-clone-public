"""Declarative fail-closed behavior for synthetic people-search fixtures.

The shared parser intentionally understands only the small sanitized fixture
contract declared by :class:`PeopleSearchFixtureSpec`. It never treats an unknown
marker as an absent listing or a successful removal.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace

from incogni.adapters.guarded import GuardedFixtureAdapter
from incogni.adapters.service import (
    BrokerMetadata,
    DiscoveryResult,
    GuardrailPause,
    RemovalPlan,
    RequestResult,
    VerificationResult,
)
from incogni.models import AutomationLevel, FindingStatus, RequestStatus


@dataclass(frozen=True)
class PeopleSearchFixtureSpec:
    """Broker-specific markers accepted by the synthetic fixture parser."""

    results_id: str
    request_status_id: str
    listing_id: str
    error_attribute: str
    redirect_attribute: str
    removal_steps: tuple[str, ...]
    listing_attribute: str = "data-listing-id"
    transport: str = "browser_form"

    def __post_init__(self) -> None:
        values = (
            self.results_id,
            self.request_status_id,
            self.listing_id,
            self.error_attribute,
            self.redirect_attribute,
            self.listing_attribute,
            self.transport,
        )
        if any(not value for value in values) or not self.removal_steps:
            raise ValueError("people-search fixture spec fields must be non-empty")


_POLL_STATES = {
    "verification_required": RequestStatus.VERIFICATION_REQUIRED,
    "processing": RequestStatus.PROCESSING,
    "confirmed": RequestStatus.CONFIRMED,
    "expired_link": RequestStatus.FAILED,
}


def _attribute_value(html: str, attribute: str) -> str | None:
    match = re.search(rf'{re.escape(attribute)}="([^"]+)"', html)
    return match.group(1) if match else None


class PeopleSearchFixtureAdapter(GuardedFixtureAdapter):
    """Shared fixture behavior with explicit broker-specific marker names."""

    def __init__(
        self,
        metadata: BrokerMetadata,
        fixture_source,
        spec: PeopleSearchFixtureSpec,
        *,
        transport=None,
        finding_source=None,
        runtime_guard=None,
        expected_page_fingerprint: str | None = None,
    ):
        if expected_page_fingerprint is not None:
            metadata = replace(
                metadata, expected_page_fingerprint=expected_page_fingerprint
            )
        super().__init__(
            metadata,
            fixture_source,
            transport=transport,
            finding_source=finding_source,
            runtime_guard=runtime_guard,
        )
        self.spec = spec

    def _inspect(self, reference: str, operation: str) -> tuple[str, tuple[str, ...]]:
        html, flags = super()._inspect(reference, operation)
        error = _attribute_value(html, self.spec.error_attribute)
        if error is not None:
            if error == "429":
                raise GuardrailPause("broker_rate_limit")
            if re.fullmatch(r"5\d\d", error):
                raise GuardrailPause("broker_outage")
            raise GuardrailPause("unexpected_broker_error")
        redirect = _attribute_value(html, self.spec.redirect_attribute)
        if redirect is not None and redirect != "expected":
            raise GuardrailPause("unexpected_redirect")
        return html, flags

    def discover(self, profile_ref: str) -> DiscoveryResult:
        html, _ = self._inspect(profile_ref, "discover")
        if f'id="{self.spec.results_id}"' not in html:
            raise GuardrailPause("selector_missing")
        marker = _attribute_value(html, "data-result")
        if marker == "ambiguous":
            return DiscoveryResult(
                self.metadata.broker_id,
                FindingStatus.AMBIGUOUS,
                reason_code="ambiguous_identity",
            )
        if marker == "none":
            return DiscoveryResult(self.metadata.broker_id, FindingStatus.NOT_FOUND)
        if marker != "match":
            raise GuardrailPause("unknown_discovery_state")
        listing_ids = re.findall(
            rf'{re.escape(self.spec.listing_attribute)}="([^"]+)"', html
        )
        if not listing_ids:
            raise GuardrailPause("selector_missing")
        if len(listing_ids) > 1:
            return DiscoveryResult(
                self.metadata.broker_id,
                FindingStatus.AMBIGUOUS,
                reason_code="ambiguous_duplicate_results",
            )
        fingerprint = "sha256:" + hashlib.sha256(
            listing_ids[0].encode()
        ).hexdigest()
        return DiscoveryResult(
            self.metadata.broker_id,
            FindingStatus.CANDIDATE,
            listing_fingerprint=fingerprint,
        )

    def prepare_removal(self, finding_id: str) -> RemovalPlan:
        flags: tuple[str, ...] = ()
        if self.finding_source(finding_id) is None:
            flags = ("finding_requires_local_lookup",)
        return RemovalPlan(
            broker_id=self.metadata.broker_id,
            finding_id=finding_id,
            flow_version=self.metadata.flow_version,
            transport=self.spec.transport,
            steps=self.spec.removal_steps,
            safety_flags=flags,
            external_side_effects=False,
        )

    def poll(self, request_id: str) -> RequestResult:
        html, _ = self._inspect(request_id, "poll")
        if f'id="{self.spec.request_status_id}"' not in html:
            raise GuardrailPause("selector_missing")
        marker = _attribute_value(html, "data-status")
        status = _POLL_STATES.get(marker or "")
        if status is None:
            raise GuardrailPause("unknown_request_state")
        reason = "verification_link_expired" if marker == "expired_link" else None
        return RequestResult(self.metadata.broker_id, status, reason_code=reason)

    def verify(self, finding_id: str) -> VerificationResult:
        html, _ = self._inspect(finding_id, "verify")
        if f'id="{self.spec.listing_id}"' not in html:
            raise GuardrailPause("selector_missing")
        marker = _attribute_value(html, "data-result")
        if marker == "none":
            status = FindingStatus.SUPPRESSED
            fingerprint = None
        elif marker == "match":
            status = FindingStatus.REAPPEARED
            opaque = _attribute_value(html, self.spec.listing_attribute)
            if opaque is None:
                raise GuardrailPause("selector_missing")
            fingerprint = "sha256:" + hashlib.sha256(opaque.encode()).hexdigest()
        else:
            raise GuardrailPause("unknown_verification_state")
        return VerificationResult(
            self.metadata.broker_id,
            status,
            listing_fingerprint=fingerprint,
        )

    def with_runtime_policy(
        self, *, automation_level: AutomationLevel, paused: bool
    ) -> "PeopleSearchFixtureAdapter":
        return PeopleSearchFixtureAdapter(
            replace(
                self.metadata,
                automation_level=automation_level,
                paused=paused,
            ),
            self.fixture_source,
            self.spec,
            transport=self.transport,
            finding_source=self.finding_source,
            runtime_guard=self.runtime_guard,
        )
