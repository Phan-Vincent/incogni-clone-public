"""Fixture-first guarded adapter platform.

This module has no production network transport. Broker definitions remain paused and
monitor-only until fixture tests, a synthetic canary, and a human-reviewed run have all
been recorded outside model context.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from html.parser import HTMLParser
from typing import Callable, Protocol

from incogni.adapters.service import (
    BrokerMetadata,
    DiscoveryResult,
    GuardrailPause,
    RemovalPlan,
    RequestResult,
    ServiceBrokerAdapter,
    VerificationResult,
)
from incogni.models import AutomationLevel, FindingStatus, RequestStatus

_SAFETY_PATTERNS = {
    "captcha": re.compile(r"captcha|recaptcha|hcaptcha", re.IGNORECASE),
    "identity_document": re.compile(
        r"(upload|submit).{0,40}(driver.?s license|passport|identity document|photo id)",
        re.IGNORECASE | re.DOTALL,
    ),
    "paywall": re.compile(r"subscribe|payment required|credit card", re.IGNORECASE),
    "authentication": re.compile(r"sign in required|log in to continue", re.IGNORECASE),
    "terms_changed": re.compile(r"terms (?:have )?(?:changed|updated)", re.IGNORECASE),
}


class _ShapeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.shape: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        safe = {"id", "name", "type", "role", "action", "method"}
        selected = sorted((key, value or "") for key, value in attrs if key in safe)
        self.shape.append(repr((tag, selected)))


def page_fingerprint(html: str) -> str:
    parser = _ShapeParser()
    parser.feed(html)
    payload = "\n".join(parser.shape).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def safety_flags(html: str) -> tuple[str, ...]:
    return tuple(code for code, pattern in _SAFETY_PATTERNS.items() if pattern.search(html))


class FixtureSource(Protocol):
    def __call__(self, broker_id: str, reference: str, operation: str) -> str: ...


class RuntimeGuard(Protocol):
    def acquire(self, broker_id: str, *, per_hour: int) -> None: ...
    def record_success(self, broker_id: str) -> None: ...
    def record_failure(self, broker_id: str) -> None: ...


class ExecutionTransport(Protocol):
    name: str

    def execute(self, plan: RemovalPlan) -> RequestResult: ...


class DisabledTransport:
    name = "disabled"

    def execute(self, plan: RemovalPlan) -> RequestResult:
        raise GuardrailPause("live_transport_disabled")


class GuardedFixtureAdapter(ServiceBrokerAdapter):
    """Adapter that can discover/verify sanitized fixtures and never defaults live."""

    def __init__(
        self,
        metadata: BrokerMetadata,
        fixture_source: FixtureSource,
        *,
        transport: ExecutionTransport | None = None,
        finding_source: Callable[[str], dict[str, str] | None] | None = None,
        runtime_guard: RuntimeGuard | None = None,
    ):
        self.metadata = metadata
        self.fixture_source = fixture_source
        self.transport = transport or DisabledTransport()
        self.finding_source = finding_source or (lambda _finding_id: None)
        self.runtime_guard = runtime_guard

    def _inspect(self, reference: str, operation: str) -> tuple[str, tuple[str, ...]]:
        html = self.fixture_source(self.metadata.broker_id, reference, operation)
        flags = safety_flags(html)
        if flags:
            raise GuardrailPause(flags[0])
        fingerprint = page_fingerprint(html)
        expected = self.metadata.expected_page_fingerprint
        if expected and expected != fingerprint:
            raise GuardrailPause("page_fingerprint_changed")
        return html, flags

    def discover(self, profile_ref: str) -> DiscoveryResult:
        html, _ = self._inspect(profile_ref, "discover")
        if 'data-result="ambiguous"' in html:
            return DiscoveryResult(
                self.metadata.broker_id,
                FindingStatus.AMBIGUOUS,
                reason_code="ambiguous_identity",
            )
        if 'data-result="match"' not in html:
            return DiscoveryResult(self.metadata.broker_id, FindingStatus.NOT_FOUND)
        listing = re.search(r'data-listing-id="([^"]+)"', html)
        opaque = listing.group(1) if listing else page_fingerprint(html)
        listing_fingerprint = "sha256:" + hashlib.sha256(opaque.encode()).hexdigest()
        return DiscoveryResult(
            self.metadata.broker_id,
            FindingStatus.CANDIDATE,
            listing_fingerprint=listing_fingerprint,
        )

    def prepare_removal(self, finding_id: str) -> RemovalPlan:
        finding = self.finding_source(finding_id)
        flags: tuple[str, ...] = ()
        if finding is None:
            flags = ("finding_requires_local_lookup",)
        return RemovalPlan(
            broker_id=self.metadata.broker_id,
            finding_id=finding_id,
            flow_version=self.metadata.flow_version,
            transport=self.transport.name,
            steps=("open_privacy_form", "populate_locally", "submit", "await_verification"),
            safety_flags=flags,
            external_side_effects=False,
        )

    def execute(self, plan: RemovalPlan, approval_token: str | None) -> RequestResult:
        if plan.broker_id != self.metadata.broker_id:
            raise GuardrailPause("broker_mismatch")
        if plan.flow_version != self.metadata.flow_version:
            raise GuardrailPause("flow_version_changed")
        if plan.external_side_effects:
            raise GuardrailPause("unsafe_plan")
        if plan.safety_flags:
            raise GuardrailPause(plan.safety_flags[0])
        if self.metadata.paused:
            raise GuardrailPause("broker_paused")
        if self.metadata.automation_level is AutomationLevel.MONITOR_ONLY:
            raise GuardrailPause("monitor_only")
        if (
            self.metadata.automation_level is AutomationLevel.APPROVAL_REQUIRED
            and not approval_token
        ):
            raise GuardrailPause("approval_required")
        if self.runtime_guard is None:
            raise GuardrailPause("runtime_guard_required")
        self.runtime_guard.acquire(
            self.metadata.broker_id,
            per_hour=self.metadata.rate_limit_per_hour,
        )
        try:
            result = self.transport.execute(plan)
        except Exception:
            self.runtime_guard.record_failure(self.metadata.broker_id)
            raise
        self.runtime_guard.record_success(self.metadata.broker_id)
        return result

    def poll(self, request_id: str) -> RequestResult:
        self._inspect(request_id, "poll")
        return RequestResult(self.metadata.broker_id, RequestStatus.PROCESSING)

    def verify(self, finding_id: str) -> VerificationResult:
        html, _ = self._inspect(finding_id, "verify")
        status = (
            FindingStatus.REAPPEARED
            if 'data-result="match"' in html
            else FindingStatus.SUPPRESSED
        )
        return VerificationResult(
            self.metadata.broker_id,
            status,
            listing_fingerprint=page_fingerprint(html),
        )

    def with_runtime_policy(
        self, *, automation_level: AutomationLevel, paused: bool
    ) -> "GuardedFixtureAdapter":
        return GuardedFixtureAdapter(
            replace(self.metadata, automation_level=automation_level, paused=paused),
            self.fixture_source,
            transport=self.transport,
            finding_source=self.finding_source,
            runtime_guard=self.runtime_guard,
        )


LIVE_BROKERS: tuple[BrokerMetadata, ...] = (
    BrokerMetadata(
        "spokeo", "Spokeo", "2026-09-manual-1", AutomationLevel.MONITOR_ONLY,
        6, ("name", "location", "email"), "email_link", 30,
        "https://www.spokeo.com/optout",
    ),
    BrokerMetadata(
        "mylife", "MyLife", "2026-08-monitor-1", AutomationLevel.MONITOR_ONLY,
        4, ("name", "location"), "email_link", 30,
        "https://www.mylife.com/privacy-policy",
    ),
    BrokerMetadata(
        "whitepages", "Whitepages", "2026-08-monitor-1", AutomationLevel.MONITOR_ONLY,
        4, ("name", "location", "phone"), "email_link", 30,
        "https://www.whitepages.com/suppression-requests",
    ),
    BrokerMetadata(
        "beenverified", "BeenVerified", "2026-08-monitor-2", AutomationLevel.MONITOR_ONLY,
        4, ("name", "location"), "email_link", 30,
        "https://www.beenverified.com/svc/optout/search/optouts",
    ),
    BrokerMetadata(
        "intelius", "Intelius", "2026-08-monitor-2", AutomationLevel.MONITOR_ONLY,
        4, ("name", "location"), "email_link", 30,
        "https://suppression.peopleconnect.us/",
    ),
)

LIVE_BROKER_BY_ID = {broker.broker_id: broker for broker in LIVE_BROKERS}


def seed_live_broker_flows(store) -> None:
    """Seed metadata and fail closed when a version changes."""

    from incogni.storage import utciso

    now = utciso()
    for metadata in LIVE_BROKERS:
        store.conn.execute(
            "INSERT INTO broker_flows(broker_id,flow_version,automation_level,paused,"
            "page_fingerprint,updated_at,monitor_since) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(broker_id) DO UPDATE SET "
            "automation_level=CASE WHEN broker_flows.flow_version<>excluded.flow_version "
            "THEN 'monitor_only' ELSE broker_flows.automation_level END,"
            "paused=CASE WHEN broker_flows.flow_version<>excluded.flow_version "
            "THEN 1 ELSE broker_flows.paused END,"
            "terms_reviewed_at=CASE WHEN broker_flows.flow_version<>excluded.flow_version "
            "THEN NULL ELSE broker_flows.terms_reviewed_at END,"
            "synthetic_canary_at=CASE WHEN broker_flows.flow_version<>excluded.flow_version "
            "THEN NULL ELSE broker_flows.synthetic_canary_at END,"
            "human_reviewed_run_at=CASE WHEN broker_flows.flow_version<>excluded.flow_version "
            "THEN NULL ELSE broker_flows.human_reviewed_run_at END,"
            "monitor_since=CASE WHEN broker_flows.flow_version<>excluded.flow_version "
            "THEN excluded.monitor_since ELSE COALESCE(broker_flows.monitor_since,"
            "excluded.monitor_since) END,"
            "flow_version=excluded.flow_version,"
            "page_fingerprint=excluded.page_fingerprint,updated_at=excluded.updated_at",
            (
                metadata.broker_id,
                metadata.flow_version,
                metadata.automation_level.value,
                int(metadata.paused),
                metadata.expected_page_fingerprint,
                now,
                now,
            ),
        )
