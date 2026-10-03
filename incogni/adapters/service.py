"""Side-effect-aware adapter contract for the autonomous service."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from incogni.models import AutomationLevel, FindingStatus, RequestStatus


class GuardrailPause(RuntimeError):
    """Raised when an operation must stop for operator review."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class BrokerMetadata:
    broker_id: str
    display_name: str
    flow_version: str
    automation_level: AutomationLevel
    rate_limit_per_hour: int
    required_identifiers: tuple[str, ...]
    verification_channel: str
    recheck_days: int
    privacy_url: str
    paused: bool = True
    expected_page_fingerprint: str | None = None


@dataclass(frozen=True)
class DiscoveryResult:
    broker_id: str
    status: FindingStatus
    listing_fingerprint: str | None = None
    matched_fields: tuple[str, ...] = ()
    reason_code: str | None = None


@dataclass(frozen=True)
class RemovalPlan:
    broker_id: str
    finding_id: str
    flow_version: str
    transport: str
    steps: tuple[str, ...]
    safety_flags: tuple[str, ...] = ()
    external_side_effects: bool = False


@dataclass(frozen=True)
class RequestResult:
    broker_id: str
    status: RequestStatus
    confirmation_id: str | None = None
    reason_code: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    broker_id: str
    status: FindingStatus
    listing_fingerprint: str | None = None
    reason_code: str | None = None


class ServiceBrokerAdapter(ABC):
    """Contract separating discovery, planning, execution, polling, and verification."""

    metadata: BrokerMetadata

    @abstractmethod
    def discover(self, profile_ref: str) -> DiscoveryResult:
        """Discover using a local encrypted profile reference."""

    @abstractmethod
    def prepare_removal(self, finding_id: str) -> RemovalPlan:
        """Build a side-effect-free removal plan."""

    @abstractmethod
    def execute(self, plan: RemovalPlan, approval_token: str | None) -> RequestResult:
        """Perform an externally visible operation only when guardrails permit it."""

    @abstractmethod
    def poll(self, request_id: str) -> RequestResult:
        """Poll a previously submitted request without creating a new one."""

    @abstractmethod
    def verify(self, finding_id: str) -> VerificationResult:
        """Check whether a historical finding remains visible."""
