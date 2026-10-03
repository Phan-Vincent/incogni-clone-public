"""Core domain types shared across the app.

These are plain dataclasses and enums so they can be serialized to JSON and
stored in the tracker database without any external dependencies.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    """A timezone-aware UTC timestamp (used so results are always comparable)."""
    return datetime.now(timezone.utc)


class OptOutMethod(str, enum.Enum):
    """How a broker accepts removal requests."""

    FORM = "form"      # fill out an online opt-out form
    EMAIL = "email"    # send an email to a support/privacy address
    API = "api"        # programmatic / authorized-agent API
    UNKNOWN = "unknown"


class ScanStatus(str, enum.Enum):
    """Outcome of a single broker scan."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    SKIPPED = "skipped"  # not enough profile data to attempt the scan


class OptOutStatus(str, enum.Enum):
    """Lifecycle of a removal request against one broker."""

    NOT_NEEDED = "not_needed"  # no record found, so nothing to remove
    PENDING = "pending"        # detected, request not yet submitted
    SUBMITTED = "submitted"    # request sent, awaiting confirmation
    CONFIRMED = "confirmed"    # broker confirmed removal
    FAILED = "failed"          # submission error


class FindingStatus(str, enum.Enum):
    NOT_FOUND = "not_found"
    CANDIDATE = "candidate"
    CONFIRMED_MATCH = "confirmed_match"
    AMBIGUOUS = "ambiguous"
    SUPPRESSED = "suppressed"
    REAPPEARED = "reappeared"
    ERROR = "error"


class RequestStatus(str, enum.Enum):
    AWAITING_APPROVAL = "awaiting_approval"
    READY = "ready"
    SUBMITTED = "submitted"
    VERIFICATION_REQUIRED = "verification_required"
    PROCESSING = "processing"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    LEASED = "leased"
    RETRY_WAIT = "retry_wait"
    BLOCKED = "blocked"
    SUCCEEDED = "succeeded"
    DEAD = "dead"


class AutomationLevel(str, enum.Enum):
    MONITOR_ONLY = "monitor_only"
    APPROVAL_REQUIRED = "approval_required"
    AUTOMATIC = "automatic"


@dataclass
class ScanResult:
    broker_id: str
    status: ScanStatus
    matched_fields: list[str] = field(default_factory=list)
    detail: str = ""
    scanned_at: datetime = field(default_factory=utcnow)

    @property
    def found(self) -> bool:
        return self.status is ScanStatus.FOUND

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["scanned_at"] = self.scanned_at.isoformat()
        return d


@dataclass
class OptOutResult:
    broker_id: str
    status: OptOutStatus
    confirmation_id: str | None = None
    message: str = ""
    submitted_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["submitted_at"] = self.submitted_at.isoformat()
        return d
