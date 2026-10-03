"""Explicit lifecycle transition validation."""

from __future__ import annotations

from enum import Enum
from typing import TypeVar

from incogni.models import FindingStatus, JobStatus, RequestStatus

State = TypeVar("State", bound=Enum)

FINDING_TRANSITIONS = {
    FindingStatus.NOT_FOUND: {FindingStatus.CANDIDATE, FindingStatus.ERROR},
    FindingStatus.CANDIDATE: {
        FindingStatus.CONFIRMED_MATCH,
        FindingStatus.AMBIGUOUS,
        FindingStatus.NOT_FOUND,
        FindingStatus.ERROR,
    },
    FindingStatus.CONFIRMED_MATCH: {
        FindingStatus.SUPPRESSED,
        FindingStatus.AMBIGUOUS,
        FindingStatus.ERROR,
    },
    FindingStatus.AMBIGUOUS: {
        FindingStatus.CONFIRMED_MATCH,
        FindingStatus.NOT_FOUND,
        FindingStatus.ERROR,
    },
    FindingStatus.SUPPRESSED: {FindingStatus.REAPPEARED, FindingStatus.ERROR},
    FindingStatus.REAPPEARED: {
        FindingStatus.CONFIRMED_MATCH,
        FindingStatus.SUPPRESSED,
        FindingStatus.ERROR,
    },
    FindingStatus.ERROR: {FindingStatus.CANDIDATE, FindingStatus.NOT_FOUND},
}

REQUEST_TRANSITIONS = {
    RequestStatus.AWAITING_APPROVAL: {
        RequestStatus.READY,
        RequestStatus.CANCELLED,
        RequestStatus.FAILED,
    },
    RequestStatus.READY: {
        RequestStatus.SUBMITTED,
        RequestStatus.CANCELLED,
        RequestStatus.FAILED,
    },
    RequestStatus.SUBMITTED: {
        RequestStatus.VERIFICATION_REQUIRED,
        RequestStatus.PROCESSING,
        RequestStatus.CONFIRMED,
        RequestStatus.FAILED,
    },
    RequestStatus.VERIFICATION_REQUIRED: {
        RequestStatus.PROCESSING,
        RequestStatus.CONFIRMED,
        RequestStatus.FAILED,
        RequestStatus.CANCELLED,
    },
    RequestStatus.PROCESSING: {
        RequestStatus.VERIFICATION_REQUIRED,
        RequestStatus.CONFIRMED,
        RequestStatus.FAILED,
    },
    RequestStatus.FAILED: {RequestStatus.READY, RequestStatus.CANCELLED},
    RequestStatus.CONFIRMED: set(),
    RequestStatus.CANCELLED: set(),
}

JOB_TRANSITIONS = {
    JobStatus.QUEUED: {JobStatus.LEASED, JobStatus.DEAD},
    JobStatus.LEASED: {
        JobStatus.RETRY_WAIT,
        JobStatus.BLOCKED,
        JobStatus.SUCCEEDED,
        JobStatus.DEAD,
    },
    JobStatus.RETRY_WAIT: {JobStatus.LEASED, JobStatus.DEAD},
    JobStatus.BLOCKED: {JobStatus.QUEUED, JobStatus.DEAD},
    JobStatus.DEAD: {JobStatus.QUEUED},
    JobStatus.SUCCEEDED: set(),
}


def ensure_transition(current: State, target: State, transitions: dict[State, set[State]]) -> None:
    if current == target:
        return
    if target not in transitions.get(current, set()):
        raise ValueError(f"invalid transition: {current.value} -> {target.value}")


def ensure_finding_transition(current: FindingStatus, target: FindingStatus) -> None:
    ensure_transition(current, target, FINDING_TRANSITIONS)


def ensure_request_transition(current: RequestStatus, target: RequestStatus) -> None:
    ensure_transition(current, target, REQUEST_TRANSITIONS)


def ensure_job_transition(current: JobStatus, target: JobStatus) -> None:
    ensure_transition(current, target, JOB_TRANSITIONS)
