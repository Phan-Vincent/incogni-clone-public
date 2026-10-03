"""Operator-performed removal flows for brokers that must not be automated.

The service never contacts these brokers. After an approval releases a removal
request, the operator receives a checklist, completes the broker's flow in their own
browser, and records each step here. The service tracks the request, reminds the
operator before a verification link expires, and schedules recheck reminders. It
stores no listing URL, email address, or other value the operator typed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from incogni.adapters.guarded import LIVE_BROKER_BY_ID
from incogni.approvals import ApprovalManager
from incogni.jobs import DurableJobQueue, Job
from incogni.models import AutomationLevel, FindingStatus, RequestStatus
from incogni.storage import ServiceStore


@dataclass(frozen=True)
class ManualFlow:
    broker_id: str
    flow_version: str
    opt_out_url: str
    terms_url: str
    terms_last_updated: str
    steps: tuple[str, ...]
    verification_window: timedelta
    reminder_lead: timedelta


MANUAL_FLOWS: dict[str, ManualFlow] = {
    "spokeo": ManualFlow(
        broker_id="spokeo",
        flow_version=LIVE_BROKER_BY_ID["spokeo"].flow_version,
        opt_out_url=LIVE_BROKER_BY_ID["spokeo"].privacy_url,
        terms_url="https://www.spokeo.com/terms-of-use",
        terms_last_updated="2022-10-26",
        steps=(
            "In your own browser, search spokeo.com for the listing that matches "
            "this finding and copy the listing's URL.",
            "Open https://www.spokeo.com/optout, paste the listing URL, and enter "
            "an email address you can read (a masked alias is fine).",
            "Complete the CAPTCHA yourself and submit the form, then record the "
            "'submitted' step here.",
            "Open the confirmation link Spokeo emails you within 72 hours, then "
            "record the 'verified' step here.",
            "Removal usually takes 24-72 hours. Once the listing no longer appears, "
            "record the 'confirmed' step here.",
        ),
        verification_window=timedelta(hours=72),
        reminder_lead=timedelta(hours=24),
    ),
}

MANUAL_BROKER_IDS = frozenset(MANUAL_FLOWS)
MANUAL_STEPS = ("submitted", "verified", "confirmed", "restart")
EXPIRED_LINK_CODE = "verification_link_expired"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ManualAssist:
    def __init__(
        self,
        store: ServiceStore,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ):
        self.store = store
        self.clock = clock
        self.queue = DurableJobQueue(store, clock=clock)

    def record_found(
        self,
        broker_id: str,
        *,
        profile_id: str = "owner",
        additional: bool = False,
    ) -> dict[str, str]:
        """Create the guarded request that begins an operator-performed flow."""

        flow = MANUAL_FLOWS.get(broker_id)
        if flow is None:
            raise ValueError("broker does not use an operator-performed flow")

        with self.store.transaction(immediate=True) as conn:
            broker = conn.execute(
                "SELECT flow_version,automation_level FROM broker_flows "
                "WHERE broker_id=?",
                (broker_id,),
            ).fetchone()
            if broker is None:
                raise KeyError(broker_id)
            if broker["flow_version"] != flow.flow_version:
                raise ValueError(
                    "broker flow version changed; review before recording a finding"
                )
            if broker["automation_level"] == AutomationLevel.MONITOR_ONLY.value:
                raise ValueError("broker flow is monitor-only")

            if self.store.get_profile(profile_id) is None:
                self.store.create_profile(profile_id, {"manual_intake": True})

            if not additional:
                open_request = conn.execute(
                    "SELECT 1 FROM removal_requests r "
                    "JOIN findings f ON f.id=r.finding_id "
                    "WHERE f.profile_id=? AND f.broker_id=? "
                    "AND r.status NOT IN ('confirmed','cancelled','failed') LIMIT 1",
                    (profile_id, broker_id),
                ).fetchone()
                if open_request is not None:
                    raise ValueError("profile and broker already have an open request")

            fingerprint = "manual:" + hashlib.sha256(uuid4().hex.encode()).hexdigest()
            finding_id = self.store.upsert_finding(
                profile_id=profile_id,
                broker_id=broker_id,
                status=FindingStatus.CONFIRMED_MATCH,
                listing_fingerprint=fingerprint,
                flow_version=flow.flow_version,
            )
            request_id = self.store.create_removal_request(finding_id)
            approval_id = ApprovalManager(self.store).create(
                "submit_removal", request_id=request_id
            )
            self.store.record_audit(
                "manual_finding_recorded",
                "request",
                request_id,
                json.dumps({"broker_id": broker_id}, separators=(",", ":")),
            )

        return {
            "finding_id": finding_id,
            "request_id": request_id,
            "approval_id": approval_id,
            "broker_id": broker_id,
        }

    def _context(self, request_id: str):
        row = self.store.conn.execute(
            "SELECT r.status,f.profile_id,f.broker_id,f.flow_version finding_flow,"
            "b.flow_version,b.automation_level,b.paused "
            "FROM removal_requests r JOIN findings f ON f.id=r.finding_id "
            "LEFT JOIN broker_flows b ON b.broker_id=f.broker_id WHERE r.id=?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise KeyError(request_id)
        flow = MANUAL_FLOWS.get(row["broker_id"])
        if flow is None:
            raise ValueError("broker does not use an operator-performed flow")
        return row, flow

    @staticmethod
    def _require_status(row, *allowed: RequestStatus) -> None:
        if RequestStatus(row["status"]) not in allowed:
            raise ValueError(
                "request is not in a state that allows this step: " + row["status"]
            )

    def _submission_count(self, request_id: str) -> int:
        return self.store.conn.execute(
            "SELECT count(*) FROM attempts WHERE request_id=? AND outcome=?",
            (request_id, RequestStatus.SUBMITTED.value),
        ).fetchone()[0]

    def checklist(self, request_id: str) -> dict[str, Any]:
        row, flow = self._context(request_id)
        self._require_status(row, RequestStatus.READY)
        if row["flow_version"] != flow.flow_version or (
            row["finding_flow"] != flow.flow_version
        ):
            raise ValueError("broker flow version changed; review before continuing")
        if row["automation_level"] != AutomationLevel.APPROVAL_REQUIRED.value:
            raise ValueError("broker flow is not approval-required")
        if row["paused"]:
            raise ValueError("broker flow is paused")
        if self.store.get_setting("emergency_stop", "false") == "true":
            raise ValueError("emergency stop is engaged")
        self.store.record_audit("manual_checklist_issued", "request", request_id)
        return {
            "request_id": request_id,
            "broker_id": flow.broker_id,
            "flow_version": flow.flow_version,
            "opt_out_url": flow.opt_out_url,
            "steps": list(flow.steps),
            "verification_window_hours": int(
                flow.verification_window.total_seconds() // 3600
            ),
        }

    def record(self, request_id: str, step: str) -> str:
        """Record one operator-performed step and return the request's new status."""

        handlers = {
            "submitted": self._record_submitted,
            "verified": self._record_verified,
            "confirmed": self._record_confirmed,
            "restart": self._record_restart,
        }
        handler = handlers.get(step)
        if handler is None:
            raise ValueError("unknown manual step")
        with self.store.transaction(immediate=True):
            row, flow = self._context(request_id)
            status = handler(request_id, row, flow)
            self.store.record_audit(
                f"manual_step_{step}",
                "request",
                request_id,
                json.dumps({"broker_id": flow.broker_id}, separators=(",", ":")),
            )
        return status.value

    def _record_submitted(self, request_id, row, flow) -> RequestStatus:
        self._require_status(row, RequestStatus.READY)
        self.store.transition_request(request_id, RequestStatus.SUBMITTED)
        self.store.transition_request(
            request_id, RequestStatus.VERIFICATION_REQUIRED
        )
        submission = self._submission_count(request_id)
        now = self.clock()
        payload = {"request_id": request_id, "submission": submission}
        scope = {"profile_id": row["profile_id"], "broker_id": flow.broker_id}
        self.queue.enqueue(
            "manual_verification_reminder",
            payload,
            idempotency_key=f"manual-verify-reminder:{request_id}:{submission}",
            available_at=now + flow.verification_window - flow.reminder_lead,
            **scope,
        )
        self.queue.enqueue(
            "manual_verification_expiry",
            payload,
            idempotency_key=f"manual-verify-expiry:{request_id}:{submission}",
            available_at=now + flow.verification_window,
            **scope,
        )
        return RequestStatus.VERIFICATION_REQUIRED

    def _record_verified(self, request_id, row, _flow) -> RequestStatus:
        self._require_status(row, RequestStatus.VERIFICATION_REQUIRED)
        self.store.transition_request(request_id, RequestStatus.PROCESSING)
        return RequestStatus.PROCESSING

    def _record_confirmed(self, request_id, row, _flow) -> RequestStatus:
        self._require_status(row, RequestStatus.PROCESSING)
        self.store.transition_request(request_id, RequestStatus.CONFIRMED)
        return RequestStatus.CONFIRMED

    def _record_restart(self, request_id, row, _flow) -> RequestStatus:
        self._require_status(row, RequestStatus.FAILED)
        last = self.store.conn.execute(
            "SELECT error_code FROM attempts WHERE request_id=? "
            "ORDER BY id DESC LIMIT 1",
            (request_id,),
        ).fetchone()
        if last is None or last["error_code"] != EXPIRED_LINK_CODE:
            raise ValueError("only an expired verification link can be restarted")
        self.store.transition_request(request_id, RequestStatus.READY)
        return RequestStatus.READY


def manual_assist_handlers(
    store: ServiceStore, notify: Callable[[str], None]
) -> dict[str, Callable[[Job], None]]:
    """Worker handlers for reminders; none of them contacts a broker."""

    def awaiting_submission(job: Job) -> str | None:
        request_id = job.payload.get("request_id")
        submission = job.payload.get("submission")
        if not isinstance(request_id, str) or not isinstance(submission, int):
            return None
        row = store.conn.execute(
            "SELECT status FROM removal_requests WHERE id=?", (request_id,)
        ).fetchone()
        if row is None or row["status"] != RequestStatus.VERIFICATION_REQUIRED.value:
            return None
        current = store.conn.execute(
            "SELECT count(*) FROM attempts WHERE request_id=? AND outcome=?",
            (request_id, RequestStatus.SUBMITTED.value),
        ).fetchone()[0]
        return request_id if current == submission else None

    def verification_reminder(job: Job) -> None:
        if awaiting_submission(job) is not None:
            notify("manual_verification_reminder")

    def verification_expiry(job: Job) -> None:
        with store.transaction(immediate=True):
            request_id = awaiting_submission(job)
            if request_id is None:
                return
            store.transition_request(
                request_id,
                RequestStatus.FAILED,
                job_id=job.id,
                error_code=EXPIRED_LINK_CODE,
            )
            notify("manual_verification_expired")

    def recheck_reminder(_job: Job) -> None:
        notify("manual_recheck_reminder")

    return {
        "manual_verification_reminder": verification_reminder,
        "manual_verification_expiry": verification_expiry,
        "manual_recheck_reminder": recheck_reminder,
    }
