"""One-time operator approvals for guarded actions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from incogni.models import RequestStatus
from incogni.storage import ServiceStore


class ApprovalManager:
    REQUEST_ACTION = "submit_removal"

    def __init__(self, store: ServiceStore):
        self.store = store

    def _validate_target(
        self,
        conn,
        *,
        action: str,
        request_id: str | None,
        job_id: str | None,
    ) -> None:
        if job_id is not None:
            target = conn.execute(
                "SELECT kind,status,last_error_code FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if target is None:
                raise ValueError("approval target job is missing")
            if target["kind"] != action:
                raise ValueError("approval action does not match job kind")
            if target["status"] == "queued":
                return
            if (
                target["status"] == "blocked"
                and target["last_error_code"] == "approval_required"
            ):
                return
            raise ValueError("approval target job is not awaiting approval")

        if action != self.REQUEST_ACTION:
            raise ValueError("approval action does not match request action")
        target = conn.execute(
            "SELECT status FROM removal_requests WHERE id=?", (request_id,)
        ).fetchone()
        if target is None:
            raise ValueError("approval target request is missing")
        if target["status"] != "awaiting_approval":
            raise ValueError("approval target request is not awaiting approval")

    def create(
        self,
        action: str,
        *,
        request_id: str | None = None,
        job_id: str | None = None,
        ttl: timedelta = timedelta(days=7),
    ) -> str:
        if bool(request_id) == bool(job_id):
            raise ValueError("exactly one request_id or job_id is required")
        if not action or ttl <= timedelta(0):
            raise ValueError("action and a positive ttl are required")
        conn = self.store.conn
        if not conn.in_transaction:
            with self.store.transaction(immediate=True):
                return self.create(
                    action, request_id=request_id, job_id=job_id, ttl=ttl
                )

        self._validate_target(
            conn, action=action, request_id=request_id, job_id=job_id
        )
        now = datetime.now(timezone.utc)
        target_column = "job_id" if job_id is not None else "request_id"
        target_id = job_id if job_id is not None else request_id
        existing = conn.execute(
            f"SELECT id,action,status,expires_at FROM approvals WHERE {target_column}=?",
            (target_id,),
        ).fetchall()
        stale = []
        for row in existing:
            if row["action"] != action:
                raise ValueError("approval target is bound to another action")
            if row["status"] in {"rejected", "used"}:
                raise ValueError("approval target already has a decided approval")
            if row["status"] in {"pending", "approved"}:
                if row["expires_at"] > now.isoformat():
                    return row["id"]
                stale.append(row["id"])
        # An undecided approval that outlived its ttl must not strand its target:
        # retire it and issue a fresh one.
        for stale_id in stale:
            conn.execute(
                "UPDATE approvals SET status='expired' WHERE id=?", (stale_id,)
            )
            self.store.record_audit("approval_expired", "approval", stale_id)

        approval_id = uuid4().hex
        approval_fingerprint = hashlib.sha256(approval_id.encode()).hexdigest()
        conn.execute(
            "INSERT INTO approvals(id,request_id,job_id,action,token_hash,status,"
            "expires_at,created_at) VALUES(?,?,?,?,?,'pending',?,?)",
            (
                approval_id,
                request_id,
                job_id,
                action,
                approval_fingerprint,
                (now + ttl).isoformat(),
                now.isoformat(),
            ),
        )
        return approval_id

    def reissue(self, approval_id: str, *, ttl: timedelta = timedelta(days=7)) -> str:
        """Replace an approval that expired undecided; return the live approval id."""

        now = datetime.now(timezone.utc).isoformat()
        with self.store.transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT request_id,job_id,action,status,expires_at FROM approvals "
                "WHERE id=?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise ValueError("approval is missing")
            if row["status"] in {"rejected", "used"}:
                raise ValueError("approval is already decided")
            if row["status"] != "expired" and row["expires_at"] > now:
                raise ValueError("approval has not expired")
            replacement = self.create(
                row["action"],
                request_id=row["request_id"],
                job_id=row["job_id"],
                ttl=ttl,
            )
            self.store.record_audit(
                "approval_reissued",
                "approval",
                replacement,
                json.dumps({"replaces": approval_id}, separators=(",", ":")),
            )
            return replacement

    def _pending(self, conn, approval_id: str, now: str):
        row = conn.execute(
            "SELECT request_id,job_id,action,status,expires_at FROM approvals "
            "WHERE id=?",
            (approval_id,),
        ).fetchone()
        if (
            row is None
            or row["status"] != "pending"
            or row["expires_at"] <= now
        ):
            raise ValueError("approval is missing, expired, or already decided")
        self._validate_target(
            conn,
            action=row["action"],
            request_id=row["request_id"],
            job_id=row["job_id"],
        )
        return row

    def decide(self, approval_id: str, *, approved: bool) -> None:
        now = datetime.now(timezone.utc).isoformat()
        status = "approved" if approved else "rejected"
        with self.store.transaction(immediate=True) as conn:
            self._pending(conn, approval_id, now)
            cursor = conn.execute(
                "UPDATE approvals SET status=? WHERE id=? AND status='pending' "
                "AND expires_at>?",
                (status, approval_id, now),
            )
            if cursor.rowcount != 1:
                raise ValueError("approval changed while it was being decided")
            self.store.record_audit(
                f"approval_{status}", "approval", approval_id
            )

    def decide_and_release(self, approval_id: str, *, approved: bool) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.store.transaction(immediate=True) as conn:
            row = self._pending(conn, approval_id, now)
            if approved:
                if row["job_id"] is not None:
                    cursor = conn.execute(
                        "UPDATE jobs SET status='queued',attempts=0,available_at=?,"
                        "lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,"
                        "updated_at=? WHERE id=? AND (status='queued' OR "
                        "(status='blocked' AND last_error_code='approval_required'))",
                        (now, now, row["job_id"]),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("approval target job changed before release")
                else:
                    self.store.transition_request(
                        row["request_id"], RequestStatus.READY
                    )
                cursor = conn.execute(
                    "UPDATE approvals SET status='used',used_at=? WHERE id=? "
                    "AND status='pending' AND expires_at>?",
                    (now, approval_id, now),
                )
                status = "approved"
            else:
                if row["job_id"] is not None:
                    cursor = conn.execute(
                        "UPDATE jobs SET status='blocked',last_error_code="
                        "'approval_rejected',lease_owner=NULL,lease_expires_at=NULL,"
                        "updated_at=? WHERE id=? AND (status='queued' OR "
                        "(status='blocked' AND last_error_code='approval_required'))",
                        (now, row["job_id"]),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("approval target job changed before rejection")
                else:
                    self.store.transition_request(
                        row["request_id"], RequestStatus.CANCELLED
                    )
                cursor = conn.execute(
                    "UPDATE approvals SET status='rejected' WHERE id=? "
                    "AND status='pending' AND expires_at>?",
                    (approval_id, now),
                )
                status = "rejected"
            if cursor.rowcount != 1:
                raise ValueError("approval changed while it was being decided")
            self.store.record_audit(
                f"approval_{status}", "approval", approval_id
            )

    def consume(self, approval_id: str, action: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self.store.transaction(immediate=True) as conn:
            cursor = conn.execute(
                "UPDATE approvals SET status='used',used_at=? WHERE id=? AND action=? "
                "AND status='approved' AND expires_at>?",
                (now, approval_id, action, now),
            )
            if cursor.rowcount != 1:
                return False
            self.store.record_audit("approval_used", "approval", approval_id)
            return True
