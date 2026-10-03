"""Durable lease-based job queue."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from incogni.models import JobStatus
from incogni.storage import ServiceStore


def operation_idempotency_key(
    profile_id: str,
    broker_id: str,
    listing_fingerprint: str,
    flow_version: str,
    operation_type: str,
) -> str:
    values = [
        profile_id,
        broker_id,
        listing_fingerprint,
        flow_version,
        operation_type,
    ]
    if any(not value for value in values):
        raise ValueError("all idempotency dimensions are required")
    canonical = json.dumps(values, separators=(",", ":")).encode()
    return "operation:" + hashlib.sha256(canonical).hexdigest()


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    profile_id: str | None
    broker_id: str | None
    status: JobStatus
    payload: dict[str, Any]
    attempts: int
    max_attempts: int
    available_at: datetime
    lease_owner: str | None
    lease_expires_at: datetime | None


class DurableJobQueue:
    def __init__(
        self,
        store: ServiceStore,
        *,
        clock: Callable[[], datetime] = _default_clock,
        random_source: random.Random | None = None,
    ):
        self.store = store
        self.clock = clock
        self.random = random_source or random.Random()

    def enqueue(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        profile_id: str | None = None,
        broker_id: str | None = None,
        max_attempts: int = 5,
        available_at: datetime | None = None,
    ) -> str:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        existing = self.store.conn.execute(
            "SELECT id FROM jobs WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing:
            return existing["id"]
        job_id = uuid4().hex
        now = self.clock()
        envelope = self.store.crypto.encrypt_json(payload, aad=f"job:{job_id}".encode())
        try:
            self.store.conn.execute(
                "INSERT INTO jobs(id,kind,profile_id,broker_id,status,idempotency_key,"
                "encrypted_payload,max_attempts,available_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    job_id,
                    kind,
                    profile_id,
                    broker_id,
                    JobStatus.QUEUED.value,
                    idempotency_key,
                    envelope,
                    max_attempts,
                    (available_at or now).isoformat(),
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
        except Exception:
            existing = self.store.conn.execute(
                "SELECT id FROM jobs WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing:
                return existing["id"]
            raise
        return job_id

    def _row_to_job(self, row: Any) -> Job:
        return Job(
            id=row["id"],
            kind=row["kind"],
            profile_id=row["profile_id"],
            broker_id=row["broker_id"],
            status=JobStatus(row["status"]),
            payload=self.store.crypto.decrypt_json(
                row["encrypted_payload"], aad=f"job:{row['id']}".encode()
            ),
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            available_at=datetime.fromisoformat(row["available_at"]),
            lease_owner=row["lease_owner"],
            lease_expires_at=(
                datetime.fromisoformat(row["lease_expires_at"])
                if row["lease_expires_at"]
                else None
            ),
        )

    def get(self, job_id: str) -> Job | None:
        row = self.store.conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._row_to_job(row) if row else None

    def claim(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 300,
        kinds: set[str] | None = None,
    ) -> Job | None:
        if not worker_id or lease_seconds < 1:
            raise ValueError("worker_id and a positive lease are required")
        if kinds is not None and not kinds:
            return None
        now = self.clock()
        with self.store.transaction(immediate=True) as conn:
            expired = conn.execute(
                "SELECT id,attempts,max_attempts FROM jobs "
                "WHERE status='leased' AND lease_expires_at<=?",
                (now.isoformat(),),
            ).fetchall()
            for row in expired:
                status = (
                    JobStatus.DEAD.value
                    if row["attempts"] >= row["max_attempts"]
                    else JobStatus.RETRY_WAIT.value
                )
                conn.execute(
                    "UPDATE jobs SET status=?,available_at=?,lease_owner=NULL,"
                    "lease_expires_at=NULL,updated_at=? WHERE id=?",
                    (status, now.isoformat(), now.isoformat(), row["id"]),
                )
            kind_clause = ""
            parameters: list[str] = [now.isoformat()]
            if kinds is not None:
                placeholders = ",".join("?" for _ in kinds)
                kind_clause = f"AND j.kind IN ({placeholders}) "
                parameters.extend(sorted(kinds))
            row = conn.execute(
                "SELECT j.* FROM jobs j WHERE j.status IN ('queued','retry_wait') "
                "AND j.available_at<=? " + kind_clause +
                "AND NOT EXISTS (SELECT 1 FROM approvals gate "
                "WHERE gate.job_id=j.id AND gate.status NOT IN ('used','expired')) "
                "AND (EXISTS (SELECT 1 FROM approvals permit "
                "WHERE permit.job_id=j.id AND permit.status='used') "
                "OR (j.kind NOT IN "
                "('broker_browser_operation','open_verification_link','execute_removal') "
                "AND NOT EXISTS (SELECT 1 FROM approvals expired "
                "WHERE expired.job_id=j.id))) "
                "AND NOT EXISTS (SELECT 1 FROM jobs active "
                "WHERE active.status='leased' AND active.id<>j.id "
                "AND active.profile_id IS j.profile_id AND active.broker_id IS j.broker_id) "
                "ORDER BY j.available_at,j.created_at LIMIT 1",
                tuple(parameters),
            ).fetchone()
            if row is None:
                return None
            lease_until = now + timedelta(seconds=lease_seconds)
            conn.execute(
                "UPDATE jobs SET status=?,attempts=attempts+1,lease_owner=?,"
                "lease_expires_at=?,updated_at=? WHERE id=?",
                (
                    JobStatus.LEASED.value,
                    worker_id,
                    lease_until.isoformat(),
                    now.isoformat(),
                    row["id"],
                ),
            )
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
        return self._row_to_job(row)

    def succeed(self, job_id: str, worker_id: str) -> None:
        self._finish(job_id, worker_id, JobStatus.SUCCEEDED)

    def block(self, job_id: str, worker_id: str, error_code: str) -> None:
        self._finish(job_id, worker_id, JobStatus.BLOCKED, error_code)

    def _finish(
        self, job_id: str, worker_id: str, status: JobStatus, error_code: str | None = None
    ) -> None:
        now = self.clock().isoformat()
        cursor = self.store.conn.execute(
            "UPDATE jobs SET status=?,lease_owner=NULL,lease_expires_at=NULL,"
            "last_error_code=?,updated_at=? WHERE id=? AND status='leased' "
            "AND lease_owner=?",
            (status.value, error_code, now, job_id, worker_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("job is not leased by this worker")

    def fail(
        self,
        job_id: str,
        worker_id: str,
        error_code: str,
        *,
        base_delay_seconds: float = 30.0,
    ) -> JobStatus:
        job = self.get(job_id)
        if job is None or job.status is not JobStatus.LEASED or job.lease_owner != worker_id:
            raise ValueError("job is not leased by this worker")
        now = self.clock()
        if job.attempts >= job.max_attempts:
            status = JobStatus.DEAD
            available = now
        else:
            status = JobStatus.RETRY_WAIT
            jitter = self.random.uniform(0, max(base_delay_seconds, 0))
            delay = max(base_delay_seconds, 0) * (2 ** (job.attempts - 1)) + jitter
            available = now + timedelta(seconds=delay)
        cursor = self.store.conn.execute(
            "UPDATE jobs SET status=?,available_at=?,lease_owner=NULL,"
            "lease_expires_at=NULL,last_error_code=?,updated_at=? WHERE id=? "
            "AND status='leased' AND lease_owner=?",
            (
                status.value,
                available.isoformat(),
                error_code,
                now.isoformat(),
                job_id,
                worker_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("job lease changed before failure was recorded")
        return status

    def retry(self, job_id: str) -> None:
        now = self.clock().isoformat()
        cursor = self.store.conn.execute(
            "UPDATE jobs SET status='queued',attempts=0,available_at=?,"
            "lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,updated_at=? "
            "WHERE id=? AND status IN ('blocked','dead','retry_wait') "
            "AND NOT EXISTS (SELECT 1 FROM approvals WHERE job_id=jobs.id)",
            (now, now, job_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("job is not retryable")
