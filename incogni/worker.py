"""Durable worker loop with an explicit handler registry."""

from __future__ import annotations

import time
from collections.abc import Callable
from uuid import uuid4

from incogni.adapters.service import GuardrailPause
from incogni.jobs import DurableJobQueue, Job
from incogni.models import JobStatus
from incogni.storage import ServiceStore, utciso

JobHandler = Callable[[Job], None]


class ServiceWorker:
    def __init__(
        self,
        store: ServiceStore,
        worker_id: str,
        handlers: dict[str, JobHandler] | None = None,
        *,
        claim_kinds: set[str] | None = None,
    ):
        self.store = store
        self.worker_id = worker_id
        self.queue = DurableJobQueue(store)
        self.handlers = handlers or {}
        self.claim_kinds = claim_kinds

    def _notify(self, kind: str) -> None:
        self.store.conn.execute(
            "INSERT INTO notifications(id,kind,status,created_at) VALUES(?,?,?,?)",
            (uuid4().hex, kind, "pending", utciso()),
        )

    def run_once(self) -> JobStatus | None:
        if self.store.get_setting("emergency_stop", "false") == "true":
            return JobStatus.BLOCKED
        job = self.queue.claim(self.worker_id, kinds=self.claim_kinds)
        if job is None:
            return None
        handler = self.handlers.get(job.kind)
        if handler is None:
            self.queue.block(job.id, self.worker_id, "unknown_job_kind")
            self._notify("job_blocked")
            return JobStatus.BLOCKED
        try:
            handler(job)
        except PermissionError:
            self.queue.block(job.id, self.worker_id, "approval_required")
            self._notify("approval_required")
            return JobStatus.BLOCKED
        except GuardrailPause as exc:
            self.queue.block(job.id, self.worker_id, exc.reason_code)
            self._notify("guardrail_blocked")
            return JobStatus.BLOCKED
        except Exception:
            status = self.queue.fail(job.id, self.worker_id, "handler_failed")
            if status is JobStatus.DEAD:
                self._notify("job_dead_letter")
            return status
        self.queue.succeed(job.id, self.worker_id)
        return JobStatus.SUCCEEDED

    def run_forever(self, *, poll_seconds: float = 2.0) -> None:
        while True:
            result = self.run_once()
            if result is None or result is JobStatus.BLOCKED:
                time.sleep(poll_seconds)
