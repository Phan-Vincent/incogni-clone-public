"""Human-guided California DROP companion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from incogni.jobs import DurableJobQueue
from incogni.storage import ServiceStore, utciso

DROP_URL = "https://privacy.ca.gov/drop/"


class DropCompanion:
    def __init__(self, store: ServiceStore):
        self.store = store
        self.queue = DurableJobQueue(store)

    def record_enrollment(
        self, *, terms_acknowledged: bool, drop_identifier: str | None = None
    ) -> None:
        if not terms_acknowledged:
            raise ValueError("DROP terms must be acknowledged by the operator")
        self.store.set_setting("drop_enrolled", "true")
        self.store.set_setting("drop_terms_ack", "true")
        self.store.set_setting("drop_updated_at", utciso())
        self.store.put_secret(
            "drop_enrollment",
            {"drop_identifier": drop_identifier} if drop_identifier else {},
        )
        self.store.record_audit("drop_enrollment_recorded", "drop", "owner")

    def schedule_status_reminders(self, start: datetime | None = None) -> list[str]:
        start = start or datetime.now(timezone.utc)
        ids = []
        for days in (45, 90):
            due = start + timedelta(days=days)
            ids.append(
                self.queue.enqueue(
                    "drop_status_reminder",
                    {},
                    idempotency_key=f"drop-status:{due.date().isoformat()}",
                    available_at=due,
                )
            )
        return ids
