"""Idempotent scheduling for recurring local service work."""

from __future__ import annotations

from datetime import datetime, timezone

from incogni.jobs import DurableJobQueue
from incogni.manual_assist import MANUAL_BROKER_IDS
from incogni.storage import ServiceStore


class ServiceScheduler:
    def __init__(self, store: ServiceStore):
        self.store = store
        self.queue = DurableJobQueue(store)

    def enqueue_daily_maintenance(self, now: datetime | None = None) -> list[str]:
        now = now or datetime.now(timezone.utc)
        day = now.date().isoformat()
        jobs = [
            self.queue.enqueue(
                "retention_cleanup",
                {},
                idempotency_key=f"retention:{day}",
            ),
            self.queue.enqueue(
                "encrypted_backup",
                {},
                idempotency_key=f"backup:{day}",
            ),
            self.queue.enqueue(
                "monthly_report",
                {},
                idempotency_key=f"monthly-report:{now.strftime('%Y-%m')}",
            ),
        ]
        if self.store.get_setting("drop_enrolled", "false") != "true":
            jobs.append(
                self.queue.enqueue(
                    "drop_reminder",
                    {},
                    idempotency_key=f"drop-reminder:{day}",
                )
            )
        jobs.extend(self.enqueue_due_rechecks(now))
        return jobs

    def enqueue_due_rechecks(self, now: datetime | None = None) -> list[str]:
        now = now or datetime.now(timezone.utc)
        rows = self.store.conn.execute(
            "SELECT r.id request_id,r.updated_at,f.id finding_id,f.profile_id,"
            "f.broker_id FROM removal_requests r JOIN findings f ON f.id=r.finding_id "
            "WHERE r.status='confirmed'"
        ).fetchall()
        jobs: list[str] = []
        for row in rows:
            confirmed_at = datetime.fromisoformat(row["updated_at"])
            age_days = (now - confirmed_at).days
            checkpoints = [days for days in (7, 30, 90) if age_days >= days]
            if age_days > 90:
                checkpoints.append(90 + 30 * ((age_days - 90) // 30))
            for days in sorted(set(checkpoints)):
                if row["broker_id"] in MANUAL_BROKER_IDS:
                    jobs.append(
                        self.queue.enqueue(
                            "manual_recheck_reminder",
                            {
                                "request_id": row["request_id"],
                                "checkpoint_days": days,
                            },
                            profile_id=row["profile_id"],
                            broker_id=row["broker_id"],
                            idempotency_key=(
                                f"manual-recheck:{row['request_id']}:{days}"
                            ),
                        )
                    )
                    continue
                jobs.append(
                    self.queue.enqueue(
                        "verify_removal",
                        {
                            "request_id": row["request_id"],
                            "finding_id": row["finding_id"],
                            "checkpoint_days": days,
                            "fixture_ref": f"scheduled_recheck_{days}",
                        },
                        profile_id=row["profile_id"],
                        broker_id=row["broker_id"],
                        idempotency_key=f"recheck:{row['request_id']}:{days}",
                    )
                )
        return jobs
