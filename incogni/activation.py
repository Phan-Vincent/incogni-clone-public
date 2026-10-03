"""Explicit per-broker promotion gates."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from incogni.manual_assist import MANUAL_BROKER_IDS
from incogni.models import AutomationLevel
from incogni.storage import ServiceStore


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BrokerActivation:
    CHECKPOINT_COLUMNS = {
        "terms": "terms_reviewed_at",
        "canary": "synthetic_canary_at",
        "human": "human_reviewed_run_at",
    }

    def __init__(
        self,
        store: ServiceStore,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ):
        self.store = store
        self.clock = clock

    def _row(self, broker_id: str):
        row = self.store.conn.execute(
            "SELECT * FROM broker_flows WHERE broker_id=?", (broker_id,)
        ).fetchone()
        if row is None:
            raise KeyError(broker_id)
        return row

    def record_checkpoint(self, broker_id: str, checkpoint: str) -> None:
        column = self.CHECKPOINT_COLUMNS.get(checkpoint)
        if column is None:
            raise ValueError("unknown activation checkpoint")
        row = self._row(broker_id)
        if checkpoint == "human" and (
            row["automation_level"] != AutomationLevel.APPROVAL_REQUIRED.value
            or row["paused"]
        ):
            raise ValueError(
                "a human-reviewed run requires an active approval-required flow"
            )
        now = self.clock().isoformat()
        self.store.conn.execute(
            f"UPDATE broker_flows SET {column}=?,updated_at=? WHERE broker_id=?",
            (now, now, broker_id),
        )
        self.store.record_audit(
            f"broker_checkpoint_{checkpoint}", "broker", broker_id
        )

    def set_level(self, broker_id: str, level: AutomationLevel) -> None:
        row = self._row(broker_id)
        now = self.clock()
        if level is AutomationLevel.MONITOR_ONLY:
            self.store.conn.execute(
                "UPDATE broker_flows SET automation_level=?,paused=1,"
                "monitor_since=?,updated_at=? WHERE broker_id=?",
                (level.value, now.isoformat(), now.isoformat(), broker_id),
            )
            self.store.record_audit("broker_demoted_monitor_only", "broker", broker_id)
            return

        monitor_since = (
            datetime.fromisoformat(row["monitor_since"])
            if row["monitor_since"]
            else now
        )
        if now - monitor_since < timedelta(days=14):
            raise ValueError("two-week monitor-only soak is incomplete")
        if not row["terms_reviewed_at"]:
            raise ValueError("current terms review is required")
        if not row["synthetic_canary_at"]:
            raise ValueError("synthetic canary is required")

        if level is AutomationLevel.AUTOMATIC:
            if broker_id in MANUAL_BROKER_IDS:
                raise ValueError("broker removals are operator-performed only")
            if row["automation_level"] != AutomationLevel.APPROVAL_REQUIRED.value:
                raise ValueError("automatic requires approval-required mode first")
            if not row["human_reviewed_run_at"]:
                raise ValueError("human-reviewed personal run is required")

        self.store.conn.execute(
            "UPDATE broker_flows SET automation_level=?,paused=1,updated_at=? "
            "WHERE broker_id=?",
            (level.value, now.isoformat(), broker_id),
        )
        self.store.record_audit(
            f"broker_level_{level.value}", "broker", broker_id
        )
