"""Persistent per-broker rate limits and circuit breakers."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from incogni.adapters.service import GuardrailPause
from incogni.storage import ServiceStore


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BrokerRuntimeGuard:
    def __init__(
        self,
        store: ServiceStore,
        *,
        clock: Callable[[], datetime] = _utcnow,
        failure_threshold: int = 3,
        circuit_cooldown: timedelta = timedelta(minutes=30),
    ):
        self.store = store
        self.clock = clock
        self.failure_threshold = failure_threshold
        self.circuit_cooldown = circuit_cooldown

    def _ensure(self, conn, broker_id: str, now: datetime) -> None:
        conn.execute(
            "INSERT INTO broker_runtime(broker_id,window_started_at,updated_at) "
            "VALUES(?,?,?) ON CONFLICT(broker_id) DO NOTHING",
            (broker_id, now.isoformat(), now.isoformat()),
        )

    def acquire(self, broker_id: str, *, per_hour: int) -> None:
        if per_hour < 1:
            raise ValueError("per_hour must be positive")
        now = self.clock()
        with self.store.transaction(immediate=True) as conn:
            self._ensure(conn, broker_id, now)
            row = conn.execute(
                "SELECT * FROM broker_runtime WHERE broker_id=?", (broker_id,)
            ).fetchone()
            if row["circuit_open_until"]:
                open_until = datetime.fromisoformat(row["circuit_open_until"])
                if open_until > now:
                    raise GuardrailPause("circuit_open")
            window = datetime.fromisoformat(row["window_started_at"])
            count = int(row["operation_count"])
            if now - window >= timedelta(hours=1):
                window = now
                count = 0
            if count >= per_hour:
                raise GuardrailPause("broker_rate_limit")
            conn.execute(
                "UPDATE broker_runtime SET window_started_at=?,operation_count=?,"
                "circuit_open_until=NULL,updated_at=? WHERE broker_id=?",
                (window.isoformat(), count + 1, now.isoformat(), broker_id),
            )

    def record_success(self, broker_id: str) -> None:
        now = self.clock()
        with self.store.transaction(immediate=True) as conn:
            self._ensure(conn, broker_id, now)
            conn.execute(
                "UPDATE broker_runtime SET consecutive_failures=0,"
                "circuit_open_until=NULL,updated_at=? WHERE broker_id=?",
                (now.isoformat(), broker_id),
            )

    def record_failure(self, broker_id: str) -> None:
        now = self.clock()
        with self.store.transaction(immediate=True) as conn:
            self._ensure(conn, broker_id, now)
            row = conn.execute(
                "SELECT consecutive_failures FROM broker_runtime WHERE broker_id=?",
                (broker_id,),
            ).fetchone()
            failures = int(row["consecutive_failures"]) + 1
            open_until = (
                (now + self.circuit_cooldown).isoformat()
                if failures >= self.failure_threshold
                else None
            )
            conn.execute(
                "UPDATE broker_runtime SET consecutive_failures=?,"
                "circuit_open_until=?,updated_at=? WHERE broker_id=?",
                (failures, open_until, now.isoformat(), broker_id),
            )
