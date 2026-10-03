"""Adapter for brokers we know about but have not integrated yet.

These brokers appear in the registry (so the user can see they exist) but no
scan/opt-out implementation is wired up. The stub records an explicit SKIPPED /
FAILED so the pipeline stays honest about coverage.
"""

from __future__ import annotations

from incogni.adapters.base import BrokerAdapter
from incogni.models import OptOutResult, OptOutStatus, ScanResult, ScanStatus
from incogni.profile import PersonProfile


class StubAdapter(BrokerAdapter):
    def __init__(self, broker_id: str):
        self.broker_id = broker_id

    def can_scan(self, profile: PersonProfile) -> bool:
        return False  # never attempted; there is no implementation

    def scan(self, profile: PersonProfile) -> ScanResult:
        return ScanResult(
            broker_id=self.broker_id,
            status=ScanStatus.SKIPPED,
            detail="no adapter implemented for this broker yet",
        )

    def submit_optout(self, profile: PersonProfile) -> OptOutResult:
        return OptOutResult(
            broker_id=self.broker_id,
            status=OptOutStatus.FAILED,
            message="no adapter implemented for this broker yet",
        )
