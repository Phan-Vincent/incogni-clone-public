"""Orchestration: scan brokers, submit opt-outs, schedule re-checks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from incogni.models import OptOutResult, OptOutStatus, ScanResult, ScanStatus
from incogni.profile import PersonProfile
from incogni.registry import BrokerRegistry
from incogni.tracker import Tracker


class Engine:
    """Ties the registry, adapters, profile, and tracker together."""

    def __init__(self, registry: BrokerRegistry, tracker: Tracker, profile: PersonProfile):
        self.registry = registry
        self.tracker = tracker
        self.profile = profile

    def scan_all(self) -> list[ScanResult]:
        """Run a scan against every broker and persist the results."""
        results: list[ScanResult] = []
        for broker in self.registry:
            # The adapter decides whether it can scan and, if not, why (e.g.
            # "no identity" vs "adapter not implemented"). No short-circuit here.
            result = broker.adapter.scan(self.profile)
            self.tracker.record_scan(result)
            self._sync_optout_state(result)
            results.append(result)
        return results

    def _sync_optout_state(self, result: ScanResult) -> None:
        """Reflect actionable scan results in the removal lifecycle.

        A newly discovered record is pending removal, while a broker that no
        longer has a record needs no action. Requests already submitted or
        confirmed are preserved: a scan alone cannot revoke those states.
        """
        existing = self.tracker.get_optout(result.broker_id)
        existing_status = existing["status"] if existing else None

        if result.status is ScanStatus.FOUND and existing_status in {
            None,
            OptOutStatus.NOT_NEEDED.value,
        }:
            self.tracker.record_optout(
                OptOutResult(
                    broker_id=result.broker_id,
                    status=OptOutStatus.PENDING,
                    message="matching record detected; removal request not yet submitted",
                    submitted_at=result.scanned_at,
                )
            )
        elif result.status is ScanStatus.NOT_FOUND and existing_status in {
            None,
            OptOutStatus.PENDING.value,
            OptOutStatus.FAILED.value,
        }:
            self.tracker.record_optout(
                OptOutResult(
                    broker_id=result.broker_id,
                    status=OptOutStatus.NOT_NEEDED,
                    message="no matching record found",
                    submitted_at=result.scanned_at,
                )
            )

    def submit_optouts(self) -> list[OptOutResult]:
        """Submit a removal request for every broker where a record was found
        and removal has not already been confirmed."""
        results: list[OptOutResult] = []
        for broker in self.registry:
            scan = self.tracker.latest_scan(broker.id)
            if not scan or scan["status"] != ScanStatus.FOUND.value:
                continue

            existing = self.tracker.get_optout(broker.id)
            if existing and existing["status"] in {
                OptOutStatus.CONFIRMED.value,
                OptOutStatus.SUBMITTED.value,
            }:
                continue  # already removed, or request in flight; idempotent

            result = broker.adapter.submit_optout(self.profile)
            self.tracker.record_optout(result)
            results.append(result)
        return results

    def confirm_optout(
        self, broker_id: str, confirmation_id: str | None = None
    ) -> OptOutResult:
        """Record external confirmation of a previously submitted request.

        Email-based removals cannot confirm synchronously, so users need a way
        to reconcile the broker's later response with the local tracker.
        """
        if self.registry.get(broker_id) is None:
            raise ValueError(f"unknown broker: {broker_id}")

        existing = self.tracker.get_optout(broker_id)
        if existing is None:
            raise ValueError(f"no removal request exists for broker: {broker_id}")
        if existing["status"] == OptOutStatus.CONFIRMED.value:
            return OptOutResult(
                broker_id=broker_id,
                status=OptOutStatus.CONFIRMED,
                confirmation_id=existing["confirmation_id"],
                message=existing["message"],
                submitted_at=datetime.fromisoformat(existing["submitted_at"]),
            )
        if existing["status"] != OptOutStatus.SUBMITTED.value:
            raise ValueError(
                f"cannot confirm {broker_id}: removal status is {existing['status']}"
            )

        result = OptOutResult(
            broker_id=broker_id,
            status=OptOutStatus.CONFIRMED,
            confirmation_id=confirmation_id or existing["confirmation_id"],
            message="broker removal confirmation recorded",
        )
        self.tracker.record_optout(result)
        return result

    def recheck_due(self, interval: timedelta) -> list[str]:
        """Broker ids whose most recent scan is older than ``interval`` (or
        missing). Used to model Incogni's recurring re-scans over time."""
        cutoff = datetime.now(timezone.utc) - interval
        due: list[str] = []
        for broker in self.registry:
            scan = self.tracker.latest_scan(broker.id)
            if scan is None:
                due.append(broker.id)
                continue
            scanned_at = datetime.fromisoformat(scan["scanned_at"])
            if scanned_at < cutoff:
                due.append(broker.id)
        return due
