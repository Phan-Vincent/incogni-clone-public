"""Durable worker handlers for explicitly injected synthetic adapters."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

from incogni.adapters.registry import SyntheticAdapterRegistry
from incogni.adapters.service import GuardrailPause, ServiceBrokerAdapter
from incogni.approvals import ApprovalManager
from incogni.jobs import Job
from incogni.models import FindingStatus, RequestStatus
from incogni.storage import ServiceStore

AdapterJobHandler = Callable[[Job], None]


def _required_text(payload: dict, key: str, reason: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise GuardrailPause(reason)
    return value


def _job_scope(job: Job) -> tuple[str, str]:
    if not job.profile_id or not job.broker_id:
        raise GuardrailPause("job_scope_missing")
    return job.profile_id, job.broker_id


def _status_fingerprint(
    profile_id: str, broker_id: str, flow_version: str, status: FindingStatus
) -> str:
    canonical = json.dumps(
        [profile_id, broker_id, flow_version, status.value], separators=(",", ":")
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def synthetic_adapter_handlers(
    store: ServiceStore,
    registry: SyntheticAdapterRegistry | None,
) -> dict[str, AdapterJobHandler]:
    """Return handlers that block unless a synthetic registry was injected."""

    def effect_committed(job: Job) -> bool:
        return (
            store.conn.execute(
                "SELECT 1 FROM audit_events WHERE event_type="
                "'synthetic_job_effect_committed' AND entity_type='job' "
                "AND entity_id=?",
                (job.id,),
            ).fetchone()
            is not None
        )

    def mark_effect_committed(job: Job) -> None:
        store.record_audit(
            "synthetic_job_effect_committed",
            "job",
            job.id,
            json.dumps({"kind": job.kind}, separators=(",", ":")),
        )

    def adapter_for(
        broker_id: str, *, expected_flow_version: str
    ) -> ServiceBrokerAdapter:
        if registry is None:
            raise GuardrailPause("fixture_source_required")
        adapter = registry.get(
            broker_id, expected_flow_version=expected_flow_version
        )
        row = store.conn.execute(
            "SELECT flow_version FROM broker_flows WHERE broker_id=?", (broker_id,)
        ).fetchone()
        if row is None:
            raise GuardrailPause("broker_flow_unregistered")
        if row["flow_version"] != adapter.metadata.flow_version:
            raise GuardrailPause("flow_version_changed")
        return adapter

    def discover_broker(job: Job) -> None:
        profile_id, broker_id = _job_scope(job)
        fixture_ref = _required_text(
            job.payload, "fixture_ref", "fixture_reference_required"
        )
        flow_version = _required_text(
            job.payload, "flow_version", "flow_version_required"
        )
        adapter = adapter_for(broker_id, expected_flow_version=flow_version)
        result = adapter.discover(fixture_ref)
        if result.broker_id != broker_id:
            raise GuardrailPause("broker_mismatch")
        fingerprint = result.listing_fingerprint or _status_fingerprint(
            profile_id, broker_id, flow_version, result.status
        )
        try:
            with store.transaction(immediate=True):
                if effect_committed(job):
                    return
                finding_id = store.upsert_finding(
                    profile_id=profile_id,
                    broker_id=broker_id,
                    status=result.status,
                    listing_fingerprint=fingerprint,
                    flow_version=flow_version,
                    payload={
                        "matched_fields": list(result.matched_fields),
                        "reason_code": result.reason_code,
                    },
                )
                store.record_audit(
                    "synthetic_discovery_completed",
                    "finding",
                    finding_id,
                    json.dumps(
                        {"broker_id": broker_id, "status": result.status.value},
                        separators=(",", ":"),
                    ),
                )
                mark_effect_committed(job)
        except ValueError as exc:
            raise GuardrailPause("finding_state_conflict") from exc

    def poll_request(job: Job) -> None:
        profile_id, broker_id = _job_scope(job)
        request_id = _required_text(job.payload, "request_id", "request_id_required")
        fixture_ref = _required_text(
            job.payload, "fixture_ref", "fixture_reference_required"
        )
        row = store.conn.execute(
            "SELECT f.profile_id,f.broker_id,f.flow_version "
            "FROM removal_requests r JOIN findings f ON f.id=r.finding_id "
            "WHERE r.id=?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise GuardrailPause("request_not_found")
        if row["profile_id"] != profile_id or row["broker_id"] != broker_id:
            raise GuardrailPause("job_scope_mismatch")
        adapter = adapter_for(
            broker_id, expected_flow_version=row["flow_version"]
        )
        result = adapter.poll(fixture_ref)
        if result.broker_id != broker_id:
            raise GuardrailPause("broker_mismatch")
        try:
            with store.transaction(immediate=True):
                if effect_committed(job):
                    return
                store.transition_request(
                    request_id,
                    result.status,
                    confirmation_id=result.confirmation_id,
                    job_id=job.id,
                )
                store.record_audit(
                    "synthetic_request_polled", "request", request_id
                )
                mark_effect_committed(job)
        except ValueError as exc:
            raise GuardrailPause("request_state_conflict") from exc

    def verify_removal(job: Job) -> None:
        profile_id, broker_id = _job_scope(job)
        finding_id = _required_text(job.payload, "finding_id", "finding_id_required")
        fixture_ref = _required_text(
            job.payload, "fixture_ref", "fixture_reference_required"
        )
        row = store.conn.execute(
            "SELECT profile_id,broker_id,flow_version FROM findings WHERE id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise GuardrailPause("finding_not_found")
        if row["profile_id"] != profile_id or row["broker_id"] != broker_id:
            raise GuardrailPause("job_scope_mismatch")
        adapter = adapter_for(
            broker_id, expected_flow_version=row["flow_version"]
        )
        result = adapter.verify(fixture_ref)
        if result.broker_id != broker_id:
            raise GuardrailPause("broker_mismatch")
        try:
            with store.transaction(immediate=True):
                if effect_committed(job):
                    return
                if result.status is FindingStatus.SUPPRESSED:
                    store.transition_finding(finding_id, FindingStatus.SUPPRESSED)
                    audited_id = finding_id
                elif result.status is FindingStatus.REAPPEARED:
                    if not result.listing_fingerprint:
                        raise GuardrailPause("listing_fingerprint_required")
                    audited_id = store.upsert_finding(
                        profile_id=profile_id,
                        broker_id=broker_id,
                        status=FindingStatus.REAPPEARED,
                        listing_fingerprint=result.listing_fingerprint,
                        flow_version=row["flow_version"],
                        payload={"reason_code": result.reason_code},
                    )
                    request_id = store.create_removal_request(
                        audited_id,
                        status=RequestStatus.AWAITING_APPROVAL,
                        payload={"source_finding_id": finding_id},
                    )
                    ApprovalManager(store).create(
                        "submit_removal", request_id=request_id
                    )
                else:
                    raise GuardrailPause("unexpected_verification_result")
                store.record_audit(
                    "synthetic_removal_verified",
                    "finding",
                    audited_id,
                    json.dumps(
                        {"broker_id": broker_id, "status": result.status.value},
                        separators=(",", ":"),
                    ),
                )
                mark_effect_committed(job)
        except ValueError as exc:
            raise GuardrailPause("finding_state_conflict") from exc

    return {
        "discover_broker": discover_broker,
        "poll_request": poll_request,
        "verify_removal": verify_removal,
    }
