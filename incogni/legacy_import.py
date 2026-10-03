"""One-way, idempotent import from the offline MVP tracker."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from incogni.models import FindingStatus, RequestStatus
from incogni.storage import ServiceStore, utciso

_SCAN_MAP = {
    "found": FindingStatus.CANDIDATE,
    "not_found": FindingStatus.NOT_FOUND,
    "error": FindingStatus.ERROR,
    "skipped": FindingStatus.NOT_FOUND,
}
_REQUEST_MAP = {
    "pending": RequestStatus.AWAITING_APPROVAL,
    "submitted": RequestStatus.SUBMITTED,
    "confirmed": RequestStatus.CONFIRMED,
    "failed": RequestStatus.FAILED,
}


def import_legacy_tracker(
    legacy_path: str | Path,
    store: ServiceStore,
    *,
    profile_id: str = "owner",
) -> dict[str, int]:
    """Import status metadata while encrypting legacy detail and messages."""

    legacy = sqlite3.connect(str(legacy_path))
    legacy.row_factory = sqlite3.Row
    imported = {"scans": 0, "optouts": 0}
    try:
        tables = {
            row[0]
            for row in legacy.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if not {"scans", "optouts"}.issubset(tables):
            raise ValueError("legacy database does not contain scans and optouts")
        if store.get_profile(profile_id) is None:
            store.create_profile(profile_id, {"legacy_import": True})
        latest = legacy.execute(
            "SELECT s.* FROM scans s JOIN (SELECT broker_id,max(id) id FROM scans "
            "GROUP BY broker_id) newest ON newest.id=s.id"
        ).fetchall()
        finding_by_broker: dict[str, str] = {}
        for row in latest:
            fingerprint = "legacy:" + hashlib.sha256(
                f"{row['broker_id']}:{row['id']}".encode()
            ).hexdigest()
            payload = {
                "matched_fields": json.loads(row["matched_fields"] or "[]"),
                "detail": row["detail"],
                "legacy_scanned_at": row["scanned_at"],
            }
            finding_id = store.upsert_finding(
                profile_id=profile_id,
                broker_id=row["broker_id"],
                status=_SCAN_MAP.get(row["status"], FindingStatus.ERROR),
                listing_fingerprint=fingerprint,
                flow_version="legacy-v1",
                payload=payload,
            )
            finding_by_broker[row["broker_id"]] = finding_id
            imported["scans"] += 1

        for row in legacy.execute("SELECT * FROM optouts").fetchall():
            finding_id = finding_by_broker.get(row["broker_id"])
            if not finding_id:
                finding_id = store.upsert_finding(
                    profile_id=profile_id,
                    broker_id=row["broker_id"],
                    status=FindingStatus.CANDIDATE,
                    listing_fingerprint="legacy:" + hashlib.sha256(
                        f"{row['broker_id']}:optout".encode()
                    ).hexdigest(),
                    flow_version="legacy-v1",
                )
            request_id = hashlib.sha256(
                f"legacy-request:{row['broker_id']}".encode()
            ).hexdigest()
            payload = store.crypto.encrypt_json(
                {
                    "message": row["message"],
                    "legacy_submitted_at": row["submitted_at"],
                },
                aad=f"request:{request_id}".encode(),
            )
            now = utciso()
            encrypted_confirmation = (
                store.crypto.encrypt_json(
                    {"confirmation_id": row["confirmation_id"]},
                    aad=f"request-confirmation:{request_id}".encode(),
                )
                if row["confirmation_id"]
                else None
            )
            store.conn.execute(
                "INSERT INTO removal_requests(id,finding_id,status,encrypted_confirmation_id,"
                "encrypted_payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO NOTHING",
                (
                    request_id,
                    finding_id,
                    _REQUEST_MAP.get(row["status"], RequestStatus.FAILED).value,
                    encrypted_confirmation,
                    payload,
                    now,
                    now,
                ),
            )
            imported["optouts"] += 1
        store.record_audit("legacy_import_completed", "profile", profile_id)
        return imported
    finally:
        legacy.close()
