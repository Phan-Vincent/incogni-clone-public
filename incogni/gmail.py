"""Dedicated Gmail boundary for generic alerts and quarantined verification links."""

from __future__ import annotations

import base64
import email
import hashlib
import re
from email.mime.text import MIMEText
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from incogni.approvals import ApprovalManager
from incogni.evidence import EvidenceStore
from incogni.jobs import DurableJobQueue
from incogni.storage import ServiceStore, utciso

_URL_RE = re.compile(r"https://[^\s<>\"']+")


class GmailGateway:
    def __init__(
        self,
        store: ServiceStore,
        gmail_service: Any,
        *,
        verification_hosts: dict[str, str],
        evidence_store: EvidenceStore,
    ):
        self.store = store
        self.gmail = gmail_service
        self.evidence = evidence_store
        self.queue = DurableJobQueue(store)
        self.approvals = ApprovalManager(store)
        self.verification_hosts = {
            host.lower(): broker_id for host, broker_id in verification_hosts.items()
        }

    def store_oauth_token(self, token: dict[str, Any]) -> None:
        self.store.put_secret("gmail_oauth", token)

    def load_oauth_token(self) -> dict[str, Any] | None:
        return self.store.get_secret("gmail_oauth")

    def scan_verification_messages(self) -> int:
        response = (
            self.gmail.users()
            .messages()
            .list(
                userId="me",
                q="is:unread (verify OR confirmation OR opt-out OR removal)",
                maxResults=50,
            )
            .execute()
        )
        created = 0
        for item in response.get("messages", []):
            message_id = str(item["id"])
            message_id_hash = hashlib.sha256(message_id.encode()).hexdigest()
            exists = self.store.conn.execute(
                "SELECT 1 FROM notifications WHERE provider_message_id=?",
                (message_id_hash,),
            ).fetchone()
            if exists:
                continue
            raw = (
                self.gmail.users()
                .messages()
                .get(userId="me", id=message_id, format="raw")
                .execute()["raw"]
            )
            raw_bytes = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            parsed = email.message_from_bytes(raw_bytes)
            text = "\n".join(
                part.get_payload(decode=True).decode(errors="replace")
                for part in parsed.walk()
                if part.get_content_type() in {"text/plain", "text/html"}
                and part.get_payload(decode=True)
            )
            matches = []
            for url in _URL_RE.findall(text):
                host = (urlparse(url).hostname or "").lower()
                broker_id = self.verification_hosts.get(host)
                if broker_id:
                    matches.append({"broker_id": broker_id, "url": url})
            notification_id = uuid4().hex
            evidence_id = uuid4().hex
            try:
                with self.store.transaction(immediate=True) as conn:
                    duplicate = conn.execute(
                        "SELECT 1 FROM notifications WHERE provider_message_id=?",
                        (message_id_hash,),
                    ).fetchone()
                    if duplicate:
                        continue
                    self.evidence.save(
                        "notification",
                        notification_id,
                        "message/rfc822",
                        raw_bytes,
                        evidence_id=evidence_id,
                    )
                    payload = {
                        "message_id": message_id,
                        "verification_links": matches,
                        "evidence_id": evidence_id,
                    }
                    encrypted = self.store.crypto.encrypt_json(
                        payload, aad=f"notification:{notification_id}".encode()
                    )
                    conn.execute(
                        "INSERT INTO notifications(id,kind,provider_message_id,status,"
                        "encrypted_payload,created_at) VALUES(?,?,?,?,?,?)",
                        (
                            notification_id,
                            "verification_email",
                            message_id_hash,
                            "approval_required" if matches else "review_required",
                            encrypted,
                            utciso(),
                        ),
                    )
                    if matches:
                        job_id = self.queue.enqueue(
                            "open_verification_link",
                            {"notification_id": notification_id},
                            idempotency_key=f"verification-email:{message_id_hash}",
                            max_attempts=1,
                        )
                        conn.execute(
                            "UPDATE jobs SET status='blocked',last_error_code="
                            "'approval_required' WHERE id=?",
                            (job_id,),
                        )
                        self.approvals.create(
                            "open_verification_link", job_id=job_id
                        )
            except Exception:
                self.evidence.discard(evidence_id)
                raise
            created += 1
        return created

    def send_generic_alert(self, recipient: str, event_code: str) -> str:
        message = MIMEText(
            "The local privacy service has an item requiring review. "
            f"Event code: {event_code}. Open the Tailscale-only dashboard for details."
        )
        message["to"] = recipient
        message["subject"] = "Privacy service action required"
        encoded = base64.urlsafe_b64encode(message.as_bytes()).decode()
        result = (
            self.gmail.users()
            .messages()
            .send(userId="me", body={"raw": encoded})
            .execute()
        )
        return str(result["id"])
