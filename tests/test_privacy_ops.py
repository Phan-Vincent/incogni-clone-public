import base64
import email
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from pathlib import Path

from incogni.approvals import ApprovalManager
from incogni.crypto import EnvelopeCrypto
from incogni.drop import DropCompanion
from incogni.evidence import EvidenceStore
from incogni.evidence import EvidenceStore
from incogni.gmail import GmailGateway
from incogni.gmail_oauth import GMAIL_SCOPES, authorize_gmail
from incogni.jobs import DurableJobQueue
from incogni.maintenance import (
    create_encrypted_backup,
    purge_old_backups,
    restore_encrypted_backup,
)
from incogni.storage import ServiceStore


class FakeMessages:
    def __init__(self, raw):
        self.raw = raw
        self.action = None
        self.sent = None

    def list(self, **kwargs):
        self.action = ("list", kwargs)
        return self

    def get(self, **kwargs):
        self.action = ("get", kwargs)
        return self

    def send(self, **kwargs):
        self.action = ("send", kwargs)
        self.sent = kwargs["body"]["raw"]
        return self

    def execute(self):
        action, _kwargs = self.action
        if action == "list":
            return {"messages": [{"id": "provider-1"}]}
        if action == "get":
            return {"raw": self.raw}
        return {"id": "sent-1"}


class FakeUsers:
    def __init__(self, messages):
        self._messages = messages

    def messages(self):
        return self._messages


class FakeGmail:
    def __init__(self, raw):
        self.messages_api = FakeMessages(raw)

    def users(self):
        return FakeUsers(self.messages_api)


class FakeCredentials:
    def to_json(self):
        return '{"refresh_token":"synthetic-oauth"}'


class FakeOAuthFlow:
    seen_scopes = None


    @classmethod
    def from_client_secrets_file(cls, path, scopes):
        del path
        cls.seen_scopes = tuple(scopes)
        return cls()

    def run_local_server(self, port, open_browser):
        assert port == 0 and open_browser
        return FakeCredentials()


class PrivacyOperationsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.crypto = EnvelopeCrypto({"test": b"k" * 32}, "test")
        self.store = ServiceStore(self.root / "service.db", self.crypto)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_gmail_oauth_uses_narrow_scopes_and_encrypted_storage(self):
        authorize_gmail(
            self.store,
            self.root / "synthetic-client.json",
            flow_factory=FakeOAuthFlow,
        )
        self.assertEqual(FakeOAuthFlow.seen_scopes, GMAIL_SCOPES)
        self.assertEqual(
            self.store.get_secret("gmail_oauth")["refresh_token"],
            "synthetic-oauth",
        )
        with open(self.root / "service.db", "rb") as handle:
            self.assertNotIn(b"synthetic-oauth", handle.read())

    def test_approval_is_one_time_and_bound_to_action(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue("submit_removal", {}, idempotency_key="approval-job")
        approval = ApprovalManager(self.store)
        approval_id = approval.create("submit_removal", job_id=job_id)
        self.assertFalse(approval.consume(approval_id, "other_action"))
        approval.decide(approval_id, approved=True)
        self.assertTrue(approval.consume(approval_id, "submit_removal"))
        self.assertFalse(approval.consume(approval_id, "submit_removal"))
        with self.assertRaises(ValueError):
            approval.decide(approval_id, approved=True)

    def test_evidence_is_encrypted_and_expired_content_is_purged(self):
        evidence = EvidenceStore(self.store, self.root / "evidence")
        with self.assertRaisesRegex(ValueError, "invalid evidence id"):
            evidence.save(
                "finding",
                "invalid",
                "text/plain",
                b"synthetic",
                evidence_id="../escape",
            )

        value = b"synthetic sensitive fixture"
        evidence_id = evidence.save(
            "finding", "fixture", "text/html", value, retention=timedelta(seconds=0)
        )
        encrypted_path = self.root / "evidence" / f"{evidence_id}.enc"
        self.assertNotIn(value, encrypted_path.read_bytes())
        self.assertEqual(evidence.read(evidence_id), value)
        self.assertEqual(
            evidence.purge_expired(datetime.now(timezone.utc) + timedelta(seconds=1)),
            1,
        )
        self.assertFalse(encrypted_path.exists())

    def test_expired_encrypted_backups_are_purged(self):
        backup = create_encrypted_backup(self.store, self.root / "backups")
        old = datetime.now(timezone.utc) - timedelta(days=31)
        os.utime(backup, (old.timestamp(), old.timestamp()))
        self.assertEqual(
            purge_old_backups(
                self.root / "backups", now=datetime.now(timezone.utc)
            ),
            1,
        )
        self.assertFalse(backup.exists())

    def test_encrypted_backup_restores_without_plaintext_at_rest(self):
        self.store.create_profile("owner", {"email": "synthetic@example.invalid"})
        backup = create_encrypted_backup(self.store, self.root / "backups")
        self.assertNotIn(b"synthetic@example.invalid", backup.read_bytes())
        restored = self.root / "restored.db"
        restore_encrypted_backup(self.store, backup, restored)
        restored_store = ServiceStore(restored, self.crypto)
        try:
            self.assertEqual(
                restored_store.get_profile("owner"),
                {"email": "synthetic@example.invalid"},
            )
        finally:
            restored_store.close()

    def test_drop_requires_acknowledgment_and_schedules_45_and_90_days(self):
        companion = DropCompanion(self.store)
        with self.assertRaises(ValueError):
            companion.record_enrollment(terms_acknowledged=False)
        companion.record_enrollment(
            terms_acknowledged=True, drop_identifier="synthetic-drop-id"
        )
        self.assertEqual(
            self.store.get_secret("drop_enrollment")["drop_identifier"],
            "synthetic-drop-id",
        )
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        ids = companion.schedule_status_reminders(start)
        due = [
            datetime.fromisoformat(self.store.conn.execute(
                "SELECT available_at FROM jobs WHERE id=?", (job_id,)
            ).fetchone()[0])
            for job_id in ids
        ]
        self.assertEqual([(date - start).days for date in due], [45, 90])

    def test_gmail_links_are_quarantined_deduplicated_and_alert_is_generic(self):
        message = MIMEText(
            "Verify synthetic request: https://verify.example.invalid/case/private-token"
        )
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode().rstrip("=")
        gmail = FakeGmail(raw)
        gateway = GmailGateway(
            self.store,
            gmail,
            verification_hosts={"verify.example.invalid": "example"},
            evidence_store=EvidenceStore(self.store, self.root / "email-evidence"),
        )
        gateway.store_oauth_token({"refresh_token": "synthetic-refresh"})
        self.assertEqual(gateway.load_oauth_token()["refresh_token"], "synthetic-refresh")
        self.assertEqual(gateway.scan_verification_messages(), 1)
        self.assertEqual(gateway.scan_verification_messages(), 0)
        row = self.store.conn.execute(
            "SELECT status,encrypted_payload FROM notifications"
        ).fetchone()
        self.assertEqual(row["status"], "approval_required")
        self.assertNotEqual(
            self.store.conn.execute(
                "SELECT provider_message_id FROM notifications"
            ).fetchone()[0],
            "provider-1",
        )
        self.assertNotIn("private-token", row["encrypted_payload"])
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM approvals WHERE status='pending'"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM jobs WHERE kind='open_verification_link'"
            ).fetchone()[0],
            "blocked",
        )
        gateway.send_generic_alert("operator@example.invalid", "BLOCKED_JOB")
        sent = email.message_from_bytes(
            base64.urlsafe_b64decode(gmail.messages_api.sent)
        )
        self.assertEqual(sent["subject"], "Privacy service action required")
        self.assertNotIn("private-token", sent.get_payload())

    def test_gmail_ingest_rolls_back_every_artifact_when_approval_fails(self):
        message = MIMEText(
            "Verify synthetic request: https://verify.example.invalid/case/rollback"
        )
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode().rstrip("=")
        evidence_root = self.root / "rollback-evidence"
        gateway = GmailGateway(
            self.store,
            FakeGmail(raw),
            verification_hosts={"verify.example.invalid": "example"},
            evidence_store=EvidenceStore(self.store, evidence_root),
        )

        def fail_approval(*_args, **_kwargs):
            raise RuntimeError("injected approval failure")

        gateway.approvals.create = fail_approval
        with self.assertRaisesRegex(RuntimeError, "injected approval failure"):
            gateway.scan_verification_messages()

        for table in ("evidence", "notifications", "jobs", "approvals"):
            self.assertEqual(
                self.store.conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(list(evidence_root.glob("*.enc")), [])

        gateway.approvals = ApprovalManager(self.store)
        self.assertEqual(gateway.scan_verification_messages(), 1)
        for table in ("evidence", "notifications", "jobs", "approvals"):
            self.assertEqual(
                self.store.conn.execute(
                    f"SELECT count(*) FROM {table}"
                ).fetchone()[0],
                1,
            )


if __name__ == "__main__":
    unittest.main()
