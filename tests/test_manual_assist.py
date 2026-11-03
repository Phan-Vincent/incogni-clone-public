import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from incogni.adapters.guarded import seed_live_broker_flows
from incogni.api import create_app
from incogni.approvals import ApprovalManager
from incogni.auth import OperatorAuth
from incogni.cli import build_parser
from incogni.crypto import EnvelopeCrypto
from incogni.manual_assist import MANUAL_FLOWS, ManualAssist
from incogni.models import FindingStatus, JobStatus, RequestStatus
from incogni.operations import default_handlers
from incogni.scheduler import ServiceScheduler
from incogni.service_config import ServiceConfig
from incogni.service_cli import cmd_manual
from incogni.storage import ServiceStore
from incogni.worker import ServiceWorker

SPOKEO_FLOW = MANUAL_FLOWS["spokeo"].flow_version


class ManualAssistTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.crypto = EnvelopeCrypto({"test": b"k" * 32}, "test")
        self.store = ServiceStore(self.root / "service.db", self.crypto)
        seed_live_broker_flows(self.store)
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.assist = ManualAssist(self.store, clock=lambda: self.now)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def activate_spokeo(self, *, paused=False):
        self.store.conn.execute(
            "UPDATE broker_flows SET automation_level='approval_required',paused=? "
            "WHERE broker_id='spokeo'",
            (int(paused),),
        )

    def approved_request(self, broker_id="spokeo", flow_version=SPOKEO_FLOW):
        self.store.create_profile("owner", {"fixture": "synthetic"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id=broker_id,
            status=FindingStatus.CANDIDATE,
            listing_fingerprint=f"sha256:{broker_id}-synthetic",
            flow_version=flow_version,
        )
        request_id = self.store.create_removal_request(finding_id)
        approvals = ApprovalManager(self.store)
        approval_id = approvals.create("submit_removal", request_id=request_id)
        approvals.decide_and_release(approval_id, approved=True)
        return request_id

    def status(self, request_id):
        return self.store.conn.execute(
            "SELECT status FROM removal_requests WHERE id=?", (request_id,)
        ).fetchone()["status"]

    def jobs(self, kind):
        return self.store.conn.execute(
            "SELECT id,available_at,profile_id,broker_id FROM jobs WHERE kind=? "
            "ORDER BY available_at",
            (kind,),
        ).fetchall()

    def run_due_jobs(self):
        handlers = default_handlers(self.store, evidence_dir=self.root / "evidence")
        worker = ServiceWorker(self.store, "test-worker", handlers)
        worker.queue.clock = lambda: self.now
        results = []
        while (result := worker.run_once()) is not None:
            results.append(result)
        return results

    def notifications(self):
        return sorted(
            row["kind"]
            for row in self.store.conn.execute("SELECT kind FROM notifications")
        )

    def test_found_intake_creates_guarded_request_and_runs_full_lifecycle(self):
        self.activate_spokeo(paused=True)
        result = self.assist.record_found("spokeo")

        finding = self.store.conn.execute(
            "SELECT status,listing_fingerprint,flow_version,encrypted_payload "
            "FROM findings WHERE id=?",
            (result["finding_id"],),
        ).fetchone()
        self.assertEqual(finding["status"], "confirmed_match")
        self.assertRegex(finding["listing_fingerprint"], r"^manual:[0-9a-f]{64}$")
        self.assertEqual(finding["flow_version"], SPOKEO_FLOW)
        self.assertIsNone(finding["encrypted_payload"])
        request = self.store.conn.execute(
            "SELECT status,encrypted_payload FROM removal_requests WHERE id=?",
            (result["request_id"],),
        ).fetchone()
        self.assertEqual(request["status"], "awaiting_approval")
        self.assertIsNone(request["encrypted_payload"])
        approval = self.store.conn.execute(
            "SELECT request_id,status FROM approvals WHERE id=?",
            (result["approval_id"],),
        ).fetchone()
        self.assertEqual(
            dict(approval),
            {
                "request_id": result["request_id"],
                "status": "pending",
            },
        )
        audit = self.store.conn.execute(
            "SELECT entity_type,entity_id,metadata_json FROM audit_events "
            "WHERE event_type='manual_finding_recorded'"
        ).fetchone()
        self.assertEqual(
            dict(audit),
            {
                "entity_type": "request",
                "entity_id": result["request_id"],
                "metadata_json": '{"broker_id":"spokeo"}',
            },
        )

        ApprovalManager(self.store).decide_and_release(
            result["approval_id"], approved=True
        )
        self.store.conn.execute(
            "UPDATE broker_flows SET paused=0 WHERE broker_id='spokeo'"
        )
        self.assertEqual(
            self.assist.checklist(result["request_id"])["broker_id"], "spokeo"
        )
        for step, status in (
            ("submitted", "verification_required"),
            ("verified", "processing"),
            ("confirmed", "confirmed"),
        ):
            self.assertEqual(self.assist.record(result["request_id"], step), status)

    def test_found_intake_rejects_ineligible_broker_flows(self):
        with self.assertRaisesRegex(ValueError, "monitor-only"):
            self.assist.record_found("spokeo")
        with self.assertRaisesRegex(ValueError, "operator-performed"):
            self.assist.record_found("whitepages")

        self.activate_spokeo()
        self.store.conn.execute(
            "UPDATE broker_flows SET flow_version='stale' WHERE broker_id='spokeo'"
        )
        with self.assertRaisesRegex(ValueError, "flow version changed"):
            self.assist.record_found("spokeo")

        self.store.conn.execute("DELETE FROM broker_flows WHERE broker_id='spokeo'")
        with self.assertRaises(KeyError):
            self.assist.record_found("spokeo")

    def test_found_intake_open_request_rules(self):
        self.activate_spokeo()
        first = self.assist.record_found("spokeo")
        with self.assertRaisesRegex(ValueError, "open request"):
            self.assist.record_found("spokeo")
        additional = self.assist.record_found("spokeo", additional=True)
        self.assertNotEqual(first["request_id"], additional["request_id"])

        closed = self.assist.record_found("spokeo", profile_id="closed")
        ApprovalManager(self.store).decide_and_release(
            closed["approval_id"], approved=True
        )
        for step in ("submitted", "verified", "confirmed"):
            self.assist.record(closed["request_id"], step)
        replacement = self.assist.record_found("spokeo", profile_id="closed")
        self.assertNotEqual(closed["request_id"], replacement["request_id"])

    def test_found_intake_preserves_existing_profile_and_creates_placeholder(self):
        self.activate_spokeo()
        self.store.create_profile("existing", {"fixture": "keep"})
        self.assist.record_found("spokeo", profile_id="existing")
        self.assertEqual(self.store.get_profile("existing"), {"fixture": "keep"})

        self.assist.record_found("spokeo", profile_id="missing")
        self.assertEqual(
            self.store.get_profile("missing"), {"manual_intake": True}
        )

    def test_found_intake_stores_no_url_or_email(self):
        self.activate_spokeo()
        result = self.assist.record_found("spokeo")
        finding = self.store.conn.execute(
            "SELECT listing_fingerprint,encrypted_payload FROM findings WHERE id=?",
            (result["finding_id"],),
        ).fetchone()
        request = self.store.conn.execute(
            "SELECT encrypted_payload FROM removal_requests WHERE id=?",
            (result["request_id"],),
        ).fetchone()
        metadata = [
            row["metadata_json"]
            for row in self.store.conn.execute(
                "SELECT metadata_json FROM audit_events WHERE entity_id=?",
                (result["request_id"],),
            )
        ]
        stored = [
            finding["listing_fingerprint"],
            finding["encrypted_payload"],
            request["encrypted_payload"],
            *metadata,
        ]
        for value in stored:
            if value is not None:
                self.assertNotIn("http", value.lower())
                self.assertNotIn("@", value)

    def test_checklist_requires_approved_request_and_active_flow(self):
        request_id = self.approved_request()
        with self.assertRaisesRegex(ValueError, "not approval-required"):
            self.assist.checklist(request_id)
        self.activate_spokeo(paused=True)
        with self.assertRaisesRegex(ValueError, "paused"):
            self.assist.checklist(request_id)
        self.activate_spokeo()
        self.store.set_setting("emergency_stop", "true")
        with self.assertRaisesRegex(ValueError, "emergency stop"):
            self.assist.checklist(request_id)
        self.store.set_setting("emergency_stop", "false")

        checklist = self.assist.checklist(request_id)
        self.assertEqual(checklist["opt_out_url"], "https://www.spokeo.com/optout")
        self.assertEqual(checklist["verification_window_hours"], 72)
        self.assertTrue(any("CAPTCHA yourself" in s for s in checklist["steps"]))
        self.assertEqual(self.status(request_id), "ready")

    def test_checklist_refuses_unapproved_stale_or_automated_brokers(self):
        self.activate_spokeo()
        self.store.create_profile("owner", {"fixture": "synthetic"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="spokeo",
            status=FindingStatus.CANDIDATE,
            listing_fingerprint="sha256:awaiting",
            flow_version=SPOKEO_FLOW,
        )
        awaiting = self.store.create_removal_request(finding_id)
        with self.assertRaisesRegex(ValueError, "awaiting_approval"):
            self.assist.checklist(awaiting)

        stale = self.approved_request(flow_version="2026-08-monitor-1")
        with self.assertRaisesRegex(ValueError, "flow version changed"):
            self.assist.checklist(stale)

        other = self.approved_request(broker_id="whitepages", flow_version="x")
        with self.assertRaisesRegex(ValueError, "operator-performed"):
            self.assist.checklist(other)
        with self.assertRaises(KeyError):
            self.assist.checklist("missing")

    def test_full_operator_lifecycle_with_reminder(self):
        self.activate_spokeo()
        request_id = self.approved_request()
        self.assertEqual(self.assist.record(request_id, "submitted"), "verification_required")
        reminder = self.jobs("manual_verification_reminder")
        expiry = self.jobs("manual_verification_expiry")
        self.assertEqual(len(reminder), 1)
        self.assertEqual(len(expiry), 1)
        self.assertEqual(reminder[0]["broker_id"], "spokeo")
        self.assertEqual(
            datetime.fromisoformat(reminder[0]["available_at"]),
            self.now + timedelta(hours=48),
        )
        self.assertEqual(
            datetime.fromisoformat(expiry[0]["available_at"]),
            self.now + timedelta(hours=72),
        )
        with self.assertRaisesRegex(ValueError, "verification_required"):
            self.assist.record(request_id, "submitted")

        self.now += timedelta(hours=49)
        self.run_due_jobs()
        self.assertEqual(self.notifications(), ["manual_verification_reminder"])

        self.assertEqual(self.assist.record(request_id, "verified"), "processing")
        self.now += timedelta(hours=24)
        self.run_due_jobs()
        self.assertEqual(self.status(request_id), "processing")
        self.assertEqual(self.notifications(), ["manual_verification_reminder"])

        self.assertEqual(self.assist.record(request_id, "confirmed"), "confirmed")
        outcomes = [
            row["outcome"]
            for row in self.store.conn.execute(
                "SELECT outcome FROM attempts WHERE request_id=? ORDER BY id",
                (request_id,),
            )
        ]
        self.assertEqual(
            outcomes,
            ["ready", "submitted", "verification_required", "processing", "confirmed"],
        )
        audit = {
            row["event_type"]
            for row in self.store.conn.execute("SELECT event_type FROM audit_events")
        }
        self.assertTrue(
            {"manual_step_submitted", "manual_step_verified", "manual_step_confirmed"}
            <= audit
        )

    def test_expired_link_fails_and_restart_resubmits(self):
        self.activate_spokeo()
        request_id = self.approved_request()
        with self.assertRaisesRegex(ValueError, "state that allows this step: ready"):
            self.assist.record(request_id, "restart")
        self.assist.record(request_id, "submitted")
        self.now += timedelta(hours=73)
        self.run_due_jobs()
        self.assertEqual(self.status(request_id), "failed")
        self.assertEqual(
            self.notifications(),
            ["manual_verification_expired", "manual_verification_reminder"],
        )

        self.assertEqual(self.assist.record(request_id, "restart"), "ready")
        self.assist.record(request_id, "submitted")
        self.assertEqual(len(self.jobs("manual_verification_expiry")), 2)
        self.assist.record(request_id, "verified")
        self.now += timedelta(hours=73)
        self.run_due_jobs()
        self.assertEqual(self.status(request_id), "processing")

    def test_stale_expiry_from_earlier_submission_is_ignored(self):
        self.activate_spokeo()
        request_id = self.approved_request()
        self.assist.record(request_id, "submitted")
        self.now += timedelta(hours=73)
        self.run_due_jobs()
        self.assist.record(request_id, "restart")
        self.assist.record(request_id, "submitted")
        first_expiry = self.jobs("manual_verification_expiry")[0]
        self.store.conn.execute(
            "UPDATE jobs SET status='queued' WHERE id=?", (first_expiry["id"],)
        )
        self.run_due_jobs()
        self.assertEqual(self.status(request_id), "verification_required")

    def test_unknown_step_and_non_manual_broker_are_rejected(self):
        self.activate_spokeo()
        request_id = self.approved_request()
        with self.assertRaisesRegex(ValueError, "unknown manual step"):
            self.assist.record(request_id, "execute")
        other = self.approved_request(broker_id="mylife", flow_version="x")
        with self.assertRaisesRegex(ValueError, "operator-performed"):
            self.assist.record(other, "submitted")
        self.assertEqual(self.status(other), "ready")

    def test_confirmed_manual_request_gets_reminders_not_automated_rechecks(self):
        self.activate_spokeo()
        request_id = self.approved_request()
        for step in ("submitted", "verified", "confirmed"):
            self.assist.record(request_id, step)
        self.store.conn.execute(
            "UPDATE removal_requests SET updated_at=? WHERE id=?",
            ((self.now - timedelta(days=31)).isoformat(), request_id),
        )
        scheduler = ServiceScheduler(self.store)
        scheduler.queue.clock = lambda: self.now  # jobs must be due on the test's clock
        scheduler.enqueue_due_rechecks(self.now)
        self.assertEqual(self.jobs("verify_removal"), [])
        self.assertEqual(len(self.jobs("manual_recheck_reminder")), 2)
        self.store.conn.execute(
            "DELETE FROM jobs WHERE kind LIKE 'manual_verification_%'"
        )
        results = self.run_due_jobs()
        self.assertEqual(results, [JobStatus.SUCCEEDED, JobStatus.SUCCEEDED])
        self.assertEqual(
            self.notifications(),
            ["manual_recheck_reminder", "manual_recheck_reminder"],
        )


class ManualAssistApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        crypto = EnvelopeCrypto({"test": b"k" * 32}, "test")
        db_path = Path(self.tmp.name) / "service.db"
        self.store = ServiceStore(db_path, crypto)
        seed_live_broker_flows(self.store)
        config = ServiceConfig(
            db_path=db_path,
            evidence_dir=Path(self.tmp.name) / "evidence",
            crypto=crypto,
            signing_key=b"k" * 32,
            admin_password_hash=OperatorAuth.hash_password("correct horse battery"),
            secure_cookies=False,
        )
        self.client = TestClient(create_app(self.store, config))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_checklist_and_steps_require_session_and_csrf(self):
        self.store.conn.execute(
            "UPDATE broker_flows SET automation_level='approval_required',paused=0 "
            "WHERE broker_id='spokeo'"
        )
        self.store.create_profile("owner", {"fixture": "synthetic"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="spokeo",
            status=FindingStatus.CANDIDATE,
            listing_fingerprint="sha256:api",
            flow_version=SPOKEO_FLOW,
        )
        request_id = self.store.create_removal_request(finding_id)
        base = f"/api/requests/{request_id}/manual"
        self.assertEqual(self.client.get(base).status_code, 401)

        csrf = self.client.post(
            "/api/login", json={"password": "correct horse battery"}
        ).json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf}
        self.assertEqual(self.client.get(base).status_code, 409)
        self.assertEqual(self.client.get("/api/requests/missing/manual").status_code, 404)

        manager = ApprovalManager(self.store)
        manager.decide_and_release(
            manager.create("submit_removal", request_id=request_id), approved=True
        )
        checklist = self.client.get(base)
        self.assertEqual(checklist.status_code, 200)
        self.assertEqual(checklist.json()["broker_id"], "spokeo")

        self.assertEqual(self.client.post(f"{base}/submitted").status_code, 403)
        self.assertEqual(
            self.client.post(f"{base}/execute", headers=headers).status_code, 422
        )
        response = self.client.post(f"{base}/submitted", headers=headers)
        self.assertEqual(response.json(), {"ok": True, "status": "verification_required"})
        self.assertEqual(
            self.client.post(f"{base}/confirmed", headers=headers).status_code, 409
        )
        self.assertEqual(
            self.client.post(f"{base}/verified", headers=headers).json()["status"],
            "processing",
        )
        self.assertEqual(
            RequestStatus(
                self.store.conn.execute(
                    "SELECT status FROM removal_requests WHERE id=?", (request_id,)
                ).fetchone()["status"]
            ),
            RequestStatus.PROCESSING,
        )

    def test_found_intake_auth_validation_and_success(self):
        endpoint = "/api/manual/spokeo/found"
        self.assertEqual(self.client.post(endpoint, json={}).status_code, 401)
        csrf = self.client.post(
            "/api/login", json={"password": "correct horse battery"}
        ).json()["csrf_token"]
        self.assertEqual(self.client.post(endpoint, json={}).status_code, 403)
        headers = {"X-CSRF-Token": csrf}
        response = self.client.post(endpoint, json={}, headers=headers)
        self.assertEqual(response.status_code, 409)
        self.assertIn("monitor-only", response.json()["detail"])

        self.store.conn.execute(
            "UPDATE broker_flows SET automation_level='approval_required' "
            "WHERE broker_id='spokeo'"
        )
        response = self.client.post(endpoint, json={}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ok"], True)
        self.assertEqual(response.json()["broker_id"], "spokeo")
        self.assertEqual(
            self.client.post(
                endpoint, json={"unexpected": True}, headers=headers
            ).status_code,
            422,
        )


class ManualAssistCliTest(unittest.TestCase):
    def test_real_parser_accepts_found_and_existing_manual_commands(self):
        parser = build_parser()
        found = parser.parse_args(["manual", "found", "spokeo", "--additional"])
        self.assertIs(found.func, cmd_manual)
        self.assertEqual(found.step, "found")
        self.assertEqual(found.broker_id, "spokeo")
        self.assertEqual(found.profile_id, "owner")
        self.assertTrue(found.additional)

        checklist = parser.parse_args(["manual", "checklist", "request-id"])
        self.assertIs(checklist.func, cmd_manual)
        self.assertEqual(checklist.step, "checklist")
        self.assertEqual(checklist.request_id, "request-id")

        submitted = parser.parse_args(["manual", "submitted", "request-id"])
        self.assertIs(submitted.func, cmd_manual)
        self.assertEqual(submitted.step, "submitted")
        self.assertEqual(submitted.request_id, "request-id")


if __name__ == "__main__":
    unittest.main()
