import tempfile
import unittest
from pathlib import Path

from incogni.adapters.guarded import LIVE_BROKER_BY_ID, seed_live_broker_flows
from incogni.adapters.registry import SyntheticAdapterRegistry
from incogni.approvals import ApprovalManager
from incogni.crypto import EnvelopeCrypto
from incogni.jobs import DurableJobQueue
from incogni.models import FindingStatus, JobStatus, RequestStatus
from incogni.operations import default_handlers
from incogni.storage import ServiceStore
from incogni.worker import ServiceWorker


def fixture_source(broker_id, reference, operation):
    documents = {
        ("spokeo", "candidate", "discover"): (
            '<section id="spokeo-results" data-result="match">'
            '<article data-listing-id="synthetic-runtime-a"></article></section>'
        ),
        ("spokeo", "poll_processing", "poll"): (
            '<section id="spokeo-request-status" data-status="processing"></section>'
        ),
        ("spokeo", "verify_suppressed", "verify"): (
            '<section id="spokeo-listing" data-result="none"></section>'
        ),
        ("spokeo", "verify_reappeared", "verify"): (
            '<section id="spokeo-listing" data-result="match" '
            'data-listing-id="synthetic-runtime-new"></section>'
        ),
    }
    return documents[(broker_id, reference, operation)]


class SyntheticAdapterRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = ServiceStore(
            self.root / "service.db",
            EnvelopeCrypto({"test": b"k" * 32}, "test"),
        )
        self.store.create_profile("owner", {"fixture": "synthetic"})
        seed_live_broker_flows(self.store)
        self.queue = DurableJobQueue(self.store)
        self.registry = SyntheticAdapterRegistry(fixture_source)
        self.handlers = default_handlers(
            self.store,
            evidence_dir=self.root / "evidence",
            backup_dir=self.root / "backups",
            adapter_registry=self.registry,
        )
        self.worker = ServiceWorker(
            self.store,
            "synthetic-worker",
            self.handlers,
            claim_kinds=set(self.handlers),
        )
        self.flow_version = LIVE_BROKER_BY_ID["spokeo"].flow_version

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def enqueue(self, kind, payload, *, broker_id="spokeo", profile_id="owner"):
        return self.queue.enqueue(
            kind,
            payload,
            profile_id=profile_id,
            broker_id=broker_id,
            idempotency_key=f"synthetic:{kind}:{len(payload)}:{payload!r}",
        )

    def test_discovery_job_persists_finding_and_audit(self):
        job_id = self.enqueue(
            "discover_broker",
            {"fixture_ref": "candidate", "flow_version": self.flow_version},
        )
        self.assertIs(self.worker.run_once(), JobStatus.SUCCEEDED)
        self.assertIs(self.queue.get(job_id).status, JobStatus.SUCCEEDED)
        finding = self.store.conn.execute(
            "SELECT status,listing_fingerprint,encrypted_payload FROM findings"
        ).fetchone()
        self.assertEqual(finding["status"], FindingStatus.CANDIDATE.value)
        self.assertTrue(finding["listing_fingerprint"].startswith("sha256:"))
        self.assertNotIn("matched_fields", finding["encrypted_payload"])
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM audit_events "
                "WHERE event_type='synthetic_discovery_completed'"
            ).fetchone()[0],
            1,
        )

    def test_poll_job_transitions_existing_request(self):
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="spokeo",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:synthetic-existing",
            flow_version=self.flow_version,
        )
        request_id = self.store.create_removal_request(
            finding_id, status=RequestStatus.SUBMITTED
        )
        job_id = self.enqueue(
            "poll_request",
            {"request_id": request_id, "fixture_ref": "poll_processing"},
        )
        self.assertIs(self.worker.run_once(), JobStatus.SUCCEEDED)
        status = self.store.conn.execute(
            "SELECT status FROM removal_requests WHERE id=?", (request_id,)
        ).fetchone()[0]
        self.assertEqual(status, RequestStatus.PROCESSING.value)
        attempt = self.store.conn.execute(
            "SELECT job_id,outcome FROM attempts WHERE request_id=?", (request_id,)
        ).fetchone()
        self.assertEqual(attempt["job_id"], job_id)
        self.assertEqual(attempt["outcome"], RequestStatus.PROCESSING.value)

    def test_suppression_updates_existing_finding(self):
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="spokeo",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:synthetic-suppression",
            flow_version=self.flow_version,
        )
        self.enqueue(
            "verify_removal",
            {"finding_id": finding_id, "fixture_ref": "verify_suppressed"},
        )
        self.assertIs(self.worker.run_once(), JobStatus.SUCCEEDED)
        status = self.store.conn.execute(
            "SELECT status FROM findings WHERE id=?", (finding_id,)
        ).fetchone()[0]
        self.assertEqual(status, FindingStatus.SUPPRESSED.value)

    def test_reappearance_creates_new_finding_and_request(self):
        original_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="spokeo",
            status=FindingStatus.SUPPRESSED,
            listing_fingerprint="sha256:synthetic-history",
            flow_version=self.flow_version,
        )
        self.enqueue(
            "verify_removal",
            {"finding_id": original_id, "fixture_ref": "verify_reappeared"},
        )
        self.assertIs(self.worker.run_once(), JobStatus.SUCCEEDED)
        rows = self.store.conn.execute(
            "SELECT id,status FROM findings ORDER BY first_seen_at,id"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM findings WHERE id=?", (original_id,)
            ).fetchone()[0],
            FindingStatus.SUPPRESSED.value,
        )
        reappeared = next(row for row in rows if row["id"] != original_id)
        self.assertEqual(reappeared["status"], FindingStatus.REAPPEARED.value)
        request = self.store.conn.execute(
            "SELECT id,status FROM removal_requests WHERE finding_id=?",
            (reappeared["id"],),
        ).fetchone()
        self.assertEqual(request["status"], RequestStatus.AWAITING_APPROVAL.value)
        approval = self.store.conn.execute(
            "SELECT id,status,used_at FROM approvals WHERE request_id=?",
            (request["id"],),
        ).fetchone()
        self.assertEqual(approval["status"], "pending")
        ApprovalManager(self.store).decide_and_release(
            approval["id"], approved=True
        )
        request_status = self.store.conn.execute(
            "SELECT status FROM removal_requests WHERE id=?", (request["id"],)
        ).fetchone()[0]
        consumed = self.store.conn.execute(
            "SELECT status,used_at FROM approvals WHERE id=?", (approval["id"],)
        ).fetchone()
        self.assertEqual(request_status, RequestStatus.READY.value)
        self.assertEqual(consumed["status"], "used")
        self.assertIsNotNone(consumed["used_at"])

    def test_reappearance_effects_are_idempotent_after_lease_replay(self):
        original_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="spokeo",
            status=FindingStatus.SUPPRESSED,
            listing_fingerprint="sha256:crash-history",
            flow_version=self.flow_version,
        )
        job_id = self.enqueue(
            "verify_removal",
            {"finding_id": original_id, "fixture_ref": "verify_reappeared"},
        )
        claimed = self.queue.claim("crashing-worker", lease_seconds=1)
        self.assertEqual(claimed.id, job_id)
        self.handlers["verify_removal"](claimed)

        self.store.conn.execute(
            "UPDATE jobs SET lease_expires_at=? WHERE id=?",
            ("1970-01-01T00:00:00+00:00", job_id),
        )
        replay = self.queue.claim("replacement-worker", lease_seconds=30)
        self.assertEqual(replay.id, job_id)
        self.handlers["verify_removal"](replay)
        self.queue.succeed(job_id, "replacement-worker")

        reappeared = self.store.conn.execute(
            "SELECT id FROM findings WHERE status=?",
            (FindingStatus.REAPPEARED.value,),
        ).fetchall()
        requests = self.store.conn.execute(
            "SELECT id,status FROM removal_requests"
        ).fetchall()
        approvals = self.store.conn.execute(
            "SELECT request_id,status FROM approvals"
        ).fetchall()
        self.assertEqual(len(reappeared), 1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["request_id"], requests[0]["id"])
        self.assertEqual(requests[0]["status"], RequestStatus.AWAITING_APPROVAL.value)
        self.assertEqual(approvals[0]["status"], "pending")
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM audit_events "
                "WHERE event_type='synthetic_removal_verified'"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM audit_events "
                "WHERE event_type='synthetic_job_effect_committed' "
                "AND entity_id=?",
                (job_id,),
            ).fetchone()[0],
            1,
        )
        self.assertEqual(self.queue.get(job_id).attempts, 2)


    def test_missing_source_unknown_broker_and_version_drift_block(self):
        no_source_handlers = default_handlers(
            self.store,
            evidence_dir=self.root / "evidence",
            backup_dir=self.root / "backups",
        )
        no_source_worker = ServiceWorker(
            self.store,
            "no-source-worker",
            no_source_handlers,
            claim_kinds=set(no_source_handlers),
        )
        missing_id = self.enqueue(
            "discover_broker",
            {"fixture_ref": "candidate", "flow_version": self.flow_version},
        )
        self.assertIs(no_source_worker.run_once(), JobStatus.BLOCKED)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT last_error_code FROM jobs WHERE id=?", (missing_id,)
            ).fetchone()[0],
            "fixture_source_required",
        )

        unknown_id = self.enqueue(
            "discover_broker",
            {"fixture_ref": "candidate", "flow_version": "synthetic"},
            broker_id="unregistered",
        )
        self.assertIs(self.worker.run_once(), JobStatus.BLOCKED)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT last_error_code FROM jobs WHERE id=?", (unknown_id,)
            ).fetchone()[0],
            "unknown_broker",
        )

        drift_id = self.enqueue(
            "discover_broker",
            {"fixture_ref": "candidate", "flow_version": "stale-flow"},
        )
        self.assertIs(self.worker.run_once(), JobStatus.BLOCKED)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT last_error_code FROM jobs WHERE id=?", (drift_id,)
            ).fetchone()[0],
            "flow_version_changed",
        )

    def test_emergency_stop_leaves_job_queued(self):
        job_id = self.enqueue(
            "discover_broker",
            {"fixture_ref": "candidate", "flow_version": self.flow_version},
        )
        self.store.set_setting("emergency_stop", "true")
        self.assertIs(self.worker.run_once(), JobStatus.BLOCKED)
        self.assertIs(self.queue.get(job_id).status, JobStatus.QUEUED)


    def test_missing_reference_and_unknown_job_kind_block(self):
        missing_id = self.enqueue(
            "discover_broker", {"flow_version": self.flow_version}
        )
        self.assertIs(self.worker.run_once(), JobStatus.BLOCKED)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT last_error_code FROM jobs WHERE id=?", (missing_id,)
            ).fetchone()[0],
            "fixture_reference_required",
        )

        unknown_id = self.enqueue("synthetic_unknown_operation", {})
        unknown_worker = ServiceWorker(self.store, "unknown-worker", {})
        self.assertIs(unknown_worker.run_once(), JobStatus.BLOCKED)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT last_error_code FROM jobs WHERE id=?", (unknown_id,)
            ).fetchone()[0],
            "unknown_job_kind",
        )

    def test_database_flow_drift_blocks_before_fixture_dispatch(self):
        self.store.conn.execute(
            "UPDATE broker_flows SET flow_version='stale-database-flow' "
            "WHERE broker_id='spokeo'"
        )
        job_id = self.enqueue(
            "discover_broker",
            {"fixture_ref": "candidate", "flow_version": self.flow_version},
        )
        self.assertIs(self.worker.run_once(), JobStatus.BLOCKED)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT last_error_code FROM jobs WHERE id=?", (job_id,)
            ).fetchone()[0],
            "flow_version_changed",
        )


if __name__ == "__main__":
    unittest.main()
