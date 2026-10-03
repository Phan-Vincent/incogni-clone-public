import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from incogni.adapters.guarded import LIVE_BROKER_BY_ID, seed_live_broker_flows
from incogni.adapters.registry import SyntheticAdapterRegistry
from incogni.crypto import EnvelopeCrypto
from incogni.models import FindingStatus, JobStatus
from incogni.operations import default_handlers
from incogni.reports import write_monthly_report
from incogni.scheduler import ServiceScheduler
from incogni.storage import ServiceStore
from incogni.worker import ServiceWorker


class SchedulerReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = ServiceStore(
            self.root / "service.db",
            EnvelopeCrypto({"test": b"k" * 32}, "test"),
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_confirmed_request_gets_7_30_90_and_monthly_rechecks(self):
        self.store.create_profile("owner", {"email": "synthetic@example.invalid"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.SUPPRESSED,
            listing_fingerprint="synthetic-fingerprint",
            flow_version="fixture-1",
        )
        now = datetime(2026, 8, 26, tzinfo=timezone.utc)
        confirmed_at = (now - timedelta(days=121)).isoformat()
        self.store.conn.execute(
            "INSERT INTO removal_requests(id,finding_id,status,created_at,updated_at) "
            "VALUES('request',?,'confirmed',?,?)",
            (finding_id, confirmed_at, confirmed_at),
        )
        scheduler = ServiceScheduler(self.store)
        first = scheduler.enqueue_due_rechecks(now)
        second = scheduler.enqueue_due_rechecks(now)
        self.assertEqual(first, second)
        payloads = [
            self.store.crypto.decrypt_json(
                row["encrypted_payload"], aad=f"job:{row['id']}".encode()
            )
            for row in self.store.conn.execute(
                "SELECT id,encrypted_payload FROM jobs WHERE kind='verify_removal'"
            ).fetchall()
        ]
        self.assertEqual(
            sorted(payload["checkpoint_days"] for payload in payloads),
            [7, 30, 90, 120],
        )
        self.assertEqual(
            sorted(payload["fixture_ref"] for payload in payloads),
            [
                "scheduled_recheck_120",
                "scheduled_recheck_30",
                "scheduled_recheck_7",
                "scheduled_recheck_90",
            ],
        )

    def test_scheduled_recheck_runs_with_injected_adapter_source(self):
        self.store.create_profile("owner", {"fixture": "synthetic"})
        seed_live_broker_flows(self.store)
        flow_version = LIVE_BROKER_BY_ID["whitepages"].flow_version
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="whitepages",
            status=FindingStatus.SUPPRESSED,
            listing_fingerprint="sha256:scheduled-execution",
            flow_version=flow_version,
        )
        now = datetime(2026, 8, 26, tzinfo=timezone.utc)
        confirmed_at = (now - timedelta(days=8)).isoformat()
        self.store.conn.execute(
            "INSERT INTO removal_requests(id,finding_id,status,created_at,updated_at) "
            "VALUES('scheduled-execution-request',?,'confirmed',?,?)",
            (finding_id, confirmed_at, confirmed_at),
        )
        jobs = ServiceScheduler(self.store).enqueue_due_rechecks(now)
        self.assertEqual(len(jobs), 1)

        def fixture_source(broker_id, reference, operation):
            self.assertEqual(
                (broker_id, reference, operation),
                ("whitepages", "scheduled_recheck_7", "verify"),
            )
            return '<section id="whitepages-listing" data-result="none"></section>'

        handlers = default_handlers(
            self.store,
            evidence_dir=self.root / "evidence",
            adapter_registry=SyntheticAdapterRegistry(fixture_source),
        )
        result = ServiceWorker(
            self.store,
            "scheduled-worker",
            handlers,
            claim_kinds={"verify_removal"},
        ).run_once()

        self.assertIs(result, JobStatus.SUCCEEDED)
        job = self.store.conn.execute(
            "SELECT status,last_error_code FROM jobs WHERE id=?", (jobs[0],)
        ).fetchone()
        self.assertEqual(job["status"], JobStatus.SUCCEEDED.value)
        self.assertIsNone(job["last_error_code"])

    def test_daily_schedule_and_report_contain_no_profile_values(self):
        self.store.create_profile("owner", {"email": "synthetic@example.invalid"})
        now = datetime(2026, 8, 26, tzinfo=timezone.utc)
        jobs = ServiceScheduler(self.store).enqueue_daily_maintenance(now)
        self.assertGreaterEqual(len(jobs), 4)
        path = write_monthly_report(self.store, self.root / "reports", generated_at=now)
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn("synthetic@example.invalid", raw)
        report = json.loads(raw)
        self.assertEqual(report["month"], "2026-08")
        self.assertIn("coverage", report)


if __name__ == "__main__":
    unittest.main()
