import json
import tempfile
import time
import unittest
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from unittest.mock import Mock, patch, sentinel

from fastapi.testclient import TestClient

from incogni.api import create_app
from incogni.approvals import ApprovalManager
from incogni.auth import LoginThrottle, OperatorAuth
from incogni.crypto import EnvelopeCrypto
from incogni.jobs import DurableJobQueue
from incogni.models import FindingStatus, JobStatus, RequestStatus
from incogni.service_cli import cmd_serve
from incogni.service_config import ServiceConfig
from incogni.storage import ServiceStore
from incogni.worker import ServiceWorker


class AuthTest(unittest.TestCase):
    def test_login_throttle_expires_and_resets(self):
        now = [100.0]
        throttle = LoginThrottle(
            max_failures=2, window_seconds=10, clock=lambda: now[0]
        )
        throttle.record_failure("local")
        self.assertTrue(throttle.allowed("local"))
        throttle.record_failure("local")
        self.assertFalse(throttle.allowed("local"))
        now[0] = 111.0
        self.assertTrue(throttle.allowed("local"))
        throttle.record_failure("local")
        throttle.record_success("local")
        self.assertTrue(throttle.allowed("local"))

    def test_parallel_attempts_are_reserved_and_verification_is_bounded(self):
        throttle = LoginThrottle(
            max_failures=5, max_concurrent_verifications=2
        )
        state = {"active": 0, "peak": 0}
        state_lock = Lock()

        def verifier():
            with state_lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.03)
            with state_lock:
                state["active"] -= 1
            return False

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(
                pool.map(
                    lambda _index: throttle.authenticate("same-source", verifier),
                    range(12),
                )
            )
        self.assertEqual(results.count(False), 5)
        self.assertEqual(results.count(None), 7)
        self.assertLessEqual(state["peak"], 2)

    def test_password_and_signed_session(self):
        password_hash = OperatorAuth.hash_password("correct horse battery")
        now = [1000.0]
        auth = OperatorAuth(
            password_hash, b"s" * 32, ttl_seconds=60, clock=lambda: now[0]
        )
        self.assertTrue(auth.verify_password("correct horse battery"))
        self.assertFalse(auth.verify_password("wrong password"))
        token, session = auth.issue_session()
        self.assertEqual(auth.verify_session(token), session)
        self.assertIsNone(auth.verify_session(token + "x"))
        now[0] = 1061
        self.assertIsNone(auth.verify_session(token))


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        crypto = EnvelopeCrypto({"test": b"k" * 32}, "test")
        self.store = ServiceStore(Path(self.tmp.name) / "service.db", crypto)
        config = ServiceConfig(
            db_path=Path(self.tmp.name) / "service.db",
            evidence_dir=Path(self.tmp.name) / "evidence",
            crypto=crypto,
            signing_key=b"k" * 32,
            admin_password_hash=OperatorAuth.hash_password(
                "correct horse battery"
            ),
            secure_cookies=False,
        )
        self.app = create_app(self.store, config)
        self.client = TestClient(self.app)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def login(self):
        response = self.client.post(
            "/api/login", json={"password": "correct horse battery"}
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["csrf_token"]

    def test_health_and_authentication(self):
        health = self.client.get("/healthz")
        self.assertEqual(health.json(), {"status": "ok"})
        self.assertEqual(health.headers["x-frame-options"], "DENY")
        self.assertEqual(health.headers["cache-control"], "no-store")
        self.assertEqual(self.client.get("/api/status").status_code, 401)
        self.assertEqual(
            self.client.post("/api/login", json={"password": "incorrect value"}).status_code,
            401,
        )
        self.login()
        self.assertEqual(self.client.get("/api/status").status_code, 200)

    def test_csrf_pause_resume_and_drop(self):
        csrf = self.login()
        self.assertEqual(self.client.post("/api/pause").status_code, 403)
        headers = {"X-CSRF-Token": csrf}
        self.assertTrue(
            self.client.post("/api/pause", headers=headers).json()["emergency_stop"]
        )
        self.assertFalse(
            self.client.post("/api/resume", headers=headers).json()["emergency_stop"]
        )
        bad = self.client.post(
            "/api/drop",
            headers=headers,
            json={"enrolled": True, "terms_acknowledged": False},
        )
        self.assertEqual(bad.status_code, 422)
        good = self.client.post(
            "/api/drop",
            headers=headers,
            json={"enrolled": True, "terms_acknowledged": True},
        )
        self.assertEqual(good.status_code, 200)
        self.assertTrue(self.client.get("/api/drop").json()["enrolled"])

    def test_logout_revokes_a_copied_session(self):
        csrf = self.login()
        token = self.client.cookies.get("incogni_session")
        self.assertEqual(
            self.client.post(
                "/api/logout", headers={"X-CSRF-Token": csrf}
            ).status_code,
            200,
        )
        with TestClient(self.app) as replay:
            replay.cookies.set("incogni_session", token)
            self.assertEqual(replay.get("/api/status").status_code, 401)

    def test_strict_models_body_limit_and_redacted_validation(self):
        oversized = "x" * (64 * 1024)
        response = self.client.post(
            "/api/login",
            content=json.dumps({"password": oversized}),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)
        self.assertNotIn(oversized[:100], response.text)

        def chunked_body():
            yield b'{"password":"'
            yield b"x" * 40_000
            yield b"x" * 40_000
            yield b'"}'

        chunked = self.client.post(
            "/api/login",
            content=chunked_body(),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(chunked.status_code, 413)
        self.assertEqual(chunked.json(), {"detail": "request body too large"})

        validation = self.client.post(
            "/api/login", json={"password": "x" * 1025}
        )
        self.assertEqual(validation.status_code, 422)
        self.assertNotIn("x" * 100, validation.text)

        csrf = self.login()
        headers = {"X-CSRF-Token": csrf}
        extra = self.client.post(
            "/api/drop",
            headers=headers,
            json={
                "enrolled": False,
                "terms_acknowledged": False,
                "unexpected": "rejected",
            },
        )
        self.assertEqual(extra.status_code, 422)
        identifier = self.client.post(
            "/api/drop",
            headers=headers,
            json={
                "enrolled": True,
                "terms_acknowledged": True,
                "identifier": "A" * 513,
            },
        )
        self.assertEqual(identifier.status_code, 422)

    def test_concurrent_approval_requests_use_independent_transactions(self):
        queue = DurableJobQueue(self.store)
        approval_ids = []
        job_ids = []
        for index in range(12):
            job_id = queue.enqueue(
                "guarded", {}, idempotency_key=f"approval-race-{index}"
            )
            claimed = queue.claim(f"seed-{index}")
            queue.block(claimed.id, f"seed-{index}", "approval_required")
            job_ids.append(job_id)
            approval_ids.append(
                ApprovalManager(self.store).create(
                    "guarded", job_id=job_id
                )
            )

        csrf = self.login()
        token = self.client.cookies.get("incogni_session")

        def approve(approval_id):
            with TestClient(self.app) as client:
                client.cookies.set("incogni_session", token)
                return client.post(
                    f"/api/approvals/{approval_id}/approve",
                    headers={"X-CSRF-Token": csrf},
                ).status_code

        with ThreadPoolExecutor(max_workers=12) as pool:
            codes = list(pool.map(approve, approval_ids))
        self.assertEqual(codes, [200] * 12)
        self.assertTrue(
            all(queue.get(job_id).status is JobStatus.QUEUED for job_id in job_ids)
        )

    def test_approval_endpoint_releases_job_once(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue("guarded", {}, idempotency_key="approval-api")
        claimed = queue.claim("worker")
        queue.block(claimed.id, "worker", "approval_required")
        approval_id = ApprovalManager(self.store).create(
            "guarded", job_id=job_id
        )
        csrf = self.login()
        response = self.client.post(
            f"/api/approvals/{approval_id}/approve",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(queue.get(job_id).status, JobStatus.QUEUED)
        replay = self.client.post(
            f"/api/approvals/{approval_id}/approve",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(replay.status_code, 409)

    def test_protected_job_requires_matching_consumed_approval(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue(
            "open_verification_link",
            {"notification_id": "synthetic"},
            idempotency_key="protected-approval",
        )
        self.assertIsNone(
            queue.claim("premature-worker", kinds={"open_verification_link"})
        )
        with self.assertRaises(ValueError):
            ApprovalManager(self.store).create("unrelated_action", job_id=job_id)

        approval_id = ApprovalManager(self.store).create(
            "open_verification_link", job_id=job_id
        )
        self.assertIsNone(
            queue.claim("still-premature", kinds={"open_verification_link"})
        )
        csrf = self.login()
        approved = self.client.post(
            f"/api/approvals/{approval_id}/approve",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(approved.status_code, 200)
        approval = self.store.conn.execute(
            "SELECT status,used_at FROM approvals WHERE id=?", (approval_id,)
        ).fetchone()
        self.assertEqual(approval["status"], "used")
        self.assertIsNotNone(approval["used_at"])

        claimed = queue.claim(
            "authorized-worker", kinds={"open_verification_link"}
        )
        self.assertEqual(claimed.id, job_id)
        queue.succeed(job_id, "authorized-worker")
        with self.assertRaises(ValueError):
            ApprovalManager(self.store).create(
                "open_verification_link", job_id=job_id
            )
        replay = self.client.post(
            f"/api/approvals/{approval_id}/approve",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(replay.status_code, 409)

    def expire_approval(self, approval_id):
        self.store.conn.execute(
            "UPDATE approvals SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
            (approval_id,),
        )

    def test_expired_job_approval_is_reissued_instead_of_stranding_job(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue(
            "open_verification_link",
            {"notification_id": "synthetic"},
            idempotency_key="expired-approval",
        )
        approvals = ApprovalManager(self.store)
        stale = approvals.create("open_verification_link", job_id=job_id)
        self.expire_approval(stale)
        csrf = self.login()
        self.assertEqual(
            self.client.post(
                f"/api/approvals/{stale}/approve", headers={"X-CSRF-Token": csrf}
            ).status_code,
            409,
        )

        fresh = approvals.create("open_verification_link", job_id=job_id)
        self.assertNotEqual(fresh, stale)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM approvals WHERE id=?", (stale,)
            ).fetchone()[0],
            "expired",
        )
        self.assertIsNone(queue.claim("premature", kinds={"open_verification_link"}))
        self.assertEqual(
            self.client.post(
                f"/api/approvals/{fresh}/approve", headers={"X-CSRF-Token": csrf}
            ).status_code,
            200,
        )
        self.assertEqual(
            queue.claim("authorized", kinds={"open_verification_link"}).id, job_id
        )

    def test_reissue_endpoint_replaces_only_expired_undecided_approvals(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue(
            "open_verification_link",
            {"notification_id": "synthetic"},
            idempotency_key="reissue-endpoint",
        )
        stale = ApprovalManager(self.store).create(
            "open_verification_link", job_id=job_id
        )
        csrf = self.login()
        headers = {"X-CSRF-Token": csrf}
        early = self.client.post(f"/api/approvals/{stale}/reissue", headers=headers)
        self.assertEqual(early.status_code, 409)
        listed = self.client.get("/api/approvals").json()
        self.assertEqual([(row["id"], row["expired"]) for row in listed], [(stale, False)])

        self.expire_approval(stale)
        listed = self.client.get("/api/approvals").json()
        self.assertEqual([(row["id"], row["expired"]) for row in listed], [(stale, True)])
        response = self.client.post(f"/api/approvals/{stale}/reissue", headers=headers)
        self.assertEqual(response.status_code, 200)
        fresh = response.json()["approval_id"]
        self.assertNotEqual(fresh, stale)
        replay = self.client.post(f"/api/approvals/{stale}/reissue", headers=headers)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json()["approval_id"], fresh)
        listed = self.client.get("/api/approvals").json()
        self.assertEqual([(row["id"], row["expired"]) for row in listed], [(fresh, False)])
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM audit_events WHERE event_type='approval_reissued' "
                "AND entity_id=?",
                (fresh,),
            ).fetchone()[0],
            2,
        )

        self.assertEqual(
            self.client.post(
                f"/api/approvals/{fresh}/approve", headers=headers
            ).status_code,
            200,
        )
        self.expire_approval(fresh)
        decided = self.client.post(f"/api/approvals/{fresh}/reissue", headers=headers)
        self.assertEqual(decided.status_code, 409)
        missing = self.client.post("/api/approvals/missing/reissue", headers=headers)
        self.assertEqual(missing.status_code, 409)
        no_csrf = self.client.post(f"/api/approvals/{stale}/reissue")
        self.assertEqual(no_csrf.status_code, 403)

    def test_expired_approval_does_not_release_unprotected_job(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue("guarded", {}, idempotency_key="expired-unprotected")
        stale = ApprovalManager(self.store).create("guarded", job_id=job_id)
        self.expire_approval(stale)
        self.assertIsNone(queue.claim("worker"))

    def test_expired_request_approval_is_reissued(self):
        self.store.create_profile("owner", {"fixture": "synthetic"})
        finding = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:expired-request-approval",
            flow_version="1",
        )
        request_id = self.store.create_removal_request(finding)
        approvals = ApprovalManager(self.store)
        stale = approvals.create("submit_removal", request_id=request_id)
        self.expire_approval(stale)
        fresh = approvals.create("submit_removal", request_id=request_id)
        self.assertNotEqual(fresh, stale)
        self.assertEqual(approvals.create("submit_removal", request_id=request_id), fresh)
        approvals.decide_and_release(fresh, approved=True)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM removal_requests WHERE id=?", (request_id,)
            ).fetchone()[0],
            RequestStatus.READY.value,
        )

    def test_request_approval_atomically_advances_or_cancels_request(self):
        self.store.create_profile("owner", {"fixture": "synthetic"})
        first_finding = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:approve-request",
            flow_version="1",
        )
        first_request = self.store.create_removal_request(first_finding)
        first_approval = ApprovalManager(self.store).create(
            "submit_removal", request_id=first_request
        )

        csrf = self.login()
        approved = self.client.post(
            f"/api/approvals/{first_approval}/approve",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM removal_requests WHERE id=?", (first_request,)
            ).fetchone()[0],
            RequestStatus.READY.value,
        )
        consumed = self.store.conn.execute(
            "SELECT status,used_at FROM approvals WHERE id=?", (first_approval,)
        ).fetchone()
        self.assertEqual(consumed["status"], "used")
        self.assertIsNotNone(consumed["used_at"])

        second_finding = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:reject-request",
            flow_version="1",
        )
        second_request = self.store.create_removal_request(second_finding)
        second_approval = ApprovalManager(self.store).create(
            "submit_removal", request_id=second_request
        )
        rejected = self.client.post(
            f"/api/approvals/{second_approval}/reject",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM removal_requests WHERE id=?", (second_request,)
            ).fetchone()[0],
            RequestStatus.CANCELLED.value,
        )


    def test_retry_endpoint(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue("unknown", {}, idempotency_key="job:1")
        claimed = queue.claim("worker")
        queue.block(claimed.id, "worker", "manual")
        csrf = self.login()
        response = self.client.post(
            "/api/retry",
            headers={"X-CSRF-Token": csrf},
            json={"job_id": job_id},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(queue.get(job_id).status, JobStatus.QUEUED)

    def test_retry_cannot_bypass_required_approval(self):
        queue = DurableJobQueue(self.store)
        job_id = queue.enqueue(
            "open_verification_link",
            {"notification_id": "synthetic-notification"},
            idempotency_key="approval-bound-retry",
        )
        self.store.conn.execute(
            "UPDATE jobs SET status='blocked',last_error_code='approval_required' "
            "WHERE id=?",
            (job_id,),
        )
        approval_id = ApprovalManager(self.store).create(
            "open_verification_link", job_id=job_id
        )

        csrf = self.login()
        response = self.client.post(
            "/api/retry",
            headers={"X-CSRF-Token": csrf},
            json={"job_id": job_id},
        )

        self.assertEqual(response.status_code, 409)
        rejection = self.client.post(
            f"/api/approvals/{approval_id}/reject",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(rejection.status_code, 200)
        replay = self.client.post(
            "/api/retry",
            headers={"X-CSRF-Token": csrf},
            json={"job_id": job_id},
        )
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(queue.get(job_id).status, JobStatus.BLOCKED)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM approvals WHERE id=?", (approval_id,)
            ).fetchone()["status"],
            "rejected",
        )


class ServiceLauncherTest(unittest.TestCase):
    def test_serve_does_not_trust_forwarded_headers(self):
        store = Mock()
        with (
            patch(
                "incogni.service_cli._open_service",
                return_value=(sentinel.config, store),
            ),
            patch("incogni.service_cli.create_app", return_value=sentinel.app),
            patch("uvicorn.run") as run,
        ):
            self.assertEqual(
                cmd_serve(Namespace(host="127.0.0.1", port=8765)), 0
            )
        run.assert_called_once_with(
            sentinel.app,
            host="127.0.0.1",
            port=8765,
            log_config=None,
            proxy_headers=False,
        )
        store.close.assert_called_once_with()


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.store = ServiceStore(
            ":memory:", EnvelopeCrypto({"test": b"k" * 32}, "test")
        )

    def tearDown(self):
        self.store.close()

    def test_success_block_failure_and_stop(self):
        queue = DurableJobQueue(self.store)
        queue.enqueue("ok", {}, idempotency_key="ok")
        worker = ServiceWorker(self.store, "w", {"ok": lambda job: None})
        self.assertEqual(worker.run_once(), JobStatus.SUCCEEDED)

        queue.enqueue("approval", {}, idempotency_key="approval")
        worker.handlers["approval"] = lambda job: (_ for _ in ()).throw(
            PermissionError()
        )
        self.assertEqual(worker.run_once(), JobStatus.BLOCKED)

        self.store.set_setting("emergency_stop", "true")
        self.assertEqual(worker.run_once(), JobStatus.BLOCKED)


if __name__ == "__main__":
    unittest.main()
