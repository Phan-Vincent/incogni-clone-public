import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from unittest.mock import patch

from incogni.crypto import EnvelopeCrypto
from incogni.models import FindingStatus, RequestStatus
from incogni.storage import ServiceStore


class ServiceStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "service.db")
        self.crypto = EnvelopeCrypto({"test": b"k" * 32}, "test")
        self.store = ServiceStore(self.path, self.crypto)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_v3_migration_encrypts_plaintext_confirmation_ids(self):
        legacy_path = self.path + ".v2"
        conn = sqlite3.connect(legacy_path)
        conn.execute(
            "CREATE TABLE broker_flows("
            "broker_id TEXT PRIMARY KEY,flow_version TEXT,automation_level TEXT,"
            "paused INTEGER,page_fingerprint TEXT,last_reviewed_at TEXT,"
            "updated_at TEXT)"
        )
        conn.execute(
            "CREATE TABLE removal_requests("
            "id TEXT PRIMARY KEY,finding_id TEXT,status TEXT,confirmation_id TEXT,"
            "encrypted_payload TEXT,created_at TEXT,updated_at TEXT)"
        )
        conn.execute(
            "INSERT INTO removal_requests VALUES("
            "'request-1','finding-1','confirmed',"
            "'synthetic-confirmation-secret',NULL,'now','now')"
        )
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
        conn.close()
        migrated = ServiceStore(legacy_path, self.crypto)
        try:
            row = migrated.conn.execute(
                "SELECT confirmation_id,encrypted_confirmation_id "
                "FROM removal_requests WHERE id='request-1'"
            ).fetchone()
            self.assertIsNone(row["confirmation_id"])
            self.assertEqual(
                migrated.crypto.decrypt_json(
                    row["encrypted_confirmation_id"],
                    aad=b"request-confirmation:request-1",
                )["confirmation_id"],
                "synthetic-confirmation-secret",
            )
        finally:
            migrated.close()
        with open(legacy_path, "rb") as handle:
            self.assertNotIn(b"synthetic-confirmation-secret", handle.read())

    def test_migration_is_idempotent_and_wal_enabled(self):
        self.assertEqual(self.store.health()["schema_version"], 6)
        self.assertEqual(self.store.conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.store.close()
        self.store = ServiceStore(self.path, self.crypto)
        self.assertEqual(self.store.health()["schema_version"], 6)

    def test_non_idempotent_migrations_recheck_version_after_lock(self):
        legacy_path = self.path + ".concurrent-v2"
        conn = sqlite3.connect(legacy_path)
        conn.execute(
            "CREATE TABLE broker_flows("
            "broker_id TEXT PRIMARY KEY,flow_version TEXT,automation_level TEXT,"
            "paused INTEGER,page_fingerprint TEXT,last_reviewed_at TEXT,"
            "updated_at TEXT)"
        )
        conn.execute(
            "CREATE TABLE removal_requests("
            "id TEXT PRIMARY KEY,finding_id TEXT,status TEXT,confirmation_id TEXT,"
            "encrypted_payload TEXT,created_at TEXT,updated_at TEXT)"
        )
        conn.execute("PRAGMA user_version = 2")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.commit()
        conn.close()

        barrier = threading.Barrier(2)
        original_transaction = ServiceStore.transaction

        @contextmanager
        def synchronized_transaction(store, *, immediate=False):
            if immediate:
                current = int(
                    store.conn.execute("PRAGMA user_version").fetchone()[0]
                )
                if current == 2:
                    barrier.wait(timeout=5)
            with original_transaction(store, immediate=immediate) as transaction:
                yield transaction

        def migrate():
            migrated = ServiceStore(legacy_path, self.crypto)
            try:
                return int(
                    migrated.conn.execute("PRAGMA user_version").fetchone()[0]
                )
            finally:
                migrated.close()

        with patch.object(ServiceStore, "transaction", synchronized_transaction):
            with ThreadPoolExecutor(max_workers=2) as pool:
                versions = list(pool.map(lambda _index: migrate(), range(2)))

        self.assertEqual(versions, [6, 6])
        conn = sqlite3.connect(legacy_path)
        try:
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(removal_requests)")
            }
            self.assertIn("encrypted_confirmation_id", columns)
        finally:
            conn.close()

    def test_v3_migration_recovers_present_column_before_version_advance(self):
        legacy_path = self.path + ".partial-v3"
        conn = sqlite3.connect(legacy_path)
        conn.execute(
            "CREATE TABLE broker_flows("
            "broker_id TEXT PRIMARY KEY,flow_version TEXT,automation_level TEXT,"
            "paused INTEGER,page_fingerprint TEXT,last_reviewed_at TEXT,"
            "updated_at TEXT)"
        )
        conn.execute(
            "CREATE TABLE removal_requests("
            "id TEXT PRIMARY KEY,finding_id TEXT,status TEXT,confirmation_id TEXT,"
            "encrypted_payload TEXT,created_at TEXT,updated_at TEXT,"
            "encrypted_confirmation_id TEXT)"
        )
        conn.execute(
            "INSERT INTO removal_requests VALUES("
            "'request-1','finding-1','confirmed','synthetic-partial-secret',"
            "NULL,'now','now',NULL)"
        )
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
        conn.close()

        migrated = ServiceStore(legacy_path, self.crypto)
        try:
            row = migrated.conn.execute(
                "SELECT confirmation_id,encrypted_confirmation_id "
                "FROM removal_requests WHERE id='request-1'"
            ).fetchone()
            self.assertIsNone(row["confirmation_id"])
            self.assertEqual(
                migrated.crypto.decrypt_json(
                    row["encrypted_confirmation_id"],
                    aad=b"request-confirmation:request-1",
                )["confirmation_id"],
                "synthetic-partial-secret",
            )
            self.assertEqual(
                migrated.conn.execute("PRAGMA user_version").fetchone()[0], 6
            )
        finally:
            migrated.close()

    def test_v4_migration_recovers_partially_added_columns(self):
        legacy_path = self.path + ".partial-v4"
        conn = sqlite3.connect(legacy_path)
        conn.execute(
            "CREATE TABLE broker_flows("
            "broker_id TEXT PRIMARY KEY,flow_version TEXT,automation_level TEXT,"
            "paused INTEGER,page_fingerprint TEXT,last_reviewed_at TEXT,"
            "updated_at TEXT,terms_reviewed_at TEXT)"
        )
        conn.execute("PRAGMA user_version = 3")
        conn.commit()
        conn.close()

        migrated = ServiceStore(legacy_path, self.crypto)
        try:
            columns = {
                row["name"]
                for row in migrated.conn.execute("PRAGMA table_info(broker_flows)")
            }
            self.assertTrue(
                {
                    "terms_reviewed_at",
                    "synthetic_canary_at",
                    "human_reviewed_run_at",
                    "monitor_since",
                }.issubset(columns)
            )
            self.assertEqual(
                migrated.conn.execute("PRAGMA user_version").fetchone()[0], 6
            )
        finally:
            migrated.close()

    def test_thread_scoped_connections_allow_concurrent_transactions(self):
        def write_setting(index):
            with self.store.transaction(immediate=True) as conn:
                conn.execute(
                    "INSERT INTO service_settings(key,value,updated_at) VALUES(?,?,?)",
                    (f"thread-{index}", str(index), "now"),
                )

        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(write_setting, range(24)))

        count = self.store.conn.execute(
            "SELECT count(*) FROM service_settings WHERE key LIKE 'thread-%'"
        ).fetchone()[0]
        self.assertEqual(count, 24)

    def test_sessions_are_hashed_persisted_and_revocable(self):
        self.store.register_session("synthetic-session-token", 4_102_444_800)
        self.assertTrue(
            self.store.session_is_active("synthetic-session-token", 4_102_444_800)
        )
        raw = self.store.conn.execute(
            "SELECT id FROM operator_sessions"
        ).fetchone()[0]
        self.assertNotEqual(raw, "synthetic-session-token")
        self.store.revoke_session("synthetic-session-token")
        self.assertFalse(
            self.store.session_is_active("synthetic-session-token", 4_102_444_800)
        )

    def test_legacy_tables_are_preserved(self):
        self.store.close()
        conn = sqlite3.connect(self.path)
        conn.execute("CREATE TABLE legacy_marker(value TEXT)")
        conn.execute("INSERT INTO legacy_marker VALUES('kept')")
        conn.commit()
        conn.close()
        self.store = ServiceStore(self.path, self.crypto)
        self.assertEqual(
            self.store.conn.execute("SELECT value FROM legacy_marker").fetchone()[0],
            "kept",
        )

    def test_profile_is_encrypted_at_rest(self):
        profile = {"email": "synthetic-secret@example.invalid", "name": "Jane"}
        self.store.create_profile("owner", profile)
        self.assertEqual(self.store.get_profile("owner"), profile)
        with open(self.path, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(b"synthetic-secret@example.invalid", raw)

    def test_finding_and_settings(self):
        self.store.create_profile("owner", {"name": "Jane"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CANDIDATE,
            listing_fingerprint="sha256:test",
            flow_version="1",
            payload={"listing": "synthetic"},
        )
        same = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:test",
            flow_version="1",
        )
        self.assertEqual(finding_id, same)
        row = self.store.conn.execute(
            "SELECT encrypted_payload FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        self.assertIsNotNone(row["encrypted_payload"])
        with self.assertRaises(ValueError):
            self.store.transition_finding(finding_id, FindingStatus.NOT_FOUND)

        request_id = self.store.create_removal_request(
            finding_id, payload={"synthetic": "request"}
        )
        self.store.transition_request(request_id, RequestStatus.READY)
        self.store.transition_request(request_id, RequestStatus.SUBMITTED)
        self.store.transition_request(
            request_id, RequestStatus.CONFIRMED, confirmation_id="synthetic-case"
        )
        request = self.store.conn.execute(
            "SELECT status,confirmation_id,encrypted_confirmation_id "
            "FROM removal_requests WHERE id=?", (request_id,)
        ).fetchone()
        self.assertEqual(request["status"], "confirmed")
        self.assertIsNone(request["confirmation_id"])
        self.assertNotIn("synthetic-case", request["encrypted_confirmation_id"])
        attempts = self.store.conn.execute(
            "SELECT outcome,error_code FROM attempts WHERE request_id=? ORDER BY id",
            (request_id,),
        ).fetchall()
        self.assertEqual(
            [row["outcome"] for row in attempts],
            [
                RequestStatus.READY.value,
                RequestStatus.SUBMITTED.value,
                RequestStatus.CONFIRMED.value,
            ],
        )
        self.assertTrue(all(row["error_code"] is None for row in attempts))
        audit_counts = {
            row["event_type"]: row["count"]
            for row in self.store.conn.execute(
                "SELECT event_type,count(*) count FROM audit_events "
                "WHERE entity_type='request' AND entity_id=? GROUP BY event_type",
                (request_id,),
            )
        }
        self.assertEqual(audit_counts["request_created"], 1)
        self.assertEqual(audit_counts["request_transitioned"], 3)

        with self.assertRaises(ValueError):
            self.store.transition_request(request_id, RequestStatus.READY)

        self.store.set_setting("emergency_stop", "true")
        self.assertTrue(self.store.health()["emergency_stop"])

    def test_attempt_write_failure_rolls_back_transition_and_audit(self):
        self.store.create_profile("owner", {"name": "Jane"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:attempt-rollback",
            flow_version="1",
        )
        request_id = self.store.create_removal_request(finding_id)
        self.store.conn.execute(
            "CREATE TRIGGER fail_attempt BEFORE INSERT ON attempts "
            "BEGIN SELECT RAISE(ABORT,'injected attempt failure'); END"
        )

        with self.assertRaises(sqlite3.IntegrityError):
            self.store.transition_request(request_id, RequestStatus.READY)

        self.assertEqual(
            self.store.conn.execute(
                "SELECT status FROM removal_requests WHERE id=?", (request_id,)
            ).fetchone()[0],
            RequestStatus.AWAITING_APPROVAL.value,
        )
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM attempts WHERE request_id=?", (request_id,)
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM audit_events WHERE entity_id=? "
                "AND event_type='request_transitioned'",
                (request_id,),
            ).fetchone()[0],
            0,
        )

    def test_parallel_request_transitions_allow_only_one_winner(self):
        self.store.create_profile("owner", {"name": "Jane"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:transition-race",
            flow_version="1",
        )
        request_id = self.store.create_removal_request(
            finding_id, status=RequestStatus.SUBMITTED
        )
        barrier = threading.Barrier(2)

        def transition(target):
            barrier.wait(timeout=5)
            try:
                self.store.transition_request(request_id, target)
                return "updated"
            except ValueError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(
                    transition,
                    (RequestStatus.CONFIRMED, RequestStatus.FAILED),
                )
            )

        self.assertEqual(sorted(outcomes), ["conflict", "updated"])
        status = self.store.conn.execute(
            "SELECT status FROM removal_requests WHERE id=?", (request_id,)
        ).fetchone()[0]
        self.assertIn(
            status, {RequestStatus.CONFIRMED.value, RequestStatus.FAILED.value}
        )

    def test_parallel_request_creation_is_idempotent_per_finding(self):
        self.store.create_profile("owner", {"name": "Jane"})
        finding_id = self.store.upsert_finding(
            profile_id="owner",
            broker_id="example",
            status=FindingStatus.CONFIRMED_MATCH,
            listing_fingerprint="sha256:create-race",
            flow_version="1",
        )
        barrier = threading.Barrier(8)

        def create(_index):
            barrier.wait(timeout=5)
            return self.store.create_removal_request(finding_id)

        with ThreadPoolExecutor(max_workers=8) as pool:
            request_ids = list(pool.map(create, range(8)))

        self.assertEqual(len(set(request_ids)), 1)
        self.assertEqual(
            self.store.conn.execute(
                "SELECT count(*) FROM removal_requests WHERE finding_id=?",
                (finding_id,),
            ).fetchone()[0],
            1,
        )



if __name__ == "__main__":
    unittest.main()
