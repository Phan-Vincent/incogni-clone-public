"""Versioned SQLite persistence for the autonomous service."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from incogni.crypto import EnvelopeCrypto
from incogni.models import FindingStatus, RequestStatus
from incogni.state_machine import (
    ensure_finding_transition,
    ensure_request_transition,
)


def utciso() -> str:
    return datetime.now(timezone.utc).isoformat()


_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    encrypted_profile TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL REFERENCES profiles(id),
    broker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    listing_fingerprint TEXT NOT NULL,
    flow_version TEXT NOT NULL,
    encrypted_payload TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(profile_id, broker_id, listing_fingerprint)
);
CREATE TABLE IF NOT EXISTS removal_requests (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    status TEXT NOT NULL,
    confirmation_id TEXT,
    encrypted_payload TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT REFERENCES removal_requests(id),
    job_id TEXT,
    outcome TEXT NOT NULL,
    error_code TEXT,
    encrypted_payload TEXT,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    profile_id TEXT,
    broker_id TEXT,
    status TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    encrypted_payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_claim
    ON jobs(status, available_at, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_scope
    ON jobs(profile_id, broker_id, status);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    request_id TEXT REFERENCES removal_requests(id),
    job_id TEXT REFERENCES jobs(id),
    action TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS broker_flows (
    broker_id TEXT PRIMARY KEY,
    flow_version TEXT NOT NULL,
    automation_level TEXT NOT NULL,
    paused INTEGER NOT NULL DEFAULT 1,
    page_fingerprint TEXT,
    last_reviewed_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    provider_message_id TEXT UNIQUE,
    status TEXT NOT NULL,
    encrypted_payload TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    content_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    encrypted_path TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS service_secrets (
    name TEXT PRIMARY KEY,
    encrypted_value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

_SCHEMA_V3 = "ALTER TABLE removal_requests ADD COLUMN encrypted_confirmation_id TEXT;"

_SCHEMA_V4 = (
    ("terms_reviewed_at", "ALTER TABLE broker_flows ADD COLUMN terms_reviewed_at TEXT"),
    ("synthetic_canary_at", "ALTER TABLE broker_flows ADD COLUMN synthetic_canary_at TEXT"),
    (
        "human_reviewed_run_at",
        "ALTER TABLE broker_flows ADD COLUMN human_reviewed_run_at TEXT",
    ),
    ("monitor_since", "ALTER TABLE broker_flows ADD COLUMN monitor_since TEXT"),
)

_SCHEMA_V5 = """
CREATE TABLE IF NOT EXISTS broker_runtime (
    broker_id TEXT PRIMARY KEY REFERENCES broker_flows(broker_id),
    window_started_at TEXT,
    operation_count INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    circuit_open_until TEXT,
    updated_at TEXT NOT NULL
);
"""

_SCHEMA_V6 = """
CREATE TABLE IF NOT EXISTS operator_sessions (
    id TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operator_sessions_expiry
    ON operator_sessions(expires_at);
"""


class ServiceStore:
    """SQLite store that keeps sensitive values encrypted at the application layer."""

    SCHEMA_VERSION = 6

    def __init__(self, db_path: str | Path, crypto: EnvelopeCrypto):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.crypto = crypto
        self._connection_lock = threading.Lock()
        self._connections: dict[int, sqlite3.Connection] = {}
        self._closed = False
        self._sqlite_uri = self.db_path == ":memory:"
        self._sqlite_target = (
            f"file:incogni-{uuid4().hex}?mode=memory&cache=shared"
            if self._sqlite_uri
            else self.db_path
        )
        self._connections[threading.get_ident()] = self._new_connection()
        self._migrate()

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._sqlite_target,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
            uri=self._sqlite_uri,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA secure_delete = ON")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        thread_id = threading.get_ident()
        with self._connection_lock:
            if self._closed:
                raise RuntimeError("service store is closed")
            connection = self._connections.get(thread_id)
            if connection is None:
                connection = self._new_connection()
                self._connections[thread_id] = connection
            return connection

    def _apply_sql_migration(self, script: str, version: int) -> None:
        try:
            self.conn.executescript(
                "BEGIN IMMEDIATE;\n"
                + script
                + f"\nPRAGMA user_version = {version};\nCOMMIT;"
            )
        except Exception:
            self.conn.rollback()
            raise

    def _migrate(self) -> None:
        version = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
        if version > self.SCHEMA_VERSION:
            raise RuntimeError("database schema is newer than this application")
        if version < 1:
            self._apply_sql_migration(_SCHEMA_V1, 1)
            version = 1
        if version < 2:
            self._apply_sql_migration(_SCHEMA_V2, 2)
            version = 2
        if version < 3:
            with self.transaction(immediate=True) as conn:
                locked_version = int(
                    conn.execute("PRAGMA user_version").fetchone()[0]
                )
                if locked_version < 3:
                    request_columns = {
                        row["name"]
                        for row in conn.execute(
                            "PRAGMA table_info(removal_requests)"
                        )
                    }
                    if "encrypted_confirmation_id" not in request_columns:
                        conn.execute(_SCHEMA_V3)
                    rows = conn.execute(
                        "SELECT id,confirmation_id FROM removal_requests "
                        "WHERE confirmation_id IS NOT NULL"
                    ).fetchall()
                    for row in rows:
                        encrypted = self.crypto.encrypt_json(
                            {"confirmation_id": row["confirmation_id"]},
                            aad=f"request-confirmation:{row['id']}".encode(),
                        )
                        conn.execute(
                            "UPDATE removal_requests SET encrypted_confirmation_id=?,"
                            "confirmation_id=NULL WHERE id=?",
                            (encrypted, row["id"]),
                        )
                    conn.execute("PRAGMA user_version = 3")
                    locked_version = 3
            version = locked_version
        if version < 4:
            with self.transaction(immediate=True) as conn:
                locked_version = int(
                    conn.execute("PRAGMA user_version").fetchone()[0]
                )
                if locked_version < 4:
                    broker_columns = {
                        row["name"]
                        for row in conn.execute("PRAGMA table_info(broker_flows)")
                    }
                    for column, statement in _SCHEMA_V4:
                        if column not in broker_columns:
                            conn.execute(statement)
                    conn.execute(
                        "UPDATE broker_flows "
                        "SET monitor_since=COALESCE(monitor_since,?)",
                        (utciso(),),
                    )
                    conn.execute("PRAGMA user_version = 4")
                    locked_version = 4
            version = locked_version
        if version < 5:
            self._apply_sql_migration(_SCHEMA_V5, 5)
            version = 5
        if version < 6:
            self._apply_sql_migration(_SCHEMA_V6, 6)
            version = 6

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        else:
            conn.commit()

    def close(self) -> None:
        with self._connection_lock:
            if self._closed:
                return
            self._closed = True
            connections = list(self._connections.values())
            self._connections.clear()
        for connection in connections:
            connection.close()

    def __enter__(self) -> "ServiceStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def create_profile(self, profile_id: str, profile: dict[str, Any]) -> None:
        now = utciso()
        encrypted = self.crypto.encrypt_json(profile, aad=f"profile:{profile_id}".encode())
        self.conn.execute(
            "INSERT INTO profiles(id, encrypted_profile, created_at, updated_at) "
            "VALUES(?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
            "encrypted_profile=excluded.encrypted_profile, updated_at=excluded.updated_at",
            (profile_id, encrypted, now, now),
        )

    def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT encrypted_profile FROM profiles WHERE id=?", (profile_id,)
        ).fetchone()
        if row is None:
            return None
        value = self.crypto.decrypt_json(
            row["encrypted_profile"], aad=f"profile:{profile_id}".encode()
        )
        if not isinstance(value, dict):
            raise ValueError("encrypted profile is not an object")
        return value

    def upsert_finding(
        self,
        *,
        profile_id: str,
        broker_id: str,
        status: FindingStatus,
        listing_fingerprint: str,
        flow_version: str,
        payload: dict[str, Any] | None = None,
    ) -> str:
        existing = self.conn.execute(
            "SELECT id,status FROM findings WHERE profile_id=? AND broker_id=? "
            "AND listing_fingerprint=?",
            (profile_id, broker_id, listing_fingerprint),
        ).fetchone()
        finding_id = existing["id"] if existing else uuid4().hex
        if existing:
            ensure_finding_transition(FindingStatus(existing["status"]), status)
        now = utciso()
        encrypted = (
            self.crypto.encrypt_json(payload, aad=f"finding:{finding_id}".encode())
            if payload is not None
            else None
        )
        self.conn.execute(
            "INSERT INTO findings(id,profile_id,broker_id,status,listing_fingerprint,"
            "flow_version,encrypted_payload,first_seen_at,last_seen_at) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(profile_id,broker_id,listing_fingerprint) "
            "DO UPDATE SET status=excluded.status,flow_version=excluded.flow_version,"
            "encrypted_payload=COALESCE(excluded.encrypted_payload,findings.encrypted_payload),"
            "last_seen_at=excluded.last_seen_at",
            (
                finding_id,
                profile_id,
                broker_id,
                status.value,
                listing_fingerprint,
                flow_version,
                encrypted,
                now,
                now,
            ),
        )
        return finding_id

    def transition_finding(self, finding_id: str, target: FindingStatus) -> None:
        row = self.conn.execute(
            "SELECT status FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if row is None:
            raise KeyError(finding_id)
        ensure_finding_transition(FindingStatus(row["status"]), target)
        self.conn.execute(
            "UPDATE findings SET status=?,last_seen_at=? WHERE id=?",
            (target.value, utciso(), finding_id),
        )

    def create_removal_request(
        self,
        finding_id: str,
        *,
        status: RequestStatus = RequestStatus.AWAITING_APPROVAL,
        payload: dict[str, Any] | None = None,
    ) -> str:
        conn = self.conn
        if not conn.in_transaction:
            with self.transaction(immediate=True):
                return self.create_removal_request(
                    finding_id, status=status, payload=payload
                )
        existing = conn.execute(
            "SELECT id FROM removal_requests WHERE finding_id=?", (finding_id,)
        ).fetchone()
        if existing is not None:
            return existing["id"]

        request_id = uuid4().hex
        encrypted = (
            self.crypto.encrypt_json(payload, aad=f"request:{request_id}".encode())
            if payload is not None
            else None
        )
        now = utciso()
        conn.execute(
            "INSERT INTO removal_requests(id,finding_id,status,encrypted_payload,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (request_id, finding_id, status.value, encrypted, now, now),
        )
        self.record_audit(
            "request_created",
            "request",
            request_id,
            json.dumps(
                {"finding_id": finding_id, "status": status.value},
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
        return request_id

    def transition_request(
        self,
        request_id: str,
        target: RequestStatus,
        *,
        confirmation_id: str | None = None,
        job_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        conn = self.conn
        if not conn.in_transaction:
            with self.transaction(immediate=True):
                return self.transition_request(
                    request_id,
                    target,
                    confirmation_id=confirmation_id,
                    job_id=job_id,
                    error_code=error_code,
                )

        row = conn.execute(
            "SELECT status FROM removal_requests WHERE id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise KeyError(request_id)
        current = RequestStatus(row["status"])
        ensure_request_transition(current, target)
        if current is target:
            return
        encrypted_confirmation = (
            self.crypto.encrypt_json(
                {"confirmation_id": confirmation_id},
                aad=f"request-confirmation:{request_id}".encode(),
            )
            if confirmation_id is not None
            else None
        )
        now = utciso()
        cursor = conn.execute(
            "UPDATE removal_requests SET status=?,"
            "encrypted_confirmation_id=COALESCE(?,encrypted_confirmation_id),"
            "confirmation_id=NULL,updated_at=? WHERE id=? AND status=?",
            (
                target.value,
                encrypted_confirmation,
                now,
                request_id,
                current.value,
            ),
        )
        if cursor.rowcount != 1:
            changed = conn.execute(
                "SELECT status FROM removal_requests WHERE id=?", (request_id,)
            ).fetchone()
            if changed is None:
                raise KeyError(request_id)
            if changed["status"] == target.value:
                return
            raise ValueError(
                f"request state changed concurrently: {current.value} -> "
                f"{changed['status']}"
            )

        conn.execute(
            "INSERT INTO attempts(request_id,job_id,outcome,error_code,occurred_at) "
            "VALUES(?,?,?,?,?)",
            (request_id, job_id, target.value, error_code, now),
        )
        metadata: dict[str, str] = {
            "from": current.value,
            "to": target.value,
        }
        if job_id is not None:
            metadata["job_id"] = job_id
        if error_code is not None:
            metadata["error_code"] = error_code
        self.record_audit(
            "request_transitioned",
            "request",
            request_id,
            json.dumps(metadata, separators=(",", ":"), sort_keys=True),
        )

    def set_setting(self, key: str, value: str) -> None:
        now = utciso()
        self.conn.execute(
            "INSERT INTO service_settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (key, value, now),
        )

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM service_settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def register_session(self, session_id: str, expires_at: int) -> None:
        now = utciso()
        with self.transaction(immediate=True) as conn:
            conn.execute(
                "DELETE FROM operator_sessions WHERE expires_at<=?",
                (int(datetime.now(timezone.utc).timestamp()),),
            )
            conn.execute(
                "INSERT INTO operator_sessions(id,expires_at,created_at) VALUES(?,?,?)",
                (hashlib.sha256(session_id.encode()).hexdigest(), expires_at, now),
            )

    def session_is_active(self, session_id: str, expires_at: int) -> bool:
        row = self.conn.execute(
            "SELECT expires_at,revoked_at FROM operator_sessions WHERE id=?",
            (hashlib.sha256(session_id.encode()).hexdigest(),),
        ).fetchone()
        return bool(
            row
            and row["revoked_at"] is None
            and int(row["expires_at"]) == expires_at
            and expires_at > int(datetime.now(timezone.utc).timestamp())
        )

    def revoke_session(self, session_id: str) -> None:
        self.conn.execute(
            "UPDATE operator_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
            (utciso(), hashlib.sha256(session_id.encode()).hexdigest()),
        )

    def put_secret(self, name: str, value: dict[str, Any]) -> None:
        encrypted = self.crypto.encrypt_json(value, aad=f"secret:{name}".encode())
        self.conn.execute(
            "INSERT INTO service_secrets(name,encrypted_value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET encrypted_value=excluded.encrypted_value,"
            "updated_at=excluded.updated_at",
            (name, encrypted, utciso()),
        )

    def get_secret(self, name: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT encrypted_value FROM service_secrets WHERE name=?", (name,)
        ).fetchone()
        if row is None:
            return None
        value = self.crypto.decrypt_json(
            row["encrypted_value"], aad=f"secret:{name}".encode()
        )
        if not isinstance(value, dict):
            raise ValueError("encrypted secret is not an object")
        return value

    def record_audit(
        self, event_type: str, entity_type: str, entity_id: str, metadata_json: str = "{}"
    ) -> None:
        self.conn.execute(
            "INSERT INTO audit_events(event_type,entity_type,entity_id,metadata_json,"
            "occurred_at) VALUES(?,?,?,?,?)",
            (event_type, entity_type, entity_id, metadata_json, utciso()),
        )

    def health(self) -> dict[str, Any]:
        return {
            "schema_version": int(self.conn.execute("PRAGMA user_version").fetchone()[0]),
            "jobs_pending": int(
                self.conn.execute(
                    "SELECT count(*) FROM jobs WHERE status IN ('queued','retry_wait','leased')"
                ).fetchone()[0]
            ),
            "emergency_stop": self.get_setting("emergency_stop", "false") == "true",
        }
