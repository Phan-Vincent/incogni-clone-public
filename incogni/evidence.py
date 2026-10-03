"""Encrypted evidence files with bounded retention."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from incogni.storage import ServiceStore


class EvidenceStore:
    def __init__(self, store: ServiceStore, root: Path):
        self.store = store
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _path_for(self, evidence_id: str) -> Path:
        if len(evidence_id) != 32 or any(
            character not in "0123456789abcdef" for character in evidence_id
        ):
            raise ValueError("invalid evidence id")
        return self.root / f"{evidence_id}.enc"

    def save(
        self,
        entity_type: str,
        entity_id: str,
        content_type: str,
        content: bytes,
        *,
        retention: timedelta = timedelta(days=30),
        evidence_id: str | None = None,
    ) -> str:
        evidence_id = evidence_id or uuid4().hex
        path = self._path_for(evidence_id)
        filename = path.name
        envelope = self.store.crypto.encrypt_bytes(
            content, aad=f"evidence:{evidence_id}".encode()
        )
        try:
            path.write_text(envelope, encoding="utf-8")
            os.chmod(path, 0o600)
            now = datetime.now(timezone.utc)
            self.store.conn.execute(
                "INSERT INTO evidence(id,entity_type,entity_id,content_type,sha256,"
                "encrypted_path,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    evidence_id,
                    entity_type,
                    entity_id,
                    content_type,
                    hashlib.sha256(content).hexdigest(),
                    filename,
                    (now + retention).isoformat(),
                    now.isoformat(),
                ),
            )
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return evidence_id

    def discard(self, evidence_id: str) -> None:
        self._path_for(evidence_id).unlink(missing_ok=True)

    def read(self, evidence_id: str) -> bytes:
        row = self.store.conn.execute(
            "SELECT encrypted_path FROM evidence WHERE id=?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise KeyError(evidence_id)
        path = (self.root / row["encrypted_path"]).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("invalid evidence path")
        return self.store.crypto.decrypt_bytes(
            path.read_text(encoding="utf-8"),
            aad=f"evidence:{evidence_id}".encode(),
        )

    def purge_expired(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        rows = self.store.conn.execute(
            "SELECT id,encrypted_path FROM evidence WHERE expires_at<=?",
            (now.isoformat(),),
        ).fetchall()
        for row in rows:
            path = (self.root / row["encrypted_path"]).resolve()
            if self.root.resolve() in path.parents:
                path.unlink(missing_ok=True)
            self.store.conn.execute("DELETE FROM evidence WHERE id=?", (row["id"],))
        return len(rows)
