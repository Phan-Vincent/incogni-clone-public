"""Encrypted local backups and retention maintenance."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from incogni.storage import ServiceStore


def create_encrypted_backup(store: ServiceStore, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    created_at = datetime.now(timezone.utc).isoformat()
    snapshot = store.conn.serialize()
    envelope = store.crypto.encrypt_bytes(
        snapshot, aad=f"backup:{created_at}".encode()
    )
    path = destination / (
        "incogni-" + created_at.replace(":", "").replace("+", "_") + ".sqlite.enc"
    )
    path.write_text(
        json.dumps({"created_at": created_at, "database": envelope}),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


def purge_old_backups(
    destination: Path,
    *,
    retention: timedelta = timedelta(days=30),
    now: datetime | None = None,
) -> int:
    if not destination.exists():
        return 0
    root = destination.resolve()
    cutoff = (now or datetime.now(timezone.utc)).timestamp() - retention.total_seconds()
    removed = 0
    for path in destination.glob("incogni-*.sqlite.enc"):
        resolved = path.resolve()
        if root not in resolved.parents:
            continue
        if path.stat().st_mtime <= cutoff:
            path.unlink()
            removed += 1
    return removed


def restore_encrypted_backup(
    store: ServiceStore, backup: Path, destination: Path
) -> None:
    payload = json.loads(backup.read_text(encoding="utf-8"))
    snapshot = store.crypto.decrypt_bytes(
        payload["database"], aad=f"backup:{payload['created_at']}".encode()
    )
    if destination.exists():
        raise FileExistsError(destination)
    destination.write_bytes(snapshot)
    os.chmod(destination, 0o600)
