"""Persistence for scan results and opt-out requests (SQLite, stdlib only)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from incogni.models import OptOutResult, ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    broker_id     TEXT NOT NULL,
    status        TEXT NOT NULL,
    matched_fields TEXT NOT NULL DEFAULT '[]',
    detail        TEXT NOT NULL DEFAULT '',
    scanned_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS optouts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    broker_id       TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL,
    confirmation_id TEXT,
    message         TEXT NOT NULL DEFAULT '',
    submitted_at    TEXT NOT NULL
);
"""


class Tracker:
    """SQLite-backed store for scans and opt-outs."""

    def __init__(self, db_path: str | Path = ":memory:"):
        # Accept both ":memory:" and filesystem paths.
        if str(db_path) == ":memory:":
            self._conn = sqlite3.connect(":memory:")
        else:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- scans --------------------------------------------------------------

    def record_scan(self, result: ScanResult) -> None:
        self._conn.execute(
            "INSERT INTO scans (broker_id, status, matched_fields, detail, scanned_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                result.broker_id,
                result.status.value,
                json.dumps(result.matched_fields),
                result.detail,
                result.scanned_at.isoformat(),
            ),
        )
        self._conn.commit()

    def latest_scan(self, broker_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM scans WHERE broker_id = ? ORDER BY id DESC LIMIT 1",
            (broker_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_scans(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # -- opt-outs -----------------------------------------------------------

    def record_optout(self, result: OptOutResult) -> None:
        self._conn.execute(
            "INSERT INTO optouts (broker_id, status, confirmation_id, message, submitted_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(broker_id) DO UPDATE SET "
            "  status = excluded.status,"
            "  confirmation_id = excluded.confirmation_id,"
            "  message = excluded.message,"
            "  submitted_at = excluded.submitted_at",
            (
                result.broker_id,
                result.status.value,
                result.confirmation_id,
                result.message,
                result.submitted_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get_optout(self, broker_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM optouts WHERE broker_id = ?", (broker_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_optouts(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM optouts ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
