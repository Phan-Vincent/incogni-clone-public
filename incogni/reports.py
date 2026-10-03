"""PII-free monthly operational summaries."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from incogni.storage import ServiceStore


def _counts(store: ServiceStore, table: str, column: str) -> dict[str, int]:
    if (table, column) not in {
        ("findings", "status"),
        ("removal_requests", "status"),
        ("jobs", "status"),
        ("notifications", "status"),
    }:
        raise ValueError("unsupported report dimension")
    rows = store.conn.execute(
        f"SELECT {column},count(*) count FROM {table} GROUP BY {column}"
    ).fetchall()
    return {str(row[column]): int(row["count"]) for row in rows}


def build_monthly_report(
    store: ServiceStore, *, generated_at: datetime | None = None
) -> dict[str, Any]:
    generated_at = generated_at or datetime.now(timezone.utc)
    return {
        "month": generated_at.strftime("%Y-%m"),
        "generated_at": generated_at.isoformat(),
        "coverage": {
            "brokers_configured": int(
                store.conn.execute("SELECT count(*) FROM broker_flows").fetchone()[0]
            ),
            "drop_enrolled": store.get_setting("drop_enrolled", "false") == "true",
        },
        "findings": _counts(store, "findings", "status"),
        "requests": _counts(store, "removal_requests", "status"),
        "jobs": _counts(store, "jobs", "status"),
        "notifications": _counts(store, "notifications", "status"),
    }


def write_monthly_report(
    store: ServiceStore,
    destination: Path,
    *,
    generated_at: datetime | None = None,
) -> Path:
    report = build_monthly_report(store, generated_at=generated_at)
    destination.mkdir(parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    path = destination / f"privacy-report-{report['month']}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    store.record_audit("monthly_report_written", "report", report["month"])
    return path
