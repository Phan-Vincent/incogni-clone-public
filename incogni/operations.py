"""Local maintenance handlers used by the durable worker."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from incogni.adapter_runtime import synthetic_adapter_handlers
from incogni.adapters.registry import SyntheticAdapterRegistry
from incogni.evidence import EvidenceStore
from incogni.jobs import Job
from incogni.maintenance import create_encrypted_backup, purge_old_backups
from incogni.manual_assist import manual_assist_handlers
from incogni.reports import write_monthly_report
from incogni.storage import ServiceStore, utciso


def _record_local_notification(store: ServiceStore, kind: str) -> None:
    store.conn.execute(
        "INSERT INTO notifications(id,kind,status,created_at) VALUES(?,?,?,?)",
        (uuid4().hex, kind, "pending", utciso()),
    )


def default_handlers(
    store: ServiceStore,
    *,
    evidence_dir: Path,
    backup_dir: Path | None = None,
    adapter_registry: SyntheticAdapterRegistry | None = None,
) -> dict[str, Callable[[Job], None]]:
    destination = backup_dir or Path(
        os.environ.get("INCOGNI_BACKUP_DIR", str(Path(store.db_path).parent / "backups"))
    )

    def retention_cleanup(_job: Job) -> None:
        EvidenceStore(store, evidence_dir).purge_expired()
        purge_old_backups(destination)

    def encrypted_backup(_job: Job) -> None:
        create_encrypted_backup(store, destination)

    def monthly_report(_job: Job) -> None:
        report_dir = Path(store.db_path).parent / "reports"
        write_monthly_report(store, report_dir)

    def drop_reminder(_job: Job) -> None:
        _record_local_notification(store, "drop_enrollment_reminder")

    def drop_status_reminder(_job: Job) -> None:
        _record_local_notification(store, "drop_status_reminder")

    handlers = {
        "retention_cleanup": retention_cleanup,
        "encrypted_backup": encrypted_backup,
        "monthly_report": monthly_report,
        "drop_reminder": drop_reminder,
        "drop_status_reminder": drop_status_reminder,
    }
    handlers.update(synthetic_adapter_handlers(store, adapter_registry))
    handlers.update(
        manual_assist_handlers(
            store, lambda kind: _record_local_notification(store, kind)
        )
    )
    return handlers
