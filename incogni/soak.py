"""Synthetic-only production-soak monitoring.

The soak monitor stores only bounded operational metadata.  It never serializes
database rows, credentials, fixture contents, host names, addresses, or command
output into its state or reports.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from incogni.adapters.guarded import LIVE_BROKERS
from incogni.adapters.registry import SyntheticAdapterRegistry
from incogni.models import FindingStatus, RequestStatus
from incogni.storage import ServiceStore


SOAK_SCHEMA_VERSION = 1
SOAK_DURATION = timedelta(days=14)
BACKUP_MAX_AGE = timedelta(hours=26)
JOURNAL_AUDIT_MAX_AGE = timedelta(minutes=70)
# A cold journalctl query opens every archived journal file; on a rotational disk
# that takes minutes, not seconds. The unit's TimeoutStartSec must exceed this.
JOURNAL_AUDIT_QUERY_TIMEOUT = 300
MIN_FREE_BYTES = 1 << 30
MIN_FREE_FRACTION = 0.10
BROKER_IDS = tuple(sorted(broker.broker_id for broker in LIVE_BROKERS))
UNIT_NAMES = (
    "incogni-api.service",
    "incogni-worker.service",
    "incogni-maintenance.timer",
    "incogni-health.timer",
    "incogni-maintenance.service",
    "incogni-health.service",
    "incogni-browser-worker.service",
    "incogni-soak.timer",
)
RESTART_UNITS = ("incogni-api.service", "incogni-worker.service")
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "soak"
JOURNAL_AUDIT_PATH = Path("/run/incogni-journal-audit/status.json")
_SAFE_DETAIL = re.compile(r"^[a-z0-9 ,.:_+()/-]+$", re.IGNORECASE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}")
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|authorization|api[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
_URL_SECRET = re.compile(r"[?&](?:token|code|key|secret)=", re.IGNORECASE)
_EXTERNAL_URL = re.compile(r"https://|http://(?!127\.0\.0\.1(?::\d+)?)", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("soak timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class SoakCheck:
    code: str
    status: str
    detail: str


@dataclass(frozen=True)
class UnitState:
    load: str
    active: str
    sub: str
    result: str
    restarts: int
    enabled: str


class SoakProbe(Protocol):
    def unit_state(self, name: str) -> UnitState: ...
    def api_healthy(self, port: int) -> bool: ...
    def listener_addresses(self, port: int) -> tuple[str, ...]: ...
    def tailscale_safe(self, port: int) -> bool: ...
    def disk_usage(self, path: Path) -> tuple[int, int]: ...
    def latest_backup(self, directory: Path) -> tuple[datetime, int] | None: ...
    def service_logs_safe(self) -> bool: ...


def _run(argv: list[str], timeout: float = 10) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(argv, 124, "", "")


class HostSoakProbe:
    """Read public service metadata without opening application artifacts."""

    def __init__(self, journal_audit_path: Path = JOURNAL_AUDIT_PATH):
        self.journal_audit_path = journal_audit_path

    def unit_state(self, name: str) -> UnitState:
        if shutil.which("systemctl") is None:
            return UnitState("missing", "unknown", "unknown", "unknown", -1, "unknown")
        result = _run(
            [
                "systemctl",
                "show",
                name,
                "--property=LoadState,ActiveState,SubState,Result,NRestarts,UnitFileState",
            ]
        )
        values: dict[str, str] = {}
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                key, separator, value = line.partition("=")
                if separator:
                    values[key] = value
        try:
            restarts = int(values.get("NRestarts", "-1"))
        except ValueError:
            restarts = -1
        return UnitState(
            values.get("LoadState", "missing"),
            values.get("ActiveState", "unknown"),
            values.get("SubState", "unknown"),
            values.get("Result", "unknown"),
            restarts,
            values.get("UnitFileState", "unknown"),
        )

    def api_healthy(self, port: int) -> bool:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/healthz", method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read(4096).decode("utf-8"))
            return response.status == 200 and payload == {"status": "ok"}
        except (OSError, ValueError, urllib.error.URLError):
            return False

    def listener_addresses(self, port: int) -> tuple[str, ...]:
        if shutil.which("ss") is None:
            return ()
        result = _run(["ss", "-H", "-ltn", f"sport = :{port}"])
        if result.returncode != 0:
            return ()
        addresses: list[str] = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[3]
            if local.startswith("["):
                address = local.split("]", 1)[0] + "]"
            else:
                address = local.rsplit(":", 1)[0]
            addresses.append(address)
        return tuple(sorted(set(addresses)))

    def tailscale_safe(self, port: int) -> bool:
        if shutil.which("tailscale") is None:
            return False
        result = _run(["tailscale", "serve", "status"])
        text = result.stdout + result.stderr
        target = f"http://127.0.0.1:{port}"
        return (
            result.returncode == 0
            and target in text
            and "Funnel on" not in text
            and "http://0.0.0.0" not in text
            and "http://[::]" not in text
        )

    def disk_usage(self, path: Path) -> tuple[int, int]:
        usage = shutil.disk_usage(path)
        return usage.free, usage.total

    def latest_backup(self, directory: Path) -> tuple[datetime, int] | None:
        latest: tuple[datetime, int] | None = None
        if not directory.is_dir() or directory.is_symlink():
            return None
        for path in directory.glob("incogni-*.sqlite.enc"):
            if path.is_symlink() or not path.is_file():
                continue
            metadata = path.stat()
            candidate = (
                datetime.fromtimestamp(metadata.st_mtime, timezone.utc),
                stat.S_IMODE(metadata.st_mode),
            )
            if latest is None or candidate[0] > latest[0]:
                latest = candidate
        return latest

    def service_logs_safe(self) -> bool:
        path = self.journal_audit_path
        if path.is_symlink() or not path.is_file():
            return False
        metadata = path.stat()
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            return False
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            checked_at = _parse_time(payload["checked_at"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False
        age = utc_now() - checked_at
        return (
            payload.get("schema_version") == 1
            and payload.get("query_ok") is True
            and payload.get("safe") is True
            and -timedelta(minutes=5) <= age <= JOURNAL_AUDIT_MAX_AGE
        )


def audit_service_journal(
    output: Path,
    *,
    clock: Callable[[], datetime] = utc_now,
    runner: Callable[..., subprocess.CompletedProcess[str]] = _run,
) -> bool:
    """Scan bounded service logs and persist no journal content or match values."""

    if not output.is_absolute() or output.is_symlink():
        raise ValueError("journal audit output must be a regular absolute path")
    parent = output.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("journal audit output directory is unavailable")
    result = runner(
        [
            "journalctl",
            "--quiet",
            "--no-pager",
            "--output=cat",
            "--lines=200",
            "-u",
            "incogni-api.service",
            "-u",
            "incogni-worker.service",
            "-u",
            "incogni-maintenance.service",
            "-u",
            "incogni-health.service",
            "-u",
            "incogni-soak.service",
        ],
        timeout=JOURNAL_AUDIT_QUERY_TIMEOUT,
    )
    query_ok = result.returncode == 0
    safe = query_ok and _payload_safe(result.stdout + result.stderr)
    payload = {
        "schema_version": 1,
        "checked_at": _iso(clock()),
        "query_ok": query_ok,
        "safe": safe,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temporary = output.with_suffix(output.suffix + ".new")
    if temporary.exists() and (temporary.is_symlink() or not temporary.is_file()):
        raise ValueError("unsafe journal audit temporary file")
    temporary.write_text(rendered, encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, output)
    return safe


class BundledFixtureSource:
    """Load only the three immutable, packaged canary fixtures per broker."""

    OPERATIONS = {
        ("candidate", "discover"): "candidate.html",
        ("poll_processing", "poll"): "poll_processing.html",
        ("verify_suppressed", "verify"): "verify_suppressed.html",
    }

    def __init__(self, root: Path = FIXTURE_ROOT):
        self.root = root

    def __call__(self, broker_id: str, reference: str, operation: str) -> str:
        if broker_id not in BROKER_IDS:
            raise ValueError("unknown synthetic broker fixture")
        filename = self.OPERATIONS.get((reference, operation))
        if filename is None:
            raise ValueError("unknown synthetic canary fixture")
        path = self.root / broker_id / filename
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError("synthetic canary fixture is missing")
        return path.read_text(encoding="utf-8")


def run_fixture_canaries(root: Path = FIXTURE_ROOT) -> bool:
    source = BundledFixtureSource(root)
    registry = SyntheticAdapterRegistry(source)
    if registry.broker_ids != BROKER_IDS:
        return False
    for broker_id in BROKER_IDS:
        adapter = registry.get(broker_id)
        if adapter.metadata.paused is not True:
            return False
        if adapter.metadata.automation_level.value != "monitor_only":
            return False
        if adapter.transport.name != "disabled":
            return False
        if adapter.discover("candidate").status is not FindingStatus.CANDIDATE:
            return False
        if adapter.poll("poll_processing").status is not RequestStatus.PROCESSING:
            return False
        if adapter.verify("verify_suppressed").status is not FindingStatus.SUPPRESSED:
            return False
    return True


def fixture_tree_safe(root: Path = FIXTURE_ROOT) -> bool:
    expected = {
        root / broker / filename
        for broker in BROKER_IDS
        for filename in BundledFixtureSource.OPERATIONS.values()
    }
    actual = set(root.glob("*/*.html")) if root.is_dir() else set()
    if actual != expected:
        return False
    for path in actual:
        if path.is_symlink():
            return False
        payload = path.read_text(encoding="utf-8")
        if not _payload_safe(payload):
            return False
    return True


def _payload_safe(payload: str) -> bool:
    return not any(
        pattern.search(payload)
        for pattern in (_EMAIL, _PHONE, _SECRET, _URL_SECRET, _EXTERNAL_URL)
    )


def _check(code: str, passed: bool, ok: str, failed: str) -> SoakCheck:
    detail = ok if passed else failed
    if not _SAFE_DETAIL.fullmatch(detail):
        raise ValueError("soak check detail is not safe operational metadata")
    return SoakCheck(code, "pass" if passed else "failure", detail)


class SoakMonitor:
    def __init__(
        self,
        store: ServiceStore,
        *,
        root: Path | None = None,
        probe: SoakProbe | None = None,
        clock: Callable[[], datetime] = utc_now,
        fixture_root: Path = FIXTURE_ROOT,
        port: int = 8765,
        browser_gate: Path = Path("/etc/incogni/browser-enabled"),
    ):
        self.store = store
        self.root = root or Path(store.db_path).parent / "soak"
        self.probe = probe or HostSoakProbe()
        self.clock = clock
        self.fixture_root = fixture_root
        self.port = port
        self.browser_gate = browser_gate
        self.state_path = self.root / "status.json"
        self.report_path = self.root / "report.json"

    def _prepare_root(self) -> None:
        if self.root.exists() and self.root.is_symlink():
            raise ValueError("soak root must not be a symbolic link")
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _read_state(self) -> dict[str, Any] | None:
        if not self.state_path.exists():
            return None
        if self.state_path.is_symlink() or not self.state_path.is_file():
            raise ValueError("unsafe soak state file")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        if state.get("schema_version") != SOAK_SCHEMA_VERSION:
            raise ValueError("unsupported soak state version")
        required = {
            "status",
            "started_at",
            "expected_completion_at",
            "completed_at",
            "stopped_at",
            "last_checked_at",
            "duration_seconds",
            "baseline_restarts",
            "history",
        }
        if not required <= state.keys() or state["status"] not in {
            "running",
            "failed",
            "passed",
            "stopped",
        }:
            raise ValueError("invalid soak state")
        if not isinstance(state["history"], list) or not isinstance(
            state["baseline_restarts"], dict
        ):
            raise ValueError("invalid soak state")
        _parse_time(state["started_at"])
        _parse_time(state["expected_completion_at"])
        return state

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if not _payload_safe(rendered):
            raise ValueError("refusing to write unsafe soak metadata")
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ValueError("unsafe soak output file")
        temporary = path.with_suffix(path.suffix + ".new")
        if temporary.exists() and (temporary.is_symlink() or not temporary.is_file()):
            raise ValueError("unsafe soak temporary file")
        temporary.write_text(rendered, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def _restart_baseline(self) -> dict[str, int]:
        return {
            name: self.probe.unit_state(name).restarts for name in RESTART_UNITS
        }

    def start(self) -> dict[str, Any]:
        self._prepare_root()
        state = self._read_state()
        if state is not None and state["status"] not in {"stopped"}:
            return state
        now = self.clock().astimezone(timezone.utc)
        state = {
            "schema_version": SOAK_SCHEMA_VERSION,
            "status": "running",
            "started_at": _iso(now),
            "expected_completion_at": _iso(now + SOAK_DURATION),
            "completed_at": None,
            "stopped_at": None,
            "last_checked_at": None,
            "duration_seconds": int(SOAK_DURATION.total_seconds()),
            "baseline_restarts": self._restart_baseline(),
            "history": [],
        }
        self._write_json(self.state_path, state)
        self._write_report(state)
        return state

    def stop(self) -> dict[str, Any]:
        self._prepare_root()
        state = self._read_state()
        if state is None:
            raise ValueError("soak has not been started")
        if state["status"] != "stopped":
            state["status"] = "stopped"
            state["stopped_at"] = _iso(self.clock())
            self._write_json(self.state_path, state)
            self._write_report(state)
        return state

    def status(self) -> dict[str, Any]:
        state = self._read_state()
        if state is None:
            return {
                "schema_version": SOAK_SCHEMA_VERSION,
                "status": "not_started",
                "started_at": None,
                "expected_completion_at": None,
                "completed_at": None,
                "stopped_at": None,
                "last_checked_at": None,
                "elapsed_seconds": 0,
                "remaining_seconds": int(SOAK_DURATION.total_seconds()),
                "checks_run": 0,
                "passed_runs": 0,
                "failed_runs": 0,
                "latest_checks": [],
            }
        now = self.clock().astimezone(timezone.utc)
        terminal_at = state.get("completed_at") or state.get("stopped_at")
        if state["status"] == "failed":
            terminal_at = state.get("last_checked_at")
        if terminal_at:
            now = _parse_time(terminal_at)
        started = _parse_time(state["started_at"])
        elapsed = max(0, int((now - started).total_seconds()))
        history = state["history"]
        return {
            "schema_version": SOAK_SCHEMA_VERSION,
            "status": state["status"],
            "started_at": state["started_at"],
            "expected_completion_at": state["expected_completion_at"],
            "completed_at": state["completed_at"],
            "stopped_at": state["stopped_at"],
            "last_checked_at": state["last_checked_at"],
            "elapsed_seconds": elapsed,
            "remaining_seconds": max(
                0, int(SOAK_DURATION.total_seconds()) - elapsed
            ),
            "checks_run": len(history),
            "passed_runs": sum(item["status"] == "pass" for item in history),
            "failed_runs": sum(item["status"] == "failure" for item in history),
            "latest_checks": history[-1]["checks"] if history else [],
        }

    def _unit_checks(self, state: dict[str, Any]) -> list[SoakCheck]:
        units = {name: self.probe.unit_state(name) for name in UNIT_NAMES}
        checks = [
            _check(
                "api_service",
                units["incogni-api.service"].active == "active"
                and units["incogni-api.service"].sub == "running"
                and units["incogni-api.service"].result == "success",
                "api service is stable",
                "api service is not stable",
            ),
            _check(
                "worker_service",
                units["incogni-worker.service"].active == "active"
                and units["incogni-worker.service"].sub == "running"
                and units["incogni-worker.service"].result == "success",
                "worker service is stable",
                "worker service is not stable",
            ),
        ]
        timers_ok = all(
            units[name].active == "active" and units[name].enabled == "enabled"
            for name in (
                "incogni-maintenance.timer",
                "incogni-health.timer",
                "incogni-soak.timer",
            )
        )
        checks.append(
            _check(
                "timer_health",
                timers_ok,
                "maintenance health and soak timers are enabled",
                "maintenance health or soak timer is unavailable",
            )
        )
        one_shots_ok = all(
            units[name].result == "success"
            for name in ("incogni-maintenance.service", "incogni-health.service")
        )
        checks.append(
            _check(
                "maintenance_results",
                one_shots_ok,
                "maintenance and health runs succeeded",
                "maintenance or health run failed",
            )
        )
        browser = units["incogni-browser-worker.service"]
        checks.append(
            _check(
                "browser_worker_disabled",
                browser.active != "active" and browser.enabled in {"disabled", "static"},
                "browser worker is disabled",
                "browser worker is enabled or active",
            )
        )
        restarts_ok = all(
            units[name].restarts == state["baseline_restarts"].get(name, -2)
            for name in RESTART_UNITS
        )
        checks.append(
            _check(
                "unexpected_restarts",
                restarts_ok,
                "service restart counters are unchanged",
                "service restart counter changed",
            )
        )
        return checks

    def _store_checks(self) -> list[SoakCheck]:
        required_columns = {
            "broker_flows": {"broker_id", "flow_version", "automation_level", "paused"},
            "jobs": {"kind", "status", "last_error_code", "encrypted_payload"},
            "removal_requests": {"status", "encrypted_payload"},
            "service_secrets": {"name", "encrypted_value"},
            "service_settings": {"key", "value"},
        }
        schema_shape_safe = all(
            columns
            <= {
                row["name"]
                for row in self.store.conn.execute(f"PRAGMA table_info({table})")
            }
            for table, columns in required_columns.items()
        )
        expected_versions = {
            broker.broker_id: broker.flow_version for broker in LIVE_BROKERS
        }
        rows = self.store.conn.execute(
            "SELECT broker_id,flow_version,automation_level,paused FROM broker_flows"
        ).fetchall()
        actual_ids = {row["broker_id"] for row in rows}
        broker_safe = actual_ids == set(BROKER_IDS) and all(
            row["automation_level"] == "monitor_only" and row["paused"] == 1
            for row in rows
        )
        versions_safe = actual_ids == set(BROKER_IDS) and all(
            row["flow_version"] == expected_versions[row["broker_id"]] for row in rows
        )
        status_counts = {
            row["status"]: row["count"]
            for row in self.store.conn.execute(
                "SELECT status,count(*) count FROM jobs GROUP BY status"
            )
        }
        bad_jobs = sum(
            status_counts.get(status, 0) for status in ("blocked", "dead", "retry_wait")
        )
        unsafe_job_count = self.store.conn.execute(
            "SELECT count(*) FROM jobs WHERE kind IN "
            "('broker_browser_operation','open_verification_link','execute_removal')"
        ).fetchone()[0]
        submission_count = self.store.conn.execute(
            "SELECT count(*) FROM removal_requests WHERE status IN "
            "('submitted','verification_required','processing','confirmed')"
        ).fetchone()[0]
        gmail_count = self.store.conn.execute(
            "SELECT count(*) FROM service_secrets WHERE name='gmail_oauth'"
        ).fetchone()[0]
        drop_secret_count = self.store.conn.execute(
            "SELECT count(*) FROM service_secrets WHERE name='drop_enrollment'"
        ).fetchone()[0]
        emergency_value = self.store.get_setting("emergency_stop", "false")
        return [
            _check(
                "schema_version",
                self.store.health()["schema_version"] == ServiceStore.SCHEMA_VERSION
                and schema_shape_safe,
                "database schema matches this release",
                "database schema drift detected",
            ),
            _check(
                "broker_safety",
                broker_safe,
                "five brokers are paused and monitor only",
                "broker safety state changed",
            ),
            _check(
                "flow_versions",
                versions_safe,
                "five broker flow versions match",
                "broker flow version drift detected",
            ),
            _check(
                "queue_health",
                bad_jobs == 0,
                "queue has no failed or dead jobs",
                "queue has failed or dead jobs",
            ),
            _check(
                "emergency_stop_available",
                emergency_value in {"true", "false"},
                "emergency stop state is available",
                "emergency stop state is invalid",
            ),
            _check(
                "gmail_disabled",
                gmail_count == 0,
                "gmail authorization is absent",
                "gmail authorization is present",
            ),
            _check(
                "drop_automation_disabled",
                drop_secret_count == 0,
                "drop automation credential is absent",
                "drop automation credential is present",
            ),
            _check(
                "broker_submissions_disabled",
                unsafe_job_count == 0 and submission_count == 0,
                "broker submission work is absent",
                "broker submission work was detected",
            ),
        ]

    def _filesystem_safe(self, latest_backup_mode: int | None) -> bool:
        paths = [self.root, self.state_path, self.report_path]
        db_path = Path(self.store.db_path)
        if db_path.exists():
            paths.extend(
                path for path in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm"))
                if path.exists()
            )
        for path in paths:
            if path.is_symlink():
                return False
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o007:
                return False
        return latest_backup_mode is None or latest_backup_mode & 0o077 == 0

    def _local_artifacts_safe(self) -> bool:
        data_dir = Path(self.store.db_path).parent
        roots = (data_dir / "reports", data_dir / "logs", self.root)
        for root in roots:
            if not root.exists():
                continue
            if root.is_symlink() or not root.is_dir():
                return False
            for path in root.glob("*"):
                if path.is_symlink() or not path.is_file():
                    return False
                if path.stat().st_size > 5 * 1024 * 1024:
                    return False
                try:
                    payload = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    return False
                if not _payload_safe(payload):
                    return False
        return True

    def _host_checks(self) -> list[SoakCheck]:
        backup = self.probe.latest_backup(Path(self.store.db_path).parent / "backups")
        now = self.clock().astimezone(timezone.utc)
        backup_fresh = backup is not None and timedelta(0) <= now - backup[0] <= BACKUP_MAX_AGE
        backup_mode = backup[1] if backup else None
        free, total = self.probe.disk_usage(Path(self.store.db_path).parent)
        disk_safe = total > 0 and free >= MIN_FREE_BYTES and free / total >= MIN_FREE_FRACTION
        addresses = self.probe.listener_addresses(self.port)
        listener_safe = addresses == ("127.0.0.1",)
        return [
            _check(
                "api_health",
                self.probe.api_healthy(self.port),
                "loopback api health check passed",
                "loopback api health check failed",
            ),
            _check(
                "backup_freshness",
                backup_fresh,
                "encrypted backup is fresh",
                "encrypted backup is missing or stale",
            ),
            _check(
                "disk_capacity",
                disk_safe,
                "disk capacity is sufficient",
                "disk capacity is below the safe threshold",
            ),
            _check(
                "loopback_listener",
                listener_safe,
                "api listener is loopback only",
                "api listener is missing or not loopback only",
            ),
            _check(
                "tailscale_serve",
                self.probe.tailscale_safe(self.port),
                "tailscale serve targets loopback without funnel",
                "tailscale serve policy is missing or unsafe",
            ),
            _check(
                "filesystem_permissions",
                self._filesystem_safe(backup_mode),
                "operational files have restricted permissions",
                "unsafe operational file permissions detected",
            ),
            _check(
                "artifact_redaction",
                self._local_artifacts_safe(),
                "local reports and logs are pii free",
                "pii or secret pattern detected in local artifacts",
            ),
            _check(
                "journal_redaction",
                self.probe.service_logs_safe(),
                "service journal is pii free",
                "pii or secret pattern detected in service journal",
            ),
            _check(
                "browser_gate_absent",
                not self.browser_gate.exists(),
                "browser activation gate is absent",
                "browser activation gate is present",
            ),
        ]

    def check(self) -> dict[str, Any]:
        self._prepare_root()
        state = self._read_state()
        if state is None:
            raise ValueError("soak has not been started")
        if state["status"] in {"stopped", "passed"}:
            return state
        now = self.clock().astimezone(timezone.utc)
        check_period = now.strftime("%Y-%m-%dT%H:00Z")
        if state["history"] and state["history"][-1].get("period") == check_period:
            self._write_report(state)
            return state
        checks: list[SoakCheck] = []
        for code, ok, failed, operation in (
            (
                "unit_metadata",
                "systemd metadata checks completed",
                "systemd metadata checks failed",
                lambda: self._unit_checks(state),
            ),
            (
                "host_metadata",
                "host metadata checks completed",
                "host metadata checks failed",
                self._host_checks,
            ),
            (
                "store_metadata",
                "database metadata checks completed",
                "database metadata checks failed",
                self._store_checks,
            ),
        ):
            try:
                checks.extend(operation())
            except Exception:
                checks.append(_check(code, False, ok, failed))
        try:
            canaries_ok = run_fixture_canaries(self.fixture_root)
        except Exception:
            canaries_ok = False
        checks.append(
            _check(
                "synthetic_canaries",
                canaries_ok,
                "five fixture canaries passed",
                "synthetic fixture canary failed",
            )
        )
        checks.append(
            _check(
                "fixture_safety",
                fixture_tree_safe(self.fixture_root),
                "canary fixtures are complete and pii free",
                "canary fixtures are missing or unsafe",
            )
        )
        checks.append(
            _check(
                "live_transports_disabled",
                canaries_ok,
                "synthetic registry has disabled transports",
                "synthetic registry transport safety failed",
            )
        )
        run_status = "failure" if any(item.status == "failure" for item in checks) else "pass"
        record = {
            "checked_at": _iso(now),
            "period": check_period,
            "status": run_status,
            "checks": [asdict(item) for item in checks],
        }
        state["history"].append(record)
        state["last_checked_at"] = record["checked_at"]
        if run_status == "failure":
            state["status"] = "failed"
        elif now >= _parse_time(state["expected_completion_at"]):
            if all(item["status"] == "pass" for item in state["history"]):
                state["status"] = "passed"
                state["completed_at"] = record["checked_at"]
        self._write_json(self.state_path, state)
        self._write_report(state)
        return state

    def _write_report(self, state: dict[str, Any]) -> None:
        history = state["history"]
        report = {
            "schema_version": SOAK_SCHEMA_VERSION,
            "status": state["status"],
            "started_at": state["started_at"],
            "expected_completion_at": state["expected_completion_at"],
            "completed_at": state["completed_at"],
            "stopped_at": state["stopped_at"],
            "checks_run": len(history),
            "passed_runs": sum(item["status"] == "pass" for item in history),
            "failed_runs": sum(item["status"] == "failure" for item in history),
            "latest": history[-1] if history else None,
            "automatic_promotion": False,
            "retained_data": "operational metadata only",
        }
        self._write_json(self.report_path, report)


def format_status(status: dict[str, Any]) -> str:
    lines = [
        f"Soak status: {status['status']}",
        f"Started: {status['started_at'] or 'not started'}",
        f"Expected completion: {status['expected_completion_at'] or 'not scheduled'}",
        f"Checks: {status['checks_run']} passed={status['passed_runs']} failed={status['failed_runs']}",
    ]
    if status["status"] not in {"not_started", "passed", "stopped"}:
        lines.append(f"Remaining seconds: {status['remaining_seconds']}")
    return "\n".join(lines)
