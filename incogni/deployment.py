"""Synthetic-only deployment inspection, staging, and rehearsal tools."""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from incogni.adapters.guarded import LIVE_BROKERS, seed_live_broker_flows
from incogni.adapters.registry import SyntheticAdapterRegistry
from incogni.auth import OperatorAuth
from incogni.crypto import EnvelopeCrypto
from incogni.jobs import DurableJobQueue
from incogni.maintenance import restore_encrypted_backup
from incogni.service_config import ServiceConfig
from incogni.soak import SoakMonitor, UnitState
from incogni.storage import ServiceStore


REPO_ROOT = Path(__file__).resolve().parent.parent
STAGE_MARKER = ".incogni-deployment-stage.json"
STAGE_VERSION = 1
SYNTHETIC_PASSWORD = "synthetic-rehearsal-password"
SYNTHETIC_SENTINEL = "SYNTHETIC-REHEARSAL-SENTINEL-DO-NOT-LOG"
PRODUCTION_PATHS = (Path("/etc"), Path("/opt"), Path("/var/lib"))
UNIT_NAMES = (
    "incogni-api.service",
    "incogni-browser-worker.service",
    "incogni-health.service",
    "incogni-health.timer",
    "incogni-journal-audit.service",
    "incogni-maintenance.service",
    "incogni-maintenance.timer",
    "incogni-soak.service",
    "incogni-soak.timer",
    "incogni-worker.service",
)


@dataclass(frozen=True)
class DeploymentCheck:
    code: str
    status: str
    detail: str


@dataclass(frozen=True)
class RehearsalResult:
    status: str
    port: int
    checks: tuple[DeploymentCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "port": self.port,
            "checks": [asdict(check) for check in self.checks],
        }


def _run(
    argv: list[str], *, env: dict[str, str] | None = None, timeout: float = 20
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


def _check(code: str, passed: bool, ok: str, failure: str) -> DeploymentCheck:
    return DeploymentCheck(code, "pass" if passed else "failure", ok if passed else failure)


def _warning(code: str, detail: str) -> DeploymentCheck:
    return DeploymentCheck(code, "warning", detail)


def _command_version(command: str, *args: str) -> str | None:
    executable = shutil.which(command)
    if executable is None:
        return None
    result = _run([executable, *args])
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else command


def _port_available(port: int) -> bool:
    if not 1 <= port <= 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _systemd_unit_source() -> Path:
    return REPO_ROOT / "deploy" / "systemd"


def run_preflight(port: int = 8765) -> list[DeploymentCheck]:
    """Inspect only public host capabilities; never open application data paths."""

    checks: list[DeploymentCheck] = []
    checks.append(
        _check(
            "host_linux",
            sys.platform.startswith("linux"),
            "Linux host detected",
            "deployment requires Linux",
        )
    )
    os_release = Path("/etc/os-release")
    release_name = "unknown Linux"
    if os_release.is_file():
        for line in os_release.read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                release_name = line.partition("=")[2].strip('"')
                break
    checks.append(DeploymentCheck("host_release", "pass", release_name))

    systemd_version = _command_version("systemd", "--version")
    checks.append(
        _check(
            "systemd_available",
            systemd_version is not None and shutil.which("systemd-analyze") is not None,
            systemd_version or "systemd available",
            "systemd or systemd-analyze is unavailable",
        )
    )
    tailscale_version = _command_version("tailscale", "version")
    checks.append(
        _check(
            "tailscale_available",
            tailscale_version is not None,
            tailscale_version or "Tailscale available",
            "Tailscale is unavailable",
        )
    )
    if shutil.which("systemctl"):
        active = _run(["systemctl", "is-active", "tailscaled"])
        checks.append(
            _check(
                "tailscaled_active",
                active.returncode == 0 and active.stdout.strip() == "active",
                "tailscaled is active",
                "tailscaled is not active",
            )
        )
    else:
        checks.append(_warning("tailscaled_active", "systemctl is unavailable"))

    checks.append(
        _check(
            "loopback_port_available",
            _port_available(port),
            f"127.0.0.1:{port} is available",
            f"127.0.0.1:{port} is already in use",
        )
    )
    required = ("curl", "systemd-analyze")
    missing = [name for name in required if shutil.which(name) is None]
    checks.append(
        _check(
            "host_commands",
            not missing,
            "required host commands are available",
            "missing commands: " + ", ".join(missing),
        )
    )

    existing_users: list[str] = []
    for name in ("incogni", "incogni-browser"):
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        existing_users.append(name)
    checks.append(
        _warning("service_accounts", "not installed on this rehearsal host")
        if not existing_users
        else DeploymentCheck(
            "service_accounts", "pass", "present: " + ", ".join(existing_users)
        )
    )

    application_paths = [
        Path("/opt/incogni"),
        Path("/etc/incogni"),
        Path("/var/lib/incogni"),
    ]
    present = [str(path) for path in application_paths if path.exists()]
    checks.append(
        _warning("production_paths", "not installed on this rehearsal host")
        if not present
        else DeploymentCheck(
            "production_paths", "pass", "present: " + ", ".join(present)
        )
    )

    python = REPO_ROOT / ".venv" / "bin" / "python"
    entrypoint = REPO_ROOT / ".venv" / "bin" / "incogni"
    if python.is_file() and os.access(python, os.X_OK) and entrypoint.is_file():
        imports = _run(
            [
                str(python),
                "-c",
                "import argon2,cryptography,fastapi,uvicorn; print('ok')",
            ]
        )
        checks.append(
            _check(
                "project_python",
                imports.returncode == 0,
                "repository virtual environment is usable",
                "repository virtual environment has missing dependencies",
            )
        )
    else:
        checks.append(
            DeploymentCheck(
                "project_python", "failure", "repository virtual environment is absent"
            )
        )

    unit_files = [_systemd_unit_source() / name for name in UNIT_NAMES]
    checks.append(
        _check(
            "systemd_units_present",
            all(path.is_file() for path in unit_files),
            "all deployment units are present",
            "one or more deployment units are missing",
        )
    )

    reasonix = shutil.which("reasonix")
    if reasonix:
        doctor = _run([reasonix, "doctor"])
        doctor_text = doctor.stdout + doctor.stderr
        if "enforce (unavailable" in doctor_text or doctor.returncode != 0:
            checks.append(
                _warning(
                    "reasonix_sandbox",
                    "enforced sandbox unavailable; Reasonix must be skipped",
                )
            )
        else:
            checks.append(
                _check(
                    "reasonix_sandbox",
                    "bash         enforce" in doctor_text,
                    "Reasonix enforced sandbox is available",
                    "Reasonix sandbox is not enforced",
                )
            )
    else:
        checks.append(_warning("reasonix_sandbox", "Reasonix is not installed"))
    return checks


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return path != parent


def validate_stage_root(root: Path) -> Path:
    raw = root.expanduser().absolute()
    if raw.exists() and raw.is_symlink():
        raise ValueError("stage root must not be a symbolic link")
    resolved = raw.resolve(strict=False)
    allowed = _is_within(resolved, Path("/tmp")) or _is_within(
        resolved, REPO_ROOT.resolve()
    )
    if not allowed:
        raise ValueError("stage root must be beneath /tmp or the repository")
    if any(
        resolved == path or _is_within(resolved, path) for path in PRODUCTION_PATHS
    ):
        raise ValueError("production paths are forbidden for staging")
    marker = resolved / STAGE_MARKER
    if marker.is_symlink():
        raise ValueError("stage ownership marker must not be a symbolic link")
    if (
        resolved.exists()
        and any(resolved.iterdir())
        and not (resolved / STAGE_MARKER).is_file()
    ):
        raise ValueError(
            "existing stage root is not owned by incogni deployment tooling"
        )
    return resolved


def stage_is_owned(root: Path) -> bool:
    try:
        root = validate_stage_root(root)
        marker = root / STAGE_MARKER
        if not stat.S_ISREG(marker.lstat().st_mode):
            return False
        payload = json.loads(marker.read_text(encoding="utf-8"))
        return (
            payload.get("stage_version") == STAGE_VERSION
            and payload.get("synthetic_only") is True
        )
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return False


def remove_stage(root: Path) -> None:
    root = validate_stage_root(root)
    if not stage_is_owned(root):
        raise ValueError("refusing to remove an unowned stage")
    shutil.rmtree(root)


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _write_once(path: Path, value: str, mode: int) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsafe staged file: {path.name}")
        return
    path.write_text(value, encoding="utf-8")
    os.chmod(path, mode)


def stage_installation(root: Path) -> Path:
    """Build an installation-shaped tree without touching privileged host paths."""

    root = validate_stage_root(root)
    _private_dir(root)
    marker = root / STAGE_MARKER
    if marker.exists():
        payload = json.loads(marker.read_text(encoding="utf-8"))
        if payload.get("stage_version") != STAGE_VERSION:
            raise ValueError("unsupported stage ownership marker")

    directories = (
        root / "etc/systemd/system",
        root / "etc/incogni/credentials",
        root / "opt/incogni/.venv/bin",
        root / "usr/bin",
        root / "var/lib/incogni/evidence",
        root / "var/lib/incogni/backups",
        root / "var/lib/incogni/reports",
        root / "var/lib/incogni/logs",
    )
    for directory in directories:
        _private_dir(directory)

    for name in UNIT_NAMES:
        source = _systemd_unit_source() / name
        target = root / "etc/systemd/system" / name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError(f"unsafe staged unit: {name}")
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)

    base_units = Path("/usr/lib/systemd/system")
    staged_base_units = root / "usr/lib/systemd/system"
    if staged_base_units.is_symlink():
        raise ValueError("staged base-unit directory must not be a symbolic link")
    if base_units.is_dir() and not staged_base_units.exists():
        shutil.copytree(
            base_units,
            staged_base_units,
            dirs_exist_ok=True,
            symlinks=True,
        )

    _write_once(
        root / "opt/incogni/.venv/bin/incogni", "#!/bin/sh\nexit 0\n", 0o755
    )
    _write_once(root / "usr/bin/curl", "#!/bin/sh\nexit 0\n", 0o755)
    credentials = root / "etc/incogni/credentials"
    _write_once(
        credentials / "incogni-master-key",
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii") + "\n",
        0o600,
    )
    _write_once(
        credentials / "incogni-admin-password",
        OperatorAuth.hash_password(SYNTHETIC_PASSWORD) + "\n",
        0o600,
    )
    manifest = {
        "stage_version": STAGE_VERSION,
        "synthetic_only": True,
        "managed_units": list(UNIT_NAMES),
        "browser_worker_enabled": False,
        "live_transports_enabled": False,
    }
    marker.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(marker, 0o600)
    return root


def validate_systemd_stage(
    root: Path,
) -> tuple[list[DeploymentCheck], dict[str, float]]:
    root = validate_stage_root(root)
    analyzer = shutil.which("systemd-analyze")
    if analyzer is None:
        return [
            DeploymentCheck(
                "systemd_verify", "failure", "systemd-analyze unavailable"
            )
        ], {}
    unit_dir = root / "etc/systemd/system"
    unit_paths = [str(unit_dir / name) for name in UNIT_NAMES]
    verified = _run(
        [analyzer, "verify", f"--root={root}", *unit_paths], timeout=60
    )
    checks = [
        _check(
            "systemd_verify",
            verified.returncode == 0,
            "exact staged units pass systemd verification",
            "systemd verification failed",
        )
    ]
    api_unit = (unit_dir / "incogni-api.service").read_text(encoding="utf-8")
    browser_unit = (unit_dir / "incogni-browser-worker.service").read_text(
        encoding="utf-8"
    )
    checks.append(
        _check(
            "systemd_safety_policy",
            all(
                (
                    "serve --host 127.0.0.1 --port 8765" in api_unit,
                    "INCOGNI_SECURE_COOKIES=true" in api_unit,
                    "ConditionPathExists=/etc/incogni/browser-enabled"
                    in browser_unit,
                    "incogni soak check"
                    in (unit_dir / "incogni-soak.service").read_text(
                        encoding="utf-8"
                    ),
                    not (root / "etc/incogni/browser-enabled").exists(),
                )
            ),
            "loopback, secure-cookie, and disabled-browser gates are intact",
            "one or more systemd deployment safety gates changed",
        )
    )
    scores: dict[str, float] = {}
    for name in (unit for unit in UNIT_NAMES if unit.endswith(".service")):
        result = _run(
            [
                analyzer,
                "security",
                "--offline=yes",
                f"--root={root}",
                "--no-pager",
                name,
            ],
            timeout=30,
        )
        combined = result.stdout + result.stderr
        match = re.search(
            r"Overall exposure level[^:]*:\s*([0-9.]+)", combined
        )
        if match:
            scores[name] = float(match.group(1))
    checks.append(
        _check(
            "systemd_security",
            len(scores) == 7 and all(score <= 7.0 for score in scores.values()),
            "offline systemd exposure scores are at or below 7.0",
            "one or more offline systemd exposure scores exceed 7.0",
        )
    )
    return checks, scores


def load_tailscale_policy() -> dict[str, Any]:
    path = REPO_ROOT / "deploy" / "tailscale" / "serve-policy.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate_tailscale_policy(policy: dict[str, Any]) -> DeploymentCheck:
    expected = {
        "mode": "serve",
        "target": "http://127.0.0.1:8765",
        "funnel": False,
        "application_authentication": True,
    }
    return _check(
        "tailscale_policy",
        policy == expected,
        "Tailscale policy is loopback-only Serve with application authentication",
        "Tailscale policy is not the approved loopback-only configuration",
    )


def _environment(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "CREDENTIALS_DIRECTORY": str(root / "etc/incogni/credentials"),
            "INCOGNI_DATA_DIR": str(root / "var/lib/incogni"),
            "INCOGNI_EVIDENCE_DIR": str(root / "var/lib/incogni/evidence"),
            "INCOGNI_BACKUP_DIR": str(root / "var/lib/incogni/backups"),
            "INCOGNI_SECURE_COOKIES": "false",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def _reserve_port(requested: int) -> int:
    if requested:
        if not _port_available(requested):
            raise RuntimeError("requested rehearsal port is unavailable")
        return requested
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _stop_processes(processes: Iterable[subprocess.Popen[str]]) -> None:
    processes = tuple(processes)
    for process in processes:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + 5
    for process in processes:
        if process.poll() is None:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def _http(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    csrf: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    request = urllib.request.Request(
        url,
        data=(json.dumps(payload).encode() if payload is not None else None),
        headers=headers,
        method=method,
    )
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else {}


def _wait_for_health(base_url: str, process: subprocess.Popen[str]) -> None:
    opener = urllib.request.build_opener()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("API process exited during startup")
        try:
            status, payload = _http(opener, base_url + "/healthz")
            if status == 200 and payload == {"status": "ok"}:
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError("API health check timed out")


def _new_client() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _start_service_processes(
    root: Path, port: int, env: dict[str, str]
) -> tuple[list[subprocess.Popen[str]], list[Any]]:
    incogni = REPO_ROOT / ".venv/bin/incogni"
    log_dir = root / "var/lib/incogni/logs"
    handles = [
        (log_dir / "api.log").open("a", encoding="utf-8"),
        (log_dir / "worker.log").open("a", encoding="utf-8"),
    ]
    processes = [
        subprocess.Popen(
            [
                str(incogni),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=REPO_ROOT,
            env=env,
            stdout=handles[0],
            stderr=subprocess.STDOUT,
            text=True,
        ),
        subprocess.Popen(
            [
                str(incogni),
                "worker",
                "--worker-id",
                "synthetic-rehearsal",
                "--poll-seconds",
                "0.05",
            ],
            cwd=REPO_ROOT,
            env=env,
            stdout=handles[1],
            stderr=subprocess.STDOUT,
            text=True,
        ),
    ]
    return processes, handles


class _patched_environment:
    def __init__(self, values: dict[str, str]):
        self.values = values
        self.previous: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for key, value in self.values.items():
            self.previous[key] = os.environ.get(key)
            os.environ[key] = value

    def __exit__(self, *_: object) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _config_from_environment(env: dict[str, str]) -> ServiceConfig:
    with _patched_environment(env):
        return ServiceConfig.from_env()


def _initialize_synthetic_store(env: dict[str, str]) -> None:
    config = _config_from_environment(env)
    with ServiceStore(config.db_path, config.crypto) as store:
        seed_live_broker_flows(store)
        store.create_profile("synthetic-owner", {"marker": SYNTHETIC_SENTINEL})
    for path in (
        config.db_path,
        Path(str(config.db_path) + "-wal"),
        Path(str(config.db_path) + "-shm"),
    ):
        if path.exists():
            os.chmod(path, 0o600)


class _SyntheticSoakProbe:
    """Installation-shaped host metadata for the offline rehearsal only."""

    def __init__(self, root: Path):
        self.root = root

    def unit_state(self, name: str) -> UnitState:
        if name == "incogni-browser-worker.service":
            return UnitState("loaded", "inactive", "dead", "success", 0, "disabled")
        if name.endswith(".timer"):
            return UnitState("loaded", "active", "waiting", "success", 0, "enabled")
        if name in {"incogni-api.service", "incogni-worker.service"}:
            return UnitState("loaded", "active", "running", "success", 0, "enabled")
        return UnitState("loaded", "inactive", "dead", "success", 0, "static")

    def api_healthy(self, _port: int) -> bool:
        return True

    def listener_addresses(self, _port: int) -> tuple[str, ...]:
        return ("127.0.0.1",)

    def tailscale_safe(self, _port: int) -> bool:
        return validate_tailscale_policy(load_tailscale_policy()).status == "pass"

    def disk_usage(self, path: Path) -> tuple[int, int]:
        usage = shutil.disk_usage(path)
        return usage.free, usage.total

    def latest_backup(self, directory: Path):
        files = [
            path
            for path in directory.glob("incogni-*.sqlite.enc")
            if path.is_file() and not path.is_symlink()
        ]
        if not files:
            return None
        latest = max(files, key=lambda path: path.stat().st_mtime)
        metadata = latest.stat()
        return (
            datetime.fromtimestamp(metadata.st_mtime, timezone.utc),
            stat.S_IMODE(metadata.st_mode),
        )

    def service_logs_safe(self) -> bool:
        return True


def _verify_synthetic_soak(config: ServiceConfig, root: Path) -> bool:
    with ServiceStore(config.db_path, config.crypto) as store:
        monitor = SoakMonitor(
            store,
            root=root / "var/lib/incogni/soak",
            probe=_SyntheticSoakProbe(root),
            browser_gate=root / "etc/incogni/browser-enabled",
        )
        monitor.start()
        monitor.check()
        first = monitor.status()
        monitor.check()
        second = monitor.status()
    return (
        first["status"] == "running"
        and first["checks_run"] == 1
        and first["failed_runs"] == 0
        and second["checks_run"] == 1
    )


def _wait_for_jobs(config: ServiceConfig, timeout: float = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with ServiceStore(config.db_path, config.crypto) as store:
            pending = store.health()["jobs_pending"]
            failed = store.conn.execute(
                "SELECT count(*) FROM jobs "
                "WHERE status IN ('blocked','dead','retry_wait')"
            ).fetchone()[0]
        if pending == 0:
            return failed == 0
        time.sleep(0.1)
    return False


def _artifact_contains(root: Path, value: bytes) -> bool:
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if value in path.read_bytes():
                return True
        except OSError:
            return True
    return False


def _validate_fixture_tree() -> bool:
    email = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    phone = re.compile(
        rb"(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}"
    )
    unsafe_url = re.compile(
        rb"https?://|[?&](?:token|code|key)=", re.IGNORECASE
    )
    for path in (REPO_ROOT / "tests/fixtures").rglob("*.html"):
        payload = path.read_bytes()
        if email.search(payload) or phone.search(payload) or unsafe_url.search(payload):
            return False
    return True


def _validate_broker_safety(config: ServiceConfig, root: Path) -> bool:
    expected = {broker.broker_id for broker in LIVE_BROKERS}
    with ServiceStore(config.db_path, config.crypto) as store:
        rows = store.conn.execute(
            "SELECT broker_id,automation_level,paused FROM broker_flows"
        ).fetchall()
    if {row["broker_id"] for row in rows} != expected:
        return False
    if any(
        row["automation_level"] != "monitor_only" or row["paused"] != 1
        for row in rows
    ):
        return False
    registry = SyntheticAdapterRegistry(
        lambda *_: '<section data-result="none"></section>'
    )
    if set(registry.broker_ids) != expected:
        return False
    if any(
        registry.get(broker_id).transport.name != "disabled"
        for broker_id in expected
    ):
        return False
    return not (root / "etc/incogni/browser-enabled").exists()


def _verify_backup(config: ServiceConfig, root: Path) -> bool:
    backups = sorted((root / "var/lib/incogni/backups").glob("*.sqlite.enc"))
    if not backups:
        return False
    restored = root / "var/lib/incogni/restored/service.db"
    restored.parent.mkdir(parents=True, exist_ok=True)
    if restored.exists():
        restored.unlink()
    with ServiceStore(config.db_path, config.crypto) as store:
        restore_encrypted_backup(store, backups[-1], restored)
        try:
            restore_encrypted_backup(store, backups[-1], restored)
            return False
        except FileExistsError:
            pass
    with ServiceStore(restored, config.crypto) as restored_store:
        if restored_store.health()["schema_version"] != ServiceStore.SCHEMA_VERSION:
            return False
        profile = restored_store.get_profile("synthetic-owner")
        if not profile or profile.get("marker") != SYNTHETIC_SENTINEL:
            return False
    wrong_crypto = EnvelopeCrypto({"primary": b"x" * 32}, "primary")
    with ServiceStore(":memory:", wrong_crypto) as wrong_store:
        wrong_destination = root / "var/lib/incogni/restored/wrong.db"
        try:
            restore_encrypted_backup(
                wrong_store, backups[-1], wrong_destination
            )
        except ValueError:
            return True
    return False


def run_rehearsal(root: Path, *, port: int = 0) -> RehearsalResult:
    root = stage_installation(root)
    selected_port = _reserve_port(port)
    env = _environment(root)
    config = _config_from_environment(env)
    _initialize_synthetic_store(env)
    checks: list[DeploymentCheck] = []
    processes: list[subprocess.Popen[str]] = []
    handles: list[Any] = []
    base_url = f"http://127.0.0.1:{selected_port}"
    try:
        processes, handles = _start_service_processes(root, selected_port, env)
        _wait_for_health(base_url, processes[0])
        opener = _new_client()
        checks.append(
            _check(
                "health_http",
                _http(opener, base_url + "/healthz")[0] == 200,
                "HTTP health probe passed",
                "HTTP health probe failed",
            )
        )
        checks.append(
            _check(
                "authentication_required",
                _http(opener, base_url + "/api/status")[0] == 401,
                "unauthenticated API access is rejected",
                "unauthenticated API access was accepted",
            )
        )
        checks.append(
            _check(
                "invalid_login",
                _http(
                    opener,
                    base_url + "/api/login",
                    method="POST",
                    payload={"password": "invalid-synthetic-password"},
                )[0]
                == 401,
                "invalid login is rejected",
                "invalid login was accepted",
            )
        )
        login_status, login = _http(
            opener,
            base_url + "/api/login",
            method="POST",
            payload={"password": SYNTHETIC_PASSWORD},
        )
        csrf = str(login.get("csrf_token", ""))
        checks.append(
            _check(
                "synthetic_login",
                login_status == 200 and bool(csrf),
                "synthetic login succeeded",
                "synthetic login failed",
            )
        )
        checks.append(
            _check(
                "csrf_required",
                _http(opener, base_url + "/api/pause", method="POST")[0] == 403,
                "CSRF protection rejected an unprotected change",
                "CSRF protection failed",
            )
        )
        pause_status, pause = _http(
            opener, base_url + "/api/pause", method="POST", csrf=csrf
        )
        checks.append(
            _check(
                "emergency_stop",
                pause_status == 200 and pause.get("emergency_stop") is True,
                "emergency stop enabled",
                "emergency stop failed",
            )
        )

        _stop_processes(processes)
        for handle in handles:
            handle.close()
        processes, handles = [], []
        scheduled = _run(
            [str(REPO_ROOT / ".venv/bin/incogni"), "schedule"], env=env
        )
        checks.append(
            _check(
                "scheduler",
                scheduled.returncode == 0,
                "one-shot scheduler completed",
                "one-shot scheduler failed",
            )
        )
        with ServiceStore(config.db_path, config.crypto) as store:
            DurableJobQueue(store).enqueue(
                "retention_cleanup",
                {},
                idempotency_key="rehearsal-restart:" + secrets.token_hex(16),
            )
        processes, handles = _start_service_processes(root, selected_port, env)
        _wait_for_health(base_url, processes[0])
        time.sleep(0.25)
        with ServiceStore(config.db_path, config.crypto) as store:
            queued_during_stop = store.health()["jobs_pending"] > 0
            stop_persisted = store.health()["emergency_stop"]
        checks.append(
            _check(
                "restart_recovery",
                queued_during_stop and stop_persisted,
                "emergency stop and queued work survived restart",
                "restart recovery invariant failed",
            )
        )

        opener = _new_client()
        login_status, login = _http(
            opener,
            base_url + "/api/login",
            method="POST",
            payload={"password": SYNTHETIC_PASSWORD},
        )
        csrf = str(login.get("csrf_token", ""))
        resume_status, resume = _http(
            opener, base_url + "/api/resume", method="POST", csrf=csrf
        )
        checks.append(
            _check(
                "emergency_resume",
                login_status == 200
                and resume_status == 200
                and resume.get("emergency_stop") is False,
                "emergency stop resumed with authenticated CSRF request",
                "emergency resume failed",
            )
        )
        checks.append(
            _check(
                "maintenance",
                _wait_for_jobs(config),
                "worker completed scheduled maintenance",
                "scheduled maintenance did not complete",
            )
        )
        cli_health = _run(
            [str(REPO_ROOT / ".venv/bin/incogni"), "health"], env=env
        )
        checks.append(
            _check(
                "health_cli",
                cli_health.returncode == 0
                and '"database": "available"' in cli_health.stdout,
                "CLI health probe passed",
                "CLI health probe failed",
            )
        )
    finally:
        _stop_processes(processes)
        for handle in handles:
            handle.close()

    checks.append(
        _check(
            "backup_restore",
            _verify_backup(config, root),
            "encrypted backup restored and fail-closed checks passed",
            "encrypted backup restoration failed",
        )
    )
    checks.append(
        _check(
            "soak_rehearsal",
            _verify_synthetic_soak(config, root),
            "synthetic soak start check and status passed",
            "synthetic soak rehearsal failed",
        )
    )
    checks.append(
        _check(
            "broker_safety",
            _validate_broker_safety(config, root),
            "five brokers remain paused, monitor-only, and transport-disabled",
            "broker safety invariant failed",
        )
    )
    checks.append(
        _check(
            "fixture_safety",
            _validate_fixture_tree(),
            "sanitized fixtures contain no PII or verification URLs",
            "fixture safety scan failed",
        )
    )
    checks.append(
        _check(
            "artifact_safety",
            not _artifact_contains(
                root / "var/lib/incogni", SYNTHETIC_SENTINEL.encode()
            ),
            "generated artifacts contain no plaintext sensitive sentinel",
            "plaintext sensitive sentinel found in generated artifacts",
        )
    )
    systemd_checks, _scores = validate_systemd_stage(root)
    checks.extend(systemd_checks)
    checks.append(validate_tailscale_policy(load_tailscale_policy()))
    status = (
        "pass" if all(check.status != "failure" for check in checks) else "failure"
    )
    return RehearsalResult(status, selected_port, tuple(checks))


def production_plan() -> str:
    """Return a human-controlled installation plan without inspecting state."""

    return """Privileged installation commands (do not run without approval):

sudo install -d -m 0700 /root/incogni-rollback
sudo /bin/sh -c 'umask 077; tailscale serve get-config --all > /root/incogni-rollback/tailscale-before.json'
sudo useradd --system --home /var/lib/incogni --shell /usr/sbin/nologin incogni
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin --gid incogni incogni-browser
sudo install -d -o root -g root -m 0755 /opt/incogni
sudo install -d -o incogni -g incogni -m 0770 /var/lib/incogni
sudo install -d -o root -g root -m 0700 /etc/incogni/credentials
sudo install -d -o root -g root -m 0755 /opt/incogni/source
git archive --format=tar --output=/tmp/incogni-source.tar HEAD
sudo tar -xf /tmp/incogni-source.tar -C /opt/incogni/source
sudo python3 -m venv /opt/incogni/.venv
sudo /opt/incogni/.venv/bin/pip install '/opt/incogni/source[service]'
sudo /opt/incogni/.venv/bin/incogni init-credentials --directory /etc/incogni/credentials
sudo install -m 0644 deploy/systemd/incogni-*.service deploy/systemd/incogni-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now incogni-api.service incogni-worker.service incogni-maintenance.timer incogni-health.timer
sudo tailscale serve --bg http://127.0.0.1:8765

Expected results:
- API listens only on 127.0.0.1:8765 and /healthz returns status ok.
- API, worker, maintenance timer, and health timer are active; browser worker is disabled.
- All five brokers report paused and monitor_only.

Recoverable rollback:
sudo systemctl disable --now incogni-api.service incogni-worker.service incogni-maintenance.timer incogni-health.timer
sudo tailscale serve set-config --all /root/incogni-rollback/tailscale-before.json
sudo install -d -m 0700 /root/incogni-rollback/files
sudo mv /etc/systemd/system/incogni-*.service /etc/systemd/system/incogni-*.timer /root/incogni-rollback/files/
sudo mv /opt/incogni /root/incogni-rollback/files/opt-incogni
sudo mv /var/lib/incogni /root/incogni-rollback/files/var-lib-incogni
sudo mv /etc/incogni /root/incogni-rollback/files/etc-incogni
sudo systemctl daemon-reload

Approval required: authorize privileged host installation and Tailscale Serve configuration only after reviewing this plan and selecting the final host."""
