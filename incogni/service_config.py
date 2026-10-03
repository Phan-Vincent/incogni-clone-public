"""Runtime configuration loaded without exposing secrets to logs."""

from __future__ import annotations

import base64
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from incogni.crypto import EnvelopeCrypto


@dataclass(frozen=True)
class ServiceConfig:
    db_path: Path
    evidence_dir: Path
    crypto: EnvelopeCrypto
    signing_key: bytes
    admin_password_hash: str
    secure_cookies: bool = True
    session_ttl_seconds: int = 3600

    @staticmethod
    def _read_secret(path: Path, *, allow_group_read: bool = False) -> str:
        if path.is_symlink():
            raise RuntimeError("credential files must not be symbolic links")
        mode = stat.S_IMODE(path.stat().st_mode)
        prohibited_bits = 0o037 if allow_group_read else 0o077
        if mode & prohibited_bits:
            raise RuntimeError("credential files must not be group or world accessible")
        return path.read_text(encoding="utf-8").strip()

    @staticmethod
    def _is_systemd_runtime_credential(path: Path, directory: Path) -> bool:
        return (
            directory.is_absolute()
            and directory.is_relative_to(Path("/run/credentials"))
            and path.parent == directory
        )

    @classmethod
    def from_env(cls) -> "ServiceConfig":
        data_dir = Path(
            os.environ.get(
                "INCOGNI_DATA_DIR",
                str(Path.home() / ".local" / "share" / "incogni"),
            )
        )
        credentials_dir = Path(os.environ.get("CREDENTIALS_DIRECTORY", data_dir))
        key_path = Path(
            os.environ.get(
                "INCOGNI_MASTER_KEY_FILE",
                str(credentials_dir / "incogni-master-key"),
            )
        )
        password_path = Path(
            os.environ.get(
                "INCOGNI_ADMIN_PASSWORD_HASH_FILE",
                str(credentials_dir / "incogni-admin-password"),
            )
        )
        key_id = os.environ.get("INCOGNI_MASTER_KEY_ID", "primary")
        try:
            key = base64.urlsafe_b64decode(
                cls._read_secret(
                    key_path,
                    allow_group_read=cls._is_systemd_runtime_credential(
                        key_path, credentials_dir
                    ),
                ).encode()
            )
        except Exception as exc:
            raise RuntimeError("master-key credential is missing or invalid") from exc
        if len(key) != 32:
            raise RuntimeError("master-key credential must decode to 32 bytes")
        try:
            password_hash = cls._read_secret(
                password_path,
                allow_group_read=cls._is_systemd_runtime_credential(
                    password_path, credentials_dir
                ),
            )
        except OSError as exc:
            raise RuntimeError("admin-password credential is missing") from exc
        return cls(
            db_path=Path(os.environ.get("INCOGNI_DB", str(data_dir / "service.db"))),
            evidence_dir=Path(
                os.environ.get("INCOGNI_EVIDENCE_DIR", str(data_dir / "evidence"))
            ),
            crypto=EnvelopeCrypto({key_id: key}, key_id),
            signing_key=key,
            admin_password_hash=password_hash,
            secure_cookies=os.environ.get("INCOGNI_SECURE_COOKIES", "true").lower()
            == "true",
            session_ttl_seconds=int(os.environ.get("INCOGNI_SESSION_TTL", "3600")),
        )
