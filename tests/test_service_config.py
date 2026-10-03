import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from incogni.service_config import ServiceConfig


class ServiceConfigTest(unittest.TestCase):
    def test_reads_private_systemd_style_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "incogni-master-key"
            password = root / "incogni-admin-password"
            key.write_text(
                base64.urlsafe_b64encode(b"k" * 32).decode() + "\n",
                encoding="utf-8",
            )
            password.write_text("$argon2id$synthetic\n", encoding="utf-8")
            os.chmod(key, 0o600)
            os.chmod(password, 0o600)
            with patch.dict(
                os.environ,
                {
                    "CREDENTIALS_DIRECTORY": str(root),
                    "INCOGNI_DATA_DIR": str(root / "data"),
                    "INCOGNI_SECURE_COOKIES": "false",
                },
                clear=False,
            ):
                config = ServiceConfig.from_env()
            self.assertEqual(config.db_path, root / "data" / "service.db")
            self.assertFalse(config.secure_cookies)

    def test_rejects_permissive_and_symlinked_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "key"
            key.write_text("secret", encoding="utf-8")
            os.chmod(key, 0o644)
            with self.assertRaisesRegex(RuntimeError, "group or world"):
                ServiceConfig._read_secret(key)
            os.chmod(key, 0o600)
            link = root / "link"
            link.symlink_to(key)
            with self.assertRaisesRegex(RuntimeError, "symbolic"):
                ServiceConfig._read_secret(link)

    def test_accepts_only_group_read_for_systemd_runtime_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            credential = Path(temp) / "credential"
            credential.write_text("synthetic-secret", encoding="utf-8")
            os.chmod(credential, 0o440)
            self.assertEqual(
                ServiceConfig._read_secret(credential, allow_group_read=True),
                "synthetic-secret",
            )
            with self.assertRaisesRegex(RuntimeError, "group or world"):
                ServiceConfig._read_secret(credential)

            for unsafe_mode in (0o460, 0o444):
                with self.subTest(mode=oct(unsafe_mode)):
                    os.chmod(credential, unsafe_mode)
                    with self.assertRaisesRegex(RuntimeError, "group or world"):
                        ServiceConfig._read_secret(
                            credential, allow_group_read=True
                        )

    def test_systemd_group_read_scope_requires_direct_runtime_child(self):
        directory = Path("/run/credentials/incogni-api.service")
        self.assertTrue(
            ServiceConfig._is_systemd_runtime_credential(
                directory / "incogni-master-key", directory
            )
        )
        self.assertFalse(
            ServiceConfig._is_systemd_runtime_credential(
                Path("/etc/incogni/credentials/incogni-master-key"), directory
            )
        )
        self.assertFalse(
            ServiceConfig._is_systemd_runtime_credential(
                Path("/tmp/incogni-master-key"), Path("/tmp")
            )
        )


if __name__ == "__main__":
    unittest.main()
