import argparse
import contextlib
import io
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from incogni.deployment import (
    REPO_ROOT,
    STAGE_MARKER,
    UNIT_NAMES,
    DeploymentCheck,
    load_tailscale_policy,
    production_plan,
    remove_stage,
    run_preflight,
    run_rehearsal,
    stage_installation,
    stage_is_owned,
    validate_stage_root,
    validate_systemd_stage,
    validate_tailscale_policy,
)
from incogni.service_cli import _print_deployment_checks, cmd_deploy_rehearse


class DeploymentStagingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp")
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_stage_is_private_idempotent_and_exact(self):
        root = self.base / "stage"
        first = stage_installation(root)
        key = root / "etc/incogni/credentials/incogni-master-key"
        password = root / "etc/incogni/credentials/incogni-admin-password"
        original_credentials = (key.read_bytes(), password.read_bytes())

        second = stage_installation(root)
        self.assertEqual(first, second)
        self.assertEqual(original_credentials, (key.read_bytes(), password.read_bytes()))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(password.stat().st_mode), 0o600)
        self.assertTrue(stage_is_owned(root))
        self.assertFalse((root / "etc/incogni/browser-enabled").exists())
        for name in UNIT_NAMES:
            self.assertEqual(
                (root / "etc/systemd/system" / name).read_bytes(),
                (REPO_ROOT / "deploy/systemd" / name).read_bytes(),
            )

    def test_rejects_production_symlink_and_unowned_roots(self):
        for path in (Path("/"), Path("/etc/incogni"), Path("/opt/incogni"), Path("/var/lib/incogni")):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_stage_root(path)

        target = self.base / "target"
        target.mkdir()
        link = self.base / "linked-stage"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            validate_stage_root(link)

        unowned = self.base / "unowned"
        unowned.mkdir()
        (unowned / "unrelated").write_text("leave me", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not owned"):
            stage_installation(unowned)
        self.assertEqual((unowned / "unrelated").read_text(encoding="utf-8"), "leave me")

    def test_rejects_symlinked_marker_and_managed_unit(self):
        marker_root = self.base / "marker-root"
        marker_root.mkdir()
        outside = self.base / "outside"
        outside.write_text("outside", encoding="utf-8")
        (marker_root / STAGE_MARKER).symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "ownership marker"):
            stage_installation(marker_root)

        root = stage_installation(self.base / "stage")
        unit = root / "etc/systemd/system/incogni-api.service"
        unit.unlink()
        unit.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "unsafe staged unit"):
            stage_installation(root)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")

    def test_remove_stage_requires_owned_marker(self):
        root = stage_installation(self.base / "stage")
        remove_stage(root)
        self.assertFalse(root.exists())
        unowned = self.base / "unowned"
        unowned.mkdir()
        (unowned / "unrelated").write_text("preserve", encoding="utf-8")
        with self.assertRaises(ValueError):
            remove_stage(unowned)
        self.assertTrue(unowned.exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and shutil.which("systemd-analyze") is not None
        and Path("/usr/lib/systemd/system").is_dir(),
        "requires a Linux systemd host",
    )
    def test_exact_units_validate_in_alternate_root(self):
        root = stage_installation(self.base / "stage")
        checks, scores = validate_systemd_stage(root)
        self.assertTrue(all(check.status == "pass" for check in checks), checks)
        self.assertEqual(len(scores), 7)
        self.assertLessEqual(max(scores.values()), 7.0)
        self.assertIn(
            "systemd_safety_policy", {check.code for check in checks}
        )


class DeploymentPolicyTest(unittest.TestCase):
    def test_journal_audit_is_scoped_and_shares_marker_with_soak(self):
        unit = (REPO_ROOT / "deploy/systemd/incogni-journal-audit.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("User=incogni\n", unit)
        self.assertIn("Group=incogni\n", unit)
        self.assertIn("SupplementaryGroups=systemd-journal", unit)
        self.assertIn("InaccessiblePaths=/etc/incogni /var/lib/incogni", unit)
        self.assertIn("RuntimeDirectory=incogni-journal-audit", unit)
        self.assertNotIn("DynamicUser=true", unit)
        self.assertNotIn("LoadCredential=", unit)

    def test_journal_audit_unit_outlasts_cold_journal_query(self):
        from incogni.soak import JOURNAL_AUDIT_QUERY_TIMEOUT

        unit = (REPO_ROOT / "deploy/systemd/incogni-journal-audit.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("TimeoutStartSec=8min\n", unit)
        self.assertLess(JOURNAL_AUDIT_QUERY_TIMEOUT + 60, 8 * 60)

    def test_health_timer_delays_first_probe_after_activation(self):
        timer = (REPO_ROOT / "deploy/systemd/incogni-health.timer").read_text(
            encoding="utf-8"
        )
        self.assertIn("OnActiveSec=2m", timer)
        self.assertIn("OnUnitActiveSec=5m", timer)
        self.assertNotIn("OnBootSec=", timer)

    def test_tailscale_policy_is_static_loopback_only(self):
        check = validate_tailscale_policy(load_tailscale_policy())
        self.assertEqual(check.status, "pass")
        policy = load_tailscale_policy()
        policy["funnel"] = True
        self.assertEqual(validate_tailscale_policy(policy).status, "failure")

    def test_production_plan_is_nonexecuting_and_tracked_source_only(self):
        plan = production_plan()
        self.assertIn("do not run without approval", plan)
        self.assertIn("git archive", plan)
        self.assertIn("Expected results:", plan)
        self.assertIn("Recoverable rollback:", plan)
        self.assertIn("Approval required:", plan)
        self.assertIn("tailscale serve get-config --all >", plan)
        self.assertIn("tailscale serve set-config --all ", plan)
        self.assertNotIn("tailscale-before.json --all", plan)
        self.assertNotIn("cp -a .", plan)

    def test_check_output_exit_codes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                _print_deployment_checks(
                    [DeploymentCheck("warn", "warning", "expected")],
                    as_json=True,
                ),
                0,
            )
            self.assertEqual(
                _print_deployment_checks(
                    [DeploymentCheck("bad", "failure", "expected")],
                    as_json=False,
                ),
                2,
            )

    def test_preflight_reads_only_public_os_release(self):
        original = Path.read_text
        reads = []

        def guarded(path, *args, **kwargs):
            reads.append(path)
            self.assertEqual(path, Path("/etc/os-release"))
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", new=guarded):
            checks = run_preflight()
        codes = {check.code for check in checks}
        self.assertIn("host_linux", codes)
        self.assertIn("reasonix_sandbox", codes)
        self.assertEqual(reads, [Path("/etc/os-release")])

    def test_invalid_preflight_port_fails_cleanly(self):
        checks = run_preflight(port=0)
        port_check = next(
            check for check in checks if check.code == "loopback_port_available"
        )
        self.assertEqual(port_check.status, "failure")


class DeploymentRehearsalTest(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and shutil.which("systemd-analyze") is not None
        and (REPO_ROOT / ".venv/bin/incogni").is_file(),
        "requires the repository Linux service environment",
    )
    def test_full_synthetic_rehearsal(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary) / "stage"
            result = run_rehearsal(root)
            self.assertEqual(result.status, "pass", result.checks)
            codes = {check.code for check in result.checks}
            self.assertTrue(
                {
                    "health_http",
                    "authentication_required",
                    "csrf_required",
                    "emergency_stop",
                    "restart_recovery",
                    "scheduler",
                    "maintenance",
                    "backup_restore",
                    "soak_rehearsal",
                    "broker_safety",
                    "fixture_safety",
                    "artifact_safety",
                    "systemd_verify",
                    "tailscale_policy",
                }.issubset(codes)
            )
            repeated = run_rehearsal(root)
            self.assertEqual(repeated.status, "pass", repeated.checks)

    def test_cli_cleans_owned_stage_after_failure(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = stage_installation(Path(temporary) / "stage")
            args = argparse.Namespace(root=str(root), port=0, keep=False)
            with patch(
                "incogni.service_cli.run_rehearsal",
                side_effect=RuntimeError("synthetic failure"),
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_deploy_rehearse(args), 2)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
