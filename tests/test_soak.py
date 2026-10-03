import json
import os
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from io import StringIO
from types import SimpleNamespace
from unittest.mock import MagicMock
from unittest.mock import patch

from incogni.adapters.guarded import seed_live_broker_flows
from incogni.crypto import EnvelopeCrypto
from incogni.jobs import DurableJobQueue
from incogni.cli import build_parser
from incogni.soak import (
    BROKER_IDS,
    HostSoakProbe,
    SoakMonitor,
    UnitState,
    audit_service_journal,
    fixture_tree_safe,
    run_fixture_canaries,
)
from incogni.storage import ServiceStore
from incogni.service_cli import cmd_soak_status


START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now


class FakeProbe:
    def __init__(self, clock):
        self.clock = clock
        self.states = {
            "incogni-api.service": UnitState(
                "loaded", "active", "running", "success", 0, "enabled"
            ),
            "incogni-worker.service": UnitState(
                "loaded", "active", "running", "success", 0, "enabled"
            ),
            "incogni-maintenance.timer": UnitState(
                "loaded", "active", "waiting", "success", 0, "enabled"
            ),
            "incogni-health.timer": UnitState(
                "loaded", "active", "waiting", "success", 0, "enabled"
            ),
            "incogni-maintenance.service": UnitState(
                "loaded", "inactive", "dead", "success", 0, "static"
            ),
            "incogni-health.service": UnitState(
                "loaded", "inactive", "dead", "success", 0, "static"
            ),
            "incogni-browser-worker.service": UnitState(
                "loaded", "inactive", "dead", "success", 0, "disabled"
            ),
            "incogni-soak.timer": UnitState(
                "loaded", "active", "waiting", "success", 0, "enabled"
            ),
        }
        self.healthy = True
        self.addresses = ("127.0.0.1",)
        self.tailscale = True
        self.free = 5 << 30
        self.total = 10 << 30
        self.backup_age = timedelta(hours=1)
        self.backup_mode = 0o600

    def unit_state(self, name):
        return self.states[name]

    def api_healthy(self, port):
        return self.healthy and port == 8765

    def listener_addresses(self, port):
        return self.addresses if port == 8765 else ()

    def tailscale_safe(self, port):
        return self.tailscale and port == 8765

    def disk_usage(self, _path):
        return self.free, self.total

    def latest_backup(self, _directory):
        if self.backup_age is None:
            return None
        return self.clock() - self.backup_age, self.backup_mode

    def service_logs_safe(self):
        return True


class SoakTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.db = self.base / "service.db"
        self.store = ServiceStore(
            self.db, EnvelopeCrypto({"test": b"k" * 32}, "test")
        )
        os.chmod(self.db, 0o600)
        seed_live_broker_flows(self.store)
        for path in (Path(str(self.db) + "-wal"), Path(str(self.db) + "-shm")):
            os.chmod(path, 0o600)
        self.clock = Clock()
        self.probe = FakeProbe(self.clock)
        self.root = self.base / "soak"
        self.monitor = SoakMonitor(
            self.store,
            root=self.root,
            probe=self.probe,
            clock=self.clock,
            browser_gate=self.base / "browser-enabled",
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def latest(self):
        return self.monitor.status()["latest_checks"]

    def result(self, code):
        return next(item for item in self.latest() if item["code"] == code)

    def test_start_stop_and_restart_are_idempotent(self):
        first = self.monitor.start()
        second = self.monitor.start()
        self.assertEqual(first, second)
        self.assertEqual(first["expected_completion_at"], (START + timedelta(days=14)).isoformat())
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.monitor.state_path.stat().st_mode), 0o600)

        stopped = self.monitor.stop()
        stopped_again = self.monitor.stop()
        self.assertEqual(stopped["stopped_at"], stopped_again["stopped_at"])
        stopped_elapsed = self.monitor.status()["elapsed_seconds"]
        self.clock.now += timedelta(hours=1)
        self.assertEqual(self.monitor.status()["elapsed_seconds"], stopped_elapsed)
        restarted = self.monitor.start()
        self.assertEqual(restarted["status"], "running")
        self.assertEqual(restarted["started_at"], self.clock().isoformat())
        self.assertEqual(restarted["history"], [])

    def test_elapsed_time_and_restart_continuity(self):
        self.monitor.start()
        self.clock.now += timedelta(days=2, seconds=7)
        reopened = SoakMonitor(
            self.store,
            root=self.root,
            probe=self.probe,
            clock=self.clock,
            browser_gate=self.base / "browser-enabled",
        )
        status = reopened.status()
        self.assertEqual(status["elapsed_seconds"], 2 * 86400 + 7)
        self.assertEqual(status["checks_run"], 0)
        reopened.check()
        self.assertEqual(reopened.status()["checks_run"], 1)

    def test_good_check_covers_every_safety_boundary(self):
        self.monitor.start()
        self.monitor.check()
        status = self.monitor.status()
        self.assertEqual(status["status"], "running")
        self.assertTrue(all(item["status"] == "pass" for item in self.latest()))
        self.assertTrue(
            {
                "api_health",
                "unexpected_restarts",
                "maintenance_results",
                "backup_freshness",
                "timer_health",
                "disk_capacity",
                "loopback_listener",
                "tailscale_serve",
                "emergency_stop_available",
                "queue_health",
                "schema_version",
                "broker_safety",
                "flow_versions",
                "synthetic_canaries",
                "fixture_safety",
                "filesystem_permissions",
                "gmail_disabled",
                "drop_automation_disabled",
                "broker_submissions_disabled",
                "browser_worker_disabled",
                "live_transports_disabled",
            }.issubset({item["code"] for item in self.latest()})
        )
        self.monitor.check()
        self.assertEqual(self.monitor.status()["checks_run"], 1)

    def test_stale_or_missing_backup_fails(self):
        for age in (timedelta(hours=27), None):
            with self.subTest(age=age):
                root = self.base / ("soak-missing" if age is None else "soak-stale")
                monitor = SoakMonitor(
                    self.store, root=root, probe=self.probe, clock=self.clock
                )
                self.probe.backup_age = age
                monitor.start()
                monitor.check()
                result = next(
                    item
                    for item in monitor.status()["latest_checks"]
                    if item["code"] == "backup_freshness"
                )
                self.assertEqual(result["status"], "failure")
        self.probe.backup_age = timedelta(hours=1)

    def test_failed_unit_and_restart_are_detected(self):
        self.monitor.start()
        self.probe.states["incogni-api.service"] = UnitState(
            "loaded", "failed", "failed", "exit-code", 1, "enabled"
        )
        self.monitor.check()
        self.assertEqual(self.result("api_service")["status"], "failure")
        self.assertEqual(self.result("unexpected_restarts")["status"], "failure")

    def test_listener_and_tailscale_policy_violations_fail(self):
        self.monitor.start()
        self.probe.addresses = ("0.0.0.0", "127.0.0.1")
        self.probe.tailscale = False
        self.monitor.check()
        self.assertEqual(self.result("loopback_listener")["status"], "failure")
        self.assertEqual(self.result("tailscale_serve")["status"], "failure")

    def test_broker_flow_and_disabled_runtime_violations_fail(self):
        self.store.conn.execute(
            "UPDATE broker_flows SET paused=0,automation_level='automatic',"
            "flow_version='drifted' WHERE broker_id='spokeo'"
        )
        self.store.put_secret("gmail_oauth", {"refresh_token": "encrypted-input"})
        self.store.put_secret("drop_enrollment", {})
        self.monitor.start()
        self.probe.states["incogni-browser-worker.service"] = UnitState(
            "loaded", "active", "running", "success", 0, "enabled"
        )
        (self.base / "browser-enabled").write_text("enabled", encoding="utf-8")
        self.monitor.check()
        for code in (
            "broker_safety",
            "flow_versions",
            "gmail_disabled",
            "drop_automation_disabled",
            "browser_worker_disabled",
            "browser_gate_absent",
        ):
            self.assertEqual(self.result(code)["status"], "failure")

    def test_queue_dead_letter_and_submission_work_fail(self):
        job = DurableJobQueue(self.store).enqueue(
            "open_verification_link", {}, idempotency_key="synthetic-unsafe"
        )
        self.store.conn.execute("UPDATE jobs SET status='dead' WHERE id=?", (job,))
        self.monitor.start()
        self.monitor.check()
        self.assertEqual(self.result("queue_health")["status"], "failure")
        self.assertEqual(
            self.result("broker_submissions_disabled")["status"], "failure"
        )

    def test_schema_drift_becomes_a_stable_failed_check(self):
        self.store.conn.execute(
            "ALTER TABLE service_settings RENAME COLUMN value TO drifted_value"
        )
        self.monitor.start()
        self.monitor.check()
        self.assertEqual(self.result("store_metadata")["status"], "failure")

    def test_missing_fixture_and_transport_assertion_fail_closed(self):
        self.assertTrue(run_fixture_canaries())
        self.assertTrue(fixture_tree_safe())
        with tempfile.TemporaryDirectory() as temporary:
            empty = Path(temporary)
            self.assertFalse(fixture_tree_safe(empty))
            with self.assertRaises(FileNotFoundError):
                run_fixture_canaries(empty)
            monitor = SoakMonitor(
                self.store,
                root=self.base / "soak-missing-fixture",
                probe=self.probe,
                clock=self.clock,
                fixture_root=empty,
                browser_gate=self.base / "browser-enabled",
            )
            monitor.start()
            monitor.check()
            latest = monitor.status()["latest_checks"]
            failures = {
                item["code"] for item in latest if item["status"] == "failure"
            }
            self.assertTrue(
                {"synthetic_canaries", "fixture_safety", "live_transports_disabled"}
                <= failures
            )

    def test_unsafe_permissions_fail_and_are_repaired_on_write(self):
        self.monitor.start()
        os.chmod(self.monitor.report_path, 0o644)
        self.monitor.check()
        self.assertEqual(self.result("filesystem_permissions")["status"], "failure")
        self.assertEqual(stat.S_IMODE(self.monitor.report_path.stat().st_mode), 0o600)

    def test_report_retains_only_redacted_operational_metadata(self):
        private_value = "private-person@example.invalid"
        self.store.create_profile("owner", {"email": private_value})
        self.monitor.start()
        self.monitor.check()
        state = self.monitor.state_path.read_text(encoding="utf-8")
        report = self.monitor.report_path.read_text(encoding="utf-8")
        for payload in (state, report):
            self.assertNotIn(private_value, payload)
            self.assertNotIn("encrypted_payload", payload)
            self.assertNotIn("127.0.0.1", payload)
            self.assertNotIn(str(self.base), payload)
        parsed = json.loads(report)
        self.assertFalse(parsed["automatic_promotion"])
        self.assertEqual(parsed["retained_data"], "operational metadata only")

    def test_successful_fourteen_day_completion_never_promotes(self):
        self.monitor.start()
        self.monitor.check()
        self.clock.now += timedelta(days=14, seconds=1)
        self.monitor.check()
        status = self.monitor.status()
        self.assertEqual(status["status"], "passed")
        self.assertIsNotNone(status["completed_at"])
        rows = self.store.conn.execute(
            "SELECT broker_id,automation_level,paused FROM broker_flows"
        ).fetchall()
        self.assertEqual({row["broker_id"] for row in rows}, set(BROKER_IDS))
        self.assertTrue(
            all(row["automation_level"] == "monitor_only" and row["paused"] == 1 for row in rows)
        )


class HostProbeParsingTest(unittest.TestCase):
    def test_isolated_journal_audit_writes_only_fresh_boolean_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "status.json"
            result = subprocess.CompletedProcess(
                ["journalctl"], 0, "service started safely\n", ""
            )
            self.assertTrue(
                audit_service_journal(
                    output, clock=lambda: START, runner=lambda *args, **kwargs: result
                )
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                payload,
                {
                    "schema_version": 1,
                    "checked_at": START.isoformat(),
                    "query_ok": True,
                    "safe": True,
                },
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            with patch("incogni.soak.utc_now", return_value=START + timedelta(minutes=1)):
                self.assertTrue(HostSoakProbe(output).service_logs_safe())
            with patch("incogni.soak.utc_now", return_value=START + timedelta(minutes=71)):
                self.assertFalse(HostSoakProbe(output).service_logs_safe())

    def test_journal_audit_allows_slow_cold_journal_queries(self):
        seen = {}

        def runner(argv, **kwargs):
            seen.update(kwargs)
            return subprocess.CompletedProcess(argv, 0, "service started safely\n", "")

        with tempfile.TemporaryDirectory() as temporary:
            audit_service_journal(
                Path(temporary) / "status.json", clock=lambda: START, runner=runner
            )
        # Cold queries across ~100 archived files took 57-112s on the host's HDD.
        self.assertGreaterEqual(seen["timeout"], 180)

    def test_journal_permission_failure_is_recorded_without_error_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "status.json"
            result = subprocess.CompletedProcess(
                ["journalctl"], 1, "", "permission denied private detail"
            )
            self.assertFalse(
                audit_service_journal(
                    output, clock=lambda: START, runner=lambda *args, **kwargs: result
                )
            )
            rendered = output.read_text(encoding="utf-8")
            self.assertNotIn("permission", rendered)
            self.assertEqual(
                json.loads(rendered)["query_ok"], False
            )

    def test_soak_status_does_not_seed_or_repair_broker_metadata(self):
        store = MagicMock()
        monitor = MagicMock()
        monitor.status.return_value = {
            "status": "not_started",
            "started_at": None,
            "expected_completion_at": None,
            "checks_run": 0,
            "passed_runs": 0,
            "failed_runs": 0,
            "remaining_seconds": 1209600,
        }
        with patch(
            "incogni.service_cli._open_service", return_value=(None, store)
        ) as opened, patch(
            "incogni.service_cli.SoakMonitor", return_value=monitor
        ), redirect_stdout(StringIO()):
            result = cmd_soak_status(SimpleNamespace(json=False))
        self.assertEqual(result, 0)
        opened.assert_called_once_with(seed_brokers=False)
        store.close.assert_called_once()

    def test_command_timeout_becomes_a_failed_probe_not_an_exception(self):
        with patch(
            "incogni.soak.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["systemctl"], 1),
        ):
            state = HostSoakProbe().unit_state("incogni-api.service")
        self.assertEqual(state.load, "missing")
        self.assertEqual(state.restarts, -1)

    def test_cli_exposes_requested_soak_commands_and_json_status(self):
        parser = build_parser()
        for command in ("start", "check", "stop"):
            args = parser.parse_args(["soak", command])
            self.assertTrue(callable(args.func))
        status = parser.parse_args(["soak", "status", "--json"])
        self.assertTrue(status.json)

    def test_tailscale_text_never_escapes_into_result(self):
        probe = HostSoakProbe()
        completed = type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "https://synthetic-host.invalid/\n|-- proxy http://127.0.0.1:8765\n",
                "stderr": "",
            },
        )()
        with patch("incogni.soak.shutil.which", return_value="/usr/bin/tailscale"), patch(
            "incogni.soak._run", return_value=completed
        ):
            self.assertTrue(probe.tailscale_safe(8765))


if __name__ == "__main__":
    unittest.main()
