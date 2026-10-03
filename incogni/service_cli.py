"""Operational CLI commands for the private local service."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import socket
from pathlib import Path

from incogni.activation import BrokerActivation
from incogni.adapters.service import GuardrailPause
from incogni.adapters.guarded import seed_live_broker_flows
from incogni.api import create_app
from incogni.approvals import ApprovalManager
from incogni.auth import OperatorAuth
from incogni.drop import DROP_URL, DropCompanion
from incogni.deployment import (
    production_plan,
    remove_stage,
    run_preflight,
    run_rehearsal,
    stage_installation,
    validate_systemd_stage,
)
from incogni.gmail_oauth import authorize_gmail
from incogni.jobs import DurableJobQueue
from incogni.manual_assist import MANUAL_STEPS, ManualAssist
from incogni.models import AutomationLevel
from incogni.operations import default_handlers
from incogni.scheduler import ServiceScheduler
from incogni.service_config import ServiceConfig
from incogni.soak import SoakMonitor, audit_service_journal, format_status
from incogni.storage import ServiceStore
from incogni.worker import ServiceWorker


def _open_service(*, seed_brokers: bool = True) -> tuple[ServiceConfig, ServiceStore]:
    config = ServiceConfig.from_env()
    store = ServiceStore(config.db_path, config.crypto)
    if seed_brokers:
        seed_live_broker_flows(store)
    return config, store


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    config, store = _open_service()
    app = create_app(store, config)
    try:
        uvicorn.run(
            app, host=args.host, port=args.port, log_config=None, proxy_headers=False
        )
    finally:
        store.close()
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    config, store = _open_service()
    worker_id = args.worker_id or f"{socket.gethostname()}-{os.getpid()}"
    handlers = default_handlers(store, evidence_dir=config.evidence_dir)
    worker = ServiceWorker(
        store, worker_id, handlers, claim_kinds=set(handlers)
    )
    try:
        if args.once:
            result = worker.run_once()
            print(result.value if result else "idle")
        else:
            worker.run_forever(poll_seconds=args.poll_seconds)
    finally:
        store.close()
    return 0


def cmd_browser_worker(args: argparse.Namespace) -> int:
    config, store = _open_service()
    worker_id = args.worker_id or f"browser-{socket.gethostname()}-{os.getpid()}"

    def disabled(_job):
        raise GuardrailPause("live_browser_flow_not_activated")

    worker = ServiceWorker(
        store,
        worker_id,
        {
            "broker_browser_operation": disabled,
            "open_verification_link": disabled,
        },
        claim_kinds={"broker_browser_operation", "open_verification_link"},
    )
    try:
        if args.once:
            result = worker.run_once()
            print(result.value if result else "idle")
        else:
            worker.run_forever(poll_seconds=args.poll_seconds)
    finally:
        store.close()
    return 0

def cmd_approve(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        manager = ApprovalManager(store)
        if args.reissue:
            print(f"reissued as {manager.reissue(args.approval_id)}")
            return 0
        manager.decide_and_release(
            args.approval_id, approved=not args.reject
        )
        print("rejected" if args.reject else "approved")
        return 0
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        store.close()


def cmd_manual(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        assist = ManualAssist(store)
        if args.step == "found":
            result = assist.record_found(
                args.broker_id,
                profile_id=args.profile_id,
                additional=args.additional,
            )
            print(f"request id: {result['request_id']}")
            print(f"approval id: {result['approval_id']}")
            print(f"Approve with: incogni approve {result['approval_id']}")
            return 0
        if args.step == "checklist":
            checklist = assist.checklist(args.request_id)
            print(f"{checklist['broker_id']} opt-out: {checklist['opt_out_url']}")
            for number, step in enumerate(checklist["steps"], start=1):
                print(f"{number}. {step}")
            return 0
        print(assist.record(args.request_id, args.step))
        return 0
    except KeyError:
        target = "broker flow" if args.step == "found" else "request"
        print(f"Error: {target} not found")
        return 2
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        store.close()


def cmd_retry(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        DurableJobQueue(store).retry(args.job_id)
        store.record_audit("job_retried", "job", args.job_id)
        print("queued")
        return 0
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        store.close()


def cmd_broker_checkpoint(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        BrokerActivation(store).record_checkpoint(args.broker, args.checkpoint)
        print("checkpoint recorded")
        return 0
    except (KeyError, ValueError) as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        store.close()

def cmd_broker_mode(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        BrokerActivation(store).set_level(
            args.broker, AutomationLevel(args.level)
        )
        print("mode recorded; broker remains paused")
        return 0
    except (KeyError, ValueError) as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        store.close()

def cmd_pause(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        if args.broker:
            cursor = store.conn.execute(
                "UPDATE broker_flows SET paused=1,updated_at=datetime('now') "
                "WHERE broker_id=?",
                (args.broker,),
            )
            if cursor.rowcount != 1:
                print("Error: unknown broker flow")
                return 2
            store.record_audit("broker_paused", "broker", args.broker)
        else:
            store.set_setting("emergency_stop", "true")
            store.record_audit("emergency_stop_enabled", "service", "local")
        print("paused")
        return 0
    finally:
        store.close()


def cmd_resume(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        if args.broker:
            cursor = store.conn.execute(
                "UPDATE broker_flows SET paused=0,updated_at=datetime('now') "
                "WHERE broker_id=?",
                (args.broker,),
            )
            if cursor.rowcount != 1:
                print("Error: unknown broker flow")
                return 2
            store.record_audit("broker_resumed", "broker", args.broker)
        else:
            store.set_setting("emergency_stop", "false")
            store.record_audit("emergency_stop_disabled", "service", "local")
        print("active")
        return 0
    finally:
        store.close()


def cmd_drop_status(_args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        result = {
            "enrolled": store.get_setting("drop_enrolled", "false") == "true",
            "terms_acknowledged": store.get_setting("drop_terms_ack", "false") == "true",
            "updated_at": store.get_setting("drop_updated_at"),
            "official_url": DROP_URL,
        }
        print(json.dumps(result, indent=2))
        return 0
    finally:
        store.close()


def cmd_drop_enroll(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        companion = DropCompanion(store)
        companion.record_enrollment(terms_acknowledged=args.terms_acknowledged)
        companion.schedule_status_reminders()
        print("DROP enrollment recorded; no government credentials were stored.")
        return 0
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        store.close()


def cmd_health(_args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        health = store.health()
        health["database"] = "available"
        print(json.dumps(health, sort_keys=True))
        return 0
    finally:
        store.close()


def cmd_schedule(_args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        jobs = ServiceScheduler(store).enqueue_daily_maintenance()
        print(json.dumps({"scheduled": len(jobs)}))
        return 0
    finally:
        store.close()


def _run_soak_command(action: str, *, as_json: bool = False) -> int:
    _config, store = _open_service(seed_brokers=False)
    try:
        monitor = SoakMonitor(store)
        if action == "start":
            monitor.start()
        elif action == "check":
            monitor.check()
        elif action == "stop":
            monitor.stop()
        status = monitor.status()
        print(
            json.dumps(status, indent=2, sort_keys=True)
            if as_json
            else format_status(status)
        )
        return 2 if status["status"] == "failed" else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        store.close()


def cmd_soak_start(_args: argparse.Namespace) -> int:
    return _run_soak_command("start")


def cmd_soak_check(_args: argparse.Namespace) -> int:
    return _run_soak_command("check")


def cmd_soak_status(args: argparse.Namespace) -> int:
    return _run_soak_command("status", as_json=args.json)


def cmd_soak_stop(_args: argparse.Namespace) -> int:
    return _run_soak_command("stop")


def cmd_soak_audit_journal(args: argparse.Namespace) -> int:
    try:
        passed = audit_service_journal(Path(args.output))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}")
        return 2
    print("journal audit passed" if passed else "journal audit failed")
    return 0 if passed else 2


def cmd_gmail_authorize(args: argparse.Namespace) -> int:
    _config, store = _open_service()
    try:
        authorize_gmail(store, Path(args.client_secret).resolve())
        print("Gmail authorization stored encrypted.")
        return 0
    finally:
        store.close()

def cmd_init_credentials(args: argparse.Namespace) -> int:
    target = Path(args.directory).resolve()
    target.mkdir(parents=True, exist_ok=True)
    os.chmod(target, 0o700)
    key_path = target / "incogni-master-key"
    password_path = target / "incogni-admin-password"
    if key_path.exists() or password_path.exists():
        print("Error: credential files already exist")
        return 2
    password = getpass.getpass("Dashboard password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation or len(password) < 12:
        print("Error: passwords must match and contain at least 12 characters")
        return 2
    key_value = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    for path, value in (
        (key_path, key_value),
        (password_path, OperatorAuth.hash_password(password)),
    ):
        with path.open("x", encoding="utf-8") as handle:
            handle.write(value + "\n")
        os.chmod(path, 0o600)
    print(f"Credentials created in {target}; keep this directory private.")
    return 0


def _print_deployment_checks(checks, *, as_json: bool) -> int:
    payload = [
        {"code": check.code, "status": check.status, "detail": check.detail}
        for check in checks
    ]
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for check in checks:
            print(f"{check.status.upper():7} {check.code}: {check.detail}")
    return 2 if any(check.status == "failure" for check in checks) else 0


def cmd_deploy_preflight(args: argparse.Namespace) -> int:
    return _print_deployment_checks(run_preflight(args.port), as_json=args.json)


def cmd_deploy_stage(args: argparse.Namespace) -> int:
    try:
        root = stage_installation(Path(args.root))
        checks, scores = validate_systemd_stage(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}")
        return 2
    print(json.dumps({"status": "staged", "systemd_scores": scores}, sort_keys=True))
    return 2 if any(check.status == "failure" for check in checks) else 0


def cmd_deploy_rehearse(args: argparse.Namespace) -> int:
    root = Path(args.root)
    try:
        result = run_rehearsal(root, port=args.port)
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.status == "pass" else 2
    except Exception as exc:
        print(f"Error: deployment rehearsal failed: {exc}")
        return 2
    finally:
        if not args.keep:
            try:
                remove_stage(root)
            except ValueError:
                pass


def cmd_deploy_production_plan(_args: argparse.Namespace) -> int:
    print(production_plan())
    return 0


def register_service_commands(sub: argparse._SubParsersAction) -> None:
    serve = sub.add_parser("serve", help="run the local authenticated dashboard/API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.set_defaults(func=cmd_serve)

    worker = sub.add_parser("worker", help="run the durable local worker")
    worker.add_argument("--worker-id")
    worker.add_argument("--poll-seconds", type=float, default=2.0)
    worker.add_argument("--once", action="store_true")
    worker.set_defaults(func=cmd_worker)

    browser = sub.add_parser(
        "browser-worker", help="run the isolated broker browser worker"
    )
    browser.add_argument("--worker-id")
    browser.add_argument("--poll-seconds", type=float, default=2.0)
    browser.add_argument("--once", action="store_true")
    browser.set_defaults(func=cmd_browser_worker)

    approve = sub.add_parser("approve", help="approve or reject one guarded action")
    approve.add_argument("approval_id")
    decision = approve.add_mutually_exclusive_group()
    decision.add_argument("--reject", action="store_true")
    decision.add_argument(
        "--reissue",
        action="store_true",
        help="replace an approval that expired before a decision",
    )
    approve.set_defaults(func=cmd_approve)

    manual = sub.add_parser(
        "manual", help="show or record an operator-performed removal step"
    )
    manual_steps = manual.add_subparsers(dest="step", required=True)
    found = manual_steps.add_parser(
        "found", help="record a finding for a manual-only broker"
    )
    found.add_argument("broker_id")
    found.add_argument("--profile", dest="profile_id", default="owner")
    found.add_argument("--additional", action="store_true")
    found.set_defaults(func=cmd_manual)
    for step in ("checklist", *MANUAL_STEPS):
        command = manual_steps.add_parser(step)
        command.add_argument("request_id")
        command.set_defaults(func=cmd_manual)

    retry = sub.add_parser("retry", help="retry a blocked or dead job")
    retry.add_argument("job_id")
    retry.set_defaults(func=cmd_retry)

    checkpoint = sub.add_parser(
        "broker-checkpoint", help="record a broker activation checkpoint"
    )
    checkpoint.add_argument("broker")
    checkpoint.add_argument("checkpoint", choices=["terms", "canary", "human"])
    checkpoint.set_defaults(func=cmd_broker_checkpoint)

    mode = sub.add_parser("broker-mode", help="promote or demote one broker flow")
    mode.add_argument("broker")
    mode.add_argument(
        "level", choices=[level.value for level in AutomationLevel]
    )
    mode.set_defaults(func=cmd_broker_mode)

    for name, func in (("pause", cmd_pause), ("resume", cmd_resume)):
        command = sub.add_parser(name, help=f"{name} all execution or one broker")
        command.add_argument("--broker")
        command.set_defaults(func=func)

    sub.add_parser("drop-status", help="show local DROP enrollment tracking").set_defaults(
        func=cmd_drop_status
    )
    drop = sub.add_parser("drop-enroll", help="record completed human DROP enrollment")
    drop.add_argument("--terms-acknowledged", action="store_true", required=True)
    drop.set_defaults(func=cmd_drop_enroll)

    sub.add_parser("health", help="check encrypted service persistence").set_defaults(
        func=cmd_health
    )
    sub.add_parser("schedule", help="enqueue daily local maintenance").set_defaults(
        func=cmd_schedule
    )

    soak = sub.add_parser("soak", help="manage the synthetic monitor-mode soak")
    soak_sub = soak.add_subparsers(dest="soak_command", required=True)
    soak_sub.add_parser("start", help="start the fourteen-day soak").set_defaults(
        func=cmd_soak_start
    )
    soak_sub.add_parser("check", help="run one synthetic soak check").set_defaults(
        func=cmd_soak_check
    )
    soak_status = soak_sub.add_parser("status", help="show soak progress")
    soak_status.add_argument("--json", action="store_true")
    soak_status.set_defaults(func=cmd_soak_status)
    soak_sub.add_parser("stop", help="stop the active soak").set_defaults(
        func=cmd_soak_stop
    )
    journal_audit = soak_sub.add_parser(
        "audit-journal", help="run the isolated PII-free journal audit"
    )
    journal_audit.add_argument("--output", required=True)
    journal_audit.set_defaults(func=cmd_soak_audit_journal)

    gmail = sub.add_parser(
        "gmail-authorize", help="complete Gmail OAuth consent in a local browser"
    )
    gmail.add_argument("--client-secret", required=True)
    gmail.set_defaults(func=cmd_gmail_authorize)

    init = sub.add_parser("init-credentials", help="create local service credentials")
    init.add_argument("--directory", required=True)
    init.set_defaults(func=cmd_init_credentials)

    deploy = sub.add_parser(
        "deploy", help="inspect and rehearse private-host deployment"
    )
    deploy_sub = deploy.add_subparsers(dest="deploy_command", required=True)
    preflight = deploy_sub.add_parser("preflight", help="read-only host inspection")
    preflight.add_argument("--port", type=int, default=8765)
    preflight.add_argument("--json", action="store_true")
    preflight.set_defaults(func=cmd_deploy_preflight)
    stage = deploy_sub.add_parser(
        "stage", help="build a synthetic installation tree"
    )
    stage.add_argument("--root", required=True)
    stage.set_defaults(func=cmd_deploy_stage)
    rehearse = deploy_sub.add_parser(
        "rehearse", help="run the synthetic host rehearsal"
    )
    rehearse.add_argument("--root", required=True)
    rehearse.add_argument("--port", type=int, default=0)
    rehearse.add_argument("--keep", action="store_true")
    rehearse.set_defaults(func=cmd_deploy_rehearse)
    plan = deploy_sub.add_parser(
        "production-plan", help="print privileged handoff only"
    )
    plan.set_defaults(func=cmd_deploy_production_plan)
