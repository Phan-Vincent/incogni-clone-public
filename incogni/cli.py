"""Command-line interface for incogni-clone."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from incogni import __version__
from incogni.engine import Engine
from incogni.profile import PersonProfile
from incogni.registry import BrokerRegistry
from incogni.service_cli import register_service_commands
from incogni.tracker import Tracker

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = REPO_ROOT / "examples" / "profile.json"
DEFAULT_DB = Path.home() / ".local" / "share" / "incogni" / "tracker.db"


def _load(args: argparse.Namespace):
    profile = PersonProfile.from_file(args.profile)
    registry = BrokerRegistry.from_file(args.brokers)
    tracker = Tracker(args.db)
    engine = Engine(registry, tracker, profile)
    return registry, tracker, engine, profile


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = "\n".join(
        "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)) for row in rows
    )
    return f"{line}\n{sep}\n{body}"


def cmd_scan(args: argparse.Namespace) -> int:
    _, _, engine, _ = _load(args)
    results = engine.scan_all()
    rows = [
        [
            r.broker_id,
            r.status.value,
            ", ".join(r.matched_fields) if r.matched_fields else "-",
            r.detail,
        ]
        for r in results
    ]
    print(_table(["broker", "status", "matched fields", "detail"], rows))
    found = sum(1 for r in results if r.found)
    print(f"\n{len(results)} brokers scanned, {found} with your data exposed.")
    return 0


def cmd_optout(args: argparse.Namespace) -> int:
    _, _, engine, _ = _load(args)
    results = engine.submit_optouts()
    if not results:
        print("Nothing to do: no newly-detected records awaiting removal.")
        return 0
    rows = [
        [r.broker_id, r.status.value, r.confirmation_id or "-", r.message]
        for r in results
    ]
    print(_table(["broker", "status", "confirmation id", "message"], rows))
    confirmed = sum(1 for r in results if r.status.value == "confirmed")
    print(f"\n{len(results)} removal request(s) processed, {confirmed} confirmed.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    registry, tracker, _, _ = _load(args)
    rows = []
    for broker in registry:
        scan = tracker.latest_scan(broker.id)
        opt = tracker.get_optout(broker.id)
        rows.append(
            [
                broker.name,
                scan["status"] if scan else "never scanned",
                opt["status"] if opt else "-",
                opt["confirmation_id"] if opt and opt["confirmation_id"] else "-",
            ]
        )
    print(_table(["broker", "scan", "opt-out", "confirmation"], rows))
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    _, _, engine, _ = _load(args)
    try:
        result = engine.confirm_optout(args.broker_id, args.confirmation_id)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(
        f"{result.broker_id} marked confirmed"
        + (f" ({result.confirmation_id})" if result.confirmation_id else "")
        + "."
    )
    return 0


def cmd_brokers(args: argparse.Namespace) -> int:
    registry, _, _, _ = _load(args)
    rows = [
        [b.id, b.name, b.category, b.optout_method, b.adapter.__class__.__name__]
        for b in registry
    ]
    print(_table(["id", "name", "category", "method", "adapter"], rows))
    print(f"\n{len(registry)} brokers registered.")
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    _, _, _, profile = _load(args)
    present = [
        name
        for name, value in profile.to_dict().items()
        if value and name not in {"first_name", "middle_name", "last_name"}
    ]
    print(json.dumps({"profile": "loaded", "identifier_types": present}, indent=2))
    return 0


def cmd_due(args: argparse.Namespace) -> int:
    _, _, engine, _ = _load(args)
    due = engine.recheck_due(timedelta(days=args.days))
    if due:
        print("Brokers due for a re-scan:")
        for broker_id in due:
            print(f"  - {broker_id}")
    else:
        print("No brokers are due for a re-scan yet.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="incogni",
        description="Scan data brokers for your PII and automate removal requests.",
    )
    parser.add_argument("--version", action="version", version=f"incogni-clone {__version__}")
    parser.add_argument(
        "--profile", default=str(DEFAULT_PROFILE),
        help="path to a JSON PII profile (default: examples/profile.json)",
    )
    parser.add_argument(
        "--db", default=str(DEFAULT_DB),
        help="path to the SQLite tracker database",
    )
    parser.add_argument(
        "--brokers", default=None,
        help="path to a brokers.json catalog (default: bundled catalog)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="scan all brokers for your PII").set_defaults(func=cmd_scan)
    sub.add_parser("optout", help="submit removal requests for detected records").set_defaults(func=cmd_optout)
    sub.add_parser("status", help="show scan + opt-out status per broker").set_defaults(func=cmd_status)
    sub.add_parser("brokers", help="list registered brokers").set_defaults(func=cmd_brokers)
    sub.add_parser("profile", help="show a redacted profile summary").set_defaults(func=cmd_profile)

    confirm = sub.add_parser(
        "confirm", help="record broker confirmation of a submitted removal request"
    )
    confirm.add_argument("broker_id", help="broker id from the brokers command")
    confirm.add_argument(
        "--confirmation-id", help="confirmation or case id supplied by the broker"
    )
    confirm.set_defaults(func=cmd_confirm)

    due = sub.add_parser("due", help="list brokers due for a re-scan")
    due.add_argument("--days", type=int, default=30, help="re-scan interval in days")
    due.set_defaults(func=cmd_due)

    register_service_commands(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
