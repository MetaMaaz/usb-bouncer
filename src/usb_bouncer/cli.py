"""Command-line entry point."""

import argparse
import json
import subprocess
import sys

from . import __version__, analyzer, events, ioreg, monitor, reporter, usb_ids


def _list(args: argparse.Namespace) -> int:
    reporter.print_table(monitor.list_devices())
    return 0


def _scan(args: argparse.Namespace) -> int:
    rules, vendors = analyzer.load_rules(), usb_ids.load_vendors()
    verdicts = [analyzer.analyze(d, rules, vendors) for d in ioreg.list_devices()]
    records = [events.verdict_record(v) for v in verdicts]
    if not args.no_log:
        for record in records:
            events.append(record)
    if args.json:
        print(json.dumps(records, indent=2))
    else:
        reporter.print_verdicts(verdicts)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="usb-bouncer",
        description="Vet USB devices for BadUSB red flags and keystroke injection.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list connected USB devices").set_defaults(run=_list)
    scan = sub.add_parser("scan", help="score connected USB devices and log the verdicts")
    scan.add_argument("--json", action="store_true", help="print the report as JSON")
    scan.add_argument("--no-log", action="store_true", help=f"do not append to {events.LOG}")
    scan.set_defaults(run=_scan)
    args = parser.parse_args(argv)

    try:
        return args.run(args)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"usb-bouncer: could not read USB devices (macOS only): {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
