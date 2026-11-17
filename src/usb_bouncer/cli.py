"""Command-line entry point."""

import argparse
import json
import subprocess
import sys
import time
from collections import deque
from collections.abc import Callable

from . import __version__, analyzer, events, hid_watch, ioreg, monitor, reporter, usb_ids
from .model import Device
from .watch import watch

HID_CLASS = 0x03
SUSPECT_WINDOW_S = 60  # how long after attaching an HID device stays a suspect
ALERT_COOLDOWN_S = 5  # a long payload is one alert, not one per ten keys


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


def _watch(args: argparse.Namespace) -> int:
    rules, vendors = analyzer.load_rules(), usb_ids.load_vendors()
    recent_hid: deque[tuple[float, Device]] = deque(maxlen=32)
    last_alert = float("-inf")

    def log(record: dict) -> None:
        if not args.no_log:
            events.append(record)

    def on_attach(d: Device) -> None:
        v = analyzer.analyze(d, rules, vendors)
        log(events.verdict_record(v))
        reporter.print_attach(v)
        if any(i.interface_class == HID_CLASS for i in d.interfaces):
            recent_hid.append((time.monotonic(), v.device))
        if v.level == "RED":
            reporter.notify("usb-bouncer: RED device", f"{d.name}: {', '.join(v.fired)}")

    def on_detach(d: Device) -> None:
        log(events.envelope("device_detached", device=events.device_block(d)))
        reporter.print_detach(d)

    def on_key(timestamp: float) -> None:
        nonlocal last_alert
        gap = detector.add(timestamp)
        now = time.monotonic()
        if gap is None or now - last_alert < ALERT_COOLDOWN_S:
            return
        last_alert = now
        suspects = [d for attached, d in recent_hid if now - attached < SUSPECT_WINDOW_S]
        log(
            events.envelope(
                "hid_timing_alert",
                verdict="RED",
                median_ms=round(gap * 1000, 1),
                threshold_ms=args.hid_threshold_ms,
                window=args.hid_window,
                suspects=[events.device_block(d) for d in suspects],
                attack_ids=["T1056.001", "T1059"],
            )
        )
        message = f"keystroke injection suspected: median gap {gap * 1000:.0f} ms"
        reporter.print_alert(message)
        reporter.notify("usb-bouncer: keystroke injection", message)

    def wait() -> None:
        time.sleep(args.interval)
        for timestamp in drain():
            on_key(timestamp)

    drain: Callable[[], list[float]] = list  # no tap, nothing to drain
    if args.hid:
        try:
            detector = hid_watch.BurstDetector(args.hid_window, args.hid_threshold_ms / 1000)
            drain = hid_watch.start()
        except ImportError:
            print('usb-bouncer: --hid needs pyobjc: pip install "usb-bouncer[hid]"', file=sys.stderr)
            return 1
        except (RuntimeError, ValueError) as exc:
            print(f"usb-bouncer: {exc}", file=sys.stderr)
            return 1

    try:
        watch(ioreg.list_devices, on_attach, on_detach, wait, args.polls)
    except KeyboardInterrupt:
        pass
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
    w = sub.add_parser("watch", help="watch for devices attaching and score each one")
    w.add_argument("--interval", type=float, default=1.0, help="seconds between polls (default 1)")
    w.add_argument("--polls", type=int, help="stop after this many polls (default: run until ^C)")
    w.add_argument("--no-log", action="store_true", help=f"do not append to {events.LOG}")
    w.add_argument("--hid", action="store_true", help="also watch keystroke timing for injection")
    w.add_argument("--hid-threshold-ms", type=float, default=40, help="median gap that counts as a machine (default 40)")
    w.add_argument("--hid-window", type=int, default=10, help="keystrokes per window (default 10)")
    w.set_defaults(run=_watch)
    args = parser.parse_args(argv)

    try:
        return args.run(args)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"usb-bouncer: could not read USB devices (macOS only): {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
