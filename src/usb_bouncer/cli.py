"""Command-line entry point."""

import argparse
import subprocess
import sys

from . import __version__, monitor, reporter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="usb-bouncer",
        description="Vet USB devices for BadUSB red flags and keystroke injection.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list connected USB devices")
    parser.parse_args(argv)  # "list" is the only command, so nothing to dispatch on yet

    try:
        devices = monitor.list_devices()
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"usb-bouncer: could not run system_profiler (macOS only): {exc}", file=sys.stderr)
        return 1
    reporter.print_table(devices)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
