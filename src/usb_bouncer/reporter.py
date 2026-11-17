"""Render devices for a human reading a terminal."""

import subprocess
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .analyzer import Verdict
from .model import Device

_MISSING = "-"


def _cell(value: str | None) -> Text:
    """Make a device-supplied string safe to print.

    Names and serials come from the device, so they are attacker-controlled.
    Text() keeps rich from reading "[red]" as markup, and replacing
    non-printable characters stops a name carrying terminal escape sequences
    from moving the cursor or rewriting the row above it.
    """
    if value is None:
        return Text(_MISSING)
    return Text("".join(ch if ch.isprintable() else "�" for ch in value))


def _hex_id(value: int | None) -> str:
    # `is None`, not truthiness: 0x0000 is a reportable ID, not a missing one
    return _MISSING if value is None else f"0x{value:04x}"


def print_table(devices: list[Device]) -> None:
    """Print one row per device to stdout."""
    table = Table(title=f"Connected USB devices ({len(devices)})")
    for column in ("Name", "VID", "PID", "Serial", "Version", "Location"):
        table.add_column(column)
    for d in devices:
        table.add_row(
            _cell(d.name),
            _hex_id(d.vendor_id),
            _hex_id(d.product_id),
            _cell(d.serial),
            _cell(d.bcd_device),
            _cell(d.location_id),
        )
    Console().print(table)


_STYLE = {"GREEN": "green", "YELLOW": "yellow", "RED": "bold red"}


def print_verdicts(verdicts: list[Verdict]) -> None:
    """Print one scored row per device to stdout."""
    table = Table(title=f"USB device verdicts ({len(verdicts)})")
    for column in ("Verdict", "Score", "Name", "VID", "PID", "Vendor", "Rules fired"):
        table.add_column(column)
    for v in verdicts:
        table.add_row(
            Text(v.level, style=_STYLE[v.level]),
            str(v.score),
            _cell(v.device.name),
            _hex_id(v.device.vendor_id),
            _hex_id(v.device.product_id),
            _cell(v.device.vendor_name),
            ", ".join(v.fired) or _MISSING,
        )
    Console().print(table)
    Console().print("GREEN means nothing scored high enough to flag. It does not mean the device is safe.", style="dim")


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def print_attach(v: Verdict) -> None:
    line = Text.assemble(
        f"{_stamp()}  ",
        (f"{v.level:<6}", _STYLE[v.level]),
        "  attached  ",
        _cell(v.device.name),
        f"  {_hex_id(v.device.vendor_id)}:{_hex_id(v.device.product_id)}",
        f"  {', '.join(v.fired)}" if v.fired else "",
    )
    Console().print(line)


def print_detach(d: Device) -> None:
    line = Text.assemble(
        f"{_stamp()}  {'':<6}  detached  ",
        _cell(d.name),
        f"  {_hex_id(d.vendor_id)}:{_hex_id(d.product_id)}",
    )
    Console().print(line, style="dim")


def print_alert(message: str) -> None:
    Console().print(Text(f"{_stamp()}  RED     {message}", style=_STYLE["RED"]))


_NOTIFY = """on run argv
display notification (item 2 of argv) with title (item 1 of argv)
end run"""


def notify(title: str, body: str) -> bool:
    """Post a macOS notification. Best effort: a failure never stops the watch.

    The text goes in as arguments, not spliced into the script. A device picks
    its own name, and a name with a quote in it would otherwise be AppleScript.
    """
    try:
        done = subprocess.run(
            ["/usr/bin/osascript", "-e", _NOTIFY, title, body],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0
