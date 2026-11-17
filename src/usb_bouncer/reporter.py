"""Render devices for a human reading a terminal."""

from rich.console import Console
from rich.table import Table
from rich.text import Text

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
