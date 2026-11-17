"""Collect USB devices from system_profiler.

The v0.1 event source: poll `system_profiler SPUSBHostDataType -json` and
flatten the bus tree into Device records. Interface classes are not available
from this source; see DESIGN.md, "Event sources and staged collection".
"""

import json
import subprocess

from .model import Device


def _snapshot_json() -> dict:
    """Run system_profiler and return its parsed JSON output."""
    out = subprocess.run(
        # absolute path: a security tool should not run whatever PATH resolves
        ["/usr/sbin/system_profiler", "SPUSBHostDataType", "-json"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


def _parse_id(raw: str | None) -> int | None:
    """Convert a reported hex ID such as '0x05ac' to an int, or None."""
    if raw is None:
        return None
    try:
        return int(raw, 16)
    except ValueError:
        return None


def _walk(node: dict, out: list[Device]) -> None:
    """Append every device node in the tree rooted at `node` to `out`."""
    if "USBDeviceKeyVendorID" in node or "USBDeviceKeyProductID" in node:
        out.append(
            Device(
                name=node["_name"],
                vendor_id=_parse_id(node.get("USBDeviceKeyVendorID")),
                product_id=_parse_id(node.get("USBDeviceKeyProductID")),
                vendor_name=None,
                manufacturer=None,
                serial=node.get("USBDeviceKeySerialNumber"),
                bcd_device=node.get("USBDeviceKeyProductVersion"),
                location_id=node.get("USBKeyLocationID"),
            )
        )
    for child in node.get("_items", []):
        _walk(child, out)


def parse_snapshot(data: dict) -> list[Device]:
    """Flatten a system_profiler snapshot into Device records."""
    devices: list[Device] = []
    for bus in data.get("SPUSBHostDataType", []):
        _walk(bus, devices)
    return devices


def list_devices() -> list[Device]:
    """Return the USB devices currently reported by system_profiler."""
    return parse_snapshot(_snapshot_json())
