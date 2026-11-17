"""Collect USB devices and their interface descriptors from ioreg.

The v0.2 event source. `ioreg -r -c IOUSBHostDevice -l -a` returns each USB
device as a plist dict with its IOUSBHostInterface children, which is where
bInterfaceClass lives. system_profiler (monitor.py) cannot see interfaces.
"""

import plistlib
import subprocess

from .model import Device, UsbInterface

STORAGE_CLASS = 0x08


def _snapshot() -> list:
    """Run ioreg and return its parsed plist output."""
    out = subprocess.run(
        # absolute path: a security tool should not run whatever PATH resolves
        ["/usr/sbin/ioreg", "-r", "-c", "IOUSBHostDevice", "-l", "-a", "-w", "0"],
        capture_output=True,
        check=True,
    ).stdout
    # with nothing matching, ioreg prints nothing at all rather than an empty plist
    return plistlib.loads(out) if out.strip() else []


def _children(node: dict) -> list[dict]:
    return node.get("IORegistryEntryChildren", [])


def _is_device(node: dict) -> bool:
    # keyed on descriptor fields, not on IOObjectClass: -c also matches
    # subclasses, and driver nodes below a device carry bDeviceClass alone
    return "idVendor" in node and "bDeviceClass" in node


def _is_interface(node: dict) -> bool:
    # HID driver nodes below an interface repeat bInterfaceClass, but only the
    # interface itself has a number
    return "bInterfaceNumber" in node


def _interfaces(node: dict) -> list[UsbInterface]:
    """Interfaces belonging to this device, not to devices downstream of it."""
    found: list[UsbInterface] = []
    for child in _children(node):
        if _is_interface(child):
            found.append(
                UsbInterface(
                    interface_class=child.get("bInterfaceClass"),
                    subclass=child.get("bInterfaceSubClass"),
                    protocol=child.get("bInterfaceProtocol"),
                )
            )
        elif not _is_device(child):  # a hub's downstream device owns its own interfaces
            found.extend(_interfaces(child))
    return found


def _hex(value: int | None, width: int) -> str | None:
    return None if value is None else f"0x{value:0{width}x}"


def _walk(node: dict, out: list[Device], seen: set[int]) -> None:
    entry_id = node.get("IORegistryEntryID")
    if _is_device(node) and entry_id not in seen:
        if entry_id is not None:
            seen.add(entry_id)  # a device below a hub can be listed under it and as a root
        interfaces = tuple(_interfaces(node))
        out.append(
            Device(
                name=node.get("USB Product Name") or node["IORegistryEntryName"],
                vendor_id=node["idVendor"],
                product_id=node.get("idProduct"),
                vendor_name=None,  # resolved from usb.ids by the analyzer
                manufacturer=node.get("USB Vendor Name"),  # the device's own string
                serial=node.get("USB Serial Number") or node.get("kUSBSerialNumberString"),
                bcd_device=_hex(node.get("bcdDevice"), 4),
                location_id=_hex(node.get("locationID"), 8),
                has_storage=any(i.interface_class == STORAGE_CLASS for i in interfaces),
                interfaces=interfaces,
            )
        )
    for child in _children(node):
        _walk(child, out, seen)


def parse_ioreg(data: list) -> list[Device]:
    """Flatten parsed ioreg output into Device records with interfaces."""
    devices: list[Device] = []
    seen: set[int] = set()
    for node in data:
        _walk(node, devices, seen)
    return devices


def list_devices() -> list[Device]:
    """Return the USB devices currently in the I/O Registry."""
    return parse_ioreg(_snapshot())
