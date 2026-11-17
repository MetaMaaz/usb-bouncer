"""Tests for the ioreg collector.

The capture is real output from a macOS 26 CI runner, pruned to the keys
listed in fixtures/README.md. Shapes not physically available (a hub, a
composite storage-plus-HID device) are built inline.
"""

import plistlib
import sys
from pathlib import Path

import pytest

from usb_bouncer.ioreg import list_devices, parse_ioreg
from usb_bouncer.model import UsbInterface

FIXTURES = Path(__file__).parent / "fixtures"


def _device(name="Flash", location=0x01100000, entry_id=None, children=()):
    node = {
        "IORegistryEntryName": name,
        "USB Product Name": name,
        "idVendor": 0x0781,
        "idProduct": 0x5581,
        "bDeviceClass": 0,
        "bcdDevice": 0x0100,
        "locationID": location,
        "IORegistryEntryChildren": list(children),
    }
    return node if entry_id is None else node | {"IORegistryEntryID": entry_id}


def _interface(cls, children=()):
    return {
        "bInterfaceNumber": 0,
        "bInterfaceClass": cls,
        "bInterfaceSubClass": 0,
        "bInterfaceProtocol": 0,
        "IORegistryEntryChildren": list(children),
    }


def test_capture_yields_devices_with_interfaces():
    with (FIXTURES / "capture_ioreg_virtual_hid.plist").open("rb") as f:
        keyboard, digitizer = parse_ioreg(plistlib.load(f))

    assert keyboard.name == "Virtual USB Keyboard"
    assert (keyboard.vendor_id, keyboard.product_id) == (0x05AC, 0x8105)
    assert keyboard.manufacturer == "Apple Inc."
    assert keyboard.serial is None  # iSerialNumber is 0 in the capture
    # same rendering as system_profiler, so both sources agree on location
    assert keyboard.location_id == "0x0c900000"
    # the HID driver nodes under the interface repeat bInterfaceClass; one
    # interface must still count once
    assert keyboard.interfaces == (UsbInterface(0x03, 1, 1),)
    assert digitizer.interfaces == (UsbInterface(0x03, 0, 0),)


def test_composite_device_reports_both_classes_and_storage():
    driver_between = {"bDeviceClass": 0, "IORegistryEntryChildren": [_interface(0x03)]}
    (device,) = parse_ioreg([_device(children=[_interface(0x08), driver_between])])
    assert [i.interface_class for i in device.interfaces] == [0x08, 0x03]
    assert device.has_storage


def test_hub_does_not_claim_its_downstream_devices_interfaces():
    keyboard = _device("Keyboard", 0x01110000, children=[_interface(0x03)])
    hub, downstream = parse_ioreg([_device("Hub", children=[_interface(0x09), keyboard])])
    assert [i.interface_class for i in hub.interfaces] == [0x09]
    assert [i.interface_class for i in downstream.interfaces] == [0x03]


def test_device_listed_under_its_hub_and_as_a_root_counts_once():
    keyboard = _device("Keyboard", 0x01110000, entry_id=2)
    hub = _device("Hub", entry_id=1, children=[keyboard])
    assert [d.name for d in parse_ioreg([hub, keyboard])] == ["Hub", "Keyboard"]


def test_serial_is_read_when_present():
    (device,) = parse_ioreg([_device() | {"USB Serial Number": "ABC123"}])
    assert device.serial == "ABC123"


def test_nothing_attached_yields_no_devices():
    assert parse_ioreg([]) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="ioreg is macOS-only")
def test_list_devices_runs_the_real_command():
    # every device the live registry reports must parse, unpruned
    assert isinstance(list_devices(), list)
