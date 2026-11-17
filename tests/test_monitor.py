"""Tests for the system_profiler collector.

Fixtures are real captures with serials replaced; see fixtures/README.md.
Structural edge cases are built inline, because a two-line dict is easier to
read than a file you have to open.
"""

import json
import sys
from pathlib import Path

import pytest

from usb_bouncer.monitor import list_devices, parse_snapshot

FIXTURES = Path(__file__).parent / "fixtures"


def _snapshot(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("capture_sandisk_flash.json", 1),
        ("capture_iphone_and_flash.json", 2),
        ("capture_dell_dock_tree.json", 12),
    ],
)
def test_capture_yields_expected_device_count(fixture, expected):
    # Counts are the devices at every depth. Each was read off the live
    # command when the capture was taken, not inferred from the file.
    assert len(parse_snapshot(_snapshot(fixture))) == expected

# Confirmed against a real capture with nothing attached: a bus with no
# devices omits _items entirely rather than reporting an empty list, and
# still carries _name, Driver, USBKeyHardwareType and USBKeyLocationID.
_EMPTY_BUS = {
    "_name": "USB 3.1 Bus",
    "Driver": "AppleT8132USBXHCI",
    "USBKeyHardwareType": "Built-in",
    "USBKeyLocationID": "0x00000000",
}


@pytest.mark.parametrize(
    "snapshot",
    [
        pytest.param({}, id="key-absent"),
        pytest.param({"SPUSBHostDataType": []}, id="no-buses"),
        pytest.param({"SPUSBHostDataType": [_EMPTY_BUS]}, id="bus-no-items"),
        # macOS does not produce this shape; kept as a guard on the .get default
        pytest.param({"SPUSBHostDataType": [_EMPTY_BUS | {"_items": []}]}, id="bus-empty-items"),
    ],
)
def test_nothing_attached_yields_no_devices(snapshot):
    assert parse_snapshot(snapshot) == []


def test_empty_capture_yields_no_devices():
    # The real thing: two built-in buses, nothing plugged in.
    snapshot = _snapshot("capture_no_devices.json")
    assert len(snapshot["SPUSBHostDataType"]) == 2
    assert parse_snapshot(snapshot) == []

def test_buses_are_not_devices():
    # Buses carry _name and USBKeyLocationID but no VID or PID, so a parser
    # keyed on location_id would report 14 devices from this file instead of 12.
    snapshot = _snapshot("capture_dell_dock_tree.json")
    buses = snapshot["SPUSBHostDataType"]
    assert len(buses) == 2

    devices = parse_snapshot(snapshot)
    bus_locations = {b["USBKeyLocationID"] for b in buses}
    assert bus_locations.isdisjoint(d.location_id for d in devices)
    assert all(d.vendor_id is not None or d.product_id is not None for d in devices)
    

def test_walk_reaches_devices_nested_below_a_hub():
    # Dock tree is bus -> dock -> dock -> keyboard. Devices three levels below
    # the bus have to arrive, and their parents have to arrive with them:
    # a walk that returns leaves only, or stops at the first device it finds,
    # both pass a plain count check on a flat capture.
    devices = parse_snapshot(_snapshot("capture_dell_dock_tree.json"))
    by_location = {d.location_id: d for d in devices}

    assert by_location["0x01200000"].name == "Dell dock"       # depth 1
    assert by_location["0x01130000"].name == "Dell dock"       # depth 2
    assert by_location["0x01132000"].name == "Dell KB216 Wired Keyboard"  # depth 3
    

def _one_device(**fields) -> dict:
    """A snapshot holding a single device node hanging off one bus."""
    return {
        "SPUSBHostDataType": [
            {"_name": "USB 3.1 Bus", "_items": [{"_name": "thing", **fields}]}
        ]
    }


def test_unparseable_id_drops_the_value_not_the_device():
    # No real capture has produced a non-hex ID under SPUSBHostDataType; values
    # arrive as bare "0x05ac". This guards against a change in output shape,
    # and pins the choice to keep a device whose descriptor is partly garbage.
    devices = parse_snapshot(
        _one_device(USBDeviceKeyVendorID="0xZZZZ", USBDeviceKeyProductID="0x55a9")
    )
    assert len(devices) == 1
    assert devices[0].vendor_id is None
    assert devices[0].product_id == 0x55A9


@pytest.mark.parametrize(
    ("fields", "vendor_id", "product_id"),
    [
        pytest.param({"USBDeviceKeyVendorID": "0x0781"}, 0x0781, None, id="vid-only"),
        pytest.param({"USBDeviceKeyProductID": "0x55a9"}, None, 0x55A9, id="pid-only"),
    ],
)
def test_either_id_alone_makes_a_device(fields, vendor_id, product_id):
    # The device test is VID *or* PID. A node declaring one and not the other
    # is a malformed descriptor, which is what should reach the table rather
    # than being dropped for looking wrong.
    (device,) = parse_snapshot(_one_device(**fields))
    assert (device.vendor_id, device.product_id) == (vendor_id, product_id)


def test_absent_optional_fields_are_none():
    (device,) = parse_snapshot(_one_device(USBDeviceKeyVendorID="0x0781"))
    assert device.serial is None
    assert device.bcd_device is None
    assert device.location_id is None
    

def test_missing_name_raises_rather_than_inventing_one():
    # _name is structural: system_profiler puts it on every node. A node
    # without one means the output shape is not what this parser was written
    # against, and KeyError names the key and points at the fixture. Same
    # argument as the UsbInterface no-defaults decision.
    snapshot = {
        "SPUSBHostDataType": [
            {"_name": "USB 3.1 Bus", "_items": [{"USBDeviceKeyVendorID": "0x0781"}]}
        ]
    }
    with pytest.raises(KeyError, match="_name"):
        parse_snapshot(snapshot)


def test_placeholder_serials_are_recorded_verbatim():
    # Real macOS reports the literal string "Not Provided" rather than an
    # absent serial: 10 of the 12 devices on this dock. The parser records it
    # as observed. Normalising here would destroy the difference between a
    # device declining to supply a serial and macOS having nothing to print,
    # and missing_serial is the rule that has to tell them apart.
    devices = parse_snapshot(_snapshot("capture_dell_dock_tree.json"))
    placeholders = [d for d in devices if d.serial == "Not Provided"]
    assert len(placeholders) == 10
    assert all(d.serial is not None for d in devices)


@pytest.mark.skipif(sys.platform != "darwin", reason="system_profiler is macOS-only")
def test_list_devices_runs_the_real_command():
    # the only test that touches the OS: proves the absolute path and the
    # data type name are right on the machine running the suite
    assert isinstance(list_devices(), list)
