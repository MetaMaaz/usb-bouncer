"""Tests for the device model."""

import pytest

from usb_bouncer.model import Device, UsbInterface


def _device(**overrides) -> Device:
    base = {
        "name": "USB Flash Drive",
        "vendor_id": 0x1234,
        "product_id": 0x5678,
        "vendor_name": None,
        "manufacturer": None,
        "serial": "ABC123",
        "bcd_device": None,
        "location_id": "0x14100000",
    }
    return Device(**(base | overrides))


def test_fingerprint_tracks_only_identifying_fields():
    a, b = _device(), _device()
    assert a.fingerprint() == b.fingerprint()
    assert _device().fingerprint() != _device(serial=None).fingerprint()
    assert _device().fingerprint() != _device(location_id="0x14200000").fingerprint()
    # name is cosmetic and attacker-controlled, so it must not move the fingerprint
    assert _device().fingerprint() == _device(name="Totally Legit Drive").fingerprint()

def test_device_is_hashable():
    # guards frozen=True and the tuple-not-list choice; snapshot diffing puts
    # Devices in sets to work out what attached and detached between polls
    d = _device(interfaces=(UsbInterface(0x03, 0x00, 0x00),))
    assert len({d, _device()}) == 2

def test_interface_fields_have_no_defaults():
    # a default of None would let a parser drop interface_class silently, and
    # storage_and_hid would then read a composite device as clean
    with pytest.raises(TypeError):
        UsbInterface(interface_class=0x03)  # pyright: ignore[reportCallIssue]
