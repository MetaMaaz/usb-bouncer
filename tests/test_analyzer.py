"""Tests for the checks, the scoring, and the event record."""

import json
import stat

import pytest

from usb_bouncer import events
from usb_bouncer.analyzer import CHECKS, analyze, load_rules
from usb_bouncer.model import Device, UsbInterface
from usb_bouncer.usb_ids import load_vendors, parse_vendors

VENDORS = {0x0781: "SanDisk Corp.", 0x05AC: "Apple, Inc."}
RULES = load_rules()
HID, STORAGE = UsbInterface(0x03, 1, 1), UsbInterface(0x08, 6, 80)


def _device(**overrides) -> Device:
    base = {
        "name": "Ultra",
        "vendor_id": 0x0781,
        "product_id": 0x5581,
        "vendor_name": None,
        "manufacturer": "SanDisk",
        "serial": "4C530001230405117382",
        "bcd_device": "0x0100",
        "location_id": "0x01100000",
        "interfaces": (STORAGE,),
    }
    return Device(**(base | overrides))


def test_ordinary_flash_drive_is_green_and_named():
    v = analyze(_device(), RULES, VENDORS)
    assert (v.level, v.score, v.fired) == ("GREEN", 0, ())
    assert v.device.vendor_name == "SanDisk Corp."


def test_storage_plus_hid_is_red_on_its_own():
    v = analyze(_device(interfaces=(STORAGE, HID)), RULES, VENDORS)
    assert v.level == "RED"
    assert v.fired == ("storage_and_hid",)
    assert v.attack_ids == ("T1091", "T1200")


def test_unknown_vendor_without_serial_is_yellow():
    v = analyze(_device(vendor_id=0xF00D, serial=None), RULES, VENDORS)
    assert (v.level, v.score) == ("YELLOW", 3)
    assert v.fired == ("unknown_vendor", "missing_serial")


@pytest.mark.parametrize("serial", [None, "", "0000000000", "Not Provided"])
def test_missing_serial_covers_every_way_of_having_none(serial):
    # "Not Provided" is what macOS prints through system_profiler (issue #32)
    assert CHECKS["missing_serial"](_device(serial=serial), VENDORS)


def test_too_many_interfaces_needs_more_than_a_dock_has():
    assert not CHECKS["too_many_interfaces"](_device(interfaces=(HID,) * 5), VENDORS)
    assert CHECKS["too_many_interfaces"](_device(interfaces=(HID,) * 6), VENDORS)


def test_vendor_string_mismatch_logic_and_why_it_ships_disabled():
    mismatch = CHECKS["vendor_string_mismatch"]
    assert not mismatch(_device(manufacturer="SanDisk"), VENDORS)
    assert mismatch(_device(manufacturer="Totally Legit Inc"), VENDORS)
    assert not mismatch(_device(manufacturer=None), VENDORS)
    # observed on a real SanDisk drive: this is the false positive from #30
    assert mismatch(_device(manufacturer=" USB"), VENDORS)
    assert analyze(_device(manufacturer=" USB"), RULES, VENDORS).level == "GREEN"


def test_disabled_rule_does_not_score():
    rules = load_rules("thresholds: {yellow: 3, red: 6}\nrules:\n"
                       "  - {id: storage_and_hid, weight: 6, enabled: false}\n")  # fmt: skip
    assert analyze(_device(interfaces=(STORAGE, HID)), rules, VENDORS).level == "GREEN"


def test_rule_without_a_check_is_rejected():
    with pytest.raises(ValueError, match="no_such_check"):
        load_rules("thresholds: {yellow: 3, red: 6}\nrules:\n  - {id: no_such_check, weight: 9}\n")


def test_every_check_has_packaged_metadata():
    assert {r["id"] for r in RULES["rules"]} == set(CHECKS)


def test_packaged_usb_ids_parse():
    vendors = load_vendors()
    assert vendors[0x05AC] == "Apple, Inc."
    assert len(vendors) > 3000


def test_vendor_parser_ignores_products_comments_and_class_tables():
    text = "# c\n0781  SanDisk Corp.\n\t5581  Ultra\nC 03  Human Interface Device\n"
    assert parse_vendors(text) == {0x0781: "SanDisk Corp."}


def test_event_record_has_the_documented_fields(tmp_path):
    v = analyze(_device(interfaces=(STORAGE, HID), name='bad"\nname'), RULES, VENDORS)
    log = tmp_path / "sub" / "events.jsonl"
    events.append(events.verdict_record(v), log)
    events.append(events.verdict_record(v), log)

    first, _ = log.read_text(encoding="utf-8").splitlines()  # one line per event
    record = json.loads(first)
    assert list(record) == [
        "ts", "event", "device", "verdict", "score", "rules_fired", "attack_ids", "host",
    ]  # fmt: skip
    assert record["event"] == "device_verdict"
    assert record["verdict"] == "RED"
    assert record["device"]["vendor_id"] == "0x0781"
    assert record["device"]["fingerprint"] == v.device.fingerprint()
    assert record["device"]["name"] == 'bad"\nname'
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
