"""Tests for the CLI and the table it prints."""

import json
from pathlib import Path

import pytest

from usb_bouncer import cli, monitor
from usb_bouncer.model import Device
from usb_bouncer.reporter import print_table

FIXTURES = Path(__file__).parent / "fixtures"


def _device(**overrides) -> Device:
    base = {
        "name": "Mouse",
        "vendor_id": 0x046D,
        "product_id": 0xC077,
        "vendor_name": None,
        "manufacturer": None,
        "serial": None,
        "bcd_device": None,
        "location_id": None,
    }
    return Device(**(base | overrides))


def test_list_prints_every_device(monkeypatch, capsys):
    snapshot = json.loads((FIXTURES / "capture_sandisk_flash.json").read_text(encoding="utf-8"))
    devices = monitor.parse_snapshot(snapshot)
    monkeypatch.setattr(monitor, "list_devices", lambda: devices)

    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert f"({len(devices)})" in out
    assert "0x0781" in out  # SanDisk VID, rendered as reported


def test_list_fails_cleanly_without_system_profiler(monkeypatch, capsys):
    def boom():
        raise FileNotFoundError("/usr/sbin/system_profiler")

    monkeypatch.setattr(monitor, "list_devices", boom)
    assert cli.main(["list"]) == 1
    assert "macOS only" in capsys.readouterr().err


def test_no_command_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_device_strings_cannot_inject_markup_or_escapes(capsys):
    # the name is attacker-controlled: it must print as data, not as styling
    print_table([_device(name="[red]evil[/red]\x1b[2J\x1b[H")])
    out = capsys.readouterr().out
    assert "[red]evil[/red]" in out
    assert "\x1b" not in out


def test_zero_id_is_shown_and_missing_id_is_not_invented(capsys):
    print_table([_device(vendor_id=0, product_id=None)])
    out = capsys.readouterr().out
    assert "0x0000" in out
    assert "0xc077" not in out
