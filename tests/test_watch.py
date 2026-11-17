"""Tests for the watch loop, the timing detector, and the watch command."""

import json
import sys
import time
from pathlib import Path

import pytest

from usb_bouncer import cli, events, hid_watch, ioreg, reporter
from usb_bouncer.hid_watch import BurstDetector
from usb_bouncer.model import Device, UsbInterface
from usb_bouncer.watch import watch

SRC = Path(__file__).parent.parent / "src" / "usb_bouncer"
macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="needs macOS")


def _device(name: str, location: str = "0x01100000", interfaces=()) -> Device:
    return Device(name, 0x0781, 0x5581, None, None, "S1", None, location, interfaces=interfaces)


MOUSE = _device("Mouse", "0x01100000")
FLASH = _device("Flash", "0x01200000")
BADUSB = _device("Bad", "0x01300000", (UsbInterface(0x08, 6, 80), UsbInterface(0x03, 1, 1)))


def _run(snapshots):
    seen: list[tuple[str, str]] = []
    feed = iter(snapshots)

    def collect():
        snapshot = next(feed)
        if isinstance(snapshot, Exception):
            raise snapshot
        return snapshot

    watch(
        collect,
        lambda d: seen.append(("attach", d.name)),
        lambda d: seen.append(("detach", d.name)),
        wait=lambda: None,
        polls=len(snapshots),
    )
    return seen


def test_watch_reports_what_changed_between_polls():
    assert _run([[MOUSE], [MOUSE, FLASH], [FLASH], [FLASH]]) == [
        ("attach", "Mouse"),  # already present at start: reported once
        ("attach", "Flash"),
        ("detach", "Mouse"),
    ]


def test_watch_survives_a_failed_poll_without_inventing_events():
    assert _run([[MOUSE], OSError("ioreg hiccup"), [MOUSE]]) == [("attach", "Mouse")]


def test_watch_does_not_swallow_a_failure_on_the_first_poll():
    with pytest.raises(OSError, match="no ioreg"):
        _run([OSError("no ioreg")])


def _feed(detector: BurstDetector, gaps_ms: list[float]) -> list[float]:
    t, alerts = 0.0, []
    for gap in [0.0, *gaps_ms]:
        t += gap / 1000
        if (hit := detector.add(t)) is not None:
            alerts.append(hit)
    return alerts


def test_machine_speed_typing_is_flagged_once_per_window():
    alerts = _feed(BurstDetector(), [5] * 19)  # 20 keys, 5 ms apart
    assert alerts == [pytest.approx(0.005)] * 2


def test_human_typing_is_not_flagged():
    assert _feed(BurstDetector(), [110, 95, 140, 80, 120, 105, 90, 130, 100] * 5) == []


def test_a_few_fast_pairs_inside_normal_typing_are_not_flagged():
    # rolled keys: four of nine gaps are fast, the median is still human
    assert _feed(BurstDetector(), [110, 12, 95, 10, 140, 15, 120, 8, 105] * 5) == []


def test_window_too_small_for_a_median_is_rejected():
    with pytest.raises(ValueError, match="at least 3"):
        BurstDetector(window=2)


def test_package_never_names_the_keycode_field():
    # The privacy property in THREAT_MODEL section 7, made mechanical: the
    # detector cannot read which key was pressed without naming this constant.
    banned = "Keyboard" + "EventKeycode"
    offenders = [p.name for p in SRC.rglob("*.py") if banned in p.read_text(encoding="utf-8")]
    assert offenders == []
    assert "kCGKeyboardEventAutorepeat" in (SRC / "hid_watch.py").read_text(encoding="utf-8")


def test_watch_command_logs_verdicts_and_notifies_on_red(monkeypatch, capsys, tmp_path):
    snapshots = iter([[MOUSE], [MOUSE, BADUSB], [BADUSB]])
    notified: list[str] = []
    monkeypatch.setattr(ioreg, "list_devices", lambda: next(snapshots))
    monkeypatch.setattr(events, "LOG", tmp_path / "events.jsonl")
    monkeypatch.setattr(reporter, "notify", lambda title, body: notified.append(body))

    assert cli.main(["watch", "--polls", "3", "--interval", "0"]) == 0

    records = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert [(r["event"], r["device"]["name"]) for r in records] == [
        ("device_verdict", "Mouse"),
        ("device_verdict", "Bad"),
        ("device_detached", "Mouse"),
    ]
    assert records[1]["verdict"] == "RED"
    assert notified == ["Bad: storage_and_hid"]
    out = capsys.readouterr().out
    assert "attached" in out and "detached" in out


def test_hid_flag_without_pyobjc_fails_with_install_hint(monkeypatch, capsys):
    def no_quartz(on_key):
        raise ImportError("No module named 'Quartz'")

    monkeypatch.setattr(hid_watch, "start", no_quartz)
    assert cli.main(["watch", "--hid", "--polls", "1"]) == 1
    assert "usb-bouncer[hid]" in capsys.readouterr().err


@macos_only
def test_notification_text_is_passed_as_arguments():
    # a quote in a device name must not break out into AppleScript
    assert reporter.notify("usb-bouncer test", 'name with "quotes" and \\ backslash')


def _type(quartz, pump, keys: int, gap_s: float) -> None:
    for _ in range(keys):
        for down in (True, False):
            event = quartz.CGEventCreateKeyboardEvent(None, 0, down)
            quartz.CGEventPost(quartz.kCGHIDEventTap, event)
        time.sleep(gap_s)
    pump(0.5)


@macos_only
def test_real_event_tap_separates_injection_from_slow_typing():
    # End to end through macOS: synthetic key events posted to the HID stream,
    # read back through the listen-only tap. The slow run is the control: it
    # fails if event timestamps are not in the unit the detector assumes.
    quartz = pytest.importorskip("Quartz")
    detector = BurstDetector()
    alerts: list[float] = []

    def on_key(timestamp: float) -> None:
        if (gap := detector.add(timestamp)) is not None:
            alerts.append(gap)

    pump = hid_watch.start(on_key)

    _type(quartz, pump, keys=12, gap_s=0.08)
    assert alerts == []

    _type(quartz, pump, keys=12, gap_s=0.005)
    assert len(alerts) == 1
    assert alerts[0] < 0.040
