"""Watch for USB attach and detach by polling and diffing snapshots."""

import sys
from collections.abc import Callable, Iterable

from .model import Device


def _ordered(devices: set[Device]) -> list[Device]:
    return sorted(devices, key=lambda d: d.location_id or "")


def watch(
    collect: Callable[[], Iterable[Device]],
    on_attach: Callable[[Device], None],
    on_detach: Callable[[Device], None],
    wait: Callable[[], None],
    polls: int | None = None,
) -> None:
    """Call on_attach / on_detach as devices come and go. Runs until `polls` runs out.

    Devices present at the first poll are reported as attached, so a watch
    starts with a full scan. A device whose descriptors change between polls
    shows up as a detach and an attach, which is what re-enumeration is.
    """
    # the first poll is allowed to raise: if it fails, nothing will ever work
    known: set[Device] = set()
    current = set(collect())
    done = 0
    while True:
        for device in _ordered(current - known):
            on_attach(device)
        for device in _ordered(known - current):
            on_detach(device)
        known = current
        done += 1
        if polls is not None and done >= polls:
            return
        wait()
        try:
            current = set(collect())
        except Exception as exc:  # noqa: BLE001  a monitor must outlive one bad poll
            print(f"usb-bouncer: poll failed, retrying: {exc}", file=sys.stderr)
