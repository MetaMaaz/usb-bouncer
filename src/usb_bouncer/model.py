"""Normalized USB device records.

Every collector (system_profiler v0.1, ioreg v0.2, IOKit v0.3) produces these
types; everything downstream reads them. No collection logic here, and no
imports from the rest of the package.
"""

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class UsbInterface:
    """One USB interface descriptor as reported by the device.

    Empty in v0.1, populated from ioreg in v0.2. Device-supplied, unverified.
    """

    interface_class: int | None   # bInterfaceClass: 0x03 HID, 0x08 mass storage
    subclass: int | None
    protocol: int | None

@dataclass(frozen=True)
class Device:
    """A USB device as observed at one point in time.

    Evidence, not a forensic capture: every field is device-reported and
    unverified. Frozen so the analyzer and event writer see identical facts,
    and so devices are hashable for snapshot diffing.
    """

    name: str
    vendor_id: int | None
    product_id: int | None
    vendor_name: str | None
    manufacturer: str | None
    serial: str | None
    bcd_device: str | None
    location_id: str | None
    has_storage: bool = False
    interfaces: tuple[UsbInterface, ...] = ()

    def fingerprint(self) -> str:
        """Correlation key for grouping events. Not an identity, not a control.

        Inputs are all device-supplied, so an attacker who clones them
        produces a matching fingerprint. Never allowlist on this.
        """
        raw = f"{self.vendor_id}:{self.product_id}:{self.serial}:{self.location_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

def _gate_check(x: int) -> int:
    return "not an int"
