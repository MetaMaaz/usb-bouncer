"""Vendor names from the public USB ID list (data/usb_ids.txt)."""

import re
from functools import cache
from importlib.resources import files

_VENDOR_LINE = re.compile(r"^([0-9a-f]{4})  (.+)$", re.MULTILINE)


def parse_vendors(text: str) -> dict[int, str]:
    """Parse usb.ids text into {vendor_id: vendor_name}.

    Vendor lines start at column 0 as '<4 hex digits>  <name>'. Product and
    interface lines are tab-indented, and the class tables after the vendor
    list start with a letter and a space ('C 03  Human Interface Device').
    """
    return {int(vid, 16): name.strip() for vid, name in _VENDOR_LINE.findall(text)}


@cache
def load_vendors() -> dict[int, str]:
    data = files("usb_bouncer").joinpath("data", "usb_ids.txt")
    # the list carries a few stray Latin-1 bytes in product names
    return parse_vendors(data.read_bytes().decode("utf-8", errors="replace"))
