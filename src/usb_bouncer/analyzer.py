"""Score a device against the registered checks.

rules.yaml carries metadata (weight, ATT&CK ids, enabled). The checks are the
functions below, registered by id. Nothing from the YAML is ever evaluated.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from importlib.resources import files

import yaml

from .model import Device

HID_CLASS, STORAGE_CLASS = 0x03, 0x08
# ponytail: one flat ceiling, not per device class. Docks and webcams with
# audio sit at 4 to 5, so this only scores 1. Make it class-aware if it gets noisy.
MAX_INTERFACES = 5
# what macOS prints through system_profiler when a device supplies no serial
SERIAL_PLACEHOLDERS = {"not provided"}

Check = Callable[[Device, dict[int, str]], bool]
CHECKS: dict[str, Check] = {}


def check(rule_id: str) -> Callable[[Check], Check]:
    def register(fn: Check) -> Check:
        CHECKS[rule_id] = fn
        return fn

    return register


@check("storage_and_hid")
def _storage_and_hid(d: Device, vendors: dict[int, str]) -> bool:
    classes = {i.interface_class for i in d.interfaces}
    return HID_CLASS in classes and (STORAGE_CLASS in classes or d.has_storage)


@check("unknown_vendor")
def _unknown_vendor(d: Device, vendors: dict[int, str]) -> bool:
    return d.vendor_id is not None and d.vendor_id not in vendors


@check("missing_serial")
def _missing_serial(d: Device, vendors: dict[int, str]) -> bool:
    serial = (d.serial or "").strip().lower()
    return not serial or serial in SERIAL_PLACEHOLDERS or set(serial) <= {"0"}


@check("too_many_interfaces")
def _too_many_interfaces(d: Device, vendors: dict[int, str]) -> bool:
    return len(d.interfaces) > MAX_INTERFACES


def _words(text: str) -> set[str]:
    # ponytail: word overlap, not fuzzy matching. Misses rebrands and OEM
    # silicon, which is why the rule ships disabled.
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 2}


@check("vendor_string_mismatch")
def _vendor_string_mismatch(d: Device, vendors: dict[int, str]) -> bool:
    official = vendors.get(d.vendor_id) if d.vendor_id is not None else None
    if not official or not d.manufacturer:
        return False
    return not (_words(official) & _words(d.manufacturer))


@dataclass(frozen=True)
class Verdict:
    device: Device
    score: int
    fired: tuple[str, ...]
    attack_ids: tuple[str, ...]
    level: str  # GREEN / YELLOW / RED


def load_rules(text: str | None = None) -> dict:
    """Parse rule metadata, defaulting to the packaged rules.yaml.

    Fails on a rule id with no registered check. Skipping it silently would
    let a typo in the config switch a detection off.
    """
    if text is None:
        text = files("usb_bouncer").joinpath("data", "rules.yaml").read_text(encoding="utf-8")
    rules = yaml.safe_load(text)
    unknown = [r["id"] for r in rules["rules"] if r["id"] not in CHECKS]
    if unknown:
        raise ValueError(f"rules.yaml names checks that do not exist: {unknown}")
    return rules


def analyze(d: Device, rules: dict, vendors: dict[int, str]) -> Verdict:
    score, fired, attacks = 0, [], set()
    for rule in rules["rules"]:
        if rule.get("enabled", True) and CHECKS[rule["id"]](d, vendors):
            score += rule["weight"]
            fired.append(rule["id"])
            attacks.update(rule.get("attack_ids", []))
    limits = rules["thresholds"]
    level = "RED" if score >= limits["red"] else "YELLOW" if score >= limits["yellow"] else "GREEN"
    named = replace(d, vendor_name=vendors.get(d.vendor_id) if d.vendor_id is not None else None)
    return Verdict(named, score, tuple(fired), tuple(sorted(attacks)), level)
