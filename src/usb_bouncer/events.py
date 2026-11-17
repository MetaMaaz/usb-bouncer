"""Verdicts as JSON records, and the append-only JSONL event log.

Schema is documented in DESIGN.md, "JSONL SIEM schema". Field names are a
contract with whatever parses the log: add fields, do not rename them.
"""

import json
import os
import socket
from datetime import UTC, datetime
from pathlib import Path

from .analyzer import Verdict
from .model import Device

LOG = Path.home() / ".usb-bouncer" / "events.jsonl"


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:04x}"


def device_block(d: Device) -> dict:
    return {
        "fingerprint": d.fingerprint(),
        "name": d.name,
        "vendor_id": _hex(d.vendor_id),
        "product_id": _hex(d.product_id),
        "vendor_name": d.vendor_name,
        "serial": d.serial,
    }


def envelope(event: str, **fields) -> dict:
    return {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": event,
        **fields,
        "host": socket.gethostname(),
    }


def verdict_record(v: Verdict) -> dict:
    return envelope(
        "device_verdict",
        device=device_block(v.device),
        verdict=v.level,
        score=v.score,
        rules_fired=list(v.fired),
        attack_ids=list(v.attack_ids),
    )


def append(record: dict, path: Path | None = None) -> None:
    """Append one record as one line. The log holds serials, so it is owner-only."""
    path = path or LOG
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # json.dumps escapes control characters, so a device name cannot break the line
    line = json.dumps(record) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line)
