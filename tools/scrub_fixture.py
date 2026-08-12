#!/usr/bin/env python3
"""Replace device serial numbers in a system_profiler fixture.

Maintainer tool, not part of the package. Operates on the raw text so the
fixture stays byte-identical to what system_profiler emitted everywhere the
serial isn't: same key spacing, same key order, no trailing newline.

Usage: python tools/scrub_fixture.py tests/fixtures/capture_foo.json
"""

import hashlib
import re
import sys
from pathlib import Path

# macOS placeholders, not device-supplied. These pass through untouched:
# a fixture that hides them stops showing what real output looks like.
PLACEHOLDERS = {"Not Provided"}

FIELD = re.compile(r'("USBDeviceKeySerialNumber"\s*:\s*")([^"]*)(")')


def fake_serial(real: str) -> str:
    """Deterministic stand-in of the same length and character class."""
    digest = hashlib.sha256(real.encode()).hexdigest()
    out = []
    for i, ch in enumerate(real):
        if ch.isdigit():
            out.append(str(int(digest[i], 16) % 10))
        elif ch.isalpha():
            pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if ch.isupper() else "abcdefghijklmnopqrstuvwxyz"
            out.append(pool[int(digest[i], 16) % 26])
        else:
            out.append(ch)
    return "".join(out)


def scrub(text: str) -> tuple[str, int]:
    count = 0

    def replace(m: re.Match) -> str:
        nonlocal count
        if m.group(2) in PLACEHOLDERS:
            return m.group(0)
        count += 1
        return m.group(1) + fake_serial(m.group(2)) + m.group(3)

    return FIELD.sub(replace, text), count


def main() -> int:
    path = Path(sys.argv[1])
    text = path.read_text(encoding="utf-8")
    scrubbed, count = scrub(text)
    path.write_text(scrubbed, encoding="utf-8")
    print(f"{path}: {count} serial(s) replaced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
