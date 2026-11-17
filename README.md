# usb-bouncer

[![CI](https://github.com/MetaMaaz/usb-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/MetaMaaz/usb-bouncer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MetaMaaz/usb-bouncer)](https://github.com/MetaMaaz/usb-bouncer/releases)

macOS tool that vets unknown USB devices for BadUSB red flags and keystroke injection.

It is a detection aid, not a prevention control. It cannot block a device, and
an attacker who clones a real device's identifiers and types at human speed
gets past it. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) says exactly what it
catches and what it does not.

## Install

```bash
pipx install git+https://github.com/MetaMaaz/usb-bouncer@v1.0.0
pipx inject usb-bouncer pyobjc-framework-Quartz   # only for watch --hid
```

## Status

`list` shows connected USB devices with the descriptors macOS reports for
them. `scan` scores each device against a set of rules and gives a GREEN,
YELLOW or RED verdict. `watch` keeps running, scores each device as it
attaches, and can watch keystroke timing for injection. The
design is in [docs/DESIGN.md](docs/DESIGN.md) and the scope in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Usage

Requires macOS and Python 3.11 or newer.

```bash
usb-bouncer list
```

```text
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Name             ┃ VID    ┃ PID    ┃ Serial       ┃ Version ┃ Location   ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━┩
│ Dell dock        │ 0x0bda │ 0x0487 │ Not Provided │ 0x0157  │ 0x01200000 │
│ USB5744          │ 0x0424 │ 0x5744 │ Not Provided │ 0x0286  │ 0x01231000 │
└──────────────────┴────────┴────────┴──────────────┴─────────┴────────────┘
```

Every value in the table is reported by the device or by macOS and is
unverified. `Not Provided` is what macOS prints when a device supplies no
serial number.

```bash
usb-bouncer scan            # verdict table, and one line per device in the event log
usb-bouncer scan --json     # the same report as JSON on stdout
usb-bouncer scan --no-log   # do not write to the event log
```

`scan` reads interface descriptors from `ioreg` and scores each device. A
device that declares both a mass-storage and an HID interface is RED. A GREEN
verdict means nothing scored high enough to flag. It does not mean the device
is safe: every input is device-supplied and can be cloned.

Each verdict is appended to `~/.usb-bouncer/events.jsonl` as one JSON object
per line, tagged with MITRE ATT&CK technique IDs, ready for a SIEM to ingest:

```json
{"ts": "2026-11-17T00:50:11Z", "event": "device_verdict", "device": {"fingerprint": "a1b2c3d4e5f6a7b8", "name": "Flash", "vendor_id": "0x0781", "product_id": "0x5581", "vendor_name": "SanDisk Corp.", "serial": null}, "verdict": "RED", "score": 7, "rules_fired": ["storage_and_hid", "missing_serial"], "attack_ids": ["T1091", "T1200"], "host": "macbook"}
```

```bash
usb-bouncer watch           # score devices as they attach, notify on RED
usb-bouncer watch --hid     # also flag machine-speed typing
```

`watch` polls once a second, so a device is noticed up to a second after it
attaches. A RED verdict posts a macOS notification.

`--hid` adds the keystroke-timing detector. It needs the optional dependency
(`pip install -e ".[dev,hid]"`) and the Input Monitoring permission for your
terminal, under System Settings > Privacy & Security. It flags a run of ten
keystrokes whose median gap is under 40 ms, which a script does and a person
does not. Tune it with `--hid-threshold-ms` and `--hid-window`.

The detector installs a global key-event tap, the same primitive a keylogger
uses. It records when keys go down and never which keys: the key code is never
read, and a test fails if the constant for it appears in the package. See
[section 7 of the threat model](docs/THREAT_MODEL.md).

Rules and weights live in `src/usb_bouncer/data/rules.yaml`. Vendor names come
from a vendored copy of the public USB ID list from linux-usb.org
(`src/usb_bouncer/data/usb_ids.txt`).

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,hid]"
ruff check . && pyright && pytest
```

A release is cut by pushing a `v*` tag that matches the package version. The
release workflow reruns the checks, builds the wheel and sdist, and attaches
them to a GitHub Release.


The protected branch requires the fixed `ci-ok` check to pass and requires the
branch to be up to date before merging. Force-pushes and deletion are
disallowed, and `enforce_admins` is off so an administrator override remains
available. `ci-ok` is separate from the test matrix because branch protection
matches check-run names literally, while matrix jobs become `test (3.11)` and
`test (3.14)`. Its `if: always()` is load-bearing: without it, the job is
skipped when a dependency fails, and the skipped required check reads as
neutral rather than failed.

Pull requests and approvals are not enforced. GitHub prevents self-approval,
making a required approval unsatisfiable on a solo repository. Its settings UI
nests approvals under the pull-request requirement, so dropping the approval
rule also drops the PR requirement; I accepted that rather than route around
the UI. I still follow one issue, one branch, one PR, comment-based
self-review, and squash merges. That workflow is a convention I practise, not a
control this repository enforces.

## License

MIT. See [LICENSE](LICENSE). `src/usb_bouncer/data/usb_ids.txt` is the public
USB ID list maintained at linux-usb.org and is redistributed unmodified.
