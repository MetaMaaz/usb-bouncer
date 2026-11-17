# usb-bouncer

macOS tool that vets unknown USB devices for BadUSB red flags and keystroke injection.

## Status

v0.1 lists connected USB devices with the descriptors macOS reports for them.
It does not score or judge anything yet. Rules and verdicts arrive in v0.2,
real-time monitoring in v0.3, and the keystroke-timing detector in v0.4. The
design is in [docs/DESIGN.md](docs/DESIGN.md) and the scope in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Usage

Requires macOS and Python 3.11 or newer.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
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

## Development

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
