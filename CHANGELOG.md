# Changelog

## 1.0.0

- Release workflow: pushing a `v*` tag runs the checks, builds the wheel and
  sdist, and creates a GitHub Release.
- `pip-audit` in CI and Dependabot for pip and GitHub Actions.
- LICENSE, install instructions, README badges.

## 0.4.0

- `usb-bouncer watch --hid`: keystroke-timing injection detector. Records
  key-down timestamps only, never key codes. Flags a 10-keystroke window with
  a median gap under 40 ms. Logs `hid_timing_alert` events.
- The optional extra is `hid`. The earlier `realtime` extra named a package
  that does not exist.

## 0.3.0

- `usb-bouncer watch`: polls once a second, scores each device as it attaches,
  logs `device_verdict` and `device_detached` events, and posts a macOS
  notification on RED.

## 0.2.0

- `usb-bouncer scan`: GREEN, YELLOW or RED verdict per device from five rules,
  with `--json` output.
- Interface classes read from `ioreg`, which makes the storage-plus-HID rule
  work.
- Vendor names from a vendored copy of the public USB ID list.
- JSONL event log at `~/.usb-bouncer/events.jsonl`, tagged with MITRE ATT&CK
  technique IDs.

## 0.1.0

- `usb-bouncer list`: connected USB devices with the descriptors
  `system_profiler` reports.
