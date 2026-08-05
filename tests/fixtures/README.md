# Fixtures

Captured with `system_profiler SPUSBHostDataType -json` on macOS, Apple silicon.

Naming:

- `capture_*` — real output with device serial numbers replaced. Structure,
  field names, and all other values are unmodified.
- `fake_*` — hand-constructed inputs simulating devices not physically
  available, such as composite storage-plus-HID.

Serials are replaced because these files are public and the originals identify
physical devices. Replacements keep the original length and character class so
serial-dependent behaviour is unaffected.
