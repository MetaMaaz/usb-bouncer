# Fixtures

Captured with `system_profiler SPUSBHostDataType -json` on macOS, Apple silicon.

Naming:

- `capture_*` — real output with device serial numbers replaced by
  `tools/scrub_fixture.py`. Structure, field names, and all other values are
  unmodified. A capture with no serials in it, such as
  `capture_no_devices.json`, is the command's output byte for byte.
- `fake_*` — hand-constructed inputs simulating devices not physically
  available, such as composite storage-plus-HID.

Serials are replaced because these files are public and the originals identify
physical devices. Replacements keep the original length and character class so
serial-dependent behaviour is unaffected, and they are derived from a SHA-256
of the real serial, so the same device gets the same stand-in in every
fixture. The macOS placeholder `Not Provided` is left alone because it is not
a serial. Device names are not scrubbed.
