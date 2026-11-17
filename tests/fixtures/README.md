# Fixtures

Captured with `system_profiler SPUSBHostDataType -json` on macOS, Apple silicon.

`capture_ioreg_*.plist` files come from
`ioreg -r -c IOUSBHostDevice -l -a -w 0`. Raw output is about 800 KB for two
devices, nearly all of it driver diagnostics, so these captures are pruned to
the registry structure (`IOObjectClass`, `IORegistryEntryName`,
`IORegistryEntryID`, `IORegistryEntryChildren`) and the USB descriptor keys
(`idVendor`, `idProduct`, `bcdDevice`, `locationID`, the `bDevice*` and
`bInterface*` keys, the `i*` string indexes, and the product, vendor and
serial strings). Values are unmodified. `capture_ioreg_virtual_hid.plist` is
from a GitHub Actions macOS 26 runner, whose only USB devices are Apple's
virtual keyboard and digitizer.

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
