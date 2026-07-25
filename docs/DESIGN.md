# usb-bouncer — Design

Design notes and the reasoning behind the tool's key decisions. Each section documents a component: what it does, why it's built this way, and the tradeoffs that choice carries.

## HID keystroke-timing detector

The detector stays dormant until a new HID device attaches. When something claiming to be a keyboard shows up, it starts recording the timestamp of each key-down event — the time only, never the key itself. It keeps the last N timestamps in a fixed-size buffer, so as new keystrokes arrive, older ones drop off and nothing accumulates. From those timestamps it computes the median gap between consecutive keystrokes. A short fast run is probably fine; a burst that stays below the threshold across its whole length is what gets flagged.
It records when you type, never what you type. The keycode is never read, so the content never enters the program at all — there is nothing to store, nothing to filter, nothing to send. That is a property you can check rather than a promise you have to trust: open the source, look at the event callback, and confirm kCGKeyboardEventKeycode never appears. Its absence is the guarantee.
The median does the work of keeping false positives down. A stray fast keystroke or two would drag an average around; the median ignores those outliers and only moves when the fast typing is consistent. That matters because humans, even quick ones, leave texture in their typing — small pauses, uneven gaps between keys. An injection tool doesn't. It dumps its payload at a uniform machine speed with no letup, and it's that sustained, even, sub-threshold rhythm the detector is built to catch.

## Device data model

Device and UsbInterface are the stable, minimal record passed through usb-bouncer: what macOS reported when a device was observed, plus whatever USB interface information the collector could see. They are an evidence model, not a complete forensic capture.

Device is declared with frozen=True, so once monitoring has constructed it, downstream code cannot alter it. The analyzer's rules and the JSONL event writer evaluate and record the same observed facts. This is an evidence-integrity guarantee inside the program; it does nothing to stop a physical USB device from reporting different descriptors on a later connection. Frozen dataclasses are also hashable, which makes Device useful when diffing snapshots to work out which devices attached or detached between polls.

The interfaces field exists in v0.1 even though it stays empty, because it fixes the model's shape early. Rules can depend on d.interfaces from the outset, and v0.2 can populate it from ioreg without changing rule signatures, restructuring the analyzer, or rewriting fixtures. An empty tuple is also honest: the tool recognises that interfaces matter, it just cannot observe them reliably from its current event source.

fingerprint() is a correlation key, not a security identity. It lets an analyst group repeated events for a device with the same reported VID, PID, serial, and location: a device that keeps reappearing stands out, one already cleared can be filtered away. It must not be used to authenticate or allowlist a device. These values are all device-supplied, and an attacker who clones a legitimate device's identifiers produces a matching fingerprint. Treat it as a trusted identity and the tool becomes worse than useless.

has_storage is a cheap proxy rather than a claim about USB interface classes. system_profiler SPUSBDataType gives device-level fields but does not reliably expose bInterfaceClass, the descriptor value that tells you whether a device presents storage (0x08), HID (0x03), or something else. A Media key suggests a mounted volume, so it is useful in v0.1 but weaker: a storage-class device that does not mount cleanly slips past it. The ioreg collector in v0.2 replaces this stopgap with real interface-class data.

The model also states what it leaves out. It does not retain keycodes, raw USB descriptor bytes, or timing histories beyond what each feature needs to reach its decision. That keeps the privacy boundary concrete and auditable, and marks the tool as a narrowly scoped device monitor rather than a full USB forensic collector.

## Event sources and staged collection

usb-bouncer starts by polling system_profiler rather than going directly to IOKit because it separates detection from operating-system plumbing. system_profiler supplies useful device-level fields with no extra dependencies, and its JSON output can be saved as fixtures for repeatable unit tests. That lets the parser, Device model, rule engine, and event writer be built and tested as pure logic before the project takes on code that subscribes to live macOS hardware events.

This first source is the weakest of the three, and that is an acceptable starting point because of what it buys in testability. It reports device information but not reliable USB interface-class descriptors. It cannot establish whether a device presents both mass-storage and HID interfaces, so v0.1 falls back on weaker proxies such as the mounted-volume has_storage flag. The cost is polling latency: a device can be connected for some time before the next poll notices it. Polling also produces snapshots rather than lifecycle events, so usb-bouncer infers attachment and removal by comparing each snapshot against the previous one.

The v0.2 stage moves to ioreg, which fills the specific gap system_profiler leaves: it exposes bInterfaceClass values. Rules such as storage-plus-HID can then reason about what a device actually declares, rather than relying on the mounted-volume proxy that v0.1 depends on. The reason this is its own stage, rather than jumping straight to IOKit, is that ioreg is still pollable and dependency-free. It closes the data gap without taking on the real-time, pyobjc-based complexity that v0.3 introduces.

IOKit is the final stage. It provides real-time attach and detach notifications, which removes polling delay and ends the need to infer lifecycle changes from snapshot diffs.

The staged approach is what keeps the analyzer independent of each collector. Each source improves the quality and timeliness of what usb-bouncer observes, but the detection rules never have to be rewritten to accommodate a stronger one.