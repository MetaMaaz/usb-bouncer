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

## No-eval rule engine

Rules in rules.yaml are not executable expressions. Passing configuration strings to eval() would turn the rule pack into a code-execution surface: a modified file, a deployment mistake, or a supply-chain compromise could make the security tool run arbitrary Python. That is a bad property for any tool, and a worse one for software meant to assess untrusted devices.

Instead, rules.yaml carries metadata: each rule's weight, description, ATT&CK identifier, and enabled status. The checks themselves are ordinary Python functions, registered under stable IDs with @check("rule_id"). The analyzer uses the ID to find the matching function and pairs its result with that rule's metadata.

This fixes the set of behaviours the tool can perform at code-review time. Configuration can enable, disable, and weight rules, but it cannot introduce a behaviour that is not already in the reviewed codebase.

The reference analyzer currently skips a YAML rule that has no registered function: the lookup returns nothing and analysis continues. That is a limitation, not validation. A later version could check the YAML and registry IDs at startup and fail on any mismatch, but the design should not claim that behaviour until it exists.

The split also keeps testing simple. Each check function can be unit-tested against a small constructed Device fixture, without parsing YAML or running the full analyzer. Separate tests cover the metadata, enabled flags, weights, and result assembly. Configuration changes cannot alter rule logic; they only decide whether a reviewed rule runs and how its finding is scored and reported.

## JSONL SIEM schema

Each usb-bouncer event is written as one JSON object per line in ~/.usb-bouncer/events.jsonl. A record carries ts, event, a nested device object, verdict, score, rules_fired, attack_ids, and host.

JSONL fits an append-only event log. New events are written without reading or rewriting earlier ones. An interrupted write may leave one malformed final line, but it damages at most that event; every preceding line stays independently valid and ingestible, and a SIEM can skip the bad line and continue. A single JSON array would mean managing commas and a closing bracket as the log grows, and CSV handles nested device data, string arrays like rules_fired and attack_ids, and optional fields poorly.

The field names are a contract with anything that parses the log: the local SIEM mapping, later dashboards, detection rules, and investigation scripts. Once one of those depends on attack_ids, renaming it to attackIds can silently break searches and alerts, or split historical data across two fields. Additive changes are usually safe; renames and incompatible type changes need an explicit migration.

ts uses ISO-8601 UTC so timestamps are unambiguous across hosts, time zones, daylight-saving changes, and SIEM deployments. The format reads cleanly to a human and still sorts correctly as a string, and UTC lets an investigator line usb-bouncer events up against endpoint, network, and identity logs without converting local time first. A Unix epoch is more compact but less inspectable, and easy to mishandle when someone assumes the wrong units.

The nested device block carries the device fingerprint as a correlation key. As covered in the device data model, it lets analysts group repeated connections from the same reported attributes, spot a recurring device, and avoid reinvestigating one they have already cleared. It is not authentication or proof of physical identity: its inputs are device-reported and can be cloned or spoofed.

Together, the line-per-event structure and the stable schema make direct SIEM ingestion predictable. An analyst can query for high-score device attachments on a host, or group events by fingerprint and ATT&CK ID to chase down recurring activity.