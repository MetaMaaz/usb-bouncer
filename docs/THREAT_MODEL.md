# Threat Model — usb-bouncer

## 1. Scope

usb-bouncer is a userspace macOS command-line tool that inspects USB devices
attached to the host and reports whether their descriptors and behaviour show
indicators consistent with a BadUSB or keystroke-injection attack.

It is a **detection and triage aid, not a prevention control**. It cannot block
a device, and it cannot tell you a device is safe — it can only tell you that a
device looks unusual, and say precisely why. Every verdict is an assertion about
*indicators*, not about intent. A GREEN verdict means "nothing this tool checks
for fired," which is a much weaker claim than "this device is benign," and the
tool's output is written to make that distinction visible rather than to hide it.

The tool runs unprivileged, in userspace, on the machine being defended. It does
not require kernel extensions, a signed system extension, or root. That
constraint is deliberate and it shapes everything in the "out of scope" section
below.

## 2. Assets

What a malicious USB device can reach on a macOS host, and therefore what this
tool is defending:

- **The keyboard input stream.** A device that claims to be a keyboard is
  trusted by the OS as a keyboard. macOS has no mechanism to distinguish a
  human pressing keys from a microcontroller replaying a script. This is the
  highest-value asset because it is the one the OS itself cannot protect.
- **The interactive user session.** Injected keystrokes execute as the logged-in
  user — opening Terminal, running a curl-to-shell one-liner, granting a TCC
  prompt. Note this is *user-level* execution, not admin. Privilege escalation is
  a separate, subsequent step that this tool does not attempt to detect.
- **Mounted storage and the files reachable from that session.** Anything the
  user can read, an injected payload can read and exfiltrate.
- **The user's trust that a device is what it physically appears to be.** A cable,
  a charger, and a flash drive are all objects users plug in without thought. This
  asset is not technical, but it is the one every USB attack actually exploits,
  and it is the reason a tool like this needs to exist at all.

## 3. Adversary

The adversary has **brief physical access** to the host, or to something the
victim will voluntarily plug into the host. They have no prior remote foothold,
no credentials, and no persistence on the machine before the device is attached.

Concrete scenarios in scope:

- **Evil maid.** Unattended laptop in a hotel room, office, or library; the
  attacker plugs in a device for seconds and leaves.
- **Drop attack.** A "found" USB stick in a car park or lobby, plugged in by a
  curious or helpful user.
- **Supply-chain / lookalike swap.** A charging cable or dock is substituted for
  a visually identical one containing an embedded HID implant (e.g. an O.MG-style
  cable).

Out of the adversary model: any attacker who already has code execution on the
host. If they are already inside, the USB layer is not where you catch them, and
nothing in this tool would help.

## 4. In-scope threats

Each threat is mapped to its MITRE ATT&CK technique and to the specific detector
that addresses it.

### 4.1 BadUSB / HID masquerading — T1200 (Hardware Additions)

A device physically shaped like a flash drive, cable, or charger enumerates as a
Human Interface Device. The OS trusts it as a keyboard because the USB spec has
no notion of a device lying about its class.

*Detection:* descriptor analysis. A device presenting an HID interface class
(0x03) when its form factor and other descriptors suggest storage is scored
heavily.

### 4.2 Keystroke injection — T1056.001 (Input Capture), T1059 (Command and Scripting Interpreter)

The classic Rubber Ducky pattern: once trusted as a keyboard, the device types a
payload faster than any human could. T1056.001 covers the input-stream abuse;
T1059 covers whatever the injected keystrokes actually execute.

*Detection:* keystroke-timing analysis. Sustained inter-arrival times below a
human threshold (~40 ms median over a rolling window) indicate a machine, not a
person. See §7 for the privacy constraint on this detector.

### 4.3 Composite device tricks — T1091 (Replication Through Removable Media) + T1200

A device exposing both mass-storage (0x08) and HID (0x03) interfaces: it mounts
as a legitimate drive to allay suspicion, while the HID interface delivers the
payload. This is the flagship rule.

*Detection:* interface-class enumeration. See §6 — this rule is only fully
functional from v0.2.0.

### 4.4 VID/PID spoofing and descriptor inconsistency — T1200

A device claims a Vendor ID belonging to a reputable manufacturer while its
descriptor strings, serial number, or interface layout contradict that claim.

*Detection:* cross-checking the claimed VID against the public USB ID database,
comparing the resolved vendor name against the device's own manufacturer string,
and flagging missing or all-zero serial numbers.

## 5. Out of scope

The following are real USB attack classes that this tool deliberately does not
address. The reason is the same for all of them, and it is a design decision
rather than an oversight: **detecting these requires kernel-level or hardware
instrumentation, and usb-bouncer is constrained to unprivileged userspace.**
Building them would mean shipping a kernel extension or system extension — a much
larger attack surface in a tool whose entire purpose is to reduce attack surface.

- **Firmware-level attacks.** Reflashing a device's controller firmware (the
  original BadUSB research). The malicious behaviour lives below the descriptor
  layer this tool reads.
- **USB Killer / electrical attacks.** A capacitor bank that destroys the port.
  This is a hardware problem with a hardware answer (a data-only "USB condom");
  no software can detect or prevent it.
- **Kernel and driver exploits over USB.** Malformed descriptors that trigger
  memory corruption in the USB stack itself. By the time the tool parses the
  descriptor, the vulnerable code has already run.
- **DMA attacks over Thunderbolt/PCIe.** These bypass the USB layer entirely and
  are addressed by IOMMU/VT-d, not by descriptor inspection.

## 6. Detection limits and known evasions

This section is deliberate. A threat model that only lists what a tool catches is
marketing, not engineering.

**A competent attacker defeats both detectors.** Clone a legitimate VID/PID pair
from a real vendor, populate the descriptor strings and serial number
consistently, and type the payload at a plausible human cadence with randomised
inter-key jitter. The descriptor checks find nothing anomalous, and the timing
detector sees a fast but human typist. Every indicator this tool relies on is
attacker-controlled data. That is the fundamental ceiling of descriptor-based
detection, and no amount of rule-tuning raises it.

**The flagship rule is not fully functional in v0.1.0.** `system_profiler
SPUSBDataType` returns device-level fields (VID, PID, serial, manufacturer) but
does not reliably expose `bInterfaceClass` for each interface. The
"storage-class device that also presents HID" rule therefore cannot be built from
`system_profiler` alone. v0.1.0 scopes to the checks that data supports; v0.2.0
adds an `ioreg`-based interface enumerator to unlock it. The rule ships in
`rules.yaml` from the start, correctly weighted, so the gap is visible in the
config rather than hidden in the code.

**The timing detector has an irreducible false-positive rate.** Fast human
typists, key-repeat, IDE autocomplete, and paste-like input from other tools can
all dip below the threshold briefly. This is why the detector requires a
*sustained* burst rather than a single fast interval, and why both the threshold
and the window length are configurable. A measured false-positive rate will be
published in `docs/POSTMORTEM.md` after v1.0.

**Scoring is heuristic, not probabilistic.** The weights in `rules.yaml` are
engineering judgement, not calibrated likelihoods. They are tunable precisely
because they are guesses, and they are exposed in config rather than hardcoded so
that a user can disagree with them.

## 7. Privacy constraint on the HID detector

The keystroke-timing detector installs a `CGEventTap` on the global key-down
event stream. **Mechanically, this is the same primitive a keylogger uses**, and
that fact deserves to be stated plainly rather than buried.

The detector records **only the arrival timestamp of each key-down event**, in a
fixed-size ring buffer. It never reads `kCGKeyboardEventKeycode`. It cannot know
which key was pressed, only that *a* key was pressed and *when*. The tap is
created in listen-only mode, so it